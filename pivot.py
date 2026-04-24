"""
FORENSTIX 2.0 — IOC Pivot Engine

Maps IOC types to the right investigation tools and executes them
synchronously (with a configurable timeout).  No job queue is needed
for the initial implementation; streaming is provided via SSE in app.py.

IOC Type → Default Tools
  domain   → subfinder, amass, dnstwist, httpx, wafw00f, nuclei, testssl
  url      → httpx, wafw00f, nuclei, testssl, katana
  email    → holehe, theharvester, maigret
  ip       → nmap, masscan
  hash     → virustotal (handled in app.py; pivot here calls external tools)
  username → sherlock, maigret, socialscan
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, Generator, List, Optional

from fx_catalog import TOOLS, by_id, Tool
from fx_env import detect as detect_env
from fx_output import parse_output, make_result, make_error

# ─── IOC → tool mapping ───────────────────────────────────────────────────

IOC_TOOL_MAP: Dict[str, List[str]] = {
    "domain":   ["subfinder", "amass", "dnstwist", "httpx", "wafw00f", "nuclei"],
    "url":      ["httpx", "wafw00f", "nuclei", "testssl", "katana"],
    "email":    ["holehe", "theharvester", "maigret"],
    "ip":       ["nmap", "masscan"],
    "hash":     [],          # handled by VirusTotal in app.py
    "username": ["sherlock", "maigret", "socialscan"],
}

# Per-tool recommended arg templates (override run_cmd from catalog)
# {target} is substituted with the actual IOC value
PIVOT_CMD_OVERRIDES: Dict[str, str] = {
    "subfinder":    "subfinder -silent -d {target}",
    "amass":        "amass enum -passive -d {target}",
    "dnstwist":     "dnstwist -r {target}",
    "httpx":        "httpx -u {target} -title -status-code -tech-detect -silent",
    "wafw00f":      "wafw00f {target}",
    "nuclei":       "nuclei -u {target} -severity medium,high,critical -silent",
    "testssl":      "testssl.sh/testssl.sh {target}",
    "katana":       "katana -u {target} -depth 2 -silent",
    "holehe":       "holehe --only-used {target}",
    "theharvester": "theHarvester -d {target} -b all",
    "maigret":      "maigret --no-color {target}",
    "nmap":         "nmap -T4 -F --open {target}",
    "masscan":      "masscan {target} -p1-1024 --rate 500",
    "sherlock":     "sherlock --print-found {target}",
    "socialscan":   "socialscan {target}",
}

DEFAULT_TIMEOUT = 60   # seconds per tool


# ─── Execution helpers ────────────────────────────────────────────────────

def _build_cmd(tool_id: str, target: str) -> Optional[str]:
    """Return the shell command string for a given tool + target."""
    if tool_id in PIVOT_CMD_OVERRIDES:
        return PIVOT_CMD_OVERRIDES[tool_id].replace("{target}", target)
    catalog = by_id()
    tool = catalog.get(tool_id)
    if tool:
        return tool.run_cmd.replace("{args}", target)
    return None


def _tool_available(tool_id: str, env=None) -> bool:
    """Check if a tool binary/docker-image is available."""
    if env is None:
        env = detect_env()

    catalog = by_id()
    tool = catalog.get(tool_id)
    if not tool:
        return False

    if env.docker_available and tool.docker_image:
        return True

    # Check for the binary name (first word of run_cmd)
    run_cmd = PIVOT_CMD_OVERRIDES.get(tool_id, tool.run_cmd)
    binary = run_cmd.split()[0]
    return shutil.which(binary) is not None


def _run_native(cmd: str, timeout: int) -> tuple[int, str, str]:
    """Run a command natively and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            ["bash", "-lc", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return (
            result.returncode,
            result.stdout.decode(errors="replace"),
            result.stderr.decode(errors="replace"),
        )
    except subprocess.TimeoutExpired:
        return (-1, "", f"Tool timed out after {timeout}s")
    except Exception as e:
        return (-1, "", str(e))


def _run_docker(image: str, cmd: str, timeout: int) -> tuple[int, str, str]:
    """Run a command in Docker."""
    docker_cmd = f"docker run --rm --network host {image} {cmd}"
    return _run_native(docker_cmd, timeout + 30)


def run_tool(
    tool_id: str,
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    evidence_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute a single tool against a target IOC.
    Returns a result envelope compatible with fx_output.make_result().
    """
    env = detect_env()
    catalog = by_id()
    tool: Optional[Tool] = catalog.get(tool_id)

    if not tool:
        return make_error(tool_id, f"Unknown tool: {tool_id}", evidence_id)

    cmd_str = _build_cmd(tool_id, target)
    if not cmd_str:
        return make_error(tool_id, "Could not build command", evidence_id)

    start = time.monotonic()
    backend = env.backend

    if env.docker_available and tool.docker_image:
        # Use purpose-built Docker image
        # Build args: strip the binary prefix from cmd_str
        img = tool.docker_image
        binary = cmd_str.split()[0]
        args = cmd_str[len(binary):].strip()
        rc, stdout, stderr = _run_docker(img, args, timeout)
        backend = "docker"
    else:
        rc, stdout, stderr = _run_native(cmd_str, timeout)

    elapsed = time.monotonic() - start
    parsed = parse_output(tool_id, stdout)

    return make_result(
        tool_id=tool_id,
        tool_name=tool.name,
        target=target,
        backend=backend,
        command=cmd_str,
        returncode=rc,
        stdout=stdout,
        stderr=stderr,
        elapsed=elapsed,
        evidence_id=evidence_id,
        parsed=parsed,
    )


def run_pivot(
    ioc_type: str,
    value: str,
    tools: Optional[List[str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    evidence_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Run all appropriate tools for an IOC value.
    Returns a list of result envelopes.
    """
    tool_ids = tools if tools else IOC_TOOL_MAP.get(ioc_type, [])
    env = detect_env()
    results = []

    for tool_id in tool_ids:
        if not _tool_available(tool_id, env):
            results.append(make_error(
                tool_id,
                f"Tool not installed — run: fx_run.py {tool_id} --install",
                evidence_id,
            ))
            continue
        results.append(run_tool(tool_id, value, timeout=timeout, evidence_id=evidence_id))

    return results


def stream_pivot(
    ioc_type: str,
    value: str,
    tools: Optional[List[str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    evidence_id: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Generator that yields SSE-formatted events for each tool result.

    Usage (Flask):
        return Response(stream_pivot(...), mimetype='text/event-stream')
    """
    tool_ids = tools if tools else IOC_TOOL_MAP.get(ioc_type, [])
    env = detect_env()

    def _sse(event: str, data: Any) -> str:
        return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"

    yield _sse("start", {"ioc_type": ioc_type, "value": value,
                          "tools": tool_ids, "evidence_id": evidence_id})

    for tool_id in tool_ids:
        catalog = by_id()
        tool = catalog.get(tool_id)
        tool_name = tool.name if tool else tool_id

        if not _tool_available(tool_id, env):
            yield _sse("result", make_error(tool_id,
                        "Tool not installed", evidence_id))
            continue

        yield _sse("running", {"tool": tool_id, "tool_name": tool_name})

        result = run_tool(tool_id, value, timeout=timeout, evidence_id=evidence_id)
        yield _sse("result", result)

    yield _sse("done", {"ioc_type": ioc_type, "value": value})
