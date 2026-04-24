#!/usr/bin/env python3
"""
FORENSTIX 2.0 — fx_run.py  (CLI tool runner)

Executes any tool in the catalog against a target, with optional caching,
audit logging, dry-run, and parallel execution.

Usage:
  python fx_run.py <tool_id> <target> [options]

Options:
  --timeout N          per-tool timeout in seconds (default 60)
  --output json|text|table  output format (default text)
  --dry-run            print the command without executing
  --parallel TOOL,...  run multiple tools against the same target
  --evidence-id ID     tag results with a case/evidence identifier
  --no-cache           bypass result cache
  --check              check whether the tool is available, then exit

Examples:
  python fx_run.py nmap 192.168.1.1 --output json
  python fx_run.py --parallel subfinder,amass,dnstwist example.com
  python fx_run.py volatility3 memory.dmp --timeout 300
  python fx_run.py nmap 10.0.0.1 --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fx_catalog import TOOLS, by_id
from fx_env import detect as detect_env
from fx_output import parse_output, make_result, make_error, format_result

# ─── Cache ────────────────────────────────────────────────────────────────

_CACHE_DIR = Path(os.environ.get("FORENSTIX_CACHE", Path.home() / ".forenstix" / "cache"))
_CACHE_TTL = int(os.environ.get("FORENSTIX_CACHE_TTL", 3600))  # 1 hour


def _cache_key(tool_id: str, target: str) -> str:
    return hashlib.sha256(f"{tool_id}::{target}".encode()).hexdigest()[:32]


def _read_cache(tool_id: str, target: str) -> Optional[Dict]:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(tool_id, target)
    path = _CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    age = time.time() - path.stat().st_mtime
    if age > _CACHE_TTL:
        path.unlink(missing_ok=True)
        return None
    try:
        result = json.loads(path.read_text())
        result["cached"] = True
        return result
    except Exception:
        return None


def _write_cache(tool_id: str, target: str, result: Dict) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(tool_id, target)
    path = _CACHE_DIR / f"{key}.json"
    try:
        path.write_text(json.dumps(result, default=str))
    except Exception:
        pass


# ─── Audit log ────────────────────────────────────────────────────────────

_AUDIT_LOG = Path(os.environ.get("FORENSTIX_AUDIT", Path.home() / ".forenstix" / "audit.jsonl"))


def _audit(result: Dict) -> None:
    _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _AUDIT_LOG.open("a") as f:
            f.write(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tool": result.get("tool"),
                "target": result.get("target"),
                "exit_code": result.get("exit_code"),
                "elapsed_sec": result.get("elapsed_sec"),
                "evidence_id": result.get("evidence_id"),
                "cached": result.get("cached", False),
            }, default=str) + "\n")
    except Exception:
        pass


# ─── Execution ────────────────────────────────────────────────────────────

def _run_native(cmd: str, timeout: int) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            ["bash", "-lc", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


def _run_docker(image: str, args: str, timeout: int) -> tuple[int, str, str]:
    cmd = f"docker run --rm --network host {image} {args}"
    return _run_native(cmd, timeout + 30)


def run_tool(
    tool_id: str,
    target: str,
    timeout: int = 60,
    evidence_id: Optional[str] = None,
    use_cache: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Run a catalog tool against a target."""
    catalog = by_id()
    tool = catalog.get(tool_id)
    if not tool:
        return make_error(tool_id, f"Unknown tool: {tool_id}", evidence_id)

    cmd_str = tool.run_cmd.replace("{args}", target)

    if dry_run:
        return {
            "tool": tool_id,
            "tool_name": tool.name,
            "target": target,
            "command": cmd_str,
            "dry_run": True,
            "ok": True,
        }

    if use_cache:
        cached = _read_cache(tool_id, target)
        if cached:
            _audit(cached)
            return cached

    env = detect_env()
    backend = env.backend
    start = time.monotonic()

    if env.docker_available and tool.docker_image:
        binary = cmd_str.split()[0]
        args = cmd_str[len(binary):].strip()
        rc, stdout, stderr = _run_docker(tool.docker_image, args, timeout)
        backend = "docker"
    else:
        rc, stdout, stderr = _run_native(cmd_str, timeout)

    elapsed = time.monotonic() - start
    parsed = parse_output(tool_id, stdout)

    result = make_result(
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

    if use_cache and rc == 0:
        _write_cache(tool_id, target, result)

    _audit(result)
    return result


def run_parallel(
    tool_ids: List[str],
    target: str,
    timeout: int = 60,
    evidence_id: Optional[str] = None,
    use_cache: bool = True,
) -> List[Dict[str, Any]]:
    """Run multiple tools in parallel using threads."""
    import threading
    results: List[Optional[Dict]] = [None] * len(tool_ids)

    def _worker(idx: int, tid: str) -> None:
        results[idx] = run_tool(tid, target, timeout, evidence_id, use_cache)

    threads = [
        threading.Thread(target=_worker, args=(i, tid))
        for i, tid in enumerate(tool_ids)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return [r for r in results if r is not None]


def check_tool(tool_id: str) -> Dict[str, Any]:
    """Return availability info for a tool."""
    catalog = by_id()
    tool = catalog.get(tool_id)
    if not tool:
        return {"tool": tool_id, "available": False, "reason": "Not in catalog"}

    env = detect_env()
    binary = tool.run_cmd.split()[0]
    native_ok = shutil.which(binary) is not None
    docker_ok = bool(env.docker_available and tool.docker_image)

    return {
        "tool": tool_id,
        "tool_name": tool.name,
        "category": tool.category,
        "binary": binary,
        "native_available": native_ok,
        "docker_available": docker_ok,
        "docker_image": tool.docker_image,
        "available": native_ok or docker_ok,
        "install_cmd": tool.install_cmd,
    }


# ─── CLI ──────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="FORENSTIX 2.0 — CLI Tool Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("tool", nargs="?", help="Tool ID (omit with --parallel)")
    p.add_argument("target", nargs="?", help="Target (IP, domain, file, etc.)")
    p.add_argument("--parallel", metavar="TOOL1,TOOL2", help="Run multiple tools")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--output", choices=["json", "text", "table"], default="text")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--evidence-id", metavar="ID")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--check", action="store_true", help="Check tool availability")
    p.add_argument("--list", action="store_true", help="List all available tools")
    p.add_argument("--category", help="Filter --list by category")
    return p


def _list_tools(category: Optional[str] = None) -> None:
    catalog = by_id()
    for tool in TOOLS:
        if category and tool.category.lower() != category.lower():
            continue
        print(f"  {tool.id:<25} {tool.category:<20} {tool.name}")


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.list:
        _list_tools(args.category)
        return 0

    if args.check:
        tool_id = args.tool or ""
        if not tool_id:
            parser.error("Provide a tool ID with --check")
        info = check_tool(tool_id)
        print(json.dumps(info, indent=2))
        return 0 if info["available"] else 1

    if args.parallel:
        tool_ids = [t.strip() for t in args.parallel.split(",") if t.strip()]
        target = args.tool or args.target
        if not target:
            parser.error("Provide a target when using --parallel")
        results = run_parallel(
            tool_ids=tool_ids,
            target=target,
            timeout=args.timeout,
            evidence_id=args.evidence_id,
            use_cache=not args.no_cache,
        )
        if args.output == "json":
            print(json.dumps(results, indent=2, default=str))
        else:
            for r in results:
                print(format_result(r, args.output))
        return 0 if all(r.get("ok") for r in results) else 1

    if not args.tool or not args.target:
        parser.error("Provide tool_id and target, or use --parallel / --list")

    result = run_tool(
        tool_id=args.tool,
        target=args.target,
        timeout=args.timeout,
        evidence_id=args.evidence_id,
        use_cache=not args.no_cache,
        dry_run=args.dry_run,
    )

    if args.output == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        print(format_result(result, args.output))

    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
