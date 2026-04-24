"""
fx_output.py — Forenstix-2.0 output parser and formatter

Converts raw tool stdout into structured data when possible, and provides
consistent JSON envelope formatting for every tool result.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Output envelope
# ---------------------------------------------------------------------------

def make_result(
    tool_id: str,
    tool_name: str,
    target: str,
    backend: str,
    command: str,
    returncode: int,
    stdout: str,
    stderr: str,
    elapsed: float,
    evidence_id: Optional[str] = None,
    cached: bool = False,
    parsed: Optional[Any] = None,
) -> Dict[str, Any]:
    """Build the standardised result envelope."""
    return {
        "tool": tool_id,
        "tool_name": tool_name,
        "target": target,
        "backend": backend,
        "command": command,
        "evidence_id": evidence_id,
        "cached": cached,
        "elapsed_sec": round(elapsed, 2),
        "exit_code": returncode,
        "ok": returncode == 0,
        "stdout": stdout,
        "stderr": stderr,
        "parsed": parsed,
    }


def make_error(
    tool_id: str,
    message: str,
    evidence_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "tool": tool_id,
        "ok": False,
        "error": message,
        "evidence_id": evidence_id,
    }


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _try_json(text: str) -> Optional[Any]:
    """Try to parse the entire output as JSON/JSONL."""
    text = text.strip()
    if not text:
        return None
    # Single JSON object/array
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # JSONL — one JSON object per line
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    parsed = []
    for line in lines:
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            return None
    return parsed if parsed else None


def _parse_nmap(text: str) -> Optional[Dict]:
    """Extract open ports from nmap output."""
    ports: List[Dict] = []
    for line in text.splitlines():
        m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)(.*)", line)
        if m:
            ports.append({
                "port": int(m.group(1)),
                "proto": m.group(2),
                "state": m.group(3),
                "service": m.group(4),
                "info": m.group(5).strip(),
            })
    if not ports:
        return None
    # Extract host
    host_match = re.search(r"Nmap scan report for (.+)", text)
    return {
        "host": host_match.group(1) if host_match else "unknown",
        "ports": ports,
    }


def _parse_subfinder(text: str) -> Optional[List[str]]:
    """One subdomain per line."""
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("[")]
    return lines if lines else None


def _parse_nuclei(text: str) -> Optional[List[Dict]]:
    """nuclei -json output."""
    items = _try_json(text)
    if items:
        return items
    # Plain text: [severity] template-id [target]
    results = []
    for line in text.splitlines():
        m = re.match(r"\[(\S+)\]\s+\[(\S+)\]\s+\[(\S+)\]\s+(.+)", line)
        if m:
            results.append({
                "severity": m.group(1),
                "template": m.group(2),
                "type": m.group(3),
                "url": m.group(4),
            })
    return results if results else None


def _parse_trufflehog(text: str) -> Optional[List[Dict]]:
    """TruffleHog v3 JSON output."""
    return _try_json(text)


def _parse_gitleaks(text: str) -> Optional[List[Dict]]:
    """Gitleaks JSON report."""
    return _try_json(text)


def _parse_rustscan(text: str) -> Optional[List[int]]:
    """Extract open ports from RustScan output."""
    m = re.search(r"Open\s+([\d.]+):(\d+)", text)
    if m:
        return [int(m.group(2))]
    ports = re.findall(r"(\d+)/open", text)
    return [int(p) for p in ports] if ports else None


def _parse_volatility(text: str) -> Optional[List[Dict]]:
    """Convert Volatility table output to list of dicts."""
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return None
    # Find header row (row with the most uppercase words)
    header_idx = 0
    for i, line in enumerate(lines[:5]):
        if re.search(r"[A-Z]{2,}", line):
            header_idx = i
            break
    header = re.split(r"\s{2,}", lines[header_idx].strip())
    rows = []
    for line in lines[header_idx + 1:]:
        if re.match(r"[=-]+", line.strip()):
            continue
        cols = re.split(r"\s{2,}", line.strip())
        row = {header[i]: cols[i] if i < len(cols) else "" for i in range(len(header))}
        rows.append(row)
    return rows if rows else None


def _parse_theharvester(text: str) -> Optional[Dict]:
    """Extract emails and hosts from theHarvester output."""
    emails = re.findall(r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}", text)
    hosts = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", text)
    if not emails and not hosts:
        return None
    return {
        "emails": sorted(set(emails)),
        "hosts": sorted(set(h for h in hosts if "." in h)),
    }


def _parse_holehe(text: str) -> Optional[List[Dict]]:
    """holehe output: [+/-] site  status"""
    results = []
    for line in text.splitlines():
        m = re.match(r"\[([+\-!])\]\s+(\S+)\s*(.*)", line)
        if m:
            results.append({
                "found": m.group(1) == "+",
                "site": m.group(2),
                "info": m.group(3).strip(),
            })
    return results if results else None


def _parse_maigret(text: str) -> Optional[Dict]:
    """Extract found/not-found counts and URLs from maigret output."""
    found = re.findall(r"\[Found\]\s+(\S+)", text, re.IGNORECASE)
    not_found = len(re.findall(r"\[Not Found\]", text, re.IGNORECASE))
    return {"found_on": found, "not_found_count": not_found} if found else None


# Registry: tool_id → parser function
_PARSERS = {
    "nmap":         _parse_nmap,
    "rustscan":     _parse_rustscan,
    "masscan":      _parse_rustscan,
    "nuclei":       _parse_nuclei,
    "subfinder":    _parse_subfinder,
    "amass":        _parse_subfinder,
    "trufflehog":   _parse_trufflehog,
    "gitleaks":     _parse_gitleaks,
    "volatility3":  _parse_volatility,
    "theharvester": _parse_theharvester,
    "holehe":       _parse_holehe,
    "maigret":      _parse_maigret,
}


def parse_output(tool_id: str, stdout: str) -> Optional[Any]:
    """Attempt to parse tool output into structured data."""
    # Always try JSON first (many modern tools support it)
    parsed = _try_json(stdout)
    if parsed is not None:
        return parsed
    # Tool-specific parsers
    parser = _PARSERS.get(tool_id)
    if parser:
        return parser(stdout)
    return None


# ---------------------------------------------------------------------------
# Terminal formatters
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[31m",   # red
    "medium":   "\033[33m",   # yellow
    "low":      "\033[32m",   # green
    "info":     "\033[36m",   # cyan
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def format_result(result: Dict[str, Any], fmt: str = "text") -> str:
    """Format a result envelope for display."""
    if fmt == "json":
        return json.dumps(result, indent=2, default=str)

    if fmt == "table":
        return _format_table(result)

    # Default: human-friendly text
    lines = []
    color = _supports_color()
    bold = _BOLD if color else ""
    reset = _RESET if color else ""

    status = "✅" if result.get("ok") else "❌"
    lines.append(f"{bold}[{result['tool']}] {result.get('tool_name','')} {status}{reset}")
    if result.get("error"):
        lines.append(f"  Error: {result['error']}")
        return "\n".join(lines)

    lines.append(f"  Target  : {result.get('target','')}")
    lines.append(f"  Backend : {result.get('backend','')}")
    if result.get("evidence_id"):
        lines.append(f"  Evidence: {result['evidence_id']}")
    lines.append(f"  Elapsed : {result.get('elapsed_sec',0):.2f}s")
    if result.get("cached"):
        lines.append("  (cached result)")
    lines.append("")

    parsed = result.get("parsed")
    if parsed:
        lines.append(f"{bold}Structured output:{reset}")
        lines.append(json.dumps(parsed, indent=2, default=str))
    else:
        lines.append(f"{bold}Raw output:{reset}")
        lines.append(result.get("stdout", "").strip())

    if result.get("stderr"):
        lines.append(f"\n{bold}Stderr:{reset}")
        lines.append(result["stderr"].strip())

    return "\n".join(lines)


def _format_table(result: Dict[str, Any]) -> str:
    """Tabular format for parsed list-of-dict results."""
    parsed = result.get("parsed")
    if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
        return format_result(result, fmt="text")

    headers = list(parsed[0].keys())
    col_widths = {h: max(len(h), max(len(str(row.get(h, ""))) for row in parsed)) for h in headers}

    sep = "+-" + "-+-".join("-" * col_widths[h] for h in headers) + "-+"
    header_row = "| " + " | ".join(h.ljust(col_widths[h]) for h in headers) + " |"

    lines = [sep, header_row, sep]
    for row in parsed:
        data_row = "| " + " | ".join(str(row.get(h, "")).ljust(col_widths[h]) for h in headers) + " |"
        lines.append(data_row)
    lines.append(sep)
    return "\n".join(lines)
