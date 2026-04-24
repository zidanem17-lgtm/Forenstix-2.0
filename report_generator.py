"""
FORENSTIX 2.0 — Humanized Report Generator
Uses Claude API to transform raw forensic data into analyst-style narratives.
"""

import os
import json
import datetime
import requests

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are a senior digital forensics analyst writing an evidence triage report.
Your writing style is:
- Professional but conversational — like a seasoned analyst briefing a colleague
- Clear, direct sentences — no jargon dumping, no filler
- You explain what you found and WHY it matters
- You use natural transitions, not robotic bullet points
- You write like a real human expert — confident, specific, occasionally dry-witted when noting something unusual
- You NEVER use phrases like "it's important to note" or "it should be noted" or "in conclusion"
- You NEVER sound like AI-generated text — no hedging, no over-qualifying, no corporate-speak
- You reference specific data points (hashes, entropy values, timestamps) naturally within sentences

Structure your report with these sections (use markdown headers):
## Executive Summary
A 2-3 sentence overview of what this file is, whether it's suspicious, and the bottom line.

## File Identity
Discuss the hashes, file type detection, and whether the file is what it claims to be.

## Content Analysis
Cover entropy findings, metadata, and any embedded artifacts (strings, URLs, emails, IPs, domains).

## Threat Indicators
Detail any YARA matches, anomalies, or embedded IOCs that suggest malicious activity. If none, say so plainly.

## Analyst Recommendation
What should be done with this file and its IOCs? Be specific and actionable. If IOCs were found,
recommend which pivot tools would be most useful to investigate further.

Keep the entire report between 350-550 words. Write it in a way that a junior analyst could
understand but a senior analyst would respect."""


def generate_humanized_report(analysis_results: dict) -> str:
    """Generate a human-style forensic narrative using Claude API."""
    if not ANTHROPIC_API_KEY:
        return _generate_fallback_report(analysis_results)

    data_summary = json.dumps(analysis_results, indent=2, default=str)
    user_prompt = f"""Here is the raw forensic analysis data for a file. Write a humanized forensic triage report based on this data.

Raw Analysis Data:
{data_summary}

Write the report now. Sound like a real forensic analyst, not an AI."""

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1800,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=30,
        )
        if response.status_code == 200:
            result = response.json()
            text = "".join(
                block["text"]
                for block in result.get("content", [])
                if block.get("type") == "text"
            )
            return text or _generate_fallback_report(analysis_results)
        print(f"API Error {response.status_code}: {response.text}")
        return _generate_fallback_report(analysis_results)
    except Exception as e:
        print(f"Report generation error: {e}")
        return _generate_fallback_report(analysis_results)


def _generate_fallback_report(results: dict) -> str:
    meta = results.get("metadata", {})
    hashes = results.get("hashes", {})
    ft = results.get("file_type", {})
    entropy = results.get("entropy", {})
    anomalies = results.get("anomalies", [])
    risk = results.get("risk_score", {})
    yara_matches = results.get("yara_matches", [])

    report = f"""## Executive Summary

Forensic triage of **{meta.get('filename', 'unknown')}**, a {meta.get('file_size_human', 'unknown')} file analyzed {datetime.datetime.now().strftime('%B %d, %Y at %I:%M %p')}. Risk score: **{risk.get('score', 0)}/100 ({risk.get('label', 'UNKNOWN')})**.

## File Identity

Detected as **{ft.get('detected_type', 'Unknown')}** by magic byte analysis (signature: `{ft.get('magic_bytes', 'N/A')}`). Claimed extension: `{meta.get('extension', 'none')}`. Detected extension: `{ft.get('detected_extension', 'unknown')}`.

Chain-of-custody hashes:
- **MD5:** `{hashes.get('md5', 'N/A')}`
- **SHA-1:** `{hashes.get('sha1', 'N/A')}`
- **SHA-256:** `{hashes.get('sha256', 'N/A')}`

## Content Analysis

Shannon entropy: **{entropy.get('entropy', 0)}** / 8.0. {entropy.get('assessment', '')}

File timestamps — Created: {meta.get('created', 'unknown')} | Modified: {meta.get('modified', 'unknown')}
"""

    if meta.get("exif"):
        report += "\nEmbedded EXIF metadata:\n"
        for k, v in meta["exif"].items():
            report += f"- **{k}:** {v}\n"

    ns = meta.get("notable_strings") or {}
    ioc_sections = [
        ("urls", "URLs"),
        ("emails", "Emails"),
        ("ip_addresses", "IP Addresses"),
        ("domains", "Domains"),
        ("hashes_sha256", "Embedded SHA-256 Hashes"),
        ("hashes_sha1", "Embedded SHA-1 Hashes"),
        ("hashes_md5", "Embedded MD5 Hashes"),
    ]
    ioc_found = False
    for key, label in ioc_sections:
        items = ns.get(key, [])
        if items:
            if not ioc_found:
                report += "\n**Embedded IOCs:**\n"
                ioc_found = True
            report += f"- *{label}:* {', '.join(f'`{v}`' for v in items[:5])}\n"

    report += "\n## Threat Indicators\n\n"

    if yara_matches:
        report += f"**YARA matches ({len(yara_matches)}):**\n"
        for m in yara_matches:
            report += f"- `{m['rule']}` — {m.get('meta', {}).get('description', 'No description')}\n"
        report += "\n"

    if anomalies:
        for a in anomalies:
            icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(a["severity"], "⚪")
            report += f"{icon} **{a['title']}** ({a['severity'].upper()})\n{a['detail']}\n"
            report += f"*{a['recommendation']}*\n\n"
    else:
        report += "No anomalies detected. The file appears consistent with its claimed type.\n"

    report += "\n## Analyst Recommendation\n\n"
    score = risk.get("score", 0)
    if score >= 70:
        report += "**Quarantine immediately.** Do not open on any production system. Sandbox detonation and behavioral analysis recommended.\n"
    elif score >= 40:
        report += "**Further investigation warranted.** Open only in an isolated environment and verify the origin independently.\n"
    elif score >= 15:
        report += "Minor indicators noted. Standard precautions apply — verify the source before use.\n"
    else:
        report += "File appears clean. No immediate action required beyond standard evidence handling.\n"

    if ioc_found:
        report += "\nIOCs extracted from this file are available as pivot targets in the investigation panel."

    return report
