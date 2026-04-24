"""
FORENSTIX 2.0 — Cross-file comparison engine.
"""

from __future__ import annotations
from typing import Any, Dict, List


def compare_files(analyses: List[Dict]) -> Dict[str, Any]:
    """Compare 2+ analyze_file() results."""
    if not analyses:
        return {}

    files_meta = []
    for a in analyses:
        meta = a.get("metadata", {})
        risk = a.get("risk_score", {})
        files_meta.append({
            "filename": meta.get("filename", "unknown"),
            "size": meta.get("file_size_bytes", 0),
            "md5": a.get("hashes", {}).get("md5", ""),
            "sha256": a.get("hashes", {}).get("sha256", ""),
            "type": a.get("file_type", {}).get("detected_type", ""),
            "entropy": a.get("entropy", {}).get("entropy", 0),
            "risk_score": risk.get("score", 0),
            "risk_label": risk.get("label", "UNKNOWN"),
            "anomaly_count": len(a.get("anomalies", [])),
        })

    risk_sorted = sorted(files_meta, key=lambda x: x["risk_score"], reverse=True)
    risk_comparison = [
        {"filename": f["filename"], "score": f["risk_score"], "label": f["risk_label"]}
        for f in risk_sorted
    ]

    entropy_comparison = sorted(
        [{"filename": f["filename"], "entropy": f["entropy"],
          "assessment": _entropy_label(f["entropy"])} for f in files_meta],
        key=lambda x: x["entropy"],
        reverse=True,
    )

    # Relationship assessment
    sha256s = [f["sha256"] for f in files_meta if f["sha256"]]
    if len(set(sha256s)) == 1 and len(sha256s) > 1:
        relationship = "DUPLICATE_FILES"
    else:
        relationship = _assess_relationship(analyses)

    # Shared artifacts
    shared = _find_shared_artifacts(analyses)

    # Findings
    findings = _generate_findings(files_meta, analyses, shared)

    return {
        "files": files_meta,
        "risk_comparison": risk_comparison,
        "entropy_comparison": entropy_comparison,
        "relationship_assessment": relationship,
        "shared_artifacts": shared,
        "findings": findings,
    }


def _entropy_label(e: float) -> str:
    if e > 7.9:
        return "Very high"
    if e > 7.0:
        return "High"
    if e > 5.0:
        return "Moderate"
    if e > 3.0:
        return "Low-moderate"
    return "Low"


def _assess_relationship(analyses: List[Dict]) -> str:
    types = [a.get("file_type", {}).get("detected_type", "") for a in analyses]
    if len(set(types)) == 1:
        for a in analyses:
            ns = (a.get("metadata", {}).get("notable_strings") or {})
            urls = set(ns.get("urls", []))
            emails = set(ns.get("emails", []))
            ips = set(ns.get("ip_addresses", []))
            if urls or emails or ips:
                return "RELATED_FILES"
        return "SAME_TYPE"
    return "UNRELATED"


def _find_shared_artifacts(analyses: List[Dict]) -> Dict:
    filenames = [a.get("metadata", {}).get("filename", "?") for a in analyses]
    type_keys = {
        "shared_urls": "urls",
        "shared_emails": "emails",
        "shared_ips": "ip_addresses",
        "shared_domains": "domains",
    }
    shared: Dict = {}
    has_shared = False
    for shared_key, ns_key in type_keys.items():
        all_vals: Dict[str, List[str]] = {}
        for fname, a in zip(filenames, analyses):
            ns = (a.get("metadata", {}).get("notable_strings") or {})
            for val in ns.get(ns_key, []):
                all_vals.setdefault(val, []).append(fname)
        multi = {v: fns for v, fns in all_vals.items() if len(fns) > 1}
        if multi:
            shared[shared_key] = multi
            has_shared = True
    shared["has_shared"] = has_shared
    return shared


def _generate_findings(files_meta, analyses, shared) -> List[Dict]:
    findings = []

    critical = [f for f in files_meta if f["risk_label"] in ("CRITICAL", "SUSPICIOUS")]
    if critical:
        findings.append({
            "severity": "critical",
            "title": "High-Risk File(s) Detected",
            "detail": ", ".join(f["filename"] for f in critical) + " scored as high risk.",
        })

    if shared.get("has_shared"):
        keys = [k for k in ("shared_urls", "shared_emails", "shared_ips", "shared_domains")
                if shared.get(k)]
        findings.append({
            "severity": "warning",
            "title": "Shared Artifacts Across Files",
            "detail": f"Files share: {', '.join(keys)}. May indicate common origin or campaign.",
        })

    high_entropy = [f for f in files_meta if f["entropy"] > 7.5]
    if high_entropy:
        findings.append({
            "severity": "warning",
            "title": "Multiple High-Entropy Files",
            "detail": f"{len(high_entropy)} file(s) show extreme entropy, suggesting encryption or packing.",
        })

    return findings
