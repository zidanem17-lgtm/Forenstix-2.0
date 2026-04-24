"""
FORENSTIX 2.0 — VirusTotal hash lookup integration.
"""

import os
import requests

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def lookup_hash(file_hash: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"status": "no_api_key",
                "message": "Set the VIRUSTOTAL_API_KEY environment variable to enable lookups."}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "status": "found",
                "hash": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
                "name": attrs.get("meaningful_name", ""),
                "type": attrs.get("type_description", ""),
                "size": attrs.get("size", 0),
                "first_seen": attrs.get("first_submission_date", ""),
                "last_seen": attrs.get("last_analysis_date", ""),
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            }
        if resp.status_code == 404:
            return {"status": "not_found", "hash": file_hash,
                    "message": "Hash not found in VirusTotal database."}
        if resp.status_code == 429:
            return {"status": "rate_limited", "hash": file_hash,
                    "message": "VirusTotal rate limit exceeded. Try again shortly."}
        return {"status": "error", "hash": file_hash,
                "message": f"VirusTotal returned HTTP {resp.status_code}."}
    except requests.exceptions.Timeout:
        return {"status": "error", "hash": file_hash, "message": "Request timed out."}
    except Exception as e:
        return {"status": "error", "hash": file_hash, "message": str(e)}
