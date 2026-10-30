"""VirusTotal file hash lookup.

GET https://www.virustotal.com/api/v3/files/{sha256}
"""
from __future__ import annotations

import logging
import re

import httpx

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
# VT's /files/{id} takes MD5, SHA1 or SHA256. Upwind reports MD5 only.
FILE_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


async def check_hash(sha256: str, api_key: str) -> dict:
    """Look up a SHA256 hash on VirusTotal.

    Returns:
        {
          "detections": int,   # malicious + suspicious engine count
          "total": int,        # total engines
          "verdict": str,      # "malicious" | "suspicious" | "clean" | "unknown"
          "malicious_names": list[str],   # top engine detection names
          "vt_link": str,
        }
    """
    empty = {"detections": 0, "total": 0, "verdict": "unknown", "malicious_names": [], "vt_link": ""}

    if not api_key or not sha256 or not FILE_HASH_RE.match(sha256):
        return empty

    try:
        async with httpx.AsyncClient(
            base_url=_VT_BASE,
            headers={"x-apikey": api_key},
            timeout=20.0,
            verify=False,
            trust_env=False,
        ) as client:
            resp = await client.get(f"/files/{sha256}")
            if resp.status_code == 404:
                return {**empty, "verdict": "unknown"}
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
    except Exception as exc:
        logger.warning("VT hash lookup failed for %s: %s", sha256[:16], exc)
        return empty

    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values()) if stats else 0

    detections = malicious + suspicious
    if malicious >= 5:
        verdict = "malicious"
    elif detections > 0:
        verdict = "suspicious"
    elif total > 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    # Top engine names that flagged it as malicious
    results = attrs.get("last_analysis_results", {})
    malicious_names = [
        v.get("result", "")
        for v in results.values()
        if v.get("category") in ("malicious", "suspicious") and v.get("result")
    ][:5]

    return {
        "detections":     detections,
        "total":          total,
        "verdict":        verdict,
        "malicious_names": malicious_names,
        "vt_link":        f"https://www.virustotal.com/gui/file/{sha256}",
    }
