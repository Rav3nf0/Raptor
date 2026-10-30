"""AbuseIPDB tool wrapper — a second IP-reputation source alongside vt_lookup_ip.

Optional and absent-safe, same pattern as VIRUSTOTAL_API_KEY: with no
ABUSEIPDB_API_KEY configured the tool reports that plainly instead of erroring, and
the model simply has one less source (VT alone still works). Registering it costs
nothing for alert families that never call it — advertised_tools_for() only trims the
Netskope DLP family's tool list, and IP reputation is irrelevant there anyway.
"""
from __future__ import annotations

import logging
import os

import httpx

from agent_tools.registry import register
from lib.mde_client import _is_private_ip

logger = logging.getLogger(__name__)

_ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB's own published guidance: >=75 is their "high confidence of abuse"
# threshold. Matches the VT-detection gates' zero-tolerance framing in
# agent_core/loop.py (_ti_flagged_detail) — kept as one constant so the two never
# drift apart if either changes.
ABUSE_CONFIDENCE_MALICIOUS_THRESHOLD = 75


@register(
    name="abuseipdb_lookup_ip",
    description=(
        "Look up an IP address on AbuseIPDB. Returns an abuse confidence score "
        "(0-100, AbuseIPDB's own scale — NOT a detections/total ratio like VirusTotal) "
        "plus report count, country, and ISP. A complementary source to vt_lookup_ip, "
        "not a replacement for it — the two draw on different report data and can "
        "disagree. Private/internal IPs are never looked up externally."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "IP address to check"},
        },
        "required": ["ip"],
    },
)
async def abuseipdb_lookup_ip(ip: str) -> dict:
    ip = (ip or "").strip()
    if _is_private_ip(ip):
        # A private/RFC1918/loopback/link-local address has no external reputation to
        # check — short-circuit before spending a call (or reporting a meaningless
        # "not configured"/"not found" for something that was never checkable).
        return {"ip": ip, "is_private": True, "abuse_confidence_score": 0,
                "verdict": "not_applicable_private_ip"}

    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured"}

    try:
        # verify=False, same as every VirusTotal call: the pod's egress goes through a
        # TLS-inspecting proxy whose CA is not in the image, so verification fails
        # (2026-10-08, CERTIFICATE_VERIFY_FAILED in prod). Trusting that CA in the image
        # is the real fix and would let both tools verify.
        async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
            resp = await client.get(
                _ABUSEIPDB_CHECK_URL,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"},
            )
            if resp.status_code == 422:
                return {"error": f"'{ip}' is not a valid IP address for AbuseIPDB"}
            if resp.status_code >= 400:
                # Keep AbuseIPDB's own reason (bad key JSON vs a Cloudflare HTML block
                # page) — a bare "403 Forbidden" can't tell the two apart.
                body = " ".join(resp.text.split())[:200]
                return {"error": f"HTTP {resp.status_code} from AbuseIPDB: {body}"}
            data = resp.json().get("data", {})
    except Exception as exc:
        return {"error": str(exc)[:200]}

    score = data.get("abuseConfidenceScore", 0)
    verdict = ("malicious" if score >= ABUSE_CONFIDENCE_MALICIOUS_THRESHOLD
               else "suspicious" if score >= 25 else "clean")
    return {
        "ip": ip,
        "is_private": False,
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports", 0),
        "verdict": verdict,
        "country": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "usage_type": data.get("usageType", ""),
        "is_whitelisted": bool(data.get("isWhitelisted", False)),
        "abuseipdb_link": f"https://www.abuseipdb.com/check/{ip}",
    }
