"""VirusTotal tool wrappers — wraps existing edr_triage/vt_hash.py."""
from __future__ import annotations

import logging
import os
import re

import httpx

from agent_tools.registry import register

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
# A hostname: labels of alnum/hyphen separated by dots, with a TLD. Deliberately
# strict enough to reject URLs, IPs, paths, and free text passed as a "domain".
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")


def _normalize_domain(raw: str) -> str:
    """Best-effort reduce a possibly-URL input to a bare hostname."""
    d = (raw or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]  # strip path/query/frag
    d = d.split("@")[-1]          # strip userinfo
    d = d.split(":", 1)[0]        # strip port
    return d.strip().strip(".").lower()


@register(
    name="vt_lookup_hash",
    description=("Look up a SHA256 file hash (64 hex chars) on VirusTotal. Returns detection "
                 "count, verdict, and engine names. Pass ONLY a real SHA256 — never a filename "
                 "(e.g. 'mfewc.exe'). If the alert has no hash, you cannot check the file here."),
    parameters={
        "type": "object",
        "properties": {
            "sha256": {"type": "string", "description": "SHA256 hash to look up — 64 hex chars, NOT a filename"},
        },
        "required": ["sha256"],
    },
)
async def vt_lookup_hash(sha256: str) -> dict:
    from edr_triage.vt_hash import check_hash
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    # Guard against the model passing a filename (or any non-hash) — VirusTotal's
    # file endpoint is keyed by hash, so a filename yields a meaningless empty
    # result that reads like "clean". Reject it with an instructive error instead
    # of silently returning 0/0, so the model doesn't infer the file is benign.
    h = (sha256 or "").strip()
    if not _SHA256_RE.match(h):
        # invalid_input: a rejected argument is the model asking wrongly, not evidence
        # we failed to retrieve — so it must not trip the critical-tool confidence cap
        # (see _apply_safety_gates). The "absence is not benign" warning below still
        # stands; it is guidance to the model, not a signal that the lookup broke.
        return {"invalid_input": True, "error": (
            f"'{sha256}' is not a SHA256. vt_lookup_hash needs a 64-hex-char SHA256, not a "
            "filename. This alert may not carry a file hash — if so, you CANNOT check the "
            "file's reputation on VirusTotal. Do NOT treat a missing/absent VT result as "
            "evidence the file is benign. Obtain the real SHA256 from the alert evidence or "
            "mde_get_timeline, or escalate to L2."
        )}
    return await check_hash(h, api_key)


@register(
    name="vt_lookup_domain",
    description="Look up a domain on VirusTotal. Returns reputation, detection ratio, and categories.",
    parameters={
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain name to check"},
        },
        "required": ["domain"],
    },
)
async def vt_lookup_domain(domain: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    # Normalize URL→host and validate — a raw URL / IP / free text sent to the
    # /domains endpoint returns an opaque 400. Give the model an actionable error.
    domain = _normalize_domain(domain)
    if not _DOMAIN_RE.match(domain):
        return {"error": (
            f"'{domain}' is not a valid domain. Pass a bare hostname (e.g. evil.example.com), "
            "not a URL, IP, or path. For an IP use vt_lookup_ip; for a file hash use vt_lookup_hash."
        )}
    try:
        async with httpx.AsyncClient(
            base_url=_VT_BASE,
            headers={"x-apikey": api_key},
            timeout=20.0,
            verify=False,
            trust_env=False,
        ) as client:
            resp = await client.get(f"/domains/{domain}")
            if resp.status_code == 404:
                return {"verdict": "unknown", "detections": 0, "total": 0}
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
    except Exception as exc:
        return {"error": str(exc)[:200]}

    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    detections = malicious + suspicious
    verdict = "malicious" if malicious >= 3 else ("suspicious" if detections > 0 else "clean" if total > 0 else "unknown")
    return {
        "domain": domain,
        "detections": detections,
        "total": total,
        "verdict": verdict,
        "categories": attrs.get("categories", {}),
        "reputation": attrs.get("reputation", 0),
        "vt_link": f"https://www.virustotal.com/gui/domain/{domain}",
    }


@register(
    name="vt_lookup_ip",
    description="Look up an IP address on VirusTotal. Returns reputation and detection ratio.",
    parameters={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "IP address to check"},
        },
        "required": ["ip"],
    },
)
async def vt_lookup_ip(ip: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}
    try:
        async with httpx.AsyncClient(
            base_url=_VT_BASE,
            headers={"x-apikey": api_key},
            timeout=20.0,
            verify=False,
            trust_env=False,
        ) as client:
            resp = await client.get(f"/ip_addresses/{ip}")
            if resp.status_code == 404:
                return {"verdict": "unknown", "detections": 0}
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
    except Exception as exc:
        return {"error": str(exc)[:200]}

    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    detections = malicious + suspicious
    verdict = "malicious" if malicious >= 3 else ("suspicious" if detections > 0 else "clean" if total > 0 else "unknown")
    return {
        "ip": ip,
        "detections": detections,
        "total": total,
        "verdict": verdict,
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn", 0),
        "as_owner": attrs.get("as_owner", ""),
        "reputation": attrs.get("reputation", 0),
        "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }
