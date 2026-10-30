"""Upwind CNAPP query tools — read the local Upwind mirror (edr_triage/upwind_mirror.py).

Read-only and never call Upwind directly: Upwind's API can't filter by resource, so a
scheduled sync mirrors detections, runtime events, critical-and-exploitable vulnerabilities
and critical misconfigurations into Mongo, and these tools query that. Results say how fresh
the mirror is. Kept to three short schemas: every advertised tool is re-sent each iteration.
"""
from __future__ import annotations

import logging

from agent_tools.registry import register

logger = logging.getLogger(__name__)

_HOST = {"type": "string", "description": "Hostname, EC2 Name tag or instance id (i-...)"}


def _not_covered(host: str) -> dict:
    return {"found": False, "host": host,
            "note": "Upwind has no record of this host (not covered by Upwind, or a name mismatch). "
                    "This is NOT evidence either way."}


@register(
    name="upwind_asset",
    description=("Upwind's view of a cloud/on-prem host: internet exposure, owner tags, count of open "
                 "Upwind threats, critical exploitable vulnerabilities (top CVEs) and critical "
                 "misconfigurations."),
    parameters={"type": "object", "properties": {"host": _HOST}, "required": ["host"]},
)
async def upwind_asset(host: str) -> dict:
    try:
        from edr_triage.upwind_mirror import lookup_asset
        a = await lookup_asset(host)
        if not a:
            return _not_covered(host)
        a = dict(a)
        a["synced_at"] = str(a.get("synced_at", ""))
        return {"found": True, **a}
    except Exception as exc:
        logger.warning("upwind_asset failed for %s: %s", host, exc)
        return {"found": False, "host": host, "error": str(exc)[:150]}


@register(
    name="upwind_threats",
    description=("Upwind threat detections and runtime events on a host in the last N days "
                 "(severity, category, title, first/last seen, status)."),
    parameters={"type": "object", "properties": {
        "host": _HOST, "days": {"type": "integer", "description": "Look-back in days (default 30)"}},
        "required": ["host"]},
)
async def upwind_threats(host: str, days: int = 30) -> dict:
    try:
        from edr_triage.upwind_mirror import threats_for
        rows = await threats_for(host, days=max(1, min(int(days or 30), 120)))
        if not rows:
            return {"found": False, "host": host, "days": days,
                    "note": "No Upwind threats on this host in the window, or the host is not covered by Upwind."}
        return {"found": True, "host": host, "days": days, "threats": [{**r, "id": r.pop("_id")} for r in rows]}
    except Exception as exc:
        logger.warning("upwind_threats failed for %s: %s", host, exc)
        return {"found": False, "host": host, "error": str(exc)[:150]}


@register(
    name="upwind_vulns",
    description=("Critical, exploitable vulnerabilities Upwind found on a host: CVE, CVSS, EPSS, "
                 "whether exploitable and whether the vulnerable code is in use, package."),
    parameters={"type": "object", "properties": {"host": _HOST}, "required": ["host"]},
)
async def upwind_vulns(host: str) -> dict:
    try:
        from edr_triage.upwind_mirror import lookup_asset
        a = await lookup_asset(host)
        if not a:
            return _not_covered(host)
        v = a.get("vulns") or {}
        return {"found": True, "host": host, "exposed": a.get("exposed"), "critical": v.get("critical", 0),
                "exploitable": v.get("exploitable", 0), "top": v.get("top", []),
                "note": "Mirror holds vulnerabilities that are BOTH critical and exploitable, not every CVE."}
    except Exception as exc:
        logger.warning("upwind_vulns failed for %s: %s", host, exc)
        return {"found": False, "host": host, "error": str(exc)[:150]}
