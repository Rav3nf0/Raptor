"""Planned activity — declared maintenance/compliance windows (time-boxed).

A KNOWN benign, usually-scripted activity (e.g. a compliance scan) that trips EDR
across many hosts at once. Without context RAPTOR correctly escalates unfamiliar
fleet-wide activity — so a planned run shows up as a batch of AI=NEEDS_L2 vs
human=FP mismatches. Declaring the run tells RAPTOR it's expected.

While a window is active the pipeline auto-closes matching alerts as FALSE POSITIVE
deterministically — no LLM call — matching a **command-line substring**, actor- and
device-agnostic, so one declaration covers the whole fleet.

Safety: entries are **time-boxed** (`expires_at`) and this matcher filters on it, so
a window is inert the moment it expires and can never suppress anything after the run
ends. The pattern must be reasonably specific (>= MIN_PATTERN_LEN) so a stray short
string can't match everything. This is deliberately NOT golden memory — it is a
temporary announcement, not a learned precedent.
"""
from __future__ import annotations

import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# A declared pattern must be at least this long — stops "e"/"ps1" style over-matching.
MIN_PATTERN_LEN = 4


async def match_planned_activity(command_lines: list[str], alert_type: str = "") -> dict | None:
    """Return an active planned-activity window whose command substring appears in
    any of the alert's command lines, else None.

    Deterministic and read-only on the hot path (uses the raw collection so it works
    even if a Beanie model isn't initialized). Matching is case-insensitive substring
    against the raw command lines — NOT normalized basenames — because a script
    (`compliance_scan.ps1`) runs under a generic host binary (`powershell.exe`) whose
    basename would over-match.
    """
    lines = [(c or "").lower() for c in (command_lines or []) if c]
    if not lines:
        return None
    try:
        from app.database import get_collection
        col = get_collection("eg_planned_activity")
        now = datetime.utcnow()
        candidates = await col.find({"expires_at": {"$gt": now}}).to_list(length=200)
        for pa in candidates:
            pat = (pa.get("pattern") or "").strip().lower()
            if len(pat) < MIN_PATTERN_LEN:
                continue
            at = pa.get("alert_type") or ""
            if at and at != alert_type:
                continue  # window scoped to a different alert type
            if any(pat in line for line in lines):
                # Best-effort hit counter for visibility — never let it break triage.
                try:
                    await col.update_one({"_id": pa["_id"]}, {"$inc": {"hit_count": 1}})
                except Exception:
                    pass
                return {
                    "id": str(pa["_id"]),
                    "pattern": pa.get("pattern", ""),
                    "label": pa.get("label", ""),
                    "alert_type": pa.get("alert_type", ""),
                    "expires_at": pa["expires_at"].isoformat() if pa.get("expires_at") else "",
                    "created_by": pa.get("created_by", ""),
                }
    except Exception as exc:
        logger.error("match_planned_activity failed: %s", exc)
    return None
