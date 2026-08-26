"""Re-triage alerts that arrived with NOTHING bound, once, after evidence lands.

A 'Powershell script was loaded in memory' alert routinely reaches triage carrying no
device, no user and no command line. RAPTOR then investigates a blank subject and
escalates — 18 of the scored misses in that family look exactly like this, and the
tickets read "Device: Unknown Device / User: Unknown User / the process command line was
not present in the MDE alert evidence".

The evidence is not missing, it is merely not there YET at read time. Binding is
attempted in two stages: the alert's own Sentinel record (immediate, but not every alert
carries entities), then a DeviceEvents hunt as fallback. Measured on this tenant,
DeviceEvents PowerShellCommand rows land 26-28 minutes after the event
(`ingestion_time() - Timestamp`, consistent across samples), while RAPTOR triages within
about a minute of the alert firing. So when stage one comes back empty, stage two is
being asked for a row that will not exist for another half hour.

Verified by hand three times — DEMO-108429, DEMO-108594 and DEMO-107068 each arrived blank
or thin, and each bound and reached a correct AUTO_CLOSED_FP when re-run later.

Deliberately narrow:
  * ONE attempt per ticket (retriaged_at must be unset), so this can never loop;
  * unresolved tickets only, so it cannot disturb anything already scored — a re-triage
    clears verdict_match, and doing that to a scored row would pull it out of the
    accuracy denominator until the closure poller catches up;
  * blank-bound only (no device AND no command), which is the signature of the failure —
    a ticket that bound something is not this problem and is left alone;
  * agent-failure shadows skipped: an ai_error row holds the playbook's fallback verdict,
    a different fault that a re-run will not fix;
  * batch-capped, so a burst cannot stampede the backend.

It logs how many blank arrivals it found even when it re-triages none of them, because
that rate is the real signal — if it climbs, the enrichment is degrading and this sweep
is papering over it rather than fixing it.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Measured ingestion lag is 26-28 minutes; 35 gives margin without holding a ticket
# longer than necessary. Anything under ~30 would re-run while the row is still absent
# and burn the single attempt for nothing.
MIN_AGE_MINUTES = 35

# Bounded so a burst of blank alerts cannot flood the agent backend in one cycle. The
# remainder is simply picked up next cycle.
MAX_PER_CYCLE = 10

# Only families whose evidence is known to arrive late. Kept explicit rather than
# "anything blank": an identity or cloud alert with no device is often blank by nature
# (45 of the 49 unbound alerts in the shadow set are port sweeps / Netskope / SSH brute
# force, and they score 0.929 exactly as they are). Re-running those would cost agent
# calls to change nothing.
ELIGIBLE_ALERT_NAMES = (
    "powershell script was loaded in memory",
)


def _is_blank(shadow) -> bool:
    """No device AND no command — the shape that makes an alert uninvestigable."""
    if (getattr(shadow, "device_name", "") or "").strip():
        return False
    _cmds = getattr(shadow, "alert_processes", None) or []
    return not _cmds


async def find_blank_shadows(limit: int = MAX_PER_CYCLE) -> list:
    """Shadows that arrived blank, are old enough for evidence to have landed, and have
    not already had their one attempt."""
    from entity_graph.models import ShadowResult
    cutoff = datetime.utcnow() - timedelta(minutes=MIN_AGE_MINUTES)
    try:
        rows = await ShadowResult.find(
            ShadowResult.created_at <= cutoff,
        ).sort(-ShadowResult.created_at).limit(400).to_list()
    except Exception as exc:
        logger.error("blank-retriage query failed: %s", exc)
        return []

    out = []
    for s in rows:
        if getattr(s, "retriaged_at", None):
            continue                                  # its one attempt is spent
        if getattr(s, "l2_resolved_at", None) or getattr(s, "l1_resolved_at", None):
            continue                                  # resolved — never touch a scored row
        if getattr(s, "ai_error", None):
            continue                                  # infra failure, not a binding gap
        if (getattr(s, "alert_name", "") or "").strip().lower() not in ELIGIBLE_ALERT_NAMES:
            continue
        if not _is_blank(s):
            continue
        out.append(s)
    return out[:limit]


async def sweep_once(dry_run: bool = False) -> dict:
    """Find blank-bound alerts past the ingestion window and re-triage each once."""
    from app.views.edr_triage_views import _run_ticket_bg

    candidates = await find_blank_shadows()
    result = {"found": len(candidates), "retriaged": 0, "keys": [], "dry_run": dry_run}
    if not candidates:
        logger.debug("blank-retriage: nothing eligible")
        return result

    logger.info("blank-retriage: %d blank-bound alert(s) past the %dm ingestion window: %s",
                len(candidates), MIN_AGE_MINUTES, [s.jira_key for s in candidates])
    if dry_run:
        result["keys"] = [s.jira_key for s in candidates]
        return result

    for s in candidates:
        try:
            # force_agent so the agent actually re-runs; _run_ticket_bg uses dry_run=True
            # internally, so this re-triages and updates the shadow WITHOUT writing to
            # Jira — the ticket keeps its original comment and no analyst sees churn.
            await _run_ticket_bg(s.jira_key, force_agent=True)
            result["retriaged"] += 1
            result["keys"].append(s.jira_key)
            logger.info("blank-retriage: re-triaged %s (was blank at %s)",
                        s.jira_key, s.created_at)
        except Exception as exc:
            logger.error("blank-retriage: %s failed: %s", s.jira_key, exc)
    return result


async def run_forever(interval_seconds: int = 900) -> None:
    """Run the blank-arrival sweep in a loop. Called from main app startup.

    15 minutes: long enough that a ticket is only picked up once its evidence should
    have landed, short enough that a blank alert is not left uninvestigated for an hour.
    """
    logger.info("Blank-arrival re-triage sweep started (interval=%ds, min_age=%dm)",
                interval_seconds, MIN_AGE_MINUTES)
    while True:
        try:
            await sweep_once()
        except Exception as exc:
            logger.error("blank-retriage cycle failed: %s", exc)
        await asyncio.sleep(interval_seconds)
