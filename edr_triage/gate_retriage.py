"""Re-triage tickets a deterministic safety gate escalated on an EVIDENCE GAP, once,
after more telemetry has had time to land.

`blank_retriage.py` proved this pattern for one narrow shape (a PowerShell alert that
arrived with no bound device). Three tickets triaged this session showed the SAME shape
recurring under different gates entirely:

  * DEMO-112040 — the multi-host gate escalated because a co-host had no CloudTrail
    telemetry yet; retriaged hours later, the telemetry existed and the model reasoned
    correctly to AUTO_CLOSED_FP.
  * DEMO-112093 — the grounding-check gate escalated because the model's reasoning
    fabricated an actor ("charlie") out of an IAM role name; retriaged hours later, with
    richer command telemetry available, the model didn't need to guess and the gate never
    fired.
  * DEMO-109735 — the concurrency-check-missing gate escalated because the model asserted
    a check it never actually called.
  * DEMO-112580 — the grounding-check gate's domain check escalated because the
    GuardDuty EC2-DNS finding hadn't landed from Sentinel yet, and the model synthesized
    a fake domain ("drive-by-source-domain.com") out of the alert's own descriptive text
    rather than a real extracted one. This is the SAME evidence-gap shape as the others —
    once the finding lands, a retriage has the real domain to reason from instead.

None of these are permanent facts. Unlike a CRITICAL severity, a real VirusTotal
detection, or a known test device — which retrying cannot change — an evidence gap is, by
definition, a state that changes as telemetry catches up. `AgentResult.safety_gate_kind`
(set alongside `blocked_by_safety` in agent_core/loop.py) is the stable, machine-readable
tag this module filters on; it never pattern-matches the free-form `safety_block_reason`
prose, which can be reworded without notice.

Deliberately narrow, same as blank_retriage.py:
  * ONE attempt per ticket (retriaged_at must be unset), so this can never loop;
  * not yet SCORED (l2_resolved_at unset) — same reasoning as blank_retriage.py: a
    re-triage clears verdict_match, and l1_*/l2_* fields survive a re-triage untouched
    (edr_triage/pipeline.py::_save_shadow_result), so re-triaging between the L1->L2
    handoff and final resolution is safe;
  * agent-failure shadows skipped (ai_error set) — an infra failure, not an evidence gap;
  * only the gate KINDS in RETRY_ELIGIBLE_KINDS — deliberately excludes the
    validation-critic layers and the REQUEST_JUSTIFICATION upgrade path, which each fold
    multiple sub-reasons together (some plausibly hard-stops) and haven't been drilled
    into individually yet. Also excludes the concurrent-open-alerts gate, which already
    has its own re-trigger path via `blocked_by_concurrent_keys` (the closure poller
    re-fires it when a sibling closes) — adding it here would be a second, redundant
    trigger.
  * batch-capped, so a burst cannot stampede the backend.

Unlike blank_retriage.py's MIN_AGE_MINUTES (measured: 26-28 minute MDE ingestion lag),
GATE_RETRIAGE_MIN_AGE_MINUTES is a placeholder, not a measurement — the two live retriages
that motivated this module succeeded at ~16h and ~24h after the alert, far longer than
blank-arrival's lag, but that is two data points, not a distribution. It is env-tunable
for exactly this reason: log how many tickets are eligible every cycle even when none are
retried (same transparency principle as blank_retriage.py), and tighten the constant once
that rate is actually measured.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Placeholder, not measured — see module docstring. Env-tunable so it can be corrected
# without a redeploy once real lag data exists.
GATE_RETRIAGE_MIN_AGE_MINUTES = int(os.getenv("GATE_RETRIAGE_MIN_AGE_MINUTES", "240"))

# Bounded so a burst of escalations cannot flood the agent backend in one cycle. The
# remainder is simply picked up next cycle.
MAX_PER_CYCLE = 10

# Kept explicit and narrow — see the module docstring for why each excluded gate stays
# excluded. Values match AgentResult.safety_gate_kind exactly (agent_core/loop.py).
RETRY_ELIGIBLE_KINDS = frozenset({
    "multi_host_unassessed",
    "grounding_actor",
    "grounding_command",
    "grounding_domain",
    "concurrency_check_missing",
    "evidence_floor",
    "hunt_errored",
})


def _is_gate_eligible(shadow) -> bool:
    """The gate that blocked this shadow is one we've classified as an evidence gap."""
    return (getattr(shadow, "safety_gate_kind", "") or "") in RETRY_ELIGIBLE_KINDS


async def find_gate_shadows(limit: int = MAX_PER_CYCLE) -> list:
    """Shadows a retry-eligible gate escalated, old enough for evidence to have landed,
    and that have not already had their one attempt."""
    from entity_graph.models import ShadowResult
    cutoff = datetime.utcnow() - timedelta(minutes=GATE_RETRIAGE_MIN_AGE_MINUTES)
    try:
        rows = await ShadowResult.find(
            ShadowResult.created_at <= cutoff,
            ShadowResult.blocked_by_safety == True,  # noqa: E712 (Beanie query operator)
        ).sort(-ShadowResult.created_at).limit(400).to_list()
    except Exception as exc:
        logger.error("gate-retriage query failed: %s", exc)
        return []

    out = []
    for s in rows:
        if getattr(s, "retriaged_at", None):
            continue                                  # its one attempt is spent
        if getattr(s, "l2_resolved_at", None):
            continue                                  # scored — never touch a resolved row
        if getattr(s, "ai_error", None):
            continue                                  # infra failure, not an evidence gap
        if not _is_gate_eligible(s):
            continue
        out.append(s)
    return out[:limit]


async def sweep_once(dry_run: bool = False) -> dict:
    """Find gate-escalated tickets past the placeholder age window and re-triage each once."""
    from app.views.edr_triage_views import _run_ticket_bg

    candidates = await find_gate_shadows()
    result = {"found": len(candidates), "retriaged": 0, "keys": [], "dry_run": dry_run}
    if not candidates:
        logger.debug("gate-retriage: nothing eligible")
        return result

    logger.info(
        "gate-retriage: %d gate-escalated ticket(s) past the %dm window: %s",
        len(candidates), GATE_RETRIAGE_MIN_AGE_MINUTES,
        [(s.jira_key, s.safety_gate_kind) for s in candidates],
    )
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
            logger.info("gate-retriage: re-triaged %s (was %s at %s)",
                        s.jira_key, s.safety_gate_kind, s.created_at)
        except Exception as exc:
            logger.error("gate-retriage: %s failed: %s", s.jira_key, exc)
    return result


async def run_forever(interval_seconds: int = 900) -> None:
    """Run the gate-escalation re-triage sweep in a loop. Called from main app startup.

    Same 15-minute cadence as blank_retriage.py — the sweep interval just controls how
    promptly an ALREADY-eligible ticket gets picked up; GATE_RETRIAGE_MIN_AGE_MINUTES is
    what actually paces re-triage against telemetry lag.
    """
    logger.info("Gate-escalation re-triage sweep started (interval=%ds, min_age=%dm)",
                interval_seconds, GATE_RETRIAGE_MIN_AGE_MINUTES)
    while True:
        try:
            await sweep_once()
        except Exception as exc:
            logger.error("gate-retriage cycle failed: %s", exc)
        await asyncio.sleep(interval_seconds)
