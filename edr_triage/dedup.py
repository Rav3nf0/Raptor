"""Burst de-duplication: one detection event, one agent run.

A single Netskope DLP sweep fans out into many Jira tickets. Measured on 2026-08-28:
DEMO-110864 through DEMO-110872 — NINE tickets in 101 seconds, same user
(hayden.roy@example.com), same verdict (AUTO_CLOSED_FP) — and each one got its own
full agent run. That day carried 111 DLP tickets against 40 tickets of ALL families
the day before, and drove Bedrock spend from $1.63 to $9.69 in one day. Per-ticket cost
was flat; the volume was the whole story, and most of the volume was the same events
re-triaged under different keys.

Design, and specifically what this does NOT do:

  * It reuses the VERDICT of the first ticket in a burst for its siblings, and skips the
    agent for them. Cost falls by (N-1)/N on a burst of N.

  * Every sibling still gets its own ShadowResult and is still scored. Nothing is
    excluded from the accuracy denominator, and no verdict is changed after the fact —
    a burst of 9 that the agent gets wrong still scores 9 misses, exactly as today. That
    is deliberate: making the metric look better by dropping rows is off the table, so
    this is a pure cost change with a neutral effect on measured accuracy.

  * Siblings are identified by the EVENT they bind, never by arrival time or by user.
    Two DLP tickets are the same event only when they bind the same Netskope DLP
    incident id(s). Time-window or same-user matching would collapse genuinely distinct
    events that merely arrived together — the exact mistake the old window-sweep bind
    made (DEMO-110841), and the reason a correct bind had to land first.

Anything without an identifying event key is left completely alone: no key, no reuse.
"""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# How far back a sibling may be reused from. A sweep fans out in seconds-to-minutes;
# hours of slack covers a slow poll cycle without letting an old verdict be reused for
# a genuinely new recurrence of the same DLP incident id.
_DUPLICATE_WINDOW_HOURS = int(os.getenv("DUPLICATE_WINDOW_HOURS", "6"))

# Verdicts that may be reused. A sibling whose run errored, or that a gate blocked, is
# NOT reused: the block may have been caused by state specific to that ticket (its own
# concurrent siblings, its own truncated evidence), and re-deriving is the safe default.
_REUSABLE = ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP", "NEEDS_L2", "REQUEST_JUSTIFICATION")


def dlp_finding_group_id(evidence: dict | None) -> str:
    """Stable identity of the DLP finding(s) this ticket binds, or "" when unknown.

    Built from Netskope's own `dlp_incident_id` values, which are the vendor's identity
    for a DLP finding — so two tickets carrying the same set are the same finding by the
    vendor's definition, not by our inference.

    Requires the bind to be the alert-scoped one (`bind_source == "alert"`). A window
    sweep returns whatever else tripped a DLP rule nearby, so its incident-id set is not
    a property of THIS alert and must never be used to call two tickets identical.

    Returns "" whenever identity cannot be established, which disables reuse.
    """
    dlp = (evidence or {}).get("netskope_dlp") or {}
    if not dlp:
        return ""
    if dlp.get("bind_source") != "alert":
        return ""
    events = dlp.get("events") or []
    ids = sorted({
        str(e.get("dlp_incident_id")).strip()
        for e in events
        if isinstance(e, dict) and str(e.get("dlp_incident_id") or "").strip()
    })
    if not ids:
        return ""
    # Format matters for a reason that is not cosmetic. The first version returned
    # "dlp:<32 hex>", which is exactly the shape a secret scanner matches — and this
    # value is written into Jira, where Acme's own Netskope DLP rules ("DLP-Secret-key",
    # "Security - Passwords") read it. A grouping id for DLP tickets that itself trips DLP
    # is self-defeating, so the value is now readable and mostly digits.
    #
    # The ids are Netskope's own incident numbers, which the L1 comment already prints
    # verbatim ("DLP Incident ID: 3899734515604419166") — so this exposes nothing new,
    # and a human can read the group id and go straight to the finding.
    joined = "-".join(ids)
    if len(joined) <= 120:
        return f"netskope-findings-{joined}"
    # Long sets fall back to a digest, kept short and label-prefixed so it still does not
    # read as a credential. Deterministic for a given set, same as the direct form.
    return (f"netskope-findings-{len(ids)}-"
            f"{hashlib.sha256(joined.encode()).hexdigest()[:10]}")


async def find_duplicate_ticket(finding_group_id: str, alert_name: str, jira_key: str):
    """The earlier ShadowResult for this same event, or None.

    Matched on finding_group_id AND alert_name: the key already implies the event, and the
    alert_name check keeps a reuse from ever crossing alert families if two rules were
    ever to reference the same vendor incident id.
    """
    if not finding_group_id or os.getenv("DUPLICATE_REUSE_DISABLED", "").lower() == "true":
        return None
    try:
        from entity_graph.models import ShadowResult
        cutoff = datetime.now(timezone.utc) - timedelta(hours=_DUPLICATE_WINDOW_HOURS)
        sibs = await ShadowResult.find(
            ShadowResult.finding_group_id == finding_group_id,
            ShadowResult.alert_name == alert_name,
        ).sort(+ShadowResult.created_at).to_list()
    except Exception as exc:
        logger.warning("burst sibling lookup failed for %s: %s", jira_key, exc)
        return None

    for s in sibs:
        if s.jira_key == jira_key:
            continue
        created = s.created_at
        if created is not None:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if created < cutoff:
                continue
        if s.ai_triage_class not in _REUSABLE:
            continue
        if getattr(s, "blocked_by_safety", False) or getattr(s, "ai_error", None):
            continue
        return s
    return None


def reuse_result(sibling, agent_result_cls, tool_call_cls=None):
    """An AgentResult carrying the sibling's verdict, marked as a reuse.

    The reasoning is rewritten to say plainly that this ticket was not independently
    investigated and which ticket was — so an L2 analyst reading the comment is never
    misled into thinking N tickets corroborate each other when they are one event.
    """
    reasoning = (
        f"Duplicate of {sibling.jira_key} — same Netskope DLP finding, fanned out into "
        f"more than one Jira ticket. This ticket was NOT investigated independently; the "
        f"verdict below is carried over.\n\n"
        f"Verdict on {sibling.jira_key}: {sibling.ai_triage_class} "
        f"(confidence {sibling.ai_confidence:.2f}).\n\n"
        f"{(sibling.ai_reasoning or '').strip()}"
    )
    return agent_result_cls(
        triage_class=sibling.ai_triage_class,
        confidence=sibling.ai_confidence,
        reasoning=reasoning[:3000],
        recommended_actions=list(sibling.ai_recommended_actions or []),
        tool_calls=[],
        iterations=0,
        pre_safety_class=getattr(sibling, "pre_safety_class", "") or sibling.ai_triage_class,
        safety_gate_kind=getattr(sibling, "safety_gate_kind", ""),
    )
