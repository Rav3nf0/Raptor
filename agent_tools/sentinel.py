"""Sentinel tool wrappers — wraps existing edr_triage/sentinel_client.py."""
from __future__ import annotations

import logging

from agent_tools.registry import register

logger = logging.getLogger(__name__)


def _neutralize_incident_verdict(incident: dict) -> dict:
    """Strip the Sentinel incident's status / classification / owner.

    L1 ALWAYS closes the Sentinel incident as FalsePositive the moment they raise the
    Jira ticket, so that close is a PROCEDURAL artifact — NOT an analyst verdict.
    Leaving it in makes the agent rubber-stamp FP off a meaningless
    "closed FP by <analyst>" signal instead of investigating. The verdict is decided
    HERE, from the evidence; the real human judgement (if any) lives in the Jira ticket.
    """
    if not isinstance(incident, dict):
        return incident
    props = incident.get("properties")
    if isinstance(props, dict):
        for f in ("status", "classification", "classificationReason",
                  "classificationComment", "owner"):
            props.pop(f, None)
        props["verdict_note"] = (
            "Sentinel incident status/classification/owner intentionally omitted: L1 ALWAYS "
            "closes the Sentinel incident as FalsePositive when raising the Jira ticket, so it "
            "is procedural, NOT an analyst verdict. Do NOT treat this incident as 'already "
            "closed FP' — decide the verdict from the evidence you gather."
        )
    return incident


@register(
    name="sentinel_get_incident",
    description="Fetch Sentinel incident details, entities, and alerts for a given incident URL.",
    parameters={
        "type": "object",
        "properties": {
            "incident_url": {"type": "string", "description": "Sentinel incident API URL"},
        },
        "required": ["incident_url"],
    },
)
async def sentinel_get_incident(incident_url: str) -> dict:
    import asyncio
    from edr_triage.sentinel_client import (
        fetch_incident, fetch_incident_entities, fetch_incident_alerts,
    )
    incident, entities, alerts = await asyncio.gather(
        fetch_incident(incident_url),
        fetch_incident_entities(incident_url),
        fetch_incident_alerts(incident_url),
    )
    return {
        "incident": _neutralize_incident_verdict(incident),
        "entities": entities,
        "alerts": alerts,
        "entity_count": len(entities),
        "alert_count": len(alerts),
    }


@register(
    name="sentinel_run_kql",
    description="FALLBACK (prefer the hunt_* tools / hunt_query). Run a hand-written KQL query against the Sentinel Log Analytics workspace. Use only when no hunt_* tool fits (identity, CloudTrail, sign-in, security-event queries).",
    parameters={
        "type": "object",
        "properties": {
            "kql": {"type": "string", "description": "KQL query targeting Sentinel tables (SigninLogs, SecurityEvent, IdentityLogonEvents, etc.)"},
        },
        "required": ["kql"],
    },
)
async def sentinel_run_kql(kql: str) -> dict:
    from lib.mde_client import run_sentinel_query, preflight_kql
    # Same strip + lint pre-flight as mde_advanced_hunt — catches malformed KQL
    # (unbalanced parens/quotes, stray backticks, truncation, empty/trailing pipes)
    # BEFORE the engine round-trip, instead of relying on the auto-fixer afterwards.
    cleaned, pf_err = preflight_kql(kql)
    if pf_err:
        return {"error": pf_err, "rows": []}
    rows, err = await run_sentinel_query(cleaned)
    if err:
        return {"error": err, "rows": []}
    if not rows:
        # Same empty-source guard as the hunt_* builders: a 0-row result from a table
        # that holds no data at all is an evidence GAP, not a clean finding. The
        # free-write path needs it too — on DEMO-107932 the agent reached SecurityEvent
        # via hunt_sentinel_event AND hunt_query and read all three empties as proof.
        from agent_tools.hunt import _leading_table, _sentinel_table_is_empty
        _tbl = _leading_table(cleaned)
        if await _sentinel_table_is_empty(_tbl):
            return {
                "error": (f"{_tbl} is EMPTY in this workspace (no rows in 30d) — this query "
                          "cannot confirm anything. Not evidence of benign; the data likely "
                          "lives in MDE (hunt_events / hunt_process) instead."),
                "rows": [], "count": 0, "source_empty": True,
            }
    return {"rows": rows, "count": len(rows)}
