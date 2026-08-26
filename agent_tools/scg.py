"""SCG query tool wrappers — lets the agent query the Security Context Graph."""
from __future__ import annotations

import logging

from agent_tools.registry import register

logger = logging.getLogger(__name__)


@register(
    name="scg_get_entity_context",
    description=(
        "Query the Security Context Graph for history about an entity (device, user, hash, domain, IP). "
        "Returns past alerts, verdicts, tags, and risk score. Call this first for every entity in the alert."
    ),
    parameters={
        "type": "object",
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": ["device", "user", "hash", "domain", "ip", "process"],
                "description": "Type of entity to look up",
            },
            "value": {"type": "string", "description": "Normalized entity value (hostname, UPN, SHA256, domain, IP)"},
        },
        "required": ["entity_type", "value"],
    },
)
async def scg_get_entity_context(entity_type: str, value: str) -> dict:
    try:
        from entity_graph.query import get_entity_context
        return await get_entity_context(entity_type, value)
    except Exception as exc:
        logger.warning("SCG query failed for %s/%s: %s", entity_type, value, exc)
        return {"entity_type": entity_type, "value": value, "found": False, "error": str(exc)[:100]}


@register(
    name="scg_recall_memories",
    description=(
        "Retrieve curated memories related to a device or user. "
        "Returns analyst verdicts, exception notes, and threat context stored from past investigations."
    ),
    parameters={
        "type": "object",
        "properties": {
            "entity_type": {
                "type": "string",
                "enum": ["device", "user", "hash", "domain", "ip"],
            },
            "value": {"type": "string"},
            "min_confidence": {
                "type": "number",
                "description": "Minimum confidence threshold (0-1). Default 0.5.",
                "default": 0.5,
            },
        },
        "required": ["entity_type", "value"],
    },
)
async def scg_recall_memories(entity_type: str, value: str, min_confidence: float = 0.5) -> dict:
    try:
        from entity_graph.memory import recall_memories
        memories = await recall_memories(entity_type, value, min_confidence=min_confidence)
        return {"memories": memories, "count": len(memories)}
    except Exception as exc:
        logger.warning("SCG memory recall failed: %s", exc)
        return {"memories": [], "count": 0, "error": str(exc)[:100]}


@register(
    name="scg_check_concurrent_alerts",
    description=(
        "Check if the same user or device has other open alerts in the past 24 hours. "
        "Returns concurrent_count, open_alerts (Jira keys), and open_alert_details (each "
        "sibling's alert_name, ai_triage_class, created_at). Used as a hard gate before "
        "auto-closing. Also lets you tell a DUPLICATE (a sibling with the SAME alert_name on "
        "the same entity at nearly the same time) apart from distinct concurrent alerts (which "
        "may be an attack chain) — a same-name concurrent sibling is likely a duplicate of that "
        "in-flight ticket, not an independent event."
    ),
    parameters={
        "type": "object",
        "properties": {
            "device_name": {"type": "string", "description": "Device hostname (optional)"},
            "user_name": {"type": "string", "description": "Username or UPN (optional)"},
        },
    },
)
async def scg_check_concurrent_alerts(device_name: str = "", user_name: str = "",
                                      exclude_jira_key: str = "",
                                      reference_time: str = "") -> dict:
    # exclude_jira_key and reference_time are injected by the agent loop (the current
    # ticket key, and when its alert fired) so a ticket doesn't self-count on re-triage
    # and the 24h window is anchored to the alert instead of wall-clock now. Both are
    # intentionally NOT in the schema above, so the model never sets them.
    try:
        from entity_graph.query import check_concurrent_alerts
        return await check_concurrent_alerts(device_name=device_name, user_name=user_name,
                                             exclude_jira_key=exclude_jira_key,
                                             reference_time=reference_time)
    except Exception as exc:
        logger.warning("SCG concurrent alert check failed: %s", exc)
        return {"concurrent_count": 0, "open_alerts": [], "open_alert_details": [], "error": str(exc)[:100]}
