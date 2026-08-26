"""Entity extractor — fires after pipeline completes to populate the SCG.

Runs as a fire-and-forget asyncio task. Never blocks or modifies the pipeline result.
"""
from __future__ import annotations

import logging
from typing import Any

from entity_graph.graph import upsert_entity, upsert_relationship

logger = logging.getLogger(__name__)


async def from_edr_alert(alert: dict, result: Any) -> None:
    """Extract entities from a processed EDR alert and upsert into SCG.

    alert: the alert_data dict from pipeline._process_ticket
    result: PlaybookResult with triage_class, labels, etc.
    """
    try:
        jira_key = alert.get("jira_key", "") or getattr(result, "jira_key", "")
        source = "mde"

        device_name = (alert.get("computerDnsName") or alert.get("machineName") or "").lower().strip()
        user_name = (
            (alert.get("relatedUser") or {}).get("userName", "")
            or (alert.get("loggedOnUsers") or [{}])[0].get("accountName", "")
            or ""
        ).lower().strip()
        # Co-users on a grouped multi-user incident, injected by the pipeline. The graph
        # must hold an entity per user, or the incident is only ever recallable through
        # accounts[0] (DEMO-107416). EMPTY for single-user alerts.
        other_users = [
            u for u in dict.fromkeys(
                (str(x) or "").lower().strip() for x in (alert.get("_additional_users") or [])
            ) if u and u != user_name
        ]
        sha256 = alert.get("_evidence", {}).get("sha256", "") or ""
        alert_name = alert.get("alertDisplayName", "")
        severity = alert.get("severity", "")
        triage_class = getattr(result, "triage_class", "")

        risk_delta = {"HIGH": 15.0, "CRITICAL": 25.0, "MEDIUM": 5.0, "LOW": 1.0}.get(severity.upper(), 0.0)
        if triage_class in ("AUTO_CLOSED_FP",):
            risk_delta = 0.0

        device_entity = None
        user_entity = None
        hash_entity = None

        if device_name:
            tags = []
            if triage_class == "AUTO_CLOSED_TP":
                tags.append("confirmed_threat")
            elif triage_class == "AUTO_CLOSED_FP":
                tags.append("known_benign_activity")
            device_entity = await upsert_entity("device", device_name, source_system=source, tags=tags, risk_delta=risk_delta)

        if user_name:
            user_entity = await upsert_entity("user", user_name, source_system=source, risk_delta=risk_delta * 0.5)

        # Same treatment for the co-users: same alert, same risk contribution.
        other_user_entities = []
        for _u in other_users:
            _e = await upsert_entity("user", _u, source_system=source, risk_delta=risk_delta * 0.5)
            if _e:
                other_user_entities.append(_e)

        if sha256 and len(sha256) == 64:
            hash_tags = []
            vt = alert.get("_vt", {})
            if vt.get("detections", 0) > 0:
                hash_tags.append("vt_flagged")
                if vt.get("verdict") == "malicious":
                    hash_tags.append("confirmed_malicious")
            hash_entity = await upsert_entity("hash", sha256, source_system=source, tags=hash_tags, risk_delta=risk_delta)

        # Relationships
        evidence_ref = jira_key or alert.get("id", "")
        if device_entity and user_entity:
            await upsert_relationship(
                str(device_entity.id), str(user_entity.id),
                "user_on_device", evidence_ref=evidence_ref,
            )
        # NB: co-users get NO user_on_device edge to `device_name` — on a grouped
        # incident each user is on their OWN host (DEMO-107416: two users, two Macs), so
        # asserting them onto the primary device would be a fabricated relationship.
        # The entity itself is what recall needs; the host binding stays unclaimed.
        if device_entity and hash_entity:
            await upsert_relationship(
                str(device_entity.id), str(hash_entity.id),
                "hash_on_device", evidence_ref=evidence_ref,
            )

    except Exception as exc:
        logger.error("from_edr_alert extractor failed: %s", exc, exc_info=True)


async def from_agent_investigation(
    jira_key: str,
    tool_calls: list[dict],
    result: Any,
) -> None:
    """Extract entities from agent tool call results post-investigation."""
    try:
        for tc in tool_calls:
            name = tc.get("name", "")
            args = tc.get("args", {})
            tool_result = tc.get("result", {})

            if name == "vt_lookup_hash" and "sha256" in args:
                tags = []
                if tool_result.get("detections", 0) > 0:
                    tags.append("vt_flagged")
                await upsert_entity("hash", args["sha256"], source_system="virustotal", tags=tags)

            elif name == "vt_lookup_domain" and "domain" in args:
                tags = []
                if tool_result.get("detections", 0) > 0:
                    tags.append("vt_flagged")
                await upsert_entity("domain", args["domain"], source_system="virustotal", tags=tags)

            elif name == "vt_lookup_ip" and "ip" in args:
                tags = []
                if tool_result.get("detections", 0) > 0:
                    tags.append("vt_flagged")
                await upsert_entity("ip", args["ip"], source_system="virustotal", tags=tags)

    except Exception as exc:
        logger.error("from_agent_investigation extractor failed for %s: %s", jira_key, exc)
