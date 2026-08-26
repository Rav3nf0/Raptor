"""Jira action tool wrappers — wraps existing edr_triage/jira_handler.py."""
from __future__ import annotations

import logging

from agent_tools.registry import register

logger = logging.getLogger(__name__)


@register(
    name="jira_add_comment",
    description="Post a comment to a Jira ticket. Use for adding investigation notes, evidence summaries, or the final L1 verdict.",
    parameters={
        "type": "object",
        "properties": {
            "issue_key": {"type": "string", "description": "Jira issue key (e.g. DEMO-98578)"},
            "text": {"type": "string", "description": "Comment text in wiki markup format"},
        },
        "required": ["issue_key", "text"],
    },
)
async def jira_add_comment(issue_key: str, text: str) -> dict:
    from edr_triage.jira_handler import add_comment
    ok = await add_comment(issue_key, text)
    return {"success": ok, "issue_key": issue_key}


@register(
    name="jira_get_ticket",
    description="Fetch a Jira ticket's current status, labels, assignee, and description.",
    parameters={
        "type": "object",
        "properties": {
            "issue_key": {"type": "string", "description": "Jira issue key"},
        },
        "required": ["issue_key"],
    },
)
async def jira_get_ticket(issue_key: str) -> dict:
    import httpx
    from edr_triage.jira_handler import _build_client
    from edr_triage.config import get_edr_config
    cfg = get_edr_config()
    try:
        async with _build_client(cfg) as client:
            resp = await client.get(
                f"/rest/api/3/issue/{issue_key}",
                params={"fields": "summary,status,labels,assignee,description,priority,created"},
            )
            resp.raise_for_status()
            data = resp.json()
            fields = data.get("fields", {})
            return {
                "key": issue_key,
                "summary": fields.get("summary", ""),
                "status": (fields.get("status") or {}).get("name", ""),
                "labels": fields.get("labels", []),
                "assignee": ((fields.get("assignee") or {}).get("displayName", "Unassigned")),
                "priority": ((fields.get("priority") or {}).get("name", "")),
                "created": fields.get("created", ""),
            }
    except Exception as exc:
        return {"error": str(exc)[:200]}
