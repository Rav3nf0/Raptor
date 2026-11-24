"""Jira tickets for Claude-confirmed /shadow true positives (2026-11-13, the user's call).

Before this, a TP decision only made a mock Sentinel incident id (clients/sentinel_mock.py) that
went nowhere. Now a Claude-verified TP (the same bar as a page: high/critical, confidence >= 0.8,
not already reviewed by a person; or a story carrying one) opens a SIM ticket, so it reaches L2's
queue, mail and SLAs.

  one ticket per group  a story, else a host or account, while it has seen a TP in the last 24h.
                        Later TPs on it become comments, not tickets (ATLAS's 60 TPs = 1 ticket).
  no second page        the ticket joins the PagerDuty incident its findings opened, as member
                        raptor:<key>. RAPTOR's intake skips tickets labelled deepintel-shadow, and
                        paging is idempotent per member, so the ticket never rings again.
  closing               when the ticket is closed in Jira, its part of the incident closes.

SHADOW_TICKETS=0 turns it off. Collection: shadow_tickets (one row per ticket).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

LABEL = "deepintel-shadow"
GROUP_HOURS = 24
CLOSED = {"closed", "resolved", "done", "cancelled", "canceled"}


def enabled() -> bool:
    return os.getenv("SHADOW_TICKETS", "1").strip().lower() in ("1", "true", "yes", "on")


def _col():
    from lib import paging
    return paging._col("shadow_tickets")


def _wiki(text: str) -> str:
    return str(text or "").replace("{", "(").replace("}", ")")


def _finding_block(f, base: str) -> list[str]:
    from shadow_hunter.stories import clean
    ev = [f"* {_wiki(clean(str(e)))[:300]}" for e in (f.ai_evidence or [])[:8]]
    return [f"*{(f.severity or '').upper()} · {f.detector}* on *{_wiki(f.device_name or f.account_name or '?')}*",
            _wiki(clean(f.summary or f.indicator or ""))[:600],
            f"Claude: *true positive* ({float(f.ai_confidence or 0):.2f}) · {_wiki(f.ai_by)}",
            "{quote}" + _wiki(clean(f.ai_reasoning or ""))[:2500] + "{quote}",
            *(["Evidence checked:"] + ev if ev else []),
            f"[Open in /shadow|{base}/shadow?finding={f.id}]"
            + (f" · [Full investigation|{base}/api/shadow/ai/trail/{f.ai_trail_id}]" if getattr(f, "ai_trail_id", "") else "")]


def description(f, story, base: str) -> str:
    lines = ["h2. /shadow: Claude-confirmed true positive", "",
             "Opened by DeepIntel /shadow. Claude reviewed this detection and called it a true positive; "
             "an analyst should confirm and respond. Further true positives on the same story or host are "
             "added as comments.", ""]
    if story:
        lines += [f"*Story:* [{_wiki(story.title)}|{base}/shadow/stories/{story.id}] ({story.severity})", ""]
    return "\n".join(lines + _finding_block(f, base))


async def _create(summary: str, desc: str, priority: str) -> str:
    from edr_triage.config import get_edr_config
    from edr_triage.jira_handler import _build_client, _wiki_to_adf
    cfg = get_edr_config()
    if not (cfg.jira_email and cfg.jira_token):
        raise RuntimeError("Jira credentials are not configured")
    payload = {"fields": {"project": {"key": cfg.jira_project_key}, "summary": summary[:250],
                          "description": _wiki_to_adf(desc), "issuetype": {"name": cfg.jira_issue_type},
                          "priority": {"name": priority}, "labels": ["deepintel", LABEL]}}
    async with _build_client(cfg) as client:
        resp = await client.post("/rest/api/3/issue", json=payload)
        if resp.status_code >= 300:
            raise RuntimeError(f"Jira create {resp.status_code}: {resp.text[:300]}")
        return resp.json()["key"]


async def ticket_for(f, story=None, now: datetime | None = None, create=None, comment=None) -> dict:
    """Open (or add to) the ticket for this Claude-confirmed TP. Idempotent per finding."""
    from lib import paging
    from shadow_hunter.paging import _entities
    from shadow_hunter.stories import clean
    now = now or datetime.now(timezone.utc)
    col = _col()
    if col.find_one({"findings": f.id}):
        return {"action": "already"}
    ents = [e for e in ([paging.entity("story", story.id)] if story else []) + _entities(f) if e]
    base = paging.base_url()
    row = col.find_one({"status": "open", "entities": {"$in": ents},
                        "last_at": {"$gte": now - timedelta(hours=GROUP_HOURS)}}, sort=[("created_at", -1)])
    if row:
        if comment is None:
            from edr_triage.jira_handler import add_comment as comment
        ok = await comment(row["_id"], "h3. Another Claude-confirmed true positive\n" + "\n".join(_finding_block(f, base)))
        if ok is False:
            raise RuntimeError(f"comment on {row['_id']} failed")
        col.update_one({"_id": row["_id"]}, {"$push": {"findings": f.id}, "$addToSet": {"entities": {"$each": ents}},
                                              "$set": {"last_at": now}})
        _attach(row["_id"], f, story)
        return {"action": "comment", "jira_key": row["_id"]}
    where = f.device_name or f.account_name or ""
    summary = clean(f"[/shadow] {f.severity} {f.detector}" + (f" on {where}" if where else "")
                    + f": {(f.summary or f.indicator or '')[:120]}")
    key = await (create or _create)(summary, description(f, story, base),
                                    "Critical" if f.severity == "critical" else "High")
    col.insert_one({"_id": key, "entities": ents, "findings": [f.id], "story_id": story.id if story else "",
                    "created_at": now, "last_at": now, "status": "open"})
    _attach(key, f, story)
    logger.info("[shadow-tickets] %s opened for finding %s", key, f.id)
    return {"action": "created", "jira_key": key}


def _attach(key: str, f, story) -> None:
    """Join the ticket to the PagerDuty incident its finding (or story) opened, as a member, so
    RAPTOR never pages it and closing it in Jira counts toward resolving the incident."""
    from lib import paging
    members = [f"shadow:finding:{f.id}", f"shadow:early:{f.id}"] + ([f"shadow:story:{story.id}"] if story else [])
    inc = next((i for i in (paging._member_incident(m) for m in members) if i), None)
    if not inc or paging._member_incident(f"raptor:{key}"):
        return
    paging._col("pd_incidents").update_one({"_id": inc["_id"]}, {"$push": {"members": {
        "id": f"raptor:{key}", "source": "shadow-ticket", "closed": False, "title": f"Jira {key}",
        "at": datetime.now(timezone.utc), "urgency": inc.get("urgency", "high"), "kind": "shadow:ticket"}}})


async def sync_closed(status=None) -> int:
    """Tickets closed in Jira: mark them and close their part of the PagerDuty incident."""
    if status is None:
        from edr_triage.jira_handler import get_status as status
    return await _sync_closed_impl(status)


async def _sync_closed_impl(status) -> int:
    from lib import paging
    n = 0
    for row in list(_col().find({"status": "open"}).limit(50)):
        st = (await status(row["_id"]) or "").strip().lower()
        if st in CLOSED:
            _col().update_one({"_id": row["_id"]}, {"$set": {"status": "closed", "closed_at": datetime.now(timezone.utc)}})
            await paging.close_member(f"raptor:{row['_id']}")
            n += 1
    return n
