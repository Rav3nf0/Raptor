"""Environment notes for the /shadow AI reviewer: facts about our estate that explain recurring
findings (an app account, a scheduled job, a known scanner), kept in Mongo and edited on /shadow.

Active notes join the hard-coded ENV_KNOWLEDGE in the reviewer's cached system prompt
(shadow_hunter/ai_review.py), under "still check that it applies to THIS host and time".

Two ways in:
  * an admin adds a note on /shadow: it is active at once;
  * an AI (a Claude Code pass today) PROPOSES one: it stays out of the prompt until an admin
    approves it. A model must never be able to write its own benign explanations into the
    prompt that judges the next finding.
Notes are retired, never deleted, so the history of what the reviewer was told stays.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

COLL = "shadow_env_notes"
MAX_TEXT = 600          # one fact, not an essay: every note is in every review call
MAX_ACTIVE = 40         # keeps the cached prompt small
STATUSES = ("active", "proposed", "retired")

_active: list[str] = []  # texts of active notes, refreshed at the start of each review run


def _coll():
    from shadow_hunter.models import Finding
    return Finding.get_pymongo_collection().database[COLL]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(text: str) -> str:
    from shadow_hunter.stories import clean      # secrets out, 12-digit ids masked
    return " ".join(clean(str(text or "")).split())


async def list_notes(include_retired: bool = False) -> list[dict]:
    q = {} if include_retired else {"status": {"$ne": "retired"}}
    rows = await _coll().find(q).sort("created_at", -1).to_list(length=500)
    return [{k: v for k, v in r.items() if k != "_id"} | {"id": r["_id"]} for r in rows]


async def add(text: str, by: str, *, proposed: bool, submitted_by: str = "", evidence: list | None = None) -> dict:
    text = _clean(text)
    if len(text) < 10:
        raise ValueError("note too short: say what it explains and where it applies")
    if len(text) > MAX_TEXT:
        raise ValueError(f"note too long ({len(text)} > {MAX_TEXT} characters): one fact per note")
    if not proposed and await _coll().count_documents({"status": "active"}) >= MAX_ACTIVE:
        raise ValueError(f"{MAX_ACTIVE} active notes already: retire one first")
    doc = {"_id": uuid.uuid4().hex[:12], "text": text, "status": "proposed" if proposed else "active",
           "by": str(by or "")[:80], "submitted_by": str(submitted_by or "")[:80],
           "evidence": [_clean(e)[:300] for e in (evidence or [])][:10],
           "created_at": _now(), "approved_by": "" if proposed else str(by or "")[:80],
           "approved_at": "" if proposed else _now(), "retired_by": "", "retired_at": ""}
    await _coll().insert_one(doc)
    if not proposed:
        await refresh()
    return {k: v for k, v in doc.items() if k != "_id"} | {"id": doc["_id"]}


async def approve(note_id: str, by: str) -> bool:
    if await _coll().count_documents({"status": "active"}) >= MAX_ACTIVE:
        raise ValueError(f"{MAX_ACTIVE} active notes already: retire one first")
    res = await _coll().update_one({"_id": note_id, "status": "proposed"},
                                   {"$set": {"status": "active", "approved_by": str(by)[:80], "approved_at": _now()}})
    await refresh()
    return bool(res.modified_count)


async def retire(note_id: str, by: str) -> bool:
    res = await _coll().update_one({"_id": note_id, "status": {"$ne": "retired"}},
                                   {"$set": {"status": "retired", "retired_by": str(by)[:80], "retired_at": _now()}})
    await refresh()
    return bool(res.modified_count)


async def refresh() -> list[str]:
    """Reload the active texts. On a database error the last good set stays in use."""
    global _active
    try:
        rows = await _coll().find({"status": "active"}).sort("created_at", 1).to_list(length=MAX_ACTIVE)
        _active = [r["text"] for r in rows]
    except Exception as exc:
        logger.warning("[env_notes] refresh failed, keeping %d cached notes: %s", len(_active), exc)
    return list(_active)


def active_texts() -> list[str]:
    return list(_active)
