"""Environment notes for the AI reviewer: admins add, AIs only propose. In-memory Mongo.

Run: python -m pytest shadow_hunter/env_notes_test.py -q
"""
from __future__ import annotations

import asyncio

import pytest
from beanie import init_beanie

AsyncMongoMockClient = pytest.importorskip("mongomock_motor").AsyncMongoMockClient  # dev extra

from app.roles import ADMIN, ANALYST, allowed
from shadow_hunter import ai_review as R
from shadow_hunter import env_notes as N
from shadow_hunter.models import AuditLog, Finding

ACCT = "1234" * 3   # a made-up account id, built so no 12-digit literal sits in the repo


def _run(coro):
    async def wrapped():
        await init_beanie(database=AsyncMongoMockClient()["notes_test"], document_models=[Finding, AuditLog])
        N._active.clear()
        return await coro()
    return asyncio.run(wrapped())


def test_an_admin_note_is_in_the_next_prompt():
    async def go():
        await N.add("oaa is the OmneSys application user on the NSE DC hosts", "admin1", proposed=False)
        await N.refresh()
        return R.system_prompt("short")
    assert "- oaa is the OmneSys application user" in _run(go)


def test_a_proposal_stays_out_of_the_prompt_until_approved():
    async def go():
        n = await N.add("jenkins-omnesys 10.0.1.160 rotates oaa keys on Saturdays", "claude-code-manual",
                        proposed=True, evidence=["Slack 19 Nov"])
        before = "jenkins-omnesys" in R.system_prompt("short")
        assert await N.approve(n["id"], "admin1")
        after = "jenkins-omnesys" in R.system_prompt("short")
        assert await N.retire(n["id"], "admin1")
        gone = "jenkins-omnesys" not in R.system_prompt("short")
        return before, after, gone
    assert _run(go) == (False, True, True)


def test_secrets_and_account_ids_are_cleaned_and_size_is_bounded():
    async def go():
        n = await N.add(f"role arn:aws:iam::{ACCT}:role/x uses password=Hunter2pass for the job", "a", proposed=False)
        with pytest.raises(ValueError):
            await N.add("x" * (N.MAX_TEXT + 1), "a", proposed=False)
        with pytest.raises(ValueError):
            await N.add("short", "a", proposed=False)
        return n["text"]
    text = _run(go)
    assert ACCT not in text and "Hunter2pass" not in text


def test_only_admins_add_or_approve_analysts_may_propose():
    assert allowed(ANALYST, "POST", "/api/shadow/env-notes/propose")
    assert not allowed(ANALYST, "POST", "/api/shadow/env-notes")
    assert not allowed(ANALYST, "POST", "/api/shadow/env-notes/abc/approve")
    assert allowed(ADMIN, "POST", "/api/shadow/env-notes/abc/approve")
