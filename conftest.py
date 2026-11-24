"""Tests must never open real Jira tickets. A local .env carries live Jira credentials, and on
2026-11-13 two paging tests that ran the whole /shadow job opened DEMO-122157..122163 for real.
Every test here gets a ticket creator that fails loudly; a test that wants tickets patches its own."""
import pytest


@pytest.fixture(autouse=True)
def _no_real_jira_tickets(monkeypatch):
    from shadow_hunter import tickets

    async def refuse(*_a, **_k):
        raise RuntimeError("tests must not create real Jira tickets (patch tickets._create)")
    monkeypatch.setattr(tickets, "_create", refuse)

    async def no_status(_key):
        return ""
    monkeypatch.setattr(tickets, "sync_closed", lambda status=None: tickets.__dict__["_sync_closed_impl"](status or no_status))
