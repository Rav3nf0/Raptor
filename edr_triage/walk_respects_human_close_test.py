"""RAPTOR never re-closes a ticket a person closed while it was working (DEMO-120563).

Run: python -m pytest edr_triage/walk_respects_human_close_test.py -q
"""
from __future__ import annotations

import asyncio

from edr_triage import jira_handler as J


def _walk(monkeypatch, current):
    moved = []

    async def status(key, cfg=None):
        return current

    async def hop(key, target, cfg=None, dry_run=False):
        moved.append(target)
        return True

    async def own(key, cfg=None):
        return True
    monkeypatch.setattr(J, "get_status", status)
    monkeypatch.setattr(J, "transition_to_status", hop)
    monkeypatch.setattr(J, "assign_to_self_if_unassigned", own)
    ok = asyncio.run(J.walk_to_status("DEMO-1", ["Assigned", "Event Analysis", "False Positive"],
                                      cfg=object()))
    return ok, moved


def test_a_ticket_a_person_already_closed_is_left_alone(monkeypatch):
    for status in ("Duplicate", "Closed", "Resolved", "No Response"):
        ok, moved = _walk(monkeypatch, status)
        assert ok is False and moved == [], status


def test_an_open_ticket_is_still_walked(monkeypatch):
    ok, moved = _walk(monkeypatch, "Event Analysis")
    assert ok is True and moved == ["False Positive"]
