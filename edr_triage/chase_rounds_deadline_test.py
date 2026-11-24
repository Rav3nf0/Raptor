"""A second chase round is routed again, and Awaiting more inputs has a deadline.

2026-10-12 16:03-16:09: L2 sent 8 answered tickets back for another round (DEMO-116367
among them). A packet anywhere on the ticket meant "handled", so the new answers would
never have reached L2. Separately, 249 quarantine-audit tickets sat in Awaiting more
inputs for up to 39 days with nobody picking them up.

Run: python -m pytest edr_triage/chase_rounds_deadline_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from edr_triage import chase_reply_poller as CR
from edr_triage.config import EDRTriageConfig

BOT = "bot@example.com"


def _c(text, hours_ago, author=BOT):
    when = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    return {"created": when, "author": {"emailAddress": author},
            "body": {"type": "doc", "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": text}]}]}}


def _desc(email="freya.lindholm@example.com"):
    return {"type": "doc", "content": [{"type": "table", "content": [
        {"type": "tableRow", "content": [
            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": "Involved Users ", "marks": [{"type": "strong"}]}]}]},
            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [
                {"type": "text", "text": email}]}]}]}]}]}


ROUND1 = [_c("Notification dispatched to Freya Lindholm. Manager: ellis.rana@example.com", 80),
          _c("freya.lindholm acknowledged involvement via slack", 10),
          _c(f"{CR._PACKET_MARKER} Users responded — for L2 approval", 9)]


def _run(monkeypatch, comments, labels=("raptor-chased",)):
    posted, claims, moved = [], [], []

    async def fake_comment(key, text, cfg=None, dry_run=False):
        posted.append(text)
        return True

    async def fake_move(key, target, cfg, dry_run=False):
        moved.append(key)
        return True
    import edr_triage.store as S
    monkeypatch.setattr("edr_triage.jira_handler.add_comment", fake_comment)
    monkeypatch.setattr(CR, "_transition_to", fake_move)
    monkeypatch.setattr(S, "claim_chase_reply", lambda k: claims.append(k) or True)
    cfg = EDRTriageConfig(_env_file=None, jira_email=BOT)
    fields = {"summary": "Netskope DLP Alerts", "description": _desc(),
              "labels": list(labels), "comment": {"comments": comments}}
    return CR._process("DEMO-116367", fields, cfg), fields, cfg, posted, claims, moved


def test_a_routed_round_with_no_new_chase_is_handled(monkeypatch):
    out, *_ = _run(monkeypatch, ROUND1)
    assert asyncio.run(out) == {"skip_reason": "already_handled"}


def test_a_second_round_waits_for_its_own_answer(monkeypatch):
    out, *_ = _run(monkeypatch, ROUND1 + [_c("Notification dispatched to Freya Lindholm.", 2)])
    r = asyncio.run(out)
    # Round one's acknowledgement does not count for round two.
    assert "waiting_hours" in r and r["silent"] == ["freya.lindholm"]


def test_a_second_round_answer_is_routed_under_its_own_claim(monkeypatch):
    out, _, _, posted, claims, moved = _run(monkeypatch, ROUND1 + [
        _c("Notification dispatched to Freya Lindholm.", 2),
        _c("freya.lindholm added a business justification via Slack: BGV tracker for HR", 1)])
    assert asyncio.run(out).get("handled")
    assert claims == ["DEMO-116367#round2"] and moved == ["DEMO-116367"]
    assert "BGV tracker" in posted[0]


def test_the_reply_handler_owns_a_running_raptor_chase():
    running = {"labels": ["raptor-chased"], "comment": {"comments": [
        _c("Notification dispatched to A.", 5)]}}
    assert CR._owned_by_reply_handler(running)
    l1_hand_chase = {"labels": [], "comment": {"comments": [_c("please justify", 200, "l1@example.com")]}}
    assert not CR._owned_by_reply_handler(l1_hand_chase)
    finished = {"labels": ["raptor-chased"], "comment": {"comments": ROUND1}}
    assert not CR._owned_by_reply_handler(finished)


def _deadline(monkeypatch, issues, claim=lambda k: True, **cfg_kw):
    posted, moved, jqls = [], [], []

    async def fake_search(cfg, jql, fields, max_pages=20):
        jqls.append(jql)
        return issues

    async def fake_comment(key, text, cfg=None, dry_run=False):
        posted.append((key, text))
        return True

    async def fake_move(key, target, cfg, dry_run=False):
        assert target == "L2 Analysis required"
        moved.append(key)
        return True
    import edr_triage.store as S
    monkeypatch.setattr(CR, "_search", fake_search)
    monkeypatch.setattr("edr_triage.jira_handler.add_comment", fake_comment)
    monkeypatch.setattr(CR, "_transition_to", fake_move)
    monkeypatch.setattr(S, "claim_chase_reply", claim)
    cfg = EDRTriageConfig(_env_file=None, jira_email=BOT, **cfg_kw)
    return asyncio.run(CR._route_overdue(cfg, dry_run=False)), posted, moved, jqls


def _issue(key, labels=(), comments=()):
    return {"key": key, "fields": {"labels": list(labels), "comment": {"comments": list(comments)}}}


def test_overdue_hand_chases_are_routed_with_a_note(monkeypatch):
    routed, posted, moved, jqls = _deadline(monkeypatch, [_issue("DEMO-1"), _issue("DEMO-2")])
    assert routed == moved == ["DEMO-1", "DEMO-2"]
    assert CR._DEADLINE_MARKER in posted[0][1] and "No answer after 7 days" in posted[0][1]
    assert 'NOT status CHANGED AFTER -7d' in jqls[0]
    assert 'CHANGED TO "Awaiting more inputs" AFTER "2026-10-12 00:00"' in jqls[0]


def test_a_running_raptor_chase_is_left_to_the_reply_handler(monkeypatch):
    running = _issue("DEMO-3", ["raptor-chased"], [_c("Notification dispatched to A.", 200)])
    routed, *_ = _deadline(monkeypatch, [running])
    assert routed == []


def test_the_per_run_cap_holds(monkeypatch):
    routed, *_ = _deadline(monkeypatch, [_issue(f"DEMO-{i}") for i in range(20)])
    assert len(routed) == 5


def test_another_pod_holding_the_claim_skips_it(monkeypatch):
    routed, posted, *_ = _deadline(monkeypatch, [_issue("DEMO-1")], claim=lambda k: False)
    assert routed == [] and posted == []


def test_zero_days_disables_it(monkeypatch):
    routed, posted, moved, jqls = _deadline(monkeypatch, [_issue("DEMO-1")],
                                            EDR_AWAITING_DEADLINE_DAYS=0)
    assert routed == [] and jqls == []
