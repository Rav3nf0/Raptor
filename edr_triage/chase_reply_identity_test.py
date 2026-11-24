"""A Slack handle that is not the address's local part still counts as that user's answer.

DEMO-116104: asked gabriel.c@example.com, replies relayed as `gabriel.cortez`.
Run: python -m pytest edr_triage/chase_reply_identity_test.py -q
"""
from __future__ import annotations

from edr_triage import chase_reply_poller as CR
from edr_triage.chase_rounds_deadline_test import _c, _desc, BOT
from edr_triage.config import EDRTriageConfig


def _process(monkeypatch, email, comments):
    moved, posted = [], []

    async def fake_comment(key, text, cfg=None, dry_run=False):
        posted.append(text)
        return True

    async def fake_move(key, target, cfg, dry_run=False):
        moved.append(key)
        return True
    import edr_triage.store as S
    monkeypatch.setattr("edr_triage.jira_handler.add_comment", fake_comment)
    monkeypatch.setattr(CR, "_transition_to", fake_move)
    monkeypatch.setattr(S, "claim_chase_reply", lambda k: True)
    # The bot address via the env alias: a jira_email= keyword is silently ignored, which
    # leaves it empty and makes every comment look like the bot's.
    monkeypatch.setenv("JIRA_EMAIL", BOT)
    cfg = EDRTriageConfig(_env_file=None)
    assert cfg.jira_email == BOT
    fields = {"summary": "Netskope DLP Alerts", "description": _desc(email),
              "labels": ["raptor-chased"], "comment": {"comments": comments}}
    import asyncio
    return asyncio.run(CR._process("DEMO-116104", fields, cfg)), posted, moved


def test_sim_116104_justification_routes_without_waiting(monkeypatch):
    out, posted, moved = _process(monkeypatch, "gabriel.c@example.com", [
        _c("Notification dispatched to Gabriel Cortez. Manager: x.y@example.com", 26),
        _c("gabriel.cortez acknowledged involvement via slack", 24),
        _c("gabriel.cortez added a business justification via Slack: partner onboarding", 22)])
    assert out.get("handled") and moved
    assert "No answer" not in posted[0] and "partner onboarding" in posted[0]


def test_a_lone_unmatched_replier_is_the_one_user_asked():
    got = CR._attribute({"pc.handle": {"justification": "", "acked": True}}, ["gabriel.c"])
    assert list(got) == ["gabriel.c"]


def test_an_ambiguous_handle_is_not_guessed_between_several_users():
    got = CR._attribute({"amit": {"justification": "", "acked": True}}, ["amit.k", "amit.s"])
    assert "amit.k" not in got and "amit.s" not in got


def test_unique_prefix_matches_among_several_users():
    got = CR._attribute({"gabriel.cortez": {"justification": "j", "acked": True}},
                        ["gabriel.c", "freya.lindholm"])
    assert got["gabriel.c"]["justification"] == "j"


def test_sim_117308_a_reason_written_on_the_ticket_counts(monkeypatch):
    out, posted, moved = _process(monkeypatch, "v-dmitri.volkov@example.com", [
        _c("Notification dispatched to Dmitri Volkov. Manager: x.y@example.com", 30),
        _c("PAN and Aadhaar of BPO testers kept for severance pay", 29,
           author="v-dmitri.volkov@example.com"),
        _c("v-dmitri.volkov acknowledged involvement via slack", 5)])
    assert out.get("handled") and moved
    assert "written on this ticket" in posted[0] and "severance pay" in posted[0]
    assert "NO justification" not in posted[0]


def test_someone_else_commenting_is_not_the_users_answer(monkeypatch):
    out, posted, moved = _process(monkeypatch, "v-dmitri.volkov@example.com", [
        _c("Notification dispatched to Dmitri Volkov. Manager: x.y@example.com", 2),
        _c("Escalating to L2", 1, author="v-some.analyst@example.com")])
    assert not out.get("handled") and not moved


def test_a_comment_before_the_ask_is_not_an_answer(monkeypatch):
    out, posted, moved = _process(monkeypatch, "v-dmitri.volkov@example.com", [
        _c("an older note", 40, author="v-dmitri.volkov@example.com"),
        _c("Notification dispatched to Dmitri Volkov. Manager: x.y@example.com", 2)])
    assert not out.get("handled") and not moved


def test_sim_116804_a_file_name_in_raptors_own_note_is_not_a_reject(monkeypatch):
    note = ("Hi Team, we have received a Netskope DLP alert. Details: File/Object: Order Rejected - "
            "PAN-Aadhaar linking - 14/07/23 " + "context " * 60)
    out, posted, moved = _process(monkeypatch, "ivan.petrov@example.com", [
        _c(note, 3), _c("Notification dispatched to Ivan Petrov. Manager: x.y@example.com", 2)])
    assert not out.get("handled") and not moved


def test_a_relayed_reject_still_routes_at_once(monkeypatch):
    out, posted, moved = _process(monkeypatch, "jules.menon@example.com", [
        _c("Notification dispatched to Jules Menon. Manager: x.y@example.com", 2),
        _c("jules.menon rejected involvement via slack", 1)])
    assert out.get("handled") and moved and "DISOWNED" in posted[0]


def test_sim_120714_a_fresh_bare_acknowledge_waits_for_its_reason(monkeypatch):
    """Victor clicked Acknowledge and was routed 3 minutes later, before his reason landed."""
    out, posted, moved = _process(monkeypatch, "victor.hale@example.com", [
        _c("Notification dispatched to Victor Hale. Manager: x.y@example.com", 1),
        _c("v-victor.hale acknowledged involvement via slack", 0.05)])
    assert out.get("ack_grace") and not posted and not moved


def test_a_bare_acknowledge_routes_once_the_grace_is_over(monkeypatch):
    out, posted, moved = _process(monkeypatch, "victor.hale@example.com", [
        _c("Notification dispatched to Victor Hale. Manager: x.y@example.com", 2),
        _c("v-victor.hale acknowledged involvement via slack", 1)])
    assert out.get("handled") and moved and "NO justification" in posted[0]


def test_a_reason_routes_at_once(monkeypatch):
    out, posted, moved = _process(monkeypatch, "victor.hale@example.com", [
        _c("Notification dispatched to Victor Hale. Manager: x.y@example.com", 1),
        _c("v-victor.hale acknowledged involvement via slack", 0.05),
        _c("v-victor.hale added a business justification via Slack:\n\nUAC campaign export", 0.02)])
    assert out.get("handled") and moved and "NO justification" not in posted[0]


def test_a_reject_never_waits(monkeypatch):
    out, posted, moved = _process(monkeypatch, "jules.menon@example.com", [
        _c("Notification dispatched to Jules Menon. Manager: x.y@example.com", 1),
        _c("jules.menon rejected involvement via slack", 0.01)])
    assert out.get("handled") and moved
