"""The deterministic user chase (Phase 1), scoped to Netskope bulk-download tickets with
exactly one eligible+reachable recipient.

Three properties matter most:
  * the model must NEVER be able to reach a Slack DM — only a deterministic playbook
    branch may set action="user_confirmation", and it must always carry pre-resolved
    chase_recipients;
  * shadow/copilot (or EDR_USER_CHASE off) post an ADVISORY comment and change nothing;
  * a failure mid-sequence aborts the rest and escalates to L2, rather than leaving a
    ticket half-walked — Involved Users written but the ticket never transitioned would
    be invisible to everyone.
"""
from __future__ import annotations

import asyncio

import pytest

from edr_triage.config import EDRTriageConfig
from edr_triage.playbooks.base import PlaybookResult
import edr_triage.pipeline as P
import edr_triage.store as store


def _cfg(**kw) -> EDRTriageConfig:
    return EDRTriageConfig(_env_file=None, **kw)


def _result(**kw) -> PlaybookResult:
    base = dict(
        triage_class="NEEDS_L2",
        action="user_confirmation",
        labels=["edr-triage-ai", "netskope-uba", "user-chase-pending"],
        chase_recipients=[{"raw": "a", "email": "a@example.com", "display_name": "A"}],
        chase_reason="Netskope bulk-download anomaly — deterministic rule",
    )
    base.update(kw)
    return PlaybookResult(**base)


# --- the phase guard treats user_confirmation as state-changing --------------

def test_user_confirmation_is_a_state_changing_action():
    assert "user_confirmation" in P.STATE_CHANGING_ACTIONS


def test_shadow_and_copilot_may_never_execute_it():
    for phase in ("shadow", "copilot"):
        assert P.may_change_ticket_state(phase, dry_run=False, test_labels_only=False) is (
            phase == "autonomous")


# --- _chase_dry_run_comment ----------------------------------------------------

def test_dry_run_comment_names_the_recipient_and_changes_nothing_visible():
    comment = P._chase_dry_run_comment(_result())
    assert "a@example.com" in comment
    assert "A" in comment
    assert "No Repsonse" in comment
    assert "unchanged" in comment.lower()
    assert "No Slack DM sent" in comment


# --- _execute_user_chase: idempotency ------------------------------------------

class _FakeChaseCol:
    """Stands in for the Mongo collection behind claim_user_chase/record_user_chase —
    a unique index on jira_key, enforced in-memory."""
    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.unavailable = False

    def create_index(self, *a, **k):
        pass

    def __bool__(self):
        return True

    def insert_one(self, doc):
        if self.unavailable:
            raise Exception("localhost:27017: [Errno 61] Connection refused")
        if doc["jira_key"] in self.docs:
            raise Exception("E11000 duplicate key error collection")
        self.docs[doc["jira_key"]] = dict(doc)

    def update_one(self, filt, update):
        key = filt["jira_key"]
        self.docs.setdefault(key, {}).update(update.get("$set", {}))


@pytest.fixture
def fake_chase_col(monkeypatch):
    col = _FakeChaseCol()
    monkeypatch.setattr(store, "_chase_col", lambda: col)

    async def _get_status(key, cfg=None):
        return "Assigned"
    monkeypatch.setattr("edr_triage.jira_handler.get_status", _get_status)
    return col


def test_claim_is_true_once_and_false_after(fake_chase_col):
    assert store.claim_user_chase("DEMO-1") is True
    assert store.claim_user_chase("DEMO-1") is False
    assert store.claim_user_chase("DEMO-2") is True


def test_a_second_execution_does_not_re_chase(monkeypatch, fake_chase_col):
    """Poller overlap or a forced re-triage must not send a second DM — DEMO-106747 got
    exactly this duplicate from the bot's own (unreliable) dedup."""
    calls = {"n": 0}
    async def _fake_get_cell(key, cfg=None):
        calls["n"] += 1
        return ""
    monkeypatch.setattr("edr_triage.jira_handler.get_involved_users_cell", _fake_get_cell)

    store.claim_user_chase("DEMO-1")   # simulate a prior run already owning this ticket
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "labels_only"
    assert calls["n"] == 0   # never even got to reading the cell


def test_no_chase_recipients_never_touches_jira(monkeypatch, fake_chase_col):
    async def _boom(*a, **k):
        raise AssertionError("must not call Jira with zero resolved recipients")
    monkeypatch.setattr("edr_triage.jira_handler.get_involved_users_cell", _boom)
    outcome = asyncio.run(P._execute_user_chase(
        "DEMO-1", _cfg(), _result(chase_recipients=[]), dry_run=False))
    assert outcome == "labels_only"


# --- _execute_user_chase: the 4-step sequence and its failure paths -----------

def _patch_chase_calls(monkeypatch, *, cell="", set_involved=True, set_cat=True,
                       to_event=True, to_awaiting=True, status="Assigned", to_assigned=True,
                       assign_ok=True):
    calls = []

    async def _get_status(key, cfg=None):
        return status

    async def _assign(key, cfg=None, dry_run=False):
        calls.append(("assign",))
        return assign_ok
    monkeypatch.setattr("edr_triage.jira_handler.get_status", _get_status)
    monkeypatch.setattr("edr_triage.jira_handler.assign_to_self_if_unassigned", _assign)

    async def _get_cell(key, cfg=None):
        calls.append(("get_cell",))
        return cell

    async def _set_involved(key, recipients, cfg=None, dry_run=False):
        calls.append(("set_involved", tuple(r["email"] for r in recipients)))
        return set_involved

    async def _set_category(key, value, cfg=None, dry_run=False):
        calls.append(("set_category", value))
        return set_cat

    async def _transition(key, target, cfg=None, dry_run=False):
        calls.append(("transition", target))
        if target == "Assigned":
            return to_assigned
        return to_event if target == cfg_event_target[0] else to_awaiting

    cfg_event_target = ["Event Analysis"]

    async def _add_comment(key, text, cfg=None, dry_run=False):
        calls.append(("comment", text))
        return True

    monkeypatch.setattr("edr_triage.jira_handler.get_involved_users_cell", _get_cell)
    monkeypatch.setattr("edr_triage.jira_handler.set_involved_users", _set_involved)
    monkeypatch.setattr("edr_triage.jira_handler.set_category", _set_category)
    monkeypatch.setattr("edr_triage.jira_handler.transition_to_status", _transition)
    monkeypatch.setattr("edr_triage.jira_handler.add_comment", _add_comment)
    return calls


def test_an_open_ticket_is_taken_and_moved_to_assigned_before_anything_is_written(
        monkeypatch, fake_chase_col):
    """DEMO-115957: from Open the workflow offers no Event Analysis transition, so every chase
    of an unassigned ticket aborted after writing Involved Users and Category."""
    calls = _patch_chase_calls(monkeypatch, status="Open")
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "user_chase_dispatched"
    assert [c[0] if c[0] != "transition" else c for c in calls][:3] == [
        "get_cell", "assign", ("transition", "Assigned")]


def test_failing_to_leave_open_writes_nothing(monkeypatch, fake_chase_col):
    for n, kw in enumerate(({"assign_ok": False}, {"to_assigned": False})):
        calls = _patch_chase_calls(monkeypatch, status="Open", **kw)
        result = _result()          # carries user-chase-pending, as the playbook sets it
        outcome = asyncio.run(P._execute_user_chase(f"DEMO-{10 + n}", _cfg(), result,
                                                    dry_run=False))
        assert outcome == "labels_only", kw
        assert not any(c[0] in ("set_involved", "set_category") for c in calls), kw
        assert "user-chase-pending" not in result.labels and "needs-l2-review" in result.labels


def test_a_ticket_a_person_has_moved_on_is_never_chased(monkeypatch, fake_chase_col):
    """DEMO-116167: retried after a pod restart, by which time an L1 had escalated it to L2
    Analysis required — the chase walked it back to Awaiting more inputs and DMed the user.
    From Awaiting more inputs it would re-fire the bot on an L1's own chase."""
    for n, status in enumerate(("L2 Analysis required", "Awaiting more inputs", "No Response",
                                "In Progress", "False Positive", "Duplicate", "")):
        calls = _patch_chase_calls(monkeypatch, status=status)
        result = _result()
        outcome = asyncio.run(P._execute_user_chase(f"DEMO-{20 + n}", _cfg(), result,
                                                    dry_run=False))
        assert outcome == "labels_only", status
        assert calls == [], status
        assert f"DEMO-{20 + n}" not in fake_chase_col.docs, status   # no claim recorded
        assert "user-chase-pending" not in result.labels, status
        assert "needs-l2-review" not in result.labels, status       # a person already has it


def test_event_analysis_is_still_chased(monkeypatch, fake_chase_col):
    _patch_chase_calls(monkeypatch, status="Event Analysis")
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "user_chase_dispatched"


def test_the_happy_path_runs_all_four_steps_in_order(monkeypatch, fake_chase_col):
    calls = _patch_chase_calls(monkeypatch)
    result = _result()
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), result, dry_run=False))
    assert outcome == "user_chase_dispatched"
    kinds = [c[0] for c in calls]
    assert kinds == ["get_cell", "set_involved", "set_category", "transition", "transition"]
    assert calls[1] == ("set_involved", ("a@example.com",))
    assert calls[2] == ("set_category", "No Repsonse")
    assert calls[3] == ("transition", "Event Analysis")
    assert calls[4] == ("transition", "Awaiting more inputs")
    assert fake_chase_col.docs["DEMO-1"]["recipients"] == ["a@example.com"]


def test_an_already_populated_cell_aborts_without_writing_anything(monkeypatch, fake_chase_col):
    calls = _patch_chase_calls(monkeypatch, cell="someone.else@example.com")
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "labels_only"
    assert [c[0] for c in calls] == ["get_cell", "comment"]


def test_an_already_populated_cell_escalates_to_l2(monkeypatch, fake_chase_col):
    _patch_chase_calls(monkeypatch, cell="someone.else@example.com")
    result = _result()
    asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), result, dry_run=False))
    assert "needs-l2-review" in result.labels


def test_no_involved_users_row_aborts_and_writes_nothing(monkeypatch, fake_chase_col):
    async def _get_cell(key, cfg=None):
        return None
    async def _boom(*a, **k):
        raise AssertionError("must not attempt a write once the row is known missing")
    monkeypatch.setattr("edr_triage.jira_handler.get_involved_users_cell", _get_cell)
    monkeypatch.setattr("edr_triage.jira_handler.set_involved_users", _boom)
    monkeypatch.setattr("edr_triage.jira_handler.add_comment",
                        lambda *a, **k: asyncio.sleep(0, result=True))
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "labels_only"


def test_a_failed_involved_users_write_stops_before_category(monkeypatch, fake_chase_col):
    calls = _patch_chase_calls(monkeypatch, set_involved=False)
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "labels_only"
    kinds = [c[0] for c in calls]
    assert "set_category" not in kinds
    assert "transition" not in kinds


def test_a_failed_category_write_stops_before_any_transition(monkeypatch, fake_chase_col):
    calls = _patch_chase_calls(monkeypatch, set_cat=False)
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "labels_only"
    assert "transition" not in [c[0] for c in calls]


def test_a_failed_event_analysis_transition_stops_before_awaiting_inputs(monkeypatch, fake_chase_col):
    calls = _patch_chase_calls(monkeypatch, to_event=False)
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "labels_only"
    transitions = [c[1] for c in calls if c[0] == "transition"]
    assert transitions == ["Event Analysis"]


def test_a_failed_final_hop_still_records_nothing_and_escalates(monkeypatch, fake_chase_col):
    calls = _patch_chase_calls(monkeypatch, to_awaiting=False)
    result = _result()
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), result, dry_run=False))
    assert outcome == "labels_only"
    assert "DEMO-1" not in fake_chase_col.docs or "recipients" not in fake_chase_col.docs.get("DEMO-1", {})
    assert "needs-l2-review" in result.labels


def test_dry_run_is_passed_through_to_every_write(monkeypatch, fake_chase_col):
    seen_dry_run = []
    async def _get_cell(key, cfg=None):
        return ""
    async def _set_involved(key, recipients, cfg=None, dry_run=False):
        seen_dry_run.append(dry_run)
        return True
    async def _set_category(key, value, cfg=None, dry_run=False):
        seen_dry_run.append(dry_run)
        return True
    async def _transition(key, target, cfg=None, dry_run=False):
        seen_dry_run.append(dry_run)
        return True
    async def _get_status(key, cfg=None):
        return "Assigned"
    monkeypatch.setattr("edr_triage.jira_handler.get_status", _get_status)
    monkeypatch.setattr("edr_triage.jira_handler.get_involved_users_cell", _get_cell)
    monkeypatch.setattr("edr_triage.jira_handler.set_involved_users", _set_involved)
    monkeypatch.setattr("edr_triage.jira_handler.set_category", _set_category)
    monkeypatch.setattr("edr_triage.jira_handler.transition_to_status", _transition)

    asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=True))
    assert seen_dry_run == [True, True, True, True]


# --- safety invariant: no model verdict can set action="user_confirmation" ---

def test_agent_verdicts_never_set_action_user_confirmation():
    """REQUEST_JUSTIFICATION and every other agent verdict must map to labels_only —
    the chase is deterministic-only. Read the source rather than trust a docstring:
    _build_playbook_result_from_agent must not contain this string anywhere."""
    import inspect
    src = inspect.getsource(P._build_playbook_result_from_agent)
    assert 'action="user_confirmation"' not in src
    assert "action = \"user_confirmation\"" not in src


# --- an unreachable claim store is an OUTAGE, not an already-chased ticket ----
#
# The 2026-09-17 live pilot's first run returned a quiet "labels_only" that read exactly
# like "already chased". The real cause was an unreachable Mongo. Both must stop the
# chase — a DM without a durable claim risks the duplicate the claim exists to prevent —
# but they must be DISTINGUISHABLE, or an outage hides as routine idempotency.

def test_an_unreachable_claim_store_raises_rather_than_reporting_a_duplicate(fake_chase_col):
    from edr_triage.store import ChaseClaimUnavailable, claim_user_chase
    fake_chase_col.unavailable = True
    with pytest.raises(ChaseClaimUnavailable):
        claim_user_chase("DEMO-1")


def test_a_genuine_duplicate_still_returns_false_not_an_exception(fake_chase_col):
    from edr_triage.store import claim_user_chase
    assert claim_user_chase("DEMO-1") is True
    assert claim_user_chase("DEMO-1") is False


def test_the_chase_fails_closed_when_the_claim_store_is_down(monkeypatch, fake_chase_col):
    """Fail CLOSED: no Jira writes at all, so no DM can go out unrecorded."""
    fake_chase_col.unavailable = True
    async def _boom(*a, **k):
        raise AssertionError("must not touch Jira when ownership is unknown")
    monkeypatch.setattr("edr_triage.jira_handler.get_involved_users_cell", _boom)
    outcome = asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    assert outcome == "labels_only"


def test_an_outage_is_logged_as_an_outage_not_as_already_chased(monkeypatch, fake_chase_col, caplog):
    import logging
    fake_chase_col.unavailable = True
    with caplog.at_level(logging.ERROR):
        asyncio.run(P._execute_user_chase("DEMO-1", _cfg(), _result(), dry_run=False))
    text = caplog.text.lower()
    assert "claim store unavailable" in text
    assert "infrastructure failure" in text
    assert "already claimed" not in text


# --- _execute_l2_route: an owner nobody can ask goes straight to L2 -----------

def _route(monkeypatch, *, status="Open", cell="", l2_ok=True, no_users_row_ok=False, **kw):
    calls = _patch_chase_calls(monkeypatch, status=status, cell=cell, **kw)

    async def _l2(key, target, cfg, dry_run=False):
        calls.append(("l2", target))
        return l2_ok
    import edr_triage.chase_reply_poller as CR
    monkeypatch.setattr(CR, "_transition_to", _l2)
    result = _result(labels=["needs-l2-review"])
    out = asyncio.run(P._execute_l2_route("DEMO-1", _cfg(), result, dry_run=False,
                                          no_users_row_ok=no_users_row_ok))
    return out, calls, result


def test_a_cyble_digest_with_no_involved_users_row_is_routed(monkeypatch, fake_chase_col):
    """Digests name no person and carry no Involved Users row — nobody for the bot to DM."""
    out, calls, _ = _route(monkeypatch, cell=None, no_users_row_ok=True)
    assert out == "routed_to_l2" and ("l2", "L2 Analysis required") in calls
    out, _, _ = _route(monkeypatch, cell="someone@example.com", no_users_row_ok=True)
    assert out == "labels_only"                        # a filled cell still stops it


def test_an_open_ticket_walks_the_l1_route_to_l2_without_writing_anything_for_the_bot(
        monkeypatch, fake_chase_col):
    out, calls, result = _route(monkeypatch)
    assert out == "routed_to_l2" and "raptor-routed-l2" in result.labels
    steps = [c for c in calls if c[0] != "comment"]
    assert steps == [("get_cell",), ("assign",), ("transition", "Assigned"),
                     ("transition", "Event Analysis"), ("transition", "Awaiting more inputs"),
                     ("l2", "L2 Analysis required")]
    assert not any(c[0] in ("set_involved", "set_category") for c in calls)
    assert "Nobody was messaged" in [c for c in calls if c[0] == "comment"][-1][1]


def test_from_event_analysis_it_skips_straight_to_awaiting(monkeypatch, fake_chase_col):
    out, calls, _ = _route(monkeypatch, status="Event Analysis")
    assert out == "routed_to_l2"
    assert [c[1] for c in calls if c[0] == "transition"] == ["Awaiting more inputs"]


def test_a_filled_or_unreadable_involved_users_cell_is_never_walked_past_the_bot(
        monkeypatch, fake_chase_col):
    """Entering Awaiting more inputs DMs whoever is in Involved Users."""
    for cell in ("someone@example.com", None):
        out, calls, _ = _route(monkeypatch, cell=cell)
        assert out == "labels_only", cell
        assert not any(c[0] in ("transition", "l2", "assign") for c in calls), cell


def test_a_ticket_a_person_moved_on_is_not_routed(monkeypatch, fake_chase_col):
    for status in ("L2 Analysis required", "Awaiting more inputs", "False Positive", "Duplicate"):
        out, calls, _ = _route(monkeypatch, status=status)
        assert out == "labels_only" and calls == [], status


def test_a_failed_hop_says_so_and_leaves_it_for_an_l1(monkeypatch, fake_chase_col):
    out, calls, result = _route(monkeypatch, l2_ok=False)
    assert out == "labels_only" and "raptor-routed-l2" not in result.labels
    assert "could not move this ticket to L2" in calls[-1][1]
    out, calls, _ = _route(monkeypatch, to_awaiting=False)
    assert out == "labels_only" and not any(c[0] == "l2" for c in calls)


def test_routing_to_l2_is_a_gated_state_change():
    assert "route_to_l2" in P.STATE_CHANGING_ACTIONS
