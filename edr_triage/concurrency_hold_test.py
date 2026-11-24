"""Root Privesc held behind an open sibling (edr_triage/concurrency_hold.py).

Run: python -m pytest edr_triage/concurrency_hold_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from edr_triage import concurrency_hold as CH

PRIVESC = "Root Privilege Escalation"


def _agent(**kw):
    base = dict(pre_safety_class="AUTO_CLOSED_FP", blocked_by_concurrent_keys=["DEMO-118007"],
                safety_block_reason="Concurrent open alerts: DEMO-118007.", confidence=0.95,
                triage_class="NEEDS_L2")
    base.update(kw)
    return SimpleNamespace(**base)


def test_the_sim_118277_shape_is_holdable():
    assert CH.holdable(_agent(), PRIVESC, "Medium", False, False) == (True, "")


@pytest.mark.parametrize("kw,args,bit", [
    ({}, ("Powershell script was loaded in memory", "Medium", False, False), "not Root"),
    ({"pre_safety_class": "NEEDS_L2"}, (PRIVESC, "Medium", False, False), "did not call it"),
    ({"pre_safety_class": "URGENT"}, (PRIVESC, "Medium", False, False), "did not call it"),
    ({"blocked_by_concurrent_keys": []}, (PRIVESC, "Medium", False, False), "not blocked"),
    ({"safety_block_reason": "Critical tool x returned an error"}, (PRIVESC, "Medium", False, False), "another gate"),
    ({}, (PRIVESC, "Critical", False, False), "CRITICAL"),
    ({}, (PRIVESC, "Medium", True, False), "test device"),
    ({}, (PRIVESC, "Medium", False, True), "ambiguous"),
])
def test_anything_else_is_not_held(kw, args, bit):
    ok, why = CH.holdable(_agent(**kw), *args)
    assert not ok and bit in why


def test_no_agent_verdict_is_not_held():
    assert CH.holdable(None, PRIVESC, "Medium", False, False)[0] is False


def test_the_comment_names_the_blocker_owner_and_every_outcome():
    t = CH.hold_comment(["DEMO-118007"], "Parker Jain")
    assert "DEMO-118007" in t and "Parker Jain" in t and "Nobody was messaged" in t
    assert "False Positive" in t and "L2 Analysis required" in t and f"{CH.HOLD_HOURS}h" in t


def test_the_hold_never_walks_through_awaiting_more_inputs(monkeypatch):
    seen = {}
    async def walk(key, route, cfg, forbidden=(), dry_run=False):
        seen["route"], seen["forbidden"] = route, forbidden
        return True
    async def owner(b, cfg): return "acc-1", "Parker Jain"
    async def ok(*a, **k): return True
    import edr_triage.jira_handler as JH
    monkeypatch.setattr(JH, "walk_to_status", walk)
    monkeypatch.setattr(JH, "assign_issue", ok)
    monkeypatch.setattr(JH, "add_labels", ok)
    monkeypatch.setattr(JH, "add_comment", ok)
    monkeypatch.setattr(CH, "blocker_owner", owner)
    monkeypatch.setattr(CH, "link_blocked_by", ok)
    cfg = SimpleNamespace(close_forbidden=lambda: ("Awaiting more inputs",))
    assert asyncio.run(CH.hold("DEMO-1", ["DEMO-118007"], cfg))
    assert seen["route"] == ["Assigned", "Event Analysis"]
    assert "Awaiting more inputs" in seen["forbidden"]


# ── the pipeline step ──────────────────────────────────────────────────────────────

def _run_step(monkeypatch, *, guard_allow=True, session_ok=True, may_hold=(True, ""),
              held_now=False, agent=None, may_close=(True, "")):
    import edr_triage.pipeline as P
    from edr_triage import privesc_guard as G
    calls = {"hold": 0, "release": []}
    async def check(*a, **k):
        return ({"allow": True, "reason": "", "precedents": [{"key": "DEMO-1"}]} if guard_allow
                else {"allow": False, "reason": "1 command(s) new", "new": ["x"]})
    async def sess(*a): return session_ok, "session from a familiar ip"
    async def mhn(*a): return may_hold
    async def hold(*a, **k):
        calls["hold"] += 1
        return True
    async def is_held(*a): return held_now
    async def release(key, why, cfg):
        calls["release"].append(why)
        return True
    async def brake(*a, **k): return False, ""
    monkeypatch.setattr(G, "check", check)
    monkeypatch.setattr(G, "session_check", sess)
    monkeypatch.setattr(CH, "may_hold_now", mhn)
    monkeypatch.setattr(CH, "hold", hold)
    monkeypatch.setattr(CH, "is_held", is_held)
    monkeypatch.setattr(CH, "release_to_l2", release)
    import edr_triage.autonomy_brake as AB
    monkeypatch.setattr(AB, "check", brake)
    cfg = SimpleNamespace(may_autoclose=lambda n, c: may_close, privesc_session_check=True)
    result = SimpleNamespace(labels=["needs-l2-review"], triage_class="NEEDS_L2")
    ag = agent or _agent()
    out = asyncio.run(P._maybe_hold_behind_sibling(
        "DEMO-118277", PRIVESC, cfg, result, False, "market-data-monitor-0101",
        "sage.kapoor@example.com", {"command_lines": ["sudo tcpdump -i ens5"]},
        {"cloudtrail": {"user_arn": "arn:aws:sts::0:assumed-role/r/sage.kapoor@example.com"}},
        {"severity": "Medium"}, {}, "u", False, ag))
    return out, calls, result


def test_every_check_passes_so_it_is_held(monkeypatch):
    out, calls, result = _run_step(monkeypatch)
    assert out == "held" and calls["hold"] == 1
    assert CH.HOLD_LABEL in result.labels and "needs-l2-review" not in result.labels


@pytest.mark.parametrize("kw", [
    {"guard_allow": False},                     # a command nobody cleared → the normal path
    {"session_ok": False},                      # unfamiliar session
    {"may_hold": (False, "Parker Jain has already picked this ticket up")},
    {"may_close": (False, "family not autonomous")},
])
def test_any_other_failed_check_is_not_held(monkeypatch, kw):
    out, calls, _ = _run_step(monkeypatch, **kw)
    assert out == "" and calls["hold"] == 0 and calls["release"] == []


def test_a_held_ticket_that_now_needs_a_person_goes_to_l2(monkeypatch):
    out, calls, _ = _run_step(monkeypatch, held_now=True, guard_allow=False)
    assert out == "routed_to_l2" and calls["release"] and "1 command(s) new" in calls["release"][0]


def test_a_held_ticket_blocked_by_another_gate_goes_to_l2(monkeypatch):
    out, calls, _ = _run_step(monkeypatch, held_now=True,
                              agent=_agent(safety_block_reason="Auto-close blocked: hunt errored"))
    assert out == "routed_to_l2" and calls["hold"] == 0


# ── release when the blocker closes ────────────────────────────────────────────────

def _retrigger(monkeypatch, final_class, held):
    import edr_triage.jira_closure_poller as JCP
    import entity_graph.models as M
    seen = {"released": [], "retriaged": []}
    class _Q:
        def __init__(self, rows): self.rows = rows
        async def to_list(self): return self.rows
    class _SR:
        blocked_by_concurrent_keys = None
        @staticmethod
        def find(*a, **k): return _Q([SimpleNamespace(jira_key="DEMO-118277")])
    monkeypatch.setattr(M, "ShadowResult", _SR)
    async def is_held(*a): return held
    async def release(key, why, cfg):
        seen["released"].append((key, why))
        return True
    monkeypatch.setattr(CH, "is_held", is_held)
    monkeypatch.setattr(CH, "release_to_l2", release)
    import edr_triage.store as ST
    def _col():
        seen["retriaged"].append("store-cleared")
        raise RuntimeError("stop before the real re-triage")
    monkeypatch.setattr(ST, "_col", _col)
    asyncio.run(JCP._retrigger_dependents("DEMO-118007", final_class))
    return seen


def test_blocker_closed_true_positive_sends_the_held_ticket_to_l2_not_the_model(monkeypatch):
    seen = _retrigger(monkeypatch, "AUTO_CLOSED_TP", held=True)
    assert seen["released"] and seen["released"][0][0] == "DEMO-118277" and seen["retriaged"] == []


def test_blocker_closed_false_positive_re_triages(monkeypatch):
    seen = _retrigger(monkeypatch, "AUTO_CLOSED_FP", held=True)
    assert seen["released"] == [] and seen["retriaged"] == ["store-cleared"]


def test_a_dependent_that_was_never_held_keeps_todays_behaviour(monkeypatch):
    seen = _retrigger(monkeypatch, "AUTO_CLOSED_TP", held=False)
    assert seen["released"] == [] and seen["retriaged"] == ["store-cleared"]


# ── the hold window ────────────────────────────────────────────────────────────────

def _expire(monkeypatch, held_at):
    import edr_triage.jira_handler as JH
    issue = {"key": "DEMO-118277", "fields": {"comment": {"comments": [
        {"created": held_at, "body": f"*{CH._MARKER}* behind DEMO-118007"}]}}}
    class _R:
        def raise_for_status(self): pass
        def json(self): return {"issues": [issue]}
    class _C:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _R()
    monkeypatch.setattr(JH, "_build_client", lambda cfg: _C())
    routed = []
    async def release(key, why, cfg):
        routed.append(key)
        return True
    monkeypatch.setattr(CH, "release_to_l2", release)
    n = asyncio.run(CH.expire_holds(SimpleNamespace(jira_project_key="SIM"),
                                    now=datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)))
    return n, routed


def test_a_hold_past_the_window_goes_to_l2(monkeypatch):
    assert _expire(monkeypatch, "2026-10-23T09:00:00.000+0000") == (1, ["DEMO-118277"])


def test_a_recent_hold_waits(monkeypatch):
    assert _expire(monkeypatch, "2026-10-24T08:00:00.000+0000") == (0, [])


def test_sibling_close_never_retriages_a_ticket_a_person_already_closed():
    """DEMO-120228: closed False Positive by L2 a minute before its sibling; the re-triage
    then asked the user on a closed ticket."""
    import inspect
    from edr_triage import jira_closure_poller as JCP
    src = inspect.getsource(JCP)
    assert "_CLOSED_FOR_RETRIAGE" in src and "comment,status" in src
    for s in ("FALSE POSITIVE", "DUPLICATE", "CLOSED", "RESOLVED"):
        assert s in JCP._CLOSED_FOR_RETRIAGE
    assert "L2 ANALYSIS REQUIRED" not in JCP._CLOSED_FOR_RETRIAGE   # held/routed tickets still re-triage
