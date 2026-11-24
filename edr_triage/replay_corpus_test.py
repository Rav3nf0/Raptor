"""Replay corpus: what is stored, what is redacted, what is never dropped."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace as NS

from edr_triage import replay_corpus as rc

_NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)


def _doc(**kw):
    agent = NS(triage_class="AUTO_CLOSED_FP", confidence=0.95, iterations=3, error=None,
               pre_safety_class="AUTO_CLOSED_FP", blocked_by_safety=False,
               safety_block_reason="", safety_gate_kind="", reasoning="benign",
               tool_calls=[NS(name="hunt_process", args={"device": "h1"},
                              result={"rows": [{"ProcessCommandLine": "ls"}], "count": 1})])
    result = NS(triage_class="AUTO_CLOSED_FP", labels=["raptor-autoclosed"],
                l1_comment="c1", l2_comment="")
    parts = dict(jira_key="DEMO-1", alert_name="Network Port Sweep detected on 7680",
                 source="sentinel", playbook="port_sweep", ticket={"description": "d"},
                 alert_data={"alertCreationTime": _NOW}, evidence={"sha256": "ab"},
                 sentinel_entities={"accounts": ["a@x.in"]}, vt={},
                 agent_inputs={"evidence": {"k": 1}}, agent_result=agent, result=result,
                 action_taken="auto_closed")
    parts.update(kw)
    return rc.build(**parts)


def test_a_record_round_trips_the_inputs_and_the_full_tool_result():
    d = _doc()
    assert d["family"] == "network port sweep detected on #"
    assert rc.load(d["tool_calls"][0]["result"]) == {"rows": [{"ProcessCommandLine": "ls"}], "count": 1}
    assert rc.load(d["sentinel_entities"]) == {"accounts": ["a@x.in"]}
    assert rc.load(d["alert_data"])["alertCreationTime"].startswith("2026-11-12")   # datetimes survive as text
    assert d["outcome"]["action_taken"] == "auto_closed" and d["agent"]["confidence"] == 0.95


def test_a_ticket_the_agent_never_saw_is_still_recorded():
    d = _doc(agent_result=None, agent_inputs={})
    assert d["agent"] is None and d["tool_calls"] == []


def test_account_ids_are_masked_and_the_record_still_parses():
    acct = "1234" + "5678" + "9012"
    d = _doc(evidence={"arn": f"arn:aws:iam::{acct}:role/x", "note": 'password="hunter2" then "more"'})
    assert acct not in d["evidence"]
    assert isinstance(rc.load(d["evidence"]), dict)


def test_an_oversized_result_is_cut_and_says_so():
    big = NS(name="hunt_file", args={}, result={"rows": ["x" * 100] * 2000})
    d = _doc(agent_result=NS(tool_calls=[big], reasoning=""))
    got = rc.load(d["tool_calls"][0]["result"])
    assert got["_truncated"] is True and got["chars"] > rc.MAX_BLOB


def _sr(**kw):
    base = dict(l2_triage_class=None, l2_resolved_at=None, reopened_at=None,
                l1_handoff_at=None, autonomous_closed_at=None, l1_awaiting_inputs_at=None)
    base.update(kw)
    return NS(**base)


def test_an_l1_false_positive_is_labelled_but_droppable():
    f = rc.verdict_fields(_sr(l2_triage_class="AUTO_CLOSED_FP", l2_resolved_at=_NOW))
    assert f["labelled"] and not f["keep"] and f["human_outcome"] == "L1: False Positive"


def test_a_raptor_close_nobody_reviewed_is_not_a_human_verdict():
    f = rc.verdict_fields(_sr(l2_triage_class="AUTO_CLOSED_FP", l2_resolved_at=_NOW,
                              autonomous_closed_at=_NOW))
    assert not f["labelled"] and not f["keep"]


def test_true_positives_l2_tickets_and_reopens_are_kept():
    assert rc.verdict_fields(_sr(l2_triage_class="AUTO_CLOSED_TP", l2_resolved_at=_NOW))["keep"]
    assert rc.verdict_fields(_sr(l1_handoff_at=_NOW))["keep"]                 # with L2, unresolved
    f = rc.verdict_fields(_sr(autonomous_closed_at=_NOW, reopened_at=_NOW))
    assert f["keep"] and f["labelled"]
    assert rc.verdict_fields(_sr(autonomous_closed_at=_NOW, l2_triage_class="AUTO_CLOSED_TP",
                                 l2_resolved_at=_NOW))["labelled"]


def test_the_cap_drops_only_old_settled_false_positives():
    rows = [{"jira_key": "old-fp", "labelled": True, "keep": False, "recorded_at": 1},
            {"jira_key": "old-tp", "labelled": True, "keep": True, "recorded_at": 2},
            {"jira_key": "pending", "labelled": False, "keep": False, "recorded_at": 3},
            {"jira_key": "new-fp", "labelled": True, "keep": False, "recorded_at": 4}]
    assert rc.droppable(rows, 4) == []
    assert rc.droppable(rows, 3) == ["old-fp"]
    assert rc.droppable(rows, 0) == ["old-fp", "new-fp"]      # kept and pending never go


def test_capture_is_off_on_a_dry_run_and_when_disabled(monkeypatch):
    seen = []
    monkeypatch.setattr(rc, "record", lambda d: seen.append(d) or False)
    asyncio.run(rc.capture(NS(replay_corpus_per_family=150), True, jira_key="DEMO-1"))
    asyncio.run(rc.capture(NS(replay_corpus_per_family=0), False, jira_key="DEMO-1"))
    assert seen == []


def test_capture_never_raises(monkeypatch):
    monkeypatch.setattr(rc, "build", lambda **k: 1 / 0)
    asyncio.run(rc.capture(NS(replay_corpus_per_family=150), False, jira_key="DEMO-1"))
