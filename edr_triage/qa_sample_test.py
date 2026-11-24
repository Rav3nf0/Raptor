"""Random autonomous closes to L2 each day, and the answers counted."""
from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone
from types import SimpleNamespace

from edr_triage import qa_sample as Q


def _c(key, name, age=2, **kw):
    return {"jira_key": key, "alert_name": name, "age_hours": age, "reopened_at": None,
            "reviewed_at": None, "qa_sampled": False, **kw}


def test_one_per_family_before_any_family_repeats():
    closes = [_c(f"P{i}", "Root Privilege Escalation") for i in range(10)] + [
        _c("D1", "Netskope DLP Alerts"), _c("S1", "Network Port Sweep detected on 7680"),
        _c("S2", "Network Port Sweep detected on 443")]
    got = Q.pick(closes, 3, random.Random(1))
    assert len(got) == 3
    assert len({Q.family(c["alert_name"]) for c in got}) == 3     # 7680 and 443 are one family


def test_only_fresh_standing_unsampled_closes():
    closes = [_c("old", "A", age=30), _c("reopened", "B", reopened_at="x"),
              _c("reviewed", "C", reviewed_at="x"), _c("again", "D", qa_sampled=True),
              _c("ok", "E")]
    assert [c["jira_key"] for c in Q.pick(closes, 5)] == ["ok"]


def test_due_only_after_10_ist():
    assert Q.due(datetime(2026, 11, 9, 4, 0, tzinfo=timezone.utc)) == ""            # 09:30 IST
    assert Q.due(datetime(2026, 11, 9, 4, 31, tzinfo=timezone.utc)) == "2026-11-09"  # 10:01 IST


def test_error_rate_counts_answered_only():
    closes = [_c("a", "A", qa_sampled=True, reviewed_at="x"),
              _c("b", "A", qa_sampled=True, reopened_at="y"),
              _c("c", "B", qa_sampled=True), _c("d", "B")]
    s = Q.summary(closes)
    assert (s["right"], s["wrong"], s["pending"], s["sampled"]) == (1, 1, 1, 3)
    assert s["error_rate"] == 0.5
    assert Q.summary([])["error_rate"] is None          # nothing answered is not 0%


def _run(monkeypatch, claimed=True, n=3):
    import edr_triage.jira_handler as JH
    import edr_triage.store as S
    calls = []

    async def lab(k, l, cfg, dry_run=False):
        calls.append(("label", k, tuple(l))); return True

    async def com(k, t, cfg, dry_run=False):
        calls.append(("comment", k)); return True

    async def asg(k, a, cfg, dry_run=False):
        calls.append(("assign", k, a)); return True
    monkeypatch.setattr(JH, "add_labels", lab)
    monkeypatch.setattr(JH, "add_comment", com)
    monkeypatch.setattr(JH, "assign_issue", asg)
    monkeypatch.setattr(S, "claim_user_chase", lambda k: claimed)
    cfg = SimpleNamespace(qa_sample_per_day=n, l2_assignee_account_id="L2")
    closes = [_c("X1", "A"), _c("X2", "B"), _c("X3", "C"), _c("X4", "D")]
    asked = asyncio.run(Q.maybe_sample(closes, cfg,
                                       now=datetime(2026, 11, 9, 6, 0, tzinfo=timezone.utc)))
    return asked, calls


def test_asks_labels_and_assigns_to_l2(monkeypatch):
    asked, calls = _run(monkeypatch)
    assert len(asked) == 3
    for k in asked:
        assert ("label", k, (Q.SAMPLE_LABEL,)) in calls and ("assign", k, "L2") in calls


def test_once_a_day_across_pods(monkeypatch):
    asked, calls = _run(monkeypatch, claimed=False)
    assert asked == [] and calls == []


def test_zero_turns_it_off(monkeypatch):
    assert _run(monkeypatch, n=0) == ([], [])


def test_the_report_carries_the_sample_and_the_label():
    import inspect
    from edr_triage import autoclose_report as R
    assert '"qa_sample": qa_sample.summary(closes)' in inspect.getsource(R.poll_once)
    assert "qa_sample.maybe_sample(closes, cfg)" in inspect.getsource(R.poll_once)
    row = R._read_close({"key": "K", "fields": {"labels": [Q.SAMPLE_LABEL], "summary": "A"},
                         "changelog": {"histories": [{"created": "2026-11-09T10:00:00.000+0530",
                                                      "author": {"emailAddress": "bot@x"},
                                                      "items": [{"field": "status",
                                                                 "toString": "False Positive"}]}]}},
                        "bot@x")
    assert row["qa_sampled"] is True


def test_off_by_default_until_turned_on():
    from edr_triage.config import EDRTriageConfig
    assert EDRTriageConfig(_env_file=None).qa_sample_per_day == 0
