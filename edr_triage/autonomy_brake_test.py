"""The automatic brake and the L2 review marker.

Run: python -m pytest edr_triage/autonomy_brake_test.py -q
"""
from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timedelta, timezone

from edr_triage import autonomy_brake as B
from edr_triage import autoclose_report as R

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _closes(n, reopened=()):
    return [{"jira_key": f"DEMO-{i}", "closed_at": T0 + timedelta(hours=n - i),
             "reopened_at": (T0 + timedelta(days=1)) if i in reopened else None} for i in range(n)]


def test_a_clean_family_is_not_braked():
    assert B.decide(_closes(30), None) == (False, "")


def test_one_reopen_in_the_last_twenty_brakes_it():
    braked, why = B.decide(_closes(30, reopened={3}), None)
    assert braked and "DEMO-3" in why and "of this family's last 20" in why


def test_an_overturn_older_than_the_window_no_longer_counts():
    assert B.decide(_closes(30, reopened={25}), None)[0] is False


def test_rearm_ignores_closes_before_it():
    closes = _closes(5, reopened={4})                    # the oldest close was overturned
    rearm = closes[3]["closed_at"]                       # re-armed after it
    assert B.decide(closes, rearm)[0] is False
    assert B.decide(closes, None)[0] is True


def test_root_privesc_is_rearmed_at_the_repeat_or_ask_switch(monkeypatch):
    monkeypatch.delenv("EDR_BRAKE_REARM", raising=False)
    assert B.rearm_times()["root privilege escalation"] == datetime(2026, 10, 5, 8, 6, tzinfo=timezone.utc)
    monkeypatch.setenv("EDR_BRAKE_REARM", "Network Port Sweep detected on 3389=2026-10-06T00:00:00Z, bad")
    r = B.rearm_times()
    assert r["network port sweep detected on 3389"] == datetime(2026, 10, 6, tzinfo=timezone.utc)
    assert "root privilege escalation" in r


def test_an_unreadable_history_fails_closed(monkeypatch):
    class Boom:
        @staticmethod
        def find(*a, **k):
            raise RuntimeError("mongo down")
    import entity_graph.models as models
    monkeypatch.setattr(models, "ShadowResult", Boom)
    braked, why = asyncio.run(B.check("Network Port Sweep detected on 3389"))
    assert braked and "could not be read" in why
    assert asyncio.run(B.check(""))[0] is True


def test_the_brake_runs_first_at_the_close_gate():
    from edr_triage import pipeline as P
    src = inspect.getsource(P._process_ticket)
    gate = src.index("_may, _why = cfg.may_autoclose(alert_name, result.confidence)")
    brake = src.index("autonomy_brake.enforce_at_close(", gate)
    spray = src.index("signin_guard.enforce_at_close(", gate)
    assert gate < brake < spray
    assert "if _blocked:\n                    _may, _why = False, _block_why" in src[brake:brake + 300]


# ---- the review marker ----

BOT = "purple.phantom@example.com"


def _issue(hist):
    return {"key": "DEMO-1", "fields": {"summary": "x", "status": {"name": "False Positive"}, "labels": []},
            "changelog": {"histories": hist}}


def _h(t, who, field, frm, to):
    return {"created": t, "author": {"emailAddress": who, "displayName": who.split("@")[0]},
            "items": [{"field": field, "fromString": frm, "toString": to}]}


CLOSE = _h("2026-10-01T10:00:00.000+0530", BOT, "status", "Event Analysis", "False Positive")


def test_a_human_review_label_marks_the_close_reviewed():
    row = R._read_close(_issue([CLOSE, _h("2026-10-01T12:00:00.000+0530", "parker.jain@example.com",
                                         "labels", "ai-fp", "ai-fp raptor-reviewed")]), BOT)
    assert row["reviewed_by"] == "parker.jain" and row["reviewed_at"].startswith("2026-10-01T12")


def test_the_label_added_by_raptor_or_before_the_close_does_not_count():
    early = _h("2026-10-01T09:00:00.000+0530", "parker.jain@example.com", "labels", "", "raptor-reviewed")
    by_bot = _h("2026-10-01T12:00:00.000+0530", BOT, "labels", "", "raptor-reviewed")
    assert R._read_close(_issue([early, CLOSE, by_bot]), BOT)["reviewed_at"] is None


def test_reviewed_closes_are_not_counted_as_unreviewed():
    src = inspect.getsource(R.poll_once)
    assert 'unreviewed = [c for c in standing if not c.get("reviewed_at")' in src
    assert '"reviewed": len(reviewed)' in src


def test_closes_recorded_outside_shadow_results_count(monkeypatch):
    """Playbook-only families (Cyble) have no ShadowResult; their reopens must still brake."""
    from datetime import datetime, timezone

    class _Q:
        def __init__(self, rows): self.rows = rows
        def sort(self, *a): return self
        def limit(self, *a): return self
        async def to_list(self): return self.rows
        def __iter__(self): return iter(self.rows)

    class _SR:
        autonomous_closed_at = 0
        @staticmethod
        def find(*a, **k): return _Q([])

    class _Col:
        def find(self, q):
            return _Q([{"jira_key": "DEMO-9", "closed_at": datetime(2026, 10, 6, tzinfo=timezone.utc),
                        "reopened_at": datetime(2026, 10, 6, 1, tzinfo=timezone.utc)}])
    import entity_graph.models as EM
    import lib.mongo as BM
    monkeypatch.setattr(EM, "ShadowResult", _SR)
    monkeypatch.setattr(BM, "get_col", lambda name: _Col())
    braked, why = asyncio.run(B.check("Found 3 alerts for x across 1 entities", pattern=r"^Found"))
    assert braked and "DEMO-9" in why


def test_dlp_is_rearmed_after_the_sim_115961_misattributed_reopen():
    t = B.rearm_times()["netskope dlp alerts"]
    reopen = datetime(2026, 10, 6, 17, 47, tzinfo=timezone.utc)
    closes = [{"jira_key": "DEMO-115961", "closed_at": datetime(2026, 10, 6, 17, 45, tzinfo=timezone.utc),
               "reopened_at": reopen}]
    assert t > reopen and B.decide(closes, t)[0] is False


