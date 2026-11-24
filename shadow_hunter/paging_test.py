"""Which /shadow findings and stories page (shadow_hunter/paging.py), on lib/paging's trial mode.
Run: python -m pytest shadow_hunter/paging_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import mongomock
import pytest

from lib import paging as P
from shadow_hunter import paging as SP
from shadow_hunter.models import AuditLog, Finding, Story

NOW = datetime(2026, 10, 19, 6, 0, tzinfo=timezone.utc)          # 11:30 IST
naive = lambda dt: dt.replace(tzinfo=None)                       # noqa: E731


@pytest.fixture
def pd(monkeypatch):
    d = mongomock.MongoClient().db
    monkeypatch.setattr(P, "_col", lambda name: d[name])
    monkeypatch.setenv("PAGERDUTY_MODE", "trial")
    monkeypatch.setenv("PAGERDUTY_PUSHES", "1")
    return d


def _f(**kw):
    base = dict(detector="upwind_threats", severity="high", device_name="publisher02",
                summary="A host is executing a command", ai_verdict="true_positive", ai_confidence=0.9,
                ai_by="claude-code-manual", ai_at=naive(NOW - timedelta(hours=1)),
                created_at=naive(NOW - timedelta(hours=2)))
    base.update(kw)
    return Finding(**base)


def _go(name, setup, runs=1, early=False):
    async def go():
        mm = pytest.importorskip("mongomock_motor")
        from beanie import init_beanie
        await init_beanie(database=mm.AsyncMongoMockClient()[name], document_models=[Finding, Story, AuditLog])
        ctx = await setup()
        outs = [await SP.run(now=NOW + timedelta(minutes=15 * i), early=early) for i in range(runs)]
        return ctx, outs
    return asyncio.run(go())


def test_claude_tp_pages_once_and_more_tps_on_the_host_fold_in(pd):
    async def setup():
        for i in range(5):
            await _f(summary=f"command {i}").insert()
    _, outs = _go("sp1", setup, runs=2)
    assert outs[0]["findings"] == 5 and outs[1]["findings"] == 0
    assert pd.pd_incidents.count_documents({}) == 1
    assert [e["action"] for e in pd.pd_events.find()] == ["page", "join", "join", "join", "join"]


def test_what_never_pages(pd):
    async def setup():
        await _f(device_name="a", ai_by="ai:mistral.large").insert()                      # not Claude
        await _f(device_name="b", ai_confidence=0.7).insert()                              # below 0.8
        await _f(device_name="c", severity="medium").insert()                              # not high/critical
        await _f(device_name="d", decision="true_positive", reviewed_at=naive(NOW - timedelta(hours=3))).insert()  # person first
        await _f(device_name="e", ai_at=naive(NOW - timedelta(hours=30))).insert()         # old verdict
        await _f(device_name="f", decision="false_positive", reviewed_at=naive(NOW)).insert()
    _go("sp2", setup)
    assert pd.pd_incidents.count_documents({}) == 0


def test_manual_claude_pass_on_an_unsure_finding_pages(pd):
    async def setup():
        await _f(device_name="g", created_at=naive(NOW - timedelta(days=4))).insert()     # old finding, fresh verdict
    _go("sp3", setup)
    assert pd.pd_incidents.count_documents({}) == 1


def test_story_joins_the_incident_its_findings_opened(pd):
    async def setup():
        f1 = _f(device_name="publisher02")
        await f1.insert()
        f2 = _f(device_name="iatlas-publisher01", severity="medium")
        await f2.insert()
        st = Story(title="iatlas-publisher01 · Upwind", severity="high", finding_ids=[f1.id, f2.id])
        await st.insert()
        return st
    st, outs = _go("sp4", setup)
    assert outs[0]["stories"] == 1 and pd.pd_incidents.count_documents({}) == 1
    inc = pd.pd_incidents.find_one()
    assert f"shadow:story:{st.id}" in [m["id"] for m in inc["members"]] and f"story:{st.id.lower()}" in inc["entities"]


def test_a_person_tp_acknowledges_and_fp_closes(pd):
    async def setup():
        f = _f()
        await f.insert()
        return f

    async def go():
        mm = pytest.importorskip("mongomock_motor")
        from beanie import init_beanie
        await init_beanie(database=mm.AsyncMongoMockClient()["sp5"], document_models=[Finding, Story, AuditLog])
        f = await setup()
        await SP.run(now=NOW, early=False)
        f.decision, f.reviewed_at = "true_positive", naive(NOW + timedelta(minutes=20))
        await f.save()
        await SP.on_decision(f)
        return pd.pd_incidents.find_one()
    inc = asyncio.run(go())
    assert inc["status"] == "resolved" and inc.get("acked_at")                   # loose finding: TP is its close


def test_story_member_closes_with_the_story(pd):
    async def go():
        mm = pytest.importorskip("mongomock_motor")
        from beanie import init_beanie
        await init_beanie(database=mm.AsyncMongoMockClient()["sp6"], document_models=[Finding, Story, AuditLog])
        f = _f()
        await f.insert()
        st = Story(title="t", severity="high", finding_ids=[f.id])
        await st.insert()
        f.story_id = st.id
        await f.save()
        await SP.run(now=NOW, early=False)
        f.decision, f.reviewed_at = "true_positive", naive(NOW)
        await f.save()
        await SP.run(now=NOW + timedelta(minutes=15), early=False)
        mid = pd.pd_incidents.find_one()["status"]
        st.status = "closed"
        await st.save()
        await SP.run(now=NOW + timedelta(minutes=30), early=False)
        return mid, pd.pd_incidents.find_one()["status"]
    assert asyncio.run(go()) == ("acknowledged", "resolved")


def test_early_push_before_claude_review_is_on(pd):
    async def setup():
        await _f(detector="ssh_backdoor", severity="medium", ai_verdict="", ai_by="", ai_at=None, device_name="mac1").insert()
        await _f(detector="edge_attacks", severity="medium", ai_verdict="false_positive", ai_by="", ai_at=None).insert()
        await _f(detector="rare_persistence", severity="high", ai_verdict="", ai_by="", ai_at=None).insert()
    _, outs = _go("sp7", setup, early=True)
    assert outs[0]["early"] == 1
    assert pd.pd_incidents.find_one()["urgency"] == "low"


def test_missed_lists_confirmed_tps_that_never_paged_with_the_reason(pd, monkeypatch):
    import edr_triage.store as store
    from entity_graph.models import ShadowResult
    recs = {"DEMO-1": {"alert_name": "Root Privilege Escalation", "triage_class": "NEEDS_L2",
                      "action_taken": "labels_only", "mitre_tactics": []},
            "DEMO-2": {"alert_name": "Possible web shell file", "triage_class": "NEEDS_L2",
                      "action_taken": "labels_only", "mitre_tactics": []}}
    monkeypatch.setattr(store, "get_alert_by_jira_key", lambda k: recs.get(k))
    pd.pd_events.insert_one({"at": NOW - timedelta(days=3), "action": "page"})

    async def go():
        mm = pytest.importorskip("mongomock_motor")
        from beanie import init_beanie
        await init_beanie(database=mm.AsyncMongoMockClient()["sp8"],
                          document_models=[Finding, Story, AuditLog, ShadowResult])
        for k in ("DEMO-1", "DEMO-2", "DEMO-3"):
            await ShadowResult(jira_key=k, alert_id=k, alert_name="x", ai_triage_class="NEEDS_L2", ai_confidence=0.5, l2_triage_class="AUTO_CLOSED_TP",
                               l2_resolved_at=naive(NOW - timedelta(days=1))).insert()
        await ShadowResult(jira_key="DEMO-0", alert_id="0", alert_name="x", ai_triage_class="NEEDS_L2", ai_confidence=0.5, l2_triage_class="AUTO_CLOSED_TP",
                           l2_resolved_at=naive(NOW - timedelta(days=5))).insert()          # before paging existed
        await P.offer("raptor", "raptor:DEMO-3", ["host:z"], "high", "t", now=NOW)           # this one paged
        await _f(device_name="m1", severity="medium", decision="true_positive", ai_verdict="", ai_by="",
                 reviewed_at=naive(NOW - timedelta(hours=5))).insert()
        return await SP.missed(7, now=NOW)
    rep = asyncio.run(go())
    by = {r["jira_key"]: r["reason"] for r in rep["raptor"]}
    assert set(by) == {"DEMO-1", "DEMO-2"}
    assert "not on the paging list" in by["DEMO-1"] and "no page was recorded" in by["DEMO-2"]
    assert rep["shadow"][0]["reason"].startswith("severity medium")
    assert "did not page" in SP.missed_text(rep)
