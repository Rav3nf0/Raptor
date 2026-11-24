"""Jira tickets for Claude-confirmed /shadow TPs (shadow_hunter/tickets.py): one per story or host,
later TPs as comments, joined to the PagerDuty incident so nothing pages twice.
Run: python -m pytest shadow_hunter/tickets_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import mongomock
import pytest

from lib import paging as P
from shadow_hunter import paging as SP
from shadow_hunter import tickets as T
from shadow_hunter.models import AuditLog, Finding, Story

NOW = datetime(2026, 11, 13, 6, 0, tzinfo=timezone.utc)
naive = lambda dt: dt.replace(tzinfo=None)                        # noqa: E731


@pytest.fixture
def pd(monkeypatch):
    d = mongomock.MongoClient().db
    monkeypatch.setattr(P, "_col", lambda name: d[name])
    monkeypatch.setenv("PAGERDUTY_MODE", "trial")
    monkeypatch.delenv("SHADOW_TICKETS", raising=False)
    return d


class Jira:
    def __init__(self):
        self.created, self.comments, self.n = [], [], 0

    async def create(self, summary, desc, priority):
        self.n += 1
        self.created.append((summary, desc, priority))
        return f"DEMO-{900 + self.n}"

    async def comment(self, key, text):
        self.comments.append((key, text))
        return True


def _f(**kw):
    base = dict(detector="upwind_threats", severity="high", device_name="publisher02",
                summary="A host is executing a command; token Bearer abcdefghijklmnop1234",
                ai_verdict="true_positive", ai_confidence=0.9, ai_by="claude-code-manual",
                ai_reasoning="webshell spawned sh", ai_evidence=["process tree", "edge requests"],
                ai_at=naive(NOW - timedelta(hours=1)), created_at=naive(NOW - timedelta(hours=2)))
    base.update(kw)
    return Finding(**base)


async def _db(name):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    await init_beanie(database=mm.AsyncMongoMockClient()[name], document_models=[Finding, Story, AuditLog])


def test_one_ticket_per_host_later_tps_comment_and_secrets_are_cleaned(pd, monkeypatch):
    j = Jira()
    monkeypatch.setattr(T, "_create", j.create)

    async def go():
        await _db("t1")
        fs = [_f(summary=f"cmd {i} Bearer abcdefghijklmnop1234") for i in range(3)]
        for f in fs:
            await f.insert()
        for f in fs:
            await T.ticket_for(f, None, now=NOW, comment=j.comment)
        assert (await T.ticket_for(fs[0], None, now=NOW, comment=j.comment))["action"] == "already"
    asyncio.run(go())
    assert len(j.created) == 1 and len(j.comments) == 2 and j.comments[0][0] == "DEMO-901"
    summary, desc, prio = j.created[0]
    assert summary.startswith("[/shadow] high upwind_threats on publisher02") and prio == "High"
    assert "abcdefghijklmnop1234" not in desc and "Claude-confirmed true positive" in desc


def test_run_pages_then_tickets_and_the_ticket_joins_the_incident(pd, monkeypatch):
    j = Jira()
    monkeypatch.setattr(T, "_create", j.create)
    monkeypatch.setattr(T, "add_comment", j.comment, raising=False)

    async def status(key):
        return "Open"
    monkeypatch.setattr(T, "sync_closed", lambda: asyncio.sleep(0, result=0))

    async def go():
        await _db("t2")
        await _f().insert()
        return await SP.run(now=NOW, early=False)
    out = asyncio.run(go())
    assert out["findings"] == 1 and out["tickets"]["created"] == 1
    inc = pd.pd_incidents.find_one()
    assert "raptor:DEMO-901" in [m["id"] for m in inc["members"]]
    # RAPTOR seeing the ticket later: already a member, so no second page
    from types import SimpleNamespace as NS
    from edr_triage import paging_rules as R
    t = NS(jira_key="DEMO-901", alert_name="[/shadow] high upwind_threats on publisher02: web shell", device_name="",
           user_name="", triage_class="URGENT", action_taken="labels_only", llm_reasoning="", mitre_tactics=[])
    assert asyncio.run(R.maybe_page(t, "https://jira"))["action"] == "member"
    assert pd.pd_incidents.count_documents({}) == 1


def test_story_gets_one_ticket_and_medium_story_tps_count(pd, monkeypatch):
    j = Jira()
    monkeypatch.setattr(T, "_create", j.create)
    monkeypatch.setattr(T, "sync_closed", lambda: asyncio.sleep(0, result=0))

    async def go():
        await _db("t3")
        a, b = _f(device_name="h1"), _f(device_name="h2", severity="medium")
        await a.insert()
        await b.insert()
        st = Story(title="2 hosts", severity="high", finding_ids=[a.id, b.id])
        await st.insert()
        for f in (a, b):
            f.story_id = st.id
            await f.save()
        T_comment = j.comment
        import shadow_hunter.tickets as TT
        orig = TT.ticket_for

        async def tf(f, st, now=None):
            return await orig(f, st, now=now, comment=T_comment)
        monkeypatch.setattr(TT, "ticket_for", tf)
        return await SP.run(now=NOW, early=False)
    out = asyncio.run(go())
    assert out["tickets"] == {"created": 1, "commented": 1, "failed": 0, "closed": 0}


def test_off_switch_and_closed_ticket_closes_its_incident_member(pd, monkeypatch):
    monkeypatch.setenv("SHADOW_TICKETS", "0")
    assert not T.enabled()
    pd.pd_incidents.insert_one({"_id": "inc1", "status": "open", "sent": False,
                                "members": [{"id": "raptor:DEMO-5", "closed": False}]})
    pd.shadow_tickets.insert_one({"_id": "DEMO-5", "status": "open", "findings": ["x"]})

    async def status(key):
        return "Closed"
    assert asyncio.run(T.sync_closed(status=status)) == 1
    assert pd.shadow_tickets.find_one()["status"] == "closed" and pd.pd_incidents.find_one()["status"] == "resolved"


def test_raptor_intake_skips_tickets_opened_by_shadow():
    import inspect
    from edr_triage import jira_poller
    assert '"deepintel-shadow"' in inspect.getsource(jira_poller.poll_new_mde_tickets)
