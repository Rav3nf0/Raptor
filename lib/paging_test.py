"""PagerDuty paging core: grouping, brake, night hold, lifecycle, trial mode, alert types."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import mongomock
import pytest

from lib import paging as P
from edr_triage import paging_rules as R

IST = P.IST
DAY = datetime(2026, 11, 2, 11, 0, tzinfo=IST).astimezone(timezone.utc)      # 11:00 IST
NIGHT = datetime(2026, 11, 2, 2, 30, tzinfo=IST).astimezone(timezone.utc)    # 02:30 IST


@pytest.fixture
def db(monkeypatch):
    d = mongomock.MongoClient().db
    monkeypatch.setattr(P, "_col", lambda name: d[name])
    monkeypatch.setenv("PAGERDUTY_MODE", "trial")
    monkeypatch.setenv("PAGERDUTY_PUSHES", "1")
    monkeypatch.delenv("EDR_PAGERDUTY_ROUTING_KEY", raising=False)
    return d


@pytest.fixture
def sent(monkeypatch):
    calls = []

    async def fake(action, key, title="", urgency="high", details=None, link=""):
        calls.append((action, key, urgency))
        return P.mode() == "live"
    monkeypatch.setattr(P, "_send", fake)
    return calls


def offer(member, ents, urgency="high", now=DAY, source="raptor"):
    return asyncio.run(P.offer(source, member, ents, urgency, f"title {member}", {}, "", "why", now=now))


def test_one_incident_per_host_dart_style(db, sent):
    assert offer("shadow:finding:1", ["host:publisher02", "story:s1"])["action"] == "page"
    for i in range(2, 61):                                   # 59 more TPs on the same story over hours
        r = offer(f"shadow:finding:{i}", ["story:s1", f"host:h{i % 3}"], now=DAY + timedelta(minutes=10 * i))
        assert r["action"] == "join"
    assert db.pd_incidents.count_documents({}) == 1
    assert len(db.pd_incidents.find_one()["members"]) == 60
    assert offer("shadow:finding:1", ["host:publisher02"])["action"] == "member"       # idempotent


def test_join_window_is_rolling_24h_from_last_activity(db, sent):
    offer("raptor:DEMO-1", ["host:a"])
    assert offer("raptor:DEMO-2", ["host:a"], now=DAY + timedelta(hours=20))["action"] == "join"
    assert offer("raptor:DEMO-3", ["host:a"], now=DAY + timedelta(hours=40))["action"] == "join"
    assert offer("raptor:DEMO-4", ["host:a"], now=DAY + timedelta(hours=70))["action"] == "page"


def test_brake_merges_the_fourth_page_in_an_hour_into_a_burst(db, sent):
    acts = [offer(f"raptor:DEMO-{i}", [f"host:h{i}"], now=DAY + timedelta(minutes=i))["action"] for i in range(6)]
    assert acts == ["page", "page", "page", "burst", "burst", "burst"]
    assert db.pd_incidents.count_documents({"burst": True}) == 1
    assert offer("raptor:DEMO-9", ["host:h9"], now=DAY + timedelta(minutes=70))["action"] == "page"


def test_night_push_is_held_until_nine_ist_but_a_phone_page_is_not(db, sent):
    assert offer("raptor:DEMO-1", ["host:a"], urgency="low", now=NIGHT)["action"] == "held"
    assert offer("raptor:DEMO-2", ["host:b"], urgency="high", now=NIGHT)["action"] == "page"
    assert asyncio.run(P.flush_held(NIGHT + timedelta(hours=1))) == 0
    nine = datetime(2026, 11, 2, 9, 0, tzinfo=IST).astimezone(timezone.utc)
    assert asyncio.run(P.flush_held(nine)) == 1
    assert db.pd_incidents.find_one({"members.id": "raptor:DEMO-1"})["sent"] is True


def test_a_phone_page_is_not_swallowed_by_an_open_push(db, sent):
    offer("shadow:early:1", ["host:a"], urgency="low")
    r = offer("shadow:finding:1", ["host:a"], urgency="high", now=DAY + timedelta(minutes=30))
    assert r["action"] == "page"
    assert db.pd_incidents.count_documents({"superseded_by": r["incident"]}) == 1


def test_lifecycle_ack_then_resolve_when_every_member_closed(db, sent, monkeypatch):
    monkeypatch.setenv("PAGERDUTY_MODE", "live")
    monkeypatch.setenv("EDR_PAGERDUTY_ROUTING_KEY", "k")
    inc = offer("raptor:DEMO-1", ["host:a"])["incident"]
    offer("raptor:DEMO-2", ["host:a"], now=DAY + timedelta(minutes=5))
    assert asyncio.run(P.acknowledge("raptor:DEMO-1"))
    assert db.pd_incidents.find_one()["status"] == "acknowledged"
    asyncio.run(P.close_member("raptor:DEMO-1"))
    assert db.pd_incidents.find_one()["status"] == "acknowledged"
    asyncio.run(P.close_member("raptor:DEMO-2"))
    assert db.pd_incidents.find_one()["status"] == "resolved"
    assert [c[0] for c in sent] == ["trigger", "trigger", "acknowledge", "resolve"] and sent[0][1] == inc
    assert not asyncio.run(P.close_member("raptor:DEMO-404"))                 # never paged: no-op


def test_trial_calls_nothing_and_off_records_nothing(db, monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: pytest.fail("trial must not call PagerDuty"))
    monkeypatch.setenv("EDR_PAGERDUTY_ROUTING_KEY", "k")
    assert offer("raptor:DEMO-1", ["host:a"])["action"] == "page"
    rep = P.report(14, now=DAY + timedelta(days=1))
    assert rep["mode"] == "trial" and rep["phone_pages"] == 1 and rep["recent"][0]["member"] == "raptor:DEMO-1"
    monkeypatch.setenv("PAGERDUTY_MODE", "off")
    assert offer("raptor:DEMO-2", ["host:b"])["action"] == "off"


def test_stale_digest_once_a_day(db, sent):
    offer("raptor:DEMO-1", ["host:a"])
    later = DAY + timedelta(hours=50)
    rows = P.stale(later)
    assert len(rows) == 1 and "open for more than 48h" in P.digest_text(rows, later)
    assert P.digest_due(later) and not P.digest_due(later + timedelta(hours=1))
    assert not P.digest_due(datetime(2026, 11, 5, 9, 0, tzinfo=IST).astimezone(timezone.utc))   # before 10:00


def test_type_key_and_first_occurrence_seeded_from_raptor_history(db):
    assert P.type_key("The EC2 instance i-0e70479780d1af6ff queried a drive-by source domain") == \
        P.type_key("The EC2 instance i-0fe93d7da005fd2ea queried a drive-by source domain")
    assert P.type_key("Found 23 alerts for stealer_logs across 2 entities") == \
        P.type_key("Found 4 alerts for stealer_logs across 3 entities")
    db.edr_triage_processed.insert_one({"alert_name": "Netskope DLP Alerts", "processed_at": DAY.timestamp() - 86400})
    assert not P.first_occurrence(P.type_key("Netskope DLP Alerts"), DAY)
    assert P.first_occurrence(P.type_key("Password spray attack against Microsoft Entra ID application"), DAY)
    assert not P.first_occurrence(P.type_key("Password spray attack against Microsoft Entra ID application"), DAY)
    assert P.first_occurrence(P.type_key("Password spray attack against Microsoft Entra ID application"),
                              DAY + timedelta(days=31))


@pytest.mark.parametrize("name,cls,action,rule,new,want", [
    ("Possible web shell file and post-exploitation activity", "NEEDS_L2", "labels_only", "", False, "high"),
    ("Suspicious behavior by Web server process", "NEEDS_L2", "routed_to_l2", "", False, "high"),
    ("Credentials for instance role ssm-ec2-role were used from an external IP address", "NEEDS_L2", "labels_only", "", False, "high"),
    ("Information stealing malware activity", "NEEDS_L2", "labels_only", "", False, "high"),
    ("anything at all", "URGENT", "labels_only", "", False, "high"),
    ("Possible web shell file", "AUTO_CLOSED_FP", "auto_closed", "", False, ""),
    ("Possible web shell file", "NEEDS_L2", "auto_duplicate", "", False, ""),
    ("Possible web shell file", "NEEDS_L2", "user_chase_dispatched", "", False, ""),
    ("Possible web shell file", "REQUEST_JUSTIFICATION", "labels_only", "", False, ""),
    ("Possible web shell file", "NEEDS_L2", "labels_only", "never", False, ""),
    ("Netskope DLP Alerts", "NEEDS_L2", "labels_only", "", False, ""),
    ("Changes made to AWS CloudTrail logs", "NEEDS_L2", "labels_only", "always", True, ""),
    ("[Cyble Intel][MDE HIT] Warlock Ransomware Uses SharePoint", "NEEDS_L2", "labels_only", "", True, ""),
    ("Found 208 alerts for stealer_logs across 3 entities", "NEEDS_L2", "labels_only", "", True, ""),
    ("CVE-2026-98432 - Linux kernel TCP UAF", "NEEDS_L2", "labels_only", "", True, ""),
    ("The EC2 instance i-0e70479780d1af6ff queried a drive-by source domain", "NEEDS_L2", "labels_only", "", True, ""),
    ("Unusual AWS IAM user creation request", "NEEDS_L2", "labels_only", "", True, "low"),
    ("Unusual AWS IAM user creation request", "NEEDS_L2", "labels_only", "always", False, "high"),
    ("Root Privilege Escalation", "NEEDS_L2", "labels_only", "", False, ""),
])
def test_raptor_rule(name, cls, action, rule, new, want):
    assert R.decide(name, cls, action, rule, new)[0] == want


def test_raptor_hook_pages_on_the_saved_verdict(db, sent):
    from types import SimpleNamespace as NS
    t = NS(jira_key="DEMO-117541", alert_name="Possible web shell file and post-exploitation activity",
           device_name="uat-atlas-pubsr.corp.example.com", user_name="", triage_class="NEEDS_L2", action_taken="labels_only",
           llm_reasoning="x")
    r = asyncio.run(R.maybe_page(t, "https://jira"))
    inc = db.pd_incidents.find_one({"_id": r["incident"]})
    assert r["action"] == "page" and inc["entities"] == ["host:uat-atlas-pubsr"]
    assert inc["title"].startswith("SecOps-DEMO-117541 Possible web shell") and inc["title"].endswith("| Tribe: SecOps")
    quiet = NS(**{**t.__dict__, "jira_key": "DEMO-2", "action_taken": "auto_closed"})
    assert asyncio.run(R.maybe_page(quiet, "https://jira"))["action"] == "none"


def test_pushes_are_off_by_default_and_only_logged(db, sent, monkeypatch):
    monkeypatch.delenv("PAGERDUTY_PUSHES")
    assert offer("raptor:DEMO-1", ["host:a"], urgency="low")["action"] == "push_skipped"
    assert offer("raptor:DEMO-1", ["host:a"], urgency="low")["action"] == "push_skipped"
    assert db.pd_incidents.count_documents({}) == 0 and sent == []
    assert P.report(14, now=DAY)["pushes_skipped"] == 1
    assert offer("raptor:DEMO-2", ["host:a"], urgency="high")["action"] == "page"


# ── 2026-11-05: MITRE tactics (observe), re-page after ack ─────────────────────

def test_tactics_from_ticket_line_category_and_technique_ids():
    assert R.tactics_of("Credential Access, Execution", "", []) == ["credentialaccess", "execution"]
    assert R.tactics_of("", "CommandAndControl", ["T1059.001", "T1567.002"]) == ["commandandcontrol", "exfiltration"]
    assert R.tactics_of("", "", None) == []


@pytest.mark.parametrize("tactics,want", [
    (["credentialaccess"], "high"), (["exfiltration", "execution"], "high"), (["execution"], ""), ([], "")])
def test_high_risk_tactic_qualifies_a_needs_l2_ticket_whatever_its_name(tactics, want):
    assert R.decide("Brand new CrowdStrike detection name", "NEEDS_L2", "labels_only", "", False, tactics)[0] == want
    assert R.decide("Brand new name", "NEEDS_L2", "auto_closed", "", False, tactics)[0] == ""      # closed: never
    assert R.decide("[Cyble Intel] x", "NEEDS_L2", "labels_only", "", False, tactics)[0] == ""     # never-list wins


def test_tactic_rule_only_observes_until_switched_live(db, sent, monkeypatch):
    from types import SimpleNamespace as NS
    t = NS(jira_key="DEMO-9", alert_name="Falcon: Credential theft attempt", device_name="srv-1", user_name="",
           triage_class="NEEDS_L2", action_taken="labels_only", llm_reasoning="", mitre_tactics=["credentialaccess"])
    monkeypatch.delenv("PAGERDUTY_TACTICS", raising=False)
    assert asyncio.run(R.maybe_page(t, "https://jira"))["action"] == "observed"
    assert db.pd_incidents.count_documents({}) == 0 and P.report(14)["observed"] == 1
    monkeypatch.setenv("PAGERDUTY_TACTICS", "live")
    assert asyncio.run(R.maybe_page(t, "https://jira"))["action"] == "page"


def test_a_new_kind_of_alert_pages_again_on_an_acknowledged_incident(db, sent):
    asyncio.run(P.offer("raptor", "raptor:DEMO-1", ["host:a"], "high", "t1", now=DAY, kind="raptor:privesc"))
    assert asyncio.run(P.acknowledge("raptor:DEMO-1"))
    same = asyncio.run(P.offer("raptor", "raptor:DEMO-2", ["host:a"], "high", "t2", now=DAY + timedelta(hours=1),
                               kind="raptor:privesc"))
    assert same["action"] == "join"                                    # same kind: stays quiet
    new = asyncio.run(P.offer("raptor", "raptor:DEMO-3", ["host:a"], "high", "t3", now=DAY + timedelta(hours=2),
                              kind="raptor:webshell"))
    assert new["action"] == "page" and db.pd_incidents.count_documents({}) == 2
    again = asyncio.run(P.offer("raptor", "raptor:DEMO-4", ["host:a"], "high", "t4", now=DAY + timedelta(hours=3),
                                kind="raptor:webshell"))
    assert again["action"] == "join" and again["incident"] == new["incident"]
    unacked = asyncio.run(P.offer("raptor", "raptor:DEMO-5", ["host:a"], "high", "t5", now=DAY + timedelta(hours=4),
                                  kind="raptor:lsass"))
    assert unacked["action"] == "join"                                 # not acknowledged: it is already ringing
