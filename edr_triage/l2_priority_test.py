"""L2 queue order: flagged tickets first, each rank explained, nothing hidden.

Run: python -m pytest edr_triage/l2_priority_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from edr_triage import l2_priority as P

NOW = datetime(2026, 11, 13, 18, 0, tzinfo=timezone.utc)


def _t(key="DEMO-1", summary="Netskope DLP Alerts", labels=(), priority="Medium",
       created="2026-11-13T10:00:00.000+0530", tactics="", device="", user=""):
    return {"key": key, "summary": summary, "labels": list(labels), "priority": priority,
            "created": created, "tactics": tactics, "device": device, "user": user}


@pytest.mark.parametrize("labels,v", [
    (["raptor-rec-urgent"], "URGENT"), (["URGENT"], "URGENT"), (["urgent", "raptor-rec-l2"], "URGENT"),
    (["raptor-rec-tp"], "TP"), (["raptor-rec-l2", "needs-l2-review"], "L2"),
    (["raptor-rec-justify"], "ASK"), (["raptor-rec-duplicate"], "DUP"),
    (["raptor-rec-fp"], "FP"), (["ai-fp"], "FP"), (["raptor-rec-cyble-fp"], "FP"),
    (["needs-l2-review", "raptor-routed-l2"], "L2"), (["raptor-rec-cyble-review"], "L2"),
    (["raptor-rec-fp", "needs-l2-review"], "FP"), (["edr-triage-ai"], ""), ([], ""),
])
def test_verdict_from_labels(labels, v):
    assert P.verdict_of(labels) == v


def test_the_revshell_raptor_called_tp_is_first_in_class():
    # DEMO-119606 as it sat on 2026-11-13: High, RAPTOR True Positive, 15 days old.
    s = P.score(_t(summary="Suspicious 'SuspiciousPosixRevShell' behavior was blocked",
                   labels=["raptor-rec-tp"], priority="High",
                   created="2026-10-29T12:00:00.000+0530"), NOW)
    assert s["tier"] == "P1" and s["points"] == P.TP + P.HIGH_PRIORITY + P.ATTACK_TYPE + P.AGE_CAP
    assert any("True Positive" in r for r in s["reasons"])


@pytest.mark.parametrize("ticket,tier", [
    (_t(labels=["raptor-rec-urgent"]), "P1"),
    (_t(labels=["raptor-rec-tp"]), "P1"),
    (_t(summary="Malware incident", labels=["raptor-rec-l2"], priority="High"), "P1"),
    (_t(summary="macOS Gatekeeper bypass", labels=["raptor-rec-l2"]), "P1"),
    (_t(summary="Canary token was accessed", labels=["raptor-rec-l2"]), "P2"),
    (_t(summary="Password spray attack", labels=["raptor-rec-l2"], tactics='["CredentialAccess"]'), "P2"),
    (_t(labels=["raptor-rec-l2"]), "P3"),
    (_t(summary="Masqueraded task or service", tactics='["DefenseEvasion"]'), "P3"),   # no verdict
    (_t(labels=["raptor-rec-fp"]), "P4"),
    (_t(labels=["raptor-rec-justify", "raptor-chased"]), "P4"),
    (_t(labels=["raptor-rec-duplicate"]), "P4"),
])
def test_tiers(ticket, tier):
    assert P.score(ticket, NOW)["tier"] == tier


def test_age_orders_within_a_tier_but_never_lifts_one():
    old = P.score(_t(labels=["raptor-rec-fp"], created="2026-08-01T10:00:00.000+0530"), NOW)
    assert old["points"] == P.AGE_CAP and old["tier"] == "P4"
    old_l2 = P.score(_t(labels=["raptor-rec-l2"], created="2026-08-01T10:00:00.000+0530"), NOW)
    assert old_l2["tier"] == "P3"


def test_a_tactic_every_ticket_of_the_type_carries_earns_nothing():
    dlp = [_t(key=f"DEMO-{n}", labels=["raptor-rec-l2"], tactics='["Exfiltration"]') for n in range(12)]
    one = _t(key="DEMO-99", summary="Exfiltration incident involving one user",
             labels=["raptor-rec-l2"], tactics='["Exfiltration"]')
    assert P.flat_tactic_families(dlp + [one]) == {"netskope dlp alerts"}
    r = {t["key"]: t for t in P.rank(dlp + [one], NOW)}
    assert r["DEMO-0"]["tier"] == "P3" and r["DEMO-99"]["tier"] == "P2"
    assert r["DEMO-99"]["reasons"] and not any("MITRE" in x for x in r["DEMO-0"]["reasons"])


def test_a_small_family_keeps_its_tactic():
    few = [_t(key=f"DEMO-{n}", summary="Uninspected TLS destination used by almost nobody",
              labels=["raptor-rec-l2"], tactics='["CommandAndControl"]') for n in range(5)]
    assert P.flat_tactic_families(few) == set()
    assert all(t["tier"] == "P2" for t in P.rank(few, NOW))


def test_same_user_or_host_as_an_urgent_ticket():
    q = [_t(key="DEMO-10", summary="Privileged Accounts - Sign in Failure Spikes involving one user",
            labels=["raptor-rec-urgent"], user="theo.malik@example.com"),
         _t(key="DEMO-11", labels=["raptor-rec-fp"], user="theo.malik@example.com"),
         _t(key="DEMO-12", labels=["raptor-rec-fp"], user="someone.else@example.com"),
         _t(key="DEMO-13", labels=["raptor-rec-tp"], device="PC1.corp.example.com"),
         _t(key="DEMO-14", labels=["raptor-rec-fp"], device="pc1")]
    r = {t["key"]: t for t in P.rank(q, NOW)}
    assert any("DEMO-10" in x for x in r["DEMO-11"]["reasons"]) and r["DEMO-11"]["tier"] == "P2"
    assert any("DEMO-13" in x for x in r["DEMO-14"]["reasons"])
    assert r["DEMO-12"]["tier"] == "P4"
    assert not any("same user" in x for x in r["DEMO-10"]["reasons"])       # not hot because of itself


def test_a_shared_account_links_nothing():
    q = [_t(key="DEMO-20", labels=["raptor-rec-urgent"], user="administrator"),
         _t(key="DEMO-21", labels=["raptor-rec-fp"], user="administrator")]
    r = {t["key"]: t for t in P.rank(q, NOW)}
    assert r["DEMO-21"]["tier"] == "P4"


def test_known_repeats_drop_but_an_urgent_one_stays_on_top():
    rep = P.score(_t(summary="The EC2 instance i-0e70479780d1af6ff queried a drive-by source domain name.",
                     labels=["raptor-rec-l2"]), NOW)
    assert rep["points"] == P.RAPTOR_L2 + P.REPEAT
    urgent = P.score(_t(summary="The EC2 instance i-0fe93d7da005fd2ea queried a drive-by source domain name.",
                        labels=["raptor-rec-urgent"]), NOW)
    assert urgent["tier"] == "P1"


def test_rank_keeps_every_ticket_and_breaks_ties_oldest_first():
    q = [_t(key="DEMO-2", labels=["raptor-rec-l2"], created="2026-11-13T12:00:00.000+0530"),
         _t(key="DEMO-1", labels=["raptor-rec-l2"], created="2026-11-13T09:00:00.000+0530"),
         _t(key="DEMO-3", labels=["raptor-rec-tp"])]
    assert [t["key"] for t in P.rank(q, NOW)] == ["DEMO-3", "DEMO-1", "DEMO-2"]


def test_fetch_takes_no_host_from_the_description(monkeypatch):
    """DEMO-120184 and DEMO-120976: "Device Name" is a table header on intel tickets, and both
    read as host "Timestamp"."""
    import edr_triage.jira_poller as JP
    desc = "Alert Display Name\nSomething\nTactics\n[\"CredentialAccess\"]\nDevice Name\nTimestamp\n"
    issue = {"key": "DEMO-5", "fields": {"summary": "Something", "labels": ["raptor-rec-l2"],
                                        "priority": {"name": "High"}, "created": "2026-11-13T10:00:00.000+0530",
                                        "assignee": {"displayName": "L2"}, "description": desc}}

    class _C:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, timeout=None):
            class R:
                def raise_for_status(self):
                    pass

                def json(self):
                    return {"issues": [issue], "isLast": True}
            return R()
    monkeypatch.setattr(JP, "_build_client", lambda cfg: _C())

    async def none(tickets):
        return None
    monkeypatch.setattr(P, "_add_entities", none)
    got = asyncio.run(P.fetch_queue(SimpleNamespace(jira_project_key="SIM")))
    assert got[0]["device"] == "" and got[0]["tactics"] == '["CredentialAccess"]'
    assert got[0]["priority"] == "High"
