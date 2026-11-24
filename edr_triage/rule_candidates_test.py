"""Rule candidates: count what people did with each shape; a candidate needs min_n False
Positive verdicts and not one True Positive.

Run: python -m pytest edr_triage/rule_candidates_test.py -q
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from edr_triage import rule_candidates as R


def _r(n, family="fam a", human="FP", tier="L1", raptor="NEEDS_L2", device="", user="",
       raptor_closed=False):
    return {"key": f"DEMO-{n}", "family": family, "raptor": raptor, "device": device, "user": user,
            "raptor_closed": raptor_closed, "human": human, "tier": tier}


def _find(out, shape, value=""):
    return [c for c in out["candidates"] if c["shape"] == shape and c["value"] == value]


def test_twenty_of_twenty_is_a_candidate():
    out = R.mine([_r(n, tier="L2" if n < 8 else "L1") for n in range(20)], days=14)
    c = _find(out, "family")[0]
    assert (c["closed_fp"], c["closed_fp_by_l2"], c["closed_tp"], c["per_week"]) == (20, 8, 0, 10.0)
    assert len(c["examples"]) == 5


def test_one_true_positive_disqualifies_and_is_named():
    out = R.mine([_r(n) for n in range(40)] + [_r(99, human="TP")])
    assert not _find(out, "family")
    near = out["one_true_positive_in_a_long_run"]
    assert near and near[0]["tp_tickets"] == ["DEMO-99"]


def test_nineteen_is_not_enough_and_duplicates_are_not_verdicts():
    out = R.mine([_r(n) for n in range(19)] + [_r(100 + n, human="DUP") for n in range(30)])
    assert not out["candidates"]


def test_raptors_own_closes_are_not_counted():
    out = R.mine([_r(n, raptor_closed=True) for n in range(50)] + [_r(100 + n) for n in range(5)])
    assert not out["candidates"]


def test_a_narrower_shape_shows_only_when_its_family_fails():
    # The family has a True Positive; one host inside it is 25 of 25.
    rows = ([_r(n, device="HOST1.corp.example.com") for n in range(25)]
            + [_r(100, human="TP", device="host2")] + [_r(200 + n, device="host2") for n in range(3)])
    out = R.mine(rows)
    assert not _find(out, "family")
    assert _find(out, "family + host", "host1")[0]["closed_fp"] == 25
    # ...and when the family itself qualifies, its hosts are not repeated under it.
    clean = R.mine([_r(n, device="host1") for n in range(25)])
    assert _find(clean, "family") and not _find(clean, "family + host", "host1")


def test_shared_accounts_are_not_a_user_shape():
    out = R.mine([_r(n, user="administrator") for n in range(25)] + [_r(99, human="TP")])
    assert not [c for c in out["candidates"] if c["shape"] == "family + user"]


def test_a_shape_nobody_answers_is_listed_not_proposed():
    # 57 PowerShell tickets on one server, all still with L2 (2026-11-13).
    out = R.mine([_r(n, human="", device="prdacmtkdbtrn1.example.com") for n in range(57)])
    assert not out["candidates"]
    assert out["unanswered"][0]["value"] == "prdacmtkdbtrn1" and out["unanswered"][0]["still_open"] == 57


def test_recent_shows_what_a_rule_would_still_save():
    """Over 90 days "Log injestion stopped" is 46 of 46 — from before its rule shipped."""
    old, new = datetime(2026, 9, 1), datetime(2026, 11, 10)
    rows = ([{**_r(n), "created": old} for n in range(46)]
            + [{**_r(100 + n, raptor_closed=True), "created": new} for n in range(19)]
            + [{**_r(200 + n, family="fam b"), "created": new} for n in range(22)])
    out = R.mine(rows, recent_since=datetime(2026, 10, 14))
    by = {c["family"]: c for c in out["candidates"] if c["shape"] == "family"}
    assert by["fam a"]["recent"] == {"days": 30, "left_for_people": 0, "people_closed_fp": 0, "raptor_closed": 19}
    assert by["fam b"]["recent"]["people_closed_fp"] == 22
    assert [c["family"] for c in out["candidates"]] == ["fam b", "fam a"]      # what is still open first


def _shadow(**kw):
    base = dict(jira_key="DEMO-1", alert_name="Netskope - Failed Login involving one user",
                ai_triage_class="NEEDS_L2", pre_safety_class="AUTO_CLOSED_FP", device_name="H1",
                user_name="a@x.com", l2_triage_class=None, l2_resolved_at=None, l1_handoff_at=None,
                autonomous_closed_at=None, reopened_at=None, duplicate_at=None,
                created_at=datetime(2026, 11, 1))
    base.update(kw)
    return SimpleNamespace(**base)


T = datetime(2026, 11, 1)


def test_row_of_reads_a_human_verdict_and_who_gave_it():
    r = R.row_of(_shadow(l2_triage_class="AUTO_CLOSED_FP", l2_resolved_at=T, l1_handoff_at=T))
    assert (r["human"], r["tier"], r["raptor"], r["raptor_closed"]) == ("FP", "L2", "AUTO_CLOSED_FP", False)
    assert R.row_of(_shadow(l2_triage_class="AUTO_CLOSED_FP", l2_resolved_at=T))["tier"] == "L1"
    assert R.row_of(_shadow(l2_triage_class="AUTO_CLOSED_TP", l2_resolved_at=T))["human"] == "TP"
    assert R.row_of(_shadow())["human"] == ""


def test_row_of_never_takes_a_raptor_close_as_a_human_verdict():
    own = R.row_of(_shadow(l2_triage_class="AUTO_CLOSED_FP", l2_resolved_at=T, autonomous_closed_at=T))
    assert own["raptor_closed"] and own["human"] == ""
    reopened = R.row_of(_shadow(autonomous_closed_at=T, reopened_at=T))
    assert not reopened["raptor_closed"] and reopened["human"] == "TP"     # overturned: breaks any run
    dup = R.row_of(_shadow(duplicate_at=T))
    assert dup["human"] == "DUP"
