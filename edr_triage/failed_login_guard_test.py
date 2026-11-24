"""Netskope Failed Login: re-fires fold into the earlier ticket; a person-cleared exact
repeat closes False Positive. Everything else stays with L2.

Run: python -m pytest edr_triage/failed_login_guard_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import timedelta
from types import SimpleNamespace

import pytest

from edr_triage import failed_login_guard as G
from edr_triage import pipeline as P
from edr_triage.playbooks.netskope import NetskopePlaybook
from edr_triage.sentinel_client import _normalize_failed_login_row

ELENA = "v-elena.rossi@acme.net"


def _fl(user=ELENA, app="Seva Sindhu", ip="125.20.216.86", n=4,
        t0="2026-11-12T08:52:10.1234567Z", t1="2026-11-12T08:56:06.2477138Z", extra=()):
    rows = [{"user_s": user, "count_": n, "app_s": app, "srcip_s": ip,
             "device_classification_s": "unmanaged", "t0": t0, "t1": t1}, *extra]
    groups = [_normalize_failed_login_row(r) for r in rows]
    return {"users": sorted({g["user"] for g in groups}), "groups": groups,
            "group_count": len(groups),
            "total_failures": sum(g["failure_count"] for g in groups),
            "max_failures": max(g["failure_count"] for g in groups), "truncated": False}


def _comment(fl) -> str:
    """The comment RAPTOR's playbook actually posts for this bind."""
    r = asyncio.run(NetskopePlaybook().run("DEMO-1", {"alert_name": "Netskope - Failed Login"},
                                           {}, {}, [], sentinel_entities={"netskope_failed_login": fl}))
    return r.l1_comment


# --- scope ------------------------------------------------------------------

@pytest.mark.parametrize("name,ok", [
    ("Netskope - Failed Login", True),
    ("Netskope - Failed Login involving one user", True),
    ("Netskope - Failed Login involving multiple users", True),
    ("Netskope -Malware alert involving one user", False),
    ("Privileged Accounts - Sign in Failure Spikes involving one user", False),
])
def test_applies(name, ok):
    assert G.applies(name) is ok


def test_bind_carries_failure_times():
    g = _fl()["groups"][0]
    assert g["first_failure"].startswith("2026-11-12T08:52") and g["last_failure"]


# --- reading RAPTOR's own comment back ----------------------------------------

def test_parses_the_playbook_comment():
    p = G.parse_playbook_comment(_comment(_fl()))
    assert p == {"users": {ELENA}, "apps": {"seva sindhu"}, "ips": {"125.20.216.86"}, "total": 4}


def test_an_unresolved_line_is_not_a_record():
    assert G.parse_playbook_comment("failed-login *4 failed logins*\n*Users:* not resolved") is None
    assert G.parse_playbook_comment("RAPTOR Copilot — recommendation") is None


def test_shape_refuses_a_group_it_cannot_compare():
    assert G.shape(_fl(t1="")) is None
    assert G.shape(_fl(ip="")) is None
    assert G.shape({**_fl(), "truncated": True}) is None


# --- re-fire ------------------------------------------------------------------
# DEMO-121981 raised 2026-11-12 18:02 IST (12:32Z); 4 failures 08:52-08:56Z. Re-fired as
# DEMO-122017 (23:03 IST) with the same 4.

T_FIRST = G._ts("2026-11-12T18:02:04.000+0530")
T_REFIRE = G._ts("2026-11-12T23:03:04.735+0530")


def _rec(fl):
    return G.parse_playbook_comment(_comment(fl))


def test_the_sim_122017_refire_folds():
    assert G.is_refire_of(G.shape(_fl()), T_REFIRE, _rec(_fl()), T_FIRST)


@pytest.mark.parametrize("cur", [
    _fl(t1="2026-11-12T13:10:00Z"),                       # a failure after the first ticket
    _fl(t1="2026-11-12T12:00:00Z"),                       # inside the ingestion margin
    _fl(ip="27.107.210.250"),                             # another source
    _fl(app="Google Accounts"),                           # another app
    _fl(n=9),                                             # more failures than it reported
    _fl(extra=({"user_s": "someone@acme.net", "count_": 3, "app_s": "Seva Sindhu",
                "srcip_s": "125.20.216.86", "t0": "2026-11-12T08:00:00Z",
                "t1": "2026-11-12T08:01:00Z"},)),         # another user joined
])
def test_anything_new_is_not_a_refire(cur):
    assert not G.is_refire_of(G.shape(cur), T_REFIRE, _rec(_fl()), T_FIRST)


def test_too_old_an_original_is_not_a_refire():
    assert not G.is_refire_of(G.shape(_fl()), T_FIRST + timedelta(hours=25), _rec(_fl()), T_FIRST)


def test_failures_the_original_could_not_see_are_not_a_refire():
    early = _fl(t0="2026-11-11T09:00:00Z")    # before the first ticket's 24h lookback
    assert not G.is_refire_of(G.shape(early), T_REFIRE, _rec(_fl()), T_FIRST)


class _Client:
    def __init__(self, issues):
        self.issues = issues

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None):
        issues = self.issues

        class R:
            def raise_for_status(self):
                pass

            def json(self):
                return {"issues": issues, "isLast": True}
        return R()


def _adf(text):
    return {"type": "doc", "content": [{"type": "paragraph", "content": [
        {"type": "text", "text": line}]} for line in text.split("\n")]}


def _issue(key, created, status, fl, author="bot@x"):
    return {"key": key, "fields": {"summary": "Netskope - Failed Login", "created": created,
                                   "status": {"name": status},
                                   "comment": {"comments": [{"author": {"emailAddress": author},
                                                             "body": _adf(_comment(fl))}]}}}


def _find(monkeypatch, issues):
    import edr_triage.jira_handler as JH
    monkeypatch.setattr(JH, "_build_client", lambda cfg: _Client(issues))
    return asyncio.run(G.find_refire("DEMO-122017", "2026-11-12T23:03:04.735+0530", _fl(),
                                     SimpleNamespace(jira_project_key="SIM", jira_email="bot@x")))


def test_find_refire_names_the_earliest_live_ticket(monkeypatch):
    got = _find(monkeypatch, [_issue("DEMO-121981", "2026-11-12T18:02:04.000+0530",
                                     "L2 Analysis required", _fl())])
    assert got == {"key": "DEMO-121981", "status": "L2 Analysis required"}


@pytest.mark.parametrize("issue", [
    _issue("DEMO-121981", "2026-11-12T18:02:04.000+0530", "Duplicate", _fl()),       # folded itself
    _issue("DEMO-121981", "2026-11-12T18:02:04.000+0530", "L2 Analysis required", _fl(),
           author="analyst@x"),                                                     # not RAPTOR's record
    _issue("DEMO-121981", "2026-11-12T18:02:04.000+0530", "L2 Analysis required",
           _fl(ip="27.107.210.250")),                                               # other source
])
def test_find_refire_refuses(monkeypatch, issue):
    assert _find(monkeypatch, [issue]) is None


def test_find_refire_fails_closed(monkeypatch):
    import edr_triage.jira_handler as JH

    def boom(cfg):
        raise RuntimeError("jira down")
    monkeypatch.setattr(JH, "_build_client", boom)
    assert asyncio.run(G.find_refire("DEMO-1", "2026-11-12T23:03:04.735+0530", _fl(),
                                     SimpleNamespace(jira_project_key="SIM", jira_email="b"))) is None


# --- person-cleared exact repeat ----------------------------------------------

def _prec(ips=("125.20.216.86",), apps=("seva sindhu",), total=4, key="DEMO-116528"):
    return {"users": {ELENA}, "apps": set(apps), "ips": set(ips), "total": total, "key": key,
            "cleared_by": "noor.hassan@example.com", "cleared_at": "2026-10-11T12:00:00+00:00"}


def test_a_cleared_repeat_is_allowed():
    ok, why, used = G.precedent_decision(G.shape(_fl()), [_prec()])
    assert ok and [p["key"] for p in used] == ["DEMO-116528"]


def test_a_new_source_ip_is_not_covered():
    # Elena was cleared from 27.107.210.250 in October; her November tickets are from
    # 125.20.216.86. Same person, different source: not the same thing a person cleared.
    ok, why, _ = G.precedent_decision(G.shape(_fl()), [_prec(ips=("27.107.210.250",))])
    assert not ok and "125.20.216.86" in why


def test_more_than_twice_the_cleared_failures_is_not_a_repeat():
    ok, why, _ = G.precedent_decision(G.shape(_fl(n=60)), [_prec(total=23)])
    assert not ok and "60" in why
    assert G.precedent_decision(G.shape(_fl(n=9)), [_prec(total=3)])[0]   # floor of 10


def test_several_users_are_never_one_persons_repeat():
    two = _fl(extra=({"user_s": "x@acme.net", "count_": 3, "app_s": "Seva Sindhu",
                      "srcip_s": "125.20.216.86", "t0": "2026-11-12T08:00:00Z",
                      "t1": "2026-11-12T08:01:00Z"},))
    assert not G.precedent_decision(G.shape(two), [_prec()])[0]


# --- the pipeline hook ------------------------------------------------------------

def _close(monkeypatch, *, prec=(), others=(), success=False, triage="NEEDS_L2",
           phase="autonomous", status="Open", enabled=True, fl=None):
    import edr_triage.autonomy_brake as AB
    import edr_triage.jira_handler as JH
    import entity_graph.query as Q
    from edr_triage.config import EDRTriageConfig
    calls = {"walk": [], "comments": []}

    async def walk(key, route, cfg, forbidden=()):
        assert not {h.lower() for h in route} & {f.lower() for f in forbidden}
        calls["walk"].append(route)
        return True

    async def comment(key, text, cfg, dry_run=False):
        calls["comments"].append(text)

    async def get_status(key, cfg):
        return status

    async def owner(key, cfg=None):
        return ""

    async def brake(name, pattern=""):
        return (False, "")

    async def precedents(user, key, cfg):
        return list(prec)

    async def conc(**kw):
        return {"open_alert_details": list(others)}

    async def later(url, user, apps, since):
        return success
    monkeypatch.setattr(JH, "walk_to_status", walk)
    monkeypatch.setattr(JH, "add_comment", comment)
    monkeypatch.setattr(JH, "get_status", get_status)
    monkeypatch.setattr(JH, "owned_by_a_person", owner)
    monkeypatch.setattr(AB, "check", brake)
    monkeypatch.setattr(G, "cleared_precedents", precedents)
    monkeypatch.setattr(Q, "check_concurrent_alerts", conc)
    monkeypatch.setattr(G, "later_success", later)
    monkeypatch.setattr(P, "_resolve_agent_phase", lambda: phase)
    real = EDRTriageConfig()
    cfg = SimpleNamespace(failed_login_close_enabled=enabled, autoclose_report_enabled=True,
                          close_route=real.close_route, close_forbidden=real.close_forbidden)
    result = SimpleNamespace(labels=[], triage_class=triage)
    out = asyncio.run(P._maybe_close_failed_login(
        "DEMO-122017", "Netskope - Failed Login", {"created_at": "2026-11-12T23:03:04.735+0530",
                                                  "incident_url": "u"},
        {"netskope_failed_login": fl or _fl()}, result, cfg, False, False))
    return out, result.labels, calls


def test_hook_closes_a_cleared_repeat(monkeypatch):
    out, labels, calls = _close(monkeypatch, prec=[_prec()])
    assert out == "auto_closed" and calls["walk"][0][-1] == "False Positive"
    assert G.CLOSE_LABEL in labels and "DEMO-116528" in calls["comments"][0]


def test_hook_ignores_refires_of_itself_as_concurrent(monkeypatch):
    out, _, _ = _close(monkeypatch, prec=[_prec()],
                       others=[{"jira_key": "DEMO-121981", "alert_name": "Netskope - Failed Login"}])
    assert out == "auto_closed"


@pytest.mark.parametrize("kw", [
    {"prec": []},                                                              # nobody cleared it
    {"prec": [_prec()], "others": [{"jira_key": "DEMO-9", "alert_name": "Netskope DLP Alerts"}]},
    {"prec": [_prec()], "success": True},                                      # a login got through
    {"prec": [_prec()], "success": None},                                      # could not check
    {"prec": [_prec()], "triage": "URGENT"},
])
def test_hook_leaves_it_with_l2(monkeypatch, kw):
    out, labels, calls = _close(monkeypatch, **kw)
    assert out == "" and not calls["walk"] and not calls["comments"]


@pytest.mark.parametrize("kw", [{"phase": "copilot"}, {"enabled": False},
                                {"status": "L2 Analysis required"}])
def test_hook_gates_only_recommend(monkeypatch, kw):
    out, labels, calls = _close(monkeypatch, prec=[_prec()], **kw)
    assert out == "" and not calls["walk"] and G.REC_LABEL in labels


def test_refire_duplicate_runs_through_the_duplicate_step(monkeypatch):
    import edr_triage.autonomy_brake as AB
    import edr_triage.jira_handler as JH
    seen = {}

    async def find(key, created, fl, cfg):
        return {"key": "DEMO-121981", "status": "L2 Analysis required"}

    async def walk(key, route, cfg, forbidden=()):
        seen["route"] = route
        return True

    async def get_status(key, cfg):
        return "Open"

    async def owner(key, cfg=None):
        return ""

    async def brake(name, pattern=""):
        seen["brake"] = pattern
        return (False, "")
    monkeypatch.setattr(G, "find_refire", find)
    monkeypatch.setattr(JH, "walk_to_status", walk)
    monkeypatch.setattr(JH, "get_status", get_status)
    monkeypatch.setattr(JH, "owned_by_a_person", owner)
    monkeypatch.setattr(AB, "check", brake)
    monkeypatch.setattr(P, "_resolve_agent_phase", lambda: "autonomous")
    cfg = SimpleNamespace(auto_duplicate_enabled=True, autoclose_report_enabled=True)
    result = SimpleNamespace(labels=[], triage_class="NEEDS_L2")
    held: list = []
    out = asyncio.run(P._maybe_mark_duplicate(
        "DEMO-122017", "Netskope - Failed Login", {"created_at": "2026-11-12T23:03:04.735+0530"},
        {"netskope_failed_login": _fl()}, result, cfg, False, False, defer=held))
    assert out == "auto_duplicate" and seen["route"] == ["Duplicate"]
    assert seen["brake"] == G.BRAKE_PATTERN and "DEMO-121981" in held[0]
