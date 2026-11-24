"""Exact-repeat DLP duplicates: the matcher, the gates in front of the transition, and the
autoclose report treating a bot Duplicate as a close.

Run: python -m pytest edr_triage/duplicate_guard_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from edr_triage import duplicate_guard as D
from edr_triage import pipeline as P
from edr_triage.autoclose_report import _read_close

EV = {"user": "a.b@example.com", "dlp_file": "Report.xlsx", "dlp_rule": "PAN 20", "app": "Slack",
      "activity": "Upload", "dlp_profile": "national ids"}
T = "2026-10-05T16:20:30.000+0530"


def _dlp(events=(EV,), source="alert", count=None):
    ev = [dict(e) for e in events]
    return {"bind_source": source, "events": ev, "event_count": len(ev) if count is None else count,
            "truncated": False}


def _cand(key, secs_before, status="False Positive"):
    t = datetime(2026, 10, 5, 16, 20, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    return {"key": key, "created": t - timedelta(seconds=secs_before), "status": status,
            "description": f"IncidentURl\nhttps://x/Incidents/{key}\nalertLink\nhttps://y/alerts/sn{key}"}


def _run(cands, rows_by_key, dlp=None, monkeypatch=None):
    async def fake_cands(jira_key, t, cfg):
        return cands

    async def fake_rows(url, aid):
        return rows_by_key.get(aid[2:], [])
    import edr_triage.jira_poller as JP
    import edr_triage.sentinel_client as SC
    monkeypatch.setattr(D, "_candidates", fake_cands)
    monkeypatch.setattr(SC, "_dlp_rows_from_alert", fake_rows)
    monkeypatch.setattr(JP, "parse_sentinel_incident_url", lambda t: "https://x/Incidents/1")
    monkeypatch.setattr(JP, "parse_sentinel_alert_id",
                        lambda t: "sn" + t.split("/alerts/sn")[1].strip())
    return asyncio.run(D.find_original("DEMO-200", T, dlp or _dlp(), SimpleNamespace()))


# --- the fingerprint ---------------------------------------------------------

def test_same_event_same_fingerprint_whatever_the_case():
    assert D.fingerprint([EV]) == D.fingerprint([{k: v.upper() for k, v in EV.items()}])


def test_a_different_user_is_a_different_event():
    """The DEMO-111945 shape humans mark Duplicate: same profile, different person."""
    assert D.fingerprint([EV]) != D.fingerprint([{**EV, "user": "c.d@example.com"}])


def test_a_missing_field_means_no_fingerprint():
    assert D.fingerprint([{**EV, "dlp_file": ""}]) is None
    assert D.fingerprint([]) is None


def test_ties_are_broken_by_key_so_a_group_has_one_original():
    t = datetime(2026, 10, 5, tzinfo=timezone.utc)
    assert D.is_earlier("DEMO-9", t, "DEMO-10", t) and not D.is_earlier("DEMO-10", t, "DEMO-9", t)


# --- find_original -----------------------------------------------------------

def test_an_exact_repeat_finds_its_original(monkeypatch):
    assert _run([_cand("DEMO-199", 10)], {"DEMO-199": [EV]}, monkeypatch=monkeypatch) == \
        {"key": "DEMO-199", "status": "False Positive"}


def test_a_different_event_is_not_a_duplicate(monkeypatch):
    assert _run([_cand("DEMO-199", 10)], {"DEMO-199": [{**EV, "user": "c.d@example.com"}]},
                monkeypatch=monkeypatch) is None


def test_a_subset_of_events_is_not_a_duplicate(monkeypatch):
    two = _dlp([EV, {**EV, "dlp_file": "Other.xlsx"}])
    assert _run([_cand("DEMO-199", 10)], {"DEMO-199": [EV]}, dlp=two, monkeypatch=monkeypatch) is None


def test_an_original_humans_folded_into_another_ticket_is_skipped(monkeypatch):
    assert _run([_cand("DEMO-198", 20, status="Duplicate"), _cand("DEMO-199", 10)],
                {"DEMO-198": [EV], "DEMO-199": [EV]}, monkeypatch=monkeypatch)["key"] == "DEMO-199"
    assert _run([_cand("DEMO-198", 20, status="Duplicate")], {"DEMO-198": [EV]},
                monkeypatch=monkeypatch) is None


def test_a_sweep_bound_or_capped_event_set_never_compares(monkeypatch):
    assert _run([_cand("DEMO-199", 10)], {"DEMO-199": [EV]}, dlp=_dlp(source="sweep"),
                monkeypatch=monkeypatch) is None
    assert _run([_cand("DEMO-199", 10)], {"DEMO-199": [EV]}, dlp=_dlp(count=40),
                monkeypatch=monkeypatch) is None


def test_a_lookup_failure_means_not_a_duplicate(monkeypatch):
    async def boom(*a):
        raise RuntimeError("jira down")
    monkeypatch.setattr(D, "_candidates", boom)
    assert asyncio.run(D.find_original("DEMO-200", T, _dlp(), SimpleNamespace())) is None


# --- the gates in the pipeline -----------------------------------------------

OWNER = {}


def _gate(monkeypatch, *, phase="autonomous", enabled=True, braked=False, status="Open",
          walk_ok=True, dry_run=False):
    calls = {"walk": [], "comments": []}

    async def orig(*a):
        return {"key": "DEMO-199", "status": "False Positive"}

    async def walk(key, route, cfg, forbidden=()):
        # The real walk refuses a route through any forbidden status before any hop
        # (DEMO-115922: the FP-close list forbade these routes' own destinations).
        assert not {h.lower() for h in route} & {f.lower() for f in forbidden}, (route, forbidden)
        assert "awaiting more inputs" in {f.lower() for f in forbidden}
        calls["walk"].append(route)
        return walk_ok

    async def comment(key, text, cfg, dry_run=False):
        calls["comments"].append(text)

    async def get_status(key, cfg):
        return status

    async def brake(name):
        return (braked, "DEMO-1 reopened" if braked else "")
    import edr_triage.autonomy_brake as AB
    import edr_triage.jira_handler as JH
    monkeypatch.setattr(D, "find_original", orig)
    monkeypatch.setattr(JH, "walk_to_status", walk)
    monkeypatch.setattr(JH, "add_comment", comment)
    monkeypatch.setattr(JH, "get_status", get_status)
    async def _owner(key, cfg=None):
        return OWNER.get("name", "")
    monkeypatch.setattr(JH, "owned_by_a_person", _owner)
    monkeypatch.setattr(AB, "check", brake)
    monkeypatch.setattr(P, "_resolve_agent_phase", lambda: phase)
    cfg = SimpleNamespace(auto_duplicate_enabled=enabled, autoclose_report_enabled=True,
                          close_forbidden=lambda: ("Awaiting more inputs",))
    result = SimpleNamespace(labels=[])
    out = asyncio.run(P._maybe_mark_duplicate(
        "DEMO-200", D.FAMILY, {"created_at": T}, {"netskope_dlp": _dlp()}, result, cfg,
        dry_run, False))
    return out, result.labels, calls


def test_autonomous_marks_duplicate_in_one_hop_and_labels_it(monkeypatch):
    out, labels, calls = _gate(monkeypatch)
    assert out == "auto_duplicate" and calls["walk"] == [["Duplicate"]]
    assert D.LABEL in labels and "raptor-autoclosed" in labels
    assert "Duplicate of DEMO-199" in calls["comments"][0]


def test_advisory_phase_only_recommends(monkeypatch):
    out, labels, calls = _gate(monkeypatch, phase="copilot")
    assert out == "" and not calls["walk"] and D.REC_LABEL in labels
    assert "Not closed" in calls["comments"][0]


def test_dry_run_flag_off_and_brake_each_only_recommend(monkeypatch):
    for kw in ({"dry_run": True}, {"enabled": False}, {"braked": True}):
        out, labels, calls = _gate(monkeypatch, **kw)
        assert out == "" and not calls["walk"] and D.REC_LABEL in labels, kw


def test_a_ticket_an_analyst_already_moved_is_left_alone(monkeypatch):
    out, _labels, calls = _gate(monkeypatch, status="Awaiting more inputs")
    assert out == "" and not calls["walk"]


def test_a_failed_transition_falls_back_to_normal_triage(monkeypatch):
    out, labels, _calls = _gate(monkeypatch, walk_ok=False)
    assert out == "" and D.LABEL not in labels


def test_other_families_are_untouched(monkeypatch):
    async def never(*a):
        raise AssertionError("must not look up")
    monkeypatch.setattr(D, "find_original", never)
    assert asyncio.run(P._maybe_mark_duplicate(
        "DEMO-200", "Root Privilege Escalation", {}, {"netskope_dlp": _dlp()},
        SimpleNamespace(labels=[]), SimpleNamespace(), False, False)) == ""


# --- the autoclose report ----------------------------------------------------

BOT, HUMAN = "purple.phantom@example.com", "v-arjun.okafor@example.com"


def _issue(events):
    return {"key": "DEMO-9", "fields": {"status": {"name": "Duplicate"}, "labels": []},
            "changelog": {"histories": [
                {"created": c, "author": {"emailAddress": e, "displayName": e.split("@")[0]},
                 "items": [{"field": "status", "fromString": f, "toString": t}]}
                for c, e, f, t in events]}}


def test_a_bot_duplicate_is_reported_as_a_close():
    row = _read_close(_issue([("2026-10-05T16:21:00.000+0530", BOT, "Open", "Duplicate")]), BOT)
    assert row and row["closed_to"] == "Duplicate" and row["reopened_at"] is None


def test_refiling_a_bot_duplicate_as_false_positive_is_agreement():
    """DEMO-118428 / DEMO-118854: re-filed False Positive the same hour, re-armed by hand."""
    row = _read_close(_issue([("2026-10-05T16:21:00.000+0530", BOT, "Open", "Duplicate"),
                              ("2026-10-05T18:00:00.000+0530", HUMAN, "Duplicate", "False Positive")]),
                      BOT)
    assert not row["reopened_to"]


def test_reopening_a_bot_duplicate_is_an_overturn():
    row = _read_close(_issue([("2026-10-05T16:21:00.000+0530", BOT, "Open", "Duplicate"),
                              ("2026-10-05T18:00:00.000+0530", HUMAN, "Duplicate", "L2 Analysis required")]),
                      BOT)
    assert row["reopened_to"] == "L2 Analysis required"


def test_a_human_duplicate_is_not_ours():
    assert _read_close(_issue([("2026-10-05T16:21:00.000+0530", HUMAN, "Open", "Duplicate")]),
                       BOT) is None


def test_route_never_passes_a_chase_trigger_and_is_allowed_by_its_own_forbidden_list():
    """DEMO-115922: the route was refused live because the FP-close forbidden list was used."""
    from edr_triage.pipeline import _CHASE_TRIGGER_STATUSES
    route = ["Duplicate"]
    assert not {h.lower() for h in route} & {f.lower() for f in _CHASE_TRIGGER_STATUSES}
    assert {"awaiting more inputs", "no response"} == {f.lower() for f in _CHASE_TRIGGER_STATUSES}


# --- Cyble twins -------------------------------------------------------------

CY = "Found 9 alerts for Social Media Monitoring across 3 entities"
CY_DESC = "Service\nsocial_media_monitoring\nTotal Alerts\n9\nEntity Breakdown\nacme 9"


class _FakeResp:
    def __init__(self, issues):
        self._j = {"issues": issues, "isLast": True}

    def raise_for_status(self):
        pass

    def json(self):
        return self._j


class _FakeClient:
    def __init__(self, issues):
        self.issues = issues

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, path, json=None):
        return _FakeResp(self.issues)


def _cy_issue(key, created, summary=CY, desc=CY_DESC, status="Open"):
    return {"key": key, "fields": {"summary": summary, "created": created,
                                   "status": {"name": status},
                                   "description": {"type": "doc", "content": [
                                       {"type": "paragraph", "content": [{"type": "text", "text": desc}]}]}}}


def _twin(monkeypatch, issues, created="2026-10-05T16:30:09.000+0530"):
    import edr_triage.jira_handler as JH
    monkeypatch.setattr(JH, "_build_client", lambda cfg: _FakeClient(issues))
    return asyncio.run(D.find_cyble_twin("DEMO-500", created, CY, CY_DESC,
                                         SimpleNamespace(jira_project_key="SIM")))


def test_an_identical_digest_seconds_later_is_a_twin(monkeypatch):
    assert _twin(monkeypatch, [_cy_issue("DEMO-499", "2026-10-05T16:30:01.000+0530")])["key"] == "DEMO-499"


def test_a_different_breakdown_or_summary_is_not_a_twin(monkeypatch):
    assert _twin(monkeypatch, [_cy_issue("DEMO-499", "2026-10-05T16:30:01.000+0530",
                                      desc=CY_DESC.replace("9", "8"))]) is None
    assert _twin(monkeypatch, [_cy_issue("DEMO-499", "2026-10-05T16:30:01.000+0530",
                                      summary=CY.replace("9 alerts", "8 alerts"))]) is None


def test_a_digest_outside_the_window_or_already_duplicate_is_not_a_twin(monkeypatch):
    assert _twin(monkeypatch, [_cy_issue("DEMO-499", "2026-10-05T16:25:00.000+0530")]) is None
    assert _twin(monkeypatch, [_cy_issue("DEMO-499", "2026-10-05T16:30:01.000+0530",
                                      status="Duplicate")]) is None


def test_the_earliest_of_several_twins_is_the_original(monkeypatch):
    got = _twin(monkeypatch, [_cy_issue("DEMO-499", "2026-10-05T16:30:05.000+0530"),
                              _cy_issue("DEMO-498", "2026-10-05T16:30:01.000+0530")])
    assert got["key"] == "DEMO-498"


def test_cyble_is_braked_as_one_family(monkeypatch):
    seen = {}

    async def brake(name, pattern=""):
        seen["pattern"] = pattern
        return (False, "")

    async def orig(*a):
        return {"key": "DEMO-499", "status": "False Positive"}
    import edr_triage.autonomy_brake as AB
    import edr_triage.jira_handler as JH

    async def walk(key, route, cfg, forbidden=()):
        return True

    async def nothing(*a, **k):
        return None

    async def st(key, cfg):
        return "Open"
    monkeypatch.setattr(D, "find_cyble_twin", orig)
    monkeypatch.setattr(AB, "check", brake)
    monkeypatch.setattr(JH, "walk_to_status", walk)
    monkeypatch.setattr(JH, "add_comment", nothing)
    monkeypatch.setattr(JH, "get_status", st)
    async def _owner(key, cfg=None):
        return ""
    monkeypatch.setattr(JH, "owned_by_a_person", _owner)
    monkeypatch.setattr(P, "_resolve_agent_phase", lambda: "autonomous")
    cfg = SimpleNamespace(auto_duplicate_enabled=True, autoclose_report_enabled=True)
    out = asyncio.run(P._maybe_mark_duplicate("DEMO-500", CY, {"created_at": "x", "description": CY_DESC},
                                              {}, SimpleNamespace(labels=[]), cfg, False, False))
    assert out == "auto_duplicate" and seen["pattern"] == D.CYBLE_BRAKE_PATTERN
    import re
    assert re.match(D.CYBLE_BRAKE_PATTERN, CY) and re.match(D.CYBLE_BRAKE_PATTERN, "Found 208 alerts for stealer_logs across 3 entities")


def test_a_ticket_an_analyst_has_picked_up_is_left_to_them(monkeypatch):
    """DEMO-115961: an L1 had assigned it to himself a minute before RAPTOR marked it Duplicate."""
    OWNER["name"] = "Noor Hassan"
    try:
        out, labels, calls = _gate(monkeypatch, status="Assigned")
        assert out == "" and not calls["walk"] and D.REC_LABEL in labels
    finally:
        OWNER.clear()


def test_the_dlp_and_rule_closing_families_never_promise_raptor_will_not_close(monkeypatch):
    """DEMO-115979 said "will not" in the same second the AnyDesk rule closed it."""
    monkeypatch.setattr(P, "_resolve_agent_phase", lambda: "autonomous")
    for name in ("'CustomEnterpriseBlock' malware was detected", "Log injestion stopped",
                 "Found 3 alerts for Social Media Monitoring across 2 entities"):
        note = P._playbook_state_note(name, "copilot")
        assert note and "may close the ticket itself" in note, name
    assert P._playbook_state_note("Root Privilege Escalation", "copilot") == ""


# --- open repeats: the same at-rest file found again while its ticket is still open ----

AT_REST = {**EV, "activity": "CASB API Scan", "app": "Google Drive"}


def _open_issue(key, created, status="L2 Analysis required"):
    return {"key": key, "fields": {"summary": D.FAMILY, "status": {"name": status},
                                   "created": created,
                                   "description": f"IncidentURl\nhttps://x/Incidents/{key}\n"
                                                  f"alertLink\nhttps://y/alerts/sn{key}"}}


def _open(monkeypatch, issues, rows_by_key, dlp=None, created="2026-10-09T10:50:00.000+0530"):
    seen = {}

    class _C(_FakeClient):
        async def post(self, path, json=None):
            seen["jql"] = json["jql"]
            return _FakeResp(self.issues)

    async def fake_rows(url, aid):
        return rows_by_key.get(aid[2:], [])
    import edr_triage.jira_handler as JH
    import edr_triage.jira_poller as JP
    import edr_triage.sentinel_client as SC
    monkeypatch.setattr(JH, "_build_client", lambda cfg: _C(issues))
    monkeypatch.setattr(SC, "_dlp_rows_from_alert", fake_rows)
    monkeypatch.setattr(JP, "parse_sentinel_incident_url", lambda t: "https://x/Incidents/1")
    monkeypatch.setattr(JP, "parse_sentinel_alert_id",
                        lambda t: "sn" + t.split("/alerts/sn")[1].strip())
    out = asyncio.run(D.find_open_repeat("DEMO-300", created, dlp or _dlp((AT_REST,)),
                                         SimpleNamespace(jira_project_key="SIM")))
    return out, seen.get("jql", "")


def test_a_rescan_of_a_file_whose_ticket_is_still_open_is_a_repeat(monkeypatch):
    """v-rory.benson's "RA Payment Done Data", ticketed 7 times 2026-10-07..09."""
    out, jql = _open(monkeypatch, [_open_issue("DEMO-250", "2026-10-07T09:41:00.000+0530")],
                     {"DEMO-250": [AT_REST]})
    assert out == {"key": "DEMO-250", "status": "L2 Analysis required"}
    assert 'status not in ("False Positive", "Duplicate", "Closed", "Resolved")' in jql
    assert 'text ~ "\\"a.b@example.com\\""' in jql


def test_a_different_file_of_the_same_user_is_not_a_repeat(monkeypatch):
    """Analysts fold these too; RAPTOR does not — a different file is a different finding."""
    out, _ = _open(monkeypatch, [_open_issue("DEMO-250", "2026-10-07T09:41:00.000+0530")],
                   {"DEMO-250": [{**AT_REST, "dlp_file": "Other.xlsx"}]})
    assert out is None


def test_only_at_rest_scans_are_open_repeats(monkeypatch):
    out, jql = _open(monkeypatch, [_open_issue("DEMO-250", "2026-10-07T09:41:00.000+0530")],
                     {"DEMO-250": [EV]}, dlp=_dlp((EV,)))
    assert out is None and jql == ""      # an Upload never even queries Jira


def test_a_closed_or_too_old_original_is_not_used(monkeypatch):
    for issue in (_open_issue("DEMO-250", "2026-10-07T09:41:00.000+0530", status="False Positive"),
                  _open_issue("DEMO-250", "2026-09-30T09:41:00.000+0530")):
        out, _ = _open(monkeypatch, [issue], {"DEMO-250": [AT_REST]})
        assert out is None, issue["fields"]


def test_a_later_ticket_is_never_the_original(monkeypatch):
    out, _ = _open(monkeypatch, [_open_issue("DEMO-350", "2026-10-09T11:00:00.000+0530")],
                   {"DEMO-350": [AT_REST]})
    assert out is None


def test_the_earliest_open_match_is_the_original(monkeypatch):
    out, _ = _open(monkeypatch, [_open_issue("DEMO-260", "2026-10-08T09:41:00.000+0530"),
                                 _open_issue("DEMO-250", "2026-10-07T09:41:00.000+0530", "Awaiting more inputs")],
                   {"DEMO-250": [AT_REST], "DEMO-260": [AT_REST]})
    assert out["key"] == "DEMO-250"


def test_an_open_repeat_lookup_failure_means_not_a_duplicate(monkeypatch):
    import edr_triage.jira_handler as JH

    def boom(cfg):
        raise RuntimeError("jira down")
    monkeypatch.setattr(JH, "_build_client", boom)
    assert asyncio.run(D.find_open_repeat("DEMO-300", T, _dlp((AT_REST,)),
                                          SimpleNamespace(jira_project_key="SIM"))) is None


def test_an_open_repeat_goes_through_the_same_gates_and_says_why(monkeypatch):
    async def none(*a):
        return None

    async def open_rep(*a):
        return {"key": "DEMO-250", "status": "L2 Analysis required"}
    monkeypatch.setattr(D, "find_original", none)
    monkeypatch.setattr(D, "find_open_repeat", open_rep)
    calls = {"walk": [], "comments": []}

    async def walk(key, route, cfg, forbidden=()):
        calls["walk"].append(route)
        return True

    async def comment(key, text, cfg, dry_run=False):
        calls["comments"].append(text)

    async def get_status(key, cfg):
        return "Open"

    async def brake(name):
        return (False, "")

    async def _owner(key, cfg=None):
        return ""
    import edr_triage.autonomy_brake as AB
    import edr_triage.jira_handler as JH
    monkeypatch.setattr(JH, "walk_to_status", walk)
    monkeypatch.setattr(JH, "add_comment", comment)
    monkeypatch.setattr(JH, "get_status", get_status)
    monkeypatch.setattr(JH, "owned_by_a_person", _owner)
    monkeypatch.setattr(AB, "check", brake)
    monkeypatch.setattr(P, "_resolve_agent_phase", lambda: "autonomous")
    cfg = SimpleNamespace(auto_duplicate_enabled=True, autoclose_report_enabled=True)
    result = SimpleNamespace(labels=["user-chase-pending"])
    out = asyncio.run(P._maybe_mark_duplicate("DEMO-300", D.FAMILY, {"created_at": T},
                                              {"netskope_dlp": _dlp((AT_REST,))}, result, cfg,
                                              False, False))
    assert out == "auto_duplicate" and calls["walk"] == [["Duplicate"]]
    assert "user-chase-pending" not in result.labels      # never chased on top of the original
    assert "still open (L2 Analysis required)" in calls["comments"][0]
    assert "found the same file again" in calls["comments"][0]
