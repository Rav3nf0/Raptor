"""Tickets RAPTOR leaves for an analyst (pipeline._handle_residual)."""
from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace

import pytest

from edr_triage import pipeline as P
from edr_triage import store


def _res(labels=None):
    return SimpleNamespace(triage_class="NEEDS_L2", labels=list(labels or ["needs-l2-review"]))


@pytest.fixture
def rec(monkeypatch):
    rows = []
    monkeypatch.setattr(store, "record_residual", lambda d: rows.append(d))
    return rows


def _run(monkeypatch, mode, refusal=None, routed="routed_to_l2"):
    calls = {"route": 0}

    async def refuse(*a, **k):
        return refusal

    async def route(*a, **k):
        calls["route"] += 1
        return routed
    monkeypatch.setattr(P, "_deterministic_close_refusal", refuse)
    monkeypatch.setattr(P, "_execute_l2_route", route)
    out = asyncio.run(P._handle_residual("DEMO-1", "Root Privilege Escalation",
                                         SimpleNamespace(residual_mode=mode), _res(), "labels_only",
                                         False, False))
    return out, calls


def test_record_notes_it_and_touches_nothing(monkeypatch, rec):
    out, calls = _run(monkeypatch, "record")
    assert out == "labels_only" and calls["route"] == 0
    assert rec and rec[0]["jira_key"] == "DEMO-1" and rec[0]["mode"] == "record"
    assert rec[0]["family"]                      # grouped family name for the report


def test_off_records_nothing(monkeypatch, rec):
    out, calls = _run(monkeypatch, "off")
    assert out == "labels_only" and rec == [] and calls["route"] == 0


def test_route_goes_to_l2_through_the_same_gate(monkeypatch, rec):
    out, calls = _run(monkeypatch, "route")
    assert out == "routed_to_l2" and calls["route"] == 1 and rec


def test_route_respects_a_gate_refusal(monkeypatch, rec):
    out, calls = _run(monkeypatch, "route", refusal="a person already owns it")
    assert out == "labels_only" and calls["route"] == 0


def test_a_store_failure_never_breaks_triage(monkeypatch):
    def boom(d):
        raise RuntimeError("mongo down")
    monkeypatch.setattr(store, "record_residual", boom)
    out, _ = _run(monkeypatch, "record")
    assert out == "labels_only"


def test_route_is_the_default_and_record_writes_nothing_to_jira():
    """2026-10-28: route what L1 used to escalate; Cyble and DLP stay report-only."""
    from edr_triage.config import EDRTriageConfig
    assert EDRTriageConfig.model_fields["residual_mode"].default == "route"
    src = inspect.getsource(P._handle_residual)
    head = src.split('if mode == "route":')[0]
    for call in ("add_comment", "add_labels", "transition", "_execute_l2_route"):
        assert call not in head, call


def test_the_hook_runs_after_every_other_step_and_never_on_a_dry_run():
    src = inspect.getsource(P._process_ticket)
    i = src.index("_handle_residual(")
    assert src.index("_l2_direct_family(alert_name) and action_taken") < i
    assert "not dry_run and not test_labels_only" in src[i - 200:i]
    assert P._RESIDUAL_ACTIONS == ("labels_only", "close_failed")


def test_the_report_groups_by_day_and_family(monkeypatch):
    import time
    from app.views.edr_triage_views import edr_residual_report
    now = time.time()
    monkeypatch.setattr(store, "list_residual", lambda since: [
        {"jira_key": "DEMO-1", "family": "Cyble Social Media", "noted_at": now},
        {"jira_key": "DEMO-2", "family": "Cyble Social Media", "noted_at": now},
        {"jira_key": "DEMO-3", "family": "Root Privilege Escalation", "noted_at": now - 86400}])
    out = asyncio.run(edr_residual_report(days=7))
    assert out["total"] == 3 and len(out["by_day_ist"]) == 2
    assert out["by_family"][0] == {"family": "Cyble Social Media", "tickets": 2, "per_day": 1.0}

def test_cyble_and_dlp_are_reported_never_routed_everything_else_routes(monkeypatch, rec):
    seen = []

    async def refuse(*a, **k): return None

    async def route(key, cfg, result, dry_run, why=""):
        seen.append(key)
        return "routed_to_l2"
    monkeypatch.setattr(P, "_deterministic_close_refusal", refuse)
    monkeypatch.setattr(P, "_execute_l2_route", route)
    for key, name in (("A", "Found 3 alerts for Social Media Monitoring across 2 entities"),
                      ("B", "Found 2 alerts for Suspicious Domains across 1 entities"),
                      ("C", "Netskope DLP Alerts"),
                      ("D", "Root Privilege Escalation"),
                      ("E", "Network Port Sweep detected on 7680"),
                      ("F", "Powershell script was loaded in memory")):
        asyncio.run(P._handle_residual(key, name, SimpleNamespace(residual_mode="route"), _res(),
                                       "labels_only", False, False))
    assert seen == ["D", "E", "F"]
    assert len(rec) == 6                                  # all six are still in the report


def test_the_l2_move_names_the_gate_that_refused_an_fp():
    """DEMO-123173: AUTO-FP 95%, then 'could not settle it' — the privesc reason was a label."""
    fp = SimpleNamespace(triage_class="AUTO_CLOSED_FP")
    w = P._residual_why(fp, "1 command(s) root has not had cleared on host — e.g. `docker`")
    assert "refused the close" in w and "has not had cleared" in w
    assert "could not settle" in P._residual_why(fp, "")
    assert "could not settle" in P._residual_why(SimpleNamespace(triage_class="NEEDS_L2"), "x")
    src = inspect.getsource(P._process_ticket)
    assert "dry_run, test_labels_only, _close_refusal)" in src


def test_a_failed_close_says_so_and_never_asks_the_user(monkeypatch):
    """DEMO-115106: 'Auto-close permitted', then 'asking the user' after the walk stalled."""
    from edr_triage import jira_handler as J
    posted = []

    async def status(k, cfg):
        return "L2 Analysis required"

    async def comment(k, text, cfg, dry_run=False):
        posted.append(text)
    monkeypatch.setattr(J, "get_status", status)
    monkeypatch.setattr(J, "add_comment", comment)
    why = asyncio.run(P._close_failed_note("DEMO-1", None, False))
    assert "L2 Analysis required" in why and posted and "Nobody was messaged" in posted[0]
    src = inspect.getsource(P._process_ticket)
    assert 'action_taken not in ("auto_closed", "close_failed")' in src
    assert "_close_refusal = await _close_failed_note(" in src
