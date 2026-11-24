"""Port Sweep hourly re-fires fold into the open L2 ticket for the same port."""
from __future__ import annotations

import asyncio
import inspect
from types import SimpleNamespace

import pytest

from edr_triage import duplicate_guard as dg


def _issue(key, created, status, path=(), summary="Network Port Sweep detected on 7680"):
    return {"key": key, "fields": {"summary": summary, "created": created, "status": {"name": status}},
            "changelog": {"histories": [{"items": [{"field": "status", "toString": s}]} for s in path]}}


@pytest.mark.parametrize("name,ok", [
    ("Network Port Sweep detected on 7680", True),
    ("Network Port Sweep detected on 3389", True),
    ("Network Port Sweep detected", False),
    ("Found 3 alerts for Social Media Monitoring across 2 entities", False),
])
def test_applies(name, ok):
    assert dg.applies_portsweep(name) is ok


@pytest.mark.parametrize("issue,ok", [
    (_issue("A", "x", "L2 Analysis required"), True),
    (_issue("A", "x", "Awaiting more inputs", ("Assigned", "L2 Analysis required", "Event Analysis")), True),
    (_issue("A", "x", "Awaiting more inputs", ("Assigned", "Event Analysis")), False),   # L1 asking, not L2
    (_issue("A", "x", "False Positive", ("L2 Analysis required",)), False),             # finished
    (_issue("A", "x", "Open"), False),
])
def test_with_l2(issue, ok):
    assert dg._with_l2(issue) is ok


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
                return {"issues": issues}
        return R()


def _find(monkeypatch, issues, created="2026-10-14T13:13:00.000+0530", name="Network Port Sweep detected on 7680"):
    import edr_triage.jira_handler as JH
    monkeypatch.setattr(JH, "_build_client", lambda cfg: _Client(issues))
    return asyncio.run(dg.find_portsweep_open("DEMO-116911", created, name,
                                              SimpleNamespace(jira_project_key="SIM")))


def test_folds_into_the_earliest_open_l2_ticket_for_the_port(monkeypatch):
    got = _find(monkeypatch, [
        _issue("DEMO-116821", "2026-10-14T01:13:00.000+0530", "Awaiting more inputs", ("L2 Analysis required",)),
        _issue("DEMO-116878", "2026-10-14T09:13:00.000+0530", "L2 Analysis required"),
    ])
    assert got == {"key": "DEMO-116821", "status": "Awaiting more inputs"}


@pytest.mark.parametrize("issues", [
    [_issue("DEMO-1", "2026-10-14T09:13:00.000+0530", "Duplicate")],                       # not with L2
    [_issue("DEMO-1", "2026-10-14T09:13:00.000+0530", "Event Analysis", ("Assigned",))],   # L1 still on it
    [_issue("DEMO-1", "2026-10-13T09:00:00.000+0530", "L2 Analysis required")],           # older than 24h
    [_issue("DEMO-1", "2026-10-14T09:13:00.000+0530", "L2 Analysis required",
            summary="Network Port Sweep detected on 445")],                              # another port
    [],
])
def test_otherwise_it_is_its_own_ticket(monkeypatch, issues):
    assert _find(monkeypatch, issues) is None


def test_a_lookup_failure_is_never_a_duplicate(monkeypatch):
    import edr_triage.jira_handler as JH
    def boom(cfg):
        raise RuntimeError("jira down")
    monkeypatch.setattr(JH, "_build_client", boom)
    assert asyncio.run(dg.find_portsweep_open("K", "2026-10-14T13:13:00.000+0530",
                                              "Network Port Sweep detected on 7680",
                                              SimpleNamespace(jira_project_key="SIM"))) is None


def test_comment_names_the_original_and_this_hours_hosts():
    c = dg.portsweep_comment("DEMO-116821", "Awaiting more inputs", "7680", ["10.10.44.112", "10.16.28.38"], True)
    assert "Duplicate of DEMO-116821" in c and "10.16.28.38" in c and "(2)" in c
    assert "Not closed" in dg.portsweep_comment("DEMO-1", "L2 Analysis required", "7680", [], False)


def test_the_pipeline_routes_port_sweeps_through_the_same_gate():
    from edr_triage import pipeline as P
    src = inspect.getsource(P._maybe_mark_duplicate)
    assert "dg.find_portsweep_open(" in src and "dg.PORTSWEEP_BRAKE_PATTERN" in src
    assert "_deterministic_close_refusal(" in src


def test_the_rearm_entry_is_keyed_by_the_brake_pattern():
    from edr_triage import autonomy_brake
    t = autonomy_brake.rearm_times().get(dg.PORTSWEEP_BRAKE_PATTERN.casefold())
    assert t is not None and t.isoformat() == "2026-10-23T21:56:00+00:00"   # re-armed after DEMO-118428
