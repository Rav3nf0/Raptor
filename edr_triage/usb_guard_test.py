"""Run: python -m pytest edr_triage/usb_guard_test.py -q"""
from __future__ import annotations

import inspect

from edr_triage import pipeline as P
from edr_triage import usb_guard as U


def test_usb_family_is_asked_not_closed():
    assert U.applies("Files Copied to USB Drives")
    assert not U.applies("Netskope DLP Alerts")
    allow = P.autonomous_alert_allowlist()
    assert P._alert_matches_allowlist("Files Copied to USB Drives", allow)
    assert "_usb_ask.applies(alert_name)" in inspect.getsource(P._process_ticket)


def test_g14_still_turns_every_usb_fp_into_an_ask():
    from agent_core import loop
    src = inspect.getsource(loop._apply_safety_gates)
    assert 'triage_class == "AUTO_CLOSED_FP" and _is_usb_copy_alert(alert_name)' in src


def test_an_allowlist_never_closes_a_usb_copy():
    src = inspect.getsource(P._process_ticket)
    i = src.index("_usbg.applies(alert_name)")
    assert "_allow = None" in src[i:i + 400]


def test_nobody_to_ask_means_l2_and_tampering_goes_to_l2():
    assert P._l2_direct_family("Files Copied to USB Drives")
    assert P._l2_direct_family("Tampering with the Microsoft Defender for Endpoint sensor")
    assert not P._alert_matches_allowlist(
        "Tampering with the Microsoft Defender for Endpoint sensor", P.autonomous_alert_allowlist())


def test_the_ask_says_l2_decides():
    c = U.ask_comment("A Person (a.person@example.com)", "r")
    assert "L2, who decides" in c and "A Person" in c


# ── No removable drive (DEMO-118633) ───────────────────────────────────────────────────────
import asyncio

from agent_core.loop import AgentResult, _apply_safety_gates

_USB = "Files Copied to USB Drives"
_INTERNAL = {"internal": True, "device": "pc.corp.example.com", "paths": ["D:\\busywin\\KRAPARA.CSS"],
             "mounts": 669, "products": ["HL-DT-ST DVD+/-RW GU90N"],
             "reason": "no removable drive: all 669 drive mounts on pc.corp.example.com ..."}


def _gates(evidence):
    r = AgentResult(triage_class="AUTO_CLOSED_FP", confidence=0.95, reasoning="Busy writes its files.")
    return _apply_safety_gates(r, severity="MEDIUM", is_test_device=False, tool_calls=[],
                               device_name="pc.corp.example.com", user_name="blair.ahuja",
                               evidence={"actor_reachable": True, **evidence}, alert_name=_USB)


def test_g14_stands_aside_only_on_a_proven_internal_drive():
    r = _gates({"usb_drive_check": _INTERNAL})
    assert r.safety_gate_kind != "usb_copy_needs_reason"
    assert "copier's reason" not in (r.safety_block_reason or "")


def test_a_proven_internal_drive_is_seen_telemetry_and_the_close_stands():
    # DEMO-122093: the no-hunt gate blocked the close G14 stands aside for. The agent ran
    # only context tools there, no hunt.
    from agent_core.result import ToolCallRecord
    calls = [ToolCallRecord("scg_check_concurrent_alerts", {"device_name": "pc.corp.example.com"},
                            {"concurrent_count": 0}),
             ToolCallRecord("scg_get_entity_context", {"value": "pc.corp.example.com"},
                            {"found": True, "alert_count": 23})]
    r = AgentResult(triage_class="AUTO_CLOSED_FP", confidence=0.95, reasoning="Busy writes its files.")
    r = _apply_safety_gates(r, severity="MEDIUM", is_test_device=False, tool_calls=calls,
                            device_name="pc.corp.example.com", user_name="blair.ahuja",
                            evidence={"actor_reachable": True, "usb_drive_check": _INTERNAL},
                            alert_name=_USB)
    assert r.safety_gate_kind != "no_hunt_data", r.safety_block_reason
    assert r.triage_class == "AUTO_CLOSED_FP", r.safety_block_reason


def test_an_unproven_drive_with_no_hunt_is_still_blocked():
    r = AgentResult(triage_class="AUTO_CLOSED_FP", confidence=0.95, reasoning="x")
    r = _apply_safety_gates(r, severity="MEDIUM", is_test_device=False, tool_calls=[],
                            device_name="pc.corp.example.com", user_name="blair.ahuja",
                            evidence={"actor_reachable": True,
                                      "usb_drive_check": {"internal": False, "reason": "x"}},
                            alert_name="Root Privilege Escalation")
    assert r.triage_class == "NEEDS_L2"


def test_g14_still_asks_when_a_removable_drive_may_be_involved():
    for ev in ({}, {"usb_drive_check": None},
               {"usb_drive_check": {"internal": False, "reason": "3 removable mounts"}},
               {"usb_drive_check": {"internal": "true"}}):      # only a real True counts
        r = _gates(ev)
        # G14 fired and the close is gone; later gates may still route the ask to L2.
        assert r.safety_gate_kind == "usb_copy_needs_reason", ev
        assert r.triage_class in ("REQUEST_JUSTIFICATION", "NEEDS_L2"), ev


def _enforce(check, monkeypatch):
    posted = []

    async def _add_comment(key, text, cfg, dry_run=False):
        posted.append(text)
    import edr_triage.jira_handler as JH
    monkeypatch.setattr(JH, "add_comment", _add_comment)
    labels: list = []
    blocked, why = asyncio.run(U.enforce_at_close(_USB, labels, "DEMO-1", check, cfg=None))
    return blocked, why, labels, posted


def test_close_gate_refuses_a_usb_close_without_proof(monkeypatch):
    for check in (None, {}, {"internal": False, "reason": "no drive mount found"}):
        blocked, why, labels, posted = _enforce(check, monkeypatch)
        assert blocked and "usb-guard" in labels and "did not auto-close" in posted[0]


def test_close_gate_permits_and_says_why(monkeypatch):
    blocked, why, labels, posted = _enforce(_INTERNAL, monkeypatch)
    assert not blocked and not labels
    assert "no removable drive was involved" in posted[0] and "KRAPARA.CSS" in posted[0]


def test_close_gate_ignores_other_families(monkeypatch):
    assert asyncio.run(U.enforce_at_close("Netskope DLP Alerts", [], "DEMO-1", None, cfg=None)) == (False, "")


def test_drive_check_fails_closed_without_ids():
    r = asyncio.run(U.drive_check("", ""))
    assert r["internal"] is False


def test_prompt_states_the_drive_check():
    from agent_core.oscar import format_alert
    txt = format_alert({}, "DEMO-1", _USB, "MEDIUM", "pc.corp.example.com", "blair.ahuja",
                       evidence={"usb_drive_check": _INTERNAL})
    assert "no removable drive was involved" in txt
    txt = format_alert({}, "DEMO-1", _USB, "MEDIUM", "pc.corp.example.com", "blair.ahuja",
                       evidence={"usb_drive_check": {"internal": False, "reason": "x"}})
    assert "removable drive may be involved" in txt


def test_drive_check_waits_for_sentinel_to_ingest_the_alert(monkeypatch):
    """DEMO-122894: triaged 2 s before the SecurityAlert row landed; read 'not found'."""
    answers = [{"internal": False, "reason": "Sentinel alert not found"},
               {"internal": False, "reason": "no file event read for D:\\x"}, _INTERNAL]
    calls = []

    async def fake(url, aid):
        calls.append(aid)
        return answers[len(calls) - 1]
    monkeypatch.setattr(U, "_drive_check", fake)
    monkeypatch.setattr(U, "RETRY_WAITS", (0.01, 0.01, 0.01))
    assert asyncio.run(U.drive_check("u", "a"))["internal"] is True and len(calls) == 3


def test_drive_check_never_retries_a_removable_mount(monkeypatch):
    calls = []

    async def fake(url, aid):
        calls.append(aid)
        return {"internal": False, "reason": "1 removable or lettered drive mount(s) on pc"}
    monkeypatch.setattr(U, "_drive_check", fake)
    monkeypatch.setattr(U, "RETRY_WAITS", (0.01, 0.01, 0.01))
    assert asyncio.run(U.drive_check("u", "a"))["internal"] is False and len(calls) == 1


def test_drive_check_gives_up_closed(monkeypatch):
    async def fake(url, aid):
        return {"internal": False, "reason": "Sentinel alert not found"}
    monkeypatch.setattr(U, "_drive_check", fake)
    monkeypatch.setattr(U, "RETRY_WAITS", (0.01, 0.01))
    assert asyncio.run(U.drive_check("u", "a"))["internal"] is False
