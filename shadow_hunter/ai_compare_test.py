"""Mistral-vs-Claude comparison on /shadow findings: selection, no side effects, summary."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from shadow_hunter import ai_compare as AC
from shadow_hunter.models import AuditLog, Finding, Story


def F(i, claude, human="", sev="high", det="lolbin_abuse"):
    return Finding(id=f"f{i}", detector=det, severity=sev, device_name=f"h{i}", indicator=f"x{i}", summary=f"s{i}",
                   raw={}, ai_by="claude-code-manual", ai_verdict=claude, ai_confidence=0.8,
                   ai_reasoning="claude says", decision=human, created_at=datetime.now(timezone.utc))


class Mistral:
    model_id = "mistral.mistral-large-3-675b-instruct"

    def __init__(self, answers):
        self.answers = answers

    async def chat(self, messages, tools):
        fid = next(k for k in self.answers if f"x{k[1:]}" in messages[-1]["content"])
        return f'<final_verdict>{{"verdict": "{self.answers[fid]}", "confidence": 0.7, "reasoning": "m"}}</final_verdict>', []


def test_compare_never_touches_findings_and_flags_mistral_misses(monkeypatch):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    from shadow_hunter import ai_triage as T

    async def none(*a, **k):
        return []
    monkeypatch.setattr(T, "precedents_for", none)
    monkeypatch.setattr(T, "rules_for", none)

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["ai_compare"], document_models=[Finding, AuditLog, Story])
        for f in (F(1, "true_positive", human="true_positive"), F(2, "unsure"), F(3, "false_positive", human="false_positive"),
                  F(4, "false_positive")):
            await f.insert()
        picked = await AC.pick(10)
        out = await AC.run("r1", 10, backend=Mistral({"f1": "false_positive", "f2": "unsure", "f3": "false_positive",
                                                      "f4": "true_positive"}), tools=[], execute=None, pace_s=0)
        return picked, out, await AC.results("r1"), await Finding.get("f1")
    picked, out, res, f1 = asyncio.run(go())
    assert set(picked) == {"f1", "f2", "f3", "f4"}
    assert out["judged"] == 4 and res["agree_with_claude"] == 2
    assert res["human_decided"] == 2 and res["claude_matches_human"] == 2 and res["mistral_matches_human"] == 1
    assert [r["finding_id"] for r in res["risky"]] == ["f1"]  # Mistral FP on a confirmed threat
    assert f1.ai_verdict == "true_positive" and f1.ai_by == "claude-code-manual"   # untouched


def test_pick_is_stratified_and_spread_across_detectors():
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["ai_compare_pick"], document_models=[Finding, AuditLog, Story])
        fs = ([F(i, "true_positive", human="true_positive", det="encoded_powershell") for i in range(20)]
              + [F(100, "false_positive", human="false_positive", det="lolbin_abuse")]
              + [F(200 + i, "unsure", det="upwind_threats") for i in range(5)]
              + [F(300 + i, "false_positive", det=d) for i, d in enumerate(["rare_persistence"] * 10 + ["exfil_patterns"] * 10)])
        for f in fs:
            await f.insert()
        return await AC.pick(9)
    p = asyncio.run(go())
    assert len(p) == 9
    assert "f100" in p                                     # the lone lolbin decision is not crowded out by DART
    assert sum(x.startswith("f2") and len(x) == 4 for x in p) == 3       # 3 Claude-unsure
    assert {x for x in p if x.startswith("f3")} & {"f300", "f310"} == {"f300", "f310"}  # both FP detectors


def test_a_failing_finding_is_recorded_the_run_finishes_and_resume_skips_judged(monkeypatch):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    real = AC._one

    async def flaky(run_id, fid, *a):
        if fid == "f2":
            raise ValueError("bad finding")
        return await real(run_id, fid, *a)
    monkeypatch.setattr(AC, "_one", flaky)
    from shadow_hunter import ai_triage as T

    async def none(*a, **k):
        return []
    monkeypatch.setattr(T, "precedents_for", none)
    monkeypatch.setattr(T, "rules_for", none)
    m = Mistral({"f1": "true_positive", "f2": "unsure", "f3": "false_positive"})

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["ai_compare_resume"], document_models=[Finding, AuditLog, Story])
        for f in (F(1, "true_positive"), F(2, "unsure"), F(3, "false_positive")):
            await f.insert()
        first = await AC.run("r2", 10, backend=m, tools=[], execute=None, pace_s=0)
        again = await AC.run("r2", 10, backend=m, tools=[], execute=None, pace_s=0)
        return first, again, await AC.results("r2")
    first, again, res = asyncio.run(go())
    assert res["status"]["state"] == "done" and res["judged"] == 3 and res["errors"] == 1
    assert again["resumed_after"] == 3 and again["judged"] == 0


def test_review_engine_compares_the_grouped_pipeline_without_recording(monkeypatch):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    import json as _json
    from shadow_hunter import ai_triage as T

    async def none(*a, **k):
        return []
    monkeypatch.setattr(T, "precedents_for", none)
    monkeypatch.setattr(T, "rules_for", none)

    class Opus:
        cache_system = False

        async def chat(self, messages, tools):
            return _json.dumps({"groups": [{"id": "g1", "verdict": "true_positive", "confidence": 0.8,
                                            "reasoning": "brute force", "checklist": {"origin": "edge"}}]}), []

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["ai_compare_review"], document_models=[Finding, AuditLog, Story])
        await F(1, "true_positive", det="edge_attacks").insert()
        await AC.run("r3", 5, backend=Mistral({"f1": "false_positive"}), tools=[], execute=None, pace_s=0,
                     engine="review", output="short", opus=Opus())
        return await AC.results("r3"), await Finding.get("f1")
    res, f1 = asyncio.run(go())
    row = res["rows"][0]
    assert row["mistral"]["verdict"] == "true_positive" and row["mistral"]["gatherer_verdict"] == "false_positive"
    assert "Opus decides" in row["mistral_model"] and res["agree_with_claude"] == 1
    assert f1.ai_by == "claude-code-manual"                      # nothing recorded on the finding
