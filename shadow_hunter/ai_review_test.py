"""Grouped /shadow review: Mistral gathers, Opus decides (shadow_hunter/ai_review.py)."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from shadow_hunter import ai_review as R
from shadow_hunter.models import AuditLog, Finding, Story

NOW = datetime(2026, 10, 28, 6, 0, tzinfo=timezone.utc)          # 11:30 IST
OPUS = "apac.anthropic.claude-opus-test"


def F(i, host, sev="medium", det="rare_persistence", ind=None, **kw):
    return Finding.model_construct(id=f"{i:08d}-x", detector=det, severity=sev, device_name=host, account_name="",
                   indicator=ind or f"\\EPPUpdateRetry_{i}|{host}|C:\\Users\\{host}u\\AppData\\stub.exe",
                   summary=f"task on {host}", raw={"first_seen": NOW.isoformat()}, created_at=NOW - timedelta(hours=i),
                   **kw)


@pytest.fixture(autouse=True)
def claude_env(monkeypatch):
    monkeypatch.setenv("SHADOW_LLM", "claude")
    monkeypatch.setenv("SHADOW_CLAUDE_MODEL", OPUS)
    monkeypatch.delenv("SHADOW_REVIEW_OUTPUT", raising=False)
    monkeypatch.delenv("SHADOW_REVIEW_BATCH_HOURS_IST", raising=False)


# ── pure parts ───────────────────────────────────────────────────────────────

def test_same_pattern_on_many_hosts_is_one_group():
    fs = [F(1, "e112kk"), F(2, "u1048g"), F(3, "r009mr"), F(4, "a1", det="lolbin_abuse", ind="certutil -urlcache x")]
    groups = R.make_groups(fs)
    assert sorted(len(g) for g in groups) == [1, 3]
    assert R.shape(fs[0]) == R.shape(fs[1])                     # host, user dir and digits normalised


def test_batch_is_due_once_per_slot():
    assert R.batch_due(None, NOW)                                # 11:30 IST, 09:00 slot never run
    assert not R.batch_due(NOW - timedelta(minutes=30), NOW)    # ran at 11:00 IST, after the 09:00 slot
    assert R.batch_due(NOW - timedelta(hours=3), NOW)           # last ran 08:30 IST, before it
    late = NOW + timedelta(hours=6)                              # 17:30 IST
    assert R.batch_due(NOW, late)
    assert not R.batch_due((NOW - timedelta(minutes=30)).replace(tzinfo=None), NOW)   # naive = UTC


def test_fp_needs_a_concrete_benign_explanation():
    assert R.guard({"verdict": "false_positive", "checklist": {"benign_explanation": "none"}})["verdict"] == "unsure"
    assert R.guard({"verdict": "false_positive", "checklist": {"benign_explanation": " N/A "}})["verdict"] == "unsure"
    ok = R.guard({"verdict": "false_positive", "confidence": "0.9",
                  "checklist": {"benign_explanation": "ReasonLabs Stub.exe, signed, Program Files"}})
    assert ok["verdict"] == "false_positive" and ok["confidence"] == 0.9
    assert R.guard({"verdict": "maybe"})["verdict"] == "unsure"


def test_parse_decisions_tolerates_fences_and_raw_newlines():
    txt = '```json\n{"groups": [{"id": "g1", "verdict": "unsure", "reasoning": "a\nb"}]}\n```'
    assert R.parse_decisions(txt)["g1"]["reasoning"] == "a\nb"


def test_system_prompt_is_stable_and_carries_the_guides():
    a, b = R.system_prompt("short"), R.system_prompt("short")
    assert a == b and "edge_attacks:" in a and "at most 60 words" in a     # cacheable prefix
    assert "up to 200 words" in R.system_prompt("full")


def test_run_kql_is_read_only_bounded_and_never_autofixed(monkeypatch):
    import lib.mde_client as M
    seen = {}

    async def fake(q, **kw):
        seen.update(q=q, **kw)
        return [{"n": 1}], None
    monkeypatch.setattr(M, "run_sentinel_query", fake)
    out = asyncio.run(R.run_kql("SigninLogs | where TimeGenerated > ago(1d)", "sentinel"))
    assert out["count"] == 1 and seen["autofix"] is False and seen["q"].endswith("| take 100")
    assert "read-only" in asyncio.run(R.run_kql(".drop table SigninLogs", "sentinel"))["error"]


# ── the run (Mongo) ──────────────────────────────────────────────────────────

class Gatherer:
    model_id = "mistral.mistral-large-3-675b-instruct"

    async def chat(self, messages, tools):
        return '<final_verdict>{"verdict": "false_positive", "confidence": 0.9, "reasoning": "vendor"}</final_verdict>', []


class Opus:
    model_id = OPUS
    cache_system = False

    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    async def chat(self, messages, tools):
        self.calls.append(messages)
        return json.dumps({"groups": self.replies.pop(0)}), []


def _fp(gid, **kw):
    return {"id": gid, "verdict": "false_positive", "confidence": 0.85, "reasoning": "ReasonLabs updater",
            "checklist": {"benign_explanation": "ReasonLabs Stub.exe signed, Program Files"}, **kw}


async def _db(name):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    from entity_graph.models import ShadowResult
    await init_beanie(database=mm.AsyncMongoMockClient()[name], document_models=[Finding, AuditLog, Story, ShadowResult])


def _patch(monkeypatch):
    from shadow_hunter import ai_triage as T

    async def none(*a, **k):
        return []

    async def no_reuse(f):
        return None
    monkeypatch.setattr(T, "precedents_for", none)
    monkeypatch.setattr(T, "rules_for", none)
    monkeypatch.setattr(T, "reusable_verdict", no_reuse)


def test_urgent_now_calm_waits_for_the_batch_and_exceptions_apply(monkeypatch):
    _patch(monkeypatch)

    async def go():
        await _db("review_run")
        crit = F(9, "uat-sify", sev="critical", det="upwind_threats", ind="shadow read")
        calm = [F(1, "h1"), F(2, "h2"), F(3, "h3")]
        for f in [crit] + calm:
            await Finding(**f.model_dump()).insert()
        await R._db()["shadow_ai_review"].insert_one({"_id": R.STATE_ID, "last_batch": NOW - timedelta(minutes=10)})
        o1 = Opus([[_fp("g1")]])                                   # the critical: FP is withheld
        r1 = await R.run(NOW, opus=o1, gatherer=Gatherer(), tools=[], execute=None, pace_s=0)
        assert (await Finding.get(calm[0].id)).ai_verdict in ("", None)      # medium waits for the batch
        o2 = Opus([[_fp("g1", exceptions=[{"id": calm[1].id[:8], "verdict": "unsure", "why": "runs from Temp"}])]])
        r2 = await R.run(NOW + timedelta(hours=6), opus=o2, gatherer=Gatherer(), tools=[], execute=None, pace_s=0)
        return r1, r2, await Finding.get(crit.id), [await Finding.get(f.id) for f in calm], o2
    r1, r2, crit, calm, o2 = asyncio.run(go())
    assert r1["groups"] == 1 and not r1["batch_due"]
    assert crit.ai_verdict == "unsure" and crit.ai_by == f"ai:{OPUS}"            # critical never FP
    assert r2["batch_due"] and r2["findings"] == 3 and len(o2.calls) == 1        # 3 findings, one Opus call
    assert [f.ai_verdict for f in calm] == ["false_positive", "unsure", "false_positive"]
    assert calm[0].ai_reasoning.startswith("[group of 3 on 3 host(s)]")
    assert "[exception: runs from Temp]" in calm[1].ai_reasoning
    assert "GROUP g1" in o2.calls[0][1]["content"] and "edge_attacks:" in o2.calls[0][0]["content"]


def test_opus_may_ask_for_one_kql_check_and_decides_again(monkeypatch):
    _patch(monkeypatch)

    async def fake_kql(kql, source):
        return {"rows": [{"Devices": 41}], "count": 1, "kql": kql}
    monkeypatch.setattr(R, "run_kql", fake_kql)

    async def go():
        await _db("review_need")
        f = F(1, "h1", sev="high")
        await Finding(**f.model_dump()).insert()
        o = Opus([[{"id": "g1", "verdict": "unsure", "checklist": {"benign_explanation": "none"},
                    "need": {"kql": "DeviceProcessEvents | where Timestamp > ago(30d) | summarize dcount(DeviceId)",
                             "source": "mde"}}],
                  [_fp("g1", reasoning="on 41 devices, vendor updater")]])
        await R.run(NOW, opus=o, gatherer=Gatherer(), tools=[], execute=None, pace_s=0)
        return await Finding.get(f.id), o
    f, o = asyncio.run(go())
    assert f.ai_verdict == "false_positive" and len(o.calls) == 2
    assert "REQUESTED CHECK mde KQL" in o.calls[1][1]["content"]
    assert any(e.startswith("check: mde KQL") for e in f.ai_evidence)


def test_opus_unavailable_records_no_verdict(monkeypatch):
    _patch(monkeypatch)

    class Down:
        cache_system = False

        async def chat(self, *a):
            raise RuntimeError("budget exceeded")

    async def go():
        await _db("review_fallback")
        hi, lo = F(1, "h1", sev="high", det="exfil_patterns", ind="curl to trycloudflare"), F(2, "h2", sev="low")
        await Finding(**hi.model_dump()).insert(); await Finding(**lo.model_dump()).insert()
        r = await R.run(NOW, opus=Down(), gatherer=Gatherer(), tools=[], execute=None, pace_s=0)
        return r, await Finding.get(hi.id), await Finding.get(lo.id)
    r, hi, lo = asyncio.run(go())
    assert r["fallback"] == 2
    # no Mistral verdict: both stay open for the next run or a manual pass
    assert not hi.ai_verdict and not lo.ai_verdict and not hi.ai_by
    assert "Opus unavailable" in hi.ai_error and "Opus unavailable" in lo.ai_error


def test_review_mode_needs_claude(monkeypatch):
    assert R.enabled_review()
    monkeypatch.setenv("SHADOW_AI_MODE", "classic")
    assert not R.enabled_review()
    monkeypatch.delenv("SHADOW_AI_MODE")
    monkeypatch.setenv("SHADOW_LLM", "mistral")
    assert not R.enabled_review()


def test_the_case_file_reaches_opus_with_secrets_redacted_and_ids_masked(monkeypatch):
    _patch(monkeypatch)

    async def go():
        await _db("review_clean")
        f = F(1, "h1", sev="high", det="lolbin_abuse",
              ind="curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456' --password=Hunter2pass "
                  "arn:aws:iam::111122223333:role/x")
        await Finding(**f.model_dump()).insert()
        o = Opus([[_fp("g1")]])
        await R.run(NOW, opus=o, gatherer=Gatherer(), tools=[], execute=None, pace_s=0)
        return o.calls[0][1]["content"]
    body = asyncio.run(go())
    assert "abcdefghijklmnopqrstuvwxyz123456" not in body and "3456>" in body     # last 4 kept
    assert "Hunter2pass" not in body and "111122223333" not in body


def test_environment_knowledge_is_in_the_cached_prompt(monkeypatch):
    monkeypatch.setenv("SHADOW_ENV_NOTES", "- build-01 runs nightly pentests")
    p = R.system_prompt("short")
    assert "IronWatch" in p and "203.0.113.10" in p and "build-01 runs nightly pentests" in p


def test_depth_scales_with_need_and_the_trail_is_stored(monkeypatch):
    _patch(monkeypatch)
    calls = []

    async def fake_need(need, f, execute):
        calls.append(need["tool"])
        return need["tool"], ({"error": "timeout"} if need["tool"] == "boom" else {"rows": [need["tool"]]})
    monkeypatch.setattr(R, "run_need", fake_need)
    unsure = lambda t: {"id": "g1", "verdict": "unsure", "checklist": {"benign_explanation": "none", "missing": "edge logs"},
                        "need": {"tool": t}}

    async def go():
        await _db("review_depth")
        calm = F(1, "h1", sev="low")
        await Finding(**calm.model_dump()).insert()
        # routine but unsure: up to 4 checks, an errored one retried for free
        o = Opus([[unsure("boom")], [unsure("a")], [unsure("b")], [unsure("c")], [unsure("d")],
                  [{**unsure("e"), "need": None}]])
        await R.run(NOW, opus=o, gatherer=Gatherer(), tools=[], execute=None, pace_s=0)
        routine_calls = list(calls)
        f = await Finding.get(calm.id)
        trail = await R._db()[R.TRAIL_COLL].find_one({"_id": f.ai_trail_id})
        return routine_calls, f, trail
    routine_calls, f, trail = asyncio.run(go())
    assert routine_calls[:5] == ["boom", "a", "b", "c", "d"]          # 1 retry + 4 checks
    assert f.ai_trail_id and trail["finding_ids"] == [f.id]
    assert [c["what"] for c in trail["checks"] if not c["what"].startswith("AUTO")] == ["boom", "a", "b", "c", "d"]
    assert trail["decision"]["checklist"]["missing"] == "edge logs"
    assert f.ai_evidence[0] == "missing: edge logs"


def test_prefetch_looks_up_public_ips_at_the_edge_but_never_the_shared_nat():
    seen = []

    async def ex(tool, args):
        seen.append((tool, args["ip"], args["source"]))
        return {"rows": []}
    f = F(1, "h1", det="edge_attacks", ind="198.51.100.44 and 203.0.113.10 hit /actuator")
    out = asyncio.run(R.prefetch(f, ex))
    assert seen == [("hunt_vlogs", "198.51.100.44", "edge")]
    assert out[0]["what"].startswith("AUTO edge activity of 198.51.100.44")
