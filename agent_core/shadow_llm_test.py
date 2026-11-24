"""Claude (Opus) on Bedrock for /shadow only: backend selection, the separate "shadow" budget,
Converse extended thinking, the in-app story report writer and the llm-check hints."""
from __future__ import annotations

import asyncio

import mongomock
import pytest

from agent_core import backend as B
from agent_core import budget

OPUS = "apac.anthropic.claude-opus-test-v1:0"


@pytest.fixture
def claude(monkeypatch):
    monkeypatch.setenv("SHADOW_LLM", "claude")
    monkeypatch.setenv("SHADOW_CLAUDE_MODEL", OPUS)
    monkeypatch.setenv("SHADOW_CLAUDE_TRANSPORT", "runtime")


@pytest.fixture
def usage(monkeypatch):
    col = mongomock.MongoClient().db.bedrock_usage
    monkeypatch.setattr(budget, "_col", lambda: col)
    return col


# ── selection ────────────────────────────────────────────────────────────────

def test_default_is_claude_once_a_model_is_set_and_mistral_on_request_raptor_untouched(monkeypatch):
    monkeypatch.delenv("SHADOW_LLM", raising=False)
    monkeypatch.delenv("SHADOW_CLAUDE_MODEL", raising=False)
    monkeypatch.setattr(B, "DEFAULT_SHADOW_CLAUDE_MODEL", "")
    assert B.shadow_llm() == "mistral"                             # no id yet: stays on Mistral
    monkeypatch.setattr(B, "DEFAULT_SHADOW_CLAUDE_MODEL", OPUS)
    assert B.shadow_llm() == "claude" and B.shadow_model_id() == OPUS
    monkeypatch.setenv("SHADOW_LLM", "mistral")
    monkeypatch.setenv("AGENT_BACKEND", "mantle")
    b = B.get_shadow_backend()
    assert isinstance(b, B.MantleBackend) and getattr(b, "budget_scope", "agent") == "agent"
    assert B.shadow_model_id().startswith("mistral.")


def test_claude_on_bedrock_runtime_is_charged_to_the_shadow_budget(claude, monkeypatch):
    monkeypatch.setenv("SHADOW_LLM", "claude")
    b = B.get_shadow_backend()
    assert isinstance(b, B.BedrockBackend) and b.model_id == OPUS and b.budget_scope == "shadow"
    assert b.thinking_budget == 0                                  # tool loops never think
    assert B.get_shadow_backend(thinking=True).thinking_budget == 6000
    monkeypatch.setenv("AGENT_BACKEND", "mantle")
    assert isinstance(B.get_backend(""), B.MantleBackend)          # RAPTOR still on Mistral
    assert getattr(B.get_backend(""), "budget_scope", "agent") == "agent"


def test_claude_via_mantle_uses_the_anthropic_path(claude, monkeypatch):
    monkeypatch.setenv("SHADOW_CLAUDE_TRANSPORT", "mantle")
    b = B.get_shadow_backend()
    assert isinstance(b, B.MantleBackend) and b.protocol == "anthropic" and b.budget_scope == "shadow"


def test_claude_without_a_model_id_fails_loudly(monkeypatch):
    monkeypatch.setenv("SHADOW_LLM", "claude")
    monkeypatch.setenv("SHADOW_CLAUDE_MODEL", "")
    with pytest.raises(B.OllamaUnavailableError, match="SHADOW_CLAUDE_MODEL"):
        B.get_shadow_backend()


# ── budget ───────────────────────────────────────────────────────────────────

def test_shadow_spend_never_counts_against_the_raptor_cap(usage, monkeypatch):
    monkeypatch.setenv("AGENT_MONTHLY_BUDGET_USD", "10")
    monkeypatch.setenv("SHADOW_CLAUDE_MONTHLY_BUDGET_USD", "5")
    usage.insert_one({"month": budget._month_key(), "cost_usd": 4.0})          # old row, no scope = agent
    budget.record(OPUS, 400_000, 0, scope="shadow")                            # 400k in at $0.015/1k = $6
    assert budget.month_to_date_usd() == pytest.approx(4.0)
    assert budget.month_to_date_usd(scope="shadow") == pytest.approx(6.0)
    assert not budget.is_over_budget() and budget.is_over_budget("shadow")
    assert budget.summary("shadow")["calls_this_month"] == 1


def test_opus_defaults_to_a_conservative_price(monkeypatch):
    for k in ("OPUS_PRICE_IN_PER_1K", "OPUS_PRICE_OUT_PER_1K"):
        monkeypatch.delenv(k, raising=False)
    assert budget._prices_per_1k(OPUS) == (0.015, 0.075)
    assert budget._prices_per_1k("anthropic.claude-sonnet-x") == (0.003, 0.015)


# ── Converse call ────────────────────────────────────────────────────────────

class FakeRuntime:
    def __init__(self):
        self.kwargs = None

    def converse(self, **kw):
        self.kwargs = kw
        return {"output": {"message": {"content": [{"reasoningContent": {"reasoningText": {"text": "hmm"}}},
                                                   {"text": "OK"}]}},
                "usage": {"inputTokens": 10, "outputTokens": 2, "totalTokens": 12}, "stopReason": "end_turn"}


def test_thinking_call_shape_and_shadow_scope(claude, usage, monkeypatch):
    rt = FakeRuntime()
    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: rt)
    b = B.get_shadow_backend(thinking=True)
    text, calls = asyncio.run(b.chat([{"role": "system", "content": "be careful"},
                                      {"role": "user", "content": "hi"}], []))
    assert text == "OK" and calls == []                            # the thinking block is not in the answer
    kw = rt.kwargs
    assert kw["modelId"] == OPUS and kw["system"] == [{"text": "be careful"}]
    assert kw["additionalModelRequestFields"] == {"thinking": {"type": "adaptive"}, "output_config": {"effort": "medium"}}
    assert "temperature" not in kw["inferenceConfig"]
    assert usage.find_one({})["scope"] == "shadow"


def test_over_the_shadow_cap_refuses_before_calling(claude, usage, monkeypatch):
    monkeypatch.setenv("SHADOW_CLAUDE_MONTHLY_BUDGET_USD", "1")
    usage.insert_one({"month": budget._month_key(), "cost_usd": 2.0, "scope": "shadow"})
    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: pytest.fail("must not call Bedrock"))
    with pytest.raises(B.OllamaUnavailableError, match="budget exceeded"):
        asyncio.run(B.get_shadow_backend().chat([{"role": "user", "content": "hi"}], []))


# ── story report writer ──────────────────────────────────────────────────────

def test_parse_sections_and_fit_bundle():
    from shadow_hunter import stories as S
    assert S.parse_sections('```json\n{"sections": [{"heading": "Status and summary", "body": "x"}, {"x": 1}]}\n```') \
        == [{"heading": "Status and summary", "body": "x"}]
    assert S.parse_sections("no json") == []
    assert S.parse_sections('{"sections": [{"heading": "Impact", "body": "line one\nline two"}]}') \
        == [{"heading": "Impact", "body": "line one\nline two"}]       # raw newline inside the string
    big = {"findings": [{"id": str(i), "raw": {"blob": "z" * 5000}} for i in range(100)],
           "vlogs": {"edge": {"1.2.3.4": {"rows": [{"n": i} for i in range(40)]}}}}
    out = S.fit_bundle(big, limit=60_000)
    assert len(out) <= 60_000 and '"_cut"' in out


def test_report_writer_is_on_with_claude_unless_switched_off(monkeypatch):
    from shadow_hunter import stories as S
    monkeypatch.setenv("SHADOW_LLM", "claude")
    monkeypatch.delenv("SHADOW_STORY_REPORTS", raising=False)
    assert S.report_writer_enabled()                               # on by default on Claude
    monkeypatch.setenv("SHADOW_STORY_REPORTS", "0")
    assert not S.report_writer_enabled()
    monkeypatch.setenv("SHADOW_STORY_REPORTS", "1")
    assert S.report_writer_enabled()
    monkeypatch.setenv("SHADOW_LLM", "mistral")
    assert not S.report_writer_enabled()                           # never an in-app report on Mistral


def test_in_app_report_is_written_in_the_background_and_stored(claude, monkeypatch):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    from shadow_hunter import stories as S
    from shadow_hunter.models import AuditLog, Finding, Story
    monkeypatch.setenv("SHADOW_STORY_REPORTS", "1")
    seen = {}

    class Fake:
        async def chat(self, messages, tools):
            seen["messages"] = messages
            return '{"sections": [{"heading": "Status and summary", "body": "Contained; token Bearer abcdefghijklmnop1234"}]}', []
    monkeypatch.setattr(B, "get_shadow_backend", lambda thinking=False: (seen.setdefault("thinking", thinking), Fake())[1])

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["shadow_llm_report"], document_models=[Finding, AuditLog, Story])
        st = Story(title="t", finding_ids=[], severity="high")
        await st.insert()
        req = await S.request_report(st.id, "riley", "https://uat.example/")
        await asyncio.gather(*list(S._WRITING))
        return req, await Story.get(st.id)
    req, st = asyncio.run(go())
    assert req["writing"] and req["prompt"]
    assert seen["thinking"] is True and "STORY BUNDLE" in seen["messages"][1]["content"]
    assert st.report["by"] == f"ai:{OPUS}" and st.report_requested_at is None
    assert "abcdefghijklmnop1234" not in st.report["sections"][0]["body"]


def test_llm_check_explains_an_access_error(claude, monkeypatch):
    from app.views import shadow_views

    class Denied:
        async def chat(self, *_):
            raise B.OllamaUnavailableError("Bedrock converse failed: AccessDeniedException: not authorized to perform "
                                           "bedrock:InvokeModel")
    monkeypatch.setattr(B, "get_shadow_backend", lambda thinking=False: Denied())
    monkeypatch.setattr(budget, "summary", lambda scope="agent": {"scope": scope})
    async def no_models():
        raise B.OllamaUnavailableError("offline")
    monkeypatch.setattr(B, "mantle_models", no_models)

    async def variants(model):
        return [{"protocol": "openai", "model": model, "ok": True}]
    monkeypatch.setattr(shadow_views, "_claude_variants", variants)
    out = asyncio.run(shadow_views.shadow_llm_check())
    assert out["llm"] == "claude" and out["model"] == OPUS and not out["ok"]
    assert "inference profile ARN" in out["hint"] and out["budget"] == {"scope": "shadow"}
    assert out["variants"][0]["ok"]                                 # the other Mantle paths were tried


def test_prompt_caching_marks_the_system_prompt_and_bills_cache_reads_cheaply(claude, usage, monkeypatch):
    class Cached(FakeRuntime):
        def converse(self, **kw):
            out = super().converse(**kw)
            out["usage"] = {"inputTokens": 1000, "outputTokens": 100, "cacheReadInputTokens": 20000,
                            "cacheWriteInputTokens": 0}
            return out
    rt = Cached()
    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: rt)
    b = B.get_shadow_backend()
    b.cache_system = True
    asyncio.run(b.chat([{"role": "system", "content": "stable guide"}, {"role": "user", "content": "case"}], []))
    assert rt.kwargs["system"] == [{"text": "stable guide"}, {"cachePoint": {"type": "default"}}]
    assert usage.find_one({})["input_tokens"] == 3000          # 1000 + 20000 x 0.1
    assert B.cache_billed_input(0, 0, 1000) == 1250


def test_settings_shows_the_shadow_budget_apart_from_the_agent_budget(claude, usage):
    from app.views import edr_triage_views as V
    budget.record(OPUS, 100_000, 1_000, scope="shadow")
    budget.record("mistral.mistral-large-3-675b-instruct", 100_000, 1_000)
    d = asyncio.run(V.edr_settings())
    sb = d["shadow_budget"]
    assert sb["enabled"] and sb["model"] == OPUS and sb["calls_this_month"] == 1
    assert sb["month_to_date_usd"] == pytest.approx(1.575) and d["month_to_date_usd"] == pytest.approx(0.0608, abs=1e-3)
    html = V._render_settings_page()
    assert 'id="sSpendBig"' in html and "SHADOW_CLAUDE_MONTHLY_BUDGET_USD" in html


def test_mantle_models_lists_ids_with_the_project_header_and_sigv4(monkeypatch):
    import httpx
    seen = {}
    monkeypatch.setattr(B, "_sigv4_headers", lambda m, url, body, h, region, svc: {**h, "Authorization": "AWS4-HMAC-SHA256 x"})

    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, headers):
            seen.update(url=url, headers=headers)
            return httpx.Response(200, text='{"data": [{"id": "mistral.mistral-large-3-675b-instruct"}, {"id": "anthropic.claude-opus-x"}]}')
    monkeypatch.setattr(httpx, "AsyncClient", C)
    monkeypatch.delenv("MANTLE_AUTH", raising=False)
    ids = asyncio.run(B.mantle_models())
    assert ids == ["anthropic.claude-opus-x", "mistral.mistral-large-3-675b-instruct"]
    assert seen["url"].endswith("/v1/models") and seen["headers"]["OpenAI-Project"].startswith("proj_")
    assert seen["headers"]["Authorization"].startswith("AWS4")


def test_mantle_claude_call_sends_effort_not_temperature(claude, usage, monkeypatch):
    import sys
    import types
    seen = []

    class Msgs:
        async def create(self, **kw):
            if "temperature" in kw:
                raise TypeError("AsyncMessages.create() got an unexpected keyword argument 'temperature'")
            seen.append(kw)
            return types.SimpleNamespace(content=[types.SimpleNamespace(type="thinking", thinking="hmm"),
                                                  types.SimpleNamespace(type="text", text="OK")],
                                         usage=types.SimpleNamespace(input_tokens=5, output_tokens=1,
                                                                     cache_read_input_tokens=0,
                                                                     cache_creation_input_tokens=0),
                                         stop_reason="end_turn")

    class Client:
        def __init__(self, **kw):
            assert "api_key" not in kw                       # pod role (SigV4), never MANTLE_API
            self.messages = Msgs()
    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(AsyncAnthropicBedrockMantle=Client))
    monkeypatch.setenv("SHADOW_CLAUDE_TRANSPORT", "mantle")
    monkeypatch.setenv("MANTLE_API", "rejected-key")
    text, _ = asyncio.run(B.get_shadow_backend().chat([{"role": "user", "content": "hi"}], []))
    assert text == "OK" and seen[0]["output_config"] == {"effort": "medium"} and "thinking" not in seen[0]
    asyncio.run(B.get_shadow_backend(thinking=True).chat([{"role": "user", "content": "hi"}], []))
    assert seen[1]["thinking"] == {"type": "adaptive"} and seen[1]["output_config"] == {"effort": "medium"}
    assert usage.find_one({})["scope"] == "shadow"


def test_default_is_the_india_profile_on_runtime_and_effort_fields_fall_back_once(monkeypatch, usage):
    from botocore.exceptions import ClientError
    for k in ("SHADOW_LLM", "SHADOW_CLAUDE_MODEL", "SHADOW_CLAUDE_TRANSPORT"):
        monkeypatch.delenv(k, raising=False)
    b = B.get_shadow_backend()
    assert isinstance(b, B.BedrockBackend) and b.model_id == "in.anthropic.claude-opus-5" and b.claude_effort == "medium"
    calls = []

    class Picky(FakeRuntime):
        def converse(self, **kw):
            calls.append(kw)
            if "additionalModelRequestFields" in kw:
                raise ClientError({"Error": {"Code": "ValidationException", "Message": "output_config not permitted"}},
                                  "Converse")
            return super().converse(**kw)
    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: Picky())
    text, _ = asyncio.run(b.chat([{"role": "user", "content": "hi"}], []))
    assert text == "OK" and len(calls) == 2 and "additionalModelRequestFields" not in calls[1]
    assert "temperature" not in calls[1]["inferenceConfig"]
