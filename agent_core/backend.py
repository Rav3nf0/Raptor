"""LLM backend — model-agnostic interface.

Primary: BedrockBackend (Mistral Large 3, in-region ap-south-1 via Converse)
Alt:     OllamaBackend (DeepSeek R1 8B, on-prem) / GeminiBackend (legacy external)
Fallback: existing hardcoded playbooks (triggered by OllamaUnavailableError)

R1 does not support native tool_calls in Ollama's /api/chat response.
Tool calls are parsed from the text content using XML-style markers:
  <tool_call>{"name": "vt_lookup_hash", "args": {"sha256": "abc..."}}</tool_call>
"""
from __future__ import annotations

import json
import logging
import os
import re
from abc import ABC, abstractmethod
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


# --- Per-run sampling-temperature override ---------------------------------
# Temperature is normally global (BEDROCK_TEMPERATURE, default 0 since 2026-09-01).
# Measuring a temperature change must NOT be done by flipping that env var:
# it would apply to every alert in flight at once, so a regression on a family
# we're not looking at would only surface after the damage. This ContextVar pins
# ONE pipeline run to a different temperature while every other run keeps the
# deployed default.
#
# Unset (None) is the only state the normal path ever sees, and it resolves to
# exactly the env value used before — so with no override requested this is a
# no-op by construction.
#
# NOTE: this covers the agent-loop backends in this module only. The KQL
# auto-fixer (lib/mde_client.py) builds its own Gemini payload at its own
# temperature 0.0 and is deliberately untouched.
_TEMPERATURE_OVERRIDE: ContextVar[float | None] = ContextVar(
    "llm_temperature_override", default=None,
)


@contextmanager
def temperature_override(value: float | None):
    """Pin sampling temperature for the duration of this context.

    Propagates into `asyncio.to_thread` calls made inside it (to_thread runs the
    target under a copy of the calling context), which is how the sync Bedrock
    and SigV4 paths inherit it. Passing None is a no-op, so callers can forward
    an optional parameter straight through without branching.
    """
    if value is None:
        yield
        return
    token = _TEMPERATURE_OVERRIDE.set(float(value))
    try:
        yield
    finally:
        _TEMPERATURE_OVERRIDE.reset(token)


def _effective_temperature(default: float) -> float:
    """The override if one is pinned for this run, else the configured default."""
    override = _TEMPERATURE_OVERRIDE.get()
    return default if override is None else override


class OllamaUnavailableError(Exception):
    pass


@dataclass
class ToolCall:
    name: str
    args: dict


class LLMBackend(ABC):
    @abstractmethod
    async def chat(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        """Send messages + tool definitions. Returns (content, tool_calls)."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the backend is reachable."""
        ...


_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*(\{.*?})\s*</tool_call>",
    re.DOTALL | re.IGNORECASE,
)

_FINAL_VERDICT_RE = re.compile(
    r"<final_verdict>\s*(\{.*?})\s*</final_verdict>",
    re.DOTALL | re.IGNORECASE,
)


def _parse_tool_calls(text: str, valid_names: set[str]) -> list[ToolCall]:
    """Parse tool calls from both <thinking> and content blocks."""
    calls: list[ToolCall] = []
    for match in _TOOL_CALL_RE.finditer(text):
        try:
            payload = json.loads(match.group(1))
            name = payload.get("name", "")
            args = payload.get("args", payload.get("arguments", {}))
            if name and name in valid_names and isinstance(args, dict):
                calls.append(ToolCall(name=name, args=args))
        except json.JSONDecodeError:
            logger.debug("Failed to parse tool_call JSON: %s", match.group(1)[:100])
    return calls


class OllamaBackend(LLMBackend):
    def __init__(self):
        self.base_url = (os.getenv("LOCAL_LLM_URL") or os.getenv("OLLAMA_URL", "http://localhost:80")).rstrip("/")
        self.model = os.getenv("LOCAL_LLM_MODEL") or os.getenv("OLLAMA_MODEL", "deepseek-r1:8b")
        self.timeout = int(os.getenv("OLLAMA_TIMEOUT", "600"))
        # Output token cap per call. R1 is a REASONING model — its <think> chain
        # plus the tool-call/verdict must fit here, or it gets cut off mid-thought
        # and never emits a verdict (→ 0.3 NEEDS_L2 fallback). Keep this generous.
        self.num_predict = int(os.getenv("OLLAMA_NUM_PREDICT", "4096"))
        # Set context window explicitly to avoid KV-cache saturation (quadratic
        # slowdown) as the ReAct message history grows across iterations.
        self.num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))
        # One retry absorbs a single transient slow/timed-out call without
        # failing the whole triage and falling back to the playbook.
        self.max_retries = int(os.getenv("OLLAMA_MAX_RETRIES", "1"))
        self.retry_backoff = float(os.getenv("OLLAMA_RETRY_BACKOFF", "2.0"))

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def chat(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        valid_names = {t["name"] for t in tools}

        # Inject tool definitions into the last user message as text
        tool_block = _format_tools_for_prompt(tools)
        augmented = _augment_last_user_message(messages, tool_block)

        import asyncio

        payload = {
            "model": self.model,
            "messages": augmented,
            "stream": False,
            "options": {
                "temperature": _effective_temperature(0.1),
                "num_predict": self.num_predict,
                "num_ctx": self.num_ctx,
            },
        }

        body = None
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                    if resp.status_code != 200:
                        raise OllamaUnavailableError(f"Ollama returned {resp.status_code}: {resp.text[:200]}")
                    body = resp.json()
                break
            except httpx.ConnectError as exc:
                last_exc = OllamaUnavailableError(f"Ollama unreachable at {self.base_url}: {exc}")
            except httpx.TimeoutException as exc:
                last_exc = OllamaUnavailableError(f"Ollama timed out after {self.timeout}s")
            if attempt < self.max_retries:
                logger.warning(
                    "Ollama chat attempt %d/%d failed (%s), retrying in %.1fs",
                    attempt + 1, self.max_retries + 1, last_exc, self.retry_backoff,
                )
                await asyncio.sleep(self.retry_backoff)
        if body is None:
            raise last_exc or OllamaUnavailableError("Ollama call failed")

        msg = body.get("message", {})
        content = msg.get("content", "")

        thinking = ""
        if "<think>" in content:
            think_match = re.search(r"<think>(.*?)</think>", content, re.DOTALL)
            if think_match:
                thinking = think_match.group(1)
                content = content[content.rfind("</think>") + len("</think>"):].strip()

        full_text = thinking + "\n" + content
        tool_calls = _parse_tool_calls(full_text, valid_names)

        return content, tool_calls


def _format_tools_for_prompt(tools: list[dict]) -> str:
    lines = ["You have access to the following tools. To call a tool, emit exactly:"]
    lines.append('<tool_call>{"name": "tool_name", "args": {"param": "value"}}</tool_call>')
    lines.append("")
    lines.append("Available tools:")
    for t in tools:
        params = t.get("parameters", {}).get("properties", {})
        required = t.get("parameters", {}).get("required", [])
        param_desc = ", ".join(
            f"{k}{'*' if k in required else ''}: {v.get('type', 'string')}"
            for k, v in params.items()
        )
        lines.append(f"- {t['name']}({param_desc}): {t['description']}")
    lines.append("")
    lines.append("When investigation is complete, emit:")
    lines.append('<final_verdict>{"triage_class": "...", "confidence": 0.0, "reasoning": "...", "actions": []}</final_verdict>')
    return "\n".join(lines)


def _augment_last_user_message(messages: list[dict], tool_block: str) -> list[dict]:
    """Insert tool definitions into the first user message (system prompt area)."""
    result = list(messages)
    for i, msg in enumerate(result):
        if msg.get("role") == "user":
            result[i] = {**msg, "content": tool_block + "\n\n" + msg["content"]}
            break
    return result


# Alert types where raw context (ARNs, instance IDs, command lines) is the core
# evidence — must stay on Ollama (internal). Everything else routes to Gemini if
# an API key is configured.
_OLLAMA_ONLY_ALERT_TYPES = frozenset({
    "cloudtrail", "privesc", "credential_access",
    "encoded_powershell", "lolbin", "guardduty",
    "netskope",           # carries usernames + internal hostnames — keep on-prem
    "endpoint_process",   # carries raw command lines — keep on-prem
    "upwind",             # carries cloud account ids + internal resource names — keep on-prem
})


class GeminiBackend(LLMBackend):
    """Gemini backend using native function calling via google-genai SDK.

    Used for alert types where evidence is public (hashes, domains, IPs) and
    the sanitizer has been applied to strip any residual sensitive identifiers.
    Much faster than Ollama (~5–30s vs 6–8 min) and supports native tool use.
    """

    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model   = os.getenv("GEMINI_AGENT_MODEL", "gemini-2.0-flash")

    async def health_check(self) -> bool:
        return bool(self.api_key)

    async def chat(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        import asyncio
        return await asyncio.to_thread(self._chat_sync, messages, tools)

    def _chat_sync(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        from google import genai
        from google.genai import types as gtypes

        client = genai.Client(api_key=self.api_key)
        valid_names = {t["name"] for t in tools}

        # Build FunctionDeclarations from our OpenAPI-style tool dicts
        func_decls = [
            gtypes.FunctionDeclaration(
                name=t["name"],
                description=t.get("description", ""),
                parameters=t.get("parameters"),
            )
            for t in tools
        ]
        gemini_tools = [gtypes.Tool(function_declarations=func_decls)] if func_decls else []

        # Convert messages to Gemini Contents — system prompt becomes system_instruction
        system_text = ""
        contents: list = []
        for msg in messages:
            role    = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_text = content
                continue
            gemini_role = "model" if role == "assistant" else "user"
            contents.append(gtypes.Content(
                role=gemini_role,
                parts=[gtypes.Part(text=content)],
            ))

        config = gtypes.GenerateContentConfig(
            tools=gemini_tools,
            temperature=_effective_temperature(0.1),
            system_instruction=system_text or None,
        )

        response = client.models.generate_content(
            model=self.model,
            contents=contents,
            config=config,
        )

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []

        candidate = response.candidates[0] if response.candidates else None
        if not candidate:
            return "", []

        for part in candidate.content.parts:
            fc = getattr(part, "function_call", None)
            if fc and fc.name in valid_names:
                tool_calls.append(ToolCall(
                    name=fc.name,
                    args=dict(fc.args) if fc.args else {},
                ))
            elif getattr(part, "text", None):
                text_parts.append(part.text)

        return "\n".join(text_parts), tool_calls


def _to_converse_messages(messages: list[dict]) -> tuple[list[dict], list[dict]]:
    """Convert the loop's text messages into Bedrock Converse format.

    - `system` messages are pulled into a separate Converse `system` list.
    - user/assistant messages become {"role", "content":[{"text": ...}]}.
    - Consecutive same-role messages are merged (Converse requires alternation).
    - Empty content is replaced (Converse rejects empty content blocks).
    - The conversation is forced to start with a user turn.
    """
    system: list[dict] = []
    conv: list[dict] = []
    for m in messages:
        role = m.get("role", "user")
        text = (m.get("content") or "").strip()
        if role == "system":
            if text:
                system.append({"text": text})
            continue
        crole = "assistant" if role == "assistant" else "user"
        if not text:
            text = "(no content)"
        if conv and conv[-1]["role"] == crole:
            conv[-1]["content"].append({"text": text})
        else:
            conv.append({"role": crole, "content": [{"text": text}]})
    if conv and conv[0]["role"] != "user":
        conv.insert(0, {"role": "user", "content": [{"text": "Begin the investigation."}]})
    return system, conv


def _to_converse_tool_config(tools: list[dict]) -> dict | None:
    """Build a Converse toolConfig from our OpenAPI-style tool dicts."""
    if not tools:
        return None
    specs = []
    for t in tools:
        schema = t.get("parameters") or {"type": "object", "properties": {}}
        specs.append({"toolSpec": {
            "name": t["name"],
            "description": t.get("description", ""),
            "inputSchema": {"json": schema},
        }})
    return {"tools": specs}


def cache_billed_input(uncached: int, cache_read: int = 0, cache_write: int = 0) -> int:
    """Input tokens as billed: cache reads ~0.1x, cache writes ~1.25x of the input price."""
    return int((uncached or 0) + 0.1 * (cache_read or 0) + 1.25 * (cache_write or 0))


def _boto_config(timeout_s: int = 0):
    """botocore read timeout; Opus with thinking can take minutes (default is 60 s)."""
    if not timeout_s:
        return None
    from botocore.config import Config
    return Config(read_timeout=int(timeout_s), connect_timeout=10, retries={"max_attempts": 2, "mode": "standard"})


class BedrockBackend(LLMBackend):
    """AWS Bedrock Converse backend — in-region (ap-south-1), native tool use.

    Default model: Mistral Large 3 (mistral.mistral-large-3-675b-instruct), an
    in-region ap-south-1 model — invoked by its bare foundation-model id, no
    inference profile needed. Because inference stays inside the AWS trust
    boundary, NO sanitizer is applied (unlike GeminiBackend) — the agent gets
    full, unredacted context.

    Uses native Converse toolConfig for tool calling, and ALSO parses the text
    `<tool_call>` / `<final_verdict>` protocol as a fallback, so it is fully
    compatible with the existing ReAct loop regardless of which form the model
    emits. On any API failure it raises OllamaUnavailableError so the pipeline
    falls back to the deterministic playbook.

    Config (env):
      AGENT_MODEL          default mistral.mistral-large-3-675b-instruct
      AWS_REGION           default ap-south-1
      BEDROCK_MAX_TOKENS   default 8192
      BEDROCK_TEMPERATURE  default 0 (see __init__)
    """

    # Which monthly cap a call counts against (agent_core/budget.py); /shadow's Claude
    # backend sets "shadow" so its spend can never stop RAPTOR triage.
    budget_scope = "agent"
    # Claude extended thinking via Converse additionalModelRequestFields; 0 = off. Only
    # for single-shot calls: a tool loop would have to hand thinking blocks back each turn.
    thinking_budget = 0
    # Prompt caching (Claude): a cache point after the system prompt, so a stable prefix is
    # billed at ~10% when the next call repeats it within ~5 minutes.
    cache_system = False

    def __init__(self) -> None:
        self.region = os.getenv("AWS_REGION", "ap-south-1")
        self.model_id = os.getenv("AGENT_MODEL", "mistral.mistral-large-3-675b-instruct")
        self.max_tokens = int(os.getenv("BEDROCK_MAX_TOKENS", "8192"))
        # Default 0, not 0.1. Sampling variance was the binding accuracy constraint:
        # measured 2026-08-28 over three arms x 3 runs on 4 tickets, verdict stability
        # 0.750 -> 1.000 and accuracy 0.667 -> 1.000 at temperature 0, with no regression
        # across 18 runs on three human-AUTO_CLOSED_TP tickets (a real threat was never
        # auto-closed). At 0.1 the same tickets returned a different verdict on ~1 run in
        # 4, which made every single-run "did the fix work?" check a coin flip.
        #
        # Known trade-offs, deliberately accepted: run-to-run variance had been acting as
        # an accidental retry (DEMO-110734 reached the right verdict only on its third
        # attempt), and a flip-flopping verdict was a usable "model is unsure" signal that
        # ai_confidence does NOT provide (DEMO-110937 was wrong at 0.95). Neither survives
        # here. Also note this is not true determinism — MoE routing, batching and float
        # non-associativity remain — and it does nothing for variance that comes from the
        # EVIDENCE changing between runs (see the hunt-window anchoring issue).
        #
        # BEDROCK_TEMPERATURE still overrides, and it is mapped in lib/config's
        # _SECRET_ENV_MAP, so reverting to "0.1" is a secret change with no deploy.
        self.temperature = float(os.getenv("BEDROCK_TEMPERATURE", "0"))

    async def health_check(self) -> bool:
        import asyncio

        def _check() -> bool:
            try:
                import boto3
                boto3.client("sts", region_name=self.region).get_caller_identity()
                return True
            except Exception:
                return False

        return await asyncio.to_thread(_check)

    async def chat(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        import asyncio
        return await asyncio.to_thread(self._chat_sync, messages, tools)

    def _chat_sync(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError

        from agent_core import budget

        # Hard monthly budget guard — refuse before spending if over the cap.
        # Raising OllamaUnavailableError makes the pipeline fall back to the
        # deterministic playbook (fail safe to L2), not silently drop the alert.
        scope = self.budget_scope
        if budget.is_over_budget(scope):
            mtd, cap = budget.month_to_date_usd(scope=scope), budget.budget_usd(scope)
            logger.error("[BEDROCK] BUDGET EXCEEDED (%s): month-to-date $%.2f >= cap $%.2f — "
                         "refusing call, falling back to playbook", scope, mtd, cap)
            raise OllamaUnavailableError(
                f"Bedrock monthly budget exceeded (${mtd:.2f} >= ${cap:.2f})"
            )

        valid_names = {t["name"] for t in tools}
        system, conv = _to_converse_messages(messages)
        tool_config = _to_converse_tool_config(tools)

        kwargs: dict = {
            "modelId": self.model_id,
            "messages": conv,
            "inferenceConfig": {"maxTokens": self.max_tokens,
                                "temperature": _effective_temperature(self.temperature)},
        }
        if system:
            kwargs["system"] = system + ([{"cachePoint": {"type": "default"}}] if self.cache_system else [])
        if tool_config:
            kwargs["toolConfig"] = tool_config
        effort = (getattr(self, "claude_effort", "") or "").strip().lower()
        if effort:
            # Newer Claude (Opus 5, 2026-11): no temperature; depth is effort, and a call that
            # asked for thinking gets adaptive thinking rather than a fixed token budget.
            kwargs["inferenceConfig"].pop("temperature", None)
            extra: dict = {"output_config": {"effort": effort}}
            if int(self.thinking_budget or 0) > 0:
                extra["thinking"] = {"type": "adaptive"}
            kwargs["additionalModelRequestFields"] = extra
        elif int(self.thinking_budget or 0) > 0:
            # Claude requires the default temperature with thinking, and maxTokens above the budget.
            kwargs["additionalModelRequestFields"] = {
                "thinking": {"type": "enabled", "budget_tokens": int(self.thinking_budget)}}
            kwargs["inferenceConfig"].pop("temperature", None)
            kwargs["inferenceConfig"]["maxTokens"] = max(self.max_tokens, int(self.thinking_budget) + 2048)

        client = boto3.client("bedrock-runtime", region_name=self.region,
                              config=_boto_config(getattr(self, "timeout", 0)))
        try:
            resp = client.converse(**kwargs)
        except ClientError as exc:
            # If Bedrock rejects the effort/thinking fields for this model, run the call plain
            # once rather than fail it; the warning says which field to revisit.
            if not (effort and exc.response.get("Error", {}).get("Code") == "ValidationException"):
                raise OllamaUnavailableError(f"Bedrock converse failed ({self.model_id}): {exc}") from exc
            logger.warning("[BEDROCK] %s rejected effort/thinking fields, retrying without them: %s",
                           self.model_id, exc)
            kwargs.pop("additionalModelRequestFields", None)
            try:
                resp = client.converse(**kwargs)
            except (ClientError, BotoCoreError) as exc2:
                raise OllamaUnavailableError(f"Bedrock converse failed ({self.model_id}): {exc2}") from exc2
        except BotoCoreError as exc:
            raise OllamaUnavailableError(f"Bedrock converse failed ({self.model_id}): {exc}") from exc

        usage = resp.get("usage", {})
        in_eff = cache_billed_input(usage.get("inputTokens", 0), usage.get("cacheReadInputTokens", 0),
                                    usage.get("cacheWriteInputTokens", 0))
        cost = budget.record(self.model_id, in_eff, usage.get("outputTokens", 0), scope=scope)
        logger.info(
            "[BEDROCK] model=%s scope=%s in=%s out=%s total=%s cost=$%.4f mtd=$%.2f stop=%s",
            self.model_id, scope, usage.get("inputTokens"), usage.get("outputTokens"),
            usage.get("totalTokens"), cost, budget.month_to_date_usd(scope=scope), resp.get("stopReason"),
        )

        blocks = resp.get("output", {}).get("message", {}).get("content", []) or []
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for b in blocks:
            if b.get("text"):
                text_parts.append(b["text"])     # reasoningContent (thinking) blocks are left out
            tu = b.get("toolUse")
            if not tu:
                continue
            args = tu.get("input") or {}
            if tu.get("name") in valid_names:
                if isinstance(args, dict):
                    tool_calls.append(ToolCall(name=tu["name"], args=args))
            elif isinstance(args, dict) and "triage_class" in args:
                # Model concluded via an unregistered "verdict" tool — surface the
                # JSON as text so the loop's verdict parser picks it up.
                text_parts.append(json.dumps(args))

        content = "\n".join(text_parts)
        # Fallback: some models emit the text <tool_call> protocol instead of
        # (or in addition to) native toolUse blocks — parse those too.
        if not tool_calls:
            tool_calls = _parse_tool_calls(content, valid_names)
        return content, tool_calls


def _to_anthropic_messages(messages: list[dict]) -> tuple[str | None, list[dict]]:
    """Convert the loop's text messages into Anthropic Messages API format.

    system messages → a single `system` string; user/assistant → {role, content:str};
    consecutive same-role merged; conversation forced to start with user.
    """
    system_parts: list[str] = []
    conv: list[dict] = []
    for m in messages:
        role = m.get("role", "user")
        text = (m.get("content") or "").strip()
        if role == "system":
            if text:
                system_parts.append(text)
            continue
        crole = "assistant" if role == "assistant" else "user"
        if not text:
            text = "(no content)"
        if conv and conv[-1]["role"] == crole:
            conv[-1]["content"] += "\n\n" + text
        else:
            conv.append({"role": crole, "content": text})
    if conv and conv[0]["role"] != "user":
        conv.insert(0, {"role": "user", "content": "Begin the investigation."})
    return ("\n\n".join(system_parts) or None), conv


def _to_anthropic_tools(tools: list[dict]) -> list[dict] | None:
    """Build Anthropic Messages API tool defs from our OpenAPI-style tool dicts."""
    if not tools:
        return None
    return [
        {"name": t["name"], "description": t.get("description", ""),
         "input_schema": t.get("parameters") or {"type": "object", "properties": {}}}
        for t in tools
    ]


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    """Convert the loop's text messages into OpenAI Chat Completions format.

    OpenAI accepts system/user/assistant roles directly and does NOT require
    strict alternation, so this is mostly a passthrough — we only drop empty
    content and coerce roles into the allowed set.
    """
    out: list[dict] = []
    for m in messages:
        role = m.get("role", "user")
        text = (m.get("content") or "").strip()
        if role not in ("system", "user", "assistant"):
            role = "user"
        if not text:
            text = "(no content)"
        out.append({"role": role, "content": text})
    if not out:
        out.append({"role": "user", "content": "Begin the investigation."})
    return out


def _to_openai_tools(tools: list[dict]) -> list[dict] | None:
    """Build OpenAI Chat Completions tool defs from our OpenAPI-style tool dicts."""
    if not tools:
        return None
    return [
        {"type": "function", "function": {
            "name": t["name"],
            "description": t.get("description", ""),
            "parameters": t.get("parameters") or {"type": "object", "properties": {}},
        }}
        for t in tools
    ]


def _sigv4_headers(method: str, url: str, body: str, headers: dict,
                   region: str, service: str = "bedrock") -> dict:
    """SigV4-sign an HTTP request with the pod's IRSA credentials.

    Mirrors the anthropic SDK's Bedrock signer: SigV4Auth(creds, "bedrock", region).
    `body` MUST be the exact string sent as the request body — SigV4 hashes the
    payload, so the caller has to POST this same string (httpx content=body), NOT
    re-serialize it. Returns the full signed header set to send.
    """
    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    session = boto3.Session(region_name=region)
    creds = session.get_credentials()
    if not creds:
        raise OllamaUnavailableError("Mantle SigV4: could not resolve AWS credentials (IRSA)")
    req = AWSRequest(method=method.upper(), url=url, data=body, headers=headers)
    SigV4Auth(creds, service, region).add_auth(req)
    prepped = req.prepare()
    return {k: v for k, v in dict(prepped.headers).items() if v is not None}


async def mantle_models() -> list[str]:
    """Model ids the Mantle project serves (GET /v1/models), signed like every Mantle call.
    For finding the Claude id to put in SHADOW_CLAUDE_MODEL."""
    import json as _json

    import httpx
    m = MantleBackend()
    url = f"{m.base_url}/models"
    headers = {"OpenAI-Project": m.project}
    if m.auth_mode == "apikey" and m.api_key:
        headers["Authorization"] = f"Bearer {m.api_key}"
    else:
        headers = _sigv4_headers("GET", url, "", headers, m.region, m.sigv4_service)
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(url, headers=headers)
    if resp.status_code >= 300:
        raise OllamaUnavailableError(f"Mantle /models {resp.status_code}: {resp.text[:300]}")
    data = _json.loads(resp.text).get("data") or []
    return sorted(str(d.get("id", "")) for d in data if d.get("id"))


class MantleBackend(LLMBackend):
    """AWS Bedrock Mantle gateway backend — project-scoped, bearer-key auth.

    Mantle is an OpenAI-compatible gateway (bedrock-mantle endpoint / Projects API).
    Non-Anthropic models — Mistral, gpt-oss — are served over the OpenAI-compatible
    /chat/completions path; the /anthropic/v1/messages path is a Claude-only shim.
    So the default protocol here is "openai": we POST directly to the Chat
    Completions endpoint with httpx (no extra SDK), bearer auth + the OpenAI-Project
    header. Native tool use via the OpenAI `tools` schema. Fails to
    OllamaUnavailableError so the pipeline falls back to the deterministic playbook.

    Auth: SigV4/IRSA by default — the pod's role has bedrock-mantle permissions and
    the endpoint accepts AWS-credential-signed HTTP requests ("AWS credentials
    (supported for HTTP requests)"). Requests are signed with SigV4Auth(creds,
    "bedrock", region), matching the anthropic SDK's Bedrock signer. Set
    MANTLE_AUTH=apikey to use a Bedrock API key (bearer token) instead.

    Set MANTLE_PROTOCOL=anthropic to invoke a Claude model on Mantle instead (uses
    the anthropic SDK's AsyncAnthropicBedrockMantle against /anthropic/v1/messages).

    Env:
      MANTLE_AUTH             "sigv4" (default) or "apikey"
      MANTLE_API_KEY          Bedrock API key for apikey mode (also MANTLE_API / MANRLE_API)
      MANTLE_PROTOCOL         "openai" (default) or "anthropic"
      MANTLE_BASE_URL         default https://bedrock-mantle.<region>.api.aws/v1
      MANTLE_SIGV4_SERVICE    SigV4 signing name, default "bedrock"
      MANTLE_PROJECT          project id for the OpenAI-Project header
                              (falls back to ANTHROPIC_WORKSPACE_ID)
      AGENT_MODEL             model id provisioned in the Mantle project
      AWS_REGION              default ap-south-1
      BEDROCK_MAX_TOKENS / BEDROCK_TEMPERATURE reused
    """

    def __init__(self) -> None:
        self.region = os.getenv("AWS_REGION", "ap-south-1")
        self.api_key = (os.getenv("MANTLE_API_KEY") or os.getenv("MANTLE_API")
                        or os.getenv("MANRLE_API", ""))
        # Default SigV4/IRSA: the bearer key proved invalid (401 invalid_api_key)
        # while SigV4 authenticates (the IRSA role has bedrock-mantle perms).
        self.auth_mode = os.getenv("MANTLE_AUTH", "sigv4").lower()
        self.sigv4_service = os.getenv("MANTLE_SIGV4_SERVICE", "bedrock")
        self.protocol = os.getenv("MANTLE_PROTOCOL", "openai").lower()
        self.base_url = (os.getenv("MANTLE_BASE_URL")
                         or f"https://bedrock-mantle.{self.region}.api.aws/v1").rstrip("/")
        # Project scoping header. ANTHROPIC_WORKSPACE_ID holds the same project id
        # (proj_axhu5xs7zltkvkc2p2gw) and is the existing secret, so reuse it.
        self.project = (os.getenv("MANTLE_PROJECT")
                        or os.getenv("ANTHROPIC_WORKSPACE_ID", "proj_axhu5xs7zltkvkc2p2gw"))
        self.model_id = os.getenv("AGENT_MODEL", "mistral.mistral-large-3-675b-instruct")
        self.max_tokens = int(os.getenv("BEDROCK_MAX_TOKENS", "8192"))
        # Default 0 — same rationale as BedrockBackend above. This is the LIVE backend
        # (AGENT_BACKEND defaults to "mantle"), so this line is the one that takes effect.
        self.temperature = float(os.getenv("BEDROCK_TEMPERATURE", "0"))
        self.timeout = int(os.getenv("MANTLE_TIMEOUT", "120"))

    async def health_check(self) -> bool:
        return bool(self.api_key and self.model_id)

    async def chat(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        from agent_core import budget

        scope = getattr(self, "budget_scope", "agent")
        if budget.is_over_budget(scope):
            mtd, cap = budget.month_to_date_usd(scope=scope), budget.budget_usd(scope)
            logger.error("[MANTLE] BUDGET EXCEEDED (%s) month-to-date $%.2f >= cap $%.2f — refusing", scope, mtd, cap)
            raise OllamaUnavailableError(f"Monthly budget exceeded (${mtd:.2f} >= ${cap:.2f})")

        if self.protocol == "anthropic":
            return await self._chat_anthropic(messages, tools)
        return await self._chat_openai(messages, tools)

    async def _chat_openai(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        """OpenAI-compatible /chat/completions path (Mistral, gpt-oss, etc.)."""
        import asyncio

        from agent_core import budget

        if self.auth_mode == "apikey" and not self.api_key:
            raise OllamaUnavailableError("Mantle apikey mode: MANTLE_API_KEY is not set")

        valid_names = {t["name"] for t in tools}
        oai_messages = _to_openai_messages(messages)
        oai_tools = _to_openai_tools(tools)

        payload: dict = {
            "model": self.model_id,
            "messages": oai_messages,
            "max_tokens": self.max_tokens,
            "temperature": _effective_temperature(self.temperature),
        }
        if oai_tools:
            payload["tools"] = oai_tools
            payload["tool_choice"] = "auto"

        url = f"{self.base_url}/chat/completions"
        # Serialize ONCE — SigV4 hashes this exact string, so we must POST the same
        # bytes (httpx content=body_str), not re-serialize via json=.
        body_str = json.dumps(payload)
        headers = {"Content-Type": "application/json", "OpenAI-Project": self.project}
        if self.auth_mode == "apikey":
            headers["Authorization"] = f"Bearer {self.api_key}"
        else:
            headers = await asyncio.to_thread(
                _sigv4_headers, "POST", url, body_str, headers, self.region, self.sigv4_service
            )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, content=body_str)
            if resp.status_code != 200:
                raise OllamaUnavailableError(
                    f"Mantle chat/completions {resp.status_code} ({self.model_id}): {resp.text[:400]}"
                )
            body = resp.json()
        except OllamaUnavailableError:
            raise
        except Exception as exc:
            raise OllamaUnavailableError(f"Mantle chat/completions failed ({self.model_id}): {exc}") from exc

        usage = body.get("usage", {}) or {}
        in_t = usage.get("prompt_tokens", 0)
        out_t = usage.get("completion_tokens", 0)
        cost = budget.record(self.model_id, in_t, out_t)

        choices = body.get("choices") or []
        msg = (choices[0].get("message", {}) if choices else {}) or {}
        finish = choices[0].get("finish_reason") if choices else ""
        logger.info("[MANTLE] model=%s in=%s out=%s cost=$%.4f mtd=$%.2f finish=%s",
                    self.model_id, in_t, out_t, cost, budget.month_to_date_usd(), finish)

        content = msg.get("content") or ""
        tool_calls: list[ToolCall] = []
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function", {}) or {}
            name = fn.get("name", "")
            raw_args = fn.get("arguments", "{}")
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
            except json.JSONDecodeError:
                args = {}
            if name in valid_names and isinstance(args, dict):
                tool_calls.append(ToolCall(name=name, args=args))
            elif isinstance(args, dict) and "triage_class" in args:
                content = (content + "\n" + json.dumps(args)).strip()

        if not tool_calls:
            tool_calls = _parse_tool_calls(content, valid_names)
        return content, tool_calls

    async def _chat_anthropic(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        """Anthropic Messages API path — Claude models only, via the anthropic SDK."""
        from agent_core import budget

        try:
            from anthropic import AsyncAnthropicBedrockMantle
        except ImportError as exc:
            raise OllamaUnavailableError(f"anthropic package not installed: {exc}") from exc

        valid_names = {t["name"] for t in tools}
        system, conv = _to_anthropic_messages(messages)
        atools = _to_anthropic_tools(tools)

        client_kwargs: dict = {
            "aws_region": self.region,
            "default_headers": {"anthropic-workspace-id": self.project},
        }
        # Same auth as the Mistral path: SigV4 with the pod's IRSA role unless MANTLE_AUTH=apikey.
        # The MANTLE_API secret holds a key Mantle rejects (401 invalid_api_key), so passing it
        # whenever it is present would fail every Claude call.
        if self.auth_mode == "apikey" and self.api_key:
            client_kwargs["api_key"] = self.api_key
        client = AsyncAnthropicBedrockMantle(**client_kwargs)
        kwargs: dict = {
            "model": self.model_id,
            "max_tokens": self.max_tokens,
            "messages": conv,
        }
        # No temperature: the current SDK's messages.create() rejects it (2026-11-04,
        # anthropic.claude-opus-5). Effort is medium for every call (the user's call,
        # 2026-11-04); only a call that asked for thinking (Opus on high/critical groups and
        # stories, the close reviewer) also gets adaptive thinking.
        _think = int(getattr(self, "thinking_budget", 0) or 0)
        if _think > 0:
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["output_config"] = {"effort": os.getenv("CLAUDE_EFFORT_THINKING", "medium").strip().lower()}
        else:
            kwargs["output_config"] = {"effort": os.getenv("CLAUDE_EFFORT", "medium").strip().lower()}
        if system:
            kwargs["system"] = ([{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
                                if getattr(self, "cache_system", False) else system)
        if atools:
            kwargs["tools"] = atools

        try:
            resp = await client.messages.create(**kwargs)
        except Exception as exc:
            raise OllamaUnavailableError(f"Mantle messages.create failed ({self.model_id}): {exc}") from exc

        usage = getattr(resp, "usage", None)
        in_t = cache_billed_input(getattr(usage, "input_tokens", 0) or 0,
                                  getattr(usage, "cache_read_input_tokens", 0) or 0,
                                  getattr(usage, "cache_creation_input_tokens", 0) or 0) if usage else 0
        out_t = getattr(usage, "output_tokens", 0) if usage else 0
        scope = getattr(self, "budget_scope", "agent")
        cost = budget.record(self.model_id, in_t, out_t, scope=scope)
        logger.info("[MANTLE] model=%s scope=%s in=%s out=%s cost=$%.4f mtd=$%.2f stop=%s",
                    self.model_id, scope, in_t, out_t, cost, budget.month_to_date_usd(scope=scope),
                    getattr(resp, "stop_reason", ""))

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for b in (resp.content or []):
            btype = getattr(b, "type", "")
            if btype == "text" and getattr(b, "text", None):
                text_parts.append(b.text)
            elif btype == "tool_use":
                nm = getattr(b, "name", "")
                inp = getattr(b, "input", {}) or {}
                if nm in valid_names and isinstance(inp, dict):
                    tool_calls.append(ToolCall(name=nm, args=inp))
                elif isinstance(inp, dict) and "triage_class" in inp:
                    text_parts.append(json.dumps(inp))

        content = "\n".join(text_parts)
        if not tool_calls:
            tool_calls = _parse_tool_calls(content, valid_names)
        return content, tool_calls


def get_backend(alert_type: str = "") -> LLMBackend:
    """Select the LLM backend. Default: Bedrock Mantle (Mistral Large 3, in-region).

    AGENT_BACKEND env controls the choice (default "mantle"):
      mantle  : Bedrock Mantle gateway (OpenAI-compatible /chat/completions) for ALL
                alert types, SigV4/IRSA-authed. Mistral Large 3 in ap-south-1 —
                inference stays in the AWS trust boundary, so sensitive alerts
                (privesc, credential_access, cloudtrail) are safe without sanitization.
                The org-sanctioned path per current IAM policy.
      bedrock : BedrockBackend via the bedrock-runtime Converse API (needs
                bedrock:InvokeModel; same in-AWS-boundary guarantee).
      ollama  : on-prem DeepSeek R1 for everything (reversible fallback).
      gemini  : legacy split — Ollama for sensitive alert types, Gemini for the
                rest (requires GEMINI_API_KEY; falls back to Ollama if unset).
    """
    backend = os.getenv("AGENT_BACKEND", "mantle").lower()
    if backend == "mantle":
        return MantleBackend()
    if backend == "bedrock":
        return BedrockBackend()
    if backend == "ollama":
        return OllamaBackend()
    if backend == "gemini":
        if alert_type in _OLLAMA_ONLY_ALERT_TYPES:
            return OllamaBackend()
        if os.getenv("GEMINI_API_KEY", ""):
            return GeminiBackend()
        return OllamaBackend()
    return OllamaBackend()


def get_internal_backend() -> LLMBackend:
    """A backend GUARANTEED to keep data in-boundary — NEVER Gemini.

    For grounding / fact-check calls that must reason over RAW alert data (users,
    commands, hostnames) which cannot be sanitized without breaking the check.
    Honors AGENT_BACKEND for the internal options (mantle / bedrock / ollama); if the
    deployment is on the external `gemini` split, forces on-prem Ollama so raw alert
    data never leaves the trust boundary. Mirrors the sensitive-alert boundary rule.
    """
    backend = os.getenv("AGENT_BACKEND", "mantle").lower()
    if backend == "bedrock":
        return BedrockBackend()
    if backend == "ollama":
        return OllamaBackend()
    if backend == "gemini":
        return OllamaBackend()   # raw grounding data stays on-prem — never Gemini
    return MantleBackend()       # mantle (default) + any unrecognized value


# /shadow runs on Claude by default (2026-11-03, the user's call): Mistral gathers evidence,
# Opus decides. Until a model id is known (set it here or SHADOW_CLAUDE_MODEL), an unset
# SHADOW_LLM stays on Mistral rather than failing every call; SHADOW_LLM=claude with no id
# fails loudly, and SHADOW_LLM=mistral goes back to Mistral only. RAPTOR never reads these.
# AWS support (2026-11-13): Opus 5 is NOT served for inference on Mantle in ap-south-1 (the
# catalogue lists it, every call 404s). Bedrock Runtime with the India cross-region profile
# keeps processing in ap-south-1/ap-south-2; the base model id is not invocable on-demand.
DEFAULT_SHADOW_CLAUDE_MODEL = "in.anthropic.claude-opus-5"


def shadow_llm() -> str:
    """Which model family /shadow uses: "claude" (default once a Claude model id is set) or
    "mistral" (the shared in-region backend). RAPTOR ticket triage never reads this."""
    want = os.getenv("SHADOW_LLM", "").strip().lower()
    if want:
        return "claude" if want == "claude" else "mistral"
    return "claude" if os.getenv("SHADOW_CLAUDE_MODEL", DEFAULT_SHADOW_CLAUDE_MODEL).strip() else "mistral"


def shadow_model_id() -> str:
    if shadow_llm() == "claude":
        return os.getenv("SHADOW_CLAUDE_MODEL", DEFAULT_SHADOW_CLAUDE_MODEL).strip()
    return os.getenv("AGENT_MODEL", "mistral.mistral-large-3-675b-instruct")


def get_shadow_backend(thinking: bool = False) -> LLMBackend:
    """The backend for /shadow only (AI suggestions, story reports). Never Gemini.

    SHADOW_LLM=claude selects Claude (e.g. Opus) on Bedrock, charged to the separate
    "shadow" budget (SHADOW_CLAUDE_MONTHLY_BUDGET_USD), so it cannot use up RAPTOR's cap:
      SHADOW_CLAUDE_MODEL          model or inference-profile id, e.g. apac.anthropic.claude-opus-…
                                   (required; Anthropic models in ap-south-1 are reached through a
                                   cross-region inference profile — apac.* keeps inference in APAC
                                   regions, global.* may route anywhere)
      SHADOW_CLAUDE_TRANSPORT      "runtime" (default: bedrock-runtime Converse with the IRSA role,
                                   needs bedrock:InvokeModel on the in.* profile and the model in
                                   ap-south-1/ap-south-2; Opus 5 is not on Mantle in ap-south-1,
                                   per AWS support 2026-11-13) or "mantle" (Mantle Anthropic path)
      SHADOW_CLAUDE_MAX_TOKENS     default 16000
      CLAUDE_EFFORT / CLAUDE_EFFORT_THINKING  mantle transport: effort for ordinary calls and
                                   for thinking=True calls (both default medium); thinking=True
                                   calls also get adaptive thinking; no temperature is sent
      SHADOW_CLAUDE_THINKING_TOKENS  runtime transport: extended thinking for single-shot calls (thinking=True),
                                   default 6000; tool loops always run without it
      SHADOW_CLAUDE_TIMEOUT        seconds, default 300
    Anything else: the shared internal backend (Mistral on Mantle), exactly as before.
    """
    if shadow_llm() != "claude":
        return get_internal_backend()
    model = shadow_model_id()
    if not model:
        raise OllamaUnavailableError("SHADOW_LLM=claude but SHADOW_CLAUDE_MODEL is not set")
    transport = os.getenv("SHADOW_CLAUDE_TRANSPORT", "runtime").strip().lower()
    b: LLMBackend
    if transport == "mantle":
        b = MantleBackend()
        b.protocol = "anthropic"
    else:
        b = BedrockBackend()
    b.model_id = model
    b.budget_scope = "shadow"
    b.max_tokens = int(os.getenv("SHADOW_CLAUDE_MAX_TOKENS", "16000"))
    b.timeout = int(os.getenv("SHADOW_CLAUDE_TIMEOUT", "300"))
    b.thinking_budget = int(os.getenv("SHADOW_CLAUDE_THINKING_TOKENS", "6000")) if thinking else 0
    if isinstance(b, BedrockBackend):           # Opus 5 on Converse: effort, no temperature
        b.claude_effort = os.getenv("CLAUDE_EFFORT_THINKING" if thinking else "CLAUDE_EFFORT", "medium")
    return b
