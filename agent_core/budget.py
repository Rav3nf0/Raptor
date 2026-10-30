"""Bedrock token usage + monthly spend guard.

Records every Converse call's token usage and computed USD cost to MongoDB
(collection ``bedrock_usage``), and enforces a hard monthly cap. Once
month-to-date spend >= AGENT_MONTHLY_BUDGET_USD, BedrockBackend refuses further
calls (raising BudgetExceededError), so triage fails safe to the deterministic
playbook / L2 instead of overspending.

Two scopes, each with its own cap: "agent" (RAPTOR ticket triage and everything else,
AGENT_MONTHLY_BUDGET_USD) and "shadow" (Claude for /shadow suggestions and story reports,
SHADOW_CLAUDE_MONTHLY_BUDGET_USD). Shadow spend never counts against the agent cap, so
an Opus-heavy month on /shadow cannot stop RAPTOR triage. Rows written before scopes
existed have no scope field and count as "agent".

This is the only *real-time, deterministic* cost cap — AWS Budgets only alert
after a billing-data lag. Pricing (per 1M tokens) defaults to Mistral Large 3 and
is overridable via env for other models / the ap-south-1 rate.

All MongoDB access here is synchronous — this module is called from inside
BedrockBackend._chat_sync, which already runs in a worker thread.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_COLLECTION = "bedrock_usage"


class BudgetExceededError(Exception):
    """Month-to-date Bedrock spend has reached the configured monthly cap."""


def _col():
    from lib.mongo import get_col
    return get_col(_COLLECTION)


def _month_key(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).strftime("%Y-%m")


def _prices_per_1k(model_id: str) -> tuple[float, float]:
    """(input, output) USD per 1,000 tokens.

    Env override (applies to whatever model is configured):
      BEDROCK_PRICE_IN_PER_1K, BEDROCK_PRICE_OUT_PER_1K
    Default: Mistral Large 3, ap-south-1 rate — $0.59 / $1.76 per 1M tokens.
    """
    # Claude (the close reviewer) is priced separately: the BEDROCK_PRICE_* override and
    # the Mistral default would under-count it several-fold and let the cap be overshot.
    # Opus is priced well above Sonnet; the defaults are deliberately high (Opus 4.1 list,
    # $15/$75 per 1M) so an unset price over-counts and the cap trips early, never late.
    # Set OPUS_PRICE_* to the Bedrock rate of the model actually configured.
    mid = (model_id or "").lower()
    if "opus" in mid:
        return (float(os.getenv("OPUS_PRICE_IN_PER_1K", "0.015")),
                float(os.getenv("OPUS_PRICE_OUT_PER_1K", "0.075")))
    if "claude" in mid or "anthropic" in mid:
        return (float(os.getenv("CLAUDE_PRICE_IN_PER_1K", "0.003")),
                float(os.getenv("CLAUDE_PRICE_OUT_PER_1K", "0.015")))
    in_1k = os.getenv("BEDROCK_PRICE_IN_PER_1K")
    out_1k = os.getenv("BEDROCK_PRICE_OUT_PER_1K")
    if in_1k and out_1k:
        return float(in_1k), float(out_1k)
    return 0.00059, 0.00176


def cost_usd(model_id: str, input_tokens: int, output_tokens: int) -> float:
    in_1k, out_1k = _prices_per_1k(model_id)
    return (int(input_tokens or 0) / 1000.0) * in_1k + (int(output_tokens or 0) / 1000.0) * out_1k


SCOPES = ("agent", "shadow")


def _scope_match(scope: str) -> dict:
    return {"scope": "shadow"} if scope == "shadow" else {"scope": {"$ne": "shadow"}}


def budget_usd(scope: str = "agent") -> float:
    """Monthly cap in USD for a scope. <= 0 disables the guard."""
    if scope == "shadow":
        try:
            return float(os.getenv("SHADOW_CLAUDE_MONTHLY_BUDGET_USD", "50"))
        except ValueError:
            return 50.0
    try:
        return float(os.getenv("AGENT_MONTHLY_BUDGET_USD", "90"))
    except ValueError:
        return 90.0


def month_to_date_usd(month: str | None = None, scope: str = "agent") -> float:
    month = month or _month_key()
    try:
        docs = list(_col().aggregate([
            {"$match": {"month": month, **_scope_match(scope)}},
            {"$group": {"_id": None, "total": {"$sum": "$cost_usd"}}},
        ]))
        return float(docs[0]["total"]) if docs else 0.0
    except Exception as exc:
        # Fail OPEN on read errors — a Mongo hiccup should not block triage.
        logger.warning("[BUDGET] month-to-date query failed (%s) — treating as $0", exc)
        return 0.0


def remaining_usd(scope: str = "agent") -> float:
    b = budget_usd(scope)
    return float("inf") if b <= 0 else max(0.0, b - month_to_date_usd(scope=scope))


def is_over_budget(scope: str = "agent") -> bool:
    b = budget_usd(scope)
    if b <= 0:
        return False
    return month_to_date_usd(scope=scope) >= b


def record(model_id: str, input_tokens: int, output_tokens: int, jira_key: str = "",
           scope: str = "agent") -> float:
    """Persist one call's usage. Returns the computed cost for logging."""
    c = cost_usd(model_id, input_tokens, output_tokens)
    try:
        _col().insert_one({
            "month": _month_key(),
            "ts": datetime.now(timezone.utc),
            "model_id": model_id,
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "cost_usd": c,
            "jira_key": jira_key,
            "scope": scope if scope in SCOPES else "agent",
        })
    except Exception as exc:
        logger.warning("[BUDGET] usage insert failed: %s", exc)
    return c


def summary(scope: str = "agent") -> dict:
    """Snapshot for the /bedrock-usage endpoint (agent) and /api/shadow/llm-check (shadow)."""
    month = _month_key()
    mtd = month_to_date_usd(month, scope)
    b = budget_usd(scope)
    calls = 0
    try:
        calls = _col().count_documents({"month": month, **_scope_match(scope)})
    except Exception:
        pass
    return {
        "month": month,
        "month_to_date_usd": round(mtd, 4),
        "budget_usd": b,
        "remaining_usd": (None if b <= 0 else round(max(0.0, b - mtd), 4)),
        "over_budget": (b > 0 and mtd >= b),
        "calls_this_month": calls,
    }
