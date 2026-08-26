"""Bedrock token usage + monthly spend guard.

Records every Converse call's token usage and computed USD cost to MongoDB
(collection ``bedrock_usage``), and enforces a hard monthly cap. Once
month-to-date spend >= AGENT_MONTHLY_BUDGET_USD, BedrockBackend refuses further
calls (raising BudgetExceededError), so triage fails safe to the deterministic
playbook / L2 instead of overspending.

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
    in_1k = os.getenv("BEDROCK_PRICE_IN_PER_1K")
    out_1k = os.getenv("BEDROCK_PRICE_OUT_PER_1K")
    if in_1k and out_1k:
        return float(in_1k), float(out_1k)
    return 0.00059, 0.00176


def cost_usd(model_id: str, input_tokens: int, output_tokens: int) -> float:
    in_1k, out_1k = _prices_per_1k(model_id)
    return (int(input_tokens or 0) / 1000.0) * in_1k + (int(output_tokens or 0) / 1000.0) * out_1k


def budget_usd() -> float:
    """Monthly cap in USD. <= 0 disables the guard."""
    try:
        return float(os.getenv("AGENT_MONTHLY_BUDGET_USD", "70"))
    except ValueError:
        return 70.0


def month_to_date_usd(month: str | None = None) -> float:
    month = month or _month_key()
    try:
        docs = list(_col().aggregate([
            {"$match": {"month": month}},
            {"$group": {"_id": None, "total": {"$sum": "$cost_usd"}}},
        ]))
        return float(docs[0]["total"]) if docs else 0.0
    except Exception as exc:
        # Fail OPEN on read errors — a Mongo hiccup should not block triage.
        logger.warning("[BUDGET] month-to-date query failed (%s) — treating as $0", exc)
        return 0.0


def remaining_usd() -> float:
    b = budget_usd()
    return float("inf") if b <= 0 else max(0.0, b - month_to_date_usd())


def is_over_budget() -> bool:
    b = budget_usd()
    if b <= 0:
        return False
    return month_to_date_usd() >= b


def record(model_id: str, input_tokens: int, output_tokens: int, jira_key: str = "") -> float:
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
        })
    except Exception as exc:
        logger.warning("[BUDGET] usage insert failed: %s", exc)
    return c


def summary() -> dict:
    """Snapshot for the /bedrock-usage endpoint."""
    month = _month_key()
    mtd = month_to_date_usd(month)
    b = budget_usd()
    calls = 0
    try:
        calls = _col().count_documents({"month": month})
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
