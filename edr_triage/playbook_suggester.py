"""Playbook suggestions queue — propose-only.

Detects where the AI's triage systematically diverges from the human L1/L2
verdict for a class of alert, then asks an on-prem LLM to propose either a
change to an existing playbook or a brand-new playbook. Suggestions are written
to a review queue (status="pending") and are NEVER auto-applied — a human
approves and implements them.

Why on-prem (Ollama): the evidence includes L1/L2 analyst comments, which can
contain usernames, hostnames, and command lines — internal data that must not
leave the network.
"""
from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta

from entity_graph.models import ShadowResult, PlaybookSuggestion

logger = logging.getLogger(__name__)

_SUGGEST_PROMPT = """\
You are a senior SOC automation engineer reviewing an AI triage bot ("OSCAR")
against human L1/L2 analysts. For the alert type below, OSCAR's verdict
disagreed with the human verdict repeatedly. Decide how the triage PLAYBOOK
should change so OSCAR matches the humans next time.

Alert name: {alert_name}
Alert type (current playbook route): {alert_type}
Number of disagreements: {count}

Examples (AI verdict + reasoning vs human verdict + note):
{examples}

Respond ONLY with valid JSON in this exact schema:
{{
  "suggestion_type": "modify" | "new" | "routing",
  "target_playbook": "<existing playbook name to change, or empty if new/routing>",
  "title": "<one-line summary of the change>",
  "divergence_summary": "<what OSCAR did vs what the humans did, 1-2 sentences>",
  "rationale": "<why this change is warranted, grounded in the examples>",
  "proposed_change": "<concrete, actionable change a developer can implement: which fields to add, which rule to adjust, or what a new playbook should do>"
}}

Guidance:
- "modify": tweak an existing playbook (add fields it omits, fix a wrong narrative, adjust an auto-close threshold).
- "new": the alert class needs its own playbook the current route mis-handles.
- "routing": the alert is being classified into the wrong playbook entirely.
- Be specific and conservative. Do not suggest auto-closing anything more aggressively.
"""


def _human_verdict(s: ShadowResult) -> str:
    return s.l2_triage_class or s.l1_triage_class or ""


def _alert_type(alert_name: str) -> str:
    try:
        from edr_triage.classifier import classify
        return classify(alert_name)
    except Exception:
        return "generic"


def _format_examples(rows: list[ShadowResult], limit: int = 6) -> str:
    parts = []
    for s in rows[:limit]:
        note = (s.l1_handoff_comment or "").strip().replace("\n", " ")[:300]
        parts.append(
            f"- {s.jira_key}: AI={s.ai_triage_class} (conf={s.ai_confidence:.0%}) "
            f"| Human={_human_verdict(s)}\n"
            f"    AI reasoning: {(s.ai_reasoning or '').strip()[:200]}\n"
            f"    Human note: {note or '(none)'}"
        )
    return "\n".join(parts)


async def _llm_suggest(alert_name: str, alert_type: str, rows: list[ShadowResult]) -> dict | None:
    """Ask on-prem Ollama for a structured suggestion. Returns None on failure."""
    import httpx

    base_url = (os.getenv("LOCAL_LLM_URL") or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
    model = os.getenv("LOCAL_LLM_MODEL") or os.getenv("OLLAMA_MODEL", "deepseek-r1:8b")
    prompt = _SUGGEST_PROMPT.format(
        alert_name=alert_name, alert_type=alert_type,
        count=len(rows), examples=_format_examples(rows),
    )
    try:
        async with httpx.AsyncClient(timeout=int(os.getenv("OLLAMA_TIMEOUT", "600"))) as client:
            resp = await client.post(
                f"{base_url}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": 1024, "num_ctx": 8192},
                },
            )
            if resp.status_code != 200:
                logger.warning("suggester LLM returned %s", resp.status_code)
                return None
            content = resp.json().get("message", {}).get("content", "")
    except Exception as exc:
        logger.warning("suggester LLM call failed: %s", exc)
        return None

    # Strip <think> and markdown fences, then extract the JSON object.
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL)
    content = re.sub(r"```(?:json)?|```", "", content)
    m = re.search(r"\{.*\}", content, flags=re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def _fallback_suggestion(alert_name: str, alert_type: str, rows: list[ShadowResult]) -> dict:
    """Rule-based suggestion when the LLM is unavailable — still surfaces the divergence."""
    ai_classes = {s.ai_triage_class for s in rows}
    human_classes = {_human_verdict(s) for s in rows if _human_verdict(s)}
    return {
        "suggestion_type": "modify",
        "target_playbook": alert_type,
        "title": f"OSCAR disagrees with L1/L2 on '{alert_name}' ({len(rows)}x)",
        "divergence_summary": f"AI verdicts {sorted(ai_classes)} vs human {sorted(human_classes)}.",
        "rationale": "Repeated AI-vs-human mismatch on this alert type — review the playbook/routing.",
        "proposed_change": "LLM analysis unavailable — review the linked tickets and adjust the "
                           f"'{alert_type}' playbook or its classifier route.",
    }


async def analyze_divergences(lookback_days: int = 14, min_mismatches: int = 3) -> dict:
    """Scan resolved shadow results for AI-vs-human divergence and queue suggestions.

    Returns a summary dict. Does not modify any playbook — writes pending
    PlaybookSuggestion documents for human review.
    """
    cutoff = datetime.utcnow() - timedelta(days=lookback_days)
    mismatches = await ShadowResult.find(
        ShadowResult.verdict_match == False,  # noqa: E712  (Beanie needs ==)
        ShadowResult.created_at >= cutoff,
    ).to_list()

    groups: dict[str, list[ShadowResult]] = defaultdict(list)
    for s in mismatches:
        groups[s.alert_name].append(s)

    created, skipped = [], []
    for alert_name, rows in groups.items():
        if len(rows) < min_mismatches:
            continue
        alert_type = _alert_type(alert_name)

        # Dedupe — one open suggestion per alert_type at a time.
        existing = await PlaybookSuggestion.find_one(
            PlaybookSuggestion.alert_type == alert_type,
            PlaybookSuggestion.status == "pending",
        )
        if existing:
            skipped.append(alert_name)
            continue

        data = await _llm_suggest(alert_name, alert_type, rows) or _fallback_suggestion(alert_name, alert_type, rows)
        sugg = PlaybookSuggestion(
            alert_type=alert_type,
            alert_name=alert_name,
            suggestion_type=data.get("suggestion_type", "modify"),
            target_playbook=data.get("target_playbook", alert_type),
            title=data.get("title", "")[:200],
            divergence_summary=data.get("divergence_summary", "")[:500],
            rationale=data.get("rationale", "")[:1000],
            proposed_change=data.get("proposed_change", "")[:2000],
            evidence_jira_keys=[s.jira_key for s in rows][:20],
            mismatch_count=len(rows),
        )
        await sugg.insert()
        created.append({"alert_type": alert_type, "alert_name": alert_name, "count": len(rows)})
        logger.info("[SUGGEST] queued playbook suggestion for %s (%d mismatches)", alert_name, len(rows))

    return {
        "lookback_days": lookback_days,
        "min_mismatches": min_mismatches,
        "mismatches_scanned": len(mismatches),
        "suggestions_created": len(created),
        "created": created,
        "skipped_existing": skipped,
    }
