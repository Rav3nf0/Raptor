"""Validation debate — a second-LLM critic that reviews OSCAR's AUTO-CLOSE verdict.

Opt-in via AGENT_CRITIC_ENABLED. One bounded LLM call per auto-close ticket; the
caller skips it entirely for NEEDS_L2 / URGENT (already headed to a human) and when
the budget guard would refuse. The critic is prompted to REFUTE the verdict and
default to escalation when evidence is thin, so it can only ever make a verdict MORE
cautious (auto-close → NEEDS_L2), never less. Runs on the same backend as OSCAR and
reuses the sanitizer for the external (Gemini) path so no raw identifiers leak.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Optional

from agent_core.result import AgentResult, ToolCallRecord, _summarize_tool_result

logger = logging.getLogger(__name__)


@dataclass
class CritiqueResult:
    agree: bool          # does the critic agree the auto-close should stand?
    confidence: float    # critic's confidence in its own judgment, 0.0-1.0
    reason: str
    ran: bool = True     # False when the critic call was skipped or failed


# Dissent only overrides the verdict when the critic is at least this confident,
# so a hesitant critic doesn't flip well-supported auto-closes.
_DISSENT_CONFIDENCE_FLOOR = 0.60


def is_enabled() -> bool:
    return os.getenv("AGENT_CRITIC_ENABLED", "false").lower() == "true"


_CRITIC_SYSTEM = (
    "You are a senior SOC reviewer auditing an AI triage bot's AUTO-CLOSE decision. "
    "Your job is to REFUTE the verdict: assume it may be wrong and look for any reason "
    "the alert should instead go to a human analyst (L2). An AUTO-CLOSE is acceptable "
    "ONLY when the investigation clearly and sufficiently supports it. If the evidence "
    "is thin, ambiguous, contradictory, or missing, you must DISAGREE and require "
    "escalation. Do not be agreeable by default. "
    'Respond with ONLY a JSON object: '
    '{"agree": true|false, "confidence": 0.0-1.0, "reason": "<one sentence>"}.'
)


def _evidence_digest(tool_calls: list[ToolCallRecord], limit: int = 12) -> str:
    if not tool_calls:
        return "(no investigative tool calls were made)"
    lines = [f"- {tc.name}: {_summarize_tool_result(tc.name, tc.result)}" for tc in tool_calls[:limit]]
    return "\n".join(lines)


def _parse(content: str) -> Optional[dict]:
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL)
    m = re.search(r"\{.*\}", content, flags=re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


async def critique(
    result: AgentResult,
    alert_name: str,
    severity: str,
    backend,
    sanitizer=None,
) -> CritiqueResult:
    """Ask a second LLM to challenge an auto-close verdict. Returns CritiqueResult.

    Never raises — on any failure it returns ran=False with agree=True so the caller
    leaves the (already safety-gated) verdict untouched.
    """
    reasoning = result.reasoning or ""
    evidence = _evidence_digest(result.tool_calls)
    if sanitizer is not None:
        reasoning = sanitizer.sanitize(reasoning)
        evidence = sanitizer.sanitize(evidence)

    user_message = (
        f"Alert: {alert_name}\n"
        f"Severity: {severity}\n"
        f"Proposed verdict: {result.triage_class} (confidence {result.confidence:.0%})\n\n"
        f"Bot reasoning:\n{reasoning}\n\n"
        f"Evidence gathered:\n{evidence}\n\n"
        "Should this AUTO-CLOSE stand, or be escalated to L2? Refute if in any doubt."
    )
    messages = [
        {"role": "system", "content": _CRITIC_SYSTEM},
        {"role": "user", "content": user_message},
    ]

    try:
        content, _ = await backend.chat(messages, [])
    except Exception as exc:
        logger.warning("[AGENT-CRITIC] call failed (%s) — leaving verdict unchanged", exc)
        return CritiqueResult(agree=True, confidence=0.0, reason=f"critic unavailable: {exc}", ran=False)

    data = _parse(content)
    if not data:
        logger.warning("[AGENT-CRITIC] unparseable response — leaving verdict unchanged")
        return CritiqueResult(agree=True, confidence=0.0, reason="critic response unparseable", ran=False)

    agree = bool(data.get("agree", True))
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    reason = str(data.get("reason", ""))[:500]
    return CritiqueResult(agree=agree, confidence=conf, reason=reason, ran=True)


def dissent_should_override(c: CritiqueResult) -> bool:
    """True when a confident critic disagreement should force escalation to L2."""
    return c.ran and (not c.agree) and c.confidence >= _DISSENT_CONFIDENCE_FLOOR


# ── Grounding critic ───────────────────────────────────────────────────────────
# Fact-checks an AUTO-CLOSE verdict's reasoning against the authoritative alert facts
# + tool results — the LLM layer above the deterministic grounding backstop in
# loop.py. Catches fabrications/mis-attributions with nuance the regex can't (a role
# name treated as a user, a command attributed from the wrong host/time). MUST run on
# an INTERNAL backend (get_internal_backend) with RAW facts — never Gemini for alert
# data — because sanitized data can't be grounded. Opt-in; one-directional.

@dataclass
class GroundingResult:
    grounded: bool           # does every concrete claim trace to the facts/tool results?
    confidence: float
    unsupported: list        # the specific claims the critic could not ground
    reason: str
    ran: bool = True


_GROUNDING_CONFIDENCE_FLOOR = 0.70   # higher than dissent floor — only confident, to avoid noise

_GROUNDING_SYSTEM = (
    "You are a strict fact-checker auditing an AI triage bot's AUTO-CLOSE reasoning. You are "
    "given the ALERT FACTS (the ONLY authoritative source for this alert) and TOOL RESULTS. "
    "Check every CONCRETE claim in the reasoning — acting user/actor, commands, hostnames, "
    "file/process names — against them. A claim is UNSUPPORTED if it names a user, command, "
    "host, or file absent from the facts and tool results, OR mis-attributes one: e.g. treating "
    "a name embedded in an IAM ROLE (like 'ssm-session-testing-charlie-role') as a user, or "
    "citing a command that ran on a different host/time as if it belonged to THIS alert. Do NOT "
    "flag reasonable paraphrase, generic statements, or correct facts — only concrete claims "
    "that invent or contradict the facts. "
    'Respond with ONLY JSON: {"grounded": true|false, "confidence": 0.0-1.0, '
    '"unsupported": ["<claim>", ...], "reason": "<one sentence>"}.'
)


def grounding_enabled() -> bool:
    return os.getenv("AGENT_GROUNDING_CRITIC_ENABLED", "false").lower() == "true"


async def ground_check(result: AgentResult, fact_sheet: str, evidence_digest: str,
                       backend) -> GroundingResult:
    """Fact-check an auto-close verdict's reasoning against authoritative facts.

    Never raises — on any failure returns ran=False/grounded=True so the caller leaves
    the (already deterministically-checked) verdict untouched. Pass RAW (unsanitized)
    fact_sheet/evidence and an INTERNAL backend only.
    """
    reasoning = result.reasoning
    if isinstance(reasoning, (list, tuple)):
        reasoning = " ".join(str(x) for x in reasoning)
    reasoning = reasoning or ""

    user_message = (
        f"ALERT FACTS (authoritative — the ONLY ground truth for this alert):\n{fact_sheet}\n\n"
        f"TOOL RESULTS gathered during investigation:\n{evidence_digest}\n\n"
        f"Bot AUTO-CLOSE reasoning to fact-check:\n{reasoning}\n\n"
        "List any concrete claim in the reasoning not supported by the ALERT FACTS or TOOL "
        "RESULTS (or that mis-attributes one). If the auto-close rests on such a claim, it is "
        "not grounded."
    )
    messages = [
        {"role": "system", "content": _GROUNDING_SYSTEM},
        {"role": "user", "content": user_message},
    ]
    try:
        content, _ = await backend.chat(messages, [])
    except Exception as exc:
        logger.warning("[AGENT-GROUNDING] call failed (%s) — leaving verdict unchanged", exc)
        return GroundingResult(grounded=True, confidence=0.0, unsupported=[], reason=f"unavailable: {exc}", ran=False)

    data = _parse(content)
    if not data:
        logger.warning("[AGENT-GROUNDING] unparseable response — leaving verdict unchanged")
        return GroundingResult(grounded=True, confidence=0.0, unsupported=[], reason="unparseable", ran=False)

    grounded = bool(data.get("grounded", True))
    try:
        conf = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    unsupported = [str(x)[:120] for x in (data.get("unsupported") or [])][:8]
    reason = str(data.get("reason", ""))[:500]
    return GroundingResult(grounded=grounded, confidence=conf, unsupported=unsupported, reason=reason, ran=True)


def grounding_should_override(g: GroundingResult) -> bool:
    """True when a confident 'not grounded' finding should force escalation to L2."""
    return g.ran and (not g.grounded) and g.confidence >= _GROUNDING_CONFIDENCE_FLOOR
