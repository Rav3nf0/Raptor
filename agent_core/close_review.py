"""Claude close reviewer — a security-engineer veto on every FP auto-close.

Missing a real attack because RAPTOR closed it as a false positive is the one failure
this programme cannot afford; an extra L2 escalation is cheap. So just before the
pipeline walks a ticket to False Positive (after every deterministic guard has already
agreed), a second, stronger model reviews the whole case and may veto the close.

  * Veto only. It can send a ticket to L2; it can never close, reopen or relax anything.
  * Full context, not a digest: the alert's own facts, the agent's reasoning, and every
    tool call WITH its result (precedents and memories arrive through those), plus the
    guard that permitted the close. The validation critic in critic.py sees a 12-line
    summary on the same model that made the call; this is the opposite on both counts.
  * Fails CLOSED: if the reviewer cannot run (model unavailable, budget, unparseable
    answer), the close does not happen. CLOSE_REVIEW_FAIL_MODE=open reverses that.
  * Off unless CLOSE_REVIEW_ENABLED=true, and needs CLOSE_REVIEW_MODEL (a Claude model id
    reachable through the in-region Bedrock Mantle gateway).
  * Scope: CLOSE_REVIEW_SCOPE=agent (default) reviews closes that rest on an agent
    verdict; "all" also reviews rule-based closes, which carry far less context.

Cost is bounded by the number of real closes (single digits a day), not by ticket volume.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

BLOCK_LABELS = ("needs-l2-review", "claude-close-review")
_CASE_LIMIT = 60_000          # chars of case file sent to the reviewer
_TOOL_RESULT_LIMIT = 3_000    # chars per tool result


def enabled() -> bool:
    return os.getenv("CLOSE_REVIEW_ENABLED", "false").strip().lower() == "true"


def scope() -> str:
    return os.getenv("CLOSE_REVIEW_SCOPE", "agent").strip().lower()


def fails_closed() -> bool:
    return os.getenv("CLOSE_REVIEW_FAIL_MODE", "closed").strip().lower() != "open"


def veto_floor() -> float:
    try:
        return float(os.getenv("CLOSE_REVIEW_VETO_FLOOR", "0.5"))
    except ValueError:
        return 0.5


SYSTEM = """You are a senior security engineer and threat hunter reviewing an automated SOC triage bot. \
The bot wants to AUTO-CLOSE this alert as a FALSE POSITIVE. No human will look at it if you agree. \
A real attack closed as false positive is the worst possible outcome; an unnecessary escalation to an L2 analyst is cheap. \
Decide whether the close is safe.

Think like an incident responder, not a classifier:
- Lineage: is the activity traced to a root (a service, a scheduled task, an RMM/management agent, a named human, an AI coding agent)? Unexplained parents, user-writable paths, interpreters spawned by unusual parents, encoded or obfuscated commands are red flags.
- Evidence vs absence: an FP needs POSITIVE benign evidence (a vendor signer, a fleet-wide schedule, a managed rollout, an exact human-cleared precedent). "No malicious indicators found", zero-row hunts, errored queries, or "VirusTotal unknown" are NOT evidence of benign.
- Precedents: a prior clearance only counts if it matches the same actor, host and command and was made by a human. A precedent for a different host, user or command does not carry over. Bot-made closes are not clearance.
- Identity: correct password from a new country, MFA failures, session reuse from new networks, actor ambiguity (several principals), or a shared/generic account all need an explanation grounded in the device's own data.
- Host context: recent malware or named-threat detections on the host, EDR silence, new persistence, or credential access weaken any benign reading.
- Grounding: every concrete claim in the bot's reasoning (users, commands, hosts, files) must be present in the alert facts or tool results. A close that rests on an invented or mis-attributed fact is unsafe.
- Scope: a close is only safe if EVERY host, actor and command in the alert is explained, not just the first one.

If the bot's evidence genuinely establishes benign activity, allow the close; do not escalate on vague unease. If anything material is unexplained, escalate and say exactly what an analyst should check.

Respond with ONLY a JSON object:
{"decision": "allow_close" | "escalate", "confidence": 0.0-1.0, "reason": "<2-3 sentences for the L2 analyst>", "concerns": ["<specific concern>", ...], "checks_for_analyst": ["<specific check>", ...]}"""


@dataclass
class Review:
    ran: bool
    decision: str = ""                  # "allow_close" | "escalate"
    confidence: float = 0.0
    reason: str = ""
    concerns: list = field(default_factory=list)
    checks: list = field(default_factory=list)
    error: str = ""


def _clip(s, n: int) -> str:
    s = s if isinstance(s, str) else json.dumps(s, default=str)
    return s if len(s) <= n else s[:n] + f" …[truncated {len(s) - n} chars]"


def build_case_file(*, jira_key: str, alert_name: str, severity: str, device: str, user: str,
                    alert_time: str, close_route: str, evidence: dict | None,
                    agent_result=None) -> str:
    """Everything the reviewer sees, as one bounded text block."""
    parts = [
        f"TICKET: {jira_key}\nALERT: {alert_name}\nSEVERITY: {severity}\n"
        f"DEVICE: {device or '(none)'}\nUSER/ACTOR: {user or '(none)'}\nALERT TIME: {alert_time or '(unknown)'}",
        f"WHY THE CLOSE IS PERMITTED (deterministic guards): {close_route or '(no extra guard)'}",
        "ALERT FACTS (authoritative):\n" + _clip(evidence or {}, 8_000),
    ]
    if agent_result is not None:
        parts.append(
            f"BOT VERDICT: {getattr(agent_result, 'triage_class', '')} "
            f"(confidence {float(getattr(agent_result, 'confidence', 0) or 0):.0%})\n"
            "BOT REASONING:\n" + _clip(getattr(agent_result, "reasoning", "") or "", 8_000))
        calls = getattr(agent_result, "tool_calls", None) or []
        lines = []
        for i, tc in enumerate(calls, 1):
            lines.append(f"[{i}] {getattr(tc, 'name', '?')}({_clip(getattr(tc, 'args', {}), 600)})\n"
                         f"    → {_clip(getattr(tc, 'result', ''), _TOOL_RESULT_LIMIT)}")
        parts.append("BOT INVESTIGATION (every tool call and its result):\n"
                     + ("\n".join(lines) if lines else "(the bot made no tool calls)"))
    else:
        parts.append("BOT VERDICT: none — this close comes from a deterministic rule, not an agent investigation.")
    return _clip("\n\n".join(parts), _CASE_LIMIT)


def _backend():
    """A Mantle backend pointed at the reviewer's Claude model, in-region."""
    from agent_core.backend import MantleBackend
    b = MantleBackend()
    b.protocol = "anthropic"
    b.model_id = os.getenv("CLOSE_REVIEW_MODEL", "").strip()
    b.max_tokens = int(os.getenv("CLOSE_REVIEW_MAX_TOKENS", "16000"))
    b.thinking_budget = int(os.getenv("CLOSE_REVIEW_THINKING_TOKENS", "8000"))
    b.timeout = int(os.getenv("CLOSE_REVIEW_TIMEOUT", "180"))
    return b


def _parse(text: str) -> dict | None:
    m = re.search(r"\{.*\}", text or "", flags=re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


async def review(case_file: str, backend=None) -> Review:
    """Run the reviewer. Never raises; ran=False carries the reason it could not run."""
    if backend is None:
        if not os.getenv("CLOSE_REVIEW_MODEL", "").strip():
            return Review(ran=False, error="CLOSE_REVIEW_MODEL is not set")
        backend = _backend()
    try:
        content, _ = await backend.chat(
            [{"role": "system", "content": SYSTEM},
             {"role": "user", "content": case_file + "\n\nIs this auto-close safe?"}], [])
    except Exception as exc:
        return Review(ran=False, error=f"reviewer call failed: {exc}"[:300])
    data = _parse(content)
    if not data or data.get("decision") not in ("allow_close", "escalate"):
        return Review(ran=False, error="reviewer answer was not the expected JSON")
    try:
        conf = float(data.get("confidence", 0))
    except (TypeError, ValueError):
        conf = 0.0
    return Review(ran=True, decision=data["decision"], confidence=conf,
                  reason=str(data.get("reason", ""))[:800],
                  concerns=[str(x)[:200] for x in (data.get("concerns") or [])][:6],
                  checks=[str(x)[:200] for x in (data.get("checks_for_analyst") or [])][:6])


def blocks(r: Review) -> tuple[bool, str]:
    """(block, reason) for a finished review."""
    if not r.ran:
        if fails_closed():
            return True, f"Claude close review could not run ({r.error}) — not closing without it"
        return False, ""
    if r.decision == "escalate" and r.confidence >= veto_floor():
        return True, f"Claude close review escalated ({r.confidence:.0%}): {r.reason}"
    return False, ""


async def enforce_at_close(*, jira_key: str, alert_name: str, severity: str, device: str,
                           user: str, alert_time: str, close_route: str, evidence: dict | None,
                           agent_result, labels: list, cfg, dry_run: bool = False,
                           backend=None) -> tuple[bool, str]:
    """The close-gate step. Called only after every other guard agreed to close.

    Returns (block, reason). On a block it adds BLOCK_LABELS and a comment for L2.
    """
    if not enabled():
        return False, ""
    if agent_result is None and scope() != "all":
        return False, ""
    case = build_case_file(jira_key=jira_key, alert_name=alert_name, severity=severity,
                           device=device, user=user, alert_time=alert_time,
                           close_route=close_route, evidence=evidence, agent_result=agent_result)
    r = await review(case, backend=backend)
    block, why = blocks(r)
    logger.info("[CLOSE-REVIEW] %s (%s): ran=%s decision=%s conf=%.2f block=%s %s",
                jira_key, alert_name, r.ran, r.decision, r.confidence, block, r.error or r.reason[:200])
    if not block:
        return False, ""
    for lab in BLOCK_LABELS:
        if lab not in labels:
            labels.append(lab)
    lines = ["*RAPTOR did not auto-close this ticket: an independent review flagged it.*", "",
             f"Reason: {r.reason if r.ran else why}"]
    if r.concerns:
        lines += ["", "*Concerns:*"] + [f"- {c}" for c in r.concerns]
    if r.checks:
        lines += ["", "*Please check:*"] + [f"- {c}" for c in r.checks]
    lines += ["", "[Auto-triaged by RAPTOR]"]
    try:
        from edr_triage.jira_handler import add_comment
        await add_comment(jira_key, "\n".join(lines), cfg, dry_run=dry_run)
    except Exception as exc:
        # The block stands even if the comment fails; the comment explains, it doesn't enforce.
        logger.error("[CLOSE-REVIEW] comment on %s failed: %s", jira_key, exc)
    return True, why
