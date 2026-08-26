"""AgentResult — the output of a complete SOC analyst investigation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


_ACTION_DETAIL_CAP = 300


def _scalar(v) -> str:
    """Render one action field as text. Nested containers are flattened rather than
    dropped, capped so a deeply nested blob can't bloat the Jira comment."""
    if v is None or isinstance(v, bool):
        return ""
    if isinstance(v, (str, int, float)):
        return str(v).strip()
    if isinstance(v, dict):
        return "; ".join(s for x in v.values() if (s := _scalar(x)))[:_ACTION_DETAIL_CAP]
    if isinstance(v, (list, tuple)):
        return "; ".join(s for x in v if (s := _scalar(x)))[:_ACTION_DETAIL_CAP]
    return str(v).strip()[:_ACTION_DETAIL_CAP]


def normalize_action(a) -> str:
    """Flatten one recommended action to a display string.

    The verdict JSON's "actions" is documented as a list of strings, but models
    routinely emit objects instead — `{"action": "close_alert", "reason": "..."}`.
    Left alone those objects render into the Jira comment as a raw Python dict
    and, because AgentResult is an unvalidated dataclass, get persisted into
    ShadowResult.ai_recommended_actions (typed list[str]) where they later break
    read-back. Normalizing here keeps both the comment and the stored row clean.
    """
    if a is None:
        return ""  # callers drop empties; "None" must never reach a Jira comment
    if isinstance(a, str):
        return a
    if isinstance(a, dict):
        _LABELS = ("action", "step", "name", "title", "description", "recommendation")
        _DETAILS = ("reason", "rationale", "detail", "details", "why",
                    "justification", "comment", "note", "explanation")
        # Prefer the human-meaningful fields, in the order models tend to use.
        label_key = next((k for k in _LABELS if a.get(k)), "")
        detail_key = next((k for k in _DETAILS if a.get(k)), "")
        label = _scalar(a[label_key]) if label_key else ""
        detail = _scalar(a[detail_key]) if detail_key else ""
        if label and not detail:
            # The key names above are a guess at what the model chose. Rather than
            # silently dropping the rationale when it used some other name, fall back
            # to whatever is left — losing the reasoning from an analyst-facing action
            # line is worse than an imperfect label. Nested values are included too:
            # a scalar-only filter dropped `{"details": {"reason": "..."}}` entirely,
            # which is the same silent loss this fallback exists to prevent.
            detail = "; ".join(
                s for k, v in a.items()
                if k != label_key and (s := _scalar(v))
            )
        if label and detail:
            return f"{label} — {detail}"
        if label or detail:
            return label or detail
    return str(a)


@dataclass
class ToolCallRecord:
    name: str
    args: dict
    result: dict


@dataclass
class AgentResult:
    triage_class: str  # AUTO_CLOSED_FP | AUTO_CLOSED_TP | NEEDS_L2 | URGENT
    confidence: float  # 0.0 - 1.0
    reasoning: str     # Full reasoning narrative for L1 comment
    recommended_actions: list[str] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    iterations: int = 0
    error: Optional[str] = None

    # Auto-close safety gate result
    blocked_by_safety: bool = False
    safety_block_reason: str = ""
    # Set ONLY by the concurrent-open-alerts gate — the OTHER ticket(s) whose still-open
    # status caused THIS one to be blocked. Lets the closure poller re-trigger this
    # ticket automatically once any of those siblings actually closes, instead of it
    # sitting at NEEDS_L2 forever with nothing tracking that the block has lifted.
    blocked_by_concurrent_keys: list[str] = field(default_factory=list)
    # The verdict the MODEL produced, before any deterministic gate/critic downgrade.
    # Lets us measure how often a gate turned an intended auto-close into an escalation
    # (i.e. whether the safety layer is over-gating), which the final triage_class hides.
    pre_safety_class: str = ""

    # Validation-debate critic outcome (agent_core/critic.py)
    critic_ran: bool = False
    critic_agreed: Optional[bool] = None
    critic_reason: str = ""

    def to_jira_comment(self, jira_key: str, alert_name: str) -> str:
        """Format as Jira wiki markup L1 comment."""
        verdict_emoji = {
            "AUTO_CLOSED_FP": "[AUTO-FP]",
            "AUTO_CLOSED_TP": "[AUTO-TP]",
            "NEEDS_L2": "[NEEDS L2]",
            "REQUEST_JUSTIFICATION": "[JUSTIFICATION NEEDED]",
            "URGENT": "[!!! URGENT]",
        }.get(self.triage_class, f"[{self.triage_class}]")

        lines = [
            f"*{verdict_emoji} AI Triage — {alert_name}*",
            "",
            f"*Verdict:* {self.triage_class}",
            f"*Confidence:* {self.confidence:.0%}",
            "",
            "*Reasoning:*",
            self.reasoning,
        ]

        if self.safety_block_reason:
            lines += ["", f"*Safety gate triggered:* {self.safety_block_reason}"]

        if self.recommended_actions:
            lines += ["", "*Recommended actions:*"]
            for action in self.recommended_actions:
                lines.append(f"# {action}")

        if self.tool_calls:
            lines += ["", f"*Evidence gathered ({len(self.tool_calls)} tool calls):*"]
            for tc in self.tool_calls:
                result_summary = _summarize_tool_result(tc.name, tc.result)
                lines.append(f"* {tc.name}({_fmt_args(tc.args)}) → {result_summary}")

        lines += ["", "[Auto-triaged by DeepIntel Agent]"]
        return "\n".join(lines)

    def to_jira_recommendation(self, alert_name: str) -> str:
        """Format as an advisory copilot comment (AGENT_PHASE=copilot).

        Deliberately NOT to_jira_comment(): that one is written in the voice of a
        decision already executed ("[AUTO-FP] … Auto-triaged"). In copilot phase
        the agent changes no ticket state, so the comment must read as a
        recommendation an analyst can ignore — otherwise L1 sees "AUTO-FP" on a
        ticket that is still open and trusts a close that never happened.
        """
        headline = {
            "AUTO_CLOSED_FP": "close as False Positive",
            "AUTO_CLOSED_TP": "confirm as True Positive",
            "NEEDS_L2": "escalate to L2",
            # Explicitly NOT an L2 escalation — this is the AWAITING MORE INPUTS loop
            # L1 owns, so the recommendation has to read as "ask the user", not "escalate".
            "REQUEST_JUSTIFICATION": "request a business justification from the acting user "
                                     "(no L2 escalation needed)",
            "URGENT": "escalate as URGENT",
        }.get(self.triage_class, self.triage_class)

        lines = [
            f"*RAPTOR Copilot — recommendation for {alert_name}*",
            "",
            f"*Recommends:* {headline} ({self.triage_class})",
            f"*Confidence:* {self.confidence:.0%}",
            "*Ticket state:* unchanged — this is advisory only. RAPTOR has not "
            "closed, resolved, or transitioned this ticket, and will not. The "
            "triage note above stands until an analyst decides.",
            "",
            "*Reasoning:*",
            self.reasoning,
        ]

        if self.safety_block_reason:
            lines += ["", f"*Safety gate triggered:* {self.safety_block_reason}"]

        if self.critic_ran and self.critic_agreed is False:
            lines += ["", f"*Validation critic disagreed:* {self.critic_reason}"]

        if self.recommended_actions:
            lines += ["", "*Suggested next steps:*"]
            for action in self.recommended_actions:
                lines.append(f"# {action}")

        if self.tool_calls:
            lines += ["", f"*Evidence gathered ({len(self.tool_calls)} tool calls):*"]
            for tc in self.tool_calls:
                lines.append(
                    f"* {tc.name}({_fmt_args(tc.args)}) → "
                    f"{_summarize_tool_result(tc.name, tc.result)}"
                )

        lines += ["", "[RAPTOR copilot · advisory only — no action taken]"]
        return "\n".join(lines)


def _fmt_args(args: dict) -> str:
    parts = []
    for k, v in args.items():
        v_str = str(v)
        if len(v_str) > 30:
            v_str = v_str[:27] + "..."
        parts.append(f"{k}={v_str!r}")
    return ", ".join(parts)


def _summarize_tool_result(name: str, result: dict) -> str:
    if result.get("error"):
        return f"ERROR: {result['error'][:60]}"
    if name.startswith("vt_lookup"):
        det = result.get("detections", "?")
        tot = result.get("total", "?")
        verdict = result.get("verdict", "?")
        return f"{det}/{tot} detections, verdict={verdict}"
    if name == "mde_get_timeline":
        # Call out AV detections rather than a bare event count — "30 events" reads
        # like routine telemetry and buries the one fact an analyst needs.
        _av = result.get("av_detections") or []
        if _av:
            _names = ", ".join(str(d.get("FileName") or "?") for d in _av[:4])
            _more = f" +{len(_av) - 4} more" if len(_av) > 4 else ""
            return (f"{result.get('count', 0)} events, {len(_av)} AV DETECTION(S): "
                    f"{_names}{_more}")
        return f"{result.get('count', 0)} events"
    if name == "hunt_ip_owner":
        # "1 rows" / "10 rows" is the one summary that must never be shown here — the
        # row COUNT is the finding (unique owner vs ambiguous), and a bare count is
        # exactly what gets read as "it resolved fine".
        return result.get("verdict") or f"{result.get('count', 0)} candidate device(s)"
    if name.startswith("hunt_") or name in ("mde_advanced_hunt", "sentinel_run_kql"):
        return f"{result.get('count', 0)} rows"
    if name == "scg_get_entity_context":
        if result.get("found"):
            return f"found: {result.get('alert_count', 0)} prior alerts, risk={result.get('risk_score', 0)}"
        return "not seen before"
    if name == "scg_check_concurrent_alerts":
        n = result.get("concurrent_count", 0)
        return f"{n} concurrent open alerts" if n else "no concurrent alerts"
    if name == "shodan_lookup":
        if result.get("found"):
            ports = result.get("ports", [])
            return f"found: {len(ports)} open ports"
        return "not found in Shodan"
    return str(result)[:80]
