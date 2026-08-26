"""Base playbook — defines the interface all playbooks implement."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PlaybookResult:
    l1_comment: str = ""
    l2_comment: str = ""
    triage_class: str = "PENDING"           # AUTO_CLOSED_TP | AUTO_CLOSED_FP | NEEDS_L2 | URGENT | PENDING
    action: str = "none"                    # resolved | event_analysis | labels_only | none
    labels: list[str] = field(default_factory=list)
    auto_close: bool = False
    llm_reasoning: str = ""


class BasePlaybook:
    """All playbooks inherit from this and implement run()."""

    async def run(
        self,
        jira_key: str,
        alert: dict,
        evidence: dict,
        vt: dict,
        timeline: list[dict],
        is_test_device: bool = False,
        sentinel_entities: dict | None = None,
        normalized=None,   # NormalizedAlert — the vendor-agnostic view of `alert`
    ) -> PlaybookResult:
        raise NotImplementedError

    # ── Shared formatting helpers ──────────────────────────────────────

    @staticmethod
    def _vt_line(vt: dict) -> str:
        if not vt or vt.get("verdict") == "unknown":
            return "VirusTotal: No data available"
        det = vt.get("detections", 0)
        total = vt.get("total", 0)
        verdict = vt.get("verdict", "unknown")
        link = vt.get("vt_link", "")
        names = vt.get("malicious_names", [])
        name_str = f" ({', '.join(names[:3])})" if names else ""
        vt_str = f"VirusTotal: {det}/{total} engines flagged{name_str} — verdict: {verdict.upper()}"
        if link:
            vt_str += f" [View]({link})"
        return vt_str

    @staticmethod
    def _precedent_section(precedents: list[dict], current_device: str = "", current_user: str = "") -> str:
        """Format a 'Previous occurrences' section for the L1 comment.

        Each line shows the prior jira key, device, user, and outcome, with
        ✓/✗ flags so L1 can immediately see if this matches a known scenario.
        """
        if not precedents:
            return ""

        _CLASS_LABEL = {
            "AUTO_CLOSED_TP": "True Positive — Auto-closed",
            "AUTO_CLOSED_FP": "False Positive — Auto-closed",
            "NEEDS_L2":       "Needs L2 Review",
            "URGENT":         "Urgent — Escalated",
            "PENDING":        "Pending",
        }

        lines = ["", "*Previous occurrences of this alert type:*"]
        for p in precedents:
            jira_key   = p.get("jira_key", "?")
            device     = p.get("device_name") or "Unknown"
            user       = p.get("user_name") or "Unknown"
            outcome    = _CLASS_LABEL.get(p.get("triage_class", ""), p.get("triage_class", "Unknown"))
            alert_time = (p.get("alert_time") or p.get("jira_created_at") or "")[:10]

            dev_flag  = "✓ same device"  if p.get("same_device")  else ("✗ different device"  if current_device else "")
            user_flag = "✓ same user"    if p.get("same_user")    else ("✗ different user"    if current_user   else "")
            flags     = " | ".join(f for f in [dev_flag, user_flag] if f)

            line = f"• *{jira_key}*"
            if alert_time:
                line += f" ({alert_time})"
            line += f" — Device: {device}"
            if dev_flag:
                line += f" _{dev_flag}_"
            line += f" | User: {user}"
            if user_flag:
                line += f" _{user_flag}_"
            line += f" | Outcome: {outcome}"
            lines.append(line)

        return "\n".join(lines)

    @staticmethod
    def _test_device_note() -> str:
        return (
            "\n⚠ *Known Test Device:* This host is a registered security testing device "
            "(sec-test-poc / uat-edr-test-115). Activity may be red-team or security team testing. "
            "*However, review is still required* — if the account, timing, or technique is "
            "anomalous, treat this as a real incident."
        )
