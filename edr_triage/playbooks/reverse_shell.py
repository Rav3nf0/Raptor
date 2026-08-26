"""Reverse shell / pentest tool / HackTool playbook.

Always NEEDS_L2. Test devices get an extra note but are still reviewed.
"""
from __future__ import annotations

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


class ReverseShellPlaybook(BasePlaybook):

    async def run(
        self,
        jira_key: str,
        alert: dict,
        evidence: dict,
        vt: dict,
        timeline: list[dict],
        is_test_device: bool = False,
        sentinel_entities: dict | None = None,
        normalized=None,
    ) -> PlaybookResult:
        from edr_triage.normalized import normalize_alert
        n = normalized or normalize_alert(alert, evidence, sentinel_entities)
        device     = n.device
        user       = n.user
        alert_name = n.name if n.name != "Alert" else "Reverse Shell Alert"
        inv_state  = n.investigation_state
        alert_time = n.alert_time
        sev        = n.severity

        file_name = n.file_name
        file_path = n.file_path
        sha256    = n.sha256
        init_proc = n.initiating_process

        l1_lines = [
            f"Hi Team,",
            f"",
            f"We have observed a *{alert_name}* alert on host *{device}* — this requires L2 sign-off.",
            f"",
            f"*User:* {user}",
        ]
        if file_name:
            l1_lines.append(f"*File name:* {file_name}")
        if file_path:
            l1_lines.append(f"*File path:* {file_path}")
        if sha256:
            l1_lines.append(f"*File hash:* {sha256}")
        if init_proc and file_name:
            l1_lines.append(f"*{file_name}* executed via *{init_proc}*.")
        l1_lines.append(f"*{self._vt_line(vt)}*")
        l1_lines.append(f"*Investigation state:* {inv_state}")
        l1_lines.append(f"*Severity:* {sev}")
        l1_lines.append(f"*Event time:* {alert_time} UTC")
        l1_lines.append(f"")
        l1_lines.append(
            f"⚠ *Reverse shell / pentest tool detected — even on test devices, "
            f"an attacker could repurpose the same technique. L2 must verify.*"
        )
        if is_test_device:
            l1_lines.append(self._test_device_note())

        l1_lines.append(f"")
        l1_lines.append(f"[Auto-triaged by RAPTOR]")

        return PlaybookResult(
            l1_comment="\n".join(l1_lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai"],
            auto_close=False,
        )
