"""Lateral movement / compromised account / hands-on-keyboard playbook.

Always URGENT + l2-escalation label. Never auto-closed.
"""
from __future__ import annotations

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


class LateralMovePlaybook(BasePlaybook):

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
        alert_name = n.name if n.name != "Alert" else "Lateral Movement Alert"
        inv_state  = n.investigation_state
        alert_time = n.alert_time
        sev        = n.severity
        tactics    = n.tactics

        file_name = n.file_name
        sha256    = n.sha256
        init_proc = n.initiating_process

        l1_lines = [
            f"🚨 *URGENT — {alert_name}* detected on *{device}*",
            f"",
            f"*User:* {user}",
            f"*Severity:* {sev}",
            f"*Investigation state:* {inv_state}",
            f"*Event time:* {alert_time} UTC",
        ]
        if tactics:
            l1_lines.append(f"*MITRE Techniques:* {', '.join(tactics)}")
        if file_name:
            l1_lines.append(f"*Tool/File:* {file_name}")
            if sha256:
                l1_lines.append(f"*Hash:* {sha256}")
        if init_proc:
            l1_lines.append(f"*Initiating process:* {init_proc}")
        l1_lines.append(f"*{self._vt_line(vt)}*")
        l1_lines.append(f"")
        l1_lines.append(
            f"⚠ *Lateral movement / hands-on-keyboard activity detected. "
            f"Potential active threat actor. Escalating to L2 immediately.*"
        )
        if is_test_device:
            l1_lines.append(self._test_device_note())
        l1_lines.append(f"")
        l1_lines.append(f"[Auto-triaged by RAPTOR]")

        return PlaybookResult(
            l1_comment="\n".join(l1_lines),
            triage_class="URGENT",
            action="labels_only",
            labels=["l2-escalation", "urgent", "edr-triage-ai"],
            auto_close=False,
        )
