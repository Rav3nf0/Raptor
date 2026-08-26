"""Block Tool playbook — handles Block Anydesk, CustomEnterpriseBlock, etc.

These are custom MDE detection rules that quarantine known remote access tools.
Auto-close as True Positive — the rule fired as designed, file was quarantined.
"""
from __future__ import annotations

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


class BlockToolPlaybook(BasePlaybook):

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
        alert_name = n.name if n.name != "Alert" else "Block Alert"
        inv_state  = "Blocked" if n.investigation_state == "UnsupportedAlertType" else n.investigation_state
        alert_time = n.alert_time
        sev        = n.severity

        file_name = n.file_name
        file_path = n.file_path
        sha256    = n.sha256
        init_proc = n.initiating_process

        l1 = "\n".join([
            f"Hi Team,",
            f"",
            f"We have observed *{alert_name}* alert on host *{device}*.",
            f"",
            f"*User:* {user}",
            *(  [f"*File name:* {file_name}"] if file_name else []),
            *(  [f"*File path:* {file_path}"] if file_path else []),
            *(  [f"*File hash:* {sha256}"] if sha256 else []),
            *(  [f"*{file_name}* was downloaded / executed by *{init_proc}*."] if init_proc and file_name else []),
            f"*{self._vt_line(vt)}*",
            f"*Investigation state:* {inv_state}",
            f"*Severity:* {sev}",
            f"*Event time:* {alert_time} UTC",
            *(  [self._test_device_note()] if is_test_device else []),
            f"",
            f"[Auto-triaged by RAPTOR]",
        ])

        if is_test_device:
            return PlaybookResult(
                l1_comment=l1,
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai"],
                auto_close=False,
            )

        l2 = "\n".join([
            f"The alert was generated due to *{file_name or alert_name}* being detected on the host.",
            f"The custom detection rule in Microsoft EDR blocked the application.",
            *(  [f"File confirmed malicious on VirusTotal ({vt['detections']}/{vt['total']} engines)."] if vt.get("detections") else []),
            f"File was detected and prevented — no further action required.",
            f"*Marking as True Positive.*",
            f"",
            f"[Auto-triaged by RAPTOR]",
        ])

        return PlaybookResult(
            l1_comment=l1,
            l2_comment=l2,
            triage_class="AUTO_CLOSED_TP",
            action="resolved",
            labels=["edr-triage-ai"],
            auto_close=True,
        )
