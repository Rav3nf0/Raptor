"""Network Port Sweep playbook — Sentinel Discovery alerts.

These Sentinel scheduled-analytics alerts ("Network Port Sweep detected on <port>")
carry no MDE evidence and no incident entities — the decision is made purely on the
swept *destination port*, per the SOC Confluence runbook:

  Sweeps on destination ports 7000, 9182, 3389, 60935 are expected/known-good
  infrastructure activity → classify + close as False Positive.
  Any other port → escalate to L2 (possible reconnaissance).

The known-good port list is configurable via EDR_PORTSWEEP_FP_PORTS.
"""
from __future__ import annotations

import re

from edr_triage.config import get_edr_config
from edr_triage.playbooks.base import BasePlaybook, PlaybookResult

# "... detected on 9182", "... on port 3389", "port sweep on 60935"
_PORT_RE = re.compile(r"\bon\s+(?:port\s+)?(\d{1,5})\b", re.IGNORECASE)
_ANY_PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)


def _extract_port(*texts: str) -> str:
    """Pull the swept destination port from the alert name / description."""
    for t in texts:
        if not t:
            continue
        m = _PORT_RE.search(t) or _ANY_PORT_RE.search(t)
        if m:
            p = m.group(1)
            if 0 < int(p) <= 65535:
                return p
    return ""


class PortSweepPlaybook(BasePlaybook):

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
        cfg = get_edr_config()
        fp_ports = cfg.portsweep_fp_ports()

        alert_name  = n.name if n.name != "Alert" else "Network Port Sweep"
        description = n.description
        device      = n.device if n.device != "Unknown Device" else ""
        sev         = n.severity
        alert_time  = n.alert_time

        port = _extract_port(alert_name, description)
        port_known_good = bool(port) and port in fp_ports
        ports_str = ", ".join(sorted(fp_ports, key=lambda x: int(x)))

        header = [
            f"Hi Team,",
            f"",
            f"We have observed *{alert_name}*" + (f" on host *{device}*." if device else "."),
            f"",
            f"A network port sweep was detected"
            + (f" targeting destination port *{port}*" if port else "")
            + " (tactic: Discovery), reported by multiple source IPs.",
            f"",
        ]
        if port:
            header.append(f"*Destination port:* {port}")
        header.append(f"*Severity:* {sev}")
        if alert_time:
            header.append(f"*Event time:* {alert_time} UTC")
        header.append("")

        # ── Known-good port → False Positive ──────────────────────────────
        if port_known_good and not is_test_device:
            l1 = "\n".join(header + [
                f"Per the SOC Confluence runbook, network port sweeps on destination ports "
                f"*{ports_str}* are expected/known-good infrastructure activity and are "
                f"classified as *False Positive*.",
                f"",
                f"Destination port *{port}* is on the known-good list — classifying and "
                f"closing as *False Positive*.",
                f"",
                f"[Auto-triaged by RAPTOR]",
            ])
            l2 = "\n".join([
                f"*{alert_name}* — destination port *{port}* matches the documented known-good "
                f"port-sweep list ({ports_str}) per the SOC Confluence runbook.",
                f"No further action required. Closed as *False Positive*.",
                f"",
                f"[Auto-triaged by RAPTOR]",
            ])
            return PlaybookResult(
                l1_comment=l1,
                l2_comment=l2,
                triage_class="AUTO_CLOSED_FP",
                action="resolved",
                labels=["edr-triage-ai"],
                auto_close=True,
            )

        # ── Unknown / non-allowlisted port (or test device) → L2 ──────────
        if port:
            reason = (
                f"Destination port *{port}* is NOT on the known-good port-sweep list "
                f"({ports_str}). This may be genuine reconnaissance."
            )
        else:
            reason = (
                "Could not determine the swept destination port from the alert — "
                "manual review required."
            )
        note = ""
        if is_test_device and port_known_good:
            note = ("\n_Note: destination port is on the known-good list, but this is a "
                    "registered test device — L2 confirmation still required._")

        l1 = "\n".join(header + [
            reason + note,
            f"",
            f"Escalating to L2 for review — confirm the source IPs and whether the scan "
            f"is authorized/expected activity.",
            f"",
            f"[Auto-triaged by RAPTOR]",
        ])
        return PlaybookResult(
            l1_comment=l1,
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai"],
            auto_close=False,
        )
