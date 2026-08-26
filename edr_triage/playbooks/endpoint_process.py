"""Endpoint-process playbook — suspicious download-tool / LOLBin process alerts.

Covers MDE endpoint alerts like "Suspicious curl behavior" (also wget, certutil,
bitsadmin). These were previously misrouted to the generic → Sentinel CloudTrail
parse, which read the WRONG host's data: it surfaced a container host's runc
process history (148 noise commands) and the wrong device/user, while the real
triggering command (the curl invocation), correct device, and user live in the
MDE alert's own evidence.

This playbook reads the MDE evidence directly:
- device/user from the MDE alert (correct endpoint)
- the actual process command line(s) from evidence.command_lines
- file path / SHA256 / VT result
"""
from __future__ import annotations

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult

# Download sources that are almost always legitimate admin/tooling activity —
# used to soften the verdict on LOLBin script alerts (e.g. AWS driver installs).
_KNOWN_GOOD_DOMAINS = (
    "amazonaws.com", "microsoft.com", "windowsupdate.com", "azure.com",
    "github.com", "githubusercontent.com", "nvidia.com", "intel.com",
)


def _domain(url: str) -> str:
    m = url.split("://", 1)[-1].split("/", 1)[0].lower()
    return m


class EndpointProcessPlaybook(BasePlaybook):

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
        alert_name = n.name if n.name != "Alert" else "Suspicious process"
        device     = n.device
        user       = n.user
        alert_time = n.alert_time

        ev         = evidence or {}
        cmds       = n.command_lines or ([ev["command_line"]] if ev.get("command_line") else [])
        file_path  = n.file_path
        sha256     = n.sha256
        init_proc  = n.initiating_process

        # LOLBin / PowerShell-in-memory enrichment (Sentinel NRT) — see pipeline.
        lolbin     = (sentinel_entities or {}).get("lolbin") or {}
        remote_urls = lolbin.get("remote_urls") or []
        known_good = [u for u in remote_urls
                      if any(_domain(u).endswith(d) for d in _KNOWN_GOOD_DOMAINS)]
        all_good   = bool(remote_urls) and len(known_good) == len(remote_urls)

        vt = vt or {}
        vt_detections = vt.get("detections", 0)

        lines = [
            "Hi Team,",
            "",
            f"We have observed a *{alert_name}* alert — a suspicious endpoint process "
            "(download utility / LOLBin) that can be used to fetch a payload or reach a "
            "command-and-control server. Details below:",
            "",
            f"*Device:* {device}",
            f"*User:* {user}",
        ]
        if alert_time:
            lines.append(f"*Event time (UTC):* {alert_time}")
        if init_proc:
            lines.append(f"*Initiating process:* {init_proc}")

        if cmds:
            lines.append("")
            lines.append(f"*Command line{'s' if len(cmds) > 1 else ''} ({len(cmds)}):*")
            for c in cmds[:10]:
                lines.append(f"  `{c}`")
            if len(cmds) > 10:
                lines.append(f"  _… {len(cmds) - 10} more suppressed_")
        else:
            lines += [
                "",
                "_Note: the process command line was not present in the MDE alert evidence — "
                "open the alert in Defender / run an mde_advanced_hunt on DeviceProcessEvents "
                "for the exact invocation._",
            ]

        if file_path:
            lines.append("")
            lines.append(f"*File path:* {file_path}")
        if sha256:
            lines.append(f"*SHA256:* {sha256}")
            if vt_detections:
                lines.append(f"*VirusTotal:* {vt_detections}/{vt.get('total', '?')} detections")
            elif vt:
                lines.append("*VirusTotal:* no detections")

        # Download-source assessment (LOLBin path).
        if remote_urls:
            lines.append("")
            lines.append(f"*Download source{'s' if len(remote_urls) > 1 else ''}:* "
                         + ", ".join(remote_urls[:5]))
            if all_good:
                lines.append(f"↳ All download sources are on known-good domains "
                             f"({', '.join(sorted({_domain(u) for u in known_good}))}) — "
                             f"consistent with legitimate admin/tooling activity, not a payload drop.")
        if lolbin.get("multi_device") and lolbin.get("other_devices"):
            lines.append("")
            lines.append(f"⚠ PowerShell activity in this window also seen on: "
                         f"{', '.join(lolbin['other_devices'][:5])} — confirm the correct host.")

        if is_test_device:
            lines += ["", self._test_device_note()]

        # Recommendation — softer verdict when the source is clearly legitimate.
        if all_good:
            rec = ("Recommendation: the command and its download source appear to be legitimate "
                   "admin/tooling activity (known-good domain). Likely benign — requesting business "
                   "justification from the user/host owner to confirm this was expected, then close "
                   "as False Positive if confirmed.")
        elif lolbin:
            rec = ("Recommendation: review the PowerShell command and its destination. Requesting "
                   "business justification for the observed activity; if the download target is "
                   "untrusted or unexpected for this user/host, treat as potential payload delivery "
                   "and contain. Escalating to L2 for validation.")
        else:
            rec = ("Recommendation: review the command and its destination (URL/host). If the download "
                   "target is untrusted or the activity is unexpected for this user/host, treat as a "
                   "potential payload delivery / C2 and contain. Escalating to L2 for validation.")
        lines += ["", rec, "", "[Auto-triaged by RAPTOR]"]

        return PlaybookResult(
            l1_comment="\n".join(lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai", "endpoint-process"],
            auto_close=False,
        )
