"""Credential Access playbook — password spray, brute force, Entra ID attacks."""
from __future__ import annotations

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


class CredentialAccessPlaybook(BasePlaybook):

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
        n = normalized or normalize_alert(alert, evidence, sentinel_entities, source="sentinel")
        alert_name   = n.name if n.name != "Alert" else "Credential Access Alert"
        severity     = n.severity
        incident_url = n.incident_url

        ent = sentinel_entities or {}

        accounts      = ent.get("accounts", [])
        ips           = ent.get("ips", [])
        locations     = ent.get("locations", [])
        start_time    = ent.get("start_time", "")
        end_time      = ent.get("end_time", "")
        signin_count  = ent.get("signin_count", "")
        location_count = ent.get("location_count", str(len(locations)) if locations else "")
        ip_count      = ent.get("ip_count", str(len(ips)) if ips else "")
        app           = ent.get("app_display_name", "")
        browser       = ent.get("browser", "")
        os_name       = ent.get("os", "")

        upn = accounts[0] if accounts else ""
        short_name = upn.split("@")[0] if "@" in upn else upn
        multi_user = len(accounts) > 1

        lines = [
            "Hi team,",
            f'we have received alert title *"{alert_name}"* '
            + (f"involving *{len(accounts)} users*" if multi_user else f'where user *"{short_name}"*')
            + " — Sign-in was blocked by built-in protections due to high confidence of risk.",
            "",
            "The account is locked; tried to sign in too many times with an incorrect user ID or password.",
            "",
        ]

        if multi_user:
            lines.append(f"*Affected Users ({len(accounts)}):*")
            for a in accounts:
                lines.append(f"  - {a}")
        elif upn:
            lines.append(f"*UserPrincipalName:* {upn}")
        if start_time:
            lines.append(f"*StartTime:* {start_time}")
        if end_time:
            lines.append(f"*EndTime:* {end_time}")
        if location_count:
            lines.append(f"*LocationCount:* {location_count}")
        if locations:
            lines.append("")
            for loc in locations:
                lines.append(loc)

        if ip_count:
            lines.append("")
            lines.append(f"*Ip Address count:* {ip_count}")
        if ips:
            lines.append("")
            for ip in ips:
                lines.append(ip)

        if app or browser or os_name or signin_count:
            lines.append("")
        if app:
            lines.append(f"*AppDisplayName:* {app}")
        if browser:
            lines.append(f"*Browser:* {browser}")
        if os_name:
            lines.append(f"*Operating System:* {os_name}")
        if signin_count:
            lines.append(f"*Sign-in Count:* {signin_count}")

        if incident_url:
            lines += ["", f"*Sentinel Incident:* {incident_url}"]

        if not ent:
            lines += [
                "",
                "_Note: Sentinel API enrichment unavailable — open the Sentinel incident for full details._",
                "",
                "*Common error codes:*",
                "  50053 — Account locked (too many failed attempts)",
                "  50055 — Expired password",
                "  50126 — Invalid username or password",
            ]

        if is_test_device:
            lines += ["", self._test_device_note()]

        lines += [
            "",
            "we are sending this ticket to L2 for further investigation.",
            "",
            "[Auto-triaged by RAPTOR]",
        ]

        return PlaybookResult(
            l1_comment="\n".join(lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai"],
            auto_close=False,
        )
