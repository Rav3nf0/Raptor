"""Netskope web-proxy playbook — "Failed Login" / blocked web-access events.

These are Netskope web-filtering / policy events (e.g. a blocked category or app
like Social Media / Facebook), NOT Azure AD credential attacks. They were
previously misrouted to the Entra credential_access playbook, which printed the
wrong "incorrect password / account locked" narrative and dropped the
Netskope-specific evidence (hostname, source IP, app, URL, user agent, category).
"""
from __future__ import annotations

import re

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


# Known Netskope field labels — used to bound a captured value so a flattened
# single-line description ("User: x Category: y Hostname: z …") doesn't let one
# field greedily swallow the rest.
_NS_LABELS = (
    r"User\s+Agent|Source\s+IP|Involved\s+Users?|Users?|Category|"
    r"Hostname|App|Url|URL|Page|DLP\s+Profile"
)


def _field(text: str, label_pattern: str) -> str:
    """Pull a single labelled field (e.g. 'Hostname: X') from alert text.

    Stops the value at the next known label or a 2+ space separator so multi-field
    lines parse cleanly.
    """
    if not text:
        return ""
    m = re.search(label_pattern + r"\s*:\s*(.+)", text, re.IGNORECASE)
    if not m:
        return ""
    val = m.group(1).splitlines()[0]
    val = re.split(r"\s{2,}", val)[0]                                  # real desc uses 2+ space separators
    val = re.split(rf"\s+(?:{_NS_LABELS})\s*:", val, flags=re.IGNORECASE)[0]  # or stop at next known label
    return val.strip()[:200]


class NetskopePlaybook(BasePlaybook):

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
        alert_name   = n.name if n.name != "Alert" else "Netskope - Failed Login"
        incident_url = n.incident_url
        desc         = n.description

        ent = sentinel_entities or {}

        # ── Netskope cloud-malware branch ─────────────────────────────────
        # Detail bound from Netskope_Alerts_CL by the pipeline (DEMO-104584).
        nm = ent.get("netskope_malware") or {}
        if nm and nm.get("malware_name"):
            action  = (nm.get("action") or "").strip()
            blocked = any(t in action.lower() for t in ("block", "prevent", "quarantin"))
            sev     = (nm.get("severity") or "").strip() or "unknown"
            lines = [
                "Hi Team,",
                f"we have received a *Netskope malware alert* — *{nm.get('malware_name')}* "
                f"({nm.get('malware_type') or 'malware'}, severity {sev}).",
                "",
            ]
            if nm.get("user"):
                lines.append(f"*User:* {nm['user']}" + (f" ({nm['user_ip']})" if nm.get("user_ip") else ""))
            if nm.get("hostname") or nm.get("device"):
                lines.append(f"*Device:* {nm.get('hostname') or nm.get('device')}"
                             + (f" — {nm['os']}" if nm.get("os") else ""))
            if nm.get("activity"):
                lines.append(f"*Activity:* {nm['activity']}" + (f" via {nm['browser']}" if nm.get("browser") else ""))
            if nm.get("app"):
                lines.append(f"*Application:* {nm['app']}")
            if nm.get("page"):
                lines.append(f"*Page/URL:* {nm['page']}")
            if nm.get("src_ip") or nm.get("dst_ip"):
                loc = f" ({nm['src_location']}, {nm['src_country']})" if nm.get("src_location") else ""
                dst = f"  →  *Dest IP:* {nm['dst_ip']}" if nm.get("dst_ip") else ""
                lines.append(f"*Source IP:* {nm.get('src_ip', '?')}{loc}{dst}")
            if nm.get("policy"):
                lines.append(f"*Policy:* {nm['policy']}")
            if nm.get("detection_engine"):
                lines.append(f"*Detection engine:* {nm['detection_engine']}")
            if nm.get("scanner_result"):
                lines.append(f"*Scanner result:* {nm['scanner_result']}")
            if action:
                flag = "  ✓ blocked/prevented" if blocked else "  ⚠ detection only — NOT confirmed blocked"
                lines.append(f"*Netskope action:* {action}{flag}")
            if nm.get("sha256"):
                lines.append(f"*SHA256:* {nm['sha256']}")
            if nm.get("ambiguous"):
                others = ", ".join([nm.get("user", "")] + (nm.get("other_users") or []))
                lines += ["", f"⚠ Multiple users had malware detections in this window ({others}) — verify this is the right user."]
            lines += [
                "",
                ("Recommendation: Netskope reports this as *blocked/prevented* — confirm remediation and "
                 "that the user did not retrieve the file; likely a false positive if prevention held. Escalating to L2."
                 if blocked else
                 "Recommendation: Netskope *detected* this malicious file but the action does not confirm a block — "
                 "verify whether the download was blocked or the file reached the endpoint (check MDE on the host) and "
                 "validate the SHA256. Escalating to L2."),
                "",
                "[Auto-triaged by RAPTOR]",
            ]
            return PlaybookResult(
                l1_comment="\n".join(lines),
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai", "netskope-malware"],
                auto_close=False,
            )

        # ── Netskope UBA branch (Bulk Upload / Bulk Download) ─────────────
        # Detail bound from Netskope_Alerts_CL by the pipeline (DEMO-107416). The rule
        # aggregates SingleAlert, so one alert covers every matched row — report EVERY
        # user, each with their own host/app/file detail. Reporting only the first
        # account entity is how DEMO-107416 named taylor.singh while L1 investigated
        # sachin.khodpia, leaving the other user's uploads unexamined on a closed ticket.
        uba = ent.get("netskope_uba") or {}
        if uba and uba.get("by_user"):
            kind      = uba.get("kind", "Upload")
            by_user   = uba["by_user"]
            uba_users = uba.get("users") or list(by_user)
            multi     = len(uba_users) > 1
            lines = [
                "Hi Team,",
                f"we have received a *Netskope bulk-{kind.lower()} anomaly* alert"
                + (f" spanning *{len(uba_users)} users* ({uba.get('event_count', 0)} events)."
                   if multi else f" ({uba.get('event_count', 0)} events)."),
                "",
                f"Netskope's UBA engine flagged an abnormal volume of file {kind.lower()}s. "
                "Each user below is a SEPARATE instance in this one alert and needs its own "
                "business justification — clearing one does not clear the others.",
                "",
            ]
            for u in uba_users:
                b = by_user.get(u) or {}
                lines.append(f"*User:* {u}  —  {b.get('events', 0)} {kind.lower()}(s)")
                if b.get("hosts"):
                    lines.append(f"  *Host:* {', '.join(b['hosts'][:4])}"
                                 + (f" ({b['device']})" if b.get("device") else "")
                                 + (f" — {b['os']}" if b.get("os") else ""))
                if b.get("apps"):
                    lines.append(f"  *App:* {', '.join(b['apps'][:4])}"
                                 + (f"  (CCL {b['ccl']})" if b.get("ccl") else ""))
                if b.get("pages"):
                    lines.append(f"  *Page:* {', '.join(b['pages'][:3])}")
                if b.get("file_types"):
                    lines.append(f"  *File type:* {', '.join(b['file_types'][:5])}")
                if b.get("total_bytes"):
                    lines.append(f"  *Total size:* {b['total_bytes']:,} bytes")
                if b.get("src_ips"):
                    lines.append(f"  *Source IP:* {', '.join(b['src_ips'][:4])}")
                if b.get("device_classification"):
                    lines.append(f"  *Device classification:* {b['device_classification']}")
                if b.get("useragent"):
                    lines.append(f"  *User agent:* {b['useragent'][:160]}")
                _fs, _ls = b.get("first_seen", ""), b.get("last_seen", "")
                if _fs:
                    lines.append(f"  *Time:* {_fs} UTC" + (f" → {_ls} UTC" if _ls and _ls != _fs else ""))
                lines.append("")
            if incident_url:
                lines += [f"*Sentinel Incident:* {incident_url}", ""]
            if is_test_device:
                lines += [self._test_device_note(), ""]
            lines += [
                "As part of the security review process, we request the business justification "
                f"for the observed {kind.lower()} activity"
                + (" from EACH user listed above." if multi else "."),
                "",
                "Escalating to L2 for review.",
                "",
                "[Auto-triaged by RAPTOR]",
            ]
            return PlaybookResult(
                l1_comment="\n".join(lines),
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai", "netskope-uba"]
                       + (["multi-user"] if multi else []),
                auto_close=False,
            )

        # Sentinel enrichment first, then fall back to parsing the alert description.
        accounts   = ent.get("accounts", []) or ([_field(desc, r"(?:Involved )?Users?")] if _field(desc, r"(?:Involved )?Users?") else [])
        category   = _field(desc, r"Category")
        app        = ent.get("app_display_name", "") or _field(desc, r"App")
        url        = (ent.get("urls") or [""])[0] or _field(desc, r"Url")
        hostname   = (ent.get("hosts") or [""])[0] or _field(desc, r"Hostname")
        source_ip  = (ent.get("ips") or [""])[0] or _field(desc, r"Source\s+IP")
        user_agent = ent.get("browser", "") or _field(desc, r"User\s+Agent")
        start_time = ent.get("start_time", "")
        end_time   = ent.get("end_time", "")

        accounts = [a for a in accounts if a]
        multi_user = len(accounts) > 1

        lines = [
            "Hi team,",
            f'we have received a Netskope web-access alert *"{alert_name}"*'
            + (f" involving *{len(accounts)} users*." if multi_user else "."),
            "",
            "Netskope blocked/failed this web request under its web-filtering policy. "
            "This is a *web-proxy policy event* (e.g. a blocked category or application), "
            "not an Azure AD credential/password attack.",
            "",
        ]

        if accounts:
            lines.append(f"*Affected Users ({len(accounts)}):*")
            for a in accounts:
                lines.append(f"  - {a}")
        if category:
            lines.append(f"*Category:* {category}")
        if app:
            lines.append(f"*App:* {app}")
        if url:
            lines.append(f"*URL:* {url}")
        if hostname:
            lines.append(f"*Hostname:* {hostname}")
        if source_ip:
            lines.append(f"*Source IP:* {source_ip}")
        if user_agent:
            lines.append(f"*User Agent:* {user_agent}")
        if start_time:
            lines.append(f"*StartTime:* {start_time}")
        if end_time:
            lines.append(f"*EndTime:* {end_time}")
        if incident_url:
            lines += ["", f"*Sentinel Incident:* {incident_url}"]

        if not any([category, app, url, hostname, source_ip, user_agent]):
            lines += [
                "",
                "_Note: Netskope event details (hostname, source IP, app, URL, user agent) "
                "were not available from the Sentinel API — open the Sentinel incident for the "
                "per-user web-access records._",
            ]

        if is_test_device:
            lines += ["", self._test_device_note()]

        lines += [
            "",
            "Recommendation: confirm whether this web access is expected for the user's role. "
            "If unexpected or policy-relevant, investigate for data exfiltration / misuse; "
            "otherwise this is likely a benign web-filtering block.",
            "",
            "Escalating to L2 for review.",
            "",
            "[Auto-triaged by RAPTOR]",
        ]

        return PlaybookResult(
            l1_comment="\n".join(lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai", "netskope-web"],
            auto_close=False,
        )
