"""AWS GuardDuty EC2-DNS playbook — "The EC2 instance i-... queried a phishing/
drive-by domain name."

These arrived via Sentinel with an essentially empty Jira description ("Involved
Users DLP Profile" — literal blank placeholders) and were previously in
classifier.py's _SKIP_PATTERNS: RAPTOR never touched them at all. L1 has been
manually opening the AWS GuardDuty console (via the finding link) and retyping
the same fields into a Jira comment every time — instance id, IAM profile,
private/public IP, the queried domain, GuardDuty's own threat classification —
for every one of dozens of near-identical tickets (DEMO-110594, DEMO-106031,
DEMO-105959, DEMO-110279, ...). Deterministic — no LLM reasoning: this replaces
the mechanical retyping, not the judgment call. Verdict is always NEEDS_L2.
"""
from __future__ import annotations

import re

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult

# Out-of-band callback services: a server resolving one means injected input made it
# call out (interactsh, Burp Collaborator, webhook.site, canarytokens).
_OAST_RE = re.compile(r"(?:^|\.)(?:oast\.(?:live|fun|pro|site|online|me)|interact\.sh|"
                      r"burpcollaborator\.net|oastify\.com|webhook\.site|canarytokens\.com)$",
                      re.IGNORECASE)


def dns_finding_kind(gd: dict | None, alert_name: str = "") -> str:
    """Which GuardDuty EC2-DNS finding this is, most serious first when one node has
    several: metadata_rebind > c2 > callback > phishing.

    The phishing/drive-by reading ("a DNS-only lookup with no follow-up traffic is the
    usual FP") is wrong for the others: DEMO-118243 was an SSRF probing IMDS through
    169.254.169.254.nip.io with no follow-up connection, a real attack that matches
    the FP pattern exactly."""
    gd = gd or {}
    types = " ".join([*(gd.get("finding_types") or []), str(gd.get("ActivityType") or ""),
                      str(gd.get("threat_family_name") or ""), alert_name or ""])
    doms = [str(d) for d in (gd.get("domains") or ([gd["Domain"]] if gd.get("Domain") else []))]
    if "MetadataDNSRebind" in types or re.search(r"dns\s+rebinding", types, re.I) \
            or any("169.254.169.254" in d for d in doms):
        return "metadata_rebind"
    if re.search(r"C&CActivity|BlackholeTraffic|DGADomainRequest|DNSDataExfiltration|"
                 r"command\s*(?:&|and)\s*control|algorithmically\s+generated", types, re.I):
        return "c2"
    if "SuspiciousDomainRequest" in types or any(_OAST_RE.search(d.rstrip(".")) for d in doms):
        return "callback"
    return "phishing"


_RECOMMENDATION = {
    "metadata_rebind": (
        "Recommendation: a lookup that resolves to the instance metadata service "
        "(169.254.169.254) is how SSRF reaches IAM credentials, and it needs no "
        "follow-up connection to the domain to matter. If this is an EKS node, find the "
        "pod that made the lookup (Upwind detections for the node, container logs) and "
        "the inbound request that carried the URL; confirm IMDSv2 is required with hop "
        "limit 1, and check CloudTrail for the node or pod roles used from outside our "
        "NAT/VPC. Do not close on 'DNS request only'."),
    "c2": (
        "Recommendation: a command-and-control, sinkholed, DGA or DNS-exfiltration "
        "lookup points at code already running on the host. Identify the process (or "
        "pod) that made it and treat the instance as possibly compromised until shown "
        "otherwise; a DNS-only lookup is not exculpatory here."),
    "callback": (
        "Recommendation: if the domain is an out-of-band callback service (interactsh "
        "*.oast.*, Burp Collaborator, webhook.site), a server resolving it means "
        "injected input made it call out: an injection or SSRF reached it. Find the "
        "workload and the inbound request that carried the payload, and confirm whether "
        "an authorised test was running. A DNS-only lookup is still the signal."),
    "phishing": (
        "Recommendation: confirm whether this EC2 instance made any further "
        "connection to the flagged domain beyond the DNS lookup (a DNS-only query "
        "with no follow-up traffic is the pattern this alert family has repeatedly "
        "closed as false positive on known internal hosts) — check outbound "
        "connection logs for the instance around this timestamp."),
}


class GuardDutyPlaybook(BasePlaybook):

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
        alert_name   = n.name if n.name != "Alert" else "AWS GuardDuty finding"
        incident_url = n.incident_url

        ent = sentinel_entities or {}
        gd = ent.get("guardduty_dns") or {}

        lines = [
            "Hi Team,",
            f'we are observing an alert indicating that *"{alert_name}"*.',
            "",
        ]
        if gd.get("InstanceId") or gd.get("Domain"):
            lines.append("*Resource Details:*")
            if gd.get("TimeGenerated"):
                lines.append(f"  Time Created (UTC): {str(gd['TimeGenerated'])[:19].replace('T', ' ')}")
            if gd.get("TenantId"):
                lines.append(f"  Tenant Id: {gd['TenantId']}")
            if gd.get("AccountId"):
                lines.append(f"  AWS Account Id: {gd['AccountId']}")
            if gd.get("InstanceId"):
                lines.append(f"  Instance Id: {gd['InstanceId']}")
            if gd.get("InstanceProfile"):
                lines.append(f"  Instance Profile Role: {gd['InstanceProfile']}")
            if gd.get("PrivateIp"):
                lines.append(f"  Private IP: {gd['PrivateIp']}")
            if gd.get("PublicIp"):
                lines.append(f"  Public IP: {gd['PublicIp']}")
            lines.append("")
            lines.append("*Service Details:*")
            # Every queried domain, each with what it actually IS. A bare hostname is
            # not actionable — the site's identity/category is the deciding fact on a
            # drive-by/phishing-domain alert, and it is what L1 hand-looks-up today.
            _doms = gd.get("domains") or ([gd["Domain"]] if gd.get("Domain") else [])
            _reps = gd.get("domain_reputation") or {}
            if _doms:
                _n = f" ({len(_doms)})" if len(_doms) > 1 else ""
                lines.append(f"  Domain{_n}: {', '.join(_doms)}")
                for _d in _doms:
                    _r = _reps.get(_d)
                    if not _r:
                        continue
                    _cats = ", ".join(sorted({str(v) for v in (_r.get("categories") or {}).values() if v})[:4])
                    lines.append(
                        f"    - {_d}: VT {_r.get('detections', 0)}/{_r.get('total', 0)} "
                        f"({_r.get('verdict', '?')})"
                        + (f", reputation {_r['reputation']}" if _r.get("reputation") else "")
                        + (f", categorised as: {_cats}" if _cats else ", no category on record")
                    )
                if not _reps:
                    lines.append("    _(domain reputation lookup unavailable — check VT manually)_")
            if gd.get("ActionType"):
                lines.append(f"  Action Type: {gd['ActionType']}")
            if gd.get("threat_purpose"):
                lines.append(f"  Threat Purpose: {gd['threat_purpose']}")
            if gd.get("resource_type_affected"):
                lines.append(f"  Resource Type Affected: {gd['resource_type_affected']}")
            if gd.get("threat_family_name"):
                lines.append(f"  Threat Family Name: {gd['threat_family_name']}")
            if len(gd.get("finding_types") or []) > 1:
                lines.append(f"  Finding Types: {', '.join(gd['finding_types'])}")
            lines.append("")
            if gd.get("DetectorId") or gd.get("Region") or gd.get("Partition") or gd.get("FindingLink"):
                lines.append("*GuardDuty Details:*")
                if gd.get("DetectorId"):
                    lines.append(f"  Detector Id: {gd['DetectorId']}")
                if gd.get("Partition"):
                    lines.append(f"  Partition: {gd['Partition']}")
                if gd.get("Region"):
                    lines.append(f"  Region: {gd['Region']}")
                _links = gd.get("finding_links") or ([gd["FindingLink"]] if gd.get("FindingLink") else [])
                if _links:
                    lines.append(f"  Finding Link{'s' if len(_links) > 1 else ''}:")
                    for _l in _links:
                        lines.append(f"    {_l}")
                if gd.get("finding_count", 0) > 1:
                    lines.append(f"  ({gd['finding_count']} GuardDuty findings in this incident window)")
                lines.append("")
        else:
            lines += [
                "_GuardDuty finding details were not available from the Sentinel API — "
                "open the Sentinel incident / AWS GuardDuty console for the resource and "
                "domain detail._",
                "",
            ]

        if incident_url:
            lines += [f"*Sentinel Incident:* {incident_url}", ""]
        if is_test_device:
            lines += [self._test_device_note(), ""]

        lines += [
            _RECOMMENDATION[dns_finding_kind(gd, alert_name)],
            "",
            "Escalating to L2 for review.",
            "",
            "[Auto-triaged by RAPTOR]",
        ]

        return PlaybookResult(
            l1_comment="\n".join(lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai", "guardduty-dns"],
            auto_close=False,
        )
