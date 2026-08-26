"""Normalized alert schema — the anti-corruption boundary between SIEM/EDR
vendors and the triage playbooks.

Playbooks should read fields off `NormalizedAlert` (n.device, n.user,
n.threat_name, n.detections …) instead of reaching into the raw vendor dict
(alert.get("computerDnsName"), alert.get("relatedUser")…). All knowledge of a
specific vendor's field names lives in `normalize_alert()` below.

Adding a new SIEM later = add one branch/adapter here that maps its payload
into NormalizedAlert. The playbooks do not change.

The original vendor payloads stay reachable via `n.raw` / `n.evidence` /
`n.sentinel` as an escape hatch for the rare playbook that needs
vendor-specific depth (e.g. generic's AWS CloudTrail parse).
"""
from __future__ import annotations

from dataclasses import dataclass, field

_LOGIN_PLACEHOLDER = "LOGIN"


@dataclass
class NormalizedAlert:
    # ── identity ──────────────────────────────────────────────────────
    name: str = ""                       # alert display name / title
    source: str = "mde"                  # "mde" | "sentinel" | future vendors
    severity: str = ""
    tactics: list = field(default_factory=list)

    # ── scope ─────────────────────────────────────────────────────────
    device: str = "Unknown Device"
    user: str = "Unknown User"

    # ── threat / disposition ──────────────────────────────────────────
    threat_name: str = ""
    threat_family: str = ""
    investigation_state: str = ""
    remediation_status: str = ""         # derived from evidence (Blocked/Remediated/…)
    status: str = ""                     # vendor case status (Resolved/New/…)
    classification: str = ""             # TruePositive / FalsePositive / …

    # ── file / process evidence ───────────────────────────────────────
    file_name: str = ""
    file_path: str = ""
    sha256: str = ""
    initiating_process: str = ""
    command_lines: list = field(default_factory=list)
    detections: list = field(default_factory=list)

    # ── context ───────────────────────────────────────────────────────
    alert_time: str = ""                 # "YYYY-MM-DD HH:MM:SS" (UTC)
    description: str = ""
    incident_url: str = ""

    # ── escape hatches (raw vendor payloads) ──────────────────────────
    raw: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    sentinel: dict = field(default_factory=dict)


def normalize_alert(
    alert: dict | None,
    evidence: dict | None = None,
    sentinel_entities: dict | None = None,
    *,
    source: str = "mde",
    device_hint: str = "",
    user_hint: str = "",
) -> NormalizedAlert:
    """Map a raw MDE alert (+ extracted evidence) into a NormalizedAlert.

    device_hint / user_hint carry any device/user the pipeline already resolved
    via Sentinel/CloudTrail enrichment; they win over the raw MDE fields when set.
    """
    alert = alert or {}
    evidence = evidence or {}

    # User: prefer the MDE relatedUser, then the real process account from evidence,
    # then a non-placeholder logged-on user, then pipeline hint, then assignee.
    # (The "LOGIN" skip and evidence-account preference were previously malware-only.)
    logged = [
        u.get("accountName", "")
        for u in (alert.get("loggedOnUsers") or [])
        if u.get("accountName") and u["accountName"].upper() != _LOGIN_PLACEHOLDER
    ]
    user = (
        (alert.get("relatedUser") or {}).get("userName", "")
        or evidence.get("account_name", "")
        or (logged[0] if logged else "")
        or user_hint
        or alert.get("assignedTo", "")
        or "Unknown User"
    )

    device = (
        device_hint
        or alert.get("computerDnsName")
        or alert.get("machineName")
        or "Unknown Device"
    )

    alert_time = (alert.get("alertCreationTime") or alert.get("firstEventTime", ""))[:19].replace("T", " ")

    return NormalizedAlert(
        name=alert.get("alertDisplayName") or alert.get("title", "") or "Alert",
        source=source,
        severity=alert.get("severity", ""),
        tactics=alert.get("mitreTechniques", []) or [],
        device=device,
        user=user,
        threat_name=alert.get("threatName", "") or alert.get("threatFamilyName", ""),
        threat_family=alert.get("threatFamilyName", ""),
        investigation_state=alert.get("investigationState", ""),
        remediation_status=evidence.get("remediation_status", ""),
        status=alert.get("status", "") or "",
        classification=alert.get("classification", "") or "",
        file_name=evidence.get("file_name", ""),
        file_path=evidence.get("file_path", ""),
        sha256=evidence.get("sha256", ""),
        initiating_process=evidence.get("initiating_process", ""),
        command_lines=evidence.get("command_lines", []) or [],
        detections=evidence.get("detections", []) or [],
        alert_time=alert_time,
        description=alert.get("_description", "") or alert.get("description", "") or "",
        incident_url=alert.get("incident_url", "") or "",
        raw=alert,
        evidence=evidence,
        sentinel=sentinel_entities or {},
    )
