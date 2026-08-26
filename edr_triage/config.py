"""EDR Triage configuration.

All credentials reuse existing env vars populated by lib/config.py from AWS
Secrets Manager. No new secrets required.
"""
from __future__ import annotations

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class EDRTriageConfig(BaseSettings):
    # ------------------------------------------------------------------
    # Jira — set JIRA_URL to your Jira Cloud site (e.g. https://your-org.atlassian.net).
    # Left empty, the ticket poller is inert (no tickets fetched) — expected in a
    # credential-free demo; drive triage via /api/edr-triage/run-synthetic instead.
    # ------------------------------------------------------------------
    jira_url: str = Field(default="", alias="JIRA_URL")
    jira_project_key: str = Field(default="SEC", alias="EDR_JIRA_PROJECT")
    jira_issue_type: str = Field(default="[System] Incident", alias="JIRA_ISSUE_TYPE")
    jira_email: Optional[str] = Field(default=None, alias="JIRA_EMAIL")
    jira_token: Optional[str] = Field(default=None, alias="JIRA_API_TOKEN")
    jira_verify_ssl: bool = Field(default=True, alias="JIRA_VERIFY_SSL")

    # ------------------------------------------------------------------
    # MDE — reuse existing credentials
    # ------------------------------------------------------------------
    mde_tenant_id: str = Field(default="", alias="MDE_TENANT_ID")
    mde_client_id: str = Field(default="", alias="MDE_CLIENT_ID")
    mde_client_secret: str = Field(default="", alias="MDE_CLIENT_SECRET")

    # ------------------------------------------------------------------
    # VirusTotal + Gemini — reuse existing credentials
    # ------------------------------------------------------------------
    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-2.5-flash", alias="GEMINI_MODEL")

    # ------------------------------------------------------------------
    # Polling behaviour
    # ------------------------------------------------------------------
    poll_interval_seconds: int = Field(default=300, alias="EDR_POLL_INTERVAL")
    jira_lookback_hours: int = Field(default=6, alias="EDR_LOOKBACK_HOURS")

    # ------------------------------------------------------------------
    # Jira transition names (must match exact names in your Jira project)
    # ------------------------------------------------------------------
    auto_close_transition: str = Field(default="Resolve", alias="EDR_CLOSE_TRANSITION")
    event_analysis_transition: str = Field(default="Event Analysis", alias="EDR_EVENT_ANALYSIS_TRANSITION")

    # ------------------------------------------------------------------
    # Chase-reply handling (edr_triage.chase_reply_poller)
    # Off by default: it is the first path where RAPTOR transitions a real ticket, so
    # it must be turned on deliberately. It can only ever route to L2 Analysis required
    # (hard allowlist) and never closes anything.
    # ------------------------------------------------------------------
    chase_reply_enabled: bool = Field(default=False, alias="EDR_CHASE_REPLY")
    # Hours a chased ticket may sit unanswered before it is REPORTED as stale. Nothing
    # is transitioned on breach — unanswered tickets stay in Awaiting more inputs by
    # design; this only keeps them visible instead of silently accumulating.
    chase_stale_hours: int = Field(default=72, alias="EDR_CHASE_STALE_HOURS")

    # ------------------------------------------------------------------
    # Known test/red-team devices (comma-separated hostnames). An entry ending in
    # "*" matches by prefix (e.g. "privesc-security-testing-*" covers the whole
    # numbered series without listing each box) — everything else matches exactly
    # or as a dot-suffixed FQDN, unchanged from before.
    # Alerts on these devices are never auto-closed; always needs-l2-review.
    # ------------------------------------------------------------------
    known_test_devices: str = Field(
        default="",
        alias="EDR_TEST_DEVICES",
    )

    # ------------------------------------------------------------------
    # Network Port Sweep — destination ports that the SOC Confluence runbook
    # documents as expected/known-good infrastructure activity. Sweeps on these
    # ports are auto-classified as False Positive; any other port → needs-l2.
    # ------------------------------------------------------------------
    port_sweep_fp_ports: str = Field(
        default="7000,9182,3389,60935", alias="EDR_PORTSWEEP_FP_PORTS"
    )

    # ------------------------------------------------------------------
    # Dry-run and test flags
    # ------------------------------------------------------------------
    dry_run: bool = Field(default=False, alias="EDR_DRY_RUN")
    test_labels_only: bool = Field(default=False, alias="EDR_TEST_LABELS_ONLY")

    class Config:
        env_file = ".env"
        extra = "ignore"

    def is_test_device(self, hostname: str) -> bool:
        """Return True if hostname matches a known test/red-team device.

        An entry ending in "*" matches by prefix (a whole numbered series of
        red-team boxes, e.g. "security-testing-*"), so a new box in that series is
        covered on day one instead of needing EDR_TEST_DEVICES updated every time
        one gets provisioned.
        """
        devices = {d.strip().lower() for d in self.known_test_devices.split(",") if d.strip()}
        h = hostname.lower()
        for d in devices:
            if d.endswith("*"):
                if h.startswith(d[:-1]):
                    return True
            elif h == d or h.startswith(d + "."):
                return True
        return False

    def portsweep_fp_ports(self) -> set[str]:
        """Return the set of known-good port-sweep destination ports (as strings)."""
        return {p.strip() for p in self.port_sweep_fp_ports.split(",") if p.strip()}


_edr_config: EDRTriageConfig | None = None


def get_edr_config() -> EDRTriageConfig:
    global _edr_config
    if _edr_config is None:
        _edr_config = EDRTriageConfig()
    return _edr_config


def reset_edr_config() -> None:
    global _edr_config
    _edr_config = None
