"""MongoDB documents for SentinelShadow findings and audit log."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from beanie import Document
from pydantic import Field


def _uid() -> str:
    return str(uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Finding(Document):
    id: str = Field(default_factory=_uid)
    detector: str = ""
    severity: str = ""
    device_id: str = ""
    device_name: str = ""
    account_name: str = ""
    indicator: str = ""
    summary: str = ""
    raw: dict = Field(default_factory=dict)
    mitre_techniques: list = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)
    reviewed_at: Optional[datetime] = None
    reviewed_by: str = ""
    decision: str = ""
    sentinel_incident_id: str = ""
    allowlisted_by_rule: str = ""
    note: str = ""
    # Pre-revamp backlog (2026-09-30: ~96.6k unreviewed, 86% from the old rare_domains).
    # Kept for replay and history, hidden from the working queue, never used for dedup.
    legacy: bool = False
    # AI suggestion (shadow_hunter/ai_triage.py, or a manual pass). Advisory only: it never
    # reviews, allowlists or escalates; an analyst's /decision does. ai_agreed is set from that
    # human decision, so agreement is measured against people, never against another AI.
    ai_verdict: str = ""             # true_positive | false_positive | unsure
    ai_confidence: Optional[float] = None
    ai_reasoning: str = ""
    ai_evidence: list = Field(default_factory=list)
    ai_by: str = ""
    ai_prompt_version: str = ""
    ai_at: Optional[datetime] = None
    ai_error: str = ""
    ai_attempts: int = 0
    # "FP, but worth acting on" (policy/exposure, e.g. an AI agent installing persistence): a
    # non-empty reason keeps the finding out of ai=fp, so bulk-snoozing AI FPs cannot bury it.
    ai_attention: str = ""
    ai_agreed: Optional[bool] = None
    # Incident story this finding was grouped into (shadow_hunter/stories.py); "" when none.
    story_id: str = ""
    # Slack alert sent for this finding (shadow_hunter/notify.py); None = not announced.
    notified_at: Optional[datetime] = None

    class Settings:
        name = "shadow_findings"
        indexes = [
            "detector",
            "severity",
            "created_at",
            "reviewed_at",
            "device_id",
            "ai_at",
            "story_id",
        ]


class Story(Document):
    """Related findings grouped into one incident (shadow_hunter/stories.py). Advisory only:
    a story never decides, snoozes or allowlists its findings. Every link between two findings
    is an edge with the reason it was made, so a grouping can be audited and undone."""
    id: str = Field(default_factory=_uid)
    title: str = ""
    status: str = "open"              # open | closed | merged
    severity: str = "medium"          # highest of its findings; never lowered
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
    entities: dict = Field(default_factory=dict)   # hosts [{name, aliases, ips, asset_ids}], accounts, indicators
    finding_ids: list = Field(default_factory=list)
    edges: list = Field(default_factory=list)      # {a, b, kind, reason, at}
    timeline: list = Field(default_factory=list)   # {ts, host, ips, event, source, severity, finding_id}
    report: dict = Field(default_factory=dict)     # {sections: [{heading, body}], by, prompt_version, at, version}
    report_history: list = Field(default_factory=list)
    detached: list = Field(default_factory=list)   # finding ids an analyst removed; never auto-rejoin
    related: list = Field(default_factory=list)    # closed stories this one continues
    merged_into: str = ""
    closed_by: str = ""
    closed_at: Optional[datetime] = None
    # Related Jira alerts and VictoriaLogs context, snapshotted (shadow_hunter/story_context.py)
    context: dict = Field(default_factory=dict)
    context_at: Optional[datetime] = None
    # "Request report" pressed and no report posted since: the next Claude pass picks it up
    report_requested_at: Optional[datetime] = None
    report_requested_by: str = ""
    # Indicators an analyst added (an attacker IP from IIS logs, a file stem): looked up in
    # VictoriaLogs with the story's own. [{value, kind: ip|term, note, by, at}]
    indicators: list = Field(default_factory=list)
    # What Slack was last told (shadow_hunter/notify.py): {severity, alerts: [jira keys], at}
    notified: dict = Field(default_factory=dict)

    class Settings:
        name = "shadow_stories"
        indexes = ["status", "updated_at", "finding_ids"]


class AuditLog(Document):
    id: str = Field(default_factory=_uid)
    actor: str = ""
    action: str = ""
    target_type: str = ""
    target_id: str = ""
    payload: dict = Field(default_factory=dict)
    ts: datetime = Field(default_factory=_now)

    class Settings:
        name = "shadow_audit_log"
