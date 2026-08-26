"""EDR Triage data models."""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class TriagedAlert(BaseModel):
    """A fully triaged MDE alert record stored in MongoDB."""

    # Jira + MDE identifiers
    jira_key: str
    alert_id: str
    alert_name: str

    # Device + user context (from MDE Alerts API)
    device_name: str = ""
    machine_id: str = ""
    user_name: str = ""
    # Co-users on a grouped multi-user incident (see ShadowResult.additional_users).
    # Read by the closure poller's no-shadow memory path, which binds entities from
    # this store record. EMPTY for single-user alerts.
    additional_users: list[str] = Field(default_factory=list)
    severity: str = ""                    # Low / Medium / High / Informational
    tactics: list[str] = Field(default_factory=list)

    # File evidence (from MDE Evidence API)
    file_name: str = ""
    file_path: str = ""
    sha256: str = ""
    initiating_process: str = ""          # what spawned the file (e.g. "Google Chrome")
    investigation_state: str = ""         # Remediated / Running / No threats found / etc.
    alert_time: str = ""                  # ISO8601 string

    # Enrichment results
    vt_detections: Optional[int] = None
    vt_total: Optional[int] = None
    vt_verdict: str = ""                  # malicious / suspicious / clean / unknown

    # Triage outcome
    playbook: str = ""                    # block_tool / malware / reverse_shell / lateral_move / generic
    triage_class: str = ""                # AUTO_CLOSED_TP / AUTO_CLOSED_FP / NEEDS_L2 / URGENT / PENDING
    l1_comment: str = ""
    # True only when l1_comment came from the DETERMINISTIC playbook (shadow/copilot —
    # code reading Sentinel/CloudTrail fields straight, no LLM involved). False in
    # autonomous phase, where l1_comment is agent_result.to_jira_comment(...) — the
    # AI's own reasoning rendered into the same field. Both look identical in shape
    # (verdict, evidence, prose); nothing else on this record tells them apart.
    # Exists so a grounding/fact-check can trust l1_comment as ground truth ONLY on
    # the deterministic path — trusting it unconditionally would let an autonomous-
    # phase ticket validate the agent's claim against the agent's OWN earlier claim.
    # Defaults False (not True) so every record written before this field existed —
    # which today are ALL deterministic, since autonomous hasn't shipped — is treated
    # as unverified rather than silently grandfathered in as trustworthy.
    l1_comment_deterministic: bool = False
    l2_comment: str = ""
    action_taken: str = ""                # resolved / event_analysis / labels_only / dry_run
    labels_applied: list[str] = Field(default_factory=list)
    is_test_device: bool = False

    # LLM reasoning trace (stored for debugging / Phase 3 skill tuning)
    llm_reasoning: str = ""

    # Timestamps
    processed_at: float = 0.0
    jira_created_at: str = ""
