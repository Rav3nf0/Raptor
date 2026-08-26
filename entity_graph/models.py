"""Security Context Graph — Beanie document models for MongoDB.

Collections:
  eg_entities       — unique entities (device, user, hash, domain, ip, process)
  eg_relationships  — edges between entities
  eg_memories       — contextual decisions with trust scores and decay
  eg_analyst_profiles — per-analyst accuracy tracking
  eg_shadow_results — shadow mode AI verdicts for comparison with L1
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from enum import Enum

from beanie import Document
from pydantic import Field, field_validator
from bson import ObjectId


class EntityType(str, Enum):
    user = "user"
    device = "device"
    domain = "domain"
    ip = "ip"
    hash = "hash"
    process = "process"


class MemoryType(str, Enum):
    analyst_verdict = "analyst_verdict"
    agent_verdict = "agent_verdict"
    exception = "exception"
    threat_context = "threat_context"


class MemoryTier(str, Enum):
    quarantine = "quarantine"
    curated = "curated"
    golden = "golden"


class TriageClass(str, Enum):
    AUTO_CLOSED_FP = "AUTO_CLOSED_FP"
    AUTO_CLOSED_TP = "AUTO_CLOSED_TP"
    NEEDS_L2 = "NEEDS_L2"
    # The activity needs a business justification from the acting principal before it
    # can be judged — the workflow's AWAITING MORE INPUTS loop, which L1 owns during
    # EVENT ANALYSIS. Deliberately distinct from NEEDS_L2: asking the user to explain
    # an admin action is NOT an L2 technical escalation, and conflating the two both
    # overstated the escalation and mis-scored the outcome (DEMO-106406).
    REQUEST_JUSTIFICATION = "REQUEST_JUSTIFICATION"
    URGENT = "URGENT"


class SCGEntity(Document):
    entity_type: EntityType
    value: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    source_systems: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    tags: list[str] = Field(default_factory=list)
    alert_count: int = 0

    class Settings:
        name = "eg_entities"
        indexes = [
            [("entity_type", 1), ("value", 1)],
        ]


class SCGRelationship(Document):
    from_id: str
    to_id: str
    rel_type: str
    evidence: list[str] = Field(default_factory=list)
    occurrence_count: int = 1
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "eg_relationships"
        indexes = [
            [("from_id", 1), ("to_id", 1), ("rel_type", 1)],
        ]


class SCGMemory(Document):
    entity_ids: list[str] = Field(default_factory=list)
    memory_type: MemoryType
    content: str
    confidence: float
    tier: MemoryTier = MemoryTier.quarantine
    decay_factor: float = 0.90
    source: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_decayed_at: datetime = Field(default_factory=datetime.utcnow)
    alert_ref: str = ""
    jira_key: str = ""
    # Alert type for playbook-level pattern learning
    alert_type: str = ""   # classifier result: "cloudtrail", "privesc", "malware", etc.
    l1_comment: str = ""   # verbatim L1 analyst comment extracted from Jira
    l2_comment: str = ""   # L2 resolution comment — the L2-specific text (not the L1 handoff), capped ~400 chars
    # Scoping — is this verdict tied to a specific actor/device, or a generalizable
    # lesson for the whole alert type? "entity" (default) is recalled ONLY when the
    # actor/device matches; "playbook" is the ONLY scope surfaced type-wide to the
    # LLM (get_playbook_memories). Defaulting to "entity" stops one actor/device FP
    # from teaching the model that the whole alert class is benign (DEMO-104192).
    scope: str = "entity"          # "entity" | "playbook"
    actor: str = ""                # principal (user / service account) the verdict is scoped to
    device: str = ""              # device the verdict is scoped to (optional)
    # Optional command/process narrowing for the actor-allowlist. When set, an
    # armed auto_fp entry only fires if EVERY normalized process in the live alert
    # is in this list — so "actor X running backup.sh is FP" never whitelists
    # "actor X running mimikatz". Empty = command-agnostic (actor+device only).
    # Stored as normalized basenames (see edr_triage.service_allowlist.normalize_process).
    commands: list[str] = Field(default_factory=list)
    # Cloud-app narrowing — the SaaS analogue of `commands`, for Netskope/CASB alerts
    # where the meaningful dimension is the destination app, not a process. "bulk
    # upload to Slack is expected for this user" must NOT also clear a bulk upload to
    # a personal Drive, so an armed entry with apps set only fires when the live
    # alert's app is in this list. Empty = app-agnostic (actor+device only).
    # The Netskope path already binds per-user apps from Netskope_Alerts_CL and prints
    # them in the L1 comment; this is where that becomes queryable rather than prose.
    apps: list[str] = Field(default_factory=list)
    # Deterministic actor-allowlist: when a golden memory has auto_fp=True and the
    # live alert's actor (+device, if set) + alert_type (+commands, if set) match,
    # the pipeline auto-closes as FP WITHOUT invoking the LLM. Human-gated: only an
    # L2 promote/arm can set this — it never auto-populates from an L1 closure.
    auto_fp: bool = False
    # Quarantine fields
    quarantine_reason: str = ""
    resolved_by: str = ""
    resolved_at: Optional[datetime] = None

    class Settings:
        name = "eg_memories"
        indexes = [
            [("entity_ids", 1)],
            [("tier", 1), ("confidence", -1)],
            [("jira_key", 1)],
            [("alert_type", 1), ("tier", 1), ("confidence", -1)],
            [("auto_fp", 1), ("tier", 1), ("alert_type", 1)],
        ]


class AnalystProfile(Document):
    analyst_id: str
    display_name: str = ""
    total_verdicts: int = 0
    correct_verdicts: int = 0
    accuracy: float = 0.0
    trust_tier: str = "new"  # "new" | "standard" | "senior"
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_active: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "eg_analyst_profiles"
        indexes = [[("analyst_id", 1)]]

    def update_accuracy(self) -> None:
        if self.total_verdicts >= 50:
            self.accuracy = self.correct_verdicts / self.total_verdicts
            if self.accuracy >= 0.75:
                self.trust_tier = "senior"
            elif self.accuracy >= 0.60:
                self.trust_tier = "standard"
            else:
                self.trust_tier = "new"
        elif self.total_verdicts > 0:
            self.accuracy = self.correct_verdicts / self.total_verdicts

    def memory_trust(self) -> float:
        return {"new": 0.65, "standard": 0.72, "senior": 0.80}.get(self.trust_tier, 0.65)


class ShadowResult(Document):
    jira_key: str
    alert_id: str
    alert_name: str
    device_name: str = ""
    user_name: str = ""
    # Every OTHER user this incident spans (a rule aggregating SingleAlert emits one
    # alert for all matched rows). `user_name` stays the PRIMARY actor — this is the
    # rest, persisted so the closure poller can link a memory to every user involved.
    # Without it the memory bound only accounts[0]: DEMO-107416's quarantine memory
    # linked taylor.singh and never sachin.khodpia, the user the verdict was
    # actually reached about — and recall is entity-id scoped, so that memory would
    # never surface for him. EMPTY for single-user alerts.
    additional_users: list[str] = Field(default_factory=list)
    severity: str = ""
    # Normalized process basenames seen in this alert (from the enrichment the
    # pipeline already computed). Persisted so the allowlist suggester can mine
    # command-level FP patterns — it is NOT used at triage time.
    alert_processes: list[str] = Field(default_factory=list)
    # AI verdict
    ai_triage_class: str
    ai_confidence: float
    ai_reasoning: str = ""
    ai_recommended_actions: list[str] = Field(default_factory=list)

    @field_validator("ai_recommended_actions", mode="before")
    @classmethod
    def _coerce_actions(cls, v):
        """Tolerate non-string actions on READ as well as write.

        The model sometimes emits `actions` as objects
        (`[{"action": "close_alert", "reason": "..."}]`) instead of strings.
        AgentResult is a plain dataclass, so nothing validated that on the way in
        and such rows reached Mongo. On the way back out they raised
        `string_type` and made the document unhydratable — which is not a
        cosmetic failure: ANY query touching the row blew up, so
        check_concurrent_alerts swallowed the error and returned
        concurrent_count=0 (safety gate silently off), the closure poller could
        not load the row to score it (accuracy point lost), and the overwrite in
        _save_shadow_result could not read the row it was meant to replace — so
        the document was permanently stuck. Coercing on read heals those rows
        in place instead of requiring DB surgery.
        """
        if not isinstance(v, list):
            return v
        from agent_core.result import normalize_action  # local: avoids import cycle
        return [s for a in v if (s := normalize_action(a).strip())]

    # Last re-triage (force=true rerun). created_at stays the ORIGINAL triage time
    # because the 24h concurrent-alert window is defined on it, so it can't double as
    # a "this was re-run" signal — hence a separate stamp. None = never re-triaged.
    retriaged_at: Optional[datetime] = None
    # Investigation trail — which tools the agent called, in order, + iteration count
    ai_iterations: int = 0
    ai_tool_calls: list[dict] = Field(default_factory=list)
    ai_error: Optional[str] = None
    # Human L1 verdict (populated by jira_closure_poller)
    l1_triage_class: Optional[str] = None
    l1_analyst_id: Optional[str] = None
    l1_resolved_at: Optional[datetime] = None
    # L1 → L2 handoff (populated when ticket hits "L2 ANALYSIS REQUIRED")
    l1_handoff_at: Optional[datetime] = None
    l1_handoff_comment: str = ""
    # L2 final verdict (populated when L2 closes the ticket)
    l2_triage_class: Optional[str] = None
    l2_analyst_id: Optional[str] = None
    l2_resolved_at: Optional[datetime] = None
    # Agreement tracking — compared against L2 verdict for escalated tickets, L1 otherwise
    verdict_match: Optional[bool] = None
    # Validation debate — second-LLM critic outcome (agent_core/critic.py)
    critic_ran: bool = False
    critic_agreed: Optional[bool] = None
    critic_reason: str = ""
    # Safety-layer visibility — did a deterministic gate/critic override the model's
    # verdict, and to what. pre_safety_class is the model's ORIGINAL verdict; when it
    # was an auto-close and ai_triage_class is NEEDS_L2, a gate escalated it. Lets us
    # measure over-gating (how much automation the safety layer costs) per reason.
    blocked_by_safety: bool = False
    safety_block_reason: str = ""
    pre_safety_class: str = ""
    # Set ONLY when blocked_by_safety came from the concurrent-open-alerts gate — the
    # OTHER ticket(s) whose still-open status blocked this one. Lets the closure poller
    # re-trigger this ticket the moment any of those siblings actually closes, instead of
    # it sitting at NEEDS_L2 forever with nothing tracking that the block has lifted.
    blocked_by_concurrent_keys: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    phase: str = "shadow"  # "shadow" | "copilot" | "autonomous"

    class Settings:
        name = "eg_shadow_results"
        indexes = [
            [("jira_key", 1)],
            [("created_at", -1)],
            [("verdict_match", 1)],
            [("blocked_by_concurrent_keys", 1)],
        ]


class PlaybookSuggestion(Document):
    """A propose-only suggestion generated when the AI's triage systematically
    diverges from the L1/L2 human verdict for a class of alert. Reviewed by a
    human via the suggestions API — never auto-applied to code/routing.
    """
    alert_type: str = ""                 # classifier category (e.g. credential_access)
    alert_name: str = ""                 # representative alert name
    suggestion_type: str = "modify"      # "modify" | "new" | "routing"
    target_playbook: str = ""            # existing playbook to change (empty for "new")
    title: str = ""
    divergence_summary: str = ""         # what the AI did vs what L1/L2 did
    rationale: str = ""                  # why the change is warranted
    proposed_change: str = ""            # concrete suggested change (human implements)
    evidence_jira_keys: list = Field(default_factory=list)
    mismatch_count: int = 0
    status: str = "pending"              # "pending" | "approved" | "dismissed" | "implemented"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_by: str = ""
    reviewed_at: Optional[datetime] = None

    class Settings:
        name = "eg_playbook_suggestions"
        indexes = [
            [("status", 1)],
            [("created_at", -1)],
            [("alert_type", 1)],
        ]


class AllowlistSuggestion(Document):
    """A propose-only suggestion to arm the deterministic actor-allowlist.

    Mined by edr_triage.allowlist_suggester from resolved shadow results where a
    human repeatedly closed an alert as FALSE POSITIVE for the same actor (+device,
    +commands) while OSCAR over-escalated it to NEEDS_L2. NEVER auto-applied — an
    L2 reviews the row and clicks Arm, which writes a golden auto_fp memory. The
    `cluster_key` dedupes one open suggestion per (alert_type, actor, device).
    """
    alert_type: str = ""                 # classifier category (e.g. privesc)
    alert_name: str = ""                 # representative alert name
    actor: str = ""                      # principal the FP closures share
    device: str = ""                     # device (empty = any)
    commands: list = Field(default_factory=list)   # normalized processes common to the cluster
    fp_count: int = 0                    # how many FP closures back this pattern
    evidence_jira_keys: list = Field(default_factory=list)
    cluster_key: str = ""                # dedupe key: f"{alert_type}|{actor}|{device}"
    status: str = "pending"              # "pending" | "armed" | "dismissed"
    armed_memory_id: str = ""            # id of the golden memory created on Arm
    created_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_by: str = ""
    reviewed_at: Optional[datetime] = None

    class Settings:
        name = "eg_allowlist_suggestions"
        indexes = [
            [("status", 1)],
            [("created_at", -1)],
            [("cluster_key", 1)],
        ]


class PlannedActivity(Document):
    """A declared maintenance/compliance window — a KNOWN benign activity (usually a
    script) that trips EDR fleet-wide. While active, the pipeline auto-closes matching
    alerts as FALSE POSITIVE deterministically (no LLM), matching on a command-line
    substring — actor- and device-agnostic — so one declaration covers the whole fleet.

    Deliberately SEPARATE from golden memory: this is a temporary announcement, not a
    learned precedent. It is **time-boxed** (`expires_at`) and inert once expired
    (the matcher filters on it), so it can never suppress anything after the run ends.
    """
    pattern: str = ""            # case-insensitive substring matched against alert command lines
    label: str = ""              # human description, e.g. "Q3 compliance scan"
    alert_type: str = ""         # optional scope; empty = any alert type
    expires_at: datetime         # required — window end (UTC); inert after this
    created_by: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    hit_count: int = 0           # alerts this window auto-closed (visibility)

    class Settings:
        name = "eg_planned_activity"
        indexes = [
            [("expires_at", -1)],
        ]


class AlertUnderTest(Document):
    """A detection rule currently known to be broken / mid-tuning (e.g. wrong KQL logic).

    While its alert_name is listed here, the closure poller (edr_triage/jira_closure_poller.py)
    never sets verdict_match on its ShadowResults and never writes a quarantine memory for
    them — grading the AI, or spending an L2 analyst's review time, against a rule that
    is not yet producing real signal penalizes the triage for a fault in the rule.
    Triage itself (labels/comments on the ticket) is UNAFFECTED — only scoring and the
    review queue are suppressed.

    Matches on exact alert NAME. Remove the entry once the rule is fixed to resume
    scoring/quarantining it normally.
    """
    alert_name: str
    reason: str = ""
    added_by: str = ""
    added_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "eg_alerts_under_test"
        indexes = [
            [("alert_name", 1)],
        ]
