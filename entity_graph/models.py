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
    # Decayed below the floor, or an allowlist entry past its expiry. Kept, not deleted:
    # these are L2-approved decisions, and deleting one used to erase the audit trail of
    # WHY a ticket was closed. Every retrieval path filters tier in (curated, golden), so
    # an archived memory is inert everywhere without any caller having to know about it.
    archived = "archived"


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
    actor: str = ""                # PRIMARY principal (user / service account) the verdict is scoped to
    # Every OTHER actor this same verdict covers, on a multi-actor incident. `actor`
    # stays the primary for backward compatibility with every existing lookup; this is
    # additive so a co-actor's justification is findable too. write_memory() dedupes
    # on jira_key (one memory per ticket), so a multi-actor incident can't just write
    # one memory per actor — this field is what makes the single memory findable for
    # each of them. EMPTY for a single-actor verdict, same as additional_users.
    actors: list[str] = Field(default_factory=list)
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
    # Which ACCOUNT of those apps (Netskope instance_id: example.onmicrosoft.com,
    # acme, ...). "Bulk upload to Slack is fine" must not clear an upload to a personal
    # Slack, so an entry with app_instances set only fires when EVERY live instance is
    # in this list — fail-closed, like commands and apps. Empty = instance-agnostic.
    app_instances: list[str] = Field(default_factory=list)
    # Netskope UBA direction the approval covers: "upload" | "download" | "" (n/a). Both
    # families share one subtype, so without this a download approval would also clear
    # the same person's UPLOADS — the exfiltration direction.
    uba_direction: str = ""
    # What the L2-approved Netskope UBA activity looked like: {"hosts": [...],
    # "max_events": int, "max_bytes": int}. uba_guard refuses a learned close from
    # another device or at more than twice the approved volume — the approval alone
    # cannot tell the owner from an insider or an attacker repeating the same shape.
    uba_baseline: dict = Field(default_factory=dict)
    # Deterministic actor-allowlist: when a golden memory has auto_fp=True and the
    # live alert's actor (+device, if set) + alert_type (+commands, if set) match,
    # the pipeline auto-closes as FP WITHOUT invoking the LLM. Human-gated: only an
    # L2 promote/arm can set this — it never auto-populates from an L1 closure.
    auto_fp: bool = False
    # Hard expiry for an armed auto_fp entry. Unlike decay, which only lowers a
    # confidence the deterministic matcher used to ignore, this bounds how long an
    # "actor X is fine" decision can close tickets without an L2 re-arming it. None on
    # rows armed before expiry existed — the matcher then derives one from
    # resolved_at/created_at, so legacy entries age out too.
    expires_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None
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
    # linked taylor.singh and never toby.vohra, the user the verdict was
    # actually reached about — and recall is entity-id scoped, so that memory would
    # never surface for him. EMPTY for single-user alerts.
    additional_users: list[str] = Field(default_factory=list)
    # Paired host<->actor groups for a multi-actor incident: [{"actor","hosts","commands"}].
    # additional_users/additional_hosts are flat, unlinked lists — neither can answer
    # "which host belongs to which actor". DEMO-109720: one incident, two actors, each
    # with their own disjoint set of hosts/commands; a justification request addressed
    # to one actor settles nothing about the other. EMPTY for single-actor alerts, and
    # for anything not on the AWS/SSM CloudTrail path (this is built from ARN session
    # principals — see edr_triage/pipeline.py::_add_actor_host).
    actor_hosts: list[dict] = Field(default_factory=list)
    severity: str = ""
    # Normalized process basenames seen in this alert (from the enrichment the
    # pipeline already computed). Persisted so the allowlist suggester can mine
    # command-level FP patterns — it is NOT used at triage time.
    alert_processes: list[str] = Field(default_factory=list)
    # Identity of the underlying detection EVENT, when it can be established from the
    # vendor's own ids (see edr_triage/burst.py). One Netskope sweep fans out into many
    # Jira tickets — DEMO-110864..110872 were 9 tickets in 101 seconds for one finding,
    # each paying for its own agent run. Tickets sharing a finding_group_id reuse the first
    # one's verdict instead of re-deriving it. EMPTY whenever event identity is unknown,
    # which disables reuse entirely. Every sibling is still scored; nothing is excluded.
    finding_group_id: str = ""
    # Set on a ticket whose verdict was carried over from a sibling rather than
    # independently investigated. Empty on a ticket that was actually triaged.
    duplicate_of: str = ""
    # How the DLP evidence was bound: "alert" (the alert's own matched rows) or
    # "window_sweep" (the fallback, whose rows are NOT established to be this alert's).
    # Persisted purely so the question is answerable from the row. Without it the two
    # are indistinguishable after the fact — a sweep filtered by user_hint returns one
    # user and one event, exactly like a correct alert-scoped bind — and answering
    # "did this ticket bind the right event?" required logs nobody can reach
    # (DEMO-110937). EMPTY on non-DLP alerts and on rows written before this existed.
    dlp_bind_source: str = ""
    # The Sentinel alert id the DLP bind actually used, and the users it returned.
    # Diagnostic: without these, "did this ticket bind its own alert's rows?" cannot be
    # answered from the row, and three separate theories about DEMO-110937 (truncation,
    # time-column mismatch, sweep fallback) were each plausible and each wrong.
    dlp_bind_alert_id: str = ""
    dlp_bound_users: list[str] = Field(default_factory=list)
    # Asset ownership at triage time. "unregistered" / "unresolved:<tag>" are recorded
    # rather than left blank: not being in the asset register is a different and
    # actionable fact from never having been looked up.
    asset_tribe: str = ""
    asset_owners: list[str] = Field(default_factory=list)
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
    # When L1 opened the business-justification loop (Jira "AWAITING MORE INPUTS").
    # Stamped once and never cleared. This is the only record that L1 CHOSE TO ASK:
    # l1_triage_class captures escalate-or-close and nothing else, so an agent verdict of
    # REQUEST_JUSTIFICATION could never be scored as agreeing with L1 even when both made
    # the same call. Read by the l1_agreement metric; it scores nothing on its own.
    l1_awaiting_inputs_at: Optional[datetime] = None
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
    # Stable machine-readable tag for WHICH gate set blocked_by_safety (e.g.
    # "multi_host_unassessed", "grounding_actor") — see AgentResult.safety_gate_kind in
    # agent_core/result.py. edr_triage/gate_retriage.py filters on this (never on the
    # free-form safety_block_reason prose) to decide which escalations are an evidence
    # gap worth an automatic deferred retry. Empty when no gate fired.
    safety_gate_kind: str = ""
    # Set ONLY when blocked_by_safety came from the concurrent-open-alerts gate — the
    # OTHER ticket(s) whose still-open status blocked this one. Lets the closure poller
    # re-trigger this ticket the moment any of those siblings actually closes, instead of
    # it sitting at NEEDS_L2 forever with nothing tracking that the block has lifted.
    blocked_by_concurrent_keys: list[str] = Field(default_factory=list)
    # ------------------------------------------------------------------
    # Autonomous close + its overturn (edr_triage.jira_closure_poller)
    #
    # Only populated when RAPTOR itself closed the ticket (AGENT_PHASE=autonomous AND the
    # family on EDR_AUTONOMOUS_FAMILIES), never when a human closed it. That distinction
    # is the whole point: an autonomous close is the only kind nobody reviewed before it
    # happened, so it is the only kind that needs a standing report.
    #
    # The overturn signal is the REOPEN, not a label or a review click. `False Positive ->
    # Event Analysis` is transition 61 and works (verified on DEMO-112428), it is what an
    # analyst would do on disagreeing anyway, and it therefore needs no new habit — an
    # unpracticed habit produces silence that reads as approval.
    #
    # CAVEAT worth remembering when reading these: a reopen detects DISAGREEMENT, not
    # diligence. reopened_at being None cannot distinguish "checked and correct" from
    # "nobody ever looked", which is why the report pairs it with age-since-close.
    # ------------------------------------------------------------------
    # Closed as a duplicate of another ticket. Stamped by
    # jira_closure_poller._mark_duplicate_resolved, which already stamps l1_resolved_at so
    # the concurrency gate stops treating the ticket as an open sibling — but left no
    # record of WHY it resolved. Without that, `verdict_match is None` plus a resolution
    # is indistinguishable from "still awaiting a human", so ~14% of all incidents (857 in
    # 45 days) reported as pending review forever. They are not pending; they will never be
    # scoreable, because "see the other ticket" is not a verdict. Reported as their own
    # bucket so the accuracy denominator is honest about what it excludes and why.
    duplicate_at: Optional[datetime] = None
    autonomous_closed_at: Optional[datetime] = None
    reopened_at: Optional[datetime] = None
    reopened_by: Optional[str] = None
    # Status the reopen landed on, so a reopen straight to `L2 Analysis required` reads
    # differently from one parked back in `Event Analysis`.
    reopened_to: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    phase: str = "shadow"  # "shadow" | "copilot" | "autonomous"

    class Settings:
        name = "eg_shadow_results"
        indexes = [
            [("jira_key", 1)],
            [("created_at", -1)],
            [("verdict_match", 1)],
            [("blocked_by_concurrent_keys", 1)],
            [("safety_gate_kind", 1)],
        ]


class TriageProgress(Document):
    """Live step-by-step progress for a manually-triggered run-ticket call, so an
    operator watching the dashboard can see what the agent is doing right now instead
    of only the finished verdict.

    Mongo-backed, not an in-memory dict — `_ticket_run_state` (app/views/edr_triage_views.py)
    already taught this lesson once: per-process state is meaningless to poll behind a
    multi-replica load balancer, since the request that started the run and the request
    polling for it can land on different pods. This document is written by whichever pod
    is actually running the triage and read by whichever pod happens to serve the poll.

    One document per jira_key, overwritten on each new run (mirrors ShadowResult's
    overwrite-on-re-triage pattern) — this is transient UI state, not a durable record,
    so there is nothing here worth keeping a history of across runs.
    """
    jira_key: str
    status: str = "running"  # "running" | "done" | "error"
    steps: list[dict] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    error: str = ""

    class Settings:
        name = "eg_triage_progress"
        indexes = [[("jira_key", 1)]]


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
    apps: list = Field(default_factory=list)       # cloud apps the pattern covers (Netskope UBA)
    app_instances: list = Field(default_factory=list)  # which ACCOUNT of those apps
    uba_direction: str = ""              # "upload" | "download" for Netskope UBA patterns
    uba_baseline: dict = Field(default_factory=dict)  # approved hosts + largest volume
    source: str = ""                     # which miner proposed it (e.g. "uba_learner")
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
