"""EDR Triage configuration.

All credentials reuse existing env vars populated by lib/config.py from AWS
Secrets Manager. No new secrets required.
"""
from __future__ import annotations

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings

# Shared severity ranking — Jira/MDE priority.name values, lowercased. Used both for
# the PagerDuty paging threshold here and, later, for the auto-containment severity
# gate (same free-text severity field, same comparison, one definition).
SEVERITY_RANK: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_rank(severity: str) -> int:
    """Rank a free-text severity string. Unknown/empty ranks below every known level
    (fails closed for paging/containment thresholds rather than defaulting to a page)."""
    return SEVERITY_RANK.get((severity or "").strip().lower(), -1)


# Tickets Claude closed in bulk on an operator's instruction (quarantine audit,
# 2026-10-12), from that operator's Jira account. They are AI closes, not analyst
# verdicts: the closure poller treats them like RAPTOR's own (not scored, no memory),
# and no guard may count one as a human clearance. Without this, closing as a person
# would have scored RAPTOR against itself and handed the repeat guards a precedent.
BULK_CLOSE_LABEL = "claude-bulk-closed"
NOT_BULK_CLOSED_JQL = f'(labels is EMPTY OR labels != "{BULK_CLOSE_LABEL}")'


class EDRTriageConfig(BaseSettings):
    # ------------------------------------------------------------------
    # Jira — reuse existing credentials
    # ------------------------------------------------------------------
    # Default matches brand_intel/config.py (same Jira Cloud site). Kept as a default
    # rather than "" because an empty base_url silently disabled the whole EDR poller:
    # httpx raises UnsupportedProtocol, poll_new_mde_tickets swallows it and returns [],
    # so triage stopped with no tickets tagged for ~2 days (last: DEMO-107156, 2026-08-03).
    # JIRA_URL still overrides for other deployments.
    jira_url: str = Field(default="https://jira.example.com", alias="JIRA_URL")
    jira_project_key: str = Field(default="SIM", alias="EDR_JIRA_PROJECT")
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
    # Jira transition names (must match exact names in your SIM project)
    # ------------------------------------------------------------------
    # DEPRECATED — do not use for new code. This matched on the TRANSITION's name, and
    # the default "Resolve" matches nothing: no status in the SIM workflow offers a
    # transition called "Resolve", and no ticket has entered `Resolved` in 60 days. Every
    # autonomous auto-close attempted through this silently no-opped. Kept only so an
    # existing EDR_CLOSE_TRANSITION override cannot break a deploy. Use auto_close_route.
    auto_close_transition: str = Field(default="Resolve", alias="EDR_CLOSE_TRANSITION")
    event_analysis_transition: str = Field(default="Event Analysis", alias="EDR_EVENT_ANALYSIS_TRANSITION")

    # ------------------------------------------------------------------
    # Autonomous auto-close route (edr_triage.jira_handler.walk_to_status)
    #
    # A fresh incident cannot reach a terminal state in one hop. `Open` only goes to
    # `Assigned`, then `Event Analysis`, and only from there to `False Positive` — which
    # is how humans do it (138 of 156 FP closes in 45 days took exactly this path).
    # Declared as a route rather than discovered, because discovering it would mean
    # transitioning real tickets to find out where transitions lead.
    # ------------------------------------------------------------------
    auto_close_route: str = Field(
        default="Assigned,Event Analysis,False Positive", alias="EDR_CLOSE_ROUTE"
    )
    # Statuses an auto-close may NEVER be walked through, checked against the whole route
    # before the first hop. `Awaiting more inputs` is the important one: entering it fires
    # the Acme Security Bot, which Slack-DMs whoever is named in the ticket. An
    # auto-close must never message a user on its way to closing their alert.
    auto_close_forbidden_statuses: str = Field(
        default="Awaiting more inputs,No Response,Duplicate,In Progress,Containment",
        alias="EDR_CLOSE_FORBIDDEN_STATUSES",
    )

    # ------------------------------------------------------------------
    # Per-family autonomy gate — NOT CONFIGURED HERE.
    #
    # It lives in AGENT_AUTONOMOUS_ALERTS, read by pipeline.autonomous_alert_allowlist()
    # and pipeline._effective_agent_phase(), which predate this module's involvement and
    # are pinned by edr_triage/agent_phase_test.py. A duplicate allowlist briefly existed
    # here and was removed: two allowlists guarding one action is worse than either
    # alone, because setting one and believing you are covered is the likely outcome.
    #
    # Note the matching differs from everything else in this file: that allowlist is an
    # EXACT, casefolded alert_name match, not a substring. "Network Port Sweep" alone
    # matches nothing — each variant must be listed ("Network Port Sweep detected on
    # 3389", "... on 9182", and so on). That fails closed on a new port, which is safe
    # but does mean a newly-seen variant silently will not be autonomous.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # User chase (outbound half — NOT BUILT YET).
    #
    # Gates the `event_analysis` action, which transitions a ticket into
    # `Awaiting more inputs` — the Acme Security Bot's trigger, which Slack-DMs whoever
    # the ticket's `Involved Users` cell names. ON since 2026-09-30, and it DOES message real
    # employees. Only the Netskope Bulk Upload / Bulk Download playbook can request a chase,
    # and only for users bound from the alert itself who pass the slack-acme reachability
    # gate; the chase itself is idempotent (store.claim_user_chase) and every answer is
    # routed to L2 by chase_reply_poller. Set EDR_USER_CHASE=false to stop all DMs.
    # ------------------------------------------------------------------
    user_chase_enabled: bool = Field(default=True, alias="EDR_USER_CHASE")
    # `Awaiting more inputs` is the status whose RE-ENTRY fires the Acme Security Bot —
    # `Event Analysis` (below, already shipped as event_analysis_transition) is only the
    # intermediate hop the L1 sequence passes through on the way there.
    awaiting_input_transition: str = Field(default="Awaiting more inputs", alias="EDR_AWAITING_INPUT_TRANSITION")
    # The Category custom field the bot watches, and the option value that fires it.
    # Field ID (never the name "category" — see set_category's docstring for why) and the
    # option's real, typo-and-all spelling: `Cyble | No Repsonse | Others | Sentinel One
    # | Sumologic` is the full option set on SIM, and "No Repsonse" is spelled that way
    # in Jira itself, not a mistake made here.
    category_field_id: str = Field(default="customfield_10335", alias="EDR_CATEGORY_FIELD_ID")
    category_no_response: str = Field(default="No Repsonse", alias="EDR_CATEGORY_NO_RESPONSE")
    # Every named user is chased (2026-09-30). The multi-address cell was verified against
    # 120 days of bot history — 6 of 7 multi-address cells got a dispatch per address,
    # including both comma-separated ones, the format set_involved_users writes. This cap
    # only guards against an absurd fan-out; above it the ticket escalates as before.
    user_chase_max_users: int = Field(default=10, alias="EDR_USER_CHASE_MAX_USERS")
    # DLP-Secret-key findings whose owner never explained such data: ask them via the
    # Security Bot (on) or leave the ticket for an analyst without messaging anyone (off).
    # Off until RAPTOR matures (2026-10-23).
    dlp_secret_key_ask: bool = Field(default=False, alias="EDR_DLP_SECRET_KEY_ASK")
    # Share of LEARNED Netskope bulk upload/download closes (uba_guard) that still go to
    # L2, drawn by a hash of the ticket key. Keeps human eyes on patterns that could
    # drift — an insider repeating an approved shape. 0 disables.
    uba_spotcheck_percent: int = Field(default=10, alias="EDR_UBA_SPOTCHECK_PERCENT")
    # The AD/Entra group `reachability()` (edr_triage/identity.py) treats as "has Slack".
    # Verified 2026-09-09 against real dispatch history — membership, not an OU or a `v-`
    # prefix, is what actually predicted both a successful chase and a silent failure.
    slack_group: str = Field(default="slack-acme", alias="EDR_SLACK_GROUP")

    # ------------------------------------------------------------------
    # Autonomous-close report (edr_triage.autoclose_report)
    #
    # The compensating control autonomy rests on: the accepted position is not that RAPTOR
    # never closes wrongly, but that an occasional wrong close is tolerable BECAUSE L2 sees
    # every close. Nothing enforces that second half except this report, so it must be ON
    # before AGENT_AUTONOMOUS_ALERTS is non-empty.
    # ------------------------------------------------------------------
    # HARDCODED on because `.env` is gitignored and untracked, so a deploy ships code only
    # and an env-only default could never be flipped without hand-editing the host. This is
    # the interlock's other half:
    # may_autoclose() refuses to close while it is off, so shipping autonomy without
    # shipping this would produce a system that quietly closes nothing.
    autoclose_report_enabled: bool = Field(default=True, alias="EDR_AUTOCLOSE_REPORT")
    # Hours an autonomous close may stand unreviewed before it is REPORTED as such.
    # Nothing is transitioned on breach. This exists because the overturn signal (a human
    # reopening the ticket) detects DISAGREEMENT, not diligence — no reopen cannot
    # distinguish "checked and correct" from "nobody looked", so the age has to be visible.
    autoclose_review_hours: int = Field(default=48, alias="EDR_AUTOCLOSE_REVIEW_HOURS")
    # Exact-repeat DLP duplicates (duplicate_guard.py): the same Netskope event ticketed
    # again within 2 minutes goes to Duplicate. Off = recommend only.
    auto_duplicate_enabled: bool = Field(default=True, alias="EDR_AUTO_DUPLICATE")
    # A national-ID DLP finding whose owner the Security Bot cannot reach goes straight to
    # L2 Analysis required (assigned to the L2 owner) instead of waiting for an L1 to move it.
    dlp_unreachable_to_l2: bool = Field(default=True, alias="EDR_DLP_UNREACHABLE_TO_L2")
    # Families L1 only ever forwards (pipeline._l2_direct_family) go straight to L2 Analysis
    # required, assigned to the L2 owner. Off = left for L1 as before.
    l2_direct_enabled: bool = Field(default=True, alias="EDR_L2_DIRECT")
    # Close the Sentinel incident once every SIM ticket naming it is decided, classified the
    # way L1 does it (sentinel_sync.py). off | dry (log only) | on (default, since MDE-API was
    # given Microsoft Sentinel Responder on 2026-10-14). "on" needs the Microsoft
    # Sentinel Responder role. Scope "raptor" = incidents behind tickets RAPTOR acted on;
    # "all" = every ticket, for when there is no L1. Days = how far back each sweep looks.
    # Tickets RAPTOR leaves for an analyst (no close, ask or route). record = note each one
    # in the store for /api/edr-triage/residual-report, nothing on the ticket; route = send
    # it to L2 the way the direct-to-L2 families go; off = nothing. "route" (user's call,
    # 2026-10-28): what L1 used to escalate reaches L2 — but Cyble digests and Netskope DLP
    # stay report-only in either mode (pipeline._RESIDUAL_REPORT_ONLY): L1 closed 94-96% of
    # those itself and L2 never handled them.
    residual_mode: str = Field(default="route", alias="EDR_RESIDUAL")
    # Root Privesc exact-repeat closes also need a familiar SSM session (privesc_guard
    # .session_check: known source IP, role and client). Off = the repeat alone closes.
    privesc_session_check: bool = Field(default=True, alias="EDR_PRIVESC_SESSION_CHECK")
    # Root Privesc blocked ONLY by another open alert is held behind it (Event Analysis,
    # the blocker's owner) instead of escalated beside it — concurrency_hold.py. Off = L2.
    concurrency_hold_enabled: bool = Field(default=True, alias="EDR_CONCURRENCY_HOLD")
    # When the agent asked for a justification, an exact repeat of a human-cleared session
    # (with a familiar session) closes instead of asking the same person again.
    privesc_rj_repeat_close: bool = Field(default=True, alias="EDR_PRIVESC_RJ_REPEAT_CLOSE")
    sentinel_close_mode: str = Field(default="on", alias="EDR_SENTINEL_CLOSE")
    sentinel_close_scope: str = Field(default="raptor", alias="EDR_SENTINEL_CLOSE_SCOPE")
    sentinel_close_days: int = Field(default=3, alias="EDR_SENTINEL_CLOSE_DAYS")
    # The first sweep after a pod starts looks back this far, to catch up anything left open.
    sentinel_close_backfill_days: int = Field(default=45, alias="EDR_SENTINEL_CLOSE_BACKFILL_DAYS")
    # Our own AnyDesk custom block rule firing on blocked / shadow-copy files is closed as a
    # true positive, as L2 always has (custom_block_guard.py). Off = recommend only.
    custom_block_close_enabled: bool = Field(default=True, alias="EDR_CUSTOM_BLOCK_CLOSE")
    # "Log injestion stopped" closes False Positive only when every silent table is one analysts
    # retired (log_ingestion_guard.py). Off = recommend only.
    log_ingestion_close_enabled: bool = Field(default=True, alias="EDR_LOG_INGESTION_CLOSE")
    # Where analysts open DeepIntel — links RAPTOR writes into tickets (the Brand Intel
    # drawer for raising a takedown). Not DEEPINTEL_URL, which is the in-pod address.
    deepintel_public_url: str = Field(default="https://deepintel.uat.example.com",
                                      alias="DEEPINTEL_PUBLIC_URL")
    # Slack INCOMING WEBHOOK url — one URL, no OAuth, no bot token, no app install, and no
    # relationship to the Acme Security Bot Logic App (which is out of scope and must not
    # be modified). Empty = Slack posting silently disabled, so the dashboard half of the
    # report ships without waiting on this credential.
    slack_webhook: str = Field(default="", alias="EDR_SLACK_WEBHOOK")
    # Hard never-close list, applied on top of everything else including an explicit
    # AGENT_AUTONOMOUS_ALERTS entry. Tampering-with-Defender is here because its FP precision
    # is 65.7% (12 of 35 AI-FP calls were closed as `Closed` by a human) and the cause is
    # an unsettled DEFINITION dispute — L2 reads authorised MDE removal as a TP. Autonomy
    # there would be shipping one side of an open argument.
    never_autoclose_families: str = Field(
        default="Tampering with the Microsoft Defender for Endpoint sensor",
        alias="EDR_NEVER_AUTOCLOSE_FAMILIES",
    )

    # ------------------------------------------------------------------
    # PagerDuty alerting (lib.pagerduty_client, triggered from pipeline._process_ticket)
    #
    # Routing key = Events API v2 integration key (triggers/resolves incidents). API
    # token = a separate PagerDuty REST API token, used only to poll ack state for the
    # future auto-containment fallback (not yet built). Empty routing key = paging
    # silently disabled, same convention as slack_webhook above — this can ship and
    # deploy before a PagerDuty service actually exists.
    # ------------------------------------------------------------------
    pagerduty_routing_key: str = Field(default="", alias="EDR_PAGERDUTY_ROUTING_KEY")
    pagerduty_api_token: str = Field(default="", alias="EDR_PAGERDUTY_API_TOKEN")
    # Minimum severity (see SEVERITY_RANK) that triggers a page. Alerts below this
    # still get their normal Jira comment/label — only paging is gated.
    pagerduty_min_severity: str = Field(default="High", alias="EDR_PAGERDUTY_MIN_SEVERITY")

    # ------------------------------------------------------------------
    # Upwind CNAPP read API (lib.upwind_client) — fetches the evidence behind an
    # Upwind detection ticket. Empty client id = lookup disabled. The org id is taken
    # from the token's org_id claim when not set. The API host is REGIONAL and a token
    # minted for one region is rejected by another (api.upwind.io 401s an AP org).
    # ------------------------------------------------------------------
    upwind_client_id: str = Field(default="", alias="UPWIND_CLIENT_ID")
    upwind_client_secret: str = Field(default="", alias="UPWIND_CLIENT_SECRET")
    upwind_org_id: str = Field(default="", alias="UPWIND_ORG_ID")
    upwind_api_base: str = Field(default="https://api.ap.upwind.io", alias="UPWIND_API_BASE")
    upwind_auth_url: str = Field(default="https://auth.upwind.io/oauth/token", alias="UPWIND_AUTH_URL")
    upwind_verify_ssl: bool = Field(default=True, alias="UPWIND_VERIFY_SSL")
    upwind_lookup_disabled: bool = Field(default=False, alias="UPWIND_LOOKUP_DISABLED")

    # ------------------------------------------------------------------
    # Chase-reply handling (edr_triage.chase_reply_poller)
    # ON since 2026-09-30, scoped to tickets RAPTOR itself chased (label raptor-chased) so
    # chases an L1 starts by hand keep their existing workflow. It routes a chase to L2
    # Analysis required once every user has answered, immediately if anyone disowns the
    # activity, or after EDR_CHASE_STALE_HOURS of silence — that is the "L2 approves any
    # close" step. It can only ever route to L2 (hard allowlist) and never closes.
    # ------------------------------------------------------------------
    chase_reply_enabled: bool = Field(default=True, alias="EDR_CHASE_REPLY")
    # Hours a chased ticket may sit unanswered before it is REPORTED as stale. Nothing
    # is transitioned on breach — unanswered tickets stay in Awaiting more inputs by
    # design; this only keeps them visible instead of silently accumulating.
    chase_stale_hours: int = Field(default=72, alias="EDR_CHASE_STALE_HOURS")
    # Deadline for ANY ticket in Awaiting more inputs, however it got there (an L1's hand
    # chase included): after this many days with no status change it is routed to L2 with
    # a note saying nobody answered. 0 disables. The 2026-10-12 quarantine audit found 249
    # disagreement tickets parked there for up to 39 days with nobody picking them up.
    awaiting_deadline_days: int = Field(default=7, alias="EDR_AWAITING_DEADLINE_DAYS")
    # Only tickets that entered Awaiting more inputs on/after this date. The backlog from
    # before it (944 tickets older than 7 days on 2026-10-12, back to March) would land on
    # L2 all at once — what to do with it is a separate decision, not a side effect.
    # Keep the time: JQL reads AFTER "2026-10-12" as after the END of that day.
    awaiting_deadline_since: str = Field(default="2026-10-12 00:00", alias="EDR_AWAITING_DEADLINE_SINCE")
    # At most this many routed per sweep, so a burst cannot flood L2 in one go.
    awaiting_deadline_max_per_run: int = Field(default=5, alias="EDR_AWAITING_DEADLINE_MAX_PER_RUN")

    # ------------------------------------------------------------------
    # L2 handoff assignee
    # Every RAPTOR-driven transition to `L2 Analysis required` assigns the ticket to a
    # named L2 owner, so a routed ticket lands in somebody's queue instead of sitting
    # unassigned in a status nobody filters on. Addressed by accountId, never by email:
    # `/rest/api/3/issue/{key}/assignee` takes accountId only (GDPR-era API), and an
    # email is not a stable identifier on Atlassian Cloud.
    #   Parker Jain <parker.jain@example.com> = 712020:00000000-0000-0000-0000-000000000000
    # Empty = do not reassign (the transition still happens) — the kill switch, so a
    # wrong/stale accountId degrades to today's behaviour rather than failing the handoff.
    # ------------------------------------------------------------------
    l2_assignee_account_id: str = Field(
        default="712020:00000000-0000-0000-0000-000000000000",
        alias="EDR_L2_ASSIGNEE_ACCOUNT_ID",
    )
    # Display-only, for log lines and the Jira comment. Not used to address the API.
    l2_assignee_name: str = Field(default="Parker Jain", alias="EDR_L2_ASSIGNEE_NAME")

    # ------------------------------------------------------------------
    # Known test/red-team devices (comma-separated hostnames). An entry ending in
    # "*" matches by prefix (e.g. "privesc-security-testing-*" covers the whole
    # numbered series without listing each box) — everything else matches exactly
    # or as a dot-suffixed FQDN, unchanged from before.
    # Alerts on these devices are never auto-closed; always needs-l2-review.
    # ------------------------------------------------------------------
    known_test_devices: str = Field(
        default="prod-poc,uatmsedrtest115,privesc-security-testing-*",
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

    # Floor on a MODEL-derived auto-close. 0.90 because the measured split is clean:
    # every autonomous close to date sat at 95-98%, while the PowerShell tickets whose
    # context channels had both gone dark (new host + generic account, DEMO-112797/112800)
    # fell to 75-85%. The model degraded honestly there and nothing downstream noticed —
    # this is what notices. Applies ONLY where a confidence exists. The live Port Sweep
    # closes DO carry one — in autonomous phase the agent owns the verdict, with the
    # port list fed to it as key evidence — and sit at 95-98%, so they pass. Unfloored
    # are the genuinely deterministic closes: actor-allowlist, DLP-Secret-key, and the
    # playbook fallback when the agent errors. Set to 0 to disable.
    autoclose_min_confidence: float = Field(
        default=0.90, alias="EDR_AUTOCLOSE_MIN_CONFIDENCE"
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
        red-team boxes, e.g. "privesc-security-testing-*"), so a new box in that
        series is covered on day one instead of needing EDR_TEST_DEVICES updated
        every time one gets provisioned (DEMO-106604: "-0201" was missed because
        only exact hostnames were ever supported).
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

    def close_route(self) -> list[str]:
        """The declared auto-close route as an ordered list of status names."""
        return [h.strip() for h in self.auto_close_route.split(",") if h.strip()]

    def close_forbidden(self) -> tuple[str, ...]:
        """Statuses an auto-close route may never pass through."""
        return tuple(
            s.strip() for s in self.auto_close_forbidden_statuses.split(",") if s.strip()
        )

    def _family_match(self, patterns: str, alert_name: str) -> str:
        """Return the matching pattern, or "" — case-insensitive substring match."""
        name = (alert_name or "").strip().lower()
        if not name:
            return ""
        for pat in (p.strip() for p in patterns.split(",")):
            if pat and pat.lower() in name:
                return pat
        return ""

    def may_autoclose(self, alert_name: str,
                      confidence: float | None = None) -> tuple[bool, str]:
        """Return (allowed, reason) for auto-closing, GIVEN the family is already
        autonomous.

        Deliberately does NOT re-check which families are autonomous. That question is
        already owned by `pipeline._effective_agent_phase()` / `AGENT_AUTONOMOUS_ALERTS`,
        which predate this and encode the measured per-family accuracy spread (Netskope
        DLP 0.84 vs Bulk Upload 0.077, 2026-08-30). An earlier version of this method
        carried its own `EDR_AUTONOMOUS_FAMILIES` allowlist, which was a straight
        duplicate — and two allowlists guarding one action is worse than either alone,
        because setting one and believing you are covered is the likely outcome.

        What remains here are the two gates that are genuinely additional to phase:

          * the never-close list — a family may be accurate enough for the agent to own
            its verdict and still be unfit to CLOSE, which is exactly
            Tampering-with-Defender: 65.7% FP precision whose failures are an unsettled
            FP-vs-TP definition dispute, not model error.
          * the report interlock — closing is only acceptable given the visibility the
            report provides, so it is a precondition and not a companion.

        Fails CLOSED on an empty alert name: a family we cannot identify is a family
        whose precision we have not measured.
        """
        if not (alert_name or "").strip():
            return False, "no alert family identified"
        blocked = self._family_match(self.never_autoclose_families, alert_name)
        if blocked:
            return False, f"family on the never-auto-close list ({blocked!r})"
        # INTERLOCK: the compensating control is a PRECONDITION of the thing it
        # compensates for. The accepted safety position is not "RAPTOR never closes
        # wrongly" but "an occasional wrong close is tolerable BECAUSE L2 sees every
        # close" — so closing while the report is off removes the only thing that made
        # closing acceptable. Enforced here rather than left to deploy discipline,
        # because a config that can be half-applied will be.
        if not self.autoclose_report_enabled:
            return False, ("EDR_AUTOCLOSE_REPORT is off — refusing to close without the "
                           "report that gives L2 visibility of every close")
        # CONFIDENCE FLOOR — the generic backstop, and the only gate here that reads
        # anything about THIS ticket rather than about its family.
        #
        # `confidence is None` means the verdict came from deterministic code, not a
        # model — an actor-allowlist match, a DLP-Secret-key rule, or the playbook
        # fallback when the agent errored. That is not a missing value to fail closed
        # on: those carry no probability. Model verdicts are floored; rules are not.
        # The rules have a different weakness — they are context-free — and a
        # confidence floor is the wrong instrument for it. (The allowlist gets its own
        # novelty gate in pipeline.py for exactly that reason.)
        floor = self.autoclose_min_confidence
        if floor and confidence is not None and confidence < floor:
            return False, (f"model confidence {confidence:.2f} is below the "
                           f"{floor:.2f} auto-close floor")
        return True, "family is autonomous, not on the never-close list, report is on"

    def should_page(self, severity: str, triage_class: str) -> bool:
        """Return True if this verdict should trigger a PagerDuty page.

        Deliberately independent of AGENT_PHASE / _effective_agent_phase: paging is a
        notification, not a ticket-state change, so shadow and copilot phases page just
        as loudly as autonomous — the phase gate exists to protect Jira ticket state,
        which this never touches.

        AUTO_CLOSED_FP is excluded even above the severity floor: the ticket is already
        resolved as a false positive, so paging it would page on a closed non-issue.
        """
        if not self.pagerduty_routing_key:
            return False
        if triage_class == "AUTO_CLOSED_FP":
            return False
        return severity_rank(severity) >= severity_rank(self.pagerduty_min_severity)

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
