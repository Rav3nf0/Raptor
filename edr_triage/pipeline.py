"""EDR Triage pipeline — orchestrates a single poll cycle.

For each new MDE ticket:
  1. Dedup check
  2. Fetch MDE alert + evidence
  3. VT hash check
  4. Device timeline fetch (malware playbooks)
  5. Classify → select playbook
  6. Run playbook → comments + action
  7. Execute Jira actions (comment, transition, labels)
  8. Persist to MongoDB
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

from edr_triage.config import EDRTriageConfig, get_edr_config
from edr_triage.models import TriagedAlert
from edr_triage.store import (claim_alert, claim_alert_with_retry, is_processed,
                              release_claim_for_retry, save_triaged_alert)

logger = logging.getLogger(__name__)


async def run_once(cfg: EDRTriageConfig | None = None) -> list[TriagedAlert]:
    """Run one poll cycle. Returns list of alerts that were processed."""
    import os
    cfg = cfg or get_edr_config()

    # Bridge: pydantic-settings reads .env into the config object but doesn't
    # write to os.environ. mde_client.get_access_token() reads os.getenv() directly.
    # In prod, lib/config.py populates os.environ from Secrets Manager. Locally we do it here.
    for env_key, cfg_attr in (
        ("MDE_TENANT_ID",    cfg.mde_tenant_id),
        ("MDE_CLIENT_ID",    cfg.mde_client_id),
        ("MDE_CLIENT_SECRET", cfg.mde_client_secret),
    ):
        if cfg_attr and not os.environ.get(env_key):
            os.environ[env_key] = cfg_attr

    from edr_triage.jira_poller import poll_new_mde_tickets
    tickets = await poll_new_mde_tickets(cfg)
    if not tickets:
        logger.info("EDR triage: no new MDE tickets found")
        return []

    from lib.mde_client import get_access_token
    token = await get_access_token()

    results: list[TriagedAlert] = []
    for ticket in tickets:
        try:
            alert = await _process_ticket(ticket, token, cfg)
            if alert:
                results.append(alert)
        except Exception as exc:
            logger.error("Error processing ticket %s: %s", ticket.get("jira_key"), exc, exc_info=True)
            # Let the next cycle retry it rather than leaving the claim PROCESSING forever.
            release_claim_for_retry(
                ticket.get("jira_key") if ticket.get("observe_only") else ticket.get("alert_id"),
                f"{type(exc).__name__}: {exc}")

    logger.info("EDR triage cycle: %d tickets processed", len(results))
    return results


async def _process_ticket(
    ticket: dict,
    token: str | None,
    cfg: EDRTriageConfig,
    force_agent: bool = False,
    progress_cb=None,
) -> TriagedAlert | None:
    from edr_triage.mde_alerts import (
        fetch_alert, fetch_alert_evidence, fetch_machine_timeline,
        extract_file_evidence,
    )
    from edr_triage.vt_hash import check_hash
    from edr_triage.classifier import classify
    from edr_triage.jira_handler import (add_comment, transition_ticket, add_labels,
                                         set_category, walk_to_status,
                                         get_involved_users_cell, set_involved_users,
                                         transition_to_status)

    from edr_triage.observations import record_observation, detect_source
    from edr_triage.classifier import classify as _classify_early

    jira_key     = ticket["jira_key"]
    alert_id     = ticket["alert_id"]
    alert_name   = ticket.get("alert_name", "")
    is_sentinel  = ticket.get("is_sentinel", False)
    is_upwind    = ticket.get("is_upwind", False)
    observe_only = ticket.get("observe_only", False)
    description  = ticket.get("description", "")
    existing_comments = ticket.get("existing_comments", "")
    # Set on the agent path below; read by the close reviewer at the auto-close gate.
    _agent_result = None
    _agent_evidence: dict = {}

    # Dedup — use jira_key for observe-only tickets
    dedup_key = jira_key if observe_only else alert_id
    _claim = claim_alert_with_retry(dedup_key)
    if _claim == "taken":
        logger.debug("[skip] %s — already claimed/processed", jira_key)
        return None
    if _claim == "retry":
        logger.warning("[RETRY] %s — an earlier triage run never finished; running again",
                       jira_key)
    if _claim == "give_up":
        # Two runs died on this ticket. Say so on it, once, instead of going silent.
        from edr_triage.store import last_claim_error
        _err = last_claim_error(dedup_key) or "the run did not finish (the process was likely restarted or ran out of memory)"
        logger.error("[GIVE-UP] %s — triage failed twice: %s", jira_key, _err)
        if not observe_only:
            from edr_triage.jira_handler import add_comment as _ac, add_labels as _al
            try:
                await _ac(jira_key, (
                    "*RAPTOR could not triage this ticket.*\n\n"
                    f"Two triage runs failed: {_err[:300]}.\n\n"
                    "Nothing was concluded about this alert — please triage it as usual.\n\n"
                    "[Auto-triaged by RAPTOR]"), cfg, dry_run=cfg.dry_run)
                await _al(jira_key, ["needs-l2-review", "raptor-error"], cfg, dry_run=cfg.dry_run)
            except Exception as _exc:
                logger.error("[GIVE-UP] %s — could not post the failure note: %s", jira_key, _exc)
        return None

    # Detect source for observation logging
    source = ("sentinel" if is_sentinel else "upwind" if is_upwind else
              ("mde" if not observe_only else detect_source(description, alert_name)))

    # Observe-only tickets (no parseable MDE alert ID or Sentinel incident URL) used
    # to log-and-stop here with zero Jira action. They now fall through the same
    # pipeline as everything else (record_observation still runs, just below): alert_id
    # is the jira_key itself for these, so the MDE fetch below finds nothing and
    # degrades to the existing Jira-description fallback (same path already used when
    # MDE is unreachable), classify() runs on whatever text is available, and — worst
    # case, nothing matches — FallbackPlaybook still posts the raw description and
    # escalates to L2 rather than staying silent.
    logger.info("Processing %s — alert_id=%s name='%s' sentinel=%s observe_only=%s",
                jira_key, alert_id, alert_name, is_sentinel, observe_only)

    # Classify early — was a hard skip before an alert-name match had a real
    # destination. It's now only a signal for observation logging; actual
    # routing (including "no dedicated playbook" -> FallbackPlaybook) happens
    # at the re-classify below, once inv_state is available too.
    early_decision = _classify_early(alert_name)
    # Record observation for all actionable tickets too
    record_observation(jira_key, alert_name, source, early_decision, description)

    # Jira-description fallback (used when MDE API is unavailable or returns 404)
    _jira_fallback = {
        "alertDisplayName": alert_name,
        "computerDnsName":  ticket.get("device_name", ""),
        "assignedTo":       ticket.get("user_name", ""),
        "severity":         ticket.get("severity", ""),
        "investigationState": "",
        "alertCreationTime": ticket.get("created_at", ""),
        "incident_url":     ticket.get("incident_url", ""),
    }

    # Fetch MDE alert data — skip for Sentinel-sourced tickets (no MDE alert ID)
    alert_data = {}
    evidence   = {}
    timeline   = []
    _mde_evidence_raw: list = []      # the alert's raw evidence entities (custom_block_guard)
    if is_sentinel:
        logger.info("%s is a Sentinel identity alert — skipping MDE API fetch", jira_key)
        alert_data = _jira_fallback
    elif is_upwind:
        # Upwind raised this; there is no MDE alert behind it to fetch. The host can
        # still be Defender-onboarded — the machineId resolve below runs on its name.
        alert_data = _jira_fallback
        _uw = ticket.get("upwind") or {}
        alert_data["_upwind"] = _uw
        # The ticket names only the resource; the evidence (file hashes, paths, instance
        # id, occurrence history) lives on the detection. get_detection never raises.
        from edr_triage.upwind_client import get_detection
        _uw_det = await get_detection(_uw.get("detection_id", ""))
        if _uw_det:
            if _uw_det.get("status") == "found" and cfg.virustotal_api_key:
                for _f in _uw_det["detection"]["files"][:3]:
                    _f["vt"] = await check_hash(_f["hash"], cfg.virustotal_api_key)
            alert_data["_upwind_detection"] = _uw_det
            evidence["upwind_detection"] = _uw_det
            # The EC2 instance id is the most reliable key into the asset register.
            _iid = ((_uw_det.get("detection") or {}).get("resource") or {}).get("instance_id")
            if _iid:
                evidence["instance_id"] = _iid
    elif token:
        alert_data = await fetch_alert(alert_id, token)
        if not alert_data:
            logger.warning("MDE alert %s returned no data — using Jira description fields for %s", alert_id, jira_key)
            alert_data = _jira_fallback
        evidence_list = await fetch_alert_evidence(alert_id, token)
        _mde_evidence_raw = evidence_list
        evidence = extract_file_evidence(evidence_list)
    else:
        logger.warning("No MDE token — using Jira description fields only for %s", jira_key)
        alert_data = _jira_fallback

    # Ensure incident_url is propagated into alert_data for playbooks
    if not alert_data.get("incident_url") and ticket.get("incident_url"):
        alert_data["incident_url"] = ticket["incident_url"]

    # Backfill sparse MDE fields from Jira description (e.g. CloudTrail alerts where
    # MDE returns data but computerDnsName / relatedUser are empty)
    if not alert_data.get("computerDnsName") and ticket.get("device_name"):
        alert_data["computerDnsName"] = ticket["device_name"]
    # Inject raw description so playbooks can parse source-specific context
    alert_data.setdefault("_description", description)

    inv_state   = alert_data.get("investigationState", "")
    machine_id  = alert_data.get("machineId", "")
    device_name = alert_data.get("computerDnsName") or alert_data.get("machineName") or ticket.get("device_name", "")

    # Sentinel-ingested alerts arrive with NO machineId even when the host is
    # Defender-onboarded. Resolve it from the hostname so the agent gets the MDE
    # handle (enables MDE hunts + the recent-alerts fetch below) and does not
    # misread a missing id as "device not onboarded". Best-effort; guarded.
    if not machine_id and device_name and token:
        from lib.mde_client import get_machine_by_dns_name
        _mach = await get_machine_by_dns_name(device_name, token)
        if _mach and _mach.get("id"):
            machine_id = _mach["id"]
            alert_data["machineId"] = machine_id
            alert_data["_mde_onboarding"] = _mach.get("onboardingStatus", "")
            logger.info("[mde-resolve] %s: %s -> machine_id=%s (onboard=%s health=%s)",
                        jira_key, device_name, str(machine_id)[:12],
                        _mach.get("onboardingStatus"), _mach.get("healthStatus"))

    # VT hash check
    vt = {}
    sha256 = (evidence or {}).get("sha256", "")
    if sha256 and cfg.virustotal_api_key:
        vt = await check_hash(sha256, cfg.virustotal_api_key)

    # Playbook selection (re-classify with inv_state now available from MDE data).
    # "skip" is a real playbook name now (FallbackPlaybook, _get_playbook above) —
    # no early return here, so an alert type with no dedicated handling still gets
    # a deterministic comment and an L2 escalation instead of sitting untouched.
    playbook_name = classify(alert_name, inv_state)
    if playbook_name == "skip":
        logger.info("[fallback] %s — alert type '%s' has no dedicated playbook, routing to L2",
                     jira_key, alert_name)

    # Device timeline — fetch for malware playbooks. Resolve by HOSTNAME when the
    # alert payload carries no machineId (common for Sentinel-ingested / Linux hosts —
    # the device is still Defender-onboarded, the payload just omits the id; this is
    # why DEMO-105292's timeline came back empty and the fetch was skipped). The window
    # is anchored on the ALERT event time (not "now") and tightly bounded, so a triage
    # running hours later still captures the detection events without a day of noise.
    # Non-onboarded hosts raise inside fetch — caught so triage still proceeds.
    _tl_ref = machine_id or device_name
    if playbook_name in ("malware",) and _tl_ref and token:
        _alert_ts = (alert_data.get("alertCreationTime", "")
                     or alert_data.get("firstEventTime", "")
                     or alert_data.get("lastEventTime", ""))
        try:
            timeline = await fetch_machine_timeline(_tl_ref, token, anchor_iso=_alert_ts, window_hours=6)
        except Exception as _tl_exc:
            timeline = []
            logger.info("[timeline] unavailable for %s (ref=%s): %s", jira_key, _tl_ref, _tl_exc)

    # Test device check
    is_test = cfg.is_test_device(device_name)

    # Sentinel enrichment — credential access (sign-in details) + privesc/generic (CloudTrail)
    sentinel_entities: dict = {}
    incident_url = ticket.get("incident_url", "") or alert_data.get("incident_url", "")
    _is_ns_malware = playbook_name == "netskope" and "malware" in (alert_name or "").lower()
    _is_ns_dlp = playbook_name == "netskope" and "dlp" in (alert_name or "").lower()
    if _is_ns_dlp:
        # Netskope DLP: bind the per-event detail (profile/rule/severity, access
        # method, app, file size) from Netskope_Alerts_CL — the Jira description
        # table only ever carries the DLP profile name, never the rest, so L1 has
        # been retyping this from the Sentinel incident by hand every time.
        if incident_url:
            from edr_triage.sentinel_client import query_netskope_dlp
            _dlp = await query_netskope_dlp(
                incident_url,
                alert_data.get("alertCreationTime", "") or ticket.get("created_at", ""),
                user_hint=ticket.get("user_name", ""),
                # Scopes the bind to THIS alert's own matched rows. Without it the bind
                # was a time-window sweep of the whole DLP table and the "users" it
                # returned were never established to be the alert's subjects
                # (DEMO-110841: one real user, 14 bound, none of them the right one).
                sentinel_alert_id=ticket.get("sentinel_alert_id", "") or "",
            )
            if _dlp and _dlp.get("events"):
                sentinel_entities = {"netskope_dlp": _dlp}
                # Union the DLP users into the account list — same reason as the UBA
                # branch below: Netskope_Alerts_CL is the ground truth for who acted,
                # and a DLP alert's Sentinel incident carries NO account entity at all.
                # Without this, user_name stays empty and the RJ safety gate blocks on
                # "no acting principal identified — there is nobody to ask", overriding
                # the agent even when it has correctly named the actors from the bound
                # events. DEMO-110712: the model reached REQUEST_JUSTIFICATION naming
                # nina.dutta / toby.vo and correctly excused the
                # gsheet.automation service account, and the gate still forced NEEDS_L2
                # because this field was blank.
                _accts = sentinel_entities.get("accounts") or []
                sentinel_entities["accounts"] = list(dict.fromkeys(
                    [*_accts, *(_dlp.get("users") or [])]
                ))
                logger.info(
                    "Netskope DLP enrichment for %s: users=%s events=%d ambiguous=%s",
                    jira_key, _dlp.get("users"), _dlp.get("event_count", 0), _dlp.get("ambiguous"),
                )
            else:
                logger.warning("Netskope DLP alert %s — no Netskope_Alerts_CL rows bound", jira_key)
        else:
            logger.warning("Netskope DLP alert %s — no incident_url", jira_key)

    elif _is_ns_malware:
        # Netskope cloud-malware: bind the malware detail (user, name/type/severity,
        # action, policy, hash) from Netskope_Alerts_CL deterministically — the agent's
        # hand-written KQL against this custom-log table kept failing (DEMO-104584).
        if incident_url:
            from edr_triage.sentinel_client import query_netskope_malware
            _nm = await query_netskope_malware(
                incident_url,
                alert_data.get("alertCreationTime", "") or ticket.get("created_at", ""),
                user_hint=ticket.get("user_name", ""),
            )
            if _nm and _nm.get("malware_name"):
                sentinel_entities = {"netskope_malware": _nm}
                logger.info(
                    "Netskope malware enrichment for %s: user=%s malware=%s action=%s ambiguous=%s",
                    jira_key, _nm.get("user"), _nm.get("malware_name"),
                    _nm.get("action"), _nm.get("ambiguous"),
                )
            else:
                logger.warning("Netskope malware alert %s — no Netskope_Alerts_CL row bound", jira_key)
        else:
            logger.warning("Netskope malware alert %s — no incident_url", jira_key)

    elif playbook_name == "guardduty":
        # EC2-DNS GuardDuty finding (phishing-domain / drive-by-source-domain): bind
        # the finding detail (instance, IP, domain, threat classification) from the
        # AWSGuardDuty Sentinel table — the Jira description carries nothing at all
        # for these, previously a hard skip (classifier.py _SKIP_PATTERNS).
        if incident_url:
            from edr_triage.sentinel_client import query_guardduty_dns_finding
            _iid = re.search(r"\bi-[0-9a-f]{8,17}\b", alert_name or "")
            _gd = await query_guardduty_dns_finding(
                incident_url,
                alert_data.get("alertCreationTime", "") or ticket.get("created_at", ""),
                instance_id=_iid.group(0) if _iid else "",
            )
            if _gd and (_gd.get("InstanceId") or _gd.get("Domain")):
                sentinel_entities = {"guardduty_dns": _gd}
                # Reputation + CATEGORY for each queried domain. A bare domain
                # (`dysonc.com`) tells an analyst nothing, which is why L1 hand-looks-up
                # what the site actually is before escalating — one real comment renders
                # the Domain field as "Accounts and payroll outsourcing services in
                # India | More4Less", i.e. the site's identity, not its hostname. For a
                # drive-by/phishing-domain alert that identity IS the deciding fact, so
                # resolve it deterministically instead of leaving it to a manual lookup.
                # Bounded to 8 domains to keep a wide incident off the VT rate limit.
                try:
                    from agent_tools.virustotal import vt_lookup_domain
                    _reps = {}
                    for _dom in (_gd.get("domains") or [])[:8]:
                        _r = await vt_lookup_domain(_dom)
                        if _r and not _r.get("error"):
                            _reps[_dom] = _r
                    if _reps:
                        _gd["domain_reputation"] = _reps
                except Exception as _exc:
                    logger.debug("GuardDuty domain reputation lookup skipped for %s: %s", jira_key, _exc)
                logger.info(
                    "GuardDuty DNS enrichment for %s: instance=%s domains=%s findings=%s vt=%d",
                    jira_key, _gd.get("InstanceId"), _gd.get("domains"),
                    _gd.get("finding_count"), len(_gd.get("domain_reputation") or {}),
                )
            else:
                logger.warning("GuardDuty EC2-DNS alert %s — no AWSGuardDuty row bound", jira_key)
        else:
            logger.warning("GuardDuty EC2-DNS alert %s — no incident_url", jira_key)

    elif playbook_name in ("credential_access", "netskope"):
        if incident_url:
            from edr_triage.sentinel_client import (
                fetch_incident, fetch_incident_entities, fetch_incident_alerts,
                extract_signin_details_async,
            )
            incident_data, entities_list, alerts_list = await asyncio.gather(
                fetch_incident(incident_url),
                fetch_incident_entities(incident_url),
                fetch_incident_alerts(incident_url),
            )
            sentinel_entities = await extract_signin_details_async(
                incident_url, incident_data, entities_list, alerts_list
            )
            # Netskope failed-login: bind the actual failure GROUPS from
            # Netskope_Alerts_CL. extract_signin_details_async above returns ENTRA
            # sign-in data, which is a different identity plane — so a *Netskope*
            # failed-login alert was being triaged without any Netskope evidence at all
            # (10 scored rows, 2 correct, all 8 misses model-chosen over-escalations).
            # Additive: the Entra block is untouched, this sits beside it.
            if re.search(r"netskope.*(?:failed\s+login|sign.?in\s+fail)",
                         (alert_name or ""), re.IGNORECASE):
                from edr_triage.sentinel_client import query_netskope_failed_login
                _fl = await query_netskope_failed_login(
                    incident_url,
                    alert_data.get("alertCreationTime", "") or ticket.get("created_at", ""),
                    user_hint=ticket.get("user_name", ""),
                )
                if _fl and _fl.get("groups"):
                    sentinel_entities = dict(sentinel_entities or {})
                    sentinel_entities["netskope_failed_login"] = _fl
                    # Union the bound users into accounts, same as the DLP/UBA branches:
                    # these alerts carry no account entity, so without this user_name
                    # stays empty and the RJ gate blocks on "nobody to ask".
                    _acc = list((sentinel_entities.get("accounts") or []))
                    for u in _fl.get("users") or []:
                        if u and u not in _acc:
                            _acc.append(u)
                    sentinel_entities["accounts"] = _acc
                    logger.info("[NETSKOPE-FL] %s bound %d group(s), %d total failures "
                                "(max %d) across %d user(s)", jira_key,
                                _fl.get("group_count"), _fl.get("total_failures"),
                                _fl.get("max_failures"), len(_fl.get("users") or []))
            logger.info(
                "Sentinel enrichment for %s: accounts=%s ips=%d locations=%d",
                jira_key,
                sentinel_entities.get("accounts"),
                len(sentinel_entities.get("ips", [])),
                len(sentinel_entities.get("locations", [])),
            )
            # Netskope UBA (Bulk Upload/Download): bind the per-user rows from
            # Netskope_Alerts_CL deterministically. The incident entities give the user
            # LIST but none of the detail (host, app, page, file type/size, source IP) —
            # the rule maps only Account, no Host entity, which is why DEMO-107416 read
            # "on host Unknown Device" while every field sat in the custom-log table.
            # Shared with the classifier so routing and binding can never disagree
            # about what a UBA anomaly is (see NETSKOPE_UBA_RE).
            from edr_triage.classifier import NETSKOPE_UBA_RE
            if NETSKOPE_UBA_RE.search(alert_name or ""):
                from edr_triage.sentinel_client import query_netskope_uba
                _inc_props = (incident_data.get("properties") or {})
                _uba = await query_netskope_uba(
                    incident_url,
                    alert_name=alert_name,
                    start_time_utc=_inc_props.get("firstActivityTimeUtc", "")
                                   or alert_data.get("alertCreationTime", "")
                                   or ticket.get("created_at", ""),
                    end_time_utc=_inc_props.get("lastActivityTimeUtc", ""),
                    # Without this the bind can only ever guess by time window. With it,
                    # the alert's own rows are used and the window becomes a fallback —
                    # see _uba_rows_from_alert / DEMO-109433.
                    sentinel_alert_id=ticket.get("sentinel_alert_id", "") or "",
                )
                if _uba and _uba.get("by_user"):
                    sentinel_entities["netskope_uba"] = _uba
                    # Union the UBA users into the account list — the table is the ground
                    # truth for who acted, and it can name a user the entity mapping missed.
                    _accts = sentinel_entities.get("accounts") or []
                    sentinel_entities["accounts"] = list(dict.fromkeys(
                        [*_accts, *(_uba.get("users") or [])]
                    ))
                    logger.info(
                        "Netskope UBA enrichment for %s: users=%s events=%d",
                        jira_key, _uba.get("users"), _uba.get("event_count", 0),
                    )
                else:
                    logger.warning("Netskope UBA alert %s — no Netskope_Alerts_CL rows bound", jira_key)
        else:
            logger.warning("%s classified as credential_access but no incident_url found", jira_key)

    elif playbook_name == "pim":
        # Entra PIM: resolve WHO granted the role (the recipient is already on the
        # Sentinel incident's own AccountEntity — the grantor is not, which is the
        # whole reason this alert family previously went to a human every time).
        if incident_url:
            from edr_triage.sentinel_client import (
                fetch_incident, fetch_incident_entities, fetch_incident_alerts,
                extract_signin_details_async, query_identity_grant_for_pim,
            )
            incident_data, entities_list, alerts_list = await asyncio.gather(
                fetch_incident(incident_url),
                fetch_incident_entities(incident_url),
                fetch_incident_alerts(incident_url),
            )
            sentinel_entities = await extract_signin_details_async(
                incident_url, incident_data, entities_list, alerts_list
            )
            recipient = (sentinel_entities.get("accounts") or [""])[0]
            if recipient:
                _grant = await query_identity_grant_for_pim(
                    incident_url, recipient,
                    alert_data.get("alertCreationTime", "") or ticket.get("created_at", ""),
                )
                if _grant:
                    sentinel_entities["identity_grant"] = _grant
                    logger.info("PIM grantor resolved for %s: recipient=%s grantor=%s",
                                jira_key, recipient, _grant.get("Actor"))
                else:
                    logger.warning("PIM alert %s — no AuditLogs grant row bound for recipient=%s",
                                   jira_key, recipient)
            else:
                logger.warning("PIM alert %s — no recipient resolved from Sentinel entities", jira_key)
        else:
            logger.warning("PIM alert %s — no incident_url", jira_key)

    elif playbook_name in ("privesc", "generic", "no_threat") and incident_url:
        from edr_triage.sentinel_client import (
            fetch_incident, fetch_incident_entities, fetch_incident_alerts,
            extract_cloudtrail_details_async, extract_entity_summary, query_sentinel_alert,
        )
        from edr_triage.rule_replay import (
            decode_alert_cloudtrail_rows, replay_alert_cloudtrail_rows,
            decode_alert_local_group_rows, replay_alert_local_group_rows,
            decode_alert_event, replay_alert_rule, custom_details_cloudtrail_rows,
        )
        incident_data, entities_list, alerts_list = await asyncio.gather(
            fetch_incident(incident_url),
            fetch_incident_entities(incident_url),
            fetch_incident_alerts(incident_url),
        )
        # Fetch THIS alert's own entities ONCE. Used two ways: (a) to bind the actor
        # when nothing else does (DEMO-104300), and (b) as the AUTHORITATIVE full
        # process list for the deterministic process check — the alert entities
        # enumerate every matched process, whereas rule_replay collapses to one row
        # and the row's process column isn't always parseable (DEMO-104466).
        _said = ticket.get("sentinel_alert_id", "")
        _alertent = (await query_sentinel_alert(incident_url, _said)) if _said else {}
        _ap = (alerts_list[0].get("properties", {}) if alerts_list else {})
        _ap.setdefault("startTimeUtc", alert_data.get("alertCreationTime", ""))

        # ── Enrichment cascade — GROUND TRUTH FIRST ────────────────────────────
        # (1) Decode THIS alert's OWN matched rows (compressedRec) → the exact
        #     per-host output the analytics rule emitted. For grouped AWS/SSM
        #     privesc this yields one CloudTrail dict PER HOST (every instance /
        #     session issuer / ARN / command) with no single-host `take 1` replica
        #     and no dependency on DeviceProcessEvents — the DEMO-106604 root cause,
        #     where the replica reported one host's cron noise and missed both SSM
        #     escalations.
        # Full host set for THIS incident — union of the incident's host entities
        # and THIS alert's own host entities. Both are the incident/alert's OWN
        # entities (never fleet-wide), always present regardless of CloudTrail
        # retention. Used to scope the rule-replay AND to backfill co-hosts below.
        _incident_hosts = extract_entity_summary(entities_list).get("hosts") or []
        _alert_hosts = _alertent.get("hosts") or []
        _all_hosts = list(dict.fromkeys([*_incident_hosts, *_alert_hosts]))

        _ct_rows = await decode_alert_cloudtrail_rows(incident_url, _ap, _said)
        if not _ct_rows:
            # (1b) The alert's own custom details: the commands and session ARNs the rule
            #      recorded when it fired. Cannot drift with the clock the way the replay
            #      below can (the rule's query is ago()-relative), and never sweeps the
            #      host's background jobs like the replica (DEMO-116682).
            _ct_rows = custom_details_cloudtrail_rows(_alertent)
            if _ct_rows:
                logger.info("CloudTrail for %s from the alert's custom details: %d row(s)",
                            jira_key, len(_ct_rows))
        if not _ct_rows:
            # (2) No compressedRec (DEMO-106604) → RE-RUN the alert's own analytics
            #     rule and map each output row to a per-host CloudTrail dict. This
            #     reproduces the rule's real SSM output (sudo sudo su / crontab -l,
            #     session issuer, ARN) for EVERY host, unlike the replica which uses
            #     a different filter and returns one host's root-cron noise. Scoped
            #     to THIS incident's own hosts (union of incident + alert host
            #     entities) so a wide window can't pull in unrelated privesc events.
            _ct_rows = await replay_alert_cloudtrail_rows(incident_url, _ap, host_filter=_all_hosts)
        cloudtrail: dict = {}
        if _ct_rows:
            cloudtrail = dict(_ct_rows[0])
            if len(_ct_rows) > 1:
                cloudtrail["additional_hosts"] = _ct_rows[1:]
            # More than one person with an SSM session on the primary host = the actor
            # is unknown (DEMO-112299). Tier 3 below sets the same flag itself.
            from edr_triage.sentinel_client import annotate_session_ambiguity
            annotate_session_ambiguity(cloudtrail, _ct_rows[1:])
        else:
            # (3) Last resort — the hand-written CloudTrail replica query (one host).
            # allow_deviceless_sweep is scoped to playbook_name=="privesc" only — its
            # fleet-wide, time-window-only fallback (no device, no incident correlation)
            # is safe for a genuine root-privesc alert missing a device entity, but not
            # for "generic"/"no_threat" alerts unrelated to AWS/root activity at all
            # (DEMO-108699: a MS-SQL-audit alert got an unrelated person's macOS session
            # attributed to it this way).
            cloudtrail = await extract_cloudtrail_details_async(
                incident_url, incident_data, entities_list, alerts_list,
                allow_deviceless_sweep=(playbook_name == "privesc"),
            )

        # (4) Backfill co-hosts from the incident/alert host ENTITIES. The CloudTrail
        #     rows (tiers 1-2) can be empty when the rule's telemetry has aged out or
        #     the alert carries no compressedRec, leaving the single-host replica — so
        #     a grouped incident would surface only one host (DEMO-106765: 2 host
        #     entities, but re-run returned 0 rows). The host entities are ALWAYS
        #     present, so list every incident host the enrichment didn't already bind
        #     as a co-host (bare — no per-host CloudTrail detail when telemetry is gone).
        if cloudtrail and _all_hosts:
            def _hmatch(a: str, b: str) -> bool:
                a, b = (a or "").lower(), (b or "").lower()
                return bool(a and b and (a in b or b in a))
            # isinstance guard: a malformed CloudTrail/rule-replay row can land a bare
            # non-dict entry in additional_hosts, and this list is read again (with the
            # SAME unguarded .get pattern) deep in the agent-loop evidence assembly —
            # where the resulting AttributeError crashes the WHOLE investigation at 0
            # iterations (DEMO-108679/108667/108518). Filtering here, at the source,
            # means a bad row costs one co-host instead of the entire ticket twice over.
            _extra = [e for e in (cloudtrail.get("additional_hosts") or []) if isinstance(e, dict)]
            _bound = [cloudtrail.get("device_name", "")] + [e.get("device_name", "") for e in _extra]
            for h in _all_hosts:
                if not any(_hmatch(h, b) for b in _bound if b):
                    _extra.append({"device_name": h})
                    _bound.append(h)
            if _extra:
                cloudtrail["additional_hosts"] = _extra

        # A CloudTrail dict is the PRIMARY enrichment only when it carries some real
        # identity/action — not just device_name + firstActivityTime (+account),
        # which extract_cloudtrail_details fills even on a miss. Broad on purpose:
        # GuardDuty / console-login dicts (guardduty_link / mfa / access_key /
        # source_ip, no SSM instance) must still render via the CloudTrail path, so
        # we accept ANY non-hollow field; only a truly hollow dict falls through to
        # rule-replay / alert-entity binding (DEMO-106604: a hollow cloudtrail once
        # short-circuited the cascade and starved the better paths).
        _CT_HOLLOW = ("device_name", "time_generated", "account_name", "additional_hosts")
        def _ct_substantive(ct: dict) -> bool:
            return bool(ct and any(v for k, v in ct.items() if k not in _CT_HOLLOW))

        if _ct_substantive(cloudtrail):
            sentinel_entities = {"cloudtrail": cloudtrail}
            logger.info(
                "Sentinel CloudTrail enrichment for %s: hosts=%d device=%s instance=%s command=%s",
                jira_key, 1 + len(cloudtrail.get("additional_hosts", [])),
                cloudtrail.get("device_name"), cloudtrail.get("instance_id"),
                cloudtrail.get("command"),
            )
        else:
            # (3) Local admin/account-group changes: no compressedRec-fetchable
            #     CloudTrail signal, and usually no re-runnable Sentinel rule either
            #     (the detection is MDE-native, just surfaced into the incident) — but
            #     the row itself names TWO principals, and the generic rule_replay
            #     path below (tier 4) would collapse them via a first-match heuristic
            #     that picks the GRANTOR over the RECIPIENT. For an FP judgment like
            #     "this person already has the role", the recipient is who matters, so
            #     this tier is tried first and keeps them separate — see
            #     rule_replay.local_group_row_to_dict.
            #     Gated on the subtype (cheap, no API call) rather than tried
            #     unconditionally — decode_alert_local_group_rows shares its underlying
            #     fetch with decode_alert_event below, and every OTHER alert in this
            #     branch (AWS/CloudTrail already excluded above, Office, port sweeps,
            #     generic Sentinel rules) would otherwise pay for that fetch twice.
            from edr_triage.classifier import alert_subtype as _alert_subtype
            _lg_rows = []
            if _alert_subtype(alert_name) == "local_admin_group_change":
                _lg_rows = await decode_alert_local_group_rows(incident_url, _ap, _said)
                if not _lg_rows:
                    _lg_rows = await replay_alert_local_group_rows(incident_url, _ap, host_filter=_all_hosts)
            if _lg_rows:
                sentinel_entities = {"local_group": dict(_lg_rows[0])}
                if len(_lg_rows) > 1:
                    sentinel_entities["local_group"]["additional_changes"] = _lg_rows[1:]
                logger.info(
                    "Local-group enrichment for %s: %d change(s), action=%s recipient=%s grantor=%s device=%s",
                    jira_key, len(_lg_rows), _lg_rows[0].get("action_type"),
                    _lg_rows[0].get("recipient_account"), _lg_rows[0].get("grantor_account"),
                    _lg_rows[0].get("device_name"),
                )
            else:
                # (4) Non-CloudTrail, non-local-group scheduled/NRT rule → summarize the
                #     decoded rows, else re-run the triggering rule over the alert window.
                replay = (await decode_alert_event(incident_url, _ap, _said)
                          or await replay_alert_rule(incident_url, _ap))
                if replay:
                    sentinel_entities = {"rule_replay": replay}
                    logger.info(
                        "Sentinel enrichment for %s: source=%s rule='%s' rows=%d device=%s user=%s op=%s",
                        jira_key, replay.get("source", "rule_replay"), replay.get("rule_name"),
                        replay.get("row_count"), replay.get("device_name"),
                        replay.get("account_name"), replay.get("operation"),
                    )
            if not sentinel_entities and _alertent and (
                    _alertent.get("account_name") or _alertent.get("device_name")
                    or _alertent.get("command_lines")):
                # (5) Microsoft-Security / MCAS alerts (e.g. "Rare and potentially
                #     high-risk Office operations") carry no compressedRec and no
                #     re-runnable KQL rule — but the alert's OWN entities still hold
                #     the actor/device (DEMO-104300: Exchange service account).
                sentinel_entities = {"sentinel_alert": _alertent}
                logger.info(
                    "Sentinel alert-entity enrichment for %s: device=%s account=%s cmds=%d",
                    jira_key, _alertent.get("device_name"), _alertent.get("account_name"),
                    len(_alertent.get("command_lines") or []),
                )
            elif not sentinel_entities and cloudtrail:
                # (6) Only device_name/time survived — keep it for host binding, but
                #     it won't win the CloudTrail renderer (_genuine_aws is False
                #     without identity facts), so the comment falls to the MDE path.
                # `not sentinel_entities` guards the tiers above (local_group,
                # rule_replay) now that they're no longer a single unbroken if/elif
                # chain with this one — without it, a successful local-group or
                # rule_replay result would be silently overwritten here whenever
                # cloudtrail also held a bare device_name/time from tier (1)-(2).
                sentinel_entities = {"cloudtrail": cloudtrail}
                logger.info("Sentinel host-only binding for %s: device=%s",
                            jira_key, cloudtrail.get("device_name"))
        # Stash the alert's full process list so the deterministic process check can
        # use it regardless of which enricher rendered primary above.
        if _alertent.get("command_lines"):
            sentinel_entities["alert_command_lines"] = _alertent["command_lines"]
        # Surface the incident's FULL account set on this path too. Each branch above
        # assigns a fresh dict keyed by its enricher, so `accounts` never existed here —
        # which is why the `(accounts or [""])[0]` step of the actor chain below is dead
        # code on privesc/generic, and why a grouped multi-user incident routed here had
        # no way to tell the agent about its other users. Union of the incident's and the
        # alert's own Account entities; empty for single-user alerts.
        _incident_accounts = extract_entity_summary(entities_list).get("accounts") or []
        _accts_all = list(dict.fromkeys(
            [*_incident_accounts, *([_alertent["account_name"]] if _alertent.get("account_name") else [])]
        ))
        if _accts_all:
            sentinel_entities["accounts"] = _accts_all

    # LOLBin / PowerShell-in-memory (Sentinel NRT): incident has no entities and the
    # MDE alert has no evidence — pull the real device/account/command from the
    # DeviceEvents PowerShellCommand telemetry.
    elif playbook_name == "endpoint_process" and incident_url and not (evidence or {}).get("command_lines"):
        from edr_triage.sentinel_client import query_powershell_script_load, query_sentinel_alert
        _ps_time = (alert_data.get("alertCreationTime") or alert_data.get("firstEventTime")
                    or ticket.get("created_at", ""))
        # Bind to THIS ticket's OWN alert first: fetch its entities by SystemAlertId
        # so the DeviceEvents hunt is scoped to the alert's real host instead of
        # guessing the temporally-nearest host workspace-wide (DEMO-104199 fix).
        _scope_host = ""
        _said = ticket.get("sentinel_alert_id", "")
        if _said:
            _alert_ent = await query_sentinel_alert(incident_url, _said)
            _scope_host = (_alert_ent or {}).get("device_name", "")
            if (_alert_ent or {}).get("event_time"):
                _ps_time = _alert_ent["event_time"] or _ps_time
            if _scope_host:
                logger.info("Sentinel alert %s → bound host=%s for %s", _said, _scope_host, jira_key)
        lolbin = await query_powershell_script_load(incident_url, _ps_time, scope_device=_scope_host)
        if _scope_host:
            # BOUND: host came from THIS alert's own matched event (compressedRec), so
            # attribution is trustworthy. Prefer the scoped-hunt command sequence for
            # fuller context; fall back to the alert's own bound command if the hunt is
            # empty (e.g. the event aged out of the DeviceEvents retention window).
            import re as _re
            _bound = lolbin if (lolbin and lolbin.get("commands")) else {}
            _cmds = _bound.get("commands") or (_alert_ent or {}).get("command_lines") or []
            if _cmds:
                _urls = _bound.get("remote_urls") or sorted({
                    m.group(0) for c in _cmds for m in [_re.search(r"https?://[^\s'\"]+", c)] if m})
                _lb = {
                    "device_name": _scope_host,
                    "account_name": _bound.get("account_name") or (_alert_ent or {}).get("account_name", ""),
                    "initiating_process": _bound.get("initiating_process") or "powershell.exe",
                    "commands": _cmds, "remote_urls": _urls,
                    "multi_device": False, "other_devices": [],
                }
                sentinel_entities = {"lolbin": _lb}
                evidence = dict(evidence or {})
                evidence["command_lines"] = _cmds
                evidence["command_line"] = _cmds[0]
                evidence["account_name"] = _lb["account_name"]
                evidence["initiating_process"] = _lb["initiating_process"]
                logger.info(
                    "Sentinel LOLBin (bound to alert) for %s: device=%s account=%s cmds=%d urls=%s",
                    jira_key, _scope_host, _lb["account_name"], len(_cmds), _urls,
                )
        elif lolbin and lolbin.get("commands"):
            # NOT bound — host guessed from a blind time-window hunt (this alert had no
            # bindable event). Unreliable (grabs high-frequency automation as "nearest"),
            # so do NOT attribute: surface candidates and let the agent / L2 escalate.
            _cands = [lolbin.get("device_name", "")] + (lolbin.get("other_devices") or [])
            _cands = [c for c in _cands if c]
            # Keep the COMMANDS even though the host is unattributable.
            #
            # Discarding them made RAPTOR blind to what the alert was even about: on
            # DEMO-108429 the ticket rendered "Device: Unknown Device / User: Unknown User
            # / the process command line was not present in the MDE alert evidence", and
            # the whole 'Powershell script was loaded in memory' family reads the same way
            # (DEMO-108122, 107947, 107771, 107068, 107067 — all Unknown/Unknown, all
            # NEEDS_L2). The invocations WERE recovered by the hunt above; only the host
            # attribution failed, and we were throwing the text away with the hostname.
            #
            # It also silently disabled every command-based control. The planned-activity
            # window for `ironwatch_windows_agent_DC.ps1` has matched nothing since it was
            # created on 2026-07-21 (hit_count 0) — not because it is wrong, but because
            # this alert class never presents a command string for it to test.
            #
            # Carried as UNATTRIBUTED context only. The safety property being protected
            # here is about the HOST — do not pin activity on a guessed machine — and that
            # is untouched: no device_name, no account, no evidence["command_line"], so
            # nothing downstream treats these as this alert's own bound telemetry, and the
            # deterministic planned-activity auto-close still cannot fire on them.
            _amb = {"candidate_devices": _cands}
            _amb_cmds = [c for c in (lolbin.get("commands") or []) if c][:10]
            if _amb_cmds:
                _amb["candidate_commands"] = _amb_cmds
                _amb["candidate_accounts"] = [
                    a for a in [lolbin.get("account_name", "")] if a
                ]
            sentinel_entities = {"lolbin_ambiguous": _amb}
            logger.warning(
                "Sentinel LOLBin host GUESSED (not bound to alert) for %s: candidates=%s — "
                "NOT attributing; carrying %d recovered command(s) as unattributed context",
                jira_key, _cands, len(_amb_cmds),
            )

    # Precedent lookup — inject previous occurrences of same alert for L1 context
    current_user = (
        (alert_data.get("relatedUser") or {}).get("userName", "")
        or (alert_data.get("loggedOnUsers") or [{}])[0].get("accountName", "")
        or ticket.get("user_name", "")
    )

    # Backfill device/user from Sentinel enrichment when the MDE/ticket fields are
    # empty. CloudTrail/identity alerts carry the real device + session principal
    # only in the Sentinel description, not the MDE fields — without this,
    # device_name/current_user stay empty, so ShadowResult, precedents, the agent's
    # entity context, and the SCG entity graph never bind to a device/user.
    _ct = sentinel_entities.get("cloudtrail") or {}
    _lb = sentinel_entities.get("lolbin") or {}
    _rr = sentinel_entities.get("rule_replay") or {}
    _sa = sentinel_entities.get("sentinel_alert") or {}
    _nm = sentinel_entities.get("netskope_malware") or {}
    _lg = sentinel_entities.get("local_group") or {}
    if not device_name:
        device_name = (_ct.get("device_name", "") or _lb.get("device_name", "")
                       or _rr.get("device_name", "") or _sa.get("device_name", "")
                       or _nm.get("hostname", "") or _lg.get("device_name", "")
                       or (sentinel_entities.get("hosts") or [""])[0])
    if not current_user:
        from edr_triage.playbooks.generic import _arn_session_user
        _ct_arn = _ct.get("user_arn", "")
        current_user = (
            _arn_session_user(_ct_arn)                   # AWS assumed-role principal (the person)
            or _ct.get("user_name", "")
            or _ct.get("session_issuer", "")
            or _ct.get("account_name", "")               # CloudTrail/GuardDuty/root entity account
            # Non-ARN Account entity. Was reaching this chain as `user_arn` before that
            # field was made honest; keep resolving the SAME actor from the renamed key
            # so no alert loses its user (the `accounts` step below never fired on this
            # path — each enricher branch assigns its own dict).
            or _ct.get("entity_account", "")
            or _lb.get("account_name", "")
            or _rr.get("account_name", "")
            or _sa.get("account_name", "")
            or _nm.get("user", "")
            # Local-group changes: the RECIPIENT (who the change is ABOUT), never the
            # grantor — an FP judgment like "this person already has the role" is about
            # the recipient, and arming an allowlist on the grantor would auto-close a
            # compromised admin account granting a NEW, unreviewed recipient. The
            # grantor stays available on _lg for whichever playbook renders the L1/L2
            # narrative — it is deliberately not folded into current_user here.
            or _lg.get("recipient_account", "")
            or (sentinel_entities.get("accounts") or [""])[0]
            # Last resort: a non-ARN principal that landed in user_arn — an Office/Exchange
            # service account (NT SERVICE\MSExchange…), an EKS/service entity, or a bare UPN
            # (GuardDuty). The AWS ARN parser above yields nothing for these, but the raw
            # value IS the actor. A bare arn:aws: string is skipped (noise, not a person).
            or (_ct_arn if _ct_arn and not _ct_arn.lower().startswith("arn:aws:") else "")
        )
    # Sentinel enrichment above may have only just resolved device_name (it wasn't in
    # alert_data at the first resolution pass ~line 190, so that pass skipped). Re-attempt
    # the MDE machineId lookup now that we have a hostname — otherwise a still-blank id makes
    # the prompt declare the host "not Defender-onboarded" even when it is (DEMO-106488: an
    # Onboarded/Active macOS host was reported unonboarded with "no EDR telemetry", despite
    # the alert itself being a Defender macOS EDR alert). Best-effort; guarded.
    if not machine_id and device_name and token:
        from lib.mde_client import get_machine_by_dns_name
        _mach2 = await get_machine_by_dns_name(device_name, token)
        if _mach2 and _mach2.get("id"):
            machine_id = _mach2["id"]
            alert_data["machineId"] = machine_id
            alert_data["_mde_onboarding"] = _mach2.get("onboardingStatus", "")
            logger.info("[mde-resolve] %s: (post-enrich) %s -> machine_id=%s (onboard=%s)",
                        jira_key, device_name, str(machine_id)[:12], _mach2.get("onboardingStatus", ""))

    # LAST RESORT: reuse the binding a PREVIOUS triage of this ticket resolved.
    #
    # device/user are re-fetched live from Sentinel every run and that fetch degrades as
    # an incident ages, so a replay can come back with nothing where the original run
    # bound correctly. Keeping the value on the saved ShadowResult (see _save_shadow_result)
    # protects the record, but the record is written at the END — the PROMPT is built from
    # these locals, so the agent still ran blind: DEMO-107797 re-triaged with a stored
    # user of emery.bose@example.com and the agent reported "No Principal Bound", could not
    # investigate, and escalated at 0.0 confidence.
    #
    # Only fills a GAP — never overrides a live value — so a genuine re-bind or a
    # correction still wins, and a ticket that legitimately has no principal (port sweeps,
    # Netskope malware: 45 of the 49 unbound alerts, scoring 0.929) is unaffected because
    # no prior binding exists to restore. Best-effort: any failure leaves today's
    # behaviour exactly as-is.
    if not (current_user and device_name):
        try:
            from entity_graph.models import ShadowResult
            _prev = await (
                ShadowResult.find(ShadowResult.jira_key == jira_key)
                .sort(-ShadowResult.created_at)
                .first_or_none()
            )
            if _prev:
                if not current_user and (getattr(_prev, "user_name", "") or "").strip():
                    current_user = _prev.user_name
                    logger.warning(
                        "%s: live enrichment bound no user — reusing %r from the previous "
                        "triage so the agent is not left unbound", jira_key, current_user)
                if not device_name and (getattr(_prev, "device_name", "") or "").strip():
                    device_name = _prev.device_name
                    logger.warning(
                        "%s: live enrichment bound no device — reusing %r from the previous "
                        "triage", jira_key, device_name)
        except Exception as exc:
            logger.debug("prior-binding reuse skipped for %s: %s", jira_key, exc)

    # Surface the resolved values to the fire-and-forget entity extractor, which
    # otherwise reads only the (empty) MDE fields and creates no entity.
    if device_name and not alert_data.get("computerDnsName"):
        alert_data["computerDnsName"] = device_name
    if current_user and not (alert_data.get("relatedUser") or {}).get("userName"):
        alert_data["relatedUser"] = {"userName": current_user}
    # relatedUser holds ONE user, so the co-users on a grouped incident travel alongside
    # it — the extractor creates an entity per user from this. EMPTY for single-user alerts.
    _other_users = [a for a in (sentinel_entities.get("accounts") or []) if a and a != current_user]

    # Co-hosts on a grouped SSM/CloudTrail incident carry their OWN session principal,
    # and it lives only inside the assumed-role ARN — not in the incident's AccountEntity
    # list, which is where _other_users comes from. So a multi-ACTOR incident was being
    # recorded as single-actor: DEMO-108127 groups 5 co-hosts and names two people in the
    # ticket body (cleo.menon on the primary, morgan.diaz on two co-hosts via
    # `.../assumed-role/ssm-session-dba-charlie-role/morgan.diaz@example.com`), yet
    # additional_users was []. The co-HOSTS were captured; the co-USERS were dropped.
    #
    # Consequences of dropping them: the SCG never creates an entity for the co-actor, so
    # their prior verdicts are not recalled on this ticket (morgan.diaz already has
    # curated DB-migration justifications from DEMO-108138/108171 — the same INT-108677
    # work — and none of it was reachable here), and scg_check_concurrent_alerts cannot
    # correlate on them at all.
    #
    # Same parser the primary actor already uses, applied to the co-host rows. Additive:
    # dedupes against the primary and anything the entity list already supplied, so no
    # single-actor alert changes shape.
    # Structured host<->actor pairing, built alongside the flat _other_users list
    # above (which stays exactly as-is — nothing that reads it changes shape). A
    # grouped incident's hosts get flattened into one bare device-name list and its
    # actors into a separate, unlinked list, so nothing downstream can tell WHICH
    # host belongs to WHICH actor. DEMO-109720: kiran ran a benign package install on
    # 2 hosts, morgan ran log-tailing/docker-status on 3 unrelated DBA hosts — the
    # flat lists made this look like one incident with two incidental extra names,
    # not two people who each need their own evidence bar. Only populated when the
    # incident spans more than one actor; a single-actor alert never sets this key.
    _actor_host_groups: dict[str, dict] = {}

    def _add_actor_host(actor: str, host: str, command: str = "") -> None:
        if not actor or not host:
            return
        grp = _actor_host_groups.setdefault(actor.lower(), {"actor": actor, "hosts": [], "commands": []})
        if host not in grp["hosts"]:
            grp["hosts"].append(host)
        if command and command not in grp["commands"]:
            grp["commands"].append(command)

    try:
        from edr_triage.playbooks.generic import _arn_session_user
        _seen = {(current_user or "").lower()} | {u.lower() for u in _other_users}
        if current_user and device_name:
            _add_actor_host(current_user, device_name,
                             cloudtrail.get("command", "") if isinstance(cloudtrail, dict) else "")
        # isinstance guard: same malformed-row shape as elsewhere in this cascade — the
        # try/except below keeps one bad row from crashing the ticket, but without this
        # it would still abort the loop and silently drop every OTHER, valid co-actor row.
        for _row in ((sentinel_entities.get("cloudtrail") or {}).get("additional_hosts") or []):
            if not isinstance(_row, dict):
                continue
            _p = _arn_session_user(_row.get("user_arn", "") or "")
            if _p and _p.lower() not in _seen:
                _other_users.append(_p)
                _seen.add(_p.lower())
                logger.info("%s: co-actor %r recovered from a co-host ARN (%s)",
                            jira_key, _p, _row.get("device_name", "?"))
            _add_actor_host(_p or _row.get("account_name", ""), _row.get("device_name", ""),
                             _row.get("command", ""))
    except Exception as exc:
        logger.debug("co-actor ARN extraction skipped for %s: %s", jira_key, exc)

    if _other_users:
        alert_data["_additional_users"] = _other_users

    # Multi-process hunting alerts ("rare process as a service") carry a LIST of
    # service executables across hosts. Enumerate the distinct set and classify
    # each against a known-good allowlist DETERMINISTICALLY (pure code — no LLM,
    # no per-process token cost). SOURCE IS RESTRICTED to the service-list enrichers
    # (rule-replay rows, the alert's own service entities). Deliberately NOT
    # _lb.commands / evidence.command_lines — those are command-based alerts (LOLBin,
    # malware) whose raw command CONTENT is the evidence and must never be summarized
    # away. The >=4-distinct gate further ensures this only fires for genuine
    # process-list alerts, not a 1-2 command event (DEMO-104466).
    _proc_cmds = (
        sentinel_entities.get("alert_command_lines")
        or _rr.get("distinct_processes")
        or _sa.get("command_lines")
        or []
    )
    # "Rare Process as a Service" IS a service list by definition, so it needs no size
    # gate: with 1-3 processes it used to get no process_check at all, so the prompt never
    # pointed at hunt_service and the fleet-signer upgrade could never fire. Every one of
    # those tickets escalated (DEMO-116509: CxAudioSvc.exe + scheduler.exe, "hunt_service
    # was not called"; DEMO-114502/115595/116342 one process each). Other families keep
    # the >=4 gate above.
    _min_procs = 1 if _is_service_list_alert(alert_name) else 4
    if len(_proc_cmds) >= _min_procs:
        from edr_triage.service_allowlist import classify_processes
        _pc = classify_processes(_proc_cmds)
        if _pc.get("distinct", 0) >= _min_procs:
            evidence = dict(evidence or {})
            evidence["process_check"] = _pc
            logger.info("Process check for %s: %s", jira_key, _pc)
            # Deterministic MDE process telemetry — resolve the FLAGGED (unknown) process
            # names to their hash / path / vendor FLEET-WIDE so the agent can VERIFY them
            # (recognized signed vendor => sound FP; blank vendor or Temp/ProgramData path =>
            # escalate) instead of escalating "no telemetry" or auto-closing on device
            # history alone. Fleet-wide, NOT device-scoped: a long-running service emits no
            # launch event on its own host in-window, so a device query is empty even at 30d;
            # keying on the rare flagged names identifies each binary in a few rows. Gated on
            # process_check (never fires on identity/cloud/network alerts). Best-effort — a
            # miss/error leaves current behavior untouched, never blocks triage.
            # Exclude ubiquitous/abusable OS binaries from the FLEET-WIDE resolution:
            # they return hundreds of legitimate rows that flood the query's `take` cap
            # and crowd out the genuinely-rare service names we actually need to vendor-
            # resolve (DEMO-106568: msiexec.exe alone returned ~15 rows and pushed the rare
            # names off the result). They REMAIN in process_check.unknown so the agent
            # still sees and verifies them — a suspected masquerade of a common name is a
            # DEVICE-scoped question, not a fleet-wide one, so a fleet summary adds no signal.
            _COMMON_FLOODERS = {
                "msiexec.exe", "svchost.exe", "spoolsv.exe", "rundll32.exe", "dllhost.exe",
                "conhost.exe", "taskhostw.exe", "wmiprvse.exe", "cmd.exe", "powershell.exe",
                "regsvr32.exe", "explorer.exe", "services.exe", "wininit.exe", "lsass.exe",
                "sqlservr.exe", "mmc.exe", "werfault.exe",
            }
            _all_unknown = _pc.get("unknown") or []
            _flagged = [p for p in _all_unknown if p.lower() not in _COMMON_FLOODERS]
            _dropped = [p for p in _all_unknown if p.lower() in _COMMON_FLOODERS]
            if _dropped:
                logger.info("[mde-proc] %s: not fleet-resolving %d common OS binar(ies) "
                            "(left in process_check for the agent): %s",
                            jira_key, len(_dropped), ", ".join(_dropped))
            if token and _flagged:
                try:
                    from lib.kql_templates import mde_process_details
                    from lib.mde_client import run_mde_query
                    _rows, _perr = await run_mde_query(
                        mde_process_details(_flagged, window_hours=168), token)
                    if _rows:
                        evidence["mde_process_details"] = _rows[:50]
                        logger.info("[mde-proc] %s: %d telemetry row(s) for %d flagged process(es)",
                                    jira_key, len(_rows), len(_flagged))
                    elif _perr:
                        logger.info("[mde-proc] %s: hunt returned error: %s", jira_key, str(_perr)[:120])
                except Exception as _pe:
                    logger.info("[mde-proc] %s: process enrichment failed: %s", jira_key, _pe)

    from edr_triage.store import attach_human_outcomes, get_precedents
    precedents = await attach_human_outcomes(get_precedents(alert_name, device_name, current_user))
    alert_data["_precedents"] = precedents
    alert_data["_current_user"] = current_user

    # Normalize the alert at the ingestion boundary — playbooks read this instead
    # of reaching into raw MDE/Sentinel field names. device_name/current_user carry
    # any Sentinel/CloudTrail enrichment the pipeline already resolved.
    from edr_triage.normalized import normalize_alert
    normalized = normalize_alert(
        alert_data, evidence, sentinel_entities,
        source=("sentinel" if is_sentinel else "mde"),
        device_hint=device_name, user_hint=current_user,
    )

    # Asset ownership — which tribe owns this host, who to ask about it.
    #
    # Resolved ONCE here, after normalization, so the agent prompt and the deterministic
    # playbook comment read the same answer. Purely additive: it names an owner, it never
    # argues for a verdict, and nothing downstream gates on it.
    #
    # Tried in widening order because a ticket names its host several ways and only one
    # is usually in the register — the InstanceId when the alert carries one (GuardDuty
    # EC2 findings do), then the normalized device, then the raw MDE/Sentinel hostname.
    if normalized.device and normalized.device != "Unknown Device":
        try:
            from lib.tribe_client import lookup_first
            _tribe = await lookup_first(
                (evidence or {}).get("instance_id") or "",
                normalized.device,
                device_name or "",
            )
            if _tribe:
                # Mutated IN PLACE, not replaced: normalized.evidence holds a reference to
                # this same dict, and rebinding the name here would silently split them.
                if evidence is None:
                    evidence = {}
                evidence["asset_tribe"] = _tribe
        except Exception as _exc:      # asset-register outage must never stop triage
            logger.debug("[tribe] skipped for %s: %s", jira_key, _exc)

    # Upwind's picture of this host — internet exposure, open Upwind threats, critical and
    # exploitable vulnerabilities, misconfigurations — read from the local mirror
    # (edr_triage/upwind_mirror.py), never from Upwind on the triage path. Same keys as the
    # tribe lookup: an MDE/GuardDuty alert on a cloud host meets Upwind's record of it by
    # instance id or Name tag. Context only; nothing gates on it.
    if normalized.device and normalized.device != "Unknown Device":
        try:
            from edr_triage.upwind_mirror import lookup_asset
            _uwa = await lookup_asset((evidence or {}).get("instance_id") or "", normalized.device,
                                      device_name or "")
            if _uwa:
                if evidence is None:
                    evidence = {}
                evidence["upwind_asset"] = _uwa
        except Exception as _exc:      # a mirror read must never stop triage
            logger.debug("[upwind] asset context skipped for %s: %s", jira_key, _exc)

    # Normalized live processes — distinct executable basenames seen in this alert.
    # Used for command-narrowed allowlist matching (below) and persisted on the
    # shadow row so the allowlist suggester can mine command-level FP patterns.
    _raw_cmds: list[str] = []
    _live_procs: list[str] = []
    try:
        from edr_triage.service_allowlist import normalize_process as _np
        # Union of raw command lines from MDE evidence + Sentinel alert entities, so
        # a compliance script is matchable whether the alert is endpoint- or
        # Sentinel-sourced (e.g. "Powershell script was loaded in memory").
        _seen_cmd: set[str] = set()
        for _src in (
            (normalized.command_lines if normalized else None),
            evidence.get("command_lines"),
            sentinel_entities.get("alert_command_lines"),
        ):
            for _c in (_src or []):
                if _c and _c not in _seen_cmd:
                    _seen_cmd.add(_c)
                    _raw_cmds.append(_c)
        _live_procs = sorted({_np(c) for c in _raw_cmds if c and _np(c)})
    except Exception as _exc:
        logger.debug("live-process extraction failed for %s: %s", jira_key, _exc)

    # Live cloud apps — the SaaS analogue of _live_procs, for app-narrowed allowlist
    # matching on Netskope/CASB alerts. The UBA enrichment already binds per-user apps
    # from Netskope_Alerts_CL (rendered as "*App:* …" in the L1 comment); this lifts
    # them into a flat set the matcher can check. Empty for non-Netskope alerts, which
    # simply means an app-pinned entry can never match them (fail-closed).
    _live_apps: list[str] = []
    _live_instances: list[str] = []
    try:
        _uba = (sentinel_entities or {}).get("netskope_uba") or {}
        _app_set: set[str] = set()
        for _b in (_uba.get("by_user") or {}).values():
            for _a in (_b.get("apps") or []):
                if _a and str(_a).strip():
                    _app_set.add(str(_a).strip().lower())
        if not _app_set:
            _app_set = set(dlp_live_apps((sentinel_entities or {}).get("netskope_dlp")))
        _live_apps = sorted(_app_set)
        # ...and which ACCOUNT of each app (Netskope instance_id). Collected with a
        # placeholder for any event that recorded none, so an account-pinned entry can
        # never match an alert whose account is unknown (the matcher requires every live
        # value to be pinned, and "" never is).
        _inst_set: set[str] = set()
        for _b in (_uba.get("by_user") or {}).values():
            _bi = [str(x).strip().lower() for x in (_b.get("instances") or []) if str(x).strip()]
            _inst_set |= set(_bi) if _bi else {"(not recorded)"}   # older binds had no field
        _live_instances = sorted(_inst_set)
    except Exception as _exc:
        logger.debug("live-app extraction failed for %s: %s", jira_key, _exc)

    # Sign-in spray check result, computed at most once per ticket: in the agent prefetch
    # when the agent runs, otherwise lazily at the close gate. See signin_guard.py.
    _spray_check = None
    # USB alert: did Sentinel show no removable drive at all? Computed in the agent prefetch;
    # the close gate refuses a USB close without an affirmative answer. See usb_guard.py.
    _usb_drive_check = None
    _spray_users = [u for u in [current_user, *(alert_data.get("_additional_users") or [])] if u]
    _spray_anchor = alert_data.get("alertCreationTime", "") or ticket.get("created_at", "")

    # Root Privesc with several SSM sessions on the host: if every one of those people
    # would pass the repeat rule and the session check on their own, who ran it no longer
    # matters — un-flag it so the agent gate and close gate treat it like one operator.
    # Anything short of that leaves actor_ambiguous set (privesc_guard.resolve_ambiguity).
    _ct_amb = (sentinel_entities or {}).get("cloudtrail") or {}
    if _ct_amb.get("actor_ambiguous"):
        from edr_triage import privesc_guard as _pg
        if _pg.applies(alert_name):
            _sess = _privesc_session(sentinel_entities, alert_data, ticket, incident_url)
            _dev, _, _cmds = _privesc_live(device_name, current_user, evidence, sentinel_entities)
            try:
                _amb_ok, _amb_why = await _pg.resolve_ambiguity(
                    jira_key, _dev, _cmds, _ct_amb, _sess["anchor"], incident_url, get_edr_config())
            except Exception as _exc:
                _amb_ok, _amb_why = False, f"check failed ({_exc})"
            logger.info("[PRIVESC-AMBIGUITY] %s: %s — %s", jira_key,
                        "cleared" if _amb_ok else "kept", _amb_why)
            if _amb_ok:
                _ct_amb["actor_ambiguous"] = False
                _ct_amb["ambiguity_cleared"] = _amb_why

    # Deterministic actor-allowlist short-circuit — if an L2 has armed a golden
    # auto_fp memory for this actor (+device, +commands) + alert type, auto-close as
    # FP WITHOUT an LLM call. This is the "hard" form of golden memory: entity-scoped,
    # human-gated, and it never fires type-wide (match keys on the specific principal).
    result = None
    # True on every path EXCEPT the autonomous-phase agent path below — allowlist,
    # planned-activity, and every playbook.run() call (agent-disabled, shadow/copilot
    # alongside the agent, and every fallback when the agent errors/times out) render
    # l1_comment from code reading Sentinel/CloudTrail fields straight, no LLM in the
    # loop. Only _build_playbook_result_from_agent() renders it from the agent's OWN
    # reasoning (to_jira_comment) — flipped to False right there, nowhere else needed.
    _l1_comment_deterministic = True
    try:
        # Scope the match on the LEARNING subtype, not the playbook name — must match
        # what allowlist_suggester._alert_type armed the entry with. Falls back to
        # classify(), so entries armed before subtypes existed keep matching.
        from edr_triage.classifier import alert_subtype as _subtype_allow
        from entity_graph.memory import match_actor_allowlist
        from edr_triage import privesc_guard as _pg_allow
        _allow = await match_actor_allowlist(
            _subtype_allow(alert_name), current_user, device_name,
            commands=_live_procs, apps=_live_apps, instances=_live_instances,
            # Whole command lines, so an entry pinned to `su - netra` clears exactly that.
            # Root Privesc reads them the way its comment and repeat rule do.
            full_commands=(_privesc_live(device_name, current_user, evidence, sentinel_entities)[2]
                           if _pg_allow.applies(alert_name) else _raw_cmds),
            direction=str(((sentinel_entities or {}).get("netskope_uba") or {}).get("kind", "")),
        )
    except Exception as _exc:
        _allow = None
        logger.debug("actor-allowlist check failed for %s: %s", jira_key, _exc)
    if _allow:
        # Novelty gate. An armed entry says "this actor's <alert> is fine" — true of the
        # owner, and equally true of an attacker holding the account on a machine the
        # owner never used. The short-circuit makes no LLM call, so nothing downstream
        # would ever see that the actor or device is new. If either is a first sighting
        # for this alert — or the history cannot be read — fall through to normal triage.
        try:
            from edr_triage.store import get_occurrence_history
            _hist = get_occurrence_history(alert_name, user_name=current_user,
                                           device_name=device_name, exclude_alert_id=alert_id)
        except Exception as _exc:
            _hist = {}
            logger.debug("allowlist novelty check failed for %s: %s", jira_key, _exc)
        _novel = (not _hist) or _hist.get("actor_first_seen") or _hist.get("device_first_seen")
        if _novel:
            logger.info("[ALLOWLIST] %s: NOT short-circuiting golden %s — %s", jira_key,
                        _allow.get("jira_key") or _allow.get("id"),
                        "history unreadable" if not _hist else "first sighting for this actor/device")
            _allow = None
    if _allow:
        from edr_triage import usb_guard as _usbg
        if _usbg.applies(alert_name):
            # G14: a USB copy is cleared only by the copier's reason for THIS copy, so an
            # earlier clearance of the same user or drive never closes a new one.
            logger.info("[ALLOWLIST] %s: not applied to a USB copy — the copier is asked",
                        jira_key)
            _allow = None
    # Netskope bulk upload/download: a learned pattern that fails any uba_guard check
    # (new device, volume jump, S3, another open alert, spot-check ...) is dropped HERE,
    # not only at the close gate. Otherwise the allowlist result would replace the
    # playbook, and a blocked repeat would reach L2 without the user ever being asked —
    # on exactly the tickets where the answer matters most.
    _uba_learned_note = ""
    if _allow:
        from edr_triage import uba_guard as _ubg
        if _ubg.applies(alert_name):
            try:
                _ok, _why = await _ubg.evaluate(
                    ["raptor-actor-allowlist"], _allow,
                    (sentinel_entities or {}).get("netskope_uba"), jira_key, get_edr_config(),
                    reference_time=_spray_anchor)
            except Exception as _exc:
                _ok, _why = False, f"the checks could not run ({_exc})"
            if not _ok:
                logger.info("[ALLOWLIST] %s: learned UBA pattern %s not applied — %s",
                            jira_key, _allow.get("id"), _why)
                _uba_learned_note = (
                    "*A learned L2-approved pattern matched this ticket but was NOT "
                    f"applied:* {_why}. The user is asked as usual and L2 decides.")
                _allow = None
    if _allow:
        result = _build_allowlist_result(_allow, alert_name, device_name, current_user)
        logger.info("[ALLOWLIST] %s auto-closed FP — actor=%s matched golden %s (%s)",
                    jira_key, current_user, _allow.get("jira_key") or "?", _allow.get("actor") or "?")

    # Planned-activity short-circuit — a declared, time-boxed maintenance/compliance
    # window (a known benign script tripping EDR fleet-wide). Matches on a command
    # substring, actor/device-agnostic, and auto-closes FP with no LLM call. Inert
    # once the window expires. Separate from golden memory (a temporary announcement).
    if result is None:
        try:
            from edr_triage.classifier import classify as _classify_pa
            from edr_triage.planned_activity import match_planned_activity
            _pa = await match_planned_activity(_raw_cmds, _classify_pa(alert_name))
        except Exception as _exc:
            _pa = None
            logger.debug("planned-activity check failed for %s: %s", jira_key, _exc)
        if _pa:
            result = _build_planned_activity_result(_pa, alert_name, device_name, current_user)
            logger.info("[PLANNED] %s auto-closed FP — matched planned activity '%s' (pattern=%s, until %s)",
                        jira_key, _pa.get("label") or "?", _pa.get("pattern") or "?", _pa.get("expires_at") or "?")

    # Run playbook (or agent loop if USE_AGENT_LOOP=true)
    playbook = _get_playbook(playbook_name)
    import os as _os
    # Default ON: the poll cycle runs the agent loop (shadow mode) on every ticket
    # to build the Mistral accuracy record. Set USE_AGENT_LOOP=false to revert to
    # playbook-only; force_agent forces it per-ticket regardless.
    _use_agent_loop = force_agent or _os.getenv("USE_AGENT_LOOP", "true").lower() == "true"
    # Families whose playbook is still being shaped run deterministically only — no
    # agent, no Bedrock spend, no AI verdict to score. Cyble threat-intel digests are
    # the current case: they were being agent-triaged purely because USE_AGENT_LOOP is
    # global, which spent credits the DLP work needs on a family we have not
    # characterised yet. `force_agent` still wins, so a single manual re-triage of one
    # of these tickets is still possible when we choose to look at one.
    if _use_agent_loop and not force_agent:
        from edr_triage.classifier import is_deterministic_only
        if is_deterministic_only(alert_name):
            _use_agent_loop = False
            logger.info("[DETERMINISTIC-ONLY] %s (%s) — playbook only, agent loop "
                        "skipped (no AI spend)", jira_key, alert_name[:60])
    # Burst de-duplication: one detection event, one agent run. A Netskope sweep fans
    # out into many Jira tickets (DEMO-110864..110872 = 9 tickets / 101 seconds / one
    # finding), and each was paying for its own full agent run. When this ticket binds
    # the SAME vendor DLP incident id(s) as a ticket already triaged, carry that verdict
    # over instead of re-deriving it.
    #
    # The sibling is still saved as its own ShadowResult and still scored — no row is
    # excluded and no verdict is altered after the fact, so measured accuracy is
    # unaffected. This is a cost change only. `force_agent` bypasses it so a deliberate
    # manual re-triage always really runs.
    _finding_group_id = ""
    _dup_reuse = None
    _duplicate_of = ""
    _dlp_bind = (sentinel_entities or {}).get("netskope_dlp") or {}
    _dlp_bind_source = _dlp_bind.get("bind_source", "")
    _dlp_bind_alert_id = _dlp_bind.get("bind_alert_id", "")
    _dlp_bound_users = _dlp_bind.get("users") or []
    if result is None and _use_agent_loop:
        try:
            from edr_triage.dedup import dlp_finding_group_id, find_duplicate_ticket
            # Computed even on a force_agent run: the key has to be STORED by real runs
            # too, or the first ticket of a burst is never findable and nothing ever
            # de-duplicates. Only the reuse itself is skipped when force_agent is set.
            # Read from sentinel_entities, NOT `evidence`: the DLP bind is stored at
            # :237 as sentinel_entities["netskope_dlp"] and only copied into the AGENT's
            # evidence later (:1196), which is after this point. Passing `evidence` here
            # meant dlp_finding_group_id never saw a DLP block and returned "" every time — so
            # burst dedup silently never fired. Caught only because dlp_bind_source
            # reported "alert" on DEMO-110937 while finding_group_id was empty, a combination
            # that cannot happen when both read the same dict.
            _finding_group_id = dlp_finding_group_id(
                {"netskope_dlp": (sentinel_entities or {}).get("netskope_dlp")})
            if _finding_group_id and not force_agent:
                _sib = await find_duplicate_ticket(_finding_group_id, alert_name, jira_key)
                if _sib is not None:
                    from agent_core.result import AgentResult as _AR
                    from edr_triage.dedup import reuse_result
                    _dup_reuse = reuse_result(_sib, _AR)
                    _duplicate_of = _sib.jira_key
                    logger.info("[BURST] %s duplicates %s (same DLP finding) — reusing "
                                "verdict %s, agent loop skipped (no AI spend)",
                                jira_key, _sib.jira_key, _sib.ai_triage_class)
        except Exception as _exc:
            # Never let dedup failure change triage: fall through to a normal agent run.
            _finding_group_id, _dup_reuse, _duplicate_of = _finding_group_id or "", None, ""
            logger.warning("burst dedup skipped for %s: %s", jira_key, _exc)

    # Advisory copilot comment — populated only in AGENT_PHASE=copilot, posted
    # after the playbook's own comments below. Stays empty on every other path
    # (shadow, autonomous, agent failure/timeout) so nothing extra is written.
    _copilot_comment = ""
    if result is None and _use_agent_loop and _dup_reuse is None:
        try:
            from agent_core.backend import get_backend, OllamaUnavailableError
            from agent_core import loop as _agent_loop
            from edr_triage.classifier import classify as _classify_alert
            _alert_type_for_backend = _classify_alert(alert_name)
            _prefetched = {
                "alert_data": alert_data,
                "alert_id": alert_id,
                "vt": vt,
                "vt_sha256": sha256,
                "timeline": timeline,
                "machine_id": machine_id,
            }
            _tactics = alert_data.get("mitreTechniques", []) or []
            # Consolidate pre-fetched evidence (command lines from MDE evidence or
            # the Sentinel/CloudTrail parse) so the agent gets it up-front.
            _ct = (sentinel_entities or {}).get("cloudtrail") or {}
            _agent_cmds = (
                (normalized.command_lines if normalized else None)
                or evidence.get("command_lines")
                or _ct.get("command_lines")
                or ([_ct["command"]] if _ct.get("command") else [])
                or []
            )
            # Defender/EDR classification (threat name, category, remediation) — the
            # native AV verdict deepintel used to miss by relying on VirusTotal alone.
            from edr_triage.mde_alerts import extract_alert_classification, fetch_machine_recent_alerts
            _cls = extract_alert_classification(alert_data)
            # Correlate other detections on the same device (e.g. a 'Trojan…prevented'
            # AV alert raised alongside this behavior alert).
            _related: list[str] = []
            if token and machine_id:
                try:
                    for _ra in await fetch_machine_recent_alerts(machine_id, token, top=15):
                        _tn = _ra.get("threatFamilyName") or _ra.get("threatName") or ""
                        _cat = (_ra.get("category") or "")
                        if _ra.get("id") != alert_id and (_tn or _cat.lower() == "malware"):
                            _related.append(
                                (_ra.get("title", "?") or "?")
                                + (f" [{_tn}]" if _tn else "")
                                + (f" — {_ra.get('severity','')}" if _ra.get("severity") else "")
                            )
                except Exception as _e:
                    logger.debug("related-alert fetch failed for %s: %s", jira_key, _e)
            # Port-sweep FP allowlist — the playbook auto-closes known-good sweep ports
            # (EDR_PORTSWEEP_FP_PORTS) as FP, but the agent has no access to that runbook
            # knowledge and escalates every sweep (DEMO-104585). Surface the allowlist
            # verdict so the shadow matches the playbook.
            _ps_check = None
            if _alert_type_for_backend == "port_sweep":
                try:
                    from edr_triage.playbooks.port_sweep import _extract_port
                    _pport = _extract_port(alert_name, alert_data.get("_description", ""))
                    if _pport:
                        _fp = cfg.portsweep_fp_ports()
                        _ps_check = {"port": _pport, "known_good": _pport in _fp,
                                     "fp_ports": sorted(_fp, key=lambda x: int(x))}
                except Exception as _e:
                    logger.debug("port_sweep check failed for %s: %s", jira_key, _e)
            # Novelty. Read here, next to the other prefetched facts, so the safety
            # gate and the prompt both see a plain value rather than doing I/O.
            try:
                from edr_triage.store import get_occurrence_history
                _occ = get_occurrence_history(
                    alert_name, user_name=current_user, device_name=device_name,
                    exclude_alert_id=alert_id)
            except Exception as _e:
                logger.warning("occurrence history unavailable for %s: %s", jira_key, _e)
                _occ = {}

            from edr_triage.classifier import signin_spray_guard_applies
            if signin_spray_guard_applies(alert_name):
                from edr_triage import signin_guard
                _spray_check = await signin_guard.check(_spray_users, _spray_anchor)

            from edr_triage import usb_guard as _usbg_dc
            if _usbg_dc.applies(alert_name):
                _usb_drive_check = await _usbg_dc.drive_check(
                    incident_url, ticket.get("sentinel_alert_id", "") or "")
                logger.info("[USB] %s drive check: internal=%s — %s", jira_key,
                            _usb_drive_check.get("internal"), _usb_drive_check.get("reason"))

            # Can the people this ticket would ask actually be reached on Slack? Read here
            # so the REQUEST_JUSTIFICATION gate stays a pure function of the evidence. A
            # justification request nobody can receive is not a justification request:
            # DEMO-115194 recommended "no L2 escalation needed" for a BPO user with no
            # Slack while the playbook comment above it said the user could not be asked.
            # Fails closed — a lookup error, or anyone unresolvable, counts as unreachable.
            _reach_users = [u for u in dict.fromkeys(
                [current_user, *((sentinel_entities or {}).get("accounts") or []),
                 *((((sentinel_entities or {}).get("netskope_uba") or {}).get("users")) or [])])
                if u and str(u).strip()][:10]
            _actor_reachable, _actor_reach_reason = False, "no named user to ask"
            if _reach_users:
                try:
                    from edr_triage.identity import eligible_recipients
                    _elig_r, _rej_r = await eligible_recipients(_reach_users)
                    _actor_reachable = bool(_elig_r) and not _rej_r
                    _actor_reach_reason = "; ".join(_rej_r)[:300]
                except Exception as _e:
                    _actor_reach_reason = f"reachability lookup failed ({str(_e)[:80]})"
                    logger.warning("reachability check failed for %s: %s", jira_key, _e)

            _agent_evidence = {
                "actor_reachable": _actor_reachable,
                "actor_reach_reason": _actor_reach_reason,
                "signin_spray_check": _spray_check,
                "usb_drive_check": _usb_drive_check,
                "command_lines": _agent_cmds,
                "port_sweep_check": _ps_check,
                # {} when unreadable — oscar renders nothing rather than guessing, since
                # "never seen" and "seen often" are both wrong answers to "don't know".
                "occurrence_history": _occ,
                # Analyst notes ALREADY on the ticket (re-triage of a ticket that has
                # been escalated/commented on) — see oscar.py for how this is weighed.
                # EMPTY on a brand-new ticket's first triage, since nothing has been
                # written yet.
                "existing_comments": existing_comments,
                "file_name": evidence.get("file_name", ""),
                "file_path": evidence.get("file_path", ""),
                "sha256": sha256,
                "initiating_process": evidence.get("initiating_process", ""),
                # NB: deliberately NOT falling back to the CloudTrail session
                # principal here — that's the misattribution bug (DEMO-103882). The
                # correct actor is already passed as user_name.
                "account_name": evidence.get("account_name", ""),
                "threat_name": _cls.get("threat_name", ""),
                "category": _cls.get("category", ""),
                "determination": _cls.get("determination", ""),
                "detection_source": _cls.get("detection_source", ""),
                "remediation_status": evidence.get("remediation_status", ""),
                "process_check": evidence.get("process_check"),
                "netskope_malware": (sentinel_entities or {}).get("netskope_malware"),
                "netskope_uba": (sentinel_entities or {}).get("netskope_uba"),
                "netskope_dlp": (sentinel_entities or {}).get("netskope_dlp"),
                "netskope_failed_login": (sentinel_entities or {}).get("netskope_failed_login"),
                "guardduty_dns": (sentinel_entities or {}).get("guardduty_dns"),
                "guardduty_ec2": _guardduty_ec2_for_agent(sentinel_entities),
                "upwind_detection": evidence.get("upwind_detection"),
                # Every OTHER account this incident spans, so the agent investigates each
                # instead of reasoning about accounts[0] alone. Exact analogue of
                # additional_hosts: EMPTY for single-user alerts → no behaviour change
                # there. DEMO-107416 grouped two users under one SingleAlert rule; the
                # agent saw only the first and never knew the second existed.
                "additional_users": [
                    a for a in ((sentinel_entities or {}).get("accounts") or [])
                    if a and a != current_user
                ],
                "related_detections": _related[:8],
                # Set when the NRT PowerShell enrichment could not uniquely attribute a
                # host (multiple concurrent LOLBin hits). Tells the agent NOT to reason
                # about a specific host/command — escalate instead of guessing.
                "host_ambiguous": bool((sentinel_entities or {}).get("lolbin_ambiguous")),
                "candidate_devices": (sentinel_entities.get("lolbin_ambiguous") or {}).get("candidate_devices", []),
                # The invocations the enrichment recovered when the HOST could not be
                # bound. Unattributed on purpose — see the lolbin_ambiguous branch — but
                # the agent needs to see WHAT ran, or it is reasoning about an alert whose
                # subject is blank (DEMO-108429: "the process command line was not present
                # in the MDE alert evidence").
                "candidate_commands": (sentinel_entities.get("lolbin_ambiguous") or {}).get("candidate_commands", []),
                # Grouped-incident co-hosts (privesc/CloudTrail): every OTHER host the
                # incident spans, so the agent investigates each — not just the primary
                # device_name (DEMO-106765, where the agent cleared the quiet host and
                # never saw the co-host's `sudo sudo su`). EMPTY for single-host and
                # non-grouped alerts → zero behaviour change on those paths.
                # isinstance guard: a malformed/partial CloudTrail or local-group replay row
                # can land a bare None in this list (DEMO-108679/108667/108518 crashed the
                # WHOLE agent loop here at 0 iterations — AttributeError: 'NoneType' object
                # has no attribute 'get' — because this comprehension runs before the loop's
                # first LLM call, inside the same try/except that reports it as
                # agent_exception). One bad row must cost that one co-host, not the
                # investigation.
                "additional_hosts": [h.get("device_name") for h in (_ct.get("additional_hosts") or [])
                                     if isinstance(h, dict) and h.get("device_name")],
                # Same co-hosts, but keeping whatever per-host command detail the
                # enrichment cascade actually recovered — empty command_lines means a
                # BARE host (telemetry aged out before any per-host CloudTrail row
                # existed for it, see the tier cascade above). oscar.py uses this to
                # give the agent the co-host's REAL triggering command when known, and
                # to warn against guessing when it isn't (DEMO-112040: the agent hunted
                # a bare co-host for `tcpdump` — the PRIMARY host's process — got 0
                # rows, and read that as "co-host cannot be cleared"; the co-host's own
                # activity was never established to be tcpdump in the first place).
                "additional_hosts_detail": [
                    {"device_name": h.get("device_name"),
                     "command_lines": (h.get("command_lines")
                                       or ([h["command"]] if h.get("command") else []))}
                    for h in (_ct.get("additional_hosts") or [])
                    if isinstance(h, dict) and h.get("device_name")
                ],
                # Paired host<->actor groups (see _add_actor_host above) — empty for
                # single-actor alerts, so nothing reading this key changes shape there.
                "actor_hosts": list(_actor_host_groups.values()),
                # AWS/SSM identity — surfaced so the agent labels the IAM role as a ROLE
                # and never reads a username out of the role name (DEMO-107147). The actor
                # is user_name (the ARN session principal), passed separately above.
                "session_issuer": _ct.get("session_issuer", ""),
                "user_arn": _ct.get("user_arn", ""),
                # Every SSM session principal on the primary host, and whether that
                # leaves the actor undetermined (more than one). The safety gate reads
                # actor_ambiguous; the model must not pick one of them.
                "session_principals": _ct.get("session_principals") or [],
                "actor_ambiguous": bool(_ct.get("actor_ambiguous")),
            }
            # Generous wall-clock failsafe: a healthy run takes 6-8 min, so this
            # only fires if the loop is genuinely hung. Tunable via env.
            _agent_wall_timeout = int(_os.getenv("AGENT_LOOP_WALL_TIMEOUT", "720"))
            _agent_result = await asyncio.wait_for(
                _agent_loop.run(
                    jira_key=jira_key,
                    alert=alert_data,
                    alert_name=alert_name,
                    severity=alert_data.get("severity", ticket.get("severity", "")),
                    device_name=device_name,
                    user_name=current_user,
                    sha256=sha256,
                    inv_state=inv_state,
                    tactics=_tactics,
                    incident_url=incident_url,
                    is_test_device=is_test,
                    backend=get_backend(_alert_type_for_backend),
                    prefetched_context=_prefetched,
                    alert_type=_alert_type_for_backend,
                    evidence=_agent_evidence,
                    source=source,
                    progress_cb=progress_cb,
                ),
                timeout=_agent_wall_timeout,
            )
            # Write shadow result for accuracy tracking
            _shadow_phase = _effective_agent_phase(alert_name)
            await _save_shadow_result(jira_key, alert_id, alert_name, device_name, current_user,
                                      alert_data.get("severity", ""), _agent_result, _shadow_phase,
                                      alert_processes=_live_procs,
                                      additional_users=_agent_evidence.get("additional_users"),
                                      actor_hosts=_agent_evidence.get("actor_hosts"),
                                      finding_group_id=_finding_group_id,
                                      dlp_bind_source=_dlp_bind_source,
                                      dlp_bind_alert_id=_dlp_bind_alert_id,
                                      dlp_bound_users=_dlp_bound_users,
                                      asset_tribe=(evidence or {}).get("asset_tribe"))
            # _shadow_phase is already _effective_agent_phase(alert_name) — the PER-FAMILY
            # phase, which resolves to copilot for any family off AGENT_AUTONOMOUS_ALERTS.
            # So this is family-scoped without any extra check.
            # Families whose PLAYBOOK keeps control of ticket state even in autonomous
            # phase. For Netskope Bulk Upload/Download the playbook's decision IS the
            # workflow — chase every named user, then L2 approves any close — so letting
            # the agent's verdict replace it would silently drop the chase. The agent's
            # verdict is still posted, as a recommendation.
            if _shadow_phase == "autonomous" and not _playbook_keeps_control(alert_name):
                # Phase 3: the agent's verdict drives comments, transitions and auto-close.
                result = _build_playbook_result_from_agent(_agent_result, jira_key)
                # PowerShell-in-memory's guard reads its precedent history from a
                # Device/User/Command block on past tickets. The playbook that used to post
                # it does not run in autonomous phase, so write the record here — or the
                # guard would starve itself of history within its 30-day window.
                from edr_triage import powershell_guard as _psg
                if _psg.applies(alert_name):
                    result.l1_comment = ((result.l1_comment or "") + "\n\n" + _psg.evidence_record(
                        normalized.device if normalized else device_name,
                        normalized.user if normalized else current_user,
                        list((normalized.command_lines if normalized else None) or [])))
                # Same for Root Privesc: its guard learns from the CloudTrail comment block
                # that generic.py posts, which autonomous phase also skips.
                from edr_triage import privesc_guard as _pvg
                if _pvg.applies(alert_name):
                    result.l1_comment = ((result.l1_comment or "") + "\n\n" + _pvg.evidence_record(
                        *_privesc_live(device_name, current_user, evidence, sentinel_entities)))
                # l1_comment here is agent_result.to_jira_comment(...) — the agent's OWN
                # reasoning, not a re-extraction of Sentinel/CloudTrail fields. Must not
                # be trusted as ground truth on a future re-triage (it would let the
                # agent validate its own claim against itself).
                _l1_comment_deterministic = False
            else:
                # Phase 1 (shadow) and Phase 2 (copilot) both keep the deterministic
                # playbook in control of ticket state — same comments, same
                # transitions, same auto-close. They differ only in whether the
                # agent's verdict is made visible on the ticket.
                logger.info("[AGENT-%s] %s: agent verdict=%s confidence=%.2f",
                            _shadow_phase.upper(), jira_key,
                            _agent_result.triage_class, _agent_result.confidence)
                result = await playbook.run(
                    jira_key=jira_key, alert=alert_data, evidence=evidence, vt=vt,
                    timeline=timeline, is_test_device=is_test, sentinel_entities=sentinel_entities,
                    normalized=normalized,
                )
                # The dashboard's "AI Reasoning · Mistral Large 3" block reads
                # result.llm_reasoning. The playbook only sets that for some alert
                # types (privesc/cloudtrail), leaving it empty for others (e.g.
                # endpoint_process) → "No AI reasoning recorded" even though the
                # agent DID reason. Surface the agent's actual reasoning so it shows
                # consistently and the label is truthful.
                if _agent_result.reasoning:
                    result.llm_reasoning = _agent_result.reasoning
                if _shadow_phase != "shadow":
                    # Advisory only: an extra comment + a filterable label. Both are
                    # non-destructive — result.action / result.auto_close are left
                    # exactly as the playbook set them, so the agent cannot close,
                    # resolve or transition anything here.
                    #
                    # Condition is "not shadow" rather than "== copilot" because this
                    # branch is now also reached in AUTONOMOUS phase, by every family the
                    # agent does not own. Left as `== copilot`, enabling the pilot would
                    # have silently stripped the agent's recommendation from every
                    # non-piloted ticket — a visibility regression disguised as a rollout.
                    _copilot_comment = _agent_result.to_jira_recommendation(
                        alert_name, state_note=_playbook_state_note(alert_name, _shadow_phase))
                    _rec_label = _COPILOT_LABELS.get(_agent_result.triage_class)
                    if _rec_label and _rec_label not in result.labels:
                        result.labels = list(result.labels) + [_rec_label]
        except asyncio.TimeoutError:
            logger.warning("Agent loop wall-clock timeout (%ds) for %s, falling back to playbook",
                           _agent_wall_timeout, jira_key)
            await _save_agent_failure_shadow(jira_key, alert_id, alert_name, device_name,
                                             current_user, alert_data.get("severity", ""),
                                             f"agent loop wall-clock timeout after {_agent_wall_timeout}s",
                                             "agent_timeout")
            result = await playbook.run(
                jira_key=jira_key, alert=alert_data, evidence=evidence, vt=vt,
                timeline=timeline, is_test_device=is_test, sentinel_entities=sentinel_entities,
                normalized=normalized,
            )
        except Exception as _exc:
            logger.warning("Agent loop failed for %s (%s), falling back to playbook", jira_key, _exc, exc_info=True)
            # Record the failure as a shadow so agent errors are VISIBLE (a silent
            # fallback is indistinguishable from 'agent never ran'). Captures the
            # exception type + message for diagnosis.
            await _save_agent_failure_shadow(jira_key, alert_id, alert_name, device_name,
                                             current_user, alert_data.get("severity", ""),
                                             f"{type(_exc).__name__}: {_exc}", "agent_exception")
            result = await playbook.run(
                jira_key=jira_key, alert=alert_data, evidence=evidence, vt=vt,
                timeline=timeline, is_test_device=is_test, sentinel_entities=sentinel_entities,
                normalized=normalized,
            )
    elif result is None and _dup_reuse is not None:
        # Burst sibling: the verdict is carried over, the agent never ran. Everything
        # downstream is deliberately identical to a real agent run in shadow/copilot —
        # the ShadowResult is written and scored like any other, so this ticket stays in
        # the accuracy denominator. The only differences are that tool_calls is empty
        # and the reasoning says plainly which ticket it came from.
        _shadow_phase = _effective_agent_phase(alert_name)
        await _save_shadow_result(jira_key, alert_id, alert_name, device_name, current_user,
                                  alert_data.get("severity", ""), _dup_reuse, _shadow_phase,
                                  alert_processes=None,
                                  finding_group_id=_finding_group_id, duplicate_of=_duplicate_of,
                                  dlp_bind_source=_dlp_bind_source,
                                  dlp_bind_alert_id=_dlp_bind_alert_id,
                                  dlp_bound_users=_dlp_bound_users,
                                  asset_tribe=(evidence or {}).get("asset_tribe"))
        if _shadow_phase == "autonomous" and not _playbook_keeps_control(alert_name):
            # The reused verdict drives state, exactly as a freshly-derived one would.
            # Without this branch autonomy was a no-op for precisely the tickets it is
            # meant to clear: a duplicate fell through to the deterministic playbook
            # (netskope.py sets auto_close=False on every DLP path), so the sibling that
            # paid for the agent run got closed and the N-1 duplicates carrying its
            # verdict stayed open — the fan-out would still need a human.
            result = _build_playbook_result_from_agent(_dup_reuse, jira_key)
            _l1_comment_deterministic = False
        else:
            result = await playbook.run(
                jira_key=jira_key, alert=alert_data, evidence=evidence, vt=vt,
                timeline=timeline, is_test_device=is_test, sentinel_entities=sentinel_entities,
                normalized=normalized,
            )
            if _dup_reuse.reasoning:
                result.llm_reasoning = _dup_reuse.reasoning
            if _shadow_phase != "shadow":
                _copilot_comment = _dup_reuse.to_jira_recommendation(
                    alert_name, state_note=_playbook_state_note(alert_name, _shadow_phase))
                _rec_label = _COPILOT_LABELS.get(_dup_reuse.triage_class)
                if _rec_label and _rec_label not in result.labels:
                    result.labels = list(result.labels) + [_rec_label]
    elif result is None:
        result = await playbook.run(
            jira_key=jira_key,
            alert=alert_data,
            evidence=evidence,
            vt=vt,
            timeline=timeline,
            is_test_device=is_test,
            sentinel_entities=sentinel_entities,
            normalized=normalized,
        )

    # SCG entity extraction — fire and forget, never blocks pipeline
    asyncio.create_task(_extract_entities_async(alert_data, result, jira_key, sha256))

    # Asset ownership line — appended at the SINGLE convergence point rather than in each
    # playbook: there are five playbook.run() call sites plus the agent-built result, and
    # twelve playbooks, so per-playbook edits would drift and miss paths. Informational,
    # like the precedent block below.
    #
    # Applied to ALL THREE comment surfaces, not just L1. It first went onto l1_comment
    # alone, which put the owner in front of the tier that does not escalate to anybody
    # and left it out of every L2-facing surface — the L2 draft and the copilot
    # recommendation, which is what L2 actually reads as "the AI triage". Ownership is
    # most useful precisely where a ticket is being handed onward and somebody has to be
    # contacted about the host.
    if (evidence or {}).get("asset_tribe"):
        from lib.tribe_client import format_tribe
        _tline = format_tribe(evidence["asset_tribe"])
        if _tline:
            _asset_section = f"\n*Asset ownership:* {_tline}"
            _footer = "[Auto-triaged by RAPTOR]"

            def _with_owner(_body: str) -> str:
                # Idempotent: a re-triage re-runs this whole path over a comment that may
                # already carry the line.
                if not _body or _tline in _body:
                    return _body
                if _footer in _body:
                    return _body.replace(_footer, _asset_section + "\n\n" + _footer)
                return _body + _asset_section

            result.l1_comment = _with_owner(result.l1_comment)
            result.l2_comment = _with_owner(result.l2_comment)
            _copilot_comment = _with_owner(_copilot_comment)

    # Upwind's picture of the host, on the same three surfaces and for the same reason: L2 is
    # who decides how urgent a compromise of an internet-exposed, exploitable host is.
    if (evidence or {}).get("upwind_asset"):
        from edr_triage.upwind_mirror import format_asset
        _uline = format_asset(evidence["upwind_asset"])
        if _uline:
            _uw_section = f"\n*Upwind cloud context:* {_uline}"
            _uw_footer = "[Auto-triaged by RAPTOR]"

            def _with_upwind(_body: str) -> str:
                if not _body or _uline in _body:          # idempotent across re-triage
                    return _body
                if _uw_footer in _body:
                    return _body.replace(_uw_footer, _uw_section + "\n\n" + _uw_footer)
                return _body + _uw_section

            result.l1_comment = _with_upwind(result.l1_comment)
            result.l2_comment = _with_upwind(result.l2_comment)
            _copilot_comment = _with_upwind(_copilot_comment)

    # Append precedent context to L1 comment (informational — never changes the outcome)
    if result.l1_comment and precedents:
        from edr_triage.playbooks.base import BasePlaybook
        precedent_section = BasePlaybook._precedent_section(precedents, device_name, current_user)
        if precedent_section:
            footer = "[Auto-triaged by RAPTOR]"
            if footer in result.l1_comment:
                result.l1_comment = result.l1_comment.replace(
                    footer, precedent_section + "\n\n" + footer
                )
            else:
                result.l1_comment += precedent_section

    if _uba_learned_note and result.l1_comment:
        result.l1_comment += "\n\n" + _uba_learned_note

    dry_run = cfg.dry_run
    test_labels_only = cfg.test_labels_only

    # The deterministic rules decide BEFORE anything is posted, so the ticket tells one story.
    # They used to run after the comments, and DEMO-116082 read "routing directly to L2", then
    # "escalate to L2 … will not close", then "RAPTOR closed this" — five seconds apart; an L1
    # reopened the correct close. Each rule has its own scope and gates: an exact repeat goes
    # to Duplicate (duplicate_guard.py), our AnyDesk block rule doing its job goes to Closed
    # (custom_block_guard.py), retired log tables go to False Positive (log_ingestion_guard.py).
    # None of these families is agent-autonomous. Their comments are held and posted in order.
    _rule_comments: list = []
    _dup_action = await _maybe_mark_duplicate(jira_key, alert_name, ticket, sentinel_entities,
                                              result, cfg, dry_run, test_labels_only,
                                              defer=_rule_comments)
    if not _dup_action:
        _dup_action = await _maybe_close_custom_block(jira_key, alert_name, alert_data,
                                                      _mde_evidence_raw, result, cfg, dry_run,
                                                      test_labels_only, defer=_rule_comments)
    if not _dup_action:
        _dup_action = await _maybe_close_log_ingestion(jira_key, alert_name, result, cfg,
                                                       dry_run, test_labels_only,
                                                       defer=_rule_comments)
    if _dup_action in RULE_CLOSE_ACTIONS:
        result.l1_comment, _copilot_comment = _one_story(result.l1_comment, _copilot_comment,
                                                         _dup_action)
        result.labels[:] = [l for l in result.labels
                            if l not in ("needs-l2-review", "no-playbook-fallback")]

    # Post L1 comment
    if result.l1_comment:
        await add_comment(jira_key, result.l1_comment, cfg, dry_run=dry_run)

    # The rule's own decision, right after the alert details it rests on.
    for _rc in _rule_comments:
        await add_comment(jira_key, _rc, cfg, dry_run=dry_run)

    # Post L2 comment (draft for L2 review or auto-resolution)
    if result.l2_comment:
        await add_comment(jira_key, result.l2_comment, cfg, dry_run=dry_run)

    # Post the copilot recommendation last, so the analyst reads the triage note
    # first and the agent's take as commentary on it (AGENT_PHASE=copilot only).
    if _copilot_comment:
        await add_comment(jira_key, _copilot_comment, cfg, dry_run=dry_run)

    # Page PagerDuty for severe, non-FP verdicts. Deliberately NOT gated by
    # _effective_agent_phase/may_change_ticket_state below — paging is a notification,
    # not a Jira state change, so it fires the same in shadow/copilot/autonomous (see
    # EDRTriageConfig.should_page). Only dry_run suppresses the real call.
    _severity = alert_data.get("severity", ticket.get("severity", ""))
    if cfg.should_page(_severity, result.triage_class):
        if dry_run:
            logger.info(
                "[DRY RUN] would page PagerDuty for %s (severity=%s triage_class=%s)",
                jira_key, _severity, result.triage_class,
            )
        else:
            # Best-effort, like every PagerDuty call: paging is a side channel, and it must
            # never be able to break triage. On 2026-09-25 an unguarded import here and in
            # the close branch shipped before lib/pagerduty_client.py was committed; every
            # autonomous close then raised AFTER walking the ticket, so its labels and
            # processed record were never written and the autoclose report went blind.
            try:
                from lib.pagerduty_client import trigger_event
                await trigger_event(
                    dedup_key=jira_key,
                    summary=f"{jira_key}: {alert_name} ({_severity})",
                    severity=_severity,
                    details={
                        "alert_name": alert_name,
                        "device_name": device_name,
                        "triage_class": result.triage_class,
                        "jira_url": f"{cfg.jira_url}/browse/{jira_key}",
                    },
                )
            except Exception as exc:
                logger.error("PagerDuty trigger for %s failed (triage unaffected): %s",
                             jira_key, exc)

    # Execute action
    #
    # Only AGENT_PHASE=autonomous may change ticket state. shadow and copilot are
    # advisory BY CONTRACT, and the copilot comment states that in writing on every
    # ticket it touches ("RAPTOR has not closed, resolved, or transitioned this ticket,
    # and will not"). DEMO-112105 made that sentence false in the same second it was
    # posted: the netskope Failed Login playbook returned action="event_analysis" and the
    # ticket went Assigned → Event Analysis while the phase was copilot.
    #
    # The invariant is enforced HERE, once, rather than by fixing the playbook that
    # happened to breach it. `dry_run` and `test_labels_only` were previously the only
    # guards on this block, so the phase contract was enforced nowhere and ANY playbook
    # setting a state-changing action bypassed it silently — malware.py:182 sets the same
    # action and has simply not won the race yet. Stated once, a future playbook that
    # invents a new state-changing action fails closed too.
    # _effective_agent_phase, not _resolve_agent_phase: the phase that governs THIS
    # ticket is the per-family one. A global "autonomous" with this family off the
    # AGENT_AUTONOMOUS_ALERTS list resolves to copilot here, so it changes no state.
    _phase = _effective_agent_phase(alert_name)
    _may_change_state = may_change_ticket_state(_phase, dry_run, test_labels_only)
    _close_refusal = ""

    action_taken = result.action
    if _dup_action:
        action_taken = _dup_action
    elif not _may_change_state and result.action in STATE_CHANGING_ACTIONS:
        logger.info(
            "[PHASE-GUARD] %s: suppressing action=%r (phase=%s dry_run=%s test_labels_only=%s)"
            " — advisory phases post comments and labels only",
            jira_key, result.action, _phase, dry_run, test_labels_only,
        )
        if result.action == "user_confirmation" and result.chase_recipients:
            # Step 4 of the user-chase plan: the advisory phases still SAY what would
            # happen, unlike every other suppressed action, which is silent. This is the
            # thing to read for a week before EDR_USER_CHASE is ever flipped on.
            await add_comment(jira_key, _chase_dry_run_comment(result), cfg, dry_run=dry_run)
        action_taken = "labels_only"
    elif _may_change_state:
        if result.action == "resolved" and result.auto_close:
            # Two independent gates, both must pass. The phase gate above is one; this is
            # the per-FAMILY gate, so flipping the phase and closing the first real
            # ticket stay two deliberate acts. Default allowlist is empty.
            _may, _why = cfg.may_autoclose(alert_name, result.confidence)
            if _may:
                # The brake: a family whose recent autonomous closes humans reopened stops
                # closing until re-armed. First, so a braked family never runs the rest.
                from edr_triage import autonomy_brake
                _blocked, _block_why = await autonomy_brake.enforce_at_close(
                    alert_name, result.labels, jira_key, cfg, dry_run=dry_run)
                if _blocked:
                    _may, _why = False, _block_why
            if _may:
                from edr_triage import signin_guard
                _blocked, _block_why, _spray_check = await signin_guard.enforce_at_close(
                    alert_name, result.labels, _spray_check, _spray_users, _spray_anchor,
                    jira_key, cfg, dry_run=dry_run)
                if _blocked:
                    _may, _why = False, _block_why
            if _may and ((sentinel_entities or {}).get("cloudtrail") or {}).get("actor_ambiguous"):
                # Several people had SSM sessions on this host in the window, so nobody
                # can say who ran the command — never closed by RAPTOR, whatever produced
                # the verdict (agent, allowlist on one of the principals, ...). DEMO-112299.
                _ct_amb = (sentinel_entities or {}).get("cloudtrail") or {}
                _may, _why = False, ("actor ambiguous — SSM sessions by "
                                     + ", ".join(_ct_amb.get("session_principals") or
                                                 _ct_amb.get("candidate_devices") or ["several principals"]))
                for _lab in ("needs-l2-review", "actor-ambiguous"):
                    if _lab not in result.labels:
                        result.labels.append(_lab)
            if _may:
                # Netskope bulk upload/download: closes ONLY via an L2-approved pattern
                # pinned to the company account — never on a model verdict.
                from edr_triage import uba_guard
                _blocked, _block_why = await uba_guard.enforce_at_close(
                    alert_name, result.labels, jira_key, _allow,
                    (sentinel_entities or {}).get("netskope_uba"), cfg, dry_run=dry_run,
                    reference_time=_spray_anchor)
                if _blocked:
                    _may, _why = False, _block_why
            if _may:
                # PowerShell-in-memory closes ONLY an exact repeat of a human-cleared run.
                # Fed from the same NormalizedAlert fields the endpoint_process comment is
                # rendered from, because that comment is where the precedent history lives.
                from edr_triage import powershell_guard
                _blocked, _block_why = await powershell_guard.enforce_at_close(
                    alert_name, result.labels, jira_key,
                    normalized.device if normalized else device_name,
                    normalized.user if normalized else current_user,
                    list((normalized.command_lines if normalized else None) or []),
                    cfg, dry_run=dry_run)
                if _blocked:
                    _may, _why = False, _block_why
            if _may:
                # A USB-copy alert closes ONLY when Sentinel proved no removable drive was
                # involved (an internal SATA drive's letterless mount fired the rule).
                from edr_triage import usb_guard as _usbg_close
                _blocked, _block_why = await _usbg_close.enforce_at_close(
                    alert_name, result.labels, jira_key, _usb_drive_check, cfg, dry_run=dry_run)
                if _blocked:
                    _may, _why = False, _block_why
            if _may:
                # Root Privesc closes ONLY an exact repeat of a human-cleared session; the
                # ASK step below decides what happens to everything else.
                from edr_triage import privesc_guard
                _blocked, _block_why = await privesc_guard.enforce_at_close(
                    alert_name, result.labels, jira_key,
                    *_privesc_live(device_name, current_user, evidence, sentinel_entities),
                    cfg, dry_run=dry_run,
                    session=_privesc_session(sentinel_entities, alert_data, ticket, incident_url))
                if _blocked:
                    _may, _why = False, _block_why
            if _may and getattr(result, "triage_class", "") == "AUTO_CLOSED_FP":
                # Last step before the walk: a Claude security-engineer review of the whole
                # case, veto only, fails closed. Off unless CLOSE_REVIEW_ENABLED=true.
                from agent_core import close_review
                _blocked, _block_why = await close_review.enforce_at_close(
                    jira_key=jira_key, alert_name=alert_name,
                    severity=(alert_data or {}).get("severity", "") or ticket.get("severity", ""),
                    device=device_name, user=current_user,
                    alert_time=(alert_data or {}).get("alertCreationTime", "") or ticket.get("created_at", ""),
                    close_route=_why, evidence=_agent_evidence, agent_result=_agent_result,
                    labels=result.labels, cfg=cfg, dry_run=dry_run)
                if _blocked:
                    _may, _why = False, _block_why
            if not _may:
                logger.info("[AUTOCLOSE-GATE] %s (%s): NOT closing — %s",
                            jira_key, alert_name, _why)
                _close_refusal = _why
                action_taken = "labels_only"
            else:
                # walk_to_status, not transition_ticket: an FP close is a 3-hop walk
                # (Open → Assigned → Event Analysis → False Positive) and the old call
                # asked for a transition named "Resolve", which does not exist on this
                # workflow — so every auto-close before this silently no-opped.
                logger.info("[AUTOCLOSE] %s (%s): closing — %s", jira_key, alert_name, _why)
                if await walk_to_status(jira_key, cfg.close_route(), cfg,
                                        forbidden=cfg.close_forbidden()):
                    action_taken = "auto_closed"
                    # One label on EVERY close RAPTOR performs, whatever produced it. The
                    # autoclose report used to query only `ai-fp`, which only the agent
                    # path adds — so an allowlist or DLP-Secret-key close would never have
                    # reached the report that is L2's visibility of every close.
                    if "raptor-autoclosed" not in result.labels:
                        result.labels.append("raptor-autoclosed")
                    if not dry_run:
                        # Resolve any open page for this ticket. Safe even when none
                        # was ever triggered here — this triage_class (AUTO_CLOSED_FP)
                        # never pages on its own (should_page excludes it), so this
                        # only matters for a ticket that paged on an EARLIER cycle
                        # (e.g. NEEDS_L2) and is only now being auto-closed.
                        # Best-effort: see the note on the trigger call above. Raising
                        # here skipped the label write for every autonomous close.
                        try:
                            from lib.pagerduty_client import resolve_event
                            await resolve_event(jira_key)
                        except Exception as exc:
                            logger.error("PagerDuty resolve for %s failed (close stands): %s",
                                         jira_key, exc)
                else:
                    # Left wherever the walk stalled. Loud, because a half-walked ticket
                    # is worse than an untouched one: it is neither closed nor in the
                    # queue position an analyst expects.
                    logger.error("[AUTOCLOSE] %s: close route FAILED — ticket not closed",
                                 jira_key)
                    action_taken = "close_failed"
        elif result.action == "event_analysis":
            # RETIRED as a state change (2026-09-30), regardless of EDR_USER_CHASE. This is
            # the legacy chase path: it transitions into `Awaiting more inputs` (the Acme
            # Security Bot's trigger) by transition NAME, sets a Category value that is not
            # a valid option, and has no reachability gate, no Involved Users writer and no
            # idempotency claim. It used to be held back only by EDR_USER_CHASE, so turning
            # the real chase on (for Netskope bulk upload/download, via user_confirmation)
            # would have silently armed this for any autonomous family whose playbook
            # emits it (netskope Failed Login, malware not-quarantined). The chase now has
            # exactly one path — user_confirmation — and this stays labels-only.
            logger.info("[CHASE-GATE] %s: event_analysis is retired as a state change — "
                        "chases go through user_confirmation only", jira_key)
            action_taken = "labels_only"
        elif result.action == "user_confirmation":
            # The deterministic user chase: every reachable, alert-bound user on a Netskope
            # bulk upload/download ticket — see playbooks/netskope.py. Gated separately from
            # `event_analysis` above even though both end in `Awaiting more inputs`:
            # this path has already resolved a real recipient via identity.py, so the
            # gate here is "may we send it", not "the machinery doesn't exist yet".
            if not cfg.user_chase_enabled:
                logger.info(
                    "[CHASE-GATE] %s: not chasing — EDR_USER_CHASE is off", jira_key)
                await add_comment(jira_key, _chase_dry_run_comment(result), cfg, dry_run=dry_run)
                action_taken = "labels_only"
            else:
                action_taken = await _execute_user_chase(jira_key, cfg, result, dry_run)
        elif result.action == "route_to_l2":
            action_taken = await _execute_l2_route(jira_key, cfg, result, dry_run)

    # Root Privesc: the agent asked for a justification, but this is an exact repeat of a
    # session a person already cleared, from the person's usual network, role and client.
    # Close it rather than ask the same person about the same routine command again —
    # being asked daily about routine work teaches people to click Acknowledge unread
    # (DEMO-116869: nico asked twice in two days about `su - netra`).
    if (action_taken == "labels_only" and _may_change_state
            and result.triage_class == "REQUEST_JUSTIFICATION"):
        action_taken = await _privesc_repeat_close_on_ask(
            jira_key, alert_name, cfg, result, dry_run, test_labels_only, device_name,
            current_user, evidence, sentinel_entities, alert_data, ticket, incident_url,
            is_test) or action_taken

    # Root Privesc whose ONLY obstacle is another open alert on the same user/host: hold it
    # behind that ticket (Event Analysis, its owner's queue) instead of a second L2 ticket
    # for the same incident. See concurrency_hold.py.
    if (action_taken in _RESIDUAL_ACTIONS and _may_change_state
            and getattr(cfg, "concurrency_hold_enabled", True)):
        action_taken = await _maybe_hold_behind_sibling(
            jira_key, alert_name, cfg, result, dry_run, device_name, current_user, evidence,
            sentinel_entities, alert_data, ticket, incident_url, is_test,
            _agent_result) or action_taken

    # ASK instead of closing — Root Privesc, PowerShell-in-memory and USB copies. When the agent leaned
    # benign (or wanted a justification) but the ticket was not closed — not an exact repeat
    # of a human-cleared run, or any other close-gate refusal — put it to the one person who
    # ran it through the user chase. Their answer routes to L2, never to a close; an L2 FP
    # close on it is the precedent the next exact repeat closes on. See privesc_guard.py and
    # powershell_guard.py.
    from edr_triage import powershell_guard as _psg_ask
    from edr_triage import privesc_guard as _pvg_ask
    from edr_triage import usb_guard as _usb_ask
    _ask_guard, _ask_user, _ask_ambiguous, _ask_reason = None, "", False, ""
    if _pvg_ask.applies(alert_name):
        _ct_now = (sentinel_entities or {}).get("cloudtrail") or {}
        _ask_guard, _ask_user = _pvg_ask, current_user
        _ask_ambiguous = bool(_ct_now.get("actor_ambiguous"))
        _ask_reason = "Root Privilege Escalation — not an exact repeat of a cleared session"
    elif _psg_ask.applies(alert_name):
        _ask_guard = _psg_ask
        _ask_user = (normalized.user if normalized else current_user) or ""
        _ask_reason = "PowerShell in memory — not an exact repeat of a cleared command"
    elif _usb_ask.applies(alert_name):
        _ask_guard = _usb_ask
        _ask_user = (normalized.user if normalized else current_user) or ""
        _ask_reason = "Files copied to a USB drive — only the copier's reason clears it"
    if (_ask_guard and _may_change_state and action_taken != "auto_closed"
            and cfg.user_chase_enabled):
        _ok_ask, _no_ask = _pvg_ask.may_ask(
            result.triage_class, _ask_ambiguous, is_test,
            alert_data.get("severity", ticket.get("severity", "")))
        _who = ""
        if _ok_ask:
            try:
                from edr_triage.identity import eligible_recipients
                _elig_a, _rej_a = await eligible_recipients([_ask_user] if _ask_user else [])
            except Exception as _exc:
                _elig_a, _rej_a = [], [f"lookup failed ({str(_exc)[:80]})"]
            if len(_elig_a) == 1 and not _rej_a:
                _who = f"{_elig_a[0]['display_name']} ({_elig_a[0]['email']})"
                result.chase_recipients = _elig_a
                result.chase_reason = _ask_reason
                await add_comment(jira_key, _ask_guard.ask_comment(
                    _who, _close_refusal or "the agent asked for a business justification"),
                    cfg, dry_run=dry_run)
                if _ask_guard.ASK_LABEL not in result.labels:
                    result.labels.append(_ask_guard.ASK_LABEL)
                action_taken = await _execute_user_chase(jira_key, cfg, result, dry_run)
            else:
                _no_ask = "; ".join(_rej_a) or "no single reachable person ran it"
        if not _who:
            logger.info("[ASK] %s (%s): not asking — %s", jira_key, alert_name, _no_ask)
            if "needs-l2-review" not in result.labels:
                result.labels.append("needs-l2-review")

    # Families L1 only ever forwards: straight to L2, as an L1 would move it. Only when RAPTOR
    # did nothing else with the ticket, and under the same gate as the deterministic closes
    # (autonomous phase, EDR_L2_DIRECT, report interlock, still Open/Assigned, nobody owns it).
    if _l2_direct_family(alert_name) and action_taken == "labels_only":
        _l2_why = await _deterministic_close_refusal(alert_name, jira_key, cfg, dry_run,
                                                     test_labels_only, cfg.l2_direct_enabled,
                                                     "EDR_L2_DIRECT")
        if _l2_why:
            logger.info("[L2-DIRECT] %s (%s): left for L1 — %s", jira_key, alert_name, _l2_why)
        else:
            if "needs-l2-review" not in result.labels:
                result.labels.append("needs-l2-review")
            action_taken = await _execute_l2_route(
                jira_key, cfg, result, dry_run,
                why=("RAPTOR did not close it, and analysts raise every such ticket to L2"
                     if _effective_agent_phase(alert_name) == "autonomous" else
                     "analysts have always raised this alert to L2, so there is no L1 step"))

    # Residual: RAPTOR closed nothing, asked nobody and routed nothing, so the ticket waits
    # for an analyst. "record" only notes it (store + log) to measure that volume — nothing
    # is written to the ticket. "route" sends it to L2 under the direct-to-L2 gate.
    if action_taken in _RESIDUAL_ACTIONS and not dry_run and not test_labels_only:
        action_taken = await _handle_residual(jira_key, alert_name, cfg, result, action_taken,
                                              dry_run, test_labels_only)

    # Apply labels
    if result.labels:
        await add_labels(jira_key, result.labels, cfg, dry_run=dry_run)

    # Persist
    triaged = TriagedAlert(
        jira_key=jira_key,
        alert_id=alert_id,
        alert_name=alert_name,
        device_name=device_name or sentinel_entities.get("cloudtrail", {}).get("device_name", ""),
        machine_id=machine_id,
        user_name=(
            (alert_data.get("relatedUser") or {}).get("userName", "")
            or (alert_data.get("loggedOnUsers") or [{}])[0].get("accountName", "")
            or ticket.get("user_name", "")
            or (sentinel_entities.get("accounts") or [""])[0]
        ),
        additional_users=[
            a for a in (sentinel_entities.get("accounts") or []) if a and a != current_user
        ],
        severity=alert_data.get("severity", ticket.get("severity", "")),
        tactics=alert_data.get("mitreTechniques", []) or [],
        file_name=evidence.get("file_name", ""),
        file_path=evidence.get("file_path", ""),
        sha256=sha256,
        initiating_process=evidence.get("initiating_process", ""),
        investigation_state=inv_state,
        alert_time=(alert_data.get("alertCreationTime") or ticket.get("created_at", ""))[:19],
        vt_detections=vt.get("detections"),
        vt_total=vt.get("total"),
        vt_verdict=vt.get("verdict", ""),
        playbook=playbook_name,
        triage_class=result.triage_class,
        l1_comment=result.l1_comment,
        l1_comment_deterministic=_l1_comment_deterministic,
        l2_comment=result.l2_comment,
        llm_reasoning=result.llm_reasoning,
        action_taken=action_taken,
        labels_applied=result.labels,
        is_test_device=is_test,
        processed_at=time.time(),
        jira_created_at=ticket.get("created_at", ""),
    )
    save_triaged_alert(triaged)

    logger.info(
        "Triaged %s: playbook=%s class=%s action=%s dry_run=%s",
        jira_key, playbook_name, result.triage_class, action_taken, dry_run,
    )
    return triaged


def _get_playbook(name: str):
    from edr_triage.playbooks.block_tool        import BlockToolPlaybook
    from edr_triage.playbooks.malware           import MalwarePlaybook
    from edr_triage.playbooks.reverse_shell     import ReverseShellPlaybook
    from edr_triage.playbooks.lateral_move      import LateralMovePlaybook
    from edr_triage.playbooks.credential_access import CredentialAccessPlaybook
    from edr_triage.playbooks.netskope          import NetskopePlaybook
    from edr_triage.playbooks.endpoint_process  import EndpointProcessPlaybook
    from edr_triage.playbooks.port_sweep         import PortSweepPlaybook
    from edr_triage.playbooks.generic           import GenericPlaybook
    from edr_triage.playbooks.fallback          import FallbackPlaybook
    from edr_triage.playbooks.guardduty         import GuardDutyPlaybook
    from edr_triage.playbooks.pim               import PimPlaybook
    from edr_triage.playbooks.upwind            import UpwindPlaybook

    return {
        "block_tool":         BlockToolPlaybook(),
        "malware":            MalwarePlaybook(),
        "reverse_shell":      ReverseShellPlaybook(),
        "lateral_move":       LateralMovePlaybook(),
        "credential_access":  CredentialAccessPlaybook(),
        "netskope":           NetskopePlaybook(),
        "guardduty":          GuardDutyPlaybook(),
        "pim":                PimPlaybook(),
        "upwind":             UpwindPlaybook(),
        "endpoint_process":   EndpointProcessPlaybook(),
        "port_sweep":         PortSweepPlaybook(),
        "privesc":            GenericPlaybook("privesc"),
        "no_threat":          GenericPlaybook("no_threat"),
        "generic":            GenericPlaybook("generic"),
        # Never silently drop a ticket — an alert name matching none of the
        # classifiers above (classify() returning "skip") still gets a
        # deterministic comment and an L2 escalation. See fallback.py.
        "skip":               FallbackPlaybook(),
    }.get(name, GenericPlaybook("generic"))


_GD_EC2_KEYS = ("finding_type", "finding_severity", "instance_id", "instance_name",
                "instance_tribe", "private_ip", "source_ip", "ip_geo",
                "event_first_seen", "event_last_seen")


def _guardduty_ec2_for_agent(sentinel_entities: dict | None) -> dict | None:
    """The GuardDuty EC2 finding the generic path bound (query_guardduty_details), for the
    agent. The L1 comment already renders it; the agent never saw it (DEMO-118243's agent
    said it lacked the private IP the comment above it printed). EC2 findings only: the
    IAM-credential shape feeds autonomous families whose evidence must not change here."""
    ct = (sentinel_entities or {}).get("cloudtrail") or {}
    if ":EC2/" not in str(ct.get("finding_type") or ""):
        return None
    return {k: ct[k] for k in _GD_EC2_KEYS if ct.get(k)}


def dlp_live_apps(dlp: dict | None) -> list[str]:
    """Apps on a Netskope DLP alert's own rows, for app-pinned allowlist matching.

    Empty (so an app-pinned entry cannot match) unless the bind is the alert's own rows
    and every row was kept and names its app: a window sweep can carry other users'
    rows, and an app on an unseen or blank row must not be assumed.
    """
    dlp = dlp or {}
    events = dlp.get("events") or []
    if dlp.get("bind_source") != "alert" or not events:
        return []
    if len(events) < (dlp.get("event_count") or 0):
        return []
    apps = [str(e.get("app") or "").strip().lower() for e in events]
    if not all(apps):
        return []
    return sorted(set(apps))


def _build_allowlist_result(allow: dict, alert_name: str, device: str, user: str):
    """Build an AUTO_CLOSED_FP result from a matched golden actor-allowlist entry.

    Deterministic path — no LLM ran. The comment is transparent about WHY it closed
    (which armed golden precedent matched, on which actor/device) so an analyst can
    audit or revert it.
    """
    from edr_triage.playbooks.base import PlaybookResult
    actor = allow.get("actor") or user or "the actor"
    src_key = allow.get("jira_key") or ""
    approver = allow.get("resolved_by") or "L2"
    scope_bits = [f"actor `{actor}`"]
    if allow.get("device"):
        scope_bits.append(f"device `{allow['device']}`")
    if allow.get("commands"):
        scope_bits.append("commands `" + "`, `".join(allow["commands"]) + "`")
    scope_desc = " + ".join(scope_bits)
    # Prefer the L2 resolution comment (the authoritative verdict), then the L1 handoff,
    # then the content preview — so a handoff-then-L2-resolved precedent surfaces the L2
    # reasoning instead of only the L1 escalation note.
    precedent = (allow.get("l2_comment") or allow.get("l1_comment") or allow.get("content") or "").strip()
    if len(precedent) > 500:
        precedent = precedent[:500].rstrip() + " …"

    l1 = [
        f"*Auto-closed as False Positive — matched trusted actor-allowlist ({scope_desc}).*",
        "",
        f"This alert (*{alert_name}*) on `{device or 'Unknown'}` by `{user or 'Unknown'}` matches an "
        f"L2-approved golden precedent for this actor and alert type. RAPTOR closed it deterministically "
        f"(no model call) per that standing decision.",
    ]
    if src_key:
        l1.append(f"Precedent: *{src_key}* (approved by {approver}, confidence {allow.get('confidence','?')}).")
    if precedent:
        l1.append("")
        l1.append(f"> {precedent}")
    l1.append("")
    l1.append("[Auto-triaged by RAPTOR]")

    return PlaybookResult(
        l1_comment="\n".join(l1),
        triage_class="AUTO_CLOSED_FP",
        action="resolved",
        auto_close=True,
        # allowlist-mem-<id> names the entry that caused the close, so a reopen can
        # disarm exactly that entry (autoclose_report -> demote_on_overturn).
        labels=["raptor-actor-allowlist"] + ([f"allowlist-mem-{allow['id']}"] if allow.get("id") else []),
        llm_reasoning=(
            f"Deterministic actor-allowlist match — {scope_desc}, alert type "
            f"'{allow.get('alert_type') or 'any'}', golden precedent {src_key or '(unlinked)'}. "
            "No LLM invoked."
        ),
    )


def _privesc_live(device_name: str, current_user: str, evidence: dict | None,
                  sentinel_entities: dict | None) -> tuple[str, str, list[str]]:
    """(device, session principal, commands) for privesc_guard — the same values the Root
    Privesc comment renders, so the live ticket is compared like for like with history."""
    from edr_triage.playbooks.generic import privesc_commands
    ct = (sentinel_entities or {}).get("cloudtrail") or {}
    dev = device_name if device_name and device_name != "Unknown Device" else ct.get("device_name", "")
    return dev, current_user or "", privesc_commands(evidence, ct)


def _privesc_session(sentinel_entities: dict | None, alert_data: dict | None, ticket: dict,
                     incident_url: str) -> dict:
    """What privesc_guard.session_check needs: the session ARN, when the alert fired, and
    the workspace to query."""
    ct = (sentinel_entities or {}).get("cloudtrail") or {}
    return {"arn": ct.get("user_arn", ""),
            "anchor": (ct.get("time_generated") or (alert_data or {}).get("alertCreationTime")
                       or ticket.get("created_at", "")),
            "incident_url": incident_url or "",
            "ambiguity_cleared": ct.get("ambiguity_cleared", "")}


async def _maybe_hold_behind_sibling(jira_key, alert_name, cfg, result, dry_run, device_name,
                                     current_user, evidence, sentinel_entities, alert_data,
                                     ticket, incident_url, is_test, agent_result) -> str:
    """"held" when the ticket was held behind its open sibling(s), else "". Every close
    check except the concurrency gate must pass first — the same ones an auto-close runs."""
    from edr_triage import concurrency_hold as ch
    from edr_triage import privesc_guard
    if not privesc_guard.applies(alert_name):
        return ""

    async def _not_held(why: str) -> str:
        # A re-check of one of OUR holds that now needs a person for another reason goes to
        # L2 at once rather than waiting out the hold window.
        logger.info("[HOLD] %s: not held — %s", jira_key, why)
        if (result.triage_class in ("NEEDS_L2", "URGENT") and not dry_run
                and await ch.is_held(jira_key, cfg)):
            if await ch.release_to_l2(jira_key, f"re-checked while held and it needs a person: {why}", cfg):
                return "routed_to_l2"
        return ""

    ct = (sentinel_entities or {}).get("cloudtrail") or {}
    sev = (alert_data or {}).get("severity", ticket.get("severity", "")) or ""
    ok, why = ch.holdable(agent_result, alert_name, sev, is_test, bool(ct.get("actor_ambiguous")))
    if not ok:
        return await _not_held(why)
    blockers = list(agent_result.blocked_by_concurrent_keys)
    may, why = cfg.may_autoclose(alert_name, agent_result.confidence)
    if may:
        from edr_triage import autonomy_brake
        braked, why = await autonomy_brake.check(alert_name)
        may = not braked
    if may:
        dev, actor, cmds = _privesc_live(device_name, current_user, evidence, sentinel_entities)
        res = await privesc_guard.check(jira_key, dev, actor, cmds, cfg)
        may, why = res["allow"], res["reason"]
        if may and getattr(cfg, "privesc_session_check", True):
            s = _privesc_session(sentinel_entities, alert_data, ticket, incident_url)
            may, why = await privesc_guard.session_check(s["arn"], s["anchor"], s["incident_url"])
            why = "" if may else f"session not familiar: {why}"
    if may:
        may, why = await ch.may_hold_now(jira_key, cfg)
    if not may:
        return await _not_held(f"blocked by {', '.join(blockers)}, and {why}")
    if not await ch.hold(jira_key, blockers, cfg, dry_run=dry_run):
        return ""
    for lab in (ch.HOLD_LABEL,):
        if lab not in result.labels:
            result.labels.append(lab)
    result.labels[:] = [l for l in result.labels if l != "needs-l2-review"]
    return "held"


async def _privesc_repeat_close_on_ask(jira_key, alert_name, cfg, result, dry_run,
                                       test_labels_only, device_name, current_user, evidence,
                                       sentinel_entities, alert_data, ticket, incident_url,
                                       is_test) -> str:
    """"auto_closed" when a Root Privesc the agent wanted justified is an exact repeat of a
    human-cleared session with a familiar session; "" to fall through to the ASK step."""
    from edr_triage import privesc_guard
    from edr_triage.jira_handler import walk_to_status
    if not privesc_guard.applies(alert_name):
        return ""
    ct = (sentinel_entities or {}).get("cloudtrail") or {}
    sev = (alert_data or {}).get("severity", ticket.get("severity", "")) or ""
    why = ("the actor is ambiguous" if ct.get("actor_ambiguous") else
           "known test/red-team device" if is_test else
           "CRITICAL severity" if sev.upper() == "CRITICAL" else "")
    if not why:
        ok, why = cfg.may_autoclose(alert_name, result.confidence)
        why = "" if ok else why
    if not why:
        why = await _deterministic_close_refusal(alert_name, jira_key, cfg, dry_run,
                                                 test_labels_only, cfg.privesc_rj_repeat_close,
                                                 "EDR_PRIVESC_RJ_REPEAT_CLOSE")
    if why:
        logger.info("[PRIVESC-REPEAT] %s: not closing on repeat — %s", jira_key, why)
        return ""
    blocked, bwhy = await privesc_guard.enforce_at_close(
        alert_name, result.labels, jira_key,
        *_privesc_live(device_name, current_user, evidence, sentinel_entities),
        cfg, dry_run=dry_run,
        session=_privesc_session(sentinel_entities, alert_data, ticket, incident_url))
    if blocked:
        logger.info("[PRIVESC-REPEAT] %s: asking instead — %s", jira_key, bwhy)
        return ""
    if not await walk_to_status(jira_key, cfg.close_route(), cfg, forbidden=cfg.close_forbidden()):
        logger.error("[PRIVESC-REPEAT] %s: close route FAILED", jira_key)
        return "close_failed"
    logger.info("[PRIVESC-REPEAT] %s: closed — exact repeat with a familiar session", jira_key)
    for lab in ("raptor-autoclosed", "privesc-repeat"):
        if lab not in result.labels:
            result.labels.append(lab)
    return "auto_closed"


def _build_planned_activity_result(pa: dict, alert_name: str, device: str, user: str):
    """Build an AUTO_CLOSED_FP result from a matched planned-activity window.

    Deterministic path — no LLM ran. The comment names the declared window and its
    expiry so the close is transparent and self-documenting (this was expected, and
    the authorization ends on a specific date).
    """
    from edr_triage.playbooks.base import PlaybookResult
    label = pa.get("label") or "declared maintenance/compliance activity"
    pattern = pa.get("pattern") or ""
    expires = (pa.get("expires_at") or "")[:16].replace("T", " ")
    who = pa.get("created_by") or "an analyst"

    l1 = [
        f"*Auto-closed as False Positive — matches a declared planned-activity window.*",
        "",
        f"This alert (*{alert_name}*) on `{device or 'Unknown'}` by `{user or 'Unknown'}` matches the "
        f"planned-activity window **{label}** (command contains `{pattern}`), declared by {who} and "
        f"authorized until *{expires or 'the window end'}* (UTC). RAPTOR closed it deterministically "
        f"(no model call) as expected, known-benign activity for this window.",
        "",
        "If this alert is NOT part of that activity, reopen it — the window is command-matched and "
        "device/actor-agnostic by design.",
        "",
        "[Auto-triaged by RAPTOR]",
    ]
    return PlaybookResult(
        l1_comment="\n".join(l1),
        triage_class="AUTO_CLOSED_FP",
        action="resolved",
        auto_close=True,
        labels=["raptor-planned-activity"],
        llm_reasoning=(
            f"Deterministic planned-activity match — window '{label}', command substring "
            f"'{pattern}', authorized until {expires or '?'} (UTC), alert type "
            f"'{pa.get('alert_type') or 'any'}'. No LLM invoked."
        ),
    )


# ---------------------------------------------------------------------------
# Agent rollout phase
# ---------------------------------------------------------------------------

#   shadow      agent runs, verdict stored only. Playbook owns Jira entirely.
#   copilot     agent's investigation is POSTED to Jira as an advisory comment
#               + advisory label. NO state change: shadow and copilot are enforced
#               comment-and-label-only by may_change_ticket_state() below. This used
#               to read "playbook still owns every state change, so ticket handling is
#               byte-identical to shadow" — which described an intent nothing enforced,
#               and the playbook duly transitioned a live ticket (DEMO-112105).
#   autonomous  agent's verdict drives comments, transitions and auto-close.
_AGENT_PHASES = {
    "shadow": "shadow",
    "copilot": "copilot",
    "autonomous": "autonomous",
    "live": "autonomous",   # legacy name used by docs/settings UI
}

# The actions that move a ticket. Anything not listed here is comments/labels, which every
# phase may do.
STATE_CHANGING_ACTIONS = ("resolved", "event_analysis", "user_confirmation", "route_to_l2")


# Lines a playbook writes as ITS recommendation, which a rule's decision overrules. Left in,
# the ticket reads "Escalating to L2" and then "RAPTOR closed this as a Duplicate" in the same
# second (DEMO-117045, which an L1 then reopened). Measured on 10 days of rule-decided tickets.
_OVERRULED_LINES = tuple(re.compile(rx, re.I) for rx in (
    r"^\s*\**\s*Escalating to L2\b.*$",
    r"^\s*\**\s*Recommendation:.*$",
    r"^\s*\**\s*⚠?\s*Immediate investigation required\b.*$",
    r"^\s*\**\s*RAPTOR will ask .*Acme Security Bot.*$",
    r"^\s*\**\s*Cannot be asked via Slack\b.*$",
))
# Only wrong when the rule did NOT close it as a false positive (Duplicate, AnyDesk TP).
_FP_CLOSE_LINES = tuple(re.compile(rx, re.I) for rx in (
    r"^\s*\**\s*Closing as a false positive\.?\s*$",
    r"^\s*\**\s*Recommend closing as a false positive\b.*$",
))
_OVERRULED_SENTENCES = (re.compile(r"\s*This may be genuine reconnaissance\.?", re.I),)


def _one_story(l1_comment: str, copilot_comment: str, action: str = "") -> tuple[str, str]:
    """When a rule has decided the ticket, nothing else on it may say otherwise. The playbook
    note keeps its facts but loses its own recommendation, and the agent's view is kept for
    the record, collapsed, as a second opinion that was not acted on (DEMO-116082, DEMO-117045)."""
    l1 = re.sub(r"\s*[—-]\s*routing directly to L2 with the raw alert details below rather "
                r"than holding it unactioned\.?", " — raw alert details below.", l1_comment or "")
    kept, dropped = [], False
    overruled = _OVERRULED_LINES + (() if action == "auto_closed" else _FP_CLOSE_LINES)
    for line in l1.split("\n"):
        if any(rx.match(line) for rx in overruled):
            dropped = True
            continue
        for rx in _OVERRULED_SENTENCES:
            line, n = rx.subn("", line)
            dropped = dropped or bool(n)
        kept.append(line)
    l1 = "\n".join(kept)
    if dropped:
        note = "_A RAPTOR rule decided this ticket — see its comment below._"
        footer = "[Auto-triaged by RAPTOR]"
        l1 = l1.replace(footer, note + "\n\n" + footer, 1) if footer in l1 else l1 + "\n\n" + note
    cop = copilot_comment
    if cop:
        cop = ("*Second opinion only — not acted on.* A RAPTOR rule decided this ticket (see its "
               "comment above); the agent's independent view is kept for the record.\n\n"
               "{expand:Agent's independent view (not acted on)}\n" + cop.strip() + "\n{expand}")
    return l1, cop


def _playbook_state_note(alert_name: str, phase: str) -> str:
    """The copilot comment's ticket-state line for a family whose ticket RAPTOR may still
    change in autonomous phase ("" = the default advisory wording, which says RAPTOR will
    not close — false for these, the DEMO-112105 contradiction again: DEMO-115979 said "will
    not" in the same second the CustomEnterpriseBlock rule closed it)."""
    from edr_triage import custom_block_guard, duplicate_guard, log_ingestion_guard
    if _resolve_agent_phase() == "autonomous" and custom_block_guard.applies(alert_name):
        return ("*Ticket state:* this recommendation does not decide it. RAPTOR may close the "
                "ticket itself under a documented rule (our AnyDesk block rule doing its job); "
                "if it does not, it moves it to L2 Analysis required — analysts raise every "
                "other such ticket to L2 — and says so in its own comment.")
    if _resolve_agent_phase() == "autonomous" and _l2_direct_family(alert_name):
        if phase == "autonomous":
            return ("*Ticket state:* RAPTOR may close this ticket itself under its rules; if it "
                    "does not, it moves it to L2 Analysis required — analysts raise every such "
                    "ticket to L2 — and says so in its own comment.")
        return ("*Ticket state:* this recommendation does not decide it. For this alert RAPTOR "
                "moves the ticket to L2 Analysis required itself — analysts have always raised "
                "it to L2 — and says so in its own comment.")
    if _resolve_agent_phase() == "autonomous" and (
            custom_block_guard.applies(alert_name) or log_ingestion_guard.applies(alert_name)
            or duplicate_guard.applies_cyble(alert_name)
            or duplicate_guard.applies_portsweep(alert_name)):
        return ("*Ticket state:* this recommendation does not decide it. For this alert RAPTOR "
                "may close the ticket itself under a documented rule; when it does, it says so "
                "in its own comment.")
    if phase != "autonomous" or not _playbook_keeps_control(alert_name):
        return ""
    if (alert_name or "").strip() == "Netskope DLP Alerts":
        return ("*Ticket state:* this recommendation does not decide it. RAPTOR closes a DLP "
                "ticket only by the standing DLP-Secret-key rule (files at rest found by a "
                "CASB API scan) or as an exact duplicate. For national-ID findings it asks the "
                "user via the Acme Security Bot, and L2 decides on the answer.")
    return ("*Ticket state:* this recommendation does not decide it. "
            "For this alert RAPTOR asks the named user(s) to explain the "
            "activity, and any close needs L2 approval.")


def _playbook_keeps_control(alert_name: str) -> bool:
    """Families whose PLAYBOOK keeps control of ticket state even in autonomous phase; the
    agent's verdict is still posted, as a recommendation.

      * Netskope Bulk Upload/Download — the playbook's decision IS the workflow: chase every
        named user, then L2 approves any close. An agent verdict would drop the chase.
      * Netskope DLP Alerts — the only state change is the standing DLP-Secret-key rule on
        files at rest (netskope.py), which humans closed 930 of 930 times in 30 days. Every
        other DLP shape stays a recommendation, so the agent must not be able to close one.
    """
    from edr_triage.classifier import NETSKOPE_UBA_RE
    return (bool(NETSKOPE_UBA_RE.search(alert_name or ""))
            or (alert_name or "").strip() == "Netskope DLP Alerts")


async def _post(jira_key, text, cfg, dry_run, defer: list | None) -> None:
    """Post a rule's comment now, or hold it for the caller to post in order."""
    if defer is not None:
        defer.append(text)
        return
    from edr_triage.jira_handler import add_comment
    await add_comment(jira_key, text, cfg, dry_run=dry_run)


RULE_CLOSE_ACTIONS = ("auto_duplicate", "auto_closed_tp", "auto_closed")


async def _maybe_mark_duplicate(jira_key, alert_name, ticket, sentinel_entities, result, cfg,
                                dry_run, test_labels_only, defer: list | None = None) -> str:
    """"auto_duplicate" when this ticket was moved to Duplicate, else "" (carry on as normal).

    Only for an exact repeat (duplicate_guard.find_original), only in the autonomous phase
    with EDR_AUTO_DUPLICATE and the autoclose-report interlock on, only while the family is
    not braked, and only while the ticket is still Open/Assigned
    (_deterministic_close_refusal). Anywhere else the match is posted as a recommendation.
    """
    from edr_triage import duplicate_guard as dg
    from edr_triage.jira_handler import add_comment, walk_to_status
    dlp = (sentinel_entities or {}).get("netskope_dlp")
    cyble = dg.applies_cyble(alert_name)
    sweep = dg.applies_portsweep(alert_name)
    sqlalter = dg.applies_sqlalter(alert_name)
    _rr = (sentinel_entities or {}).get("rule_replay") or {}
    _sql_t = dg.sqlalter_event_time(_rr) if sqlalter else ""
    if sqlalter:
        orig = await dg.find_sqlalter_original(jira_key, ticket.get("created_at", ""), _sql_t, cfg)
    elif sweep:
        orig = await dg.find_portsweep_open(jira_key, ticket.get("created_at", ""), alert_name, cfg)
    elif cyble:
        orig = await dg.find_cyble_twin(jira_key, ticket.get("created_at", ""), alert_name,
                                        ticket.get("description", ""), cfg)
    elif dg.applies(alert_name) and dlp:
        orig = await dg.find_original(jira_key, ticket.get("created_at", ""), dlp, cfg)
        if not orig:
            orig = await dg.find_open_repeat(jira_key, ticket.get("created_at", ""), dlp, cfg)
            if orig:
                orig["open_repeat"] = True
    else:
        return ""
    if not orig:
        return ""
    if sweep:
        _dests = await _portsweep_destinations(ticket)
        _port = dg.PORTSWEEP_RE.match(alert_name).group(1)
    _say = ((lambda closed: dg.sqlalter_comment(orig["key"], orig["status"], _sql_t,
                                                 str(_rr.get("command") or ""), closed))
            if sqlalter else
            (lambda closed: dg.portsweep_comment(orig["key"], orig["status"], _port, _dests, closed))
            if sweep else
            (lambda closed: dg.cyble_comment(orig["key"], closed)) if cyble else
            (lambda closed: dg.open_repeat_comment(orig["key"], orig["status"], dlp, closed))
            if orig.get("open_repeat") else
            (lambda closed: dg.comment(orig["key"], dlp, closed)))
    why = await _deterministic_close_refusal(alert_name, jira_key, cfg, dry_run, test_labels_only,
                                             cfg.auto_duplicate_enabled, "EDR_AUTO_DUPLICATE",
                                             brake_pattern=(dg.CYBLE_BRAKE_PATTERN if cyble else
                                                            dg.PORTSWEEP_BRAKE_PATTERN if sweep else
                                                            dg.SQLALTER_BRAKE_PATTERN if sqlalter else ""))
    if why:
        logger.info("[DUPLICATE] %s: exact repeat of %s — recommending only (%s)",
                    jira_key, orig["key"], why)
        if dg.REC_LABEL not in result.labels:
            result.labels.append(dg.REC_LABEL)
        await _post(jira_key, _say(False), cfg, dry_run, defer)
        return ""
    if not await walk_to_status(jira_key, ["Duplicate"], cfg, forbidden=_CHASE_TRIGGER_STATUSES):
        logger.error("[DUPLICATE] %s: transition to Duplicate FAILED — triaging as normal", jira_key)
        return ""
    logger.info("[DUPLICATE] %s: closed as Duplicate of %s", jira_key, orig["key"])
    result.labels[:] = [l for l in result.labels if l != "user-chase-pending"]  # the duplicate is never chased
    for lab in (dg.LABEL, "raptor-autoclosed"):
        if lab not in result.labels:
            result.labels.append(lab)
    await _post(jira_key, _say(True), cfg, dry_run, defer)
    return "auto_duplicate"


async def _portsweep_destinations(ticket: dict) -> list[str]:
    """The destination IPs the Port Sweep rule recorded on THIS alert (custom details
    AllDstIpAddr). [] when unreadable — the duplicate still links the original."""
    try:
        import json as _json
        from edr_triage.sentinel_client import query_sentinel_alert
        ent = await query_sentinel_alert(ticket.get("incident_url", ""),
                                         ticket.get("sentinel_alert_id", ""))
        raw = ((ent or {}).get("custom_details") or {}).get("AllDstIpAddr") or []
        out: list[str] = []
        for v in raw if isinstance(raw, list) else [raw]:
            vals = _json.loads(v) if isinstance(v, str) and v.strip().startswith("[") else [v]
            out += [str(x) for x in vals if x]
        return list(dict.fromkeys(out))
    except Exception as exc:
        logger.warning("port-sweep destinations unreadable: %s", exc)
        return []


async def _maybe_close_log_ingestion(jira_key, alert_name, result, cfg, dry_run,
                                     test_labels_only, defer: list | None = None) -> str:
    """"auto_closed" when every table the ingestion rule names is one analysts retired —
    see log_ingestion_guard.py — else "". A table not on that list is named for a person."""
    from edr_triage import log_ingestion_guard as lg
    from edr_triage.jira_handler import add_comment, walk_to_status
    if not lg.applies(alert_name):
        return ""
    stale = await lg.stale_tables()
    ok, reason = lg.decide(stale)
    if not ok:
        logger.info("[LOG-INGESTION] %s: left for a person — %s", jira_key, reason)
        if stale:
            await _post(jira_key, lg.comment(False, reason, stale), cfg, dry_run, defer)
        return ""
    why = await _deterministic_close_refusal(alert_name, jira_key, cfg, dry_run, test_labels_only,
                                             cfg.log_ingestion_close_enabled,
                                             "EDR_LOG_INGESTION_CLOSE")
    if why:
        logger.info("[LOG-INGESTION] %s: would close (%s) — not closing: %s", jira_key, reason, why)
        if "raptor-rec-fp" not in result.labels:
            result.labels.append("raptor-rec-fp")
        return ""
    if not await walk_to_status(jira_key, cfg.close_route(), cfg, forbidden=cfg.close_forbidden()):
        logger.error("[LOG-INGESTION] %s: close route FAILED — ticket not closed", jira_key)
        return "close_failed"
    logger.info("[LOG-INGESTION] %s: closed False Positive — %s", jira_key, reason)
    for lab in (lg.LABEL, "raptor-autoclosed"):
        if lab not in result.labels:
            result.labels.append(lab)
    await _post(jira_key, lg.comment(True, reason, stale), cfg, dry_run, defer)
    return "auto_closed"


async def _deterministic_close_refusal(alert_name, jira_key, cfg, dry_run, test_labels_only,
                                       enabled: bool, flag: str, brake_pattern: str = "") -> str:
    """Why a deterministic close may NOT run now ("" = it may). Shared by the duplicate and
    custom-block closes: autonomous phase, its own flag, the report interlock, the brake,
    and a ticket still Open/Assigned — one an analyst already moved on is theirs."""
    from edr_triage.jira_handler import get_status
    if _resolve_agent_phase() != "autonomous" or dry_run or test_labels_only:
        return "advisory run"
    if not enabled:
        return f"{flag} is off"
    if not cfg.autoclose_report_enabled:
        return "EDR_AUTOCLOSE_REPORT is off"
    from edr_triage import autonomy_brake
    _braked, _bwhy = await (autonomy_brake.check(alert_name, pattern=brake_pattern)
                            if brake_pattern else autonomy_brake.check(alert_name))
    if _braked:
        return f"autonomy is braked: {_bwhy}"
    _st = (await get_status(jira_key, cfg) or "").strip().lower()
    if _st not in ("open", "assigned"):
        return f"ticket already in {_st or 'an unknown status'}"
    # An analyst who has picked the ticket up owns it, even while it still says Assigned:
    # DEMO-115961 was assigned to an L1 a minute before RAPTOR marked it Duplicate, and he
    # then reopened it. RAPTOR closes only tickets nobody — or RAPTOR itself — owns.
    from edr_triage.jira_handler import owned_by_a_person
    _owner = await owned_by_a_person(jira_key, cfg)
    if _owner is None:
        return "could not read who owns the ticket"
    if _owner:
        return f"{_owner} has already picked this ticket up"
    return ""


async def _maybe_close_custom_block(jira_key, alert_name, alert_data, evidence_raw, result, cfg,
                                    dry_run, test_labels_only, defer: list | None = None) -> str:
    """"auto_closed_tp" when our AnyDesk custom block rule fired on nothing but blocked or
    shadow-copy AnyDesk files — see custom_block_guard.py — else "". Never on a ticket the
    agent called URGENT."""
    from edr_triage import custom_block_guard as cb
    from edr_triage.jira_handler import add_comment, walk_to_status
    if not cb.applies(alert_name):
        return ""
    ok, reason = cb.decide(alert_data, evidence_raw)
    if not ok:
        logger.info("[CUSTOM-BLOCK] %s: left for a person — %s", jira_key, reason)
        return ""
    why = ("the agent called it URGENT" if result.triage_class == "URGENT" else
           await _deterministic_close_refusal(alert_name, jira_key, cfg, dry_run, test_labels_only,
                                              cfg.custom_block_close_enabled,
                                              "EDR_CUSTOM_BLOCK_CLOSE"))
    if why:
        logger.info("[CUSTOM-BLOCK] %s: would close (%s) — not closing: %s", jira_key, reason, why)
        if "raptor-rec-custom-block" not in result.labels:
            result.labels.append("raptor-rec-custom-block")
        return ""
    if not await walk_to_status(jira_key, cb.CLOSE_ROUTE, cfg, forbidden=_CHASE_TRIGGER_STATUSES):
        logger.error("[CUSTOM-BLOCK] %s: close route FAILED — ticket not closed", jira_key)
        return "close_failed"
    logger.info("[CUSTOM-BLOCK] %s: closed as true positive — %s", jira_key, reason)
    for lab in (cb.LABEL, "raptor-autoclosed") + ((cb.ON_DISK_LABEL,) if cb.on_disk(evidence_raw) else ()):
        if lab not in result.labels:
            result.labels.append(lab)
    await _post(jira_key, cb.comment(alert_data, evidence_raw), cfg, dry_run, defer)
    return "auto_closed_tp"


def _chase_dry_run_comment(result) -> str:
    """The advisory comment posted in shadow/copilot (or EDR_USER_CHASE=false) instead
    of actually chasing. Deliberately not a state change, consistent with the copilot
    contract of comments-and-labels-only — this is what to read for a week before the
    flag is ever flipped on."""
    r = (result.chase_recipients or [{}])[0]
    return (
        "*RAPTOR — would request user confirmation*\n"
        f"Trigger: {result.chase_reason or 'deterministic user-chase rule'}\n"
        f"Would set Involved Users: {r.get('email', '?')} ({r.get('display_name', '?')})\n"
        "Would then: Category = \"No Repsonse\" \u2192 Event Analysis \u2192 Awaiting more inputs\n"
        "Ticket state: unchanged. No Slack DM sent.\n\n"
        "[RAPTOR \u2014 automated user-chase, dry-run]"
    )


_CHASE_FROM_STATUSES = ("open", "assigned", "event analysis")


async def _execute_user_chase(jira_key: str, cfg, result, dry_run: bool) -> str:
    """Run the 4-step L1 sequence that fires the Acme Security Bot, for a ticket whose
    playbook has already resolved its eligible+reachable recipients (all of them).

    Order matches the L1 by hand: write Involved Users, set Category, Event Analysis,
    then Awaiting more inputs — the last hop is the bot's actual trigger. Any step
    failing aborts the rest and escalates to L2 rather than leaving the ticket half-walked
    (a chase that silently stalls mid-sequence is worse than one that never started —
    nobody would know to look for it).
    """
    from edr_triage.store import (ChaseClaimUnavailable, claim_user_chase,
                                  record_user_chase)
    from edr_triage.jira_handler import (add_comment, add_labels, get_involved_users_cell,
                                         set_involved_users, set_category,
                                         transition_to_status, get_status,
                                         assign_to_self_if_unassigned)

    recipients = result.chase_recipients or []
    if not recipients:
        logger.error("[CHASE] %s: action=user_confirmation with no chase_recipients — "
                     "not chasing", jira_key)
        return "labels_only"

    # Chase only a ticket nobody has moved on yet. The Event Analysis hop is offered from
    # almost every status, so without this a late run walks a ticket back: DEMO-116167
    # (2026-10-08) was retried after a pod restart, by which time an L1 had escalated it
    # to L2 Analysis required — the chase pulled it out of L2 and DMed the user again.
    # From Awaiting more inputs it would re-fire the bot on an L1's own chase. Checked
    # before the claim, so nothing is recorded and no ticket field is touched.
    status = ((await get_status(jira_key, cfg)) or "").strip()
    if status.lower() not in _CHASE_FROM_STATUSES:
        logger.info("[CHASE] %s: ticket is in %r — a person has already moved it on; "
                    "not chasing", jira_key, status or "unknown")
        result.labels[:] = [l for l in result.labels if l != "user-chase-pending"]
        return "labels_only"

    try:
        if not claim_user_chase(jira_key):
            logger.info("[CHASE] %s: already claimed by a prior run — not re-chasing", jira_key)
            return "labels_only"
    except ChaseClaimUnavailable as exc:
        # Stop, but say so loudly and differently. Chasing without a durable claim risks
        # the duplicate DM the claim exists to prevent, so failing closed is right — but
        # an unreachable claim store is an OUTAGE, not a ticket that was already handled,
        # and logging it as the latter is how it hides. No Jira comment: if the store is
        # down this fires on every ticket, and that noise would be worse than the silence.
        logger.error("[CHASE] %s: claim store unavailable (%s) — NOT chasing. This is an "
                     "infrastructure failure, not an already-chased ticket.", jira_key, exc)
        return "labels_only"

    async def _abort(reason: str) -> str:
        logger.error("[CHASE] %s: aborting — %s", jira_key, reason)
        await add_comment(
            jira_key,
            f"*RAPTOR \u2014 user chase aborted:* {reason}\n"
            "Escalating to L2 rather than leaving the ticket in an unclear state.\n\n"
            "[RAPTOR \u2014 automated user-chase]",
            cfg, dry_run=dry_run,
        )
        if "needs-l2-review" not in result.labels:
            result.labels.append("needs-l2-review")
        result.labels[:] = [l for l in result.labels if l != "user-chase-pending"]  # nobody was asked
        return "labels_only"

    existing_cell = await get_involved_users_cell(jira_key, cfg)
    if existing_cell is None:
        return await _abort("description has no 'Involved Users' row to write into")
    if existing_cell.strip():
        return await _abort(
            f"'Involved Users' already reads {existing_cell!r} — not overwriting "
            "something an analyst or the SOAR may have set deliberately")

    # A fresh ticket is Open, and from Open the workflow offers only Assigned or Duplicate
    # — never Event Analysis — and Open -> Assigned rejects an unassigned issue. So every
    # chase on an unassigned ticket aborted at "transition to 'Event Analysis' failed"
    # (DEMO-115957, 2026-10-06); the Bulk Download chases only ever worked because an L1
    # had assigned the ticket first. Done BEFORE any write, so a failure leaves nothing
    # half-set. An analyst's assignment is kept, never taken over.
    if status.lower() == "open":
        if not dry_run and not await assign_to_self_if_unassigned(jira_key, cfg):
            return await _abort("could not take ownership of the Open ticket")
        if not await transition_to_status(jira_key, "Assigned", cfg, dry_run=dry_run):
            return await _abort("transition from Open to 'Assigned' failed")

    if not await set_involved_users(jira_key, recipients, cfg, dry_run=dry_run):
        return await _abort("writing the 'Involved Users' cell failed")
    if not await set_category(jira_key, cfg.category_no_response, cfg, dry_run=dry_run):
        return await _abort(f"setting Category to {cfg.category_no_response!r} failed")
    if not await transition_to_status(jira_key, cfg.event_analysis_transition, cfg,
                                      dry_run=dry_run):
        return await _abort(f"transition to {cfg.event_analysis_transition!r} failed")
    if not await transition_to_status(jira_key, cfg.awaiting_input_transition, cfg,
                                      dry_run=dry_run):
        return await _abort(f"transition to {cfg.awaiting_input_transition!r} failed "
                            "(Involved Users and Category are already set)")

    record_user_chase(
        jira_key,
        recipients=[r.get("email", "") for r in recipients],
        trigger_reason=result.chase_reason,
        dry_run=dry_run,
    )
    logger.info("[CHASE] %s: dispatched to %s", jira_key,
               ", ".join(r.get("email", "") for r in recipients))
    # The mark chase_reply_poller scopes itself to. Added ONLY here, after all four steps
    # landed: `user-chase-pending` is on the playbook result and is written even when an
    # advisory phase suppressed the chase, so it cannot tell "asked" from "would have".
    if "raptor-chased" not in result.labels:
        result.labels.append("raptor-chased")
    return "user_chase_dispatched"



# Families an L1 only ever forwards to L2 — measured 2026-09-15..10-08 over the tickets
# RAPTOR marked needs-l2-review: EC2 drive-by 47/47 raised to L2, Local Admin Group Changes
# 33/33, Suspicious decoding 34/38, USB copy 23/26. Added 2026-10-12, measured 2026-09-12..
# 10-12: Netskope Malware 19/19, Netskope Failed Login 13/15, CloudTrail log changes 11/11,
# Authentication Methods Changed for a privileged account 8/8, anomalous JAMF sign-in 4/4 —
# and, for the two agent-closed families, the tickets RAPTOR did NOT close: AWS credential
# abuse 18/18, privileged sign-in failure spikes 5/5 (their closes are untouched). Routing
# changes no verdict: it is the move an L1 makes by hand, minus the wait. Added 2026-10-16:
# Tampering with the MDE sensor, 88/88 raised to L2 over 60 days (63 FP, 25 Closed). USB copy
# is asked first (usb_guard.py) and lands here only when nobody can be asked. Added 2026-10-17:
# CustomEnterpriseBlock — every one of the 98 tickets in 60 days that the AnyDesk rule
# (custom_block_guard.py) did not close went to L2; the rule's closes run first, untouched.
_INVOLVING = r"(?: involving (?:one user|multiple users))?"
_L2_DIRECT = re.compile(
    r"^(?:The EC2 instance i-[0-9a-f]+ queried a drive-by source domain name\.?"
    r"|Local Admin Group Changes|Files Copied to USB Drives"
    r"|Suspicious decoding of encoded content into script"
    r"|Tampering with the Microsoft Defender for Endpoint sensor"
    r"|(?:An active )?'CustomEnterpriseBlock' malware was (?:detected|prevented|blocked)"
    r"|Netskope ?- ?Malware alert" + _INVOLVING +
    r"|Netskope - Failed Login" + _INVOLVING +
    r"|Changes made to AWS CloudTrail logs" + _INVOLVING +
    r"|Authentication Methods Changed for Privileged Account" + _INVOLVING +
    r"|Anomalous sign-in location by \S+ to JAMF Connect" + _INVOLVING +
    r"|Monitor AWS Credential abuse or hijacking" + _INVOLVING +
    r"|Privileged Accounts - Sign in Failure Spikes" + _INVOLVING + r")\s*$", re.I)


def _is_service_list_alert(alert_name: str) -> bool:
    """The hunting rule whose whole payload is a list of service executables."""
    return "rare process as a service" in (alert_name or "").lower()


def _l2_direct_family(alert_name: str) -> bool:
    return bool(_L2_DIRECT.match((alert_name or "").strip()))


_RESIDUAL_ACTIONS = ("labels_only", "close_failed")


def _residual_report_only(alert_name: str) -> bool:
    """Families whose leftovers are reported, never routed (user, 2026-10-28): Cyble digests
    and Netskope DLP — in the 14 days to 2026-10-27, L1 closed 94% and 96% of what RAPTOR
    left there, and L2 never handled them. Every other family's leftovers were what L1
    escalated, so those go to L2."""
    from edr_triage.duplicate_guard import applies_cyble
    return applies_cyble(alert_name) or (alert_name or "").strip().casefold() == "netskope dlp alerts"


async def _handle_residual(jira_key: str, alert_name: str, cfg, result, action_taken: str,
                           dry_run: bool, test_labels_only: bool) -> str:
    """Note (or, in route mode, route) a ticket RAPTOR is leaving for an analyst. Never
    raises and never writes to the ticket in record mode."""
    mode = (getattr(cfg, "residual_mode", "off") or "off").lower()
    if mode not in ("record", "route"):
        return action_taken
    try:
        from edr_triage import store
        from edr_triage.classifier import display_alert_family
        store.record_residual({
            "jira_key": jira_key, "alert_name": alert_name,
            "family": display_alert_family(alert_name),
            "triage_class": getattr(result, "triage_class", "") or "",
            "labels": [l for l in (getattr(result, "labels", None) or [])
                       if l.startswith(("raptor-", "needs-", "privesc-", "ai-"))],
            "action": action_taken, "mode": mode,
        })
        logger.info("[RESIDUAL] %s (%s): left for an analyst (%s)", jira_key, alert_name,
                    getattr(result, "triage_class", ""))
        if mode == "route" and _residual_report_only(alert_name):
            logger.info("[RESIDUAL] %s: report only for this family — not routed", jira_key)
            return action_taken
        if mode == "route":
            why = await _deterministic_close_refusal(alert_name, jira_key, cfg, dry_run,
                                                     test_labels_only, True, "EDR_RESIDUAL")
            if why:
                logger.info("[RESIDUAL] %s: not routed — %s", jira_key, why)
                return action_taken
            if "needs-l2-review" not in result.labels:
                result.labels.append("needs-l2-review")
            return await _execute_l2_route(
                jira_key, cfg, result, dry_run,
                why="RAPTOR could not settle it on the evidence, so it needs an analyst")
    except Exception as exc:
        logger.warning("[RESIDUAL] %s: %s", jira_key, exc)
    return action_taken


async def _execute_l2_route(jira_key: str, cfg, result, dry_run: bool,
                            why: str = "the user cannot be asked via the Acme Security Bot "
                                       "(see above), so there is no L1 step left",
                            no_users_row_ok: bool = False) -> str:
    """Move a ticket nobody can be asked about to L2 Analysis required, assigned to the L2
    owner — what an L1 does by hand for a DLP finding whose owner is not on Slack.

    The workflow has no direct edge: L2 Analysis required is reached only from Awaiting
    more inputs (or No Response), and entering Awaiting more inputs is the Acme Security
    Bot's trigger. The bot DMs whoever is in Involved Users, so the hop is taken only while
    that cell exists and is EMPTY (with it empty the bot does nothing — DEMO-112070, where
    L1s passed through it twice). Category is never set. Same status rule as the chase:
    only a ticket nobody has moved on. Any failure leaves today's behaviour — the
    needs-l2-review label for an L1 to act on — and says so on the ticket.
    """
    from edr_triage.chase_reply_poller import _transition_to
    from edr_triage.jira_handler import (add_comment, assign_to_self_if_unassigned,
                                         get_involved_users_cell, get_status,
                                         transition_to_status)

    status = ((await get_status(jira_key, cfg)) or "").strip()
    if status.lower() not in _CHASE_FROM_STATUSES:
        logger.info("[L2-ROUTE] %s: ticket is in %r — a person has already moved it on",
                    jira_key, status or "unknown")
        return "labels_only"
    cell = await get_involved_users_cell(jira_key, cfg)
    # A Cyble digest has no Involved Users row by design — it names no person, so the bot
    # has nobody to message (L1 parks digests in Awaiting routinely). Only for callers that
    # say so; everywhere else a missing row still means "cannot be sure", and stops here.
    if cell is None and no_users_row_ok:
        cell = ""
    if cell != "":
        logger.info("[L2-ROUTE] %s: Involved Users is %s — not passing through the bot's "
                    "trigger; left for an L1", jira_key,
                    "missing or unreadable" if cell is None else f"set to {cell!r}")
        return "labels_only"

    async def _fail(step: str) -> str:
        logger.error("[L2-ROUTE] %s: %s — left for an L1", jira_key, step)
        await add_comment(jira_key, f"*RAPTOR could not move this ticket to L2:* {step}. "
                          "An analyst needs to route it.\n\n[Auto-triaged by RAPTOR]",
                          cfg, dry_run=dry_run)
        return "labels_only"

    if status.lower() == "open":
        if not dry_run and not await assign_to_self_if_unassigned(jira_key, cfg):
            return await _fail("could not take ownership of the Open ticket")
        if not await transition_to_status(jira_key, "Assigned", cfg, dry_run=dry_run):
            return await _fail("transition from Open to 'Assigned' failed")
    if status.lower() != "event analysis" and not await transition_to_status(
            jira_key, cfg.event_analysis_transition, cfg, dry_run=dry_run):
        return await _fail(f"transition to {cfg.event_analysis_transition!r} failed")
    if not await transition_to_status(jira_key, cfg.awaiting_input_transition, cfg,
                                      dry_run=dry_run):
        return await _fail(f"transition to {cfg.awaiting_input_transition!r} failed")
    if not await _transition_to(jira_key, "L2 Analysis required", cfg, dry_run):
        return await _fail("transition to 'L2 Analysis required' failed (the ticket is in "
                           "Awaiting more inputs; nobody was messaged)")
    who = getattr(cfg, "l2_assignee_name", "") or "the L2 owner"
    await add_comment(jira_key, f"*RAPTOR moved this ticket to L2 Analysis required* and "
                      f"assigned it to {who}: {why}. Nobody was messaged.\n\n"
                      "[Auto-triaged by RAPTOR]", cfg, dry_run=dry_run)
    if "raptor-routed-l2" not in result.labels:
        result.labels.append("raptor-routed-l2")
    logger.info("[L2-ROUTE] %s: moved to L2 Analysis required", jira_key)
    return "routed_to_l2"


def may_change_ticket_state(phase: str, dry_run: bool, test_labels_only: bool) -> bool:
    """Whether this run is permitted to move a ticket at all.

    A named function rather than an inline expression because it is the phase contract
    itself, and the contract was previously asserted only in prose — the comment above
    claims copilot handling is "byte-identical to shadow", while the execute block guarded
    on nothing but `dry_run`/`test_labels_only`. DEMO-112105 transitioned a real ticket
    Assigned → Event Analysis under AGENT_PHASE=copilot, in the same second as a comment
    saying it had not. Prose is not an invariant; this is, and it is tested.

    Deliberately takes `phase` as an argument instead of reading the env itself, so a test
    can assert every phase without mutating process state.
    """
    return phase == "autonomous" and not dry_run and not test_labels_only

_COPILOT_LABELS = {
    "AUTO_CLOSED_FP": "raptor-rec-fp",
    "AUTO_CLOSED_TP": "raptor-rec-tp",
    "NEEDS_L2": "raptor-rec-l2",
    "REQUEST_JUSTIFICATION": "raptor-rec-justify",
    "URGENT": "raptor-rec-urgent",
}


def _resolve_agent_phase() -> str:
    """Normalize AGENT_PHASE to one of shadow|copilot|autonomous.

    Baseline is AUTONOMOUS (hardcoded default), because `.env` is gitignored and untracked
    — a deploy ships code only, so an env-only switch could never be flipped without
    hand-editing the host. This default IS the live setting.

    It is far narrower than the word suggests, and that narrowing is what makes it safe to
    hardcode. This function answers only "what phase was configured"; three further gates
    stand between that and any ticket changing:

      * _effective_agent_phase(alert_name) downgrades to copilot for every family not in
        AGENT_AUTONOMOUS_ALERTS — currently the two Port Sweep variants, ~0.35 closes/day.
        Every other family behaves exactly as it did in copilot.
      * a close also needs may_autoclose(): the never-close list, and the
        EDR_AUTOCLOSE_REPORT interlock (no report, no closing).
      * `event_analysis` stays suppressed behind EDR_USER_CHASE at any phase, because
        entering `Awaiting more inputs` fires the Slack chase bot at a real employee.

    AGENT_PHASE overrides: ``shadow`` silences the agent (verdict stored only),
    ``copilot`` restores advisory-only behaviour everywhere — that plus
    ``AGENT_AUTONOMOUS_ALERTS=""`` are the two kill switches. Unrecognized values fall
    back to COPILOT, never to the default, so a typo can only ever narrow autonomy.
    """
    import os as _os
    raw = (_os.getenv("AGENT_PHASE") or "autonomous").strip().lower()
    phase = _AGENT_PHASES.get(raw)
    if phase is None:
        logger.warning("Unrecognized AGENT_PHASE=%r — falling back to copilot (advisory-only, no state changes). Valid: %s",
                       raw, ", ".join(sorted(_AGENT_PHASES)))
        return "copilot"
    return phase


# The pilot scope, HARDCODED. `.env` is gitignored and untracked, so a deploy ships code
# only — an env-only allowlist could never be changed without hand-editing the host.
#
# Port Sweep first because its verdict is a deterministic port allowlist
# (EDR_PORTSWEEP_FP_PORTS), runbook-backed, 21-for-21 on 60 days of FP recommendations with
# no duplicates and none pending. Model risk is ~0, so the pilot exercises the transition
# machinery and the auto-close report rather than the model. ~0.35 closes/day.
#
# Exact alert_name values, because that is how this allowlist matches (see below) — and
# only these two: of the five Port Sweep variants seen in 90 days, only 3389 and 9182 are
# on EDR_PORTSWEEP_FP_PORTS, so they are the only ones the playbook can clear. They are
# 133 of the 137 tickets. 445/49382/60762 stay advisory, which is correct.
# Precision below is the LABEL PROXY, measured 2026-09-16 over 90 days: of the tickets
# RAPTOR labelled `raptor-rec-fp`/`ai-fp`, the share a human then closed as False Positive.
# The denominator counts only TERMINAL human outcomes — `False Positive` against
# `Closed`/`Resolved`/`Containment`+. `L2 Analysis required` and `Awaiting more inputs`
# are IN-FLIGHT, not verdicts, and counting them as disagreement is what made an earlier
# read of this same data show Office operations at 0.960 instead of its true 24/24.
_DEFAULT_AUTONOMOUS_ALERTS = ",".join((
    # ---- pilot, live since 2026-09-12; 2 closes, 0 overturns -------------------
    "Network Port Sweep detected on 3389",                      # 12/12
    "Network Port Sweep detected on 9182",                      # 12/12
    # ---- added 2026-09-16 ------------------------------------------------------
    "Rare and potentially high-risk Office operations",         # 24/24
    "Potential beaconing from 192.168.75.49 to 13.235.12.227",  # 11/11  (see note)
    "Monitor AWS Credential abuse or hijacking",                #  8/8
    # ---- added 2026-09-25 — first batch under the confidence floor + novelty signal.
    # Both are agent-decided (neither is observe-only or deterministic-only), so the
    # 0.90 floor and the first-seen fact apply to every close. Measured over 120d:
    "Privileged Accounts - Sign in Failure Spikes",              # 10/10 FP recs confirmed,
                                                                 # all at 95% (see note)
    "Rare Process as a Service",                                 #  9/9 FP recs confirmed;
                                                                 # 1 was at 85% -> floored
    # ---- added 2026-09-28 — behind edr_triage/powershell_guard.py, which permits a close
    # ONLY for an exact repeat of a command a human cleared on the same device + account in
    # the last 30 days. Replayed over 1,793 tickets / 180d: 343 would close, and not one of
    # them is a ticket humans failed to clear. Closes little at quiet times (0 in Sep);
    # it earns its keep in bursts.
    "Powershell script was loaded in memory",
    # ---- added 2026-09-30 — CHASE, not close. Autonomous so the playbook may run the
    # chase (every named user is asked via the Security Bot) and chase_reply_poller may
    # route the answers to L2. These families are playbook-driven, so the agent's verdict
    # never replaces the chase, and uba_guard refuses any close that is not a repeat of an
    # L2-approved pattern pinned to the company account. All live spellings, including
    # the vendor's own typo — the most common of the three — and the corrected one.
    "Netskope - Bulk Upload detection",
    "Netskope - Bulk Downnload detection",
    "Netskope - Bulk Download detection",
    "Netskope - Suspicious Bulk Download Detection",
    # ---- re-enrolled 2026-10-05 — REPEAT OR ASK, behind edr_triage/privesc_guard.py. It
    # closes only an exact repeat of commands a human cleared for the same session
    # principal on the same host in 30 days (never on red flags such as persistence), and
    # puts anything new to that person through the user chase, with L2 deciding.
    # Withdrawn earlier the same day: closing on the model's verdict matched human action
    # only ~83% once FP calls humans parked to ask the user were counted (DEMO-115542).
    "Root Privilege Escalation",
    # ---- added 2026-10-06 — PLAYBOOK-DRIVEN (_playbook_keeps_control): the agent never
    # closes DLP. The only close is the standing DLP-Secret-key rule (2026-09-22) and only
    # when every event is a CASB API Scan of a file at rest: humans closed all 930 such
    # tickets in 30 days (467 False Positive, 463 Duplicate; none asked, none escalated).
    # Secret-key Uploads (2 of 37 asked) and every national-ID finding stay recommendations.
    # Exact-repeat duplicates are handled separately (duplicate_guard.py).
    "Netskope DLP Alerts",
    # ---- added 2026-10-16 — ASK, never close (usb_guard.py). Gate G14 turns every FP call
    # into a justification request, so autonomy here only lets RAPTOR put the question to
    # the one reachable copier; the answer or silence goes to L2. 36 of 43 tickets in 60
    # days already went to L2, who closed them on the copier's or IT's word.
    "Files Copied to USB Drives",
))
# Privileged Accounts - Sign in Failure Spikes: the benign cause here is overwhelmingly
# ResultType 70044 (Conditional Access sign-in-frequency expiry — DEMO-107545, 608 of
# them). The dangerous version of the same alert is a spray that SUCCEEDS: invalid-
# password failures followed by a success. The agent sees outcomes counted by result
# type via sentinel_signin_summary, so a success is visible to it — and since 2026-09-26
# a deterministic guard (edr_triage/signin_guard.py) refuses the close at the pipeline
# gate whenever a success follows invalid-password failures, or the check can't run.
# Rare Process as a Service: a rare process installed as a service is also a classic
# persistence technique. Its FP recommendations are clean, and the agent separately
# over-escalates this family heavily (25 escalations in 120d that humans closed FP) —
# autonomy changes nothing about those, it only acts on the ~2/month FP calls.
# Deliberately NOT here, and why:
#   Netskope DLP Alerts                 402/402 — the right end state, but it is 58% of all
#                                        volume; enrolling it makes autonomy a DLP decision
#                                        rather than a per-family one. Last, deliberately.
#   Powershell script was loaded in memory
#                                        HISTORY: dropped from the 2026-09-18 batch (new
#                                        hosts on generic accounts left the model with no
#                                        context), then ENROLLED 2026-09-28 — but only
#                                        behind powershell_guard, because this family's
#                                        human truth is a person vouching, not evidence
#                                        the model sees. See the entry above.
#   Netskope - Suspicious Bulk Download   1/1 — n=1 terminal, and 3 of its 4 tickets are
#                                        parked in `Awaiting more inputs`. It scored 0.100
#                                        on the shadow metric. It is the natural
#                                        REQUEST_JUSTIFICATION family, NOT a close family.
#   Tampering with the MDE sensor        23/35 — on EDR_NEVER_AUTOCLOSE_FAMILIES; the cause
#                                        is an unsettled FP-vs-TP definition, not a model
#                                        error, so autonomy would take a side in an open
#                                        argument.
#   Privileged Accounts - Sign in         9/9 — a credible next candidate, held back only to
#   Failure Spikes                       keep this step to four families.
#
# Note on beaconing: the two IPs are part of the alert NAME, so a new source/destination
# pair is a NEW family that falls closed to copilot. That is the correct default — a
# beacon to an address we have never cleared is exactly the case not to auto-close. Do
# NOT wildcard this one; see _alert_matches_allowlist for when a wildcard is appropriate.


def autonomous_alert_allowlist() -> set[str]:
    """Alert families permitted to reach autonomous.

    Comma-separated EXACT alert_name values, matched case-insensitively — a family prefix
    matches nothing, so each variant must be listed. That fails closed on a newly-seen
    variant, which is safe but does mean it will silently not be autonomous.

    Defaults to _DEFAULT_AUTONOMOUS_ALERTS (the live pilot scope). AGENT_AUTONOMOUS_ALERTS
    overrides it, and setting it to empty is the kill switch:

        AGENT_AUTONOMOUS_ALERTS=""      -> no family is autonomous, everything advisory

    Note `or` is not used for the fallback: an explicitly-empty env var must mean "none",
    not "fall back to the default", or the kill switch would silently re-enable the pilot.
    """
    import os as _os
    raw = _os.getenv("AGENT_AUTONOMOUS_ALERTS")
    if raw is None:
        raw = _DEFAULT_AUTONOMOUS_ALERTS
    return {p.strip().casefold() for p in raw.split(",") if p.strip()}


def _alert_matches_allowlist(alert_name: str, allow: set[str]) -> bool:
    """Exact match, plus an opt-in `*` for alert names that embed variable data.

    Some detections put per-incident data INTO the alert name, so the family has no single
    stable string to list. Observed live:

        The EC2 instance i-05ffef14b782e39d2 queried a drive-by source domain name.
        Found 22 alerts for Social Media Monitoring across 2 entities
        Anomalous sign-in location by avery.gomez@example.com to JAMF Connect

    An exact-match allowlist cannot express those at all: every incident mints a new name,
    so the family is permanently stuck on copilot no matter how well it scores. The escape
    hatch is a `*` in the allowlist ENTRY, and it is deliberately a weak one:

      * `*` matches ONE whitespace-free run (`[^\s]+`) — never `.*`. So
        `Found * alerts for Social Media Monitoring across * entities` accepts any counts
        but NOT a different Cyble category, and `The EC2 instance * queried a drive-by
        source domain name.` accepts any instance id but no other EC2 alert. The wildcard
        stands in for a token, not for an arbitrary tail.
      * the match is ANCHORED at both ends, so an entry can never match a longer name that
        merely starts with it.
      * an entry that is only wildcards and separators (`*`, `* *`) would match every
        single-token alert name, which is autonomy-for-everything written as a typo. It is
        REFUSED with an error and dropped, not honoured.

    Entries WITHOUT a `*` take the original exact path unchanged — which is every entry
    shipped today. Port Sweep in particular must stay exact: its ports are bare integers,
    so any numeric wildcard would collapse 3389/9182 together with 445/49382/60762, ports
    the playbook cannot clear and that are advisory on purpose.

    A wildcard widens what autonomy covers, so it should only be written for a family whose
    variable part is genuinely incidental (a counter, an instance id) — never for one where
    it names the thing being judged, e.g. the beacon destination IP.
    """
    probe = (alert_name or "").strip().casefold()
    if not probe:
        return False
    if probe in allow:
        return True
    for entry in allow:
        if "*" not in entry:
            continue
        if not entry.replace("*", "").strip():
            logger.error(
                "AGENT_AUTONOMOUS_ALERTS entry %r is only wildcards — it would make every "
                "alert family autonomous. Refusing it; fix the config.", entry)
            continue
        pattern = "".join(
            r"[^\s]+" if part == "*" else re.escape(part)
            for part in re.split(r"(\*)", entry) if part
        )
        if re.fullmatch(pattern, probe):
            return True
    return False


def _effective_agent_phase(alert_name: str) -> str:
    """The phase that governs THIS alert family's ticket state changes.

    Autonomy is per-family because measured accuracy is per-family and the spread is
    enormous. Measured 2026-08-30 on the live shadow metric: Netskope DLP scored 0.84
    (42/50) with 42/42 precision on its FP recommendations and ZERO cases of
    recommending FP where a human said TP — while on the same metric Netskope Bulk
    Upload scored 0.077, Bulk Download 0.100, Netskope Failed Login 0.154 and Rare
    Process as a Service 0.417. A single global AGENT_PHASE=autonomous hands ticket
    closure to the agent for all of them at once, which is not a decision anyone would
    make deliberately.

    So autonomy must NAME ITS SCOPE: AGENT_PHASE=autonomous with an empty
    AGENT_AUTONOMOUS_ALERTS downgrades to copilot and logs a warning, rather than
    silently going live everywhere. Nothing regresses by requiring this — no ticket has
    ever run autonomous (every ShadowResult on record carries phase=shadow or copilot),
    so this only ever narrows a phase, never widens one.

    shadow and copilot are returned unchanged: they are already non-destructive.
    """
    phase = _resolve_agent_phase()
    if phase != "autonomous":
        return phase
    allow = autonomous_alert_allowlist()
    if not allow:
        logger.warning(
            "AGENT_PHASE=autonomous but AGENT_AUTONOMOUS_ALERTS is empty — staying on "
            "copilot (advisory-only). Autonomy must name the alert families it applies "
            "to; set AGENT_AUTONOMOUS_ALERTS to opt a family in."
        )
        return "copilot"
    if not _alert_matches_allowlist(alert_name, allow):
        logger.info(
            "[AGENT] %r is not in AGENT_AUTONOMOUS_ALERTS — advisory copilot for this "
            "alert family (autonomous is scoped to: %s)",
            alert_name, ", ".join(sorted(allow)),
        )
        return "copilot"
    return "autonomous"


# ---------------------------------------------------------------------------
# Agent loop helpers — fire-and-forget tasks
# ---------------------------------------------------------------------------

async def _extract_entities_async(alert_data: dict, result, jira_key: str, sha256: str) -> None:
    """Fire-and-forget SCG entity extraction after pipeline completes."""
    try:
        from entity_graph.extractor import from_edr_alert
        alert_data["jira_key"] = jira_key
        alert_data["_evidence"] = {"sha256": sha256}
        await from_edr_alert(alert_data, result)
    except Exception as exc:
        logger.warning("SCG entity extraction failed for %s: %s", jira_key, exc)


async def _save_agent_failure_shadow(jira_key: str, alert_id: str, alert_name: str,
                                     device_name: str, user_name: str, severity: str,
                                     error: str, error_code: str) -> None:
    """Record a shadow row when the agent loop errors/times out and falls back to
    the playbook — so the failure is visible via /shadow instead of being silent."""
    try:
        from entity_graph.models import ShadowResult
        shadow = ShadowResult(
            jira_key=jira_key, alert_id=alert_id, alert_name=alert_name,
            device_name=(device_name or "").lower(), user_name=(user_name or "").lower(),
            severity=severity,
            ai_triage_class="NEEDS_L2", ai_confidence=0.0,
            ai_reasoning=f"Agent loop did not complete — fell back to playbook. {error[:600]}",
            ai_error=error_code, phase=_effective_agent_phase(alert_name),
        )
        await shadow.insert()
    except Exception as exc:
        logger.warning("Agent-failure shadow save failed for %s: %s", jira_key, exc)


async def _refresh_pending_memory_verdict(jira_key: str, agent_result) -> None:
    """Update a still-PENDING quarantine row's caption after a re-triage.

    The row written at L2 hand-off records the AI verdict as it stood then, and is
    only rewritten when the ticket RESOLVES. A re-triage in between leaves the queue
    asserting something that is no longer true: DEMO-108429 read "Pending L2 resolution
    — AI concurred (NEEDS_L2)" while its shadow had moved to AUTO_CLOSED_FP, which is
    exactly backwards for an L2 deciding whether to promote or dismiss it.

    Deliberately narrow — the mirror of _heal_stale_quarantine on the other side of the
    lifecycle:
      * only rows still in quarantine with NO human decision (resolved_by empty), so a
        promotion is never overwritten;
      * only the AI-verdict text and the pending reason; tier, scope, auto_fp, commands,
        apps, actor and device are human decisions and are not touched;
      * never creates a row, and never runs on a resolved ticket — the closure poller
        already owns that path.
    """
    try:
        from app.database import get_collection
        import re as _re
        col = get_collection("eg_memories")
        doc = await col.find_one(
            {"jira_key": jira_key},
            {"_id": 1, "tier": 1, "resolved_by": 1, "content": 1, "quarantine_reason": 1},
        )
        if not doc or (doc.get("tier") or "") != "quarantine":
            return
        if (doc.get("resolved_by") or "").strip():
            return
        _reason = doc.get("quarantine_reason") or ""
        if not _reason.startswith("Pending L2 resolution"):
            return          # a real conflict caption — the poller owns it, leave it alone
        _cls = agent_result.triage_class
        _conf = getattr(agent_result, "confidence", 0.0) or 0.0
        _content_old = doc.get("content") or ""
        # Record the TRANSITION, never just the new value. The shadow is overwritten in
        # place on re-triage (_save_shadow_result keeps one row per ticket), so this
        # caption is the only surviving trace of what the AI said the FIRST time. An L2
        # working the queue needs "it used to say NEEDS_L2 and now says AUTO_CLOSED_FP"
        # — that the model changed its mind, usually after a code change, is the most
        # informative thing on the row. Overwriting in place would silently erase it.
        # Straight overwrite — the row states the CURRENT verdict, no history.
        # A superseded triage is not something an L2 needs to act on, and carrying it
        # only makes the caption longer. `[^)]*` on the match so any row already
        # carrying an older annotated form is still recognised and replaced cleanly
        # rather than left frozen.
        _new = f"AI: {_cls} (conf={_conf:.0%})"
        # Same caption logic the hand-off write uses — imported, not re-implemented.
        # Hardcoding "AI concurred" here mislabelled a genuine AI/L1 split as agreement
        # the moment a re-triage moved the AI off NEEDS_L2, which hides the review case
        # the caption exists for.
        from edr_triage.jira_closure_poller import pending_reason
        _reason = pending_reason(_cls, getattr(agent_result, "error", None))
        _content, _n = _re.subn(r"AI: [A-Z0-9_]+ \(conf=\d+%[^)]*\)", _new, _content_old, count=1)
        _set = {"quarantine_reason": _reason}
        if _n:
            _set["content"] = _content
        await col.update_one({"_id": doc["_id"]}, {"$set": _set})
        logger.info("Refreshed pending quarantine caption for %s → %s", jira_key, _cls)
    except Exception as exc:
        logger.debug("pending-memory refresh skipped for %s: %s", jira_key, exc)


# Fields that are re-fetched LIVE from Sentinel on every run rather than produced by
# the agent, so a re-triage returning nothing means the fetch degraded, not that the
# binding is gone.
_STICKY_FIELDS = ("device_name", "user_name", "machine_id", "additional_users", "actor_hosts")


def sticky_keep_stored(field: str, new_value, stored_value, user_rebound: bool) -> bool:
    """True when a re-triage's value for `field` must NOT overwrite the stored one.

    A binding is EVIDENCE — never let a re-run erase one. device_name / user_name /
    additional_users are re-fetched live from Sentinel every run (incident
    AccountEntity + alert ExtendedProperties), and that fetch degrades as an incident
    ages. DEMO-107545 bound satish.pengal@example.com on 2026-08-06 and returned NOTHING six
    days later, so the re-triage overwrote a correct actor with "". A fetch that comes
    back empty is MISSING information, not a finding that the actor is unknown — and the
    blanked ticket then had no principal at all, at which point the agent invented one
    (jamie.w@example.com, an identity with zero rows anywhere in the tenant) and
    investigated that instead.

    One-directional: a NEW non-empty value always wins (a genuine re-bind, or a
    correction), and an empty one is simply not applied over a stored value. It can only
    ever preserve information, never fabricate it.

    THE COUPLING RULE: user_name and additional_users describe ONE bound set, so they
    are sticky together or not at all. Held independently, a re-bind that NARROWS the
    set corrupts it. DEMO-110933 was bound by the old window sweep to 7 users (primary
    jules.menon + 6 others); the alert-scoped re-bind returned the single correct user
    v-payal.berdiya1, so user_name was replaced while the empty additional_users left
    the 6 sweep users in place. The row that results is not merely stale, it is
    impossible — the primary appears inside additional_users, a list built precisely by
    excluding it — and the agent is then handed 6 unrelated co-users to investigate,
    re-introducing the cross-attribution the alert-scoped bind exists to remove.

    A non-empty user_name IS the signal that this run re-bound the actor, so its
    companion list is authoritative too, empty or not. When user_name comes back empty
    the DEMO-107545 protection is untouched: both stay sticky.
    """
    if field not in _STICKY_FIELDS:
        return False
    if field == "additional_users" and user_rebound:
        return False
    return not new_value and bool(stored_value)


async def _save_shadow_result(
    jira_key: str, alert_id: str, alert_name: str,
    device_name: str, user_name: str, severity: str,
    agent_result, phase: str,
    alert_processes: list[str] | None = None,
    additional_users: list[str] | None = None,
    actor_hosts: list[dict] | None = None,
    finding_group_id: str = "",
    duplicate_of: str = "",
    dlp_bind_source: str = "",
    dlp_bind_alert_id: str = "",
    dlp_bound_users: list[str] | None = None,
    asset_tribe: dict | None = None,
) -> None:
    """Save agent verdict to eg_shadow_results for accuracy tracking."""
    try:
        from entity_graph.models import ShadowResult
        from agent_core.result import _summarize_tool_result, _fmt_args
        tool_trail = [
            {"name": tc.name, "args": _fmt_args(tc.args),
             "result": _summarize_tool_result(tc.name, tc.result)}
            for tc in (agent_result.tool_calls or [])
        ]
        # AI-side fields — everything a (re-)triage produces.
        # Asset ownership, flattened for the shadow row. The STATUS is kept in the label
        # rather than blanked, because "not in the asset register" is a different and
        # actionable fact from "we never looked" — one is somebody's to fix.
        _at = asset_tribe or {}
        _st = _at.get("status")
        if _st == "found":
            _asset_tribe_label = _at.get("tribe") or ""
        elif _st == "tribe_missing":
            _asset_tribe_label = f"unresolved:{_at.get('tribe_tag') or '?'}"
        elif _st == "no_asset":
            _asset_tribe_label = "unregistered"
        else:
            _asset_tribe_label = ""
        _asset_owner_list = [str(o) for o in (_at.get("owners") or []) if o]

        ai_fields = dict(
            alert_id=alert_id,
            alert_name=alert_name,
            device_name=device_name.lower(),
            user_name=user_name.lower(),
            # Lowercased + deduped to match user_name, and the primary is excluded so
            # the two fields never restate the same actor.
            additional_users=[
                u for u in dict.fromkeys(
                    (str(x) or "").lower().strip() for x in (additional_users or [])
                ) if u and u != user_name.lower()
            ],
            actor_hosts=[g for g in (actor_hosts or []) if isinstance(g, dict)],
            severity=severity,
            alert_processes=alert_processes or [],
            # Event identity + provenance. finding_group_id is written by BOTH the real agent
            # run and a reuse, because the first ticket of a burst is what later siblings
            # look themselves up against — write it only on reuses and the very first
            # ticket would never be findable, so nothing would ever de-duplicate.
            finding_group_id=finding_group_id,
            duplicate_of=duplicate_of,
            dlp_bind_source=dlp_bind_source,
            dlp_bind_alert_id=dlp_bind_alert_id,
            dlp_bound_users=[str(u) for u in (dlp_bound_users or []) if u],
            # Asset ownership, persisted so L2 can see it in the dashboard and not only
            # in the Jira comment. asset_tribe carries the STATUS words too
            # ("no_asset" / "tribe_missing"), because "not in the register" is a
            # different and actionable fact from "not looked up".
            asset_tribe=_asset_tribe_label,
            asset_owners=_asset_owner_list,
            ai_triage_class=agent_result.triage_class,
            ai_confidence=agent_result.confidence,
            ai_reasoning=agent_result.reasoning[:3000],
            ai_recommended_actions=agent_result.recommended_actions,
            ai_iterations=agent_result.iterations,
            ai_tool_calls=tool_trail,
            ai_error=agent_result.error,
            critic_ran=getattr(agent_result, "critic_ran", False),
            critic_agreed=getattr(agent_result, "critic_agreed", None),
            critic_reason=getattr(agent_result, "critic_reason", ""),
            blocked_by_safety=getattr(agent_result, "blocked_by_safety", False),
            safety_block_reason=getattr(agent_result, "safety_block_reason", ""),
            pre_safety_class=getattr(agent_result, "pre_safety_class", "") or agent_result.triage_class,
            safety_gate_kind=getattr(agent_result, "safety_gate_kind", ""),
            blocked_by_concurrent_keys=getattr(agent_result, "blocked_by_concurrent_keys", []) or [],
            phase=phase,
        )

        # One shadow per ticket: OVERWRITE on re-triage instead of inserting a duplicate.
        #
        # Duplicates were actively harmful, not just untidy:
        #   * check_concurrent_alerts() reads ShadowResult and excludes rows a human has
        #     resolved. A fresh duplicate carries no resolution stamps, so an
        #     already-closed ticket re-appeared as a live "concurrent open alert" and
        #     tripped that safety gate on its siblings (DEMO-107206 was closed in Jira yet
        #     blocked DEMO-107211/107218 after a re-run);
        #   * the closure poller's find_one could pick any row, so a re-triage verdict
        #     was often never scored at all.
        #
        # Human closure fields (l1_*/l2_*) are PRESERVED — they come from Jira, not from
        # the agent, and must survive a re-triage. verdict_match is cleared because the
        # AI verdict just changed: keeping the old value would report accuracy for a
        # verdict that no longer exists. The closure poller re-scores it from the
        # preserved human verdict on its next pass.
        existing = await (
            ShadowResult.find(ShadowResult.jira_key == jira_key)
            .sort(-ShadowResult.created_at)
            .first_or_none()
        )
        if existing:
            # A binding is EVIDENCE — never let a re-run erase one. See
            # sticky_keep_stored for the full rationale and the coupling rule.
            _user_rebound = bool(ai_fields.get("user_name"))
            for _k, _v in ai_fields.items():
                if sticky_keep_stored(_k, _v, getattr(existing, _k, None), _user_rebound):
                    logger.warning(
                        "Re-triage of %s returned no %s — keeping the stored value %r "
                        "(live Sentinel enrichment degrades as an incident ages)",
                        jira_key, _k, getattr(existing, _k),
                    )
                    continue
                if (_k == "additional_users" and _user_rebound
                        and list(_v or []) != list(getattr(existing, _k, None) or [])):
                    logger.info(
                        "Re-triage of %s re-bound user_name=%r — replacing "
                        "additional_users %r with %r (one bound set, one write)",
                        jira_key, ai_fields.get("user_name"),
                        getattr(existing, _k, None), _v,
                    )
                setattr(existing, _k, _v)
            existing.verdict_match = None
            # created_at deliberately keeps the ORIGINAL triage time (the 24h
            # concurrent-alert window is defined on it), so it cannot signal that a
            # re-triage happened. Stamp retriaged_at instead — otherwise a re-run is
            # indistinguishable from a no-op to any caller waiting on the result,
            # and a re-run producing the same verdict changes no field at all.
            from datetime import datetime
            existing.retriaged_at = datetime.utcnow()
            await existing.save()
            logger.info("Shadow overwritten for %s (verdict=%s) — re-scoring pending",
                        jira_key, agent_result.triage_class)
            await _refresh_pending_memory_verdict(jira_key, agent_result)
        else:
            await ShadowResult(jira_key=jira_key, **ai_fields).insert()
    except Exception as exc:
        logger.warning("Shadow result save failed for %s: %s", jira_key, exc)


def _build_playbook_result_from_agent(agent_result, jira_key: str):
    """Convert AgentResult → PlaybookResult shape for co-pilot/autonomous modes."""
    from edr_triage.playbooks.base import PlaybookResult

    tc = agent_result.triage_class
    # Only an FP verdict may move the ticket. Everything else is labels-only.
    #
    # This used to be `"resolved" if FP else "event_analysis"`, which pushed EVERY other
    # verdict — including URGENT and AUTO_CLOSED_TP — into the user-justification loop:
    # transitioned to Event Analysis and stamped Category="User Not Responded". An active
    # threat parked awaiting a user's explanation is the worst possible disposition, and a
    # confirmed TP belongs in the IR chain, not in L1's inbox.
    #
    # AUTO_CLOSED_TP is deliberately NOT given a route to `In Progress` either — but note
    # the reason is scope, not impossibility. An earlier version of this comment claimed
    # the only path to `In Progress` ran through `Awaiting more inputs` (the Slack chase
    # trigger); walking DEMO-112428 disproved that: `Event Analysis -> In Progress` is
    # transition 91, direct, no bot involved. So a safe TP route DOES exist
    # (Open -> Assigned -> Event Analysis -> In Progress) and can be added later.
    # It is out of scope now because the pilot is FP-only, confirmed TPs are ~1.6% of
    # volume (3 raptor-rec-tp labels in 45 days), and the IR chain past `In Progress`
    # (Containment -> Eradication -> Recovery -> RCA) is a human process regardless.
    # A TP gets the label and the comment; humans drive containment.
    action = "resolved" if tc == "AUTO_CLOSED_FP" else "labels_only"
    auto_close = tc == "AUTO_CLOSED_FP"

    labels: list[str] = []
    if tc == "AUTO_CLOSED_FP":
        labels.append("ai-fp")
    elif tc == "URGENT":
        labels.append("URGENT")
    elif tc == "NEEDS_L2":
        labels.append("needs-l2-review")
    elif tc == "REQUEST_JUSTIFICATION":
        # NOT needs-l2-review — this stays with L1 in the AWAITING MORE INPUTS loop.
        # The label is the whole mechanism: `action` is now "labels_only" like every
        # other non-FP verdict, so RJ introduces no transition of its own. That is
        # deliberate — RJ means "chase this user", and the model must not be able to
        # reach a Slack DM until the chase ships with its own reachability gate.
        labels.append("awaiting-justification")
    elif tc == "AUTO_CLOSED_TP":
        labels.append("ai-tp")

    alert_name = agent_result.reasoning[:40]
    l1_comment = agent_result.to_jira_comment(jira_key, alert_name)

    return PlaybookResult(
        triage_class=tc,
        l1_comment=l1_comment,
        l2_comment="",
        action=action,
        auto_close=auto_close,
        labels=labels,
        llm_reasoning=agent_result.reasoning or "",
        # Carried so may_autoclose() can floor it. Only the agent path sets this.
        confidence=getattr(agent_result, "confidence", None),
    )
