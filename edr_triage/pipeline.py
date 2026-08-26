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
from edr_triage.store import claim_alert, is_processed, save_triaged_alert

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

    logger.info("EDR triage cycle: %d tickets processed", len(results))
    return results


async def _process_ticket(
    ticket: dict,
    token: str | None,
    cfg: EDRTriageConfig,
    force_agent: bool = False,
) -> TriagedAlert | None:
    from edr_triage.mde_alerts import (
        fetch_alert, fetch_alert_evidence, fetch_machine_timeline,
        extract_file_evidence,
    )
    from edr_triage.vt_hash import check_hash
    from edr_triage.classifier import classify
    from edr_triage.jira_handler import add_comment, transition_ticket, add_labels, set_category

    from edr_triage.observations import record_observation, detect_source
    from edr_triage.classifier import classify as _classify_early

    jira_key     = ticket["jira_key"]
    alert_id     = ticket["alert_id"]
    alert_name   = ticket.get("alert_name", "")
    is_sentinel  = ticket.get("is_sentinel", False)
    observe_only = ticket.get("observe_only", False)
    description  = ticket.get("description", "")
    existing_comments = ticket.get("existing_comments", "")

    # Dedup — use jira_key for observe-only tickets
    dedup_key = jira_key if observe_only else alert_id
    if not claim_alert(dedup_key):
        logger.debug("[skip] %s — already claimed/processed", jira_key)
        return None

    # Detect source for observation logging
    source = ("sentinel" if is_sentinel else
              ("mde" if not observe_only else detect_source(description, alert_name)))

    # Observe-only tickets: log + mark processed, no Jira actions
    if observe_only:
        decision = _classify_early(alert_name)
        record_observation(jira_key, alert_name, source, decision, description)
        save_triaged_alert.__module__  # noqa — just ensure import works
        from edr_triage.store import _col as _store_col
        try:
            import time as _t
            _store_col().update_one(
                {"alert_id": dedup_key},
                {"$set": {"alert_id": dedup_key, "jira_key": jira_key,
                          "alert_name": alert_name, "triage_class": "OBSERVED",
                          "action_taken": "observe_only", "processed_at": _t.time()}},
                upsert=True,
            )
        except Exception:
            pass
        logger.info("[observe] %s — '%s' logged (source=%s decision=%s)", jira_key, alert_name, source, decision)
        return None

    logger.info("Processing %s — alert_id=%s name='%s' sentinel=%s", jira_key, alert_id, alert_name, is_sentinel)

    # Classify early — skip non-EDR alert types before hitting MDE API
    early_decision = _classify_early(alert_name)
    # Record observation for all actionable tickets too
    record_observation(jira_key, alert_name, source, early_decision, description)

    if early_decision == "skip":
        logger.info("[skip] %s — alert type '%s' is not an EDR endpoint alert", jira_key, alert_name)
        # Mark as processed so we don't re-observe on every poll
        try:
            import time as _t
            from edr_triage.store import _col as _store_col
            _store_col().update_one(
                {"alert_id": alert_id},
                {"$set": {"alert_id": alert_id, "jira_key": jira_key,
                          "alert_name": alert_name, "triage_class": "SKIPPED",
                          "action_taken": "skip", "processed_at": _t.time()}},
                upsert=True,
            )
        except Exception:
            pass
        return None

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
    if is_sentinel:
        logger.info("%s is a Sentinel identity alert — skipping MDE API fetch", jira_key)
        alert_data = _jira_fallback
    elif token:
        alert_data = await fetch_alert(alert_id, token)
        if not alert_data:
            logger.warning("MDE alert %s returned no data — using Jira description fields for %s", alert_id, jira_key)
            alert_data = _jira_fallback
        evidence_list = await fetch_alert_evidence(alert_id, token)
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

    # Playbook selection (re-classify with inv_state now available from MDE data)
    playbook_name = classify(alert_name, inv_state)
    if playbook_name == "skip":
        logger.info("[skip] %s — alert type '%s' is not an EDR endpoint alert", jira_key, alert_name)
        return None

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
    if _is_ns_malware:
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
            if re.search(r"bulk\s+(?:upload|download)", (alert_name or ""), re.IGNORECASE):
                from edr_triage.sentinel_client import query_netskope_uba
                _inc_props = (incident_data.get("properties") or {})
                _uba = await query_netskope_uba(
                    incident_url,
                    alert_name=alert_name,
                    start_time_utc=_inc_props.get("firstActivityTimeUtc", "")
                                   or alert_data.get("alertCreationTime", "")
                                   or ticket.get("created_at", ""),
                    end_time_utc=_inc_props.get("lastActivityTimeUtc", ""),
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

    elif playbook_name in ("privesc", "generic", "no_threat") and incident_url:
        from edr_triage.sentinel_client import (
            fetch_incident, fetch_incident_entities, fetch_incident_alerts,
            extract_cloudtrail_details_async, extract_entity_summary, query_sentinel_alert,
        )
        from edr_triage.rule_replay import (
            decode_alert_cloudtrail_rows, replay_alert_cloudtrail_rows,
            decode_alert_local_group_rows, replay_alert_local_group_rows,
            decode_alert_event, replay_alert_rule,
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
        else:
            # (3) Last resort — the hand-written CloudTrail replica query (one host).
            # allow_deviceless_sweep is scoped to playbook_name=="privesc" only — its
            # fleet-wide, time-window-only fallback (no device, no incident correlation)
            # is safe for a genuine root-privesc alert missing a device entity, but not
            # for "generic"/"no_threat" alerts unrelated to AWS/root activity at all
            # (a MS-SQL-audit alert once got an unrelated person's macOS session
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
            # iterations. Filtering here, at the source, means a bad row costs one
            # co-host instead of the entire ticket twice over.
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
    # user of jordan.lee@example.com and the agent reported "No Principal Bound", could not
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
    # ticket body (rajat.pandey on the primary, sam.rivera on two co-hosts via
    # `.../assumed-role/ssm-session-dba-charlie-role/sam.rivera@example.com`), yet
    # additional_users was []. The co-HOSTS were captured; the co-USERS were dropped.
    #
    # Consequences of dropping them: the SCG never creates an entity for the co-actor, so
    # their prior verdicts are not recalled on this ticket (sam.rivera already has
    # curated DB-migration justifications from DEMO-108138/108171 — the same change-ticket
    # work — and none of it was reachable here), and scg_check_concurrent_alerts cannot
    # correlate on them at all.
    #
    # Same parser the primary actor already uses, applied to the co-host rows. Additive:
    # dedupes against the primary and anything the entity list already supplied, so no
    # single-actor alert changes shape.
    try:
        from edr_triage.playbooks.generic import _arn_session_user
        _seen = {(current_user or "").lower()} | {u.lower() for u in _other_users}
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
    if len(_proc_cmds) >= 4:
        from edr_triage.service_allowlist import classify_processes
        _pc = classify_processes(_proc_cmds)
        if _pc.get("distinct", 0) >= 4:
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

    from edr_triage.store import get_precedents
    precedents = get_precedents(alert_name, device_name, current_user)
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
    try:
        _uba = (sentinel_entities or {}).get("netskope_uba") or {}
        _app_set: set[str] = set()
        for _b in (_uba.get("by_user") or {}).values():
            for _a in (_b.get("apps") or []):
                if _a and str(_a).strip():
                    _app_set.add(str(_a).strip().lower())
        _live_apps = sorted(_app_set)
    except Exception as _exc:
        logger.debug("live-app extraction failed for %s: %s", jira_key, _exc)

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
        _allow = await match_actor_allowlist(
            _subtype_allow(alert_name), current_user, device_name,
            commands=_live_procs, apps=_live_apps,
        )
    except Exception as _exc:
        _allow = None
        logger.debug("actor-allowlist check failed for %s: %s", jira_key, _exc)
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
    # Advisory copilot comment — populated only in AGENT_PHASE=copilot, posted
    # after the playbook's own comments below. Stays empty on every other path
    # (shadow, autonomous, agent failure/timeout) so nothing extra is written.
    _copilot_comment = ""
    if result is None and _use_agent_loop:
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
            _agent_evidence = {
                "command_lines": _agent_cmds,
                "port_sweep_check": _ps_check,
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
                # can land a bare None in this list, crashing the WHOLE agent loop here at 0
                # iterations (AttributeError: 'NoneType' object has no attribute 'get') —
                # because this comprehension runs before the loop's first LLM call, inside
                # the same try/except that reports it as agent_exception. One bad row must
                # cost that one co-host, not the investigation.
                "additional_hosts": [h.get("device_name") for h in (_ct.get("additional_hosts") or [])
                                     if isinstance(h, dict) and h.get("device_name")],
                # AWS/SSM identity — surfaced so the agent labels the IAM role as a ROLE
                # and never reads a username out of the role name (DEMO-107147). The actor
                # is user_name (the ARN session principal), passed separately above.
                "session_issuer": _ct.get("session_issuer", ""),
                "user_arn": _ct.get("user_arn", ""),
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
                ),
                timeout=_agent_wall_timeout,
            )
            # Write shadow result for accuracy tracking
            _shadow_phase = _resolve_agent_phase()
            await _save_shadow_result(jira_key, alert_id, alert_name, device_name, current_user,
                                      alert_data.get("severity", ""), _agent_result, _shadow_phase,
                                      alert_processes=_live_procs,
                                      additional_users=_agent_evidence.get("additional_users"))
            if _shadow_phase == "autonomous":
                # Phase 3: the agent's verdict drives comments, transitions and auto-close.
                result = _build_playbook_result_from_agent(_agent_result, jira_key)
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
                if _shadow_phase == "copilot":
                    # Advisory only: an extra comment + a filterable label. Both are
                    # non-destructive — result.action / result.auto_close are left
                    # exactly as the playbook set them, so the agent cannot close,
                    # resolve or transition anything in this phase.
                    _copilot_comment = _agent_result.to_jira_recommendation(alert_name)
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

    dry_run = cfg.dry_run
    test_labels_only = cfg.test_labels_only

    # Post L1 comment
    if result.l1_comment:
        await add_comment(jira_key, result.l1_comment, cfg, dry_run=dry_run)

    # Post L2 comment (draft for L2 review or auto-resolution)
    if result.l2_comment:
        await add_comment(jira_key, result.l2_comment, cfg, dry_run=dry_run)

    # Post the copilot recommendation last, so the analyst reads the triage note
    # first and the agent's take as commentary on it (AGENT_PHASE=copilot only).
    if _copilot_comment:
        await add_comment(jira_key, _copilot_comment, cfg, dry_run=dry_run)

    # Execute action
    action_taken = result.action
    if not dry_run and not test_labels_only:
        if result.action == "resolved" and result.auto_close:
            await transition_ticket(jira_key, cfg.auto_close_transition, cfg)
        elif result.action == "event_analysis":
            await transition_ticket(jira_key, cfg.event_analysis_transition, cfg)
            await set_category(jira_key, "User Not Responded", cfg)
    elif test_labels_only and result.action in ("resolved", "event_analysis"):
        logger.info("[TEST_LABELS_ONLY] skipping transition for %s (would: %s)", jira_key, result.action)
        action_taken = "labels_only"

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

    return {
        "block_tool":         BlockToolPlaybook(),
        "malware":            MalwarePlaybook(),
        "reverse_shell":      ReverseShellPlaybook(),
        "lateral_move":       LateralMovePlaybook(),
        "credential_access":  CredentialAccessPlaybook(),
        "netskope":           NetskopePlaybook(),
        "endpoint_process":   EndpointProcessPlaybook(),
        "port_sweep":         PortSweepPlaybook(),
        "privesc":            GenericPlaybook("privesc"),
        "no_threat":          GenericPlaybook("no_threat"),
        "generic":            GenericPlaybook("generic"),
    }.get(name, GenericPlaybook("generic"))


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
        labels=["raptor-actor-allowlist"],
        llm_reasoning=(
            f"Deterministic actor-allowlist match — {scope_desc}, alert type "
            f"'{allow.get('alert_type') or 'any'}', golden precedent {src_key or '(unlinked)'}. "
            "No LLM invoked."
        ),
    )


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
#               + advisory label. Playbook still owns every state change, so
#               ticket handling is byte-identical to shadow.
#   autonomous  agent's verdict drives comments, transitions and auto-close.
_AGENT_PHASES = {
    "shadow": "shadow",
    "copilot": "copilot",
    "autonomous": "autonomous",
    "live": "autonomous",   # legacy name used by docs/settings UI
}

_COPILOT_LABELS = {
    "AUTO_CLOSED_FP": "raptor-rec-fp",
    "AUTO_CLOSED_TP": "raptor-rec-tp",
    "NEEDS_L2": "raptor-rec-l2",
    "REQUEST_JUSTIFICATION": "raptor-rec-justify",
    "URGENT": "raptor-rec-urgent",
}


def _resolve_agent_phase() -> str:
    """Normalize AGENT_PHASE to one of shadow|copilot|autonomous.

    Baseline is COPILOT (hardcoded default): the agent's investigation is POSTED
    as an advisory comment + a filterable ``raptor-rec-*`` label, but the
    deterministic playbook still owns EVERY ticket state change (comments,
    transitions, auto-close) — copilot is strictly non-destructive.

    AGENT_PHASE still overrides the default when set: ``shadow`` silences the
    agent (verdict stored only), ``autonomous``/``live`` lets the agent's verdict
    drive closure. Unrecognized values fall back to copilot (advisory-only) and
    log a warning. Autonomy is NEVER reached by accident — it requires the exact
    ``autonomous``/``live`` value; a typo can only ever land on advisory copilot.
    """
    import os as _os
    raw = (_os.getenv("AGENT_PHASE") or "copilot").strip().lower()
    phase = _AGENT_PHASES.get(raw)
    if phase is None:
        logger.warning("Unrecognized AGENT_PHASE=%r — falling back to copilot (advisory-only, no state changes). Valid: %s",
                       raw, ", ".join(sorted(_AGENT_PHASES)))
        return "copilot"
    return phase


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
            ai_error=error_code, phase=_resolve_agent_phase(),
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


async def _save_shadow_result(
    jira_key: str, alert_id: str, alert_name: str,
    device_name: str, user_name: str, severity: str,
    agent_result, phase: str,
    alert_processes: list[str] | None = None,
    additional_users: list[str] | None = None,
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
            severity=severity,
            alert_processes=alert_processes or [],
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
            # A binding is EVIDENCE — never let a re-run erase one.
            #
            # device_name / user_name / additional_users are not agent output: they are
            # re-fetched LIVE from Sentinel on every run (incident AccountEntity +
            # alert ExtendedProperties), and that fetch degrades as an incident ages.
            # DEMO-107545 bound chris.morgan@example.com on 2026-08-06 and returned NOTHING
            # six days later, so the re-triage overwrote a correct actor with "". A
            # fetch that comes back empty is MISSING information, not a finding that the
            # actor is unknown — and the blanked ticket then had no principal at all, at
            # which point the agent invented one (demo.user@example.com, an identity with
            # zero rows anywhere in the tenant) and investigated that instead.
            #
            # One-directional: a NEW non-empty value always wins (a genuine re-bind, or
            # a correction), and an empty one is simply not applied over a stored value.
            # It can only ever preserve information, never fabricate it.
            _sticky = ("device_name", "user_name", "machine_id", "additional_users")
            for _k, _v in ai_fields.items():
                if _k in _sticky and not _v and getattr(existing, _k, None):
                    logger.warning(
                        "Re-triage of %s returned no %s — keeping the stored value %r "
                        "(live Sentinel enrichment degrades as an incident ages)",
                        jira_key, _k, getattr(existing, _k),
                    )
                    continue
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
    action = "resolved" if tc == "AUTO_CLOSED_FP" else "event_analysis"
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
        # action is already "event_analysis" (every non-FP verdict is), which is exactly
        # where the justification loop lives, so no new transition is introduced.
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
    )
