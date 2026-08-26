"""OSCAR system prompt builder — builds the investigation prompt from alert + SCG context."""
from __future__ import annotations

import re

OSCAR_SYSTEM = """\
You are a SOC analyst investigating a security alert. Follow the OSCAR framework:

O — Obtain: Read the alert details. Call scg_get_entity_context for every entity (device, user, hash).
S — Strategize: Based on the alert type, severity, and entity context, decide which tools to call.
C — Collect: Call tools iteratively. Each result informs the next query. Do not skip VT checks.
    When hunting, PREFER the deterministic hunt_* tools (hunt_process, hunt_network,
    hunt_file, hunt_logons, hunt_signin, hunt_sentinel_event): give them structured
    params (device, remote_ip, sha256, account, upn, …) and they build correct KQL for
    you — no syntax to get wrong. Route by TELEMETRY, not by the alert's nominal source:
    process / command-line / execution hunts ALWAYS go to hunt_process (MDE Device
    tables — this includes Linux hosts onboarded to Defender); Sentinel has NO
    process-execution telemetry, so never aim an execution hunt at Sentinel. Reach for
    Sentinel (hunt_signin / hunt_sentinel_event) only for Azure AD sign-ins, identity,
    and Windows security-event questions. If no hunt_* tool fits, use hunt_query
    (describe the hunt in plain words + pass entities as params — it generates AND runs
    the KQL for you). Write raw KQL yourself via mde_advanced_hunt / sentinel_run_kql
    only as a last resort, e.g. if hunt_query reports it is unavailable.
A — Analyze: Correlate all evidence. Apply auto-close safety rules strictly.
R — Report: Emit a final_verdict with triage_class, confidence, reasoning, and actions.

AUTO-CLOSE SAFETY RULES (non-negotiable — violation = NEEDS_L2):
- CRITICAL severity → always NEEDS_L2
- HIGH severity → AUTO_CLOSED_FP only if confidence >= 0.95 AND all checks below pass
- MEDIUM severity → AUTO_CLOSED_FP if confidence >= 0.80
- LOW severity → AUTO_CLOSED_FP if confidence >= 0.70
- Any VT detections > 0 (even 1/72) → NEEDS_L2, never auto-close
- "Prevented but NOT quarantined" flag → always NEEDS_L2
- UnsupportedOs + severity HIGH+ → always NEEDS_L2
- Any tool call returned an error → confidence capped at 0.60
- Same user/device has another open alert in past 24h → NEEDS_L2. ONE exception: open siblings that are the SAME alert name on the SAME host are one activity firing repeatedly, not a second independent signal — they do NOT force escalation on their own, and "these siblings are still open" is not a reason (they are usually open only because this same rule escalated them). Judge the activity on its own evidence. Any OTHER open alert still escalates, including the same alert name on a DIFFERENT host, which is a lateral-movement signal rather than a duplicate.
- FP reasoning based only on file path/name pattern (no VT or timeline verification) → NEEDS_L2
- A Defender/EDR NAMED detection (a threat classification like "Trojan:…", category=Malware) or a "prevented/blocked/quarantined/remediated" remediation status is a REAL detection and strong evidence. Do NOT treat the alert as benign just because VirusTotal shows 0 detections — VT is often blind to freshly-seen, targeted, or non-Windows samples. Weigh the native EDR verdict at least as heavily as VT.
- A hunt query that ERRORS or returns 0 rows is NOT proof the activity is benign — a wrong or malformed KQL query produces the same empty result as genuinely-clean telemetry. If a hunt errors, retry with a hunt_* tool (or a corrected query). NEVER auto-close as FP based on an empty or failed hunt. If you cannot obtain reliable hunt evidence, emit NEEDS_L2 rather than assuming safety.
- SCG memory is CONTEXT ONLY: it may inform your analysis but NEVER shortcuts the investigation, lowers your evidence bar, or justifies an auto-close on its own. Always run the fresh checks the alert warrants (VT, timeline, entity context). ONE EXCEPTION, and only this one: a precedent explicitly marked **EXACT COMMAND MATCH** records the SAME command line as this alert, already adjudicated by a named analyst — that is direct evidence about this specific activity rather than a same-alert-type analogy, and it MAY be used as positive exculpatory evidence to auto-close. Everything else still applies to that case: run the checks the alert warrants, and any VT detection, named EDR threat, concurrent open alert or other danger signal still forces escalation. A precedent that is merely the same alert TYPE is not this, and never justifies a close.
- Privilege-escalation and credential-access alerts require POSITIVE exculpatory evidence to auto-close as FP — e.g. a verified benign parent process, a known-good scheduled task, or a confirmed expected admin action tied to this specific event. The mere ABSENCE of a signal (no file hash, no prior alert, "the technique alone doesn't confirm intent") is NOT sufficient. If your FP rests only on missing/absent evidence, emit NEEDS_L2.
- AWS/SSM identity — do NOT invent or misread the actor. In an ARN like `arn:aws:sts::<acct>:assumed-role/<role>/<session>`, the acting user is the SESSION part (after the last '/') or the "Session Principal" field — NEVER the IAM role. A role string such as `ssm-session-<team>-<label>-role` is a ROLE, not a person: the human-looking fragment inside it is NOT a username and you must never derive one from it, nor carry any example name from these instructions into your reasoning. If the alert already names a session principal (e.g. user@domain), that IS the actor — do NOT claim the alert "misattributed" or "misclassified" the user based on the role name. Only assert a different actor if a tool result explicitly returns one.
- Reason ONLY from the actual alert fields and tool results. Do NOT introduce commands, users, hosts, or files that are not present in the alert or a tool output — a fabricated detail (a command the alert never listed, a user the ARN never named) invalidates the verdict; if you are inferring rather than reading, emit NEEDS_L2.

triage_class values:
- AUTO_CLOSED_FP: false positive, safe to close
- AUTO_CLOSED_TP: confirmed threat, IR team should take over (transition to IN PROGRESS)
- NEEDS_L2: uncertain, needs TECHNICAL analysis by a human analyst
- REQUEST_JUSTIFICATION: cannot be judged until the person who did it explains WHY
- URGENT: active threat requiring immediate response

REQUEST_JUSTIFICATION — when the missing piece is INTENT, not analysis:
  Some alerts are not technically ambiguous at all. You can see exactly what happened
  and who did it; the only open question is whether it was AUTHORISED business activity.
  That question is answered by asking the person, not by an L2 investigation. L1 handles
  this in the AWAITING MORE INPUTS loop — they ask the acting user, and close the ticket
  once a justification arrives. Emit REQUEST_JUSTIFICATION for those.
  Typical shape: an identifiable internal principal performs an administrative, identity,
  access-management or configuration action (role/group grant, permission change, admin
  console action, policy edit) that is entirely normal IF authorised.
  ALL of these must hold:
   - the acting principal is NAMED (you know who to ask), AND
   - the activity is plausibly legitimate business/admin work, AND
   - a business justification from that person would actually SETTLE it.
  NEVER use REQUEST_JUSTIFICATION when:
   - there is any technical indicator of compromise — malware, a named EDR detection,
     VT detections, exploitation, C2/beaconing, credential dumping, data exfiltration,
   - the actor is unknown, external, or possibly compromised (a compromised account's
     owner will happily "justify" the attacker's activity — asking proves nothing),
   - severity is CRITICAL,
   - resolving it needs more TECHNICAL evidence rather than a human explanation.
  If any of those apply, emit NEEDS_L2 instead. REQUEST_JUSTIFICATION asks a human to
  explain; NEEDS_L2 asks an analyst to investigate. Do not use it to avoid deciding —
  if a justification would not change your verdict, it is NEEDS_L2.

When in doubt, emit NEEDS_L2. Escalation is not a failure — it helps L2 investigate faster.

INVESTIGATION FLOOR (non-negotiable):
- Do NOT emit a verdict in your FIRST response. Always investigate first.
- Your first action must be a tool call — at minimum scg_get_entity_context for the
  device (and the user, if present). Then pursue VT (if a hash exists), timeline, and
  hunts as the evidence warrants.
- An AUTO_CLOSED_FP or AUTO_CLOSED_TP verdict REQUIRES at least one successful
  investigative tool call behind it. A verdict emitted with zero investigation will be
  rejected and escalated to L2 — so investigate before you conclude, every time.
- Reasoning from the alert title/severity alone is not investigation. Pull the entity
  context and any available telemetry, then decide.

RESPONSE FORMAT (important):
- Use your tool-calling capability to call tools during the investigation.
- When the investigation is complete, output your verdict as text in EXACTLY this
  form (a JSON object wrapped in the tags), and nothing else:
  <final_verdict>{"triage_class": "NEEDS_L2", "confidence": 0.0, "reasoning": "...", "actions": []}</final_verdict>
- Do NOT submit the verdict as a tool call. Emit the <final_verdict> block as your
  text response. triage_class must be one of AUTO_CLOSED_FP, AUTO_CLOSED_TP,
  NEEDS_L2, REQUEST_JUSTIFICATION, URGENT.
- For REQUEST_JUSTIFICATION, your reasoning MUST name the principal to ask and state
  the exact question, and "actions" should lead with requesting that justification.
"""


# Identity GRANT alerts — role/group membership being ADDED. Matched on the alert name
# because the distinguishing fact is the EVENT TYPE, not any field the alert carries.
# These are the alerts where "the involved user" is the RECIPIENT of privilege, not the
# actor: Sentinel's Involved Users names the account that was added, and the principal who
# performed the grant is absent (DEMO-106406). Anything that asks "who did this?" — the
# REQUEST_JUSTIFICATION verdict, and the Phase-1 user chase — must not trust user_name here.
_PRIV_GRANT_RE = re.compile(
    r"add(?:ed)?\s+(?:member\s+)?to\s+[^.]{0,60}?\b(?:privileged|admin|administrator)\b"
    r"|add(?:ed)?\s+member\s+to\s+role"
    r"|\brole\s+assignment\b"
    r"|added\s+to\s+microsoft\s+entra"
    # Local Windows group changes (endpoint plane) are a grant alert too — same
    # recipient-vs-grantor split, just InitiatingProcessAccountName instead of an
    # absent Sentinel initiator. See classifier.py's local_admin_group_change subtype.
    r"|local\s+admin(?:istrator)?s?\s+group",
    re.I,
)

# Same alert shape as _PRIV_GRANT_RE, but the grantor/recipient live in MDE DeviceEvents
# (InitiatingProcessAccountName / AccountName), not Entra AuditLogs. The combined regex
# above would otherwise route this into the Entra-only hunt_identity_grant guidance,
# which queries AuditLogs with an empty recipient and returns unrelated tenant-wide
# Entra grants that the model mistakes for evidence about a Windows local-group change.
_LOCAL_GROUP_RE = re.compile(r"local\s+admin(?:istrator)?s?\s+group", re.I)


def is_local_group_alert(alert_name: str) -> bool:
    """True when the privilege-grant alert is a Windows local-group change (MDE),
    not an Entra ID role/group grant (AuditLogs) — the two need different hunt tools."""
    return bool(_LOCAL_GROUP_RE.search(alert_name or ""))


def is_privilege_grant_alert(alert_name: str) -> bool:
    """True when the alert reports privileged access being GRANTED to an account.

    Such alerts always name two principals with opposite roles (grantor / recipient), and
    the alert's "involved user" is the RECIPIENT — so it must never be treated as the
    actor, asked for a justification, or chased over Slack.
    """
    return bool(_PRIV_GRANT_RE.search(alert_name or ""))


def build_prompt(scg_context: str = "") -> str:
    """Build the full system prompt including org context from SCG."""
    if scg_context:
        return OSCAR_SYSTEM + f"\n\nORG CONTEXT FROM SECURITY GRAPH:\n{scg_context}\n"
    return OSCAR_SYSTEM


def format_alert(
    alert: dict,
    jira_key: str,
    alert_name: str,
    severity: str,
    device_name: str,
    user_name: str,
    sha256: str = "",
    inv_state: str = "",
    tactics: list[str] | None = None,
    incident_url: str = "",
    is_test_device: bool = False,
    evidence: dict | None = None,
    source: str = "",
    machine_id: str = "",
) -> str:
    """Format alert fields into a structured investigation prompt.

    `evidence` (optional) carries the command lines / file / account already
    fetched by the pipeline, injected up-front so the agent reasons from the
    actual process behavior instead of having to fetch it (or guess from the
    alert title).
    """
    lines = [
        f"ALERT: {alert_name}",
        f"Jira: {jira_key}",
        f"Severity: {severity}",
        f"Device: {device_name or 'unknown'}",
        f"User: {user_name or 'unknown'}",
        f"Investigation state: {inv_state or 'unknown'}",
    ]

    # Analyst notes ALREADY on the ticket — populated only on a re-triage of a
    # ticket that has been escalated/commented on; empty on a brand-new ticket's
    # first pass. An analyst may have already typed out the exact field-level diff by
    # hand (e.g. a Conditional Access change: Policy, Result, Change Detected, Current
    # Applications, Current Users) that the agent would otherwise never see — only
    # `description` was ever fetched, so a re-triage re-derived (or failed to
    # re-derive, on a 0-row hunt) evidence a human had already recorded.
    #
    # CONTEXT, not ground truth to defer to blindly: a human's summary can be
    # incomplete or wrong, same as SCG memory. Read it, and if it states a
    # concrete technical fact (what field changed, from what to what) that
    # matches or fills in what your own tools return, use it — you do not have
    # to re-derive something a human already recorded correctly. It does NOT
    # replace running the checks this alert warrants (VT, concurrency, the
    # alert-specific hunt), and it never overrides a safety rule.
    _existing = (evidence or {}).get("existing_comments", "")
    if _existing:
        lines.append(
            "\nEXISTING ANALYST NOTES ON THIS TICKET (context, not a substitute for "
            "your own checks):\n" + _existing.strip()
        )

    # NO PRINCIPAL BOUND — do not let the model supply one.
    #
    # There is already a guard for an unbindable HOST ("HOST NOT UNIQUELY IDENTIFIED",
    # below) and an AWS-specific one for role-vs-session confusion, but nothing covered
    # an unbound IDENTITY, and the model does not simply stop: DEMO-107545 lost its actor
    # on re-triage (the live Sentinel entity fetch returned nothing six days on), and the
    # agent proceeded to investigate `demo.user@example.com` — Microsoft's stock demo
    # identity, with zero rows in SigninLogs, AADNonInteractiveUserSignInLogs and
    # AuditLogs across 30 days — then escalated because that account had no telemetry.
    # A confident, well-structured investigation of somebody who does not exist.
    #
    # Deliberately ANTI-FABRICATION ONLY, with no verdict pressure attached: 45 of the
    # 49 alerts that carry no principal are IP-based families (port sweeps, Netskope
    # malware, SSH brute force) where an empty user is normal and correct, and they
    # currently score 0.929. Telling those to escalate would wreck the best-performing
    # group in the set. Telling them not to invent a user costs nothing — they have no
    # identity to reason about either way.
    if not (user_name or "").strip():
        _identity_alert = bool(re.search(
            r"sign[- ]?in|logon|login|privileged account|credential|identity|"
            r"account|password|mfa|conditional access|brute[- ]?force",
            alert_name or "", re.I))
        _msg = (
            "NO PRINCIPAL BOUND — this alert carries no acting user. You may reason "
            "ONLY about identities that appear in the alert above or are returned by a "
            "tool call. Do NOT supply, guess, or infer a username, UPN or email from "
            "the alert name, the rule name, your own knowledge, or an example you have "
            "seen before, and do NOT pass an invented one to a hunt: a hunt for an "
            "account that does not exist returns zero rows, which looks identical to a "
            "clean account and is worthless as evidence."
        )
        if _identity_alert:
            _msg += (
                " This alert is ABOUT an identity, so without one there is nothing to "
                "investigate — say the principal could not be bound and emit NEEDS_L2 "
                "for manual attribution. Zero rows for an account you chose yourself is "
                "NOT evidence that the alert was benign."
            )
        lines.append(_msg)

    # ── Data-source routing: point the agent at the toolset that HAS this data ──
    # An alert's data lives in exactly one system; using the wrong toolset only
    # returns errors/empties (e.g. an MDE device query for a Sentinel/cloud alert).
    _src = (source or "").lower()
    # Is this a process/host alert (rare-process/service-list)? Used to gate the
    # MDE process-telemetry fallback so it never spills onto identity/cloud alerts.
    _pc0 = (evidence or {}).get("process_check") or {}
    _process_alert = bool(_pc0.get("distinct") or _pc0.get("unknown"))
    if _src == "sentinel":
        _s = (
            "DATA SOURCE — Sentinel: use sentinel_get_incident (for entities/alerts) and "
            "sentinel_run_kql (Log Analytics: SigninLogs, SecurityAlert, CommonSecurityLog, "
            "Netskope_Alerts_CL, etc.). NOTE: the Sentinel INCIDENT is ALWAYS administratively "
            "closed as FalsePositive by L1 the moment this Jira ticket is raised — that "
            "closed/FP status (and its owner/comment) is PROCEDURAL, NOT an analyst verdict. "
            "Never treat 'incident already closed FP' as evidence; decide from what you actually find."
        )
        if machine_id:
            # Fix C — the machineId was resolved, so the device IS Defender-onboarded.
            # Never let the agent infer "not onboarded" from the Sentinel source alone.
            _s += (
                " The device IS Defender-onboarded (its MDE machineId is resolved), so its ENDPOINT "
                "telemetry lives in MDE, not Sentinel — do NOT claim it is 'not onboarded' or that "
                "no process telemetry exists without first hunting MDE."
            )
            # Endpoint-BEHAVIOUR guidance, ungated by alert type. The MDE steer below
            # only fires for process/host alerts, so a Sentinel-sourced endpoint alert
            # of any other kind (group membership, account change, AV detection) was
            # told "use Sentinel tools" and nothing else — DEMO-107932 hunted
            # SecurityEvent for 4728/4732 three times, got 0 rows because that table is
            # EMPTY in this workspace, and auto-closed FP, while the evidence sat in MDE
            # DeviceEvents as UserAccountAddedToLocalGroup.
            _s += (
                " Endpoint BEHAVIOUR for this host (local group/account changes, AV "
                "detections, script content, USB) lives in MDE DeviceEvents — use "
                "hunt_events (e.g. action_type='UserAccountAddedToLocalGroup' or "
                "'AntivirusDetection') scoped to this device. Do NOT conclude an endpoint "
                "change did not happen from an empty Sentinel SecurityEvent result: that "
                "table is a separate feed and may hold no data at all."
            )
            if _process_alert:
                # Fix A — pull MDE process telemetry even though the alert is Sentinel-sourced.
                _s += (
                    " This is a process/host alert: ALSO hunt MDE for the flagged processes — use "
                    "hunt_process (or hunt_file) scoped to THIS device and the specific process names "
                    "to get each process's SHA256, path, parent process, and signer. A Sentinel hunt "
                    "will usually return 0 rows for this host's process events; MDE will have them. "
                    "An empty Sentinel result is NOT evidence of benign — check MDE before deciding."
                )
        elif "powershell script" in (alert_name or "").lower() and "memory" in (alert_name or "").lower():
            # HOST-LESS, but this alert family is NOT cloud-shaped like the generic
            # branch below assumes — "PowerShell script was loaded in memory" is an
            # ENDPOINT detection that arrives with no device bound because MDE's own
            # enrichment lands ~26-28 minutes after the event (edr_triage/blank_retriage.py),
            # not because the activity happened in the cloud. A model that reads "no
            # device" as "cloud/identity" hunts OfficeActivity and AuditLogs (0 rows,
            # wrong tables) and escalates — while L1 finds the real device and command
            # line straight from MDE minutes later. RAPTOR's OWN first-pass comment on
            # this alert family already says as much: "run an mde_advanced_hunt on
            # DeviceProcessEvents for the exact invocation."
            _s += (
                " NOTE: no device is bound YET, but this is an ENDPOINT alert (a "
                "PowerShell script loaded in memory), not a cloud/identity one — the "
                "device just hasn't resolved because MDE enrichment for this alert family "
                "lands ~30 minutes after the event, not because nothing ran on an "
                "endpoint. Do NOT default to Sentinel/OfficeActivity/AuditLogs for this "
                "alert type. Try hunt_query or mde_advanced_hunt against DeviceEvents/"
                "DeviceProcessEvents for the alert's OWN time window (no device filter — "
                "search fleet-wide for the matching PowerShell activity) to recover the "
                "real device and command line before concluding anything from an empty "
                "cloud-side result."
            )
        elif not (device_name or "").strip():
            # HOST-LESS alert — no device at all, not merely an unresolved one. The
            # branch below is written for "a host exists but its machineId didn't
            # resolve" and steers at MDE, which has nothing whatsoever for an alert
            # with no endpoint. DEMO-108121 ('Rare and potentially high-risk Office
            # operations', actor NT SERVICE\MSExchangeAdminApiNetCore, no device)
            # hunted SecurityEvent — empty workspace-wide — got the empty-source
            # error, and the errored-hunt gate correctly refused the auto-close
            # because nothing had returned data. The seven siblings that closed FP
            # had gone to OfficeActivity and got 17 rows. The difference was table
            # choice, and nothing told it which table to pick.
            _s += (
                " NOTE: this alert has NO DEVICE — it is an Office 365 / identity / cloud "
                "event, not an endpoint one. MDE holds NOTHING for it: do not hunt MDE, and "
                "do not read an empty MDE or SecurityEvent result as benign. Hunt the table "
                "the alert actually comes from, via hunt_query with source='sentinel' — "
                "OfficeActivity for Exchange/SharePoint/Teams admin operations, SigninLogs "
                "or AuditLogs for identity, the vendor *_CL feed for a SaaS alert. Name the "
                "operation and the acting account in `intent`. If your first table returns "
                "nothing, that is a signal you picked the wrong table, NOT that nothing "
                "happened — try the right one before concluding anything."
            )
            # For Office/Exchange specifically there is a deterministic tool, and it
            # matters WHICH projection is used: a free-written OfficeActivity query
            # returns the operation name and little else, and DEMO-108121 refused to
            # decide on exactly that ("no critical details like the target mailbox,
            # specific parameters modified, or the result status").
            if "conditional access" in (alert_name or "").lower():
                # The audit record stores the whole policy as JSON old/new, so the
                # change is unreadable without a diff — DEMO-108039 hunted, found
                # nothing and concluded the update "may be a false positive or a
                # misconfiguration"; DEMO-108099 tried three times and got 0 rows.
                # State the timestamp LITERALLY, same reason as the host-binding block
                # below: described rather than printed, the model invents one. Anchoring
                # matters more here than anywhere — DEMO-108099 hunted an unanchored 24h,
                # got 0 rows, and escalated for "missing evidence about the policy
                # change"; the same window centred on the alert returns 13 rows.
                _ca_t = str(
                    (alert or {}).get("alertCreationTime")
                    or (alert or {}).get("firstEventTime")
                    or (alert or {}).get("lastEventTime")
                    or (evidence or {}).get("alert_time")
                    or ""
                ).strip()
                _ca_when = (f' Pass alert_time="{_ca_t}" EXACTLY as written — do not '
                            "reformat it and do not substitute one of your own; the "
                            "window is centred on it." if _ca_t else "")
                _s += (
                    " This is a Conditional Access alert: use hunt_ca_policy_change "
                    "(NOT hunt_signin, NOT a raw AuditLogs query) — it DIFFS the policy "
                    "and returns which principals entered or left each exclusion list "
                    "plus the grant controls and enabled state on both sides. Judge by "
                    "that diff: an exclusion changed while MFA remains in the grant "
                    "controls and the policy stays enabled is a scoped change; MFA "
                    "removed, the policy disabled, or a broad group/role excluded is "
                    "the weakening this alert exists to catch." + _ca_when +
                    " If it still returns 0 rows, that is a WINDOW problem, not an "
                    "answer: widen window_hours and retry, and drop the actor filter "
                    "before you conclude anything. AuditLogs holds ~118M rows over 6 "
                    "months — the change named on the ticket is in there. Never treat "
                    "an empty CA hunt as evidence the change was benign, and never "
                    "escalate for 'missing evidence' without having widened at least "
                    "once."
                    " A SCOPED change that also REVERTS within the alert window (the "
                    "exclusion added, then removed again hours later, same day) is NOT "
                    "thereby proven authorised — reverting quickly is exactly what a "
                    "compromised account covering its tracks looks like too. 'Scoped "
                    "and reverted' rules out an ONGOING weakening; it says nothing about "
                    "INTENT. Do NOT auto-close FP on 'this looks like routine admin/"
                    "troubleshooting work' for a scoped-and-reverted change — the named "
                    "actor plus a plausible business reason plus a justification that "
                    "would settle it is REQUEST_JUSTIFICATION, not AUTO_CLOSED_FP. A "
                    "near-identical sibling of one such ticket, same user, same shape, "
                    "minutes later, correctly asked the actor instead — "
                    "REQUEST_JUSTIFICATION is the correct call here."
                )
            if "office" in (alert_name or "").lower() or "exchange" in (alert_name or "").lower():
                _s += (
                    " This is an Office/Exchange admin alert: use hunt_office (NOT "
                    "hunt_query) — it returns the target object, the parameters changed, "
                    "the result status and ExternalAccess, which is what decides whether "
                    "an admin operation was routine. Judge by the TARGET and the "
                    "PARAMETERS: Exchange system mailboxes (arbitration, soft-deleted) "
                    "changed by a service app-pool account with ExternalAccess=false is "
                    "routine platform housekeeping; a change to a PERSON's mailbox that "
                    "adds forwarding, delegation or external access is not."
                )
        else:
            _s += (
                " NOTE: an MDE machineId could NOT be resolved for this host — treat that as "
                "INCONCLUSIVE, not as proof it is unonboarded. macOS/Linux and short-hostname devices "
                "frequently fail the name lookup while being fully Defender-onboarded. Do NOT state "
                "'not onboarded', 'unsupported OS', or 'no EDR telemetry' as fact. If the alert itself "
                "carries endpoint telemetry (file/process/registry/logon events), the host IS producing "
                "Defender data — reason from that. An MDE hunt by device name may still work; an "
                "empty/failed hunt is inconclusive, never proof of benign."
            )
        lines.append(_s)
    elif _src == "mde":
        lines.append(
            "DATA SOURCE — MDE/Defender: use mde_get_alert, mde_get_timeline, and mde_advanced_hunt "
            "(Device* tables). sentinel_run_kql/Sentinel tables generally won't have this endpoint "
            "alert."
        )
    if sha256:
        lines.append(f"File hash (SHA256): {sha256}")
    if tactics:
        lines.append(f"MITRE tactics: {', '.join(tactics)}")
    if incident_url:
        lines.append(f"Incident URL: {incident_url}")
    if is_test_device:
        lines.append("NOTE: This is a known test/red-team device — never auto-close, always NEEDS_L2.")

    # Network alert that names a private source IP. The hostname printed on these
    # tickets is frequently NOT the machine that owns the address — it is bound
    # upstream by time proximity, not by the IP. Ten sibling beaconing alerts sharing
    # one source IP each named a DIFFERENT device and not one was the real owner
    # (DEMO-107982 named WKSTN-8271; 10.0.0.49 belonged to srv-app-49.example.com,
    # which made 761 connections to the flagged destination while the named host made
    # none). Hunting the ticket's host returns 0 rows and looks like a clean result.
    import re as _re
    import ipaddress as _ipa

    def _is_priv(_v: str) -> bool:
        try:
            return _ipa.ip_address(_v).is_private
        except ValueError:
            return False

    _ev_ip = " ".join(str((evidence or {}).get(k) or "")
                      for k in ("source_ip", "local_ip", "src_ip"))
    _priv_ips = [ip for ip in dict.fromkeys(
        _re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", f"{alert_name} {_ev_ip}")) if _is_priv(ip)]
    if _priv_ips:
        # State the timestamp LITERALLY. Left to describe it ("this alert's time") the
        # model invented one — DEMO-107982's re-run passed alert_time=2024-07-30, two
        # years off, which lands outside DeviceNetworkInfo's 30d retention and comes
        # back "unresolvable" for a lookup that resolves cleanly at the real time.
        _evt_t = str(
            (alert or {}).get("alertCreationTime")
            or (alert or {}).get("firstEventTime")
            or (alert or {}).get("lastEventTime")
            or (evidence or {}).get("alert_time")
            or ""
        ).strip()
        _when = (f'alert_time="{_evt_t}"' if _evt_t
                 else "alert_time omitted (this alert carries no usable timestamp)")
        lines.append(
            f"HOST BINDING UNVERIFIED — this alert names private IP(s) "
            f"{', '.join(_priv_ips[:3])}. The device on this ticket may NOT be the machine "
            f"that held that address. Call hunt_ip_owner (ip=\"{_priv_ips[0]}\", {_when}) "
            "BEFORE attributing any activity, and hunt whatever device it returns rather "
            "than the one named above. Pass that timestamp EXACTLY as written — do not "
            "reformat it and do not substitute one of your own; the lookup is anchored on "
            "it and a wrong date returns nothing. If it returns more than one device, or "
            "none, the host is NOT established: do NOT attribute the traffic to any host "
            "and do NOT auto-close — an empty hunt against an unconfirmed host is not "
            "evidence of benign, it is evidence you asked the wrong machine."
        )

    # ── Defender/EDR native verdict (independent of VirusTotal) ───────────
    ev = evidence or {}
    if ev.get("host_ambiguous"):
        _cands = ev.get("candidate_devices") or []
        lines.append(
            "WARNING — HOST NOT UNIQUELY IDENTIFIED: this NRT alert has no entities, and its "
            "host could NOT be bound from the alert itself. Any host below is a GUESS from a "
            f"time-window hunt ({len(_cands) or 'multiple'} candidate(s)"
            + (f": {', '.join(_cands[:6])}" if _cands else "") + ") and is frequently WRONG "
            "(a high-frequency automation host gets grabbed as the 'nearest' event). Do NOT "
            "attribute any host's activity, command line, or reputation to this alert. This "
            "verdict MUST be NEEDS_L2 for manual host attribution — do NOT AUTO_CLOSE even if "
            "the incident shows a prior human closure or the guessed host looks benign; that "
            "closure may belong to a DIFFERENT alert grouped in the same incident."
        )
        # WHAT ran, even though we cannot say WHERE. The host is unattributable; the
        # command text is still the only description of the activity this ticket exists
        # for, and without it the agent reasons about a blank subject — DEMO-108429 and
        # its whole family render as "Device: Unknown / User: Unknown / command line not
        # present". Listing them lets the agent recognise a known script (the IronWatch
        # scan, a patch job) and SAY so in its comment, which is what an analyst needs,
        # while the escalation above still stands.
        _acmds = ev.get("candidate_commands") or []
        if _acmds:
            lines.append(
                "  Recovered invocations in the same window (UNATTRIBUTED — these came "
                "from a time-window hunt, NOT from this alert's own evidence, so they may "
                "belong to a different host or a different alert entirely):"
            )
            for _c in _acmds[:8]:
                lines.append(f"    - {str(_c)[:300]}")
            lines.append(
                "  Use these to say WHAT the activity looks like — if you recognise a "
                "known internal script or scheduled job, name it in your reasoning so the "
                "analyst does not have to rediscover it. They are NOT grounds to close: "
                "you cannot show any of them belongs to this alert, and the host is still "
                "unattributed, so the verdict stays NEEDS_L2."
            )
    # Grouped multi-host incident (privesc/CloudTrail). Fires ONLY when the incident
    # genuinely spans >1 host AND the host is not ambiguous — single-host and other
    # alert types never see this. The primary host is rendered inline elsewhere; here
    # we name the CO-hosts so the agent investigates each instead of clearing the
    # incident from the primary alone (DEMO-106765). Consistent with the privesc rule:
    # FP requires POSITIVE exculpatory evidence — extended to EVERY host.
    _addl = [h for h in (ev.get("additional_hosts") or []) if h]
    if _addl and not ev.get("host_ambiguous"):
        lines.append(
            f"MULTI-HOST INCIDENT — this incident groups {len(_addl) + 1} hosts. The primary "
            f"host above is only ONE of them; the other{'s' if len(_addl) > 1 else ''}: "
            + ", ".join(_addl[:10])
            + (f" (+{len(_addl) - 10} more)" if len(_addl) > 10 else "")
            + ". You MUST investigate EACH co-host before any verdict — run "
            "scg_get_entity_context and a hunt (hunt_process / hunt_logons) on it. Per the "
            "privilege-escalation rule, auto-closing FP requires POSITIVE exculpatory evidence "
            "for EVERY host: a co-host you cannot assess (no telemetry / failed hunt) or that "
            "shows unexplained activity means NEEDS_L2, not FP. Do NOT reach a benign verdict "
            "from the primary host alone."
        )
        # Service-process alerts satisfy "every host" differently, and without this the
        # rule is unsatisfiable: these group 138-151 hosts, so per-host hunting can never
        # finish. DEMO-107772 hunted, wrote "the hunt_service results confirmed that all
        # flagged service processes are legitimate, signed, and prevalent across the
        # fleet", and escalated anyway — "130+ hosts remain unchecked … a procedural
        # escalation due to the scale of the incident, not a technical indicator". It had
        # the evidence and the rule would not let it use it.
        # The question these alerts ask is about the BINARY, not per-host behaviour, and
        # hunt_service answers it fleet-wide by construction: it counts the devices
        # running each binary across the whole estate, co-hosts included. Scoped to
        # process_check, which only fires on process-list alerts (>=4 distinct
        # processes) — privesc/identity/cloud/network alerts never see this and keep the
        # strict per-host rule.
        if (ev.get("process_check") or {}).get("distinct"):
            lines.append(
                "  EXCEPTION for this alert — it flags SERVICE PROCESSES, and the question "
                "is whether those BINARIES are legitimate, not what each host did. "
                "hunt_service already answers that across the entire fleet: its device "
                "counts span these co-hosts. If every flagged process comes back TRUSTED, "
                "that IS positive exculpatory evidence for every host and you may close FP "
                "— do NOT hold out for per-host hunts you cannot complete, and do NOT "
                "escalate on host count alone. Escalate only if a process is UNTRUSTED, or "
                "a specific co-host shows unexplained activity of its own."
                "\n  This exception is COMPLETE, not partial — do not add a second, unstated "
                "requirement on top of it. Real tickets escalated anyway with reasoning "
                "shaped exactly like this: 'the processes are trusted, but that only confirms "
                "the BINARY is legitimate, not that no unexplained activity is happening on "
                "each host' (both against L1 verdicts of FP). That reasoning is WRONG for "
                "this alert type specifically: a 'rare process as a service' alert exists to "
                "ask exactly one question — is this rare service binary malicious or "
                "masquerading software — and TRUSTED answers it in full. 'Something else "
                "unrelated might be happening on this host' is not evidence of anything; it "
                "is true of every host, always, and demanding it be ruled out is how this "
                "exact exception gets talked past every time. If your own draft reasoning "
                "uses the phrase 'only confirms/addresses X, not Y' to hold out after every "
                "flagged process comes back TRUSTED, stop — Y is not what this alert is "
                "asking, and the exception above already applies in full."
            )
    # Grouped multi-USER incident — the user-side analogue of the co-host block above.
    # A rule that aggregates SingleAlert emits ONE alert covering every matched row, so
    # the acting user named above can be just the first of several. On DEMO-107416 the
    # agent reasoned only about accounts[0] because the other account was never passed
    # to it; L1 then investigated the OTHER user, and the ticket closed FP with one
    # user's uploads never examined by anyone. EMPTY for single-user alerts.
    _addl_u = [u for u in (ev.get("additional_users") or []) if u]
    if _addl_u:
        lines.append(
            f"MULTI-USER INCIDENT — this incident groups {len(_addl_u) + 1} users. The acting "
            f"user above is only ONE of them; the other{'s' if len(_addl_u) > 1 else ''}: "
            + ", ".join(str(u) for u in _addl_u[:10])
            + (f" (+{len(_addl_u) - 10} more)" if len(_addl_u) > 10 else "")
            + ". Each is a SEPARATE instance of the same detection. Investigate EACH user "
            "(scg_get_entity_context, and a hunt where telemetry exists) and name EVERY user "
            "in your reasoning and comment — a benign explanation for one user does NOT clear "
            "the others. A user you cannot assess means NEEDS_L2, not FP."
        )
    # Identity GRANT alert (role/group membership added). These carry TWO principals with
    # OPPOSITE roles — whoever performed the grant, and the account that received it — but
    # Sentinel's "Involved Users" names only the RECIPIENT. Verified on DEMO-106406:
    # user_name = the account ADDED, additional_users = [], while the grant was actually
    # performed by a different admin who appears nowhere in the alert.
    # So the "acting user" above is the wrong person by construction. Say so plainly rather
    # than let the model narrate the recipient as the actor.
    if is_privilege_grant_alert(alert_name):
        lines.append(
            "IDENTITY GRANT — this alert reports privileged access being GRANTED. It "
            "involves two DIFFERENT principals: the one who PERFORMED the grant, and the "
            "account that RECEIVED it. The user named above is the RECIPIENT — the account "
            "that was added. It is NOT the actor, and the acting principal is usually NOT "
            "present in this alert at all. Do NOT describe the recipient as having "
            "performed the action, and do NOT request a business justification from them — "
            "they may have done nothing."
        )
        if is_local_group_alert(alert_name):
            # This is a Windows local-group change, not an Entra grant. The
            # grantor/recipient live in MDE DeviceEvents (InitiatingProcessAccountName
            # / AccountName), not AuditLogs — hunt_identity_grant queries the wrong table
            # entirely and, with no recipient to scope on, returns unrelated tenant-wide
            # Entra grants that look like "evidence" but say nothing about this alert.
            lines.append(
                "  -> This is a LOCAL Windows group change (endpoint plane), NOT an Entra "
                "grant — do NOT call hunt_identity_grant, it queries AuditLogs and cannot "
                "see this event. Call hunt_events with device=\"" + (device_name or "") +
                "\" and action_type=\"UserAccountAddedToLocalGroup\" (or "
                "\"UserAccountRemovedFromLocalGroup\") to resolve the row: AccountName is "
                "the RECIPIENT, InitiatingProcessAccountName is the GRANTOR who ran the "
                "change. Once the grantor is known, remember that ATTRIBUTION IS NOT "
                "AUTHORISATION — naming them does not make the change sanctioned, and "
                "their own alert history is not evidence about it. A change with an "
                "unexplained purpose is REQUEST_JUSTIFICATION directed at the GRANTOR; a "
                "self-grant, or a change you cannot attribute at all, is NEEDS_L2."
            )
        else:
            # Until now this block ended by telling the agent to emit NEEDS_L2 when it could
            # not identify the actor — and there was no tool that could. DEMO-106406 duly ran
            # hunt_query, got 50 rows, reported "acting principal, target group name and
            # target user were missing", and escalated. The fields were there; the projection
            # was wrong. Name the tool, and state the timestamp literally (described rather
            # than printed, the model invents one).
            _ig_t = str(
                (alert or {}).get("alertCreationTime")
                or (alert or {}).get("firstEventTime")
                or (alert or {}).get("lastEventTime")
                or (evidence or {}).get("alert_time")
                or ""
            ).strip()
            _ig_when = (f' alert_time="{_ig_t}" (pass it EXACTLY as written)' if _ig_t
                        else " (no usable alert timestamp on this ticket)")
            lines.append(
                f"  -> Call hunt_identity_grant with recipient=\"{(ev.get('user_name') or '').strip()}\","
                f"{_ig_when} to resolve the acting principal, the recipient and the roles "
                "granted. Do NOT use hunt_query for this: the role name is not in "
                "TargetResources.displayName (empty for roles) but in modifiedProperties "
                "under Role.DisplayName, so a free-written query returns rows with the "
                "deciding fields missing. Once the grantor is known, remember that "
                "ATTRIBUTION IS NOT AUTHORISATION — naming them does not make the grant "
                "sanctioned, and their own alert history is not evidence about it. A "
                "delegated grant with an unexplained purpose is REQUEST_JUSTIFICATION "
                "directed at the GRANTOR; a self-grant, or a grant you cannot attribute at "
                "all, is NEEDS_L2."
            )
    # AWS/SSM identity — label the IAM role explicitly so the agent never mistakes a
    # name embedded in the role for the acting user (DEMO-107147: "…-charlie-role" read
    # as user "charlie"). The actor is `user_name` above / the ARN session principal.
    if ev.get("session_issuer"):
        lines.append(
            f"AWS IAM role (a ROLE, NOT a person — do NOT derive a username from this "
            f"name; the actor is the user above): {ev['session_issuer']}"
        )
    if ev.get("user_arn"):
        lines.append(f"AWS session ARN (actor = the part after the last '/'): {ev['user_arn']}")
    if ev.get("threat_name"):
        lines.append(f"Defender detection: {ev['threat_name']}  (a NAMED AV detection — a real threat classification, independent of VirusTotal)")
    if ev.get("category"):
        lines.append(f"Alert category: {ev['category']}")
    if ev.get("remediation_status"):
        lines.append(f"Remediation status: {ev['remediation_status']}  (Defender already acted on this)")
    if ev.get("determination"):
        lines.append(f"Determination: {ev['determination']}")
    _rel = ev.get("related_detections") or []
    if _rel:
        lines.append("Related detections on this device:")
        for r in _rel[:8]:
            lines.append(f"  - {r}")

    # ── Key evidence (pre-fetched) — surfaced prominently ─────────────────
    cmds = ev.get("command_lines") or []
    if ev.get("file_name"):
        lines.append(f"File name: {ev['file_name']}")
    if ev.get("file_path"):
        lines.append(f"File path: {ev['file_path']}")
    if ev.get("initiating_process"):
        lines.append(f"Initiating process: {ev['initiating_process']}")
    if ev.get("account_name"):
        lines.append(f"Process account: {ev['account_name']}")
    # Raw command lines are ALWAYS shown (capped) — for command-based alerts (LOLBin,
    # malware) the command content is the evidence and must never be summarized away.
    if cmds:
        lines.append(f"\nProcess command line{'s' if len(cmds) > 1 else ''} (KEY EVIDENCE — reason from these):")
        for c in cmds[:12]:
            lines.append(f"  $ {c}")
        if len(cmds) > 12:
            lines.append(f"  … {len(cmds) - 12} more")
        # A PARAMETERISED destination is unresolved evidence. The captured text is the
        # script's shape, not where it went: `Invoke-RestMethod -Uri "$ApiUrl/api/..."`
        # looks byte-identical whether $ApiUrl is the corporate server or attacker
        # infrastructure. That is the one gap an exact-command precedent cannot close,
        # and it is the first thing an analyst asks. Only fires when a variable actually
        # appears inside a URL/URI argument, so ordinary command lines are unaffected.
        # `(?:env:)?` because PowerShell environment variables carry a colon —
        # `$env:ServerEndpoint` is the same unresolved-destination case as `$ApiUrl`.
        _param = [c for c in cmds
                  if re.search(r"(?:-Uri|-Url|https?://|\bUri\s*=)[^\s]*\$(?:env:)?\w+", str(c), re.I)
                  or re.search(r"\$(?:env:)?\w*(?:url|uri|server|endpoint|host)\w*\b", str(c), re.I)]
        if _param and (device_name or "").strip():
            lines.append(
                "  NOTE — the destination above is a VARIABLE, not a value, so this "
                "command line does NOT tell you where the script connected; an identical "
                "command can reach a completely different host. Call hunt_script_egress "
                f"(device=\"{device_name}\") to resolve the real destinations before "
                "concluding. Destinations consistent with what the script claims to do "
                "corroborate a benign reading; an unexpected external host or a bare IP "
                "does not."
            )
    # Multi-process hunting alerts additionally get the DETERMINISTIC classification
    # of ALL distinct processes (compact) — set only for genuine service-list alerts,
    # so it augments rather than replaces the raw evidence above.
    pc = ev.get("process_check")
    if pc and pc.get("distinct"):
        from edr_triage.service_allowlist import summarize_check
        lines.append("\nService-process check (all distinct processes classified): "
                     + summarize_check(pc))
        if pc.get("unknown"):
            more = f" (+{pc['unknown_more']} more)" if pc.get("unknown_more") else ""
            lines.append("  UNKNOWN — verify these before any FP: " + ", ".join(pc["unknown"]) + more)
            # Point at the ONE tool that can clear these. Left to its own devices the
            # agent reaches for hunt_process, which cannot answer: a service starts at
            # boot and never re-launches in-window, so it returns 0 rows however wide
            # the window (DEMO-107943 burned 27 calls on this, DEMO-107772 13, and both
            # escalated a family L1 closes FP).
            lines.append(
                "  -> Call hunt_service with EXACTLY these names to resolve them by "
                "Authenticode signer and fleet prevalence. Do NOT use hunt_process for "
                "service processes: they start at boot and emit no launch event inside "
                "any window, so 0 rows there is a property of services, not evidence "
                "about the binary — do not retry it and do not escalate on it. A "
                "trusted vendor signature on a normal vendor path across many devices "
                "IS the positive exculpatory evidence, and is enough to auto-close. "
                "Report each process EXACTLY as its `verdict` field states — a TRUSTED "
                "row is trusted whoever signed it (Lenovo, Intel, Dell, McAfee, Flexera, "
                "eMudhra and the like are trusted publishers, the same as Microsoft). "
                "Calling a TRUSTED row 'untrusted' because the signer is not Microsoft "
                "is a factual error about the evidence in front of you, not a cautious "
                "reading of it.")

    # Deterministic MDE process telemetry (pipeline-resolved) — the flagged processes'
    # hash + on-disk vendor, so the agent VERIFIES them from real telemetry instead of
    # guessing or escalating "no telemetry". Present iff the device is MDE-onboarded.
    mpd = ev.get("mde_process_details")
    if mpd:
        lines.append("\nMDE process telemetry (KEY EVIDENCE — verified hash + vendor for the flagged "
                     "processes; reason from THIS, not from any empty Sentinel hunt):")
        for r in mpd[:20]:
            fn = r.get("FileName", "?")
            sha = (r.get("SHA256") or "").strip()
            vend = (r.get("ProcessVersionInfoCompanyName") or r.get("ProcessVersionInfoProductName") or "").strip()
            path = (r.get("FolderPath") or "").strip()
            ndev = r.get("Devices")
            seen = f"  seen_on={ndev}_devices" if ndev else ""
            lines.append(
                f"  - {fn}  vendor={vend or '(NONE — unsigned / no version info; scrutinize)'}  "
                f"sha256={sha or '(none)'}  path={path or '?'}{seen}")
        lines.append(
            "  How to judge: a recognized software vendor (CompanyName/ProductName) seen across many "
            "devices + a normal Program Files path is strong benign evidence; run vt_lookup_hash on "
            "these REAL SHA256s to confirm. A blank vendor, a user/Temp/ProgramData path, or a hash VT "
            "flags => do NOT auto-close, escalate. Do not re-hunt for these — the telemetry is already here.")

    # Netskope cloud-malware, bound from Netskope_Alerts_CL (don't re-query it).
    nm = ev.get("netskope_malware")
    if nm and nm.get("malware_name"):
        act = (nm.get("action") or "")
        blocked = any(t in act.lower() for t in ("block", "prevent", "quarantin"))
        lines.append(
            f"\nNetskope malware (KEY EVIDENCE — bound from Netskope_Alerts_CL, do NOT re-query): "
            f"{nm.get('malware_name')} ({nm.get('malware_type') or 'malware'}, sev {nm.get('severity') or '?'}) "
            f"| user={nm.get('user') or '?'} host={nm.get('hostname') or nm.get('device') or '?'} "
            f"| action={act or '?'} " + ("(BLOCKED/prevented)" if blocked else "(DETECTION ONLY — not confirmed blocked)")
            + (f" | sha256={nm['sha256']}" if nm.get("sha256") else ""))
        lines.append("  Malware is never auto-closed on detection alone; if action does not confirm a block, escalate (NEEDS_L2).")

    # Netskope UBA anomaly (Bulk Upload/Download), bound from Netskope_Alerts_CL. Given
    # deterministically because hand-written KQL against this custom-log table keeps
    # failing — on DEMO-107416 both attempts died on syntax errors, so the agent reached
    # its verdict with zero evidence and a 0.60 confidence cap.
    uba = ev.get("netskope_uba")
    if uba and uba.get("by_user"):
        _kind = uba.get("kind", "Upload").lower()
        lines.append(
            f"\nNetskope bulk-{_kind} detail (KEY EVIDENCE — bound from Netskope_Alerts_CL, "
            f"do NOT re-query it; hand-written KQL against this table fails): "
            f"{uba.get('event_count', 0)} event(s) across {uba.get('user_count', 0)} user(s).")
        for _u, _b in list((uba.get("by_user") or {}).items())[:10]:
            lines.append(
                f"  - {_u}: {_b.get('events', 0)} {_kind}(s)"
                + (f" | app={', '.join(_b.get('apps') or [])}" if _b.get("apps") else "")
                + (f" | page={', '.join((_b.get('pages') or [])[:2])}" if _b.get("pages") else "")
                + (f" | host={', '.join(_b.get('hosts') or [])}" if _b.get("hosts") else "")
                + (f" | file_type={', '.join((_b.get('file_types') or [])[:3])}" if _b.get("file_types") else "")
                + (f" | {_b['total_bytes']:,} bytes" if _b.get("total_bytes") else "")
                + (f" | src_ip={', '.join(_b.get('src_ips') or [])}" if _b.get("src_ips") else "")
                + (f" | device={_b['device_classification']}" if _b.get("device_classification") else "")
                + (f" | {_b.get('first_seen', '')} UTC" if _b.get("first_seen") else ""))
        lines.append(
            "  How to judge: this is a VOLUME anomaly, not a malware verdict — the question is "
            "whether the destination and the volume fit the user's role. A sanctioned corporate "
            "app on a managed device is weak-to-moderate benign evidence; an unsanctioned or "
            "personal-cloud/AI destination, an unmanaged device, or an archive/bulk file type is "
            "potential exfiltration. There is no telemetry here that establishes business intent, "
            "so an FP verdict needs a documented justification — otherwise escalate (NEEDS_L2) and "
            "ask the user(s) for justification. Address EVERY user listed above by name.")

    # Port-sweep FP allowlist verdict (SOC runbook — the deciding factor for these alerts).
    ps = ev.get("port_sweep_check")
    if ps and ps.get("port"):
        if ps.get("known_good"):
            lines.append(
                f"\nPort-sweep allowlist (KEY EVIDENCE): destination port {ps['port']} is on the SOC "
                f"known-good port-sweep list ({', '.join(ps.get('fp_ports', []))}) — documented "
                "expected/known-good infrastructure activity → FALSE POSITIVE. This is the deciding "
                "factor; the swept port being known-good overrides the generic high-severity escalation.")
        else:
            lines.append(
                f"\nPort-sweep allowlist (KEY EVIDENCE): destination port {ps['port']} is NOT on the "
                f"known-good list ({', '.join(ps.get('fp_ports', []))}) — possible reconnaissance → escalate (NEEDS_L2).")

    unsupported_os = alert.get("osPlatform", "").lower() in ("unknown", "unsupportedos", "")
    if unsupported_os and severity.upper() in ("HIGH", "CRITICAL"):
        lines.append("WARNING: UnsupportedOs flag — limited visibility, escalate if HIGH+ severity.")

    description = alert.get("_description", "")
    if description:
        lines.append(f"\nAlert description:\n{description[:1200]}")

    # ── Netskope data-source hint ─────────────────────────────────────────
    # Netskope alerts arrive via Sentinel with EMPTY structured entities (no
    # device/user/hash) — the real indicators live in the Netskope_Alerts_CL
    # custom-log table, NOT in the incident entities or SecurityAlert. Tell the
    # agent exactly where to look so it doesn't conclude "no data".
    if "netskope" in (alert_name or "").lower():
        _evt = ""
        if isinstance(alert, dict):
            _evt = str(alert.get("alertCreationTime") or alert.get("firstEventTime") or "").strip()
        # SCOPE the query to this alert's time window — Netskope_Alerts_CL holds EVERY
        # Netskope alert, so an unscoped query pulls unrelated rows for other users/
        # alerts and muddles attribution (DEMO-104375 mixed two users). Anchor on the
        # alert's event time when known, else a tight recent window.
        _time_filter = (
            f"| where TimeGenerated between (datetime('{_evt}') - 30m .. datetime('{_evt}') + 15m)"
            if _evt else "| where TimeGenerated > ago(2h)"
        )
        lines.append(
            "\nDATA SOURCE — Netskope: this alert's entities are NOT in the incident. "
            "Query Netskope_Alerts_CL via sentinel_run_kql for the actual indicators — but "
            "SCOPE it to THIS alert's time window (the table holds every Netskope alert; an "
            "unscoped query returns other users'/alerts' rows and muddles attribution). Example:\n"
            "  Netskope_Alerts_CL\n"
            "  | where alert_type_s == \"Malware\"\n"
            f"  {_time_filter}\n"
            "  | project TimeGenerated, user_s, userip_s, alert_name_s, activity_s, "
            "policy_s, device_s, srcip_s, dstip_s, malware_name_s, "
            "malware_severity_s, malware_type_s, app_name_s, detection_engine_s, scanner_result_s\n"
            "Reason only about rows inside this alert's window. If several distinct users "
            "appear (a genuine 'involving multiple users' alert), treat each separately — do "
            "not merge them into one host/user. "
            "NOTE: malware_name_s / scanner_result_s / alert_name_s are DETECTION NAMES "
            "(e.g. 'Trojan.Generic.38158348', 'CMD:Heur.BZC…'), NOT file hashes — never pass "
            "them to vt_lookup_hash. Only a real 64-hex SHA256 goes to vt_lookup_hash. "
            "Do not conclude 'no data' before querying Netskope_Alerts_CL."
        )

    lines.append(
        "\nInvestigate this alert. Your FIRST response must be a tool call — start with "
        "scg_get_entity_context for device and user (do not emit a verdict yet). "
        "vt_lookup_hash needs a REAL 64-hex SHA256 — never pass a process/file NAME (e.g. "
        "'foo.exe') or a detection name to it; that only errors. If you have process names but "
        "no hashes, obtain the SHA256 from an MDE hunt (hunt_process / DeviceProcessEvents) FIRST, "
        "then run vt_lookup_hash on the real hash. Run relevant KQL if needed. "
        "Emit final_verdict only once you have gathered evidence."
    )
    return "\n".join(lines)
