#!/usr/bin/env python3
"""Seed synthetic demo data for the RAPTOR open-source demo.

Populates the RAPTOR + Security Context Graph collections with fictional
"Northwind Securities" data so the console, triage queue, and AI-Memory pages
render fully without any real telemetry or credentials.

Idempotent: clears the demo collections, then re-inserts.

    python demo/seed_demo.py            # uses MONGODB_URI / MONGODB_DB (defaults: localhost / deepintel)

Timestamp types matter (matching how the app writes them):
  - edr_triage_processed / bedrock_usage  -> epoch float  (processed_at, ts)
  - eg_* (Beanie-backed)                  -> BSON datetime (created_at, ...)
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from pymongo import MongoClient

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB = os.getenv("MONGODB_DB", "deepintel")

NOW = datetime.now(timezone.utc)
NOW_TS = time.time()


def dt(days_ago: float) -> datetime:
    return NOW - timedelta(days=days_ago)


def fut(days_ahead: float) -> datetime:
    return NOW + timedelta(days=days_ahead)


def ts(days_ago: float) -> float:
    return NOW_TS - days_ago * 86400


# ── Fictional identity ──────────────────────────────────────────────────────
DEVICES = ["WKSTN-4471", "LAPTOP-2210", "WKSTN-8830", "SRV-APP-12", "LAPTOP-6654", "WKSTN-3390"]
USERS = ["alice.chen", "raj.patel", "sam.rivera", "jordan.lee", "chris.morgan", "taylor.singh"]

# (jira_key, alert_name, playbook, severity, tactics, triage_class, ai_class, conf,
#  l1_class, match, device, user, vt_verdict, days_ago)
ALERTS = [
    ("DEMO-1012", "Infostealer — Lumma Stealer",                 "malware",          "High",          ["Execution", "Collection"],       "URGENT",          "URGENT",          0.93, "URGENT",          True,  "LAPTOP-2210", "raj.patel",   "malicious", 0.05),
    ("DEMO-1011", "Suspicious Encoded PowerShell",               "privesc",          "High",          ["Execution"],                      "AUTO_CLOSED_FP",  "AUTO_CLOSED_FP",  0.86, "AUTO_CLOSED_FP",  True,  "WKSTN-4471",  "alice.chen",  "clean",     0.12),
    ("DEMO-1010", "CloudTrail — AssumedRole privilege escalation","generic",         "High",          ["Privilege Escalation"],           "NEEDS_L2",        "NEEDS_L2",        0.48, "NEEDS_L2",        True,  "SRV-APP-12",  "jordan.lee",  "unknown",   0.25),
    ("DEMO-1009", "Remote tool — AnyDesk detected",              "block_tool",       "Low",           ["Command and Control"],            "AUTO_CLOSED_FP",  "AUTO_CLOSED_FP",  0.90, "AUTO_CLOSED_FP",  True,  "WKSTN-8830",  "sam.rivera",  "unknown",   0.4),
    ("DEMO-1008", "Password spray — Entra ID",                   "credential_access","High",          ["Credential Access"],              "NEEDS_L2",        "NEEDS_L2",        0.55, "NEEDS_L2",        True,  "LAPTOP-6654", "taylor.singh","unknown",   0.6),
    ("DEMO-1007", "Suspicious curl download",                    "endpoint_process", "Medium",        ["Command and Control"],            "AUTO_CLOSED_TP",  "AUTO_CLOSED_TP",  0.81, "AUTO_CLOSED_TP",  True,  "WKSTN-3390",  "chris.morgan","malicious", 1.1),
    ("DEMO-1006", "Netskope — failed login",                     "netskope",         "Informational", ["Initial Access"],                 "AUTO_CLOSED_FP",  "AUTO_CLOSED_FP",  0.88, "AUTO_CLOSED_FP",  True,  "LAPTOP-2210", "raj.patel",   "unknown",   1.6),
    ("DEMO-1005", "LOLBin abuse — certutil download",            "endpoint_process", "Medium",        ["Defense Evasion"],                "NEEDS_L2",        "AUTO_CLOSED_FP",  0.62, "NEEDS_L2",        False, "WKSTN-4471",  "alice.chen",  "clean",     2.2),
    ("DEMO-1004", "Reverse shell — meterpreter signature",       "reverse_shell",    "High",          ["Execution", "Command and Control"],"URGENT",         "URGENT",          0.91, "URGENT",          True,  "SRV-APP-12",  "jordan.lee",  "malicious", 3.1),
    ("DEMO-1003", "Ransomware behavior detected",                "malware",          "High",          ["Impact"],                         "AUTO_CLOSED_TP",  "AUTO_CLOSED_TP",  0.84, "AUTO_CLOSED_TP",  True,  "WKSTN-8830",  "sam.rivera",  "malicious", 4.0),
    ("DEMO-1002", "Suspicious PowerShell — download cradle",     "privesc",          "Medium",        ["Execution"],                      "AUTO_CLOSED_FP",  "NEEDS_L2",        0.58, "AUTO_CLOSED_FP",  False, "LAPTOP-6654", "taylor.singh","clean",     5.5),
    ("DEMO-1001", "Lateral movement — PsExec",                   "lateral_move",     "High",          ["Lateral Movement"],               "NEEDS_L2",        "NEEDS_L2",        0.66, "NEEDS_L2",        True,  "WKSTN-3390",  "chris.morgan","unknown",   6.8),
]

MITRE = {
    "Execution": "T1059", "Privilege Escalation": "T1548", "Credential Access": "T1110",
    "Command and Control": "T1219", "Defense Evasion": "T1140", "Impact": "T1486",
    "Collection": "T1119", "Initial Access": "T1078", "Lateral Movement": "T1021",
}


def _sha(seed: str) -> str:
    import hashlib
    return hashlib.sha256(seed.encode()).hexdigest()


_VERDICT_LABEL = {
    "AUTO_CLOSED_FP": "False Positive — auto-closed",
    "AUTO_CLOSED_TP": "True Positive — auto-closed",
    "NEEDS_L2": "Needs L2 review",
    "URGENT": "Urgent — escalated",
}


def build_comment(name, cls, conf, pb, sev, tactics, dev, user, vt) -> str:
    """The wiki-markup comment RAPTOR posts to the Jira ticket (same string that
    is stored on the record and rendered in the console's Jira panel)."""
    techs = ", ".join(f"{t} ({MITRE.get(t, '?')})" for t in tactics)
    vt_line = {
        "malicious": "41/72 engines flagged — verdict MALICIOUS",
        "clean": "0/72 engines flagged — verdict CLEAN",
        "unknown": "no hash / no reputation data",
    }.get(vt, "no data")
    if cls == "AUTO_CLOSED_FP":
        rec = "Auto-closed as a false positive. No action required."
    elif cls == "AUTO_CLOSED_TP":
        rec = "Confirmed malicious — device remediated by EDR. Verify containment."
    elif cls == "URGENT":
        rec = "Escalated to on-call. Isolate the device and rotate the user's credentials."
    else:
        rec = "Insufficient signal for an automated decision — routed to L2 for review."
    return (
        f"h2. RAPTOR triage — {_VERDICT_LABEL.get(cls, cls)}\n"
        f"*Confidence:* {conf:.2f}    *Playbook:* {pb}    *Severity:* {sev}\n"
        "\n"
        "h3. Evidence\n"
        f"* Device: {dev}\n"
        f"* User: {user}@example.com\n"
        f"* MITRE ATT&CK: {techs}\n"
        f"* VirusTotal: {vt_line}\n"
        "\n"
        "h3. Recommendation\n"
        f"* {rec}\n"
        "\n"
        "{noformat}\n"
        "Data-sovereignty note: device/user/command-line identifiers were tokenized\n"
        "before any external-LLM call and restored before tool execution.\n"
        "{noformat}"
    )


def _short_hash(sha: str) -> str:
    return (sha[:8] + "…" + sha[-4:]) if sha else ""


def _tc(name: str, args: str, result: str) -> dict:
    """One ReAct tool call, in the shape the console renders (name + string args + result)."""
    return {"name": name, "args": args, "result": result}


def agent_trace(key, name, pb, sev, tactics, ai_cls, conf, dev, user, vt, sha):
    """Produce a realistic ReAct trace (numbered-markdown reasoning + tool calls) for one
    alert — the same shape Mistral Large 3 / Gemini emit through the agent loop: a short
    lead, evidence-linked numbered findings with **bold** claims and `backticked`
    artifacts, then a verdict finding. Reflects the MODEL's own verdict (ai_cls)."""
    upn = f"{user}@example.com"
    h = _short_hash(sha)
    mitre = ", ".join(f"{t} ({MITRE.get(t, '?')})" for t in tactics)
    fp, tp = ai_cls == "AUTO_CLOSED_FP", ai_cls == "AUTO_CLOSED_TP"
    urg, l2 = ai_cls == "URGENT", ai_cls == "NEEDS_L2"
    ctx = _tc("scg_get_entity_context", f"device='{dev}', user='{upn}'",
              "device onboarded 41d; 2 prior alerts (both FP); user in standard group, no VIP/exec flag")
    calls = [ctx]
    R = []

    if pb == "malware" and (urg or tp):
        calls.append(_tc("vt_lookup_hash", f"sha256='{h}'",
                         "41/72 malicious — family Lumma/Amadey" if vt == "malicious" else "no reputation data"))
        calls.append(_tc("mde_get_timeline", f"device='{dev}', window_hours='3'",
                         "file write → process create → outbound TLS to 3 external IPs within 90s"))
        calls.append(_tc("scg_recall", f"alert_type='malware', device='{dev}'", "0 exculpatory precedents"))
        R = [
            f"**VirusTotal** — `{h}` is flagged **41/72**, consistently attributed to the **Lumma infostealer** family. High-confidence malicious, not a heuristic-only hit.",
            f"**Native EDR verdict** — Defender recorded a `Malware` classification with a *quarantined* remediation status on `{dev}`. Per policy the native EDR verdict is weighted at least as heavily as VT, and it agrees here.",
            f"**Behavior** — the device timeline shows `file-write → process-create → outbound TLS` to three external IPs inside 90 seconds, consistent with stealer staging and C2 check-in ({mitre}).",
            "**Precedents** — no exculpatory precedent for this hash or family on this host; the actor is on no allowlist for this activity.",
            f"**Verdict: URGENT.** Confirmed infostealer with live C2 egress on an active endpoint — isolate `{dev}` and rotate `{upn}`'s credentials. Confidence {conf:.2f}." if urg else
            f"**Verdict: AUTO_CLOSED_TP.** Malicious and already contained by EDR; recording the true-positive and flagging for containment verification. Confidence {conf:.2f}.",
        ]
    elif pb == "reverse_shell":
        calls.append(_tc("vt_lookup_hash", f"sha256='{h}'", "38/70 malicious — Meterpreter/Metasploit stager"))
        calls.append(_tc("hunt_network", f"device='{dev}', window_hours='2'",
                         "established TCP to 45.-redacted-:4444, 3 keepalives in 6 min"))
        calls.append(_tc("hunt_process", f"device='{dev}', process_name='powershell'",
                         "encoded one-liner spawning `cmd` child; parent = winword.exe"))
        R = [
            "**Signature** — the detection matches a **Meterpreter reverse-shell** stager; VirusTotal corroborates at **38/70**.",
            "**Network** — `hunt_network` confirms an *established* outbound session to a non-corporate host on `:4444` with periodic keepalives — a live C2 channel, not a scan artefact.",
            "**Execution chain** — `winword.exe → powershell.exe (encoded) → cmd.exe`: a document-macro delivery path ({0}).".format(mitre),
            f"**Verdict: URGENT.** Active interactive C2 on `{dev}`. Contain the host immediately and pull `{upn}`'s recent auth. Confidence {conf:.2f}.",
        ]
    elif pb == "privesc" and fp:
        calls.append(_tc("hunt_process", f"device='{dev}', process_name='powershell'",
                         "1 match: scheduled task `FIN-MacroSign` under SYSTEM, signed by corp cert"))
        calls.append(_tc("scg_recall", f"alert_type='privesc', device='{dev}'",
                         "EXACT COMMAND MATCH — DEMO-0904, closed FP by analyst (macro-signing job)"))
        R = [
            "**Command** — the encoded PowerShell decodes to the finance **macro-signing scheduled task** (`FIN-MacroSign`), running as SYSTEM and signed by the corporate code-signing certificate.",
            "**Precedent** — SCG returns an **EXACT COMMAND MATCH** (DEMO-0904) previously adjudicated **False Positive** by a named analyst for this same recurring job — direct evidence about this specific activity, not a same-type analogy.",
            "**Corroboration** — the parent chain and signer match the known-good task; no lateral movement or credential access followed in the window.",
            f"**Verdict: AUTO_CLOSED_FP.** Recurring, signed, analyst-adjudicated benign job. Confidence {conf:.2f}.",
        ]
    elif pb == "privesc" and l2:
        calls.append(_tc("hunt_process", f"device='{dev}', process_name='powershell'",
                         "download cradle `IEX (New-Object Net.WebClient).DownloadString(...)` — 0 rows for the fetched payload"))
        calls.append(_tc("hunt_network", f"device='{dev}', window_hours='4'", "0 rows — no matching egress in retained telemetry"))
        R = [
            "**Command** — a PowerShell **download cradle** (`IEX … DownloadString`) that pulls and executes remote code in memory ({0}).".format(mitre),
            "**Gap** — the payload it fetched is **not resolvable**: `hunt_process` returned 0 rows for the downloaded content and `hunt_network` shows no matching egress in the retained window. I cannot confirm what actually ran.",
            "**Reasoning** — a privilege/execution alert cannot be closed on the *absence* of a signal; the cradle is a real capability and the payload is unknown. No exculpatory precedent for this actor.",
            f"**Verdict: NEEDS_L2.** Insufficient positive evidence to clear — routing for an analyst to recover the payload from longer-retention telemetry. Confidence {conf:.2f}.",
        ]
    elif pb == "credential_access":
        calls.append(_tc("hunt_logons", f"user='{upn}', window_hours='24'",
                         "63 failed sign-ins from 11 IPs across 3 countries, then 1 success"))
        calls.append(_tc("hunt_identity_grant", f"recipient='{upn}'", "no role/group change following the success"))
        calls.append(_tc("scg_check_concurrent_alerts", f"user='{upn}'", "1 other open sign-in alert for this user"))
        R = [
            "**Pattern** — `hunt_logons` shows **63 failed Entra sign-ins** from 11 source IPs across 3 countries within 24h, followed by a single success — a classic password-spray shape ({0}).".format(mitre),
            "**Post-auth** — no privileged role or group grant followed the successful sign-in, and no mailbox rule/OAuth consent in the window; impact is unconfirmed either way.",
            "**Correlation** — one *other* open sign-in alert exists for this user (distinct alert), so this is not an isolated event.",
            f"**Verdict: NEEDS_L2.** Credential-access alerts require positive confirmation of legitimacy or compromise; the successful auth's origin needs an analyst to confirm against `{upn}`'s known devices/geos. Confidence {conf:.2f}.",
        ]
    elif pb == "lateral_move":
        calls.append(_tc("hunt_logons", f"device='{dev}', window_hours='6'", "Type-3 (network) logon from WKSTN-4471 using a service account"))
        calls.append(_tc("hunt_process", f"device='{dev}', process_name='psexesvc'", "psexesvc.exe created; 1 remote command executed"))
        calls.append(_tc("scg_check_concurrent_alerts", f"device='{dev}'", "0 concurrent alerts on this host"))
        R = [
            "**Mechanism** — `PsExec` service (`psexesvc.exe`) was created on `{0}` following a Type-3 network logon from another workstation — a remote-execution / lateral-movement pattern ({1}).".format(dev, mitre),
            "**Actor** — the source used a service account rather than an interactive user; whether this is sanctioned admin tooling or misuse is not determinable from telemetry alone.",
            "**Scope** — no concurrent alerts on the host, and the single executed command is not independently malicious.",
            f"**Verdict: NEEDS_L2.** Legitimate-vs-malicious PsExec turns on change context an analyst must confirm (is there a change ticket for admin work on `{dev}`?). Confidence {conf:.2f}.",
        ]
    elif pb == "block_tool":
        calls.append(_tc("scg_recall", f"alert_type='block_tool', device='{dev}'",
                         "golden entry — AnyDesk sanctioned on helpdesk-tagged hosts (armed FP)"))
        calls.append(_tc("hunt_process", f"device='{dev}', process_name='anydesk'", "signed AnyDesk binary, interactive session to internal helpdesk range"))
        R = [
            "**Tool** — the alert is a remote-access utility (**AnyDesk**), signed, running interactively on a helpdesk-tagged host.",
            "**Precedent** — SCG holds a **golden, armed** entry: AnyDesk is a sanctioned remote-support tool for this device class, closed FP repeatedly by analysts.",
            "**Session** — the connection is to the internal helpdesk range, not an external peer — consistent with IT remote assistance, not exfiltration/C2.",
            f"**Verdict: AUTO_CLOSED_FP.** Sanctioned tool, armed precedent, internal peer. Confidence {conf:.2f}.",
        ]
    elif pb == "netskope":
        calls.append(_tc("hunt_query", "source='netskope', intent='failed login for this user + app'",
                         "17 rows: repeated failed SSO to a sanctioned SaaS app, then success"))
        calls.append(_tc("scg_recall", f"alert_type='netskope', user='{upn}'", "prior FP — stale cached token after password reset"))
        R = [
            "**Event** — repeated **failed SSO logins** to a sanctioned SaaS app for this user, resolving to a success — surfaced by Netskope, informational severity.",
            "**Cause** — matches a known-benign pattern (stale cached OAuth token after a password change); SCG holds a prior FP for this user/app shape.",
            "**Impact** — no data-movement or policy-violation event accompanied the logins; the app is on the sanctioned list.",
            f"**Verdict: AUTO_CLOSED_FP.** Benign auth churn, precedented. Confidence {conf:.2f}.",
        ]
    elif pb == "endpoint_process" and tp:
        calls.append(_tc("hunt_process", f"device='{dev}', process_name='curl'",
                         "curl fetching a script from a raw-paste host → piped to `bash`"))
        calls.append(_tc("vt_lookup_hash", f"sha256='{h}'", "29/68 malicious — downloader/dropper"))
        calls.append(_tc("hunt_network", f"device='{dev}', window_hours='2'", "outbound to the paste host, then to a second unknown IP"))
        R = [
            "**Action** — `curl` fetched a shell script from a raw-paste host and piped it straight to `bash` (`curl … | bash`) — a live-off-the-land download-and-execute ({0}).".format(mitre),
            f"**Reputation** — the fetched payload hash is **29/68 malicious** (downloader/dropper) on VirusTotal.",
            "**Network** — egress to the paste host followed by a second unknown IP — staging then likely C2.",
            f"**Verdict: AUTO_CLOSED_TP.** Confirmed malicious download-execute; EDR contained it. Recording the true-positive and flagging for containment verification. Confidence {conf:.2f}.",
        ]
    elif pb == "endpoint_process" and l2:
        calls.append(_tc("hunt_process", f"device='{dev}', process_name='certutil'",
                         "certutil `-urlcache -f` fetch from an external host to `%TEMP%`"))
        calls.append(_tc("vt_lookup_hash", f"sha256='{h}'", "0/71 — no detections (unknown file)"))
        calls.append(_tc("scg_recall", f"alert_type='endpoint_process', device='{dev}'", "1 prior FP for this dev — approved toolchain fetch"))
        R = [
            "**Action** — `certutil.exe -urlcache -f` was used to download a file from an external host to `%TEMP%` — a classic LOLBin download technique ({0}).".format(mitre),
            "**Reputation** — VirusTotal shows **0/71** on the fetched file, but it is *unknown* (never seen), so a clean VT score is not exculpatory here.",
            "**Ambiguity** — there is a prior FP for this developer (approved toolchain fetch), but the destination host on *this* event is not on the allowlist, so the precedent does not cleanly apply.",
            f"**Assessment (model): AUTO_CLOSED_FP** — leaning benign on the developer precedent and clean VT. *(Note: a downstream gate/analyst may override — the destination host is unverified.)* Confidence {conf:.2f}.",
        ]
    else:  # generic / cloudtrail
        calls.append(_tc("hunt_query", "source='cloudtrail', intent='AssumeRole + subsequent API calls for this role'",
                         "AssumeRole by a role session, then 2 IAM read calls; no write/escalation in window"))
        calls.append(_tc("hunt_identity_grant", "actor='role-session'", "0 rows — no role/policy grant recorded"))
        R = [
            "**Event** — a CloudTrail **AssumedRole** privilege-escalation signal on `{0}`: a role session was assumed, followed by IAM read calls ({1}).".format(dev, mitre),
            "**Attribution vs authorisation** — the acting principal is a role *session*, and the alert names the role, not the human who assumed it. Naming the grantor would establish *who to ask*, not that the action was sanctioned.",
            "**Gap** — no policy/role grant is recorded in the retained window and no write/escalation API followed, so neither malicious intent nor a clean bill of health is established.",
            f"**Verdict: NEEDS_L2.** A privesc-shaped CloudTrail event with an unresolved acting principal — an analyst needs to confirm against change/IAM records. Confidence {conf:.2f}.",
        ]

    # number the findings; the console's reasonHTML renders "N. …" into a stepped list
    reasoning = "\n".join(f"{i+1}. {line}" for i, line in enumerate(R))
    return reasoning, calls, len(calls) + 1


def seed():
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=4000)
    db = client[MONGODB_DB]

    collections = [
        "edr_triage_processed", "eg_shadow_results", "eg_memories",
        "eg_analyst_profiles", "eg_entities", "eg_relationships", "bedrock_usage",
        "eg_planned_activity",
    ]
    for c in collections:
        db[c].delete_many({})

    # ── edr_triage_processed (RAPTOR queue) — epoch-float processed_at ──────
    processed = []
    shadows = []
    for (key, name, pb, sev, tactics, cls, ai_cls, conf, l1_cls, match, dev, user, vt, ago) in ALERTS:
        sha = _sha(key + name)
        action = "resolved" if cls.startswith("AUTO_CLOSED") else "event_analysis"
        labels = ["raptor-triaged", f"verdict-{cls.lower()}", f"pb-{pb}"]
        reasoning, tool_calls, iters = agent_trace(key, name, pb, sev, tactics, ai_cls, conf, dev, user, vt, sha)
        processed.append({
            "alert_id": f"da_{key}",
            "jira_key": key,
            "alert_name": name,
            "device_name": dev,
            "user_name": f"{user}@example.com",
            "severity": sev,
            "tactics": tactics,
            "sha256": sha if vt != "unknown" else "",
            "vt_verdict": vt,
            "vt_detections": {"malicious": 41, "clean": 0, "unknown": 0}.get(vt, 0),
            "playbook": pb,
            "triage_class": cls,
            "l1_comment": build_comment(name, cls, conf, pb, sev, tactics, dev, user, vt),
            "llm_reasoning": reasoning,
            "labels_applied": labels,
            "action_taken": action,
            "investigation_state": "Remediated" if vt == "malicious" else "No threats found",
            "processed_at": ts(ago),
        })
        shadows.append({
            "jira_key": key,
            "alert_id": f"da_{key}",
            "alert_name": name,
            "device_name": dev,
            "user_name": f"{user}@example.com",
            "severity": sev,
            "ai_triage_class": ai_cls,
            "ai_confidence": conf,
            "ai_reasoning": reasoning,
            "ai_recommended_actions": (
                ["isolate_device", "escalate"] if ai_cls == "URGENT"
                else (["close_alert"] if ai_cls.startswith("AUTO_CLOSED") else ["escalate_l2"])
            ),
            "ai_iterations": iters,
            "ai_tool_calls": tool_calls,
            "l1_triage_class": l1_cls,
            "l1_analyst_id": "priya.l1@example.com",
            "l1_resolved_at": dt(ago - 0.02),
            "verdict_match": match,
            "blocked_by_safety": (ai_cls != cls),
            "safety_block_reason": ("errored/blank hunt is not exculpatory — escalated" if ai_cls != cls else ""),
            "pre_safety_class": ai_cls,
            "created_at": dt(ago),
            "phase": "copilot",
        })
    db["edr_triage_processed"].insert_many(processed)
    db["eg_shadow_results"].insert_many(shadows)

    # ── eg_memories — quarantine / curated / golden ────────────────────────
    memories = [
        dict(memory_type="analyst_verdict", content="Encoded PowerShell from the finance macro-signing job is a recurring benign pattern on finance workstations.",
             confidence=0.94, tier="golden", source="closure_poller", alert_ref="DEMO-0904", jira_key="DEMO-0904",
             alert_type="privesc", l1_comment="Confirmed FP — known scheduled macro-signing job. Closing.", scope="playbook",
             actor="", device="", auto_fp=False, entity_ids=[], created_at=dt(21), last_decayed_at=dt(1)),
        dict(memory_type="agent_verdict", content="AnyDesk on helpdesk-tagged workstations is expected; IT support uses it for remote assistance.",
             confidence=0.88, tier="golden", source="closure_poller", alert_ref="DEMO-0951", jira_key="DEMO-0951",
             alert_type="block_tool", l1_comment="FP — sanctioned remote-support tool for helpdesk.", scope="entity",
             actor="sam.rivera@example.com", device="WKSTN-8830", auto_fp=True, entity_ids=[], created_at=dt(18), last_decayed_at=dt(2)),
        dict(memory_type="analyst_verdict", content="certutil download by this developer was part of an approved toolchain install — benign this time.",
             confidence=0.71, tier="curated", source="closure_poller", alert_ref="DEMO-0988", jira_key="DEMO-0988",
             alert_type="endpoint_process", l1_comment="FP — approved dev toolchain fetch, verified with user.", scope="entity",
             actor="alice.chen@example.com", device="WKSTN-4471", auto_fp=False, entity_ids=[], created_at=dt(9), last_decayed_at=dt(1)),
        dict(memory_type="analyst_verdict", content="Password-spray source correlated to a misconfigured mobile client, not an attacker — benign after review.",
             confidence=0.69, tier="curated", source="closure_poller", alert_ref="DEMO-0995", jira_key="DEMO-0995",
             alert_type="credential_access", l1_comment="FP — stale cached creds on a personal device; user reset.", scope="entity",
             actor="taylor.singh@example.com", device="", auto_fp=False, entity_ids=[], created_at=dt(7), last_decayed_at=dt(1)),
        dict(memory_type="agent_verdict", content="AI said AUTO_CLOSED_FP but L1 escalated: LOLBin certutil fetch reached an untrusted host. Needs L2 review of the pattern.",
             confidence=0.5, tier="quarantine", source="closure_poller", alert_ref="DEMO-1005", jira_key="DEMO-1005",
             alert_type="endpoint_process", l1_comment="Not benign — destination host is not on the allowlist. Escalating.", scope="entity",
             actor="alice.chen@example.com", device="WKSTN-4471", auto_fp=False,
             quarantine_reason="AI said AUTO_CLOSED_FP, L1 said NEEDS_L2", entity_ids=[], created_at=dt(2.1), last_decayed_at=dt(2.1)),
        dict(memory_type="agent_verdict", content="AI said NEEDS_L2 but L1 auto-closed FP: download cradle was a known internal deployment script.",
             confidence=0.5, tier="quarantine", source="closure_poller", alert_ref="DEMO-1002", jira_key="DEMO-1002",
             alert_type="privesc", l1_comment="FP — internal deployment script, not a threat.", scope="entity",
             actor="taylor.singh@example.com", device="LAPTOP-6654", auto_fp=False,
             quarantine_reason="AI said NEEDS_L2, L1 said AUTO_CLOSED_FP", entity_ids=[], created_at=dt(5.4), last_decayed_at=dt(5.4)),
        # Missed true positive (worst case) — AI cleared a real threat, L2 confirmed malicious.
        dict(memory_type="agent_verdict", content="AI cleared a suspicious OAuth consent grant as FP, trusting a benign-looking publisher name; L2 confirmed it was an attacker-registered app with mailbox.Read scope.",
             confidence=0.5, tier="quarantine", source="closure_poller", alert_ref="DEMO-0972", jira_key="DEMO-0972",
             alert_type="credential_access", l1_comment="Escalated to L2 — publisher not in our tenant app registry.",
             l2_comment="TRUE POSITIVE — malicious OAuth app, consent revoked and tokens invalidated. AI over-trusted the display name.",
             scope="entity", actor="jordan.lee@example.com", device="", auto_fp=False,
             quarantine_reason="AI said AUTO_CLOSED_FP, L2 said AUTO_CLOSED_TP", entity_ids=[], created_at=dt(3.3), last_decayed_at=dt(3.3)),
        # Over-alarm — AI escalated URGENT on an unrecognized-but-sanctioned tool, L1 closed FP.
        dict(memory_type="agent_verdict", content="AI escalated a signed vendor updater as URGENT because it didn't recognize the binary name; L1 closed FP — it is the sanctioned Dell SupportAssist update service.",
             confidence=0.5, tier="quarantine", source="closure_poller", alert_ref="DEMO-0968", jira_key="DEMO-0968",
             alert_type="block_tool", l1_comment="FP — Dell SupportAssist, signed and expected on this fleet. Over-escalation.",
             scope="entity", actor="sam.rivera@example.com", device="WKSTN-8830", auto_fp=False,
             quarantine_reason="AI said URGENT, L1 said AUTO_CLOSED_FP", entity_ids=[], created_at=dt(4.6), last_decayed_at=dt(4.6)),
        # False alarm on an auto-close-TP — AI called it a confirmed threat, L1 verified benign.
        dict(memory_type="agent_verdict", content="AI auto-closed as TP on a ransomware-behavior heuristic (bulk file rewrites); L1 verified it was the nightly backup agent re-encrypting its own archive — benign.",
             confidence=0.5, tier="quarantine", source="closure_poller", alert_ref="DEMO-0959", jira_key="DEMO-0959",
             alert_type="malware", l1_comment="FP — Veeam backup job, not ransomware. AI mis-read mass file writes as impact.",
             scope="entity", actor="chris.morgan@example.com", device="WKSTN-3390", auto_fp=False,
             quarantine_reason="AI said AUTO_CLOSED_TP, L1 said AUTO_CLOSED_FP", entity_ids=[], created_at=dt(6.1), last_decayed_at=dt(6.1)),
        # Under-rated severity — AI routed to L2 at low confidence, L2 raised to URGENT.
        dict(memory_type="agent_verdict", content="AI routed a PsExec lateral-movement alert to L2 at low confidence; L2 raised it to URGENT after correlating an interactive hands-on-keyboard session on the target.",
             confidence=0.5, tier="quarantine", source="closure_poller", alert_ref="DEMO-0947", jira_key="DEMO-0947",
             alert_type="lateral_move", l1_comment="Escalated — unusual admin share access outside change window.",
             l2_comment="URGENT — active operator moving between hosts; contained and IR engaged. AI under-rated severity.",
             scope="entity", actor="chris.morgan@example.com", device="WKSTN-3390", auto_fp=False,
             quarantine_reason="AI said NEEDS_L2, L2 said URGENT", entity_ids=[], created_at=dt(8.2), last_decayed_at=dt(8.2)),
        # Critical miss — AI closed FP on absence of egress, L1 escalated URGENT after finding a beacon.
        dict(memory_type="agent_verdict", content="AI cleared an in-memory encoded PowerShell as FP citing no observed network egress; L1 escalated URGENT after a hunt found a periodic beacon to an external host.",
             confidence=0.5, tier="quarantine", source="closure_poller", alert_ref="DEMO-0933", jira_key="DEMO-0933",
             alert_type="privesc", l1_comment="Not benign — C2 beacon to an unrecognized domain. Absence of egress in the first pass was a data gap, not proof.",
             scope="entity", actor="alice.chen@example.com", device="WKSTN-4471", auto_fp=False,
             quarantine_reason="AI said AUTO_CLOSED_FP, L1 said URGENT", entity_ids=[], created_at=dt(10.5), last_decayed_at=dt(10.5)),
    ]
    db["eg_memories"].insert_many(memories)

    # ── eg_planned_activity — declared maintenance/compliance windows ──────
    # A known-benign activity that trips EDR fleet-wide; while active, matching
    # alerts auto-close as FP deterministically (no LLM). Time-boxed via expires_at.
    db["eg_planned_activity"].insert_many([
        dict(pattern="invoke-atomicredteam", label="Q3 purple-team / control-validation exercise",
             alert_type="", created_by="dana.l2@example.com", expires_at=fut(3),
             created_at=dt(1), hit_count=14),
        dict(pattern="qualysagent.exe", label="Quarterly authenticated vulnerability scan (Qualys)",
             alert_type="endpoint_process", created_by="marcus.l1@example.com", expires_at=fut(5),
             created_at=dt(0.5), hit_count=8),
        dict(pattern="ccmexec.exe /deploy", label="Monthly patch deployment window (SCCM)",
             alert_type="", created_by="priya.l1@example.com", expires_at=fut(1),
             created_at=dt(2), hit_count=22),
        # An expired window — shows the active/expired distinction in the UI.
        dict(pattern="bcdedit /set", label="DR failover test (last month)",
             alert_type="", created_by="dana.l2@example.com", expires_at=dt(2),
             created_at=dt(9), hit_count=5),
    ])

    # ── eg_analyst_profiles — leaderboard ──────────────────────────────────
    db["eg_analyst_profiles"].insert_many([
        dict(analyst_id="priya.l1@example.com", display_name="Priya (L1)", total_verdicts=142, correct_verdicts=131,
             accuracy=0.923, trust_tier="senior", first_seen=dt(120), last_active=dt(0.1)),
        dict(analyst_id="marcus.l1@example.com", display_name="Marcus (L1)", total_verdicts=88, correct_verdicts=71,
             accuracy=0.807, trust_tier="senior", first_seen=dt(90), last_active=dt(0.3)),
        dict(analyst_id="dana.l2@example.com", display_name="Dana (L2)", total_verdicts=54, correct_verdicts=49,
             accuracy=0.907, trust_tier="senior", first_seen=dt(140), last_active=dt(0.5)),
    ])

    # ── eg_entities + eg_relationships — small SCG graph ───────────────────
    # Risk + alert-count derived from the alerts each entity is involved in, so the
    # graph has visibly "hot" nodes (URGENT/TP) rather than a uniform field.
    from collections import defaultdict
    _rw = {"URGENT": 0.9, "AUTO_CLOSED_TP": 0.62, "NEEDS_L2": 0.45, "AUTO_CLOSED_FP": 0.16}
    dev_risk, dev_cnt = defaultdict(float), defaultdict(int)
    usr_risk, usr_cnt = defaultdict(float), defaultdict(int)
    for _a in ALERTS:
        _cls, _dev, _usr = _a[5], _a[10], _a[11]  # triage_class, device, user
        dev_risk[_dev] = max(dev_risk[_dev], _rw.get(_cls, 0.2)); dev_cnt[_dev] += 1
        usr_risk[_usr] = max(usr_risk[_usr], _rw.get(_cls, 0.2)); usr_cnt[_usr] += 1
    ents = []
    for d in DEVICES:
        ents.append(dict(entity_type="device", value=d, source_systems=["MDE"],
                         risk_score=round(dev_risk.get(d, 0.15), 2),
                         tags=[], alert_count=dev_cnt.get(d, 1), first_seen=dt(30), last_seen=dt(0.2)))
    for u in USERS:
        ents.append(dict(entity_type="user", value=f"{u}@example.com", source_systems=["Entra"],
                         risk_score=round(usr_risk.get(u, 0.12), 2),
                         tags=[], alert_count=usr_cnt.get(u, 1), first_seen=dt(30), last_seen=dt(0.3)))
    res = db["eg_entities"].insert_many(ents)
    ids = res.inserted_ids
    # a few device→user edges
    rels = []
    for i in range(min(len(DEVICES), len(USERS))):
        rels.append(dict(from_id=str(ids[i]), to_id=str(ids[len(DEVICES) + i]), rel_type="logged_on",
                        evidence=["DEMO-100" + str(i + 1)], occurrence_count=3, first_seen=dt(20), last_seen=dt(0.5)))
    db["eg_relationships"].insert_many(rels)

    # ── bedrock_usage — AI-spend ledger for the current month ──────────────
    month = NOW.strftime("%Y-%m")
    db["bedrock_usage"].insert_many([
        dict(month=month, model_id="mistral-large-3", input_tokens=182000, output_tokens=41000,
             cost_usd=0.179, jira_key="DEMO-1011", ts=ts(0.2)),
        dict(month=month, model_id="mistral-large-3", input_tokens=290000, output_tokens=63000,
             cost_usd=0.282, jira_key="DEMO-1010", ts=ts(0.5)),
        dict(month=month, model_id="mistral-large-3", input_tokens=1_450_000, output_tokens=320000,
             cost_usd=1.42, jira_key="", ts=ts(3)),
    ])

    print(f"Seeded demo data into '{MONGODB_DB}':")
    for c in collections:
        print(f"  {c}: {db[c].count_documents({})} docs")
    client.close()


if __name__ == "__main__":
    seed()
