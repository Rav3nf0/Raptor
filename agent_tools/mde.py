"""MDE API tool wrappers — wraps existing lib/mde_client.py and edr_triage/mde_alerts.py."""
from __future__ import annotations

import logging

from agent_tools.registry import register

logger = logging.getLogger(__name__)


@register(
    name="mde_get_alert",
    description="Fetch full MDE alert data by alert ID. Returns severity, device, user, investigation state, MITRE techniques.",
    parameters={
        "type": "object",
        "properties": {
            "alert_id": {"type": "string", "description": "MDE alert ID"},
        },
        "required": ["alert_id"],
    },
)
async def mde_get_alert(alert_id: str) -> dict:
    from edr_triage.mde_alerts import fetch_alert, fetch_alert_evidence, extract_file_evidence
    from lib.mde_client import get_access_token
    # Sentinel alert/incident IDs (sn-prefixed) are not in MDE — every such call
    # was failing "not found". Redirect the model to the right tool instead of a
    # wasted round-trip that reads like "no data".
    if (alert_id or "").lower().startswith("sn"):
        return {"invalid_input": True, "error": (
            f"'{alert_id}' is a Sentinel alert/incident ID, not an MDE alert. MDE only holds "
            "Defender endpoint alerts. Use sentinel_get_incident with the incident URL for this "
            "alert's details, and sentinel_run_kql for hunting."
        )}
    # A JIRA KEY is not an alert id. The model reaches for the ticket key it has been
    # given all along — DEMO-107068 called mde_get_alert(alert_id='DEMO-107067'), got
    # "not found", and that error capped its confidence at 0.60 and overturned a
    # correct AUTO_CLOSED_FP. Name the mistake instead of letting it read as missing
    # evidence about the alert.
    import re as _re
    if _re.fullmatch(r"[A-Za-z]{2,6}-\d+", (alert_id or "").strip()):
        return {"invalid_input": True, "error": (
            f"'{alert_id}' is a JIRA ticket key, not an MDE alert id. The ticket key identifies "
            "the case, not the detection. This alert's own details are already in your prompt; "
            "for a DIFFERENT ticket use scg_check_concurrent_alerts or the SCG entity context "
            "rather than trying to fetch it from MDE."
        )}
    token = await get_access_token()
    if not token:
        return {"error": "MDE token unavailable"}
    alert = await fetch_alert(alert_id, token)
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    evidence_list = await fetch_alert_evidence(alert_id, token)
    evidence = extract_file_evidence(evidence_list)
    return {"alert": alert, "evidence": evidence}


@register(
    name="mde_get_timeline",
    description=(
        "Fetch device event timeline for a machine (process, file, network, logon events). "
        "Accepts an MDE machine ID or a hostname/FQDN (resolved automatically). Only works for "
        "Defender-onboarded endpoints — Sentinel-origin/Linux/cloud hosts won't have MDE telemetry."
    ),
    parameters={
        "type": "object",
        "properties": {
            "machine_id": {"type": "string", "description": "MDE machine ID or device hostname/FQDN"},
            "lookback_hours": {"type": "integer", "description": "Hours to look back (default 24)", "default": 24},
        },
        "required": ["machine_id"],
    },
)
async def mde_get_timeline(machine_id: str, lookback_hours: int = 24) -> dict:
    from edr_triage.mde_alerts import fetch_machine_timeline
    from lib.mde_client import get_access_token
    token = await get_access_token()
    if not token:
        return {"error": "MDE token unavailable"}
    try:
        events = await fetch_machine_timeline(machine_id, token, lookback_hours=lookback_hours)
    except ValueError as exc:
        # Device not in MDE — surface explicitly so an empty timeline isn't misread
        # as "clean" (absence of MDE telemetry is not exculpatory).
        return {"error": str(exc), "events": [], "count": 0}

    # SIGNAL FIRST. The agent loop truncates every tool result to 1500 chars before
    # the model sees it; a raw chronological dump of this timeline is ~20k chars, so
    # the model got the first ~7% — pure process churn — and NONE of the detections
    # (measured on DEMO-107628: 4 AntivirusDetection rows present, 0 visible). Dict
    # order is preserved through json.dumps, so the high-signal fields are emitted
    # BEFORE the bulk event list and always survive truncation.
    detections = [e for e in events if "AntivirusDetection" in str(e.get("ActionType") or "")]
    by_table: dict = {}
    for e in events:
        by_table[e.get("Table", "?")] = by_table.get(e.get("Table", "?"), 0) + 1
    return {
        "machine_id": machine_id,
        "count": len(events),
        # Compact: the detection rows are the whole reason to read a timeline on an
        # AV alert, so they go first and carry only the fields that identify them.
        "av_detections": [
            {"Timestamp": d.get("Timestamp"), "FileName": d.get("FileName"),
             "FolderPath": d.get("FolderPath")}
            for d in detections
        ],
        "events_by_table": by_table,
        "events": events,
    }


@register(
    name="mde_advanced_hunt",
    description=(
        "FALLBACK (prefer the hunt_* tools / hunt_query — they build correct KQL for you). "
        "Run a hand-written KQL query against MDE Advanced Hunting (Device* tables) or Sentinel "
        "Log Analytics. Returns matching rows. Use only when no hunt_* tool fits.\n"
        "VALID MDE TABLES + key columns:\n"
        "- DeviceProcessEvents: Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, "
        "InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256\n"
        "- DeviceNetworkEvents: Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, "
        "InitiatingProcessFileName\n"
        "- DeviceFileEvents: Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, "
        "InitiatingProcessFileName\n"
        "- DeviceLogonEvents: Timestamp, DeviceName, AccountName, LogonType, RemoteIP, ActionType\n"
        "- DeviceEvents, DeviceRegistryEvents, DeviceImageLoadEvents also exist. There is NO "
        "'DeviceServices' table.\n"
        "Sentinel/Log Analytics tables: SigninLogs, SecurityAlert, CommonSecurityLog, and custom "
        "_CL tables like Netskope_Alerts_CL.\n"
        "RULES: start with the table name (never a // comment or backticks); add a time filter "
        "(Timestamp>ago(24h) for MDE, TimeGenerated>ago(24h) for Sentinel); end with | take 50.\n"
        "Example (MDE):\n"
        "  DeviceProcessEvents | where DeviceName == \"host1.corp\" | where Timestamp > ago(24h) "
        "| where FileName =~ \"powershell.exe\" | take 50\n"
        "Example (Sentinel):\n"
        "  SigninLogs | where TimeGenerated > ago(24h) | where UserPrincipalName == \"u@x.com\" "
        "| project TimeGenerated, ResultType, IPAddress | take 50"
    ),
    parameters={
        "type": "object",
        "properties": {
            "kql": {"type": "string", "description": "KQL query — begin with a valid table name (see description), add a time filter, end with | take 50. No // comment or backticks at the start."},
        },
        "required": ["kql"],
    },
)
async def mde_advanced_hunt(kql: str) -> dict:
    from lib.mde_client import (
        run_mde_query, run_sentinel_query, SENTINEL_TABLE_SCHEMA,
        MDE_TABLE_SCHEMA, get_access_token, preflight_kql,
    )

    # Shared pre-flight: strip leading comment/blank lines (so the real first token —
    # the table — is what we route/validate on) and lint for lexical breakage before
    # the API round-trip. Same guardrail sentinel_run_kql now uses.
    cleaned, pf_err = preflight_kql(kql)
    if pf_err:
        return {"error": pf_err, "rows": []}

    first_token = cleaned.split()[0] if cleaned.split() else ""
    # KQL query-construct keywords that legitimately START a query instead of a
    # table name (union DeviceX, DeviceY | ...; let x = ...; search "...").
    # Don't validate these as tables — the query engine resolves the real tables.
    _KQL_LEAD = {"union", "let", "search", "print", "find", "range",
                 "datatable", "externaldata", "materialize", "evaluate"}
    lead = first_token.lower()
    # _CL = Log Analytics custom-log table (e.g. Netskope_Alerts_CL) — always lives
    # in the Sentinel workspace, so route it there rather than MDE. For a leading
    # keyword (union/let/...), route to Sentinel if a _CL table appears anywhere.
    use_sentinel = (first_token in SENTINEL_TABLE_SCHEMA or first_token.endswith("_CL")
                    or (lead in _KQL_LEAD and "_CL" in cleaned))
    valid_mde = first_token in MDE_TABLE_SCHEMA

    # Fail fast with an instructive error when the query targets a table that
    # doesn't exist (e.g. the hallucinated 'DeviceServices') — better a clear
    # "pick a real table" message the model can act on than an opaque MDE 400
    # (and the auto-fix can't rescue a query whose table doesn't exist). Leading
    # KQL keywords are exempt (they aren't table names).
    if lead not in _KQL_LEAD and not use_sentinel and not valid_mde:
        return {
            "error": (
                f"'{first_token}' is not a valid table. Rewrite the query to start with a real "
                f"MDE table: {', '.join(sorted(MDE_TABLE_SCHEMA))}. "
                "(For process/command-line activity use DeviceProcessEvents; for services/autoruns "
                "use DeviceRegistryEvents or DeviceEvents — there is no DeviceServices table.)"
            ),
            "rows": [],
        }

    if use_sentinel:
        rows, err = await run_sentinel_query(cleaned)
    else:
        token = await get_access_token()
        if not token:
            return {"error": "MDE token unavailable"}
        rows, err = await run_mde_query(cleaned, token)
    if err:
        return {"error": err, "rows": []}
    return {"rows": rows, "count": len(rows)}
