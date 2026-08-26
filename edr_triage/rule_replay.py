"""Generic Sentinel alert enrichment by re-running the triggering analytics rule.

Many Sentinel scheduled/NRT alerts arrive with NO incident entities — the evidence
(user, host, operation, command, IP) only exists in the rule's underlying table
(OfficeActivity, AWSCloudTrail, DeviceEvents, …). Instead of hand-writing one query
per alert family, this fetches the analytics rule that fired the alert and re-runs
its own KQL scoped to the incident window, returning the triggering row(s).

Covers: Scheduled + NRT analytics rules whose KQL is fetchable via ARM.
Does NOT cover: MDE-native alerts, Fusion/ML alerts (no fetchable query) — callers
fall back to their existing behaviour when this returns {}.
"""
from __future__ import annotations

import logging
import re

import httpx

from edr_triage.sentinel_client import (
    parse_incident_url, get_management_token, _run_la_query,
    _MGMT_API, _API_VERSION, _VERIFY_SSL, _URL_RE,
)

logger = logging.getLogger(__name__)

_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

# Column-name → normalized-field heuristics (first match wins, checked in order).
_DEVICE_COLS = ("DeviceName", "Computer", "HostName", "Hostname")
_USER_COLS   = ("InitiatingProcessAccountName", "AccountName", "UserId",
                "UserName", "UserIdentityUserName", "UserPrincipalName",
                "UserIdentityPrincipalid", "Account")
_IP_COLS     = ("ClientIPOnly", "ClientIP", "SourceIpAddress", "IPAddress",
                "RemoteIP", "IpAddress")
_OP_COLS     = ("Operation", "EventName", "ActionType", "OperationName")
_CMD_COLS    = ("ProcessCommandLine", "InitiatingProcessCommandLine", "Command", "CommandLine")

# Candidate timestamp columns (a row's time, for anchoring on the alert moment).
# Includes post-`summarize` names (StartTimeUtc/EndTimeUtc) since rules often
# aggregate away TimeGenerated.
_TIME_COLS = ("TimeGenerated", "Timestamp", "EndTimeUtc", "StartTimeUtc",
              "TimeCreated", "CreationTime", "ProcessCreationTime")

# Allowlist of column names safe + useful to surface in a Jira comment. Matched
# on the base name (trailing underscores stripped) so KQL join-suffixed dupes like
# "UserId_" collapse onto "UserId". Anything NOT here is dropped — a denylist would
# leak unexpected/sensitive columns (tokens, PII, raw request blobs) into the ticket.
_SAFE_COLS = {
    # actor / identity
    "AccountName", "AccountDomain", "AccountUpn", "AccountUPNSuffix", "UserId",
    "UserName", "UserPrincipalName", "UserIdentityUserName", "UserIdentityPrincipalid",
    "UserIdentityArn", "UserType", "UserKey", "InitiatingProcessAccountName",
    "InitiatingProcessAccountDomain", "SessionIssuer", "UserAgent",
    # action / operation
    "Operation", "EventName", "EventTypeName", "EventSource", "ActionType",
    "OperationName", "RecordType", "OfficeWorkload", "Category",
    # target / resource
    "DeviceName", "Computer", "HostName", "ResourceDisplayName", "MailboxOwnerUPN",
    "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName",
    # network / geo
    "ClientIP", "ClientIPOnly", "SourceIpAddress", "IPAddress", "RemoteIP",
    "ClientIPAddress", "Location", "City", "Country", "CountryCode",
    # process / command
    "ProcessCommandLine", "InitiatingProcessCommandLine", "Command", "CommandLine",
    # result / auth
    "ResultStatus", "ResultReasonType", "ResultType", "SessionMfaAuthenticated",
    "MfaDetail", "ExternalAccess", "LogonType", "ErrorCode",
    # cloud context
    "RecipientAccountId", "UserIdentityAccountId", "AWSRegion", "AWSRegion_",
    # window
    "StartTimeUtc", "EndTimeUtc",
}


# Name patterns for security-relevant columns a rule may compute under custom
# names the exact allowlist can't anticipate (e.g. LocalGroupSID, AddedAccount,
# Actor). Kept in ADDITION to _SAFE_COLS.
_KEEP_SUBSTR = (
    "sid", "account", "group", "actor", "added", "target", "initiating",
    "user", "device", "host", "command", "operation", "event", "result",
    "file", "folder", "logon", "mfa", "region", "location", "domain",
    "principal", "mailbox", "agent",
)
# Always-drop: noise, correlation ids, and raw/sensitive blobs (belt-and-braces
# with the 300-char size cap). Checked as case-insensitive substrings.
_DENY_SUBSTR = (
    "token", "tenantid", "organizationid", "sessionid", "correlation",
    "reportid", "resourceid", "requestparameters", "responseelements",
    "additionaleventdata", "additionalfields", "resources", "sourcesystem",
    "originalrequest", "rawevent", "secret", "password", "credential",
)


def _keep_col(base: str) -> bool:
    """Keep a column for display: sensitive/noise names dropped, then the exact
    allowlist, then useful-looking names by pattern."""
    low = base.lower()
    if any(d in low for d in _DENY_SUBSTR):
        return False
    if base in _SAFE_COLS:
        return True
    return any(p in low for p in _KEEP_SUBSTR)


def _row_time(row: dict):
    """Best-effort UTC datetime for a replayed row, or None."""
    from datetime import datetime
    for c in _TIME_COLS:
        v = row.get(c)
        if not v:
            continue
        try:
            return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except Exception:
            continue
    return None


async def _fetch_rule(parts: dict, rule_id: str) -> dict:
    """Fetch a Sentinel analytics rule definition by id. Tries the default
    api-version, then a newer one (NRT rules need a recent api-version)."""
    token = await get_management_token()
    if not token:
        return {}
    base = (f"{_MGMT_API}/subscriptions/{parts['subscription_id']}"
            f"/resourceGroups/{parts['resource_group']}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{parts['workspace_name']}"
            f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}")
    for api in (_API_VERSION, "2024-09-01", "2023-12-01-preview"):
        try:
            async with httpx.AsyncClient(verify=_VERIFY_SSL, timeout=20.0) as c:
                r = await c.get(f"{base}?api-version={api}",
                                headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 200:
                return r.json()
            if r.status_code not in (400, 404):
                logger.warning("_fetch_rule %s: HTTP %s", rule_id, r.status_code)
        except Exception as exc:
            logger.error("_fetch_rule error: %s", exc)
    return {}


def _rule_id_from_alert(alert_props: dict) -> str:
    """The analytics rule id is the trailing GUID of alertType (workspace_ruleid)."""
    guids = _GUID.findall(alert_props.get("alertType", "") or "")
    return guids[-1] if guids else ""


def summarize_rows(rows: list[dict], anchor=None) -> dict:
    """Map replayed rule rows → normalized-ish fields + a compact key:value view.

    The *primary* row (headlined User/Operation/etc.) is the one whose timestamp is
    closest to `anchor` (the alert moment) — NOT an arbitrary first row — so a busy
    multi-actor window doesn't misattribute the alert to the wrong actor.
    Displayed fields are allowlisted and join-dupes (UserId/UserId_) collapsed.
    """
    if not rows:
        return {}

    # #1: pick the row closest to the alert time as the primary; fall back to the
    # first row when no timestamps are parseable or no anchor is given.
    if anchor is not None:
        timed = [(r, _row_time(r)) for r in rows]
        if any(t for _, t in timed):
            rows = [r for r, _ in sorted(
                timed, key=lambda rt: abs((rt[1] - anchor).total_seconds()) if rt[1] else 1e18)]
    row = rows[0]

    def _first(cols):
        for c in cols:
            v = row.get(c)
            if v not in (None, "", "-"):
                return str(v)
        return ""

    device = _first(_DEVICE_COLS)
    user   = _first(_USER_COLS)
    ip     = _first(_IP_COLS)
    op     = _first(_OP_COLS)
    cmd    = _first(_CMD_COLS)

    # URLs across all rows (benign-source hinting reuse).
    urls = sorted({m.group(0) for r in rows for v in r.values()
                   if isinstance(v, str) for m in [_URL_RE.search(v)] if m})

    # #4: allowlisted display fields from the primary row. Match on the base name
    # (strip trailing underscores) so join-suffixed dupes collapse; drop empties,
    # oversized values, and repeated (name, value) pairs.
    fields, seen = {}, set()
    for k, v in row.items():
        base = k.rstrip("_")
        if not _keep_col(base) or v in (None, "", "-"):
            continue
        s = str(v)
        if len(s) > 300:
            continue
        pair = (base.lower(), s)
        if pair in seen:
            continue
        seen.add(pair)
        fields[base] = s

    # Distinct process/command per row across the WHOLE result set — for
    # multi-process hunting alerts ("rare process as a service"), this is the
    # list an analyst actually vets. Collected here for free (rows already in
    # hand); the primary-row `command` above is just the headline.
    distinct_processes: list[str] = []
    _seen_p: set[str] = set()
    for r in rows:
        for c in _CMD_COLS:
            v = r.get(c)
            if v not in (None, "", "-"):
                sv = str(v)
                if sv not in _seen_p:
                    _seen_p.add(sv)
                    distinct_processes.append(sv)
                break

    return {
        "device_name": device, "account_name": user, "source_ip": ip,
        "operation": op, "command": cmd, "remote_urls": urls,
        "fields": fields, "row_count": len(rows),
        "distinct_users": sorted({str(r.get(c)) for r in rows for c in _USER_COLS if r.get(c)})[:8],
        "distinct_processes": distinct_processes[:100],
    }


async def _fetch_alert_events(
    incident_url: str,
    alert_props: dict,
    sentinel_alert_id: str = "",
    window_pad_minutes: int = 30,
) -> tuple[list[dict], object, str]:
    """Fetch + decode THIS alert's OWN matched-event row(s) from the compressedRec
    blob Sentinel embeds in the alert's ExtendedProperties.

    Shared by decode_alert_event (which summarizes the rows into a rule_replay
    dict) and decode_alert_cloudtrail_rows (which maps them into per-host CloudTrail
    dicts). Returns (events, anchor, alert_name); events is [] when the alert has no
    id / no compressedRec / nothing decodable.
    """
    from edr_triage.sentinel_client import _run_la_query, decode_compressed_recs
    parts = parse_incident_url(incident_url)
    if not parts:
        return [], None, ""
    pid = (sentinel_alert_id or alert_props.get("providerAlertId", "") or "")
    pid = pid[2:] if pid.lower().startswith("sn") else pid
    if not pid:
        return [], None, ""

    anchor = None
    timespan = None
    try:
        from datetime import datetime, timedelta
        s = alert_props.get("startTimeUtc") or alert_props.get("timeGenerated")
        e = alert_props.get("endTimeUtc") or alert_props.get("timeGenerated")
        if s and e:
            t0 = datetime.fromisoformat(s.replace("Z", "+00:00")) - timedelta(minutes=window_pad_minutes)
            t1 = datetime.fromisoformat(e.replace("Z", "+00:00")) + timedelta(minutes=window_pad_minutes)
            timespan = f"{t0.strftime('%Y-%m-%dT%H:%M:%SZ')}/{t1.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        _anc = alert_props.get("timeGenerated") or e
        anchor = datetime.fromisoformat(_anc.replace("Z", "+00:00")) if _anc else None
    except Exception:
        pass

    kql = (f'SecurityAlert | where VendorOriginalId in ("{pid}") or SystemAlertId in ("{pid}")'
           f' | top 1 by TimeGenerated desc | project TimeGenerated, AlertName, ExtendedProperties')
    rows = await _run_la_query(parts, kql, timespan=timespan)
    if not rows:
        return [], anchor, ""
    events = decode_compressed_recs(rows[0].get("ExtendedProperties"))
    return events, anchor, (rows[0].get("AlertName", "") or "")


async def decode_alert_event(
    incident_url: str,
    alert_props: dict,
    sentinel_alert_id: str = "",
    window_pad_minutes: int = 30,
) -> dict:
    """PRIMARY enrichment: decode THIS alert's OWN matched event(s) from the
    compressedRec blob Sentinel embeds in the alert's ExtendedProperties.

    More reliable than re-running the rule: for broad/high-frequency rules the rule
    query matches many entities in the window and picking one is a guess, whereas
    compressedRec is the exact row(s) bound to *this* alert (DEMO-104199). Returns a
    replay-shaped dict, or {} to fall back to replay_alert_rule.
    """
    events, anchor, alert_name = await _fetch_alert_events(
        incident_url, alert_props, sentinel_alert_id, window_pad_minutes)
    if not events:
        return {}
    result = summarize_rows(events, anchor=anchor)
    result["rule_name"] = alert_name or alert_props.get("alertDisplayName", "")
    result["source"] = "compressedRec"
    logger.info("decode_alert_event: %d event(s); device=%s user=%s op=%s",
                result["row_count"], result.get("device_name"),
                result.get("account_name"), result.get("operation"))
    return result


def _ci(row: dict, *names) -> str:
    """Case-insensitive first-non-empty lookup across candidate column names."""
    low = {str(k).lower(): v for k, v in (row or {}).items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, "", "-"):
            return str(v)
    return ""


def _split_cmds(raw: str) -> list[str]:
    """Split an InitiatingCommands blob into individual commands. The rule joins
    with ';' or ', '; we split on ';'/newlines only (reliable) — never on ','
    (commands legitimately contain commas). Falls back to the whole string."""
    if not raw:
        return []
    parts = [c.strip() for c in re.split(r"[;\n]+", raw) if c.strip()]
    return parts or [raw.strip()]


def cloudtrail_row_to_dict(ev: dict) -> dict:
    """Map ONE decoded rule-output row → the cloudtrail-shaped dict the privesc
    playbook renders. Keys on the rule's OWN projected column names (InstanceId /
    SessionIssuerUserName / UserIdentityArn / InitiatingCommands) that the generic
    summarize_rows heuristics don't fully map."""
    cmd = _ci(ev, "InitiatingCommands", "InitiatingProcessCommandLine",
              "ProcessCommands", "ProcessCommandLine", "Command", "CommandLine")
    out = {
        "device_name":    _ci(ev, "DeviceName", "Computer", "HostName"),
        "account_name":   _ci(ev, "AccountName", "InitiatingProcessAccountName"),
        "instance_id":    _ci(ev, "InstanceId"),
        "session_issuer": _ci(ev, "SessionIssuerUserName", "SessionIssuer"),
        "user_arn":       _ci(ev, "UserIdentityArn", "UserIdentityPrincipalid"),
        "event_name":     _ci(ev, "EventName", "Operation", "OperationName"),
        "time_generated": _ci(ev, "TimeGenerated", "Timestamp", "StartTimeUtc"),
        "source_ip":      _ci(ev, "SourceIpAddress", "ClientIP", "ClientIPOnly",
                               "IpAddress", "IPAddress"),
    }
    if cmd:
        out["command"] = cmd
        out["command_lines"] = _split_cmds(cmd)
    return {k: v for k, v in out.items() if v}


async def decode_alert_cloudtrail_rows(
    incident_url: str,
    alert_props: dict,
    sentinel_alert_id: str = "",
    window_pad_minutes: int = 30,
) -> list[dict]:
    """GROUND-TRUTH CloudTrail/SSM enrichment: decode THIS alert's own matched rows
    (the exact per-host output the analytics rule emitted) and map each to a
    cloudtrail dict — ONE entry PER HOST.

    Unlike the hand-written replica (query_cloudtrail_event: single bound device +
    `take 1`, anchored on DeviceProcessEvents), a grouped root-privesc incident here
    surfaces EVERY host's instance / session issuer / ARN / command, straight from
    the rule's own output (DEMO-106604: the replica saw one host's cron noise and
    missed both real SSM escalations).

    Returns [] when the alert has no compressedRec or the rows carry no AWS/SSM
    identity — the caller then falls back to the replica / rule-replay path.
    """
    events, _anchor, _name = await _fetch_alert_events(
        incident_url, alert_props, sentinel_alert_id, window_pad_minutes)
    if not events:
        return []
    rows: list[dict] = []
    seen: set = set()
    for ev in events:
        d = cloudtrail_row_to_dict(ev)
        # SSM-session signal ONLY (instance/issuer) — deliberately NOT a bare
        # arn:aws principal. GuardDuty / console-login / access-key AWS alerts carry
        # an ARN but no SSM instance/session, and the replica path enriches them
        # richly (MFA / geo / access-key / finding link from ExtendedProperties)
        # in ways this row mapping can't — so they must stay on the replica, not be
        # captured here. Non-CloudTrail rules likewise fall through to rule-replay.
        if not (d.get("instance_id") or d.get("session_issuer")):
            continue
        key = (d.get("device_name", ""), d.get("instance_id", ""), d.get("command", ""))
        if key in seen:
            continue
        seen.add(key)
        rows.append(d)
    return rows


def _host_match(device: str, host_filter: list) -> bool:
    """Loose host match (short name vs FQDN vs cloud DNS) for scoping replayed
    rows to the incident's own hosts."""
    if not host_filter:
        return True
    d = (device or "").lower()
    if not d:
        return False
    for h in host_filter:
        h = (h or "").lower()
        if h and (h in d or d in h):
            return True
    return False


async def replay_alert_cloudtrail_rows(
    incident_url: str,
    alert_props: dict,
    host_filter: list | None = None,
    window_pad_minutes: int = 30,
    row_cap: int = 50,
) -> list[dict]:
    """Re-run THIS alert's OWN analytics rule and map each output row → a CloudTrail
    dict, ONE per host.

    Faithful multi-host fallback when the alert embeds no compressedRec (DEMO-106604:
    the Root Privilege Escalation rule doesn't, so decode_alert_cloudtrail_rows is
    empty). Re-running the rule reproduces its exact per-host SSM output — instance /
    session issuer / ARN / the *real* escalation command (`sudo sudo su`) — instead
    of the DeviceProcessEvents replica's root-cron noise, which uses a different
    filter and grabs the wrong activity. Scoped to `host_filter` (the incident's own
    host entities) so a wide window can't pull unrelated privesc events.

    Returns [] when the rule isn't fetchable/replayable or yields no AWS/SSM rows.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        return []
    rule_id = _rule_id_from_alert(alert_props)
    if not rule_id:
        return []
    rule = await _fetch_rule(parts, rule_id)
    query = ((rule or {}).get("properties", {}) or {}).get("query", "")
    if not query.strip():
        logger.info("replay_alert_cloudtrail_rows: rule %s not fetchable/replayable", rule_id)
        return []

    timespan = None
    try:
        from datetime import datetime, timedelta
        s = alert_props.get("startTimeUtc") or alert_props.get("timeGenerated")
        e = alert_props.get("endTimeUtc") or alert_props.get("timeGenerated")
        t0 = datetime.fromisoformat(s.replace("Z", "+00:00")) - timedelta(minutes=window_pad_minutes)
        t1 = datetime.fromisoformat(e.replace("Z", "+00:00")) + timedelta(minutes=window_pad_minutes)
        timespan = f"{t0.strftime('%Y-%m-%dT%H:%M:%SZ')}/{t1.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    except Exception:
        pass

    from edr_triage.sentinel_client import _run_la_query
    scoped = query.rstrip().rstrip(";") + f"\n| take {row_cap}"
    raw = await _run_la_query(parts, scoped, timespan=timespan)
    if not raw:
        logger.info("replay_alert_cloudtrail_rows: rule %s returned 0 rows for %s", rule_id, timespan)
        return []

    out: list[dict] = []
    seen: set = set()
    for r in raw:
        d = cloudtrail_row_to_dict(r)
        # SSM-session signal only (see decode_alert_cloudtrail_rows) — keeps
        # GuardDuty / console / access-key AWS alerts on the richer replica path.
        if not (d.get("instance_id") or d.get("session_issuer")):
            continue
        if not _host_match(d.get("device_name", ""), host_filter or []):
            continue
        key = (d.get("device_name", ""), d.get("instance_id", ""), d.get("command", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


_LOCAL_GROUP_ACTIONS = ("UserAccountAddedToLocalGroup", "UserAccountRemovedFromLocalGroup")


def local_group_row_to_dict(ev: dict) -> dict:
    """Map ONE decoded local-group-membership row → a dict that keeps its two
    principals SEPARATE instead of collapsing them into one 'user'.

    A UserAccountAddedToLocalGroup/RemovedFromLocalGroup row always names two
    accounts: the RECIPIENT (bare AccountName — who the change is ABOUT, i.e. who now
    holds the role) and the GRANTOR (InitiatingProcessAccountName — who ran the
    change). Collapsing these is the DEMO-106406 bug shape again: whichever a generic
    heuristic picks first, the other is silently lost. The recipient is the one an FP
    judgment like "this person already has the role" is actually about — arming an
    allowlist on the grantor instead would auto-close a compromised admin account
    granting a NEW, unreviewed recipient, which is exactly what this alert exists to
    catch."""
    out = {
        "action_type":       _ci(ev, "ActionType"),
        "device_name":       _ci(ev, "DeviceName", "Computer", "HostName"),
        "recipient_account":  _ci(ev, "AccountName"),
        "recipient_domain":   _ci(ev, "AccountDomain"),
        "grantor_account":    _ci(ev, "InitiatingProcessAccountName"),
        "grantor_domain":     _ci(ev, "InitiatingProcessAccountDomain"),
        "time_generated":    _ci(ev, "TimeGenerated", "Timestamp"),
    }
    return {k: v for k, v in out.items() if v}


async def decode_alert_local_group_rows(
    incident_url: str,
    alert_props: dict,
    sentinel_alert_id: str = "",
    window_pad_minutes: int = 30,
) -> list[dict]:
    """GROUND-TRUTH local-group enrichment: decode THIS alert's own matched rows
    (compressedRec) and map each local-group-membership row to a recipient/grantor
    dict, ONE per (device, recipient, action).

    Returns [] when the alert has no compressedRec or none of its rows are a
    UserAccountAdded/RemovedFromLocalGroup action — the caller then falls through to
    the generic rule-replay/entity-binding path, unchanged for every other alert type.
    """
    events, _anchor, _name = await _fetch_alert_events(
        incident_url, alert_props, sentinel_alert_id, window_pad_minutes)
    if not events:
        return []
    rows: list[dict] = []
    seen: set = set()
    for ev in events:
        if _ci(ev, "ActionType") not in _LOCAL_GROUP_ACTIONS:
            continue
        d = local_group_row_to_dict(ev)
        if not d.get("recipient_account"):
            continue
        key = (d.get("device_name", ""), d.get("recipient_account", ""), d.get("action_type", ""))
        if key in seen:
            continue
        seen.add(key)
        rows.append(d)
    return rows


async def replay_alert_local_group_rows(
    incident_url: str,
    alert_props: dict,
    host_filter: list | None = None,
    window_pad_minutes: int = 30,
    row_cap: int = 50,
) -> list[dict]:
    """Re-run THIS alert's own analytics rule (when fetchable) and map local-group rows
    the same way as decode_alert_local_group_rows.

    Most MDE-native local-group detections surfaced via a Sentinel incident have no
    fetchable rule (this returns [] then, same as replay_alert_rule) — kept for the
    Sentinel-NATIVE case, and for symmetry with the CloudTrail decode/replay pair.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        return []
    rule_id = _rule_id_from_alert(alert_props)
    if not rule_id:
        return []
    rule = await _fetch_rule(parts, rule_id)
    query = ((rule or {}).get("properties", {}) or {}).get("query", "")
    if not query.strip():
        return []

    timespan = None
    try:
        from datetime import datetime, timedelta
        s = alert_props.get("startTimeUtc") or alert_props.get("timeGenerated")
        e = alert_props.get("endTimeUtc") or alert_props.get("timeGenerated")
        t0 = datetime.fromisoformat(s.replace("Z", "+00:00")) - timedelta(minutes=window_pad_minutes)
        t1 = datetime.fromisoformat(e.replace("Z", "+00:00")) + timedelta(minutes=window_pad_minutes)
        timespan = f"{t0.strftime('%Y-%m-%dT%H:%M:%SZ')}/{t1.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    except Exception:
        pass

    from edr_triage.sentinel_client import _run_la_query
    scoped = query.rstrip().rstrip(";") + f"\n| take {row_cap}"
    raw = await _run_la_query(parts, scoped, timespan=timespan)
    if not raw:
        return []

    out: list[dict] = []
    seen: set = set()
    for r in raw:
        if _ci(r, "ActionType") not in _LOCAL_GROUP_ACTIONS:
            continue
        d = local_group_row_to_dict(r)
        if not d.get("recipient_account"):
            continue
        if not _host_match(d.get("device_name", ""), host_filter or []):
            continue
        key = (d.get("device_name", ""), d.get("recipient_account", ""), d.get("action_type", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


async def replay_alert_rule(
    incident_url: str,
    alert_props: dict,
    window_pad_minutes: int = 30,
    row_cap: int = 25,
) -> dict:
    """Re-run the analytics rule that fired this alert, scoped to the incident
    window, and return the triggering row(s) mapped to normalized-ish fields.

    Returns {} when not applicable (no rule id, un-fetchable rule kind, no rows,
    or missing RBAC) so callers can fall back to existing behaviour.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        return {}
    rule_id = _rule_id_from_alert(alert_props)
    if not rule_id:
        return {}

    rule = await _fetch_rule(parts, rule_id)
    rp = (rule or {}).get("properties", {})
    query = rp.get("query", "")
    if not query.strip():
        logger.info("replay_alert_rule: rule %s not fetchable/replayable (kind=%s)",
                    rule_id, (rule or {}).get("kind"))
        return {}

    # Window from the alert's own start/end (± pad); scope via the timespan param
    # so we never have to rewrite the rule's KQL. Anchor = the detection moment
    # (timeGenerated, else end of window) — used to pick the primary row.
    anchor = None
    try:
        from datetime import datetime, timedelta
        s = alert_props.get("startTimeUtc") or alert_props.get("timeGenerated")
        e = alert_props.get("endTimeUtc") or alert_props.get("timeGenerated")
        t0 = datetime.fromisoformat(s.replace("Z", "+00:00")) - timedelta(minutes=window_pad_minutes)
        t1 = datetime.fromisoformat(e.replace("Z", "+00:00")) + timedelta(minutes=window_pad_minutes)
        timespan = f"{t0.strftime('%Y-%m-%dT%H:%M:%SZ')}/{t1.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        _anc = alert_props.get("timeGenerated") or alert_props.get("endTimeUtc") or e
        anchor = datetime.fromisoformat(_anc.replace("Z", "+00:00")) if _anc else None
    except Exception:
        timespan = None

    # Cap rows (safe as a trailing operator on any tabular result).
    scoped = query.rstrip().rstrip(";") + f"\n| take {row_cap}"
    rows = await _run_la_query(parts, scoped, timespan=timespan)
    if not rows:
        logger.info("replay_alert_rule: rule %s (%s) returned 0 rows for %s",
                    rule_id, rp.get("displayName"), timespan)
        return {}

    result = summarize_rows(rows, anchor=anchor)
    result["rule_name"] = rp.get("displayName", "")
    result["rule_id"] = rule_id
    result["rule_kind"] = (rule or {}).get("kind", "")
    logger.info(
        "replay_alert_rule: rule '%s' (%s) → %d row(s); device=%s user=%s op=%s",
        result["rule_name"], result["rule_kind"], result["row_count"],
        result.get("device_name"), result.get("account_name"), result.get("operation"),
    )
    return result
