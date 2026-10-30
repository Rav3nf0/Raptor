"""Sentinel Incidents API client — enriches credential/identity alerts with entity data."""
from __future__ import annotations

import os
import re
import time
import logging

import httpx

logger = logging.getLogger(__name__)

_LA_TOKEN_CACHE: dict = {"token": None, "expires_at": 0.0}
_WS_GUID_CACHE:    dict = {}  # workspace_name → customerId GUID

_INCIDENT_URL_RE = re.compile(
    r'subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/'
    r'Microsoft\.OperationalInsights/workspaces/([^/]+)/providers/'
    r'Microsoft\.SecurityInsights/Incidents/([^/?&#\s]+)',
    re.IGNORECASE,
)

_VERIFY_SSL = os.getenv("MDE_VERIFY_SSL", os.getenv("CYBLE_VERIFY_SSL", "true")).lower() not in (
    "false", "0", "no"
)
_MGMT_API = "https://management.azure.com"
_LA_API   = "https://api.loganalytics.io"
_API_VERSION = "2024-03-01"


def parse_incident_url(url: str) -> dict | None:
    """Parse an Azure portal Sentinel incident URL.

    Returns dict with subscription_id, resource_group, workspace_name, incident_id
    or None if the URL does not match.
    """
    m = _INCIDENT_URL_RE.search(url or "")
    if not m:
        return None
    return {
        "subscription_id": m.group(1),
        "resource_group":  m.group(2),
        "workspace_name":  m.group(3),
        "incident_id":     m.group(4),
    }


async def get_management_token() -> str | None:
    """Return a cached OAuth2 token for management.azure.com.

    Delegates to lib.mde_client which owns the single shared token cache.
    """
    from lib.mde_client import get_management_token as _get_mgmt_token
    return await _get_mgmt_token()


async def get_la_token() -> str | None:
    """Return a cached OAuth2 token scoped to api.loganalytics.io."""
    now = time.time()
    if _LA_TOKEN_CACHE["token"] and now < _LA_TOKEN_CACHE["expires_at"] - 60:
        return _LA_TOKEN_CACHE["token"]

    tenant_id     = os.getenv("MDE_TENANT_ID", "")
    client_id     = os.getenv("MDE_CLIENT_ID", "")
    client_secret = os.getenv("MDE_CLIENT_SECRET", "")
    if not all([tenant_id, client_id, client_secret]):
        return None

    try:
        async with httpx.AsyncClient(verify=_VERIFY_SSL, timeout=15.0) as client:
            resp = await client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={"grant_type": "client_credentials", "client_id": client_id,
                      "client_secret": client_secret, "scope": "https://api.loganalytics.io/.default"},
            )
            resp.raise_for_status()
            data = resp.json()
            token = data.get("access_token")
            if not token:
                return None
            _LA_TOKEN_CACHE["token"] = token
            _LA_TOKEN_CACHE["expires_at"] = now + int(data.get("expires_in", 3600))
            return token
    except Exception as exc:
        logger.error("LA token fetch error: %s", exc)
        return None


async def get_workspace_guid(parts: dict) -> str | None:
    """Resolve the Log Analytics workspace customerId (GUID) from ARM.

    Needed for the api.loganalytics.io query endpoint which uses the GUID,
    not the workspace name. Result is cached in-process.
    """
    ws_name = parts["workspace_name"]
    if ws_name in _WS_GUID_CACHE:
        return _WS_GUID_CACHE[ws_name]

    token = await get_management_token()
    if not token:
        return None

    sub, rg = parts["subscription_id"], parts["resource_group"]
    url = (
        f"{_MGMT_API}/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws_name}"
        f"?api-version=2023-09-01"
    )
    try:
        async with httpx.AsyncClient(verify=_VERIFY_SSL, timeout=15.0) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            guid = resp.json().get("properties", {}).get("customerId")
            if guid:
                _WS_GUID_CACHE[ws_name] = guid
            return guid
    except Exception as exc:
        logger.warning("get_workspace_guid failed for %s: %s", ws_name, exc)
        return None


async def _run_la_query(parts: dict, kql: str, timespan: str | None = None) -> list[dict]:
    """Run a KQL query via api.loganalytics.io. Returns list of row dicts, or [].

    timespan (ISO8601 interval, e.g. "2026-07-13T07:00:00Z/2026-07-13T13:30:00Z")
    scopes the *entire* query globally without editing its text — used to safely
    re-run arbitrary analytics-rule KQL for a specific alert window.
    """
    ws_guid = await get_workspace_guid(parts)
    if not ws_guid:
        return []
    la_token = await get_la_token()
    if not la_token:
        return []

    url = f"{_LA_API}/v1/workspaces/{ws_guid}/query"
    body = {"query": kql}
    if timespan:
        body["timespan"] = timespan
    try:
        async with httpx.AsyncClient(verify=_VERIFY_SSL, timeout=30.0) as client:
            resp = await client.post(
                url, json=body,
                headers={"Authorization": f"Bearer {la_token}", "Content-Type": "application/json"},
            )
            if resp.status_code == 403:
                logger.warning("_run_la_query: 403 — Log Analytics Reader role may not be propagated yet")
                return []
            resp.raise_for_status()
            tables = resp.json().get("tables", [])
            if not tables or not tables[0].get("rows"):
                return []
            cols = [c["name"] for c in tables[0]["columns"]]
            return [dict(zip(cols, row)) for row in tables[0]["rows"]]
    except Exception as exc:
        logger.error("_run_la_query error: %s", exc)
        return []


async def fetch_incident(incident_url: str) -> dict:
    """Fetch the Sentinel incident resource from Azure Resource Manager.

    Returns the parsed JSON dict or {} on any failure.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        logger.warning("fetch_incident: could not parse incident URL: %s", incident_url)
        return {}

    token = await get_management_token()
    if not token:
        return {}

    sub  = parts["subscription_id"]
    rg   = parts["resource_group"]
    ws   = parts["workspace_name"]
    iid  = parts["incident_id"]
    url  = (
        f"{_MGMT_API}/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/providers/Microsoft.SecurityInsights/incidents/{iid}"
        f"?api-version={_API_VERSION}"
    )

    try:
        async with httpx.AsyncClient(verify=_VERIFY_SSL, timeout=20.0) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 403:
                logger.warning(
                    "fetch_incident: 403 Forbidden — service principal may lack Sentinel Reader role "
                    "(incident %s)", iid
                )
                return {}
            if resp.status_code == 404:
                logger.warning("fetch_incident: 404 for incident %s", iid)
                return {}
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as exc:
        logger.warning("fetch_incident HTTP %s for %s: %s", exc.response.status_code, iid, exc)
        return {}
    except Exception as exc:
        logger.error("fetch_incident unexpected error for %s: %s", iid, exc, exc_info=True)
        return {}


async def fetch_incident_entities(incident_url: str) -> list[dict]:
    """POST to the Sentinel incident entities endpoint and return the entity list.

    Returns [] on any failure.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        logger.warning("fetch_incident_entities: could not parse incident URL: %s", incident_url)
        return []

    token = await get_management_token()
    if not token:
        return []

    sub  = parts["subscription_id"]
    rg   = parts["resource_group"]
    ws   = parts["workspace_name"]
    iid  = parts["incident_id"]
    url  = (
        f"{_MGMT_API}/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/providers/Microsoft.SecurityInsights/incidents/{iid}/entities"
        f"?api-version={_API_VERSION}"
    )

    try:
        async with httpx.AsyncClient(verify=_VERIFY_SSL, timeout=20.0) as client:
            resp = await client.post(
                url,
                json={},
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code == 403:
                logger.warning(
                    "fetch_incident_entities: 403 Forbidden — service principal may lack "
                    "Sentinel Reader role (incident %s)", iid
                )
                return []
            if resp.status_code == 404:
                logger.warning("fetch_incident_entities: 404 for incident %s", iid)
                return []
            resp.raise_for_status()
            data = resp.json()
            entities = data.get("entities", [])
            logger.debug("fetch_incident_entities: %d entities for incident %s", len(entities), iid)
            return entities
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "fetch_incident_entities HTTP %s for %s: %s", exc.response.status_code, iid, exc
        )
        return []
    except Exception as exc:
        logger.error(
            "fetch_incident_entities unexpected error for %s: %s", iid, exc, exc_info=True
        )
        return []


async def fetch_incident_alerts(incident_url: str) -> list[dict]:
    """GET alerts linked to a Sentinel incident. Returns [] on any failure."""
    parts = parse_incident_url(incident_url)
    if not parts:
        return []

    token = await get_management_token()
    if not token:
        return []

    sub, rg, ws, iid = parts["subscription_id"], parts["resource_group"], parts["workspace_name"], parts["incident_id"]
    url = (
        f"{_MGMT_API}/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/providers/Microsoft.SecurityInsights/incidents/{iid}/alerts"
        f"?api-version={_API_VERSION}"
    )
    try:
        async with httpx.AsyncClient(verify=_VERIFY_SSL, timeout=20.0) as client:
            resp = await client.post(url, json={}, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code in (403, 404):
                logger.warning("fetch_incident_alerts: %d for incident %s", resp.status_code, iid)
                return []
            resp.raise_for_status()
            return resp.json().get("value", [])
    except Exception as exc:
        logger.error("fetch_incident_alerts unexpected error for %s: %s", iid, exc)
        return []


async def query_signin_logs(
    incident_url: str,
    upn: str,
    start_utc: str,
    end_utc: str,
) -> dict:
    """Query Log Analytics SigninLogs for a user in a given window.

    Mirrors the analytics rule KQL: unions SigninLogs + AADNonInteractiveUserSignInLogs,
    filters for password-failure error codes, and extracts location/IP/browser/OS/counts.

    Returns a dict with signin_count, location_count, locations (list),
    ip_count, ips (list), app_display_name, browser, os.
    Returns {} on any failure.
    """
    parts = parse_incident_url(incident_url)
    if not parts or not upn:
        return {}

    kql = f"""let aadFunc = (tableName:string){{
table(tableName)
| where OperationName =~ "Sign-in activity"
| where ResultType in ("50126", "50053", "50055", "50056")
| where UserPrincipalName =~ '{upn}'
| where TimeGenerated between (datetime('{start_utc}') .. datetime('{end_utc}'))
| extend DeviceDetail = todynamic(DeviceDetail), LocationDetails = todynamic(LocationDetails)
| extend OS = tostring(DeviceDetail.operatingSystem), Browser = tostring(DeviceDetail.browser)
| extend LocationString = strcat(tostring(LocationDetails.countryOrRegion), "/", tostring(LocationDetails.state), "/", tostring(LocationDetails.city))
| summarize
    StartTime        = min(TimeGenerated),
    EndTime          = max(TimeGenerated),
    LocationCount    = dcount(LocationString),
    Locations        = make_set(LocationString, 100),
    IPAddresses      = make_set(IPAddress, 100),
    IPAddressCount   = dcount(IPAddress),
    AppDisplayName   = make_set(AppDisplayName, 10),
    Browser          = make_set(Browser, 5),
    OS               = make_set(OS, 5),
    SigninCount      = count()
  by UserPrincipalName, Type
}};
let aadSignin = aadFunc("SigninLogs");
let aadNonInt = aadFunc("AADNonInteractiveUserSignInLogs");
union isfuzzy=true aadSignin, aadNonInt"""

    try:
        all_rows = await _run_la_query(parts, kql)
        if not all_rows:
            logger.info("query_signin_logs: no rows returned for %s", upn)
            return {}

            import json as _json
            def _parse_set(val):
                if isinstance(val, list):
                    return val
                try:
                    return _json.loads(val) if val else []
                except Exception:
                    return [val] if val else []

            # Merge across rows (SigninLogs + AADNonInteractiveUserSignInLogs)
            locations: list = []
            ips: list = []
            apps: list = []
            browsers: list = []
            oses: list = []
            signin_count = 0
            for row in all_rows:
                locations += [l for l in _parse_set(row.get("Locations", [])) if l not in locations]
                ips       += [ip for ip in _parse_set(row.get("IPAddresses", [])) if ip not in ips]
                apps      += [a for a in _parse_set(row.get("AppDisplayName", [])) if a not in apps]
                browsers  += [b for b in _parse_set(row.get("Browser", [])) if b not in browsers]
                oses      += [o for o in _parse_set(row.get("OS", [])) if o not in oses]
                signin_count += int(row.get("SigninCount") or 0)

            return {
                "signin_count":    str(signin_count) if signin_count else "",
                "location_count":  str(len(locations)),
                "locations":       locations,
                "ip_count":        str(len(ips)),
                "ips":             ips,
                "app_display_name": ", ".join(apps) if apps else "",
                "browser":         ", ".join(browsers) if browsers else "",
                "os":              ", ".join(oses) if oses else "",
            }
    except Exception as exc:
        logger.error("query_signin_logs unexpected error for %s: %s", upn, exc)
        return {}


def _parse_extended_properties(alerts: list[dict]) -> dict:
    """Extract sign-in detail fields from Sentinel alert extendedProperties.

    The analytics rule for password cracking stores data in one of these paths:
      alert.properties.additionalData.ExtendedProperties  (JSON string)
      alert.properties.description                         (plain text fallback)
    Returns a flat dict with whatever it can find.
    UPNs are aggregated across ALL alerts (upns: list); other fields taken from
    the first alert that has them.
    """
    import json as _json

    result: dict = {}
    all_upns: list[str] = []

    for alert in alerts:
        props = alert.get("properties") or {}
        ext_raw = (props.get("additionalData") or {}).get("ExtendedProperties", "")
        if not ext_raw:
            continue
        try:
            ext = _json.loads(ext_raw)
        except Exception:
            ext = {}

        def _get(*keys):
            for k in keys:
                for d_key in ext:
                    if d_key.lower() == k.lower():
                        return ext[d_key]
            return None

        upn = _get("UserPrincipalName", "AccountName", "UPN")
        if upn and upn not in all_upns:
            all_upns.append(upn)

        # Non-UPN fields — take from first alert that has them
        if not result.get("signin_count"):
            v = _get("SignInCount", "SigninCount", "Count")
            if v:
                result["signin_count"] = str(v)

        if not result.get("location_count"):
            v = _get("LocationCount", "UniqueLocationCount")
            if v:
                result["location_count"] = str(v)

        if not result.get("ip_count"):
            v = _get("IPsCount", "IPCount", "UniqueIPCount")
            if v:
                result["ip_count"] = str(v)

        if not result.get("locations"):
            locations_raw = _get("Locations", "LocationList")
            if locations_raw:
                try:
                    loc_list = _json.loads(locations_raw) if isinstance(locations_raw, str) else locations_raw
                    if isinstance(loc_list, list):
                        formatted = []
                        for loc in loc_list:
                            if isinstance(loc, dict):
                                parts_loc = [
                                    loc.get("CountryOrRegion", ""),
                                    loc.get("State", loc.get("Region", "")),
                                    loc.get("City", ""),
                                ]
                                formatted.append(" / ".join(p for p in parts_loc if p))
                            elif isinstance(loc, str):
                                formatted.append(loc)
                        result["locations"] = formatted
                except Exception:
                    pass

        if not result.get("app_display_name"):
            v = _get("AppDisplayName", "Application", "ResourceDisplayName")
            if v:
                result["app_display_name"] = v

        if not result.get("browser"):
            v = _get("Browser", "UserAgent", "BrowserFamily")
            if v:
                result["browser"] = v

        if not result.get("os"):
            v = _get("OperatingSystem", "OS", "OSFamily", "DeviceOS")
            if v:
                result["os"] = v

        if not result.get("start_time"):
            v = _get("StartTime", "FirstSeen")
            if v:
                result["start_time"] = v

        if not result.get("end_time"):
            v = _get("EndTime", "LastSeen")
            if v:
                result["end_time"] = v

    if all_upns:
        result["upn"]  = all_upns[0]   # backward compat
        result["upns"] = all_upns
    return result


def extract_signin_details(incident: dict, entities: list[dict], alerts: list[dict]) -> dict:
    """Build a unified sign-in details dict from incident, entities, and alerts.

    Merges:
    - Incident firstActivityTimeUtc / lastActivityTimeUtc
    - Account entities (target UPN)
    - IP entities (source IPs)
    - Alert extendedProperties (location list, browser, OS, counts)
    """
    result: dict = {}

    # Incident times
    inc_props = (incident.get("properties") or {})
    if inc_props.get("firstActivityTimeUtc"):
        result["start_time"] = inc_props["firstActivityTimeUtc"].replace("T", " ").replace("Z", " UTC")[:23]
    if inc_props.get("lastActivityTimeUtc"):
        result["end_time"] = inc_props["lastActivityTimeUtc"].replace("T", " ").replace("Z", " UTC")[:23]

    # Entity summary
    ent = extract_entity_summary(entities)
    result["accounts"] = ent.get("accounts", [])
    result["ips"]      = ent.get("ips", [])
    result["hosts"]    = ent.get("hosts", [])   # Netskope: source hostname(s)
    result["urls"]     = ent.get("urls", [])    # Netskope: accessed URL(s)

    # Extended properties from alerts (richer than entities)
    ext = _parse_extended_properties(alerts)
    for upn in reversed(ext.get("upns") or ([ext["upn"]] if ext.get("upn") else [])):
        if upn not in result["accounts"]:
            result["accounts"].insert(0, upn)
    if ext.get("signin_count"):
        result["signin_count"] = ext["signin_count"]
    if ext.get("location_count"):
        result["location_count"] = ext["location_count"]
    if ext.get("ip_count"):
        result["ip_count"] = ext["ip_count"]
    if ext.get("locations"):
        result["locations"] = ext["locations"]
    if ext.get("app_display_name"):
        result["app_display_name"] = ext["app_display_name"]
    if ext.get("browser"):
        result["browser"] = ext["browser"]
    if ext.get("os"):
        result["os"] = ext["os"]
    if ext.get("start_time") and "start_time" not in result:
        result["start_time"] = ext["start_time"]
    if ext.get("end_time") and "end_time" not in result:
        result["end_time"] = ext["end_time"]

    return result


async def extract_signin_details_async(
    incident_url: str,
    incident: dict,
    entities: list[dict],
    alerts: list[dict],
) -> dict:
    """Like extract_signin_details but falls back to query_signin_logs when
    extended properties don't contain location/IP data (e.g. analytics rules
    that don't embed ExtendedProperties).
    """
    result = extract_signin_details(incident, entities, alerts)

    if not result.get("locations") and not result.get("ips"):
        upn   = result["accounts"][0] if result.get("accounts") else ""
        start = (incident.get("properties") or {}).get("firstActivityTimeUtc", "")
        end   = (incident.get("properties") or {}).get("lastActivityTimeUtc", "")
        if upn and start and end:
            logger.info("Falling back to Log Analytics query_signin_logs for %s", upn)
            signin_data = await query_signin_logs(incident_url, upn, start, end)
            for k, v in signin_data.items():
                if v and not result.get(k):
                    result[k] = v

    return result


def extract_entity_summary(entities: list[dict]) -> dict:
    """Parse a Sentinel entity list into a structured summary dict.

    Returns:
        {
            "accounts": ["user@domain.com", ...],  # AccountEntity
            "ips":      ["1.2.3.4", ...],           # IpEntity
            "hosts":    ["hostname.domain", ...],   # HostEntity
            "urls":     ["https://...", ...],        # UrlEntity
        }
    """
    accounts: list[str] = []
    ips: list[str] = []
    hosts: list[str] = []
    urls: list[str] = []
    process_commands: list[str] = []   # command lines of the FLAGGED processes in the alert

    for entity in (entities or []):
        kind = (entity.get("kind") or "").lower()
        props = entity.get("properties") or {}

        if kind == "process":
            cl = (props.get("commandLine") or "").strip()
            # Skip bare PIDs / empties; dedup — the alert often lists the same
            # flagged command many times. These are the commands L1 actually cites.
            if cl and not cl.isdigit() and cl not in process_commands:
                process_commands.append(cl)
            elif not cl:
                # Service/persistence alerts carry the executable in imageFile with no
                # commandLine — capture the file name so the service list isn't lost
                # (DEMO-106568). Additive; command-based alerts keep their commandLine.
                img = props.get("imageFile") or {}
                nm = ""
                if isinstance(img, dict):
                    nm = ((img.get("properties") or {}).get("fileName")
                          or img.get("fileName") or img.get("name") or "")
                nm = (nm or "").strip()
                if nm and not nm.isdigit() and nm not in process_commands:
                    process_commands.append(nm)
            continue

        if kind == "account":
            upn = props.get("userPrincipalName", "")
            if upn:
                accounts.append(upn)
            else:
                name   = props.get("accountName", "")
                suffix = props.get("upnSuffix", "")
                if name and "@" in name:          # Name already carries the domain
                    accounts.append(name)
                elif name and suffix:
                    accounts.append(f"{name}@{suffix}")
                elif name:
                    accounts.append(name)

        elif kind == "ip":
            addr = props.get("address", "")
            if addr:
                ips.append(addr)

        elif kind == "host":
            host_name  = props.get("hostName", "")
            dns_domain = props.get("dnsDomain", "")
            if host_name and dns_domain:
                hosts.append(f"{host_name}.{dns_domain}")
            elif host_name:
                hosts.append(host_name)

        elif kind == "url":
            u = props.get("url", "")
            if u:
                urls.append(u)

    return {
        "accounts": accounts,
        "ips":      ips,
        "hosts":    hosts,
        "urls":     urls,
        "process_commands": process_commands,
    }


# AWS CloudTrail / SSM field parsers — colon-separated in Sentinel alert descriptions
_CLOUDTRAIL_RE = {
    "device_name":    re.compile(r'Device\s+Name\s*:\s*(.+)',                                                   re.IGNORECASE),
    "time_generated": re.compile(r'Time\s+Generated\s*(?:\([^)]*\))?\s*:\s*(.+)',                              re.IGNORECASE),
    "account_name":   re.compile(r'Account\s+Name\s*:\s*(.+)',                                                  re.IGNORECASE),
    "event_name":     re.compile(r'Event\s+Name\s*:\s*(.+)',                                                    re.IGNORECASE),
    "instance_id":    re.compile(r'Instance\s+ID\s*:\s*(\S+)',                                                  re.IGNORECASE),
    "session_issuer": re.compile(r'Session\s+Issuer\s+User\s+Name\s*:\s*(.+)',                                  re.IGNORECASE),
    "user_arn":       re.compile(r'User\s+Identity\s+ARN\s*:\s*(.+)',                                           re.IGNORECASE),
    "command":        re.compile(r'Initiating\s+Command\s*:\s*(.+)',                                            re.IGNORECASE),
    "source_ip":      re.compile(r'(?:IP\s+[Aa]ddress|Source\s+IP|ipAddressV4)\s*[:\s]*(\d{1,3}(?:\.\d{1,3}){3})', re.IGNORECASE),
    "user_name":      re.compile(r'(?:User\s+Name|userName)\s*:\s*(\S+)',                                       re.IGNORECASE),
    "guardduty_link": re.compile(r'(?:FindingLink|Finding\s+Link)\s*:\s*(https?://\S+)',                        re.IGNORECASE),
}


def extract_cloudtrail_details(
    incident: dict,
    entities: list[dict],
    alerts: list[dict],
) -> dict:
    """Extract AWS CloudTrail / SSM context from a Sentinel incident.

    Parses structured fields (Device Name, Instance ID, SSM command, User ARN, etc.)
    from the alert description text, supplemented by Sentinel entity data.
    Returns an empty dict if no CloudTrail indicators are found.
    """
    result: dict = {}

    import json as _json

    # Entity summary — host, account, IP, and URL from Sentinel entities
    ent = extract_entity_summary(entities)
    if ent.get("hosts"):
        result["device_name"] = ent["hosts"][0]
    if ent.get("accounts"):
        # An Account entity is only an ARN when it actually IS one. Assigning a bare
        # UPN to `user_arn` made the playbook print "*User ARN:* taylor.singh@example.com"
        # on a Netskope alert (DEMO-107416) and fed a non-AWS identity to the ARN parser.
        # The actor resolution in pipeline.py reads sentinel_entities["accounts"][0]
        # independently, so nothing loses the user by keeping this field honest.
        _acct0 = ent["accounts"][0]
        if _acct0.lower().startswith("arn:"):
            result["user_arn"] = _acct0
        else:
            result["entity_account"] = _acct0
    if ent.get("ips"):
        result["source_ip"] = ent["ips"][0]
    if ent.get("urls"):
        # GuardDuty finding link comes through as a URL entity
        result["guardduty_link"] = ent["urls"][0]
    if ent.get("process_commands"):
        # The FLAGGED process command lines from the alert's Process entities —
        # this is what L1 actually cites (e.g. tee/flux/scrub), not the whole
        # device process history. Preferred over the KQL make_list fallback.
        result["command_lines"] = ent["process_commands"]
        result["command"] = "; ".join(ent["process_commands"])

    # Parse CloudTrail structured fields from each alert's description + ExtendedProperties
    for alert in alerts:
        props = alert.get("properties") or {}

        # Regex-match the alert description text
        text = props.get("description", "")
        for key, pat in _CLOUDTRAIL_RE.items():
            if key not in result:
                m = pat.search(text)
                if m:
                    result[key] = m.group(1).strip()

        # Parse ExtendedProperties JSON for GuardDuty-specific fields
        ext_raw = (props.get("additionalData") or {}).get("ExtendedProperties", "")
        if ext_raw:
            try:
                ext = _json.loads(ext_raw)
            except Exception:
                ext = {}

            def _get(*keys):
                for k in keys:
                    for dk in ext:
                        if dk.lower() == k.lower():
                            return ext[dk]
                return None

            if not result.get("user_name"):
                v = _get("userName", "UserName")
                if v:
                    result["user_name"] = str(v)
            if not result.get("source_ip"):
                v = _get("ipAddressV4", "SourceIpAddress", "RemoteIpAddress")
                if v:
                    result["source_ip"] = str(v)
            if not result.get("access_key_id"):
                v = _get("accessKeyId", "AccessKeyId")
                if v:
                    result["access_key_id"] = str(v)
            if not result.get("guardduty_link"):
                v = _get("FindingLink", "findingLink")
                if v:
                    result["guardduty_link"] = str(v)

            # MFA status from sessionContext.attributes.mfaStatus
            if not result.get("mfa_status"):
                sc_raw = _get("sessionContext", "SessionContext")
                if sc_raw:
                    try:
                        sc = _json.loads(sc_raw) if isinstance(sc_raw, str) else sc_raw
                        mfa = (sc.get("attributes") or {}).get("mfaStatus", "")
                        if mfa:
                            result["mfa_status"] = mfa
                    except Exception:
                        pass

            # IP geolocation from GuardDuty city/country/organization fields
            if not result.get("ip_geo"):
                parts = []
                try:
                    city_raw = _get("city", "City")
                    city = (_json.loads(city_raw) if isinstance(city_raw, str) else city_raw or {})
                    if city.get("cityName"):
                        parts.append(city["cityName"])
                except Exception:
                    pass
                try:
                    country_raw = _get("country", "Country")
                    country = (_json.loads(country_raw) if isinstance(country_raw, str) else country_raw or {})
                    if country.get("countryName"):
                        parts.append(country["countryName"])
                except Exception:
                    pass
                try:
                    org_raw = _get("organization", "Organization")
                    org = (_json.loads(org_raw) if isinstance(org_raw, str) else org_raw or {})
                    isp = org.get("isp") or org.get("asnOrg", "")
                    if isp:
                        parts.append(f"via {isp}")
                except Exception:
                    pass
                if parts:
                    result["ip_geo"] = ", ".join(parts)

    # Incident firstActivityTime as fallback for time_generated
    if not result.get("time_generated"):
        t = (incident.get("properties") or {}).get("firstActivityTimeUtc", "")
        if t:
            result["time_generated"] = t

    # Return whatever we found — even just device_name + time is useful
    # (caller checks for non-empty dict)
    return result


def _principal(arn: str) -> str:
    from edr_triage.playbooks.generic import _arn_session_user
    return (_arn_session_user(arn or "") or (arn or "")).strip()


def annotate_session_ambiguity(primary: dict, rows: list[dict]) -> dict:
    """Record every SSM session principal on the PRIMARY host, and flag the actor as
    ambiguous when there is more than one.

    Root Privilege Escalation joins a root process to the SSM StartSession events on the
    same instance by time window only, so when two people had sessions on the box the
    telemetry cannot say which of them ran the command. DEMO-112299: `v-quinn.foster`
    and `v-shreyas.jadhav` both used ssm-session-nerve-charlie-role on the same instance;
    RAPTOR named one of them, arbitrarily. An ambiguous actor must never be auto-closed
    or have one person asked to justify it — the gate in agent_core/loop.py and the
    pipeline's close gate both read `actor_ambiguous`.
    """
    dev = (primary.get("device_name") or "").lower()
    principals = sorted({_principal(r.get("user_arn", "")) for r in [primary, *rows]
                         if isinstance(r, dict) and r.get("user_arn")
                         and (r.get("device_name") or "").lower() == dev} - {""})
    if principals:
        primary["session_principals"] = principals
        # Kept so privesc_guard.resolve_ambiguity can check each person's session.
        primary["session_arns"] = sorted({r["user_arn"] for r in [primary, *rows]
                                          if isinstance(r, dict) and r.get("user_arn")
                                          and (r.get("device_name") or "").lower() == dev})
    primary["actor_ambiguous"] = len(principals) > 1
    return primary


def merge_replica_rows(rows: list[dict]) -> dict:
    """Fold every row of the CloudTrail replica query into one deterministic dict.

    The rows arrive ordered (DeviceName, UserIdentityArn, SessionStart desc), so the
    primary is stable across runs. Commands are the union over every row of the primary
    host — rows differ by initiating account, and keeping one row dropped the others'
    commands. More than one host (the deviceless sweep) or more than one session
    principal on the host marks the actor ambiguous.
    """
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        return {}
    first = rows[0]
    dev = first.get("DeviceName", "")
    same = [r for r in rows if r.get("DeviceName", "") == dev]
    cmds: list[str] = []
    for r in same:
        for c in str(r.get("InitiatingCommands") or "").split("; "):
            if c.strip() and c not in cmds:
                cmds.append(c)
    result: dict = {}
    if dev:                                   result["device_name"]    = dev
    if first.get("TimeGenerated"):            result["time_generated"] = str(first["TimeGenerated"])
    if first.get("AccountName"):              result["account_name"]   = first["AccountName"]
    if first.get("EventName"):                result["event_name"]     = first["EventName"]
    if first.get("InstanceId"):               result["instance_id"]    = first["InstanceId"]
    if first.get("SessionIssuerUserName"):    result["session_issuer"] = first["SessionIssuerUserName"]
    if first.get("UserIdentityArn"):          result["user_arn"]       = first["UserIdentityArn"]
    if cmds:                                  result["command"]        = "; ".join(cmds[:40])
    annotate_session_ambiguity(result, [{"device_name": r.get("DeviceName", ""),
                                         "user_arn": r.get("UserIdentityArn", "")} for r in same])
    devices = sorted({r.get("DeviceName", "") for r in rows} - {""})
    if len(devices) > 1:
        # Deviceless sweep matched several hosts: which one this alert is about is unknown.
        result["candidate_devices"] = devices
        result["actor_ambiguous"] = True
    return result


async def query_cloudtrail_event(
    incident_url: str,
    device_name: str,
    alert_time_utc: str,
) -> dict:
    """Query Log Analytics for the CloudTrail/SSM event that triggered the alert.

    Replicates the Root Privilege Escalation analytics rule KQL with a fixed
    time window (±90 min around the alert time) so we get Instance ID,
    session issuer, user ARN, initiating command, and account name.

    Requires Log Analytics Reader RBAC on the workspace.
    Returns {} on permission error or no results.
    """
    parts = parse_incident_url(incident_url)
    if not parts or not device_name or not alert_time_utc:
        return {}

    # Parse alert time and build ±90 min window
    try:
        from datetime import datetime, timedelta, timezone
        t = datetime.fromisoformat(alert_time_utc.replace("Z", "+00:00"))
        start = (t - timedelta(minutes=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end   = (t + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return {}

    # Adapted from the analytics rule KQL — fixed time window, specific device
    kql = f"""
let start_time = datetime('{start}');
let end_time   = datetime('{end}');
let target_device = "{device_name}";
let ProcessData =
    DeviceProcessEvents
    | where TimeGenerated between (start_time .. end_time)
    | where DeviceName has target_device
    | where AccountName == "root"
    | where not(isempty(InitiatingProcessAccountName))
    // Exclude routine agent/onboarding/system noise so the command set reflects
    // real activity, not host background chatter (this was producing 600KB blobs).
    | where InitiatingProcessCommandLine !has "MdeInstallerWrapper"
        and InitiatingProcessCommandLine !has "/usr/lib/postfix"
        and InitiatingProcessCommandLine !has "amazon/ssm"
        and InitiatingProcessCommandLine !has "inspector-vm-scanner"
        and InitiatingProcessCommandLine !has "needrestart"
        and InitiatingProcessCommandLine !has "dpkg"
        and InitiatingProcessCommandLine !has "/snap/"
        and InitiatingProcessCommandLine !has "cloud-init"
        and InitiatingProcessCommandLine !has "runc --root"
    | summarize
        // make_set dedups identical commands (make_list kept every repeat);
        // cap at 40 so a busy host can't flood the result.
        InitiatingCommands = make_set(InitiatingProcessCommandLine, 40),
        TimeGenerated = arg_max(TimeGenerated, *)
        by DeviceName, AccountName, InitiatingProcessAccountName;
let DeviceInfoData =
    DeviceInfo
    | where TimeGenerated between (start_time .. end_time)
    | extend InstanceId = extract(@"machines/(.+)$", 1, AzureResourceId)
    | where isnotempty(InstanceId)
    | distinct DeviceName, InstanceId;
let AWSData =
    AWSCloudTrail
    | where TimeGenerated between (start_time .. end_time)
    | where EventSource contains "ssm.amazonaws.com"
    | where EventName == "StartSession"
    | extend InstanceId = tostring(parse_json(RequestParameters).target)
    // Only sessions that actually opened on a machine. A failed or denied StartSession
    // has no target, and an empty InstanceId on BOTH sides is a match in a Kusto join:
    // whenever the DeviceInfo lookup missed, a failed request anywhere in the fleet became
    // "the actor" (DEMO-114340 named jit-s3-rw-somendra-raj, who never reached the host).
    | where isnotempty(InstanceId) and isempty(ErrorCode)
    | project InstanceId, SessionIssuerUserName, UserIdentityArn, EventName,
              SessionStart = TimeGenerated;
let Enriched = ProcessData | join kind=leftouter DeviceInfoData on DeviceName;
Enriched
| join kind=leftouter AWSData on InstanceId
| project DeviceName, TimeGenerated, AccountName,
          InitiatingCommands = strcat_array(InitiatingCommands, "; "),
          InstanceId, SessionIssuerUserName, UserIdentityArn, EventName, SessionStart
// Every joined row, in a fixed order. This used to be `take 1`, which kept ONE of up
// to N (initiating account x DeviceInfo row x SSM session) rows at random — so both
// the actor and the command set were arbitrary (DEMO-112299). merge_replica_rows()
// unions the commands and flags more than one session principal as ambiguous.
| order by DeviceName asc, UserIdentityArn asc, SessionStart desc
| take 200
"""

    try:
        rows = await _run_la_query(parts, kql)
        if not rows:
            logger.info("query_cloudtrail_event: no rows for device=%s window=%s→%s", device_name, start, end)
            return {}

        result = merge_replica_rows(rows)
        logger.info(
            "query_cloudtrail_event: %d row(s) for %s — instance=%s principals=%s%s",
            len(rows), device_name, result.get("instance_id"),
            result.get("session_principals"), " AMBIGUOUS" if result.get("actor_ambiguous") else "",
        )
        return result

    except Exception as exc:
        logger.error("query_cloudtrail_event unexpected error for %s: %s", device_name, exc)
        return {}


# URLs inside a PowerShell command (for benign-source hinting).
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)

def _is_ps_noise(cmd: str) -> bool:
    """True if a PowerShellCommand line is cmdlet-internal tracing, not a user command."""
    c = cmd.strip()
    if c.startswith("$"):                       # variable assignments inside a cmdlet
        return True
    low = c.lower()
    _noise = (
        "helper", "write-progress", "progressbar", "resolve-path", "psconsolehost",
        "prompt", "$pscmdlet", "compressionassemblies", "[ref]", "-erroraction stop",
    )
    return any(tok in low for tok in _noise)


# LOLBin / living-off-the-land signatures — the patterns the NRT rule keys on.
# Filtering to these is what isolates the *triggering* PowerShellCommand event
# from the firehose of benign monitoring scripts (which also log as PowerShellCommand).
_LOLBIN_INDICATORS = [
    "invoke-webrequest", "iwr ", "invoke-expression", "iex ", "downloadstring",
    "downloadfile", "net.webclient", "start-bitstransfer", "frombase64string",
    "-enc ", "-encodedcommand", "reflection.assembly", ".load(", "new-object net",
    "bitsadmin", "certutil", "wget ", "curl ",
]


def decode_compressed_recs(ext_props) -> list[dict]:
    """Decode the matched event row(s) embedded in a Sentinel alert's
    ExtendedProperties.Query as a `compressedRec` datatable (base64 + zlib of JSON).

    This is the ONLY reliable per-alert binding for scheduled/NRT rules whose
    incident + SecurityAlert.Entities are empty: Sentinel embeds the exact row(s)
    that triggered THIS alert here. Returns a list of flattened event dicts
    (AdditionalFields merged up so e.g. `Command` is top-level)."""
    import base64, zlib, json as _json
    if not ext_props:
        return []
    q = ext_props
    if isinstance(ext_props, dict):
        q = ext_props.get("Query", "")
    elif isinstance(ext_props, str):
        try:
            q = _json.loads(ext_props).get("Query", "")
        except Exception:
            q = ext_props
    out: list[dict] = []
    for b64 in re.findall(r"'(e[A-Za-z0-9+/=]{40,})'", q or ""):
        try:
            obj = _json.loads(zlib.decompress(base64.b64decode(b64)).decode("utf-8", "replace"))
        except Exception:
            continue
        for o in (obj if isinstance(obj, list) else [obj]):
            if isinstance(o, dict):
                af = o.pop("AdditionalFields", None)
                if isinstance(af, dict):
                    o.update(af)
                out.append(o)
    return out


async def query_sentinel_alert(incident_url: str, alert_id: str) -> dict:
    """Fetch a SPECIFIC Sentinel alert's OWN triggering event from SecurityAlert.

    Binds enrichment to the ticket's own alert instead of guessing from the grouped
    incident — the fix for cross-attribution (DEMO-104199, where a grouped incident's
    time-window hunt pulled a different alert's host). The portal alertLink id is
    "sn<guid>"; that guid is SecurityAlert.VendorOriginalId (NOT SystemAlertId).

    Reads the alert's Entities first; when those are empty (the common case for
    scheduled/NRT rules), decodes the compressedRec-embedded matched event.
    Returns {device_name, account_name, command_lines, alert_name, event_time} or {}.
    """
    parts = parse_incident_url(incident_url)
    if not parts or not alert_id:
        return {}
    guid = alert_id[2:] if alert_id.lower().startswith("sn") else alert_id
    kql = f"""
SecurityAlert
| where VendorOriginalId in ("{guid}", "{alert_id}") or SystemAlertId in ("{guid}", "{alert_id}")
| top 1 by TimeGenerated desc
| project TimeGenerated, AlertName, CompromisedEntity, Entities, ExtendedProperties
"""
    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.error("query_sentinel_alert error for %s: %s", alert_id, exc)
        return {}
    if not rows:
        return {}
    row = rows[0]

    import json as _json
    def _load(v):
        if isinstance(v, (list, dict)):
            return v
        try:
            return _json.loads(v) if v else []
        except Exception:
            return []

    ents = _load(row.get("Entities"))
    host = account = ""
    hosts: list[str] = []   # EVERY host entity — a grouped SSM/privesc alert lists >1
    cmds: list[str] = []
    event_time = str(row.get("TimeGenerated", ""))
    for e in ents if isinstance(ents, list) else []:
        if not isinstance(e, dict):
            continue
        etype = str(e.get("Type") or e.get("kind") or "").lower()
        if etype in ("host", "machine"):
            hn = e.get("HostName") or e.get("NetBiosName") or ""
            dom = e.get("DnsDomain") or ""
            h = f"{hn}.{dom}" if hn and dom else hn
            if h and h not in hosts:
                hosts.append(h)
            if not host:               # first host stays the primary binder
                host = h
            continue
        elif etype == "account" and not account:
            nm = e.get("Name") or ""
            upns = e.get("UPNSuffix") or ""
            # Don't re-append the suffix when Name already carries the domain,
            # else we get "user@example.com@example.com".
            if nm and "@" in nm:
                account = nm
            elif nm and upns:
                account = f"{nm}@{upns}"
            else:
                account = nm or e.get("AadUserId") or ""
        elif etype == "process":
            cl = e.get("CommandLine") or ""
            if cl:
                cmds.append(cl)
            else:
                # "Rare process as a service" / persistence alerts list the flagged
                # executable in the process entity's ImageFile with an EMPTY CommandLine
                # (a long-running service has no captured launch command). Fall back to
                # the image/file name so the service list isn't silently dropped — without
                # it the deterministic process-check + MDE vendor enrichment never fire
                # and the agent escalates "no telemetry" on benign signed services
                # (DEMO-106568). Additive: command-based alerts keep their CommandLine.
                img = e.get("ImageFile") or e.get("imageFile") or {}
                nm = ""
                if isinstance(img, dict):
                    nm = (img.get("Name") or img.get("name")
                          or (img.get("properties") or {}).get("fileName") or "")
                nm = (nm or e.get("Name") or "").strip()
                if nm and not nm.isdigit() and nm not in cmds:
                    cmds.append(nm)
    if not host:
        host = row.get("CompromisedEntity") or ""

    # Entities empty (scheduled/NRT rule) → recover the bound event(s) from
    # compressedRec. A grouped rule embeds one row PER host, so collect every
    # DeviceName — not just the first — to keep the full host set (line-up with
    # the Entities path above).
    if not (host or account or cmds):
        events = decode_compressed_recs(row.get("ExtendedProperties"))
        if events:
            ev = events[0]
            host = ev.get("DeviceName") or ev.get("Computer") or host
            account = (ev.get("InitiatingProcessAccountName") or ev.get("AccountName")
                       or ev.get("UserId") or account)
            event_time = ev.get("Timestamp") or ev.get("TimeGenerated") or event_time
            for e in events:
                dn = e.get("DeviceName") or e.get("Computer") or ""
                if dn and dn not in hosts:
                    hosts.append(dn)
                c = (e.get("Command") or e.get("ProcessCommandLine")
                     or e.get("InitiatingProcessCommandLine") or "")
                if c and c not in cmds:
                    cmds.append(c)

    # Ensure the primary binder is in the host set (CompromisedEntity fallback,
    # or the first entity when no explicit host list was built).
    if host and host not in hosts:
        hosts.insert(0, host)

    # The rule's custom details as recorded when it FIRED — for Root Privilege Escalation
    # the matched commands and session ARNs. Unlike a rule replay (its query uses ago(),
    # so re-running it later can come back empty) this cannot drift with the clock. Read
    # before the empty-alert check: a Port Sweep alert has no entities at all, only its
    # destination list here (DEMO-117045 said "hosts listed" and listed none).
    _ext = _load(row.get("ExtendedProperties"))
    _cd = _load(_ext.get("Custom Details")) if isinstance(_ext, dict) else {}
    if not (host or account or cmds or (isinstance(_cd, dict) and _cd)):
        return {}
    return {
        "device_name": host,
        "account_name": account,
        "hosts": hosts,            # ALL hosts on the alert — the replay host-filter source
        "command_lines": cmds,
        "alert_name": row.get("AlertName", ""),
        "event_time": event_time,
        "custom_details": _cd if isinstance(_cd, dict) else {},
    }


async def query_powershell_script_load(
    incident_url: str,
    alert_time_utc: str,
    window_minutes: int = 90,
    scope_device: str = "",
) -> dict:
    """Enrich a Sentinel NRT 'PowerShell script was loaded in memory' alert.

    These NRT alerts arrive with NO incident entities and empty AlertEvidence —
    the command, device, and account only exist in DeviceEvents where
    ActionType == 'PowerShellCommand' (script text in AdditionalFields.Command).

    Strategy: PowerShellCommand is high-volume telemetry, so we DON'T pick the
    busiest host. We filter to the LOLBin signatures the rule keys on, anchor on
    the matching event closest to the alert time, then pull that host's command
    sequence for context. Returns {} on permission error / no results.

    When `scope_device` is given (the host from the alert's OWN entities), the hunt
    is filtered to that host — eliminating the cross-attribution risk of picking a
    different concurrent alert's host from a shared/grouped incident.
    """
    parts = parse_incident_url(incident_url)
    if not parts or not alert_time_utc:
        return {}
    try:
        from datetime import datetime, timedelta
        t = datetime.fromisoformat(alert_time_utc.replace("Z", "+00:00"))
        start = (t - timedelta(minutes=window_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end   = (t + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return {}

    has_any = ", ".join(f'"{i}"' for i in _LOLBIN_INDICATORS)
    _dev_filter = f'| where DeviceName == "{scope_device}"\n' if scope_device else ""
    anchor_kql = f"""
DeviceEvents
| where TimeGenerated between (datetime('{start}') .. datetime('{end}'))
| where ActionType == "PowerShellCommand"
{_dev_filter}| extend Command = tostring(parse_json(AdditionalFields).Command)
| where isnotempty(Command)
| where Command has_any ({has_any})
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessCommandLine, Command
| order by TimeGenerated asc
| take 100
"""
    try:
        rows = await _run_la_query(parts, anchor_kql)
    except Exception as exc:
        logger.error("query_powershell_script_load error: %s", exc)
        return {}
    if not rows:
        return {}

    # Anchor = the LOLBin event closest to the alert time (NRT lag is small).
    def _t(r):
        try:
            from datetime import datetime
            return datetime.fromisoformat(str(r["TimeGenerated"]).replace("Z", "+00:00"))
        except Exception:
            return t
    anchor = min(rows, key=lambda r: abs((_t(r) - t).total_seconds()))
    device = anchor.get("DeviceName", "")
    account = anchor.get("InitiatingProcessAccountName", "")

    # Pull the anchor host's full PowerShellCommand sequence in a tight window
    # around the anchor (download → expand → install tells the benign/malicious story).
    from datetime import timedelta
    at = _t(anchor)
    # Genuine ambiguity = other hosts with a LOLBin hit within ±5 min of the anchor.
    # (Distant hits are unrelated alerts, not the same trigger.)
    devices = {r.get("DeviceName") for r in rows
               if r.get("DeviceName") and abs((_t(r) - at).total_seconds()) <= 300}
    seq_start = (at - timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seq_end   = (at + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seq_kql = f"""
DeviceEvents
| where TimeGenerated between (datetime('{seq_start}') .. datetime('{seq_end}'))
| where ActionType == "PowerShellCommand"
| where DeviceName == "{device}"
| extend Command = tostring(parse_json(AdditionalFields).Command)
| where isnotempty(Command)
| project TimeGenerated, Command
| order by TimeGenerated asc
| take 40
"""
    seq_rows = await _run_la_query(parts, seq_kql)
    # De-dup while preserving order, and drop PowerShell script-internal noise
    # (cmdlet implementation lines traced as PowerShellCommand: variable
    # assignments, module helpers, progress bars, the interactive prompt).
    trigger = (anchor.get("Command", "") or "").strip()
    commands, seen = [], set()
    for r in (seq_rows or [{"Command": trigger}]):
        c = (r.get("Command") or "").strip()
        if not c or c in seen:
            continue
        seen.add(c)
        if c == trigger or not _is_ps_noise(c):
            commands.append(c)
    if trigger and trigger not in commands:      # always keep the triggering command
        commands.insert(0, trigger)
    urls = sorted({m.group(0) for c in commands for m in [_URL_RE.search(c)] if m})

    result = {
        "device_name": device,
        "account_name": account,
        "initiating_process": (anchor.get("InitiatingProcessCommandLine", "") or "").strip().strip('"') or "powershell.exe",
        "trigger_command": anchor.get("Command", ""),
        "commands": commands,
        "event_time": str(anchor.get("TimeGenerated", "")),
        "remote_urls": urls,
        "multi_device": len(devices) > 1,
        "other_devices": sorted(d for d in devices if d and d != device),
    }
    logger.info(
        "query_powershell_script_load: device=%s account=%s cmds=%d urls=%s multi_device=%s",
        device, account, len(commands), urls, result["multi_device"],
    )
    return result


async def _query_cloudtrail_no_device(incident_url: str, alert_time_utc: str) -> dict:
    """Broader fallback: query Log Analytics for root privesc CloudTrail events
    when no device name is available. Returns the first match found."""
    parts = parse_incident_url(incident_url)
    if not parts or not alert_time_utc:
        return {}
    try:
        from datetime import datetime, timedelta, timezone
        t = datetime.fromisoformat(alert_time_utc.replace("Z", "+00:00"))
        start = (t - timedelta(minutes=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end   = (t + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return {}

    kql = f"""
let start_time = datetime('{start}');
let end_time   = datetime('{end}');
let ProcessData =
    DeviceProcessEvents
    | where TimeGenerated between (start_time .. end_time)
    | where AccountName == "root"
    | where not(isempty(InitiatingProcessAccountName))
    | distinct DeviceName, AccountName, InitiatingProcessAccountName,
               InitiatingProcessCommandLine, TimeGenerated
    | summarize
        InitiatingCommands = make_list(InitiatingProcessCommandLine),
        TimeGenerated = arg_max(TimeGenerated, *)
        by DeviceName, AccountName, InitiatingProcessAccountName;
let DeviceInfoData =
    DeviceInfo
    | where TimeGenerated between (start_time .. end_time)
    | extend InstanceId = extract(@"machines/(.+)$", 1, AzureResourceId)
    | where isnotempty(InstanceId)
    | distinct DeviceName, InstanceId;
let AWSData =
    AWSCloudTrail
    | where TimeGenerated between (start_time .. end_time)
    | where EventSource contains "ssm.amazonaws.com"
    | where EventName == "StartSession"
    | extend InstanceId = tostring(parse_json(RequestParameters).target)
    // Only sessions that actually opened on a machine. A failed or denied StartSession
    // has no target, and an empty InstanceId on BOTH sides is a match in a Kusto join:
    // whenever the DeviceInfo lookup missed, a failed request anywhere in the fleet became
    // "the actor" (DEMO-114340 named jit-s3-rw-somendra-raj, who never reached the host).
    | where isnotempty(InstanceId) and isempty(ErrorCode)
    | project InstanceId, SessionIssuerUserName, UserIdentityArn, EventName,
              SessionStart = TimeGenerated;
let Enriched = ProcessData | join kind=leftouter DeviceInfoData on DeviceName;
Enriched
| join kind=leftouter AWSData on InstanceId
| project DeviceName, TimeGenerated, AccountName,
          InitiatingCommands = strcat_array(InitiatingCommands, "; "),
          InstanceId, SessionIssuerUserName, UserIdentityArn, EventName, SessionStart
// Every joined row, in a fixed order. This used to be `take 1`, which kept ONE of up
// to N (initiating account x DeviceInfo row x SSM session) rows at random — so both
// the actor and the command set were arbitrary (DEMO-112299). merge_replica_rows()
// unions the commands and flags more than one session principal as ambiguous.
| order by DeviceName asc, UserIdentityArn asc, SessionStart desc
| take 200
"""
    try:
        rows = await _run_la_query(parts, kql)
        if not rows:
            return {}
        result = merge_replica_rows(rows)
        logger.info("_query_cloudtrail_no_device: %d row(s), device=%s for window %s→%s%s",
                    len(rows), result.get("device_name"), start, end,
                    " AMBIGUOUS" if result.get("actor_ambiguous") else "")
        return result
    except Exception as exc:
        logger.error("_query_cloudtrail_no_device error: %s", exc)
        return {}


_GD_FINDING_ID = re.compile(r"[?&#]fId=([0-9a-f]{20,})", re.I)


def guardduty_finding_id(link: str) -> str:
    """The finding id in a GuardDuty console link (`...#/findings?fId=<id>`), or ""."""
    m = _GD_FINDING_ID.search(link or "")
    return m.group(1).lower() if m else ""


async def query_guardduty_details(incident_url: str, alert_time_utc: str,
                                  finding_id: str = "") -> dict:
    """Query AWSGuardDuty for the finding's details.

    By FINDING ID when the link carries one: exact, and independent of the alert time.
    DEMO-117504 searched ±2 h around the Sentinel incident's firstActivityTime (00:35 UTC)
    while the finding row was written at 02:40 UTC, so it found nothing and the comment
    lacked everything the L1 then listed by hand. Without an id it falls back to the
    newest row in that window, which can be a different finding.
    Returns {} if no match or Log Analytics is unavailable.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        return {}
    fid = re.sub(r"[^0-9a-f]", "", (finding_id or "").lower())
    if fid:
        where = f"| where TimeGenerated > ago(7d)\n| where Id == '{fid}'"
    else:
        if not alert_time_utc:
            return {}
        try:
            from datetime import datetime, timedelta
            t = datetime.fromisoformat(alert_time_utc.replace("Z", "+00:00"))
            start = (t - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            end = (t + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return {}
        where = f"| where TimeGenerated between (datetime('{start}') .. datetime('{end}'))"

    kql = f"""
AWSGuardDuty
{where}
| extend rd = todynamic(ResourceDetails)
| extend sd = todynamic(ServiceDetails)
| extend akd        = rd.accessKeyDetails
| extend inst       = rd.instanceDetails
| extend apiAction  = sd.action.awsApiCallAction
| extend remoteIp   = apiAction.remoteIpDetails
| project
    TimeGenerated,
    Title,
    ActivityType,
    Severity,
    UserName       = tostring(akd.userName),
    UserType       = tostring(akd.userType),
    AccessKeyId    = tostring(akd.accessKeyId),
    PrincipalId    = tostring(akd.principalId),
    MfaStatus      = tostring(akd.sessionContext.attributes.mfaStatus),
    InstanceId     = tostring(inst.instanceId),
    PrivateIp      = tostring(inst.networkInterfaces[0].privateIpAddress),
    Tags           = inst.tags,
    IpAddress      = tostring(remoteIp.ipAddressV4),
    CityName       = tostring(remoteIp.city.cityName),
    CountryName    = tostring(remoteIp.country.countryName),
    Isp            = tostring(remoteIp.organization.isp),
    AsnOrg         = tostring(remoteIp.organization.asnOrg),
    ServiceName    = tostring(apiAction.serviceName),
    Api            = tostring(apiAction.api),
    ErrorCode      = tostring(apiAction.errorCode),
    FirstSeen      = tostring(sd.eventFirstSeen),
    LastSeen       = tostring(sd.eventLastSeen)
| where isnotempty(UserName) or isnotempty(IpAddress) or isnotempty(InstanceId)
| order by TimeGenerated desc
| take 1
"""

    ws_guid = await get_workspace_guid(parts)
    if not ws_guid:
        return {}

    try:
        token = await get_la_token()
        import httpx as _httpx
        async with _httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.post(
                f"{_LA_API}/v1/workspaces/{ws_guid}/query",
                headers={"Authorization": f"Bearer {token}"},
                json={"query": kql},
            )
            if resp.status_code != 200:
                logger.warning("query_guardduty_details: HTTP %s", resp.status_code)
                return {}

            tables = resp.json().get("tables", [])
            if not tables or not tables[0].get("rows"):
                logger.info("query_guardduty_details: no row (finding_id=%s)", fid or "-")
                return {}

            cols = [c["name"] for c in tables[0]["columns"]]
            row  = dict(zip(cols, tables[0]["rows"][0]))
        return _guardduty_row_to_fields(row)

    except Exception as exc:
        logger.warning("query_guardduty_details failed: %s", exc)
        return {}


def _guardduty_row_to_fields(row: dict) -> dict:
    """AWSGuardDuty projection -> the cloudtrail dict keys the playbook renders."""
    import json as _json
    result: dict = {}
    for col, key in (("UserName", "user_name"), ("AccessKeyId", "access_key_id"),
                     ("PrincipalId", "principal_id"), ("MfaStatus", "mfa_status"),
                     ("IpAddress", "source_ip"), ("ServiceName", "service_name"),
                     ("Api", "event_name"), ("InstanceId", "instance_id"),
                     ("PrivateIp", "private_ip"), ("ErrorCode", "api_error_code"),
                     ("ActivityType", "finding_type"), ("FirstSeen", "event_first_seen"),
                     ("LastSeen", "event_last_seen"), ("UserType", "user_type")):
        if row.get(col):
            result[key] = str(row[col])
    if row.get("Severity") not in (None, ""):
        result["finding_severity"] = str(row["Severity"])
    tags = row.get("Tags")
    try:
        tags = _json.loads(tags) if isinstance(tags, str) else (tags or [])
        tagmap = {str(t.get("key")): str(t.get("value")) for t in tags if isinstance(t, dict)}
        if tagmap.get("Name"):
            result["instance_name"] = tagmap["Name"]
        if tagmap.get("Tribe"):
            result["instance_tribe"] = tagmap["Tribe"]
    except Exception:
        pass
    geo_parts = [p for p in [row.get("CityName"), row.get("CountryName")] if p]
    isp = row.get("Isp") or row.get("AsnOrg", "")
    if isp:
        geo_parts.append(f"via {isp}")
    if geo_parts:
        result["ip_geo"] = ", ".join(geo_parts)
    logger.info("query_guardduty_details: found userName=%s ip=%s api=%s error=%s",
                result.get("user_name"), result.get("source_ip"), result.get("event_name"),
                result.get("api_error_code"))
    return result


# GuardDuty finding families that are a DNS lookup by an EC2 instance — the shape
# query_guardduty_dns_finding reads (action.dnsRequestAction.domain). DEMO-118243: an
# SSRF probing IMDS via 169.254.169.254.nip.io (MetadataDNSRebind) and its interactsh
# callback to *.oast.live (SuspiciousDomainRequest) were dropped by a phishing/drive-by
# only filter, so the agent saw no instance, no IP and no domain.
GUARDDUTY_DNS_FAMILIES = (
    "PhishingDomainRequest", "DriveBySourceTraffic", "MetadataDNSRebind",
    "SuspiciousDomainRequest", "C&CActivity", "BlackholeTraffic",
    "DGADomainRequest", "DNSDataExfiltration",
)


async def query_guardduty_dns_finding(incident_url: str, alert_time_utc: str,
                                      instance_id: str = "") -> dict:
    """Query AWSGuardDuty for a DNS_REQUEST-shaped EC2 finding (phishing-domain /
    drive-by-source-domain — "The EC2 instance i-... queried a ... domain name").

    Same table and connection plumbing as query_guardduty_details (reused, not
    duplicated) — different finding shape: these are resourceType=Instance,
    action.actionType=DNS_REQUEST findings, not the AWS-API-call/IAM shape that
    function reads. Every one of these tickets was previously skipped entirely
    (classifier.py _SKIP_PATTERNS) — L1 has been retyping the full finding by
    hand from the AWS console every time (DEMO-110594, DEMO-106031): instance id,
    IAM instance profile, private/public IP, the queried domain, and GuardDuty's
    own threat classification (Type, formatted "<ThreatPurpose>:<ResourceType>/
    <ThreatFamilyName>", e.g. "Trojan:EC2/PhishingDomainRequest!DNS").

    ResourceDetails.instanceDetails / ServiceDetails.action.dnsRequestAction
    field paths follow AWS's own published GuardDuty finding schema (a stable,
    documented public contract) rather than a guessed proprietary layout, as
    was the case for the Netskope DLP query — meaningfully more likely correct
    on first try, but still unverified against this specific Sentinel ingestion
    connector's exact column choices. Dynamic (JSON path) field access in KQL
    degrades to null on a wrong path rather than failing the query, same safety
    property column_ifexists gives literal columns — verify on first live use.

    Returns {} when nothing binds.
    """
    parts = parse_incident_url(incident_url)
    if not parts or not alert_time_utc:
        return {}

    try:
        from datetime import datetime, timedelta, timezone
        t = datetime.fromisoformat(alert_time_utc.replace("Z", "+00:00"))
        start = (t - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end   = (t + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return {}

    # Pin to the alert's own instance when its title names one: with every DNS family
    # in the filter, an unpinned window would bind another node's findings.
    _iid = instance_id if re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id or "") else ""
    _inst_filter = f"| where tostring(inst.instanceId) == '{_iid}'" if _iid else ""
    _families = "|".join(re.escape(f) for f in GUARDDUTY_DNS_FAMILIES)

    kql = f"""
let start_time = datetime('{start}');
let end_time   = datetime('{end}');
AWSGuardDuty
| where TimeGenerated between (start_time .. end_time)
| where ActivityType matches regex @"({_families})"
    or Title has_any ("phishing domain", "drive-by")
| extend rd = todynamic(ResourceDetails)
| extend sd = todynamic(ServiceDetails)
| extend inst      = rd.instanceDetails
| extend dnsAction = sd.action.dnsRequestAction
{_inst_filter}
| project
    TimeGenerated,
    Title,
    ActivityType,
    Region,
    Partition,
    TenantId,
    AccountId        = column_ifexists("AccountId", ""),
    InstanceId       = tostring(inst.instanceId),
    InstanceProfile  = tostring(inst.iamInstanceProfile.arn),
    PrivateIp        = tostring(inst.networkInterfaces[0].privateIpAddress),
    PublicIp         = tostring(inst.networkInterfaces[0].publicIp),
    Domain           = tostring(dnsAction.domain),
    ActionType       = tostring(sd.action.actionType),
    DetectorId       = tostring(sd.detectorId),
    FindingLink      = column_ifexists("FindingLink", "")
| order by TimeGenerated desc
| take 25
"""

    ws_guid = await get_workspace_guid(parts)
    if not ws_guid:
        return {}

    try:
        token = await get_la_token()
        import httpx as _httpx
        async with _httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.post(
                f"{_LA_API}/v1/workspaces/{ws_guid}/query",
                headers={"Authorization": f"Bearer {token}"},
                json={"query": kql},
            )
            if resp.status_code != 200:
                logger.warning("query_guardduty_dns_finding: HTTP %s", resp.status_code)
                return {}

            tables = resp.json().get("tables", [])
            if not tables or not tables[0].get("rows"):
                return {}

            cols = [c["name"] for c in tables[0]["columns"]]
            rows = [dict(zip(cols, r)) for r in tables[0]["rows"]]

        row = rows[0]  # newest — carries the instance/account facts, identical across rows
        result: dict = {k: v for k, v in row.items() if v not in (None, "")}
        # GuardDuty's finding Type is "<ThreatPurpose>:<ResourceTypeAffected>/<ThreatFamilyName>"
        # (e.g. "Trojan:EC2/PhishingDomainRequest!DNS") — split it into the three fields
        # L1's own comment template names separately, rather than showing the raw string.
        # `Type` on this table is the table name ("AWSGuardDuty"); the finding type is
        # ActivityType, so the three threat fields below never rendered before.
        _type = str(row.get("ActivityType") or "")
        if ":" in _type and "/" in _type:
            purpose, rest = _type.split(":", 1)
            resource_type, family = rest.split("/", 1)
            result["threat_purpose"] = purpose
            result["resource_type_affected"] = resource_type
            result["threat_family_name"] = family

        # EVERY domain and finding link in the window, not just the newest. One
        # GuardDuty DNS incident routinely covers several queried domains, and L1's own
        # comment lists them all — DEMO-110711 named five (dysonc.com, homvela.com,
        # heavty.com, fivejm.com, savdz.com) with a finding link each. The original
        # `take 1` reduced that to one domain, i.e. strictly less than L1 already
        # writes by hand, which defeats the point of the playbook.
        result["domains"] = list(dict.fromkeys(
            str(r.get("Domain") or "").strip() for r in rows if (r.get("Domain") or "").strip()
        ))
        result["finding_links"] = list(dict.fromkeys(
            str(r.get("FindingLink") or "").strip() for r in rows if (r.get("FindingLink") or "").strip()
        ))
        result["finding_count"] = len(rows)
        # Every finding type in the window: the newest row alone decides threat_purpose,
        # and one node can carry an IMDS rebind and an OAST callback side by side.
        result["finding_types"] = list(dict.fromkeys(
            str(r.get("ActivityType") or "").strip() for r in rows
            if (r.get("ActivityType") or "").strip()
        ))

        logger.info("query_guardduty_dns_finding: instance=%s domains=%s findings=%d",
                    result.get("InstanceId"), result.get("domains"), len(rows))
        return result

    except Exception as exc:
        logger.warning("query_guardduty_dns_finding failed: %s", exc)
        return {}


async def query_identity_grant_for_pim(incident_url: str, recipient: str, alert_time_utc: str = "") -> dict:
    """Resolve WHO granted a privileged role to `recipient` outside the PIM flow —
    "Privileged Role Assigned Outside PIM" alerts, previously classifier.py
    _SKIP_PATTERNS (never triaged at all).

    Reuses lib.kql_templates.sentinel_identity_grant verbatim — the SAME KQL
    template already proven live this project (DEMO-106406: correctly resolved
    tatum.shah as the grantor for hayden.roy's 5 admin-role grants)
    via the agent loop's hunt_identity_grant tool. This just runs that same query
    text through the deterministic playbook's own connection path (_run_la_query)
    instead of the agent tool's (lib.mde_client.run_sentinel_query) — same
    query, same correctness, different caller.

    Returns {} when nothing binds or `recipient` is empty (unscoped AuditLogs
    queries return unrelated tenant-wide grants — sentinel_identity_grant itself
    refuses to build one; this mirrors that by simply not calling it).
    """
    if not recipient:
        return {}
    parts = parse_incident_url(incident_url)
    if not parts:
        return {}

    from lib.kql_templates import sentinel_identity_grant
    anchor = (alert_time_utc or "").replace(" ", "T")[:19]
    try:
        kql = sentinel_identity_grant(recipient=recipient, window_hours=24,
                                      anchor_iso=f"{anchor}Z" if anchor else "")
    except ValueError:
        return {}

    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.warning("query_identity_grant_for_pim failed: %s", exc)
        return {}
    if not rows:
        return {}

    row = rows[0]  # highest-event-count grantor for this recipient in the window
    result = {k: v for k, v in row.items() if v not in (None, "", [])}
    logger.info("query_identity_grant_for_pim: recipient=%s grantor=%s roles=%s",
                recipient, result.get("Actor"), result.get("Roles"))
    return result


async def extract_cloudtrail_details_async(
    incident_url: str,
    incident: dict,
    entities: list[dict],
    alerts: list[dict],
    allow_deviceless_sweep: bool = False,
) -> dict:
    """Like extract_cloudtrail_details but falls back to Log Analytics query
    when the Sentinel API doesn't return the rich CloudTrail context.

    allow_deviceless_sweep gates the last-resort fleet-wide query
    (_query_cloudtrail_no_device) for alerts with no device entity at all. That
    query has NO correlation to the incident beyond a +-90min time window — it
    finds "some root-account process activity somewhere in the fleet around
    this timestamp" and attributes it to THIS alert. That is a reasonable last
    resort for a genuine CloudTrail/root-privesc alert that happens to lack a
    device entity (what the query was built for), but it is not safe for an
    alert that has nothing to do with AWS/root privesc at all. DEMO-108699 (a
    custom MS-SQL-audit alert, classify()=='generic', no device entity because
    it is not an MDE-onboarded host) got a completely unrelated person's
    macOS/JAMF session glued onto it this way — RAPTOR investigated the wrong
    entity and recommended closing FP without ever looking at the real actor
    or server the alert was actually about. Default False: a caller must know
    the alert is plausibly privesc/CloudTrail-shaped before opting into an
    unscoped fleet-wide match.
    """
    result = extract_cloudtrail_details(incident, entities, alerts)

    alert_time_utc = result.get("time_generated") or (incident.get("properties") or {}).get("firstActivityTimeUtc", "")

    # GuardDuty path: missing role name / MFA / geo → query AWSGuardDuty table
    if result.get("guardduty_link") or not any(result.get(k) for k in ("user_name", "mfa_status")):
        if result.get("guardduty_link"):
            logger.info("Querying AWSGuardDuty table for enriched finding details")
            gd_data = await query_guardduty_details(
                incident_url, alert_time_utc,
                finding_id=guardduty_finding_id(result["guardduty_link"]))
            for k, v in gd_data.items():
                if v and not result.get(k):
                    result[k] = v

    # SSM/CloudTrail path: fetch instance_id / session_issuer / user_arn from Log
    # Analytics when the incident didn't provide them. Commands come from the
    # alert's flagged Process entities (see extract_cloudtrail_details); we must
    # NOT overwrite those with the device-wide make_list firehose — the KQL
    # command is used ONLY when the alert had no Process entities (e.g. SSM
    # StartSession alerts that carry just a Host entity).
    _have_entity_cmds = bool(result.get("command_lines"))
    # `entity_account` is included so this guard behaves exactly as it did when a bare
    # UPN was stored in `user_arn` — a non-AWS Account entity still suppresses the
    # deviceless CloudTrail sweep instead of newly triggering it on every such alert.
    if not any(result.get(k) for k in ("instance_id", "session_issuer", "user_arn", "entity_account")):
        device_name = result.get("device_name", "")
        la_data: dict = {}
        if device_name and alert_time_utc:
            logger.info("Falling back to Log Analytics query_cloudtrail_event for %s", device_name)
            la_data = await query_cloudtrail_event(incident_url, device_name, alert_time_utc)
        elif alert_time_utc and not device_name and allow_deviceless_sweep:
            logger.info("No device name for %s — attempting deviceless CloudTrail query", incident_url)
            la_data = await _query_cloudtrail_no_device(incident_url, alert_time_utc)
        for k, v in (la_data or {}).items():
            if not v:
                continue
            if k in ("command", "command_lines") and _have_entity_cmds:
                continue  # keep the flagged entity commands, not the whole-device firehose
            result[k] = v

    return result


async def query_netskope_malware(
    incident_url: str,
    alert_time_utc: str = "",
    user_hint: str = "",
) -> dict:
    """Bind a Netskope -Malware alert to its row in Netskope_Alerts_CL.

    The malware evidence (user, malware name/type/severity, policy, action, IPs,
    file hash) lives ONLY in this custom-log table — not the incident entities —
    which is why the agent's hand-written KQL kept failing (DEMO-104584). This is
    the deterministic canned query: exact columns (the ones the detection rule
    projects), scoped to the alert's time window. `action`/`scanner_result` drive
    the verdict (Detection/alert = NOT confirmed blocked → escalate).

    Returns {} when nothing binds. Sets `ambiguous`+`other_users` when the window
    holds malware detections for more than one user and no user_hint disambiguates.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        return {}

    # Time window around the alert (± 6h); fall back to a 3-day sweep.
    _t = (alert_time_utc or "").replace(" ", "T")[:19]
    if _t and len(_t) >= 16:
        window = f"| where TimeGenerated between (datetime({_t}Z) - 6h .. datetime({_t}Z) + 6h)"
    else:
        window = "| where TimeGenerated > ago(3d)"

    kql = (
        "Netskope_Alerts_CL\n"
        f"{window}\n"
        '| where alert_type_s =~ "Malware"\n'
        "| project TimeGenerated, user=user_s, user_ip=userip_s, src_ip=srcip_s, dst_ip=dstip_s,\n"
        "    malware_name=malware_name_s, malware_type=malware_type_s, severity=malware_severity_s,\n"
        "    policy=policy_s, app=app_name_s, activity=activity_s, device=device_s, browser=browser_s,\n"
        "    os=os_s, detection_engine=detection_engine_s, scanner_result=scanner_result_s,\n"
        "    src_location=src_location_s, src_country=src_country_s, object_type=object_type_s,\n"
        "    file_size=file_size_d, page=page_s, malware_id=malware_id_g,\n"
        '    action=column_ifexists("action_s", ""), sha256=column_ifexists("local_sha256_s", ""),\n'
        '    hostname=column_ifexists("hostname_s", "")\n'
        "| top 25 by TimeGenerated desc"
    )
    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.warning("query_netskope_malware failed: %s", exc)
        return {}
    if not rows:
        return {}

    if user_hint:
        h = user_hint.split("@")[0].split("\\")[-1].lower()
        matched = [r for r in rows if h and h in str(r.get("user", "")).lower()]
        rows = matched or rows

    users = sorted({str(r.get("user", "")) for r in rows if r.get("user")})
    row = rows[0]  # newest in window
    out = {k: v for k, v in row.items() if v not in (None, "", "0", 0)}
    out["ambiguous"] = (not user_hint) and len(users) > 1
    out["other_users"] = [u for u in users if u != row.get("user")][:8]
    return out


def _normalize_uba_row(raw: dict) -> dict:
    """Map one Netskope UBA row from the alert's own compressedRec onto the keys the
    rest of this module reads.

    Same translation problem `_normalize_dlp_row` solves: the alert embeds RAW column
    names (`user_s`, `app_s`, `file_size_d`, ...) while the window sweep below aliases
    them (`user`, `app`, `file_size`, ...). `query_netskope_uba`'s by_user aggregation
    only knows the aliased form, so an alert-bound row has to be translated or every
    field reads empty and the bind looks worse than the sweep it replaced.
    """
    def pick(*names):
        for n in names:
            for cand in (n, f"{n}_s", f"{n}_d", f"{n}_t"):
                v = raw.get(cand)
                if v not in (None, ""):
                    return v
        return ""

    return {
        "TimeGenerated":          pick("TimeGenerated", "timestamp", "time"),
        "user":                   pick("user"),
        "app":                    pick("app"),
        "activity":               pick("activity"),
        "alert_name":             pick("alert_name"),
        "file_type":              pick("file_type", "true_filetype"),
        "file_size":              pick("file_size"),
        "page":                   pick("page", "site", "page_site"),
        "device":                 pick("device"),
        "hostname":               pick("hostname"),
        "os":                     pick("os"),
        "src_ip":                 pick("srcip", "src_ip"),
        "user_ip":                pick("userip", "user_ip"),
        "dst_ip":                 pick("dstip", "dst_ip"),
        "object_type":            pick("object_type"),
        "device_classification":  pick("device_classification"),
        "cci":                    pick("cci"),
        "ccl":                    pick("ccl"),
        "useragent":              pick("useragent"),
        "policy":                 pick("all_policy_matches", "policy"),
        # WHICH account of the app — example.onmicrosoft.com / acme / a personal
        # gmail.com. The fact that separates a company workspace from a personal one of
        # the same "approved" app, which is the whole exfiltration question for UBA.
        "instance":               pick("instance_id", "instance"),
        "severity":               pick("severity"),
    }


async def _uba_rows_from_alert(incident_url: str, sentinel_alert_id: str) -> list[dict]:
    """The exact Netskope rows THIS UBA alert fired on, from its own compressedRec.

    Byte-for-byte the same approach as `_dlp_rows_from_alert`, and for the same reason:
    Sentinel embeds the precise row(s) that triggered a scheduled rule in the alert's
    ExtendedProperties, so binding by time window is guessing when the exact answer is
    already in the alert.

    DEMO-109433 is what the window costs here. The alert named exactly ONE account
    (harper.nair, single event at 2026-08-20T06:57:30Z, StartTime == EndTime).
    Because start and end are the same instant, the sweep's `start-5m .. end+5m` became
    a flat 10-minute window, and Netskope UBA fires often enough that the window held 9
    unrelated anomalies from 9 different users. All 9 were attributed to the ticket and
    written into its permanent record; the real subject sat fourth in the list,
    indistinguishable from eight bystanders. The ticket was labelled `multi-user`, the
    agent reasoned across all nine, and it then sat in `Awaiting more inputs` for four
    weeks while an L1 had already identified the correct single user by hand.

    Returns [] so the caller can fall back to the sweep.
    """
    parts = parse_incident_url(incident_url)
    if not parts or not sentinel_alert_id:
        return []
    guid = sentinel_alert_id[2:] if sentinel_alert_id.lower().startswith("sn") else sentinel_alert_id
    kql = (
        "SecurityAlert\n"
        f'| where VendorOriginalId in ("{guid}", "{sentinel_alert_id}") '
        f'or SystemAlertId in ("{guid}", "{sentinel_alert_id}")\n'
        "| top 1 by TimeGenerated desc\n"
        "| project ExtendedProperties"
    )
    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.warning("_uba_rows_from_alert failed for %s: %s", sentinel_alert_id, exc)
        return []
    if not rows:
        return []
    events = decode_compressed_recs(rows[0].get("ExtendedProperties"))
    return [_normalize_uba_row(e) for e in events if isinstance(e, dict)]


async def query_netskope_uba(
    incident_url: str,
    alert_name: str = "",
    start_time_utc: str = "",
    end_time_utc: str = "",
    sentinel_alert_id: str = "",
) -> dict:
    """Bind a Netskope UBA anomaly alert (Bulk Upload / Bulk Download) to its rows.

    Same deterministic-template rationale as `query_netskope_malware`: the evidence
    (user, app, page, file type/size, hostname, device, OS, source IP, user agent)
    lives ONLY in `Netskope_Alerts_CL`, and the agent's hand-written KQL against this
    custom-log table keeps failing — on DEMO-107416 both attempts died on syntax errors
    after two auto-fixes, capping confidence at 0.60 with zero evidence gathered.

    The filter mirrors the analytics rule's own query, so the rows returned are exactly
    the rows the rule fired on. The rule aggregates with SingleAlert, so ONE alert
    covers EVERY row — i.e. potentially several users. `users` / `by_user` therefore
    carry the full set; nothing here collapses to a single actor.

    Returns {} when nothing binds.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        return {}

    kind = "Download" if "download" in (alert_name or "").lower() else "Upload"

    # PRIMARY: the alert's own matched rows. Exact — no window to miss, no window to
    # OVER-reach, and no rule-filter copy to drift. The sweep below is the fallback, and
    # it is flagged as an unverified subject because that is exactly what it is: on
    # DEMO-109433 it turned a one-user alert into a nine-user ticket (see
    # _uba_rows_from_alert). Ported from the identical fix already shipped for DLP.
    if sentinel_alert_id:
        _bound = await _uba_rows_from_alert(incident_url, sentinel_alert_id)
        # Rows with no IDENTIFIABLE user are a FAILED bind, not a successful one. The
        # column names `_normalize_uba_row` reads are inferred from the sibling DLP
        # normaliser, not verified against a live UBA compressedRec — and if that guess
        # is wrong, every row decodes with an empty `user`, `_shape_uba_rows` files them
        # all under "(unknown)", and the ticket renders "User: (unknown)". That is
        # strictly WORSE than the sweep it replaced, which at least contains the real
        # subject somewhere in its list. Falling through costs nothing when the guess is
        # right, and removes the whole failure class when it is not.
        if _bound and not any(str(r.get("user", "")).strip() for r in _bound):
            logger.error("query_netskope_uba: alert %s decoded %d row(s) but NONE carried "
                         "a user — the compressedRec column names are not what "
                         "_normalize_uba_row expects. Falling back to the window sweep.",
                         sentinel_alert_id, len(_bound))
            _bound = []
        if _bound:
            _res = _shape_uba_rows(_bound, kind)
            _res["bind_source"] = "alert"
            _res["bind_alert_id"] = sentinel_alert_id
            _res["subject_unverified"] = False
            logger.info("query_netskope_uba: bound %d event(s) / %d user(s) from the "
                        "alert's own compressedRec (alert_id=%s)",
                        _res["event_count"], _res["user_count"], sentinel_alert_id)
            return _res
        logger.warning("query_netskope_uba: alert %s carried no decodable rows — falling "
                       "back to the window sweep (subject UNVERIFIED)", sentinel_alert_id)

    def _clean(t: str) -> str:
        return (t or "").replace(" ", "T").replace("Z", "")[:19]

    # Prefer the incident's own activity window. It is derived from these very rows
    # (firstActivityTimeUtc == the first row's TimeGenerated), so pad it only slightly —
    # the rule runs every 5h, so a wide pad can pull in a DIFFERENT firing's anomalies
    # and attribute another event to this alert. Fall back to ±6h around a single
    # timestamp: the alert's own timeGenerated trails the last event materially
    # (DEMO-107416 fired at 11:23Z for events ending 09:39Z).
    _s, _e = _clean(start_time_utc), _clean(end_time_utc)
    if len(_s) >= 16 and len(_e) >= 16:
        window = (f"| where TimeGenerated between (datetime({_s}Z) - 5m .. "
                  f"datetime({_e}Z) + 5m)")
    elif len(_s) >= 16:
        window = f"| where TimeGenerated between (datetime({_s}Z) - 6h .. datetime({_s}Z) + 6h)"
    else:
        window = "| where TimeGenerated > ago(3d)"

    # The exclusions below are the analytics rule's own, verbatim — trusted enterprise
    # destinations, sanctioned file-sharing apps, and the low-trust/unmanaged gate. They
    # are NOT optional noise reduction: without them this returns rows the rule never
    # fired on, and the L1 comment then attributes an unrelated upload to the alert
    # (a sanctioned Google Drive upload surfaced under DEMO-107416 during verification).
    kql = (
        "Netskope_Alerts_CL\n"
        f"{window}\n"
        '| where alert_type_s == "uba"\n'
        f'| where alert_name_s has "Bulk {kind}" or activity_s has "{kind}"\n'
        '| where action_s == "anomaly_detection"\n'
        "| where file_size_d > 0\n"
        "| where cci_d < 80 or device_classification_s != \"managed\"\n"
        '| where page_s !in ("amazonaws.com", "bitbucket.org", "blob.core.windows.net")\n'
        '| where app_s !in ("Google Drive", "Microsoft Office 365 Outlook.com", "Google Gmail",\n'
        '                   "Microsoft Office 365 OneDrive for Business")\n'
        "| project TimeGenerated, user=user_s, app=app_s, activity=activity_s,\n"
        "    alert_name=alert_name_s, file_type=file_type_s, file_size=file_size_d,\n"
        "    page=page_s, device=device_s, hostname=hostname_s, os=os_s, src_ip=srcip_s,\n"
        "    user_ip=userip_s, dst_ip=dstip_s, object_type=object_type_s,\n"
        "    device_classification=device_classification_s, cci=cci_d, ccl=ccl_s,\n"
        "    useragent=useragent_s,\n"
        '    policy=column_ifexists("all_policy_matches_s", ""),\n'
        '    severity=column_ifexists("severity_s", ""),\n'
        '    instance=column_ifexists("instance_id_s", "")\n'
        "| sort by TimeGenerated asc\n"
        "| take 100"
    )
    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.warning("query_netskope_uba failed: %s", exc)
        return {}
    if not rows:
        return {}

    _res = _shape_uba_rows(rows, kind)
    # The sweep cannot know WHICH of these rows the alert actually fired on. Say so, so
    # downstream can treat the user list as a candidate set rather than as fact — the
    # playbook refuses to chase on this, and the L1 comment carries a caveat.
    _res["bind_source"] = "window_sweep"
    _res["bind_alert_id"] = sentinel_alert_id
    _res["bind_alert_lookup_failed"] = bool(sentinel_alert_id)
    _res["subject_unverified"] = True
    return _res


def _shape_uba_rows(rows: list[dict], kind: str) -> dict:
    """Aggregate Netskope UBA rows into the per-user shape the playbook renders.

    Shared by both bind paths on purpose: when this lived only in the sweep, adding the
    alert-scoped bind would have meant a second copy, and the two would have drifted
    into disagreeing about what a bound result looks like.
    """
    users = list(dict.fromkeys(str(r.get("user", "")) for r in rows if r.get("user")))
    by_user: dict = {}
    for r in rows:
        u = str(r.get("user", "")) or "(unknown)"
        b = by_user.setdefault(u, {
            "events": 0, "apps": [], "hosts": [], "src_ips": [], "file_types": [],
            "pages": [], "total_bytes": 0, "first_seen": "", "last_seen": "",
            "device": "", "os": "", "useragent": "", "device_classification": "", "ccl": "",
            "instances": [],
        })
        b["events"] += 1
        for key, col in (("apps", "app"), ("hosts", "hostname"), ("src_ips", "src_ip"),
                         ("file_types", "file_type"), ("pages", "page"),
                         ("instances", "instance")):
            v = str(r.get(col, "") or "")
            if key == "instances" and not v:
                # Explicit, per EVENT: one event with no recorded account must keep the
                # whole ticket from matching an account-pinned approval.
                v = "(not recorded)"
            if v and v not in b[key]:
                b[key].append(v)
        try:
            b["total_bytes"] += int(float(r.get("file_size") or 0))
        except (TypeError, ValueError):
            pass
        t = str(r.get("TimeGenerated", "") or "")[:19].replace("T", " ")
        if t:
            b["first_seen"] = b["first_seen"] or t
            b["last_seen"] = t
        for col in ("device", "os", "useragent", "device_classification", "ccl"):
            if not b[col]:
                b[col] = str(r.get(col, "") or "")

    return {
        "kind": kind,
        "users": users,
        "user_count": len(users),
        "event_count": len(rows),
        "by_user": by_user,
        "events": rows[:50],
    }


# The WHERE clauses of the live Sentinel analytics rule that raises
# "Netskope DLP Alerts". Copied from the production rule on 2026-08-28.
#
# Why this has to be here: the bind used to select on `alert_type_s =~ "DLP"` alone,
# which is a strict superset of what the rule fires on. Every other DLP row in the
# +/-6h window came back too — low-severity rows, blocked actions, rows with no file,
# excluded apps/sites — and with `take 25 | sort by TimeGenerated desc` that noise can
# crowd the alert's ACTUAL subject out of the evidence entirely.
#
# DEMO-110841 is the case: the agent was handed 5 users (Google Drive / CASB API Scan),
# reasoned "All five users ... scanner-driven ... false positive", and auto-closed FP at
# 0.85 — while the user the alert was actually raised for, yash.oberoi@example.com,
# appeared nowhere in the evidence at all. Reasoning cannot be right about people it was
# never shown; binding the wrong rows is not a model problem, it is an input problem.
#
# KEEP IN SYNC with the analytics rule. When the rule changes and this does not, the
# strict bind returns nothing and the caller falls back to the loose bind with
# bind_strict=False — degraded, flagged, never silent.
#
# `dlp_file_s` is projected directly rather than through column_ifexists: the production
# rule filters on `isnotempty(dlp_file_s)`, so the column definitively exists. (An
# earlier note in this file concluded from a 400 on DEMO-110712 that it did not — that
# conclusion was wrong; something else in that ad-hoc query was at fault.)
_DLP_ALERT_RULE_EXCLUDED_SITES = (
    '"rum-ingress-coralogix", "Mixpanel", "Microsoft Office 365 OneDrive for Business", '
    '"Microsoft Office 365 Outlook.com", "Google Gmail", "Google Drive", "HDFC Bank", "Acme"'
)
_DLP_ALERT_RULE_EXCLUDED_URLS = (
    "safebrowsing.google.com/safebrowsing/clientreport/realtime",
    "acme-cmp.s3.ap-south-1.amazonaws.com",
    "acme-udp-glue-artifacts.s3.ap-south-1.amazonaws.com",
    "support.example.com/",
    "acme-uat-ds-dl-processed.s3.ap-south-1.amazonaws.com/",
    "app.clear.in/storage/v1/ap-south-1",
    "ds-dl-processed.s3.ap-south-1.amazonaws.com/",
    "acme-crisis-comms-data.s3.ap-south-1.amazonaws.com/",
)
_DLP_ALERT_RULE_FILTER = (
    '| where activity_s <> "Introspection Scan"\n'
    '| where access_method_s <> "Endpoint"\n'
    '| where dlp_rule_severity_s in ("High", "Critical")\n'
    '| where action_s <> "block"\n'
    "| where isnotempty(dlp_file_s)\n"
    "| where isnotempty(dlp_rule_s)\n"
    '| where dlp_profile_s <> "Acme-SourceCode"\n'
    "| where not(\n"
    f"    page_site_s in ({_DLP_ALERT_RULE_EXCLUDED_SITES})\n"
    '    or object_s == "blob"\n'
    + "".join(f'    or url_s has "{u}"\n' for u in _DLP_ALERT_RULE_EXCLUDED_URLS)
    + '    or app_s has "Microsoft Office 365 OneDrive for Business"\n'
    ")\n"
)

# Was 25. A DLP incident routinely spans more than that (DEMO-110772 alone carried 15
# events across 13 users), and at 25 the cap was reached silently — `event_count` was
# computed AFTER the cap, so "exactly 25" and "25 of 200" were indistinguishable to
# every downstream consumer.
_DLP_ROW_CAP = 200


# --- Netskope failed-login bind ------------------------------------------------
# Mirrors the WHERE/summarize logic of the live "Netskope - Failed Login" analytics rule
# (copied from the production rule 2026-09-01). Two things about that rule shape the bind:
#
#   1. It is an AGGREGATE: `summarize count() by <many fields> | where count_ > 2`. The
#      alert does not fire on a login failure, it fires on a REPEATED one. So the count
#      is the signal — 3 failures is a mistyped password, 300 is something else — and a
#      bind that returned individual rows without the count would throw away the only
#      thing that made this an alert.
#   2. It excludes OneDrive (`app_s <> "Microsoft Office 365 OneDrive for Business"`) and
#      looks back 24h.
#
# Why this exists at all: "Netskope - Failed Login" routes to the Netskope playbook but
# received NO Netskope_Alerts_CL evidence — only Entra sign-in logs from
# extract_signin_details_async. The agent was reasoning about a Netskope alert without
# ever seeing the Netskope data. Measured 2026-09-01: 10 scored rows, 2 correct (0.154),
# and every one of the 8 misses was an over-escalation the model chose itself
# (blocked_by_safety=False), the same signature DLP had before it got a real bind.
_FAILED_LOGIN_FILTER = (
    '| where app_s <> "Microsoft Office 365 OneDrive for Business"\n'
    '| where activity_s == "Login Failed"\n'
)

# The rule groups by these; keeping the same keys means a bound group corresponds 1:1 to
# a group that could have fired the alert. `device_classification_s` (managed vs
# unmanaged) and `ccl_s` (Netskope's cloud-confidence level) are the two an analyst reads
# first, and neither was reaching the agent at all before this.
_FAILED_LOGIN_GROUP_KEYS = (
    "alert_name_s", "app_s", "device_classification_s", "page_site_s", "from_user_s",
    "other_categories_s", "page_s", "url_s", "browser_s", "useragent_s", "action_s",
    "Category", "ccl_s", "device_s", "dstip_s", "dstport_d", "hostname_s", "os_s",
    "policy_s", "srcip_s", "user_s", "userip_s",
)

_FAILED_LOGIN_MIN_COUNT = 2      # the rule's own `| where count_ > 2`
_FAILED_LOGIN_GROUP_CAP = 25


def _normalize_failed_login_row(raw: dict) -> dict:
    """Map one summarized failed-login group onto reader-friendly keys."""
    def pick(*names):
        for n in names:
            for cand in (n, f"{n}_s", f"{n}_d", f"{n}_t"):
                v = raw.get(cand)
                if v not in (None, ""):
                    return v
        return ""

    return {
        "user":                 pick("user"),
        "from_user":            pick("from_user"),
        # The whole reason the alert fired. Kept as an int so a gate can compare it.
        "failure_count":        int(pick("count_", "count") or 0),
        "app":                  pick("app"),
        "action":               pick("action"),
        "device":               pick("device"),
        "device_classification": pick("device_classification"),
        "hostname":             pick("hostname"),
        "os":                   pick("os"),
        "browser":              pick("browser"),
        "src_ip":               pick("srcip", "src_ip"),
        "user_ip":              pick("userip", "user_ip"),
        "dst_ip":               pick("dstip", "dst_ip"),
        "dst_port":             pick("dstport", "dst_port"),
        "policy":               pick("policy"),
        "page_site":            pick("page_site"),
        "url":                  pick("url"),
        "ccl":                  pick("ccl"),
        "category":             pick("Category", "category"),
        "alert_name":           pick("alert_name"),
    }


async def query_netskope_failed_login(
    incident_url: str,
    alert_time_utc: str = "",
    user_hint: str = "",
) -> dict:
    """Bind a "Netskope - Failed Login" ticket to the failure GROUPS behind it.

    Returns {} when nothing binds, so a run with no evidence is unchanged rather than
    given an empty block to reason about.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        return {}

    # The rule looks back 24h from its own run, so the failures precede the alert. A
    # small forward margin absorbs ingestion lag (the same lag _BLANK_BOUND_LAG_MINUTES
    # exists for elsewhere in this codebase). The pipeline passes Jira's `created`
    # ('...+0530'); slicing it read IST as UTC and moved the window 5.5h late, dropping
    # the first 5.5h of the 24h lookback and counting failures after the alert.
    _tu = _dlp_time_utc(alert_time_utc)
    _t = f"{_tu:%Y-%m-%dT%H:%M:%S}" if _tu else ""
    if _t:
        window = (f"| where TimeGenerated between "
                  f"(datetime({_t}Z) - 24h .. datetime({_t}Z) + 1h)")
    else:
        window = "| where TimeGenerated > ago(24h)"

    keys = ", ".join(_FAILED_LOGIN_GROUP_KEYS)
    kql = (
        "Netskope_Alerts_CL\n"
        f"{window}\n"
        f"{_FAILED_LOGIN_FILTER}"
        f"| summarize count() by {keys}\n"
        f"| where count_ > {_FAILED_LOGIN_MIN_COUNT}\n"
        "| sort by count_ desc\n"
        f"| take {_FAILED_LOGIN_GROUP_CAP}"
    )
    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.warning("query_netskope_failed_login failed: %s", exc)
        return {}
    if not rows:
        return {}

    groups = [_normalize_failed_login_row(r) for r in rows if isinstance(r, dict)]
    if user_hint:
        h = user_hint.split("@")[0].split("\\")[-1].lower()
        matched = [g for g in groups
                   if h and (h in str(g.get("user", "")).lower()
                             or h in str(g.get("from_user", "")).lower())]
        groups = matched or groups

    users = sorted({str(g.get("user") or g.get("from_user") or "") for g in groups
                   if (g.get("user") or g.get("from_user"))})
    return {
        "users": users,
        "groups": groups[:10],
        "group_count": len(groups),
        "total_failures": sum(int(g.get("failure_count") or 0) for g in groups),
        "max_failures": max((int(g.get("failure_count") or 0) for g in groups), default=0),
        "truncated": len(rows) >= _FAILED_LOGIN_GROUP_CAP,
        "ambiguous": (not user_hint) and len(users) > 1,
    }


def _normalize_dlp_row(raw: dict) -> dict:
    """Map one Netskope row from the analytics rule's own projection onto the keys the
    rest of the pipeline reads.

    The rule projects raw column names (`user_s`, `activity_s`, `dlp_rule_s`, ...) while
    the window-sweep query aliases them (`user`, `activity`, `dlp_rule`, ...). Consumers
    — oscar's DLP evidence block's activity/access_method
    check — only know the aliased form, so a row arriving from the alert has to be
    translated or it reads as an empty event.

    Accepts either form for every field, so it is safe if the rule is edited to alias
    its projection later.
    """
    def pick(*names):
        for n in names:
            for cand in (n, f"{n}_s", f"{n}_d", f"{n}_t"):
                v = raw.get(cand)
                if v not in (None, ""):
                    return v
        return ""

    return {
        "TimeGenerated":     pick("TimeGenerated", "timestamp", "time"),
        "user":              pick("user"),
        "app":               pick("app"),
        "activity":          pick("activity"),
        "access_method":     pick("access_method"),
        "dlp_rule":          pick("dlp_rule"),
        "dlp_profile":       pick("dlp_profile"),
        "dlp_rule_severity": pick("dlp_rule_severity"),
        "dlp_incident_id":   pick("dlp_incident_id"),
        "dlp_file":          pick("dlp_file", "file_name", "object"),
        "file_size":         pick("file_size"),
        "hostname":          pick("hostname"),
        "device":            pick("device", "hostname"),
        "url":               pick("url"),
        "site":              pick("site", "page_site", "page"),
        "true_filetype":     pick("true_filetype"),
        "src_country":       pick("src_country"),
        "dst_country":       pick("dst_country"),
    }


async def _dlp_rows_from_alert(incident_url: str, sentinel_alert_id: str) -> list[dict]:
    """The exact Netskope rows THIS alert fired on, from the alert's own compressedRec.

    This is the correct way to bind a DLP ticket, and the reason the window sweep below
    must never be the primary path. `decode_compressed_recs`' own docstring says it:
    Sentinel embeds the precise row(s) that triggered a scheduled rule in the alert's
    ExtendedProperties, and for these rules the incident and SecurityAlert.Entities are
    empty. `query_sentinel_alert` has used this since DEMO-104199 (cross-attribution on a
    grouped incident); the DLP bind was written against a time window instead and so was
    never scoped to the alert at all.

    DEMO-110841 is the cost of that: the alert named exactly one user
    (yash.oberoi@example.com) and the sweep handed the agent 5 unrelated users, then
    14 after the cap was raised — the agent's `user_name` even changed identity between
    runs, which a correctly-bound query cannot do. Returns [] so the caller can fall back.
    """
    parts = parse_incident_url(incident_url)
    if not parts or not sentinel_alert_id:
        return []
    guid = sentinel_alert_id[2:] if sentinel_alert_id.lower().startswith("sn") else sentinel_alert_id
    kql = (
        "SecurityAlert\n"
        f'| where VendorOriginalId in ("{guid}", "{sentinel_alert_id}") '
        f'or SystemAlertId in ("{guid}", "{sentinel_alert_id}")\n'
        "| top 1 by TimeGenerated desc\n"
        "| project ExtendedProperties"
    )
    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.warning("_dlp_rows_from_alert failed for %s: %s", sentinel_alert_id, exc)
        return []
    if not rows:
        return []
    events = decode_compressed_recs(rows[0].get("ExtendedProperties"))
    if not events:
        # No compressedRec: a grouped overflow alert carries the rule's query instead.
        return await _grouped_alert_rows(parts, rows[0].get("ExtendedProperties"))
    return [_normalize_dlp_row(e) for e in events if isinstance(e, dict)]


def _dlp_time_utc(value: str):
    """A Jira or Sentinel timestamp as naive UTC, or None.

    Jira writes '2026-10-08T13:20:01.123+0530' and Sentinel '2026-10-08T07:49:52.1213926Z'
    or '2026-10-08 06:44:46Z'. Slicing to 19 characters dropped Jira's +0530, so an IST
    time was read as UTC: every ticket looked 5.5 hours in the future, the ingest-lag guard
    never fired, and the sweep window sat 5.5 hours from the alert. A value with no offset
    is taken as UTC.
    """
    from datetime import datetime, timedelta
    s = (value or "").strip().replace(" ", "T")
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?)(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$", s)
    if not m:
        return None
    try:
        t = datetime.fromisoformat(m.group(1))
    except ValueError:
        return None
    off = m.group(2) or "Z"
    if off != "Z":
        sign = 1 if off[0] == "+" else -1
        hh, mm = int(off[1:3]), int(off[-2:])
        t -= sign * timedelta(hours=hh, minutes=mm)
    return t


async def _grouped_alert_rows(parts: dict, ext_props) -> list[dict]:
    """The rows of a grouped overflow alert, by re-running the alert's own query.

    When one hourly run of the DLP rule returns more than 150 results, Sentinel puts all of
    them into one alert ("For rules of this kind, events grouping supports up to 150
    results. All results were grouped into this alert") with no compressedRec, only the
    rule's KQL and the exact window it ran over. The binder took that as "no rows" and
    swept ±6h of the table instead: DEMO-116203's alert held 181 results from 27 users, and
    the sweep handed the ticket 15 rows nobody could tie to it. That was 14 of the 40
    sweep-bound DLP tickets 2026-10-08..17.

    The alert's own query over its own window is the alert. The result must match the
    alert's "Search Query Results Overall Count", or nothing is returned: a row that
    reached the table after the rule ran, or a boundary off by a second, would make it a
    different set.
    """
    import json as _json
    from datetime import timedelta
    ep = ext_props
    if isinstance(ep, str):
        try:
            ep = _json.loads(ep)
        except Exception:
            return []
    if not isinstance(ep, dict) or not ep.get("Grouping Message"):
        return []
    q = ep.get("Query") or ""
    t0 = _dlp_time_utc(ep.get("Query Start Time UTC", ""))
    t1 = _dlp_time_utc(ep.get("Query End Time UTC", ""))
    try:
        want = int(str(ep.get("Search Query Results Overall Count", "")).strip())
    except ValueError:
        return []
    if not (q.strip() and t0 and t1 and want > 0):
        return []
    # The window is published to the second; the rule ran to the millisecond, so the end
    # is rounded up. The count check below rejects anything this lets in or out.
    span = f"{t0:%Y-%m-%dT%H:%M:%S}Z/{t1 + timedelta(seconds=1):%Y-%m-%dT%H:%M:%S}Z"
    try:
        rows = await _run_la_query(parts, q, timespan=span)
    except Exception as exc:
        logger.warning("_grouped_alert_rows: re-running the alert query failed: %s", exc)
        return []
    if len(rows) != want:
        logger.warning("_grouped_alert_rows: alert query returned %d rows, the alert says %d "
                       "— not binding", len(rows), want)
        return []
    out = [_normalize_dlp_row(r) for r in rows if isinstance(r, dict)]
    for r in out:
        r["alert_grouped"] = True
    return out


def _dlp_ingest_lag_minutes() -> int:
    """How long a DLP alert's SecurityAlert row may take to reach Log Analytics.

    Measured boundary was 7.9 min (last sweep-bound) vs 8.8 min (first alert-bound);
    15 gives margin without cost, because the guard is only consulted after the alert
    lookup has already returned nothing. Env-overridable so it can be widened or
    switched off (0) without a deploy.
    """
    import os as _os
    try:
        return max(0, int(_os.getenv("DLP_ALERT_INGEST_LAG_MINUTES", "15")))
    except ValueError:
        return 15


_DLP_BIND_RETRY_SECONDS = 30


async def _bind_sleep(seconds: float) -> None:
    import asyncio
    await asyncio.sleep(seconds)


def _wait_for_dlp_alert_row(alert_time_utc: str) -> bool:
    """True while it is still worth waiting for the alert's SecurityAlert row: the alert is
    younger than DLP_ALERT_BIND_WAIT_MINUTES (default 3, past the measured p99 of 2.1).
    0 turns the wait off. An unusable timestamp never waits."""
    import os as _os
    from datetime import datetime
    try:
        cap = max(0.0, float(_os.getenv("DLP_ALERT_BIND_WAIT_MINUTES", "3")))
    except ValueError:
        cap = 3.0
    ts = _dlp_time_utc(alert_time_utc)
    if not cap or ts is None:
        return False
    age_min = (datetime.utcnow() - ts).total_seconds() / 60.0
    return 0 <= age_min < cap


def _too_early_for_dlp_alert_row(alert_time_utc: str) -> bool:
    """True when the alert is too young for its SecurityAlert row to exist yet.

    Returns False on an unusable/absent timestamp, so a parse failure falls through to
    the previous behaviour rather than silently suppressing all DLP evidence.
    """
    # datetime is imported function-locally throughout this module, not at module scope.
    from datetime import datetime

    lag = _dlp_ingest_lag_minutes()
    if not lag:
        return False
    ts = _dlp_time_utc(alert_time_utc)
    if ts is None:
        return False
    age_min = (datetime.utcnow() - ts).total_seconds() / 60.0
    # A future-dated or wildly skewed timestamp is not evidence of freshness; only a
    # genuinely recent event suppresses the sweep.
    return 0 <= age_min < lag


async def query_netskope_dlp(
    incident_url: str,
    alert_time_utc: str = "",
    user_hint: str = "",
    strict: bool = True,
    sentinel_alert_id: str = "",
) -> dict:
    """Bind a "Netskope DLP Alerts" ticket to its row(s) in Netskope_Alerts_CL.

    Same deterministic-template rationale as query_netskope_malware/query_netskope_uba:
    the per-event detail (which DLP rule/profile fired, on what app, how much data,
    via what access method) lives only in this custom-log table — the Jira description
    table only ever carries the DLP profile name, never the rest (DEMO-110575: "User",
    "Access Method", "Activity", "DLP Rule", "DLP Rule Severity", "DLP Incident ID",
    "File Size" and "Timestamp" were all typed by hand from this table by L1 every time).

    Column names for the DLP-specific fields (dlp_profile_s, dlp_rule_s,
    dlp_rule_severity_s, dlp_incident_id_s, access_method_s) are inferred from the
    generic naming pattern the two sibling queries above already use — NOT verified
    against a live Sentinel workspace (this environment has no direct KQL access).
    Every DLP-specific column is wrapped in column_ifexists so a wrong guess returns
    an empty field instead of failing the whole query; the generic columns already
    confirmed correct by the malware/UBA queries (user_s, app_s, activity_s, page_s,
    file_size_d, device_s, hostname_s) are requested directly. Verify against a real
    row on first live use and correct any DLP-specific column name that comes back
    empty across the board.

    An incident can carry MULTIPLE DLP hits (the rule aggregates), so this returns
    every row in the window, not just one — unlike query_netskope_malware's
    single-row bind, a DLP ticket must not silently drop a second flagged file.

    Returns {} when nothing binds.
    """
    parts = parse_incident_url(incident_url)
    if not parts:
        return {}

    # PRIMARY: the alert's own matched rows. Exact, so there is no window to miss, no
    # cap to truncate, and no rule-filter copy to drift. Only when this yields nothing
    # do we fall back to the window sweep, which is flagged as an unverified subject.
    if sentinel_alert_id:
        _bound = await _dlp_rows_from_alert(incident_url, sentinel_alert_id)
        # The row usually lands within a minute or two of the alert (p99 2.1 min over 8,168
        # DLP alerts, 2026-10-08..18), and RAPTOR triages 0.5-2 min after the ticket opens,
        # so the first lookup often comes too soon: 26 of the 40 sweep-bound tickets
        # 2026-10-08..17 bind to exactly one user when looked up again. Wait for it, a short
        # bounded time — tickets are triaged one at a time, so this holds up the queue.
        while not _bound and _wait_for_dlp_alert_row(alert_time_utc):
            await _bind_sleep(_DLP_BIND_RETRY_SECONDS)
            _bound = await _dlp_rows_from_alert(incident_url, sentinel_alert_id)
        if _bound:
            _users = sorted({str(r.get("user", "")) for r in _bound if r.get("user")})
            _grouped = any(r.get("alert_grouped") for r in _bound)
            logger.info("query_netskope_dlp: bound %d event(s) / %d user(s) from the "
                        "alert's own compressedRec (alert_id=%s)",
                        len(_bound), len(_users), sentinel_alert_id)
            return {
                "users": _users,
                "events": _bound[:15],
                "event_count": len(_bound),
                "events_shown": min(len(_bound), 15),
                "truncated": False,
                "bind_strict": True,
                "bind_source": "alert",
                # WHICH alert row these came from. Persisted because two different
                # alertLink guids (DEMO-110937 sn912c9218..., DEMO-110933 sn622575ea...)
                # both bound the same wrong user, and from outside there is no way to
                # tell whether the lookup matched the wrong SecurityAlert row or the
                # right row carried the wrong content.
                "bind_alert_id": sentinel_alert_id,
                "ambiguous": False,   # these ARE the alert's rows — nothing to disambiguate
                # Sentinel's grouped overflow alert: every result of one rule run, bound by
                # re-running the alert's own query (_grouped_alert_rows).
                "bind_grouped": _grouped,
            }
        # TOO EARLY TO SWEEP. The SecurityAlert row is not in Log Analytics yet, so an
        # empty lookup here means "not ingested", not "no such alert".
        #
        # Measured 2026-09-02 over 68 DLP tickets, and the separation is total: every
        # ticket that bound from its own alert was triaged 8.8-67.6 min after its event
        # (median 32.9), and every ticket that fell back to the sweep was triaged
        # 1.2-7.9 min after it (median 4.4). No overlap. Same tenant already documents
        # this lag for another table — see _BLANK_BOUND_LAG_MINUTES in agent_core/loop.py
        # ("rows land 26-28 minutes after the event").
        #
        # Sweeping instead is not a degraded answer, it is a WRONG one: DEMO-111418 was
        # triaged 4.2 min after its event, swept up 13 unrelated users, and
        # `sorted()[0]` attributed the ticket to rowan.mehta when the alert was
        # about finley.rao. Returning nothing lets the RJ/no-principal gate escalate
        # honestly, and a later re-triage binds correctly once the row lands.
        #
        # Only reachable when the alert lookup ALREADY failed, so a generous threshold
        # costs nothing: a ticket that binds at 10 min returned above and never gets
        # here. Fails toward current behaviour when the timestamp is unusable.
        if _too_early_for_dlp_alert_row(alert_time_utc):
            logger.warning(
                "query_netskope_dlp: alert %s not in SecurityAlert yet (event %s is "
                "younger than the %d-min ingest lag) — returning NO evidence rather "
                "than a window sweep whose subject would be unverified",
                sentinel_alert_id, alert_time_utc, _dlp_ingest_lag_minutes())
            return {}
        logger.warning("query_netskope_dlp: alert %s carried no decodable rows — "
                       "falling back to the window sweep (subject UNVERIFIED)",
                       sentinel_alert_id)
        # Carry the ATTEMPTED id into the sweep result. Without this the sweep dict has
        # no bind_alert_id at all, so the shadow row shows an empty
        # dlp_bind_alert_id — which reads as "this ticket had no alertLink to parse"
        # when the truth is "it had one, we queried it, and SecurityAlert gave us
        # nothing decodable". Those need completely different fixes, and the blank
        # field sent a whole investigation down the wrong path on DEMO-111418, whose
        # description does carry alertLink .../alerts/sn69fb43f1-9e2f-4628-b3f4-fea936c3ddf9.
        _swept = await query_netskope_dlp(incident_url, alert_time_utc, user_hint,
                                          strict=strict, sentinel_alert_id="")
        if _swept:
            _swept["bind_alert_id"] = sentinel_alert_id
            _swept["bind_alert_lookup_failed"] = True
        return _swept

    _tu = _dlp_time_utc(alert_time_utc)
    _t = f"{_tu:%Y-%m-%dT%H:%M:%S}" if _tu else ""
    if _t:
        window = f"| where TimeGenerated between (datetime({_t}Z) - 6h .. datetime({_t}Z) + 6h)"
    else:
        window = "| where TimeGenerated > ago(3d)"

    kql = (
        "Netskope_Alerts_CL\n"
        f"{window}\n"
        '| where alert_type_s =~ "DLP"\n'
        f"{_DLP_ALERT_RULE_FILTER if strict else ''}"
        "| project TimeGenerated, user=user_s, app=app_s, activity=activity_s, page=page_s,\n"
        "    file_size=file_size_d, device=device_s, hostname=hostname_s, src_ip=srcip_s,\n"
        "    user_ip=userip_s, object_type=object_type_s,\n"
        '    dlp_profile=column_ifexists("dlp_profile_s", ""),\n'
        '    dlp_rule=column_ifexists("dlp_rule_s", ""),\n'
        '    dlp_rule_severity=column_ifexists("dlp_rule_severity_s", ""),\n'
        '    dlp_incident_id=column_ifexists("dlp_incident_id_s", ""),\n'
        '    access_method=column_ifexists("access_method_s", ""),\n'
        '    policy=column_ifexists("all_policy_matches_s", ""),\n'
        # WHICH file matched — the projection shipped without it and only had
        # object_type_s (the TYPE). On DEMO-110712 the agent noticed the gap, went to
        # fetch it with its own KQL, guessed `dlp_file_s` (no such column), got a 400,
        # and then discounted all the evidence it DID have as "unverified". For a DLP
        # alert "which file held the PAN data" is a core question, so it belongs here.
        # All three names are candidates and none is verified — column_ifexists makes a
        # wrong guess free (empty field, query still runs), which is exactly how the
        # right one gets discovered. Never add a bare guessed column here.
        '    object_name=column_ifexists("object_s", ""),\n'
        "    dlp_file=dlp_file_s,\n"
        '    file_name=column_ifexists("file_name_s", ""),\n'
        '    file_path=column_ifexists("file_path_s", "")\n'
        "| sort by TimeGenerated desc\n"
        f"| take {_DLP_ROW_CAP}"
    )
    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.warning("query_netskope_dlp failed (strict=%s): %s", strict, exc)
        # A strict-bind failure is most likely a column the rule uses but this
        # workspace does not have. Retry loose rather than return no evidence at all.
        if strict:
            logger.info("query_netskope_dlp: retrying loose after strict failure")
            return await query_netskope_dlp(incident_url, alert_time_utc, user_hint,
                                            strict=False)
        return {}

    if not rows:
        # No row passed the rule's own filter. Either the rule has drifted from the
        # copy above, or the alert's rows fell outside the window. Fall back to the
        # loose bind so triage still has evidence — flagged, not silent.
        if strict:
            logger.warning("query_netskope_dlp: strict bind returned 0 rows — falling "
                           "back to loose bind, evidence subject is UNVERIFIED")
            loose = await query_netskope_dlp(incident_url, alert_time_utc, user_hint,
                                             strict=False)
            if loose:
                loose["bind_strict"] = False
            return loose
        return {}

    if user_hint:
        h = user_hint.split("@")[0].split("\\")[-1].lower()
        matched = [r for r in rows if h and h in str(r.get("user", "")).lower()]
        rows = matched or rows

    users = sorted({str(r.get("user", "")) for r in rows if r.get("user")})
    return {
        "users": users,
        # Events are capped for prompt size, but `users` is derived from every row, so
        # the user list is never truncated by this slice even when the events are.
        "events": rows[:15],
        "event_count": len(rows),
        "events_shown": min(len(rows), 15),
        # True when the ROW CAP was hit, i.e. there may be events we never saw. A
        # verdict — especially an auto-close — must not rest on evidence known to be
        # partial; see the DLP truncation gate in agent_core/loop.py.
        "truncated": len(rows) >= _DLP_ROW_CAP,
        "bind_strict": strict,
        # A time-window sweep, NOT the alert's own rows: these users are whoever else
        # tripped a DLP rule nearby, so they are not established as this alert's
        # subjects. Kept only as a fallback for tickets with no usable alert id.
        "bind_source": "window_sweep",
        "ambiguous": (not user_hint) and len(users) > 1,
    }
