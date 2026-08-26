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
    | project DeviceName, InstanceId;
let AWSData =
    AWSCloudTrail
    | where TimeGenerated between (start_time .. end_time)
    | where EventSource contains "ssm.amazonaws.com"
    | where EventName == "StartSession"
    | extend InstanceId = tostring(parse_json(RequestParameters).target)
    | project InstanceId, SessionIssuerUserName, UserIdentityArn, EventName;
let Enriched = ProcessData | join kind=leftouter DeviceInfoData on DeviceName;
Enriched
| join kind=leftouter AWSData on InstanceId
| project DeviceName, TimeGenerated, AccountName,
          InitiatingCommands = strcat_array(InitiatingCommands, "; "),
          InstanceId, SessionIssuerUserName, UserIdentityArn, EventName
| take 1
"""

    try:
        rows = await _run_la_query(parts, kql)
        if not rows:
            logger.info("query_cloudtrail_event: no rows for device=%s window=%s→%s", device_name, start, end)
            return {}

        row = rows[0]
        logger.info(
            "query_cloudtrail_event: got result for %s — instance=%s issuer=%s",
            device_name, row.get("InstanceId"), row.get("SessionIssuerUserName"),
        )
        result = {}
        if row.get("DeviceName"):       result["device_name"]    = row["DeviceName"]
        if row.get("TimeGenerated"):    result["time_generated"] = str(row["TimeGenerated"])
        if row.get("AccountName"):      result["account_name"]   = row["AccountName"]
        if row.get("EventName"):        result["event_name"]     = row["EventName"]
        if row.get("InstanceId"):       result["instance_id"]    = row["InstanceId"]
        if row.get("SessionIssuerUserName"): result["session_issuer"] = row["SessionIssuerUserName"]
        if row.get("UserIdentityArn"):  result["user_arn"]       = row["UserIdentityArn"]
        if row.get("InitiatingCommands"): result["command"]      = row["InitiatingCommands"]
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

    if not (host or account or cmds):
        return {}
    return {
        "device_name": host,
        "account_name": account,
        "hosts": hosts,            # ALL hosts on the alert — the replay host-filter source
        "command_lines": cmds,
        "alert_name": row.get("AlertName", ""),
        "event_time": event_time,
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
    | project DeviceName, InstanceId;
let AWSData =
    AWSCloudTrail
    | where TimeGenerated between (start_time .. end_time)
    | where EventSource contains "ssm.amazonaws.com"
    | where EventName == "StartSession"
    | extend InstanceId = tostring(parse_json(RequestParameters).target)
    | project InstanceId, SessionIssuerUserName, UserIdentityArn, EventName;
let Enriched = ProcessData | join kind=leftouter DeviceInfoData on DeviceName;
Enriched
| join kind=leftouter AWSData on InstanceId
| project DeviceName, TimeGenerated, AccountName,
          InitiatingCommands = strcat_array(InitiatingCommands, "; "),
          InstanceId, SessionIssuerUserName, UserIdentityArn, EventName
| take 1
"""
    try:
        rows = await _run_la_query(parts, kql)
        if not rows:
            return {}
        row = rows[0]
        logger.info("_query_cloudtrail_no_device: found device=%s for window %s→%s", row.get("DeviceName"), start, end)
        result = {}
        if row.get("DeviceName"):           result["device_name"]    = row["DeviceName"]
        if row.get("TimeGenerated"):        result["time_generated"] = str(row["TimeGenerated"])
        if row.get("AccountName"):          result["account_name"]   = row["AccountName"]
        if row.get("EventName"):            result["event_name"]     = row["EventName"]
        if row.get("InstanceId"):           result["instance_id"]    = row["InstanceId"]
        if row.get("SessionIssuerUserName"): result["session_issuer"] = row["SessionIssuerUserName"]
        if row.get("UserIdentityArn"):      result["user_arn"]       = row["UserIdentityArn"]
        if row.get("InitiatingCommands"):   result["command"]        = row["InitiatingCommands"]
        return result
    except Exception as exc:
        logger.error("_query_cloudtrail_no_device error: %s", exc)
        return {}


async def query_guardduty_details(incident_url: str, alert_time_utc: str) -> dict:
    """Query AWSGuardDuty table for enriched finding details.

    Extracts: userName (IAM role), accessKeyId, MFA status, source IP,
    IP geolocation (city/country/ISP), and service name.
    Returns {} if no match or Log Analytics is unavailable.
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

    kql = f"""
let start_time = datetime('{start}');
let end_time   = datetime('{end}');
AWSGuardDuty
| where TimeGenerated between (start_time .. end_time)
| extend rd = todynamic(ResourceDetails)
| extend sd = todynamic(ServiceDetails)
| extend akd        = rd.accessKeyDetails
| extend apiAction  = sd.action.awsApiCallAction
| extend remoteIp   = apiAction.remoteIpDetails
| project
    TimeGenerated,
    Title,
    ActivityType,
    UserName       = tostring(akd.userName),
    AccessKeyId    = tostring(akd.accessKeyId),
    PrincipalId    = tostring(akd.principalId),
    MfaStatus      = tostring(akd.sessionContext.attributes.mfaStatus),
    IpAddress      = tostring(remoteIp.ipAddressV4),
    CityName       = tostring(remoteIp.city.cityName),
    CountryName    = tostring(remoteIp.country.countryName),
    Isp            = tostring(remoteIp.organization.isp),
    AsnOrg         = tostring(remoteIp.organization.asnOrg),
    ServiceName    = tostring(apiAction.serviceName),
    Api            = tostring(apiAction.api)
| where isnotempty(UserName) or isnotempty(IpAddress)
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
                return {}

            cols = [c["name"] for c in tables[0]["columns"]]
            row  = dict(zip(cols, tables[0]["rows"][0]))

        result: dict = {}
        if row.get("UserName"):    result["user_name"]    = row["UserName"]
        if row.get("AccessKeyId"): result["access_key_id"] = row["AccessKeyId"]
        if row.get("PrincipalId"): result["principal_id"] = row["PrincipalId"]
        if row.get("MfaStatus"):   result["mfa_status"]   = row["MfaStatus"]
        if row.get("IpAddress"):   result["source_ip"]    = row["IpAddress"]
        if row.get("ServiceName"): result["service_name"] = row["ServiceName"]
        if row.get("Api"):         result["event_name"]   = row["Api"]

        # Build geo string
        geo_parts = [p for p in [row.get("CityName"), row.get("CountryName")] if p]
        isp = row.get("Isp") or row.get("AsnOrg", "")
        if isp:
            geo_parts.append(f"via {isp}")
        if geo_parts:
            result["ip_geo"] = ", ".join(geo_parts)

        logger.info("query_guardduty_details: found userName=%s ip=%s mfa=%s",
                    result.get("user_name"), result.get("source_ip"), result.get("mfa_status"))
        return result

    except Exception as exc:
        logger.warning("query_guardduty_details failed: %s", exc)
        return {}


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
    alert that has nothing to do with AWS/root privesc at all: a custom
    MS-SQL-audit alert (classify()=='generic', no device entity because it is
    not an MDE-onboarded host) could get a completely unrelated person's
    macOS/JAMF session glued onto it this way — investigating the wrong entity
    and recommending FP without ever looking at the real actor or server the
    alert was about. Default False: a caller must know the alert is plausibly
    privesc/CloudTrail-shaped before opting into an unscoped fleet-wide match.
    """
    result = extract_cloudtrail_details(incident, entities, alerts)

    alert_time_utc = result.get("time_generated") or (incident.get("properties") or {}).get("firstActivityTimeUtc", "")

    # GuardDuty path: missing role name / MFA / geo → query AWSGuardDuty table
    if result.get("guardduty_link") or not any(result.get(k) for k in ("user_name", "mfa_status")):
        if alert_time_utc and result.get("guardduty_link"):
            logger.info("Querying AWSGuardDuty table for enriched finding details")
            gd_data = await query_guardduty_details(incident_url, alert_time_utc)
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


async def query_netskope_uba(
    incident_url: str,
    alert_name: str = "",
    start_time_utc: str = "",
    end_time_utc: str = "",
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
        '    severity=column_ifexists("severity_s", "")\n'
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

    users = list(dict.fromkeys(str(r.get("user", "")) for r in rows if r.get("user")))
    by_user: dict = {}
    for r in rows:
        u = str(r.get("user", "")) or "(unknown)"
        b = by_user.setdefault(u, {
            "events": 0, "apps": [], "hosts": [], "src_ips": [], "file_types": [],
            "pages": [], "total_bytes": 0, "first_seen": "", "last_seen": "",
            "device": "", "os": "", "useragent": "", "device_classification": "", "ccl": "",
        })
        b["events"] += 1
        for key, col in (("apps", "app"), ("hosts", "hostname"), ("src_ips", "src_ip"),
                         ("file_types", "file_type"), ("pages", "page")):
            v = str(r.get(col, "") or "")
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
