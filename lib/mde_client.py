"""Microsoft Defender for Endpoint (MDE) Advanced Hunting + Log Analytics client.

Provides:
- OAuth2 token acquisition for both MDE and Azure management APIs
- KQL query execution via MDE Advanced Hunting API (Device* tables)
- KQL query execution via Log Analytics workspace API (Sentinel tables)
- Automatic routing: queries are sent to the correct endpoint based on table name
- KQL block extraction from Gemini markdown output
- False-positive filtering (CDN/corporate domains, RFC-1918 IPs)
- DataAnonymizer — strips tenant identifiers before sending context to Gemini

Environment variables:
    MDE_TENANT_ID              Azure AD tenant ID
    MDE_CLIENT_ID              App registration client ID
    MDE_CLIENT_SECRET          App registration client secret
    SENTINEL_SUBSCRIPTION_ID   Azure subscription containing the workspace
    SENTINEL_RESOURCE_GROUP    Resource group of the Log Analytics workspace
    SENTINEL_WORKSPACE_NAME    Log Analytics workspace name
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
from typing import Any

import httpx

logger = logging.getLogger("mde_client")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MDE_VERIFY_SSL = os.getenv("MDE_VERIFY_SSL", os.getenv("CYBLE_VERIFY_SSL", "true")).lower() not in ("false", "0", "no")

_MDE_RESOURCE = "https://api.securitycenter.microsoft.com"
_HUNTING_URL  = "https://api.security.microsoft.com/api/advancedqueries/run"

# ---------------------------------------------------------------------------
# False-positive domain set
# CDN, corporate, and security-vendor domains that appear in telemetry but
# are not threat indicators for Acme.
# ---------------------------------------------------------------------------

_FP_DOMAINS: frozenset[str] = frozenset([
    # Acme production infra (our own domains should not be escalated as FPs
    # from external threat intel; they surface naturally when compromised)
    "example.com", "example.com", "example.com",
    # Microsoft infra
    "microsoft.com", "microsoftonline.com", "windows.com", "windowsupdate.com",
    "office.com", "office365.com", "azure.com", "azurefd.net", "msftconnecttest.com",
    "live.com", "outlook.com", "bing.com", "msn.com",
    # Akamai / CDN
    "akamai.com", "akamaiedge.net", "akamaized.net", "akadns.net",
    "cloudfront.net", "fastly.net", "cloudflare.com", "cloudflare.net",
    "cdn77.com", "edgecastcdn.net",
    # Google
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "googlevideo.com", "youtube.com", "doubleclick.net",
    # AWS
    "amazonaws.com", "awsstatic.com", "amazon.com",
    # Apple
    "apple.com", "icloud.com",
    # Security vendors (telemetry noise)
    "symantec.com", "norton.com", "mcafee.com", "kaspersky.com",
    "eset.com", "bitdefender.com", "crowdstrike.com", "sentinelone.com",
    "cylance.com", "carbonblack.com",
    # File/content delivery CDNs
    "filestackcontent.com", "filestack.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "bootstrapcdn.com", "jquery.com",
    # Common infra
    "digicert.com", "verisign.com", "sectigo.com", "letsencrypt.org",
    "ocsp.msocsp.com", "crl.microsoft.com",
    # NSS / CDN
    "nsatc.net", "nflxvideo.net", "netflixdns.com",
    "twitter.com", "x.com", "facebook.com", "instagram.com", "tiktok.com",
])


# ---------------------------------------------------------------------------
# Public / shared-hosting suffixes
#
# These are registrable suffixes under which anyone can stand up a hostname —
# Cloudflare Workers, GitHub Pages, Azure blob storage, Firebase, etc. Threat
# feeds routinely list one as a "domain" IOC when the actual indicator was a
# specific subdomain (DEMO-112467: the BlueMoon advisory shipped a bare
# "workers.dev", which matched 91 rows of ordinary corporate traffic and none
# of the real C2 infrastructure).
#
# An IOC that is ONLY a suffix identifies a hosting platform, not an attacker.
# A hostname *under* one of these (evil-c2.workers.dev) is still a valid IOC
# and is not rejected.
# ---------------------------------------------------------------------------

_HOSTING_SUFFIXES: frozenset[str] = frozenset([
    # Cloudflare
    "workers.dev", "pages.dev", "r2.dev", "trycloudflare.com", "cfargotunnel.com",
    # GitHub / GitLab / Bitbucket
    "github.io", "githubusercontent.com", "gitlab.io", "bitbucket.io",
    # Google / Firebase
    "web.app", "firebaseapp.com", "appspot.com", "googlecode.com",
    "storage.googleapis.com", "drive.google.com", "docs.google.com",
    "script.google.com", "sites.google.com", "page.link", "firebasestorage.app",
    # Microsoft / Azure
    "blob.core.windows.net", "file.core.windows.net", "queue.core.windows.net",
    "table.core.windows.net", "azurewebsites.net", "azureedge.net",
    "cloudapp.azure.com", "cloudapp.net", "sharepoint.com", "onedrive.live.com",
    "1drv.ms",
    # AWS
    "s3.amazonaws.com", "amazonaws.com", "elasticbeanstalk.com",
    "execute-api.amazonaws.com", "cloudfront.net", "awsapprunner.com",
    # PaaS / hosting / tunnels
    "herokuapp.com", "netlify.app", "vercel.app", "now.sh", "surge.sh",
    "glitch.me", "repl.co", "replit.dev", "render.com", "fly.dev",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "loca.lt", "serveo.net",
    "localtunnel.me", "tunnelto.dev", "telebit.io",
    # File sharing / paste / messaging CDNs
    "dropbox.com", "dropboxusercontent.com", "box.com", "mediafire.com",
    "mega.nz", "anonfiles.com", "gofile.io", "transfer.sh", "file.io",
    "pastebin.com", "paste.ee", "ghostbin.com", "hastebin.com",
    "discord.com", "discordapp.com", "discordapp.net", "cdn.discordapp.com",
    "t.me", "telegram.org", "telegra.ph",
    # Dynamic DNS
    "duckdns.org", "no-ip.org", "no-ip.com", "ddns.net", "hopto.org",
    "zapto.org", "sytes.net", "serveo.com", "myftp.org", "onthewifi.com",
    "dynu.com", "freedns.afraid.org", "chickenkiller.com", "mooo.com",
    # URL shorteners
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    # Blogging / free web hosts
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com",
    "000webhostapp.com", "altervista.org", "neocities.org", "webflow.io",
    "squarespace.com", "myshopify.com",
    # Misc shared infra
    "sendgrid.net", "mailchimp.com", "hubspotusercontent.com",
    "zendesk.com", "atlassian.net", "notion.site", "canva.site",
])


# ---------------------------------------------------------------------------
# Vendor-owned SaaS domains abused as C2 / dead-drop channels
#
# Unlike _HOSTING_SUFFIXES, nobody can register a subdomain here — every host
# under them (api.github.com, main.realtime.ably.net) is the vendor's own
# service, used by the whole fleet. Threat feeds still list them when a
# campaign hides C2 inside one (a GitHub repo, an Ably channel). The attacker
# lives in the URL path, never the host: DEMO-117968 hunted "api.github.com"
# from the IOC hxxps://api.github.com/repos/<attacker> plus "ably.net" and
# returned 4,085 rows of developer and browser traffic.
#
# Matched by suffix. A bare domain IOC here is dropped; a URL IOC is hunted
# by its full URL only.
# ---------------------------------------------------------------------------

_SHARED_SERVICE_DOMAINS: frozenset[str] = frozenset([
    "github.com", "githubusercontent.com", "githubassets.com",
    "gitlab.com", "bitbucket.org",
    "ably.io", "ably.net", "ably-realtime.com",
    "telegram.org", "discord.com", "discordapp.com", "discordapp.net",
    "slack.com", "pastebin.com", "dropbox.com", "dropboxusercontent.com",
])


def _refang(value: str) -> str:
    """Undo threat-feed defanging so a value can be matched against telemetry.

    Feeds ship indicators neutered for safe display ("hxxps://evil[.]com/a").
    Those forms can never match a real RemoteUrl, so they must be refanged
    before being embedded in KQL. Display/storage keeps the defanged form.
    """
    d = (value or "").strip()
    if not d:
        return ""
    d = (d.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
          .replace("[:]", ":").replace("[/]", "/").replace("[@]", "@"))
    d = re.sub(r"^hxx(?=ps?://)", "htt", d, flags=re.IGNORECASE)  # hxxps:// -> https://
    d = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", lambda m: m.group(0).lower(), d)
    return d.strip()


def _strip_to_host(value: str) -> str:
    """Reduce a domain/URL IOC to its bare lowercase hostname.

    Handles defanged forms (hxxp, [.]), schemes, ports, paths, credentials.
    """
    d = _refang(value).lower()
    if not d:
        return ""
    d = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", d)
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.split(":", 1)[0]
    return d.strip(".")


def is_hosting_suffix_only(value: str) -> bool:
    """True if value is a bare shared-hosting suffix, not an attacker-owned host.

    "workers.dev"           -> True   (platform suffix; matches everyone)
    "evil-c2.workers.dev"   -> False  (specific attacker host; keep it)
    "secboxes.com"          -> False
    """
    host = _strip_to_host(value)
    if not host:
        return True  # nothing usable to hunt on
    host = host.removeprefix("www.")
    return host in _HOSTING_SUFFIXES


def is_shared_service_host(value: str) -> bool:
    """True if the host of value is a vendor-owned SaaS service the fleet uses.

    "api.github.com/repos/x" -> True   (hunt the URL, never the host)
    "main.realtime.ably.net" -> True
    "evil.github.io"         -> False  (tenant host; see _HOSTING_SUFFIXES)
    """
    host = _strip_to_host(value)
    return bool(host) and any(host == s or host.endswith("." + s)
                              for s in _SHARED_SERVICE_DOMAINS)


def _is_private_ip(ip: str) -> bool:
    """Return True if ip is RFC-1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _domain_is_fp(domain: str) -> bool:
    d = _strip_to_host(domain).removeprefix("www.")
    return any(d == fp or d.endswith("." + fp) for fp in _FP_DOMAINS)


# ---------------------------------------------------------------------------
# Token cache (simple in-memory, thread-safe enough for single-process use)
# ---------------------------------------------------------------------------

_token_cache: dict[str, Any] = {"token": None, "expires_at": 0.0}
_mgmt_token_cache: dict[str, Any] = {"token": None, "expires_at": 0.0}


async def get_access_token() -> str | None:
    """Return a valid Bearer token for MDE, fetching a new one when expired."""
    # Read credentials lazily so Secrets Manager values loaded into os.environ
    # at app startup (via lib/config.py) are available even if this module was
    # imported before get_config() ran.
    mde_tenant_id     = os.getenv("MDE_TENANT_ID", "")
    mde_client_id     = os.getenv("MDE_CLIENT_ID", "")
    mde_client_secret = os.getenv("MDE_CLIENT_SECRET", "")

    if not all([mde_tenant_id, mde_client_id, mde_client_secret]):
        logger.warning("MDE credentials not configured — skipping MDE hunting")
        return None

    now = time.monotonic()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 30:
        return _token_cache["token"]

    token_url = f"https://login.microsoftonline.com/{mde_tenant_id}/oauth2/token"
    try:
        async with httpx.AsyncClient(timeout=15, verify=MDE_VERIFY_SSL) as client:
            resp = await client.post(
                token_url,
                data={
                    "grant_type":    "client_credentials",
                    "client_id":     mde_client_id,
                    "client_secret": mde_client_secret,
                    "resource":      _MDE_RESOURCE,
                },
            )
            resp.raise_for_status()
            body = resp.json()
            _token_cache["token"]      = body["access_token"]
            _token_cache["expires_at"] = now + int(body.get("expires_in", 3600))
            logger.info("MDE token acquired (expires in %ss)", body.get("expires_in", 3600))
            return _token_cache["token"]
    except Exception as exc:
        logger.error("Failed to acquire MDE token: %s", exc)
        return None


async def get_management_token() -> str | None:
    """Return a valid Bearer token for management.azure.com (Log Analytics)."""
    tenant_id     = os.getenv("MDE_TENANT_ID", "")
    client_id     = os.getenv("MDE_CLIENT_ID", "")
    client_secret = os.getenv("MDE_CLIENT_SECRET", "")

    if not all([tenant_id, client_id, client_secret]):
        return None

    now = time.monotonic()
    if _mgmt_token_cache["token"] and now < _mgmt_token_cache["expires_at"] - 30:
        return _mgmt_token_cache["token"]

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    try:
        async with httpx.AsyncClient(timeout=15, verify=MDE_VERIFY_SSL) as client:
            resp = await client.post(
                token_url,
                data={
                    "grant_type":    "client_credentials",
                    "client_id":     client_id,
                    "client_secret": client_secret,
                    "scope":         "https://management.azure.com/.default",
                },
            )
            resp.raise_for_status()
            body = resp.json()
            _mgmt_token_cache["token"]      = body["access_token"]
            _mgmt_token_cache["expires_at"] = now + int(body.get("expires_in", 3600))
            logger.info("Management token acquired (expires in %ss)", body.get("expires_in", 3600))
            return _mgmt_token_cache["token"]
    except Exception as exc:
        logger.error("Failed to acquire management token: %s", exc)
        return None


async def get_machine_by_dns_name(host: str, token: str) -> dict | None:
    """Resolve a device by its computerDnsName to its MDE machine record.

    Sentinel-ingested alerts arrive with NO machineId even when the host IS
    Defender-onboarded, so a missing machineId must never be read as "not
    onboarded". This looks the host up in MDE and returns the machine record
    (id, onboardingStatus, healthStatus, lastSeen, osPlatform) or None if the
    host is genuinely unknown to MDE / the lookup fails. Tries the exact FQDN
    first, then a short-name prefix (covers FQDN-vs-hostname mismatch).
    """
    if not host or not token:
        return None
    esc = host.replace("'", "''")            # OData string-literal escape
    short = host.split(".")[0].replace("'", "''")
    filters = [f"computerDnsName eq '{esc}'"]
    if short and short != esc:
        filters.append(f"startswith(computerDnsName,'{short}')")
    try:
        async with httpx.AsyncClient(timeout=15, verify=MDE_VERIFY_SSL) as client:
            for filt in filters:
                resp = await client.get(
                    f"{_MDE_RESOURCE}/api/machines",
                    params={"$filter": filt},
                    headers={"Authorization": f"Bearer {token}"},
                )
                if resp.status_code != 200:
                    logger.info("MDE machine lookup %r -> HTTP %s", host, resp.status_code)
                    continue
                machines = resp.json().get("value", [])
                if machines:
                    machines.sort(key=lambda m: m.get("lastSeen") or "", reverse=True)
                    return machines[0]
    except Exception as exc:
        logger.info("MDE machine lookup for %r failed: %s", host, exc)
    return None


# ---------------------------------------------------------------------------
# MDE table schemas — fetched live via `| getschema` on 2026-06-18.
# Alert/Email/Identity tables are not accessible via the MDE-only token;
# they require M365 Defender unified RBAC and are excluded from _VALID_MDE_TABLES.
# ---------------------------------------------------------------------------

# Sentinel-internal metadata columns — not real MDE columns, exclude from hints.
_SENTINEL_COLS = frozenset(["TenantId", "Type", "SourceSystem", "MachineGroup", "TimeGenerated"])

MDE_TABLE_SCHEMA: dict[str, list[str]] = {
    "DeviceEvents": [c for c in [
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName", "FolderPath",
        "SHA1", "SHA256", "MD5", "FileSize", "AccountDomain", "AccountName", "AccountSid",
        "RemoteUrl", "RemoteDeviceName", "ProcessId", "ProcessCommandLine",
        "ProcessCreationTime", "ProcessTokenElevation", "LogonId", "RegistryKey",
        "RegistryValueName", "RegistryValueData", "RemoteIP", "RemotePort", "LocalIP",
        "LocalPort", "FileOriginUrl", "FileOriginIP", "InitiatingProcessSHA1",
        "InitiatingProcessSHA256", "InitiatingProcessMD5", "InitiatingProcessFileName",
        "InitiatingProcessFileSize", "InitiatingProcessFolderPath", "InitiatingProcessId",
        "InitiatingProcessCommandLine", "InitiatingProcessCreationTime",
        "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
        "InitiatingProcessAccountObjectId", "InitiatingProcessVersionInfoCompanyName",
        "InitiatingProcessVersionInfoProductName", "InitiatingProcessVersionInfoProductVersion",
        "InitiatingProcessVersionInfoInternalFileName", "InitiatingProcessVersionInfoOriginalFileName",
        "InitiatingProcessVersionInfoFileDescription", "InitiatingProcessParentId",
        "InitiatingProcessParentFileName", "InitiatingProcessParentCreationTime",
        "InitiatingProcessLogonId", "ReportId", "AppGuardContainerId", "AdditionalFields",
        "InitiatingProcessSessionId", "IsInitiatingProcessRemoteSession",
        "InitiatingProcessRemoteSessionDeviceName", "InitiatingProcessRemoteSessionIP",
        "CreatedProcessSessionId", "IsProcessRemoteSession", "ProcessRemoteSessionDeviceName",
        "ProcessRemoteSessionIP", "InitiatingProcessUniqueId",
    ] if c not in _SENTINEL_COLS],

    "DeviceFileEvents": [c for c in [
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName", "FolderPath",
        "SHA1", "SHA256", "MD5", "FileOriginUrl", "FileOriginReferrerUrl", "FileOriginIP",
        "PreviousFolderPath", "PreviousFileName", "FileSize",
        "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
        "InitiatingProcessAccountObjectId", "InitiatingProcessMD5", "InitiatingProcessSHA1",
        "InitiatingProcessSHA256", "InitiatingProcessFolderPath", "InitiatingProcessFileName",
        "InitiatingProcessFileSize", "InitiatingProcessVersionInfoCompanyName",
        "InitiatingProcessVersionInfoProductName", "InitiatingProcessVersionInfoProductVersion",
        "InitiatingProcessVersionInfoInternalFileName", "InitiatingProcessVersionInfoOriginalFileName",
        "InitiatingProcessVersionInfoFileDescription", "InitiatingProcessId",
        "InitiatingProcessCommandLine", "InitiatingProcessCreationTime",
        "InitiatingProcessIntegrityLevel", "InitiatingProcessTokenElevation",
        "InitiatingProcessParentId", "InitiatingProcessParentFileName",
        "InitiatingProcessParentCreationTime", "RequestProtocol", "RequestSourceIP",
        "RequestSourcePort", "RequestAccountName", "RequestAccountDomain", "RequestAccountSid",
        "ShareName", "SensitivityLabel", "SensitivitySubLabel", "IsAzureInfoProtectionApplied",
        "ReportId", "AppGuardContainerId", "AdditionalFields", "InitiatingProcessSessionId",
        "IsInitiatingProcessRemoteSession", "InitiatingProcessRemoteSessionDeviceName",
        "InitiatingProcessRemoteSessionIP", "InitiatingProcessUniqueId",
    ] if c not in _SENTINEL_COLS],

    "DeviceImageLoadEvents": [c for c in [
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName", "FolderPath",
        "SHA1", "SHA256", "MD5", "FileSize",
        "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
        "InitiatingProcessAccountObjectId", "InitiatingProcessIntegrityLevel",
        "InitiatingProcessTokenElevation", "InitiatingProcessSHA1", "InitiatingProcessSHA256",
        "InitiatingProcessMD5", "InitiatingProcessFileName", "InitiatingProcessFileSize",
        "InitiatingProcessVersionInfoCompanyName", "InitiatingProcessVersionInfoProductName",
        "InitiatingProcessVersionInfoProductVersion", "InitiatingProcessVersionInfoInternalFileName",
        "InitiatingProcessVersionInfoOriginalFileName", "InitiatingProcessVersionInfoFileDescription",
        "InitiatingProcessId", "InitiatingProcessCommandLine", "InitiatingProcessCreationTime",
        "InitiatingProcessFolderPath", "InitiatingProcessParentId",
        "InitiatingProcessParentFileName", "InitiatingProcessParentCreationTime",
        "ReportId", "AppGuardContainerId", "InitiatingProcessSessionId",
        "IsInitiatingProcessRemoteSession", "InitiatingProcessRemoteSessionDeviceName",
        "InitiatingProcessRemoteSessionIP", "InitiatingProcessUniqueId",
    ] if c not in _SENTINEL_COLS],

    "DeviceLogonEvents": [c for c in [
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "LogonType", "AccountDomain",
        "AccountName", "AccountSid", "Protocol", "FailureReason", "IsLocalAdmin", "LogonId",
        "RemoteDeviceName", "RemoteIP", "RemoteIPType", "RemotePort",
        "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
        "InitiatingProcessAccountObjectId", "InitiatingProcessIntegrityLevel",
        "InitiatingProcessTokenElevation", "InitiatingProcessSHA1", "InitiatingProcessSHA256",
        "InitiatingProcessMD5", "InitiatingProcessFileName", "InitiatingProcessFileSize",
        "InitiatingProcessVersionInfoCompanyName", "InitiatingProcessVersionInfoProductName",
        "InitiatingProcessVersionInfoProductVersion", "InitiatingProcessVersionInfoInternalFileName",
        "InitiatingProcessVersionInfoOriginalFileName", "InitiatingProcessVersionInfoFileDescription",
        "InitiatingProcessId", "InitiatingProcessCommandLine", "InitiatingProcessCreationTime",
        "InitiatingProcessFolderPath", "InitiatingProcessParentId",
        "InitiatingProcessParentFileName", "InitiatingProcessParentCreationTime",
        "ReportId", "AppGuardContainerId", "AdditionalFields", "InitiatingProcessSessionId",
        "IsInitiatingProcessRemoteSession", "InitiatingProcessRemoteSessionDeviceName",
        "InitiatingProcessRemoteSessionIP", "InitiatingProcessUniqueId",
    ] if c not in _SENTINEL_COLS],

    "DeviceNetworkEvents": [c for c in [
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "RemoteIP", "RemotePort",
        "RemoteUrl", "LocalIP", "LocalPort", "Protocol", "LocalIPType", "RemoteIPType",
        "InitiatingProcessSHA1", "InitiatingProcessSHA256", "InitiatingProcessMD5",
        "InitiatingProcessFileName", "InitiatingProcessFileSize",
        "InitiatingProcessVersionInfoCompanyName", "InitiatingProcessVersionInfoProductName",
        "InitiatingProcessVersionInfoProductVersion", "InitiatingProcessVersionInfoInternalFileName",
        "InitiatingProcessVersionInfoOriginalFileName", "InitiatingProcessVersionInfoFileDescription",
        "InitiatingProcessId", "InitiatingProcessCommandLine", "InitiatingProcessCreationTime",
        "InitiatingProcessFolderPath", "InitiatingProcessParentFileName",
        "InitiatingProcessParentId", "InitiatingProcessParentCreationTime",
        "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
        "InitiatingProcessAccountObjectId", "InitiatingProcessIntegrityLevel",
        "InitiatingProcessTokenElevation", "ReportId", "AppGuardContainerId", "AdditionalFields",
        "InitiatingProcessSessionId", "IsInitiatingProcessRemoteSession",
        "InitiatingProcessRemoteSessionDeviceName", "InitiatingProcessRemoteSessionIP",
        "InitiatingProcessUniqueId",
    ] if c not in _SENTINEL_COLS],

    "DeviceProcessEvents": [c for c in [
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName", "FolderPath",
        "SHA1", "SHA256", "MD5", "FileSize", "ProcessVersionInfoCompanyName",
        "ProcessVersionInfoProductName", "ProcessVersionInfoProductVersion",
        "ProcessVersionInfoInternalFileName", "ProcessVersionInfoOriginalFileName",
        "ProcessVersionInfoFileDescription", "ProcessId", "ProcessCommandLine",
        "ProcessIntegrityLevel", "ProcessTokenElevation", "ProcessCreationTime",
        "AccountDomain", "AccountName", "AccountSid", "AccountUpn", "AccountObjectId",
        "LogonId", "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
        "InitiatingProcessAccountObjectId", "InitiatingProcessLogonId",
        "InitiatingProcessIntegrityLevel", "InitiatingProcessTokenElevation",
        "InitiatingProcessSHA1", "InitiatingProcessSHA256", "InitiatingProcessMD5",
        "InitiatingProcessFileName", "InitiatingProcessFileSize",
        "InitiatingProcessVersionInfoCompanyName", "InitiatingProcessVersionInfoProductName",
        "InitiatingProcessVersionInfoProductVersion", "InitiatingProcessVersionInfoInternalFileName",
        "InitiatingProcessVersionInfoOriginalFileName", "InitiatingProcessVersionInfoFileDescription",
        "InitiatingProcessId", "InitiatingProcessCommandLine", "InitiatingProcessCreationTime",
        "InitiatingProcessFolderPath", "InitiatingProcessParentId",
        "InitiatingProcessParentFileName", "InitiatingProcessParentCreationTime",
        "InitiatingProcessSignerType", "InitiatingProcessSignatureStatus",
        "ReportId", "AppGuardContainerId", "AdditionalFields", "InitiatingProcessSessionId",
        "IsInitiatingProcessRemoteSession", "InitiatingProcessRemoteSessionDeviceName",
        "InitiatingProcessRemoteSessionIP", "CreatedProcessSessionId",
        "IsProcessRemoteSession", "ProcessRemoteSessionDeviceName", "ProcessRemoteSessionIP",
        "ProcessUniqueId", "InitiatingProcessUniqueId",
    ] if c not in _SENTINEL_COLS],

    "DeviceRegistryEvents": [c for c in [
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "RegistryKey",
        "RegistryValueType", "RegistryValueName", "RegistryValueData",
        "PreviousRegistryKey", "PreviousRegistryValueName", "PreviousRegistryValueData",
        "InitiatingProcessAccountDomain", "InitiatingProcessAccountName",
        "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
        "InitiatingProcessAccountObjectId", "InitiatingProcessSHA1", "InitiatingProcessSHA256",
        "InitiatingProcessMD5", "InitiatingProcessFileName", "InitiatingProcessFileSize",
        "InitiatingProcessVersionInfoCompanyName", "InitiatingProcessVersionInfoProductName",
        "InitiatingProcessVersionInfoProductVersion", "InitiatingProcessVersionInfoInternalFileName",
        "InitiatingProcessVersionInfoOriginalFileName", "InitiatingProcessVersionInfoFileDescription",
        "InitiatingProcessId", "InitiatingProcessCommandLine", "InitiatingProcessCreationTime",
        "InitiatingProcessFolderPath", "InitiatingProcessParentId",
        "InitiatingProcessParentFileName", "InitiatingProcessParentCreationTime",
        "InitiatingProcessIntegrityLevel", "InitiatingProcessTokenElevation",
        "ReportId", "AppGuardContainerId", "InitiatingProcessSessionId",
        "IsInitiatingProcessRemoteSession", "InitiatingProcessRemoteSessionDeviceName",
        "InitiatingProcessRemoteSessionIP", "InitiatingProcessUniqueId",
    ] if c not in _SENTINEL_COLS],
}


def _schema_hint(table: str) -> str:
    """Return a compact comma-separated column list for use in prompts."""
    cols = MDE_TABLE_SCHEMA.get(table) or SENTINEL_TABLE_SCHEMA.get(table, [])
    return ", ".join(cols) if cols else "(schema unknown)"


# ---------------------------------------------------------------------------
# Sentinel (Log Analytics workspace) table schemas — fetched live 2026-06-19.
# These tables are queried via the Log Analytics API using a management token.
# Sentinel-internal metadata columns (TenantId, SourceSystem, Type) excluded.
# ---------------------------------------------------------------------------

_SENTINEL_INTERNAL = frozenset(["TenantId", "SourceSystem", "Type", "_ResourceId", "MG",
                                 "TimeCollected", "ManagementGroupName", "PartitionKey",
                                 "RowKey", "StorageAccount", "AzureDeploymentID", "AzureTableName"])

SENTINEL_TABLE_SCHEMA: dict[str, list[str]] = {
    "AlertInfo": [c for c in [
        "TimeGenerated", "Timestamp", "AlertId", "Title", "Category", "Severity",
        "ServiceSource", "DetectionSource", "AttackTechniques",
    ] if c not in _SENTINEL_INTERNAL],

    "AlertEvidence": [c for c in [
        "TimeGenerated", "Timestamp", "AlertId", "Title", "Categories", "AttackTechniques",
        "ServiceSource", "DetectionSource", "EntityType", "EvidenceRole", "EvidenceDirection",
        "FileName", "FolderPath", "SHA1", "SHA256", "FileSize", "ThreatFamily",
        "RemoteIP", "RemoteUrl", "AccountName", "AccountDomain", "AccountSid",
        "AccountObjectId", "AccountUpn", "DeviceId", "DeviceName", "LocalIP",
        "NetworkMessageId", "EmailSubject", "ApplicationId", "Application",
        "OAuthApplicationId", "ProcessCommandLine", "AdditionalFields",
        "RegistryKey", "RegistryValueName", "RegistryValueData",
        "CloudPlatform", "CloudResource", "Severity",
    ] if c not in _SENTINEL_INTERNAL],

    "IdentityLogonEvents": [c for c in [
        "TimeGenerated", "Timestamp", "ActionType", "Application", "LogonType", "Protocol",
        "FailureReason", "AccountName", "AccountDomain", "AccountUpn", "AccountSid",
        "AccountObjectId", "AccountDisplayName", "DeviceName", "DeviceType", "OSPlatform",
        "IPAddress", "Port", "DestinationDeviceName", "DestinationIPAddress",
        "DestinationPort", "TargetDeviceName", "TargetAccountDisplayName",
        "Location", "ISP", "ReportId", "AdditionalFields",
        "LastSeenForUser", "UncommonForUser",
    ] if c not in _SENTINEL_INTERNAL],

    "IdentityInfo": [c for c in [
        "TimeGenerated", "AccountName", "AccountDomain", "AccountUPN", "AccountSID",
        "AccountObjectId", "AccountTenantId", "AccountDisplayName", "AccountCloudSID",
        "GivenName", "Surname", "Department", "JobTitle", "EmployeeId",
        "MailAddress", "AdditionalMailAddresses", "Manager", "Phone",
        "StreetAddress", "City", "State", "Country", "CompanyName",
        "IsAccountEnabled", "IsServiceAccount", "IsMFARegistered",
        "RiskLevel", "RiskLevelDetails", "RiskState", "EntityRiskScore",
        "BlastRadius", "InvestigationPriority", "InvestigationPriorityPercentile",
        "GroupMembership", "AssignedRoles", "Tags", "Applications", "ServicePrincipals",
        "RelatedAccounts", "AccountCreationTime", "DeletedDateTime", "LastSeenDate",
        "UACFlags", "UserAccountControl", "UserState", "UserStateChangedOn", "UserType",
        "OnPremisesAccountObjectId", "OnPremisesDistinguishedName", "OnPremisesExtensionAttributes",
        "ExtensionProperty", "SAMAccountName", "ChangeSource",
    ] if c not in _SENTINEL_INTERNAL],

    "SecurityEvent": [c for c in [
        "TimeGenerated", "EventID", "Activity", "EventSourceName", "Channel",
        "Task", "Level", "EventLevelName", "EventData", "EventRecordId", "EventOriginId",
        "Computer", "Account", "AccountType", "AccountName", "AccountDomain",
        "AccountExpires", "AccountSessionIdentifier",
        "SamAccountName", "UserPrincipalName", "UserAccountControl", "UserParameters",
        "UserWorkstations",
        "SubjectUserName", "SubjectUserSid", "SubjectDomainName", "SubjectLogonId",
        "SubjectAccount", "SubjectMachineName", "SubjectMachineSID", "SubjectKeyIdentifier",
        "TargetUserName", "TargetUserSid", "TargetDomainName", "TargetLogonId",
        "TargetAccount", "TargetSid", "TargetUser", "TargetServerName", "TargetInfo",
        "TargetLinkedLogonId", "TargetLogonGuid", "TargetOutboundDomainName",
        "TargetOutboundUserName",
        "LogonType", "LogonTypeName", "LogonProcessName", "LogonGuid", "LogonID",
        "LogonHours", "AuthenticationPackageName", "LmPackageName",
        "AuthenticationLevel", "AuthenticationProvider", "AuthenticationServer",
        "AuthenticationService", "AuthenticationType",
        "IpAddress", "IpPort", "WorkstationName", "Workstation",
        "ClientAddress", "ClientIPAddress", "ClientName",
        "ProcessName", "ProcessId", "NewProcessName", "NewProcessId",
        "CallerProcessId", "CallerProcessName", "ParentProcessName",
        "Process", "CommandLine",
        "FailureReason", "Status", "SubStatus", "ErrorCode",
        "PrivilegeList", "ImpersonationLevel", "ElevatedToken", "TokenElevationType",
        "MandatoryLabel", "RestrictedAdminMode", "VirtualAccount", "MachineLogon",
        "ObjectName", "ObjectType", "ObjectServer", "ObjectValueName",
        "NewValue", "OldValue", "NewValueType", "OldValueType",
        "ShareName", "ShareLocalPath", "RelativeTargetName",
        "ServiceName", "ServiceFileName", "ServiceType", "ServiceStartType", "ServiceAccount",
        "AccessList", "AccessMask", "AccessReason", "HandleId",
        "KeyLength", "SecurityDescriptor",
        "DomainName", "DomainSid", "DCDNSName", "DomainBehaviorVersion", "DomainPolicyChanged",
        "MemberName", "MemberSid", "GroupMembership", "SidHistory",
        "AuditPolicyChanges", "AuditsDiscarded",
        "FileHash", "FilePath", "FilePathNoUser", "Fqbn",
        "HomeDirectory", "HomePath", "ProfilePath", "ScriptPath",
        "RemoteIpAddress", "RemotePort",
        "NASIdentifier", "NASIPv4Address", "NASIPv6Address", "NASPort", "NASPortType",
        "NetworkPolicyName", "ProxyPolicyName",
        "EAPType", "CACertificateHash", "CAPublicKeyHash", "CertificateDatabaseHash",
        "CalledStationID", "CallingStationID",
        "DeviceDescription", "DeviceId", "DisplayName", "Disposition",
        "HardwareIds", "VendorIds", "CompatibleIds",
        "ClassId", "ClassName",
        "InterfaceUuid", "ProtocolSequence", "PackageName",
        "LockoutDuration", "LockoutObservationWindow", "LockoutThreshold",
        "MachineAccountQuota", "MachineInventory",
        "MaxPasswordAge", "MinPasswordAge", "MinPasswordLength",
        "PasswordHistoryLength", "PasswordLastSet", "PasswordProperties",
        "MixedDomainMode", "DomainSid",
        "NewDate", "NewTime", "PreviousDate", "PreviousTime",
        "NewMaxUsers", "OldMaxUsers", "NewRemark", "OldRemark",
        "NewShareFlags", "OldShareFlags", "NewUacValue", "OldUacValue",
        "OemInformation", "LocationInformation",
        "Filter", "ForceLogoff",
        "FullyQualifiedSubjectMachineName", "FullyQualifiedSubjectUserName",
        "AllowedToDelegateTo", "Attributes",
        "OperationType", "CategoryId",
        "PrimaryGroupId", "PrivateKeyUsageCount",
        "Properties", "RequestId", "Requester",
        "RowsDeleted", "SessionName", "Subject",
        "SubcategoryGuid", "SubcategoryId", "TableId",
        "TemplateContent", "TemplateDSObjectFQDN", "TemplateInternalName",
        "TemplateOID", "TemplateSchemaVersion", "TemplateVersion",
        "TransmittedServices",
        "AdditionalInfo", "AdditionalInfo2",
        "QuarantineHelpURL", "QuarantineSessionID", "QuarantineSessionIdentifier",
        "QuarantineState", "QuarantineSystemHealthResult", "ExtendedQuarantineState",
        "LoggingResult",
        "SourceComputerId", "SystemProcessId", "SystemThreadId", "SystemUserId",
        "Version", "Opcode", "Keywords", "Correlation",
    ] if c not in _SENTINEL_INTERNAL],

    "SigninLogs": [c for c in [
        "TimeGenerated", "OperationName", "OperationVersion", "Category",
        "ResultType", "ResultSignature", "ResultDescription", "DurationMs",
        "CorrelationId", "Resource", "ResourceGroup", "ResourceProvider",
        "ResourceId", "ResourceDisplayName", "ResourceIdentity",
        "ResourceServicePrincipalId", "ResourceTenantId", "ResourceOwnerTenantId",
        "Identity", "Level", "Location",
        "UserPrincipalName", "UserDisplayName", "UserId", "UserType",
        "AlternateSignInName", "SignInIdentifier", "SignInIdentifierType",
        "AppDisplayName", "AppId",
        "IPAddress", "IPAddressFromResourceProvider",
        "LocationDetails", "NetworkLocationDetails",
        "DeviceDetail", "ClientAppUsed",
        "IsInteractive", "IsRisky", "FlaggedForReview",
        "RiskDetail", "RiskEventTypes", "RiskEventTypes_V2", "RiskLevel",
        "RiskLevelAggregated", "RiskLevelDuringSignIn", "RiskState",
        "ConditionalAccessStatus", "ConditionalAccessPolicies",
        "ConditionalAccessAudiences", "AppliedConditionalAccessPolicies",
        "AuthenticationRequirement", "AuthenticationRequirementPolicies",
        "AuthenticationDetails", "AuthenticationMethodsUsed",
        "AuthenticationProcessingDetails", "AuthenticationContextClassReferences",
        "AuthenticationProtocol", "AuthenticationAppDeviceDetails",
        "AuthenticationAppPolicyEvaluationDetails",
        "MfaDetail", "Status", "TokenIssuerName", "TokenIssuerType",
        "TokenProtectionStatusDetails", "IncomingTokenType",
        "HomeTenantId", "HomeTenantName", "CrossTenantAccessType",
        "ServicePrincipalId", "ServicePrincipalName",
        "AppOwnerTenantId", "SourceAppClientId",
        "SessionId", "SessionLifetimePolicies", "UniqueTokenIdentifier",
        "OriginalRequestId", "OriginalTransferMethod",
        "ProcessingTimeInMilliseconds", "Id", "CreatedDateTime",
        "ClientCredentialType", "FederatedCredentialId",
        "GlobalSecureAccessIpAddress", "IsTenantRestricted", "IsThroughGlobalSecureAccess",
        "AutonomousSystemNumber", "Agent", "UserAgent",
        "AADTenantId", "AppliedEventListeners", "AuthenticatorAppLocation",
    ] if c not in _SENTINEL_INTERNAL],

    "AADNonInteractiveUserSignInLogs": [c for c in [
        "TimeGenerated", "OperationName", "OperationVersion", "Category",
        "ResultType", "ResultSignature", "ResultDescription", "DurationMs",
        "CorrelationId", "ResourceGroup", "Identity", "Level", "Location",
        "UserPrincipalName", "UserDisplayName", "UserId", "UserType",
        "AlternateSignInName", "SignInIdentifierType", "SignInEventTypes",
        "AppDisplayName", "AppId",
        "IPAddress", "LocationDetails", "NetworkLocationDetails",
        "DeviceDetail", "ClientAppUsed", "ClientSessionId",
        "IsInteractive", "IsRisky",
        "RiskDetail", "RiskEventTypes", "RiskEventTypes_V2",
        "RiskLevelAggregated", "RiskLevelDuringSignIn", "RiskState",
        "ConditionalAccessStatus", "ConditionalAccessPolicies",
        "ConditionalAccessPoliciesV2", "ConditionalAccessAudiences",
        "AuthenticationRequirement", "AuthenticationRequirementPolicies",
        "AuthenticationDetails", "AuthenticationMethodsUsed",
        "AuthenticationProcessingDetails", "AuthenticationContextClassReferences",
        "AuthenticationProtocol", "AuthenticatorAppLocation",
        "MfaDetail", "Status", "TokenIssuerName", "TokenIssuerType",
        "TokenProtectionStatusDetails", "IncomingTokenType",
        "HomeTenantId", "HomeTenantName", "CrossTenantAccessType",
        "ServicePrincipalId", "ResourceDisplayName", "ResourceIdentity",
        "ResourceServicePrincipalId", "ResourceTenantId", "ResourceOwnerTenantId",
        "AppOwnerTenantId", "SessionId", "SessionLifetimePolicies",
        "UniqueTokenIdentifier", "OriginalRequestId", "OriginalTransferMethod",
        "ProcessingTimeInMs", "Id", "CreatedDateTime",
        "ClientCredentialType", "FederatedCredentialId",
        "GlobalSecureAccessIpAddress", "IsTenantRestricted", "IsThroughGlobalSecureAccess",
        "AutonomousSystemNumber", "Agent", "UserAgent",
        "AADTenantId", "AppliedEventListeners",
    ] if c not in _SENTINEL_INTERNAL],

    "SecurityAlert": [c for c in [
        "TimeGenerated", "DisplayName", "AlertName", "AlertSeverity", "AlertType",
        "Description", "ProviderName", "VendorName", "VendorOriginalId",
        "SystemAlertId", "ResourceId", "SourceComputerId", "ConfidenceLevel",
        "ConfidenceScore", "IsIncident", "StartTime", "EndTime", "ProcessingEndTime",
        "RemediationSteps", "ExtendedProperties", "Entities", "ExtendedLinks",
        "ProductName", "ProductComponentName", "AlertLink", "Status",
        "WorkspaceSubscriptionId", "WorkspaceResourceGroup",
        "CompromisedEntity", "Tactics", "Techniques", "SubTechniques",
    ] if c not in _SENTINEL_INTERNAL],
}

# Tables the agent's hunts reach for beyond the ones above (log ingestion, Office, Entra
# audit, CloudTrail, firewall/CEF). Without them every Gemini query on these tables had
# its `where` filter read as an unknown column and was rejected whole, so hunt_query
# reported "empty KQL" (log-ingestion triage failed on every run, 9-13 Oct). Columns
# read from the workspace with `<table> | getschema` on 2026-10-14, not written by hand.
_SENTINEL_EXTRA_TABLES: dict[str, list[str]] = {
    "Usage": [c for c in [
        "TenantId", "Computer", "TimeGenerated", "Plan", "SourceSystem", "StartTime",
        "EndTime", "ResourceUri", "LinkedResourceUri", "DataType", "Solution",
        "BatchesWithinSla", "BatchesOutsideSla", "BatchesCapped", "TotalBatches",
        "AvgLatencyInSeconds", "Quantity", "QuantityUnit", "IsBillable", "MeterId",
        "LinkedMeterId", "Type",
    ] if c not in _SENTINEL_INTERNAL],
    "Heartbeat": [c for c in [
        "TenantId", "SourceSystem", "TimeGenerated", "MG", "ManagementGroupName",
        "SourceComputerId", "ComputerIP", "Computer", "Category", "OSType", "OSName",
        "OSMajorVersion", "OSMinorVersion", "Version", "SCAgentChannel",
        "IsGatewayInstalled", "RemoteIPLongitude", "RemoteIPLatitude",
        "RemoteIPCountry", "SubscriptionId", "ResourceGroup", "ResourceProvider",
        "Resource", "ResourceId", "ResourceType", "ComputerEnvironment", "Solutions",
        "VMUUID", "ComputerPrivateIPs", "Type",
    ] if c not in _SENTINEL_INTERNAL],
    "SentinelHealth": [c for c in [
        "TenantId", "TimeGenerated", "OperationName", "SentinelResourceId",
        "SentinelResourceName", "Status", "Description", "Reason", "WorkspaceId",
        "SentinelResourceType", "SentinelResourceKind", "RecordId",
        "ExtendedProperties", "SourceSystem", "Type",
    ] if c not in _SENTINEL_INTERNAL],
    "OfficeActivity": [c for c in [
        "TenantId", "Application", "UserDomain", "Activity", "UserAgent", "RecordType",
        "TimeGenerated", "Operation", "OrganizationId", "OrganizationId_", "UserType",
        "UserKey", "OfficeWorkload", "ResultStatus", "ResultReasonType",
        "OfficeObjectId", "UserId", "UserId_", "ClientIP", "ClientIP_", "Scope",
        "Site_", "ItemType", "EventSource", "Source_Name", "MachineDomainInfo",
        "MachineId", "Site_Url", "Site_Url_", "SourceRelativeUrl", "SourceRelativeUrl_",
        "SourceFileName", "SourceFileName_", "SourceFileExtension",
        "DestinationRelativeUrl", "DestinationFileName", "DestinationFileExtension",
        "UserSharedWith", "SharingType", "CustomEvent", "Event_Data",
        "ModifiedObjectResolvedName", "Parameters", "ExternalAccess",
        "OriginatingServer", "OrganizationName", "Logon_Type", "InternalLogonType",
        "MailboxGuid", "MailboxOwnerUPN", "MailboxOwnerSid",
        "MailboxOwnerMasterAccountSid", "LogonUserSid", "LogonUserDisplayName",
        "ClientInfoString", "Client_IPAddress", "ClientMachineName",
        "ClientProcessName", "ClientVersion", "Folder", "CrossMailboxOperations",
        "DestMailboxId", "DestMailboxOwnerUPN", "DestMailboxOwnerSid",
        "DestMailboxOwnerMasterAccountSid", "DestFolder", "Folders", "AffectedItems",
        "Item", "ModifiedProperties", "SendAsUserSmtp", "SendAsUserMailboxGuid",
        "SendOnBehalfOfUserSmtp", "SendonBehalfOfUserMailboxGuid", "ExtendedProperties",
        "Client", "LoginStatus", "Actor", "ActorContextId", "ActorIpAddress",
        "InterSystemsId", "IntraSystemId", "SupportTicketId", "TargetContextId",
        "DataCenterSecurityEventType", "EffectiveOrganization", "ElevationTime",
        "ElevationApprover", "ElevationApprovedTime", "ElevationRequestId",
        "ElevationRole", "ElevationDuration", "GenericInfo", "SourceSystem", "OfficeId",
        "SourceRecordId", "AzureActiveDirectory_EventType", "AADTarget", "Start_Time",
        "OfficeTenantId", "OfficeTenantId_", "TargetUserOrGroupName",
        "TargetUserOrGroupType", "MessageId", "Members", "TeamName", "TeamGuid",
        "ChannelType", "ChannelName", "ChannelGuid", "ExtraProperties", "AddOnType",
        "AddonName", "TabType", "Name", "OldValue", "NewValue", "ItemName",
        "ChatThreadId", "ChatName", "CommunicationType", "AADGroupId", "AddOnGuid",
        "AppDistributionMode", "TargetUserId", "OperationScope", "AzureADAppId",
        "OperationProperties", "AppId", "ClientAppId", "ApplicationId", "SRPolicyId",
        "SRPolicyName", "SRRuleMatchDetails", "IsManagedDevice", "AppPoolName",
        "UniqueTokenId", "IssuedAtTime", "AppAccessContext", "Attendees",
        "ArtifactsShared", "IsJoinedFromLobby", "JoinTime", "LeaveTime",
        "DeviceInformation", "MeetingDetailId", "ListItemUniqueId",
        "SensitivityLabelId", "UniqueSharingId", "ActorContextId_", "Type",
    ] if c not in _SENTINEL_INTERNAL],
    "AuditLogs": [c for c in [
        "TenantId", "SourceSystem", "TimeGenerated", "ResourceId", "OperationName",
        "OperationVersion", "Category", "ResultType", "ResultSignature",
        "ResultDescription", "DurationMs", "CorrelationId", "Resource", "ResourceGroup",
        "ResourceProvider", "Identity", "Level", "Location", "AdditionalDetails", "Id",
        "InitiatedBy", "LoggedByService", "Result", "ResultReason", "TargetResources",
        "AADTenantId", "ActivityDisplayName", "ActivityDateTime", "AADOperationType",
        "Type",
    ] if c not in _SENTINEL_INTERNAL],
    "AWSCloudTrail": [c for c in [
        "TimeGenerated", "AwsEventId", "EventVersion", "EventSource", "EventTypeName",
        "EventName", "UserIdentityType", "UserIdentityPrincipalid", "UserIdentityArn",
        "UserIdentityAccountId", "UserIdentityInvokedBy", "UserIdentityAccessKeyId",
        "UserIdentityUserName", "SessionMfaAuthenticated", "SessionCreationDate",
        "SessionIssuerType", "SessionIssuerPrincipalId", "SessionIssuerArn",
        "SessionIssuerAccountId", "SessionIssuerUserName", "AWSRegion",
        "SourceIpAddress", "UserAgent", "ErrorCode", "ErrorMessage",
        "RequestParameters", "ResponseElements", "AdditionalEventData", "AwsRequestId",
        "AwsRequestId_", "Resources", "APIVersion", "ReadOnly", "RecipientAccountId",
        "ServiceEventDetails", "SharedEventId", "VpcEndpointId", "ManagementEvent",
        "TenantId", "SourceSystem", "OperationName", "Category", "EC2RoleDelivery",
        "TlsVersion", "CipherSuite", "ClientProvidedHostHeader", "IpProtocol",
        "SourcePort", "DestinationPort", "CidrIp", "UserIdentityUserId",
        "UserIdentityStoreArn", "Type",
    ] if c not in _SENTINEL_INTERNAL],
    "CommonSecurityLog": [c for c in [
        "TenantId", "TimeGenerated", "DeviceVendor", "DeviceProduct", "DeviceVersion",
        "DeviceEventClassID", "Activity", "LogSeverity", "OriginalLogSeverity",
        "AdditionalExtensions", "DeviceAction", "ApplicationProtocol", "EventCount",
        "DestinationDnsDomain", "DestinationServiceName",
        "DestinationTranslatedAddress", "DestinationTranslatedPort",
        "CommunicationDirection", "DeviceDnsDomain", "DeviceExternalID",
        "DeviceFacility", "DeviceInboundInterface", "DeviceNtDomain",
        "DeviceOutboundInterface", "DevicePayloadId", "ProcessName",
        "DeviceTranslatedAddress", "DestinationHostName", "DestinationMACAddress",
        "DestinationNTDomain", "DestinationProcessId", "DestinationUserPrivileges",
        "DestinationProcessName", "DestinationPort", "DestinationIP", "DeviceTimeZone",
        "DestinationUserID", "DestinationUserName", "DeviceAddress", "DeviceName",
        "DeviceMacAddress", "ProcessID", "EndTime", "ExternalID", "ExtID",
        "FileCreateTime", "FileHash", "FileID", "FileModificationTime", "FilePath",
        "FilePermission", "FileType", "FileName", "FileSize", "ReceivedBytes",
        "Message", "OldFileCreateTime", "OldFileHash", "OldFileID",
        "OldFileModificationTime", "OldFileName", "OldFilePath", "OldFilePermission",
        "OldFileSize", "OldFileType", "SentBytes", "EventOutcome", "Protocol", "Reason",
        "RequestURL", "RequestClientApplication", "RequestContext", "RequestCookies",
        "RequestMethod", "ReceiptTime", "SourceHostName", "SourceMACAddress",
        "SourceNTDomain", "SourceDnsDomain", "SourceServiceName",
        "SourceTranslatedAddress", "SourceTranslatedPort", "SourceProcessId",
        "SourceUserPrivileges", "SourceProcessName", "SourcePort", "SourceIP",
        "StartTime", "SourceUserID", "SourceUserName", "EventType",
        "DeviceEventCategory", "DeviceCustomIPv6Address1",
        "DeviceCustomIPv6Address1Label", "DeviceCustomIPv6Address2",
        "DeviceCustomIPv6Address2Label", "DeviceCustomIPv6Address3",
        "DeviceCustomIPv6Address3Label", "DeviceCustomIPv6Address4",
        "DeviceCustomIPv6Address4Label", "DeviceCustomFloatingPoint1",
        "DeviceCustomFloatingPoint1Label", "DeviceCustomFloatingPoint2",
        "DeviceCustomFloatingPoint2Label", "DeviceCustomFloatingPoint3",
        "DeviceCustomFloatingPoint3Label", "DeviceCustomFloatingPoint4",
        "DeviceCustomFloatingPoint4Label", "DeviceCustomNumber1",
        "FieldDeviceCustomNumber1", "DeviceCustomNumber1Label", "DeviceCustomNumber2",
        "FieldDeviceCustomNumber2", "DeviceCustomNumber2Label", "DeviceCustomNumber3",
        "FieldDeviceCustomNumber3", "DeviceCustomNumber3Label", "DeviceCustomString1",
        "DeviceCustomString1Label", "DeviceCustomString2", "DeviceCustomString2Label",
        "DeviceCustomString3", "DeviceCustomString3Label", "DeviceCustomString4",
        "DeviceCustomString4Label", "DeviceCustomString5", "DeviceCustomString5Label",
        "DeviceCustomString6", "DeviceCustomString6Label", "DeviceCustomDate1",
        "DeviceCustomDate1Label", "DeviceCustomDate2", "DeviceCustomDate2Label",
        "FlexDate1", "FlexDate1Label", "FlexNumber1", "FlexNumber1Label", "FlexNumber2",
        "FlexNumber2Label", "FlexString1", "FlexString1Label", "FlexString2",
        "FlexString2Label", "RemoteIP", "RemotePort", "MaliciousIP", "ThreatSeverity",
        "IndicatorThreatType", "ThreatDescription", "ThreatConfidence",
        "ReportReferenceLink", "MaliciousIPLongitude", "MaliciousIPLatitude",
        "MaliciousIPCountry", "Computer", "SourceSystem", "SimplifiedDeviceAction",
        "CollectorHostName", "Type",
    ] if c not in _SENTINEL_INTERNAL],
}
SENTINEL_TABLE_SCHEMA.update(_SENTINEL_EXTRA_TABLES)


def _sentinel_query_url() -> str | None:
    """Build the Log Analytics query URL from env vars. Returns None if not configured.

    Falls back to SHADOW_SENTINEL_* — the Sentinel workspace creds are provisioned
    under those names in Secrets Manager (the SENTINEL_* names were never set, which
    is why every sentinel_run_kql returned 'workspace not configured').
    """
    # TEMPORARY hardcoded fallback so we can test end-to-end while the secret's
    # shadow_sentinel_* values are still empty. These are non-secret Azure resource
    # identifiers (the subscription GUID is already visible in every incident URL).
    # Once the values are in security/uat/deepintel, REVERT this to the env-only form.
    sub = (os.getenv("SENTINEL_SUBSCRIPTION_ID") or os.getenv("SHADOW_SENTINEL_SUBSCRIPTION_ID")
           or "00000000-0000-0000-0000-000000000000")
    rg  = (os.getenv("SENTINEL_RESOURCE_GROUP") or os.getenv("SHADOW_SENTINEL_RESOURCE_GROUP")
           or "acme-siem")
    ws  = (os.getenv("SENTINEL_WORKSPACE_NAME") or os.getenv("SHADOW_SENTINEL_WORKSPACE_NAME")
           or "acme-siem-ws")
    if not all([sub, rg, ws]):
        return None
    return (
        f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/api/query?api-version=2020-08-01"
    )


async def run_sentinel_query(
    kql: str,
    timeout: int = 60,
    iocs: dict | None = None,
    on_query=None,
    autofix: bool = True,
) -> tuple[list[dict], str | None]:
    """Execute one KQL query against the Log Analytics workspace.

    Returns (rows, error_message). error_message is None on success.
    On a syntax error, attempts one Gemini-powered auto-fix and retries.
    """
    query_url = _sentinel_query_url()
    if not query_url:
        _have = [v for v in ("SUBSCRIPTION_ID", "RESOURCE_GROUP", "WORKSPACE_NAME")
                 if os.getenv(f"SENTINEL_{v}") or os.getenv(f"SHADOW_SENTINEL_{v}")]
        return [], ("Sentinel workspace not configured — need SENTINEL_* or SHADOW_SENTINEL_* "
                    f"(SUBSCRIPTION_ID/RESOURCE_GROUP/WORKSPACE_NAME); present: {_have or 'none'}")

    token = await get_management_token()
    if not token:
        return [], "management token acquisition failed"

    async def _execute(query: str) -> tuple[list[dict], str | None]:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=MDE_VERIFY_SSL) as client:
                resp = await client.post(
                    query_url,
                    json={"query": query},
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                )
                if resp.status_code == 400:
                    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                    msg = (body.get("error") or {}).get("message") or resp.text[:200]
                    return [], msg
                if resp.status_code == 403:
                    return [], "permission denied (Log Analytics Reader role required)"
                resp.raise_for_status()
                # Log Analytics returns PascalCase keys
                tables = resp.json().get("Tables") or resp.json().get("tables") or []
                if not tables:
                    return [], None
                t0 = tables[0]
                cols = [c.get("ColumnName") or c.get("name") for c in (t0.get("Columns") or t0.get("columns") or [])]
                rows = t0.get("Rows") or t0.get("rows") or []
                return [dict(zip(cols, row)) for row in rows], None
        except httpx.ReadTimeout:
            return [], f"timed out after {timeout}s"
        except Exception as exc:
            return [], str(exc)[:120]

    rows, err = await _execute(kql)
    if err is None:
        if on_query:
            on_query(kql)
        return rows, None

    if "permission denied" in err or "timed out" in err or not autofix:
        # autofix=False: the caller must not send its query to the (Gemini) fixer — /shadow
        # data never leaves the AWS boundary
        logger.warning("Sentinel query error (no fix attempted): %s", err)
        return [], err

    return await _autofix_loop(kql, err, _execute, "Sentinel", iocs=iocs, on_query=on_query)


# ---------------------------------------------------------------------------
# KQL extraction from Gemini markdown
# ---------------------------------------------------------------------------

_KQL_PATTERN = re.compile(r"```(?:kql|kusto|sql)?\n(.*?)```", re.DOTALL | re.IGNORECASE)

_ALL_KNOWN_TABLES = set(MDE_TABLE_SCHEMA.keys()) | set(SENTINEL_TABLE_SCHEMA.keys())

# Only tables accessible via MDE Advanced Hunting API with client_credentials token.
# Alert/Email/Identity tables require M365 Defender unified RBAC — excluded.
_VALID_MDE_TABLES = set(MDE_TABLE_SCHEMA.keys())

# Union of every valid column name across all known tables.
# Any PascalCase identifier Gemini uses that isn't here is a hallucination.
_ALL_VALID_COLUMNS: frozenset[str] = frozenset(
    col
    for cols in list(MDE_TABLE_SCHEMA.values()) + list(SENTINEL_TABLE_SCHEMA.values())
    for col in cols
)

# PascalCase tokens that appear in KQL but are NOT column names — ActionType values,
# join kind names, bool literals, OS/platform strings, etc.
_KQL_VALUE_TOKENS: frozenset[str] = frozenset([
    "True", "False", "Null",
    "Public", "Private", "Loopback",
    "ConnectionInitiated", "ConnectionFound", "ConnectionAttempted", "ConnectionFailed",
    "InboundInternetScanInspected",
    "FileCreated", "FileModified", "FileDeleted", "FileRenamed",
    "ProcessCreated", "OpenProcessApiCall",
    "LogonSuccess", "LogonFailed", "LogonAttempted",
    "NetworkConnectionFound",
    "RegistryValueSet", "RegistryKeyCreated", "RegistryKeyDeleted",
    "Inner", "LeftOuter", "RightOuter", "FullOuter", "Anti", "InnerUnique",
    "Windows", "Linux",  # macOS has no PascalCase ambiguity
])

# Matches unquoted PascalCase identifiers (group 1 is non-None only for unquoted matches)
_UNQUOTED_PASCAL_RE = re.compile(r'"[^"]*"|\'[^\']*\'|(\b[A-Z][A-Za-z0-9]+\b)')


def _invalid_cols(line: str) -> set[str]:
    """Return PascalCase tokens in line that aren't a known column or KQL value token."""
    tokens = {m.group(1) for m in _UNQUOTED_PASCAL_RE.finditer(line) if m.group(1)}
    return tokens - _ALL_VALID_COLUMNS - _KQL_VALUE_TOKENS


def _sanitize_kql_columns(kql: str) -> str | None:
    """Drop or trim pipe stages that reference columns not in any known schema.

    - ``| project``: removes individual invalid column names from the list.
    - ``| where``: returns None — the whole query is rejected. Dropping a filter WIDENS
      the hunt: a PascalCase `let MaliciousDomains` read as an unknown column removed
      `where RemoteUrl has_any (MaliciousDomains)` and the IOC hunt ran against all
      non-browser traffic (DEMO-115974: 30,372 "hits", zero IOC matches).
    - All other pipe stages (extend, summarize, …): drops the whole line.

    Names declared by `let` in the query are valid. Anything else Gemini invents that
    isn't in MDE_TABLE_SCHEMA or SENTINEL_TABLE_SCHEMA is pruned.
    """
    declared = set(re.findall(r"^\s*let\s+([A-Za-z_]\w*)\s*=", kql, re.MULTILINE))
    out = []
    for line in kql.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            out.append(line)
            continue

        bad = _invalid_cols(stripped) - declared
        if not bad:
            out.append(line)
            continue

        rest = stripped.lstrip("|").strip()
        keyword = rest.split()[0].lower() if rest.split() else ""

        if keyword == "where":
            logger.warning("Rejecting KQL block: `where` references unknown %s — dropping "
                           "the filter would widen the hunt", sorted(bad))
            return None
        if keyword == "project":
            new = line
            for col in bad:
                # remove ", Col" or "Col, " or standalone "Col"
                new = re.sub(rf',\s*\b{re.escape(col)}\b', '', new)
                new = re.sub(rf'\b{re.escape(col)}\b\s*,\s*', '', new)
                new = re.sub(rf'\b{re.escape(col)}\b', '', new)
            # drop if project is now empty
            if not re.search(r'\bproject\b\s*\S', new):
                continue
            out.append(new)
        # all other clauses: drop the line entirely
    return "\n".join(out)


# A `let` statement, including multi-line dynamic([...]) bodies. Non-greedy to the
# first ';' — KQL let bodies used here contain no semicolons.
_LET_RE = re.compile(r"^[ \t]*let\s+([A-Za-z_]\w*)\s*=.*?;", re.DOTALL | re.MULTILINE)


def _split_lets(block: str) -> tuple[dict[str, str], str]:
    """Split a KQL block into its `let` declarations and the remaining body.

    Returns ({name: statement}, body_without_lets).
    """
    lets = {m.group(1): m.group(0).strip() for m in _LET_RE.finditer(block)}
    return lets, _LET_RE.sub("", block)


def _first_table_token(body: str) -> str:
    """First meaningful token of a KQL body — the table name, or "" if none."""
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        return stripped.split()[0]
    return ""


def extract_kql_blocks(text: str) -> list[str]:
    """Extract KQL code blocks from a Gemini markdown response.

    Filters out blocks that are markdown prose, headers, or reference unknown tables.
    Applies column whitelisting to every surviving block.

    `let` declarations are carried forward across blocks. Gemini routinely emits a
    shared preamble of `let ioc_domains = dynamic([...]);` in its OWN fenced block
    and then references those names from later query blocks. Treating each fence
    independently dropped the preamble and left the queries referencing undefined
    variables — MDE 400s, the auto-fixer then invented placeholder literals to make
    them resolve, and the hunt "matched" example.com / 1.1.1.1 (DEMO-113069: 1416
    fabricated hits, zero real IOC matches). Only the declarations a block actually
    references are prepended, so an unused or malformed one can't break a good query.
    """
    blocks = [b.strip() for b in _KQL_PATTERN.findall(text) if b.strip()]
    pending_lets: dict[str, str] = {}
    valid = []
    for b in blocks:
        lets, body = _split_lets(b)
        first_token = _first_table_token(body)

        if first_token not in _ALL_KNOWN_TABLES:
            # Not a runnable query. If it declared lets, keep them for later blocks.
            if lets:
                pending_lets.update(lets)
            continue
        if len(body.strip()) < 20 or "|" not in body:
            continue

        # Carry forward only the declarations this block references and does not
        # already declare itself.
        needed = [stmt for name, stmt in pending_lets.items()
                  if name not in lets and re.search(rf"\b{re.escape(name)}\b", body)]
        if needed:
            logger.info("Prepending %d carried-forward let declaration(s) to %s block",
                        len(needed), first_token)
            b = "\n".join(needed) + "\n" + b
        pending_lets.update(lets)
        clean = _sanitize_kql_columns(b)
        if clean is not None:
            valid.append(clean)
    return valid


# ---------------------------------------------------------------------------
# Local KQL lint — cheap pre-flight checks (no API round-trip)
# ---------------------------------------------------------------------------

def lint_kql(kql: str) -> str | None:
    """Cheap local sanity checks for a KQL query. Returns an actionable error
    string if the query is obviously malformed, else None.

    Catches the common LLM mistakes seen in prod — unbalanced parens/brackets/
    quotes, stray backticks / markdown fences, trailing or empty pipe stages —
    BEFORE the API round-trip, so the caller (agent or auto-fix) gets specific
    feedback instead of an opaque MDE/Sentinel 400.
    """
    if not kql or not kql.strip():
        return "empty query"
    s = kql
    # Stray backticks — KQL has no backticks; these are leftover markdown fences.
    if "`" in s:
        return "remove backticks (`) — they're markdown fences, not valid KQL"
    # Balanced brackets.
    for op, cl, name in (("(", ")", "parentheses"), ("[", "]", "brackets"), ("{", "}", "braces")):
        if s.count(op) != s.count(cl):
            return f"unbalanced {name}: {s.count(op)} '{op}' vs {s.count(cl)} '{cl}' — close them"
    # Balanced double-quotes (ignore escaped \"). Single quotes are skipped to
    # avoid false positives on apostrophes inside string literals.
    dq = len(re.findall(r'(?<!\\)"', s))
    if dq % 2 != 0:
        return f"unbalanced double-quotes ({dq}) — every string literal must be closed"
    # Trailing / empty pipe stages.
    body_lines = [ln for ln in s.splitlines() if ln.strip() and not ln.strip().startswith("//")]
    joined = " ".join(body_lines).strip()
    if joined.endswith("|"):
        return "query ends with a trailing '|' — remove it or complete the operator"
    if re.search(r"\|\s*\|", joined):
        return "empty pipe stage ('| |') — remove the empty operator"
    return None


def preflight_kql(kql: str) -> tuple[str, str | None]:
    """Shared pre-flight for the agent's hunt tools — strip leading comment/blank
    lines, reject empty, and lint (unbalanced parens/quotes/backticks, trailing or
    empty pipe stages). Returns ``(cleaned_kql, error_or_None)``.

    Used by BOTH ``mde_advanced_hunt`` and ``sentinel_run_kql`` so Sentinel-side
    free-written KQL gets the same lexical guardrails MDE already had — closing the
    gap that let a malformed Sentinel query reach the engine unchecked (DEMO-105621).
    """
    cleaned = "\n".join(
        ln for ln in (kql or "").splitlines()
        if ln.strip() and not ln.strip().startswith("//")
    ).strip()
    if not cleaned:
        return "", "empty KQL after stripping comments — provide a query starting with a table name"
    le = lint_kql(cleaned)
    if le:
        return cleaned, f"KQL is malformed — {le}. Rewrite and resubmit."
    return cleaned, None


# ---------------------------------------------------------------------------
# KQL auto-fix via Gemini
# ---------------------------------------------------------------------------

def _gemini_model() -> str:
    """Single source of truth for the Gemini model id (also read by
    agent_tools.kql_generator). Configurable via GEMINI_MODEL; defaults to a
    known-available id. Centralizing this avoids the drift where the fixer and the
    generator ran different (and possibly invalid) model ids and failed silently."""
    return os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


def _gemini_url(model: str | None = None) -> str:
    return f"https://generativelanguage.googleapis.com/v1beta/models/{model or _gemini_model()}:generateContent"


# ---------------------------------------------------------------------------
# Repair grounding — a fixed query must not invent new indicators
# ---------------------------------------------------------------------------

# Dotted literals whose last label is one of these are filenames, not hostnames.
_NON_DOMAIN_TLDS: frozenset[str] = frozenset([
    "exe", "dll", "sys", "py", "sh", "ps1", "bat", "cmd", "vbs", "js", "jar",
    "cfg", "conf", "ini", "yaml", "yml", "json", "xml", "html", "htm", "csv",
    "log", "txt", "md", "dat", "bin", "tmp", "zip", "gz", "tar", "rar", "7z",
    "msi", "scr", "lnk", "so", "dylib", "c", "cpp", "go", "rs", "php", "asp",
])

_STR_LIT_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'')


def _looks_like_indicator(value: str) -> bool:
    """True if a string literal looks like a hostname or IP address."""
    v = (value or "").strip()
    if not v or len(v) > 253:
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        pass
    if not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", v):
        return False
    tld = v.rsplit(".", 1)[1].lower()
    return tld not in _NON_DOMAIN_TLDS and bool(re.fullmatch(r"[A-Za-z]{2,}", tld))


def _grounded_ioc_values(iocs: dict | None) -> set[str]:
    """Every indicator value the repair is allowed to reference, normalized."""
    allowed: set[str] = set()
    for values in (iocs or {}).values():
        for v in (values or []):
            if not isinstance(v, str) or not v.strip():
                continue
            allowed.add(v.strip().lower())
            host = _strip_to_host(v)
            if host:
                allowed.add(host)
    return allowed


def _ungrounded_indicators(kql: str, iocs: dict | None) -> set[str]:
    """Host/IP literals in `kql` that are not in the IOC set and not known-safe.

    The auto-fixer is never given the IOC values, so when it repairs a query that
    referenced an undefined `ioc_domains`, its only way to make the query resolve
    is to invent literals — and it reaches for placeholders (example.com, 1.1.1.1).
    Those execute cleanly and produce thousands of meaningless "hits". Any network
    indicator in a repair that did not come from the advisory is fabricated.

    Known-safe CDN/corporate domains are allowed: repairs legitimately carry the
    exclusion lists (`not(RemoteUrl has_any(safe_cdn_domains))`) as inline literals.
    """
    allowed = _grounded_ioc_values(iocs)
    found: set[str] = set()
    for m in _STR_LIT_RE.finditer(kql):
        lit = (m.group(1) if m.group(1) is not None else m.group(2) or "").strip()
        if not _looks_like_indicator(lit):
            continue
        host = _strip_to_host(lit) or lit.lower()
        if host in allowed or lit.lower() in allowed:
            continue
        if _domain_is_fp(host):
            continue  # CDN/corporate exclusion list, not an indicator
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                continue
        except ValueError:
            pass
        found.add(lit)
    return found


async def _fix_kql_with_gemini(broken_kql: str, error_msg: str, kind: str = "MDE",
                               iocs: dict | None = None) -> str | None:
    """Ask Gemini to fix a KQL syntax error. Returns corrected query or None.

    SOURCE-AWARE: MDE repairs are grounded on MDE_TABLE_SCHEMA + ``Timestamp``;
    Sentinel repairs on SENTINEL_TABLE_SCHEMA + ``TimeGenerated`` and are NEVER
    pushed toward MDE ``Device*`` tables — the Sentinel schema list is
    non-exhaustive (CommonSecurityLog / AWSCloudTrail / OfficeActivity / *_CL, …),
    so we keep the query's table unless it is clearly invalid. Retries on 429/5xx.
    """
    import asyncio
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None

    is_sentinel = kind.lower().startswith("sent")
    schema_map = SENTINEL_TABLE_SCHEMA if is_sentinel else MDE_TABLE_SCHEMA
    time_field = "TimeGenerated" if is_sentinel else "Timestamp"
    first_token = broken_kql.split()[0] if broken_kql.split() else ""
    table_known = first_token in schema_map
    schema_section = (
        f"\nVALID COLUMNS for {first_token}:\n{_schema_hint(first_token)}\n"
        if table_known else ""
    )
    valid_tables = ", ".join(sorted(schema_map))
    if table_known:
        table_rule = "- Keep the same intent and table as the original\n"
    elif is_sentinel:
        table_rule = "- Keep the query's table unless it is clearly invalid; do not invent or swap tables\n"
    else:
        table_rule = (
            f"- The table '{first_token}' does NOT exist — switch to the correct valid MDE table for "
            "the intent (e.g. DeviceProcessEvents for process/command-line activity, "
            "DeviceRegistryEvents or DeviceEvents for services/autoruns)\n"
        )
    engine = "Microsoft Sentinel Log Analytics" if is_sentinel else "Microsoft Defender Advanced Hunting"
    tables_label = ("KNOWN Sentinel tables (not exhaustive — other valid tables exist):"
                    if is_sentinel else "VALID MDE TABLES (use ONLY these):")

    # Ground the repair in the real indicators. Without this the fixer has no way
    # to resolve a dangling `ioc_domains` except to invent literals, and it reaches
    # for placeholders (example.com, 1.1.1.1) that match thousands of benign rows.
    allowed = sorted(_grounded_ioc_values(iocs))
    if allowed:
        ioc_section = (
            "\nINDICATORS from the advisory — the ONLY indicator values you may use:\n"
            + "\n".join(f"  {v}" for v in allowed[:60])
            + "\n"
        )
        ioc_rule = (
            "- If the query references an undefined variable (ioc_domains, ioc_urls, ioc_ipv4, …), "
            "replace it with an inline dynamic([...]) built ONLY from the INDICATORS listed above\n"
            "- NEVER invent indicator values. Do not emit placeholders such as example.com, "
            "test.com, 1.1.1.1, 8.8.8.8, or 127.0.0.1. A repair that hunts a value not in the "
            "INDICATORS list is worse than no query at all\n"
            "- If an undefined variable has no corresponding indicator above, delete that filter "
            "stage rather than substituting a value\n"
        )
    else:
        ioc_section = ""
        ioc_rule = ("- Do NOT introduce any new domain, hostname or IP literal that is not already "
                    "present in the broken query\n")

    prompt = (
        f"Fix this {engine} KQL query that failed with an error.\n\n"
        f"error: {error_msg}\n"
        f"{tables_label} {valid_tables}\n"
        f"{schema_section}"
        f"{ioc_section}\n"
        "Broken query:\n"
        f"{broken_kql}\n\n"
        "Rules:\n"
        "- Return ONLY the corrected KQL, no explanation, no markdown fences\n"
        "- The query must START with a valid table name, not a comment\n"
        f"{table_rule}"
        f"{ioc_rule}"
        "- Use valid columns for the table — remove or replace any column not valid for it\n"
        f"- Add | where {time_field} > ago(7d) if no time filter exists"
    )
    url = _gemini_url()
    # thinkingBudget=0: gemini-2.5-flash's default thinking burns the output-token
    # budget and truncates the repaired KQL — the same failure this fixer exists to fix.
    payload = {"contents": [{"parts": [{"text": prompt}]}],
               "generationConfig": {"temperature": 0.0, "maxOutputTokens": 2048,
                                    "thinkingConfig": {"thinkingBudget": 0}}}
    last = None
    # Retry on 429/5xx so a throttled fixer doesn't read as "auto-fix failed".
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(f"{url}?key={api_key}", json=payload)
            if resp.status_code == 200:
                text = (resp.json().get("candidates", [{}])[0]
                        .get("content", {}).get("parts", [{}])[0].get("text", "")).strip()
                if text.startswith("```"):
                    text = re.sub(r"^```[a-z]*\n?", "", text).rstrip("`").strip()
                return text if text and len(text) > 10 else None
            last = f"HTTP {resp.status_code}"
            if resp.status_code not in (429, 500, 502, 503, 504):
                logger.warning("KQL auto-fix: Gemini %s (model=%s) — not retrying", resp.status_code, _gemini_model())
                return None
        except Exception as exc:
            last = str(exc)[:100]
        if attempt < 2:
            await asyncio.sleep(1.5 * (attempt + 1))
    logger.warning("KQL auto-fix: Gemini failed after retries (last=%s, model=%s)", last, _gemini_model())
    return None


async def _autofix_loop(kql, err, execute, kind: str, attempts: int = 2,
                        iocs: dict | None = None, on_query=None):
    """Gemini auto-fix loop: up to `attempts` fixes, linting each candidate before
    executing so we don't burn an API round-trip on a still-malformed query, and
    feeding both the engine error and the lint error back into the next fix.

    `execute` is the caller's async (query) -> (rows, err|None). Returns the same.
    """
    current_err = str(err)
    candidate = kql
    ungrounded: set[str] = set()
    for i in range(attempts):
        logger.warning("%s KQL auto-fix attempt %d/%d: %s", kind, i + 1, attempts, current_err[:120])
        fixed = await _fix_kql_with_gemini(candidate, current_err, kind, iocs=iocs)
        if not fixed:
            logger.warning("%s KQL auto-fix: Gemini returned nothing (attempt %d)", kind, i + 1)
            break
        candidate = fixed
        lint = lint_kql(fixed)
        if lint:
            # Still malformed — don't execute; feed the lint error into the next fix.
            logger.warning("%s KQL auto-fix attempt %d still lints bad: %s", kind, i + 1, lint)
            current_err = f"{current_err}; lint: {lint}"
            continue
        # Grounding gate: refuse to run a repair that hunts indicators the advisory
        # never mentioned. A fabricated literal executes cleanly and reports
        # confident hits on benign traffic, which is worse than a failed query —
        # a failure falls through to the programmatic IOC fallback.
        if iocs:
            invented = _ungrounded_indicators(fixed, iocs)
            if invented:
                ungrounded |= invented
                logger.warning("%s KQL auto-fix attempt %d invented indicators %s — rejected",
                               kind, i + 1, sorted(invented))
                current_err = (f"{current_err}; the previous fix invented indicator values "
                               f"{sorted(invented)} that are NOT in the advisory — use only the "
                               f"INDICATORS listed, or delete the filter stage")
                continue
        rows, err2 = await execute(fixed)
        if err2 is None:
            logger.info("%s KQL auto-fix succeeded on attempt %d", kind, i + 1)
            if on_query:
                on_query(fixed)
            return rows, None
        current_err = str(err2)
    # Don't call every failure a SYNTAX error. Azure returns the same generic 400
    # ("The request had some invalid properties") for a reference to a column that
    # does not exist, which is a SCHEMA problem, not a grammar one — and the Gemini
    # fixer cannot solve it, because it does not know the table's columns either, so
    # it burns both attempts rewriting a query whose syntax was already fine.
    # DEMO-110712: the agent queried Netskope_Alerts_CL for `dlp_file_s` (no such
    # column; the real ones are dlp_profile_s / dlp_rule_s / dlp_rule_severity_s /
    # dlp_incident_id_s), and the run reported "syntax error", which sent the
    # investigation looking for a malformed query that never existed. Naming the
    # likely cause is what makes the next failure diagnosable.
    # A grounding rejection is not a schema problem — say so, or the next person
    # debugging this goes looking for a column that was never wrong.
    if ungrounded:
        return [], (f"auto-fix rejected after {attempts} attempts: the repair kept inventing "
                    f"indicators not in the advisory ({sorted(ungrounded)}); "
                    f"original error: {str(err)[:100]}")
    _e = current_err.lower()
    _kind = ("query failed — possibly an unknown column/table for this schema"
             if ("invalid properties" in _e or "could not be resolved" in _e
                 or "unknown function" in _e or "failed to resolve" in _e)
             else "query failed")
    return [], (f"{_kind} (auto-fix failed after {attempts} attempts): "
                f"{current_err[:140]}")


# ---------------------------------------------------------------------------
# Run a single KQL query (with auto-fix retries on syntax error)
# ---------------------------------------------------------------------------

async def run_mde_query(
    kql: str,
    token: str,
    timeout: int = 60,
    iocs: dict | None = None,
    on_query=None,
    autofix: bool = True,
) -> tuple[list[dict], str | None]:
    """Execute one KQL query against MDE Advanced Hunting.

    Returns (rows, error_message). error_message is None on success.
    On a 400 syntax error, attempts one Gemini-powered auto-fix and retries.
    """

    async def _execute(query: str) -> tuple[list[dict], str | None]:
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=MDE_VERIFY_SSL) as client:
                resp = await client.post(
                    _HUNTING_URL,
                    json={"Query": query},
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type":  "application/json",
                    },
                )
                if resp.status_code == 400:
                    err = (resp.json().get("error", {})
                           if resp.headers.get("content-type", "").startswith("application/json")
                           else {})
                    msg = err.get("message") or resp.text[:200]
                    return [], msg
                if resp.status_code == 403:
                    return [], "permission denied (AdvancedQuery.Read.All required)"
                resp.raise_for_status()
                return resp.json().get("Results", []), None
        except httpx.ReadTimeout:
            return [], f"timed out after {timeout}s"
        except Exception as exc:
            return [], str(exc)[:120]

    rows, err = await _execute(kql)
    if err is None:
        if on_query:
            on_query(kql)
        return rows, None

    # Non-syntax errors (auth, timeout) — don't bother fixing
    if "permission denied" in err or "timed out" in err:
        logger.warning("MDE query error (no fix attempted): %s", err)
        return [], err

    # Syntax error — ask Gemini to fix and retry once
    if not autofix:
        return [], err
    return await _autofix_loop(kql, err, _execute, "MDE", iocs=iocs, on_query=on_query)


# ---------------------------------------------------------------------------
# False-positive filtering
# ---------------------------------------------------------------------------

def filter_false_positives(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split results into (real_hits, false_positives).

    Decision logic (in priority order):
    1. If any domain field resolves to a non-FP domain → real hit (genuine indicator).
    2. If all non-empty domain fields resolve to FP domains → FP, regardless of IP.
       (This prevents public IPs on known-safe CDNs like amazonaws.com from overriding
        a domain-level FP verdict.)
    3. No domain fields present → fall back to IP check: all-private = FP, any-public = real.
    """
    real: list[dict] = []
    fps:  list[dict] = []

    _DOMAIN_FIELDS = frozenset(["RemoteUrl", "Url", "Domain", "DestinationUrl",
                                  "DnsQuestion", "TargetDomain", "ThreatName"])
    _IP_FIELDS     = frozenset(["RemoteIP", "DestinationIPAddress", "SourceIPAddress",
                                  "LocalIP"])

    for row in rows:
        fp_domain_confirmed = False   # a domain field positively matched a known-safe domain
        non_fp_domain_found = False   # a domain field pointed to something unknown/suspicious

        for field in _DOMAIN_FIELDS:
            val = (row.get(field) or "").strip()
            if not val:
                continue
            if _domain_is_fp(val):
                fp_domain_confirmed = True
            else:
                non_fp_domain_found = True
                break  # one suspicious domain is enough to call it real

        if non_fp_domain_found:
            verdict_fp = False
        elif fp_domain_confirmed:
            # Every non-empty domain field matched a known-safe domain —
            # don't let a public IP override this (e.g. amazonaws.com IPs are public but safe)
            verdict_fp = True
        else:
            # No domain fields at all — fall back to IP check
            verdict_fp = True
            for field in _IP_FIELDS:
                val = (row.get(field) or "").strip()
                if val and not _is_private_ip(val):
                    verdict_fp = False
                    break

        (fps if verdict_fp else real).append(row)

    return real, fps


# ---------------------------------------------------------------------------
# Programmatic fallback IOC queries (syntax-safe, no Gemini dependency)
# ---------------------------------------------------------------------------

_HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


def _classify_ioc_key(key: str) -> str:
    """Map an IOC dict key to a canonical kind.

    Producers disagree on key names: the Cyble service emits "domains"/"ipv4"/
    "sha256", while OTX passes its own type strings straight through
    ("URL", "IPv4", "FileHash-SHA256"). Matching on an exact lowercase literal
    silently dropped most of them, so classify structurally instead.
    Returns one of: domain, ip, md5, sha1, sha256, "" (unrecognized).
    """
    k = re.sub(r"[^a-z0-9]", "", (key or "").lower())
    if "sha256" in k:
        return "sha256"
    if "sha1" in k:
        return "sha1"
    if "md5" in k:
        return "md5"
    if k in ("hash", "hashes", "filehash", "filehashes"):
        return "hash"  # kind decided per-value by length
    if any(t in k for t in ("domain", "url", "hostname", "host", "fqdn")):
        return "domain"
    if k.startswith("ip") or k.endswith("ip") or k.endswith("ips") or "ipaddress" in k:
        return "ip"
    return ""


def build_ioc_fallback_queries(iocs: dict) -> list[str]:
    """Build simple, guaranteed-valid KQL queries directly from an IOC dict.

    Used as a safety net when Gemini-generated KQL has syntax errors or is
    missing entirely — ensures IOC presence in the environment is always
    checked regardless of KQL quality.

    Values are refanged before being embedded: feeds ship "hxxps://evil[.]com",
    which matches nothing in telemetry.
    """
    queries: list[str] = []

    buckets: dict[str, list[str]] = {"domain": [], "ip": [], "md5": [], "sha1": [], "sha256": []}
    for key, values in (iocs or {}).items():
        kind = _classify_ioc_key(key)
        if not kind:
            continue
        for v in (values or []):
            if not (isinstance(v, str) and v.strip()):
                continue
            if kind == "hash":
                resolved = _HASH_LEN.get(len(v.strip()))
                if resolved:
                    buckets[resolved].append(v.strip())
                continue
            buckets[kind].append(v.strip())

    # ── Domains / URLs / hostnames ──────────────────────────────────────────
    domains: list[str] = []
    for v in buckets["domain"]:
        host = _strip_to_host(v)
        if not host:
            continue
        if _domain_is_fp(host):
            continue
        refanged = _refang(v)
        # A real path segment after the host — not the scheme's "//", a bare
        # trailing "/", or a query string ("https://api.github.com/" is the host).
        _rest = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", refanged)
        has_path = bool(_rest.partition("/")[2].split("?", 1)[0].split("#", 1)[0].strip("/"))
        if is_hosting_suffix_only(host) or is_shared_service_host(host):
            # A platform host (workers.dev, api.github.com, ably.net) sweeps
            # every tenant or user of that service rather than the attacker —
            # see _HOSTING_SUFFIXES / _SHARED_SERVICE_DOMAINS. Only the full
            # URL, which names the attacker's repo/bucket/paste, is hunted.
            if has_path:
                domains.append(refanged)
            else:
                logger.warning("Dropping shared platform host from fallback IOC query: %s", v)
            continue
        # Hunt the hostname, and the full URL too when the IOC carried a path —
        # MDE's RemoteUrl holds either form depending on the data source.
        domains.append(host)
        if has_path:
            domains.append(refanged)
    domains = list(dict.fromkeys(domains))[:15]  # dedupe, cap
    if domains:
        quoted = ", ".join(f'"{d}"' for d in domains)
        queries.append(
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(30d)\n"
            f"| where RemoteUrl has_any({quoted})\n"
            "| project Timestamp, DeviceName, RemoteUrl, RemoteIP, ActionType, InitiatingProcessFileName"
        )

    # ── IPs ─────────────────────────────────────────────────────────────────
    ips: list[str] = []
    for v in buckets["ip"]:
        ip = _refang(v).strip("[]")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue  # CIDR ranges and malformed values break `in (...)`
        if not _is_private_ip(ip):
            ips.append(ip)
    ips = list(dict.fromkeys(ips))[:15]
    if ips:
        quoted = ", ".join(f'"{ip}"' for ip in ips)
        queries.append(
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(30d)\n"
            f"| where RemoteIP in ({quoted})\n"
            "| project Timestamp, DeviceName, RemoteIP, RemoteUrl, ActionType, InitiatingProcessFileName"
        )

    # ── File hashes ─────────────────────────────────────────────────────────
    for column, kind in (("SHA256", "sha256"), ("SHA1", "sha1"), ("MD5", "md5")):
        hashes = [h for h in buckets[kind] if len(h) == {"sha256": 64, "sha1": 40, "md5": 32}[kind]
                  and re.fullmatch(r"[0-9a-fA-F]+", h)]
        hashes = list(dict.fromkeys(hashes))[:10]
        if not hashes:
            continue
        quoted = ", ".join(f'"{h}"' for h in hashes)
        queries.append(
            "DeviceFileEvents\n"
            "| where Timestamp > ago(30d)\n"
            f"| where {column} in~ ({quoted})\n"
            f"| project Timestamp, DeviceName, FileName, FolderPath, {column}, InitiatingProcessFileName"
        )

    return queries


# ---------------------------------------------------------------------------
# Run all KQL blocks from a Gemini analysis, return aggregated hits
# ---------------------------------------------------------------------------

_TIME_FILTER_RE = re.compile(r'\b(Timestamp|TimeGenerated)\b.*\bago\b', re.IGNORECASE)


def _extract_kql_reason(kql: str) -> str:
    """Return the first meaningful where-clause condition from a KQL query.

    Skips the time-range filter (Timestamp/TimeGenerated > ago(...)) since that
    is always present and tells the analyst nothing about WHY the row matched.
    Returns a short string suitable for display as a match-reason label.
    """
    for line in kql.splitlines():
        stripped = line.strip().lstrip("|").strip()
        if not stripped.lower().startswith("where "):
            continue
        condition = stripped[6:].strip()  # drop leading "where "
        if _TIME_FILTER_RE.search(condition):
            continue
        return condition[:150]
    return ""


async def hunt_with_kql(
    kql_analysis: str,
    max_queries: int = 6,
    per_query_timeout: int = 60,
    iocs: dict | None = None,
) -> dict[str, Any]:
    """Run all KQL blocks extracted from a Gemini analysis.

    Queries are routed automatically:
    - Device* tables  → MDE Advanced Hunting API
    - Sentinel tables → Log Analytics workspace API

    Returns:
        {
          "real_hits":  list[dict],
          "fp_hits":    list[dict],
          "queries_run": int,
          "queries_with_hits": int,
          "queries_errored": int,
          "error": str | None,
        }
    """
    result: dict[str, Any] = {
        "real_hits": [],
        "fp_hits":   [],
        "queries_run": 0,
        "queries_with_hits": 0,
        "queries_errored": 0,
        "error": None,
    }

    blocks = extract_kql_blocks(kql_analysis)
    if not blocks:
        # Don't return yet — no KQL is precisely when the programmatic IOC
        # fallback below matters. Only give up if there are no IOCs either.
        logger.info("No KQL blocks found in analysis (falling back to IOC queries)")
        if not iocs:
            return result

    mde_token = await get_access_token()

    query_errors: list[str] = []
    for kql in blocks[:max_queries]:
        # Strip let declarations before looking for the table name — a multi-line
        # `let x = dynamic([...])` would otherwise route on a continuation line.
        _, _body = _split_lets(kql)
        first_token = _first_table_token(_body)
        # _CL custom-log tables (e.g. Netskope_Alerts_CL) live in the Sentinel
        # workspace, not MDE — route them to Log Analytics.
        use_sentinel = first_token in SENTINEL_TABLE_SCHEMA or first_token.endswith("_CL")

        result["queries_run"] += 1
        # The query that actually runs may be an auto-fixed rewrite of this one.
        # Report the rewrite, not the original: DEMO-113069's Match Reason column
        # showed `has_any (ioc_domains)` for rows produced by a repaired query
        # that hunted something else entirely, which made the hits unexplainable.
        executed = {"kql": kql}
        _note = lambda q: executed.__setitem__("kql", q)  # noqa: E731

        if use_sentinel:
            rows, err = await run_sentinel_query(kql, timeout=per_query_timeout,
                                                 iocs=iocs, on_query=_note)
        else:
            if not mde_token:
                result["queries_errored"] += 1
                query_errors.append("MDE credentials not configured or token acquisition failed")
                continue
            rows, err = await run_mde_query(kql, mde_token, timeout=per_query_timeout,
                                            iocs=iocs, on_query=_note)

        if err:
            result["queries_errored"] += 1
            query_errors.append(err)
            continue
        if not rows:
            continue
        ran = executed["kql"]
        kql_reason = _extract_kql_reason(ran)
        if ran != kql:
            logger.info("Query %d was auto-fixed; reporting the executed query",
                        result["queries_run"])
        real, fps = filter_false_positives(rows)
        for row in real:
            row["_query_idx"] = result["queries_run"]
            row["_table"] = first_token
            row["_kql_reason"] = kql_reason
            row["_kql_query"] = ran[:500]
        result["real_hits"].extend(real)
        result["fp_hits"].extend(fps)
        if real:
            result["queries_with_hits"] += 1
        await asyncio.sleep(1)

    if query_errors:
        result["error"] = f"{len(query_errors)} quer{'y' if len(query_errors)==1 else 'ies'} failed: {query_errors[0]}"

    # ── Fallback IOC queries (MDE only — programmatically built, always valid) ──
    if iocs and (result["queries_errored"] > 0 or not blocks):
        fallback = build_ioc_fallback_queries(iocs)
        if fallback:
            logger.info("Running %d fallback IOC queries (KQL errors=%d)",
                        len(fallback), result["queries_errored"])
        if fallback and not mde_token:
            mde_token = await get_access_token()
        for kql in fallback:
            if not mde_token:
                break
            result["queries_run"] += 1
            executed = {"kql": kql}
            rows, err = await run_mde_query(
                kql, mde_token, timeout=per_query_timeout, iocs=iocs,
                on_query=lambda q: executed.__setitem__("kql", q),
            )
            if err:
                result["queries_errored"] += 1
                continue
            if not rows:
                continue
            ran = executed["kql"]
            kql_reason = _extract_kql_reason(ran)
            real, fps = filter_false_positives(rows)
            for row in real:
                row["_query_idx"] = result["queries_run"]
                row["_table"] = "ioc-fallback"
                row["_kql_reason"] = kql_reason
                row["_kql_query"] = ran[:500]
            result["real_hits"].extend(real)
            result["fp_hits"].extend(fps)
            if real:
                result["queries_with_hits"] += 1
            await asyncio.sleep(1)

    logger.info(
        "Hunt complete: %d queries (%d errored), %d real hits, %d FP hits",
        result["queries_run"], result["queries_errored"],
        len(result["real_hits"]), len(result["fp_hits"]),
    )
    return result


# ---------------------------------------------------------------------------
# DataAnonymizer — strips tenant identifiers before sending to Gemini
# ---------------------------------------------------------------------------

_BRAND_PATTERNS = [
    re.compile(r"\bacme[a-z0-9\-\.]*\b", re.IGNORECASE),
    re.compile(r"\b[A-Z][a-z]+\.[A-Z][a-z]+\b"),           # FirstName.LastName pattern
    re.compile(r"\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b"),  # private IPs
    re.compile(r"\bDEVICE-[A-Z0-9\-]+\b"),
]

_FIELD_ANONYMIZE = frozenset([
    "DeviceName", "AccountName", "AccountUpn", "InitiatingProcessAccountName",
    "InitiatingProcessAccountUpn", "RemoteIP", "LocalIP",
    "DestinationIPAddress", "SourceIPAddress",
])


class DataAnonymizer:
    """Replace sensitive tenant fields with generic placeholders."""

    _device_map:  dict[str, str]
    _account_map: dict[str, str]
    _ip_map:      dict[str, str]

    def __init__(self) -> None:
        self._device_map  = {}
        self._account_map = {}
        self._ip_map      = {}

    def anonymize_rows(self, rows: list[dict]) -> list[dict]:
        return [self._anonymize_row(r) for r in rows]

    def _anonymize_row(self, row: dict) -> dict:
        out = {}
        for k, v in row.items():
            if not isinstance(v, str):
                out[k] = v
                continue
            if k in ("DeviceName",):
                out[k] = self._replace(v, self._device_map, "DEVICE-{n}")
            elif k in ("AccountName", "AccountUpn",
                       "InitiatingProcessAccountName", "InitiatingProcessAccountUpn"):
                out[k] = self._replace(v, self._account_map, "USER-{n}")
            elif k in ("RemoteIP", "LocalIP", "DestinationIPAddress", "SourceIPAddress"):
                out[k] = self._replace(v, self._ip_map, "IP-{n}")
            else:
                # scrub any remaining acme-like patterns
                s = v
                for pat in _BRAND_PATTERNS:
                    s = pat.sub("[REDACTED]", s)
                out[k] = s
        return out

    @staticmethod
    def _replace(val: str, mapping: dict[str, str], template: str) -> str:
        if val not in mapping:
            mapping[val] = template.format(n=len(mapping) + 1)
        return mapping[val]
