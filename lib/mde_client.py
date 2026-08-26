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
# are not threat indicators. Add your own owned domains here (or via config).
# ---------------------------------------------------------------------------

_FP_DOMAINS: frozenset[str] = frozenset([
    # Your production infra (own domains should not be escalated as FPs from
    # external threat intel; they surface naturally when compromised)
    "example.com", "example.app", "example.net",
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


def _is_private_ip(ip: str) -> bool:
    """Return True if ip is RFC-1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _domain_is_fp(domain: str) -> bool:
    d = domain.lower().lstrip("www.")
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


def _sentinel_query_url() -> str | None:
    """Build the Log Analytics query URL from env vars. Returns None if not configured.

    Reads SENTINEL_* first, then the SHADOW_SENTINEL_* aliases. If neither is set,
    returns None and Sentinel hunts report 'workspace not configured' (expected in
    a credential-free run).
    """
    sub = os.getenv("SENTINEL_SUBSCRIPTION_ID") or os.getenv("SHADOW_SENTINEL_SUBSCRIPTION_ID")
    rg  = os.getenv("SENTINEL_RESOURCE_GROUP") or os.getenv("SHADOW_SENTINEL_RESOURCE_GROUP")
    ws  = os.getenv("SENTINEL_WORKSPACE_NAME") or os.getenv("SHADOW_SENTINEL_WORKSPACE_NAME")
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
        return rows, None

    if "permission denied" in err or "timed out" in err:
        logger.warning("Sentinel query error (no fix attempted): %s", err)
        return [], err

    return await _autofix_loop(kql, err, _execute, "Sentinel")


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


def _sanitize_kql_columns(kql: str) -> str:
    """Drop or trim pipe stages that reference columns not in any known schema.

    - ``| project``: removes individual invalid column names from the list.
    - All other pipe stages (where, extend, summarize, …): drops the whole line.

    This is a whitelist approach — no enumeration of bad columns needed; anything
    Gemini invents that isn't in MDE_TABLE_SCHEMA or SENTINEL_TABLE_SCHEMA is pruned.
    """
    out = []
    for line in kql.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            out.append(line)
            continue

        bad = _invalid_cols(stripped)
        if not bad:
            out.append(line)
            continue

        rest = stripped.lstrip("|").strip()
        keyword = rest.split()[0].lower() if rest.split() else ""

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


def extract_kql_blocks(text: str) -> list[str]:
    """Extract KQL code blocks from a Gemini markdown response.

    Filters out blocks that are markdown prose, headers, or reference unknown tables.
    Applies column whitelisting to every surviving block.
    """
    blocks = [b.strip() for b in _KQL_PATTERN.findall(text) if b.strip()]
    valid = []
    for b in blocks:
        if len(b) < 20 or "|" not in b:
            continue
        # Skip leading comment and let-binding lines to find the table name
        first_token = ""
        for line in b.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("let "):
                continue
            first_token = stripped.split()[0]
            break
        if first_token not in _ALL_KNOWN_TABLES:
            continue
        valid.append(_sanitize_kql_columns(b))
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


async def _fix_kql_with_gemini(broken_kql: str, error_msg: str, kind: str = "MDE") -> str | None:
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

    prompt = (
        f"Fix this {engine} KQL query that failed with an error.\n\n"
        f"error: {error_msg}\n"
        f"{tables_label} {valid_tables}\n"
        f"{schema_section}\n"
        "Broken query:\n"
        f"{broken_kql}\n\n"
        "Rules:\n"
        "- Return ONLY the corrected KQL, no explanation, no markdown fences\n"
        "- The query must START with a valid table name, not a comment\n"
        f"{table_rule}"
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


async def _autofix_loop(kql, err, execute, kind: str, attempts: int = 2):
    """Gemini auto-fix loop: up to `attempts` fixes, linting each candidate before
    executing so we don't burn an API round-trip on a still-malformed query, and
    feeding both the engine error and the lint error back into the next fix.

    `execute` is the caller's async (query) -> (rows, err|None). Returns the same.
    """
    current_err = str(err)
    candidate = kql
    for i in range(attempts):
        logger.warning("%s KQL auto-fix attempt %d/%d: %s", kind, i + 1, attempts, current_err[:120])
        fixed = await _fix_kql_with_gemini(candidate, current_err, kind)
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
        rows, err2 = await execute(fixed)
        if err2 is None:
            logger.info("%s KQL auto-fix succeeded on attempt %d", kind, i + 1)
            return rows, None
        current_err = str(err2)
    return [], f"syntax error (auto-fix failed after {attempts} attempts): {current_err[:100]}"


# ---------------------------------------------------------------------------
# Run a single KQL query (with auto-fix retries on syntax error)
# ---------------------------------------------------------------------------

async def run_mde_query(
    kql: str,
    token: str,
    timeout: int = 60,
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
        return rows, None

    # Non-syntax errors (auth, timeout) — don't bother fixing
    if "permission denied" in err or "timed out" in err:
        logger.warning("MDE query error (no fix attempted): %s", err)
        return [], err

    # Syntax error — ask Gemini to fix and retry once
    return await _autofix_loop(kql, err, _execute, "MDE")


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

def build_ioc_fallback_queries(iocs: dict) -> list[str]:
    """Build simple, guaranteed-valid KQL queries directly from an IOC dict.

    Used as a safety net when Gemini-generated KQL has syntax errors — ensures
    IOC presence in the environment is always checked regardless of KQL quality.
    """
    queries: list[str] = []

    # Domains / URLs / hostnames
    domains: list[str] = []
    for key in ("domains", "domain", "urls", "url", "hostnames", "hostname"):
        for v in (iocs.get(key) or []):
            if isinstance(v, str) and v and not _domain_is_fp(v):
                domains.append(v)
    domains = list(dict.fromkeys(domains))[:15]  # dedupe, cap
    if domains:
        quoted = ", ".join(f'"{d}"' for d in domains)
        queries.append(
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(30d)\n"
            f"| where RemoteUrl has_any({quoted})\n"
            "| project Timestamp, DeviceName, RemoteUrl, RemoteIP, ActionType, InitiatingProcessFileName"
        )

    # IPs
    ips: list[str] = []
    for key in ("ips", "ip_addresses", "ip", "c2_ips"):
        for v in (iocs.get(key) or []):
            if isinstance(v, str) and v and not _is_private_ip(v):
                ips.append(v)
    ips = list(dict.fromkeys(ips))[:15]
    if ips:
        quoted = ", ".join(f'"{ip}"' for ip in ips)
        queries.append(
            "DeviceNetworkEvents\n"
            "| where Timestamp > ago(30d)\n"
            f"| where RemoteIP in ({quoted})\n"
            "| project Timestamp, DeviceName, RemoteIP, RemoteUrl, ActionType, InitiatingProcessFileName"
        )

    # SHA256 file hashes
    hashes: list[str] = []
    for key in ("sha256", "sha256_hashes", "file_hashes", "hashes"):
        for v in (iocs.get(key) or []):
            if isinstance(v, str) and len(v) == 64:
                hashes.append(v)
    hashes = list(dict.fromkeys(hashes))[:10]
    if hashes:
        quoted = ", ".join(f'"{h}"' for h in hashes)
        queries.append(
            "DeviceFileEvents\n"
            "| where Timestamp > ago(30d)\n"
            f"| where SHA256 in~ ({quoted})\n"
            "| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName"
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
        logger.info("No KQL blocks found in analysis")
        return result

    mde_token = await get_access_token()

    query_errors: list[str] = []
    for kql in blocks[:max_queries]:
        first_token = ""
        for line in kql.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("let "):
                continue
            first_token = stripped.split()[0]
            break
        # _CL custom-log tables (e.g. Netskope_Alerts_CL) live in the Sentinel
        # workspace, not MDE — route them to Log Analytics.
        use_sentinel = first_token in SENTINEL_TABLE_SCHEMA or first_token.endswith("_CL")

        result["queries_run"] += 1
        kql_reason = _extract_kql_reason(kql)

        if use_sentinel:
            rows, err = await run_sentinel_query(kql, timeout=per_query_timeout)
        else:
            if not mde_token:
                result["queries_errored"] += 1
                query_errors.append("MDE credentials not configured or token acquisition failed")
                continue
            rows, err = await run_mde_query(kql, mde_token, timeout=per_query_timeout)

        if err:
            result["queries_errored"] += 1
            query_errors.append(err)
            continue
        if not rows:
            continue
        real, fps = filter_false_positives(rows)
        for row in real:
            row["_query_idx"] = result["queries_run"]
            row["_table"] = first_token
            row["_kql_reason"] = kql_reason
            row["_kql_query"] = kql[:500]
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
            kql_reason = _extract_kql_reason(kql)
            rows, err = await run_mde_query(kql, mde_token, timeout=per_query_timeout)
            if err:
                result["queries_errored"] += 1
                continue
            if not rows:
                continue
            real, fps = filter_false_positives(rows)
            for row in real:
                row["_query_idx"] = result["queries_run"]
                row["_table"] = "ioc-fallback"
                row["_kql_reason"] = kql_reason
                row["_kql_query"] = kql[:500]
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

# Company brand to scrub from displayed telemetry — set SANITIZER_COMPANY_NAME
# (e.g. "acme") to strip your org's name; left unset, only the generic patterns run.
_COMPANY_NAME = os.getenv("SANITIZER_COMPANY_NAME", "").strip().lower()
_COMPANY_PATTERNS = [p for p in [
    re.compile(rf"\b{re.escape(_COMPANY_NAME)}[a-z0-9\-\.]*\b", re.IGNORECASE) if _COMPANY_NAME else None,
    re.compile(r"\b[A-Z][a-z]+\.[A-Z][a-z]+\b"),           # FirstName.LastName pattern
    re.compile(r"\b(?:10|172|192)\.(?:\d{1,3}\.){2}\d{1,3}\b"),  # private IPs
    re.compile(r"\bDEVICE-[A-Z0-9\-]+\b"),
] if p is not None]

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
                # scrub any remaining company/PII-like patterns
                s = v
                for pat in _COMPANY_PATTERNS:
                    s = pat.sub("[REDACTED]", s)
                out[k] = s
        return out

    @staticmethod
    def _replace(val: str, mapping: dict[str, str], template: str) -> str:
        if val not in mapping:
            mapping[val] = template.format(n=len(mapping) + 1)
        return mapping[val]
