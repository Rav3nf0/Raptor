"""Detectors that need the Sentinel workspace (AWSCloudTrail, SigninLogs), not only MDE.

Both came out of INC-2026-0911-KB: the endpoint score only flagged macbook-pro-51 on Sep 10,
because its MDE sensor was silent Sep 2-9 — the week an attacker replayed the user's AWS
session from elsewhere (Sep 7). Measured on UAT's Sentinel data, 2026-09-30.

cloud_session_split — one AWS session credential used from two places. A session key (ASIA…)
lives on one machine. The same human SSO session calling AWS within ten minutes from a
network that person never used in the previous 14 days AND either from a different OS than
the other place, or from 5+ addresses in that new network (a rotating proxy), is a copied
credential. Networks alone are not enough: Indian mobile carriers move users across /16s all
day, and browser traffic flips between Netskope egress and home ISPs. Replayed: incident week
(Sep 2-9) 1 key — the stolen one, Windows CLI from 27 rotating IPs next to the user's Mac;
a normal week (Sep 20-27) 0.

edr_silent_active — a device the EDR has not heard from for over a day, while the device
itself is demonstrably up: it signed in to Entra as itself, or its user's AWS CLI/SDK is
calling from the device's own public IP — at least 6 hours earlier, so it is not MDE's normal
start-up delay after a weekend. Replayed at five times: 0-5 devices, and at Sep 7 18:00 UTC
macbook-pro-51 (24 CLI calls from its own IP five days into its silence). CLI evidence is
high (cloud credentials in use on a machine nothing is watching); Entra-only is medium (the
sensor is broken or removed — a coverage gap until someone looks).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from shadow_hunter.detectors.base import Detector, mask_ids

HUMAN_CLIENTS = ("aws-cli", "Boto3", "botocore", "aws-sdk", "Terraform")


def _human_calls(t0: str, t1: str) -> str:
    """AWSCloudTrail calls made with a person's SSO session from outside AWS, by a real client."""
    return f"""AWSCloudTrail
     | where TimeGenerated between ({t0} .. {t1})
     | where UserIdentityType == "AssumedRole" and UserIdentityArn contains "@"
     | where isnotempty(UserIdentityAccessKeyId) and isnotempty(SourceIpAddress)
     | where not(SourceIpAddress endswith ".amazonaws.com" or SourceIpAddress == "AWS Internal")
     | where not(ipv4_is_private(SourceIpAddress))
     | extend Client = case(UserAgent has "aws-cli", "cli", UserAgent has_any ("Boto3", "botocore"), "boto",
                            UserAgent has "Mozilla", "browser", UserAgent has "aws-sdk", "sdk",
                            UserAgent has "Terraform", "terraform", "")
     | where isnotempty(Client)
     | extend User = tostring(split(UserIdentityArn, "/")[-1]),
              Net = iff(SourceIpAddress contains ":", strcat_array(array_slice(split(SourceIpAddress, ":"), 0, 2), ":"),
                        strcat_array(array_slice(split(SourceIpAddress, "."), 0, 1), ".")),
              OS = case(UserAgent has "Windows", "windows", UserAgent has_any ("macos", "Macintosh", "darwin"), "mac",
                        UserAgent has "Linux", "linux", "other")"""


def build_split_kql(lookback_hours: int = 24, history_days: int = 14, min_rotation_ips: int = 5,
                    end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    return f"""
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let calls = {_human_calls("windowStart", "windowEnd")};
        // networks each person used before the window
        let hist = {_human_calls(f"windowStart - {history_days}d", "windowStart")} | distinct User, Net;
        let cand = calls
            | summarize Nets = make_set(Net, 10), OSes = make_set_if(OS, OS != "other", 4)
                by Key = UserIdentityAccessKeyId, User, Bin = bin(TimeGenerated, 10m)
            | where array_length(Nets) >= 2;
        let newNets = cand | mv-expand Net = Nets to typeof(string) | join kind=leftanti hist on User, Net
            | distinct Key, Bin, Net;
        let newNetIPs = calls | join kind=inner newNets on $left.UserIdentityAccessKeyId == $right.Key, Net
            | summarize NewNetIPs = dcount(SourceIpAddress), NewNetAgents = make_set(substring(UserAgent, 0, 80), 3)
                by Key = UserIdentityAccessKeyId;
        let hits = cand | join kind=inner (newNets | summarize NewNets = make_set(Net, 5) by Key, Bin) on Key, Bin
            | summarize OSDiffer = max(array_length(OSes)) >= 2, OSes = make_set(OSes, 4), NewNets = make_set(NewNets, 5),
                        FirstBin = min(Bin) by Key, User
            | join kind=leftouter newNetIPs on Key
            | where OSDiffer or NewNetIPs >= {min_rotation_ips};
        // what the key did in the window, wherever it was used from
        calls
        | join kind=inner (hits | project Key, User, OSDiffer, OSes, NewNets, NewNetIPs, NewNetAgents, FirstBin)
            on $left.UserIdentityAccessKeyId == $right.Key
        | summarize Calls = count(), Errors = countif(isnotempty(ErrorCode)), First = min(TimeGenerated), Last = max(TimeGenerated),
                    Actions = make_set(strcat(EventName, iff(isnotempty(ErrorCode), strcat(" (", ErrorCode, ")"), "")), 25),
                    Roles = make_set(SessionIssuerUserName, 4), Accounts = make_set(RecipientAccountId, 4),
                    AllIPs = dcount(SourceIpAddress)
            by Key, User, OSDiffer, OSes = tostring(OSes), NewNets = tostring(NewNets), NewNetIPs,
               NewNetAgents = tostring(NewNetAgents), FirstBin
        | take 50
        """


class CloudSessionSplitDetector(Detector):
    name = "cloud_session_split"
    mitre_techniques = ["T1550.001", "T1078.004", "T1528"]
    severity = "high"
    cadence_minutes = 180
    query_name = "cloud_session_split"

    def kql(self, lookback_hours: int) -> str:
        return build_split_kql(lookback_hours=lookback_hours)

    async def fetch(self, defender, lookback_hours: int = 24) -> list[dict]:
        from shadow_hunter.clients import MockDefenderClient, SentinelLogsClient
        if isinstance(defender, MockDefenderClient):
            return await defender.hunt(self.query_name)
        return await SentinelLogsClient().query(self.kql(lookback_hours))

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            r = mask_ids(dict(r))
            key = str(r.get("Key") or "")
            key_short = f"{key[:4]}…{key[-4:]}" if len(key) > 8 else key
            actions = _as_list(r.get("Actions"))
            why = ("a different OS" if _truthy(r.get("OSDiffer")) else "") + \
                  (" and " if _truthy(r.get("OSDiffer")) and int(r.get("NewNetIPs") or 0) >= 5 else "") + \
                  (f"{r.get('NewNetIPs')} rotating addresses" if int(r.get("NewNetIPs") or 0) >= 5 else "")
            out.append({
                "detector": self.name,
                "severity": self.severity,
                "device_id": "",
                "device_name": "",
                "account_name": str(r.get("User") or ""),
                "indicator": f"{r.get('User')}|{key_short}",
                "summary": (f"AWS session {key_short} of '{r.get('User')}' was used within minutes from a network "
                            f"this person never used ({', '.join(_as_list(r.get('NewNets')))}) — {why or 'split use'}. "
                            f"{r.get('Calls')} calls, {r.get('Errors')} denied/failed, roles "
                            f"{', '.join(_as_list(r.get('Roles')))}: {', '.join(actions[:8])}"
                            + (" …" if len(actions) > 8 else "")),
                "raw": {**r, "Key": key_short},
                "mitre_techniques": self.mitre_techniques,
            })
        return out


# ── EDR silent while the device is up ──────────────────────────────────────────────────

def build_silent_mde_kql(end: str = "now()", days: int = 8) -> str:
    # Last-seen from every DeviceInfo row: its partial rows have empty OSPlatform and
    # LoggedOnUsers, and filtering those first made healthy devices look silent. By hostname,
    # not DeviceId: a re-onboarded machine leaves an old DeviceId that really is silent.
    return f"""
        DeviceInfo | where Timestamp between ({end} - {days}d .. {end})
        | extend Host = tostring(split(tolower(DeviceName), ".")[0])
        | summarize Last = max(Timestamp), PublicIPs = make_set_if(PublicIP, isnotempty(PublicIP), 8),
                    OS = take_anyif(OSPlatform, isnotempty(OSPlatform)), DeviceId = take_any(DeviceId),
                    UsersRaw = make_set_if(LoggedOnUsers, isnotempty(LoggedOnUsers) and LoggedOnUsers != "[]", 5)
            by Host
        | where OS in~ ("macOS", "Windows10", "Windows11")
        """


def build_silent_activity_kql(end: str = "now()", lookback_hours: int = 24) -> str:
    return f"""
        let t1 = {end}; let t0 = t1 - {lookback_hours}h;
        union
          (AWSCloudTrail | where TimeGenerated between (t0 .. t1)
           | where UserIdentityType == "AssumedRole" and UserIdentityArn contains "@"
           | where UserAgent has_any ("aws-cli", "Boto3", "botocore", "aws-sdk", "Terraform")
           | extend Who = tostring(split(UserIdentityArn, "/")[-1]), Src = "cloudtrail", Dev = "", Ip = SourceIpAddress),
          (SigninLogs | where TimeGenerated between (t0 .. t1) | where ResultType == "0" or ResultType == 0
           | extend Who = UserPrincipalName, Src = "signin", Dev = tolower(tostring(DeviceDetail.displayName)), Ip = IPAddress)
        | summarize Calls = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Who, Src, Dev, Ip
        """


def _norm_user(u: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (u or "").lower().split("@")[0])


def _host(n: str) -> str:
    return (n or "").lower().split(".")[0]


def _ts(v) -> datetime:
    return datetime.fromisoformat(str(v)[:19] + "+00:00")


def _as_list(v) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v.startswith("["):
        try:
            return json.loads(v)
        except ValueError:
            return [v]
    return [v] if v else []


def _truthy(v) -> bool:
    return v is True or v == 1 or str(v).lower() == "true"


def _users(raw_sets) -> set[str]:
    names = set()
    for raw in _as_list(raw_sets):
        try:
            for u in (json.loads(raw) if isinstance(raw, str) else raw) or []:
                if u.get("UserName"):
                    names.add(_norm_user(u["UserName"]))
        except (ValueError, AttributeError, TypeError):
            continue
    return names


AFTER_SILENCE_H = 1
MIN_SIGNINS = 2
MIN_SIGNIN_SPAN_H = 1


def match_silent(devices: list[dict], activity: list[dict], now: datetime,
                 silent_hours: int = 48, min_up_hours: int = 6) -> list[dict]:
    """Pure join: devices silent for `silent_hours` (48: idle Windows laptops can go ~a day
    between DeviceInfo reports — 24 h gave 12 in four days on UAT, 9 of them 24-27 h) that are
    demonstrably up — Entra sign-in
    as the device, or the user's AWS CLI/SDK from the device's own public IP — with that
    evidence at least `min_up_hours` old and starting over AFTER_SILENCE_H after the last report.
    Entra alone needs MIN_SIGNINS spread over MIN_SIGNIN_SPAN_H: a single sign-in is a laptop
    waking from standby (holiday-weekend replay at 2026-10-03 18:00: 2 findings -> 0)."""
    cutoff = now - timedelta(hours=min_up_hours)
    by_dev: dict[str, list[dict]] = {}
    by_user_ip: dict[tuple, list[dict]] = {}
    for a in activity:
        if _ts(a["First"]) > cutoff:
            continue
        if a["Src"] == "signin" and a.get("Dev"):
            by_dev.setdefault(_host(a["Dev"]), []).append(a)
        if a["Src"] == "cloudtrail":
            by_user_ip.setdefault((_norm_user(a["Who"]), a["Ip"]), []).append(a)
    out = []
    for d in devices:
        last = _ts(d["Last"])
        if (now - last).total_seconds() <= silent_hours * 3600:
            continue
        host = _host(d.get("Host") or d.get("DeviceName"))
        # Evidence only counts once the sensor should have spoken: a sign-in at shutdown, minutes
        # after the last report, says nothing about the silence that followed.
        after = last + timedelta(hours=AFTER_SILENCE_H)
        entra = [a for a in by_dev.get(host, []) if _ts(a["First"]) > after]
        cli = [a for u in _users(d.get("UsersRaw")) for ip in _as_list(d.get("PublicIPs"))
               for a in by_user_ip.get((u, ip), []) if _ts(a["First"]) > after]
        # One Entra sign-in is a laptop waking from standby to refresh its token (9 of 12
        # medium findings over the 2026-10-02 holiday weekend, all reporting again by Oct 5).
        # Use means repeated sign-ins over at least an hour.
        if entra and not cli:
            span = max(_ts(a["Last"]) for a in entra) - min(_ts(a["First"]) for a in entra)
            if sum(a["Calls"] for a in entra) < MIN_SIGNINS or span < timedelta(hours=MIN_SIGNIN_SPAN_H):
                entra = []
        if not entra and not cli:
            continue
        out.append({"Host": host, "DeviceId": d.get("DeviceId", ""), "OS": d.get("OS", ""),
                    "LastTelemetry": str(d["Last"])[:19] + "Z", "SilentHours": round((now - last).total_seconds() / 3600),
                    "EntraSignins": sum(a["Calls"] for a in entra),
                    "EntraUsers": sorted({a.get("Who", "") for a in entra})[:3],
                    "CliCalls": sum(a["Calls"] for a in cli),
                    "CliUsers": sorted({a["Who"] for a in cli})[:3],
                    "CliFrom": sorted({a["Ip"] for a in cli})[:3],
                    "FirstEvidence": min(str(a["First"])[:19] for a in entra + cli) + "Z"})
    return out


class EdrSilentActiveDetector(Detector):
    name = "edr_silent_active"
    mitre_techniques = ["T1562.001", "T1562.006"]
    severity = "medium"
    cadence_minutes = 360
    query_name = "edr_silent_active"

    def kql(self, lookback_hours: int) -> str:
        return build_silent_mde_kql()

    async def fetch(self, defender, lookback_hours: int = 24) -> list[dict]:
        from shadow_hunter.clients import MockDefenderClient, SentinelLogsClient
        if isinstance(defender, MockDefenderClient):
            return await defender.hunt(self.query_name)
        devices = await defender.hunt(self.query_name, kql=build_silent_mde_kql())
        activity = await SentinelLogsClient().query(build_silent_activity_kql(lookback_hours=lookback_hours))
        return match_silent(devices, activity, datetime.now(timezone.utc))

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            r = mask_ids(dict(r))
            cli = int(r.get("CliCalls") or 0)
            host = r.get("Host", "")
            evidence = []
            if cli:
                evidence.append(f"{cli} AWS CLI/SDK call(s) by {', '.join(r.get('CliUsers') or [])} from its own IP "
                                f"{', '.join(r.get('CliFrom') or [])}")
            if int(r.get("EntraSignins") or 0):
                evidence.append(f"{r['EntraSignins']} Entra sign-in(s) as this device")
            out.append({
                "detector": self.name,
                # cloud credentials in use on a machine nothing is watching vs a broken sensor
                "severity": "high" if cli else "medium",
                "device_id": r.get("DeviceId") or host,
                "device_name": host,
                "account_name": ", ".join(r.get("CliUsers") or []),
                # one finding per silence episode, not one per device forever
                "indicator": f"{host}@{str(r.get('LastTelemetry', ''))[:10]}",
                "summary": (f"'{host}' has sent no EDR telemetry for {r.get('SilentHours')}h (last "
                            f"{r.get('LastTelemetry')}) but is up: " + "; ".join(evidence)),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
