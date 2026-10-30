"""Fleet-new, fleet-rare external destinations reached by an unusual process.

The previous version emitted 82,904 of /shadow's 96,597 unreviewed findings (2026-09-30)
and still never flagged INC-2026-0911-KB's beacon. Two reasons, both verified live against
MDE on 2026-09-30:

  * It counted every process, so browsers, Teams, Zoom and OS daemons — whose job is
    talking to arbitrary CDN hosts — produced ~950 "rare" destinations a day.
  * It filtered on RemoteIPType == "Public", and macOS ConnectionSuccess rows carry an
    EMPTY RemoteIPType. Every successful Mac connection was invisible, including
    macbook-pro-51's launchd -> python beacon to 144.172.101.226 / datamnw.com.

A destination now qualifies only when all of these hold: reached by an interpreter/shell/
downloader, OR by a binary name almost no other device runs when launched from persistence
(so a compiled implant is not invisible; it ranks below the interpreter tier until another
signal on the same entity raises it);
seen on at most `max_fleet_devices` devices fleet-wide over `history_days`; first seen in
the fleet within `new_within_hours`; and not one of our own domains. Replayed on the
incident day the two C2 indicators rank first.
"""
from __future__ import annotations

from shadow_hunter.detectors.base import Detector

# Exact process names (lowercased, .exe stripped) plus version-suffixed interpreters.
INTERPRETERS = ("osascript", "bash", "sh", "zsh", "dash", "ksh", "curl", "wget", "powershell",
                "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32")
INTERPRETER_PREFIXES = ("python", "node", "ruby", "perl", "php")
# Parents that mean "running detached / from persistence" rather than from a user's shell.
PERSISTENT_PARENTS = ("launchd", "cron", "crond", "systemd", "services", "taskeng")
# Tunnelling, dynamic-DNS, paste/webhook and out-of-band-testing services: a classic C2 and
# exfil channel, rarely a script's legitimate destination. Flagged in the summary here; the
# /shadow row for reaching one comes from exfil_patterns, which owns the service category.
TUNNEL_SUFFIXES = ("trycloudflare.com", "ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok-free.dev",
                   "ngrok.dev", "serveo.net", "localtunnel.me", "loca.lt", "localhost.run",
                   "pagekite.me", "duckdns.org", "ddns.net", "no-ip.org", "hopto.org", "zapto.org",
                   "dynu.net", "webhook.site", "requestbin.com", "pipedream.net", "interact.sh",
                   "oast.fun", "oast.live", "oast.me", "oast.online", "oast.pro", "oast.site",
                   "burpcollaborator.net", "pastebin.com", "transfer.sh", "file.io", "0x0.st")
# Our own estates — reaching them is not "rare external". Suffix match on the host.
# example.com / upstx.bo are the prod / UAT Active Directory domains; some prod example.com hosts
# resolve to 191.1.1.x, which MDE (correctly) types as Public.
OWN_DOMAINS = ("example.com", "example.com", "corp.example.com", "example.com", "upstx.bo")


def _kql_list(items) -> str:
    return ", ".join(f'"{i}"' for i in items)


def build_kql(lookback_hours: int = 24, history_days: int = 7, max_fleet_devices: int = 2,
              new_within_hours: int = 72, max_binary_devices: int = 3, end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    # Empty RemoteIPType (macOS ConnectionSuccess) falls back to "not private/loopback IPv4".
    public = ('(RemoteIPType == "Public" or (isempty(RemoteIPType) and isnotempty(RemoteIP) '
              'and not(ipv4_is_private(RemoteIP)) and RemoteIP !startswith "127."))')
    # RemoteUrl may be a full URL (http://144.172.101.226/update2.php); compare by host.
    dest = ('iff(isnotempty(RemoteUrl), tolower(coalesce(tostring(parse_url(RemoteUrl).Host), '
            'RemoteUrl)), RemoteIP)')
    proc = 'trim_end(@"\\.exe", tolower(InitiatingProcessFileName))'
    parent = 'trim_end(@"\\.exe", tolower(InitiatingProcessParentFileName))'
    return f"""
        let interpreters = dynamic([{_kql_list(INTERPRETERS)}]);
        let persistentParents = dynamic([{_kql_list(PERSISTENT_PARENTS)}]);
        let ownDomains = dynamic([{_kql_list(OWN_DOMAINS)}]);
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let recentAll = DeviceNetworkEvents
            | where Timestamp between (windowStart .. windowEnd)
            | where ActionType == "ConnectionSuccess" and {public}
            | extend P = {proc}, PP = {parent}
            | extend IsInterp = P in (interpreters) or P matches regex @"^(python|node|ruby|perl|php)",
                     IsDetached = PP in (persistentParents)
            | extend Destination = {dest}
            | where not(Destination has_any (ownDomains));
        // A process NAME almost no other device runs. By name, not SHA256: auto-updating
        // apps (Chrome helpers, VPN clients, TeamViewer) carry a different hash on nearly
        // every device, so hash rarity flagged them all (2026-09-30 replay: 334 highs, C2
        // pushed to rank 304). Name rarity catches a compiled implant; a masquerade under
        // a common name is left to other detectors.
        let candNames = recentAll | where not(IsInterp) | distinct P;
        let rareNames = DeviceNetworkEvents
            | where Timestamp between ((windowEnd - {history_days}d) .. windowEnd)
            | extend P = {proc}
            | where P in (candNames)
            | summarize BinaryDevices = dcount(DeviceId) by P
            | where BinaryDevices <= {max_binary_devices}
            | project P;
        let recent = recentAll
            | extend IsRareBinary = P in (rareNames)
            // A rare binary counts only when run from persistence; a niche app a user
            // opened is not the implant shape.
            | where IsInterp or (IsRareBinary and IsDetached);
        let candUrls = recent | where isnotempty(RemoteUrl) | distinct RemoteUrl;
        let candIps = recent | distinct RemoteIP;
        let fleet = DeviceNetworkEvents
            | where Timestamp between ((windowEnd - {history_days}d) .. windowEnd)
            | where ActionType == "ConnectionSuccess"
            | where RemoteUrl in~ (candUrls) or RemoteIP in (candIps)
            | extend Destination = {dest}
            | summarize FleetDevices = dcount(DeviceId), DaysSeen = dcount(bin(Timestamp, 1d)),
                        FirstSeen = min(Timestamp) by Destination
            | where FleetDevices <= {max_fleet_devices}
            | where FirstSeen >= windowEnd - {new_within_hours}h;
        recent
        | summarize ConnectionCount = count(),
                    Interp = max(toint(IsInterp)), Detached = max(toint(IsDetached)),
                    RareBinary = max(toint(IsRareBinary)),
                    DeviceIds = make_set(DeviceId, 5),
                    Devices = make_set(DeviceName, 5),
                    InitiatingProcesses = make_set(InitiatingProcessFileName, 5),
                    ParentProcesses = make_set(InitiatingProcessParentFileName, 5),
                    SampleCommandLines = make_set(InitiatingProcessCommandLine, 3)
            by Destination
        | join kind=inner fleet on Destination
        | extend Rank = iff(Interp == 1 and Detached == 1, 3, iff(RareBinary == 1, 2, 1))
        | project Destination, FleetDevices, DaysSeen, FirstSeen, ConnectionCount, Interp,
                  Detached, RareBinary, DeviceIds, Devices, InitiatingProcesses, ParentProcesses,
                  SampleCommandLines, Rank
        | order by Rank desc, FleetDevices asc
        | take 500
        """


def _as_list(v):
    return v if isinstance(v, list) else ([v] if v else [])


class RareDomainsDetector(Detector):
    name = "rare_external_domains"
    mitre_techniques = ["T1071.001"]
    severity = "medium"
    cadence_minutes = 60
    query_name = "rare_domains"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def should_persist(self, finding: dict) -> bool:
        # ~200 medium rows a day on UAT (2026-09-30), 262 of 476 from two dev Macs' curl and
        # 57 from two forward proxies — a row each is unreadable. Mediums still reach the
        # behaviour score via behavior.network_counts, where they only matter alongside other
        # unusual behaviour on the same device. Tunnel/paste destinations are persisted by
        # exfil_patterns, so they are not reported twice.
        return finding["severity"] == "high"

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            devices = _as_list(r.get("Devices"))
            device_ids = _as_list(r.get("DeviceIds"))
            procs = _as_list(r.get("InitiatingProcesses"))
            parents = _as_list(r.get("ParentProcesses"))
            days = int(r.get("DaysSeen") or 1)
            interp = bool(int(r.get("Interp") or 0))
            rare_bin = bool(int(r.get("RareBinary") or 0))
            detached = bool(int(r.get("Detached") or 0))
            # Tiers (Rank in the query): an interpreter run from persistence reaching a
            # fleet-new host is high. A fleet-rare binary from persistence is medium — the
            # fleet's long tail of niche apps (CCleaner, Telegram, MEGA…) looks identical on
            # the network, so it needs a second signal on the same entity to rise. An
            # interpreter from a user's shell is a developer as often as not — medium.
            severity = "high" if interp and detached else "medium"
            device_name = devices[0] if devices else ""
            dest = str(r.get("Destination", "")).lower()
            tunnel = any(dest == t or dest.endswith("." + t) for t in TUNNEL_SUFFIXES)
            out.append({
                "detector": self.name,
                "severity": severity,
                "device_id": device_ids[0] if device_ids else device_name,
                "device_name": device_name,
                "account_name": "",
                "indicator": r.get("Destination", ""),
                "summary": (f"'{device_name}' reached {r.get('Destination', '?')} — seen on "
                            f"{r.get('FleetDevices', '?')} device(s) fleet-wide, {days} day(s); "
                            f"{r.get('ConnectionCount', '?')} connection(s) by "
                            f"{', '.join(map(str, procs)) or '?'}"
                            + (f" (parent {', '.join(map(str, parents))})" if parents else "")
                            + (" — binary rare in fleet" if rare_bin else "")
                            + (" — TUNNELLING / out-of-band service" if tunnel else "")),
                "raw": {**r, "tunnel": tunnel},
                "mitre_techniques": self.mitre_techniques,
            })
        return out
