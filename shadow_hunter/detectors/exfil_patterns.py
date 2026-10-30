"""A non-browser process reaching a file-drop, paste, chat-webhook or tunnelling service.

The previous version returned nothing at all on UAT (2026-09-30), for two reasons:
  * It filtered on RemoteIPType == "Public", and macOS ConnectionSuccess rows carry an EMPTY
    RemoteIPType (the same blind spot rare_domains had), so no Mac was ever checked.
  * Its second branch — >500 connections to one public IP over >1h — measures chattiness,
    not data leaving (MDE records no byte counts), and never fired. It is gone; how much
    leaves is Netskope DLP's job.

What is left is what the destination category can say. Over a week of UAT these services
were reached by browsers (a person using WeTransfer or Discord — DLP's territory, excluded
here) and by tinyproxy on the forward proxies relaying ngrok tunnels. A script, CLI tool or
unknown binary talking to one of them is the classic exfil/C2 channel. Interpreters and
transfer tools are high; anything else (proxies, apps) is medium. rare_domains stops
persisting tunnel destinations — this detector owns the category, whatever the fleet rarity.
"""
from __future__ import annotations

from shadow_hunter.detectors.base import Detector, kql_list
from shadow_hunter.detectors.rare_domains import TUNNEL_SUFFIXES

FILE_DROP_SUFFIXES = ("transfer.sh", "file.io", "wetransfer.com", "we.tl", "anonfiles.com", "mega.nz",
                      "mega.io", "mediafire.com", "sendspace.com", "gofile.io", "catbox.moe",
                      "litterbox.catbox.moe", "temp.sh", "0x0.st", "bashupload.com", "oshi.at",
                      "filebin.net", "pixeldrain.com", "anonymfile.com", "tmpfiles.org",
                      "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co",
                      "dpaste.com", "dpaste.org", "termbin.com", "api.telegram.org",
                      "discord.com", "discordapp.com")
SERVICE_SUFFIXES = tuple(dict.fromkeys(FILE_DROP_SUFFIXES + TUNNEL_SUFFIXES))
# Browsers and the chat apps whose own traffic these hosts are; lowercased substrings.
BROWSER_LIKE = ("chrome", "msedge", "edge helper", "firefox", "safari", "webkit", "brave",
                "opera", "arc helper", "vivaldi", "discord", "telegram")
HIGH_PROCS = ("curl", "wget", "powershell", "pwsh", "python", "node", "bash", "sh", "zsh", "dash",
              "osascript", "perl", "ruby", "php", "certutil", "bitsadmin", "rclone", "megacmd",
              "mega-cmd", "cmd", "wscript", "cscript", "mshta", "rundll32", "nc", "ncat", "socat")


def _service(host: str) -> str:
    host = (host or "").lower()
    for s in SERVICE_SUFFIXES:
        if host == s or host.endswith("." + s):
            return s
    return ""


def build_kql(lookback_hours: int = 24, end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    public = ('(RemoteIPType == "Public" or (isempty(RemoteIPType) and isnotempty(RemoteIP) '
              'and not(ipv4_is_private(RemoteIP)) and RemoteIP !startswith "127."))')
    browser = " or ".join(f'Proc has "{b}"' for b in BROWSER_LIKE)
    return f"""
        let windowEnd = {end};
        let services = dynamic([{kql_list(SERVICE_SUFFIXES)}]);
        DeviceNetworkEvents
        | where Timestamp between ((windowEnd - {lookback_hours}h) .. windowEnd)
        | where ActionType == "ConnectionSuccess" and isnotempty(RemoteUrl)
        | where {public}
        | extend Host = tolower(coalesce(tostring(parse_url(RemoteUrl).Host), RemoteUrl))
        | extend Host = iff(isempty(Host), tolower(RemoteUrl), Host)
        | where Host has_any (services)
        | extend Proc = tolower(InitiatingProcessFileName)
        | where not({browser})
        | summarize ConnectionCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
                    Hosts = make_set(Host, 10), RemoteIPs = make_set(RemoteIP, 5),
                    Accounts = make_set(InitiatingProcessAccountName, 3),
                    ParentProcesses = make_set(tolower(InitiatingProcessParentFileName), 3),
                    CommandLines = make_set(substring(InitiatingProcessCommandLine, 0, 200), 2)
            by DeviceId, DeviceName, InitiatingProcessFileName = Proc
        | order by ConnectionCount desc
        | take 200
        """


class ExfilPatternsDetector(Detector):
    name = "exfil_patterns"
    mitre_techniques = ["T1048", "T1567", "T1572", "T1071.001"]
    severity = "high"
    cadence_minutes = 30
    query_name = "exfil_patterns"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        from shadow_hunter.behavior import redact_cmd
        out = []
        for r in rows:
            device = r.get("DeviceName", "")
            proc = (r.get("InitiatingProcessFileName", "") or "").lower()
            hosts = r.get("Hosts") or ([r["RemoteUrl"]] if r.get("RemoteUrl") else [])
            hosts = [h.split("//")[-1].split("/")[0] for h in hosts]  # pre-rework mock rows carry URLs
            services = sorted({_service(h) for h in hosts} - {""}) or hosts[:1]
            base = proc[:-4] if proc.endswith(".exe") else proc
            high = base in HIGH_PROCS or base.startswith(("python", "node", "ruby", "perl"))
            accounts = r.get("Accounts") or ([r["InitiatingProcessAccountName"]]
                                             if r.get("InitiatingProcessAccountName") else [])
            cmds = r.get("CommandLines") or []
            proxy = "proxy" in base
            out.append({
                "detector": self.name,
                "severity": "high" if high else "medium",
                "device_id": r.get("DeviceId") or device,
                "device_name": device,
                "account_name": accounts[0] if accounts else "",
                "indicator": f"{proc}->{','.join(services)}"[:120],
                "summary": (f"'{proc}' on '{device}' reached {', '.join(services)} "
                            f"({r.get('ConnectionCount', 1)} connection(s); {', '.join(hosts[:3])})"
                            + (" — relayed by a proxy: the originating client is in the proxy's own logs"
                               if proxy else "")
                            + (f"; {redact_cmd(str(cmds[0]))[:120]}" if cmds else "")),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
