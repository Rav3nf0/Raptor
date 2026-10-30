"""Signed Windows binaries used for their known abuse techniques, with a command the fleet has not run.

The previous patterns matched ordinary use. `regsvr32 /s` is just "silent" and is on nearly
every DLL registration (Lenovo Vantage, Firefox, FileZilla, WPS: 104 distinct commands in a
week of UAT, 2026-09-30). `rundll32 ... http:` was almost always davclnt.dll,DavSetCookie,
the Windows WebDAV client opening an internal file share. Each run also collapsed the whole
fleet into one finding per binary, credited to whichever device came first.

Now only the abuse forms match: certutil download/decode, mshta script or URL, regsvr32
remote scriptlets (Squiblydoo), bitsadmin jobs, wmic remote/process-create, rundll32 script
protocols or URLs (not url.dll opening a web link in the browser, which Slack and CLI logins
do all day), msiexec installing from a URL, mshta on a .hta outside an install directory,
WebDAV to a raw public IP (the NTLM-leak lure; to names — shares, SharePoint, Google — it is
the WebClient's routine). Each device's command, normalised, must also be fleet-rare. WebDAV
is medium; the rest high. ClickOnce (dfshim) is left to suspicious_parent_child.
"""
from __future__ import annotations

from shadow_hunter.detectors.base import MASS_HISTORY_DAYS, Detector, kql_fleet, kql_list, kql_shape, mass_summary

MEDIUM_MARKERS = ("davclnt.dll",)


def build_kql(lookback_hours: int = 24, history_days: int = 7, max_fleet_devices: int = 2,
              end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    lol = f"""
            | where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("urlcache", "-decode", "-decodehex", "-encode", "verifyctl"))
                 or (FileName =~ "mshta.exe" and (ProcessCommandLine has_any ("http", "javascript:", "vbscript:")
                      // a local .hta from anywhere but an install directory (a downloaded one)
                      or (ProcessCommandLine contains ".hta" and not(ProcessCommandLine contains @"\\program files")
                          and not(ProcessCommandLine contains @"\\windows\\"))))
                 or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("/i:http", "/i:ftp", "-i:http", "scrobj.dll"))
                 or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ("/transfer", "/create", "/addfile", "/setnotifycmdline"))
                 or (FileName =~ "wmic.exe" and ProcessCommandLine has_any ("process call create", "/node:"))
                 or (FileName =~ "rundll32.exe" and ProcessCommandLine has_any ("javascript:", "vbscript:", "http:", "https:")
                      // opening a web link in the default browser (Slack, CLI logins) is not abuse;
                      // ClickOnce from a browser or mail client is suspicious_parent_child's
                      and not(ProcessCommandLine matches regex @"(?i)url\\.dll\\s*,\\s*(fileprotocolhandler|openurl)\\s+""?https?://")
                      and not(ProcessCommandLine contains "dfshim.dll"))
                 or (FileName =~ "msiexec.exe" and ProcessCommandLine has_any ("http://", "https://"))
            // The WebDAV client (davclnt.dll,DavSetCookie) runs for every share, SharePoint and
            // web lookup; only one aimed at a raw public IP is the NTLM-leak lure shape.
            | extend DavIP = extract(@"(?i)davsetcookie\\s+(\\d{{1,3}}(?:\\.\\d{{1,3}}){{3}})", 1, ProcessCommandLine)
            | where not(ProcessCommandLine contains "davsetcookie")
                 or (isnotempty(DavIP) and not(ipv4_is_private(DavIP)) and DavIP !startswith "127.")
            | extend Shape = strcat(tolower(FileName), "|", {kql_shape('ProcessCommandLine')})"""
    fleet = kql_fleet(f"""DeviceProcessEvents
            | where Timestamp between ((windowEnd - {MASS_HISTORY_DAYS}d) .. windowEnd){lol}
            | where Shape in (cand)""", "Shape", max_fleet_devices, history_days)
    return f"""
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let recent = DeviceProcessEvents
            | where Timestamp between (windowStart .. windowEnd){lol};
        let cand = recent | distinct Shape;
        let fleet = {fleet};
        let scored = recent | join kind=inner fleet on Shape;
        union
            (scored | where not(Mass)
             | summarize Count = count(), FirstSeen = min(Timestamp), FleetDevices = take_any(FleetDevices),
                    Accounts = make_set(AccountName, 3), Parents = make_set(InitiatingProcessFileName, 3),
                    SampleCommands = make_set(substring(ProcessCommandLine, 0, 300), 3)
                 by DeviceId, DeviceName, FileName, Shape
             | extend Mass = false),
            // new to the fleet and already widespread: one finding for the push, not one per device
            (scored | where Mass
             | summarize Count = count(), FirstSeen = min(Timestamp), FleetDevices = take_any(FleetDevices),
                    Accounts = make_set(AccountName, 3), Parents = make_set(InitiatingProcessFileName, 3),
                    SampleCommands = make_set(substring(ProcessCommandLine, 0, 300), 3), Devices = make_set(DeviceName, 25)
                 by FileName, Shape
             | extend Mass = true, DeviceId = "", DeviceName = strcat(tostring(FleetDevices), " devices"))
        | order by Mass desc, FleetDevices asc, Count desc
        | take 200
        """


class LOLBinAbuseDetector(Detector):
    name = "lolbin_abuse"
    mitre_techniques = ["T1218", "T1218.001", "T1218.005", "T1218.007", "T1218.010", "T1218.011",
                        "T1105", "T1197"]
    severity = "high"
    cadence_minutes = 60
    query_name = "lolbin_abuse"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        from shadow_hunter.behavior import redact_cmd
        out = []
        for r in rows:
            devices = r.get("Devices") or []  # pre-rework mock rows
            device = r.get("DeviceName") or (devices[0] if devices else "")
            binary = (r.get("FileName", "") or "?").lower()
            cmds = r.get("SampleCommands") or []
            sample = redact_cmd(str(cmds[0])) if cmds else ""
            parents = r.get("Parents") or []
            accounts = r.get("Accounts") or []
            medium = any(m in sample.lower() for m in MEDIUM_MARKERS)
            out.append({
                "detector": self.name,
                "severity": "medium" if medium and not r.get("Mass") else "high",
                "device_id": r.get("DeviceId") or device,
                "device_name": device,
                "account_name": accounts[0] if accounts else "",
                "indicator": (("mass|" if r.get("Mass") else "") + (r.get("Shape") or f"{binary}|{sample}"))[:120],
                "summary": (f"'{binary}' used as a proxy/downloader"
                            + ("" if r.get("Mass") else f" on '{device}'")
                            + (f" (parent: {', '.join(parents)})" if parents else "")
                            + (" — " + mass_summary(r) if r.get("Mass") else
                               f" — command seen on {r.get('FleetDevices', '?')} device(s) fleet-wide")
                            + f": {sample[:140]}"),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
