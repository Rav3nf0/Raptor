"""A document, mail or browser process starting a shell or LOLBin with a command the fleet has not run.

The previous version grouped the whole fleet's parent/child pairs into one high finding per
pair, credited to whichever device came first, and fired every run on the same helpers:
chrome.exe -> cmd.exe for native-messaging hosts (Windows sign-in's BrowserCore, 1Password,
Claude's browser extension) and msedge.exe -> rundll32 dfshim.dll for ClickOnce apps. Over a
week of UAT (2026-09-30) these pairs produced only ten distinct command shapes, all but one
on many devices. It also skipped devices with an MDE alert.

Now each device's child command, normalised for user directories, GUIDs and digits, is
judged by how many devices ran the same parent -> child -> command; only fleet-rare ones are
kept. Office/mail/Teams parents or script-capable children are high; a browser starting cmd,
rundll32 or regsvr32 is medium (that is how native-messaging hosts and ClickOnce start).
macOS Office apps starting a shell or interpreter are covered the same way.
"""
from __future__ import annotations

from shadow_hunter.detectors.base import MASS_HISTORY_DAYS, Detector, kql_fleet, kql_list, kql_shape, mass_summary

WIN_PARENTS = ("outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe",
               "teams.exe", "msteams.exe", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe")
WIN_CHILDREN = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
                "installutil.exe", "regasm.exe")
MAC_PARENTS = ("microsoft word", "microsoft excel", "microsoft powerpoint", "microsoft outlook")
MAC_CHILDREN = ("sh", "bash", "zsh", "osascript", "curl", "python3", "python", "perl", "ruby")
BROWSERS = ("msedge.exe", "chrome.exe", "firefox.exe", "brave.exe")
BROWSER_HELPERS = ("cmd.exe", "rundll32.exe", "regsvr32.exe")


def build_kql(lookback_hours: int = 24, history_days: int = 7, max_fleet_devices: int = 2,
              end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    pc = f"""
            | where (InitiatingProcessFileName in~ ({kql_list(WIN_PARENTS)}) and FileName in~ ({kql_list(WIN_CHILDREN)}))
                 or (InitiatingProcessFileName in~ ({kql_list(MAC_PARENTS)}) and FileName in~ ({kql_list(MAC_CHILDREN)}))
            | extend Shape = strcat(tolower(InitiatingProcessFileName), ">", tolower(FileName), "|",
                                    {kql_shape('ProcessCommandLine')})"""
    fleet = kql_fleet(f"""DeviceProcessEvents
            | where Timestamp between ((windowEnd - {MASS_HISTORY_DAYS}d) .. windowEnd){pc}
            | where Shape in (cand)""", "Shape", max_fleet_devices, history_days)
    return f"""
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let recent = DeviceProcessEvents
            | where Timestamp between (windowStart .. windowEnd){pc};
        let cand = recent | distinct Shape;
        let fleet = {fleet};
        let scored = recent | join kind=inner fleet on Shape;
        union
            (scored | where not(Mass)
             | summarize Count = count(), FirstSeen = min(Timestamp), FleetDevices = take_any(FleetDevices),
                    Accounts = make_set(AccountName, 3),
                    SampleCommandLines = make_set(substring(ProcessCommandLine, 0, 300), 3)
                 by DeviceId, DeviceName, InitiatingProcessFileName, FileName, Shape
             | extend Mass = false),
            // new to the fleet and already widespread: one finding for the push, not one per device
            (scored | where Mass
             | summarize Count = count(), FirstSeen = min(Timestamp), FleetDevices = take_any(FleetDevices),
                    Accounts = make_set(AccountName, 3),
                    SampleCommandLines = make_set(substring(ProcessCommandLine, 0, 300), 3), Devices = make_set(DeviceName, 25)
                 by InitiatingProcessFileName, FileName, Shape
             | extend Mass = true, DeviceId = "", DeviceName = strcat(tostring(FleetDevices), " devices"))
        | order by Mass desc, FleetDevices asc, Count desc
        | take 200
        """


class SuspiciousParentChildDetector(Detector):
    name = "suspicious_parent_child"
    mitre_techniques = ["T1204", "T1059.001", "T1059.005"]
    severity = "high"
    cadence_minutes = 30
    query_name = "suspicious_parent_child"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        from shadow_hunter.behavior import redact_cmd
        out = []
        for r in rows:
            devices = r.get("Devices") or []  # pre-rework mock rows
            device = r.get("DeviceName") or (devices[0] if devices else "")
            parent = (r.get("InitiatingProcessFileName", "") or "?").lower()
            child = (r.get("FileName", "") or "?").lower()
            cmds = r.get("SampleCommandLines") or []
            sample = redact_cmd(str(cmds[0])) if cmds else ""
            accounts = r.get("Accounts") or []
            browser_helper = parent in BROWSERS and child in BROWSER_HELPERS
            out.append({
                "detector": self.name,
                # a push to many machines is high even for a browser helper
                "severity": "high" if r.get("Mass") or not browser_helper else "medium",
                "device_id": r.get("DeviceId") or device,
                "device_name": device,
                "account_name": accounts[0] if accounts else "",
                "indicator": (("mass|" if r.get("Mass") else "") + (r.get("Shape") or f"{parent}>{child}"))[:120],
                "summary": ((f"'{parent}' started '{child}' — " + mass_summary(r) + f": {sample[:140]}")
                            if r.get("Mass") else
                            (f"'{parent}' started '{child}' on '{device}' ({r.get('Count', '?')} time(s)) — "
                             f"command seen on {r.get('FleetDevices', '?')} device(s) fleet-wide: {sample[:140]}")),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
