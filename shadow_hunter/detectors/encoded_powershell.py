"""Encoded / obfuscated PowerShell whose decoded content almost no other device runs.

The previous version flagged every PowerShell command line containing -enc, IEX, [Convert]::
and the like, as high: 13 findings in a day on UAT (2026-09-30), every one the Azure Arc
Guest Configuration agent (gc_worker.exe, SYSTEM) — which runs the same -encodedCommand on 42
servers, 2,663 times a week, and it decodes to `[Environment]::OSVersion.Version`. It also
skipped devices that already had an MDE alert, which hides an attacker on any device that
tripped something else.

The payload is now decoded in KQL (base64 of UTF-16LE) and judged by how many devices ran the
same decoded content, normalised for user directories, GUIDs and digits, with the parent
process. Fleet-standard automation drops out; a payload new to the fleet stays — including one
launched under a trusted parent's name. Download/execute content, or a document/browser/script
host as the parent, is high.
"""
from __future__ import annotations

import re

from shadow_hunter.detectors.base import MASS_HISTORY_DAYS, Detector, kql_fleet, kql_list, kql_shape, mass_summary

MARKERS = ("-enc", "-encodedcommand", "-e ", "-ec ", "FromBase64String", "IEX", "Invoke-Expression",
           "[Convert]::", "IO.MemoryStream", "IO.Compression", "Net.WebClient", "DownloadString",
           "DownloadFile")
# Content that fetches or executes something, in the decoded payload or the command line.
DOWNLOAD_EXEC = ("iex", "invoke-expression", "downloadstring", "downloadfile", "downloaddata",
                 "net.webclient", "invoke-webrequest", "iwr ", "invoke-restmethod", "irm ",
                 "start-bitstransfer", "frombase64string", "reflection.assembly", "virtualalloc",
                 "-bxor", "http://", "https://")
AGENT_RISKY_RE = "|".join(re.escape(m.strip()) for m in DOWNLOAD_EXEC if m != "frombase64string")
CLAUDE_CODE_LAUNCHER_RE = (r'^"?powershell\.exe"?\s+-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command '
                           r'"\$__claudeCodeScript = \$env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT; '
                           r'\$env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT = \$null; Invoke-Expression -Command '
                           r'\$__claudeCodeScript"\s*$')
RISKY_PARENTS = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
                 "msedge.exe", "chrome.exe", "firefox.exe", "wscript.exe", "cscript.exe",
                 "mshta.exe", "wmiprvse.exe", "rundll32.exe", "regsvr32.exe")


def build_kql(lookback_hours: int = 24, history_days: int = 7, max_fleet_devices: int = 2,
              end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    ps = f"""
            | where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
            | where ProcessCommandLine has_any ({kql_list(MARKERS)})
            | extend Payload = extract(@"(?i)\\s-e[a-z]*\\s+([A-Za-z0-9+/=]{{16,}})", 1, ProcessCommandLine)
            // MDE truncates long command lines (~31k chars) mid-base64, and a payload that is not
            // whole 4-char blocks decodes to nothing: trim to whole blocks first.
            | extend Payload = substring(Payload, 0, strlen(Payload) - strlen(Payload) % 4)
            | extend Decoded = iff(isempty(Payload), "", replace_string(base64_decode_tostring(Payload), "\\u0000", ""))
            // AI agents encode every command they run, so each one is "new to the fleet" (Claude
            // desktop on u145dmorioprwl1, 2026-10-05: 10 findings of pip list / file listings).
            // Claude's wrapper carries the real command as a second base64 layer: judge that,
            // and keep it only when it downloads or executes something.
            | extend Inner = extract(@"\\$EncodedCommand\\s*=\\s*'([A-Za-z0-9+/=]{{16,}})", 1, Decoded)
            | extend Inner = substring(Inner, 0, strlen(Inner) - strlen(Inner) % 4)
            | extend InnerDecoded = iff(isempty(Inner), "", base64_decode_tostring(Inner))
            | extend AgentWrapped = isnotempty(InnerDecoded) and InitiatingProcessFileName =~ "claude.exe"
            | extend Decoded = iff(AgentWrapped, InnerDecoded, Decoded)
            | where not(AgentWrapped and not(Decoded matches regex @"(?i){AGENT_RISKY_RE}"))
            // Claude Code's Windows shell launcher: a fixed command line that runs a script from an
            // environment variable, so there is nothing to judge here. The commands it runs
            // appear as their own processes (behaviour lineages). Exact form only.
            | where not(ProcessCommandLine matches regex @'{CLAUDE_CODE_LAUNCHER_RE}')
            | extend Shape = strcat(tolower(InitiatingProcessFileName), "|",
                                    {kql_shape('iff(isnotempty(Decoded), Decoded, ProcessCommandLine)')})"""
    fleet = kql_fleet(f"""DeviceProcessEvents
            | where Timestamp between ((windowEnd - {MASS_HISTORY_DAYS}d) .. windowEnd){ps}
            | where Shape in (cand)""", "Shape", max_fleet_devices, history_days)
    return f"""
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let recent = DeviceProcessEvents
            | where Timestamp between (windowStart .. windowEnd){ps};
        let cand = recent | distinct Shape;
        let fleet = {fleet};
        let scored = recent | join kind=inner fleet on Shape;
        union
            (scored | where not(Mass)
             | summarize Count = count(), FirstSeen = min(Timestamp), FleetDevices = take_any(FleetDevices),
                         Accounts = make_set(AccountName, 3),
                         InitiatingProcessFileName = take_any(InitiatingProcessFileName),
                         ParentCommandLine = take_any(substring(InitiatingProcessCommandLine, 0, 200)),
                         ProcessCommandLine = take_any(substring(ProcessCommandLine, 0, 400)),
                         Decoded = take_any(substring(Decoded, 0, 400))
                 by DeviceId, DeviceName, Shape
             | extend Mass = false),
            // new to the fleet and already widespread: one finding for the push, not one per device
            (scored | where Mass
             | summarize Count = count(), FirstSeen = min(Timestamp), FleetDevices = take_any(FleetDevices),
                         Accounts = make_set(AccountName, 3), Devices = make_set(DeviceName, 25),
                         InitiatingProcessFileName = take_any(InitiatingProcessFileName),
                         ParentCommandLine = take_any(substring(InitiatingProcessCommandLine, 0, 200)),
                         ProcessCommandLine = take_any(substring(ProcessCommandLine, 0, 400)),
                         Decoded = take_any(substring(Decoded, 0, 400))
                 by Shape
             | extend Mass = true, DeviceId = "", DeviceName = strcat(tostring(FleetDevices), " devices"))
        | order by Mass desc, FleetDevices asc, Count desc
        | take 200
        """


class EncodedPowerShellDetector(Detector):
    name = "encoded_powershell"
    mitre_techniques = ["T1059.001", "T1027"]
    severity = "medium"
    cadence_minutes = 30
    query_name = "encoded_powershell"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        from shadow_hunter.behavior import redact_cmd
        out = []
        for r in rows:
            device = r.get("DeviceName", "")
            accounts = r.get("Accounts") or r.get("AccountName") or []
            account = accounts[0] if isinstance(accounts, list) and accounts else str(accounts or "")
            cmdline = r.get("ProcessCommandLine", "") or ""
            decoded = r.get("Decoded", "") or ""
            parent = (r.get("InitiatingProcessFileName", "") or "").lower()
            content = (decoded or cmdline).lower()
            # A new script pushed to many machines at once is high whatever it contains.
            risky = any(m in content for m in DOWNLOAD_EXEC) or parent in RISKY_PARENTS or bool(r.get("Mass"))
            shown = redact_cmd(re.sub(r"\s+", " ", decoded or cmdline).strip())
            out.append({
                "detector": self.name,
                "severity": "high" if risky else "medium",
                "device_id": r.get("DeviceId") or device,
                "device_name": device,
                "account_name": account,
                "indicator": (("mass|" if r.get("Mass") else "") + (r.get("Shape") or f"{parent}|{cmdline}"))[:120],
                "summary": ((f"{'Encoded' if decoded else 'Obfuscated'} PowerShell (parent: {parent or '?'}) — "
                             + mass_summary(r) + f": {shown[:160]}") if r.get("Mass") else
                            (f"{'Encoded' if decoded else 'Obfuscated'} PowerShell on '{device}' by "
                             f"'{account}' (parent: {parent or '?'}) — content seen on "
                             f"{r.get('FleetDevices', '?')} device(s) fleet-wide: {shown[:160]}")),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
