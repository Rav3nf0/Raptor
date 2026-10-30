"""Defender exclusions added by a script host or shell rather than central management.

Kept from the original: the signal is precise (Group Policy's svchost writes ~13 exclusion
values on most workstations every few days and is excluded; nothing else writes them
routinely). Two changes, from UAT on 2026-09-30:
  * One PowerShell run on uat-dart-pubsr on 2026-09-26 wrote 52 exclusion values, which made
    52 findings. Values from one writer command on one device are now one finding.
  * macOS was invisible. `mdatp exclusion ... add` is now covered.
  * 2026-10-05: MDE's own Security Settings Management (SenseCM.exe > powershell running the
    signed SenseCM\\AntiVirus.psm1 as SYSTEM) is central management too.
Extension exclusions are the broadest bypass and stay critical.
"""
from __future__ import annotations

from shadow_hunter.detectors.base import Detector, kql_list

# Processes that legitimately write Defender exclusions centrally.
_TRUSTED_WRITERS = {
    "intunemanagementextension.exe",   # Microsoft Intune
    "ccmexec.exe",                     # SCCM / ConfigMgr
    "svchost.exe",                     # Group Policy engine (gpsvc)
    "msiexec.exe",                     # MSI installers pushed via GP
    "MsMpEng.exe",                     # Defender itself (self-management)
    "AgentExecutor.exe",               # Intune agent executor
}
_SUSPICIOUS_WRITERS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                       "mshta.exe", "rundll32.exe", "regsvr32.exe")
_EXTENSION_KEY = "extensions"


def build_kql(lookback_hours: int = 24, end: str = "now()") -> str:
    return f"""
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let win = DeviceRegistryEvents
            | where Timestamp between (windowStart .. windowEnd)
            | where RegistryKey has "Windows Defender\\\\Exclusions" and ActionType == "RegistryValueSet"
            | where InitiatingProcessFileName !in~ ({kql_list(sorted(_TRUSTED_WRITERS))})
            // MDE Security Settings Management applies portal/Intune AV policy through its
            // own signed module, launched by SenseCM.exe as SYSTEM (prdaccord49 and 3 others,
            // 2026-10-02: 67 values). All three must hold; a lookalike name alone does not.
            | where not(InitiatingProcessParentFileName =~ "SenseCM.exe"
                        and InitiatingProcessAccountName =~ "system"
                        and InitiatingProcessCommandLine has @"\\SenseCM\\AntiVirus.psm1")
            | where InitiatingProcessFileName in~ ({kql_list(_SUSPICIOUS_WRITERS)})
                 or InitiatingProcessCommandLine has_any ("Set-MpPreference", "Add-MpPreference",
                      "ExclusionPath", "ExclusionExtension", "ExclusionProcess")
            | extend ExclusionType = tostring(split(RegistryKey, "\\\\")[-1]), Value = RegistryValueName;
        let mac = DeviceProcessEvents
            | where Timestamp between (windowStart .. windowEnd)
            | where FileName =~ "mdatp" and ProcessCommandLine has "exclusion" and ProcessCommandLine has " add"
            | extend ExclusionType = coalesce(extract(@"exclusion\\s+(\\S+)", 1, ProcessCommandLine), "unknown"),
                     Value = coalesce(extract(@"--(?:path|name|extension)\\s+(\\S+)", 1, ProcessCommandLine),
                                      substring(ProcessCommandLine, 0, 160)),
                     InitiatingProcessFileName = FileName, InitiatingProcessCommandLine = ProcessCommandLine,
                     InitiatingProcessAccountName = AccountName;
        union win, mac
        | summarize Count = count(), FirstSeen = min(Timestamp),
                    ExclusionTypes = make_set(ExclusionType, 5), Values = make_set(Value, 25),
                    InitiatingProcessAccountName = take_any(InitiatingProcessAccountName)
            by DeviceName, InitiatingProcessFileName,
               InitiatingProcessCommandLine = substring(InitiatingProcessCommandLine, 0, 300)
        | order by FirstSeen desc
        """


class DefenderExclusionsDetector(Detector):
    name = "defender_exclusions"
    mitre_techniques = ["T1562.001"]
    severity = "high"       # default; escalated to critical for extension exclusions
    cadence_minutes = 60
    query_name = "defender_exclusions"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            device = r.get("DeviceName", "")
            account = r.get("InitiatingProcessAccountName", "")
            process = r.get("InitiatingProcessFileName", "")
            types = r.get("ExclusionTypes") or []
            values = r.get("Values") or []
            if not types and r.get("RegistryKey"):  # pre-rework mock rows: one value per row
                types = [r["RegistryKey"].split("\\")[-1]]
                values = [r.get("RegistryValueName") or r.get("RegistryValueData", "")]
            severity = "critical" if any(t.lower() == _EXTENSION_KEY for t in types) else self.severity
            cmd = r.get("InitiatingProcessCommandLine", "") or ""
            out.append({
                "detector": self.name,
                "severity": severity,
                "device_id": device,
                "device_name": device,
                "account_name": account,
                "indicator": f"{process}|{','.join(sorted(types))}|{cmd[:80]}"[:120],
                "summary": (f"{len(values)} Defender exclusion(s) ({', '.join(types) or '?'}) added on "
                            f"'{device}' by '{account}' via '{process}': "
                            + ", ".join(str(v) for v in values[:5])
                            + (f" (+{len(values) - 5} more)" if len(values) > 5 else "")),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
