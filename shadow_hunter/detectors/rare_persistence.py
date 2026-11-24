"""Fleet-rare persistence being created — Windows Run keys, scheduled tasks and Startup-folder
scripts, macOS launchd, cron.

Replaces persistence_registry, which flagged ANY Run/RunOnce/Winlogon write on any Windows
device: 754 findings across 367 devices in one day (2026-09-30), almost all fleet-standard
software — msedge.exe (383), installers' setup.exe (310), Slack, Chrome, OneDrive, VC++
redistributables. It also skipped devices with open MDE alerts, and could not see macOS or
Linux persistence at all.

A persistence item qualifies only when it is fleet-rare (seen being set on at most
`max_fleet_devices` devices over `history_days`) and, for Windows, points outside the
standard install locations and is not an installer's RunOnce resume entry. Estimated on that
day's findings: 754 -> ~8 per day. Writers that are script hosts or interpreters are high.

Startup-folder drops (2026-10-30): the trojanized Cursor Claude Code extension falls back to
copying sysmon.cmd into the user's Startup folder when it cannot register its SysMon task.
Only scripts and executables count — shortcuts (.lnk) are how installers add ordinary apps
there (Send to OneNote on 13 devices). 30 days to 2026-10-30 had ~5 such fleet-rare files.
"""
from __future__ import annotations

from shadow_hunter.detectors.base import MASS_HISTORY_DAYS, Detector, kql_fleet, mass_summary

RUN_KEYS = ("\\\\CurrentVersion\\\\Run", "\\\\CurrentVersion\\\\RunOnce", "\\\\CurrentVersion\\\\RunServices",
            "\\\\CurrentVersion\\\\Winlogon", "\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run",
            "\\\\CurrentVersion\\\\Windows\\\\Load", "\\\\CurrentVersion\\\\Windows\\\\Run")
SCRIPT_WRITERS = ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe",
                  "rundll32.exe", "regsvr32.exe", "python", "python3", "bash", "sh", "zsh", "osascript",
                  "node", "perl", "ruby", "curl")


def _kql_list(items) -> str:
    return ", ".join(f'"{i}"' for i in items)


# Windows 10 Extended Security Updates enrolment (2026-09-21 onward, ~9 devices a week): Windows
# servicing registers these with a placeholder `cmd` action, then ClipESUConsumer.exe. Skipped
# only by exact name AND one of those two actions, so a lookalike under the same name that runs
# anything else is still reported.
ESU_TASKS = tuple(f"@'\\microsoft\\windows\\clip\\{n}'" for n in (
    "clipesu", "enableclipesu", "clipesuconsumer", "clipesuconsumerprocesspreorder",
    "clipesuconsumerprocessrefund", "clipesuconsumerprocessecupdate"))


def build_kql(lookback_hours: int = 24, history_days: int = 7, max_fleet_devices: int = 2,
              max_ns_devices: int = 5, end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    win_filter = f"""
            | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
            | where RegistryKey has_any ({_kql_list(RUN_KEYS)})
            | extend Exe = tolower(extract(@'([A-Za-z]:\\\\[^"]*?\\.exe|[^"\\s\\\\]+\\.exe)', 1, RegistryValueData))
            | extend Item = extract(@'([^\\\\]+\\.exe)$', 1, Exe)
            | where isnotempty(Item)"""
    mac_filter = """
            | where (FileName =~ "launchctl" and ProcessCommandLine has_any (" bootstrap ", " load ", " enable ", " submit "))
                or (FileName in~ ("plistbuddy", "defaults") and ProcessCommandLine has_any ("LaunchAgents", "LaunchDaemons"))
                or (FileName =~ "crontab" and not(ProcessCommandLine has " -l"))
            | extend Item = tolower(coalesce(extract(@"([A-Za-z0-9._@-]+\\.plist)", 1, ProcessCommandLine),
                                             extract(@"submit\\s+-l\\s+(\\S+)", 1, ProcessCommandLine),
                                             iff(FileName =~ "crontab", "crontab", "")))
            | where isnotempty(Item)
            | extend Mechanism = iff(FileName =~ "crontab", "cron", "launchd")
            | extend NS = extract(@"^([a-z0-9-]+\\.[a-z0-9-]+)\\.", 1, Item),
                     SystemPath = ProcessCommandLine has_any ("/System/Library/", "/Library/Apple/")"""
    # Every creation method (schtasks, Register-ScheduledTask, the COM API), not just schtasks.exe
    # as the old scheduled_task_creation detector saw. Task names embed per-user SIDs, GUIDs and
    # versions ("OneDrive Standalone Update Task-S-1-5-21-..."), normalised so copies match.
    task_filter = """
            | where ActionType == "ScheduledTaskCreated"
            | extend Item = tolower(tostring(parse_json(AdditionalFields).TaskName))
            | extend Item = replace_regex(Item, @"s-1-5-21(-\\d+)+", "<sid>")
            | extend Item = replace_regex(Item, @"\\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\}?", "<guid>")
            | extend Item = replace_regex(Item, @"[0-9]+", "#")
            | where isnotempty(Item)"""
    startup_filter = """
            | where ActionType == "FileCreated" and FolderPath has @"\\Start Menu\\Programs\\Startup\\"
            | extend Item = tolower(FileName)
            | where Item matches regex @"\\.(cmd|bat|vbs|vbe|js|jse|wsf|ps1|hta|exe|scr|com|pif)$"
"""
    hist = f"(windowEnd - {MASS_HISTORY_DAYS}d) .. windowEnd"
    win_fleet = kql_fleet(f"""DeviceRegistryEvents
            | where Timestamp between ({hist}){win_filter}
            | where Item in (winCand)""", "Item", max_fleet_devices, history_days)
    mac_fleet = kql_fleet(f"""DeviceProcessEvents
            | where Timestamp between ({hist}){mac_filter}
            | where Item in (macCand)""", "Mechanism, Item", max_fleet_devices, history_days)
    startup_fleet = kql_fleet(f"""DeviceFileEvents
            | where Timestamp between ({hist}){startup_filter}
            | where Item in (startupCand)""", "Item", max_fleet_devices, history_days)
    task_fleet = kql_fleet(f"""DeviceEvents
            | where Timestamp between ({hist}){task_filter}
            | where Item in (taskCand)""", "Item", max_fleet_devices, history_days)
    writer = ("Writer = InitiatingProcessFileName, WriterCmd = InitiatingProcessCommandLine, "
              "WriterPath = InitiatingProcessFolderPath")
    return f"""
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let historyStart = windowEnd - {history_days}d;
        let winRecent = DeviceRegistryEvents
            | where Timestamp between (windowStart .. windowEnd){win_filter}
            // installer resume entries: RunOnce pointing into a package cache
            | where not(RegistryKey has "RunOnce" and Exe has "package cache")
            // Windows' restart manager reopening an app that was open at shutdown: csrss from
            // System32 writes RunOnce "Application Restart #n" (Task Manager, 2026-09-29)
            | where not(RegistryKey has "RunOnce" and RegistryValueName startswith "Application Restart #"
                        and InitiatingProcessFileName =~ "csrss.exe"
                        and InitiatingProcessFolderPath startswith "c:\\\\windows\\\\system32")
            // Program Files is where installed software lives. C:\\Windows and
            // ProgramData\\Microsoft used to be skipped too — the folders admin-level malware
            // hides in under a Windows-looking name — so a rare item there now counts.
            | where not(Exe startswith "c:\\\\program files")
            | extend Mechanism = "run_key",
                     Sample = strcat(RegistryKey, " = ", substring(RegistryValueData, 0, 200));
        let startupRecent = DeviceFileEvents
            | where Timestamp between (windowStart .. windowEnd){startup_filter}
            | extend Mechanism = "startup_folder", Sample = FolderPath;
        let macRecentAll = DeviceProcessEvents
            | where Timestamp between (windowStart .. windowEnd){mac_filter}
            | extend Sample = substring(ProcessCommandLine, 0, 240);
        let taskRecent = DeviceEvents
            | where Timestamp between (windowStart .. windowEnd){task_filter}
            | extend TaskExec = parse_json(tostring(parse_json(AdditionalFields).TaskContent)).Actions.Exec
            | extend TaskCmd = tolower(tostring(TaskExec.Command)), TaskArgs = tostring(TaskExec.Arguments)
            | where not(Item in ({", ".join(ESU_TASKS)})
                        and ((TaskCmd == "cmd" and isempty(TaskArgs))
                             or TaskCmd endswith @"\\system32\\clipesuconsumer.exe"))
            // Intune MDM enrolment registers ...\\EnterpriseMgmt\\<guid>\\... tasks running Windows'
            // own deviceenroller.exe (22 findings to 2026-11-06, 0 TP), and the Azure Arc agent
            // installs \\azcmagent running its script from its Program Files folder. Skipped only in
            // that exact form: the same names running anything else are still reported.
            | where not(Item has "enterprisemgmt" and TaskCmd endswith @"\\system32\\deviceenroller.exe")
            | where not(Item == @"\\azcmagent" and TaskArgs has @"\\Program Files\\AzureConnectedMachineAgent\\")
            // Windows Update's own tasks as they appear while an update rolls out (14 findings to
            // 2026-11-11, 0 TP): WaaSMedic's DeferredWork/MaintenanceWork are only ever its COM
            // handler, and MRT's MRT_ERROR_HB only ever System32\\MRT.exe /EHB. Same exact-form rule.
            | where not(Item has "waasmedic" and isempty(TaskCmd)
                        and tostring(parse_json(tostring(parse_json(AdditionalFields).TaskContent)).Actions.ComHandler.ClassId)
                            == "{{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}}")
            | where not(Item has "removaltools" and TaskCmd endswith @"\\system32\\mrt.exe" and TaskArgs startswith "/EHB ")
            // UpdateOrchestrator, the ManageEngine agent and Google Updater (25 findings to 2026-11-12,
            // 0 TP), in the one form each takes across 30 days of the fleet: USO only runs System32's
            // usoclient / musnotification / mlenginestub; \\DCAgentUpdater and \\UEMSLogCollector only
            // their own exe from ManageEngine\\UEMS_Agent\\bin with "Task"; GoogleUpdater only
            // Google\\GoogleUpdater\\<version>\\updater.exe --wake.
            | where not(Item has "updateorchestrator"
                        and TaskCmd matches regex @"^%(systemroot|windir)%\\\\system32\\\\(usoclient|musnotification|mlenginestub)\\.exe$")
            | where not(Item in (@"\\dcagentupdater", @"\\uemslogcollector") and TaskArgs == "Task"
                        and TaskCmd matches regex @"^c:\\\\program files \\(x86\\)\\\\manageengine\\\\uems_agent\\\\bin\\\\(dcagentupgrader|uemslogcollector)\\.exe$")
            | where not(Item has "googleupdater" and TaskArgs in ("--wake", "--wake --system")
                        and TaskCmd matches regex @"\\\\google\\\\googleupdater\\\\[0-9.]+\\\\updater\\.exe""?$")
            | extend Mechanism = "scheduled_task",
                     Sample = substring(tostring(parse_json(AdditionalFields).TaskContent), 0, 240),
                     TaskNS = extract(@"^\\\\([^\\\\]+)\\\\", 1, Item),
                     TaskFolder = extract(@"^(\\\\[^\\\\]+\\\\[^\\\\]+\\\\[^\\\\]+)\\\\", 1, Item);
        let taskCand = taskRecent | distinct Item;
        let taskFleet = {task_fleet}
            | extend Mechanism = "scheduled_task";
        let winCand = winRecent | distinct Item;
        let winFleet = {win_fleet}
            | extend Mechanism = "run_key";
        let startupCand = startupRecent | distinct Item;
        let startupFleet = {startup_fleet}
            | extend Mechanism = "startup_folder";
        let macCand = macRecentAll | distinct Item;
        let macFleet = {mac_fleet};
        // A vendor namespace (com.fortinet, com.google, com.netskope, homebrew.mxcl) that is
        // common across the fleet is normal even when one of its plists is rare — FortiClient
        // installing on two Macs made a dozen "rare" plists. Apple's namespace only counts as
        // normal from Apple's own system directories: implants masquerade as com.apple.*.
        // Judged on the days BEFORE the window, so a namespace pushed to many Macs today is
        // not made "common" by its own push.
        let commonNS = DeviceProcessEvents
            | where Timestamp between (historyStart .. windowStart){mac_filter}
            | where isnotempty(NS)
            | summarize NSDevices = dcount(DeviceId) by NS
            | where NSDevices > {max_ns_devices}
            | project NS;
        let macRecent = macRecentAll
            | where not(NS in (commonNS) and (NS != "com.apple" or SystemPath))
            // Google Updater bootstrapping its own wake job, from its own binary only
            | where not(Item in ("com.google.googleupdater.wake.plist", "com.google.googleupdater.wake.system.plist")
                        and InitiatingProcessFileName =~ "googleupdater");
        // Same idea for task folders (\\lenovo, \\mozilla, \\powertoys) — except \\microsoft,
        // which malware routinely registers under, as it masquerades as com.apple on macOS.
        let commonTaskNS = DeviceEvents
            | where Timestamp between (historyStart .. windowStart){task_filter}
            | extend TaskNS = extract(@"^\\\\([^\\\\]+)\\\\", 1, Item)
            | where isnotempty(TaskNS) and TaskNS != "microsoft"
            | summarize NSDevices = dcount(DeviceId) by TaskNS
            | where NSDevices > {max_ns_devices}
            | project TaskNS;
        // One Intune enrollment writes ~10 \\microsoft\\windows\\enterprisemgmt\\<guid>\\... tasks;
        // report the folder once per device rather than every task in it.
        let tasks = taskRecent
            | where not(TaskNS in (commonTaskNS))
            | join kind=inner taskFleet on Item
            | extend Item = iff(isnotempty(TaskFolder), strcat(TaskFolder, "\\\\..."), Item)
            | project Timestamp, DeviceId, DeviceName, Mechanism, Item, Sample, FleetDevices, Mass, {writer};
        let fleet = union winFleet, macFleet, startupFleet;
        // (not `others` — that is a reserved word in KQL)
        let nonTask = union
            (winRecent | project Timestamp, DeviceId, DeviceName, Mechanism, Item, Sample, {writer}),
            (macRecent | project Timestamp, DeviceId, DeviceName, Mechanism, Item, Sample, {writer}),
            (startupRecent | project Timestamp, DeviceId, DeviceName, Mechanism, Item, Sample, {writer})
            | join kind=inner fleet on Mechanism, Item
            | project Timestamp, DeviceId, DeviceName, Mechanism, Item, Sample, FleetDevices, Mass,
                      Writer, WriterCmd, WriterPath;
        let persisted = union nonTask, tasks;
        union
            (persisted | where not(Mass)
             | summarize Count = count(), FirstSeen = min(Timestamp), FleetDevices = take_any(FleetDevices),
                         Samples = make_set(Sample, 3), Writers = make_set(Writer, 5),
                         WriterCmds = make_set(substring(WriterCmd, 0, 200), 2), WriterPaths = make_set(WriterPath, 5)
                 by DeviceId, DeviceName, Mechanism, Item
             | extend Mass = false),
            // new to the fleet and already widespread: one finding for the push, not one per device
            (persisted | where Mass
             | summarize Count = count(), FirstSeen = min(Timestamp), FleetDevices = take_any(FleetDevices),
                         Samples = make_set(Sample, 3), Writers = make_set(Writer, 5),
                         WriterCmds = make_set(substring(WriterCmd, 0, 200), 2), WriterPaths = make_set(WriterPath, 5),
                         Devices = make_set(DeviceName, 25)
                 by Mechanism, Item
             | extend Mass = true, DeviceId = "", DeviceName = strcat(tostring(FleetDevices), " devices"))
        | order by Mass desc, FleetDevices asc, Count desc
        | take 300
        """


def _as_list(v):
    return v if isinstance(v, list) else ([v] if v else [])


class RarePersistenceDetector(Detector):
    name = "rare_persistence"
    mitre_techniques = ["T1547.001", "T1543.001", "T1053.003", "T1053.005"]
    severity = "medium"
    cadence_minutes = 60
    query_name = "rare_persistence"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            writers = [str(w).lower() for w in _as_list(r.get("Writers"))]
            # Installers run through bash/sh on macOS, so a shell writer alone is not the
            # tell there; an interpreter or script host other than the plain shells is.
            shells = {"bash", "sh", "zsh"} if r.get("Mechanism") == "launchd" else set()
            device = r.get("DeviceName", "")
            mech, item = r.get("Mechanism", ""), r.get("Item", "")
            # `brew services start redis` writes its LaunchAgent from Homebrew's own Ruby: a
            # scripted writer, but the package manager — medium, not high (2026-10-01).
            paths = [str(p).lower() for p in _as_list(r.get("WriterPaths"))]
            homebrew = (str(item).startswith(("homebrew.mxcl.", "sh.brew.")) and paths
                        and all(p.startswith(("/opt/homebrew/", "/usr/local/homebrew/", "/usr/local/cellar/")) for p in paths))
            scripted = not homebrew and any((w in SCRIPT_WRITERS or w.startswith("python")) and w not in shells
                                            for w in writers)
            samples = _as_list(r.get("Samples"))
            out.append({
                "detector": self.name,
                # new persistence pushed to many machines at once is high whoever wrote it
                "severity": "high" if scripted or r.get("Mass") else "medium",
                "device_id": r.get("DeviceId") or device,
                "device_name": device,
                "account_name": "",
                "indicator": f"{'mass' if r.get('Mass') else device}:{mech}:{item}",
                "summary": ((f"New {mech.replace('_', ' ')} persistence '{item}' — " + mass_summary(r))
                            if r.get("Mass") else
                            (f"Rare {mech.replace('_', ' ')} persistence '{item}' set on '{device}' — seen on "
                             f"{r.get('FleetDevices', '?')} device(s) fleet-wide"))
                           + f"; written by {', '.join(writers) or 'an unrecorded process'}"
                           + (f"; {str(samples[0])[:120]}" if samples else ""),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
