"""rare_persistence — replaces persistence_registry (754 findings/day, almost all fleet-standard
software). Replayed live 2026-09-30: 9, 2 and 5 findings on three days.

Run: python -m pytest shadow_hunter/rare_persistence_test.py -q
"""
from __future__ import annotations

from shadow_hunter.detectors.rare_persistence import RarePersistenceDetector, build_kql


def test_query_covers_windows_macos_and_cron():
    k = build_kql()
    assert "DeviceRegistryEvents" in k and "launchctl" in k and "crontab" in k


def test_standard_paths_and_installer_resume_entries_are_excluded():
    k = build_kql()
    assert 'Exe startswith "c:\\\\program files"' in k
    assert 'RegistryKey has "RunOnce" and Exe has "package cache"' in k


def test_common_vendor_namespaces_are_normal_except_masquerading_apple():
    k = build_kql(max_ns_devices=5)
    assert "NSDevices > 5" in k
    assert 'not(NS in (commonNS) and (NS != "com.apple" or SystemPath))' in k


def test_devices_with_alerts_are_not_excluded():
    assert "AlertEvidence" not in build_kql()


def test_plist_names_with_at_signs_parse():
    assert "[A-Za-z0-9._@-]+" in build_kql()


def _row(**kw):
    return {"DeviceId": "d1", "DeviceName": "mac-1", "Mechanism": "launchd", "Item": "com.x.agent.plist",
            "FleetDevices": 1, "Writers": ["bash"], "Samples": ["launchctl load ~/Library/LaunchAgents/com.x.agent.plist"],
            **kw}


def test_a_shell_installing_a_launchd_item_is_medium_not_high():
    assert RarePersistenceDetector().to_findings([_row()])[0]["severity"] == "medium"


def test_a_script_host_writing_a_run_key_is_high():
    f = RarePersistenceDetector().to_findings([_row(Mechanism="run_key", Item="x.exe", Writers=["powershell.exe"])])[0]
    assert f["severity"] == "high"


def test_an_interpreter_installing_a_launchd_item_is_high():
    assert RarePersistenceDetector().to_findings([_row(Writers=["python3"])])[0]["severity"] == "high"


def test_scheduled_tasks_use_every_creation_method_and_normalise_names():
    k = build_kql()
    assert 'ActionType == "ScheduledTaskCreated"' in k      # not only schtasks.exe
    assert '"<sid>"' in k and '"<guid>"' in k


def test_vendor_task_folders_are_normal_except_microsoft():
    k = build_kql(max_ns_devices=5)
    assert 'TaskNS != "microsoft"' in k and "not(TaskNS in (commonTaskNS))" in k


def test_tasks_are_grouped_per_folder():
    assert 'strcat(TaskFolder, "\\\\...")' in build_kql()


def test_no_reserved_word_is_used_as_a_variable():
    # `others` is reserved in KQL; using it as a let name broke the whole query.
    import re
    assert "others" not in re.findall(r"let (\w+) =", build_kql())


def test_homebrew_services_are_medium_other_ruby_writers_high():
    from shadow_hunter.detectors.rare_persistence import RarePersistenceDetector
    base = {"DeviceName": "m", "Mechanism": "launchd", "Writers": ["ruby"], "FleetDevices": 1}
    brew = RarePersistenceDetector().to_findings([{**base, "Item": "sh.brew.redis.plist",
                                                   "WriterPaths": ["/opt/homebrew/Cellar/ruby/3.4/bin/ruby"]}])[0]
    other = RarePersistenceDetector().to_findings([{**base, "Item": "sh.brew.redis.plist",
                                                    "WriterPaths": ["/Users/x/.cache/ruby"]}])[0]
    assert brew["severity"] == "medium" and other["severity"] == "high"


def test_restart_manager_and_windows_esu_tasks_are_skipped_only_in_their_exact_form():
    from shadow_hunter.detectors.rare_persistence import build_kql
    kql = build_kql()
    assert 'RegistryValueName startswith "Application Restart #"' in kql and 'InitiatingProcessFileName =~ "csrss.exe"' in kql
    assert r"@'\microsoft\windows\clip\enableclipesu'" in kql
    assert '(TaskCmd == "cmd" and isempty(TaskArgs))' in kql and r'endswith @"\system32\clipesuconsumer.exe"' in kql


def test_mde_security_settings_management_is_central_management():
    from shadow_hunter.detectors.defender_exclusions import build_kql
    kql = build_kql()
    assert 'InitiatingProcessParentFileName =~ "SenseCM.exe"' in kql and 'InitiatingProcessAccountName =~ "system"' in kql
    assert r'has @"\SenseCM\AntiVirus.psm1"' in kql


def test_startup_folder_scripts_count_shortcuts_do_not():
    kql = build_kql()
    assert r'FolderPath has @"\Start Menu\Programs\Startup\"' in kql
    assert "(cmd|bat|vbs|vbe|js|jse|wsf|ps1|hta|exe|scr|com|pif)$" in kql and "lnk" not in kql
    assert 'Mechanism = "startup_folder"' in kql and "union winFleet, macFleet, startupFleet" in kql
