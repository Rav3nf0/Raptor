"""rare_external_domains — the query shape and the severity it assigns.

Replayed live against MDE on 2026-09-30: the old query produced ~950 destinations a day
and never saw macOS successful connections at all (their RemoteIPType is empty). The
rewrite gave 20 on the INC-2026-0911-KB day with the two C2 indicators as the only highs,
and 27 / 189 with zero highs on two ordinary days. These tests pin the properties that
produced that, so a later edit cannot quietly undo one.

Run: python -m pytest shadow_hunter/rare_domains_test.py -q
"""
from __future__ import annotations

import asyncio
import pathlib

from shadow_hunter.detectors.rare_domains import OWN_DOMAINS, RareDomainsDetector, build_kql


def test_macos_success_rows_are_not_filtered_out():
    kql = build_kql()
    assert 'isempty(RemoteIPType)' in kql and "ipv4_is_private(RemoteIP)" in kql


def test_urls_compare_by_host():
    assert "parse_url(RemoteUrl).Host" in build_kql()


def test_qualifies_on_interpreter_or_rare_binary_from_persistence():
    kql = build_kql()
    assert "where IsInterp or (IsRareBinary and IsDetached)" in kql
    # A detached ORDINARY service (VPN, svchost, TeamViewer) is not enough on its own.
    assert "IsInterp or IsDetached" not in kql


def test_binary_rarity_is_by_name_not_hash():
    # Auto-updating apps carry a different SHA256 per device; hash rarity flagged them all.
    kql = build_kql()
    assert "InitiatingProcessSHA256 in" not in kql and "P in (candNames)" in kql


def test_interpreter_from_persistence_ranks_first():
    assert "iff(Interp == 1 and Detached == 1, 3" in build_kql()


def test_devices_with_alerts_are_no_longer_excluded():
    assert "AlertEvidence" not in build_kql()


def test_rarity_is_fleet_wide_new_and_bounded():
    kql = build_kql(history_days=7, max_fleet_devices=2, new_within_hours=72)
    assert "FleetDevices <= 2" in kql
    assert "windowEnd - 7d" in kql and "windowEnd - 72h" in kql


def test_own_domains_are_excluded():
    kql = build_kql()
    assert all(d in kql for d in OWN_DOMAINS)


def test_replay_window_is_substituted():
    assert "let windowEnd = datetime(2026-09-10T12:00:00Z);" in build_kql(end="datetime(2026-09-10T12:00:00Z)")
    assert "let windowEnd = now();" in build_kql()


def _row(**kw):
    base = {"Destination": "evil.example", "FleetDevices": 1, "DaysSeen": 1, "ConnectionCount": 2,
            "Interp": 1, "Detached": 0, "DeviceIds": ["abc123"], "Devices": ["mac-1"],
            "InitiatingProcesses": ["python3.13"], "ParentProcesses": ["zsh"]}
    return {**base, **kw}


def test_interpreter_from_persistence_is_high():
    f = RareDomainsDetector().to_findings([_row(Detached=1, ParentProcesses=["launchd"])])[0]
    assert f["severity"] == "high"


def test_rare_binary_from_persistence_is_medium_until_another_signal_raises_it():
    f = RareDomainsDetector().to_findings([_row(Interp=0, RareBinary=1, Detached=1,
                                                InitiatingProcesses=["megasync"],
                                                ParentProcesses=["launchd"])])[0]
    assert f["severity"] == "medium" and "binary rare in fleet" in f["summary"]


def test_interpreter_from_a_shell_is_medium_even_when_recurring():
    f = RareDomainsDetector().to_findings([_row(DaysSeen=3)])[0]
    assert f["severity"] == "medium"


def test_device_id_is_the_id_not_the_name():
    f = RareDomainsDetector().to_findings([_row()])[0]
    assert (f["device_id"], f["device_name"]) == ("abc123", "mac-1")


def test_summary_states_the_rarity_facts():
    s = RareDomainsDetector().to_findings([_row(Detached=1, ParentProcesses=["launchd"])])[0]["summary"]
    assert "1 device(s) fleet-wide" in s and "python3.13" in s and "parent launchd" in s


def test_old_shape_mock_rows_still_convert():
    from shadow_hunter.clients.defender_mock import MockDefenderClient
    rows = asyncio.run(MockDefenderClient().hunt("rare_domains"))
    out = RareDomainsDetector().to_findings(rows)
    assert len(out) == len(rows) and all(f["severity"] == "medium" for f in out)


def test_ordinary_medium_destinations_are_not_persisted_but_still_scored():
    d = RareDomainsDetector()
    f = d.to_findings([_row(Destination="api.example.com")])[0]
    assert f["severity"] == "medium" and d.should_persist(f) is False


def test_tunnelling_services_are_flagged_but_left_to_exfil_patterns():
    d = RareDomainsDetector()
    for dest in ("abc-def.trycloudflare.com", "x.ngrok-free.dev", "webhook.site"):
        f = d.to_findings([_row(Destination=dest)])[0]
        assert f["raw"]["tunnel"] and not d.should_persist(f), dest


def test_high_findings_are_persisted():
    d = RareDomainsDetector()
    f = d.to_findings([_row(Detached=1, ParentProcesses=["launchd"])])[0]
    assert f["severity"] == "high" and d.should_persist(f)


def test_lookalike_hosts_are_not_tunnels():
    f = RareDomainsDetector().to_findings([_row(Destination="notngrok.io.example.com")])[0]
    assert f["raw"]["tunnel"] is False
