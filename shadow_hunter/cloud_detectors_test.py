"""cloud_session_split and edr_silent_active — pinned on the properties that separated the
INC-2026-0911-KB replay from ordinary days (see detectors/cloud.py).

Run: python -m pytest shadow_hunter/cloud_detectors_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from shadow_hunter.detectors import DETECTORS
from shadow_hunter.detectors.base import mask_ids
from shadow_hunter.detectors.cloud import (CloudSessionSplitDetector, EdrSilentActiveDetector, build_silent_mde_kql,
                                           build_split_kql, match_silent)

ACCOUNT = "9" * 3 + "1" * 6 + "903"          # a 12-digit account ID, built so none sits in the source
NOW = datetime(2026, 9, 7, 18, tzinfo=timezone.utc)


def test_both_are_registered():
    names = {d.name for d in DETECTORS}
    assert {"cloud_session_split", "edr_silent_active"} <= names


def test_account_ids_are_masked_everywhere():
    got = mask_ids({"a": f"arn:aws:iam::{ACCOUNT}:role/x", "b": [ACCOUNT], "c": "1" * 14})
    assert got == {"a": "arn:aws:iam::99…903:role/x", "b": ["99…903"], "c": "1" * 14}


# ── cloud_session_split ─────────────────────────────────────────────────────────────

def test_split_needs_a_network_new_for_the_person_and_an_os_change_or_rotation():
    kql = build_split_kql(history_days=14, min_rotation_ips=5)
    assert 'UserIdentityArn contains "@"' in kql                   # human SSO sessions only
    assert "join kind=leftanti hist on User, Net" in kql            # new for THIS person
    assert "windowStart - 14d" in kql and "bin(TimeGenerated, 10m)" in kql
    assert "where OSDiffer or NewNetIPs >= 5" in kql                # networks alone are mobile carriers


def test_split_excludes_aws_service_backends_and_private_addresses():
    kql = build_split_kql()
    assert 'SourceIpAddress endswith ".amazonaws.com"' in kql and "ipv4_is_private(SourceIpAddress)" in kql
    assert "where isnotempty(Client)" in kql                         # python-requests / Go / Jersey backends dropped


def test_split_finding_masks_ids_and_names_the_behaviour():
    row = {"Key": "ASIAABCDEFGHIJ3O5A", "User": "someone@example.com", "OSDiffer": True, "NewNets": '["193.37"]',
           "NewNetIPs": 27, "Calls": 259, "Errors": 17, "Roles": '["ReadOnly"]',
           "Accounts": f'["{ACCOUNT}"]', "Actions": '["ListSecrets", "PutRolePolicy (AccessDenied)"]'}
    f = CloudSessionSplitDetector().to_findings([row])[0]
    assert f["severity"] == "high" and f["indicator"] == "someone@example.com|ASIA…3O5A"
    assert "a different OS and 27 rotating addresses" in f["summary"] and "PutRolePolicy (AccessDenied)" in f["summary"]
    assert ACCOUNT not in str(f) and f["raw"]["Key"] == "ASIA…3O5A"


# ── edr_silent_active ───────────────────────────────────────────────────────────────

def _dev(host, last, ips=("103.101.102.187",), user="lanesethi", os="macOS"):
    return {"Host": host, "Last": last, "PublicIPs": list(ips), "OS": os, "DeviceId": f"id-{host}",
            "UsersRaw": [f'[{{"UserName":"{user}"}}]']}


def _act(src, who, first, ip="103.101.102.187", dev="", calls=3, last=None):
    return {"Src": src, "Who": who, "First": first, "Last": last or first, "Ip": ip, "Dev": dev, "Calls": calls}


def test_cli_from_the_devices_own_ip_while_silent_is_caught():
    devs = [_dev("macbook-pro-51", "2026-09-02T04:22:40Z")]
    act = [_act("cloudtrail", "lane.sethi@example.com", "2026-09-07T08:49:14Z", calls=24)]
    hit = match_silent(devs, act, NOW)[0]
    assert hit["Host"] == "macbook-pro-51" and hit["CliCalls"] == 24 and hit["SilentHours"] == 134
    f = EdrSilentActiveDetector().to_findings([hit])[0]
    assert f["severity"] == "high" and f["indicator"] == "macbook-pro-51@2026-09-02"


def test_entra_sign_in_as_the_device_is_a_medium_coverage_gap():
    devs = [_dev("e750rchouoprwl", "2026-09-02T10:04:04Z", os="Windows11", user="raam")]
    act = [_act("signin", "raam@example.com", "2026-09-07T05:00:00Z", ip="1.2.3.4", dev="E750RCHOUOPRWL",
                last="2026-09-07T07:30:00Z")]
    f = EdrSilentActiveDetector().to_findings(match_silent(devs, act, NOW))[0]
    assert f["severity"] == "medium" and "Entra sign-in(s) as this device" in f["summary"]


def test_a_laptop_waking_or_signing_in_at_shutdown_is_not_a_device_in_use():
    # 2026-10-02 holiday weekend: 9 of 12 findings were one sign-in, some minutes after the last report
    devs = [_dev("vpsawaaotwl3", "2026-09-05T05:58:31Z", os="Windows11", user="v")]
    one = [_act("signin", "v@example.com", "2026-09-06T12:00:00Z", dev="vpsawaaotwl3", calls=1)]
    at_shutdown = [_act("signin", "v@example.com", "2026-09-05T06:31:34Z", dev="vpsawaaotwl3", calls=4,
                        last="2026-09-05T08:00:00Z")]
    assert match_silent(devs, one, NOW) == [] and match_silent(devs, at_shutdown, NOW) == []


def test_no_hit_when_the_device_reported_recently_or_the_evidence_is_too_fresh():
    act = [_act("cloudtrail", "lane.sethi@example.com", "2026-09-07T08:49:14Z")]
    assert match_silent([_dev("mac", "2026-09-07T01:00:00Z")], act, NOW) == []      # silent < 24h
    fresh = [_act("cloudtrail", "lane.sethi@example.com", "2026-09-07T15:00:00Z")]   # < 6h ago: start-up delay
    assert match_silent([_dev("mac", "2026-09-02T04:22:40Z")], fresh, NOW) == []


def test_no_hit_from_another_ip_or_another_person():
    devs = [_dev("mac", "2026-09-02T04:22:40Z")]
    assert match_silent(devs, [_act("cloudtrail", "lane.sethi@example.com", "2026-09-07T08:00:00Z", ip="8.8.8.8")], NOW) == []
    assert match_silent(devs, [_act("cloudtrail", "someone.else@example.com", "2026-09-07T08:00:00Z")], NOW) == []


def test_last_seen_uses_every_row_by_hostname():
    kql = build_silent_mde_kql()
    assert "take_anyif(OSPlatform, isnotempty(OSPlatform))" in kql and "by Host" in kql
    assert "mv-expand" not in kql      # expanding empty LoggedOnUsers dropped rows and faked silence


def test_mock_mode_returns_no_rows_without_touching_sentinel():
    from shadow_hunter.clients import MockDefenderClient
    for d in (CloudSessionSplitDetector(), EdrSilentActiveDetector()):
        assert asyncio.run(d.fetch(MockDefenderClient())) == []
