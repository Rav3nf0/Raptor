"""Behaviour scoring — the properties that made the incident rank #1 without a signature.

Run: python -m pytest shadow_hunter/behavior_test.py -q
"""
from __future__ import annotations

from datetime import date

from shadow_hunter.behavior import (build_common_kql, build_rare_kql, prior_devices,
                                    rows_to_rare_docs, score_entities as _score, severity_for)


def score_entities(today, history, common, net):
    return _score(today, prior_devices(history), common, net)


def _doc(L, devices, interp=True, sens=False, det=False, day="2026-09-10", cmd=None):
    return {"day": day, "L": L, "interp": interp, "sens": sens, "det": det,
            "devices": [{"id": i, "name": i, "n": 1, "cmd": cmd or f"cmd {L}"} for i in devices]}


def _by(ents):
    return {e["device"]: e for e in ents}


def test_new_rare_risky_lineage_is_novel():
    e = _by(score_entities([_doc("sh > kubectl > kubectl", ["m51"], interp=False, sens=True)], [], set(), {}))
    assert len(e["m51"]["novel_risky"]) == 1


def test_lineage_the_device_already_ran_is_not_novel():
    today = [_doc("zsh > python# > python#", ["m51"])]
    hist = [_doc("zsh > python# > python#", ["m51"], day="2026-09-08")]
    assert _by(score_entities(today, hist, set(), {})) == {}


def test_persistent_implant_still_counts_when_no_longer_new():
    # launchd > python# > python# ran every day: self-novelty has learned it; fleet rarity has not.
    L = "launchd > python# > python#"
    today = [_doc(L, ["m51"], det=True)]
    hist = [_doc(L, ["m51"], det=True, day=f"2026-09-0{d}") for d in (3, 5, 9)]
    e = _by(score_entities(today, hist, set(), {}))["m51"]
    assert e["novel_risky"] == [] and len(e["rare_persistent"]) == 1


def test_lineage_common_anywhere_in_the_window_is_ignored():
    L = "cursor > cursor > cursor helper"
    assert score_entities([_doc(L, ["m51"])], [], {L}, {}) == []


def test_lineage_spreading_across_the_fleet_stops_being_rare():
    L = "zsh > node > node"
    hist = [_doc(L, ["a", "b", "c"], day="2026-09-09")]
    assert score_entities([_doc(L, ["m51"])], hist, set(), {}) == []   # 4 devices > NOVEL_MAX_FLEET


def test_different_kinds_of_signal_outrank_one_noisy_kind():
    noisy = [_doc(f"zsh > python# > tool{i}", ["dev"]) for i in range(10)]
    incident = [_doc("sh > kubectl > kubectl", ["m51"], interp=False, sens=True),
                _doc("launchd > python# > python#", ["m51"], det=True)]
    ranked = score_entities(noisy + incident, [], set(), {"m51": {"high": 2, "medium": 0}})
    assert ranked[0]["device"] == "m51" and ranked[0]["stages"] == 3
    assert severity_for(ranked[0]) == "high"
    assert severity_for(_by(ranked)["dev"]) != "high"


def test_network_only_entity_is_scored():
    e = score_entities([], [], set(), {"srv": {"high": 1, "medium": 0}})
    assert e[0]["device"] == "srv" and e[0]["stages"] == 1


def test_rows_group_into_one_doc_per_lineage():
    rows = [{"L": "a > b > c", "DeviceId": "1", "DeviceName": "x", "n": 2, "cmd": "c", "IsInterp": 1, "IsSens": 0, "IsDet": 0},
            {"L": "a > b > c", "DeviceId": "2", "DeviceName": "y", "n": 1, "cmd": "c", "IsInterp": 0, "IsSens": 0, "IsDet": 1}]
    docs = rows_to_rare_docs(rows, date(2026, 9, 10))
    assert len(docs) == 1 and len(docs[0]["devices"]) == 2
    assert docs[0]["interp"] and docs[0]["det"] and docs[0]["day"] == "2026-09-10"


def test_builder_scans_one_day_only_and_normalises_versions():
    kql = build_rare_kql(date(2026, 9, 10))
    assert "datetime(2026-09-10)" in kql and "between (D .. D + 1d)" in kql
    assert 'replace_regex(' in kql and '@"[0-9]+", "#"' in kql
    assert "DevCount <= 5" in kql and "DevCount > 5" in build_common_kql(date(2026, 9, 10))


def test_a_run_left_running_by_a_dead_process_goes_stale():
    from datetime import datetime, timedelta, timezone
    from shadow_hunter.behavior import _is_stale
    now = datetime.now(timezone.utc)
    assert _is_stale({"started": (now - timedelta(hours=1)).isoformat()})
    assert not _is_stale({"started": (now - timedelta(minutes=5)).isoformat()})
    assert _is_stale({})
    # a long run that is still reporting progress is alive
    assert not _is_stale({"started": (now - timedelta(hours=2)).isoformat(),
                          "stage_at": (now - timedelta(minutes=3)).isoformat()})


def test_a_failed_stalled_or_missed_night_is_recovered_a_finished_one_is_not():
    from datetime import datetime, timedelta, timezone
    from shadow_hunter.behavior import needs_recovery
    now = datetime(2026, 10, 5, 22, 0, tzinfo=timezone.utc)
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    fresh = datetime.now(timezone.utc).isoformat()
    full = {"build": True, "score": True}
    assert needs_recovery(None, is_yesterday=True, now=now) == full
    assert needs_recovery(None, is_yesterday=True, now=now.replace(hour=21, minute=10)) is None
    assert needs_recovery(None, is_yesterday=False, now=now) is None
    assert needs_recovery({"state": "failed", "build": True, "score": True, "stage": "querying_rare"},
                          is_yesterday=True, now=now) == full
    # died while scoring: the history is built, only score again
    assert needs_recovery({"state": "running", "started": old, "stage_at": old, "build": True, "score": True,
                           "stage": "scoring_network"}, is_yesterday=True, now=now) == {"build": False, "score": True}
    assert needs_recovery({"state": "running", "started": old, "stage_at": fresh, "stage": "scoring_load"},
                          is_yesterday=True, now=now) is None
    assert needs_recovery({"state": "done"}, is_yesterday=True, now=now) is None
    assert needs_recovery({"state": "failed", "attempts": 3}, is_yesterday=True, now=now) is None


def test_novelty_is_judged_against_the_devices_own_normal():
    today = ([_doc(f"zsh > python# > t{i}", ["noisy-dev"]) for i in range(10)]
             + [_doc(f"zsh > python# > q{i}", ["quiet"]) for i in range(10)])
    e = _by(_score(today, {}, set(), {}, {"noisy-dev": 20.0, "quiet": 0.0}))
    assert e["quiet"]["score"] > e["noisy-dev"]["score"]
    assert e["noisy-dev"]["novelty_points"] == 2.0 and e["quiet"]["novelty_points"] == 10.0


def test_persistence_and_network_are_not_dampened_by_a_noisy_baseline():
    today = [_doc("launchd > python# > python#", ["m51"], det=True)]
    e = _score(today, {}, set(), {"m51": {"high": 2, "medium": 0}}, {"m51": 50.0})[0]
    # Persistence (3) and network (4 x 2) keep full weight; the lineage's novelty is dampened
    # to ~0.1 by the noisy baseline and does not count as a stage of its own.
    assert e["stages"] == 2 and e["novelty_points"] < 1 and 33 <= e["score"] < 34


# ── redaction ────────────────────────────────────────────────────────────────────────

import pytest
from shadow_hunter.behavior import lineage_flags, redact_cmd


@pytest.mark.parametrize("raw,secret", [
    ("mysql -u root --password=S3cr3tPass -h db", "S3cr3tPass"),
    ("curl -H 'Authorization: Bearer abcDEF123.xyz' https://api", "abcDEF123.xyz"),
    ("psql postgresql://admin:hunter2@db.internal:5432/app", "hunter2"),
    ("export AWS_SECRET_ACCESS_KEY=short1", "short1"),
    ("aws s3 ls AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("x token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcd1234efgh", "eyJhbGciOiJIUzI1NiJ9"),
    ("curl -H 'X-Api-Key: k123' https://x", "k123"),
    ("echo 972690494903", "972690494903"),
])
def test_secrets_never_reach_storage(raw, secret):
    assert secret not in redact_cmd(raw)


@pytest.mark.parametrize("cmd", [
    "kubectl exec pps-worker-6c4d6f5474-85fjp -n payments -- sh",
    "python3 -",
    "git -c core.quotepath=false rev-parse --show-toplevel",
])
def test_ordinary_command_lines_keep_their_evidence(cmd):
    assert redact_cmd(cmd) == cmd


def test_stored_docs_are_redacted_and_expire():
    docs = rows_to_rare_docs([{"L": "a > b > c", "DeviceId": "1", "DeviceName": "x", "n": 1,
                               "cmd": "mysql --password=hunter2", "IsInterp": 0, "IsSens": 0, "IsDet": 0}],
                             date(2026, 9, 10))
    assert "hunter2" not in docs[0]["devices"][0]["cmd"]
    assert docs[0]["redacted"] is True and docs[0]["expires_at"].date() == date(2026, 10, 25)


# ── compiled implants: a fleet-rare binary counts like an interpreter ─────────────────

def test_rare_compiled_binary_from_persistence_is_counted():
    L = "launchd > gohelper > gohelper"          # not an interpreter
    e = _by(_score([_doc(L, ["m51"], interp=False, det=True,
                         cmd="/Users/k/Library/.cache/gohelper --daemon")], {}, set(), {}))["m51"]
    assert len(e["rare_persistent"]) == 1 and e["rare_persistent"][0]["rare_binary"]
    assert len(e["novel_risky"]) == 1


def test_binary_common_elsewhere_in_the_fleet_is_not_rare():
    L = "launchd > slack > slack"
    assert _score([_doc(L, ["m51"], interp=False, det=True, cmd="/tmp/slack")], {}, set(), {},
                  common_bins={"slack"}) == []


@pytest.mark.parametrize("cmd", [
    '"/Applications/Telegram.app/Contents/MacOS/Telegram"',
    "/System/Applications/Dictionary.app/Contents/MacOS/Dictionary",
    '"/Library/Application Support/Logitech/logioptionsplus_updater"',
    '"C:\\Program Files\\Fortinet\\FortiProxy.exe" -s FC_x',
    "Telegram",                                  # no path in the sample: not counted
])
def test_niche_apps_in_standard_locations_are_not_rare_binaries(cmd):
    L = "launchd > nicheapp > nicheapp"
    assert _score([_doc(L, ["m"], interp=False, det=True, cmd=cmd)], {}, set(), {}) == []


def test_binary_on_several_devices_is_not_rare():
    L = "launchd > agent > agent"
    today = [_doc(L, ["a", "b", "c"], interp=False, det=True)]
    assert _score(today, {}, set(), {}) == []


# ── spread: a risky lineage common on its first day ──────────────────────────────────

def test_spread_is_its_own_signal_kind():
    e = _by(_score([], {}, set(), {"dev1": {"high": 1, "medium": 0}},
                   spread={"dev1": ["node > sh > curl"], "dev2": ["node > sh > curl"]}))
    assert e["dev1"]["stages"] == 2 and e["dev2"]["stages"] == 1
    assert e["dev1"]["score"] > e["dev2"]["score"]


def test_spread_only_counts_for_attacker_tools():
    from shadow_hunter.behavior import SPREAD_CHILDREN, lineage_parts
    assert lineage_parts(" > dash > pgrep")[2] not in SPREAD_CHILDREN
    assert lineage_parts(" > dash > fuser")[2] not in SPREAD_CHILDREN
    assert lineage_parts("node > sh > curl")[2] in SPREAD_CHILDREN
    assert lineage_parts("npm > node > python#")[2] in SPREAD_CHILDREN


def test_lineage_flags_match_the_builder_classification():
    assert lineage_flags("launchd > python#.# > python#.#") == {"interp": True, "sens": False, "det": True}
    assert lineage_flags("sh > bash > kubectl") == {"interp": True, "sens": True, "det": False}
    assert lineage_flags("cursor > cursor > cursor helper") == {"interp": False, "sens": False, "det": False}


def test_redaction_keeps_long_file_paths_readable():
    p = "/System/Library/PrivateFrameworks/RemoteManagement.framework/RemoteManagementAgent -x"
    assert redact_cmd(p) == p


def test_a_path_mangled_by_old_redaction_is_unknown_not_nonstandard():
    from shadow_hunter.behavior import nonstandard_path
    assert nonstandard_path("/<blob>.<blob>.<blob>") is False
    assert nonstandard_path("/tmp/x/agent") is True


def test_three_weak_signal_kinds_are_not_high():
    assert severity_for({"stages": 3, "score": 29.3}) == "medium"
    assert severity_for({"stages": 3, "score": 60.1}) == "high"       # the incident
    assert severity_for({"stages": 3, "score": 45.0}) == "high"
    assert severity_for({"stages": 2, "score": 55.0}) == "medium"


def test_new_rare_persistence_is_its_own_signal_kind():
    today = [_doc("launchd > python#.# > python#.#", ["m51"], det=True)]
    without = _score(today, {}, set(), {})[0]
    with_p = _score(today, {}, set(), {}, persistence_new={"m51": ["launchd:com.evil.agent.plist"]})[0]
    assert with_p["stages"] == without["stages"] + 1 and with_p["score"] > without["score"]


def test_the_rare_scan_never_ships_whole_command_lines():
    from datetime import date
    from shadow_hunter.behavior import build_rare_kql
    assert "take_any(substring(ProcessCommandLine, 0, 600))" in build_rare_kql(date(2026, 10, 5))
