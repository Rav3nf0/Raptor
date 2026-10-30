"""score_day's write path against an in-memory Mongo: every ranked device is stored, only
medium and high become /shadow findings. MDE-backed signals and the scorer are stubbed.

Run: python -m pytest shadow_hunter/behavior_store_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import date, timedelta

import pytest
from beanie import init_beanie

AsyncMongoMockClient = pytest.importorskip("mongomock_motor").AsyncMongoMockClient  # dev extra

from shadow_hunter import behavior
from shadow_hunter.models import Finding

DAY = date(2026, 9, 28)


def _entity(device, score, stages):
    return {"device": device, "score": score, "stages": stages, "novelty_baseline": 1.0,
            "novelty_points": 2.0, "novel_risky": [{"lineage": "zsh > python# > sh", "cmd": "x"}],
            "rare_persistent": [], "spread": [], "persistence_new": [], "net_high": 0, "net_med": 1}


async def _run(monkeypatch):
    await init_beanie(database=AsyncMongoMockClient()["behavior_test"], document_models=[Finding])
    db = behavior._db()
    # the warm-up guard needs HISTORY_DAYS built days before DAY
    await db[behavior.RARE_COLL].insert_many([{"day": (DAY - timedelta(days=i)).isoformat(), "L": f"h{i}",
                                               "devices": []} for i in range(1, behavior.HISTORY_DAYS + 1)])

    async def none(*a, **k):
        return {}

    async def no_spread(*a, **k):
        return {}, []
    monkeypatch.setattr(behavior, "network_counts", none)
    monkeypatch.setattr(behavior, "persistence_counts", none)
    monkeypatch.setattr(behavior, "access_counts", none)
    monkeypatch.setattr(behavior, "spreading_lineages", no_spread)
    monkeypatch.setattr(behavior, "score_entities", lambda *a, **k: [
        _entity("implant-mac", 60.1, 3), _entity("busy-dev", 30.0, 2), _entity("quiet", 12.0, 1)])
    out = await behavior.score_day(DAY)
    findings = await Finding.find(Finding.detector == "entity_behavior").to_list()
    stored = await behavior.scores(DAY.isoformat())
    latest = await behavior.scores()
    return out, findings, stored, latest


def test_low_scores_are_stored_but_not_queued(monkeypatch):
    out, findings, stored, latest = asyncio.run(_run(monkeypatch))
    assert out["by_severity"] == {"high": 1, "medium": 1, "low": 1} and out["written"] == 2
    assert sorted((f.device_name, f.severity) for f in findings) == [("busy-dev", "medium"), ("implant-mac", "high")]
    assert [(r["device"], r["severity"], r["rank"]) for r in stored["scores"]] == [
        ("implant-mac", "high", 1), ("busy-dev", "medium", 2), ("quiet", "low", 3)]
    assert latest["day"] == DAY.isoformat() and "expires_at" not in stored["scores"][0]


def test_queued_finding_raw_matches_the_stored_score(monkeypatch):
    _, findings, stored, _ = asyncio.run(_run(monkeypatch))
    hi = next(f for f in findings if f.severity == "high")
    doc = next(r for r in stored["scores"] if r["device"] == "implant-mac")
    assert hi.raw["score"] == doc["score"] == 60.1 and hi.raw["rank"] == 1 and "severity" not in hi.raw


def test_installer_provenance_needs_an_install_location_not_just_a_name():
    lib = "/Library/Application Support/Logi/LogiOptionsPlus/depots/1/logioptionsplus_updater"
    rows = [
        {"DeviceName": "m1", "Mechanism": "launchd", "Item": "com.logitech.agent.plist", "Writers": ["bash"],
         "WriterPaths": ["/bin/bash"],
         "WriterCmds": ["/bin/bash /tmp/PKInstallSandbox.H4n2db/Scripts/com.logitech.pkg/preinstall"]},
        {"DeviceName": "m1", "Mechanism": "launchd", "Item": "com.logi.updater.plist",
         "Writers": ["logioptionsplus_updater"], "WriterPaths": [lib]},
        # the same names from user-writable paths are not trusted
        {"DeviceName": "m2", "Mechanism": "launchd", "Item": "com.google.keystone.plist",
         "Writers": ["googleupdater"], "WriterPaths": ["/Users/x/Library/Caches/GoogleUpdater/googleupdater"]},
        {"DeviceName": "m3", "Mechanism": "launchd", "Item": "com.docker.vmnetd.plist", "Writers": ["install"],
         "WriterPaths": ["/tmp/docker-desktop-privileged1/install"]},
        {"DeviceName": "m4", "Mechanism": "launchd", "Item": "x.plist", "Writers": ["python3"],
         "WriterPaths": ["/usr/bin/python3"]},
        {"DeviceName": "m5", "Mechanism": "launchd", "Item": "nopath.plist", "Writers": ["softwareupdater"]},
        {"DeviceName": "3 devices", "Mechanism": "launchd", "Item": "pushed.plist", "Writers": ["bash"],
         "WriterPaths": ["/bin/bash"], "Mass": True, "Devices": ["a", "b", "c"]},
    ]

    class Fake:
        async def hunt(self, *a, **k):
            return rows
    out = asyncio.run(behavior.persistence_counts(DAY, client=Fake()))
    tag = behavior.INSTALLER_TAG
    assert out["m1"] == ["launchd:com.logitech.agent.plist" + tag, "launchd:com.logi.updater.plist" + tag]
    assert out["m2"] == ["launchd:com.google.keystone.plist"] and out["m3"] == ["launchd:com.docker.vmnetd.plist"]
    assert out["m4"] == ["launchd:x.plist"] and out["m5"] == ["launchd:nopath.plist"]
    assert out["a"] == out["b"] == out["c"] == ["launchd:pushed.plist"]


def test_installer_persistence_adds_points_but_not_a_signal_kind():
    from shadow_hunter.behavior import score_entities
    doc = {"day": "2026-09-28", "L": "zsh > python# > sh", "interp": True, "sens": False, "det": False,
           "devices": [{"id": "m", "name": "m", "n": 1, "cmd": "sh -c x"}]}
    net = {"m": {"high": 0, "medium": 2}}
    tag = behavior.INSTALLER_TAG
    inst = score_entities([doc], {}, set(), net, persistence_new={"m": ["launchd:a.plist" + tag, "launchd:b.plist" + tag]})[0]
    own = score_entities([doc], {}, set(), net, persistence_new={"m": ["launchd:a.plist", "launchd:b.plist"]})[0]
    assert inst["stages"] == own["stages"] - 1 and inst["score"] < own["score"]
    assert behavior.severity_for(own) == "high" or own["stages"] == 3


def test_rdp_access_new_to_the_target_is_a_signal_kind():
    from shadow_hunter.behavior import score_entities
    doc = {"day": "2026-09-28", "L": "zsh > python# > sh", "interp": True, "sens": False, "det": False,
           "devices": [{"id": "srv", "name": "srv", "n": 1, "cmd": "sh -c x"}]}
    base = score_entities([doc], {}, set(), {})[0]
    moved = score_entities([doc], {}, set(), {}, access_new={"srv": ["rms.a1 from 192.168.75.10"]})[0]
    assert moved["stages"] == base["stages"] + 1 and moved["score"] > base["score"]
    assert moved["access_new"] == ["rms.a1 from 192.168.75.10"]


def test_rescoring_updates_an_open_case_and_retires_one_that_fell_to_low(monkeypatch):
    async def go():
        await _run(monkeypatch)                       # implant-mac high, busy-dev medium
        monkeypatch.setattr(behavior, "score_entities", lambda *a, **k: [
            _entity("busy-dev", 58.7, 3), _entity("implant-mac", 11.0, 1)])
        await behavior.score_day(DAY)
        return {f.device_name: (f.severity, f.legacy, f.raw["score"])
                for f in await Finding.find(Finding.detector == "entity_behavior").to_list()}
    got = asyncio.run(go())
    assert got == {"busy-dev": ("high", False, 58.7), "implant-mac": ("high", True, 60.1)}


def test_rescoring_drops_entities_that_no_longer_rank(monkeypatch):
    async def go():
        await _run(monkeypatch)                       # implant-mac, busy-dev, quiet
        monkeypatch.setattr(behavior, "score_entities", lambda *a, **k: [
            _entity("shared~aaaaaa", 30.0, 2), _entity("busy-dev", 30.0, 2)])
        await behavior.score_day(DAY)
        stored = [r["device"] for r in (await behavior.scores(DAY.isoformat()))["scores"]]
        open_ = {f.device_name for f in await Finding.find(Finding.detector == "entity_behavior",
                                                          Finding.legacy != True).to_list()}  # noqa: E712
        return stored, open_
    stored, open_ = asyncio.run(go())
    assert sorted(stored) == ["busy-dev", "shared~aaaaaa"]
    assert open_ == {"busy-dev", "shared~aaaaaa"}


def test_recovery_reruns_a_dead_night_and_counts_attempts(monkeypatch):
    from datetime import datetime, timezone
    from types import SimpleNamespace
    import shadow_hunter.config as cfg

    async def go():
        await init_beanie(database=AsyncMongoMockClient()["recover_test"], document_models=[Finding])
        monkeypatch.setattr(cfg, "get_shadow_config", lambda: SimpleNamespace(mode="live"))
        calls = []

        async def fake_build(day, progress=None):
            calls.append(("build", day))
            return {}

        async def fake_score(day, progress=None):
            calls.append(("score", day))
            return {"written": 1}
        monkeypatch.setattr(behavior, "build_day", fake_build)
        monkeypatch.setattr(behavior, "score_day", fake_score)
        now = datetime.now(timezone.utc)
        y = now.date() - timedelta(days=1)
        await behavior._db()[behavior.RUNS_COLL].insert_one(
            {"_id": y.isoformat(), "state": "running", "started": "2026-01-01T00:00:00+00:00",
             "stage_at": "2026-01-01T00:00:00+00:00", "stage": "scoring_load", "build": True, "score": True,
             "attempts": 1})
        out = await behavior.recover_missed()
        rec = await behavior._db()[behavior.RUNS_COLL].find_one({"_id": y.isoformat()})
        again = await behavior.recover_missed()
        return calls, out, rec, again, y
    calls, out, rec, again, y = asyncio.run(go())
    assert ("score", y) in calls and ("build", y) not in calls        # resumed at scoring
    assert out[0]["state"] == "done" and rec["attempts"] == 2
    assert again == [] or all(r["day"] != y.isoformat() for r in again)


def test_package_manager_rollouts_are_not_spreading_lineages():
    assert behavior._from_installer("dpkg > dash > python#.#")
    assert behavior._from_installer("#-peazip-#.#.#.win#.tmp > peazip > reg")
    assert not behavior._from_installer("zsh > node > curl")


def test_a_hostname_shared_by_several_devices_is_scored_per_device():
    from shadow_hunter.behavior import score_entities, device_key
    name = "administrators-macbook-pro"
    docs = [{"day": "2026-09-29", "L": f"zsh > python# > t{i}", "interp": True, "sens": False, "det": False,
             "devices": [{"id": did, "name": name, "n": 1, "cmd": "x"}]}
            for i, did in enumerate(["aaaaaa11", "bbbbbb22", "cccccc33"])]
    net = {device_key(name, "aaaaaa11"): {"high": 0, "medium": 4}, device_key(name, "bbbbbb22"): {"high": 0, "medium": 3}}
    ents = {e["device"]: e for e in score_entities(docs, {}, set(), net)}
    assert set(ents) == {f"{name}~aaaaaa", f"{name}~bbbbbb", f"{name}~cccccc"}
    assert ents[f"{name}~aaaaaa"]["net_med"] == 4 and ents[f"{name}~cccccc"]["net_med"] == 0
    assert ents[f"{name}~bbbbbb"]["device_id"] == "bbbbbb22"
    # a unique name keeps its plain key, whatever the source keyed it by
    one = score_entities(docs[:1], {}, set(), {device_key(name, "aaaaaa11"): {"high": 1, "medium": 0}})
    assert [(e["device"], e["net_high"]) for e in one] == [(name, 1)]
