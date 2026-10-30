"""Person cases: scoring rules and the case write path (Sentinel stubbed, in-memory Mongo).

Run: python -m pytest shadow_hunter/person_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import date

import pytest

from shadow_hunter import person as P

# the incident Mac (replayed from Sentinel): fleet-new destinations reached by interpreters from
# 2026-08-26, and by the implant from persistence from 08-27
DEV = {"c2_high": ["mac-1: 144.172.101.226"], "rare_dest": ["mac-1: updateserver.xyz", "mac-1: aptupdate.org"],
       "persistence": []}
STOLEN_KEY = {"new_net_calls": 257, "new_net_ips": 27, "session_split": True, "ips": ["193.37.32.48"],
              "new_net_sensitive": ["ListSecrets", "GetSecretValue", "PutRolePolicy", "SendCommand"],
              "first_sensitive": ["ListSecrets", "GetSecretValue", "PutRolePolicy"]}


def _day(day, **planes):
    return {"day": day, "person": "a.user@corp.in", "devices": ["mac-1"], **planes}


def test_the_incident_shape_is_one_high_case_in_attack_order():
    days = [_day("2026-08-26", endpoint=DEV),
            _day("2026-08-27", endpoint=DEV),
            _day("2026-09-07", cloud=STOLEN_KEY),
            _day("2026-09-10", identity={"password_ok_mfa_stopped": 3, "ips": ["193.37.32.48"]})]
    c = P.score_case(days)
    assert c["severity"] == "high" and c["chain"] is True
    assert set(c["strong_planes"]) >= {"endpoint", "cloud", "identity"} and c["shared_ips"] == ["193.37.32.48"]


def test_a_single_source_never_makes_a_case_however_loud():
    loud = _day("2026-09-07", cloud={"new_net_calls": 900, "new_net_sensitive": ["ListSecrets"], "session_split": True,
                                     "first_sensitive": ["ListSecrets", "CreateAccessKey", "PutRolePolicy"]})
    assert P.score_case([loud])["severity"] == "none"


def test_background_noise_stays_below_a_finding():
    # a developer touching a few fleet-new sites and one failed Tor sign-in attempt: two planes, but weak
    days = [_day("2026-10-05", network={"rare_new": 4}, identity={"new_country_failed": 1})]
    assert P.score_case(days)["severity"] == "none"


def test_travel_without_device_activity_is_at_most_medium():
    days = [_day("2026-10-01", identity={"new_country_ok": 4, "ips": ["203.0.113.5"]}),
            _day("2026-10-01", cloud={"new_net_calls": 30, "ips": ["198.51.100.7"]})]
    assert P.score_case(days)["severity"] in ("none", "low", "medium")


def test_plane_points_cap_one_chatty_signal():
    flood = P.plane_points({"network": {"rare_new": 80}})
    assert flood["network"] == P.W["net_rare"] * P.CAPS["net_rare"]


def test_run_day_writes_one_case_and_grows_it(monkeypatch):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    from shadow_hunter.models import Finding
    signals = {
        date(2026, 8, 26): {"a.user@corp.in": _day("2026-08-26", endpoint=DEV)},
        date(2026, 9, 1): {"a.user@corp.in": _day("2026-09-01", endpoint=DEV)},       # the C2 kept beaconing
        date(2026, 9, 7): {"a.user@corp.in": _day("2026-09-07", cloud=STOLEN_KEY)},
        date(2026, 9, 10): {"a.user@corp.in": _day("2026-09-10", identity={
            "password_ok_mfa_stopped": 3, "ips": ["193.37.32.48"]})},
    }

    async def fake_daily(day, client=None):
        return signals.get(day, {})

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["person_test"], document_models=[Finding])
        monkeypatch.setattr(P, "daily_signals", fake_daily)
        outs = [await P.run_day(d) for d in sorted(signals)]
        rows = await Finding.find(Finding.detector == "person_behavior").to_list()
        return outs, rows
    outs, rows = asyncio.run(go())
    assert outs[0]["written"] == outs[1]["written"] == 0  # endpoint alone: no case
    assert outs[2]["written"] == 1 and outs[3]["updated"] == 1
    assert len(rows) == 1 and rows[0].severity == "high" and rows[0].indicator == "a.user@corp.in@2026-08-26"
    assert rows[0].raw["shared_ips"] == ["193.37.32.48"] and rows[0].account_name == "a.user@corp.in"


def test_an_unchanged_case_keeps_its_ai_suggestion(monkeypatch):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    from shadow_hunter.models import Finding
    day = {"a.user@corp.in": _day("2026-09-07", endpoint=DEV, cloud=STOLEN_KEY)}

    async def fake_daily(d, client=None):
        return day if d == date(2026, 9, 7) else {}

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["person_ai"], document_models=[Finding])
        monkeypatch.setattr(P, "daily_signals", fake_daily)
        await P.run_day(date(2026, 9, 7))
        f = await Finding.find_one(Finding.detector == "person_behavior")
        f.ai_verdict = "true_positive"
        await f.save()
        await P.run_day(date(2026, 9, 8))               # nothing new that day
        return await Finding.find_one(Finding.detector == "person_behavior")
    assert asyncio.run(go()).ai_verdict == "true_positive"


def test_routine_engineering_never_anchors_a_case():
    # 2026-09-21..10-06 replay: denial bursts, SSM sessions from home, travel, mobile IP churn
    days = [_day("2026-09-25", cloud={"denied": 27633, "new_net_calls": 40, "new_net_ips": 6,
                                      "new_net_sensitive": ["StartSession"]},
                 identity={"new_country_ok": 3, "new_countries": ["NL"]},
                 network={"upload_anomaly": True, "upload_mb": 900, "prior_max_mb": 200}),
            _day("2026-09-20", network={"alert_kinds": ["malsite"], "alerts": 1})]
    assert P.score_case(days)["severity"] in ("none", "medium")
    assert P.score_case([days[0]])["severity"] != "high"


def test_a_weak_account_event_pairs_only_with_a_nearby_device_event():
    travel = _day("2026-09-25", identity={"new_country_ok": 2, "new_countries": ["TH"]})
    far = _day("2026-09-15", network={"alert_kinds": ["malsite"], "alerts": 1})
    near = _day("2026-09-24", network={"alert_kinds": ["malsite"], "alerts": 1})
    assert P.score_case([far, travel])["severity"] == "none"
    assert P.score_case([near, travel])["severity"] == "medium"


def test_summary_reads_with_only_weak_events():
    days = [_day("2026-09-29", identity={"new_country_ok": 1, "new_countries": ["TH"]}),
            _day("2026-10-01", network={"upload_anomaly": True, "upload_mb": 4219, "prior_max_mb": 101})]
    c = P.score_case(days)
    s = P.summarize_case("a.user@corp.in", c)
    assert c["severity"] == "medium" and ": ;" not in s and "new country" in s and "4219 MB" in s


def test_runs_are_recorded_including_failures(monkeypatch):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    from shadow_hunter.models import Finding

    async def boom(day, client=None):
        raise RuntimeError("sentinel down")

    async def go():
        await init_beanie(database=mm.AsyncMongoMockClient()["person_runs"], document_models=[Finding])
        monkeypatch.setattr(P, "daily_signals", lambda d, client=None: _empty())
        ok = await P.run_logged(date(2026, 10, 7))
        monkeypatch.setattr(P, "run_day", boom)
        bad = await P.run_logged(date(2026, 10, 8))
        return ok, bad, await P.status()
    ok, bad, st = asyncio.run(go())
    assert ok["state"] == "done" and bad["state"] == "failed" and "sentinel down" in bad["error"]
    assert [r["day"] for r in st["runs"]] == ["2026-10-08", "2026-10-07"]


async def _empty():
    return {}
