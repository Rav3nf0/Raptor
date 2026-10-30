"""UI allowlist rules in Mongo: shared, safe, reversible. In-memory Mongo.

Run: python -m pytest shadow_hunter/allowlist_store_test.py -q
"""
from __future__ import annotations

import asyncio
import pathlib

import pytest
from beanie import init_beanie

AsyncMongoMockClient = pytest.importorskip("mongomock_motor").AsyncMongoMockClient  # dev extra

from shadow_hunter.allowlist import AllowlistEngine, AllowlistRule
from shadow_hunter.models import AuditLog, Finding

REPO_RULES = pathlib.Path(__file__).parent / "allowlist" / "rules.yaml"


def _run(coro):
    async def wrapped():
        await init_beanie(database=AsyncMongoMockClient()["allow_test"], document_models=[Finding, AuditLog])
        return await coro()
    return asyncio.run(wrapped())


def _rule(**kw):
    return AllowlistRule(**{"name": "fp-x", "detector": "rare_persistence",
                            "match": {"indicator_contains": "lenovo"}, "owner": "a", **kw})


def test_a_rule_that_would_match_everything_is_refused():
    async def go():
        return (await AllowlistEngine.add_rule(_rule(match={"indicator_contains": ""})),
                await AllowlistEngine.add_rule(_rule(match={})))
    assert _run(go) == (None, None)


def test_ui_rules_join_the_repo_rules_under_unique_names():
    async def go():
        a = await AllowlistEngine.add_rule(_rule())
        b = await AllowlistEngine.add_rule(_rule())
        eng = await AllowlistEngine.load_all(REPO_RULES)
        return a, b, eng
    a, b, eng = _run(go)
    assert (a.name, b.name) == ("fp-x", "fp-x-2")
    ui = [r for r in eng.rules if r.source == "ui"]
    assert [r.name for r in ui] == ["fp-x", "fp-x-2"] and any(r.source == "repo" for r in eng.rules)
    assert eng.match({"detector": "rare_persistence", "indicator": "dev:run_key:lenovovantage.exe"}).name == "fp-x"


def test_a_new_rule_hides_its_open_siblings_and_removing_it_restores_them():
    async def go():
        for dev in ("d1", "d2"):
            await Finding(detector="rare_persistence", severity="medium", device_name=dev,
                          indicator=f"{dev}:run_key:lenovovantage.exe").insert()
        await Finding(detector="rare_persistence", severity="medium", device_name="d3",
                      indicator="d3:run_key:implant.exe").insert()
        rule = await AllowlistEngine.add_rule(_rule())
        hidden = await AllowlistEngine.apply_to_open(rule)
        after_add = sorted(f.device_name for f in await Finding.find(Finding.allowlisted_by_rule == "fp-x").to_list())
        out = await AllowlistEngine.delete_rule("fp-x")
        after_del = await Finding.find(Finding.allowlisted_by_rule == "fp-x").count()
        missing = await AllowlistEngine.delete_rule("fp-x")
        return hidden, after_add, out, after_del, missing
    hidden, after_add, out, after_del, missing = _run(go)
    assert hidden == 2 and after_add == ["d1", "d2"]
    assert out == {"deleted": True, "restored": 2} and after_del == 0
    assert missing == {"deleted": False, "restored": 0}


def test_dismissing_from_the_ui_stores_the_rule_in_mongo_not_the_yaml():
    from app.views import shadow_views

    async def go():
        before = REPO_RULES.read_text()
        f = Finding(detector="rare_persistence", severity="medium", device_name="d1",
                    indicator="d1:run_key:lenovovantage.exe")
        await f.insert()
        await Finding(detector="rare_persistence", severity="medium", device_name="d9",
                      indicator="d1:run_key:lenovovantage.exe-other").insert()
        res = await shadow_views.shadow_decide(f.id, shadow_views.DecisionIn(decision="false_positive", reviewer="t"))
        listed = await shadow_views.shadow_allowlist(limit=500)
        return before, res, listed
    before, res, listed = _run(go)
    assert REPO_RULES.read_text() == before
    assert res["allowlist_rule"] and res["also_hidden"] == 1
    assert any(r["name"] == res["allowlist_rule"] and r["source"] == "ui" for r in listed["rules"])


def test_dismissing_rdp_allowlists_the_pair_not_the_account():
    r = AllowlistEngine.rule_from_finding({"detector": "unusual_remote_logons", "indicator": "rms.a1@rms-nt-admin-09.corp.example.com",
                                           "account_name": "rms.a1", "raw": {"SourceIPs": ["10.51.24.32"]}}, "t", "")
    eng = AllowlistEngine([r])
    assert eng.match({"detector": "unusual_remote_logons", "indicator": "rms.a1@rms-nt-admin-09.corp.example.com"})
    assert not eng.match({"detector": "unusual_remote_logons", "indicator": "rms.a1@prod-db-01.corp.example.com"})
    assert not eng.match({"detector": "unusual_remote_logons", "indicator": "xrms.a1@rms-nt-admin-09.corp.example.com"})
