"""Detector run health: a detector that cannot reach its source must be told apart from a
quiet one. In-memory Mongo.

Run: python -m pytest shadow_hunter/hunter_status_test.py -q
"""
from __future__ import annotations

import asyncio

import pytest
from beanie import init_beanie

AsyncMongoMockClient = pytest.importorskip("mongomock_motor").AsyncMongoMockClient  # dev extra

from shadow_hunter import hunter
from shadow_hunter.detectors.base import Detector
from shadow_hunter.models import AuditLog, Finding


class _Broken(Detector):
    name = "broken_src"

    def kql(self, lookback_hours):
        return ""

    async def fetch(self, defender, lookback_hours=24):
        raise RuntimeError("OSV unreachable — package reputation unknown for this run")

    def to_findings(self, rows):
        return []


class _Fine(_Broken):
    name = "fine_src"

    async def fetch(self, defender, lookback_hours=24):
        return [{"x": 1}]

    def to_findings(self, rows):
        return [{"detector": self.name, "severity": "medium", "device_name": "d", "indicator": "i", "summary": "s"}]


def test_failed_and_ok_runs_are_recorded(monkeypatch):
    monkeypatch.setenv("SHADOW_MODE", "mock")

    async def go():
        await init_beanie(database=AsyncMongoMockClient()["runs_test"], document_models=[Finding, AuditLog])
        bad = await hunter.run_detector(_Broken())
        ok = await hunter.run_detector(_Fine())
        runs = {r["detector"]: r for r in await Finding.get_pymongo_collection().database[hunter.RUNS_COLL]
                .find({}, {"_id": 0}).to_list(length=None)}
        return bad, ok, runs
    bad, ok, runs = asyncio.run(go())
    assert bad == {"inserted": 0, "allowlisted": 0, "skipped_existing": 0}
    assert runs["broken_src"]["ok"] is False and "OSV unreachable" in runs["broken_src"]["error"]
    assert "last_ok" not in runs["broken_src"]
    assert ok["inserted"] == 1 and runs["fine_src"]["ok"] is True and runs["fine_src"]["rows"] == 1
    assert runs["fine_src"]["last_ok"] == runs["fine_src"]["last_run"]
