"""Shared MongoDB client — single cached pymongo connection pool.

Used by the RAPTOR stores that write via raw pymongo (epoch-float timestamps):
edr_triage_processed, edr_triage_rules, edr_triage_observations,
edr_analyst_roles, bedrock_usage.
"""
from __future__ import annotations

from pymongo import MongoClient
from pymongo.collection import Collection

_client_cache: MongoClient | None = None


def _client() -> MongoClient:
    global _client_cache
    if _client_cache is None:
        from lib.config import get_config
        cfg = get_config()
        _client_cache = MongoClient(cfg.mongodb_uri, serverSelectionTimeoutMS=3000)
    return _client_cache


def get_col(name: str) -> Collection:
    from lib.config import get_config
    cfg = get_config()
    return _client()[cfg.mongodb_db][name]
