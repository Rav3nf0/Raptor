"""MongoDB init for the standalone shadow-hunter service.

The main app (app/database.py) adds Finding + AuditLog to its own Beanie
init so API routes work.  This module is only used by the standalone
services/shadow_hunter/main.py worker.
"""
from __future__ import annotations

import os

from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie

_client: AsyncIOMotorClient | None = None


async def init_db() -> None:
    global _client
    from shadow_hunter.models import AuditLog, Finding, Story  # noqa: F401

    uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
    db_name = os.environ.get("MONGODB_DB", "deepintel")

    _client = AsyncIOMotorClient(uri)
    await init_beanie(
        database=_client[db_name],
        document_models=[Finding, AuditLog, Story],
    )


async def close_db() -> None:
    global _client
    if _client:
        _client.close()
        _client = None
