"""
Database connection — MongoDB (Motor + Beanie).
Initialized at app startup using config (env or Secrets Manager).

RAPTOR edition: only the Security Context Graph (SCG) documents are Beanie-managed.
The triage stores (edr_triage_processed, edr_triage_rules, bedrock_usage, …) use
raw pymongo via lib.mongo.get_col and need no registration here.
"""
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie

from lib.config import get_config
from entity_graph.models import (
    SCGEntity,
    SCGRelationship,
    SCGMemory,
    AnalystProfile,
    ShadowResult,
    PlaybookSuggestion,
    AllowlistSuggestion,
    PlannedActivity,
    AlertUnderTest,
)

_client: AsyncIOMotorClient | None = None


async def init_db() -> None:
    config = get_config()
    global _client
    _client = AsyncIOMotorClient(config.mongodb_uri)
    database = _client[config.mongodb_db]
    await init_beanie(
        database=database,
        document_models=[
            SCGEntity,
            SCGRelationship,
            SCGMemory,
            AnalystProfile,
            ShadowResult,
            PlaybookSuggestion,
            AllowlistSuggestion,
            PlannedActivity,
            AlertUnderTest,
        ],
    )


async def close_db() -> None:
    global _client
    if _client:
        _client.close()
        _client = None


def get_collection(name: str):
    """Return the raw motor collection by name — bypasses Beanie for direct updates."""
    config = get_config()
    return _client[config.mongodb_db][name]
