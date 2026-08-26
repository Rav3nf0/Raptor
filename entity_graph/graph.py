"""SCG graph operations — upsert entities and relationships."""
from __future__ import annotations

import logging
from datetime import datetime

from entity_graph.models import SCGEntity, SCGRelationship, EntityType

logger = logging.getLogger(__name__)


async def upsert_entity(
    entity_type: str,
    value: str,
    source_system: str = "",
    tags: list[str] | None = None,
    risk_delta: float = 0.0,
) -> SCGEntity | None:
    """Upsert an entity. Returns the entity doc (created or updated)."""
    if not value or not value.strip():
        return None
    value = value.strip().lower() if entity_type in ("domain", "user", "ip", "device") else value.strip()
    try:
        entity = await SCGEntity.find_one(
            SCGEntity.entity_type == entity_type,
            SCGEntity.value == value,
        )
        now = datetime.utcnow()
        if entity is None:
            entity = SCGEntity(
                entity_type=EntityType(entity_type),
                value=value,
                first_seen=now,
                last_seen=now,
                source_systems=[source_system] if source_system else [],
                tags=tags or [],
                risk_score=max(0.0, min(100.0, risk_delta)),
                alert_count=1,
            )
            await entity.insert()
        else:
            entity.last_seen = now
            entity.alert_count += 1
            if source_system and source_system not in entity.source_systems:
                entity.source_systems.append(source_system)
            if tags:
                for t in tags:
                    if t not in entity.tags:
                        entity.tags.append(t)
            if risk_delta:
                entity.risk_score = max(0.0, min(100.0, entity.risk_score + risk_delta))
            await entity.save()
        return entity
    except Exception as exc:
        logger.error("upsert_entity(%s, %s) failed: %s", entity_type, value[:40], exc)
        return None


async def upsert_relationship(
    from_id: str,
    to_id: str,
    rel_type: str,
    evidence_ref: str = "",
) -> SCGRelationship | None:
    """Upsert a directed relationship edge between two entity IDs."""
    try:
        rel = await SCGRelationship.find_one(
            SCGRelationship.from_id == from_id,
            SCGRelationship.to_id == to_id,
            SCGRelationship.rel_type == rel_type,
        )
        now = datetime.utcnow()
        if rel is None:
            rel = SCGRelationship(
                from_id=from_id,
                to_id=to_id,
                rel_type=rel_type,
                evidence=[evidence_ref] if evidence_ref else [],
                occurrence_count=1,
                first_seen=now,
                last_seen=now,
            )
            await rel.insert()
        else:
            rel.last_seen = now
            rel.occurrence_count += 1
            if evidence_ref and evidence_ref not in rel.evidence:
                rel.evidence.append(evidence_ref)
            await rel.save()
        return rel
    except Exception as exc:
        logger.error("upsert_relationship(%s->%s %s) failed: %s", from_id[:8], to_id[:8], rel_type, exc)
        return None


async def get_entity(entity_type: str, value: str) -> SCGEntity | None:
    """Look up an entity by type + value."""
    normalized = value.strip().lower() if entity_type in ("domain", "user", "ip", "device") else value.strip()
    try:
        return await SCGEntity.find_one(
            SCGEntity.entity_type == entity_type,
            SCGEntity.value == normalized,
        )
    except Exception as exc:
        logger.error("get_entity(%s, %s) failed: %s", entity_type, value[:40], exc)
        return None
