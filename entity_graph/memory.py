"""Memory store — tiered write (quarantine → curated → golden), decay, recall."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from beanie.odm.operators.find.comparison import In

from entity_graph.models import SCGMemory, MemoryTier, MemoryType

logger = logging.getLogger(__name__)


async def write_memory(
    entity_ids: list[str],
    memory_type: str,
    content: str,
    confidence: float,
    source: str,
    alert_ref: str = "",
    jira_key: str = "",
    tier: str = "quarantine",
    quarantine_reason: str = "",
    alert_type: str = "",
    l1_comment: str = "",
    actor: str = "",
    device: str = "",
) -> SCGMemory | None:
    """Write a new memory to the SCG.

    New memories are always `scope="entity"` (tied to `actor`/`device`) and never
    `auto_fp` — the deterministic actor-allowlist is human-gated and can only be
    turned on by an L2 promote (see promote_memory).
    """
    decay_map = {
        "quarantine": 0.90,
        "curated": 0.90,
        "golden": 0.85,
    }
    try:
        if jira_key:
            existing = await SCGMemory.find_one(SCGMemory.jira_key == jira_key)
            if existing:
                logger.debug("Memory for %s already exists (tier=%s) — skipping duplicate", jira_key, existing.tier.value)
                return existing
        mem = SCGMemory(
            entity_ids=entity_ids,
            memory_type=MemoryType(memory_type),
            content=content,
            confidence=confidence,
            tier=MemoryTier(tier),
            decay_factor=decay_map.get(tier, 0.90),
            source=source,
            alert_ref=alert_ref,
            jira_key=jira_key,
            quarantine_reason=quarantine_reason,
            alert_type=alert_type,
            l1_comment=l1_comment,
            scope="entity",
            actor=actor,
            device=device,
            auto_fp=False,
        )
        await mem.insert()
        logger.info("Memory written: tier=%s source=%s jira=%s", tier, source, jira_key)
        return mem
    except Exception as exc:
        logger.error("write_memory failed: %s", exc)
        return None


async def update_memory_l2_verdict(
    jira_key: str,
    l2_triage_class: str,
    l2_comment: str,
    ai_triage_class: str,
    ai_confidence: float,
    ai_agreed: bool | None,
) -> bool:
    """Enrich a Stage-1 quarantine memory once L2 resolves the ticket.

    Reclassifies tier (curated if AI matched L2, quarantine if not) and
    appends the L2 comment to the content. Returns False if no memory found.

    ``ai_agreed`` must be the caller's already-computed ``shadow.verdict_match`` —
    NOT recomputed here from a naive ``ai_triage_class == l2_triage_class`` string
    match, which this function used to do and which was wrong two ways: (1) it
    credits a WARRANTED escalation (AI said NEEDS_L2, L2 confirmed TP, or L2 closed
    FP off a justification the AI couldn't have seen at triage time — DEMO-106480)
    as a match, which the naive string compare doesn't; (2) an ai_error shadow (agent
    exception, no tool calls, ...) holds a deterministic FALLBACK verdict, not a real
    opinion — ``verdict_match`` is deliberately left ``None`` for those so they never
    count as a hit or a miss. The naive compare treated that "no real verdict" case
    as a plain string mismatch and mislabeled an infra failure as an AI-vs-L2
    disagreement in the quarantine queue. ``shadow.verdict_match`` already gets this
    right in one place — recomputing it here let this path drift out of sync with it.
    ``None`` means "nothing to adjudicate" (routes like a warranted match: curated,
    no quarantine_reason) rather than "disagreement".
    """
    from app.database import get_collection
    col = get_collection("eg_memories")
    existing = await col.find_one({"jira_key": jira_key})
    if not existing:
        logger.debug("update_memory_l2_verdict: no memory found for %s", jira_key)
        return False

    _no_real_verdict = ai_agreed is None
    new_tier = "quarantine" if ai_agreed is False else "curated"
    new_confidence = 0.50 if (_no_real_verdict or not ai_agreed) else (ai_confidence + 0.65) / 2

    content = existing.get("content", "")
    content = content.replace("\n[Pending L2 resolution]", "").strip()
    l2_seg = ""
    if l2_comment:
        # Stage 1 already appended the escalation thread head; l2_comment is the FULL
        # thread at close time and re-includes that same escalation block, so a blind
        # append duplicates it (and starts with the L1 text, not the L2 verdict). Keep
        # only the genuinely NEW lines — the L2 resolution's own text — and CAP at 400
        # so a verbose L2 note can't flood the memory / recall context.
        seen = {ln.strip() for ln in content.splitlines() if ln.strip()}
        fresh = [ln for ln in l2_comment.splitlines() if ln.strip() and ln.strip() not in seen]
        if fresh:
            from lib.comment_utils import verdict_aware_truncate
            l2_seg = verdict_aware_truncate("\n".join(fresh), 400)
            content += "\n" + l2_seg

    _reason = (f"AI said {ai_triage_class}, L2 said {l2_triage_class}"
               if ai_agreed is False else "")
    # An L2 promotion owns the tier. Without this a re-score recomputes the tier from
    # AI-vs-human agreement and writes it back over the human's decision — which takes
    # a promoted memory out of recall entirely, since get_playbook_memories and
    # recall_memories both filter tier in [curated, golden]. DEMO-107947 was promoted to
    # a golden playbook precedent and was back in the quarantine queue one poll later.
    # Keep the human's tier/confidence; still refresh the verdict text, and mark a
    # disagreement [FLAGGED] so it surfaces for review instead of silently reversing
    # them. Mirrors the same guard in jira_closure_poller._refresh_verdict_memory.
    _human = bool((existing.get("resolved_by") or "").strip())
    set_fields = {
        "content": content,   # capped preview
        "quarantine_reason": (f"[FLAGGED] {_reason}" if (_human and _reason) else _reason),
    }
    if _human:
        if (existing.get("tier") or "") != new_tier:
            logger.warning(
                "Memory %s re-score would have re-tiered %s -> %s, but it was promoted by "
                "%s — keeping the human tier and flagging instead",
                jira_key, existing.get("tier"), new_tier, existing.get("resolved_by"),
            )
    else:
        set_fields["tier"] = new_tier
        set_fields["confidence"] = new_confidence
    # Dedicated l2_comment field holds the SAME 400-capped L2 resolution text — separate
    # from l1_comment (the L1 handoff) and given priority on recall — but bounded so a
    # verbose L2 comment doesn't flood the agent's recall context.
    if l2_seg:
        set_fields["l2_comment"] = l2_seg

    await col.update_one(
        {"jira_key": jira_key},
        {"$set": set_fields},
    )
    logger.info(
        "Memory L2 update %s: ai=%s l2=%s agreed=%s → tier=%s conf=%.2f",
        jira_key, ai_triage_class, l2_triage_class, ai_agreed, new_tier, new_confidence,
    )
    return True


async def promote_memory(
    memory_id: str,
    resolved_by: str = "",
    scope: str | None = None,
    auto_fp: bool | None = None,
    apps: list[str] | None = None,
) -> bool:
    """Promote a quarantined memory to golden tier (L2 approved).

    Scope defaults to "entity" (actor/device-specific — recalled only on match).
    Pass scope="playbook" to widen it into a generalizable lesson surfaced type-wide,
    or auto_fp=True to arm the deterministic actor-allowlist short-circuit. auto_fp is
    only honoured for entity-scoped memories that carry an `actor` — a type-wide
    auto-close would be exactly the over-suppression we are trying to prevent.

    ``apps`` records WHICH cloud app the verdict covers (e.g. ["slack"]) for
    Netskope/CASB alerts. Before this the app existed only inside the analyst's prose
    ("approved applications such as Slack" — DEMO-107886), so recall could not tell
    "bulk upload to Slack is fine" apart from "bulk upload anywhere is fine". Stored
    lowercased/de-duped so matching does not hinge on how the analyst typed it.
    """
    from beanie import PydanticObjectId
    from app.database import get_collection
    try:
        oid = PydanticObjectId(memory_id)
        col = get_collection("eg_memories")
        doc = await col.find_one({"_id": oid}, {"confidence": 1, "actor": 1, "scope": 1})
        if not doc:
            logger.warning("promote_memory: id %s not found", memory_id)
            return False
        new_conf = min(0.95, (doc.get("confidence") or 0.5) + 0.15)
        set_fields = {
            "tier": "golden",
            "confidence": new_conf,
            "resolved_by": resolved_by,
            "resolved_at": datetime.utcnow(),
        }
        eff_scope = scope if scope in ("entity", "playbook") else (doc.get("scope") or "entity")
        set_fields["scope"] = eff_scope
        if apps is not None:
            set_fields["apps"] = list(dict.fromkeys(
                str(a).strip().lower() for a in apps if str(a).strip()
            ))
        if auto_fp is not None:
            # Guard: only entity-scoped memories with a concrete actor may auto-close.
            set_fields["auto_fp"] = bool(auto_fp) and eff_scope == "entity" and bool(doc.get("actor"))
        result = await col.update_one({"_id": oid}, {"$set": set_fields})
        return result.modified_count == 1
    except Exception as exc:
        logger.error("promote_memory(%s) failed: %s", memory_id, exc)
        return False


def _norm_principal(name: str) -> set[str]:
    """Normalize a principal into the set of forms we'll compare on.

    Actors arrive in many shapes — `DOMAIN\\svc`, `svc@corp.com`, `NT SERVICE\\X`,
    bare `svc`. We compare on the lowercased full string AND the "leaf" (part after
    the last backslash / before the @) so `CORP\\nilesh.dosi` matches `nilesh.dosi`.
    """
    if not name:
        return set()
    n = name.strip().lower()
    forms = {n}
    if "\\" in n:
        forms.add(n.rsplit("\\", 1)[-1])
    if "@" in n:
        forms.add(n.split("@", 1)[0])
    return {f for f in forms if f}


async def match_actor_allowlist(
    alert_type: str, actor: str, device: str = "", commands: list[str] | None = None,
    apps: list[str] | None = None,
) -> dict | None:
    """Deterministic actor-allowlist lookup for the pipeline short-circuit.

    Returns the matching golden `auto_fp` memory (as a dict) when the live alert's
    actor — and device/commands, if the memory pinned them — matches an L2-armed
    allowlist entry for this alert type. Returns None otherwise. This is the "hard"
    path: a hit auto-closes the ticket as FP without an LLM call.

    Command narrowing (fail-closed): if the memory pinned `commands`, EVERY
    normalized process in the live alert must be in that set. If the memory pinned
    commands but the live alert has none we could extract, we do NOT match — an
    unverifiable command is treated as a mismatch, never a pass.

    App narrowing (fail-closed, identical rule): if the memory pinned `apps`, EVERY
    app in the live alert must be allowlisted. This is what keeps "bulk upload to
    Slack is expected for this user" from also clearing a bulk upload to a personal
    Drive — without it an app-scoped memory would record the app for humans to read
    while the matcher quietly ignored it.
    """
    if not actor:
        return None
    want_actor = _norm_principal(actor)
    if not want_actor:
        return None
    want_device = (device or "").strip().lower()
    live_cmds = {(c or "").strip().lower() for c in (commands or []) if (c or "").strip()}
    live_apps = {(a or "").strip().lower() for a in (apps or []) if (a or "").strip()}
    try:
        from app.database import get_collection
        col = get_collection("eg_memories")
        query = {"tier": "golden", "auto_fp": True}
        if alert_type:
            # Match this alert type, or a type-agnostic entry (alert_type left blank).
            query["alert_type"] = {"$in": [alert_type, ""]}
        candidates = await col.find(query).sort("confidence", -1).limit(50).to_list(length=50)
        for m in candidates:
            if not (_norm_principal(m.get("actor", "")) & want_actor):
                continue
            mem_device = (m.get("device") or "").strip().lower()
            if mem_device and mem_device != want_device:
                continue  # memory pinned a device and this alert is on a different one
            mem_cmds = {(c or "").strip().lower() for c in (m.get("commands") or []) if (c or "").strip()}
            if mem_cmds:
                # Fail closed: need live commands, and every one must be allowlisted.
                if not live_cmds or not live_cmds.issubset(mem_cmds):
                    continue
            mem_apps = {(a or "").strip().lower() for a in (m.get("apps") or []) if (a or "").strip()}
            if mem_apps:
                # Same fail-closed rule as commands: an unverifiable app is a mismatch.
                if not live_apps or not live_apps.issubset(mem_apps):
                    continue
            return {
                "id": str(m["_id"]),
                "actor": m.get("actor", ""),
                "device": m.get("device", ""),
                "commands": sorted(mem_cmds),
                "apps": sorted(mem_apps),
                "alert_type": m.get("alert_type", ""),
                "confidence": round(m.get("confidence", 0.0), 2),
                "jira_key": m.get("jira_key", ""),
                "content": m.get("content", ""),
                "l1_comment": m.get("l1_comment", ""),
                "l2_comment": m.get("l2_comment", ""),
                "resolved_by": m.get("resolved_by", ""),
            }
    except Exception as exc:
        logger.error("match_actor_allowlist(%s, %s) failed: %s", alert_type, actor, exc)
    return None


async def create_allowlist_memory(
    alert_type: str,
    actor: str,
    device: str = "",
    commands: list[str] | None = None,
    content: str = "",
    jira_key: str = "",
    evidence_jira_keys: list[str] | None = None,
    resolved_by: str = "l2_analyst",
    confidence: float = 0.90,
    alert_name: str = "",
) -> str | None:
    """Arm the actor-allowlist directly by inserting a golden auto_fp memory.

    Used when an L2 approves an AllowlistSuggestion — there is no pre-existing
    quarantine memory to promote, so we create the golden entry from scratch.
    Entity-scoped and actor-required by construction (the same guard promote_memory
    enforces). Returns the new memory id, or None on failure / missing actor.
    """
    actor = (actor or "").strip()
    if not actor:
        logger.warning("create_allowlist_memory refused: no actor")
        return None
    cmds = sorted({(c or "").strip().lower() for c in (commands or []) if (c or "").strip()})
    try:
        keys = evidence_jira_keys or ([jira_key] if jira_key else [])
        body = content or (
            f"L2-armed actor-allowlist for '{alert_type or 'any'}' — actor {actor}"
            + (f" on {device}" if device else "")
            + (f", commands {cmds}" if cmds else "")
            + ". Future matching alerts auto-close as FP with no LLM call."
        )
        if keys:
            body += f" Backed by {len(keys)} FP closure(s): {', '.join(keys[:10])}."
        mem = SCGMemory(
            entity_ids=[],
            memory_type=MemoryType.exception,
            content=body,
            confidence=min(0.95, confidence),
            tier=MemoryTier.golden,
            decay_factor=0.85,
            source="allowlist_suggestion",
            alert_ref=(alert_name or f"Allowlist · {actor}"),
            jira_key=jira_key,
            alert_type=alert_type,
            scope="entity",
            actor=actor,
            device=device,
            commands=cmds,
            auto_fp=True,
            resolved_by=resolved_by,
            resolved_at=datetime.utcnow(),
        )
        await mem.insert()
        logger.info("[ALLOWLIST] armed golden memory %s — actor=%s device=%s cmds=%s type=%s",
                    str(mem.id), actor, device or "any", cmds or "any", alert_type or "any")
        return str(mem.id)
    except Exception as exc:
        logger.error("create_allowlist_memory failed: %s", exc)
        return None


async def set_memory_scope(
    memory_id: str,
    scope: str | None = None,
    auto_fp: bool | None = None,
) -> bool:
    """Edit scope / auto_fp on an existing (golden) memory without re-promoting.

    Lets an L2 arm or disarm the actor-allowlist, or widen/narrow scope, from the
    Golden tab. Same guard as promote: auto_fp only sticks for entity-scoped
    memories that carry an actor.
    """
    from beanie import PydanticObjectId
    from app.database import get_collection
    try:
        oid = PydanticObjectId(memory_id)
        col = get_collection("eg_memories")
        doc = await col.find_one({"_id": oid}, {"actor": 1, "scope": 1, "auto_fp": 1})
        if not doc:
            return False
        set_fields: dict = {}
        eff_scope = scope if scope in ("entity", "playbook") else (doc.get("scope") or "entity")
        if scope in ("entity", "playbook"):
            set_fields["scope"] = scope
        if auto_fp is not None:
            set_fields["auto_fp"] = bool(auto_fp) and eff_scope == "entity" and bool(doc.get("actor"))
        elif scope == "playbook":
            set_fields["auto_fp"] = False  # widening to type-wide disarms any hard auto-close
        if not set_fields:
            return True
        result = await col.update_one({"_id": oid}, {"$set": set_fields})
        return result.matched_count == 1
    except Exception as exc:
        logger.error("set_memory_scope(%s) failed: %s", memory_id, exc)
        return False


async def dismiss_memory(memory_id: str) -> bool:
    """Delete a quarantined memory (L2 rejected it)."""
    try:
        mem = await SCGMemory.get(memory_id)
        if mem:
            await mem.delete()
        return True
    except Exception as exc:
        logger.error("dismiss_memory(%s) failed: %s", memory_id, exc)
        return False


async def flag_memory(memory_id: str) -> bool:
    """Mark a quarantined memory as flagged-for-review (idempotent).

    Uses a partial collection update — NOT SCGMemory.get()+save() — so it never
    re-validates the whole (possibly older-schema) document, which would 500.
    """
    from beanie import PydanticObjectId
    from app.database import get_collection
    try:
        oid = PydanticObjectId(memory_id)
        col = get_collection("eg_memories")
        doc = await col.find_one({"_id": oid}, {"quarantine_reason": 1})
        if not doc:
            logger.warning("flag_memory: id %s not found", memory_id)
            return False
        reason = doc.get("quarantine_reason") or ""
        if not reason.startswith("[FLAGGED]"):
            reason = ("[FLAGGED] " + reason).strip()
        result = await col.update_one({"_id": oid}, {"$set": {"quarantine_reason": reason}})
        return result.matched_count == 1
    except Exception as exc:
        logger.error("flag_memory(%s) failed: %s", memory_id, exc)
        return False


async def recall_memories(
    entity_type: str,
    value: str,
    min_confidence: float = 0.5,
) -> list[dict]:
    """Recall curated + golden memories for an entity."""
    from entity_graph.graph import get_entity
    entity = await get_entity(entity_type, value)
    if not entity:
        return []
    try:
        entity_id = str(entity.id)
        memories = await SCGMemory.find(
            In(SCGMemory.entity_ids, [entity_id]),
            SCGMemory.confidence >= min_confidence,
            In(SCGMemory.tier, [MemoryTier.curated, MemoryTier.golden]),
        ).sort(-SCGMemory.confidence).to_list()
        return [
            {
                "id": str(m.id),
                "content": m.content,
                # L2 resolution reasoning — the authoritative verdict, surfaced as its own
                # field (higher priority than content on the allowlist path). Capped at 400
                # so a verbose L2 note can't flood recall (defensive; storage already caps it).
                "l2_comment": (getattr(m, "l2_comment", "") or "")[:400],
                "confidence": round(m.confidence, 2),
                "tier": m.tier.value,
                "source": m.source,
                "memory_type": m.memory_type.value,
                "alert_ref": m.alert_ref,
                "jira_key": m.jira_key,
                "scope": getattr(m, "scope", "entity"),
                "actor": getattr(m, "actor", ""),
                "auto_fp": bool(getattr(m, "auto_fp", False)),
                "created_at": m.created_at.isoformat(),
            }
            for m in memories
        ]
    except Exception as exc:
        logger.error("recall_memories failed: %s", exc)
        return []


async def apply_decay() -> int:
    """Apply monthly confidence decay to all curated/golden memories. Returns count updated."""
    cutoff = datetime.utcnow() - timedelta(days=30)
    count = 0
    try:
        memories = await SCGMemory.find(
            SCGMemory.last_decayed_at <= cutoff,
            In(SCGMemory.tier, [MemoryTier.curated, MemoryTier.golden]),
        ).to_list()
        for mem in memories:
            mem.confidence *= mem.decay_factor
            mem.last_decayed_at = datetime.utcnow()
            if mem.confidence < 0.30:
                await mem.delete()
            else:
                await mem.save()
            count += 1
    except Exception as exc:
        logger.error("apply_decay failed: %s", exc)
    return count


async def demote_memory(memory_id: str) -> bool:
    """Move a golden/curated memory back to quarantine."""
    from beanie import PydanticObjectId
    from app.database import get_collection
    try:
        result = await get_collection("eg_memories").update_one(
            {"_id": PydanticObjectId(memory_id)},
            {"$set": {"tier": "quarantine"}, "$unset": {"resolved_by": "", "resolved_at": ""}},
        )
        return result.matched_count == 1
    except Exception as exc:
        logger.error("demote_memory(%s) failed: %s", memory_id, exc)
        return False


async def count_golden_memories() -> int:
    """True count of curated + golden memories — the authoritative total for the UI
    count (which must NOT be inferred from a paginated list length, or it saturates
    at the page size)."""
    try:
        from app.database import get_collection
        col = get_collection("eg_memories")
        return await col.count_documents({"tier": {"$in": ["curated", "golden"]}})
    except Exception as exc:
        logger.error("count_golden_memories failed: %s", exc)
        return 0


async def get_golden_memories(limit: int = 200, offset: int = 0) -> list[dict]:
    """Return a page of curated + golden memories for L2 review/management.

    `offset` skips rows so the caller can page through the whole set (the list view
    must be able to surface every memory, not just the newest `limit`).
    """
    try:
        from app.database import get_collection
        col = get_collection("eg_memories")
        cursor = col.find(
            {"tier": {"$in": ["curated", "golden"]}},
        ).sort("created_at", -1).skip(max(0, offset)).limit(limit)
        raw_docs = await cursor.to_list(length=limit)
        return [
            {
                "id": str(m["_id"]),
                "content": m.get("content", ""),
                "confidence": round(m.get("confidence", 0.0), 2),
                "tier": m.get("tier", ""),
                "source": m.get("source", ""),
                "memory_type": m.get("memory_type", ""),
                "alert_ref": m.get("alert_ref", ""),
                "jira_key": m.get("jira_key", ""),
                "entity_ids": m.get("entity_ids", []),
                "alert_type": m.get("alert_type", ""),
                "l1_comment": m.get("l1_comment", ""),
                "l2_comment": m.get("l2_comment", ""),
                "scope": m.get("scope", "entity"),
                "actor": m.get("actor", ""),
                "device": m.get("device", ""),
                "commands": m.get("commands", []),
                "apps": m.get("apps", []),
                "auto_fp": bool(m.get("auto_fp", False)),
                "resolved_by": m.get("resolved_by") or "",
                "resolved_at": m["resolved_at"].isoformat() if m.get("resolved_at") else None,
                "created_at": m["created_at"].isoformat() if m.get("created_at") else None,
            }
            for m in raw_docs
        ]
    except Exception as exc:
        logger.error("get_golden_memories failed: %s", exc)
        return []


async def get_quarantined_memories(limit: int = 50) -> list[dict]:
    """Return memories awaiting L2 review.

    Carries `resolved_by`/`resolved_at`: a quarantined row that already has them was
    PROMOTED by a human at some point and has come back. An L2 working this queue
    needs to see "you already ruled on this" rather than meeting it as a fresh
    conflict — and it is how a previously-promoted memory that got demoted is found.
    """
    try:
        memories = await SCGMemory.find(
            SCGMemory.tier == MemoryTier.quarantine,
        ).sort(-SCGMemory.created_at).limit(limit).to_list()
        return [
            {
                "id": str(m.id),
                "content": m.content,
                "confidence": round(m.confidence, 2),
                "source": m.source,
                "memory_type": m.memory_type.value,
                "alert_ref": m.alert_ref,
                "jira_key": m.jira_key,
                "quarantine_reason": m.quarantine_reason,
                "entity_ids": m.entity_ids,
                "alert_type": m.alert_type,
                "l1_comment": m.l1_comment,
                "l2_comment": getattr(m, "l2_comment", ""),
                "scope": getattr(m, "scope", "entity"),
                "actor": getattr(m, "actor", ""),
                "device": getattr(m, "device", ""),
                "commands": list(getattr(m, "commands", []) or []),
                "apps": list(getattr(m, "apps", []) or []),
                "auto_fp": bool(getattr(m, "auto_fp", False)),
                "resolved_by": getattr(m, "resolved_by", "") or "",
                "resolved_at": (getattr(m, "resolved_at", None).isoformat()
                                if getattr(m, "resolved_at", None) else None),
                "created_at": m.created_at.isoformat(),
            }
            for m in memories
        ]
    except Exception as exc:
        logger.error("get_quarantined_memories failed: %s", exc)
        return []
