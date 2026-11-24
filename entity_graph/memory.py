"""Memory store — tiered write (quarantine → curated → golden), decay, recall."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from beanie.odm.operators.find.comparison import In

from entity_graph.models import SCGMemory, MemoryTier, MemoryType

logger = logging.getLogger(__name__)

# Monthly decay per tier. Golden used to decay FASTEST (0.85 vs 0.90), so promoting a
# memory to the most trusted tier shortened its life by about two months. Golden now
# decays slowest. apply_decay() takes the SLOWER of this and a row's stored factor, so
# rows written under the old 0.85 get the new rate without a migration — this can only
# ever slow decay, never speed it up.
TIER_DECAY = {"quarantine": 0.90, "curated": 0.90, "golden": 0.93}

# Below this, a memory is archived rather than deleted.
ARCHIVE_BELOW = 0.30
# Every recall path filters confidence >= this; the deterministic allowlist matcher now
# does too (it used to be the one path that ignored decay until deletion).
RECALL_FLOOR = 0.50


def allowlist_ttl_days() -> int:
    """How long an armed auto_fp entry may close tickets before an L2 must re-arm it."""
    import os
    try:
        return max(1, int(os.getenv("ALLOWLIST_TTL_DAYS", "90")))
    except ValueError:
        return 90


def allowlist_pin_problem(alert_type: str, device: str = "",
                          commands: list[str] | None = None,
                          apps: list[str] | None = None) -> str:
    """Why an auto_fp entry is too broad to arm, or "" if it is acceptable.

    An auto_fp entry closes tickets with no LLM call, no confidence floor and no
    novelty check. Scoped only to an actor, it says "this person's alerts are fine" on
    ANY machine — which is exactly what an attacker holding that account inherits. So
    an entry must name the alert type AND pin at least one thing about the activity
    itself: the device, the processes, or the cloud apps.
    """
    if not (alert_type or "").strip():
        return "no alert type — a type-agnostic entry would close every alert for this actor"
    has_cmds = any((c or "").strip() for c in (commands or []))
    has_apps = any((a or "").strip() for a in (apps or []))
    if not ((device or "").strip() or has_cmds or has_apps):
        return ("pins only the actor — it would close this alert type for them on any "
                "machine; pin a device, commands or apps")
    if (alert_type or "").strip().lower() == "privesc" and not has_cmds:
        # A Root Privesc entry pinned to actor + device would close ANY root command that
        # person runs on that host — `crontab -e` as readily as `su - netra`.
        return "Root Privesc entries must pin the exact commands they clear"
    return ""


def canon_commands(cmds: list[str] | None) -> list[str]:
    """Commands as an allowlist entry stores and matches them: one run of a repeated
    command collapsed to one (the rule joins `su - netra` x3 with ", "), trimmed,
    lowercased, de-duplicated."""
    from edr_triage.privesc_guard import canon
    out: list[str] = []
    for c in cmds or []:
        c = canon(str(c or "")).strip().lower()
        if c and c not in out:
            out.append(c)
    return out


def allowlist_expiry(mem: dict) -> datetime:
    """Effective expiry of an auto_fp entry, including legacy rows with no expires_at."""
    if mem.get("expires_at"):
        return mem["expires_at"]
    armed = mem.get("resolved_at") or mem.get("created_at") or datetime.utcnow()
    return armed + timedelta(days=allowlist_ttl_days())


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
    actors: list[str] | None = None,
) -> SCGMemory | None:
    """Write a new memory to the SCG.

    New memories are always `scope="entity"` (tied to `actor`/`device`) and never
    `auto_fp` — the deterministic actor-allowlist is human-gated and can only be
    turned on by an L2 promote (see promote_memory).

    `actors` is the full actor list for a multi-actor incident (`actor` stays the
    primary) — see SCGMemory.actors. Omitted/empty for a single-actor verdict.
    """
    decay_map = TIER_DECAY
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
            actors=[a for a in (actors or []) if a and a.lower() != (actor or "").lower()],
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
    commands: list[str] | None = None,
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
        doc = await col.find_one({"_id": oid}, {"confidence": 1, "actor": 1, "scope": 1,
                                                "alert_type": 1, "device": 1,
                                                "commands": 1, "apps": 1})
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
        if commands is not None:
            set_fields["commands"] = canon_commands(commands)
        if auto_fp is not None:
            # Guard: only entity-scoped memories with a concrete actor may auto-close.
            arm = bool(auto_fp) and eff_scope == "entity" and bool(doc.get("actor"))
            if arm:
                _why = allowlist_pin_problem(
                    doc.get("alert_type", ""), doc.get("device", ""),
                    set_fields["commands"] if commands is not None else doc.get("commands"),
                    apps if apps is not None else doc.get("apps"))
                if _why:
                    # Still promoted to golden (the recall value stands) — only the
                    # auto-close is refused, and the reason is recorded on the row.
                    logger.warning("promote_memory(%s): NOT arming auto_fp — %s", memory_id, _why)
                    set_fields["quarantine_reason"] = f"[AUTO-FP REFUSED] {_why}"
                    arm = False
            set_fields["auto_fp"] = arm
            if arm:
                set_fields["expires_at"] = datetime.utcnow() + timedelta(days=allowlist_ttl_days())
        result = await col.update_one({"_id": oid}, {"$set": set_fields})
        return result.modified_count == 1
    except Exception as exc:
        logger.error("promote_memory(%s) failed: %s", memory_id, exc)
        return False


def _norm_principal(name: str) -> set[str]:
    """Normalize a principal into the set of forms we'll compare on.

    Actors arrive in many shapes — `DOMAIN\\svc`, `svc@corp.com`, `NT SERVICE\\X`,
    bare `svc`. We compare on the lowercased full string AND the "leaf" (part after
    the last backslash / before the @) so `CORP\\victor.dosi` matches `victor.dosi`.
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
    apps: list[str] | None = None, instances: list[str] | None = None,
    direction: str = "",
    full_commands: list[str] | None = None,
) -> dict | None:
    """Deterministic actor-allowlist lookup for the pipeline short-circuit.

    ``full_commands`` are the alert's whole command lines (``commands`` are executable
    basenames). A pinned entry matches when EVERY live basename is pinned, or EVERY live
    full command is (canon_commands) — so an entry pinned to `su - netra` clears that
    command and never `su - root`, while legacy basename-pinned entries match as before.

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
    live_full = set(canon_commands(full_commands))
    live_apps = {(a or "").strip().lower() for a in (apps or []) if (a or "").strip()}
    live_insts = {(a or "").strip().lower() for a in (instances or []) if (a or "").strip()}
    try:
        from app.database import get_collection
        col = get_collection("eg_memories")
        if not alert_type:
            return None   # a type-agnostic match is exactly what allowlist_pin_problem forbids
        # Exact alert type only — blank-type entries no longer match anything. The recall
        # floor applies here too: this path used to ignore decay entirely until deletion.
        query = {"tier": "golden", "auto_fp": True, "alert_type": alert_type,
                 "confidence": {"$gte": RECALL_FLOOR}}
        candidates = await col.find(query).sort(
            [("confidence", -1), ("created_at", -1)]).limit(50).to_list(length=50)
        _now = datetime.utcnow()
        for m in candidates:
            # Legacy rows armed before the pin rule existed: refuse at match time too, so
            # an actor-only entry already in production stops closing on deploy.
            if allowlist_pin_problem(m.get("alert_type", ""), m.get("device", ""),
                                     m.get("commands"), m.get("apps")):
                continue
            if allowlist_expiry(m) <= _now:
                continue
            if not (_norm_principal(m.get("actor", "")) & want_actor):
                continue
            mem_device = (m.get("device") or "").strip().lower()
            if mem_device and mem_device != want_device:
                continue  # memory pinned a device and this alert is on a different one
            mem_cmds = {(c or "").strip().lower() for c in (m.get("commands") or []) if (c or "").strip()}
            if mem_cmds:
                # Fail closed: need live commands, and every one must be allowlisted.
                if not ((live_cmds and live_cmds.issubset(mem_cmds))
                        or (live_full and live_full.issubset(mem_cmds))):
                    continue
            mem_apps = {(a or "").strip().lower() for a in (m.get("apps") or []) if (a or "").strip()}
            if mem_apps:
                # Same fail-closed rule as commands: an unverifiable app is a mismatch.
                if not live_apps or not live_apps.issubset(mem_apps):
                    continue
            mem_dir = (m.get("uba_direction") or "").strip().lower()
            if mem_dir and mem_dir != (direction or "").strip().lower():
                continue  # a download approval never clears an upload, and vice versa
            mem_insts = {(a or "").strip().lower()
                         for a in (m.get("app_instances") or []) if (a or "").strip()}
            if mem_insts:
                # And the same again for the app's ACCOUNT: a company-Slack approval must
                # never clear a personal-Slack upload, and an unrecorded account is a miss.
                if not live_insts or not live_insts.issubset(mem_insts):
                    continue
            return {
                "id": str(m["_id"]),
                "actor": m.get("actor", ""),
                "device": m.get("device", ""),
                "commands": sorted(mem_cmds),
                "apps": sorted(mem_apps),
                "app_instances": sorted(mem_insts),
                "uba_direction": mem_dir,
                "uba_baseline": m.get("uba_baseline") or {},
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
    apps: list[str] | None = None,
    app_instances: list[str] | None = None,
    uba_direction: str = "",
    uba_baseline: dict | None = None,
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
    _apps = sorted({(a or "").strip().lower() for a in (apps or []) if (a or "").strip()})
    _insts = sorted({(a or "").strip().lower() for a in (app_instances or []) if (a or "").strip()})
    _why = allowlist_pin_problem(alert_type, device, cmds, _apps)
    if _why:
        logger.warning("create_allowlist_memory refused for %s: %s", actor, _why)
        return None
    try:
        keys = evidence_jira_keys or ([jira_key] if jira_key else [])
        body = content or (
            f"L2-armed actor-allowlist for '{alert_type or 'any'}' — actor {actor}"
            + (f" on {device}" if device else "")
            + (f", commands {cmds}" if cmds else "")
            + (f", apps {_apps}" if _apps else "")
            + (f" on account(s) {_insts}" if _insts else "")
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
            decay_factor=TIER_DECAY["golden"],
            source="allowlist_suggestion",
            alert_ref=(alert_name or f"Allowlist · {actor}"),
            jira_key=jira_key,
            alert_type=alert_type,
            scope="entity",
            actor=actor,
            device=device,
            commands=cmds,
            apps=_apps,
            app_instances=_insts,
            uba_direction=(uba_direction or "").strip().lower(),
            uba_baseline=dict(uba_baseline or {}),
            auto_fp=True,
            resolved_by=resolved_by,
            resolved_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=allowlist_ttl_days()),
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
        ).sort(-SCGMemory.confidence, -SCGMemory.created_at).to_list()
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
    """Monthly confidence decay for curated/golden memories. Returns rows touched.

    Two changes from the original:

      * ARCHIVE, don't delete. A row that decays below ARCHIVE_BELOW used to be deleted,
        which silently erased an L2-approved decision and the audit trail of why tickets
        were closed on it. It now moves to tier=archived, auto_fp off — inert on every
        retrieval path, still readable.
      * Expired allowlist entries are archived here too, so the Golden tab stops showing
        an entry that the matcher already refuses to fire.

    The factor used is the SLOWER of the row's stored factor and TIER_DECAY for its
    tier, so golden rows written at the old 0.85 pick up the new rate without a
    migration.
    """
    cutoff = datetime.utcnow() - timedelta(days=30)
    now = datetime.utcnow()
    count = 0
    try:
        memories = await SCGMemory.find(
            SCGMemory.last_decayed_at <= cutoff,
            In(SCGMemory.tier, [MemoryTier.curated, MemoryTier.golden]),
        ).to_list()
        for mem in memories:
            factor = max(mem.decay_factor or 0.0, TIER_DECAY.get(mem.tier.value, 0.90))
            mem.confidence *= factor
            mem.last_decayed_at = now
            if mem.confidence < ARCHIVE_BELOW:
                _archive(mem, f"decayed below {ARCHIVE_BELOW:.2f}")
            await mem.save()
            count += 1
        # Allowlist entries past expiry, independent of the 30-day decay cadence.
        expired = await SCGMemory.find(
            SCGMemory.tier == MemoryTier.golden, SCGMemory.auto_fp == True,  # noqa: E712
        ).to_list()
        for mem in expired:
            if allowlist_expiry(mem.model_dump()) <= now:
                _archive(mem, "allowlist entry expired — re-arm if it still holds")
                await mem.save()
                count += 1
    except Exception as exc:
        logger.error("apply_decay failed: %s", exc)
    return count


_SELF_VERDICT_WHY = ("RAPTOR's own auto-close was recorded as an analyst verdict (closure "
                     "poller before 69bd294, 2026-09-30) — no human reviewed this ticket")


def is_raptor_self_verdict(mem, shadow) -> bool:
    """A curated 'analyst' memory that is really RAPTOR's own unreviewed close.

    Before 69bd294 the closure poller read a bot-authored `-> False Positive` as an L1
    verdict that agreed with the AI, and wrote it as curated, source=analyst, conf ~0.8.
    Those rows then came back to the agent as analyst precedent for the next close.
    Golden rows are left alone (a human promoted them), as is anything a human
    commented on or reopened. `l2_resolved_at` is NOT a human signal here: that same
    poller stamped it when it filed the bot's close as an L1 resolution.
    """
    if shadow is None or getattr(mem, "tier", None) != MemoryTier.curated:
        return False
    if getattr(mem, "memory_type", None) != MemoryType.analyst_verdict:
        return False
    if (getattr(mem, "l1_comment", "") or "").strip() or (getattr(mem, "l2_comment", "") or "").strip():
        return False
    return bool(getattr(shadow, "autonomous_closed_at", None)
                and not getattr(shadow, "reopened_at", None))


async def archive_raptor_self_verdicts(apply: bool = False) -> dict:
    """Find (and with apply=True, archive) curated memories that are RAPTOR's own closes.

    Archived, not deleted: inert on every recall path, and a later human close of the
    same ticket refreshes the row back into a trusted tier through the normal path.
    """
    from entity_graph.models import ShadowResult

    mems = await SCGMemory.find(
        SCGMemory.tier == MemoryTier.curated,
        SCGMemory.memory_type == MemoryType.analyst_verdict,
    ).to_list()
    hits = []
    for mem in mems:
        if not mem.jira_key:
            continue
        shadow = await (ShadowResult.find(ShadowResult.jira_key == mem.jira_key)
                        .sort(-ShadowResult.created_at).first_or_none())
        if not is_raptor_self_verdict(mem, shadow):
            continue
        hits.append({"memory_id": str(mem.id), "jira_key": mem.jira_key,
                     "alert_type": mem.alert_type, "confidence": mem.confidence})
        if apply:
            _archive(mem, _SELF_VERDICT_WHY)
            await mem.save()
    return {"applied": apply, "scanned": len(mems), "matched": len(hits), "memories": hits}


def _archive(mem: SCGMemory, why: str) -> None:
    mem.tier = MemoryTier.archived
    mem.auto_fp = False
    mem.archived_at = datetime.utcnow()
    mem.quarantine_reason = f"[ARCHIVED] {why}"
    logger.info("memory %s (%s) archived: %s", mem.id, mem.jira_key or "-", why)


def _covers(mem: dict, actor: str, device: str) -> bool:
    """Does this memory speak about this actor (and, if it pinned one, this device)?"""
    if not (_norm_principal(mem.get("actor", "")) & _norm_principal(actor)):
        return False
    pinned = (mem.get("device") or "").strip().lower()
    return not pinned or pinned == (device or "").strip().lower()


async def reconcile_human_verdict(alert_types: list[str], actor: str, device: str,
                                  human_class: str, jira_key: str) -> dict:
    """Feed a HUMAN terminal verdict back into the memories that speak about it.

    Decay was purely time-based: a pattern L2 confirmed twenty times this month aged
    exactly like one nobody had seen since June. So:

      * human says FP  -> REFRESH matching curated/golden memories (reset the decay
        clock). Freshness only — confidence is not raised, so repeated confirmation
        cannot inflate a memory past what an L2 set.
      * human says TP  -> DEMOTE any armed auto_fp entry for this actor + alert type to
        quarantine, auto_fp off. A human just called a real incident on the exact scope
        the entry asserts is always benign; waiting months for decay to catch up would
        leave it closing tickets in the meantime.

    The CALLER must establish that the verdict is a human's. RAPTOR's own closes must
    never reach here, or every autonomous close would reinforce the memory that caused
    it — a self-validating loop. Returns counts for logging.

    `alert_types` is a LIST because memories live under two namespaces: verdict
    memories under memory_alert_type (e.g. netskope_dlp) and allowlist entries under
    alert_subtype (e.g. netskope). Looking under only one would silently miss the other.
    """
    out = {"refreshed": 0, "demoted": 0}
    types = sorted({t for t in (alert_types or []) if t and t != "skip"})
    if not (types and actor and human_class in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP")):
        return out
    from app.database import get_collection
    col = get_collection("eg_memories")
    now = datetime.utcnow()
    try:
        if human_class == "AUTO_CLOSED_FP":
            cur = col.find({"alert_type": {"$in": types},
                            "tier": {"$in": ["curated", "golden"]},
                            "jira_key": {"$ne": jira_key}})
            async for m in cur:
                if _covers(m, actor, device):
                    await col.update_one({"_id": m["_id"]}, {"$set": {"last_decayed_at": now}})
                    out["refreshed"] += 1
        else:
            cur = col.find({"alert_type": {"$in": types}, "tier": "golden", "auto_fp": True})
            async for m in cur:
                if _covers(m, actor, device):
                    await col.update_one({"_id": m["_id"]}, {"$set": {
                        "tier": "quarantine", "auto_fp": False,
                        "quarantine_reason": (f"[CONTRADICTED] {jira_key} was closed as a "
                                              f"true positive for {actor} — auto-close "
                                              "disarmed pending L2 review"),
                    }})
                    out["demoted"] += 1
                    logger.warning("allowlist memory %s disarmed: %s closed TP for %s",
                                   m["_id"], jira_key, actor)
    except Exception as exc:
        logger.error("reconcile_human_verdict(%s) failed: %s", jira_key, exc)
    return out


async def demote_on_overturn(memory_id: str, jira_key: str, reopened_by: str) -> bool:
    """A close that an allowlist entry caused was reopened by a human — disarm it now."""
    from beanie import PydanticObjectId
    from app.database import get_collection
    try:
        res = await get_collection("eg_memories").update_one(
            {"_id": PydanticObjectId(memory_id), "auto_fp": True},
            {"$set": {"tier": "quarantine", "auto_fp": False,
                      "quarantine_reason": (f"[OVERTURNED] {reopened_by or 'a human'} reopened "
                                            f"{jira_key}, which this entry auto-closed — "
                                            "disarmed pending L2 review")}})
        if res.modified_count:
            logger.warning("allowlist memory %s disarmed: %s reopened by %s",
                           memory_id, jira_key, reopened_by)
        return bool(res.modified_count)
    except Exception as exc:
        logger.error("demote_on_overturn(%s) failed: %s", memory_id, exc)
        return False


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


def days_until_inert(m: dict, now: datetime | None = None) -> tuple[int, str]:
    """(days, kind) until this memory stops influencing triage.

    kind="allowlist": an armed auto_fp entry reaching its hard expiry.
    kind="recall":    decay taking confidence below RECALL_FLOOR, after which no
                      prompt path retrieves it. Decay steps every 30 days from
                      last_decayed_at at the slower of the stored and tier factor —
                      the same arithmetic apply_decay() uses.
    Shown on the Golden tab so L2 can re-validate what still holds BEFORE it drops out,
    instead of discovering months later that a pattern quietly stopped applying.
    """
    import math
    now = now or datetime.utcnow()
    if m.get("auto_fp"):
        return max(0, (allowlist_expiry(m) - now).days), "allowlist"
    conf = float(m.get("confidence") or 0.0)
    if conf < RECALL_FLOOR:
        return 0, "recall"
    f = max(float(m.get("decay_factor") or 0.0), TIER_DECAY.get(m.get("tier", ""), 0.90))
    if f >= 1.0:
        return 10_000, "recall"
    steps = max(1, math.floor(math.log(RECALL_FLOOR / conf) / math.log(f)) + 1)
    last = m.get("last_decayed_at") or m.get("created_at") or now
    return max(0, (last + timedelta(days=30 * steps) - now).days), "recall"


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
                "expires_in_days": days_until_inert(m)[0],
                "expiry_kind": days_until_inert(m)[1],
            }
            for m in raw_docs
        ]
    except Exception as exc:
        logger.error("get_golden_memories failed: %s", exc)
        return []


async def get_quarantine_counts_by_type() -> dict:
    """TRUE quarantine count per alert_type, independent of any page limit.

    The review queue fetches a capped page of newest-first rows, so a high-volume
    alert family can fill that page and make every other family invisible — and the
    UI's type filter was populated FROM that page, so the starved families were not
    even selectable. These counts come from the whole collection, so the filter can
    offer every bucket that actually exists and show how big each really is.

    Returns {"counts": {alert_type: n, ...}, "total": n}.
    """
    try:
        coll = SCGMemory.get_pymongo_collection()
        rows = await coll.aggregate([
            {"$match": {"tier": MemoryTier.quarantine.value}},
            {"$group": {"_id": "$alert_type", "n": {"$sum": 1}}},
            {"$sort": {"n": -1}},
        ]).to_list(length=None)
        counts = {(r["_id"] or "(none)"): r["n"] for r in rows}
        return {"counts": counts, "total": sum(counts.values())}
    except Exception as exc:
        logger.error("get_quarantine_counts_by_type failed: %s", exc)
        return {"counts": {}, "total": 0}


async def _verdict_pairs(jira_keys: list[str]) -> dict[str, tuple[str, str, str, bool]]:
    """{jira_key: (ai_verdict, l1_verdict, l2_verdict)} for the given tickets.

    Batched deliberately — one query for the whole page, not one per row. None of this is
    on SCGMemory (the verdicts appear only inside the free-text `content`), and parsing
    them out of prose would break the first time the caption wording changes.

    L1 and L2 are returned SEPARATELY rather than collapsed into one "human verdict",
    because which one you compare against depends on the question being asked. See
    `_disagrees_with_l1`.
    """
    if not jira_keys:
        return {}
    # Only the five fields read here, in chunks: the disagreement count now covers the
    # whole queue (1,300+ rows), and a full ShadowResult carries every tool output —
    # loading them all would not fit the 256 MiB pod. Oldest first, so a re-triage's
    # newer row wins for a ticket that has more than one.
    _fields = {"jira_key": 1, "ai_triage_class": 1, "l1_triage_class": 1,
               "l2_triage_class": 1, "l1_awaiting_inputs_at": 1, "_id": 0}
    keys = list(dict.fromkeys(k for k in jira_keys if k))
    out: dict[str, tuple[str, str, str, bool]] = {}
    try:
        from entity_graph.models import ShadowResult
        col = ShadowResult.get_pymongo_collection()
        for i in range(0, len(keys), 500):
            rows = await col.find({"jira_key": {"$in": keys[i:i + 500]}}, _fields
                                  ).sort("created_at", 1).to_list(length=None)
            for r in rows:
                out[r["jira_key"]] = (
                    r.get("ai_triage_class") or "",
                    r.get("l1_triage_class") or "",
                    r.get("l2_triage_class") or "",
                    bool(r.get("l1_awaiting_inputs_at")),
                )
    except Exception as exc:
        logger.warning("_verdict_pairs failed: %s", exc)
        return {}
    return out


def _disagrees_with_l1(ai: str, l1: str, l1_asked: bool = False) -> bool:
    """True only when the agent and L1 both decided, and decided differently.

    Compared against L1 SPECIFICALLY, not against the final L2 verdict, because the
    programme is to replace L1: a ticket where the agent said NEEDS_L2 and L1 also
    escalated is a SUCCESS for that purpose even if L2 later closed it FP. Those rows are
    not review work — the agent did what the L1 it replaces would have done.

    Two exclusions this makes, both of which are the bulk of the queue:
      * ai == l1 (most often NEEDS_L2 == NEEDS_L2) — agreement that reads as a conflict.
      * l1 absent — nobody has decided yet, so there is nothing to disagree with. Every
        memory is written at tier=quarantine and only graduates once the ticket resolves
        with the AI agreeing, so unresolved tickets dominate the raw count.

    NOTE: this is a REVIEW-QUEUE filter. It does not change the accuracy metric, which
    still scores against the terminal human verdict (L2 where present). Re-basing that
    metric onto L1 would raise the number without the agent changing, and is a separate
    decision that is not ours to make as a side effect of a filter.
    """
    # L1 moving the ticket to AWAITING MORE INPUTS is a decision — "ask the user" — and
    # it is not captured by l1_triage_class, which only records escalate-or-close. An
    # agent that also said REQUEST_JUSTIFICATION made the same call, so this is NOT review
    # work. Without this the queue shows every RJ row as a conflict with L1 even where L1
    # opened the same justification loop.
    if ai == "REQUEST_JUSTIFICATION" and l1_asked:
        return False
    return bool(ai) and bool(l1) and ai != l1


async def get_quarantined_memories(limit: int = 50, alert_type: str = "",
                                   disagreement_only: bool = False,
                                   with_total: bool = False) -> list[dict] | dict:
    """Return memories awaiting L2 review.

    Carries `resolved_by`/`resolved_at`: a quarantined row that already has them was
    PROMOTED by a human at some point and has come back. An L2 working this queue
    needs to see "you already ruled on this" rather than meeting it as a fresh
    conflict — and it is how a previously-promoted memory that got demoted is found.

    `alert_type` scopes the page SERVER-side. Without it, one high-volume family
    (Netskope DLP is the one that prompted this) fills the page and starves every
    other family out of the queue — client-side filtering cannot recover rows the
    server never sent. Empty string keeps the previous unfiltered behaviour exactly.

    `with_total=True` returns {"memories": [...], "total": n} instead of the bare list,
    where n is the number of rows matching the filter across the WHOLE queue, not the page.
    """
    total = None
    try:
        _q = [SCGMemory.tier == MemoryTier.quarantine]
        if alert_type:
            _q.append(SCGMemory.alert_type == alert_type)
        if disagreement_only:
            # The filter needs the ShadowResult verdicts, which Mongo cannot join on here,
            # so it runs in Python over EVERY quarantined row (id + key only), and only
            # the page is then loaded in full. It used to over-fetch the newest 600 and
            # filter those, so older disagreements never appeared and the page showed
            # ~95 of the 520 that existed (quarantine audit 2026-10-12).
            _match = {"tier": MemoryTier.quarantine.value}
            if alert_type:
                _match["alert_type"] = alert_type
            heads = await SCGMemory.get_pymongo_collection().find(
                _match, {"jira_key": 1}).sort("created_at", -1).to_list(length=None)
            _pairs = await _verdict_pairs([h.get("jira_key") for h in heads])
            _hit = [h["_id"] for h in heads
                    if h.get("jira_key") in _pairs
                    and _disagrees_with_l1(_pairs[h["jira_key"]][0], _pairs[h["jira_key"]][1],
                                           _pairs[h["jira_key"]][3])]
            total = len(_hit)
            _page = _hit[:limit]
            _by_id = {m.id: m for m in await SCGMemory.find(In(SCGMemory.id, _page)).to_list()}
            memories = [_by_id[i] for i in _page if i in _by_id]
        else:
            memories = await SCGMemory.find(
                *_q,
            ).sort(-SCGMemory.created_at).limit(limit).to_list()
            _pairs = await _verdict_pairs([m.jira_key for m in memories if m.jira_key])

        def _trio(m):
            return _pairs.get(m.jira_key, ("", "", "", False))

        rows = [
            {
                # The verdicts, on every row whether filtered or not — an L2 working this
                # queue cannot tell a real conflict from a pending agreement without them,
                # and they were previously visible only buried in `content` prose.
                "ai_verdict": _trio(m)[0],
                "l1_verdict": _trio(m)[1],
                "l2_verdict": _trio(m)[2],
                "l1_asked_for_justification": _trio(m)[3],
                "disagrees_with_l1": _disagrees_with_l1(_trio(m)[0], _trio(m)[1],
                                                        _trio(m)[3]),
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
        if with_total:
            return {"memories": rows, "total": total if total is not None else len(rows)}
        return rows
    except Exception as exc:
        logger.error("get_quarantined_memories failed: %s", exc)
        return {"memories": [], "total": 0} if with_total else []
