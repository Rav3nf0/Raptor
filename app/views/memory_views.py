"""Memory views — /memory/quarantine page + action endpoints.

Routes:
    GET  /memory/quarantine                       — quarantine review page (L2)
    GET  /api/memory/quarantine                   — JSON list of quarantined memories
    POST /api/memory/quarantine/{id}/promote      — promote to golden tier
    POST /api/memory/quarantine/{id}/dismiss      — delete memory
    POST /api/memory/quarantine/{id}/flag         — flag for further review
    GET  /api/memory/golden?limit&offset          — page of curated/golden memories + true total
    POST /api/memory/golden/{id}/demote           — move golden memory back to quarantine
    POST /api/memory/golden/{id}/scope            — set scope / arm-disarm actor-allowlist
    DELETE /api/memory/golden/{id}               — permanently delete a golden memory
    GET  /api/memory/shadow-stats                 — AI vs L1 accuracy stats (lifetime)
    GET  /api/memory/pollution                    — memory tier distribution + pollution rate
    GET  /api/memory/overturn-trend               — weekly AI-vs-human accuracy series
    GET  /api/memory/analyst-profiles             — per-analyst escalation-precision profiles
    GET  /api/memory/analysts                     — list analyst role registry
    POST /api/memory/analysts                     — add / update analyst
    DELETE /api/memory/analysts/{email}           — remove analyst
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Body, BackgroundTasks
from fastapi.responses import HTMLResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["memory"])


# ---------------------------------------------------------------------------
# Memory API
# ---------------------------------------------------------------------------

@router.get("/api/memory/quarantine")
async def list_quarantine(limit: int = 50):
    from entity_graph.memory import get_quarantined_memories
    return await get_quarantined_memories(limit=limit)


@router.post("/api/memory/quarantine/{memory_id}/promote")
async def promote(memory_id: str, payload: dict = Body(default={})):
    """Promote a quarantined memory to golden.

    Optional body: {"scope": "entity"|"playbook", "auto_fp": bool, "apps": [str]}.
    scope defaults to "entity" (actor/device-specific). auto_fp arms the deterministic
    actor-allowlist (honoured only for entity-scoped memories that carry an actor).
    apps records the cloud app(s) the verdict covers (e.g. ["Slack"]) for
    Netskope/CASB alerts, so "bulk upload to Slack is expected" is not recalled as
    "bulk upload anywhere is expected".
    """
    from entity_graph.memory import promote_memory
    scope = (payload or {}).get("scope")
    auto_fp = (payload or {}).get("auto_fp")
    apps = (payload or {}).get("apps")
    if isinstance(apps, str):           # tolerate "Slack" or "Slack, Drive"
        apps = [a for a in (p.strip() for p in apps.split(",")) if a]
    ok = await promote_memory(memory_id, resolved_by="l2_analyst", scope=scope,
                              auto_fp=auto_fp, apps=apps)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"ok": True, "memory_id": memory_id, "action": "promoted",
            "scope": scope or "entity", "auto_fp": bool(auto_fp), "apps": apps or []}


@router.post("/api/memory/quarantine/{memory_id}/dismiss")
async def dismiss(memory_id: str):
    from entity_graph.memory import dismiss_memory
    ok = await dismiss_memory(memory_id)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"ok": True, "memory_id": memory_id, "action": "dismissed"}


@router.post("/api/memory/quarantine/{memory_id}/flag")
async def flag(memory_id: str):
    from entity_graph.memory import flag_memory
    ok = await flag_memory(memory_id)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"ok": True, "memory_id": memory_id, "action": "flagged"}


@router.get("/api/memory/poll-debug")
async def poll_debug(lookback_minutes: int = 120):
    """Diagnostic: show raw Jira search results and why each ticket was accepted/skipped."""
    from edr_triage.config import get_edr_config
    cfg = get_edr_config()
    result = {
        "jira_url": cfg.jira_url,
        "jira_email": cfg.jira_email,
        "jira_project_key": cfg.jira_project_key,
        "has_token": bool(cfg.jira_token),
        "lookback_minutes": lookback_minutes,
        "tickets": [],
        "error": None,
    }
    try:
        from edr_triage.jira_closure_poller import _fetch_recently_closed, _TERMINAL_STATES, _SKIP_STATES
        import httpx

        # Primary query — same as the poller uses
        tickets = await _fetch_recently_closed(cfg, lookback_minutes)
        result["raw_count"] = len(tickets)
        for t in tickets:
            fields = t.get("fields", {})
            status = (fields.get("status") or {}).get("name", "")
            result["tickets"].append({
                "key": t.get("key"),
                "summary": (fields.get("summary") or "")[:80],
                "status": status,
                "in_terminal": status.upper() in _TERMINAL_STATES,
                "in_skip": status.upper() in _SKIP_STATES,
                "assignee": (fields.get("assignee") or {}).get("emailAddress", "—"),
                "comment_count": len((fields.get("comment") or {}).get("comments") or []),
            })

        # Broader probe — last 20 SIM tickets regardless of status, to check actual status names
        import httpx as _httpx
        async with _httpx.AsyncClient(
            base_url=cfg.jira_url.rstrip("/"),
            auth=_httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=20.0,
            verify=cfg.jira_verify_ssl,
        ) as client:
            broad_jql = f"project = {cfg.jira_project_key} ORDER BY updated DESC"
            resp = await client.post("/rest/api/3/search/jql", json={
                "jql": broad_jql, "fields": ["summary", "status", "updated"], "maxResults": 20,
            })
            resp.raise_for_status()
            broad_issues = resp.json().get("issues", [])
            result["recent_any_status"] = [
                {
                    "key": i.get("key"),
                    "status": (i.get("fields", {}).get("status") or {}).get("name", ""),
                    "updated": i.get("fields", {}).get("updated", ""),
                    "summary": (i.get("fields", {}).get("summary") or "")[:60],
                }
                for i in broad_issues
            ]
    except Exception as exc:
        result["error"] = str(exc)
    return result


@router.post("/api/memory/rescore/{jira_key}")
async def rescore_ticket(jira_key: str):
    """Re-score ONE ticket by key, bypassing the poller's search window.

    poll-now can only reach what a `updated >= -Nm` search returns before the page cap
    truncates it, so an older ticket is unreachable at any window size. That matters
    because a re-triage clears verdict_match: without this, such a row leaves the
    accuracy denominator and cannot be put back except by having a human comment on the
    Jira ticket to move its `updated`.

    Reads the human verdict only — it never re-runs the agent, so the AI verdict being
    scored is whatever the shadow already holds.
    """
    try:
        from edr_triage.jira_closure_poller import rescore_one
        return await rescore_one(jira_key)
    except Exception as exc:
        logger.exception("rescore failed for %s", jira_key)
        return {"ok": False, "jira_key": jira_key, "error": str(exc)}


@router.post("/api/memory/poll-now")
async def poll_now(lookback_minutes: int = 60):
    """Manually trigger the Jira closure poller with a configurable lookback window.

    Useful after a pod redeploy where recent tickets fell outside the 5-min window.
    """
    try:
        from edr_triage.jira_closure_poller import poll_once
        updated = await poll_once(lookback_minutes=lookback_minutes)
        return {"ok": True, "lookback_minutes": lookback_minutes, "memories_written": updated}
    except Exception as exc:
        logger.exception("poll_now failed")
        raise HTTPException(500, str(exc))


@router.get("/api/memory/golden")
async def list_golden(limit: int = 200, offset: int = 0):
    """A page of curated + golden memories plus the TRUE total.

    `total` is a real `.count()` — the UI count must come from this, not from
    `len(memories)`, which caps at `limit` and misreports once the set exceeds a page.
    The client pages with `offset` to load them all.
    """
    from entity_graph.memory import get_golden_memories, count_golden_memories
    memories = await get_golden_memories(limit=limit, offset=offset)
    total = await count_golden_memories()
    return {"memories": memories, "total": total, "limit": limit, "offset": offset}


@router.post("/api/memory/golden/{memory_id}/demote")
async def demote(memory_id: str):
    from entity_graph.memory import demote_memory
    ok = await demote_memory(memory_id)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"ok": True, "memory_id": memory_id, "action": "demoted"}


@router.post("/api/memory/golden/{memory_id}/scope")
async def set_scope(memory_id: str, payload: dict = Body(default={})):
    """Edit scope / auto_fp on an existing golden memory — arm or disarm the
    actor-allowlist, or widen/narrow scope, without demote+re-promote.

    Body: {"scope": "entity"|"playbook", "auto_fp": bool}.
    """
    from entity_graph.memory import set_memory_scope
    scope = (payload or {}).get("scope")
    auto_fp = (payload or {}).get("auto_fp")
    ok = await set_memory_scope(memory_id, scope=scope, auto_fp=auto_fp)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"ok": True, "memory_id": memory_id, "action": "scope_updated",
            "scope": scope, "auto_fp": auto_fp}


@router.delete("/api/memory/golden/{memory_id}")
async def delete_golden(memory_id: str):
    from entity_graph.memory import dismiss_memory
    ok = await dismiss_memory(memory_id)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"ok": True, "memory_id": memory_id, "action": "deleted"}


@router.get("/api/memory/shadow-stats")
async def shadow_stats():
    from entity_graph.models import ShadowResult
    try:
        total = await ShadowResult.count()
        # Exclude agent-failure shadows (ai_error set — e.g. the Mantle/SCP outage): they
        # hold the playbook fallback verdict, not a real agent decision, so counting them
        # would score the agent for runs it never made.
        resolved = await ShadowResult.find(
            ShadowResult.verdict_match != None, ShadowResult.ai_error == None).count()  # noqa: E711
        matches = await ShadowResult.find(
            ShadowResult.verdict_match == True, ShadowResult.ai_error == None).count()  # noqa: E712
        accuracy = round(matches / resolved, 3) if resolved else None

        # Rolling 30-day accuracy, ALONGSIDE the lifetime figure — never instead of it.
        #
        # Lifetime is a cumulative average over every ticket ever scored, so a bad early
        # week holds the headline down long after the cause is fixed: 2026-W30 alone is
        # 73 tickets at 0.384, on a code path since largely rewritten, and it will dilute
        # every improvement for months. That makes lifetime a poor read on how the system
        # behaves TODAY, which is the question people actually ask of it.
        #
        # The honest fix is a second number, not a smaller denominator. Dropping the old
        # rows was considered and rejected: they are real agent decisions (real tool
        # calls, ~0.9 confidence), so excluding them would be editing the record rather
        # than improving the system — and it moves the figure enormously (excluding the
        # 59 rows that never got a memory row alone takes 0.588 -> 0.757, because those
        # rows are ~all from July and July is when the system did worst). A metric that
        # can be raised 17 points by a definitional change stops being able to report a
        # regression. Same window/exclusions as lifetime; only the date bound differs.
        from datetime import datetime, timedelta
        _cut = datetime.utcnow() - timedelta(days=30)
        resolved_30d = await ShadowResult.find(
            ShadowResult.verdict_match != None, ShadowResult.ai_error == None,  # noqa: E711
            ShadowResult.created_at >= _cut).count()
        matches_30d = await ShadowResult.find(
            ShadowResult.verdict_match == True, ShadowResult.ai_error == None,  # noqa: E712
            ShadowResult.created_at >= _cut).count()

        return {
            "total_shadow_results": total,
            "resolved": resolved,
            "ai_l1_matches": matches,
            "ai_l1_accuracy": accuracy,
            # Rolling window — the read on current behaviour.
            "resolved_30d": resolved_30d,
            "ai_l1_matches_30d": matches_30d,
            "ai_l1_accuracy_30d": round(matches_30d / resolved_30d, 3) if resolved_30d else None,
            "window_days": 30,
        }
    except Exception as exc:
        return {"error": str(exc)}


@router.post("/api/memory/shadow/exclude-alert")
async def exclude_alert_from_accuracy(payload: dict = Body(...)):
    """Retroactively clean up one alert NAME's existing shadows/quarantine rows, AND
    (unless dry_run) register it on the standing AlertUnderTest list so every FUTURE
    ticket for this alert is skipped too — the poller checks that list before it scores
    or quarantines anything (edr_triage/jira_closure_poller._alert_under_test).

    For a detection rule under active development whose KQL logic is known-wrong right
    now — its firings are not genuine analyst decisions, so scoring them (or surfacing
    them as disagreements to review) grades the AI against a broken rule rather than
    real triage.

    Existing scored rows: sets verdict_match=None, the SAME exclusion the metric already
    gives ai_error/outage rows (shadow_stats above) — non-destructive, reversible, and
    the rows stay in the DB for whenever the rule is fixed and this alert_name is worth
    scoring again. Existing quarantine memories for this alert (scored OR still pending
    L2 resolution) are deleted outright — dismiss_memory's own semantics.

    Body: {"alert_name": str, "reason": str, "dry_run": bool (default False)}.
    """
    alert_name = (payload or {}).get("alert_name", "").strip()
    reason = (payload or {}).get("reason", "").strip()
    dry_run = bool((payload or {}).get("dry_run", False))
    if not alert_name:
        raise HTTPException(400, "alert_name is required")

    from entity_graph.models import ShadowResult, SCGMemory, MemoryTier, AlertUnderTest

    all_shadows = await ShadowResult.find(ShadowResult.alert_name == alert_name).to_list()
    all_keys = [s.jira_key for s in all_shadows]
    scored = [s for s in all_shadows if s.verdict_match is not None]
    unscored_keys = [s.jira_key for s in scored]
    if not dry_run:
        for s in scored:
            s.verdict_match = None
            await s.save()

    mems = await SCGMemory.find(
        SCGMemory.tier == MemoryTier.quarantine,
        SCGMemory.jira_key != "",
    ).to_list()
    removed = [m.jira_key for m in mems if m.jira_key in all_keys]
    if not dry_run:
        for m in mems:
            if m.jira_key in all_keys:
                await m.delete()

    if not dry_run:
        existing = await AlertUnderTest.find_one(AlertUnderTest.alert_name == alert_name)
        if not existing:
            await AlertUnderTest(alert_name=alert_name, reason=reason).insert()

    logger.info("[ADMIN] exclude-alert '%s' (reason=%s, dry_run=%s): %d shadow(s) unscored, "
                "%d quarantine memory(ies) removed, registered for future exclusion=%s",
                alert_name, reason, dry_run, len(unscored_keys), len(removed), not dry_run)
    return {
        "ok": True, "alert_name": alert_name, "reason": reason, "dry_run": dry_run,
        "shadows_unscored": unscored_keys, "quarantine_removed": removed,
        "registered_for_future_exclusion": not dry_run,
    }


@router.get("/api/memory/alerts-under-test")
async def list_alerts_under_test():
    """List alert names currently excluded from scoring + quarantine (rules under test)."""
    from entity_graph.models import AlertUnderTest
    rows = await AlertUnderTest.find().sort(-AlertUnderTest.added_at).to_list()
    return [
        {
            "id": str(r.id), "alert_name": r.alert_name, "reason": r.reason,
            "added_by": r.added_by, "added_at": r.added_at.isoformat(),
        }
        for r in rows
    ]


@router.post("/api/memory/alerts-under-test", status_code=201)
async def add_alert_under_test(payload: dict = Body(...)):
    """Add one alert NAME to the standing exclusion list (see AlertUnderTest docstring).

    Idempotent — re-adding an alert_name already on the list just updates its reason.
    Does NOT retroactively touch existing shadows/quarantine rows — use
    POST /api/memory/shadow/exclude-alert for that (it also registers here).
    """
    from entity_graph.models import AlertUnderTest
    alert_name = (payload or {}).get("alert_name", "").strip()
    reason = (payload or {}).get("reason", "").strip()
    added_by = (payload or {}).get("added_by", "").strip()
    if not alert_name:
        raise HTTPException(400, "alert_name is required")
    existing = await AlertUnderTest.find_one(AlertUnderTest.alert_name == alert_name)
    if existing:
        existing.reason = reason or existing.reason
        await existing.save()
        return {"ok": True, "alert_name": alert_name, "action": "updated"}
    await AlertUnderTest(alert_name=alert_name, reason=reason, added_by=added_by).insert()
    return {"ok": True, "alert_name": alert_name, "action": "added"}


@router.delete("/api/memory/alerts-under-test/{alert_name}")
async def remove_alert_under_test(alert_name: str):
    """Take one alert NAME off the exclusion list — its tickets resume being scored
    and quarantined normally from the next poll onward. Does not touch past rows."""
    from entity_graph.models import AlertUnderTest
    existing = await AlertUnderTest.find_one(AlertUnderTest.alert_name == alert_name)
    if not existing:
        raise HTTPException(404, "alert_name not on the under-test list")
    await existing.delete()
    return {"ok": True, "alert_name": alert_name, "action": "removed"}


# ---------------------------------------------------------------------------
# Bulk maintenance (destructive) — DISABLED / commented out on purpose.
# These were a one-time slate-reset tool (clear the quarantine backlog / reset
# the accuracy counter). They wipe whole collections, so they must NOT sit live
# in the API. Kept in source for a future reset: uncomment, redeploy, call with
# {"confirm": true}, then comment out and redeploy again.
# ---------------------------------------------------------------------------

# @router.post("/api/memory/quarantine/clear")
# async def clear_quarantine(payload: dict = Body(default={})):
#     """Delete ALL quarantine-tier memories (clears the L2 review backlog).
#     Destructive; requires {"confirm": true}. Curated/golden are NOT touched."""
#     if not (payload or {}).get("confirm"):
#         raise HTTPException(400, 'pass {"confirm": true} to clear the quarantine queue')
#     from app.database import get_collection
#     col = get_collection("eg_memories")
#     res = await col.delete_many({"tier": "quarantine"})
#     logger.info("[ADMIN] cleared quarantine — deleted %d memories", res.deleted_count)
#     return {"ok": True, "deleted": res.deleted_count, "tier": "quarantine"}


# @router.post("/api/memory/shadow/reset")
# async def reset_shadow_results(payload: dict = Body(default={})):
#     """Reset the AI-accuracy counter by deleting only RESOLVED shadow results.
#     Destructive; requires {"confirm": true}. Memories (curated/golden) untouched.
#     SCOPED to verdict_match != None on purpose: deleting UNRESOLVED shadows (still-open
#     tickets) orphans them, so they can never be compared when the human finally closes
#     them ('no AI triage to compare against'). The accuracy counter only measures
#     resolved results, so clearing just those resets it without harming in-flight tickets."""
#     if not (payload or {}).get("confirm"):
#         raise HTTPException(400, 'pass {"confirm": true} to reset the accuracy counter')
#     from app.database import get_collection
#     col = get_collection("eg_shadow_results")
#     res = await col.delete_many({"verdict_match": {"$ne": None}})  # resolved only — keep open tickets
#     logger.info("[ADMIN] reset accuracy history — deleted %d resolved shadow results", res.deleted_count)
#     return {"ok": True, "deleted": res.deleted_count}


# ---------------------------------------------------------------------------
# One-time relabel backfill — repairs human-only (no-shadow) memories whose
# verdict line was hard-coded "L1:" even when the ticket went L1 -> L2 and L2
# made the final call (fixed at source in jira_closure_poller._write_direct_memory).
# NON-DESTRUCTIVE: recomputes the verdict tier from each memory's OWN stored
# l1_comment thread ([L2 — …] tags), rewrites only the header verdict line + the
# quarantine_reason, touches nothing else. Idempotent, dry_run-capable.
# Run: uncomment, redeploy, POST {"dry_run": true} to preview, then {} to apply,
# then comment out + redeploy again.
# ---------------------------------------------------------------------------

# @router.post("/api/memory/admin/relabel-tier")
# async def relabel_tier(payload: dict = Body(default={})):
#     """Relabel human-only memories that mis-attribute an L2 close to L1.
#
#     Selects memories whose quarantine_reason marks them as no-shadow/human-only,
#     reads the attributed comment thread; if an L2 analyst resolved it, rewrites the
#     header ``— L1: <CLASS>`` to ``— L2: <CLASS> (escalated by L1)``. Fill/repair
#     only — never flips an L2 label back to L1. Body: {"dry_run"?: bool}.
#     """
#     import re as _re
#     dry = bool((payload or {}).get("dry_run"))
#     from app.database import get_collection
#     col = get_collection("eg_memories")
#     cursor = col.find({"quarantine_reason": {"$regex": "no AI triage to compare against"}})
#     results = []
#     async for doc in cursor:
#         lc = doc.get("l1_comment") or ""
#         content = doc.get("content") or ""
#         went_l2 = "[L2 —" in lc or "[L2 -" in lc
#         header = content.split("\n", 1)[0]
#         needs = went_l2 and _re.search(r"— L1: \S+", header)
#         if not needs:
#             continue
#         new_header = _re.sub(r"— L1: (\S+)", r"— L2: \1 (escalated by L1)", header, count=1)
#         new_content = new_header + content[len(header):]
#         set_fields = {
#             "content": new_content,
#             "quarantine_reason": "Human-only memory — no AI triage to compare against",
#         }
#         mid = str(doc.get("_id"))
#         jk = doc.get("jira_key")
#         if dry:
#             results.append({"memory_id": mid, "jira_key": jk, "status": "would-update",
#                             "new_header": new_header})
#             continue
#         res = await col.update_one({"_id": doc["_id"]}, {"$set": set_fields})
#         logger.info("[admin-relabel] %s (%s): L1 -> L2 (escalated)", mid, jk)
#         results.append({"memory_id": mid, "jira_key": jk,
#                         "status": "updated" if res.modified_count == 1 else "nochange",
#                         "new_header": new_header})
#     return {
#         "ok": True, "dry_run": dry,
#         "matched": len(results),
#         "updated": sum(1 for r in results if r["status"] == "updated"),
#         "results": results,
#     }


# ---------------------------------------------------------------------------
# One-time actor/device backfill endpoint — DISABLED (commented out after use).
# Used once to repair memories whose actor was dropped by the empty-actor
# enrichment bug (fixed in the pipeline by the cloudtrail user_arn/account_name
# binding + the UPN-suffix fix). It is NON-DESTRUCTIVE (fill-only: sets actor
# only when empty, never overwrites) and idempotent. Kept in source for a future
# re-run: uncomment, redeploy, POST the payload (supports {"dry_run": true}),
# then comment out and redeploy again.
# ---------------------------------------------------------------------------

# @router.post("/api/memory/admin/backfill-actor")
# async def backfill_actor(payload: dict = Body(...)):
#     """One-time, NON-DESTRUCTIVE backfill of actor/device on memories that lost them
#     to the empty-actor enrichment bug (cloudtrail user_arn / account_name not bound).
#     FILL-ONLY (never overwrites an existing actor), idempotent, dry_run-capable.
#     Body: {"items": [{"memory_id": str, "actor": str, "device"?: str}], "dry_run"?: bool}
#     """
#     items = (payload or {}).get("items") or []
#     dry = bool((payload or {}).get("dry_run"))
#     if not isinstance(items, list) or not items:
#         raise HTTPException(400, 'body must be {"items": [{"memory_id","actor","device?"}], "dry_run?"}')
#     from beanie import PydanticObjectId
#     from app.database import get_collection
#     col = get_collection("eg_memories")
#     results = []
#     for it in items:
#         mid = str((it or {}).get("memory_id") or "").strip()
#         actor = str((it or {}).get("actor") or "").strip()
#         device = str((it or {}).get("device") or "").strip()
#         if not mid or not actor:
#             results.append({"memory_id": mid, "status": "skipped", "reason": "missing memory_id/actor"})
#             continue
#         try:
#             oid = PydanticObjectId(mid)
#         except Exception:
#             results.append({"memory_id": mid, "status": "skipped", "reason": "bad memory_id"})
#             continue
#         doc = await col.find_one({"_id": oid}, {"actor": 1, "device": 1, "jira_key": 1})
#         if not doc:
#             results.append({"memory_id": mid, "status": "notfound"})
#             continue
#         if (doc.get("actor") or "").strip():
#             results.append({"memory_id": mid, "status": "skipped", "reason": "actor already set",
#                             "existing_actor": doc.get("actor")})
#             continue
#         set_fields = {"actor": actor}
#         if device and not (doc.get("device") or "").strip():
#             set_fields["device"] = device
#         if dry:
#             results.append({"memory_id": mid, "status": "would-update",
#                             "jira_key": doc.get("jira_key"), "set": set_fields})
#             continue
#         res = await col.update_one({"_id": oid}, {"$set": set_fields})
#         logger.info("[admin-backfill] %s (%s): set %s", mid, doc.get("jira_key"), set_fields)
#         results.append({"memory_id": mid, "status": "updated" if res.modified_count == 1 else "nochange",
#                         "jira_key": doc.get("jira_key"), "set": set_fields})
#     return {
#         "ok": True, "dry_run": dry, "requested": len(items),
#         "updated": sum(1 for r in results if r["status"] == "updated"),
#         "skipped": sum(1 for r in results if r["status"] == "skipped"),
#         "results": results,
#     }


@router.get("/api/memory/pollution")
async def memory_pollution():
    """Memory-pollution rate — tier distribution of institutional memory plus the
    share sitting in quarantine, and how much of that quarantine is driven by
    AI-vs-human disagreement (quarantine_reason starts with 'AI said')."""
    from entity_graph.models import SCGMemory, MemoryTier
    try:
        total = await SCGMemory.count()
        quarantine = await SCGMemory.find(SCGMemory.tier == MemoryTier.quarantine).count()
        curated = await SCGMemory.find(SCGMemory.tier == MemoryTier.curated).count()
        golden = await SCGMemory.find(SCGMemory.tier == MemoryTier.golden).count()
        coll = SCGMemory.get_pymongo_collection()
        ai_disagreement = await coll.count_documents({"quarantine_reason": {"$regex": "^AI said"}})
        return {
            "total": total,
            "by_tier": {"quarantine": quarantine, "curated": curated, "golden": golden},
            "quarantine_rate": round(quarantine / total, 3) if total else None,
            "trusted_rate": round((curated + golden) / total, 3) if total else None,
            "ai_disagreement_quarantine": ai_disagreement,
        }
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/memory/overturn-trend")
async def overturn_trend(weeks: int = 12):
    """Weekly AI-vs-human agreement/overturn series. shadow-stats is a lifetime
    aggregate; this buckets resolved ShadowResults by ISO week so drift is visible."""
    from entity_graph.models import ShadowResult
    try:
        coll = ShadowResult.get_pymongo_collection()
        pipeline = [
            {"$match": {"verdict_match": {"$ne": None}, "ai_error": None}},  # exclude agent-failure (outage) shadows
            {"$group": {
                "_id": {"$dateToString": {"format": "%G-W%V", "date": "$created_at"}},
                "total": {"$sum": 1},
                "matches": {"$sum": {"$cond": ["$verdict_match", 1, 0]}},
            }},
            {"$sort": {"_id": 1}},
        ]
        rows = await coll.aggregate(pipeline).to_list(length=None)
        rows = rows[-max(1, weeks):]
        series = [
            {
                "week": r["_id"],
                "total": r["total"],
                "matches": r["matches"],
                "accuracy": round(r["matches"] / r["total"], 3) if r["total"] else None,
                "overturn_rate": round(1 - r["matches"] / r["total"], 3) if r["total"] else None,
            }
            for r in rows
        ]
        return {"weeks": len(series), "series": series}
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/memory/analyst-profiles")
async def analyst_profiles(limit: int = 100):
    """Per-analyst escalation-precision profiles (see entity_graph/analyst_profile).
    Only analysts with ground-truth-scored decisions appear; accuracy is meaningful
    only once total_verdicts is non-trivial (trust tier locks in at >=50)."""
    from entity_graph.models import AnalystProfile
    try:
        profiles = (
            await AnalystProfile.find_all()
            .sort(-AnalystProfile.total_verdicts)
            .limit(limit)
            .to_list()
        )
        return [
            {
                "analyst_id": p.analyst_id,
                "display_name": p.display_name,
                "total_verdicts": p.total_verdicts,
                "correct_verdicts": p.correct_verdicts,
                "accuracy": round(p.accuracy, 3),
                "trust_tier": p.trust_tier,
                "last_active": p.last_active.isoformat() if p.last_active else None,
            }
            for p in profiles
        ]
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Analyst registry API
# ---------------------------------------------------------------------------

@router.get("/api/memory/analysts")
async def get_analysts():
    import asyncio
    from edr_triage.analyst_store import list_analysts
    return await asyncio.to_thread(list_analysts)


@router.post("/api/memory/analysts", status_code=201)
async def add_analyst(payload: dict = Body(...)):
    import asyncio
    from edr_triage.analyst_store import upsert_analyst
    email = (payload.get("email") or "").strip().lower()
    display_name = (payload.get("display_name") or "").strip()
    role = (payload.get("role") or "").strip().upper()
    if not email:
        raise HTTPException(400, "email required")
    if role not in ("L1", "L2"):
        raise HTTPException(400, "role must be L1 or L2")
    await asyncio.to_thread(upsert_analyst, email, display_name, role)
    return {"ok": True, "email": email, "role": role}


@router.delete("/api/memory/analysts/{email}")
async def delete_analyst(email: str):
    import asyncio
    from edr_triage.analyst_store import remove_analyst
    await asyncio.to_thread(remove_analyst, email)
    return {"ok": True, "email": email}


# ---------------------------------------------------------------------------
# Actor-allowlist suggestions (propose-only) — mined from repeated FP closures.
# Arming writes a golden auto_fp memory; nothing here auto-suppresses anything.
# ---------------------------------------------------------------------------

@router.get("/api/memory/suggestions")
async def list_allowlist_suggestions(status: str = "pending", limit: int = 100):
    """List actor-allowlist suggestions (propose-only queue)."""
    from entity_graph.models import AllowlistSuggestion
    query = AllowlistSuggestion.find()
    if status:
        query = AllowlistSuggestion.find(AllowlistSuggestion.status == status)
    docs = await query.sort(-AllowlistSuggestion.fp_count).limit(limit).to_list()
    return {
        "suggestions": [
            {
                "id": str(d.id),
                "alert_type": d.alert_type,
                "alert_name": d.alert_name,
                "actor": d.actor,
                "device": d.device,
                "commands": d.commands,
                "fp_count": d.fp_count,
                "evidence_jira_keys": d.evidence_jira_keys,
                "status": d.status,
                "armed_memory_id": d.armed_memory_id,
                "created_at": d.created_at.isoformat() if d.created_at else None,
            }
            for d in docs
        ]
    }


@router.post("/api/memory/suggestions/analyze", status_code=202)
async def analyze_allowlist_suggestions(
    background_tasks: BackgroundTasks, lookback_days: int = 30, min_count: int = 3,
):
    """Trigger FP-cluster mining — queues suggestions where a human repeatedly
    closed an alert FP for one actor while OSCAR escalated it. Non-blocking."""
    from edr_triage.allowlist_suggester import analyze_fp_clusters
    background_tasks.add_task(analyze_fp_clusters, lookback_days, min_count)
    return {"ok": True, "status": "analysis_started", "lookback_days": lookback_days}


@router.post("/api/memory/suggestions/{suggestion_id}/arm")
async def arm_allowlist_suggestion(suggestion_id: str, payload: dict = Body(default={})):
    """Approve a suggestion — writes a golden auto_fp memory so the pipeline
    short-circuit auto-closes this actor's future FPs. Body may override
    {device, commands} before arming (e.g. narrow to a command set). Reversible:
    disarm/delete the resulting golden memory from the Golden tab.
    """
    from entity_graph.models import AllowlistSuggestion
    from entity_graph.memory import create_allowlist_memory
    sugg = await AllowlistSuggestion.get(suggestion_id)
    if not sugg:
        raise HTTPException(404, "Suggestion not found")
    body = payload or {}
    device = body.get("device", sugg.device)
    commands = body.get("commands", sugg.commands)
    mem_id = await create_allowlist_memory(
        alert_type=sugg.alert_type,
        actor=sugg.actor,
        device=device,
        commands=commands,
        jira_key=(sugg.evidence_jira_keys or [""])[0],
        evidence_jira_keys=sugg.evidence_jira_keys,
        resolved_by="l2_analyst",
        alert_name=sugg.alert_name,
    )
    if not mem_id:
        raise HTTPException(400, "Could not arm — suggestion has no actor")
    from datetime import datetime as _dt
    sugg.status = "armed"
    sugg.armed_memory_id = mem_id
    sugg.reviewed_by = "l2_analyst"
    sugg.reviewed_at = _dt.utcnow()
    await sugg.save()
    return {"ok": True, "id": suggestion_id, "status": "armed", "memory_id": mem_id}


@router.post("/api/memory/suggestions/{suggestion_id}/dismiss")
async def dismiss_allowlist_suggestion(suggestion_id: str):
    """Dismiss a suggestion without arming anything."""
    from entity_graph.models import AllowlistSuggestion
    from datetime import datetime as _dt
    sugg = await AllowlistSuggestion.get(suggestion_id)
    if not sugg:
        raise HTTPException(404, "Suggestion not found")
    sugg.status = "dismissed"
    sugg.reviewed_by = "l2_analyst"
    sugg.reviewed_at = _dt.utcnow()
    await sugg.save()
    return {"ok": True, "id": suggestion_id, "status": "dismissed"}


# ---------------------------------------------------------------------------
# Planned activity — declared maintenance/compliance windows (time-boxed).
# A known benign script tripping EDR fleet-wide; auto-closes matches as FP while
# active. Separate from golden memory (temporary announcement, self-expiring).
# ---------------------------------------------------------------------------

@router.get("/api/memory/planned-activity")
async def list_planned_activity(limit: int = 100):
    """List planned-activity windows (active + expired, newest expiry first)."""
    from entity_graph.models import PlannedActivity
    from datetime import datetime as _dt
    docs = await PlannedActivity.find().sort(-PlannedActivity.expires_at).limit(limit).to_list()
    now = _dt.utcnow()
    return {
        "windows": [
            {
                "id": str(d.id),
                "pattern": d.pattern,
                "label": d.label,
                "alert_type": d.alert_type,
                "expires_at": d.expires_at.isoformat() if d.expires_at else None,
                "active": bool(d.expires_at and d.expires_at > now),
                "created_by": d.created_by,
                "created_at": d.created_at.isoformat() if d.created_at else None,
                "hit_count": d.hit_count,
            }
            for d in docs
        ]
    }


@router.post("/api/memory/planned-activity", status_code=201)
async def create_planned_activity(payload: dict = Body(...)):
    """Declare a maintenance/compliance window. Body: {pattern, label?, alert_type?,
    and an expiry — either expires_at (ISO 'YYYY-MM-DD' or full timestamp) or days:int}.
    A date-only expiry is treated as end of that day (UTC)."""
    from entity_graph.models import PlannedActivity
    from edr_triage.planned_activity import MIN_PATTERN_LEN
    from datetime import datetime as _dt, timedelta
    pattern = (payload.get("pattern") or "").strip()
    if len(pattern) < MIN_PATTERN_LEN:
        raise HTTPException(400, f"pattern must be at least {MIN_PATTERN_LEN} characters (be specific)")
    label = (payload.get("label") or "").strip()
    alert_type = (payload.get("alert_type") or "").strip()

    exp = None
    if payload.get("expires_at"):
        raw = str(payload["expires_at"]).strip()
        try:
            exp = _dt.fromisoformat(raw.replace("Z", ""))
        except ValueError:
            raise HTTPException(400, "expires_at must be ISO (YYYY-MM-DD or full timestamp)")
        if len(raw) == 10:  # date-only → include the whole day
            exp = exp.replace(hour=23, minute=59, second=59)
    elif payload.get("days") is not None:
        try:
            days = int(payload["days"])
        except (TypeError, ValueError):
            raise HTTPException(400, "days must be an integer")
        if days <= 0:
            raise HTTPException(400, "days must be positive")
        exp = _dt.utcnow() + timedelta(days=days)
    else:
        raise HTTPException(400, "expiry required — provide expires_at or days")

    if exp <= _dt.utcnow():
        raise HTTPException(400, "expiry must be in the future")
    doc = PlannedActivity(pattern=pattern, label=label, alert_type=alert_type,
                          expires_at=exp, created_by="l2_analyst")
    await doc.insert()
    return {"ok": True, "id": str(doc.id), "expires_at": exp.isoformat()}


@router.delete("/api/memory/planned-activity/{window_id}")
async def delete_planned_activity(window_id: str):
    """Delete a planned-activity window (end it early or clear an expired one)."""
    from entity_graph.models import PlannedActivity
    doc = await PlannedActivity.get(window_id)
    if not doc:
        raise HTTPException(404, "Window not found")
    await doc.delete()
    return {"ok": True, "id": window_id, "action": "deleted"}


@router.get("/api/memory/graph")
async def memory_graph():
    """Node-link view of the Security Context Graph: the entities RAPTOR knows
    (devices / users), the alerts that touched them, and the memories it learned —
    composed read-only from the live collections for the console's graph view.

    Node kinds: device, user, alert. Alert nodes carry the AI verdict, whether it
    matched the human outcome, and any memory tier learned from the ticket. Edges:
    device<->user (logged_on), alert->device (on), alert->user (by)."""
    from app.database import get_collection
    ents = await get_collection("eg_entities").find({}).to_list(500)
    rels = await get_collection("eg_relationships").find({}).to_list(1000)
    shadows = await get_collection("eg_shadow_results").find({}).to_list(500)
    mems = await get_collection("eg_memories").find({}).to_list(500)

    mem_by_key: dict[str, dict] = {}
    for m in mems:
        k = m.get("jira_key") or ""
        if k:
            mem_by_key[k] = {"tier": m.get("tier", ""), "reason": m.get("quarantine_reason", "")}

    nodes: list[dict] = []
    seen: set[str] = set()

    def add(nid: str, kind: str, label: str, **extra) -> None:
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "kind": kind, "label": label, **extra})

    id2node: dict[str, str] = {}
    for e in ents:
        et = e.get("entity_type")
        val = e.get("value", "")
        if et == "device":
            nid = "device:" + val
            add(nid, "device", val, risk=round(float(e.get("risk_score", 0) or 0), 2),
                alerts=int(e.get("alert_count", 0) or 0))
        elif et == "user":
            nid = "user:" + val
            add(nid, "user", val.split("@")[0], risk=round(float(e.get("risk_score", 0) or 0), 2),
                alerts=int(e.get("alert_count", 0) or 0))
        else:
            continue
        id2node[str(e.get("_id"))] = nid

    edges: list[dict] = []
    for r in rels:
        s = id2node.get(str(r.get("from_id")))
        t = id2node.get(str(r.get("to_id")))
        if s and t:
            edges.append({"s": s, "t": t, "kind": r.get("rel_type", "rel")})

    for sh in shadows:
        key = sh.get("jira_key", "")
        if not key:
            continue
        aid = "alert:" + key
        mem = mem_by_key.get(key, {})
        add(aid, "alert", (sh.get("alert_name", key) or key)[:36], jira=key,
            verdict=sh.get("ai_triage_class", ""), match=sh.get("verdict_match"),
            tier=mem.get("tier", ""), conflict=mem.get("reason", ""))
        dev = sh.get("device_name", "")
        usr = sh.get("user_name", "")
        if dev and ("device:" + dev) in seen:
            edges.append({"s": aid, "t": "device:" + dev, "kind": "on"})
        if usr and ("user:" + usr) in seen:
            edges.append({"s": aid, "t": "user:" + usr, "kind": "by"})

    return {"nodes": nodes, "edges": edges,
            "counts": {"device": sum(1 for n in nodes if n["kind"] == "device"),
                       "user": sum(1 for n in nodes if n["kind"] == "user"),
                       "alert": sum(1 for n in nodes if n["kind"] == "alert")}}


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------

@router.get("/memory/quarantine", response_class=HTMLResponse, include_in_schema=False)
async def quarantine_page():
    return HTMLResponse(_render_page())


@router.get("/memory/graph", response_class=HTMLResponse, include_in_schema=False)
async def graph_page():
    """Standalone full-screen Security Context Graph — same data + rendering as the
    AI-Memory tab, on its own page (opens in a new tab; nice for a clean recording)."""
    return HTMLResponse(_render_graph_page())


def _render_graph_page() -> str:
    return (r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Security Context Graph — RAPTOR</title>
<style>
  :root{--ink:#080A0E;--ink-2:#0C1116;--panel:#12151B;--panel-3:#1E2430;--line:#252B36;--line-2:#2E3644;
    --text:#DDE1E8;--text-bright:#F3F6FB;--muted:#8E96A4;--faint:#59616E;--ghost:#3C4757;--accent:#9E86F0;
    --accent-soft:rgba(158,134,240,.10);--good:#46B87A;--med:#E6C34C;--pend:#6C93C0;
    --mono:"SF Mono",ui-monospace,Menlo,Consolas,monospace;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;}
  *{box-sizing:border-box;}
  html,body{height:100%;margin:0;}
  body{background:var(--ink);color:var(--text);font-family:var(--sans);font-size:13px;display:flex;flex-direction:column;overflow:hidden;-webkit-font-smoothing:antialiased;}
  header{flex:0 0 auto;display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,var(--ink-2),var(--ink));}
  header .wm{font-family:var(--mono);letter-spacing:.16em;font-size:14px;font-weight:650;color:var(--accent);}
  header h1{margin:0;font-size:14px;font-weight:600;letter-spacing:.02em;color:var(--text-bright);}
  header .sub{color:var(--faint);font-size:11px;font-family:var(--mono);}
  header .sp{flex:1;}
  header a{color:var(--muted);font-size:12.5px;font-weight:600;border:1px solid var(--line-2);padding:7px 12px;border-radius:9px;transition:.15s;text-decoration:none;}
  header a:hover{color:var(--text);background:var(--panel);}
  main{flex:1 1 auto;min-height:0;display:grid;grid-template-columns:1fr 320px;gap:14px;padding:14px 18px 18px;}
  @media (max-width:900px){main{grid-template-columns:1fr;}}
  .gcanvas-wrap{position:relative;background:radial-gradient(ellipse 80% 80% at 50% 40%,#0e131b,var(--ink-2));border:1px solid var(--line);border-radius:12px;overflow:hidden;height:100%;}
  #gcanvas{display:block;width:100%;height:100%;cursor:grab;}
  #gcanvas:active{cursor:grabbing;}
  .glegend{position:absolute;top:12px;left:12px;background:rgba(8,10,14,.72);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:11px;color:var(--muted);backdrop-filter:blur(4px);pointer-events:none;}
  .gl-row{display:flex;align-items:center;gap:8px;line-height:1.7;}
  .gl-dot{width:9px;height:9px;border-radius:50%;flex:none;}
  .gl-ring{width:10px;height:10px;border-radius:50%;flex:none;border:1.5px dashed var(--med);}
  .ghint{position:absolute;bottom:11px;left:0;right:0;text-align:center;font-family:var(--mono);font-size:10px;color:var(--faint);pointer-events:none;}
  .ginfo{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;overflow-y:auto;height:100%;}
  .gi-empty{color:var(--faint);font-size:12px;line-height:1.6;}
  .gi-empty span{color:var(--ghost);font-size:11.5px;}
  .gi-kind{font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);}
  .gi-title{font-size:15px;font-weight:700;letter-spacing:-.02em;margin:6px 0 12px;word-break:break-word;color:var(--text-bright);}
  .gi-kv{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid var(--line);font-size:12px;}
  .gi-kv .k{color:var(--faint);}
  .gi-kv .v{color:var(--text);font-family:var(--mono);text-align:right;}
  .gi-bar{height:6px;border-radius:4px;background:var(--panel-3);overflow:hidden;margin-top:6px;}
  .gi-bar i{display:block;height:100%;border-radius:4px;}
  .gi-links{margin-top:14px;}
  .gi-link{display:flex;align-items:center;gap:8px;font-size:12px;padding:6px 0;color:var(--muted);border-bottom:1px solid rgba(37,43,54,.5);cursor:pointer;}
  .gi-link:hover{color:var(--text);}
  .gi-link .gl-dot{width:8px;height:8px;}
</style></head>
<body>
  <header>
    <span class="wm">R<b style="color:var(--text-bright)">A</b>PTOR</span>
    <h1>Security Context Graph</h1>
    <span class="sub" id="gcount"></span>
    <span class="sp"></span>
    <a href="/edr-triage">Triage Console</a>
    <a href="/memory/quarantine">AI Memory</a>
  </header>
  <main>
    <div class="gcanvas-wrap">
      <canvas id="gcanvas"></canvas>
      <div class="glegend">
        <div class="gl-row"><span class="gl-dot" style="background:#6C93C0"></span>Device</div>
        <div class="gl-row"><span class="gl-dot" style="background:#9E86F0"></span>User</div>
        <div class="gl-row" style="margin-top:6px;color:var(--faint);font-size:9.5px;letter-spacing:.08em">ALERT VERDICT</div>
        <div class="gl-row"><span class="gl-dot" style="background:#46B87A"></span>Auto-closed FP</div>
        <div class="gl-row"><span class="gl-dot" style="background:#E8913A"></span>Auto-closed TP</div>
        <div class="gl-row"><span class="gl-dot" style="background:#6C93C0"></span>Needs L2</div>
        <div class="gl-row"><span class="gl-dot" style="background:#F05552"></span>Urgent</div>
        <div class="gl-row" style="margin-top:6px"><span class="gl-ring"></span>AI&#8596;human disagreement</div>
      </div>
      <div class="ghint">drag to reposition &#183; hover a node to trace its links &#183; click for details</div>
    </div>
    <div class="ginfo" id="ginfo">
      <div class="gi-empty">Hover or click a node.<br/><span>Devices and users are the entities RAPTOR tracks; alerts link them, colored by verdict. A dashed ring marks where the AI and the analyst disagreed — the memory it learned from.</span></div>
    </div>
  </main>
<script>
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
//%%GRAPH_JS%%
document.addEventListener('DOMContentLoaded',function(){gInit();loadGraph();
  var c=document.getElementById('gcount');
  fetch('/api/memory/graph').then(function(r){return r.json();}).then(function(d){var k=d.counts||{};if(c)c.textContent=(k.device||0)+' devices · '+(k.user||0)+' users · '+(k.alert||0)+' alerts';}).catch(function(){});
});
</script>
</body></html>""".replace("//%%GRAPH_JS%%", _GRAPH_JS))


_GRAPH_JS = r'''
/* ── Context Graph — self-contained canvas force-graph (no libraries) ───────── */
var GRAPH={nodes:[],edges:[],idx:{},data:null,built:false,started:false,raf:null,hover:null,sel:null,drag:null};
function gVcol(v){return {AUTO_CLOSED_FP:'#46B87A',AUTO_CLOSED_TP:'#E8913A',NEEDS_L2:'#6C93C0',URGENT:'#F05552',PENDING:'#8E96A4'}[v]||'#8E96A4';}
function gColor(n){return n.kind==='device'?'#6C93C0':(n.kind==='user'?'#9E86F0':gVcol(n.verdict));}
function gR(n){return n.kind==='alert'?6:Math.min(8+(n.alerts||0)*1.6+(n.risk||0)*10,20);}
function loadGraph(){
  fetch('/api/memory/graph').then(function(r){return r.json();}).then(function(d){
    GRAPH.data=d;GRAPH.built=false;
    var tc=document.getElementById('cnt-graph-tab');if(tc)tc.textContent=(d.nodes||[]).length;
    var pane=document.getElementById('pane-graph');
    var show=pane?pane.classList.contains('on'):!!document.getElementById('gcanvas');
    if(show){gInit();ensureGraph();startGraph();}
  }).catch(function(){});
}
function ensureGraph(){
  if(GRAPH.built||!GRAPH.data)return;
  var cv=document.getElementById('gcanvas');if(!cv)return;
  var W=cv.clientWidth||900,H=cv.clientHeight||560,d=GRAPH.data,idx={};
  GRAPH.nodes=d.nodes.map(function(n,i){
    var a=(i/Math.max(d.nodes.length,1))*Math.PI*2,rad=Math.min(W,H)*0.34;
    var nn={};for(var k in n)nn[k]=n[k];
    nn.x=W/2+Math.cos(a)*rad+(i%7-3)*6;nn.y=H/2+Math.sin(a)*rad+(i%5-2)*6;nn.vx=0;nn.vy=0;
    idx[n.id]=nn;return nn;
  });
  GRAPH.edges=d.edges.map(function(e){return {s:idx[e.s],t:idx[e.t],kind:e.kind};}).filter(function(e){return e.s&&e.t;});
  GRAPH.idx=idx;GRAPH.built=true;
}
function gTick(){
  var N=GRAPH.nodes,E=GRAPH.edges,cv=document.getElementById('gcanvas');if(!cv)return;
  var W=cv.clientWidth,H=cv.clientHeight,i,j;
  for(i=0;i<N.length;i++){var a=N[i];for(j=i+1;j<N.length;j++){var b=N[j];
    var dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy+0.01,dist=Math.sqrt(d2),f=3000/d2,fx=dx/dist*f,fy=dy/dist*f;
    a.vx+=fx;a.vy+=fy;b.vx-=fx;b.vy-=fy;}}
  E.forEach(function(e){var dx=e.t.x-e.s.x,dy=e.t.y-e.s.y,dist=Math.sqrt(dx*dx+dy*dy)+0.01;
    var tgt=e.kind==='logged_on'?95:78,f=(dist-tgt)*0.02,fx=dx/dist*f,fy=dy/dist*f;
    e.s.vx+=fx;e.s.vy+=fy;e.t.vx-=fx;e.t.vy-=fy;});
  N.forEach(function(n){n.vx+=(W/2-n.x)*0.0022;n.vy+=(H/2-n.y)*0.0022;n.vx*=0.85;n.vy*=0.85;
    if(n!==GRAPH.drag){n.x+=n.vx;n.y+=n.vy;}
    n.x=Math.max(22,Math.min(W-22,n.x));n.y=Math.max(22,Math.min(H-22,n.y));});
}
function gDraw(){
  var cv=document.getElementById('gcanvas');if(!cv)return;var ctx=cv.getContext('2d');
  var dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;
  if(cv.width!==Math.round(W*dpr)||cv.height!==Math.round(H*dpr)){cv.width=Math.round(W*dpr);cv.height=Math.round(H*dpr);}
  ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);
  var hl=GRAPH.hover||GRAPH.sel,near={};
  if(hl){near[hl.id]=1;GRAPH.edges.forEach(function(e){if(e.s===hl)near[e.t.id]=1;if(e.t===hl)near[e.s.id]=1;});}
  GRAPH.edges.forEach(function(e){var on=hl&&(e.s===hl||e.t===hl);
    ctx.strokeStyle=on?'rgba(158,134,240,.6)':(hl?'rgba(80,90,105,.09)':'rgba(96,106,122,.22)');
    ctx.lineWidth=on?1.7:1;ctx.beginPath();ctx.moveTo(e.s.x,e.s.y);ctx.lineTo(e.t.x,e.t.y);ctx.stroke();});
  GRAPH.nodes.forEach(function(n){
    var dim=hl&&!near[n.id],r=gR(n),col=gColor(n);ctx.globalAlpha=dim?0.22:1;
    if(n.kind==='alert'&&n.match===false){ctx.beginPath();ctx.arc(n.x,n.y,r+4,0,6.2832);ctx.setLineDash([3,3]);ctx.strokeStyle='#E6C34C';ctx.lineWidth=1.5;ctx.stroke();ctx.setLineDash([]);}
    else if(n.tier==='golden'){ctx.beginPath();ctx.arc(n.x,n.y,r+4,0,6.2832);ctx.strokeStyle='#E6C34C';ctx.lineWidth=1.5;ctx.stroke();}
    ctx.beginPath();ctx.arc(n.x,n.y,r,0,6.2832);ctx.fillStyle=col;ctx.fill();
    if(n===hl){ctx.lineWidth=2;ctx.strokeStyle='#F3F6FB';ctx.stroke();}
    var lab=n.kind!=='alert'||n===hl||(near[n.id]&&hl);
    if(lab&&!dim){ctx.globalAlpha=0.92;ctx.fillStyle=n.kind==='alert'?'#AEB6C2':'#DDE1E8';
      ctx.font=(n.kind==='alert'?'10px ':'11px ')+'ui-monospace,Menlo,monospace';ctx.textAlign='center';
      ctx.fillText(n.label,n.x,n.y-r-5);}
    ctx.globalAlpha=1;});
}
function gLoop(){if(!GRAPH.started)return;var s;for(s=0;s<2;s++)gTick();gDraw();GRAPH.raf=requestAnimationFrame(gLoop);}
function startGraph(){if(GRAPH.started||!GRAPH.built)return;GRAPH.started=true;gLoop();}
function stopGraph(){GRAPH.started=false;if(GRAPH.raf)cancelAnimationFrame(GRAPH.raf);}
function gNodeAt(mx,my){var best=null,bd=1e9;GRAPH.nodes.forEach(function(n){var r=gR(n)+5,dx=mx-n.x,dy=my-n.y,d=dx*dx+dy*dy;if(d<r*r&&d<bd){bd=d;best=n;}});return best;}
function gInit(){
  var cv=document.getElementById('gcanvas');if(!cv||cv._wired)return;cv._wired=true;
  function P(ev){var r=cv.getBoundingClientRect();return {x:ev.clientX-r.left,y:ev.clientY-r.top};}
  cv.addEventListener('mousemove',function(ev){var p=P(ev);if(GRAPH.drag){GRAPH.drag.x=p.x;GRAPH.drag.y=p.y;GRAPH.drag.vx=0;GRAPH.drag.vy=0;}else{GRAPH.hover=gNodeAt(p.x,p.y);}});
  cv.addEventListener('mousedown',function(ev){var p=P(ev),n=gNodeAt(p.x,p.y);if(n){GRAPH.drag=n;GRAPH.sel=n;showGraphInfo(n);}});
  window.addEventListener('mouseup',function(){GRAPH.drag=null;});
  cv.addEventListener('mouseleave',function(){GRAPH.hover=null;});
}
function showGraphInfo(n){
  var el=document.getElementById('ginfo');if(!el)return;var col=gColor(n);
  var h='<div class="gi-kind">'+esc(n.kind)+'</div><div class="gi-title" style="color:'+col+'">'+esc(n.label)+'</div>';
  if(n.kind==='alert'){
    h+='<div class="gi-kv"><span class="k">AI verdict</span><span class="v" style="color:'+col+'">'+esc(n.verdict||'—')+'</span></div>';
    var mc=n.match===false?'#F05552':(n.match===true?'#46B87A':'#8E96A4'),mt=n.match===false?'no — disagreement':(n.match===true?'agreed':'—');
    h+='<div class="gi-kv"><span class="k">Matched human</span><span class="v" style="color:'+mc+'">'+mt+'</span></div>';
    if(n.tier)h+='<div class="gi-kv"><span class="k">Memory learned</span><span class="v">'+esc(n.tier)+'</span></div>';
    if(n.jira)h+='<div class="gi-kv"><span class="k">Ticket</span><span class="v">'+esc(n.jira)+'</span></div>';
    if(n.conflict)h+='<div style="margin-top:12px;font-size:11.5px;color:var(--muted);line-height:1.55">'+esc(n.conflict)+'</div>';
  }else{
    var pct=Math.round((n.risk||0)*100),rc=pct>=66?'#F05552':(pct>=33?'#E8913A':'#46B87A');
    h+='<div class="gi-kv"><span class="k">Risk score</span><span class="v" style="color:'+rc+'">'+pct+'%</span></div>';
    h+='<div class="gi-bar"><i style="width:'+pct+'%;background:'+rc+'"></i></div>';
    h+='<div class="gi-kv" style="margin-top:8px"><span class="k">Alerts touched</span><span class="v">'+(n.alerts||0)+'</span></div>';
  }
  var nb=[];GRAPH.edges.forEach(function(e){if(e.s===n)nb.push(e.t);else if(e.t===n)nb.push(e.s);});
  if(nb.length){h+='<div class="gi-links"><div class="gi-kind">Linked · '+nb.length+'</div>';
    nb.slice(0,14).forEach(function(m){h+='<div class="gi-link" onclick="gSelect(\''+esc(m.id)+'\')"><span class="gl-dot" style="background:'+gColor(m)+'"></span>'+esc(m.label)+'</div>';});
    h+='</div>';}
  el.innerHTML=h;
}
function gSelect(id){var n=GRAPH.idx[id];if(n){GRAPH.sel=n;showGraphInfo(n);}}
'''


def _render_page() -> str:
    return (r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>AI Memory — Security Context Graph</title>
<style>
  :root{
    --ink:#080A0E; --ink-2:#0C1116;
    --panel:#12151B; --panel-2:#181C24; --panel-3:#1E2430;
    --line:#252B36; --line-2:#2E3644;
    --text:#DDE1E8; --text-bright:#F3F6FB; --muted:#8E96A4; --faint:#59616E; --ghost:#3C4757;
    --accent:#9E86F0; --accent-dim:#5B3FB0; --accent-glow:rgba(158,134,240,.18); --accent-soft:rgba(158,134,240,.10);
    --crit:#F05552; --high:#E8913A; --med:#E6C34C; --good:#46B87A; --pend:#6C93C0; --violet:#9E86F0;
    --quar:#E8913A; --cur:#9E86F0; --gold:#E6C34C;
    --mono:"SF Mono",ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;
  }
  *{box-sizing:border-box;}
  html{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
  body{margin:0;background:var(--ink);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.5;letter-spacing:-0.004em;min-height:100vh;-webkit-font-smoothing:antialiased;}
  body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(#1A1F28 1px,transparent 1px),linear-gradient(90deg,#1A1F28 1px,transparent 1px);background-size:48px 48px;opacity:.35;mask-image:radial-gradient(ellipse 90% 70% at 70% 0%,#000 30%,transparent 75%);}
  ::-webkit-scrollbar{width:9px;height:9px;}
  ::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:9px;border:2px solid var(--ink);}
  a{color:inherit;text-decoration:none;}
  .mono{font-family:var(--mono);font-variant-numeric:tabular-nums;}

  .shell{position:relative;z-index:1;display:grid;grid-template-columns:66px 1fr;min-height:100vh;}
  .rail{background:linear-gradient(180deg,var(--ink-2),var(--ink));border-right:1px solid var(--line);display:flex;flex-direction:column;align-items:center;gap:6px;padding:16px 0;position:sticky;top:0;height:100vh;z-index:30;}
  .glyph{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;margin-bottom:14px;background:linear-gradient(160deg,var(--panel-3),var(--panel));border:1px solid var(--line-2);}
  .glyph svg{width:20px;height:20px;}
  .navbtn{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;color:var(--ghost);cursor:pointer;position:relative;transition:.16s;border:1px solid transparent;background:transparent;-webkit-appearance:none;appearance:none;}
  .navbtn svg{width:19px;height:19px;}
  .navbtn:hover{color:var(--muted);background:var(--panel);}
  .navbtn.active{color:var(--accent);background:var(--accent-soft);border-color:var(--accent-dim);}
  .navbtn.active::before{content:"";position:absolute;left:-16px;top:9px;bottom:9px;width:3px;border-radius:3px;background:var(--accent);}
  .rail .spacer{flex:1;}
  .tip{position:absolute;left:52px;white-space:nowrap;background:var(--panel-3);border:1px solid var(--line-2);color:var(--text);font-size:12px;padding:5px 9px;border-radius:8px;opacity:0;pointer-events:none;transform:translateX(-4px);transition:.14s;z-index:40;}
  .navbtn:hover .tip{opacity:1;transform:translateX(0);}

  .main{padding:22px 30px 60px;max-width:1500px;width:100%;}
  .topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:22px;flex-wrap:wrap;}
  .brand h1{margin:0;font-size:16px;font-weight:650;letter-spacing:0.02em;line-height:1;display:flex;align-items:center;gap:9px;color:var(--text-bright);}
  .brand h1 .wm{font-family:var(--mono);letter-spacing:0.16em;}
  .brand h1 .wm b{color:var(--accent);font-weight:650;}
  .brand p{margin:5px 0 0;color:var(--faint);font-family:var(--sans);font-size:10.5px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;}
  .actions{display:flex;align-items:center;gap:10px;}
  .btn{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;font-weight:600;letter-spacing:-0.01em;padding:8px 13px;border-radius:10px;border:1px solid var(--line-2);background:var(--panel);color:var(--text);cursor:pointer;transition:.15s;white-space:nowrap;font-family:var(--sans);}
  .btn svg{width:14px;height:14px;}
  .btn:hover{background:var(--panel-2);border-color:#33475d;transform:translateY(-1px);}
  .btn.ghost{background:transparent;color:var(--muted);}
  .btn.ghost:hover{color:var(--text);}
  .btn.primary{background:linear-gradient(180deg,rgba(158,134,240,.16),rgba(158,134,240,.06));border-color:var(--accent-dim);color:var(--accent);}
  .btn.primary:hover{border-color:var(--accent);box-shadow:0 0 18px var(--accent-glow);}
  .btn.sm{padding:5px 10px;font-size:11.5px;border-radius:8px;}

  /* stats */
  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px;}
  .stat{position:relative;background:linear-gradient(180deg,var(--panel-2),var(--panel));border:1px solid var(--line);border-radius:8px;padding:14px 16px;overflow:hidden;transition:transform .16s,border-color .16s;box-shadow:0 10px 26px -18px rgba(0,0,0,0.85);}
  .stat:hover{border-color:var(--line-2);transform:translateY(-2px);}
  .stat .stripe{position:absolute;left:0;top:0;bottom:0;width:3px;}
  .stat .lbl{font-family:var(--sans);font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--faint);display:flex;align-items:center;justify-content:space-between;}
  .stat .lbl svg{width:14px;height:14px;}
  .stat .big{font-family:var(--sans);font-size:28px;font-weight:700;letter-spacing:-0.025em;margin:9px 0 2px;font-variant-numeric:tabular-nums;line-height:1;color:var(--text-bright);}
  .stat .sub{font-size:11px;color:var(--muted);}

  /* tier flow banner — two branches by whether AI & L1 agreed */
  .flow{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px 18px;margin-bottom:22px;overflow-x:auto;}
  .flow .lanes{display:flex;flex-direction:column;gap:11px;min-width:600px;}
  .flow .lane{display:flex;align-items:center;gap:0;}
  .flow .chip{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:9px;font-size:12px;font-weight:600;border:1px solid;white-space:nowrap;}
  .flow .chip .d{width:7px;height:7px;border-radius:50%;}
  .flow .arrow{color:var(--ghost);margin:0 13px;flex:none;font-size:14px;display:flex;flex-direction:column;align-items:center;line-height:1;}
  .flow .arrow small{font-size:8.5px;color:var(--faint);font-family:var(--mono);margin-top:3px;white-space:nowrap;}
  .flow .tail{font-size:10px;color:var(--faint);font-family:var(--mono);margin-left:11px;text-transform:uppercase;letter-spacing:.06em;}
  .flow .note{margin-top:13px;padding-top:12px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:8px;}
  .flow .note svg{width:14px;height:14px;color:var(--accent);flex:none;}

  /* tabs */
  .tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:20px;}
  .tab{padding:9px 16px;font-size:13px;font-weight:600;color:var(--faint);cursor:pointer;border-bottom:2px solid transparent;transition:.14s;display:flex;align-items:center;gap:8px;background:none;border-top:none;border-left:none;border-right:none;font-family:var(--sans);}
  .tab:hover{color:var(--muted);}
  .tab.on{color:var(--text);border-bottom-color:var(--accent);}
  .tab .cnt{font-family:var(--mono);font-size:10px;padding:1px 7px;border-radius:20px;background:var(--panel-2);color:var(--faint);}
  .tab.on .cnt{background:var(--accent-soft);color:var(--accent);}

  .toolbar{display:flex;align-items:center;gap:11px;margin-bottom:14px;flex-wrap:wrap;}
  .search{display:flex;align-items:center;gap:8px;background:var(--ink-2);border:1px solid var(--line);border-radius:10px;padding:7px 11px;min-width:280px;}
  .search:focus-within{border-color:var(--accent-dim);}
  .search svg{width:14px;height:14px;color:var(--faint);flex:none;}
  .search input{background:none;border:none;outline:none;color:var(--text);font-size:13px;width:100%;font-family:var(--sans);}
  .search input::placeholder{color:var(--ghost);}
  select.f{background:var(--ink-2);border:1px solid var(--line);border-radius:10px;padding:8px 11px;color:var(--text);font-size:12.5px;font-family:var(--sans);outline:none;cursor:pointer;}
  select.f:focus{border-color:var(--accent-dim);}
  .toolbar .right{margin-left:auto;display:flex;gap:9px;align-items:center;}

  .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden;box-shadow:0 14px 38px -24px rgba(0,0,0,0.9);}
  .twrap{overflow-x:auto;}
  table{border-collapse:collapse;width:100%;min-width:820px;}
  thead th{font-family:var(--sans);font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.05em;text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);font-weight:600;background:var(--ink-2);}
  tbody tr{border-bottom:1px solid rgba(30,40,54,.5);transition:background .12s;cursor:pointer;}
  tbody tr:last-child{border-bottom:none;}
  tbody tr:hover{background:#131c28;}
  tbody td{padding:11px 14px;vertical-align:top;}
  .alert-cell .an{font-weight:600;color:var(--text);font-size:12.5px;max-width:210px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .jira{font-family:var(--mono);font-size:10px;color:var(--good);margin-top:3px;display:inline-block;cursor:pointer;}
  .jira:hover{color:#5fd67f;text-decoration:underline;}
  .content{font-size:12.5px;color:var(--muted);line-height:1.5;max-width:340px;}
  .content .qt{color:var(--ghost);}
  .type{font-family:var(--mono);font-size:11px;color:var(--muted);}
  .type::before{content:"›";color:var(--ghost);margin-right:5px;}
  .cell-faint{font-family:var(--mono);font-size:11px;color:var(--faint);}

  .badge{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.03em;padding:3px 8px;border-radius:20px;text-transform:uppercase;white-space:nowrap;border:1px solid transparent;}
  .badge .d{width:5px;height:5px;border-radius:50%;background:currentColor;}
  .t-quar{color:var(--quar);background:rgba(232,145,58,.1);border-color:rgba(232,145,58,.25);}
  .t-cur{color:var(--cur);background:var(--accent-soft);border-color:var(--accent-dim);}
  .t-gold{color:var(--gold);background:rgba(230,195,76,.1);border-color:rgba(230,195,76,.28);}
  .t-ent{color:var(--muted);background:rgba(139,152,171,.09);border-color:var(--line-2);}
  .t-pb{color:var(--pend);background:rgba(108,147,192,.1);border-color:rgba(108,147,192,.28);}
  .t-afp{color:var(--good);background:rgba(70,184,122,.1);border-color:rgba(70,184,122,.3);}
  .promobox{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;display:flex;flex-direction:column;gap:10px;}
  .promobox .opt{display:flex;gap:9px;align-items:flex-start;font-size:12.5px;color:var(--muted);line-height:1.45;cursor:pointer;}
  .promobox .opt input{margin-top:2px;flex:none;accent-color:var(--accent);}
  .promobox .opt b{color:var(--text);font-weight:600;}
  .promobox .opt.afp{border-top:1px solid var(--line);padding-top:10px;margin-top:1px;}
  .promobox code{font-family:var(--mono);font-size:11px;color:var(--accent);background:var(--accent-soft);padding:1px 5px;border-radius:5px;}
  .conflict{display:inline-flex;flex-direction:column;gap:2px;font-family:var(--mono);font-size:10px;}
  .conflict .ai{color:var(--faint);}
  .conflict .l1{color:var(--crit);}
  .conflict.agree .l1{color:var(--good);}
  .conf{font-family:var(--mono);font-size:11.5px;color:var(--muted);font-variant-numeric:tabular-nums;}
  .role{font-family:var(--mono);font-size:10px;font-weight:600;padding:2px 8px;border-radius:6px;}
  .role-l1{background:rgba(108,147,192,.12);color:var(--pend);}
  .role-l2{background:rgba(158,134,240,.14);color:var(--violet);}

  .rowacts{display:flex;gap:5px;}
  .ib{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;border:1px solid var(--line);background:var(--ink-2);cursor:pointer;transition:.13s;color:var(--faint);}
  .ib svg{width:14px;height:14px;}
  .ib:hover{transform:translateY(-1px);}
  .ib.ok:hover{color:var(--good);border-color:rgba(70,184,122,.4);background:rgba(70,184,122,.1);}
  .ib.flag:hover{color:var(--med);border-color:rgba(230,195,76,.4);background:rgba(230,195,76,.1);}
  .ib.no:hover{color:var(--crit);border-color:rgba(240,85,82,.4);background:rgba(240,85,82,.1);}
  .flagged{color:var(--med);}

  .empty{padding:56px 20px;text-align:center;color:var(--faint);font-size:13px;}
  .pane{display:none;}
  .pane.on{display:block;}

  /* context graph */
  .gwrap{display:grid;grid-template-columns:1fr 300px;gap:14px;align-items:stretch;}
  @media (max-width:1100px){.gwrap{grid-template-columns:1fr;}}
  .gcanvas-wrap{position:relative;background:radial-gradient(ellipse 80% 80% at 50% 40%,#0e131b,var(--ink-2));border:1px solid var(--line);border-radius:12px;overflow:hidden;height:560px;}
  #gcanvas{display:block;width:100%;height:100%;cursor:grab;}
  #gcanvas:active{cursor:grabbing;}
  .glegend{position:absolute;top:12px;left:12px;background:rgba(8,10,14,.72);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:11px;color:var(--muted);backdrop-filter:blur(4px);pointer-events:none;}
  .gl-row{display:flex;align-items:center;gap:8px;line-height:1.7;}
  .gl-dot{width:9px;height:9px;border-radius:50%;flex:none;}
  .gl-ring{width:10px;height:10px;border-radius:50%;flex:none;border:1.5px dashed var(--med);}
  .ghint{position:absolute;bottom:11px;left:0;right:0;text-align:center;font-family:var(--mono);font-size:10px;color:var(--faint);pointer-events:none;}
  .ginfo{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 16px 18px;overflow-y:auto;height:560px;}
  .gi-empty{color:var(--faint);font-size:12px;line-height:1.6;}
  .gi-empty span{color:var(--ghost);font-size:11.5px;}
  .gi-kind{font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);}
  .gi-title{font-size:15px;font-weight:700;letter-spacing:-.02em;margin:6px 0 12px;word-break:break-word;color:var(--text-bright);}
  .gi-kv{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid var(--line);font-size:12px;}
  .gi-kv .k{color:var(--faint);}
  .gi-kv .v{color:var(--text);font-family:var(--mono);text-align:right;}
  .gi-bar{height:6px;border-radius:4px;background:var(--panel-3);overflow:hidden;margin-top:6px;}
  .gi-bar i{display:block;height:100%;border-radius:4px;}
  .gi-links{margin-top:14px;}
  .gi-link{display:flex;align-items:center;gap:8px;font-size:12px;padding:6px 0;color:var(--muted);border-bottom:1px solid rgba(37,43,54,.5);cursor:pointer;}
  .gi-link:hover{color:var(--text);}
  .gi-link .gl-dot{width:8px;height:8px;}
  .gfs{position:absolute;top:12px;right:12px;background:rgba(8,10,14,.8);border:1px solid var(--line-2);color:var(--muted);font-size:11.5px;font-weight:600;padding:6px 11px;border-radius:9px;text-decoration:none;display:flex;align-items:center;gap:6px;transition:.15s;z-index:5;}
  .gfs svg{width:13px;height:13px;}
  .gfs:hover{color:var(--accent);border-color:var(--accent-dim);background:var(--accent-soft);}

  /* add analyst form */
  .addform{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:18px;max-width:620px;}
  .addform .h{font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin-bottom:14px;}
  .addform .row{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;}
  .field label{display:block;font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-bottom:6px;}
  .field input,.field select{background:var(--ink-2);border:1px solid var(--line);border-radius:9px;padding:8px 11px;color:var(--text);font-size:13px;font-family:var(--sans);outline:none;}
  .field input:focus,.field select:focus{border-color:var(--accent-dim);}

  /* drawer */
  .overlay{position:fixed;inset:0;background:rgba(4,7,11,.62);backdrop-filter:blur(3px);opacity:0;pointer-events:none;transition:.2s;z-index:50;}
  .overlay.open{opacity:1;pointer-events:auto;}
  .drawer{position:fixed;top:0;right:0;height:100vh;width:min(540px,94vw);background:var(--ink-2);border-left:1px solid var(--line-2);transform:translateX(100%);transition:transform .26s cubic-bezier(.4,0,.2,1);z-index:60;display:flex;flex-direction:column;box-shadow:-30px 0 60px rgba(0,0,0,.5);}
  .drawer.open{transform:translateX(0);}
  .dhead{padding:20px 24px 16px;border-bottom:1px solid var(--line);flex:0 0 auto;}
  .dhead .eyebrow{font-family:var(--mono);font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;color:var(--faint);display:flex;align-items:center;justify-content:space-between;}
  .dhead .eyebrow .x{cursor:pointer;color:var(--faint);font-size:20px;line-height:1;padding:2px 6px;border-radius:6px;}
  .dhead .eyebrow .x:hover{color:var(--text);background:var(--panel);}
  .dhead h3{margin:10px 0 12px;font-size:15px;font-weight:700;letter-spacing:-0.02em;line-height:1.35;text-wrap:balance;}
  .dhead .strip{display:flex;gap:8px;flex-wrap:wrap;align-items:center;}
  .dbody{padding:18px 24px 30px;overflow-y:auto;flex:1 1 auto;min-height:0;display:flex;flex-direction:column;gap:18px;}
  .dbody>*{flex-shrink:0;}
  .sect-h{font-family:var(--sans);font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--faint);margin-bottom:9px;display:flex;align-items:center;gap:8px;}
  .sect-h::after{content:"";height:1px;flex:1;background:var(--line);}
  .memtext{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 15px;font-size:13px;color:var(--text);line-height:1.6;border-left:3px solid var(--accent);}
  .ai-block{background:var(--accent-soft);border:1px solid var(--accent-dim);border-radius:12px;padding:13px 15px;}
  .ai-block .ah{display:flex;align-items:center;gap:7px;font-family:var(--sans);font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--accent);margin-bottom:9px;}
  .ai-block .ah svg{width:12px;height:12px;}
  .ai-block pre{margin:0;font-family:var(--mono);font-size:11.5px;line-height:1.65;color:#cdbff5;white-space:pre-wrap;word-break:break-word;}
  .vchip{font-family:var(--mono);font-size:10px;font-weight:600;padding:2px 7px;border-radius:5px;border:1px solid;white-space:nowrap;}
  .vchip.fp{color:var(--good);border-color:rgba(70,184,122,.4);background:rgba(70,184,122,.1);}
  .vchip.tp{color:var(--high);border-color:rgba(232,145,58,.4);background:rgba(232,145,58,.1);}
  .vchip.l2{color:var(--pend);border-color:rgba(108,147,192,.4);background:rgba(108,147,192,.1);}
  .vchip.urgent{color:#fff;border-color:var(--crit);background:var(--crit);}
  .vchip.pend{color:var(--muted);border-color:var(--line-2);}
  .convo{display:flex;flex-direction:column;gap:10px;}
  .cmsg{border:1px solid var(--line);border-radius:10px;padding:11px 13px;background:var(--panel);}
  .cmsg .who{font-family:var(--mono);font-size:10px;margin-bottom:5px;display:flex;align-items:center;gap:6px;}
  .cmsg .who .tag{padding:1px 6px;border-radius:5px;font-weight:600;}
  .cmsg p{margin:0;font-size:12.5px;color:var(--muted);line-height:1.55;}
  .kv{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
  .kv .cell{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:10px 13px;}
  .kv .k{font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-bottom:5px;}
  .kv .v{font-family:var(--mono);font-size:12px;color:var(--text);}
  .entities{display:flex;flex-wrap:wrap;gap:7px;}
  .ent{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;color:var(--muted);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:5px 9px;}
  .ent .ico{color:var(--accent);}
  .dact{display:flex;gap:9px;padding:15px 24px;border-top:1px solid var(--line);background:var(--ink-2);flex:0 0 auto;}
  .dact .btn{flex:1;justify-content:center;}
  .btn.ok{color:var(--good);border-color:rgba(70,184,122,.3);background:rgba(70,184,122,.07);}
  .btn.ok:hover{border-color:var(--good);box-shadow:0 0 16px rgba(70,184,122,.14);}
  .btn.warn{color:var(--med);border-color:rgba(230,195,76,.3);background:rgba(230,195,76,.06);}
  .btn.no{color:#ff8f8f;border-color:rgba(240,85,82,.25);background:rgba(240,85,82,.06);}

  .hrow{display:flex;gap:32px;flex-wrap:wrap;align-items:flex-start;}
  .hlabel{font-family:var(--mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
  .hbig{font-size:26px;font-weight:700;color:var(--quar);line-height:1;}
  .hsub{font-size:11px;color:var(--muted);margin-top:4px;}
  .hmeta{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:8px;}
  .trend{display:flex;gap:8px;align-items:flex-end;height:66px;padding-top:6px;}
  .tbar{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:4px;height:100%;}
  .tfill{width:16px;border-radius:3px 3px 0 0;min-height:6px;}
  .tw{font-family:var(--mono);font-size:9px;color:var(--muted);}
  @media (max-width:1100px){.stats{grid-template-columns:repeat(2,1fr);} .flow{display:none;}}
  @media (max-width:720px){.shell{grid-template-columns:1fr;}.rail{display:none;}.main{padding:18px 16px 50px;}}
  .fade{opacity:0;transform:translateY(8px);animation:fin .5s forwards;}
  @keyframes fin{to{opacity:1;transform:none;}}
</style>
</head>
<body>


<div class="shell">
  <aside class="rail">
    <div class="glyph"><svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 L20 7 L17 14 C15.5 18 12 22 12 22 C12 22 8.5 18 7 14 L4 7 Z"/><path d="M12 8 L12 15 M9 11 L12 8 L15 11"/></svg></div>
    <button class="navbtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"/></svg><span class="tip">Triage Console</span></button>
    <button class="navbtn active"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg><span class="tip">AI Memory</span></button>
    <button class="navbtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12l9-9 9 9M5 10v10h14V10"/></svg><span class="tip">Dashboard</span></button>
    <button class="navbtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1" fill="currentColor"/></svg><span class="tip">Threat Hunting</span></button>
    <div class="spacer"></div>
    <button class="navbtn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 100-6 3 3 0 000 6z"/><path d="M19 12a7 7 0 00-.1-1l2-1.6-2-3.4-2.4 1a7 7 0 00-1.7-1L14.5 2h-5l-.3 2.9a7 7 0 00-1.7 1l-2.4-1-2 3.4L3.1 11a7 7 0 000 2l-2 1.6 2 3.4 2.4-1a7 7 0 001.7 1L9.5 22h5l.3-2.9a7 7 0 001.7-1l2.4 1 2-3.4-2-1.6a7 7 0 00.1-1z"/></svg><span class="tip">Settings</span></button>
  </aside>

  <main class="main">
    <div class="topbar fade">
      <div class="brand">
        <h1><span class="wm"><b>RAP</b>TOR</span></h1>
        <p>AI Memory · Security Context Graph</p>
      </div>
      <div class="actions">
        <button class="btn ghost" onclick="flash(this,'Refreshed')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 019-9 9 9 0 016.7 3M21 12a9 9 0 01-9 9 9 9 0 01-6.7-3"/><path d="M18 3v3.5H14.5M6 21v-3.5H9.5"/></svg>Refresh</button>
        <button class="btn primary" id="pollBtn" onclick="pollJira(this)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4v6h6M20 20v-6h-6"/><path d="M20 8a8 8 0 00-14-3M4 16a8 8 0 0014 3"/></svg>Poll Jira now</button>
      </div>
    </div>

    <!-- stats -->
    <div class="stats fade" style="animation-delay:.05s">
      <div class="stat">
        <div class="stripe" style="background:var(--quar)"></div>
        <div class="lbl">In Queue <svg viewBox="0 0 24 24" fill="none" stroke="var(--quar)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8v4l3 2"/><circle cx="12" cy="12" r="9"/></svg></div>
        <div class="big" style="color:var(--quar)">14</div>
        <div class="sub">awaiting L2 review</div>
      </div>
      <div class="stat">
        <div class="stripe" style="background:var(--gold)"></div>
        <div class="lbl">Golden Memories <svg viewBox="0 0 24 24" fill="none" stroke="var(--gold)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l2.9 6.3 6.9.7-5.2 4.6 1.5 6.8L12 17.8 5.9 20.4l1.5-6.8L2.2 9l6.9-.7z"/></svg></div>
        <div class="big" style="color:var(--gold)">63</div>
        <div class="sub">ground-truth precedents</div>
      </div>
      <div class="stat">
        <div class="stripe" style="background:var(--good)"></div>
        <div class="lbl">AI Accuracy <svg viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.1V12a10 10 0 11-5.9-9.1"/><path d="M22 4L12 14.01l-3-3"/></svg></div>
        <div class="big" style="color:var(--good)">74<span style="font-size:18px">%</span></div>
        <div class="sub">AI vs L1 agreement</div>
      </div>
      <div class="stat">
        <div class="stripe" style="background:var(--pend)"></div>
        <div class="lbl">Verdicts Tracked <svg viewBox="0 0 24 24" fill="none" stroke="var(--pend)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg></div>
        <div class="big" style="color:var(--pend)">1,284</div>
        <div class="sub">lifetime closures compared</div>
      </div>
    </div>

    <!-- tier flow: routed by whether AI agreed with the analyst on Jira closure -->
    <div class="flow fade" style="animation-delay:.08s">
      <div class="lanes">
        <div class="lane">
          <span class="chip" style="color:var(--good);border-color:rgba(70,184,122,.3)"><span class="d" style="background:var(--good)"></span>AI &amp; L1 agreed</span>
          <div class="arrow">→<small>auto</small></div>
          <span class="chip" style="color:var(--cur);border-color:var(--accent-dim)"><span class="d" style="background:var(--cur)"></span>Curated</span>
          <span class="tail">used in prompts</span>
        </div>
        <div class="lane">
          <span class="chip" style="color:var(--crit);border-color:rgba(240,85,82,.28)"><span class="d" style="background:var(--crit)"></span>AI ↔ L1 conflict</span>
          <div class="arrow">→</div>
          <span class="chip" style="color:var(--quar);border-color:rgba(232,145,58,.3)"><span class="d" style="background:var(--quar)"></span>Quarantine</span>
          <div class="arrow">→<small>L2 promotes</small></div>
          <span class="chip" style="color:var(--gold);border-color:rgba(230,195,76,.3)"><span class="d" style="background:var(--gold)"></span>Golden</span>
          <span class="tail">used in prompts · max weight</span>
        </div>
      </div>
      <div class="note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a5 5 0 00-5 5c0 2 1 3 1 5h8c0-2 1-3 1-5a5 5 0 00-5-5zM9 20h6M10 22h4"/></svg>Curated &amp; Golden memories are injected into every RAPTOR prompt as prior analyst decisions. An L2 can demote either back to Quarantine.</div>
    </div>

    <!-- memory health & overturn trend -->
    <div class="flow fade" style="animation-delay:.09s">
      <div class="hrow">
        <div class="hblock">
          <div class="hlabel">Memory pollution</div>
          <div class="hbig" id="mh-quarrate">—</div>
          <div class="hsub">quarantine share of all memory</div>
          <div class="hmeta" id="mh-tierdist">—</div>
        </div>
        <div class="hblock" style="flex:1;min-width:280px">
          <div class="hlabel">Overturn trend — weekly AI vs human agreement</div>
          <div class="trend" id="mh-trend"><span class="cell-faint">loading…</span></div>
        </div>
      </div>
    </div>

    <!-- tabs -->
    <div class="tabs fade" style="animation-delay:.1s">
      <button class="tab on" data-p="quar" onclick="switchTab('quar')">Quarantine Queue <span class="cnt">14</span></button>
      <button class="tab" data-p="graph" onclick="switchTab('graph')">Context Graph <span class="cnt" id="cnt-graph-tab">0</span></button>
      <button class="tab" data-p="sugg" onclick="switchTab('sugg')">Allowlist Suggestions <span class="cnt" id="cnt-sugg-tab">0</span></button>
      <button class="tab" data-p="plan" onclick="switchTab('plan')">Planned Activity <span class="cnt" id="cnt-plan-tab">0</span></button>
      <button class="tab" data-p="gold" onclick="switchTab('gold')">Golden Memory <span class="cnt">63</span></button>
      <button class="tab" data-p="acc" onclick="switchTab('acc')">Analyst Accuracy <span class="cnt" id="cnt-acc-tab">0</span></button>
      <button class="tab" data-p="ana" onclick="switchTab('ana')">Analyst Registry <span class="cnt">6</span></button>
    </div>

    <!-- QUARANTINE PANE -->
    <div class="pane on" id="pane-quar">
      <div class="toolbar">
        <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
          <input id="q-quar" placeholder="Filter by content, alert, type…" oninput="renderQuar()"/></div>
        <select class="f" id="ft-quar" onchange="renderQuar()"><option value="">All alert types</option></select>
        <div class="right"><span class="cell-faint" id="cnt-quar"></span></div>
      </div>
      <div class="card"><div class="twrap"><table>
        <thead><tr><th>Alert / Jira</th><th>Type</th><th>Memory content</th><th>Conflict</th><th>Conf</th><th>Date</th><th></th></tr></thead>
        <tbody id="tb-quar"></tbody>
      </table></div></div>
    </div>

    <!-- CONTEXT GRAPH PANE -->
    <div class="pane" id="pane-graph">
      <div class="gwrap">
        <div class="gcanvas-wrap">
          <canvas id="gcanvas"></canvas>
          <a class="gfs" href="/memory/graph" target="_blank" rel="noopener"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>Open full screen</a>
          <div class="glegend">
            <div class="gl-row"><span class="gl-dot" style="background:#6C93C0"></span>Device</div>
            <div class="gl-row"><span class="gl-dot" style="background:#9E86F0"></span>User</div>
            <div class="gl-row" style="margin-top:6px;color:var(--faint);font-size:9.5px;letter-spacing:.08em">ALERT VERDICT</div>
            <div class="gl-row"><span class="gl-dot" style="background:#46B87A"></span>Auto-closed FP</div>
            <div class="gl-row"><span class="gl-dot" style="background:#E8913A"></span>Auto-closed TP</div>
            <div class="gl-row"><span class="gl-dot" style="background:#6C93C0"></span>Needs L2</div>
            <div class="gl-row"><span class="gl-dot" style="background:#F05552"></span>Urgent</div>
            <div class="gl-row" style="margin-top:6px"><span class="gl-ring"></span>AI↔human disagreement</div>
          </div>
          <div class="ghint">drag to reposition · hover a node to trace its links · click for details</div>
        </div>
        <div class="ginfo" id="ginfo">
          <div class="gi-empty">Hover or click a node.<br/><span>Devices and users are the entities RAPTOR tracks; alerts link them, colored by verdict. A dashed ring marks where the AI and the analyst disagreed — the memory it learned from.</span></div>
        </div>
      </div>
    </div>

    <!-- GOLDEN PANE -->
    <div class="pane" id="pane-gold">
      <div class="toolbar">
        <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
          <input id="q-gold" placeholder="Filter by content, alert, source…" oninput="renderGold()"/></div>
        <select class="f" id="ft-gold" onchange="renderGold()"><option value="">All alert types</option></select>
        <div class="right"><span class="cell-faint" id="cnt-gold"></span></div>
      </div>
      <div class="card"><div class="twrap"><table>
        <thead><tr><th>Alert / Jira</th><th>Type</th><th>Memory content</th><th>Tier</th><th>Scope</th><th>Conf</th><th>Approved by</th><th>Date</th><th></th></tr></thead>
        <tbody id="tb-gold"></tbody>
      </table></div></div>
    </div>

    <!-- SUGGESTIONS PANE -->
    <div class="pane" id="pane-sugg">
      <div class="toolbar">
        <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
          <input id="q-sugg" placeholder="Filter by actor, alert, type…" oninput="renderSugg()"/></div>
        <div class="right">
          <span class="cell-faint" id="cnt-sugg"></span>
          <button class="btn primary sm" id="anBtn" onclick="analyzeSugg(this)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4v6h6M20 20v-6h-6"/><path d="M20 8a8 8 0 00-14-3M4 16a8 8 0 0014 3"/></svg>Analyze closures</button>
        </div>
      </div>
      <div class="card"><div class="twrap"><table>
        <thead><tr><th>Alert type</th><th>Actor / Device</th><th>Commands pinned</th><th>Pattern</th><th>Evidence</th><th></th></tr></thead>
        <tbody id="tb-sugg"></tbody>
      </table></div></div>
      <div class="note" style="margin-top:12px;font-size:12px;color:var(--muted);display:flex;gap:8px;align-items:flex-start"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="flex:none;margin-top:2px"><path d="M12 2a5 5 0 00-5 5c0 2 1 3 1 5h8c0-2 1-3 1-5a5 5 0 00-5-5zM9 20h6M10 22h4"/></svg><span>Mined from tickets a human closed <b>False Positive</b> repeatedly for the same actor while RAPTOR escalated to NEEDS_L2. <b>Arm</b> writes a golden auto-close entry (actor + device + any pinned commands) — future matches close deterministically with no LLM call. Nothing is suppressed until you arm it, and it's reversible from the Golden tab.</span></div>
    </div>

    <!-- PLANNED ACTIVITY PANE -->
    <div class="pane" id="pane-plan">
      <div class="addform" style="max-width:820px">
        <div class="h">Declare a maintenance / compliance window</div>
        <div class="row">
          <div class="field"><label>Command / script substring</label><input id="pa-pattern" type="text" placeholder="compliance_scan.ps1" style="width:240px"/></div>
          <div class="field"><label>Label</label><input id="pa-label" type="text" placeholder="Q3 compliance scan" style="width:190px"/></div>
          <div class="field"><label>Active until (UTC)</label><input id="pa-until" type="date" style="width:150px"/></div>
          <button class="btn primary" onclick="addPA()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Declare</button>
        </div>
        <div class="cell-faint" style="margin-top:11px;font-size:11.5px;line-height:1.5">Matches the substring against alert command lines (case-insensitive, actor- and device-agnostic). Auto-closes matches as FALSE POSITIVE until the date, then <b>self-expires</b>. Min 4 chars — be specific (a whole script name, not <code>.ps1</code>). This is <b>not</b> golden memory — it's a temporary announcement.</div>
      </div>
      <div class="card"><div class="twrap"><table style="min-width:820px">
        <thead><tr><th>Window</th><th>Command match</th><th>Scope</th><th>Status</th><th>Auto-closed</th><th>Expires (UTC)</th><th></th></tr></thead>
        <tbody id="tb-plan"></tbody>
      </table></div></div>
    </div>

    <!-- ANALYST PANE -->
    <div class="pane" id="pane-ana">
      <div class="addform">
        <div class="h">Add / update analyst</div>
        <div class="row">
          <div class="field"><label>Email</label><input id="a-email" type="email" placeholder="john@example.com" style="width:220px"/></div>
          <div class="field"><label>Display name</label><input id="a-name" type="text" placeholder="John Doe" style="width:170px"/></div>
          <div class="field"><label>Role</label><select id="a-role"><option value="L1">L1 Analyst</option><option value="L2">L2 Analyst</option></select></div>
          <button class="btn primary" onclick="addAnalyst()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Add</button>
        </div>
      </div>
      <div class="card"><div class="twrap"><table style="min-width:560px">
        <thead><tr><th>Display name</th><th>Email</th><th>Role</th><th>Attributed comments</th><th></th></tr></thead>
        <tbody id="tb-ana"></tbody>
      </table></div></div>
    </div>

    <!-- ANALYST ACCURACY PANE -->
    <div class="pane" id="pane-acc">
      <div class="card"><div class="twrap"><table style="min-width:640px">
        <thead><tr><th>Analyst</th><th>Scored (correct / total)</th><th>Escalation precision</th><th>Trust tier</th><th>Last active</th></tr></thead>
        <tbody id="tb-acc"></tbody>
      </table></div></div>
      <div class="note" style="margin-top:12px;font-size:12px;color:var(--muted)"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg> Escalation precision is scored only on tickets that went L1 → L2 (the only case with an independent second opinion). An escalation counts as correct when L2 confirmed a true positive. Trust tier locks in after 50 scored decisions.</div>
    </div>
  </main>
</div>

<!-- drawer -->
<div class="overlay" id="ov" onclick="closeDrawer()"></div>
<aside class="drawer" id="drawer">
  <div class="dhead">
    <div class="eyebrow"><span id="d-eyebrow">Quarantined memory</span><span class="x" onclick="closeDrawer()">×</span></div>
    <h3 id="d-title"></h3>
    <div class="strip" id="d-strip"></div>
  </div>
  <div class="dbody" id="d-body"></div>
  <div class="dact" id="d-act"></div>
</aside>

<script>
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
var JIRA_BASE='https://jira.example.com/browse/';
function jiraLink(k){return k?'<a href="'+JIRA_BASE+encodeURIComponent(k)+'" target="_blank" rel="noopener" onclick="event.stopPropagation()" class="jira">'+esc(k)+' ↗</a>':'';}
var _sp=document.createElement('style');_sp.textContent='@keyframes sp{to{transform:rotate(360deg)}}';document.head.appendChild(_sp);
function relTime(iso){if(!iso)return '—';var t=Date.parse(iso);if(isNaN(t))return esc(String(iso));var d=(Date.now()-t)/1000;if(d<60)return 'just now';if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago';}
function stripFlag(s){s=s||'';return s.indexOf('[FLAGGED]')===0?s.slice(9).trim():s;}
function isFlagged(m){return (m.quarantine_reason||'').indexOf('[FLAGGED]')===0;}
function scopeBadge(m){return (m.scope==='playbook')?'<span class="badge t-pb"><span class="d"></span>Playbook</span>':'<span class="badge t-ent"><span class="d"></span>Entity</span>';}
function afpBadge(m){return m.auto_fp?'<span class="badge t-afp" title="Deterministic auto-close FP when this actor recurs">⚡ Auto-FP</span>':'';}

var QUAR=[],GOLD=[],ANA=[],SUGG=[],PLAN=[];

function setTab(p,n){var e=document.querySelector('.tab[data-p="'+p+'"] .cnt');if(e)e.textContent=n;}
function statEls(){return document.querySelectorAll('.stats .stat .big');}
function setStat(i,txt){var e=statEls()[i];if(e)e.textContent=txt;}

function fillTypes(sel,arr){
  var cur=document.getElementById(sel);if(!cur)return;var v=cur.value;
  var types=Array.from(new Set(arr.map(function(x){return x.alert_type;}).filter(Boolean))).sort();
  cur.innerHTML='<option value="">All alert types</option>'+types.map(function(t){return '<option value="'+esc(t)+'">'+esc(t)+'</option>';}).join('');
  cur.value=v;
}

function loadShadow(){
  fetch('/api/memory/shadow-stats').then(function(r){return r.json();}).then(function(d){
    var acc=d.ai_l1_accuracy;
    var el=statEls()[2];if(el)el.innerHTML=(acc!=null?Math.round(acc*100):'—')+'<span style="font-size:18px">%</span>';
    setStat(3,(d.total_shadow_results||0).toLocaleString());
  }).catch(function(){});
}
function loadQuar(){
  fetch('/api/memory/quarantine?limit=200').then(function(r){return r.json();}).then(function(d){
    QUAR=Array.isArray(d)?d:(d.memories||[]);setStat(0,QUAR.length);setTab('quar',QUAR.length);fillTypes('ft-quar',QUAR);renderQuar();
  }).catch(function(){QUAR=[];renderQuar();});
}
function loadGold(){
  // Page through the whole curated+golden set so the tab shows EVERY memory, not the
  // newest page. Count comes from the server's true total, never len(list) (which caps
  // at the page size). Guarded against runaway loops by the total / short-page checks.
  var PAGE=500;GOLD=[];
  function fetchPage(offset){
    return fetch('/api/memory/golden?limit='+PAGE+'&offset='+offset).then(function(r){return r.json();}).then(function(d){
      var rows=Array.isArray(d)?d:(d.memories||[]);
      var total=(d&&!Array.isArray(d)&&typeof d.total==='number')?d.total:null;
      GOLD=GOLD.concat(rows);
      var more=(total!=null)?(GOLD.length<total&&rows.length>0):(rows.length===PAGE);
      return more?fetchPage(offset+PAGE):(total!=null?total:GOLD.length);
    });
  }
  fetchPage(0).then(function(total){
    setStat(1,total);setTab('gold',total);fillTypes('ft-gold',GOLD);renderGold();
  }).catch(function(){GOLD=[];renderGold();});
}
function loadAna(){
  fetch('/api/memory/analysts').then(function(r){return r.json();}).then(function(d){
    ANA=Array.isArray(d)?d:(d.analysts||[]);setTab('ana',ANA.length);renderAna();
  }).catch(function(){ANA=[];renderAna();});
}
function loadHealth(){
  fetch('/api/memory/pollution').then(function(r){return r.json();}).then(function(d){
    if(!d||d.error)return;
    var qr=d.quarantine_rate;
    document.getElementById('mh-quarrate').textContent=(qr!=null?Math.round(qr*100)+'%':'—');
    var bt=d.by_tier||{};
    document.getElementById('mh-tierdist').textContent=
      'quarantine '+(bt.quarantine||0)+' · curated '+(bt.curated||0)+' · golden '+(bt.golden||0)
      +'  |  AI-conflict '+(d.ai_disagreement_quarantine||0);
  }).catch(function(){});
  fetch('/api/memory/overturn-trend?weeks=10').then(function(r){return r.json();}).then(function(d){
    renderTrend((d&&d.series)||[]);
  }).catch(function(){renderTrend([]);});
}
function renderTrend(series){
  var el=document.getElementById('mh-trend');
  if(!series.length){el.innerHTML='<span class="cell-faint">no resolved verdicts yet</span>';return;}
  el.innerHTML=series.map(function(w){
    var acc=w.accuracy==null?0:w.accuracy;
    var h=Math.max(6,Math.round(acc*46));
    var col=acc>=0.75?'var(--good)':(acc>=0.5?'var(--quar)':'var(--crit)');
    var tip=w.week+' · '+(w.accuracy==null?'—':Math.round(acc*100)+'%')+' ('+w.matches+'/'+w.total+')';
    return '<span class="tbar" title="'+esc(tip)+'"><span class="tfill" style="height:'+h+'px;background:'+col+'"></span><span class="tw">'+esc(w.week.replace(/^\d+-/,''))+'</span></span>';
  }).join('');
}
function loadAcc(){
  fetch('/api/memory/analyst-profiles?limit=100').then(function(r){return r.json();}).then(function(d){
    var arr=Array.isArray(d)?d:[];setTab('acc',arr.length);renderAcc(arr);
  }).catch(function(){renderAcc([]);});
}
function renderAcc(list){
  var tb=document.getElementById('tb-acc');
  if(!list.length){tb.innerHTML='<tr><td colspan="5"><div class="empty">No scored analysts yet — escalation precision is recorded only when a ticket goes L1 → L2</div></td></tr>';return;}
  tb.innerHTML=list.map(function(a){
    var acc=a.total_verdicts?Math.round((a.accuracy||0)*100)+'%':'—';
    var tier=a.trust_tier||'new';
    var tc=tier==='senior'?'role-l2':(tier==='standard'?'role-l1':'');
    return '<tr style="cursor:default">'
      +'<td style="font-weight:600;color:var(--text);font-size:13px">'+esc(a.display_name||a.analyst_id||'—')+'</td>'
      +'<td class="cell-faint">'+(a.correct_verdicts||0)+' / '+(a.total_verdicts||0)+'</td>'
      +'<td class="conf">'+acc+'</td>'
      +'<td><span class="role '+tc+'">'+esc(tier)+'</span></td>'
      +'<td class="cell-faint">'+esc(relTime(a.last_active))+'</td>'
      +'</tr>';
  }).join('');
}

// Header is the ticket ID (the queue's convention). alert_ref is only a fallback —
// it's an opaque MDE/Sentinel alert id (e.g. a GUID_1) and must never be the title
// (DEMO-106488 showed "da6877f6bd-296a-…" because alert_ref was preferred over jira_key).
function memTitle(m){return m.jira_key||m.alert_ref||'Untitled memory';}

function renderQuar(){
  var q=(document.getElementById('q-quar').value||'').toLowerCase();
  var ft=document.getElementById('ft-quar').value;
  var rows=QUAR.filter(function(m){
    if(ft&&m.alert_type!==ft)return false;
    if(q&&!((memTitle(m)+(m.content||'')+(m.alert_type||'')).toLowerCase().includes(q)))return false;return true;});
  document.getElementById('cnt-quar').textContent=rows.length+' in queue';
  var tb=document.getElementById('tb-quar');
  if(!rows.length){tb.innerHTML='<tr><td colspan="7"><div class="empty">Queue clear — no conflicts awaiting review</div></td></tr>';return;}
  tb.innerHTML=rows.map(function(m){
    var reason=stripFlag(m.quarantine_reason)||'—';
    return '<tr onclick="openMem(\''+esc(m.id)+'\',\'quar\')">'
      +'<td class="alert-cell"><div class="an">'+(isFlagged(m)?'<span class="flagged">⚑ </span>':'')+esc(memTitle(m))+'</div>'+jiraLink(m.jira_key)+'</td>'
      +'<td><span class="type">'+esc(m.alert_type||'—')+'</span></td>'
      +'<td><div class="content"><span class="qt">“</span>'+esc((m.content||'').slice(0,110))+((m.content||'').length>110?'…':'')+'<span class="qt">”</span></div></td>'
      +'<td><div class="conflict"><span class="l1">'+esc(reason.slice(0,60))+(reason.length>60?'…':'')+'</span></div></td>'
      +'<td class="conf">'+Math.round((m.confidence||0)*100)+'%</td>'
      +'<td class="cell-faint">'+esc(relTime(m.created_at))+'</td>'
      +'<td onclick="event.stopPropagation()"><div class="rowacts">'
      +'<button class="ib ok" title="Promote to golden" onclick="act(\''+esc(m.id)+'\',\'promote\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></button>'
      +'<button class="ib flag" title="Flag for review" onclick="act(\''+esc(m.id)+'\',\'flag\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7"/></svg></button>'
      +'<button class="ib no" title="Dismiss" onclick="act(\''+esc(m.id)+'\',\'dismiss\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg></button>'
      +'</div></td></tr>';
  }).join('');
}
function renderGold(){
  var q=(document.getElementById('q-gold').value||'').toLowerCase();
  var ft=document.getElementById('ft-gold').value;
  var rows=GOLD.filter(function(m){
    if(ft&&m.alert_type!==ft)return false;
    if(q&&!((memTitle(m)+(m.content||'')+(m.alert_type||'')+(m.resolved_by||'')).toLowerCase().includes(q)))return false;return true;});
  document.getElementById('cnt-gold').textContent=rows.length+' memories';
  var tb=document.getElementById('tb-gold');
  if(!rows.length){tb.innerHTML='<tr><td colspan="9"><div class="empty">No memories match</div></td></tr>';return;}
  tb.innerHTML=rows.map(function(m){
    var isG=m.tier==='golden';var tbc=isG?'t-gold':'t-cur';var tl=isG?'Golden':'Curated';
    var scopeCell=scopeBadge(m)+(m.auto_fp?' '+afpBadge(m):'')+(m.actor?'<div class="cell-faint" style="font-size:10px;margin-top:3px">'+esc(m.actor)+(m.device?' · '+esc(m.device):'')+'</div>':'')
      // App scope is the distinguishing fact on a CASB verdict — show it on the row so
      // "Slack-only" is visible without opening the drawer.
      +((m.apps&&m.apps.length)?'<div class="cell-faint" style="font-size:10px;margin-top:2px">app: '+esc(m.apps.join(', '))+'</div>':'');
    return '<tr onclick="openMem(\''+esc(m.id)+'\',\'gold\')">'
      +'<td class="alert-cell"><div class="an">'+esc(memTitle(m))+'</div>'+jiraLink(m.jira_key)+'</td>'
      +'<td><span class="type">'+esc(m.alert_type||'—')+'</span></td>'
      +'<td><div class="content"><span class="qt">“</span>'+esc((m.content||'').slice(0,110))+((m.content||'').length>110?'…':'')+'<span class="qt">”</span></div></td>'
      +'<td><span class="badge '+tbc+'"><span class="d"></span>'+tl+'</span></td>'
      +'<td>'+scopeCell+'</td>'
      +'<td class="conf">'+Math.round((m.confidence||0)*100)+'%</td>'
      +'<td class="cell-faint" style="font-family:var(--sans);color:var(--muted)">'+esc(m.resolved_by||'—')+'</td>'
      +'<td class="cell-faint">'+esc(relTime(m.resolved_at||m.created_at))+'</td>'
      +'<td onclick="event.stopPropagation()"><div class="rowacts">'
      +'<button class="ib flag" title="Demote to quarantine" onclick="act(\''+esc(m.id)+'\',\'demote\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12l7 7 7-7"/></svg></button>'
      +'<button class="ib no" title="Delete memory" onclick="act(\''+esc(m.id)+'\',\'delete\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M10 11v6M14 11v6M6 7l1 13h10l1-13"/></svg></button>'
      +'</div></td></tr>';
  }).join('');
}
function renderAna(){
  var tb=document.getElementById('tb-ana');
  if(!ANA.length){tb.innerHTML='<tr><td colspan="4"><div class="empty">No analysts registered yet</div></td></tr>';return;}
  tb.innerHTML=ANA.map(function(a){
    return '<tr style="cursor:default">'
      +'<td style="font-weight:600;color:var(--text);font-size:13px">'+esc(a.display_name||'—')+'</td>'
      +'<td class="cell-faint">'+esc(a.email||'')+'</td>'
      +'<td><span class="role '+(a.role==='L2'?'role-l2':'role-l1')+'">'+esc(a.role||'')+'</span></td>'
      +'<td style="text-align:right"><button class="ib no" title="Remove analyst" onclick="delAna(\''+esc(a.email)+'\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M10 11v6M14 11v6M6 7l1 13h10l1-13"/></svg></button></td>'
      +'</tr>';
  }).join('');
}
function loadSugg(){
  fetch('/api/memory/suggestions?status=pending&limit=100').then(function(r){return r.json();}).then(function(d){
    SUGG=(d&&d.suggestions)||[];setTab('sugg',SUGG.length);renderSugg();
  }).catch(function(){SUGG=[];renderSugg();});
}
function cmdChips(cmds){
  if(!cmds||!cmds.length)return '<span class="cell-faint">any command</span>';
  var s=cmds.slice(0,4).map(function(c){return '<code style="font-family:var(--mono);font-size:10.5px;color:var(--accent);background:var(--accent-soft);padding:1px 5px;border-radius:5px;margin-right:3px">'+esc(c)+'</code>';}).join('');
  return s+(cmds.length>4?'<span class="cell-faint">+'+(cmds.length-4)+'</span>':'');
}
function renderSugg(){
  var q=(document.getElementById('q-sugg').value||'').toLowerCase();
  var rows=SUGG.filter(function(s){if(q&&!(((s.alert_type||'')+(s.actor||'')+(s.device||'')+(s.alert_name||'')).toLowerCase().includes(q)))return false;return true;});
  document.getElementById('cnt-sugg').textContent=rows.length+' pending';
  var tb=document.getElementById('tb-sugg');
  if(!rows.length){tb.innerHTML='<tr><td colspan="6"><div class="empty">No suggestions — click “Analyze closures” to mine repeated same-actor FP patterns</div></td></tr>';return;}
  tb.innerHTML=rows.map(function(s){
    var keys=s.evidence_jira_keys||[];
    var ev=keys.slice(0,3).map(jiraLink).join(' ')+(keys.length>3?' <span class="cell-faint">+'+(keys.length-3)+'</span>':'');
    return '<tr style="cursor:default">'
      +'<td><span class="type">'+esc(s.alert_type||'—')+'</span><div class="cell-faint" style="margin-top:3px;max-width:210px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(s.alert_name||'')+'</div></td>'
      +'<td><div class="mono" style="font-size:12px;color:var(--text)">'+esc(s.actor||'—')+'</div><div class="cell-faint">'+esc(s.device||'any device')+'</div></td>'
      +'<td style="max-width:230px">'+cmdChips(s.commands)+'</td>'
      +'<td><span class="badge t-afp"><span class="d"></span>'+(s.fp_count||0)+' FP closures</span></td>'
      +'<td class="cell-faint">'+ev+'</td>'
      +'<td onclick="event.stopPropagation()"><div class="rowacts">'
      +'<button class="ib ok" title="Arm actor-allowlist" onclick="armSugg(\''+esc(s.id)+'\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h7l-1 8 10-12h-7z"/></svg></button>'
      +'<button class="ib no" title="Dismiss" onclick="dismissSugg(\''+esc(s.id)+'\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg></button>'
      +'</div></td></tr>';
  }).join('');
}
function armSugg(id){
  var s=null;for(var i=0;i<SUGG.length;i++){if(SUGG[i].id===id){s=SUGG[i];break;}}
  var who=s?(s.actor+(s.device?' on '+s.device:'')):'this actor';
  if(!window.confirm('Arm the actor-allowlist for '+who+'?\n\nFuture matching alerts auto-close as FALSE POSITIVE with no LLM call. Reversible from the Golden Memory tab.'))return;
  fetch('/api/memory/suggestions/'+encodeURIComponent(id)+'/arm',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(r){return r.json();}).then(function(){loadSugg();loadGold();}).catch(function(){});
}
function dismissSugg(id){
  fetch('/api/memory/suggestions/'+encodeURIComponent(id)+'/dismiss',{method:'POST'}).then(function(r){return r.json();}).then(function(){loadSugg();}).catch(function(){});
}
function analyzeSugg(btn){
  var o=btn.innerHTML;btn.disabled=true;btn.style.opacity='.7';
  btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:sp 1s linear infinite"><path d="M12 3a9 9 0 109 9"/></svg>Analyzing…';
  fetch('/api/memory/suggestions/analyze?lookback_days=30&min_count=3',{method:'POST'}).then(function(r){return r.json();}).then(function(){
    setTimeout(function(){btn.disabled=false;btn.style.opacity='';btn.innerHTML=o;loadSugg();},3000);
  }).catch(function(){btn.disabled=false;btn.style.opacity='';btn.innerHTML=o;});
}
function loadPA(){
  fetch('/api/memory/planned-activity?limit=100').then(function(r){return r.json();}).then(function(d){
    PLAN=(d&&d.windows)||[];
    var active=PLAN.filter(function(w){return w.active;}).length;
    setTab('plan',active);renderPA();
  }).catch(function(){PLAN=[];renderPA();});
}
function renderPA(){
  var tb=document.getElementById('tb-plan');
  if(!PLAN.length){tb.innerHTML='<tr><td colspan="7"><div class="empty">No windows declared — add one above when a compliance/maintenance script is scheduled to run fleet-wide</div></td></tr>';return;}
  tb.innerHTML=PLAN.map(function(w){
    var status=w.active
      ?'<span class="badge t-afp"><span class="d"></span>Active</span>'
      :'<span class="badge t-quar" style="opacity:.75"><span class="d"></span>Expired</span>';
    var exp=(w.expires_at||'').slice(0,16).replace('T',' ');
    return '<tr style="cursor:default'+(w.active?'':';opacity:.55')+'">'
      +'<td><div style="font-weight:600;color:var(--text);font-size:12.5px">'+esc(w.label||'(no label)')+'</div><div class="cell-faint">'+esc(w.created_by||'')+'</div></td>'
      +'<td><code style="font-family:var(--mono);font-size:11px;color:var(--accent);background:var(--accent-soft);padding:2px 6px;border-radius:5px">'+esc(w.pattern||'')+'</code></td>'
      +'<td><span class="type">'+esc(w.alert_type||'any')+'</span></td>'
      +'<td>'+status+'</td>'
      +'<td class="conf">'+(w.hit_count||0)+'</td>'
      +'<td class="cell-faint">'+esc(exp)+'</td>'
      +'<td onclick="event.stopPropagation()"><div class="rowacts"><button class="ib no" title="Delete window" onclick="delPA(\''+esc(w.id)+'\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M10 11v6M14 11v6M6 7l1 13h10l1-13"/></svg></button></div></td>'
      +'</tr>';
  }).join('');
}
function addPA(){
  var pat=document.getElementById('pa-pattern').value.trim();
  var label=document.getElementById('pa-label').value.trim();
  var until=document.getElementById('pa-until').value;
  if(pat.length<4){alert('Command substring must be at least 4 characters — be specific (a whole script name).');return;}
  if(!until){alert('Pick an "active until" date.');return;}
  fetch('/api/memory/planned-activity',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pattern:pat,label:label,expires_at:until})})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){
      if(!res.ok){alert('Could not declare: '+((res.j&&res.j.detail)||'error'));return;}
      document.getElementById('pa-pattern').value='';document.getElementById('pa-label').value='';document.getElementById('pa-until').value='';
      loadPA();
    }).catch(function(){});
}
function delPA(id){
  if(!window.confirm('Delete this planned-activity window? Matching alerts will no longer auto-close.'))return;
  fetch('/api/memory/planned-activity/'+encodeURIComponent(id),{method:'DELETE'}).then(function(r){return r.json();}).then(function(){loadPA();}).catch(function(){});
}
function switchTab(p){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('on',t.dataset.p===p);});
  document.querySelectorAll('.pane').forEach(function(pane){pane.classList.toggle('on',pane.id==='pane-'+p);});
  if(p==='graph'){gInit();ensureGraph();startGraph();}else{stopGraph();}
}

//%%GRAPH_JS%%
function act(id,kind){
  var url,method='POST';
  if(kind==='promote')url='/api/memory/quarantine/'+encodeURIComponent(id)+'/promote';
  else if(kind==='dismiss')url='/api/memory/quarantine/'+encodeURIComponent(id)+'/dismiss';
  else if(kind==='flag')url='/api/memory/quarantine/'+encodeURIComponent(id)+'/flag';
  else if(kind==='demote')url='/api/memory/golden/'+encodeURIComponent(id)+'/demote';
  else if(kind==='delete'){url='/api/memory/golden/'+encodeURIComponent(id);method='DELETE';}
  else return;
  fetch(url,{method:method}).then(function(r){return r.json();}).then(function(){
    if(kind==='flag'){loadQuar();return;}
    closeDrawer();
    if(kind==='promote'||kind==='dismiss'){loadQuar();loadGold();loadShadow();}
    else{loadGold();loadQuar();}
  }).catch(function(){});
}
function delAna(email){
  fetch('/api/memory/analysts/'+encodeURIComponent(email),{method:'DELETE'}).then(function(r){return r.json();}).then(function(){loadAna();}).catch(function(){});
}
function addAnalyst(){
  var e=document.getElementById('a-email').value.trim(),n=document.getElementById('a-name').value.trim(),r=document.getElementById('a-role').value;
  if(!e||!n)return;
  fetch('/api/memory/analysts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:e,display_name:n,role:r})})
    .then(function(x){return x.json();}).then(function(){document.getElementById('a-email').value='';document.getElementById('a-name').value='';loadAna();}).catch(function(){});
}
function pollJira(btn){
  var o=btn.innerHTML;btn.disabled=true;btn.style.opacity='.7';
  btn.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:sp 1s linear infinite"><path d="M12 3a9 9 0 109 9"/></svg>Polling…';
  fetch('/api/memory/poll-now?lookback_minutes=120',{method:'POST'}).then(function(r){return r.json();}).then(function(){
    btn.disabled=false;btn.style.opacity='';btn.innerHTML=o;loadQuar();loadGold();loadShadow();
  }).catch(function(){btn.disabled=false;btn.style.opacity='';btn.innerHTML=o;});
}
function flash(btn){var o=btn.style.opacity;btn.style.opacity=.6;setTimeout(function(){btn.style.opacity=o;loadQuar();loadGold();loadAna();loadShadow();loadSugg();loadPA();},400);}

function findMem(id,kind){var a=kind==='quar'?QUAR:GOLD;for(var i=0;i<a.length;i++){if(a[i].id===id)return a[i];}return null;}

// Promotion-scope chooser shown in the quarantine drawer.
function promoteScopeBox(m){
  var at=esc(m.alert_type||'this type');
  var actor=m.actor?'<code>'+esc(m.actor)+'</code>':'<span class="cell-faint">(no actor captured)</span>';
  var dev=m.device?(' on <code>'+esc(m.device)+'</code>'):'';
  var afpDis=m.actor?'':' disabled';
  return '<div><div class="sect-h">Promote as</div><div class="promobox">'
    +'<label class="opt"><input type="radio" name="pscope" value="entity" checked><span><b>Entity-scoped</b> — applies only to actor '+actor+dev+'. Recalled ONLY when this actor/device recurs.</span></label>'
    +'<label class="opt"><input type="radio" name="pscope" value="playbook"><span><b>Playbook lesson</b> — generalize to all <code>'+at+'</code> alerts, surfaced to the model type-wide. Use only for durable, generalizable patterns.</span></label>'
    +'<label class="opt afp"><input type="checkbox" id="pafp"'+afpDis+'><span><b>⚡ Arm auto-close</b> — deterministically close future FPs from this actor with no LLM call. '+(m.actor?'':'<span class="cell-faint">Needs a captured actor.</span>')+'</span></label>'
    +appsBox(m)
    +'</div></div>';
}
// Cloud-app narrowing. Only meaningful for CASB/Netskope verdicts, where the app IS
// the distinguishing fact — "bulk upload to Slack is expected" must not be recalled
// as "bulk upload anywhere is expected" (DEMO-107886, where the app existed only in
// the analyst's prose). Prefilled from the apps the alert itself named so this is a
// confirmation rather than a from-memory retype.
function appsBox(m){
  if((m.alert_type||'')!=='netskope' && !(m.apps&&m.apps.length)) return '';
  var pre=(m.apps&&m.apps.length)?m.apps.join(', '):(memAppsFromText(m)||'');
  return '<label class="opt"><span style="width:100%"><b>App scope</b> — which cloud app(s) this verdict covers. '
    +'<span class="cell-faint">Leave blank for app-agnostic.</span>'
    +'<input id="papps" placeholder="e.g. Slack" value="'+esc(pre)+'" '
    +'style="width:100%;margin-top:6px;padding:6px 8px;border-radius:6px;border:1px solid var(--line);'
    +'background:var(--bg);color:var(--text);font-size:12px"/></span></label>';
}
// Best-effort prefill: pull an "*App:* X" line out of the stored L1 comment/content.
function memAppsFromText(m){
  var blob=(m.l1_comment||'')+'\n'+(m.content||'');
  var mm=blob.match(/\*?App:?\*?\s*([A-Za-z0-9 ._-]{2,40})/);
  return mm?mm[1].trim().replace(/\s*\(CCL.*$/i,''):'';
}
// Scope + allowlist management shown in the golden drawer.
function goldScopeBox(m){
  var armed=m.auto_fp, canArm=(m.scope!=='playbook')&&m.actor, toggle='';
  if(canArm){
    toggle=armed
      ?'<button class="btn warn" style="margin-top:10px;width:100%" onclick="scopeMem(\''+esc(m.id)+'\',{auto_fp:false})">Disarm auto-close</button>'
      :'<button class="btn ok" style="margin-top:10px;width:100%" onclick="scopeMem(\''+esc(m.id)+'\',{auto_fp:true})">⚡ Arm auto-close for this actor</button>';
  }
  var widen=(m.scope==='playbook')
    ?'<button class="btn ghost sm" onclick="scopeMem(\''+esc(m.id)+'\',{scope:\'entity\'})">Narrow to entity-scoped</button>'
    :'<button class="btn ghost sm" onclick="scopeMem(\''+esc(m.id)+'\',{scope:\'playbook\'})">Widen to playbook lesson</button>';
  return '<div><div class="sect-h">Scope &amp; allowlist</div><div class="promobox">'
    +'<div class="kv" style="grid-template-columns:1fr 1fr">'
    +'<div class="cell"><div class="k">Scope</div><div class="v">'+esc(m.scope||'entity')+'</div></div>'
    +'<div class="cell"><div class="k">Auto-FP</div><div class="v" style="color:'+(armed?'var(--good)':'var(--faint)')+'">'+(armed?'ARMED ⚡':'off')+'</div></div>'
    +'<div class="cell"><div class="k">Actor</div><div class="v">'+esc(m.actor||'—')+'</div></div>'
    +'<div class="cell"><div class="k">Device</div><div class="v">'+esc(m.device||'any')+'</div></div>'
    +'<div class="cell" style="grid-column:1/3"><div class="k">Commands</div><div class="v">'+((m.commands&&m.commands.length)?m.commands.map(esc).join(', '):'any command')+'</div></div>'
    +'<div class="cell" style="grid-column:1/3"><div class="k">App scope</div><div class="v">'+((m.apps&&m.apps.length)?m.apps.map(esc).join(', '):'any app')+'</div></div>'
    +'</div>'+toggle+'<div style="margin-top:8px">'+widen+'</div>'
    +'</div></div>';
}
function promoteMem(id){
  var sc=document.querySelector('input[name="pscope"]:checked');
  var scope=sc?sc.value:'entity';
  var afpEl=document.getElementById('pafp');
  var auto_fp=!!(afpEl&&afpEl.checked&&!afpEl.disabled);
  var appsEl=document.getElementById('papps');
  var body={scope:scope,auto_fp:auto_fp};
  // Only send apps when the field was actually shown AND filled — omitting it leaves
  // the memory app-agnostic, which is the pre-existing behaviour for every other type.
  if(appsEl&&appsEl.value.trim()){
    body.apps=appsEl.value.split(',').map(function(s){return s.trim();}).filter(Boolean);
  }
  fetch('/api/memory/quarantine/'+encodeURIComponent(id)+'/promote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(function(r){return r.json();}).then(function(){closeDrawer();loadQuar();loadGold();loadShadow();}).catch(function(){});
}
function scopeMem(id,body){
  fetch('/api/memory/golden/'+encodeURIComponent(id)+'/scope',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(function(r){return r.json();}).then(function(){closeDrawer();loadGold();}).catch(function(){});
}
function parseConflict(reason){var r=stripFlag(reason||'');var mm=r.match(/AI said (\w+),\s*L([12]) said (\w+)/i);if(!mm)return null;return {ai:mm[1].toUpperCase(),who:'L'+mm[2],human:mm[3].toUpperCase()};}
function vShort(v){var M={AUTO_CLOSED_FP:['fp','FP'],AUTO_CLOSED_TP:['tp','TP'],NEEDS_L2:['l2','L2'],URGENT:['urgent','URG'],PENDING:['pend','PEND']};return M[v]||['l2',(v||'?').slice(0,8)];}
function conflictPanel(c){var a=vShort(c.ai),h=vShort(c.human);return '<div class="kv" style="grid-template-columns:1fr 1fr;margin-top:2px"><div class="cell"><div class="k">RAPTOR proposed</div><div class="v"><span class="vchip '+a[0]+'">'+esc(c.ai)+'</span></div></div><div class="cell"><div class="k">'+esc(c.who)+' decided</div><div class="v"><span class="vchip '+h[0]+'">'+esc(c.human)+'</span></div></div></div>';}
function loadMemReason(jira){var slot=document.getElementById('d-reason');if(!slot||!jira)return;fetch('/api/edr-triage/shadow/'+encodeURIComponent(jira)).then(function(r){return r.json();}).then(function(sh){if(!sh||!sh.found||!sh.ai_reasoning)return;slot.innerHTML='<div class="ai-block"><div class="ah"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4M12 18v4M2 12h4M18 12h4M5 5l2.5 2.5M16.5 16.5L19 19M19 5l-2.5 2.5M7.5 16.5L5 19"/><circle cx="12" cy="12" r="3.5"/></svg>RAPTOR reasoning · Mistral Large 3'+(sh.ai_triage_class?' · '+esc(sh.ai_triage_class):'')+'</div><pre>'+esc(sh.ai_reasoning)+'</pre></div>';}).catch(function(){});}
function openMem(id,kind){
  var m=findMem(id,kind);if(!m)return;
  document.getElementById('d-eyebrow').textContent=(kind==='quar'?'Quarantined memory · ':'Trusted memory · ')+(m.alert_type||'');
  document.getElementById('d-title').textContent=memTitle(m);
  var conf=Math.round((m.confidence||0)*100);
  var strip;
  if(kind==='quar'){strip='<span class="badge t-quar"><span class="d"></span>Quarantine</span><span class="conf" style="margin-left:auto">'+conf+'% confidence</span>';}
  else{var isG=m.tier==='golden';strip='<span class="badge '+(isG?'t-gold':'t-cur')+'"><span class="d"></span>'+(isG?'Golden':'Curated')+'</span><span class="conf" style="margin-left:auto">'+conf+'% confidence</span>';}
  document.getElementById('d-strip').innerHTML=strip;
  var b='';
  b+='<div><div class="sect-h">Memory</div><div class="memtext">'+esc(m.content||'')+'</div></div>';
  if(kind==='quar'&&m.quarantine_reason){
    var _cf=parseConflict(m.quarantine_reason);
    b+='<div><div class="sect-h">Why quarantined — AI ↔ human conflict</div>'+(isFlagged(m)?'<div style="color:var(--med);font-family:var(--mono);font-size:10px;margin-bottom:8px">⚑ flagged for review</div>':'')+(_cf?conflictPanel(_cf):'<div class="memtext" style="border-left-color:var(--quar)">'+esc(stripFlag(m.quarantine_reason))+'</div>')+'</div>';
  }
  b+='<div id="d-reason"></div>';
  b+=(kind==='quar'?promoteScopeBox(m):goldScopeBox(m));
  b+='<div class="kv">'
    +'<div class="cell"><div class="k">Jira</div><div class="v" style="color:var(--good)">'+(m.jira_key?jiraLink(m.jira_key):'—')+'</div></div>'
    +'<div class="cell"><div class="k">Alert type</div><div class="v">'+esc(m.alert_type||'—')+'</div></div>'
    +(kind==='gold'?'<div class="cell"><div class="k">Approved by</div><div class="v" style="font-family:var(--sans)">'+esc(m.resolved_by||'—')+'</div></div><div class="cell"><div class="k">Date</div><div class="v">'+esc(relTime(m.resolved_at||m.created_at))+'</div></div>':'<div class="cell"><div class="k">Raised</div><div class="v">'+esc(relTime(m.created_at))+'</div></div><div class="cell"><div class="k">Source</div><div class="v">'+esc(m.source||'—')+'</div></div>')
    +'</div>';
  if(m.entity_ids&&m.entity_ids.length){
    b+='<div><div class="sect-h">Linked entities</div><div class="entities"><span class="ent"><span class="ico">◈</span>'+m.entity_ids.length+' linked '+(m.entity_ids.length===1?'entity':'entities')+' in the graph</span></div></div>';
  }
  if(m.l1_comment){
    b+='<div><div class="sect-h">Attributed conversation</div><div class="memtext" style="white-space:pre-wrap;border-left-color:var(--line-2);font-size:12.5px;color:var(--muted)">'+esc(m.l1_comment)+'</div></div>';
  }
  document.getElementById('d-body').innerHTML=b;
  loadMemReason(m.jira_key);
  var act;
  if(kind==='quar'){
    act='<button class="btn ok" onclick="promoteMem(\''+esc(m.id)+'\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>Promote to golden</button>'
      +'<button class="btn warn" onclick="act(\''+esc(m.id)+'\',\'flag\')">Flag</button>'
      +'<button class="btn no" onclick="act(\''+esc(m.id)+'\',\'dismiss\')">Dismiss</button>';
  }else{
    act='<button class="btn warn" style="flex:1" onclick="act(\''+esc(m.id)+'\',\'demote\')">Demote to quarantine</button>'
      +'<button class="btn no" style="flex:1" onclick="act(\''+esc(m.id)+'\',\'delete\')">Delete</button>';
  }
  document.getElementById('d-act').innerHTML=act;
  document.getElementById('drawer').classList.add('open');
  document.getElementById('ov').classList.add('open');
  document.body.style.overflow='hidden';
}
function closeDrawer(){
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('ov').classList.remove('open');
  document.body.style.overflow='';
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeDrawer();});

// nav wiring by tooltip label
var NAV={'Triage Console':'/edr-triage','AI Memory':'/memory/quarantine','Settings':'/settings'};
document.querySelectorAll('.rail .navbtn').forEach(function(b){var tip=(b.querySelector('.tip')||{}).textContent||'';if(NAV[tip])b.onclick=function(){location.href=NAV[tip];};});

loadShadow();loadQuar();loadGold();loadAna();loadHealth();loadAcc();loadSugg();loadPA();loadGraph();
</script>

</body>
</html>""".replace("//%%GRAPH_JS%%", _GRAPH_JS))
