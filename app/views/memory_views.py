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
    GET  /api/memory/shadow-stats                 — AI vs L1 accuracy stats (lifetime + 30d + by alert_name)
    POST /api/memory/playbook-context             — upsert a general, alert-type-wide context memory (scope=playbook)
    POST /api/memory/shadow/exclude-alert         — unscore + dequarantine one alert NAME, register it for future exclusion
    GET  /api/memory/alerts-under-test            — list alert names excluded from scoring/quarantine
    POST /api/memory/alerts-under-test            — add an alert NAME to the exclusion list
    DELETE /api/memory/alerts-under-test/{name}   — remove an alert NAME from the exclusion list
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


def is_dlp_alert(alert_name: str) -> bool:
    """True for a Netskope DLP alert family.

    Substring match on "dlp" rather than an exact-name list, so a second DLP rule
    (a new profile, a renamed policy) is classified correctly the day it appears
    instead of silently landing back in the threat-triage headline. Alert names come
    from the Sentinel rule and are not under our control — "Netskope DLP Alerts"
    today, but the family has been renamed before.

    ONE definition, imported by every consumer (stats rollups, the DLP dashboard tab,
    the quarantine scoping) so the split cannot mean different things in different
    places — the failure mode where a row is in neither bucket, or in both.
    """
    return "dlp" in (alert_name or "").casefold()


# ---------------------------------------------------------------------------
# Memory API
# ---------------------------------------------------------------------------

@router.get("/api/memory/quarantine")
async def list_quarantine(limit: int = 50, alert_type: str = "",
                          disagreement_only: bool = False):
    """Quarantine review page. `alert_type` scopes it server-side so a high-volume
    family (Netskope DLP) cannot starve the others out of the page — see
    entity_graph.memory.get_quarantined_memories.

    `disagreement_only=true` keeps only rows where the agent and L1 both decided and
    decided DIFFERENTLY — the actual review work if the goal is replacing L1. It drops
    the two populations that make the raw count unworkable: agreements that read as
    conflicts (most often ai=NEEDS_L2 with L1 also escalating) and tickets nobody has
    resolved yet. Compared against L1, not the final L2 verdict, deliberately.

    Every row now also carries ai_verdict / l1_verdict / l2_verdict, filtered or not."""
    from entity_graph.memory import get_quarantined_memories
    # The filtered view also returns the true total, so the page can say how many
    # disagreements exist rather than how many fit in one page.
    return await get_quarantined_memories(limit=limit, alert_type=alert_type,
                                          disagreement_only=disagreement_only,
                                          with_total=disagreement_only)


@router.get("/api/memory/quarantine/counts")
async def quarantine_counts():
    """True per-alert_type quarantine counts, independent of any page limit — lets the
    review queue offer every bucket that exists rather than only the ones that fit on
    the newest-first page."""
    from entity_graph.memory import get_quarantine_counts_by_type
    return await get_quarantine_counts_by_type()


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
    # The exact commands an armed entry clears, one per line (a Root Privesc arm without
    # them is refused — allowlist_pin_problem).
    commands = (payload or {}).get("commands")
    if isinstance(commands, str):
        commands = [c for c in (p.strip() for p in commands.splitlines()) if c]
    ok = await promote_memory(memory_id, resolved_by="l2_analyst", scope=scope,
                              auto_fp=auto_fp, apps=apps, commands=commands)
    if not ok:
        raise HTTPException(404, "Memory not found")
    return {"ok": True, "memory_id": memory_id, "action": "promoted",
            "scope": scope or "entity", "auto_fp": bool(auto_fp), "apps": apps or [],
            "commands": commands or []}


@router.get("/api/memory/quarantine/{memory_id}/commands")
async def memory_commands(memory_id: str):
    """The commands the memory's alert ran, for the arm box: the memory's own when set,
    else read once from RAPTOR's comment on the ticket (Device Name / Session Principal /
    Initiating Commands) and kept on the memory. Read-only for anything else."""
    from beanie import PydanticObjectId
    from app.database import get_collection
    from entity_graph.memory import canon_commands
    col = get_collection("eg_memories")
    doc = await col.find_one({"_id": PydanticObjectId(memory_id)},
                             {"commands": 1, "jira_key": 1, "alert_type": 1})
    if not doc:
        raise HTTPException(404, "Memory not found")
    if doc.get("commands"):
        return {"commands": doc["commands"], "source": "memory"}
    if not doc.get("jira_key"):
        return {"commands": [], "source": "none"}
    cmds = await _ticket_commands(doc["jira_key"])
    if cmds:
        await col.update_one({"_id": doc["_id"]}, {"$set": {"commands": canon_commands(cmds)}})
    return {"commands": canon_commands(cmds), "source": "ticket" if cmds else "none"}


async def _ticket_commands(jira_key: str) -> list[str]:
    """Initiating Commands from RAPTOR's own comment on the ticket ([] when absent)."""
    from edr_triage.config import get_edr_config
    from edr_triage.jira_handler import _build_client
    from edr_triage.jira_poller import _adf_to_text, adf_to_marked_text
    from edr_triage.privesc_guard import parse_comment
    cfg = get_edr_config()
    try:
        async with _build_client(cfg) as c:
            r = await c.get(f"/rest/api/3/issue/{jira_key}", params={"fields": "comment"})
            r.raise_for_status()
            comments = ((r.json().get("fields") or {}).get("comment") or {}).get("comments") or []
    except Exception as exc:
        logger.warning("memory commands: %s unreadable: %s", jira_key, exc)
        return []
    for cm in comments:
        body = cm.get("body")
        parsed = ((parse_comment(adf_to_marked_text(body)) or parse_comment(_adf_to_text(body)))
                  if isinstance(body, dict) else parse_comment(str(body or "")))
        if parsed:
            return parsed["cmds"]
    return []


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
    Jira ticket to move its `updated` (what DEMO-106604 needed).

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

        # Per-alert-name breakdown — the single headline number hides that some
        # alert families run far worse (or better) than the average, and a newly
        # un-skipped family (e.g. Netskope DLP) starts with zero history and needs
        # its own visible track record rather than being invisible inside one blended
        # figure. Same exclusions/definitions as the headline metric, grouped by the
        # raw alert_name rather than a coarser playbook classification — this is the
        # granularity an analyst actually asks "how is THIS alert type doing" at.
        coll = ShadowResult.get_pymongo_collection()

        # TWO agreement lenses, reported side by side. The headline `accuracy` above is a
        # BLEND: verdict_match scores against whichever human closed the ticket, so an
        # L1-closed ticket is scored against L1 and an L2-closed one against L2. That
        # answers "does the agent agree with the outcome", which is not the same question
        # as "can the agent replace L1".
        #
        #   l1_agreement — agent vs L1's OWN decision. l1_triage_class is always exactly
        #                  that: "NEEDS_L2" when L1 escalated (stamped by
        #                  _handle_l2_handoff), or the terminal class when L1 closed it.
        #                  This is the L1-replacement measure: agent NEEDS_L2 against L1
        #                  NEEDS_L2 is a SUCCESS here even where L2 later closed FP.
        #   l2_agreement — agent vs L2, over the subset L2 actually ruled on. The harder
        #                  bar, and the one that matters for autonomy beyond L1.
        #
        # ADDITIVE ONLY. The blended headline stays exactly as it was, same denominator,
        # nothing excluded — these are two extra readings of the same rows, not a
        # redefinition.
        #
        # BOTH read LOWER than the headline, and that is expected, not a regression. These
        # are RAW agreement: no escalation credit. The headline's verdict_match adds
        # _warranted_escalation (agent NEEDS_L2 where the outcome was AUTO_CLOSED_TP, and
        # agent REQUEST_JUSTIFICATION where the outcome was TP, or FP with a justification
        # detected), so it is a more forgiving measure by construction. Measured on a
        # 160-row sample 2026-09-03: blended headline ~0.73, L1 agreement 0.613, L2
        # agreement 0.569.
        #
        # Raw was chosen deliberately: "does the agent agree with L1" should mean
        # agreement, not agreement-plus-credits. The RJ-with-justification credit could
        # not be reproduced here anyway — `_justified` is computed at close time and never
        # persisted on the row.
        #
        # Compare these two against EACH OTHER, and each against its own history. Do not
        # read either against the headline; the basis and the crediting both differ.
        #
        # URGENT counts as agreeing with an L1 escalation: both said "a human must look",
        # which is the decision being compared. Every other class is strict equality.
        _ESCALATIONS = ["NEEDS_L2", "URGENT"]
        _agree_pipeline = [
            {"$match": {"ai_error": None, "verdict_match": {"$ne": None}}},
            {"$project": {
                "ai": "$ai_triage_class", "l1": "$l1_triage_class", "l2": "$l2_triage_class",
                "vm": "$verdict_match", "created_at": 1,
                "asked": "$l1_awaiting_inputs_at", "alert_name": 1,
            }},
        ]
        _agree_rows = await coll.aggregate(_agree_pipeline).to_list(length=None)

        def _agrees(ai: str, human: str) -> bool:
            if not ai or not human:
                return False
            if ai == human:
                return True
            return human in _ESCALATIONS and ai in _ESCALATIONS

        def _agrees_l1(r: dict) -> bool:
            """L1 agreement, with the justification loop counted as a decision.

            l1_triage_class only ever records escalate-or-close, so L1 moving a ticket to
            AWAITING MORE INPUTS — choosing to ask the user — left no trace. An agent
            REQUEST_JUSTIFICATION could not be scored as agreeing with L1 even when both
            made the identical call. l1_awaiting_inputs_at is that trace.

            Credited regardless of what L1 did AFTER the reply came back: the decision
            being compared is "ask the user first", and the agent made it too. An agent
            NEEDS_L2 against an L1 who asked is still a disagreement — escalating is not
            asking.
            """
            if r.get("ai") == "REQUEST_JUSTIFICATION" and r.get("asked"):
                return True
            return _agrees(r.get("ai"), r.get("l1"))

        _l1_rows = [r for r in _agree_rows if r.get("l1") or r.get("asked")]
        _l2_rows = [r for r in _agree_rows if r.get("l2")]
        _l1_ok = sum(1 for r in _l1_rows if _agrees_l1(r))
        _l2_ok = sum(1 for r in _l2_rows if _agrees(r.get("ai"), r.get("l2")))
        l1_agreement = {
            "scored": len(_l1_rows), "matches": _l1_ok,
            "accuracy": round(_l1_ok / len(_l1_rows), 3) if _l1_rows else None,
            "basis": "raw agreement, agent vs L1's own decision (ask / escalate / close) — the L1-replacement measure. Counts L1's AWAITING MORE INPUTS as an ask, so an agent REQUEST_JUSTIFICATION matching it scores as agreement. No escalation credit, so not comparable to ai_l1_accuracy.",
        }
        l2_agreement = {
            "scored": len(_l2_rows), "matches": _l2_ok,
            "accuracy": round(_l2_ok / len(_l2_rows), 3) if _l2_rows else None,
            "basis": "raw agreement, agent vs L2 over the tickets L2 ruled on — the harder bar; no escalation credit",
        }

        # ------------------------------------------------------------------ #
        # l1_replacement — ONE number for "could this have stood in for L1?"
        #
        # Asked for 2026-09-09: the agent is correct when it AGREED WITH L1, or when it
        # disagreed with L1 and L2 then backed the agent. The two existing lenses each
        # answer half of that (l1_agreement ignores L2 entirely; the headline scores
        # against the terminal verdict and so punishes the agent for matching L1), and
        # neither is the question the programme is actually gated on.
        #
        # Why this is not the headline with nicer arithmetic: measured over 949 scored
        # rows it moves 122 rows INTO correct and 38 rows OUT of it. A reframing that only
        # ever adds points would not be a measure.
        #
        # The four clauses, and what each one rests on:
        def _replaces_l1(r: dict) -> bool:
            ai = r.get("ai") or ""
            l1 = r.get("l1") or ""
            l2 = r.get("l2") or ""

            # (1) Agreed with L1 — the decision being replaced. Reuses _agrees_l1 so the
            #     AWAITING-MORE-INPUTS handling cannot drift between the two metrics.
            if _agrees_l1(r):
                return True

            # (2) Asked the user first. Decided 2026-09-09 that REQUEST_JUSTIFICATION is an
            #     INTERMEDIATE state, not a verdict — it collects a justification and then
            #     closes or escalates on what comes back — so comparing its class string
            #     against a human who never asked cannot establish the agent was wrong.
            #     CARVE-OUT: a confirmed true positive. Asking the actor to explain
            #     themselves on a real threat delays response and tips the actor off, and
            #     is the one direction where RJ is a definite failure. Without it RJ could
            #     never score wrong at all — 95 of 949 rows, 10% of the set — and the
            #     metric would be structurally blind to a bad ask. Two rows currently fail
            #     here (DEMO-108306, DEMO-111848).
            if ai == "REQUEST_JUSTIFICATION":
                return l2 != "AUTO_CLOSED_TP"

            # (3) Disagreed with L1, and L2 backed the agent. Gated on L1 having ACTUALLY
            #     escalated, because l2_triage_class is not an independent L2 ruling: where
            #     L1 closed the ticket itself it is a verbatim copy of l1_triage_class
            #     (measured 2026-09-09: 0 differences across 636 such rows). With no second
            #     opinion on record, L1's call is the ground truth and an agent that
            #     escalated it is simply wrong — which is what keeps the 151-row
            #     over-escalation class counting against the agent.
            if l1 in _ESCALATIONS and _agrees(ai, l2):
                return True

            # (4) Escalated something that turned out to be a real threat. Same credit the
            #     headline's _warranted_escalation gives, kept for the same reason: calling
            #     that a miss would penalise the agent for being right about a TP.
            if ai in _ESCALATIONS and l2 == "AUTO_CLOSED_TP":
                return True

            return False

        def _repl_rollup(rows: list[dict]) -> dict:
            ok = sum(1 for r in rows if _replaces_l1(r))
            r30 = [r for r in rows if (r.get("created_at") or _cut) >= _cut]
            ok30 = sum(1 for r in r30 if _replaces_l1(r))
            return {
                "scored": len(rows), "matches": ok,
                "accuracy": round(ok / len(rows), 3) if rows else None,
                "scored_30d": len(r30), "matches_30d": ok30,
                "accuracy_30d": round(ok30 / len(r30), 3) if r30 else None,
            }

        _repl_rows = [r for r in _agree_rows if r.get("l1") or r.get("asked")]
        l1_replacement = _repl_rollup(_repl_rows)
        l1_replacement["basis"] = (
            "agent could have stood in for L1: it agreed with L1's own decision, or it "
            "disagreed with L1 and L2 then backed the agent. Credits an escalation of a "
            "confirmed TP, and credits REQUEST_JUSTIFICATION except where the truth was a "
            "TP. Scored over the same rows as the headline — nothing excluded."
        )
        l1_replacement["dlp"] = _repl_rollup(
            [r for r in _repl_rows if is_dlp_alert(r.get("alert_name") or "")])
        l1_replacement["excluding_dlp"] = _repl_rollup(
            [r for r in _repl_rows if not is_dlp_alert(r.get("alert_name") or "")])

        pipeline = [
            {"$match": {"verdict_match": {"$ne": None}, "ai_error": None}},
            {"$group": {
                "_id": "$alert_name",
                "resolved": {"$sum": 1},
                "matches": {"$sum": {"$cond": ["$verdict_match", 1, 0]}},
                "resolved_30d": {"$sum": {"$cond": [{"$gte": ["$created_at", _cut]}, 1, 0]}},
                "matches_30d": {"$sum": {"$cond": [
                    {"$and": ["$verdict_match", {"$gte": ["$created_at", _cut]}]}, 1, 0,
                ]}},
                # Said FP, a human found it real — the one miss that can lose a TP. The
                # by-type table colours red on this, not on low agreement, which for most
                # families is over-escalation (the safe side).
                "missed_tp": {"$sum": {"$cond": [{"$and": [
                    {"$eq": ["$ai_triage_class", "AUTO_CLOSED_FP"]},
                    {"$eq": [{"$ifNull": ["$l2_triage_class", "$l1_triage_class"]}, "AUTO_CLOSED_TP"]},
                ]}, 1, 0]}},
            }},
            {"$sort": {"resolved": -1}},
        ]
        rows = await coll.aggregate(pipeline).to_list(length=None)
        # Per-family L1 basis, so the by-type table can be read the way the programme is
        # actually framed. The `accuracy` column beside it is scored against the TERMINAL
        # human verdict — which for an escalated ticket is L2's, not L1's. Consequence,
        # measured on a 200-row sample 2026-09-03: of 30 rows where the agent AND L1 both
        # said NEEDS_L2, **26 are scored as misses**, because L2 went on to close them FP.
        # The agent matched L1 exactly and still lost the point. `accuracy_l1` is the
        # column that counts those as the agreement they are.
        _fam_l1: dict = {}
        for r in _agree_rows:
            b = _fam_l1.setdefault(r.get("alert_name") or "(unknown)", [0, 0])
            if r.get("l1") or r.get("asked"):
                b[0] += 1
                if _agrees_l1(r):
                    b[1] += 1

        # Merge families fragmented by an embedded entity identifier before reporting.
        # Measured 2026-09-06: 78 distinct alert_name values, of which 22 were really two
        # detections — "The EC2 instance i-<id> queried a drive-by source domain name"
        # appeared as 11 separate rows totalling 18 verdicts, mostly rows of ONE. A family
        # with one scored row cannot be read, so the detection's real accuracy was
        # invisible in the table people use to decide where to work. Cyble digests
        # fragmented the same way on their two counts.
        #
        # Grouping only — the underlying rows keep their real alert_name, and routing,
        # memory bucketing and every gate still see it. See classifier.display_alert_family
        # for what is collapsed and, more importantly, what deliberately is not.
        from edr_triage.classifier import display_alert_family as _fam_display

        _merged: dict = {}
        for r in rows:
            key = _fam_display(r["_id"] or "(unknown)")
            b = _merged.setdefault(key, {"_id": key, "resolved": 0, "matches": 0,
                                         "resolved_30d": 0, "matches_30d": 0,
                                         "missed_tp": 0, "_names": set()})
            for f in ("resolved", "matches", "resolved_30d", "matches_30d", "missed_tp"):
                b[f] += r.get(f, 0) or 0
            b["_names"].add(r["_id"] or "(unknown)")
        rows = sorted(_merged.values(), key=lambda b: -b["resolved"])

        # The per-family L1 tallies have to be re-keyed the same way or they would be
        # looked up by a name that no longer exists after the merge.
        _fam_l1_merged: dict = {}
        for name, pair in _fam_l1.items():
            b = _fam_l1_merged.setdefault(_fam_display(name), [0, 0])
            b[0] += pair[0]
            b[1] += pair[1]
        _fam_l1 = _fam_l1_merged

        by_alert_name = [
            {
                "alert_name": r["_id"] or "(unknown)",
                # How many raw alert names were folded together, so a merged row is
                # visibly a merge rather than silently one detection.
                "merged_from": len(r.get("_names") or []) if len(r.get("_names") or []) > 1 else None,
                "resolved": r["resolved"],
                "matches": r["matches"],
                "accuracy": round(r["matches"] / r["resolved"], 3) if r["resolved"] else None,
                "resolved_30d": r["resolved_30d"],
                "matches_30d": r["matches_30d"],
                "accuracy_30d": round(r["matches_30d"] / r["resolved_30d"], 3) if r["resolved_30d"] else None,
                "missed_tp": r.get("missed_tp", 0),
                # Agreement with L1's OWN decision (escalate / ask / close). Both sides
                # saying NEEDS_L2 counts here, which is the whole point of the column.
                "scored_l1": _fam_l1.get(r["_id"] or "(unknown)", [0, 0])[0],
                "matches_l1": _fam_l1.get(r["_id"] or "(unknown)", [0, 0])[1],
                "accuracy_l1": (
                    round(_fam_l1[r["_id"] or "(unknown)"][1]
                          / _fam_l1[r["_id"] or "(unknown)"][0], 3)
                    if _fam_l1.get(r["_id"] or "(unknown)", [0, 0])[0] else None
                ),
            }
            for r in rows
        ]

        # DLP is split out because it is a DIFFERENT WORKFLOW, not because of its number.
        # A DLP verdict is a business-justification question ("is this person's team
        # allowed to hold PAN/Aadhaar data for this process?") resolved by asking the
        # user; every other family is a threat-triage question resolved from telemetry.
        # Blending them makes the headline unreadable: measured 2026-09-01, DLP was 110
        # of 523 scored rows — a fifth of the metric — on a workflow whose ground truth
        # is an email reply.
        #
        # BOTH numbers are returned, always. This is the same call the lifetime-vs-30d
        # comment above makes: a second number, never a smaller denominator. The
        # combined figures (ai_l1_accuracy*) keep their exact original meaning so no
        # caller silently changes behaviour, and nothing is dropped from the record —
        # `dlp` and `excluding_dlp` are additive views over the same rows.
        #
        # Splitting also makes a real property VISIBLE that the blend hides: DLP's
        # accuracy is dragged down entirely by OVER-escalation (2026-09-01: 33 NEEDS_L2
        # + 7 REQUEST_JUSTIFICATION that humans closed FP), while its FP recommendations
        # were right 70 out of 70 — zero cases of recommending FP where a human said TP.
        # A single 0.633 reads as "unreliable"; the split shows a conservative bias.
        _dlp_rows = [r for r in by_alert_name if is_dlp_alert(r["alert_name"])]
        _other_rows = [r for r in by_alert_name if not is_dlp_alert(r["alert_name"])]

        def _rollup(rows: list[dict]) -> dict:
            res = sum(r["resolved"] for r in rows)
            mat = sum(r["matches"] for r in rows)
            res30 = sum(r["resolved_30d"] for r in rows)
            mat30 = sum(r["matches_30d"] for r in rows)
            return {
                "resolved": res,
                "ai_l1_matches": mat,
                "ai_l1_accuracy": round(mat / res, 3) if res else None,
                "resolved_30d": res30,
                "ai_l1_matches_30d": mat30,
                "ai_l1_accuracy_30d": round(mat30 / res30, 3) if res30 else None,
                "alert_names": sorted(r["alert_name"] for r in rows),
            }

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
            # Two agreement lenses on the SAME rows as the headline — additive, nothing
            # excluded. See the comment where they are computed.
            "l1_agreement": l1_agreement,
            "l2_agreement": l2_agreement,
            # The L1-replacement measure — see the comment where it is computed.
            "l1_replacement": l1_replacement,
            "by_alert_name": by_alert_name,
            # Additive views over the same rows — see the comment above.
            "excluding_dlp": _rollup(_other_rows),
            "dlp": _rollup(_dlp_rows),
        }
    except Exception as exc:
        return {"error": str(exc)}


@router.get("/api/memory/calibration")
async def calibration_report(since_days: int = 0, min_family_n: int = 10):
    """Read-only: does ai_confidence mean what the 0.90 auto-close floor assumes?
    See edr_triage/calibration.py for the row rules and caveats. since_days=0 is lifetime."""
    from datetime import datetime, timedelta
    from entity_graph.models import ShadowResult
    from edr_triage.calibration import build_report
    from edr_triage.pipeline import autonomous_alert_allowlist, _alert_matches_allowlist
    try:
        match: dict = {"ai_error": None, "verdict_match": {"$ne": None}}
        if since_days > 0:
            match["created_at"] = {"$gte": datetime.utcnow() - timedelta(days=since_days)}
        rows = await ShadowResult.get_pymongo_collection().aggregate([
            {"$match": match},
            {"$project": {"_id": 0, "alert_name": 1, "ai_triage_class": 1, "ai_confidence": 1,
                          "verdict_match": 1, "pre_safety_class": 1,
                          "autonomous_closed_at": 1, "reopened_at": 1}},
        ]).to_list(length=None)
        allow = autonomous_alert_allowlist()
        report = build_report(rows, is_autonomous=lambda n: _alert_matches_allowlist(n, allow),
                              min_family_n=min_family_n)
        report["since_days"] = since_days or None
        return report
    except Exception as exc:
        logger.error("calibration report failed: %s", exc)
        return {"error": str(exc)[:300]}


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


@router.get("/api/memory/raptor-self-verdicts")
async def preview_raptor_self_verdicts():
    """Curated 'analyst' memories that are really RAPTOR's own unreviewed closes. Read-only."""
    from entity_graph.memory import archive_raptor_self_verdicts
    return await archive_raptor_self_verdicts(apply=False)


@router.post("/api/memory/raptor-self-verdicts/archive")
async def apply_raptor_self_verdicts():
    """Archive what the GET above lists. Reversible: archived rows are inert, not deleted."""
    from entity_graph.memory import archive_raptor_self_verdicts
    return await archive_raptor_self_verdicts(apply=True)


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
    from datetime import datetime
    from entity_graph.models import ShadowResult
    try:
        coll = ShadowResult.get_pymongo_collection()
        # The misses are split by DIRECTION so the chart cannot be read as "RAPTOR got
        # worse" when it only escalated more. A low week (2026-W41, 26%) was almost all
        # escalations a human then closed FP — the safe direction — while RAPTOR's own
        # closes, which are never scored here, had moved out of the denominator. The
        # agreement figure itself is unchanged: same rows, same verdict_match.
        _final = {"$ifNull": ["$l2_triage_class", "$l1_triage_class"]}
        pipeline = [
            {"$match": {"verdict_match": {"$ne": None}, "ai_error": None}},  # exclude agent-failure (outage) shadows
            {"$group": {
                "_id": {"$dateToString": {"format": "%G-W%V", "date": "$created_at"}},
                "total": {"$sum": 1},
                "matches": {"$sum": {"$cond": ["$verdict_match", 1, 0]}},
                # Said FP, a human found it real: the only miss that can cost a TP.
                "missed_tp": {"$sum": {"$cond": [{"$and": [
                    {"$eq": ["$ai_triage_class", "AUTO_CLOSED_FP"]},
                    {"$eq": [_final, "AUTO_CLOSED_TP"]},
                ]}, 1, 0]}},
                # Escalated or asked, a human closed it FP: costs analyst time, not a TP.
                "over_escalated": {"$sum": {"$cond": [{"$and": [
                    {"$eq": ["$verdict_match", False]},
                    {"$ne": ["$ai_triage_class", "AUTO_CLOSED_FP"]},
                    {"$eq": [_final, "AUTO_CLOSED_FP"]},
                ]}, 1, 0]}},
            }},
            {"$sort": {"_id": 1}},
        ]
        rows = await coll.aggregate(pipeline).to_list(length=None)
        rows = rows[-max(1, weeks):]

        # RAPTOR's own closes, per week of the close. Never scored above (it would be
        # marking its own work), so they are reported beside the bars instead.
        auto_rows = await coll.aggregate([
            {"$match": {"autonomous_closed_at": {"$ne": None}}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%G-W%V", "date": "$autonomous_closed_at"}},
                "closes": {"$sum": 1},
                "reopened": {"$sum": {"$cond": [{"$ne": [{"$ifNull": ["$reopened_at", None]}, None]}, 1, 0]}},
            }},
        ]).to_list(length=None)
        auto = {r["_id"]: r for r in auto_rows}

        _now = datetime.utcnow().isocalendar()
        current_week = f"{_now[0]}-W{_now[1]:02d}"
        series = [
            {
                "week": r["_id"],
                "total": r["total"],
                "matches": r["matches"],
                "accuracy": round(r["matches"] / r["total"], 3) if r["total"] else None,
                "overturn_rate": round(1 - r["matches"] / r["total"], 3) if r["total"] else None,
                "missed_tp": r.get("missed_tp", 0),
                "over_escalated": r.get("over_escalated", 0),
                "other_miss": max(0, r["total"] - r["matches"]
                                  - r.get("missed_tp", 0) - r.get("over_escalated", 0)),
                "autonomous_closes": auto.get(r["_id"], {}).get("closes", 0),
                "autonomous_reopened": auto.get(r["_id"], {}).get("reopened", 0),
                # Bucketed by ticket creation, so the running week holds only what was
                # resolved fastest — mostly quick FP closes of escalated digests.
                "in_progress": r["_id"] == current_week,
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
                "apps": getattr(d, "apps", []) or [],
                "app_instances": getattr(d, "app_instances", []) or [],
                "uba_direction": getattr(d, "uba_direction", "") or "",
                "uba_baseline": getattr(d, "uba_baseline", {}) or {},
                "source": getattr(d, "source", "") or "",
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
        apps=body.get("apps", getattr(sugg, "apps", []) or []),
        app_instances=body.get("app_instances", getattr(sugg, "app_instances", []) or []),
        uba_direction=getattr(sugg, "uba_direction", "") or "",
        uba_baseline=getattr(sugg, "uba_baseline", {}) or {},
        jira_key=(sugg.evidence_jira_keys or [""])[0],
        evidence_jira_keys=sugg.evidence_jira_keys,
        resolved_by="l2_analyst",
        alert_name=sugg.alert_name,
    )
    if not mem_id:
        raise HTTPException(400, "Could not arm — no actor, or too broad (it must name an "
                                 "alert type and pin a device, commands or apps)")
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


@router.post("/api/memory/playbook-context", status_code=201)
async def set_playbook_context(payload: dict = Body(...)):
    """Upsert a general, alert-type-wide context memory (scope=playbook) — e.g.
    common legitimate-trigger patterns distilled from historical L2 resolutions,
    surfaced on every alert of that type. CONTEXT ONLY, same rule as every other
    SCG memory: it informs a human/agent's read of a new alert, it never authorizes
    skipping investigation or auto-closing on a pattern match alone.

    Body: {alert_type, content, confidence?, append?}. Keyed on (alert_type, source) —
    posting the same alert_type again REPLACES the content rather than creating a
    duplicate, so this doubles as the update path when the context needs revising.
    append=true adds `content` after the existing text instead (a no-op if that exact
    text is already there), so a host-specific note never wipes the type-wide one.
    """
    from entity_graph.models import SCGMemory, MemoryTier, MemoryType
    from datetime import datetime as _dt

    alert_type = (payload.get("alert_type") or "").strip()
    content = (payload.get("content") or "").strip()
    if not alert_type or not content:
        raise HTTPException(400, "alert_type and content are required")
    confidence = float(payload.get("confidence", 0.75))

    existing = await SCGMemory.find_one(
        SCGMemory.alert_type == alert_type,
        SCGMemory.scope == "playbook",
        SCGMemory.source == "admin_context_import",
    )
    if existing:
        if payload.get("append"):
            if content in (existing.content or ""):
                return {"ok": True, "id": str(existing.id), "updated": False, "appended": False,
                        "reason": "this text is already in the context"}
            content = ((existing.content or "").rstrip() + "\n\n" + content).strip()
        existing.content = content
        existing.confidence = confidence
        existing.tier = MemoryTier.curated
        existing.last_decayed_at = _dt.utcnow()
        await existing.save()
        return {"ok": True, "id": str(existing.id), "updated": True}

    doc = SCGMemory(
        entity_ids=[], memory_type=MemoryType.threat_context, content=content,
        confidence=confidence, tier=MemoryTier.curated, source="admin_context_import",
        alert_type=alert_type, scope="playbook",
    )
    await doc.insert()
    return {"ok": True, "id": str(doc.id), "updated": False}


@router.delete("/api/memory/planned-activity/{window_id}")
async def delete_planned_activity(window_id: str):
    """Delete a planned-activity window (end it early or clear an expired one)."""
    from entity_graph.models import PlannedActivity
    doc = await PlannedActivity.get(window_id)
    if not doc:
        raise HTTPException(404, "Window not found")
    await doc.delete()
    return {"ok": True, "id": window_id, "action": "deleted"}


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------

@router.get("/memory/quarantine", response_class=HTMLResponse, include_in_schema=False)
async def quarantine_page():
    return HTMLResponse(_render_page())


def _render_page() -> str:
    return r"""<!DOCTYPE html>
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
  .seg{display:inline-flex;border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--ink-2);}
  .seg button{background:none;border:0;color:var(--muted);padding:8px 12px;font-size:12.5px;font-family:var(--sans);cursor:pointer;}
  .seg button+button{border-left:1px solid var(--line);}
  .seg button.on{background:var(--panel);color:var(--text-bright);box-shadow:inset 0 -2px 0 var(--quar);}
  .seg button:focus-visible{outline:2px solid var(--accent-dim);outline-offset:-2px;}
  .seg .n{font-family:var(--mono);margin-left:6px;color:var(--quar);}
  .toolbar .right{margin-left:auto;display:flex;gap:9px;align-items:center;}

  .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden;box-shadow:0 14px 38px -24px rgba(0,0,0,0.9);}
  .twrap{overflow-x:auto;}
  .pgbar{display:flex;align-items:center;gap:6px;justify-content:flex-end;padding:9px 4px 2px;font-size:11.5px;color:var(--muted);flex-wrap:wrap;}
  .pgbar .pginfo{font-family:var(--mono);letter-spacing:.02em;}
  .pgb{background:var(--ink-2);color:var(--text);border:1px solid var(--line);border-radius:5px;
       padding:2px 8px;cursor:pointer;font-size:12px;line-height:1.65;font-family:var(--mono);}
  .pgb:hover:not(:disabled){border-color:var(--accent);color:var(--text-bright);}
  .pgb:disabled{opacity:.32;cursor:default;}
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
  .trend{display:flex;gap:8px;align-items:flex-end;height:96px;padding-top:6px;}
  .tbar{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:3px;height:100%;}
  .tbar.partial{opacity:.45;}
  .tstack{width:18px;height:56px;display:flex;flex-direction:column-reverse;border-radius:3px 3px 0 0;overflow:hidden;background:var(--line);}
  .tstack span{display:block;width:100%;}
  .tstack span.tred{min-height:3px;}
  .tpct{font-family:var(--mono);font-size:9px;color:var(--text);}
  .tw{font-family:var(--mono);font-size:9px;color:var(--muted);}
  .tauto{font-family:var(--mono);font-size:8.5px;color:var(--muted);}
  .tlegend{display:flex;flex-wrap:wrap;gap:4px 14px;margin-top:8px;font-size:11px;color:var(--muted);}
  .tlegend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:-1px;}
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
      <div class="stat" title="Could the agent have stood in for L1? Correct when it agreed with L1's own decision, or when it disagreed with L1 and L2 then backed the agent. Same rows as every other measure — nothing excluded.">
        <div class="stripe" style="background:var(--good)"></div>
        <div class="lbl">L1 Replacement <svg viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><path d="M20 8v6M23 11h-6"/></svg></div>
        <div class="big" style="color:var(--good)" id="acc-repl-big">—<span style="font-size:18px">%</span></div>
        <div class="sub" id="acc-repl-sub">agreed with L1, or L2 backed the agent</div>
      </div>
      <div class="stat" title="Scored against the TERMINAL human verdict, which for an escalated ticket is L2's. An agent that made L1's exact call still loses the point here when L2 later overturned L1 — that is the gap between this number and L1 Replacement.">
        <div class="stripe" style="background:var(--muted)"></div>
        <div class="lbl">vs Final Verdict <span style="font-size:10px;color:var(--muted);font-weight:500">EXCL. DLP</span> <svg viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.1V12a10 10 0 11-5.9-9.1"/><path d="M22 4L12 14.01l-3-3"/></svg></div>
        <div class="big" style="color:var(--muted);font-size:26px" id="acc-excl-dlp-big">—<span style="font-size:15px">%</span></div>
        <div class="sub" id="acc-excl-dlp-sub">threat triage · terminal verdict</div>
      </div>
      <div class="stat">
        <div class="stripe" style="background:var(--accent)"></div>
        <div class="lbl">DLP Accuracy <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l7 4v6c0 5-3 8-7 10-4-2-7-5-7-10V6z"/></svg></div>
        <div class="big" style="color:var(--accent)" id="acc-dlp-big">—<span style="font-size:18px">%</span></div>
        <div class="sub" id="acc-dlp-sub">business-justification loop</div>
      </div>
      <div class="stat" title="Agreement with L2 over the tickets L2 actually ruled on — the harder bar, and the one that matters for autonomy beyond L1.">
        <div class="stripe" style="background:var(--accent)"></div>
        <div class="lbl">Agrees with L2 <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg></div>
        <div class="big" style="color:var(--accent)" id="acc-l2-big">—<span style="font-size:18px">%</span></div>
        <div class="sub" id="acc-l2-sub">the harder bar</div>
      </div>
      <div class="stat">
        <div class="stripe" style="background:var(--pend)"></div>
        <div class="lbl">Verdicts Tracked <svg viewBox="0 0 24 24" fill="none" stroke="var(--pend)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg></div>
        <div class="big" style="color:var(--pend)" id="verdicts-tracked-big">1,284</div>
        <div class="sub" id="verdicts-tracked-sub">lifetime closures compared</div>
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
          <div class="hlabel">Weekly AI vs human — and which way the AI was wrong</div>
          <div class="trend" id="mh-trend"><span class="cell-faint">loading…</span></div>
          <div class="tlegend">
            <span><i style="background:var(--good)"></i>agreed</span>
            <span><i style="background:var(--quar)"></i>escalated, human closed FP (safe side)</span>
            <span><i style="background:var(--crit)"></i>said FP, human closed TP — check each</span>
            <span><i style="background:var(--muted)"></i>other</span>
          </div>
          <div class="hmeta" id="mh-trend-sum"></div>
        </div>
      </div>
    </div>

    <!-- tabs -->
    <div class="tabs fade" style="animation-delay:.1s">
      <button class="tab on" data-p="quar" onclick="switchTab('quar')">Quarantine Queue <span class="cnt">14</span></button>
      <button class="tab" data-p="dlp" onclick="switchTab('dlp')">Netskope DLP <span class="cnt" id="cnt-dlp-tab">0</span></button>
      <button class="tab" data-p="sugg" onclick="switchTab('sugg')">Allowlist Suggestions <span class="cnt" id="cnt-sugg-tab">0</span></button>
      <button class="tab" data-p="plan" onclick="switchTab('plan')">Planned Activity <span class="cnt" id="cnt-plan-tab">0</span></button>
      <button class="tab" data-p="gold" onclick="switchTab('gold')">Golden Memory <span class="cnt">63</span></button>
      <button class="tab" data-p="fpr" onclick="switchTab('fpr')">Accuracy &amp; FP Review</button>
      <button class="tab" data-p="acc" onclick="switchTab('acc')">Analyst Accuracy <span class="cnt" id="cnt-acc-tab">0</span></button>
      <button class="tab" data-p="ana" onclick="switchTab('ana')">Analyst Registry <span class="cnt">6</span></button>
    </div>

    <!-- ACCURACY & FP REVIEW PANE -->
    <div class="pane" id="pane-fpr">
      <div class="flow fade" style="animation-delay:.095s">
      <div class="hrow">
        <div class="hblock" style="flex:1;min-width:280px">
          <div class="hlabel" style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
            <span>Weekly false-positive review</span>
            <button class="f" style="cursor:pointer" onclick="downloadFpReport(7)">Download this week (CSV)</button>
            <button class="f" style="cursor:pointer" onclick="downloadFpReport(30)">Last 30 days</button>
            <span id="fp-report-note" class="cell-faint" style="font-size:11.5px"></span>
          </div>
          <div id="fp-report-summary" style="margin:8px 0 22px;font-size:12.5px;color:var(--muted)">loading…</div>

          <!-- Autonomous closes. Deliberately its own block rather than folded into the
               numbers above: the FP review pack covers what the agent RECOMMENDED, which
               in copilot phase a human still closed and therefore reviewed. These are the
               ones RAPTOR closed itself, i.e. the only ones nobody saw first. -->
          <div class="hlabel" style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
            <span>Autonomous closes — RAPTOR closed these itself</span>
            <span id="ac-note" class="cell-faint" style="font-size:11.5px"></span>
          </div>
          <div id="ac-summary" style="margin:8px 0 10px;font-size:12.5px;color:var(--muted)">loading…</div>
          <!-- Paginated, not a scroll box: a fixed-height window over an unknown
               number of closes hides how many there are. See pgPaint/pgSlice. -->
          <div id="ac-rows" style="margin:0;font-size:12px"></div>
          <div id="pg-ac" style="margin:0 0 22px"></div>

          <div class="hlabel">AI vs L1 accuracy — by alert type
            <label style="float:right;font-weight:400;font-size:11.5px;color:var(--muted);cursor:pointer">
              <input type="checkbox" id="ft-observed" onchange="toggleObserved()" style="vertical-align:-1px">
              show observed-only families
            </label>
          </div>
          <div id="acc-obs-note" style="margin-top:6px;font-size:11.5px;color:var(--muted)"></div>
          <div id="acc-by-type" style="margin-top:10px">
            <span class="cell-faint">loading…</span>
          </div>
          <div id="pg-acc"></div>
        </div>
      </div>
    </div>
    </div>

    <!-- QUARANTINE PANE -->
    <div class="pane on" id="pane-quar">
      <div class="toolbar">
        <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
          <input id="q-quar" placeholder="Filter by content, alert, type…" oninput="quarFilter('quar')"/></div>
        <select class="f" id="ft-quar" onchange="loadQuar()"><option value="">All alert types</option></select>
        <div class="seg" role="group" aria-label="Quarantine view">
          <button type="button" id="qv-attn" class="on" aria-pressed="true" onclick="setQuarView(true)"
                  title="Only rows where the agent and L1 both decided, and decided DIFFERENTLY. That is the review work for replacing L1. Agreements (usually both escalated) and tickets nobody has decided yet are hidden: they leave quarantine on their own when the ticket resolves.">Needs attention <span class="n" id="qn-attn">…</span></button>
          <button type="button" id="qv-all" aria-pressed="false" onclick="setQuarView(false)"
                  title="Every memory still in quarantine, including agreements and tickets still waiting on L2 or the user.">All in quarantine <span class="n" id="qn-all">…</span></button>
        </div>
        <div class="right"><span class="cell-faint" id="cnt-quar"></span></div>
      </div>
      <div class="card"><div class="twrap"><table>
        <thead><tr><th>Alert / Jira</th><th>Type</th><th>Memory content</th><th>Conflict</th><th>Conf</th><th>Date</th><th></th></tr></thead>
        <tbody id="tb-quar"></tbody>
      </table></div></div>
      <div id="pg-quar"></div>
    </div>

    <!-- DLP PANE — its own queue + memory. A DLP verdict answers a business-
         justification question resolved by asking the user, not a threat-triage
         question resolved from telemetry, so it is reviewed separately. The rows are
         the same records, scoped: the main Quarantine and Golden tabs exclude DLP. -->
    <div class="pane" id="pane-dlp">
      <!-- Sized inline, like the other notes outside .flow (the .flow .note svg rule
           does not reach this pane, so an unsized svg rendered at its default size). -->
      <div class="note" style="margin-bottom:14px;font-size:12px;color:var(--muted);display:flex;gap:8px;align-items:flex-start"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="flex:none;margin-top:2px"><path d="M12 2l7 4v6c0 5-3 8-7 10-4-2-7-5-7-10V6z"/></svg><span id="dlp-note">Netskope DLP is tracked separately from threat triage. Its verdicts turn on business justification — which team the actor is on and whether that process legitimately holds PAN/Aadhaar data.</span></div>

      <div class="toolbar">
        <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
          <input id="q-dlpquar" placeholder="Filter DLP queue by content, actor…" oninput="quarFilter('dlpquar')"/></div>
        <div class="right"><span class="cell-faint" id="cnt-dlpquar"></span></div>
      </div>
      <div class="card" style="margin-bottom:18px"><div class="twrap"><table>
        <thead><tr><th>Alert / Jira</th><th>Type</th><th>Memory content</th><th>Conflict</th><th>Conf</th><th>Date</th><th></th></tr></thead>
        <tbody id="tb-dlpquar"></tbody>
      </table></div></div>
      <div id="pg-dlpquar" style="margin-bottom:18px"></div>

      <div class="toolbar">
        <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
          <input id="q-dlpgold" placeholder="Filter DLP memory by content, actor, source…" oninput="goldFilter('dlpgold')"/></div>
        <div class="right"><span class="cell-faint" id="cnt-dlpgold"></span></div>
      </div>
      <div class="card"><div class="twrap"><table>
        <thead><tr><th>Alert / Jira</th><th>Type</th><th>Memory content</th><th>Tier</th><th>Scope</th><th>Conf</th><th>Approved by</th><th>Date</th><th></th></tr></thead>
        <tbody id="tb-dlpgold"></tbody>
      </table></div></div>
      <div id="pg-dlpgold"></div>
    </div>

    <!-- GOLDEN PANE -->
    <div class="pane" id="pane-gold">
      <div class="toolbar">
        <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>
          <input id="q-gold" placeholder="Filter by content, alert, source…" oninput="goldFilter('gold')"/></div>
        <select class="f" id="ft-gold" onchange="goldFilter('gold')"><option value="">All alert types</option></select>
        <div class="right"><span class="cell-faint" id="cnt-gold"></span></div>
      </div>
      <div class="card"><div class="twrap"><table>
        <thead><tr><th>Alert / Jira</th><th>Type</th><th>Memory content</th><th>Tier</th><th>Scope</th><th>Conf</th><th>Approved by</th><th>Date</th><th></th></tr></thead>
        <tbody id="tb-gold"></tbody>
      </table></div></div>
      <div id="pg-gold"></div>
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

/* ---- shared pagination ------------------------------------------------------
   Every list on this page used to render EVERY row. The long tables grew the page
   without bound, and the two FP-review blocks were fixed-height scroll boxes — the
   worse of the two, because a 300px window over an unknown number of rows hides how
   much is actually there and makes a specific row unfindable without dragging.

   One pager for all of them, so they behave identically. The page index is keyed per
   list and survives a re-render (promote/dismiss/refresh), but pgReset() clears it
   whenever a filter or search changes: narrowing a 200-row list to 3 while sitting on
   page 5 would otherwise show an empty table. pgSlice also clamps, so a list that
   shrinks underneath you lands on the last real page instead of nothing. */
var PG={}, PG_RENDER={};
function pgState(key,per){if(!PG[key])PG[key]={i:0,n:per||25};if(per)PG[key].n=per;return PG[key];}
function pgReset(key){if(PG[key])PG[key].i=0;}
function pgSlice(key,rows,per){
  var st=pgState(key,per), last=Math.max(0,Math.ceil(rows.length/st.n)-1);
  if(st.i>last)st.i=last;
  return rows.slice(st.i*st.n,(st.i+1)*st.n);
}
function pgGo(key,to){var st=PG[key];if(!st)return;st.i=Math.max(0,to);var f=PG_RENDER[key];if(f)f();}
/* Paint the bar for `key` into #pg-<key>. Called BEFORE any empty-list early return,
   so an emptied list cannot leave a stale pager behind pointing at rows that are gone. */
function pgPaint(key,total,per){
  var host=document.getElementById('pg-'+key); if(!host)return;
  var st=pgState(key,per), pages=Math.max(1,Math.ceil(total/st.n));
  if(total<=st.n){host.innerHTML='';return;}
  var from=st.i*st.n+1, to=Math.min(total,(st.i+1)*st.n);
  function b(lbl,dest,dis,title){
    return '<button class="pgb" title="'+title+'"'+(dis?' disabled':'')
      +' onclick="pgGo(\''+key+'\','+dest+')">'+lbl+'</button>';
  }
  host.innerHTML='<div class="pgbar"><span class="pginfo">'+from+'\u2013'+to+' of '+total+'</span>'
    +b('\u00ab',0,st.i===0,'First page')
    +b('\u2039',st.i-1,st.i===0,'Previous page')
    +'<span class="pginfo">'+(st.i+1)+' / '+pages+'</span>'
    +b('\u203a',st.i+1,st.i>=pages-1,'Next page')
    +b('\u00bb',pages-1,st.i>=pages-1,'Last page')
    +'</div>';
}
/* Filter/search entry points — reset to page 1, then render. */
function quarFilter(v){pgReset(v);renderQuar(v);}
function goldFilter(v){pgReset(v);renderGold(v);}
var _sp=document.createElement('style');_sp.textContent='@keyframes sp{to{transform:rotate(360deg)}}';document.head.appendChild(_sp);
function relTime(iso){if(!iso)return '—';var t=Date.parse(iso);if(isNaN(t))return esc(String(iso));var d=(Date.now()-t)/1000;if(d<60)return 'just now';if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago';}
function stripFlag(s){s=s||'';return s.indexOf('[FLAGGED]')===0?s.slice(9).trim():s;}
function isFlagged(m){return (m.quarantine_reason||'').indexOf('[FLAGGED]')===0;}
function scopeBadge(m){return (m.scope==='playbook')?'<span class="badge t-pb"><span class="d"></span>Playbook</span>':'<span class="badge t-ent"><span class="d"></span>Entity</span>';}
function expiryBadge(m){
  var d=m.expires_in_days; if(d==null||d>30)return '';
  var what=m.expiry_kind==='allowlist'?'auto-close expires':'leaves recall';
  var col=d<=7?'var(--crit)':'var(--warn)';
  return '<div style="font-size:10px;margin-top:3px;color:'+col+'" title="Re-validate before it stops applying">'
    +'\u23f3 '+what+(d===0?' now':' in '+d+'d')+'</div>';
}
function afpBadge(m){return m.auto_fp?'<span class="badge t-afp" title="Deterministic auto-close FP when this actor recurs">⚡ Auto-FP</span>':'';}

var QUAR=[],GOLD=[],ANA=[],SUGG=[],PLAN=[];

function setTab(p,n){var e=document.querySelector('.tab[data-p="'+p+'"] .cnt');if(e)e.textContent=n;}
function statEls(){return document.querySelectorAll('.stats .stat .big');}
function setStat(i,txt){var e=statEls()[i];if(e)e.textContent=txt;}
function setStatSub(i,txt){var e=document.querySelectorAll('.stats .stat .sub')[i];if(e)e.textContent=txt;}
// Quarantine opens on what needs a person: the AI-vs-L1 disagreements. "All" is one click away.
var QUAR_ATTN=true;
function setQuarView(attn){
  QUAR_ATTN=!!attn;
  [['qv-attn',QUAR_ATTN],['qv-all',!QUAR_ATTN]].forEach(function(x){
    var b=document.getElementById(x[0]);if(!b)return;
    b.classList.toggle('on',x[1]);b.setAttribute('aria-pressed',x[1]?'true':'false');
  });
  loadQuar();
}

function fillTypes(sel,arr){
  var cur=document.getElementById(sel);if(!cur)return;var v=cur.value;
  var types=Array.from(new Set(arr.map(function(x){return x.alert_type;}).filter(Boolean))).sort();
  cur.innerHTML='<option value="">All alert types</option>'+types.map(function(t){return '<option value="'+esc(t)+'">'+esc(t)+'</option>';}).join('');
  cur.value=v;
}

function loadShadow(){
  fetch('/api/memory/shadow-stats').then(function(r){return r.json();}).then(function(d){
    // Addressed by ID, not by card position: the accuracy cards are no longer the
    // 3rd/4th .stat, and a positional lookup silently writes the wrong number into
    // the wrong card the moment a card is inserted.
    function pctBig(id,a){
      var e=document.getElementById(id);if(!e)return;
      e.innerHTML=(a!=null?Math.round(a*100):'—')+'<span style="font-size:18px">%</span>';
    }
    function setTxt(id,t){var e=document.getElementById(id);if(e)e.textContent=t;}
    function pctOf(a){return a!=null?Math.round(a*100)+'%':'—';}

    var ex=d.excluding_dlp||{}, dlp=d.dlp||{};
    // L1 Replacement leads the page: it is the measure the programme is gated on. The
    // terminal-verdict number stays, smaller and greyed, because the GAP between them is
    // itself the finding — 100 rows where the agent made L1's exact call and L2 overturned
    // L1. Removing it would hide that, and would also let the higher number read as though
    // the old one had improved.
    var rp=d.l1_replacement||{}, rpex=rp.excluding_dlp||{}, rpdlp=rp.dlp||{};
    pctBig('acc-repl-big', rp.accuracy);
    if(rp.scored!=null){
      setTxt('acc-repl-sub','30d '+pctOf(rp.accuracy_30d)+' · '+(rp.matches||0)+'/'+(rp.scored||0)
        +' · threat triage '+pctOf(rpex.accuracy)+' · DLP '+pctOf(rpdlp.accuracy));
    }
    pctBig('acc-excl-dlp-big', ex.ai_l1_accuracy);
    pctBig('acc-dlp-big',      dlp.ai_l1_accuracy);

    // The COMBINED figure has to stay READABLE somewhere. The headline is split because
    // DLP is a different workflow, not to retire the blended number — leaving it off makes
    // the split look like the metric was simply made smaller, and it also means the card
    // labelled "EXCL. DLP" gets read as "the" accuracy. It had no card of its own, so it
    // rides in this card's subline: asked on 2026-09-08 what the accuracy was, the page
    // could only answer 64% when the all-in figure was 67%.
    // Lead each card with its 30-DAY figure, not just lifetime. Lifetime hides the only
    // real difference between these two: measured 2026-09-03 the lifetime numbers were
    // 0.679 (threat triage) and 0.678 (DLP) — indistinguishable, so both cards read "68%"
    // and DLP looked like the drag on a headline it was not moving. Over 30 days they
    // separate: 0.734 vs 0.678. The recent window is where these are monitorable.
    if(ex.resolved!=null){
      setTxt('acc-excl-dlp-sub','30d '+pctOf(ex.ai_l1_accuracy_30d)+' ('+(ex.ai_l1_matches_30d||0)+'/'+(ex.resolved_30d||0)+')'
        +' · lifetime '+(ex.ai_l1_matches||0)+'/'+(ex.resolved||0)
        +' · blended '+pctOf(d.ai_l1_accuracy)+' incl. DLP');
    }
    if(dlp.resolved!=null){
      setTxt('acc-dlp-sub','30d '+pctOf(dlp.ai_l1_accuracy_30d)+' ('+(dlp.ai_l1_matches_30d||0)+'/'+(dlp.resolved_30d||0)+')'
        +' · lifetime '+(dlp.ai_l1_matches||0)+'/'+(dlp.resolved||0));
    }
    // Two agreement lenses. Both read LOWER than the blended headline by construction:
    // they are RAW agreement, while the headline adds warranted-escalation credit. The
    // denominators are printed because the two can differ, and a ratio without its
    // denominator is unreadable.
    // "Agrees with L1" card removed 2026-09-03. It read 63% and could not be acted on:
    // raw agreement with no escalation credit, so it sat below the headline for a reason
    // that had nothing to do with agent quality, and crediting it was measured worth only
    // ~1pp (0.662 -> 0.670) because the RJ-with-justification credit cannot be
    // reconstructed — `_justified` is computed at close time and never persisted.
    // l1_agreement stays in the API (the aggregation runs anyway for the by-type vs-L1
    // column) but nothing renders it.
    var a2=d.l2_agreement||{};
    pctBig('acc-l2-big', a2.accuracy);
    if(a2.scored!=null) setTxt('acc-l2-sub','the harder bar · '+(a2.matches||0)+'/'+(a2.scored||0));
    setTxt('verdicts-tracked-big',(d.total_shadow_results||0).toLocaleString());
    var dn=document.getElementById('dlp-note');
    if(dn&&dlp.resolved){
      // The lifetime comparison is COMPUTED, never narrated. It was hardcoded as "the two
      // are indistinguishable" off a 2026-09-03 reading where they really were 0.679 and
      // 0.678; by 2026-09-08 DLP had pulled ~8pp AHEAD (0.720 vs 0.643) and the sentence
      // was printing two plainly different numbers while calling them the same.
      var gap=(dlp.ai_l1_accuracy!=null&&ex.ai_l1_accuracy!=null)
        ? dlp.ai_l1_accuracy-ex.ai_l1_accuracy : null;
      var life='';
      if(gap==null){
        life='';
      } else if(Math.abs(gap)<0.02){
        life='LIFETIME the two are indistinguishable ('+pctOf(dlp.ai_l1_accuracy)+' vs '
          +pctOf(ex.ai_l1_accuracy)+'), so splitting DLP out does not move the blended figure.';
      } else {
        life='LIFETIME DLP runs '+Math.round(Math.abs(gap)*100)+'pp '+(gap>0?'AHEAD of':'BEHIND')
          +' threat triage ('+pctOf(dlp.ai_l1_accuracy)+' vs '+pctOf(ex.ai_l1_accuracy)+'), so the '
          +'EXCL. DLP card reads '+(gap>0?'BELOW':'ABOVE')+' the blended '+pctOf(d.ai_l1_accuracy)
          +' over all '+(d.resolved||0)+' scored verdicts.';
      }
      dn.textContent='Netskope DLP is reported separately because it is a different workflow — '
        +'a business-justification question (which team the actor is on, whether that process '
        +'legitimately holds PAN/Aadhaar data), not a threat-triage one. Over the last 30 days: '
        +'DLP '+pctOf(dlp.ai_l1_accuracy_30d)+' on '+(dlp.resolved_30d||0)+' scored verdicts vs '
        +pctOf(ex.ai_l1_accuracy_30d)+' on '+(ex.resolved_30d||0)+' for everything else. '+life;
    }
    renderAccByType(d.by_alert_name||[]);
  }).catch(function(){});
}
// Families that were SKIPPED entirely until 2026-08-27 and are now triaged. They are
// high-volume and mostly business-justification workflows, so listing all 48 of them
// buries the threat-triage families this table exists to surface — the dashboard read
// better when these simply were not there. Hidden by DEFAULT to restore that, but the
// count of what is hidden is always printed: a filtered view must never be mistakable
// for the whole picture.
var OBSERVED_RE = /netskope|^found\s+\d+\s+alerts?\s+for|cyble/i;

function observedShown(){
  try { return localStorage.getItem('raptorShowObserved') === '1'; } catch(e) { return false; }
}
function toggleObserved(){
  var cb=document.getElementById('ft-observed');
  try { localStorage.setItem('raptorShowObserved', cb && cb.checked ? '1' : '0'); } catch(e) {}
  pgReset('acc');   // the row set changes under the pager
  if(window._accByTypeRows) renderAccByType(window._accByTypeRows);
}

/* Weekly FP review pack. Downloads client-side as CSV so it opens in Excel/Sheets for
   management without anyone needing API access. Deliberately labelled "recommended", not
   "closed": in copilot phase the agent posts an advisory comment and the deterministic
   playbook still owns every ticket state change. */
function loadFpReport(){
  fetch('/api/edr-triage/fp-report?days=7').then(function(r){return r.json();}).then(function(d){
    var el=document.getElementById('fp-report-summary');if(!el)return;
    var scored=(d.agreed||0)+(d.overturned||0);
    var rate=d.agreement_rate!=null?Math.round(d.agreement_rate*100)+'%':'—';
    el.innerHTML='<b style="color:var(--text-bright)">'+(d.total_fp_verdicts||0)+'</b> false-positive recommendations in the last '
      +(d.window_days||7)+' days · <b style="color:var(--good)">'+(d.agreed||0)+'</b> confirmed by an analyst · '
      +'<b style="color:'+((d.overturned||0)?'var(--crit)':'var(--good)')+'">'+(d.overturned||0)+'</b> overturned · '
      +(d.pending_human_review||0)+' awaiting review'
      +((d.closed_as_duplicate||0)?(' · '+d.closed_as_duplicate+' closed as duplicate (never scoreable)'):'')
      +' · agreement <b>'+rate+'</b> across the '+scored+' resolved'
      +'<br><span style="font-size:11.5px">Phase <span class="mono">'+(d.agent_phase||'?')+'</span>'
      +((d.agent_phase==='copilot')?' — advisory only, the agent closed none of these.':'')+'</span>';
  }).catch(function(){var el=document.getElementById('fp-report-summary');if(el)el.textContent='report unavailable';});
}

/* Autonomous closes. Two numbers matter and they are NOT interchangeable:
   `overturned` is a human reopening a ticket RAPTOR closed — real disagreement — while
   `unreviewed_beyond_threshold` is closes nobody has looked at yet. A reopen detects
   disagreement, not diligence, so zero overturns with a large unreviewed count means
   "nobody checked", not "all correct". Both are shown, always, side by side. */
function loadAutocloseReport(){
  fetch('/api/edr-triage/autoclose-report?lookback_days=30').then(function(r){return r.json();})
  .then(function(d){
    var el=document.getElementById('ac-summary'); if(!el)return;
    var n=d.autonomous_closes||0, ov=d.overturned||0, un=d.unreviewed_beyond_threshold||0,
        rv=d.reviewed||0, lbl=d.reviewed_label||'raptor-reviewed';
    if(!n){
      el.innerHTML='<b style="color:var(--text-bright)">0</b> autonomous closes in the last '
        +(d.window_days||30)+' days — RAPTOR has closed nothing itself. '
        +'<span style="font-size:11.5px">Autonomy needs BOTH AGENT_PHASE=autonomous and the '
        +'alert family on AGENT_AUTONOMOUS_ALERTS.</span>';
      document.getElementById('ac-rows').innerHTML=''; return;
    }
    var prec=d.precision!=null?Math.round(d.precision*1000)/10+'%':'—';
    el.innerHTML='<b style="color:var(--text-bright)">'+n+'</b> closed by RAPTOR in the last '
      +(d.window_days||30)+' days · <b style="color:'+(ov?'var(--crit)':'var(--good)')+'">'+ov
      +'</b> reopened by a human · precision <b>'+prec+'</b> · <b>'+rv+'</b> reviewed'
      +'<br><span style="font-size:11.5px'+(un?';color:var(--warn)':'')+'">'
      +(un?('⚠ '+un+' still unreviewed after '+(d.review_threshold_hours||48)+'h — no reopen is not evidence of agreement')
          :'all unreviewed closes are inside the review window')
      +' · L2: add the Jira label <code>'+esc(lbl)+'</code> once checked, or reopen if wrong</span>';
    window._AC_CLOSES = d.closes||[];
    renderAcCloses();
  }).catch(function(){
    var el=document.getElementById('ac-summary');
    if(el)el.textContent='autonomous-close report unavailable';
  });
}

/* Reopened closes sort FIRST, regardless of page. An overturn is the only row here
   that needs acting on, and burying it on page 3 by date is how it would be missed. */
function renderAcCloses(){
  PG_RENDER['ac']=renderAcCloses;
  var host=document.getElementById('ac-rows'); if(!host)return;
  var all=(window._AC_CLOSES||[]).slice().sort(function(a,b){
    var ra=a.reopened_at?0:1, rb=b.reopened_at?0:1;
    if(ra!==rb)return ra-rb;
    return (a.age_hours||0)-(b.age_hours||0);
  });
  pgPaint('ac',all.length,10);
  if(!all.length){host.innerHTML='';return;}
  host.innerHTML=pgSlice('ac',all,10).map(function(c){
    var bad=!!c.reopened_at;
    return '<div style="padding:5px 0;border-bottom:1px solid var(--line)">'
      +jiraLink(c.jira_key)+' '
      +'<span style="color:var(--muted)">'+esc((c.alert_name||'').slice(0,64))+'</span> \u00b7 '
      +Math.round(c.age_hours)+'h ago \u00b7 '
      +(bad?'<b style="color:var(--crit)">REOPENED to '+esc(c.reopened_to||'?')+' by '
             +esc(c.reopened_by||'?')+'</b>'
           :(c.reviewed_at?'<span style="color:var(--good)">reviewed by '+esc(c.reviewed_by||'?')+'</span>'
                          :'<span style="color:var(--muted)">standing, not yet reviewed</span>'))
      +'</div>';
  }).join('');
}

function downloadFpReport(days){
  var note=document.getElementById('fp-report-note');
  if(note)note.textContent='building…';
  fetch('/api/edr-triage/fp-report?days='+days).then(function(r){return r.json();}).then(function(d){
    function esc(v){v=(v==null?'':String(v));return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;}
    var out=[];
    out.push('# RAPTOR false-positive review');
    out.push('# window_days,'+d.window_days+',generated,'+d.generated_at+',phase,'+d.agent_phase);
    out.push('# NOTE: in copilot phase these are RECOMMENDATIONS. The agent closed nothing;');
    out.push('# the deterministic playbook owns every ticket state change.');
    out.push('# total,'+d.total_fp_verdicts+',confirmed,'+d.agreed+',overturned,'+d.overturned
             +',awaiting,'+d.pending_human_review+',agreement,'+(d.agreement_rate==null?'n/a':d.agreement_rate));
    out.push('');
    out.push(['outcome','jira_key','alert_name','user','device','ai_confidence','l1_verdict','l2_verdict','created_at','ai_reasoning'].join(','));
    // Overturned FIRST — it is the section that needs acting on.
    [['OVERTURNED',d.overturned_alerts],['CONFIRMED',d.agreed_alerts],['AWAITING',d.pending_alerts]]
      .forEach(function(pair){
        (pair[1]||[]).forEach(function(a){
          out.push([pair[0],a.jira_key,esc(a.alert_name),esc(a.user_name),esc(a.device_name),
                    a.confidence,a.l1_verdict,a.l2_verdict,a.created_at,
                    esc((a.reasoning||'').replace(/\s+/g,' '))].join(','));
        });
      });
    var blob=new Blob([out.join('\n')],{type:'text/csv;charset=utf-8'});
    var url=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=url;a.download='raptor-fp-review-'+(d.generated_at||'').slice(0,10)+'-'+days+'d.csv';
    document.body.appendChild(a);a.click();document.body.removeChild(a);
    setTimeout(function(){URL.revokeObjectURL(url);},1000);
    if(note)note.textContent=(d.total_fp_verdicts||0)+' rows downloaded';
  }).catch(function(e){if(note)note.textContent='download failed: '+e;});
}

function renderAccByType(rows){
  var el=document.getElementById('acc-by-type');if(!el)return;
  window._accByTypeRows = rows;
  var cb=document.getElementById('ft-observed');
  if(cb) cb.checked = observedShown();
  var note=document.getElementById('acc-obs-note');
  if(!observedShown()){
    var hid=rows.filter(function(r){return OBSERVED_RE.test(r.alert_name||'');});
    var hr=hid.reduce(function(a,r){return a+(r.resolved||0);},0);
    var hm=hid.reduce(function(a,r){return a+(r.matches||0);},0);
    rows=rows.filter(function(r){return !OBSERVED_RE.test(r.alert_name||'');});
    if(note) note.textContent = hid.length
      ? hid.length+' observed-only families hidden ('+hm+'/'+hr+' verdicts'
        +(hr?' · '+Math.round(hm/hr*100)+'%':'')+') — still counted in the headline'
      : '';
  } else if(note) { note.textContent=''; }
  PG_RENDER['acc']=function(){renderAccByType(window._accByTypeRows||[]);};
  pgPaint('acc',rows.length,15);
  if(!rows.length){el.innerHTML='<span class="cell-faint">no resolved verdicts yet</span>';return;}
  var pageRows=pgSlice('acc',rows,15);
  // Low agreement is amber, never red: on most families it is over-escalation (the safe
  // side). Red is kept for the Said FP→TP column — RAPTOR said FP, a human closed it TP.
  function colorFor(a){return a==null?'var(--muted)':(a>=0.75?'var(--good)':'var(--quar)');}
  function pct(a){return a==null?'—':Math.round(a*100)+'%';}
  el.innerHTML='<table style="width:100%;border-collapse:collapse;font-size:12.5px">'
    +'<thead><tr style="color:var(--muted);text-align:left">'
    +'<th style="padding:4px 8px 8px 0;font-weight:500">Alert Type</th>'
    +'<th style="padding:4px 8px 8px;font-weight:500;text-align:right">Lifetime</th>'
    +'<th style="padding:4px 8px 8px;font-weight:500;text-align:right" title="Agreement with L1&#39;s OWN decision (escalate / ask / close). Agent NEEDS_L2 with L1 also NEEDS_L2 counts as agreement here — the Lifetime column scores against the TERMINAL verdict instead, which is L2&#39;s on an escalated ticket, so it marks those as misses.">vs L1</th>'
    +'<th style="padding:4px 8px 8px;font-weight:500;text-align:right">30d</th>'
    +'<th style="padding:4px 8px 8px;font-weight:500;text-align:right" title="RAPTOR said false positive and a human closed it as TP — the only miss that can lose a true positive. Check each: a TP close also covers authorised activity (TP-benign).">Said FP→TP</th>'
    +'<th style="padding:4px 0 8px;font-weight:500;text-align:right">Verdicts</th>'
    +'</tr></thead><tbody>'
    +pageRows.map(function(r){
      return '<tr style="border-top:1px solid var(--line)">'
        +'<td style="padding:6px 8px 6px 0;color:var(--text-bright)">'+esc(r.alert_name)+'</td>'
        +'<td style="padding:6px 8px;text-align:right;color:'+colorFor(r.accuracy)+'" class="mono">'+pct(r.accuracy)+'</td>'
        +'<td style="padding:6px 8px;text-align:right;color:'+colorFor(r.accuracy_l1)+'" class="mono" title="'+(r.matches_l1||0)+' of '+(r.scored_l1||0)+' agreed with L1">'+pct(r.accuracy_l1)+'</td>'
        +'<td style="padding:6px 8px;text-align:right;color:'+colorFor(r.accuracy_30d)+'" class="mono">'+pct(r.accuracy_30d)+'</td>'
        +'<td style="padding:6px 8px;text-align:right;color:'+((r.missed_tp||0)?'var(--crit);font-weight:700':'var(--good)')+'" class="mono">'+(r.missed_tp==null?'—':r.missed_tp)+'</td>'
        +'<td style="padding:6px 0;text-align:right;color:var(--muted)" class="mono">'+r.resolved+'</td>'
        +'</tr>';
    }).join('')
    +'</tbody></table>';
}
function loadQuar(){
  // Type filter is applied SERVER-side and its options come from true whole-collection
  // counts (/quarantine/counts), not from the fetched page. Deriving the options from
  // the page was the starvation bug: one high-volume family (Netskope DLP) filled the
  // 200-row page, so every other family was neither shown NOR selectable.
  var sel=document.getElementById('ft-quar');
  var ft=sel?sel.value:'';
  pgReset('quar'); pgReset('dlpquar');   // a refetch replaces the rows entirely
  var dis=QUAR_ATTN?'&disagreement_only=true':'';
  fetch('/api/memory/quarantine/counts').then(function(r){return r.json();}).then(function(c){
    var counts=(c&&c.counts)||{},total=(c&&c.total)||0;
    if(sel){
      var cur=sel.value;
      var types=Object.keys(counts).sort(function(a,b){return counts[b]-counts[a];});
      sel.innerHTML='<option value="">All alert types ('+total+')</option>'
        +types.map(function(t){return '<option value="'+esc(t)+'">'+esc(t)+' ('+counts[t]+')</option>';}).join('');
      sel.value=cur;
    }
    var na=document.getElementById('qn-all');if(na)na.textContent=total;
    if(!dis){setTab('quar',total);setStat(0,total);setStatSub(0,'in quarantine');}   // filtered: the list response sets it
  }).catch(function(){});
  // Disagreement filter runs SERVER-side over the whole queue: it needs the ShadowResult
  // verdicts, which are not on the memory row. Filtered, every disagreement is loaded and
  // the tab shows the true count; unfiltered stays a 200-row page of the newest.
  fetch('/api/memory/quarantine?limit='+(dis?2000:200)+(ft?'&alert_type='+encodeURIComponent(ft):'')+dis).then(function(r){return r.json();}).then(function(d){
    QUAR=Array.isArray(d)?d:(d.memories||[]);renderQuar('quar');renderQuar('dlpquar');
    if(d&&!Array.isArray(d)&&typeof d.total==='number'){
      setTab('quar',d.total);setStat(0,d.total);setStatSub(0,'need a person (AI and L1 disagree)');
      var nt=document.getElementById('qn-attn');if(nt)nt.textContent=d.total;
    }
    setTab('dlp',QUAR.filter(function(m){return isDlpAlert(m.alert_type);}).length);
  }).catch(function(){QUAR=[];renderQuar('quar');renderQuar('dlpquar');});
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
    setStat(1,total);setTab('gold',total);fillTypes('ft-gold',GOLD);
    renderGold('gold');renderGold('dlpgold');
  }).catch(function(){GOLD=[];renderGold('gold');renderGold('dlpgold');});
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
  // Each bar is the week's scored tickets split by outcome. Red is reserved for the one
  // miss that can lose a true positive (RAPTOR said FP, a human closed it TP); an
  // escalation a human closed FP is amber, because it cost time, not a TP. Colouring the
  // whole bar by agreement made a week of over-escalation read as "RAPTOR got worse".
  var sum=document.getElementById('mh-trend-sum');
  el.innerHTML=series.map(function(w){
    var n=w.total||0;
    function seg(k,col){var v=w[k]||0;return v&&n?'<span'+(k==='missed_tp'?' class="tred"':'')+' style="height:'+(v/n*100)+'%;background:'+col+'"></span>':'';}
    var thin=w.in_progress||n<20;
    var tip=w.week+(w.in_progress?' (in progress — only the fastest-resolved tickets so far)':'')
      +'\n'+n+' scored · '+(w.matches||0)+' agreed'
      +'\n'+(w.over_escalated||0)+' escalated, human closed FP'
      +'\n'+(w.missed_tp||0)+' said FP, human closed TP'
      +((w.other_miss||0)?'\n'+w.other_miss+' other':'')
      +'\n'+(w.autonomous_closes||0)+' closed by RAPTOR itself (not scored)'
      +((w.autonomous_reopened||0)?', '+w.autonomous_reopened+' reopened':'');
    return '<span class="tbar'+(thin?' partial':'')+'" title="'+esc(tip)+'">'
      +'<span class="tpct">'+(w.accuracy==null?'—':Math.round(w.accuracy*100)+'%')+'</span>'
      +'<span class="tstack">'+seg('matches','var(--good)')+seg('other_miss','var(--muted)')
      +seg('over_escalated','var(--quar)')+seg('missed_tp','var(--crit)')+'</span>'
      +'<span class="tw">'+esc(w.week.replace(/^\d+-/,''))+(w.in_progress?'*':'')+'</span>'
      +'<span class="tauto" style="'+((w.autonomous_reopened||0)?'color:var(--crit)':'')+'">'
      +((w.autonomous_closes||0)?'+'+w.autonomous_closes+' auto':'&nbsp;')+'</span>'
      +'</span>';
  }).join('');
  if(!sum)return;
  var missed=series.reduce(function(a,w){return a+(w.missed_tp||0);},0);
  var full=series.filter(function(w){return !w.in_progress;});
  var lw=full.length?full[full.length-1]:null;
  var txt='<b style="color:'+(missed?'var(--crit)':'var(--good)')+'">'+missed+' ticket'+(missed===1?'':'s')
    +' RAPTOR called FP that a human closed as TP</b> in these '+series.length+' weeks'
    +(missed?' — check each: a TP close also covers authorised activity (TP-benign), not only real attacks.':'.');
  if(lw){
    var miss=(lw.total||0)-(lw.matches||0);
    txt+=' Last full week ('+esc(lw.week.replace(/^\d+-/,''))+'): '+(miss?(lw.over_escalated||0)+' of '+miss
      +' disagreements were escalations a human closed FP.':'no disagreements.')
      +' RAPTOR closed '+(lw.autonomous_closes||0)+' itself'
      +((lw.autonomous_reopened||0)?' ('+lw.autonomous_reopened+' reopened)':'')
      +'; those are not in the bars — see Autonomous closes.';
  }
  if(series.some(function(w){return w.in_progress;})) txt+=' * = week in progress.';
  sum.innerHTML=txt;
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

// DLP is reviewed in its own tab because it is a different workflow: a DLP memory
// records a business justification ("this team is allowed to hold PAN data for this
// process"), not a threat-triage precedent. Mirrors is_dlp_alert() in Python — keep
// the two in step.
function isDlpAlert(n){return (n||'').toLowerCase().indexOf('dlp')>=0;}

// One row renderer, two views. The DLP tab is the SAME table scoped to the DLP
// families; the main tab excludes them. Duplicating the row markup would let the two
// drift, so the view only supplies element ids and a scope.
var QUAR_VIEWS={
  quar:    {q:'q-quar',    ft:'ft-quar', cnt:'cnt-quar',    tb:'tb-quar',    dlp:false},
  dlpquar: {q:'q-dlpquar', ft:'',        cnt:'cnt-dlpquar', tb:'tb-dlpquar', dlp:true}
};
/* The agent-vs-L1 pair, rendered on the row. Without it a reviewer cannot tell a real
   conflict from a pending agreement — the verdicts were only ever visible inside the
   `content` prose. L1 is the comparison that matters here: the programme is to replace
   L1, so agent NEEDS_L2 against L1 NEEDS_L2 is a success, not review work, even where L2
   later closed it FP (which is shown too, when it differs). */
function verdictPair(m){
  var ai=m.ai_verdict||'',l1=m.l1_verdict||'',l2=m.l2_verdict||'';
  if(!ai&&!l1)return '';
  var cls=m.disagrees_with_l1?'crit':'muted';
  var txt='AI '+(ai||'—')+' vs L1 '+(l1||'pending');
  if(l2&&l2!==l1)txt+=' (L2 '+l2+')';
  return '<div class="mono" style="font-size:10.5px;color:var(--'+cls+');margin-bottom:2px">'+esc(txt)+'</div>';
}

function renderQuar(view){
  var V=QUAR_VIEWS[view||'quar'];if(!V)return;
  var qEl=document.getElementById(V.q);if(!qEl)return;
  var q=(qEl.value||'').toLowerCase();
  var ftEl=V.ft?document.getElementById(V.ft):null;
  var ft=ftEl?ftEl.value:'';
  var rows=QUAR.filter(function(m){
    if(isDlpAlert(m.alert_type)!==V.dlp)return false;
    if(ft&&m.alert_type!==ft)return false;
    if(q&&!((memTitle(m)+(m.content||'')+(m.alert_type||'')).toLowerCase().includes(q)))return false;return true;});
  // Say so when the 200-row page is full — the true bucket total is in the type
  // filter, and silently showing a capped list reads as "this is everything".
  document.getElementById(V.cnt).textContent=
    rows.length+' shown'+(QUAR.length>=200?' (page capped at 200 — narrow by alert type)':' in queue');
  var tb=document.getElementById(V.tb);
  PG_RENDER[view||'quar']=function(){renderQuar(view||'quar');};
  pgPaint(view||'quar',rows.length,25);
  if(!rows.length){tb.innerHTML='<tr><td colspan="7"><div class="empty">Queue clear — no conflicts awaiting review</div></td></tr>';return;}
  tb.innerHTML=pgSlice(view||'quar',rows,25).map(function(m){
    var reason=stripFlag(m.quarantine_reason)||'—';
    return '<tr onclick="openMem(\''+esc(m.id)+'\',\'quar\')">'
      +'<td class="alert-cell"><div class="an">'+(isFlagged(m)?'<span class="flagged">⚑ </span>':'')+esc(memTitle(m))+'</div>'+jiraLink(m.jira_key)+'</td>'
      +'<td><span class="type">'+esc(m.alert_type||'—')+'</span></td>'
      +'<td><div class="content"><span class="qt">“</span>'+esc((m.content||'').slice(0,110))+((m.content||'').length>110?'…':'')+'<span class="qt">”</span></div></td>'
      +'<td><div class="conflict">'+verdictPair(m)+'<span class="l1">'+esc(reason.slice(0,60))+(reason.length>60?'…':'')+'</span></div></td>'
      +'<td class="conf">'+Math.round((m.confidence||0)*100)+'%</td>'
      +'<td class="cell-faint">'+esc(relTime(m.created_at))+'</td>'
      +'<td onclick="event.stopPropagation()"><div class="rowacts">'
      +'<button class="ib ok" title="Promote to golden" onclick="act(\''+esc(m.id)+'\',\'promote\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg></button>'
      +'<button class="ib flag" title="Flag for review" onclick="act(\''+esc(m.id)+'\',\'flag\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7"/></svg></button>'
      +'<button class="ib no" title="Dismiss" onclick="act(\''+esc(m.id)+'\',\'dismiss\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg></button>'
      +'</div></td></tr>';
  }).join('');
}
var GOLD_VIEWS={
  gold:    {q:'q-gold',    ft:'ft-gold', cnt:'cnt-gold',    tb:'tb-gold',    dlp:false},
  dlpgold: {q:'q-dlpgold', ft:'',        cnt:'cnt-dlpgold', tb:'tb-dlpgold', dlp:true}
};
function renderGold(view){
  var V=GOLD_VIEWS[view||'gold'];if(!V)return;
  var qEl=document.getElementById(V.q);if(!qEl)return;
  var q=(qEl.value||'').toLowerCase();
  var ftEl=V.ft?document.getElementById(V.ft):null;
  var ft=ftEl?ftEl.value:'';
  var rows=GOLD.filter(function(m){
    if(isDlpAlert(m.alert_type)!==V.dlp)return false;
    if(ft&&m.alert_type!==ft)return false;
    if(q&&!((memTitle(m)+(m.content||'')+(m.alert_type||'')+(m.resolved_by||'')).toLowerCase().includes(q)))return false;return true;});
  var _soon=rows.filter(function(m){return m.expires_in_days!=null&&m.expires_in_days<=30;}).length;
  document.getElementById(V.cnt).textContent=rows.length+' memories'
    +(_soon?' \u00b7 '+_soon+' going inert within 30d':'');
  var tb=document.getElementById(V.tb);
  PG_RENDER[view||'gold']=function(){renderGold(view||'gold');};
  pgPaint(view||'gold',rows.length,25);
  if(!rows.length){tb.innerHTML='<tr><td colspan="9"><div class="empty">No memories match</div></td></tr>';return;}
  tb.innerHTML=pgSlice(view||'gold',rows,25).map(function(m){
    var isG=m.tier==='golden';var tbc=isG?'t-gold':'t-cur';var tl=isG?'Golden':'Curated';
    var scopeCell=scopeBadge(m)+(m.auto_fp?' '+afpBadge(m):'')+(m.actor?'<div class="cell-faint" style="font-size:10px;margin-top:3px">'+esc(m.actor)+(m.device?' · '+esc(m.device):'')+'</div>':'')
      // App scope is the distinguishing fact on a CASB verdict — show it on the row so
      // "Slack-only" is visible without opening the drawer.
      +((m.apps&&m.apps.length)?'<div class="cell-faint" style="font-size:10px;margin-top:2px">app: '+esc(m.apps.join(', '))+'</div>':'')
      // Going inert soon: an allowlist entry about to expire, or a memory about to decay
      // out of recall. Shown so L2 can re-validate what still holds before it drops out.
      +expiryBadge(m);
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
  var body={};
  var pinned=s&&(s.device||(s.commands&&s.commands.length)||(s.apps&&s.apps.length));
  if(s&&!pinned){
    // An entry must pin something beyond the actor. DLP and other cloud alerts have no
    // device or command, so the app is the pin — e.g. "Google Drive".
    var app=window.prompt('This entry pins only '+s.actor+' and would be refused.\n\nWhich app should it be limited to? (e.g. Google Drive)','');
    if(app===null)return;
    app=app.trim(); if(!app){window.alert('Not armed: an app is required.');return;}
    body.apps=[app];
    who+=' in '+app;
  }
  if(!window.confirm('Arm the actor-allowlist for '+who+'?\n\nFuture matching alerts auto-close as FALSE POSITIVE with no LLM call. Reversible from the Golden Memory tab.'))return;
  fetch('/api/memory/suggestions/'+encodeURIComponent(id)+'/arm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
    .then(function(x){
      if(!x.ok){window.alert('Not armed: '+((x.d&&x.d.detail)||'the server refused this entry'));return;}
      loadSugg();loadGold();
    })
    .catch(function(){window.alert('Not armed: the request failed. Reload the page and try again.');});
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
// The tab is in the URL so a pane can be LINKED. The weekly FP review exists to be sent
// to L2 and management; a view reachable only by clicking through from the quarantine
// queue is not something you can put in an email. All loaders run once on page load and
// switchTab only toggles classes, so a deep link needs no extra fetch.
function switchTab(p,skipHash){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('on',t.dataset.p===p);});
  document.querySelectorAll('.pane').forEach(function(pane){pane.classList.toggle('on',pane.id==='pane-'+p);});
  if(!skipHash){ try{ history.replaceState(null,'','#'+p); }catch(e){} }
}
function tabFromHash(){
  var p=(location.hash||'').replace(/^#/,'');
  // Only a hash naming a pane that exists — otherwise leave the default tab alone.
  if(p && document.getElementById('pane-'+p)) switchTab(p,true);
}
window.addEventListener('hashchange',tabFromHash);
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
    +cmdsBox(m)
    +'</div></div>';
}
// The exact commands an armed entry clears. Root Privesc must pin them (an entry pinned
// to actor + device would close any root command on that host). Filled from the memory,
// or read off RAPTOR's comment on the ticket by loadMemCmds when the drawer opens.
function cmdsBox(m){
  if((m.alert_type||'')!=='privesc' && !(m.commands&&m.commands.length)) return '';
  var pre=(m.commands&&m.commands.length)?m.commands.join('\n'):'';
  return '<label class="opt"><span style="width:100%"><b>Commands</b> — arming clears exactly these, one per line. '
    +'<span class="cell-faint">'+((m.alert_type||'')==='privesc'?'Required to arm Root Privesc.':'Blank = any command.')+'</span>'
    +'<textarea id="pcmds" rows="3" placeholder="e.g. su - netra" '
    +'style="width:100%;margin-top:6px;padding:6px 8px;border-radius:6px;border:1px solid var(--line);'
    +'background:var(--bg);color:var(--text);font-size:12px;font-family:var(--mono,monospace)">'+esc(pre)+'</textarea></span></label>';
}
function loadMemCmds(m){
  var el=document.getElementById('pcmds');
  if(!el||el.value.trim()||!m||!m.id)return;
  el.placeholder='reading the ticket…';
  fetch('/api/memory/quarantine/'+encodeURIComponent(m.id)+'/commands').then(function(r){return r.json();})
    .then(function(j){var c=(j&&j.commands)||[];if(c.length&&!el.value.trim()){el.value=c.join('\n');m.commands=c;}
      el.placeholder=c.length?'':'no commands found on the ticket — type them';}).catch(function(){el.placeholder='could not read the ticket — type them';});
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
  var cmdsEl=document.getElementById('pcmds');
  if(cmdsEl&&cmdsEl.value.trim()){
    body.commands=cmdsEl.value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
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
  if(kind==='quar')loadMemCmds(m);
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
var NAV={'Triage Console':'/edr-triage','AI Memory':'/memory/quarantine','Dashboard':'/dashboard','Threat Hunting':'/shadow','Settings':'/settings'};
document.querySelectorAll('.rail .navbtn').forEach(function(b){var tip=(b.querySelector('.tip')||{}).textContent||'';if(NAV[tip])b.onclick=function(){location.href=NAV[tip];};});

tabFromHash();
loadShadow();loadFpReport();loadAutocloseReport();loadQuar();loadGold();loadAna();loadHealth();loadAcc();loadSugg();loadPA();
</script>

</body>
</html>"""
