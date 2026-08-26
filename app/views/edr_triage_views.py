"""EDR Triage views — /edr-triage page + JSON API.

Routes:
    GET  /edr-triage                       — full triage page
    GET  /api/edr-triage/stats             — KPI counters
    GET  /api/edr-triage/alerts            — paginated triaged alerts table
    GET  /api/edr-triage/alerts/{id}       — single alert detail (drawer)
    POST /api/edr-triage/run               — trigger immediate poll cycle
    GET  /api/edr-triage/observations      — ticket observatory (all seen types)
    POST /api/edr-triage/observations/review — mark an alert type as reviewed
    GET  /api/edr-triage/rules             — list user-defined triage rules
    POST /api/edr-triage/rules             — create a rule
    DELETE /api/edr-triage/rules/{id}      — delete a rule
"""
from __future__ import annotations

import logging
import os
import re

from fastapi import APIRouter, BackgroundTasks, HTTPException, Body
from fastapi.responses import HTMLResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["edr-triage"])

_run_state: dict = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "processed": 0,
    "error": None,
}


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@router.get("/api/edr-triage/stats")
async def edr_stats():
    import asyncio
    from edr_triage.store import get_stats
    return await asyncio.to_thread(get_stats)


async def _attach_agent_verdicts(alerts: list[dict]) -> None:
    """Attach each row's CURRENT agent verdict alongside the one that was acted on.

    Two records hold a verdict and they legitimately disagree. The alert record's
    triage_class is what the playbook acted on — the labels it wrote to Jira. A later
    re-triage runs dry: it rewrites the shadow (and the alert's llm_reasoning) but
    never re-labels the ticket. So a re-triaged alert reads NEEDS_L2 on the alert and
    AUTO_CLOSED_FP on the shadow, and the console showed the first in the queue row
    and the second in the trace panel below it, with no hint they were different
    facts rather than a bug.

    Both are surfaced rather than one overwriting the other: the shadow verdict is
    what the accuracy metric counts, but the verdict filter queries alert.triage_class
    server-side, so swapping the displayed class would put a row under a filter chip
    that no longer describes it.
    """
    keys = [a.get("jira_key") for a in alerts if a.get("jira_key")]
    if not keys:
        return
    try:
        from beanie.operators import In
        from entity_graph.models import ShadowResult
        shadows = await ShadowResult.find(In(ShadowResult.jira_key, keys)).to_list()
    except Exception as exc:                       # never fail the queue over this
        logger.warning("could not attach agent verdicts: %s", exc)
        return
    latest: dict = {}
    for s in shadows:                              # newest wins on duplicate keys
        prev = latest.get(s.jira_key)
        if prev is None or s.created_at > prev.created_at:
            latest[s.jira_key] = s
    for a in alerts:
        s = latest.get(a.get("jira_key"))
        if not s:
            continue
        # Distinct keys on purpose. ai_confidence is already rendered beside the
        # acted-on verdict, so writing the shadow's number into it would pair a
        # NEEDS_L2 pill with the confidence of the FP the re-triage produced —
        # the same two-stories problem one field lower down.
        a["agent_triage_class"] = s.ai_triage_class
        a["agent_confidence"] = s.ai_confidence
        a["agent_retriaged_at"] = _iso(getattr(s, "retriaged_at", None))


@router.get("/api/edr-triage/alerts")
async def edr_alerts(
    limit: int = 20,
    offset: int = 0,
    triage_class: str = "",
    severity: str = "",
    hide_observed: bool = False,
    search: str = "",
):
    import asyncio
    from edr_triage.store import get_recent_alerts
    data = await asyncio.to_thread(get_recent_alerts, limit, offset, triage_class,
                                   severity, hide_observed, search)
    await _attach_agent_verdicts(data.get("alerts") or [])
    return data


@router.get("/api/edr-triage/alerts/{alert_id:path}")
async def edr_alert_detail(alert_id: str):
    import asyncio
    from edr_triage.store import get_alert_by_id
    data = await asyncio.to_thread(get_alert_by_id, alert_id)
    if not data:
        raise HTTPException(404, f"Alert not found: {alert_id}")
    await _attach_agent_verdicts([data])
    return data


@router.post("/api/edr-triage/run", status_code=202)
async def edr_run(background_tasks: BackgroundTasks):
    if _run_state["running"]:
        return {"status": "already_running"}
    background_tasks.add_task(_run_bg)
    return {"status": "started"}


@router.get("/api/edr-triage/run-status")
async def edr_run_status():
    return dict(_run_state)


_test_state: dict = {"running": False, "results": None, "started_at": None, "finished_at": None}

_synthetic_state: dict = {"running": False, "result": None, "error": None}

_SYNTHETIC_TICKET = {
    "jira_key":   "DEMO-9001",
    "alert_id":   "da637000000000000_test",
    "alert_name": "Suspicious PowerShell encoded command execution",
    "description": "MDE Alert: Suspicious PowerShell encoded command execution\nDevice: WKSTN-4471\nUser: alice.chen@example.com",
    "severity":   "Medium",
    "tactics":    "Execution",
    "device_name": "WKSTN-4471",
    "user_name":  "alice.chen@example.com",
    "incident_url": "",
    "is_sentinel": False,
    "observe_only": False,
    "created_at": "",
}


@router.post("/api/edr-triage/run-synthetic", status_code=202)
async def edr_run_synthetic(background_tasks: BackgroundTasks):
    """Run the full pipeline with a synthetic test ticket to verify the agent loop end-to-end."""
    if _synthetic_state["running"]:
        return {"status": "already_running"}
    _synthetic_state.update(running=True, result=None, error=None)
    background_tasks.add_task(_run_synthetic_bg)
    return {"status": "started", "jira_key": _SYNTHETIC_TICKET["jira_key"]}


@router.get("/api/edr-triage/run-synthetic-status")
async def edr_run_synthetic_status():
    """Poll for synthetic pipeline result + check if ShadowResult was saved."""
    state = dict(_synthetic_state)
    if not state["running"]:
        try:
            from entity_graph.models import ShadowResult
            shadow = await ShadowResult.find_one(
                ShadowResult.jira_key == _SYNTHETIC_TICKET["jira_key"]
            )
            state["shadow_result"] = {
                "found": bool(shadow),
                "ai_triage_class": shadow.ai_triage_class if shadow else None,
                "ai_confidence": shadow.ai_confidence if shadow else None,
                "phase": shadow.phase if shadow else None,
            }
        except Exception as e:
            state["shadow_result"] = {"error": str(e)}
    return state


async def _run_synthetic_bg() -> None:
    try:
        from edr_triage.pipeline import _process_ticket
        from edr_triage.config import get_edr_config
        cfg = get_edr_config()
        result = await _process_ticket(_SYNTHETIC_TICKET, token=None, cfg=cfg)
        _synthetic_state.update(running=False, result=str(result))
    except Exception as exc:
        logger.exception("Synthetic pipeline run failed")
        _synthetic_state.update(running=False, error=str(exc))


# ---------------------------------------------------------------------------
# Run real Jira ticket through pipeline (dry_run=True — no Jira writes)
# ---------------------------------------------------------------------------

_ticket_run_state: dict = {
    "running": False, "jira_key": None, "result": None, "error": None,
    "started_at": None, "finished_at": None,
}


@router.post("/api/edr-triage/run-ticket/{jira_key}", status_code=202)
async def edr_run_ticket(
    jira_key: str,
    background_tasks: BackgroundTasks,
    force: bool = False,
    force_agent: bool = False,
):
    """Fetch a real Jira ticket and run it through the full pipeline (dry_run=True).

    force=true       clears the dedup record so a previously-processed ticket reruns.
    force_agent=true runs the agent loop (Bedrock/Mistral) for THIS ticket even when
                     USE_AGENT_LOOP is globally off — realistic single-ticket test.
    """
    if _ticket_run_state["running"]:
        return {"status": "already_running", "jira_key": _ticket_run_state["jira_key"]}
    if force:
        try:
            import asyncio
            from edr_triage.store import _col as _store_col
            # Delete by both alert_id and jira_key — initial claim only has alert_id,
            # fully-saved records have both. For Sentinel tickets alert_id == jira_key.
            await asyncio.to_thread(lambda: _store_col().delete_many(
                {"$or": [{"alert_id": jira_key}, {"jira_key": jira_key}]}
            ))
        except Exception as exc:
            logger.warning("Could not clear dedup record for %s: %s", jira_key, exc)
    import datetime as _dt
    _ticket_run_state.update(
        running=True, jira_key=jira_key, result=None, error=None,
        started_at=_dt.datetime.utcnow().isoformat(), finished_at=None,
    )
    background_tasks.add_task(_run_ticket_bg, jira_key, force_agent)
    return {"status": "started", "jira_key": jira_key, "force": force, "force_agent": force_agent}


@router.get("/api/edr-triage/shadows")
async def edr_list_shadows(limit: int = 20):
    """List most recent ShadowResults — confirms agent loop is running on real tickets."""
    try:
        from app.database import get_collection
        col = get_collection("eg_shadow_results")
        docs = await col.find({}).sort("created_at", -1).limit(limit).to_list(length=limit)
        return {
            "total": len(docs),
            "shadows": [
                {
                    "jira_key": d.get("jira_key"),
                    "alert_name": d.get("alert_name"),
                    "ai_triage_class": d.get("ai_triage_class"),
                    "ai_confidence": d.get("ai_confidence"),
                    "phase": d.get("phase"),
                    "created_at": d["created_at"].isoformat() if d.get("created_at") else None,
                }
                for d in docs
            ],
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.post("/api/edr-triage/shadows/cleanup")
async def edr_cleanup_shadows(dry_run: bool = True):
    """Remove stale duplicate ShadowResults — keep only the NEWEST row per jira_key.

    Reruns (force=true) leave older rows behind, including the dead 0.0-confidence
    agent-failure rows from before Mantle worked. Those inflate counts and skew any
    accuracy stat. This keeps the newest row per jira_key and deletes the rest.

    dry_run=true (default) only reports what WOULD be deleted; pass dry_run=false to
    actually delete.
    """
    try:
        from app.database import get_collection
        col = get_collection("eg_shadow_results")
        docs = await col.find({}).sort("created_at", -1).to_list(length=10000)
        seen: set[str] = set()
        to_delete: list = []
        deleted_preview: list[dict] = []
        for d in docs:  # newest-first, so the first row per key is the keeper
            k = d.get("jira_key")
            if k in seen:
                to_delete.append(d["_id"])
                deleted_preview.append({
                    "jira_key": k,
                    "created_at": d["created_at"].isoformat() if d.get("created_at") else None,
                    "ai_triage_class": d.get("ai_triage_class"),
                    "ai_confidence": d.get("ai_confidence"),
                    "ai_error": d.get("ai_error"),
                })
            else:
                seen.add(k)
        out = {
            "dry_run": dry_run,
            "total_rows": len(docs),
            "unique_keys": len(seen),
            "duplicates": len(to_delete),
            "would_delete" if dry_run else "deleted_preview": deleted_preview,
        }
        if not dry_run and to_delete:
            res = await col.delete_many({"_id": {"$in": to_delete}})
            out["deleted"] = res.deleted_count
        return out
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# Standalone agent loop run — no dedup, no Jira fetch, no playbook
# ---------------------------------------------------------------------------

_agent_run_state: dict = {"running": False, "jira_key": None, "result": None, "error": None}


@router.post("/api/edr-triage/run-agent", status_code=202)
async def edr_run_agent(background_tasks: BackgroundTasks, payload: dict = Body(...)):
    """Run the agent loop directly on provided alert data. Saves a ShadowResult to MongoDB.

    Body: { jira_key, alert_name, description, severity, device_name, user_name, incident_url }
    """
    if _agent_run_state["running"]:
        return {"status": "already_running", "jira_key": _agent_run_state["jira_key"]}
    jira_key = payload.get("jira_key", "AGENT-TEST-001")
    _agent_run_state.update(running=True, jira_key=jira_key, result=None, error=None)
    background_tasks.add_task(_run_agent_bg, jira_key, payload)
    return {"status": "started", "jira_key": jira_key}


@router.get("/api/edr-triage/run-agent-status")
async def edr_run_agent_status():
    state = dict(_agent_run_state)
    jira_key = state.get("jira_key")
    if not state["running"] and jira_key:
        try:
            from entity_graph.models import ShadowResult
            shadow = await ShadowResult.find_one(ShadowResult.jira_key == jira_key)
            state["shadow_result"] = {
                "found": bool(shadow),
                "ai_triage_class": shadow.ai_triage_class if shadow else None,
                "ai_confidence": shadow.ai_confidence if shadow else None,
                "ai_reasoning": shadow.ai_reasoning[:400] if shadow and shadow.ai_reasoning else None,
            }
        except Exception as exc:
            state["shadow_result"] = {"error": str(exc)}
    return state


async def _run_agent_bg(jira_key: str, payload: dict) -> None:
    try:
        from agent_core import loop as _agent_loop
        from agent_core.backend import get_backend
        from edr_triage.pipeline import _save_shadow_result

        alert_name   = payload.get("alert_name", "Test Alert")
        description  = payload.get("description", "")
        severity     = payload.get("severity", "Medium")
        device_name  = payload.get("device_name", "")
        user_name    = payload.get("user_name", "")
        incident_url = payload.get("incident_url", "")

        from edr_triage.classifier import classify
        alert_type = classify(alert_name)
        backend = get_backend(alert_type)

        agent_result = await _agent_loop.run(
            jira_key=jira_key,
            alert={"_description": description},
            alert_name=alert_name,
            severity=severity,
            device_name=device_name,
            user_name=user_name,
            sha256="",
            inv_state="",
            tactics=[],
            incident_url=incident_url,
            is_test_device=False,
            backend=backend,
        )

        await _save_shadow_result(
            jira_key=jira_key,
            alert_id=jira_key,
            alert_name=alert_name,
            device_name=device_name,
            user_name=user_name,
            severity=severity,
            agent_result=agent_result,
            phase="shadow",
            # This diagnostic path builds its own single-user context (no Sentinel
            # enrichment), so there are no co-users to record.
            additional_users=None,
        )

        _agent_run_state.update(running=False, result={
            "triage_class": agent_result.triage_class,
            "confidence": agent_result.confidence,
            "reasoning": agent_result.reasoning[:400],
            "iterations": agent_result.iterations,
            "tool_calls": len(agent_result.tool_calls),
        })
    except Exception as exc:
        logger.exception("Standalone agent run failed for %s", jira_key)
        _agent_run_state.update(running=False, error=str(exc))


_probe_state: dict = {"running": False, "result": None, "error": None}


@router.get("/api/edr-triage/agent-probe")
async def edr_agent_probe(background_tasks: BackgroundTasks):
    """Smoke-test agent loop imports + Ollama health (fast), then kick off a 1-iter background loop test."""
    result: dict = {}
    try:
        import agent_tools.virustotal  # noqa
        import agent_tools.mde         # noqa
        import agent_tools.sentinel    # noqa
        import agent_tools.scg         # noqa
        import agent_tools.jira        # noqa
        import agent_tools.kql_generator  # noqa
        import agent_tools.vuln_check  # noqa
        result["imports"] = "ok"
    except Exception as exc:
        result["imports"] = f"FAILED: {exc}"
        return result

    try:
        from agent_core.backend import OllamaBackend
        backend = OllamaBackend()
        reachable = await backend.health_check()
        result["ollama_reachable"] = reachable
        result["ollama_url"] = backend.base_url
        result["ollama_model"] = backend.model
    except Exception as exc:
        result["ollama_reachable"] = f"FAILED: {exc}"
        return result

    if not _probe_state["running"]:
        _probe_state.update(running=True, result=None, error=None)
        background_tasks.add_task(_run_probe_bg)
        result["loop_test"] = "started — poll /api/edr-triage/agent-probe-status"
    else:
        result["loop_test"] = "already running"
    return result


@router.get("/api/edr-triage/agent-probe-status")
async def edr_agent_probe_status():
    return dict(_probe_state)


async def _run_probe_bg() -> None:
    try:
        from agent_core import loop as _agent_loop
        from agent_core.backend import OllamaBackend
        probe_result = await _agent_loop.run(
            jira_key="PROBE-001",
            alert={"_description": "Test alert for smoke test"},
            alert_name="Test Alert",
            severity="Low",
            device_name="test-device",
            user_name="test-user",
            sha256="",
            inv_state="",
            tactics=[],
            incident_url="",
            is_test_device=True,
            backend=OllamaBackend(),
            max_iter=1,
        )
        _probe_state.update(running=False, result={
            "triage_class": probe_result.triage_class,
            "confidence": probe_result.confidence,
            "error": probe_result.error,
            "iterations": probe_result.iterations,
        })
    except Exception as exc:
        _probe_state.update(running=False, error=str(exc))


def _iso(dt):
    """Serialize an optional datetime; None stays None rather than becoming "None"."""
    return dt.isoformat() if dt else None


@router.get("/api/edr-triage/shadow/{jira_key}")
async def edr_shadow_result(jira_key: str):
    """Look up a ShadowResult directly by Jira key — pod-independent."""
    try:
        from entity_graph.models import ShadowResult
        shadow = await (
            ShadowResult.find(ShadowResult.jira_key == jira_key)
            .sort(-ShadowResult.created_at)
            .first_or_none()
        )
        if not shadow:
            return {"found": False, "jira_key": jira_key}
        return {
            "found": True,
            "jira_key": jira_key,
            # Actor set: the primary user plus every co-user on a grouped incident.
            # Surfaced so "did this alert's other users get recorded?" is answerable
            # from the API — the question DEMO-107416 raised.
            "user_name": getattr(shadow, "user_name", ""),
            "additional_users": getattr(shadow, "additional_users", []) or [],
            "device_name": getattr(shadow, "device_name", ""),
            "ai_triage_class": shadow.ai_triage_class,
            "ai_confidence": shadow.ai_confidence,
            "phase": shadow.phase,
            "ai_reasoning": shadow.ai_reasoning,
            "ai_recommended_actions": shadow.ai_recommended_actions,
            "ai_iterations": getattr(shadow, "ai_iterations", 0),
            "ai_tool_calls": getattr(shadow, "ai_tool_calls", []),
            "ai_error": getattr(shadow, "ai_error", None),
            "blocked_by_safety": getattr(shadow, "blocked_by_safety", False),
            "safety_block_reason": getattr(shadow, "safety_block_reason", ""),
            "pre_safety_class": getattr(shadow, "pre_safety_class", ""),
            "verdict_match": getattr(shadow, "verdict_match", None),
            "created_at": shadow.created_at.isoformat(),
            "retriaged_at": _iso(getattr(shadow, "retriaged_at", None)),
            # Human verdict + closure stamps. These decide whether the
            # concurrent-alert gate treats this ticket as still open
            # (l2_resolved_at set, or l1_resolved_at with no l1_handoff_at = closed),
            # so without them a "why did the gate fire?" question is unanswerable
            # from the API alone.
            "l1_triage_class": getattr(shadow, "l1_triage_class", None),
            "l1_analyst_id": getattr(shadow, "l1_analyst_id", None),
            "l1_resolved_at": _iso(getattr(shadow, "l1_resolved_at", None)),
            "l1_handoff_at": _iso(getattr(shadow, "l1_handoff_at", None)),
            "l2_triage_class": getattr(shadow, "l2_triage_class", None),
            "l2_resolved_at": _iso(getattr(shadow, "l2_resolved_at", None)),
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.get("/api/edr-triage/chase-replies")
async def edr_chase_replies(lookback_days: int = 14, apply: bool = False):
    """Chased tickets waiting on a user, and any whose reply is ready to route to L2.

    Read-only by default (`apply=false`): reports what WOULD happen — which tickets have
    an answer waiting and which are stale — without commenting or transitioning anything.
    Pass `apply=true` to actually post the verification packet and route replies to L2.
    """
    from edr_triage.chase_reply_poller import poll_once
    # dry_run=True unless the caller explicitly asks to apply — passed as a real
    # argument (not a config patch) so a read-only call provably cannot mutate a ticket.
    return await poll_once(lookback_days=lookback_days, dry_run=(not apply))


@router.get("/api/edr-triage/blank-retriage")
async def edr_blank_retriage(apply: bool = False):
    """Alerts that arrived with NOTHING bound (no device, no command) and are now past
    the evidence-ingestion window.

    READ-ONLY unless apply=true. Shows exactly what the background sweep would re-triage,
    so the blank-arrival RATE is visible even when the sweep is disabled — that rate is
    the real signal; the sweep only papers over it.
    """
    from edr_triage.blank_retriage import sweep_once, MIN_AGE_MINUTES, MAX_PER_CYCLE
    out = await sweep_once(dry_run=not apply)
    out["min_age_minutes"] = MIN_AGE_MINUTES
    out["max_per_cycle"] = MAX_PER_CYCLE
    return out


@router.get("/api/edr-triage/gate-stats")
async def edr_gate_stats(limit: int = 500):
    """Over-gating visibility: across the recent shadows, how often did the safety
    layer turn the MODEL's intended auto-close into an escalation, and via which gate.

    `automation_lost` = auto-close verdicts the model produced that a gate escalated —
    the cost of the safety layer. A high count for one gate flags it as over-firing.
    """
    from entity_graph.models import ShadowResult
    from collections import Counter
    shadows = await (
        ShadowResult.find().sort(-ShadowResult.created_at).limit(limit).to_list()
    )
    def _bucket(reason: str) -> str:
        r = (reason or "").lower()
        if not r.strip():
            return "(none)"
        if "co-host" in r or "grouped incident" in r:            return "multi-host"
        if "asserts user" in r or "cites command" in r:         return "grounding(deterministic)"
        if "grounding critic" in r:                              return "grounding(LLM)"
        if "no investigation" in r or "zero tool" in r:         return "evidence-floor"
        if "vt " in r or "detections" in r:                     return "vt-detections"
        if "hunt" in r and "error" in r:                        return "hunt-error"
        if "confidence" in r and "requires" in r:               return "confidence-threshold"
        if "critical severity" in r:                            return "critical-severity"
        if "test" in r and "device" in r:                       return "test-device"
        if "critic" in r:                                       return "validation-critic"
        return "other"

    n = len(shadows)
    post = Counter(s.ai_triage_class for s in shadows)
    pre = Counter((getattr(s, "pre_safety_class", "") or s.ai_triage_class) for s in shadows)
    _AC = ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP")
    # A gate escalated an intended auto-close when pre was an auto-close but final is NEEDS_L2.
    escalated = [s for s in shadows
                 if (getattr(s, "pre_safety_class", "") or s.ai_triage_class) in _AC
                 and s.ai_triage_class == "NEEDS_L2"]
    by_gate = Counter(_bucket(getattr(s, "safety_block_reason", "")) for s in escalated)
    pre_ac = sum(pre.get(k, 0) for k in _AC)
    post_ac = sum(post.get(k, 0) for k in _AC)
    return {
        "sample_size": n,
        "verdict_distribution_final": dict(post),
        "auto_close_rate_final": round(post_ac / n, 3) if n else 0,
        "auto_close_rate_model_intended": round(pre_ac / n, 3) if n else 0,
        "automation_lost_to_gates": len(escalated),
        "automation_lost_pct_of_intended_autocloses": round(len(escalated) / pre_ac, 3) if pre_ac else 0,
        "escalations_by_gate": dict(by_gate.most_common()),
        "note": ("pre_safety_class is only populated on shadows written after the "
                 "instrumentation deploy; older rows count as (none)."),
    }


@router.get("/api/edr-triage/bedrock-models")
async def edr_bedrock_models():
    """Diagnostic: list the Bedrock inference profiles + Anthropic foundation
    models actually available to this account/region, so we use the exact
    valid identifier. Logs the list to stdout (Argo CD) and returns JSON.
    """
    import asyncio
    import os

    region = os.getenv("AWS_REGION", "ap-south-1")

    def _run() -> dict:
        import boto3
        from botocore.exceptions import ClientError, BotoCoreError

        out: dict = {"region": region, "inference_profiles": [], "foundation_models": []}
        bc = boto3.client("bedrock", region_name=region)
        # ALL inference profiles (every provider) — this is the authoritative menu
        # of what is invocable in this region via a profile.
        try:
            profs = bc.list_inference_profiles().get("inferenceProfileSummaries", [])
            out["inference_profiles"] = [
                {"id": p.get("inferenceProfileId"),
                 "name": p.get("inferenceProfileName"),
                 "status": p.get("status"),
                 "type": p.get("type")}
                for p in profs
            ]
        except (ClientError, BotoCoreError) as exc:
            out["inference_profiles_error"] = str(exc)
        # ALL foundation models (every provider) with their inference types —
        # inference_types containing ON_DEMAND == in-region on-demand available.
        try:
            fms = bc.list_foundation_models().get("modelSummaries", [])
            out["foundation_models"] = [
                {"id": m.get("modelId"),
                 "provider": m.get("providerName"),
                 "inference_types": m.get("inferenceTypesSupported", [])}
                for m in fms
            ]
        except (ClientError, BotoCoreError) as exc:
            out["foundation_models_error"] = str(exc)
        return out

    result = await asyncio.to_thread(_run)
    logger.info(
        "BEDROCK-MODELS region=%s profiles=%s models=%s",
        result["region"],
        [p["id"] for p in result["inference_profiles"]],
        [m["id"] for m in result["foundation_models"]],
    )
    if result.get("inference_profiles_error"):
        logger.error("BEDROCK-MODELS list_inference_profiles failed: %s", result["inference_profiles_error"])
    if result.get("foundation_models_error"):
        logger.error("BEDROCK-MODELS list_foundation_models failed: %s", result["foundation_models_error"])
    return result


@router.get("/api/edr-triage/sentinel-check")
async def edr_sentinel_check():
    """Diagnose the Log Analytics workspace config for sentinel_run_kql.

    Reports which workspace coords are present (booleans only — never the values),
    whether the query URL resolves, whether a management token acquires, and the
    result of a trivial live query. Answers: are the workspace coords in the pod's
    secret, and can the agent actually run Sentinel KQL?
    """
    import os

    def _present(name: str) -> bool:
        return bool(os.getenv(name))

    out: dict = {
        "env_present": {
            v: {
                "SENTINEL": _present(f"SENTINEL_{v}"),
                "SHADOW_SENTINEL": _present(f"SHADOW_SENTINEL_{v}"),
            }
            for v in ("SUBSCRIPTION_ID", "RESOURCE_GROUP", "WORKSPACE_NAME")
        },
        "mde_creds_present": all(_present(v) for v in ("MDE_TENANT_ID", "MDE_CLIENT_ID", "MDE_CLIENT_SECRET")),
    }

    # Inspect the raw secret (KEY PATHS + has-value booleans + value LENGTH only —
    # never the values themselves). Walks nested structures so we catch coords that
    # are stored under a nested object rather than flat shadow_sentinel_* keys.
    try:
        from lib.secretsmanager import SecretsManager
        secret_name = os.getenv("AWS_SECRET_NAME", "")
        region = os.getenv("AWS_REGION", "ap-south-1")
        secrets = SecretsManager().get_secrets(secret_name, region)
        out["secret_name_read"] = secret_name
        out["secret_top_level_key_count"] = len(secrets) if isinstance(secrets, dict) else None

        _terms = ("sentinel", "workspace", "subscription", "resource_group", "resourcegroup")
        matches: dict = {}

        def _walk(node, path=""):
            if isinstance(node, dict):
                for k, v in node.items():
                    _walk(v, f"{path}.{k}" if path else str(k))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    _walk(v, f"{path}[{i}]")
            else:
                if any(t in path.lower() for t in _terms):
                    sval = "" if node is None else str(node)
                    matches[path] = {"has_value": bool(sval.strip()), "len": len(sval.strip())}

        _walk(secrets)
        out["secret_keys_matching"] = matches or "no sentinel/workspace/subscription keys found at any depth"
    except Exception as exc:
        out["secret_inspect_error"] = str(exc)[:200]
    try:
        from lib.mde_client import _sentinel_query_url, get_management_token, run_sentinel_query
        out["query_url_resolves"] = _sentinel_query_url() is not None
        token = await get_management_token()
        out["management_token_ok"] = bool(token)
        # Trivial live probe — 1 row, cheap. Surfaces auth/permission vs config.
        rows, err = await run_sentinel_query("Netskope_Alerts_CL | take 1")
        out["probe_error"] = err
        out["probe_rows"] = len(rows)
    except Exception as exc:
        out["error"] = str(exc)[:300]
    return out


@router.get("/api/edr-triage/bedrock-check")
async def edr_bedrock_check():
    """Diagnostic: verify the CONFIGURED agent backend can invoke its model.

    Exercises the same code path the agent loop uses (get_backend().chat) with a
    tiny prompt, so it covers whichever backend AGENT_BACKEND selects
    (bedrock / mantle / ollama / gemini). LOGS the outcome to stdout. No triage/Jira.
    """
    import os
    from agent_core.backend import get_backend

    region  = os.getenv("AWS_REGION", "ap-south-1")
    out: dict = {"region": region, "ok": False}

    try:
        backend = get_backend("")
        out["backend"] = type(backend).__name__
        out["model_id"] = getattr(backend, "model_id", "")
        out["api_key_present"] = bool(getattr(backend, "api_key", "") or "")
        content, _tcs = await backend.chat(
            [{"role": "user", "content": "Reply with the single word: OK"}], []
        )
        out["ok"] = True
        out["reply"] = (content or "").strip()[:120]
        logger.info("BEDROCK-CHECK OK backend=%s model=%s reply=%r",
                    out["backend"], out.get("model_id"), out["reply"])
    except Exception as exc:
        out["error_code"] = type(exc).__name__
        out["error"] = str(exc)[:500]
        logger.error("BEDROCK-CHECK FAILED backend=%s model=%s code=%s error=%s",
                     out.get("backend"), out.get("model_id"), out["error_code"], out["error"])
    return out


@router.get("/api/edr-triage/bedrock-usage")
async def edr_bedrock_usage(recent: int = 10):
    """Month-to-date Bedrock token spend + budget status (the $70 guard).

    Returns the running monthly cost, the configured cap, remaining headroom,
    and the most recent per-call usage records.
    """
    import asyncio
    from agent_core import budget

    def _run() -> dict:
        s = budget.summary()
        try:
            docs = list(budget._col().find({"month": s["month"]}).sort("ts", -1).limit(recent))
            s["recent_calls"] = [
                {"ts": d["ts"].isoformat() if d.get("ts") else None,
                 "model_id": d.get("model_id"),
                 "input_tokens": d.get("input_tokens"),
                 "output_tokens": d.get("output_tokens"),
                 "cost_usd": round(d.get("cost_usd", 0.0), 6),
                 "jira_key": d.get("jira_key", "")}
                for d in docs
            ]
        except Exception as exc:
            s["recent_calls_error"] = str(exc)
        return s

    return await asyncio.to_thread(_run)


@router.get("/api/edr-triage/scg-graph")
async def edr_scg_graph(limit: int = 500):
    """Read-only dump of the SCG memory graph — entities + relationships."""
    from entity_graph.models import SCGEntity, SCGRelationship

    ents = await SCGEntity.find_all().sort(-SCGEntity.alert_count).limit(limit).to_list()
    rels = await SCGRelationship.find_all().sort(-SCGRelationship.occurrence_count).limit(limit).to_list()

    by_type: dict = {}
    for e in ents:
        by_type[str(e.entity_type)] = by_type.get(str(e.entity_type), 0) + 1

    return {
        "entity_total": await SCGEntity.count(),
        "relationship_total": await SCGRelationship.count(),
        "entities_by_type": by_type,
        "entities": [
            {"id": str(e.id), "type": str(e.entity_type), "value": e.value,
             "risk_score": e.risk_score, "alert_count": e.alert_count,
             "tags": e.tags, "source_systems": e.source_systems,
             "first_seen": e.first_seen.isoformat() if e.first_seen else None,
             "last_seen": e.last_seen.isoformat() if e.last_seen else None}
            for e in ents
        ],
        "relationships": [
            {"from_id": r.from_id, "to_id": r.to_id, "rel_type": r.rel_type,
             "occurrences": r.occurrence_count}
            for r in rels
        ],
    }


@router.get("/api/edr-triage/suggestions")
async def edr_list_suggestions(status: str = "pending", limit: int = 50):
    """List playbook-improvement suggestions (propose-only queue)."""
    from entity_graph.models import PlaybookSuggestion
    query = {} if status == "all" else {"status": status}
    docs = await PlaybookSuggestion.find(query).sort(-PlaybookSuggestion.created_at).limit(limit).to_list()
    return {
        "count": len(docs),
        "suggestions": [
            {
                "id": str(d.id),
                "alert_type": d.alert_type,
                "alert_name": d.alert_name,
                "suggestion_type": d.suggestion_type,
                "target_playbook": d.target_playbook,
                "title": d.title,
                "divergence_summary": d.divergence_summary,
                "rationale": d.rationale,
                "proposed_change": d.proposed_change,
                "evidence_jira_keys": d.evidence_jira_keys,
                "mismatch_count": d.mismatch_count,
                "status": d.status,
                "created_at": d.created_at.isoformat(),
                "reviewed_by": d.reviewed_by,
                "reviewed_at": d.reviewed_at.isoformat() if d.reviewed_at else None,
            }
            for d in docs
        ],
    }


@router.post("/api/edr-triage/suggestions/analyze", status_code=202)
async def edr_analyze_suggestions(background_tasks: BackgroundTasks, lookback_days: int = 14, min_mismatches: int = 3):
    """Trigger divergence analysis — queues suggestions where AI vs L1/L2 disagree. Non-blocking."""
    from edr_triage.playbook_suggester import analyze_divergences
    background_tasks.add_task(analyze_divergences, lookback_days, min_mismatches)
    return {"ok": True, "status": "analyzing", "lookback_days": lookback_days, "min_mismatches": min_mismatches}


async def _set_suggestion_status(suggestion_id: str, status: str, reviewed_by: str = "l2_analyst"):
    import datetime as _dt
    from entity_graph.models import PlaybookSuggestion
    sugg = await PlaybookSuggestion.get(suggestion_id)
    if not sugg:
        raise HTTPException(404, "Suggestion not found")
    sugg.status = status
    sugg.reviewed_by = reviewed_by
    sugg.reviewed_at = _dt.datetime.utcnow()
    await sugg.save()
    return {"ok": True, "id": suggestion_id, "status": status}


@router.post("/api/edr-triage/suggestions/{suggestion_id}/approve")
async def edr_approve_suggestion(suggestion_id: str):
    """Approve a suggestion (marks it for a human to implement — does NOT auto-edit code)."""
    return await _set_suggestion_status(suggestion_id, "approved")


@router.post("/api/edr-triage/suggestions/{suggestion_id}/dismiss")
async def edr_dismiss_suggestion(suggestion_id: str):
    """Dismiss a suggestion."""
    return await _set_suggestion_status(suggestion_id, "dismissed")


@router.get("/api/edr-triage/run-ticket-status")
async def edr_run_ticket_status():
    """Poll for run-ticket result + the ShadowResult the run produced.

    `running` stays True until the whole pipeline (agent + playbook + save) returns,
    so `running == False` is the reliable "this run is done" signal — poll THAT, not
    the shadow's created_at (which changes mid-pipeline). The shadow is fetched newest
    -first so reruns never surface a stale duplicate row.
    """
    state = dict(_ticket_run_state)
    jira_key = state.get("jira_key")
    if not state["running"] and jira_key:
        try:
            from entity_graph.models import ShadowResult
            shadow = await (
                ShadowResult.find(ShadowResult.jira_key == jira_key)
                .sort(-ShadowResult.created_at)
                .first_or_none()
            )
            state["shadow_result"] = {
                "found": bool(shadow),
                "ai_triage_class": shadow.ai_triage_class if shadow else None,
                "ai_confidence": shadow.ai_confidence if shadow else None,
                "phase": shadow.phase if shadow else None,
                "ai_iterations": getattr(shadow, "ai_iterations", 0) if shadow else None,
                "ai_tool_calls": len(getattr(shadow, "ai_tool_calls", []) or []) if shadow else None,
                "ai_error": getattr(shadow, "ai_error", None) if shadow else None,
                "created_at": shadow.created_at.isoformat() if shadow and shadow.created_at else None,
                "ai_reasoning": shadow.ai_reasoning[:300] if shadow and shadow.ai_reasoning else None,
            }
        except Exception as exc:
            state["shadow_result"] = {"error": str(exc)}
    return state


async def _run_ticket_bg(jira_key: str, force_agent: bool = False) -> None:
    try:
        import httpx
        from edr_triage.config import get_edr_config
        from edr_triage.jira_poller import (
            parse_mde_alert_id, parse_description_fields,
            parse_sentinel_incident_url, parse_sentinel_alert_id, _adf_to_text,
        )
        from edr_triage.pipeline import _process_ticket
        from lib.mde_client import get_access_token

        cfg = get_edr_config()

        # Fetch ticket from Jira
        async with httpx.AsyncClient(
            base_url=cfg.jira_url.rstrip("/"),
            auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
            headers={"Accept": "application/json"},
            timeout=20.0,
            verify=cfg.jira_verify_ssl,
        ) as client:
            resp = await client.get(
                f"/rest/api/3/issue/{jira_key}",
                params={"fields": "summary,description,created,priority,labels,comment"},
            )
            resp.raise_for_status()
            issue = resp.json()

        fields = issue.get("fields", {})
        desc_raw = fields.get("description") or {}
        description = _adf_to_text(desc_raw) if isinstance(desc_raw, dict) else str(desc_raw or "")

        # Analyst notes ALREADY on the ticket — a re-triage is exactly when these
        # exist and matter (an analyst's full policy-change breakdown was never seen
        # by the agent because only `description` was ever fetched).
        from edr_triage.jira_closure_poller import _extract_all_comments
        existing_comments, _, _ = _extract_all_comments(fields, bot_email=cfg.jira_email or "")

        alert_id = parse_mde_alert_id(description)
        parsed = parse_description_fields(description)
        sentinel_url = parse_sentinel_incident_url(description)
        alert_name = parsed.get("alert_name", fields.get("summary", ""))

        if alert_id:
            ticket = {
                "jira_key":    jira_key,
                "alert_id":    alert_id,
                "alert_name":  alert_name,
                "description": description,
                "created_at":  fields.get("created", ""),
                "severity":    (fields.get("priority") or {}).get("name", ""),
                "tactics":     parsed.get("tactics", ""),
                "device_name": parsed.get("device", ""),
                "user_name":   parsed.get("user", ""),
                "incident_url": parsed.get("incident_url", ""),
                "is_sentinel": False,
                "observe_only": False,
                "existing_comments": existing_comments,
            }
        elif sentinel_url:
            ticket = {
                "jira_key":    jira_key,
                "alert_id":    jira_key,
                "alert_name":  alert_name,
                "description": description,
                "created_at":  fields.get("created", ""),
                "severity":    (fields.get("priority") or {}).get("name", ""),
                "tactics":     parsed.get("tactics", ""),
                "device_name": parsed.get("device", ""),
                "user_name":   parsed.get("user", ""),
                "incident_url": sentinel_url,
                "sentinel_alert_id": parse_sentinel_alert_id(description) or "",
                "is_sentinel": True,
                "observe_only": False,
                "existing_comments": existing_comments,
            }
        else:
            import datetime as _dt
            _ticket_run_state.update(
                running=False,
                error=f"{jira_key} is not an MDE or Sentinel ticket — no alert ID found in description",
                finished_at=_dt.datetime.utcnow().isoformat(),
            )
            return

        # Run with dry_run=True so no Jira comments or transitions fire
        dry_cfg = cfg.model_copy(update={"dry_run": True})

        # Fetch the MDE token for BOTH MDE and Sentinel tickets. A Sentinel-sourced alert
        # on a Defender-onboarded host still needs it for machineId resolution AND the
        # fleet-wide process-telemetry enrichment (mde_process_details). Gating on
        # `not is_sentinel` silently passed token=None for Sentinel tickets, which disabled
        # both — so a "rare process as a service" re-run never got its vendor evidence and
        # escalated on "no hashes" (DEMO-106608). The normal poller fetches the token for
        # every ticket; this makes run-ticket re-runs match that behaviour.
        token = None
        try:
            token = await get_access_token()
        except Exception as exc:
            logger.warning("MDE token fetch failed for %s — proceeding without: %s", jira_key, exc)

        result = await _process_ticket(ticket, token=token, cfg=dry_cfg, force_agent=force_agent)
        import datetime as _dt
        _ticket_run_state.update(
            running=False, result=str(result), finished_at=_dt.datetime.utcnow().isoformat(),
        )
    except Exception as exc:
        logger.exception("run-ticket pipeline failed for %s", jira_key)
        import datetime as _dt
        _ticket_run_state.update(
            running=False, error=str(exc), finished_at=_dt.datetime.utcnow().isoformat(),
        )


@router.post("/api/edr-triage/test", status_code=202)
async def edr_triage_test(background_tasks: BackgroundTasks):
    """Start the AI triage test suite as a background task (avoids LB timeout)."""
    if _test_state["running"]:
        return {"status": "already_running"}
    background_tasks.add_task(_test_bg)
    return {"status": "started"}


@router.get("/api/edr-triage/test-status")
async def edr_triage_test_status():
    """Poll for test results. Falls back to MongoDB if request lands on a different pod."""
    state = dict(_test_state)
    if not state.get("running") and state.get("results") is None:
        try:
            import asyncio
            from lib.mongo import get_col
            doc = await asyncio.to_thread(
                lambda: get_col("edr_triage_test_results").find_one({"_id": "latest"})
            )
            if doc:
                state["results"]  = doc.get("results")
                state["saved_at"] = doc.get("saved_at")
        except Exception:
            pass
    return state


async def _test_bg() -> None:
    import time as _t
    from edr_triage.triage_test import run_suite
    started = _t.time()
    _test_state.update(running=True, results=None, started_at=started, finished_at=None)
    try:
        results = await run_suite()
        results["duration_s"] = round(_t.time() - started, 2)
        _test_state.update(running=False, results=results, finished_at=_t.time())
        _save_test_results(results)
    except Exception as exc:
        r = {"error": str(exc), "passed": 0, "failed": 0, "total": 0, "checks": []}
        _test_state.update(running=False, finished_at=_t.time(), results=r)
        _save_test_results(r)


def _save_test_results(results: dict) -> None:
    """Persist test results to MongoDB so any pod replica can serve /test-status."""
    try:
        from lib.mongo import get_col
        import time as _t
        col = get_col("edr_triage_test_results")
        col.replace_one(
            {"_id": "latest"},
            {"_id": "latest", "results": results, "saved_at": _t.time()},
            upsert=True,
        )
        logger.info("[TEST] Results saved to MongoDB: passed=%s/%s", results.get("passed"), results.get("total"))
    except Exception as exc:
        logger.warning("Failed to save test results to MongoDB: %s", exc)


async def _run_bg() -> None:
    import time as _t
    from edr_triage.pipeline import run_once
    _run_state.update(running=True, started_at=_t.time(), error=None)
    try:
        alerts = await run_once()
        _run_state.update(running=False, finished_at=_t.time(), processed=len(alerts))
    except Exception as exc:
        _run_state.update(running=False, finished_at=_t.time(), error=str(exc))
        logger.error("EDR triage manual run error: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# Observatory API
# ---------------------------------------------------------------------------

@router.get("/api/edr-triage/observations")
async def edr_observations(
    limit: int = 100,
    offset: int = 0,
    source: str = "",
    reviewed: str = "",
):
    import asyncio
    from edr_triage.observations import get_observations
    return await asyncio.to_thread(get_observations, limit, offset, source, reviewed)


@router.get("/api/edr-triage/observations/stats")
async def edr_observation_stats():
    import asyncio
    from edr_triage.observations import get_observation_stats
    return await asyncio.to_thread(get_observation_stats)


@router.post("/api/edr-triage/observations/review")
async def edr_review_observation(payload: dict = Body(...)):
    import asyncio
    from edr_triage.observations import mark_reviewed
    key    = payload.get("alert_name_key", "")
    action = payload.get("review_action", "")
    note   = payload.get("review_note", "")
    if not key or not action:
        raise HTTPException(400, "alert_name_key and review_action required")
    ok = await asyncio.to_thread(mark_reviewed, key, action, note)
    return {"ok": ok}


# ---------------------------------------------------------------------------
# Rules API
# ---------------------------------------------------------------------------

@router.get("/api/edr-triage/rules")
async def edr_rules():
    import asyncio
    from edr_triage.rules import get_rules
    return {"rules": await asyncio.to_thread(get_rules)}


@router.post("/api/edr-triage/rules", status_code=201)
async def edr_create_rule(payload: dict = Body(...)):
    import asyncio
    from edr_triage.rules import create_rule
    try:
        rule = await asyncio.to_thread(
            create_rule,
            payload.get("pattern", ""),
            payload.get("playbook", "generic"),
            payload.get("match_type", "contains"),
            payload.get("example_alert", ""),
            payload.get("note", ""),
        )
    except (ValueError, Exception) as exc:
        raise HTTPException(400, str(exc))
    if not rule:
        raise HTTPException(500, "Failed to create rule")
    return rule


@router.delete("/api/edr-triage/alerts")
async def edr_clear_alerts():
    import asyncio
    from edr_triage.store import clear_all_alerts
    deleted = await asyncio.to_thread(clear_all_alerts)
    return {"ok": True, "deleted": deleted}


@router.delete("/api/edr-triage/rules/{rule_id}")
async def edr_delete_rule(rule_id: str):
    import asyncio
    from edr_triage.rules import delete_rule
    ok = await asyncio.to_thread(delete_rule, rule_id)
    if not ok:
        raise HTTPException(404, "Rule not found")
    return {"ok": True}


@router.get("/api/edr-triage/settings")
async def edr_settings():
    """Read-only effective pipeline configuration (from env) + Bedrock budget.

    Surfaced in the Settings page. These are environment-managed; the UI shows
    them but does not write them (they take effect via deployment config).
    """
    import asyncio
    from edr_triage.pipeline import _resolve_agent_phase

    def _budget() -> dict:
        try:
            from agent_core import budget
            return budget.summary()
        except Exception:
            return {}

    b = await asyncio.to_thread(_budget)
    return {
        "use_agent_loop": os.getenv("USE_AGENT_LOOP", "true").lower() == "true",
        "agent_backend":  os.getenv("AGENT_BACKEND", "bedrock").lower(),
        # Normalized, not raw — so the legacy "live" value and any typo report as
        # the phase the pipeline will actually run (typo → shadow).
        "agent_phase":    _resolve_agent_phase(),
        "poll_interval":  int(os.getenv("EDR_POLL_INTERVAL", "300")),
        "dry_run":        os.getenv("EDR_DRY_RUN", "false").lower() == "true",
        "aws_region":     os.getenv("AWS_REGION", "ap-south-1"),
        "agent_model":    os.getenv("AGENT_MODEL", "mistral.mistral-large-3-675b-instruct"),
        "jira_project":   os.getenv("JIRA_PROJECT_KEY", "SIM"),
        "jira_email":     os.getenv("JIRA_EMAIL", ""),
        "llm_url":        os.getenv("LOCAL_LLM_URL") or os.getenv("OLLAMA_URL", ""),
        "budget_usd":         b.get("budget_usd"),
        "month_to_date_usd":  b.get("month_to_date_usd", 0.0),
    }


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------

@router.get("/edr-triage", response_class=HTMLResponse, include_in_schema=False)
async def edr_triage_page():
    return HTMLResponse(_render_page())


@router.get("/edr-triage/investigation/{alert_id:path}", response_class=HTMLResponse, include_in_schema=False)
async def edr_investigation_page(alert_id: str):
    """Full-page investigation record for a single alert (opened from the console drawer)."""
    import json as _json
    return HTMLResponse(_INVESTIGATION_TPL.replace("__ALERT_ID__", _json.dumps(alert_id)))


@router.get("/settings", response_class=HTMLResponse, include_in_schema=False)
async def edr_settings_page():
    return HTMLResponse(_render_settings_page())


def _render_page() -> str:
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>RAPTOR — Triage Console</title>
<style>
  :root {
    --ground: #080A0E;
    --surface: #12151B;
    --surface-2: #181C24;
    --surface-3: #1E2430;
    --line: #252B36;
    --line-soft: #1A1F28;
    --text: #DDE1E8;
    --text-bright: #F3F6FB;
    --text-dim: #8E96A4;
    --text-faint: #59616E;
    --accent: #9E86F0;
    --accent-deep: #5B3FB0;
    --accent-glow: rgba(158,134,240,0.12);
    --crit: #F05552;
    --high: #E8913A;
    --med: #E6C34C;
    --low: #6C93C0;
    --good: #46B87A;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, system-ui, sans-serif;
    --font-mono: "SF Mono", ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
    --r: 6px;
  }

  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body {
    background: var(--ground);
    color: var(--text);
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }
  /* faint radar grid over the ground */
  body::before {
    content: "";
    position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image:
      linear-gradient(var(--line-soft) 1px, transparent 1px),
      linear-gradient(90deg, var(--line-soft) 1px, transparent 1px);
    background-size: 48px 48px;
    opacity: 0.35;
    mask-image: radial-gradient(ellipse 90% 70% at 70% 0%, #000 30%, transparent 75%);
  }

  .num { font-variant-numeric: tabular-nums; font-family: var(--font-mono); }
  .mono { font-family: var(--font-mono); }
  .eyebrow {
    font-family: var(--font-sans);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-faint);
  }

  a { color: inherit; text-decoration: none; }
  button { font-family: inherit; cursor: pointer; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 3px; }

  /* ---------- shell ---------- */
  .app {
    position: relative; z-index: 1;
    display: grid;
    grid-template-columns: 66px 1fr;
    height: 100vh;
  }

  /* ---------- rail ---------- */
  .rail {
    position: sticky; top: 0; height: 100vh; z-index: 30;
    display: flex; flex-direction: column; align-items: center;
    gap: 6px; padding: 16px 0;
    background: linear-gradient(180deg, #0C1116, #090C10);
    border-right: 1px solid var(--line);
  }
  .glyph { width: 38px; height: 38px; border-radius: 11px; display: grid; place-items: center; margin-bottom: 14px; background: linear-gradient(160deg, var(--surface-3), var(--surface)); border: 1px solid var(--line); }
  .glyph svg { width: 20px; height: 20px; }
  .navbtn { width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; color: var(--text-faint); cursor: pointer; position: relative; transition: .16s; border: 1px solid transparent; background: transparent; -webkit-appearance: none; appearance: none; }
  .navbtn svg { width: 19px; height: 19px; }
  .navbtn:hover { color: var(--text-dim); background: var(--surface-2); }
  .navbtn.active { color: var(--accent); background: var(--accent-glow); border-color: var(--accent-deep); }
  .navbtn.active::before { content: ""; position: absolute; left: -16px; top: 9px; bottom: 9px; width: 3px; border-radius: 3px; background: var(--accent); }
  .rail .spacer { flex: 1; }
  .tip { position: absolute; left: 52px; white-space: nowrap; background: var(--surface-3); border: 1px solid var(--line); color: var(--text); font-size: 12px; padding: 5px 9px; border-radius: 8px; opacity: 0; pointer-events: none; transform: translateX(-4px); transition: .14s; z-index: 40; }
  .navbtn:hover .tip { opacity: 1; transform: translateX(0); }
  .brand-mark {
    width: 34px; height: 34px; margin-bottom: 16px;
    color: var(--accent);
    filter: drop-shadow(0 0 8px var(--accent-glow));
  }
  .rail-btn {
    position: relative;
    width: 42px; height: 40px;
    display: flex; align-items: center; justify-content: center;
    color: var(--text-faint);
    background: transparent; border: 0; border-radius: var(--r);
    transition: color .15s, background .15s;
  }
  .rail-btn:hover { color: var(--text-dim); background: var(--surface-2); }
  .rail-btn.active { color: var(--accent); background: var(--accent-glow); }
  .rail-btn.active::before {
    content: ""; position: absolute; left: -14px; top: 8px; bottom: 8px;
    width: 3px; border-radius: 3px; background: var(--accent);
    box-shadow: 0 0 10px var(--accent);
  }
  .rail-btn svg { width: 19px; height: 19px; }
  .rail-spacer { flex: 1; }
  .rail-tip {
    position: absolute; left: 52px; white-space: nowrap;
    background: var(--surface-3); border: 1px solid var(--line);
    color: var(--text); font-size: 11px; padding: 3px 8px; border-radius: 4px;
    opacity: 0; transform: translateX(-4px); pointer-events: none; transition: .12s;
    font-family: var(--font-mono); letter-spacing: .02em; z-index: 20;
  }
  .rail-btn:hover .rail-tip { opacity: 1; transform: translateX(0); }

  /* ---------- main ---------- */
  .main { display: grid; grid-template-rows: auto 1fr; min-width: 0; }

  .topbar {
    display: flex; align-items: center; gap: 20px;
    padding: 0 20px; height: 54px;
    border-bottom: 1px solid var(--line);
    background: rgba(12,17,22,0.7); backdrop-filter: blur(6px);
  }
  .title-block { display: flex; flex-direction: column; gap: 1px; }
  .title-block h1 {
    margin: 0; font-size: 15px; font-weight: 650; letter-spacing: 0.02em;
    display: flex; align-items: center; gap: 9px;
  }
  .title-block .wm { font-family: var(--font-mono); letter-spacing: 0.16em; }
  .title-block .wm b { color: var(--accent); font-weight: 650; }

  .topbar-spacer { flex: 1; }

  .boundary-status {
    display: flex; align-items: center; gap: 14px;
    padding: 6px 12px; border: 1px solid var(--line);
    border-radius: var(--r); background: var(--surface);
  }
  .zone { display: flex; align-items: center; gap: 7px; }
  .zone .eyebrow { color: var(--text-dim); }
  .dot { width: 8px; height: 8px; border-radius: 50%; position: relative; }
  .dot.on { background: var(--good); box-shadow: 0 0 0 3px rgba(70,184,122,0.16); }
  .dot.cloud { background: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  .dot.live::after {
    content: ""; position: absolute; inset: -3px; border-radius: 50%;
    border: 1px solid currentColor; animation: ping 2.4s ease-out infinite;
  }
  .zone.on-prem .dot.live::after { color: var(--good); }
  .zone.cloud .dot.live::after { color: var(--accent); }
  @keyframes ping { 0% { transform: scale(1); opacity: .7; } 100% { transform: scale(2.4); opacity: 0; } }
  .zone-sep { width: 1px; height: 22px; background: var(--line); }

  .meter-group { display: flex; align-items: center; gap: 16px; }
  .meter { display: flex; flex-direction: column; gap: 4px; min-width: 142px; }
  .meter-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
  .meter-head .val { font-family: var(--font-sans); font-size: 12px; font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }
  .meter-track { height: 4px; border-radius: 2px; background: var(--surface-3); overflow: hidden; }
  .meter-fill { height: 100%; border-radius: 2px; width: 0; transition: width 1.1s cubic-bezier(.2,.7,.2,1); }

  .phase-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.08em;
    color: var(--accent); background: var(--accent-glow);
    border: 1px solid var(--accent-deep); border-radius: 20px; padding: 4px 11px;
  }

  /* ---------- content ---------- */
  .content { overflow: auto; padding: 18px 20px 40px; }

  /* KPI strip */
  .kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin-bottom: 18px; }
  .kpi {
    position: relative; overflow: hidden;
    background: linear-gradient(180deg, var(--surface-2), var(--surface));
    border: 1px solid var(--line); border-radius: var(--r);
    padding: 13px 15px; display: flex; flex-direction: column; gap: 7px;
    box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset, 0 10px 26px -18px rgba(0,0,0,0.85);
    transition: transform .16s, border-color .16s;
  }
  .kpi::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--kpi-accent, var(--line-2)); }
  .kpi:hover { transform: translateY(-2px); border-color: var(--line-2); }
  .kpi .eyebrow { color: var(--text-faint); }
  .kpi .figure { font-family: var(--font-sans); font-size: 28px; font-weight: 700; letter-spacing: -0.025em; line-height: 1; color: var(--text-bright); font-variant-numeric: tabular-nums; }
  .kpi .sub { font-family: var(--font-sans); font-size: 11.5px; color: var(--text-dim); }
  .kpi .sub b { color: var(--good); font-weight: 600; }
  .kpi.attn .figure { color: var(--high); }
  .kpi.crit .figure { color: var(--crit); }
  .kpi .spark { height: 22px; margin-top: 2px; }

  /* work area */
  .work { display: block; }
  @media (max-width: 1180px) { .work { grid-template-columns: 1fr; } }

  .panel { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; box-shadow: 0 14px 38px -24px rgba(0,0,0,0.9); }
  .panel-head {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 14px; border-bottom: 1px solid var(--line);
  }
  .panel-head h2 { margin: 0; font-size: 12px; font-weight: 600; letter-spacing: 0.02em; }
  .panel-head .count {
    font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);
    background: var(--surface-3); border-radius: 20px; padding: 2px 9px;
  }
  .panel-head .spacer { flex: 1; }
  .ph-btn {
    font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.04em;
    color: var(--text-dim); background: var(--surface-2);
    border: 1px solid var(--line); border-radius: 5px; padding: 4px 9px;
    display: inline-flex; align-items: center; gap: 5px; transition: .15s;
  }
  .ph-btn:hover { color: var(--text); border-color: var(--accent-deep); }
  .ph-btn svg { width: 13px; height: 13px; }

  /* queue table */
  .q-wrap { overflow-x: auto; }
  table.queue { width: 100%; border-collapse: collapse; }
  table.queue thead th {
    font-family: var(--font-sans); font-size: 10px; letter-spacing: 0.05em; text-transform: uppercase;
    color: var(--text-faint); font-weight: 600; text-align: left;
    padding: 9px 10px; border-bottom: 1px solid var(--line); white-space: nowrap;
  }
  table.queue tbody td { padding: 10px 10px; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }
  table.queue tbody td:first-child { box-shadow: inset 3px 0 0 var(--sevcol, transparent); }
  .c-dev, .c-usr { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); max-width: 168px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .c-usr { color: var(--text-faint); }
  table.queue tbody tr { cursor: pointer; transition: background .12s; position: relative; }
  table.queue tbody tr:hover { background: var(--surface-2); }
  table.queue tbody tr.sel { background: linear-gradient(90deg, var(--accent-glow), transparent 60%); }
  table.queue tbody tr.sel td:first-child { box-shadow: inset 3px 0 0 var(--accent); }

  .tkt { font-family: var(--font-mono); font-size: 11.5px; color: var(--text); } a.tkt { cursor: pointer; } a.tkt:hover { color: var(--accent); text-decoration: underline; } .jl { color: var(--good); text-decoration: none; } .jl:hover { text-decoration: underline; }
  .alert-name { font-size: 13px; color: var(--text-bright); font-weight: 500; }
  .alert-name .whom { font-family: var(--font-mono); font-size: 10.5px; color: var(--text-faint); display: block; margin-top: 2px; }

  .sev { display: inline-flex; align-items: center; gap: 7px; font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.05em; }
  .sev::before { content: ""; width: 3px; height: 13px; border-radius: 2px; background: currentColor; }
  .sev.crit { color: var(--crit); } .sev.high { color: var(--high); }
  .sev.med { color: var(--med); } .sev.low { color: var(--low); } .sev.info { color: var(--text-faint); }

  .verdict {
    font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.03em;
    padding: 3px 8px; border-radius: 4px; border: 1px solid; white-space: nowrap;
  }
  .verdict.fp { color: var(--good); border-color: rgba(70,184,122,0.4); background: rgba(70,184,122,0.08); }
  .verdict.tp { color: var(--high); border-color: rgba(232,145,58,0.4); background: rgba(232,145,58,0.08); }
  .verdict.l2 { color: var(--low); border-color: rgba(108,147,192,0.4); background: rgba(108,147,192,0.08); }
  .verdict.urgent { color: #fff; border-color: var(--crit); background: var(--crit); font-weight: 600; }

  /* Shown only when a re-triage moved the agent's verdict away from the one the
     playbook acted on. The row keeps the acted-on class (that is what the verdict
     filter and the Jira labels agree with); this says where the agent stands now. */
  .reclass { display: inline-flex; align-items: center; gap: 4px; margin-left: 6px; font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.03em; color: var(--accent); background: var(--accent-glow); border: 1px solid var(--accent-deep); border-radius: 4px; padding: 2px 6px; white-space: nowrap; cursor: help; }
  .reclass::before { content: "\21BB"; font-size: 10px; }

  .conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }
  .backend {
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.06em; text-transform: uppercase;
    color: var(--text-dim); display: inline-flex; align-items: center; gap: 5px;
  }
  .backend svg { width: 11px; height: 11px; }
  .backend.onprem { color: var(--good); }
  .backend.cloudb { color: var(--accent); }
  .t-ago { font-family: var(--font-mono); font-size: 11px; color: var(--text-faint); text-align: right; }

  /* ---------- detail panel ---------- */
  .detail .panel-head .tkt-lg { font-family: var(--font-mono); font-size: 13px; color: var(--accent); }
  .detail-body { padding: 14px; display: flex; flex-direction: column; gap: 16px; }

  .d-headline { display: flex; flex-direction: column; gap: 8px; }
  .d-headline .name { font-size: 15px; font-weight: 600; letter-spacing: 0.01em; }
  .d-meta { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip {
    font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.04em;
    color: var(--text-dim); border: 1px solid var(--line); border-radius: 4px; padding: 2px 7px;
  }
  .chip.mitre { color: var(--text); border-color: var(--accent-deep); }

  .section-label { display: flex; align-items: center; gap: 8px; margin-bottom: 9px; }
  .section-label .eyebrow { color: var(--text-dim); }
  .section-label .rule { flex: 1; height: 1px; background: var(--line); }

  /* boundary visualization */
  .boundary {
    border: 1px solid var(--line); border-radius: 7px; overflow: hidden;
    background: var(--surface-2);
  }
  .boundary-grid { display: grid; grid-template-columns: 1fr 30px 1fr; }
  .bzone { padding: 11px 12px; }
  .bzone.regulated { background: rgba(70,184,122,0.045); }
  .bzone.cloudzone { background: rgba(158,134,240,0.04); }
  .bzone .bz-head {
    display: flex; align-items: center; gap: 6px; margin-bottom: 9px;
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.08em; text-transform: uppercase;
  }
  .bzone.regulated .bz-head { color: var(--good); }
  .bzone.cloudzone .bz-head { color: var(--accent); }
  .bzone .bz-head svg { width: 12px; height: 12px; }
  .bz-row { font-family: var(--font-mono); font-size: 10.5px; line-height: 1.9; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bz-row .k { color: var(--text-faint); }
  .bz-row .real { color: var(--text); }
  .bz-row .tok { color: var(--accent); }
  .bz-row .red { color: var(--high); }
  .bz-row .kept { color: var(--good); }
  .b-divider { position: relative; }
  .b-divider::before {
    content: ""; position: absolute; left: 50%; top: 6px; bottom: 6px; width: 0;
    border-left: 1px dashed var(--accent-deep); transform: translateX(-50%);
  }
  .b-divider .arrow {
    position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%);
    color: var(--accent); width: 16px; height: 16px;
  }
  .b-caption {
    padding: 7px 12px; border-top: 1px solid var(--line);
    font-family: var(--font-mono); font-size: 10px; color: var(--text-faint); letter-spacing: 0.02em;
  }
  .b-caption b { color: var(--good); font-weight: 500; }

  /* agent trace */
  .trace { display: flex; flex-direction: column; gap: 0; }
  .trace-step { display: grid; grid-template-columns: 20px 1fr; gap: 10px; padding: 0 0 14px; position: relative; }
  .trace-step:not(:last-child)::before {
    content: ""; position: absolute; left: 9px; top: 18px; bottom: 0; width: 1px; background: var(--line);
  }
  .trace-node {
    width: 19px; height: 19px; border-radius: 50%; z-index: 1;
    display: flex; align-items: center; justify-content: center;
    background: var(--surface-3); border: 1px solid var(--line);
  }
  .trace-node svg { width: 11px; height: 11px; color: var(--text-dim); }
  .trace-step.think .trace-node { border-color: var(--accent-deep); }
  .trace-step.think .trace-node svg { color: var(--accent); }
  .trace-step.final .trace-node { background: var(--accent); border-color: var(--accent); }
  .trace-step.final .trace-node svg { color: #06110F; }
  .trace-body { min-width: 0; }
  .trace-kind {
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--text-faint); margin-bottom: 3px;
  }
  .trace-step.think .trace-kind { color: var(--accent); }
  .trace-text { font-size: 12px; color: var(--text-dim); }
  .tool-call {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    font-family: var(--font-mono); font-size: 11px;
  }
  .tool-name { color: var(--text); background: var(--surface-3); border: 1px solid var(--line); border-radius: 4px; padding: 2px 7px; }
  .tool-arg { color: var(--text-faint); }
  .tool-res { color: var(--text-dim); }
  .tool-res .ok { color: var(--good); } .tool-res .flag { color: var(--high); }

  .verdict-final {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    padding: 11px 13px; border-radius: 7px;
    background: rgba(70,184,122,0.07); border: 1px solid rgba(70,184,122,0.3);
  }
  .verdict-final .vf-label { font-family: var(--font-mono); font-size: 15px; letter-spacing: 0.04em; color: var(--good); font-weight: 600; }
  .verdict-final .vf-conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }
  .verdict-final .vf-conf b { color: var(--text); }
  .verdict-final .spacer { flex: 1; }
  .vf-actions { display: flex; gap: 7px; }
  .vf-btn { font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.03em; padding: 6px 12px; border-radius: 5px; border: 1px solid var(--line); background: var(--surface-2); color: var(--text-dim); transition: .15s; }
  .vf-btn:hover { color: var(--text); }
  .vf-btn.primary { background: var(--accent); border-color: var(--accent); color: #06110F; font-weight: 600; }
  .vf-btn.primary:hover { filter: brightness(1.08); }
  .vf-advisory { font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text-faint); border: 1px dashed var(--line); border-radius: 4px; padding: 4px 9px; white-space: nowrap; }

  /* SCG memory precedents */
  .mem { display: flex; flex-direction: column; gap: 8px; }
  .mem-row {
    display: grid; grid-template-columns: auto 1fr auto; gap: 11px; align-items: center;
    padding: 9px 11px; border: 1px solid var(--line); border-radius: 6px; background: var(--surface-2);
  }
  .tier { font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; padding: 3px 7px; border-radius: 3px; text-transform: uppercase; }
  .tier.golden { color: var(--med); background: rgba(230,195,76,0.1); border: 1px solid rgba(230,195,76,0.35); }
  .tier.curated { color: var(--accent); background: var(--accent-glow); border: 1px solid var(--accent-deep); }
  .mem-txt { font-size: 12px; color: var(--text-dim); min-width: 0; }
  .mem-txt .m-tkt { font-family: var(--font-mono); font-size: 11px; color: var(--text); }
  .mem-txt .m-note { display: block; font-size: 11px; color: var(--text-faint); margin-top: 2px; }
  .mem-conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); text-align: right; }
  .mem-conf small { display: block; color: var(--text-faint); font-size: 9px; letter-spacing: 0.08em; }

  @media (prefers-reduced-motion: reduce) {
    * { animation: none !important; transition: none !important; }
    .meter-fill { transition: none; }
  }

  /* ---- topbar action buttons ---- */
  .tb-actions { display:flex; align-items:center; gap:7px; }
  .btn { display:inline-flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:11px; letter-spacing:0.03em; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); border-radius:5px; padding:6px 10px; transition:.15s; white-space:nowrap; }
  .btn svg { width:13px; height:13px; }
  .btn:hover { color:var(--text); border-color:var(--accent-deep); }
  .btn.primary { color:#06110F; background:var(--accent); border-color:var(--accent); font-weight:600; }
  .btn.primary:hover { filter:brightness(1.08); }
  .btn.danger { color:var(--crit); border-color:rgba(240,85,82,0.35); background:rgba(240,85,82,0.06); }
  .btn.danger:hover { background:rgba(240,85,82,0.12); }

  /* ---- queue sub-toolbar ---- */
  .subbar { display:flex; align-items:center; gap:9px; padding:9px 12px; border-bottom:1px solid var(--line); flex-wrap:wrap; }
  .seg { display:flex; background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:2px; gap:2px; }
  .seg button { font-family:var(--font-mono); font-size:10.5px; letter-spacing:0.02em; color:var(--text-dim); background:none; border:0; padding:4px 9px; border-radius:3px; transition:.13s; white-space:nowrap; }
  .seg button:hover { color:var(--text); }
  .seg button.on { background:var(--surface-3); color:var(--text); }
  .seg .cnt { color:var(--text-faint); margin-left:4px; }
  .seg button.on .cnt { color:var(--accent); }
  .search { display:flex; align-items:center; gap:7px; background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:5px 9px; min-width:150px; flex:1; }
  .search:focus-within { border-color:var(--accent-deep); }
  .search svg { width:13px; height:13px; color:var(--text-faint); flex:none; }
  .search input { background:none; border:0; outline:none; color:var(--text); font-size:12px; width:100%; font-family:var(--font-sans); }
  .search input::placeholder { color:var(--text-faint); }
  .tgl { display:inline-flex; align-items:center; gap:7px; font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:5px 9px; cursor:pointer; user-select:none; white-space:nowrap; }
  .tgl .sw { width:26px; height:15px; border-radius:20px; background:var(--surface-3); border:1px solid var(--line); position:relative; transition:.15s; flex:none; }
  .tgl .sw::before { content:""; position:absolute; left:2px; top:1.5px; width:10px; height:10px; border-radius:50%; background:var(--text-faint); transition:.15s; }
  .tgl.on { color:var(--text); }
  .tgl.on .sw { background:var(--accent-glow); border-color:var(--accent-deep); }
  .tgl.on .sw::before { transform:translateX(11px); background:var(--accent); }

  /* ---- pager ---- */
  .pager-bar { display:flex; align-items:center; justify-content:space-between; padding:9px 12px; border-top:1px solid var(--line); }
  .pager-bar .pi { font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); }
  .pager { display:flex; gap:6px; }
  .pager button { font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); padding:5px 10px; border-radius:4px; transition:.13s; }
  .pager button:hover:not(:disabled) { color:var(--text); border-color:var(--accent-deep); }
  .pager button:disabled { opacity:.35; }
  .pb { font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); }

  /* ---- detail: verdict / meta / VT / comments / reasoning ---- */
  .verdict-top { display:flex; align-items:center; gap:11px; padding:11px 13px; border-radius:7px; border:1px solid; }
  .verdict-top .vt-dot { width:9px; height:9px; border-radius:50%; flex:none; }
  .verdict-top .vt-name { font-family:var(--font-mono); font-size:14px; font-weight:600; letter-spacing:0.03em; }
  .verdict-top .vt-conf { margin-left:auto; font-family:var(--font-mono); font-size:11px; color:var(--text-dim); }
  .meta-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
  .meta { background:var(--surface-2); border:1px solid var(--line); border-radius:6px; padding:9px 11px; min-width:0; }
  .meta .mk { font-family:var(--font-sans); font-size:9.5px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:var(--text-faint); margin-bottom:4px; }
  .meta .mv { font-family:var(--font-mono); font-size:11.5px; color:var(--text); word-break:break-word; }
  .meta.full { grid-column:1 / -1; }
  .vt-card { display:flex; align-items:center; gap:12px; background:var(--surface-2); border:1px solid var(--line); border-radius:7px; padding:11px 13px; }
  .vt-ring { width:42px; height:42px; border-radius:50%; flex:none; display:grid; place-items:center; }
  .vt-ring b { width:32px; height:32px; border-radius:50%; background:var(--surface); display:grid; place-items:center; font-family:var(--font-mono); font-size:12px; font-weight:600; }
  .vt-info .a { font-size:12.5px; color:var(--text); }
  .vt-info .b { font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); margin-top:2px; }
  .cmd { background:var(--ground); border:1px solid var(--line); border-radius:6px; padding:11px 12px; font-family:var(--font-mono); font-size:11px; color:#b7c6d8; white-space:pre-wrap; word-break:break-word; line-height:1.6; }
  /* Mock Jira panel — the exact comment/transition/labels RAPTOR posts to the ticket */
  .jira-card { border:1px solid var(--line); border-radius:8px; overflow:hidden; background:var(--surface); }
  .jira-head { display:flex; align-items:center; gap:10px; padding:9px 12px; border-bottom:1px solid var(--line); background:var(--surface-2); }
  .jira-key { font-family:var(--font-mono); font-size:12px; font-weight:600; color:var(--accent); }
  .jira-mock { font-family:var(--font-mono); font-size:9px; letter-spacing:0.06em; text-transform:uppercase; color:var(--text-faint); border:1px solid var(--line); border-radius:3px; padding:2px 6px; }
  .jira-head .spacer { flex:1; }
  .jira-trans { font-family:var(--font-mono); font-size:10.5px; padding:3px 9px; border:1px solid; border-radius:20px; white-space:nowrap; }
  .jira-labels { display:flex; flex-wrap:wrap; gap:6px; padding:10px 12px 0; }
  .jira-chip { font-family:var(--font-mono); font-size:10px; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); border-radius:4px; padding:2px 8px; }
  .jira-comment { padding:11px 12px 12px; }
  .jira-comment-head { display:flex; align-items:center; gap:8px; font-size:11px; color:var(--text-dim); margin-bottom:9px; }
  .jira-avatar { width:20px; height:20px; border-radius:50%; background:var(--accent); color:#0b0d11; font-weight:700; font-size:11px; display:flex; align-items:center; justify-content:center; }
  .jira-comment-body { font-size:12.5px; color:var(--text); line-height:1.55; }
  .jira-comment-body .jira-h { font-weight:600; color:var(--text); margin:11px 0 5px; font-size:12.5px; }
  .jira-comment-body .jira-h:first-child { margin-top:0; }
  .jira-comment-body .jira-p { margin:4px 0; color:var(--text-dim); }
  .jira-comment-body .jira-ul { margin:4px 0 4px 2px; padding:0; list-style:none; }
  .jira-comment-body .jira-ul li { position:relative; padding-left:14px; margin:3px 0; color:var(--text-dim); }
  .jira-comment-body .jira-ul li::before { content:"\2022"; position:absolute; left:2px; color:var(--accent); }
  .jira-comment-body .jira-pre { background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:8px 10px; font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); white-space:pre-wrap; margin:8px 0 0; }
  .ai-block { background:var(--accent-glow); border:1px solid var(--accent-deep); border-radius:7px; padding:12px 13px; }
  .ai-block .ah { display:flex; align-items:center; gap:7px; font-family:var(--font-mono); font-size:10px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:var(--accent); margin-bottom:8px; }
  .ai-block .ah svg { width:12px; height:12px; }
  .ai-block pre { margin:0; font-family:var(--font-mono); font-size:11px; line-height:1.65; color:#cdbff5; white-space:pre-wrap; word-break:break-word; }

  /* ---- shared preview head + entities + full-page (consistency with AI Memory) ---- */
  .prev-head { display: flex; align-items: center; gap: 10px; padding: 11px 14px; border-bottom: 1px solid var(--line); }
  .prev-head .pref { font-family: var(--font-mono); font-size: 13px; color: var(--accent); }
  .ents { display: flex; flex-wrap: wrap; gap: 7px; }
  .ent { display: inline-flex; align-items: center; gap: 6px; font-family: var(--font-mono); font-size: 10.5px; color: var(--text-dim); background: var(--surface-2); border: 1px solid var(--line); border-radius: 5px; padding: 4px 8px; }
  .ent svg { width: 11px; height: 11px; color: var(--accent); }
  .fullpage { position: fixed; inset: 0; z-index: 80; background: var(--ground); overflow: auto; display: none; }
  .fullpage.on { display: block; }
  .fp-bar { position: sticky; top: 0; z-index: 2; display: flex; align-items: center; gap: 14px; padding: 0 24px; height: 54px; border-bottom: 1px solid var(--line); background: rgba(11,13,17,0.85); backdrop-filter: blur(6px); }
  .fp-back { display: inline-flex; align-items: center; gap: 7px; font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); cursor: pointer; }
  .fp-back:hover { color: var(--text); }
  .fp-wrap { max-width: 1060px; margin: 0 auto; padding: 26px 24px 60px; }
  .fp-eyebrow { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .fp-title { font-size: 22px; font-weight: 650; letter-spacing: 0.01em; margin: 0 0 6px; }
  .fp-sub { font-family: var(--font-mono); font-size: 11.5px; color: var(--text-dim); }
  .fp-quote { border: 1px solid var(--line); border-left: 3px solid var(--accent); background: var(--surface); border-radius: 0 8px 8px 0; padding: 16px 18px; font-size: 14px; line-height: 1.65; color: var(--text); margin: 20px 0; }
  .fp-timeline { display: flex; align-items: stretch; gap: 0; margin: 18px 0; flex-wrap: wrap; }
  .tl-step { flex: 1; min-width: 150px; border: 1px solid var(--line); background: var(--surface); border-radius: 7px; padding: 12px 14px; position: relative; }
  .tl-step + .tl-step { margin-left: 22px; }
  .tl-step + .tl-step::before { content: "\2192"; position: absolute; left: -18px; top: 50%; transform: translateY(-50%); color: var(--text-faint); font-family: var(--font-mono); }
  .tl-step .ts-k { font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-faint); margin-bottom: 6px; }
  .tl-step .ts-v { font-family: var(--font-mono); font-size: 13px; font-weight: 600; }
  .tl-step .ts-note { font-size: 11px; color: var(--text-dim); margin-top: 4px; }
  .fp-cols { display: grid; grid-template-columns: 1.3fr 1fr; gap: 20px; align-items: start; margin-top: 8px; }
  @media (max-width: 900px) { .fp-cols { grid-template-columns: 1fr; } }
  .fp-actions { display: flex; gap: 9px; margin-top: 24px; flex-wrap: wrap; align-items: center; }
  .fp-sect { margin-top: 22px; }
  .fp-sect > .section-label { margin-bottom: 12px; }
  .trace-cmd { margin: 6px 0 2px 30px; }

  /* ---- investigation drawer (preview, ~560px slide-over) ---- */
  .overlay { position: fixed; inset: 0; background: rgba(4,7,11,0.6); backdrop-filter: blur(3px); opacity: 0; pointer-events: none; transition: .2s; z-index: 70; }
  .overlay.open { opacity: 1; pointer-events: auto; }
  .drawer { position: fixed; top: 0; right: 0; height: 100vh; width: min(560px, 94vw); background: var(--surface); border-left: 1px solid var(--line); transform: translateX(100%); transition: transform .26s cubic-bezier(.4,0,.2,1); z-index: 75; display: flex; flex-direction: column; box-shadow: -30px 0 60px rgba(0,0,0,.5); }
  .drawer.open { transform: translateX(0); }
  .dhead { padding: 15px 18px 13px; border-bottom: 1px solid var(--line); flex: 0 0 auto; }
  .dh-top { display: flex; align-items: center; justify-content: space-between; }
  .dx { cursor: pointer; color: var(--text-faint); font-size: 20px; line-height: 1; padding: 0 4px; }
  .dx:hover { color: var(--text); }
  .dstrip { display: flex; align-items: center; gap: 7px; margin-top: 11px; }
  .dbody { padding: 16px 18px 40px; overflow-y: auto; flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; gap: 15px; }
  .dbody > * { flex-shrink: 0; }
</style>
</head>
<body>
<div class="app">
  <aside class="rail">
    <div class="glyph"><svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 L20 7 L17 14 C15.5 18 12 22 12 22 C12 22 8.5 18 7 14 L4 7 Z"/><path d="M12 8 L12 15 M9 11 L12 8 L15 11"/></svg></div>
    <button class="navbtn active" onclick="location.href='/edr-triage'"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"/></svg><span class="tip">Triage Console</span></button>
    <button class="navbtn" onclick="location.href='/memory/quarantine'"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg><span class="tip">AI Memory</span></button>
    <div class="spacer"></div>
    <button class="navbtn" onclick="location.href='/settings'"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 100-6 3 3 0 000 6z"/><path d="M19 12a7 7 0 00-.1-1l2-1.6-2-3.4-2.4 1a7 7 0 00-1.7-1L14.5 2h-5l-.3 2.9a7 7 0 00-1.7 1l-2.4-1-2 3.4L3.1 11a7 7 0 000 2l-2 1.6 2 3.4 2.4-1a7 7 0 001.7 1L9.5 22h5l.3-2.9a7 7 0 001.7-1l2.4 1 2-3.4-2-1.6a7 7 0 00.1-1z"/></svg><span class="tip">Settings</span></button>
  </aside>
  <div class="main">
    <header class="topbar">
      <div class="title-block"><h1><span class="wm"><b>RAP</b>TOR</span></h1><span class="eyebrow">Reactive Alert Processing &amp; Threat Orchestration</span></div>
      <div class="topbar-spacer"></div>
      <div class="meter" id="spendMeter"><div class="meter-head"><span class="eyebrow">Spend · MTD</span><span class="val" id="spendVal">—</span></div><div class="meter-track"><div class="meter-fill" id="spendFill" style="width:0;background:var(--accent)"></div></div></div>
      <button class="btn" onclick="location.href='/memory/quarantine'" title="Open AI Memory — Security Context Graph"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></svg>AI Memory</button>
      <span class="phase-badge"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/><circle cx="12" cy="12" r="4"/></svg><span id="phaseTxt">PHASE · COPILOT</span></span>
      <div class="tb-actions">
        <button class="btn" onclick="reloadAll()" title="Reload"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></svg>Refresh</button>
        <button class="btn primary" id="runBtn" onclick="runTriage()" title="Run triage now"><svg viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M8 5v14l11-7z"/></svg>Run Triage</button>
        <button class="btn danger" onclick="clearAll()" title="Clear all triaged alerts"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M10 11v6M14 11v6M6 7l1 13h10l1-13"/></svg>Clear</button>
      </div>
    </header>
    <div class="content">
      <section class="kpis" aria-label="Triage summary">
        <div class="kpi" style="--kpi-accent:var(--line-2)"><span class="eyebrow">Total processed</span><span class="figure num">—</span><span class="sub">lifetime</span></div>
        <div class="kpi" style="--kpi-accent:var(--good)"><span class="eyebrow">Auto-closed</span><span class="figure num">—</span><span class="sub"><span id="rateSub">—</span></span></div>
        <div class="kpi attn" style="--kpi-accent:var(--high)"><span class="eyebrow">Needs L2</span><span class="figure num">—</span><span class="sub">awaiting analyst</span></div>
        <div class="kpi crit" style="--kpi-accent:var(--crit)"><span class="eyebrow">Urgent</span><span class="figure num">—</span><span class="sub">escalate now</span></div>
        <div class="kpi" style="--kpi-accent:var(--low)"><span class="eyebrow">Pending</span><span class="figure num">—</span><span class="sub">in triage queue</span></div>
        <div class="kpi" style="--kpi-accent:var(--accent)"><span class="eyebrow">SCG memories</span><span class="figure num">—</span><span class="sub" id="scgSub">curated + golden</span></div>
      </section>
      <section class="panel" aria-label="Triage queue">
        <div class="panel-head"><h2>Triaged Alerts</h2><span class="count" id="q-count">—</span><div class="spacer"></div>
          <button class="ph-btn" onclick="runTriage()" title="Poll Jira for new open tickets and triage them now"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg>Poll now</button></div>
        <div class="subbar">
          <div class="seg" id="seg">
            <button class="on" data-f="">All</button>
            <button data-f="URGENT">Urgent <span class="cnt">0</span></button>
            <button data-f="NEEDS_L2">Needs L2 <span class="cnt">0</span></button>
            <button data-f="AUTO_CLOSED_TP">Closed TP</button>
            <button data-f="AUTO_CLOSED_FP">Closed FP</button>
            <button data-f="PENDING">Pending</button>
          </div>
          <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg><input id="q" placeholder="Search ticket, alert, device, user…"/></div>
          <div class="tgl on" id="obsToggle" title="Hide observe-only / skipped alerts (e.g. Netskope DLP)"><span class="sw"></span>Hide observed</div>
        </div>
        <div class="q-wrap"><table class="queue"><thead><tr><th>Ticket</th><th>Alert</th><th>Device</th><th>User</th><th>Sev</th><th>Verdict</th><th>Conf</th><th>Playbook</th><th style="text-align:right">Age</th></tr></thead><tbody id="q-rows"></tbody></table></div>
        <div class="pager-bar"><span class="pi" id="pageinfo">—</span><div class="pager"><button id="prev" disabled>← Prev</button><button id="next" disabled>Next →</button></div></div>
      </section>
    </div>
  </div>
</div>
<div class="overlay" id="ov" onclick="closeDrawer()"></div>
<aside class="drawer" id="drawer" aria-label="Investigation preview">
  <div class="dhead">
    <div class="dh-top"><span class="eyebrow">Investigation · <span class="mono" id="dId"></span></span><span class="dx" onclick="closeDrawer()">&times;</span></div>
    <div class="dstrip"><span id="dStrip"></span><button class="btn primary" style="margin-left:auto" onclick="openInvestigation()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>Open in new page</button></div>
  </div>
  <div class="dbody" id="dBody"></div>
</aside>
<script>
var JIRA='https://jira.example.com/browse/';
function jiraLink(k){return '<a class="jl" href="https://jira.example.com/browse/'+encodeURIComponent(k)+'" target="_blank" rel="noopener" onclick="event.stopPropagation()">'+esc(k)+' \u2197</a>';}
function metaJira(jk){return '<div class="meta"><div class="mk">Jira ticket</div><div class="mv">'+(jk?jiraLink(jk):'<span style="color:var(--text-faint)">not raised</span>')+'</div></div>';}
var SPARK='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4M12 18v4M2 12h4M18 12h4M5 5l2.5 2.5M16.5 16.5L19 19M19 5l-2.5 2.5M7.5 16.5L5 19"/><circle cx="12" cy="12" r="3.5"/></svg>';
var ACTSVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M20 7 9 18l-5-5"/></svg>';
var THINKSVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10.5c.8.7 1 1 1 2.5h6c0-1.5.2-1.8 1-2.5A6 6 0 0 0 12 3Z"/></svg>';
var VSVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M20 6 9 17l-5-5"/></svg>';

function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function rgba(hex,a){var n=parseInt(hex.slice(1),16);return 'rgba('+((n>>16)&255)+','+((n>>8)&255)+','+(n&255)+','+a+')';}
function relTime(sec){if(!sec)return '—';var d=Date.now()/1000-sec;if(d<60)return 'just now';if(d<3600)return Math.floor(d/60)+'m ago';if(d<86400)return Math.floor(d/3600)+'h ago';return Math.floor(d/86400)+'d ago';}
function pctv(x){return (x==null)?'—':Math.round(x*100)+'%';}

var SEV={High:['high','HIGH'],Medium:['med','MED'],Low:['low','LOW'],Informational:['info','INFO'],Critical:['crit','CRIT']};
var SEVCOL={crit:'var(--crit)',high:'var(--high)',med:'var(--med)',low:'var(--low)',info:'var(--text-faint)'};
var VERD={AUTO_CLOSED_FP:['fp','AUTO_CLOSED_FP'],AUTO_CLOSED_TP:['tp','AUTO_CLOSED_TP'],NEEDS_L2:['l2','NEEDS_L2'],URGENT:['urgent','URGENT'],PENDING:['pend','PENDING'],OBSERVED:['pend','OBSERVED'],SKIPPED:['pend','SKIPPED'],PROCESSING:['pend','PROCESSING']};
var VCOL={AUTO_CLOSED_FP:'#46B87A',AUTO_CLOSED_TP:'#E8913A',NEEDS_L2:'#6C93C0',URGENT:'#F05552',PENDING:'#8E96A4',OBSERVED:'#59616E',SKIPPED:'#59616E',PROCESSING:'#8E96A4'};
function sevInfo(s){return SEV[s]||['info',(s||'—').toString().toUpperCase()];}
function verdInfo(v){return VERD[v]||['l2',v||'PENDING'];}

var filter='',page=0,PS=25,total=0,curRows=[];
var hideObserved=(localStorage.getItem('raptorHideObs')!=='0');
var curAlertId=null;

function setFig(i,v){var els=document.querySelectorAll('.kpis .kpi .figure');if(els[i])els[i].textContent=(+v).toLocaleString();}
function loadStats(){
  fetch('/api/edr-triage/stats').then(function(r){return r.json();}).then(function(d){
    setFig(0,d.total||0);setFig(1,d.auto_closed||0);setFig(2,d.needs_l2||0);setFig(3,d.urgent||0);setFig(4,d.pending||0);
    var rate=d.total?Math.round((d.auto_closed/d.total)*100):0;var rs=document.getElementById('rateSub');if(rs)rs.innerHTML='<b>'+rate+'%</b> auto-resolution';
    var su=document.querySelector('.seg button[data-f="URGENT"] .cnt');if(su)su.textContent=d.urgent||0;
    var sl=document.querySelector('.seg button[data-f="NEEDS_L2"] .cnt');if(sl)sl.textContent=d.needs_l2||0;
  }).catch(function(){});
}
function loadScg(){fetch('/api/memory/pollution').then(function(r){return r.json();}).then(function(d){var bt=(d&&d.by_tier)||{};setFig(5,(bt.golden||0)+(bt.curated||0));var sub=document.getElementById('scgSub');if(sub)sub.textContent=(bt.golden||0)+' golden';}).catch(function(){});}
function loadSpend(){
  fetch('/api/edr-triage/bedrock-usage').then(function(r){return r.json();}).then(function(d){
    var cap=(d.budget_usd!=null)?d.budget_usd:d.budget;var mtd=(d.month_to_date_usd!=null)?d.month_to_date_usd:(d.spent_usd||0);
    var box=document.getElementById('spendMeter');
    if(cap==null){if(box)box.style.display='none';return;}
    var v=document.getElementById('spendVal');if(v)v.innerHTML='$'+(+mtd).toFixed(0)+'<span style="color:var(--text-faint)">/'+(+cap).toFixed(0)+'</span>';
    var pct=cap>0?Math.min(100,(mtd/cap)*100):0;var f=document.getElementById('spendFill');if(f){f.style.width=pct+'%';f.style.background=pct>=100?'var(--crit)':pct>=80?'var(--med)':'var(--accent)';}
  }).catch(function(){});
}
function loadPhase(){fetch('/api/edr-triage/settings').then(function(r){return r.json();}).then(function(d){var p=(d&&(d.agent_phase||d.phase))||'';var el=document.getElementById('phaseTxt');if(el&&p)el.textContent='PHASE · '+String(p).toUpperCase();}).catch(function(){});}

function loadAlerts(){
  var tb=document.getElementById('q-rows');tb.innerHTML='<tr><td colspan="9"><div class="prev-empty" style="padding:36px">Loading…</div></td></tr>';
  var url='/api/edr-triage/alerts?limit='+PS+'&offset='+(page*PS);
  if(filter)url+='&triage_class='+encodeURIComponent(filter);
  if(hideObserved)url+='&hide_observed=true';
  // Search server-side so a ticket key finds its row on ANY page, not just the 25
  // rows already loaded.
  var sq=(document.getElementById('q')||{}).value||'';
  if(sq.trim())url+='&search='+encodeURIComponent(sq.trim());
  fetch(url).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();}).then(function(d){total=d.total||0;curRows=d.alerts||[];renderRows();}).catch(function(e){tb.innerHTML='<tr><td colspan="9"><div class="prev-empty" style="padding:36px;color:var(--crit)">'+esc(String(e))+'</div></td></tr>';});
}
// Filtering is done server-side now (see loadAlerts). It used to happen here over the
// current page only, and jira_key wasn't in the haystack — so searching a ticket key
// showed "No alerts match" even when the ticket was present.

/* A re-triage updates the shadow and nothing else — the ticket keeps the labels the
   playbook wrote. Where the two disagree the queue used to show only the acted-on
   verdict while the trace panel below showed the current one, which read as a bug
   rather than as two true facts about the same alert. */
function reclassChip(a,acted){
  var now=a.agent_triage_class;
  if(!now||!a.agent_retriaged_at||now===acted)return '';
  var c=(a.agent_confidence!=null)?' at '+Math.round(a.agent_confidence*100)+'% confidence':'';
  return '<span class="reclass" title="Re-triaged '+esc(String(a.agent_retriaged_at).replace("T"," ").slice(0,16))
    +' — the agent now says '+esc(now)+c+'. The ticket keeps its original '+esc(acted)+' labels.">'+esc(now)+'</span>';
}

function visibleRows(){return curRows;}
function renderRows(){
  var v=visibleRows();var tb=document.getElementById('q-rows');
  document.getElementById('q-count').textContent=total+' alert'+(total!==1?'s':'');
  if(!v.length){tb.innerHTML='<tr><td colspan="9"><div class="prev-empty" style="padding:36px">No alerts match</div></td></tr>';}
  else{
    tb.innerHTML=v.map(function(a){
      var cls=a.triage_class||'PENDING';var vi=verdInfo(cls);var si=sevInfo(a.severity);
      var conf=(a.ai_confidence!=null?a.ai_confidence:a.confidence);
      var moved=reclassChip(a,cls);
      return '<tr data-id="'+esc(a.alert_id||'')+'" data-sev="'+si[0]+'" style="--sevcol:'+(SEVCOL[si[0]]||'transparent')+'">'
        +'<td>'+(a.jira_key?'<a class="tkt" href="https://jira.example.com/browse/'+encodeURIComponent(a.jira_key)+'" target="_blank" rel="noopener" onclick="event.stopPropagation()">'+esc(a.jira_key)+'</a>':'<span class="tkt">'+esc(a.alert_id||'')+'</span>')+'</td>'
        +'<td><span class="alert-name">'+esc(a.alert_name||'—')+'</span></td>'
        +'<td class="c-dev">'+(a.device_name?esc(a.device_name):'—')+'</td>'
        +'<td class="c-usr">'+(a.user_name?esc(a.user_name):'—')+'</td>'
        +'<td><span class="sev '+si[0]+'">'+esc(si[1])+'</span></td>'
        +'<td><span class="verdict '+vi[0]+'">'+esc(vi[1])+'</span>'+moved+'</td>'
        +'<td><span class="conf">'+pctv(conf)+'</span></td>'
        +'<td><span class="pb">'+esc(a.playbook||'—')+'</span></td>'
        +'<td class="t-ago">'+esc(relTime(a.processed_at))+'</td>'
        +'</tr>';
    }).join('');
  }
  var pages=Math.max(1,Math.ceil(total/PS));var st=total?page*PS+1:0,en=Math.min(page*PS+PS,total);
  document.getElementById('pageinfo').textContent=total?(st+'–'+en+' of '+total):'No results';
  document.getElementById('prev').disabled=page===0;document.getElementById('next').disabled=page>=pages-1;
}

function cell(k,v,color){return '<div class="meta"><div class="mk">'+esc(k)+'</div><div class="mv"'+(color?' style="color:'+color+'"':'')+'>'+esc(v)+'</div></div>';}
function cellFull(k,v,color){return '<div class="meta full"><div class="mk">'+esc(k)+'</div><div class="mv"'+(color?' style="color:'+color+'"':'')+'>'+esc(v)+'</div></div>';}
function aiBlock(title,txt){return '<div class="ai-block"><div class="ah">'+SPARK+esc(title)+'</div><pre>'+esc(txt)+'</pre></div>';}
// Render a subset of Jira wiki markup (h2./h3., * bullets, {noformat}, *bold*) to HTML.
function wikiToHtml(s){
  if(!s)return '';
  function e(t){return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function inl(t){return e(t).replace(/\*([^*]+)\*/g,'<b>$1</b>').replace(/\[([^\|\]]+)\|[^\]]+\]/g,'$1');}
  var lines=String(s).split('\n'),out=[],i=0,inList=false;
  function endList(){if(inList){out.push('</ul>');inList=false;}}
  while(i<lines.length){
    var ln=lines[i];
    if(ln.trim()==='{noformat}'){endList();var code=[];i++;while(i<lines.length&&lines[i].trim()!=='{noformat}'){code.push(lines[i]);i++;}i++;out.push('<pre class="jira-pre">'+e(code.join('\n'))+'</pre>');continue;}
    var hm=ln.match(/^h[1-6]\.\s+(.*)/);
    if(hm){endList();out.push('<div class="jira-h">'+inl(hm[1])+'</div>');i++;continue;}
    if(ln.indexOf('* ')===0){if(!inList){out.push('<ul class="jira-ul">');inList=true;}out.push('<li>'+inl(ln.slice(2))+'</li>');i++;continue;}
    if(!ln.trim()){endList();i++;continue;}
    endList();out.push('<div class="jira-p">'+inl(ln)+'</div>');i++;
  }
  endList();return out.join('');
}
// The mock Jira panel — the exact comment/transition/labels RAPTOR would post
// (dry-run: stored, not sent). Sourced from the same fields written to the ticket.
function jiraPanel(a){
  if(!a.l1_comment)return '';
  var act=a.action_taken||'';
  var tr = act==='resolved' ? {t:'→ Resolve',c:'var(--good)'}
         : act==='event_analysis' ? {t:'→ Event Analysis',c:'var(--med)'}
         : act==='labels_only' ? {t:'labels only',c:'var(--text-dim)'}
         : {t:'advisory · no transition',c:'var(--text-dim)'};
  var chips=(a.labels_applied||[]).map(function(l){return '<span class="jira-chip">'+esc(l)+'</span>';}).join('');
  var h='<div><div class="section-label"><span class="eyebrow">Posted to Jira</span><span class="rule"></span></div>';
  h+='<div class="jira-card"><div class="jira-head"><span class="jira-key">'+esc(a.jira_key||'—')+'</span>'
    +'<span class="jira-mock">mock · dry-run</span><span class="spacer"></span>'
    +'<span class="jira-trans" style="color:'+tr.c+';border-color:'+tr.c+'">'+tr.t+'</span></div>';
  if(chips)h+='<div class="jira-labels">'+chips+'</div>';
  h+='<div class="jira-comment"><div class="jira-comment-head"><span class="jira-avatar">R</span> RAPTOR bot · added a comment</div>'
    +'<div class="jira-comment-body">'+wikiToHtml(a.l1_comment)+'</div></div></div></div>';
  return h;
}

function openDrawer(id){
  if(!id)return;curAlertId=id;
  document.getElementById('dId').textContent=id;
  document.getElementById('dStrip').innerHTML='';
  document.getElementById('dBody').innerHTML='<div class="prev-empty">Loading…</div>';
  document.getElementById('drawer').classList.add('open');document.getElementById('ov').classList.add('open');
  fetch('/api/edr-triage/alerts/'+encodeURIComponent(id)).then(function(r){if(!r.ok)return r.json().then(function(e){throw new Error(e.detail||('HTTP '+r.status));});return r.json();})
    .then(function(a){renderDrawer(a);if(a.jira_key){fetch('/api/edr-triage/shadow/'+encodeURIComponent(a.jira_key)).then(function(r){return r.json();}).then(function(sh){if(sh&&sh.found)renderTrace(sh,a);}).catch(function(){});}})
    .catch(function(e){document.getElementById('dBody').innerHTML='<div class="prev-empty" style="color:var(--crit)">'+esc(String(e.message||e))+'</div>';});
}
function renderDrawer(a){
  var cls=a.triage_class||'PENDING';var vi=verdInfo(cls);var si=sevInfo(a.severity);var vcol=VCOL[cls]||'#8E96A4';
  document.getElementById('dId').textContent=a.jira_key||a.alert_id||'';
  var moved=reclassChip(a,cls);
  document.getElementById('dStrip').innerHTML='<span class="sev '+si[0]+'">'+esc(si[1])+'</span> <span class="verdict '+vi[0]+'">'+esc(vi[1])+'</span>'+moved;
  var conf=(a.ai_confidence!=null?a.ai_confidence:a.confidence);
  var reasoning=a.llm_reasoning||'';
  var at=a.alert_time?String(a.alert_time).replace('T',' ').slice(0,16):relTime(a.processed_at);
  var b='';
  b+='<div class="d-headline"><span class="name">'+esc(a.alert_name||a.alert_id||'Alert')+'</span></div>';
  b+='<div class="verdict-top" style="border-color:'+rgba(vcol,.35)+';background:'+rgba(vcol,.07)+'"><span class="vt-dot" style="background:'+vcol+';box-shadow:0 0 10px '+rgba(vcol,.6)+'"></span><span class="vt-name" style="color:'+vcol+'">'+esc(cls)+'</span>'+(conf!=null?'<span class="vt-conf">confidence '+Math.round(conf*100)+'%</span>':'')+'</div>';
  // Where the two records disagree, say so in words rather than leaving the reader
  // to notice that the panel below contradicts the pill above.
  if(moved){
    b+='<div class="cmd" style="border-color:var(--accent-deep);color:var(--text)">Ticket state is <b>'+esc(cls)
      +'</b> — the labels the playbook wrote to Jira. The agent re-triaged this alert on '
      +esc(String(a.agent_retriaged_at).replace('T',' ').slice(0,16))+' and now says <b>'+esc(a.agent_triage_class)
      +'</b>. The re-run is advisory, so the ticket was not re-labelled.</div>';
  }
  b+='<div class="meta-grid">'
    +cell('Device',a.device_name||'—')
    +cell('User',a.user_name||'—')
    +metaJira(a.jira_key)
    +cell('Alert time',at)
    +(a.action_taken?cell('Action',a.action_taken):'')
    +(a.file_name?cell('File',a.file_name):'')
    +(a.sha256?cellFull('SHA-256',String(a.sha256).slice(0,44)+(String(a.sha256).length>44?'…':'')):'')
    +((a.labels_applied&&a.labels_applied.length)?cellFull('Labels',a.labels_applied.join(' · ')):'')
    +'</div>';
  if(a.is_test_device){b+='<div class="verdict-top" style="border-color:'+rgba('#E6C34C',.35)+';background:'+rgba('#E6C34C',.07)+';padding:10px 13px"><span class="vt-name" style="color:var(--med);font-size:13px">⚠ Known test device</span></div>';}
  if(a.vt_detections!=null&&a.vt_total){var p=Math.round(a.vt_detections/a.vt_total*100);var vok=a.vt_detections===0;var vc=vok?'var(--good)':'var(--crit)';
    b+='<div><div class="section-label"><span class="eyebrow">VirusTotal</span><span class="rule"></span></div><div class="vt-card"><div class="vt-ring" style="background:conic-gradient('+vc+' '+p+'%, var(--line) 0)"><b style="color:'+vc+'">'+a.vt_detections+'</b></div><div class="vt-info"><div class="a">'+a.vt_detections+' / '+a.vt_total+' engines flagged</div><div class="b">verdict: '+esc(a.vt_verdict||'—')+'</div></div></div></div>';}
  b+='<div id="traceSlot"></div>';
  b+=jiraPanel(a);
  if(reasoning){b+=aiBlock('AI reasoning · Mistral Large 3',reasoning);}
  if(a.l2_comment){b+='<div><div class="section-label"><span class="eyebrow">L2 comment / draft</span><span class="rule"></span></div><div class="cmd">'+esc(a.l2_comment)+'</div></div>';}
  document.getElementById('dBody').innerHTML=b;
}
function toolStep(c){
  return '<div class="trace-step"><div class="trace-node">'+ACTSVG+'</div><div class="trace-body"><div class="trace-kind">Act · tool</div>'
    +'<div class="tool-call"><span class="tool-name">'+esc(c.name||'')+'</span> <span class="tool-arg">'+esc(c.args||'')+'</span> <span class="tool-res">→ '+esc(c.result||'')+'</span></div></div></div>';
}
function renderTrace(sh,a){
  var slot=document.getElementById('traceSlot');if(!slot)return;
  var calls=sh.ai_tool_calls||[];if(!calls.length&&!sh.ai_reasoning)return;
  var vi=verdInfo(sh.ai_triage_class||a.triage_class);var vcol=VCOL[sh.ai_triage_class||a.triage_class]||'#46B87A';
  var h='<div><div class="section-label"><span class="eyebrow">Agent investigation'+(sh.ai_iterations?' · '+sh.ai_iterations+' iteration'+(sh.ai_iterations!==1?'s':''):'')+' · Bedrock Mantle</span><span class="rule"></span></div><div class="trace">';
  h+='<div class="trace-step think"><div class="trace-node">'+THINKSVG+'</div><div class="trace-body"><div class="trace-kind">Think</div><div class="trace-text">Investigated with the tools below, then emitted a verdict.</div></div></div>';
  calls.forEach(function(c){h+=toolStep(c);});
  h+='<div class="trace-step final"><div class="trace-node">'+VSVG+'</div><div class="trace-body"><div class="trace-kind" style="color:var(--good)">Verdict</div>'
    +'<div class="verdict-final"><span class="vf-label" style="color:'+vcol+'">'+esc(sh.ai_triage_class||a.triage_class||'')+'</span>'+(sh.ai_confidence!=null?'<span class="vf-conf">conf <b>'+(+sh.ai_confidence).toFixed(2)+'</b></span>':'')+'<span class="spacer"></span><span class="vf-advisory">advisory · L1 retains the decision</span></div></div></div>';
  h+='</div></div>';
  slot.innerHTML=h;
}
function closeDrawer(){document.getElementById('drawer').classList.remove('open');document.getElementById('ov').classList.remove('open');}
function openInvestigation(){if(curAlertId)location.href='/edr-triage/investigation/'+encodeURIComponent(curAlertId);}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeDrawer();});

function runTriage(){
  var b=document.getElementById('runBtn');if(!b||b.disabled)return;var o=b.innerHTML;b.disabled=true;b.style.opacity='.7';
  b.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite;width:13px;height:13px"><path d="M12 3a9 9 0 109 9"/></svg>Triaging…';
  fetch('/api/edr-triage/run',{method:'POST'}).then(function(r){return r.json();}).then(function(){
    var t=setInterval(function(){fetch('/api/edr-triage/run-status').then(function(r){return r.json();}).then(function(s){
      if(!s.running){clearInterval(t);b.disabled=false;b.style.opacity='';b.innerHTML=o;reloadAll();}
    }).catch(function(){clearInterval(t);b.disabled=false;b.style.opacity='';b.innerHTML=o;});},3000);
  }).catch(function(){b.disabled=false;b.style.opacity='';b.innerHTML=o;});
}
function clearAll(){if(!confirm('Delete ALL triaged alerts? This cannot be undone.'))return;fetch('/api/edr-triage/alerts',{method:'DELETE'}).then(function(r){return r.json();}).then(function(){page=0;loadStats();loadAlerts();}).catch(function(){});}
function reloadAll(){loadStats();loadScg();loadSpend();loadAlerts();}

document.getElementById('q-rows').addEventListener('click',function(e){var tr=e.target.closest('tr[data-id]');if(tr)openDrawer(tr.getAttribute('data-id'));});
document.getElementById('seg').addEventListener('click',function(e){var b=e.target.closest('button');if(!b)return;[].forEach.call(this.children,function(x){x.classList.remove('on');});b.classList.add('on');filter=b.getAttribute('data-f');page=0;loadAlerts();});
// Debounced server-side search: reset to page 0 so results aren't hidden behind the
// offset of whatever page was open when the user started typing.
var qTmr=null;
document.getElementById('q').addEventListener('input',function(){
  clearTimeout(qTmr);
  qTmr=setTimeout(function(){page=0;loadAlerts();},250);
});
(function(){var t=document.getElementById('obsToggle');function sync(){t.classList.toggle('on',hideObserved);}t.onclick=function(){hideObserved=!hideObserved;localStorage.setItem('raptorHideObs',hideObserved?'1':'0');sync();page=0;loadAlerts();};sync();})();
document.getElementById('prev').onclick=function(){if(page>0){page--;loadAlerts();}};
document.getElementById('next').onclick=function(){page++;loadAlerts();};
(function(){var sp=document.createElement('style');sp.textContent='@keyframes spin{to{transform:rotate(360deg)}}';document.head.appendChild(sp);})();

loadStats();loadScg();loadSpend();loadPhase();loadAlerts();

</script>
</body>
</html>"""


_INVESTIGATION_TPL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Investigation — RAPTOR</title>
<style>
  :root {
    --ground: #080A0E;
    --surface: #12151B;
    --surface-2: #181C24;
    --surface-3: #1E2430;
    --line: #252B36;
    --line-soft: #1A1F28;
    --text: #DDE1E8;
    --text-bright: #F3F6FB;
    --text-dim: #8E96A4;
    --text-faint: #59616E;
    --accent: #9E86F0;
    --accent-deep: #5B3FB0;
    --accent-glow: rgba(158,134,240,0.12);
    --crit: #F05552;
    --high: #E8913A;
    --med: #E6C34C;
    --low: #6C93C0;
    --good: #46B87A;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, system-ui, sans-serif;
    --font-mono: "SF Mono", ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
    --r: 6px;
  }

  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body {
    background: var(--ground);
    color: var(--text);
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }
  /* faint radar grid over the ground */
  body::before {
    content: "";
    position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image:
      linear-gradient(var(--line-soft) 1px, transparent 1px),
      linear-gradient(90deg, var(--line-soft) 1px, transparent 1px);
    background-size: 48px 48px;
    opacity: 0.35;
    mask-image: radial-gradient(ellipse 90% 70% at 70% 0%, #000 30%, transparent 75%);
  }

  .num { font-variant-numeric: tabular-nums; font-family: var(--font-mono); }
  .mono { font-family: var(--font-mono); }
  .eyebrow {
    font-family: var(--font-sans);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-faint);
  }

  a { color: inherit; text-decoration: none; }
  button { font-family: inherit; cursor: pointer; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 3px; }

  /* ---------- shell ---------- */
  .app {
    position: relative; z-index: 1;
    display: grid;
    grid-template-columns: 66px 1fr;
    height: 100vh;
  }

  /* ---------- rail ---------- */
  .rail {
    position: sticky; top: 0; height: 100vh; z-index: 30;
    display: flex; flex-direction: column; align-items: center;
    gap: 6px; padding: 16px 0;
    background: linear-gradient(180deg, #0C1116, #090C10);
    border-right: 1px solid var(--line);
  }
  .glyph { width: 38px; height: 38px; border-radius: 11px; display: grid; place-items: center; margin-bottom: 14px; background: linear-gradient(160deg, var(--surface-3), var(--surface)); border: 1px solid var(--line); }
  .glyph svg { width: 20px; height: 20px; }
  .navbtn { width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; color: var(--text-faint); cursor: pointer; position: relative; transition: .16s; border: 1px solid transparent; background: transparent; -webkit-appearance: none; appearance: none; }
  .navbtn svg { width: 19px; height: 19px; }
  .navbtn:hover { color: var(--text-dim); background: var(--surface-2); }
  .navbtn.active { color: var(--accent); background: var(--accent-glow); border-color: var(--accent-deep); }
  .navbtn.active::before { content: ""; position: absolute; left: -16px; top: 9px; bottom: 9px; width: 3px; border-radius: 3px; background: var(--accent); }
  .rail .spacer { flex: 1; }
  .tip { position: absolute; left: 52px; white-space: nowrap; background: var(--surface-3); border: 1px solid var(--line); color: var(--text); font-size: 12px; padding: 5px 9px; border-radius: 8px; opacity: 0; pointer-events: none; transform: translateX(-4px); transition: .14s; z-index: 40; }
  .navbtn:hover .tip { opacity: 1; transform: translateX(0); }
  .brand-mark {
    width: 34px; height: 34px; margin-bottom: 16px;
    color: var(--accent);
    filter: drop-shadow(0 0 8px var(--accent-glow));
  }
  .rail-btn {
    position: relative;
    width: 42px; height: 40px;
    display: flex; align-items: center; justify-content: center;
    color: var(--text-faint);
    background: transparent; border: 0; border-radius: var(--r);
    transition: color .15s, background .15s;
  }
  .rail-btn:hover { color: var(--text-dim); background: var(--surface-2); }
  .rail-btn.active { color: var(--accent); background: var(--accent-glow); }
  .rail-btn.active::before {
    content: ""; position: absolute; left: -14px; top: 8px; bottom: 8px;
    width: 3px; border-radius: 3px; background: var(--accent);
    box-shadow: 0 0 10px var(--accent);
  }
  .rail-btn svg { width: 19px; height: 19px; }
  .rail-spacer { flex: 1; }
  .rail-tip {
    position: absolute; left: 52px; white-space: nowrap;
    background: var(--surface-3); border: 1px solid var(--line);
    color: var(--text); font-size: 11px; padding: 3px 8px; border-radius: 4px;
    opacity: 0; transform: translateX(-4px); pointer-events: none; transition: .12s;
    font-family: var(--font-mono); letter-spacing: .02em; z-index: 20;
  }
  .rail-btn:hover .rail-tip { opacity: 1; transform: translateX(0); }

  /* ---------- main ---------- */
  .main { display: grid; grid-template-rows: auto 1fr; min-width: 0; }

  .topbar {
    display: flex; align-items: center; gap: 20px;
    padding: 0 20px; height: 54px;
    border-bottom: 1px solid var(--line);
    background: rgba(12,17,22,0.7); backdrop-filter: blur(6px);
  }
  .title-block { display: flex; flex-direction: column; gap: 1px; }
  .title-block h1 {
    margin: 0; font-size: 15px; font-weight: 650; letter-spacing: 0.02em;
    display: flex; align-items: center; gap: 9px;
  }
  .title-block .wm { font-family: var(--font-mono); letter-spacing: 0.16em; }
  .title-block .wm b { color: var(--accent); font-weight: 650; }

  .topbar-spacer { flex: 1; }

  .boundary-status {
    display: flex; align-items: center; gap: 14px;
    padding: 6px 12px; border: 1px solid var(--line);
    border-radius: var(--r); background: var(--surface);
  }
  .zone { display: flex; align-items: center; gap: 7px; }
  .zone .eyebrow { color: var(--text-dim); }
  .dot { width: 8px; height: 8px; border-radius: 50%; position: relative; }
  .dot.on { background: var(--good); box-shadow: 0 0 0 3px rgba(70,184,122,0.16); }
  .dot.cloud { background: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  .dot.live::after {
    content: ""; position: absolute; inset: -3px; border-radius: 50%;
    border: 1px solid currentColor; animation: ping 2.4s ease-out infinite;
  }
  .zone.on-prem .dot.live::after { color: var(--good); }
  .zone.cloud .dot.live::after { color: var(--accent); }
  @keyframes ping { 0% { transform: scale(1); opacity: .7; } 100% { transform: scale(2.4); opacity: 0; } }
  .zone-sep { width: 1px; height: 22px; background: var(--line); }

  .meter-group { display: flex; align-items: center; gap: 16px; }
  .meter { display: flex; flex-direction: column; gap: 4px; min-width: 142px; }
  .meter-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
  .meter-head .val { font-family: var(--font-sans); font-size: 12px; font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }
  .meter-track { height: 4px; border-radius: 2px; background: var(--surface-3); overflow: hidden; }
  .meter-fill { height: 100%; border-radius: 2px; width: 0; transition: width 1.1s cubic-bezier(.2,.7,.2,1); }

  .phase-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.08em;
    color: var(--accent); background: var(--accent-glow);
    border: 1px solid var(--accent-deep); border-radius: 20px; padding: 4px 11px;
  }

  /* ---------- content ---------- */
  .content { overflow: auto; padding: 18px 20px 40px; }

  /* KPI strip */
  .kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin-bottom: 18px; }
  .kpi {
    position: relative; overflow: hidden;
    background: linear-gradient(180deg, var(--surface-2), var(--surface));
    border: 1px solid var(--line); border-radius: var(--r);
    padding: 13px 15px; display: flex; flex-direction: column; gap: 7px;
    box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset, 0 10px 26px -18px rgba(0,0,0,0.85);
    transition: transform .16s, border-color .16s;
  }
  .kpi::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--kpi-accent, var(--line-2)); }
  .kpi:hover { transform: translateY(-2px); border-color: var(--line-2); }
  .kpi .eyebrow { color: var(--text-faint); }
  .kpi .figure { font-family: var(--font-sans); font-size: 28px; font-weight: 700; letter-spacing: -0.025em; line-height: 1; color: var(--text-bright); font-variant-numeric: tabular-nums; }
  .kpi .sub { font-family: var(--font-sans); font-size: 11.5px; color: var(--text-dim); }
  .kpi .sub b { color: var(--good); font-weight: 600; }
  .kpi.attn .figure { color: var(--high); }
  .kpi.crit .figure { color: var(--crit); }
  .kpi .spark { height: 22px; margin-top: 2px; }

  /* work area */
  .work { display: block; }
  @media (max-width: 1180px) { .work { grid-template-columns: 1fr; } }

  .panel { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; box-shadow: 0 14px 38px -24px rgba(0,0,0,0.9); }
  .panel-head {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 14px; border-bottom: 1px solid var(--line);
  }
  .panel-head h2 { margin: 0; font-size: 12px; font-weight: 600; letter-spacing: 0.02em; }
  .panel-head .count {
    font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);
    background: var(--surface-3); border-radius: 20px; padding: 2px 9px;
  }
  .panel-head .spacer { flex: 1; }
  .ph-btn {
    font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.04em;
    color: var(--text-dim); background: var(--surface-2);
    border: 1px solid var(--line); border-radius: 5px; padding: 4px 9px;
    display: inline-flex; align-items: center; gap: 5px; transition: .15s;
  }
  .ph-btn:hover { color: var(--text); border-color: var(--accent-deep); }
  .ph-btn svg { width: 13px; height: 13px; }

  /* queue table */
  .q-wrap { overflow-x: auto; }
  table.queue { width: 100%; border-collapse: collapse; }
  table.queue thead th {
    font-family: var(--font-sans); font-size: 10px; letter-spacing: 0.05em; text-transform: uppercase;
    color: var(--text-faint); font-weight: 600; text-align: left;
    padding: 9px 10px; border-bottom: 1px solid var(--line); white-space: nowrap;
  }
  table.queue tbody td { padding: 10px 10px; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }
  table.queue tbody td:first-child { box-shadow: inset 3px 0 0 var(--sevcol, transparent); }
  .c-dev, .c-usr { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); max-width: 168px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .c-usr { color: var(--text-faint); }
  table.queue tbody tr { cursor: pointer; transition: background .12s; position: relative; }
  table.queue tbody tr:hover { background: var(--surface-2); }
  table.queue tbody tr.sel { background: linear-gradient(90deg, var(--accent-glow), transparent 60%); }
  table.queue tbody tr.sel td:first-child { box-shadow: inset 3px 0 0 var(--accent); }

  .tkt { font-family: var(--font-mono); font-size: 11.5px; color: var(--text); } a.tkt { cursor: pointer; } a.tkt:hover { color: var(--accent); text-decoration: underline; } .jl { color: var(--good); text-decoration: none; } .jl:hover { text-decoration: underline; }
  .alert-name { font-size: 13px; color: var(--text-bright); font-weight: 500; }
  .alert-name .whom { font-family: var(--font-mono); font-size: 10.5px; color: var(--text-faint); display: block; margin-top: 2px; }

  .sev { display: inline-flex; align-items: center; gap: 7px; font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.05em; }
  .sev::before { content: ""; width: 3px; height: 13px; border-radius: 2px; background: currentColor; }
  .sev.crit { color: var(--crit); } .sev.high { color: var(--high); }
  .sev.med { color: var(--med); } .sev.low { color: var(--low); } .sev.info { color: var(--text-faint); }

  .verdict {
    font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.03em;
    padding: 3px 8px; border-radius: 4px; border: 1px solid; white-space: nowrap;
  }
  .verdict.fp { color: var(--good); border-color: rgba(70,184,122,0.4); background: rgba(70,184,122,0.08); }
  .verdict.tp { color: var(--high); border-color: rgba(232,145,58,0.4); background: rgba(232,145,58,0.08); }
  .verdict.l2 { color: var(--low); border-color: rgba(108,147,192,0.4); background: rgba(108,147,192,0.08); }
  .verdict.urgent { color: #fff; border-color: var(--crit); background: var(--crit); font-weight: 600; }

  .conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }
  .backend {
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.06em; text-transform: uppercase;
    color: var(--text-dim); display: inline-flex; align-items: center; gap: 5px;
  }
  .backend svg { width: 11px; height: 11px; }
  .backend.onprem { color: var(--good); }
  .backend.cloudb { color: var(--accent); }
  .t-ago { font-family: var(--font-mono); font-size: 11px; color: var(--text-faint); text-align: right; }

  /* ---------- detail panel ---------- */
  .detail .panel-head .tkt-lg { font-family: var(--font-mono); font-size: 13px; color: var(--accent); }
  .detail-body { padding: 14px; display: flex; flex-direction: column; gap: 16px; }

  .d-headline { display: flex; flex-direction: column; gap: 8px; }
  .d-headline .name { font-size: 15px; font-weight: 600; letter-spacing: 0.01em; }
  .d-meta { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip {
    font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.04em;
    color: var(--text-dim); border: 1px solid var(--line); border-radius: 4px; padding: 2px 7px;
  }
  .chip.mitre { color: var(--text); border-color: var(--accent-deep); }

  .section-label { display: flex; align-items: center; gap: 8px; margin-bottom: 9px; }
  .section-label .eyebrow { color: var(--text-dim); }
  .section-label .rule { flex: 1; height: 1px; background: var(--line); }

  /* boundary visualization */
  .boundary {
    border: 1px solid var(--line); border-radius: 7px; overflow: hidden;
    background: var(--surface-2);
  }
  .boundary-grid { display: grid; grid-template-columns: 1fr 30px 1fr; }
  .bzone { padding: 11px 12px; }
  .bzone.regulated { background: rgba(70,184,122,0.045); }
  .bzone.cloudzone { background: rgba(158,134,240,0.04); }
  .bzone .bz-head {
    display: flex; align-items: center; gap: 6px; margin-bottom: 9px;
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.08em; text-transform: uppercase;
  }
  .bzone.regulated .bz-head { color: var(--good); }
  .bzone.cloudzone .bz-head { color: var(--accent); }
  .bzone .bz-head svg { width: 12px; height: 12px; }
  .bz-row { font-family: var(--font-mono); font-size: 10.5px; line-height: 1.9; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bz-row .k { color: var(--text-faint); }
  .bz-row .real { color: var(--text); }
  .bz-row .tok { color: var(--accent); }
  .bz-row .red { color: var(--high); }
  .bz-row .kept { color: var(--good); }
  .b-divider { position: relative; }
  .b-divider::before {
    content: ""; position: absolute; left: 50%; top: 6px; bottom: 6px; width: 0;
    border-left: 1px dashed var(--accent-deep); transform: translateX(-50%);
  }
  .b-divider .arrow {
    position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%);
    color: var(--accent); width: 16px; height: 16px;
  }
  .b-caption {
    padding: 7px 12px; border-top: 1px solid var(--line);
    font-family: var(--font-mono); font-size: 10px; color: var(--text-faint); letter-spacing: 0.02em;
  }
  .b-caption b { color: var(--good); font-weight: 500; }

  /* agent trace */
  .trace { display: flex; flex-direction: column; gap: 0; }
  .trace-step { display: grid; grid-template-columns: 20px 1fr; gap: 10px; padding: 0 0 14px; position: relative; }
  .trace-step:not(:last-child)::before {
    content: ""; position: absolute; left: 9px; top: 18px; bottom: 0; width: 1px; background: var(--line);
  }
  .trace-node {
    width: 19px; height: 19px; border-radius: 50%; z-index: 1;
    display: flex; align-items: center; justify-content: center;
    background: var(--surface-3); border: 1px solid var(--line);
  }
  .trace-node svg { width: 11px; height: 11px; color: var(--text-dim); }
  .trace-step.think .trace-node { border-color: var(--accent-deep); }
  .trace-step.think .trace-node svg { color: var(--accent); }
  .trace-step.final .trace-node { background: var(--accent); border-color: var(--accent); }
  .trace-step.final .trace-node svg { color: #06110F; }
  .trace-body { min-width: 0; }
  .trace-kind {
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--text-faint); margin-bottom: 3px;
  }
  .trace-step.think .trace-kind { color: var(--accent); }
  .trace-text { font-size: 12px; color: var(--text-dim); }
  .tool-call {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    font-family: var(--font-mono); font-size: 11px;
  }
  .tool-name { color: var(--text); background: var(--surface-3); border: 1px solid var(--line); border-radius: 4px; padding: 2px 7px; }
  .tool-arg { color: var(--text-faint); }
  .tool-res { color: var(--text-dim); }
  .tool-res .ok { color: var(--good); } .tool-res .flag { color: var(--high); }

  .verdict-final {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    padding: 11px 13px; border-radius: 7px;
    background: rgba(70,184,122,0.07); border: 1px solid rgba(70,184,122,0.3);
  }
  .verdict-final .vf-label { font-family: var(--font-mono); font-size: 15px; letter-spacing: 0.04em; color: var(--good); font-weight: 600; }
  .verdict-final .vf-conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }
  .verdict-final .vf-conf b { color: var(--text); }
  .verdict-final .spacer { flex: 1; }
  .vf-actions { display: flex; gap: 7px; }
  .vf-btn { font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.03em; padding: 6px 12px; border-radius: 5px; border: 1px solid var(--line); background: var(--surface-2); color: var(--text-dim); transition: .15s; }
  .vf-btn:hover { color: var(--text); }
  .vf-btn.primary { background: var(--accent); border-color: var(--accent); color: #06110F; font-weight: 600; }
  .vf-btn.primary:hover { filter: brightness(1.08); }
  .vf-advisory { font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text-faint); border: 1px dashed var(--line); border-radius: 4px; padding: 4px 9px; white-space: nowrap; }

  /* SCG memory precedents */
  .mem { display: flex; flex-direction: column; gap: 8px; }
  .mem-row {
    display: grid; grid-template-columns: auto 1fr auto; gap: 11px; align-items: center;
    padding: 9px 11px; border: 1px solid var(--line); border-radius: 6px; background: var(--surface-2);
  }
  .tier { font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; padding: 3px 7px; border-radius: 3px; text-transform: uppercase; }
  .tier.golden { color: var(--med); background: rgba(230,195,76,0.1); border: 1px solid rgba(230,195,76,0.35); }
  .tier.curated { color: var(--accent); background: var(--accent-glow); border: 1px solid var(--accent-deep); }
  .mem-txt { font-size: 12px; color: var(--text-dim); min-width: 0; }
  .mem-txt .m-tkt { font-family: var(--font-mono); font-size: 11px; color: var(--text); }
  .mem-txt .m-note { display: block; font-size: 11px; color: var(--text-faint); margin-top: 2px; }
  .mem-conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); text-align: right; }
  .mem-conf small { display: block; color: var(--text-faint); font-size: 9px; letter-spacing: 0.08em; }

  @media (prefers-reduced-motion: reduce) {
    * { animation: none !important; transition: none !important; }
    .meter-fill { transition: none; }
  }

  /* ---- topbar action buttons ---- */
  .tb-actions { display:flex; align-items:center; gap:7px; }
  .btn { display:inline-flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:11px; letter-spacing:0.03em; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); border-radius:5px; padding:6px 10px; transition:.15s; white-space:nowrap; }
  .btn svg { width:13px; height:13px; }
  .btn:hover { color:var(--text); border-color:var(--accent-deep); }
  .btn.primary { color:#06110F; background:var(--accent); border-color:var(--accent); font-weight:600; }
  .btn.primary:hover { filter:brightness(1.08); }
  .btn.danger { color:var(--crit); border-color:rgba(240,85,82,0.35); background:rgba(240,85,82,0.06); }
  .btn.danger:hover { background:rgba(240,85,82,0.12); }

  /* ---- queue sub-toolbar ---- */
  .subbar { display:flex; align-items:center; gap:9px; padding:9px 12px; border-bottom:1px solid var(--line); flex-wrap:wrap; }
  .seg { display:flex; background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:2px; gap:2px; }
  .seg button { font-family:var(--font-mono); font-size:10.5px; letter-spacing:0.02em; color:var(--text-dim); background:none; border:0; padding:4px 9px; border-radius:3px; transition:.13s; white-space:nowrap; }
  .seg button:hover { color:var(--text); }
  .seg button.on { background:var(--surface-3); color:var(--text); }
  .seg .cnt { color:var(--text-faint); margin-left:4px; }
  .seg button.on .cnt { color:var(--accent); }
  .search { display:flex; align-items:center; gap:7px; background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:5px 9px; min-width:150px; flex:1; }
  .search:focus-within { border-color:var(--accent-deep); }
  .search svg { width:13px; height:13px; color:var(--text-faint); flex:none; }
  .search input { background:none; border:0; outline:none; color:var(--text); font-size:12px; width:100%; font-family:var(--font-sans); }
  .search input::placeholder { color:var(--text-faint); }
  .tgl { display:inline-flex; align-items:center; gap:7px; font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:5px 9px; cursor:pointer; user-select:none; white-space:nowrap; }
  .tgl .sw { width:26px; height:15px; border-radius:20px; background:var(--surface-3); border:1px solid var(--line); position:relative; transition:.15s; flex:none; }
  .tgl .sw::before { content:""; position:absolute; left:2px; top:1.5px; width:10px; height:10px; border-radius:50%; background:var(--text-faint); transition:.15s; }
  .tgl.on { color:var(--text); }
  .tgl.on .sw { background:var(--accent-glow); border-color:var(--accent-deep); }
  .tgl.on .sw::before { transform:translateX(11px); background:var(--accent); }

  /* ---- pager ---- */
  .pager-bar { display:flex; align-items:center; justify-content:space-between; padding:9px 12px; border-top:1px solid var(--line); }
  .pager-bar .pi { font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); }
  .pager { display:flex; gap:6px; }
  .pager button { font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); padding:5px 10px; border-radius:4px; transition:.13s; }
  .pager button:hover:not(:disabled) { color:var(--text); border-color:var(--accent-deep); }
  .pager button:disabled { opacity:.35; }
  .pb { font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); }

  /* ---- detail: verdict / meta / VT / comments / reasoning ---- */
  .verdict-top { display:flex; align-items:center; gap:11px; padding:11px 13px; border-radius:7px; border:1px solid; }
  .verdict-top .vt-dot { width:9px; height:9px; border-radius:50%; flex:none; }
  .verdict-top .vt-name { font-family:var(--font-mono); font-size:14px; font-weight:600; letter-spacing:0.03em; }
  .verdict-top .vt-conf { margin-left:auto; font-family:var(--font-mono); font-size:11px; color:var(--text-dim); }
  .meta-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
  .meta { background:var(--surface-2); border:1px solid var(--line); border-radius:6px; padding:9px 11px; min-width:0; }
  .meta .mk { font-family:var(--font-sans); font-size:9.5px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:var(--text-faint); margin-bottom:4px; }
  .meta .mv { font-family:var(--font-mono); font-size:11.5px; color:var(--text); word-break:break-word; }
  .meta.full { grid-column:1 / -1; }
  .vt-card { display:flex; align-items:center; gap:12px; background:var(--surface-2); border:1px solid var(--line); border-radius:7px; padding:11px 13px; }
  .vt-ring { width:42px; height:42px; border-radius:50%; flex:none; display:grid; place-items:center; }
  .vt-ring b { width:32px; height:32px; border-radius:50%; background:var(--surface); display:grid; place-items:center; font-family:var(--font-mono); font-size:12px; font-weight:600; }
  .vt-info .a { font-size:12.5px; color:var(--text); }
  .vt-info .b { font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); margin-top:2px; }
  .cmd { background:var(--ground); border:1px solid var(--line); border-radius:6px; padding:11px 12px; font-family:var(--font-mono); font-size:11px; color:#b7c6d8; white-space:pre-wrap; word-break:break-word; line-height:1.6; }
  /* Mock Jira panel — the exact comment/transition/labels RAPTOR posts to the ticket */
  .jira-card { border:1px solid var(--line); border-radius:8px; overflow:hidden; background:var(--surface); }
  .jira-head { display:flex; align-items:center; gap:10px; padding:9px 12px; border-bottom:1px solid var(--line); background:var(--surface-2); }
  .jira-key { font-family:var(--font-mono); font-size:12px; font-weight:600; color:var(--accent); }
  .jira-mock { font-family:var(--font-mono); font-size:9px; letter-spacing:0.06em; text-transform:uppercase; color:var(--text-faint); border:1px solid var(--line); border-radius:3px; padding:2px 6px; }
  .jira-head .spacer { flex:1; }
  .jira-trans { font-family:var(--font-mono); font-size:10.5px; padding:3px 9px; border:1px solid; border-radius:20px; white-space:nowrap; }
  .jira-labels { display:flex; flex-wrap:wrap; gap:6px; padding:10px 12px 0; }
  .jira-chip { font-family:var(--font-mono); font-size:10px; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); border-radius:4px; padding:2px 8px; }
  .jira-comment { padding:11px 12px 12px; }
  .jira-comment-head { display:flex; align-items:center; gap:8px; font-size:11px; color:var(--text-dim); margin-bottom:9px; }
  .jira-avatar { width:20px; height:20px; border-radius:50%; background:var(--accent); color:#0b0d11; font-weight:700; font-size:11px; display:flex; align-items:center; justify-content:center; }
  .jira-comment-body { font-size:12.5px; color:var(--text); line-height:1.55; }
  .jira-comment-body .jira-h { font-weight:600; color:var(--text); margin:11px 0 5px; font-size:12.5px; }
  .jira-comment-body .jira-h:first-child { margin-top:0; }
  .jira-comment-body .jira-p { margin:4px 0; color:var(--text-dim); }
  .jira-comment-body .jira-ul { margin:4px 0 4px 2px; padding:0; list-style:none; }
  .jira-comment-body .jira-ul li { position:relative; padding-left:14px; margin:3px 0; color:var(--text-dim); }
  .jira-comment-body .jira-ul li::before { content:"\2022"; position:absolute; left:2px; color:var(--accent); }
  .jira-comment-body .jira-pre { background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:8px 10px; font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); white-space:pre-wrap; margin:8px 0 0; }
  .ai-block { background:var(--accent-glow); border:1px solid var(--accent-deep); border-radius:7px; padding:12px 13px; }
  .ai-block .ah { display:flex; align-items:center; gap:7px; font-family:var(--font-mono); font-size:10px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:var(--accent); margin-bottom:8px; }
  .ai-block .ah svg { width:12px; height:12px; }
  .ai-block pre { margin:0; font-family:var(--font-mono); font-size:11px; line-height:1.65; color:#cdbff5; white-space:pre-wrap; word-break:break-word; }

  /* ---- shared preview head + entities + full-page (consistency with AI Memory) ---- */
  .prev-head { display: flex; align-items: center; gap: 10px; padding: 11px 14px; border-bottom: 1px solid var(--line); }
  .prev-head .pref { font-family: var(--font-mono); font-size: 13px; color: var(--accent); }
  .ents { display: flex; flex-wrap: wrap; gap: 7px; }
  .ent { display: inline-flex; align-items: center; gap: 6px; font-family: var(--font-mono); font-size: 10.5px; color: var(--text-dim); background: var(--surface-2); border: 1px solid var(--line); border-radius: 5px; padding: 4px 8px; }
  .ent svg { width: 11px; height: 11px; color: var(--accent); }
  .fullpage { position: fixed; inset: 0; z-index: 80; background: var(--ground); overflow: auto; display: none; }
  .fullpage.on { display: block; }
  .fp-bar { position: sticky; top: 0; z-index: 2; display: flex; align-items: center; gap: 14px; padding: 0 24px; height: 54px; border-bottom: 1px solid var(--line); background: rgba(11,13,17,0.85); backdrop-filter: blur(6px); }
  .fp-back { display: inline-flex; align-items: center; gap: 7px; font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); cursor: pointer; }
  .fp-back:hover { color: var(--text); }
  .fp-wrap { max-width: 1060px; margin: 0 auto; padding: 26px 24px 60px; }
  .fp-eyebrow { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .fp-title { font-size: 22px; font-weight: 650; letter-spacing: 0.01em; margin: 0 0 6px; }
  .fp-sub { font-family: var(--font-mono); font-size: 11.5px; color: var(--text-dim); }
  .fp-quote { border: 1px solid var(--line); border-left: 3px solid var(--accent); background: var(--surface); border-radius: 0 8px 8px 0; padding: 16px 18px; font-size: 14px; line-height: 1.65; color: var(--text); margin: 20px 0; }
  .fp-timeline { display: flex; align-items: stretch; gap: 0; margin: 18px 0; flex-wrap: wrap; }
  .tl-step { flex: 1; min-width: 150px; border: 1px solid var(--line); background: var(--surface); border-radius: 7px; padding: 12px 14px; position: relative; }
  .tl-step + .tl-step { margin-left: 22px; }
  .tl-step + .tl-step::before { content: "\2192"; position: absolute; left: -18px; top: 50%; transform: translateY(-50%); color: var(--text-faint); font-family: var(--font-mono); }
  .tl-step .ts-k { font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-faint); margin-bottom: 6px; }
  .tl-step .ts-v { font-family: var(--font-mono); font-size: 13px; font-weight: 600; }
  .tl-step .ts-note { font-size: 11px; color: var(--text-dim); margin-top: 4px; }
  .fp-cols { display: grid; grid-template-columns: 1.3fr 1fr; gap: 20px; align-items: start; margin-top: 8px; }
  @media (max-width: 900px) { .fp-cols { grid-template-columns: 1fr; } }
  .fp-actions { display: flex; gap: 9px; margin-top: 24px; flex-wrap: wrap; align-items: center; }
  .fp-sect { margin-top: 22px; }
  .fp-sect > .section-label { margin-bottom: 12px; }
  .trace-cmd { margin: 6px 0 2px 30px; }

  /* ---- adjudication: AI vs L1 vs L2, and whether it scored ----
     The accuracy metric is read off exactly these values, so the page that explains
     a verdict has to show them; without it you cannot tell a hit from a miss from a
     row the scorer simply has not reached yet. */
  .adj { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
  .adj-c { background: var(--surface); border: 1px solid var(--line); border-radius: 7px; padding: 11px 13px; min-width: 0; }
  .adj-c.is-out { border-style: dashed; }
  .adj-k { font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-faint); margin-bottom: 6px; }
  .adj-v { font-family: var(--font-mono); font-size: 12.5px; font-weight: 600; word-break: break-word; }
  .adj-n { font-size: 10.5px; color: var(--text-dim); margin-top: 5px; line-height: 1.45; }
  .adj-n b { color: var(--text); font-weight: 600; }

  /* ---- safety gate: only drawn when a gate actually moved the verdict ---- */
  .gate { display: flex; align-items: flex-start; gap: 11px; border: 1px solid var(--high); background: rgba(232,145,58,0.08); border-radius: 7px; padding: 12px 14px; }
  .gate svg { width: 15px; height: 15px; color: var(--high); flex: none; margin-top: 1px; }
  .gate .gt { font-family: var(--font-mono); font-size: 11.5px; color: var(--text-bright); }
  .gate .gt .arr { color: var(--text-faint); margin: 0 6px; }
  .gate .gr { font-size: 11.5px; color: var(--text-dim); margin-top: 5px; line-height: 1.5; }

  /* ---- chips on the eyebrow row (phase, re-triage, gate state) ---- */
  .fchip { display: inline-flex; align-items: center; gap: 5px; font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.04em; text-transform: uppercase; color: var(--text-dim); background: var(--surface-2); border: 1px solid var(--line); border-radius: 20px; padding: 3px 9px; }
  .fchip b { color: var(--text); font-weight: 600; }
  .fchip.warn { color: var(--high); border-color: rgba(232,145,58,0.4); background: rgba(232,145,58,0.08); }

  /* ---- structured reasoning: numbered findings, not a wall of <pre> ---- */
  .rsn { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 12px; }
  .rsn-i { display: flex; gap: 11px; }
  .rsn-n { flex: none; width: 19px; height: 19px; border-radius: 50%; display: grid; place-items: center; background: var(--accent-glow); border: 1px solid var(--accent-deep); color: var(--accent); font-family: var(--font-mono); font-size: 10px; font-weight: 600; margin-top: 1px; }
  .rsn-t { font-size: 12.5px; line-height: 1.62; color: var(--text); min-width: 0; word-break: break-word; }
  .rsn-t strong { color: var(--text-bright); font-weight: 650; }
  .rsn-t code { font-family: var(--font-mono); font-size: 11px; background: var(--ground); border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; color: #b7c6d8; word-break: break-all; }
  .rsn-sub { list-style: none; margin: 6px 0 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
  .rsn-sub li { position: relative; padding-left: 13px; font-size: 12px; color: var(--text-dim); line-height: 1.55; }
  .rsn-sub li::before { content: ""; position: absolute; left: 2px; top: 8px; width: 4px; height: 4px; border-radius: 50%; background: var(--text-faint); }
  .rsn-p { margin: 7px 0 0; }

  /* ---- tool trace: name + parsed argument chips + result ---- */
  .tcall { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .targ { font-family: var(--font-mono); font-size: 10px; color: var(--text-dim); background: var(--surface-2); border: 1px solid var(--line); border-radius: 4px; padding: 2px 7px; }
  .targ b { color: var(--text); font-weight: 600; }
  .tres { margin: 7px 0 2px 30px; display: flex; gap: 8px; align-items: baseline; }
  .tres .rk { font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-faint); flex: none; }
  .tres .rv { font-family: var(--font-mono); font-size: 11px; color: #b7c6d8; word-break: break-word; min-width: 0; line-height: 1.55; }
  .tres .rv.none { color: var(--text-faint); }

  /* ---- investigation drawer (preview, ~560px slide-over) ---- */
  .overlay { position: fixed; inset: 0; background: rgba(4,7,11,0.6); backdrop-filter: blur(3px); opacity: 0; pointer-events: none; transition: .2s; z-index: 70; }
  .overlay.open { opacity: 1; pointer-events: auto; }
  .drawer { position: fixed; top: 0; right: 0; height: 100vh; width: min(560px, 94vw); background: var(--surface); border-left: 1px solid var(--line); transform: translateX(100%); transition: transform .26s cubic-bezier(.4,0,.2,1); z-index: 75; display: flex; flex-direction: column; box-shadow: -30px 0 60px rgba(0,0,0,.5); }
  .drawer.open { transform: translateX(0); }
  .dhead { padding: 15px 18px 13px; border-bottom: 1px solid var(--line); flex: 0 0 auto; }
  .dh-top { display: flex; align-items: center; justify-content: space-between; }
  .dx { cursor: pointer; color: var(--text-faint); font-size: 20px; line-height: 1; padding: 0 4px; }
  .dx:hover { color: var(--text); }
  .dstrip { display: flex; align-items: center; gap: 7px; margin-top: 11px; }
  .dbody { padding: 16px 18px 40px; overflow-y: auto; flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; gap: 15px; }
  .dbody > * { flex-shrink: 0; }
</style>
</head>
<body>
<div class="fullpage on">
  <div class="fp-bar">
    <a class="fp-back" href="/edr-triage"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M11 6l-6 6 6 6"/></svg>RAPTOR — Triage</a>
    <span class="eyebrow" id="crumb">Investigation</span>
    <div style="flex:1"></div>
    <button class="btn" id="jiraBtn" style="display:none"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6M10 14 21 3"/></svg>Open Jira ticket</button>
  </div>
  <div class="fp-wrap" id="wrap"><div class="prev-empty">Loading…</div></div>
</div>
<script>
var ALERT_ID=__ALERT_ID__;
var SPARK='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4M12 18v4M2 12h4M18 12h4M5 5l2.5 2.5M16.5 16.5L19 19M19 5l-2.5 2.5M7.5 16.5L5 19"/><circle cx="12" cy="12" r="3.5"/></svg>';
var ACTSVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M20 7 9 18l-5-5"/></svg>';
var THINKSVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10.5c.8.7 1 1 1 2.5h6c0-1.5.2-1.8 1-2.5A6 6 0 0 0 12 3Z"/></svg>';
var VSVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M20 6 9 17l-5-5"/></svg>';
var ENTSVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>';
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function rgba(hex,a){var n=parseInt(hex.slice(1),16);return 'rgba('+((n>>16)&255)+','+((n>>8)&255)+','+(n&255)+','+a+')';}
var VCOL={AUTO_CLOSED_FP:'#46B87A',AUTO_CLOSED_TP:'#E8913A',NEEDS_L2:'#6C93C0',URGENT:'#F05552',PENDING:'#8E96A4',OBSERVED:'#59616E',SKIPPED:'#59616E',PROCESSING:'#8E96A4'};
// Render a subset of Jira wiki markup (h2./h3., * bullets, {noformat}, *bold*) to HTML.
function wikiToHtml(s){
  if(!s)return '';
  function e(t){return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function inl(t){return e(t).replace(/\*([^*]+)\*/g,'<b>$1</b>').replace(/\[([^\|\]]+)\|[^\]]+\]/g,'$1');}
  var lines=String(s).split('\n'),out=[],i=0,inList=false;
  function endList(){if(inList){out.push('</ul>');inList=false;}}
  while(i<lines.length){
    var ln=lines[i];
    if(ln.trim()==='{noformat}'){endList();var code=[];i++;while(i<lines.length&&lines[i].trim()!=='{noformat}'){code.push(lines[i]);i++;}i++;out.push('<pre class="jira-pre">'+e(code.join('\n'))+'</pre>');continue;}
    var hm=ln.match(/^h[1-6]\.\s+(.*)/);
    if(hm){endList();out.push('<div class="jira-h">'+inl(hm[1])+'</div>');i++;continue;}
    if(ln.indexOf('* ')===0){if(!inList){out.push('<ul class="jira-ul">');inList=true;}out.push('<li>'+inl(ln.slice(2))+'</li>');i++;continue;}
    if(!ln.trim()){endList();i++;continue;}
    endList();out.push('<div class="jira-p">'+inl(ln)+'</div>');i++;
  }
  endList();return out.join('');
}
function jiraPanel(a){
  if(!a.l1_comment)return '';
  var act=a.action_taken||'';
  var tr = act==='resolved' ? {t:'→ Resolve',c:'var(--good)'}
         : act==='event_analysis' ? {t:'→ Event Analysis',c:'var(--med)'}
         : act==='labels_only' ? {t:'labels only',c:'var(--text-dim)'}
         : {t:'advisory · no transition',c:'var(--text-dim)'};
  var chips=(a.labels_applied||[]).map(function(l){return '<span class="jira-chip">'+esc(l)+'</span>';}).join('');
  var h='<div class="fp-sect" style="margin-top:0"><div class="section-label"><span class="eyebrow">Posted to Jira</span><span class="rule"></span></div>';
  h+='<div class="jira-card"><div class="jira-head"><span class="jira-key">'+esc(a.jira_key||'—')+'</span>'
    +'<span class="jira-mock">mock · dry-run</span><span class="spacer"></span>'
    +'<span class="jira-trans" style="color:'+tr.c+';border-color:'+tr.c+'">'+tr.t+'</span></div>';
  if(chips)h+='<div class="jira-labels">'+chips+'</div>';
  h+='<div class="jira-comment"><div class="jira-comment-head"><span class="jira-avatar">R</span> RAPTOR bot · added a comment</div>'
    +'<div class="jira-comment-body">'+wikiToHtml(a.l1_comment)+'</div></div></div></div>';
  return h;
}
function cell(k,v,color,full){return '<div class="meta'+(full?' full':'')+'"><div class="mk">'+esc(k)+'</div><div class="mv"'+(color?' style="color:'+color+'"':'')+'>'+esc(v)+'</div></div>';}
function jiraLink(k){return '<a class="jl" href="https://jira.example.com/browse/'+encodeURIComponent(k)+'" target="_blank" rel="noopener" onclick="event.stopPropagation()">'+esc(k)+' \u2197</a>';}
function metaJira(jk){return '<div class="meta"><div class="mk">Jira ticket</div><div class="mv">'+(jk?jiraLink(jk):'<span style="color:var(--text-faint)">not raised</span>')+'</div></div>';}
function ent(k,v){return '<span class="ent">'+ENTSVG+esc(k)+' · '+esc(v)+'</span>';}
var GATESVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>';

/* The model writes its reasoning as markdown — numbered findings, **bold** claims,
   `backticked` commands and indented sub-bullets. Rendering that into a <pre> shows
   the syntax instead of the structure, which is why the egress lists in these
   verdicts read as one run-on line. Convert the small subset actually emitted. */
function mdInline(s){
  return esc(s)
    .replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>')
    .replace(/`([^`]+)`/g,'<code>$1</code>')
    .replace(/\b(SIM-\d+)\b/g,'<a class="jl" href="https://jira.example.com/browse/$1" target="_blank" rel="noopener">$1</a>');
}
function reasonHTML(text){
  var raw=String(text||'').trim();
  if(!raw)return '';
  // Split on "1." / "2." at the head of a line; anything before the first number
  // (a preamble) is kept as an unnumbered lead item rather than dropped.
  var parts=raw.split(/\n\s*(?=\d+[.)]\s)/).map(function(p){return p.trim();}).filter(Boolean);
  var items=parts.map(function(p){
    var m=p.match(/^(\d+)[.)]\s+([\s\S]*)$/);
    return m?{n:m[1],body:m[2].trim()}:{n:null,body:p};
  });
  // A single unnumbered blob is prose, not a list — render it as one paragraph.
  if(items.length===1&&items[0].n===null)return '<div class="rsn-t">'+mdInline(items[0].body).replace(/\n/g,'<br>')+'</div>';
  var h='<ol class="rsn">';
  items.forEach(function(it,i){
    // Walk the lines in order rather than collecting prose and bullets separately:
    // a finding often closes with a sentence AFTER its list ("...no external hosts
    // were observed"), and hoisting that above the list inverts what it summarises.
    var blocks=[],cur=null;
    it.body.split('\n').forEach(function(l){
      var sm=l.match(/^\s*[-*•]\s+(.*)$/);
      var kind=sm?'ul':(l.trim()?'p':null);
      if(!kind)return;
      if(!cur||cur.k!==kind){cur={k:kind,v:[]};blocks.push(cur);}
      cur.v.push(sm?sm[1]:l.trim());
    });
    h+='<li class="rsn-i"><span class="rsn-n">'+esc(it.n||(i+1))+'</span><div class="rsn-t">';
    blocks.forEach(function(b,bi){
      if(b.k==='ul'){h+='<ul class="rsn-sub">'+b.v.map(function(s){return '<li>'+mdInline(s)+'</li>';}).join('')+'</ul>';}
      else{h+=bi?'<p class="rsn-p">'+mdInline(b.v.join(' '))+'</p>':mdInline(b.v.join(' '));}
    });
    h+='</div></li>';
  });
  return h+'</ol>';
}

/* Tool args arrive as "device='x', window_hours='24'". Splitting them into chips
   makes "which host did it actually hunt, over what window" answerable at a glance
   — the question every one of these blank-binding investigations turns on. */
function argChips(args){
  var s=String(args==null?'':args).trim();
  if(!s)return '<span class="targ">no arguments</span>';
  var parts=s.split(/,\s*(?=[A-Za-z_][A-Za-z0-9_]*\s*=)/);
  var ok=parts.every(function(p){return /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(p);});
  if(!ok)return '<span class="targ">'+esc(s)+'</span>';
  return parts.map(function(p){
    var i=p.indexOf('='), k=p.slice(0,i).trim(), v=p.slice(i+1).trim().replace(/^['"]|['"]$/g,'');
    return '<span class="targ">'+esc(k)+' <b>'+esc(v||'—')+'</b></span>';
  }).join('');
}

function fmtStamp(v){return v?String(v).replace('T',' ').slice(0,16):'';}

/* AI verdict vs the humans'. verdict_match is what the accuracy metric counts, and
   it stays null until the closure poller scores the row — so "not yet scored" has
   to be distinguishable from a miss, and from a ticket no human has closed yet. */
function adjudication(sh){
  var ai=sh.ai_triage_class, l1=sh.l1_triage_class, l2=sh.l2_triage_class, m=sh.verdict_match;
  var human=l2||l1, out, col, note;
  if(m===true){out='Match';col='var(--good)';note='Counted as a hit in the shadow-accuracy metric.';}
  else if(m===false){out='Miss';col='var(--crit)';note='Counted against accuracy — AI said <b>'+esc(ai||'—')+'</b>, the human verdict was <b>'+esc(human||'—')+'</b>.';}
  else if(human){out='Not yet scored';col='var(--med)';note='A human verdict is recorded but the closure poller has not scored this row yet.';}
  else{out='Awaiting closure';col='var(--text-dim)';note='No human has resolved this ticket, so there is nothing to score against.';}
  var h='<div class="adj">';
  h+='<div class="adj-c"><div class="adj-k">AI verdict</div><div class="adj-v" style="color:'+(VCOL[ai]||'#8E96A4')+'">'+esc(ai||'—')+'</div>'
    +'<div class="adj-n">'+(sh.ai_confidence!=null?'confidence '+Math.round(sh.ai_confidence*100)+'%':'confidence not recorded')+'</div></div>';
  h+='<div class="adj-c"><div class="adj-k">L1 analyst</div><div class="adj-v" style="color:'+(l1?(VCOL[l1]||'#8E96A4'):'var(--text-faint)')+'">'+esc(l1||'—')+'</div>'
    +'<div class="adj-n">'+(sh.l1_resolved_at?esc(fmtStamp(sh.l1_resolved_at))+(sh.l1_analyst_id?' · '+esc(sh.l1_analyst_id):''):'not resolved')
    +(sh.l1_handoff_at?' · handed to L2':'')+'</div></div>';
  h+='<div class="adj-c"><div class="adj-k">L2 analyst</div><div class="adj-v" style="color:'+(l2?(VCOL[l2]||'#8E96A4'):'var(--text-faint)')+'">'+esc(l2||'—')+'</div>'
    +'<div class="adj-n">'+(sh.l2_resolved_at?esc(fmtStamp(sh.l2_resolved_at)):'not resolved')+'</div></div>';
  h+='<div class="adj-c is-out"><div class="adj-k">Scoring</div><div class="adj-v" style="color:'+col+'">'+esc(out)+'</div><div class="adj-n">'+note+'</div></div>';
  return h+'</div>';
}

function render(a,sh){
  sh=sh||{};
  var cls=sh.ai_triage_class||a.triage_class||'PENDING';var vcol=VCOL[cls]||'#8E96A4';
  var conf=(sh.ai_confidence!=null)?sh.ai_confidence:(a.ai_confidence!=null?a.ai_confidence:a.confidence);
  var reasoning=(sh.ai_reasoning||a.llm_reasoning||'');
  var iters=sh.ai_iterations||0;
  var crumb=document.getElementById('crumb');if(crumb)crumb.textContent='Investigation · '+(a.jira_key||a.alert_id||'');
  if(a.jira_key){var jb=document.getElementById('jiraBtn');if(jb){jb.style.display='';jb.onclick=function(){window.open('https://jira.example.com/browse/'+encodeURIComponent(a.jira_key),'_blank');};}}
  var at=a.alert_time?String(a.alert_time).replace('T',' ').slice(0,16):'';
  // The shadow is the authority on what the agent actually bound: an alert that
  // arrived blank and was re-triaged later carries its device/user here and nowhere
  // else, so falling back to the alert record would show "Unknown" for exactly the
  // tickets whose binding is the thing under question.
  var dev=sh.device_name||a.device_name||'';
  var usr=sh.user_name||a.user_name||'';
  var extraUsers=sh.additional_users||a.additional_users||[];
  var gated=!!sh.blocked_by_safety||(!!sh.pre_safety_class&&!!cls&&sh.pre_safety_class!==cls);
  var h='';
  h+='<div class="fp-eyebrow"><span class="verdict-final" style="padding:4px 10px;border:none;background:'+rgba(vcol,.12)+'"><span class="vf-label" style="font-size:12px;color:'+vcol+'">'+esc(cls)+'</span></span><span class="eyebrow">ReAct'+(iters?' · '+iters+' iterations':'')+' · Bedrock Mantle</span>';
  if(sh.phase)h+='<span class="fchip">phase <b>'+esc(sh.phase)+'</b></span>';
  if(gated)h+='<span class="fchip warn">safety gate applied</span>';
  if(sh.retriaged_at)h+='<span class="fchip">re-triaged <b>'+esc(fmtStamp(sh.retriaged_at))+'</b></span>';
  h+='</div>';
  h+='<h1 class="fp-title">'+esc(a.alert_name||a.alert_id||'Alert')+'</h1>';
  h+='<div class="fp-sub">'+esc(a.jira_key||a.alert_id||'')+(a.severity?' · '+esc(a.severity)+' severity':'')+(a.playbook?' · '+esc(a.playbook):'')+(conf!=null?' · confidence '+Math.round(conf*100)+'%':'')+'</div>';
  // A gate silently rewriting the verdict is the single hardest thing to explain
  // from this page, so it gets stated before the reasoning — the reasoning below
  // argues for pre_safety_class, not for the verdict that shipped.
  if(gated){
    h+='<div class="fp-sect"><div class="gate">'+GATESVG+'<div><div class="gt">'
      +esc(sh.pre_safety_class||'—')+'<span class="arr">→</span>'+esc(cls)
      +'</div><div class="gr">A safety gate overrode the model. The reasoning below argues for <b>'
      +esc(sh.pre_safety_class||'—')+'</b>; the verdict that shipped is <b>'+esc(cls)+'</b>.'
      +(sh.safety_block_reason?'<br>Reason: '+esc(sh.safety_block_reason):'')+'</div></div></div></div>';
  }
  if(sh.ai_error){h+='<div class="fp-sect"><div class="gate" style="border-color:var(--crit);background:rgba(240,85,82,0.08);color:var(--crit)">'+GATESVG+'<div><div class="gt" style="color:var(--crit)">Agent failed</div><div class="gr">'+esc(sh.ai_error)+'<br>The verdict shown is the playbook fallback, not an agent decision.</div></div></div></div>';}
  if(reasoning){h+='<div class="fp-quote">'+reasonHTML(reasoning)+'</div>';}
  // adjudication — AI vs L1 vs L2 vs the metric
  if(sh.found!==false&&(sh.ai_triage_class||sh.l1_triage_class||sh.l2_triage_class)){
    h+='<div class="fp-sect"><div class="section-label"><span class="eyebrow">Adjudication</span><span class="rule"></span></div>'+adjudication(sh)+'</div>';
  }
  // decision path
  h+='<div class="section-label"><span class="eyebrow">Decision path</span><span class="rule"></span></div>';
  h+='<div class="fp-timeline">'
    +'<div class="tl-step"><div class="ts-k">Alert ingested</div><div class="ts-v" style="color:var(--text-dim)">'+esc(a.playbook||'triage')+'</div><div class="ts-note">'+esc(at||'—')+'</div></div>'
    +'<div class="tl-step"><div class="ts-k">Agent investigation</div><div class="ts-v" style="color:var(--accent)">'+((sh.ai_tool_calls||[]).length)+' tool calls</div><div class="ts-note">'+(iters?iters+' iterations':'ReAct')+'</div></div>'
    +'<div class="tl-step"><div class="ts-k">Verdict</div><div class="ts-v" style="color:'+vcol+'">'+esc(cls)+'</div><div class="ts-note">'+(conf!=null?'confidence '+Math.round(conf*100)+'%':'')+'</div></div>'
    +'<div class="tl-step"><div class="ts-k">Action</div><div class="ts-v" style="color:var(--text-dim)">'+esc(a.action_taken||'advisory comment')+'</div><div class="ts-note">'+(a.is_test_device?'test device':'ticket state per phase')+'</div></div>'
    +'</div>';
  // full trace
  var calls=sh.ai_tool_calls||[];
  if(calls.length){
    h+='<div class="fp-sect"><div class="section-label"><span class="eyebrow">Agent investigation · full trace</span><span class="rule"></span></div><div class="trace">';
    h+='<div class="trace-step think"><div class="trace-node">'+THINKSVG+'</div><div class="trace-body"><div class="trace-kind">Think</div><div class="trace-text">Investigated the alert with the tools below, then emitted a verdict.</div></div></div>';
    calls.forEach(function(c){
      var res=String(c.result==null?'':c.result).trim();
      // An empty result is the finding, not a blank field — most of the thin verdicts
      // in this family come from a hunt that returned nothing, so say so.
      var none=!res||/^(0 rows|no |none|not seen|not found)/i.test(res);
      h+='<div class="trace-step"><div class="trace-node">'+ACTSVG+'</div><div class="trace-body"><div class="trace-kind">Act · tool</div>'
        +'<div class="tool-call tcall"><span class="tool-name">'+esc(c.name||'')+'</span>'+argChips(c.args)+'</div>'
        +'<div class="tres"><span class="rk">returned</span><span class="rv'+(none?' none':'')+'">'+esc(res||'nothing')+'</span></div>'
        +'</div></div>';
    });
    var adv=(sh.phase==='autonomous')?'autonomous · the agent acts on this verdict'
      :(sh.phase==='shadow')?'shadow · recorded only, nothing written to the ticket'
      :'advisory · L1 retains the decision';
    h+='<div class="trace-step final"><div class="trace-node">'+VSVG+'</div><div class="trace-body"><div class="trace-kind" style="color:var(--good)">Verdict</div>'
      +'<div class="verdict-final"><span class="vf-label" style="color:'+vcol+'">'+esc(cls)+'</span>'+(conf!=null?'<span class="vf-conf">conf <b>'+(+conf).toFixed(2)+'</b></span>':'')+'<span class="spacer"></span><span class="vf-advisory">'+esc(adv)+'</span></div></div></div>';
    h+='</div></div>';
  }
  // columns: comment/reasoning | provenance/entities/VT
  var left='';
  if(a.l1_comment){left+=jiraPanel(a);}
  if(reasoning){left+='<div class="fp-sect"'+(a.l1_comment?'':' style="margin-top:0"')+'><div class="ai-block"><div class="ah">'+SPARK+'AI reasoning · Mistral Large 3</div>'+reasonHTML(reasoning)+'</div></div>';}
  if(a.l2_comment){left+='<div class="fp-sect"><div class="section-label"><span class="eyebrow">L2 comment / draft</span><span class="rule"></span></div><div class="cmd">'+esc(a.l2_comment)+'</div></div>';}
  var right='<div class="fp-sect" style="margin-top:0"><div class="section-label"><span class="eyebrow">Provenance</span><span class="rule"></span></div><div class="meta-grid">'
    +cell('Device',dev||'unbound')+cell('User',usr||'unbound')
    +(extraUsers.length?cell('Co-actors',extraUsers.join(' · '),'',true):'')
    +metaJira(a.jira_key)
    +cell('Alert time',at||'—')
    +(sh.retriaged_at?cell('Re-triaged',fmtStamp(sh.retriaged_at)):'')
    +(a.action_taken?cell('Action',a.action_taken):'')
    +(a.file_name?cell('File',a.file_name):'')
    +(a.sha256?cell('SHA-256',String(a.sha256).slice(0,44)+(String(a.sha256).length>44?'…':''),'',true):'')
    +((a.labels_applied&&a.labels_applied.length)?cell('Labels',a.labels_applied.join(' · '),'',true):'')
    +'</div></div>';
  var ents='';
  if(dev)ents+=ent('device',dev);
  if(usr)ents+=ent('user',usr);
  extraUsers.forEach(function(u){ents+=ent('co-actor',u);});
  if(a.sha256)ents+=ent('sha256',String(a.sha256).slice(0,12)+'…');
  if(ents)right+='<div class="fp-sect"><div class="section-label"><span class="eyebrow">Entities</span><span class="rule"></span></div><div class="ents">'+ents+'</div></div>';
  if(a.vt_detections!=null&&a.vt_total){var p=Math.round(a.vt_detections/a.vt_total*100);var vok=a.vt_detections===0;var vc=vok?'var(--good)':'var(--crit)';
    right+='<div class="fp-sect"><div class="section-label"><span class="eyebrow">VirusTotal</span><span class="rule"></span></div><div class="vt-card"><div class="vt-ring" style="background:conic-gradient('+vc+' '+p+'%, var(--line) 0)"><b style="color:'+vc+'">'+a.vt_detections+'</b></div><div class="vt-info"><div class="a">'+a.vt_detections+' / '+a.vt_total+' engines flagged</div><div class="b">verdict: '+esc(a.vt_verdict||'—')+'</div></div></div></div>';}
  h+='<div class="fp-cols"><div class="fp-block">'+(left||'<div class="prev-empty">No comment or reasoning recorded.</div>')+'</div><div class="fp-block">'+right+'</div></div>';
  document.getElementById('wrap').innerHTML=h;
}

fetch('/api/edr-triage/alerts/'+encodeURIComponent(ALERT_ID)).then(function(r){if(!r.ok)return r.json().then(function(e){throw new Error(e.detail||('HTTP '+r.status));});return r.json();})
  .then(function(a){
    if(a.jira_key){fetch('/api/edr-triage/shadow/'+encodeURIComponent(a.jira_key)).then(function(r){return r.json();}).then(function(sh){render(a,(sh&&sh.found)?sh:null);}).catch(function(){render(a,null);});}
    else{render(a,null);}
  }).catch(function(e){document.getElementById('wrap').innerHTML='<div class="prev-empty" style="color:var(--crit)">'+esc(String(e.message||e))+'</div>';});

</script>
</body>
</html>"""


def _render_settings_page() -> str:
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Settings — RAPTOR</title>
<style>
  :root {
    --ground: #080A0E;
    --surface: #12151B;
    --surface-2: #181C24;
    --surface-3: #1E2430;
    --line: #252B36;
    --line-soft: #1A1F28;
    --text: #DDE1E8;
    --text-bright: #F3F6FB;
    --text-dim: #8E96A4;
    --text-faint: #59616E;
    --accent: #9E86F0;
    --accent-deep: #5B3FB0;
    --accent-glow: rgba(158,134,240,0.12);
    --crit: #F05552;
    --high: #E8913A;
    --med: #E6C34C;
    --low: #6C93C0;
    --good: #46B87A;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, system-ui, sans-serif;
    --font-mono: "SF Mono", ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
    --r: 6px;
  }

  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body {
    background: var(--ground);
    color: var(--text);
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }
  /* faint radar grid over the ground */
  body::before {
    content: "";
    position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image:
      linear-gradient(var(--line-soft) 1px, transparent 1px),
      linear-gradient(90deg, var(--line-soft) 1px, transparent 1px);
    background-size: 48px 48px;
    opacity: 0.35;
    mask-image: radial-gradient(ellipse 90% 70% at 70% 0%, #000 30%, transparent 75%);
  }

  .num { font-variant-numeric: tabular-nums; font-family: var(--font-mono); }
  .mono { font-family: var(--font-mono); }
  .eyebrow {
    font-family: var(--font-sans);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-faint);
  }

  a { color: inherit; text-decoration: none; }
  button { font-family: inherit; cursor: pointer; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 3px; }

  /* ---------- shell ---------- */
  .app {
    position: relative; z-index: 1;
    display: grid;
    grid-template-columns: 66px 1fr;
    height: 100vh;
  }

  /* ---------- rail ---------- */
  .rail {
    position: sticky; top: 0; height: 100vh; z-index: 30;
    display: flex; flex-direction: column; align-items: center;
    gap: 6px; padding: 16px 0;
    background: linear-gradient(180deg, #0C1116, #090C10);
    border-right: 1px solid var(--line);
  }
  .glyph { width: 38px; height: 38px; border-radius: 11px; display: grid; place-items: center; margin-bottom: 14px; background: linear-gradient(160deg, var(--surface-3), var(--surface)); border: 1px solid var(--line); }
  .glyph svg { width: 20px; height: 20px; }
  .navbtn { width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; color: var(--text-faint); cursor: pointer; position: relative; transition: .16s; border: 1px solid transparent; background: transparent; -webkit-appearance: none; appearance: none; }
  .navbtn svg { width: 19px; height: 19px; }
  .navbtn:hover { color: var(--text-dim); background: var(--surface-2); }
  .navbtn.active { color: var(--accent); background: var(--accent-glow); border-color: var(--accent-deep); }
  .navbtn.active::before { content: ""; position: absolute; left: -16px; top: 9px; bottom: 9px; width: 3px; border-radius: 3px; background: var(--accent); }
  .rail .spacer { flex: 1; }
  .tip { position: absolute; left: 52px; white-space: nowrap; background: var(--surface-3); border: 1px solid var(--line); color: var(--text); font-size: 12px; padding: 5px 9px; border-radius: 8px; opacity: 0; pointer-events: none; transform: translateX(-4px); transition: .14s; z-index: 40; }
  .navbtn:hover .tip { opacity: 1; transform: translateX(0); }
  .brand-mark {
    width: 34px; height: 34px; margin-bottom: 16px;
    color: var(--accent);
    filter: drop-shadow(0 0 8px var(--accent-glow));
  }
  .rail-btn {
    position: relative;
    width: 42px; height: 40px;
    display: flex; align-items: center; justify-content: center;
    color: var(--text-faint);
    background: transparent; border: 0; border-radius: var(--r);
    transition: color .15s, background .15s;
  }
  .rail-btn:hover { color: var(--text-dim); background: var(--surface-2); }
  .rail-btn.active { color: var(--accent); background: var(--accent-glow); }
  .rail-btn.active::before {
    content: ""; position: absolute; left: -14px; top: 8px; bottom: 8px;
    width: 3px; border-radius: 3px; background: var(--accent);
    box-shadow: 0 0 10px var(--accent);
  }
  .rail-btn svg { width: 19px; height: 19px; }
  .rail-spacer { flex: 1; }
  .rail-tip {
    position: absolute; left: 52px; white-space: nowrap;
    background: var(--surface-3); border: 1px solid var(--line);
    color: var(--text); font-size: 11px; padding: 3px 8px; border-radius: 4px;
    opacity: 0; transform: translateX(-4px); pointer-events: none; transition: .12s;
    font-family: var(--font-mono); letter-spacing: .02em; z-index: 20;
  }
  .rail-btn:hover .rail-tip { opacity: 1; transform: translateX(0); }

  /* ---------- main ---------- */
  .main { display: grid; grid-template-rows: auto 1fr; min-width: 0; }

  .topbar {
    display: flex; align-items: center; gap: 20px;
    padding: 0 20px; height: 54px;
    border-bottom: 1px solid var(--line);
    background: rgba(12,17,22,0.7); backdrop-filter: blur(6px);
  }
  .title-block { display: flex; flex-direction: column; gap: 1px; }
  .title-block h1 {
    margin: 0; font-size: 15px; font-weight: 650; letter-spacing: 0.02em;
    display: flex; align-items: center; gap: 9px;
  }
  .title-block .wm { font-family: var(--font-mono); letter-spacing: 0.16em; }
  .title-block .wm b { color: var(--accent); font-weight: 650; }

  .topbar-spacer { flex: 1; }

  .boundary-status {
    display: flex; align-items: center; gap: 14px;
    padding: 6px 12px; border: 1px solid var(--line);
    border-radius: var(--r); background: var(--surface);
  }
  .zone { display: flex; align-items: center; gap: 7px; }
  .zone .eyebrow { color: var(--text-dim); }
  .dot { width: 8px; height: 8px; border-radius: 50%; position: relative; }
  .dot.on { background: var(--good); box-shadow: 0 0 0 3px rgba(70,184,122,0.16); }
  .dot.cloud { background: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  .dot.live::after {
    content: ""; position: absolute; inset: -3px; border-radius: 50%;
    border: 1px solid currentColor; animation: ping 2.4s ease-out infinite;
  }
  .zone.on-prem .dot.live::after { color: var(--good); }
  .zone.cloud .dot.live::after { color: var(--accent); }
  @keyframes ping { 0% { transform: scale(1); opacity: .7; } 100% { transform: scale(2.4); opacity: 0; } }
  .zone-sep { width: 1px; height: 22px; background: var(--line); }

  .meter-group { display: flex; align-items: center; gap: 16px; }
  .meter { display: flex; flex-direction: column; gap: 4px; min-width: 142px; }
  .meter-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
  .meter-head .val { font-family: var(--font-sans); font-size: 12px; font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }
  .meter-track { height: 4px; border-radius: 2px; background: var(--surface-3); overflow: hidden; }
  .meter-fill { height: 100%; border-radius: 2px; width: 0; transition: width 1.1s cubic-bezier(.2,.7,.2,1); }

  .phase-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.08em;
    color: var(--accent); background: var(--accent-glow);
    border: 1px solid var(--accent-deep); border-radius: 20px; padding: 4px 11px;
  }

  /* ---------- content ---------- */
  .content { overflow: auto; padding: 18px 20px 40px; }

  /* KPI strip */
  .kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin-bottom: 18px; }
  .kpi {
    position: relative; overflow: hidden;
    background: linear-gradient(180deg, var(--surface-2), var(--surface));
    border: 1px solid var(--line); border-radius: var(--r);
    padding: 13px 15px; display: flex; flex-direction: column; gap: 7px;
    box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset, 0 10px 26px -18px rgba(0,0,0,0.85);
    transition: transform .16s, border-color .16s;
  }
  .kpi::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--kpi-accent, var(--line-2)); }
  .kpi:hover { transform: translateY(-2px); border-color: var(--line-2); }
  .kpi .eyebrow { color: var(--text-faint); }
  .kpi .figure { font-family: var(--font-sans); font-size: 28px; font-weight: 700; letter-spacing: -0.025em; line-height: 1; color: var(--text-bright); font-variant-numeric: tabular-nums; }
  .kpi .sub { font-family: var(--font-sans); font-size: 11.5px; color: var(--text-dim); }
  .kpi .sub b { color: var(--good); font-weight: 600; }
  .kpi.attn .figure { color: var(--high); }
  .kpi.crit .figure { color: var(--crit); }
  .kpi .spark { height: 22px; margin-top: 2px; }

  /* work area */
  .work { display: block; }
  @media (max-width: 1180px) { .work { grid-template-columns: 1fr; } }

  .panel { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; box-shadow: 0 14px 38px -24px rgba(0,0,0,0.9); }
  .panel-head {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 14px; border-bottom: 1px solid var(--line);
  }
  .panel-head h2 { margin: 0; font-size: 12px; font-weight: 600; letter-spacing: 0.02em; }
  .panel-head .count {
    font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);
    background: var(--surface-3); border-radius: 20px; padding: 2px 9px;
  }
  .panel-head .spacer { flex: 1; }
  .ph-btn {
    font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.04em;
    color: var(--text-dim); background: var(--surface-2);
    border: 1px solid var(--line); border-radius: 5px; padding: 4px 9px;
    display: inline-flex; align-items: center; gap: 5px; transition: .15s;
  }
  .ph-btn:hover { color: var(--text); border-color: var(--accent-deep); }
  .ph-btn svg { width: 13px; height: 13px; }

  /* queue table */
  .q-wrap { overflow-x: auto; }
  table.queue { width: 100%; border-collapse: collapse; }
  table.queue thead th {
    font-family: var(--font-sans); font-size: 10px; letter-spacing: 0.05em; text-transform: uppercase;
    color: var(--text-faint); font-weight: 600; text-align: left;
    padding: 9px 10px; border-bottom: 1px solid var(--line); white-space: nowrap;
  }
  table.queue tbody td { padding: 10px 10px; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }
  table.queue tbody td:first-child { box-shadow: inset 3px 0 0 var(--sevcol, transparent); }
  .c-dev, .c-usr { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); max-width: 168px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .c-usr { color: var(--text-faint); }
  table.queue tbody tr { cursor: pointer; transition: background .12s; position: relative; }
  table.queue tbody tr:hover { background: var(--surface-2); }
  table.queue tbody tr.sel { background: linear-gradient(90deg, var(--accent-glow), transparent 60%); }
  table.queue tbody tr.sel td:first-child { box-shadow: inset 3px 0 0 var(--accent); }

  .tkt { font-family: var(--font-mono); font-size: 11.5px; color: var(--text); } a.tkt { cursor: pointer; } a.tkt:hover { color: var(--accent); text-decoration: underline; } .jl { color: var(--good); text-decoration: none; } .jl:hover { text-decoration: underline; }
  .alert-name { font-size: 13px; color: var(--text-bright); font-weight: 500; }
  .alert-name .whom { font-family: var(--font-mono); font-size: 10.5px; color: var(--text-faint); display: block; margin-top: 2px; }

  .sev { display: inline-flex; align-items: center; gap: 7px; font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.05em; }
  .sev::before { content: ""; width: 3px; height: 13px; border-radius: 2px; background: currentColor; }
  .sev.crit { color: var(--crit); } .sev.high { color: var(--high); }
  .sev.med { color: var(--med); } .sev.low { color: var(--low); } .sev.info { color: var(--text-faint); }

  .verdict {
    font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.03em;
    padding: 3px 8px; border-radius: 4px; border: 1px solid; white-space: nowrap;
  }
  .verdict.fp { color: var(--good); border-color: rgba(70,184,122,0.4); background: rgba(70,184,122,0.08); }
  .verdict.tp { color: var(--high); border-color: rgba(232,145,58,0.4); background: rgba(232,145,58,0.08); }
  .verdict.l2 { color: var(--low); border-color: rgba(108,147,192,0.4); background: rgba(108,147,192,0.08); }
  .verdict.urgent { color: #fff; border-color: var(--crit); background: var(--crit); font-weight: 600; }

  .conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }
  .backend {
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.06em; text-transform: uppercase;
    color: var(--text-dim); display: inline-flex; align-items: center; gap: 5px;
  }
  .backend svg { width: 11px; height: 11px; }
  .backend.onprem { color: var(--good); }
  .backend.cloudb { color: var(--accent); }
  .t-ago { font-family: var(--font-mono); font-size: 11px; color: var(--text-faint); text-align: right; }

  /* ---------- detail panel ---------- */
  .detail .panel-head .tkt-lg { font-family: var(--font-mono); font-size: 13px; color: var(--accent); }
  .detail-body { padding: 14px; display: flex; flex-direction: column; gap: 16px; }

  .d-headline { display: flex; flex-direction: column; gap: 8px; }
  .d-headline .name { font-size: 15px; font-weight: 600; letter-spacing: 0.01em; }
  .d-meta { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip {
    font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.04em;
    color: var(--text-dim); border: 1px solid var(--line); border-radius: 4px; padding: 2px 7px;
  }
  .chip.mitre { color: var(--text); border-color: var(--accent-deep); }

  .section-label { display: flex; align-items: center; gap: 8px; margin-bottom: 9px; }
  .section-label .eyebrow { color: var(--text-dim); }
  .section-label .rule { flex: 1; height: 1px; background: var(--line); }

  /* boundary visualization */
  .boundary {
    border: 1px solid var(--line); border-radius: 7px; overflow: hidden;
    background: var(--surface-2);
  }
  .boundary-grid { display: grid; grid-template-columns: 1fr 30px 1fr; }
  .bzone { padding: 11px 12px; }
  .bzone.regulated { background: rgba(70,184,122,0.045); }
  .bzone.cloudzone { background: rgba(158,134,240,0.04); }
  .bzone .bz-head {
    display: flex; align-items: center; gap: 6px; margin-bottom: 9px;
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.08em; text-transform: uppercase;
  }
  .bzone.regulated .bz-head { color: var(--good); }
  .bzone.cloudzone .bz-head { color: var(--accent); }
  .bzone .bz-head svg { width: 12px; height: 12px; }
  .bz-row { font-family: var(--font-mono); font-size: 10.5px; line-height: 1.9; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bz-row .k { color: var(--text-faint); }
  .bz-row .real { color: var(--text); }
  .bz-row .tok { color: var(--accent); }
  .bz-row .red { color: var(--high); }
  .bz-row .kept { color: var(--good); }
  .b-divider { position: relative; }
  .b-divider::before {
    content: ""; position: absolute; left: 50%; top: 6px; bottom: 6px; width: 0;
    border-left: 1px dashed var(--accent-deep); transform: translateX(-50%);
  }
  .b-divider .arrow {
    position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%);
    color: var(--accent); width: 16px; height: 16px;
  }
  .b-caption {
    padding: 7px 12px; border-top: 1px solid var(--line);
    font-family: var(--font-mono); font-size: 10px; color: var(--text-faint); letter-spacing: 0.02em;
  }
  .b-caption b { color: var(--good); font-weight: 500; }

  /* agent trace */
  .trace { display: flex; flex-direction: column; gap: 0; }
  .trace-step { display: grid; grid-template-columns: 20px 1fr; gap: 10px; padding: 0 0 14px; position: relative; }
  .trace-step:not(:last-child)::before {
    content: ""; position: absolute; left: 9px; top: 18px; bottom: 0; width: 1px; background: var(--line);
  }
  .trace-node {
    width: 19px; height: 19px; border-radius: 50%; z-index: 1;
    display: flex; align-items: center; justify-content: center;
    background: var(--surface-3); border: 1px solid var(--line);
  }
  .trace-node svg { width: 11px; height: 11px; color: var(--text-dim); }
  .trace-step.think .trace-node { border-color: var(--accent-deep); }
  .trace-step.think .trace-node svg { color: var(--accent); }
  .trace-step.final .trace-node { background: var(--accent); border-color: var(--accent); }
  .trace-step.final .trace-node svg { color: #06110F; }
  .trace-body { min-width: 0; }
  .trace-kind {
    font-family: var(--font-mono); font-size: 9.5px; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--text-faint); margin-bottom: 3px;
  }
  .trace-step.think .trace-kind { color: var(--accent); }
  .trace-text { font-size: 12px; color: var(--text-dim); }
  .tool-call {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    font-family: var(--font-mono); font-size: 11px;
  }
  .tool-name { color: var(--text); background: var(--surface-3); border: 1px solid var(--line); border-radius: 4px; padding: 2px 7px; }
  .tool-arg { color: var(--text-faint); }
  .tool-res { color: var(--text-dim); }
  .tool-res .ok { color: var(--good); } .tool-res .flag { color: var(--high); }

  .verdict-final {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
    padding: 11px 13px; border-radius: 7px;
    background: rgba(70,184,122,0.07); border: 1px solid rgba(70,184,122,0.3);
  }
  .verdict-final .vf-label { font-family: var(--font-mono); font-size: 15px; letter-spacing: 0.04em; color: var(--good); font-weight: 600; }
  .verdict-final .vf-conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }
  .verdict-final .vf-conf b { color: var(--text); }
  .verdict-final .spacer { flex: 1; }
  .vf-actions { display: flex; gap: 7px; }
  .vf-btn { font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.03em; padding: 6px 12px; border-radius: 5px; border: 1px solid var(--line); background: var(--surface-2); color: var(--text-dim); transition: .15s; }
  .vf-btn:hover { color: var(--text); }
  .vf-btn.primary { background: var(--accent); border-color: var(--accent); color: #06110F; font-weight: 600; }
  .vf-btn.primary:hover { filter: brightness(1.08); }
  .vf-advisory { font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text-faint); border: 1px dashed var(--line); border-radius: 4px; padding: 4px 9px; white-space: nowrap; }

  /* SCG memory precedents */
  .mem { display: flex; flex-direction: column; gap: 8px; }
  .mem-row {
    display: grid; grid-template-columns: auto 1fr auto; gap: 11px; align-items: center;
    padding: 9px 11px; border: 1px solid var(--line); border-radius: 6px; background: var(--surface-2);
  }
  .tier { font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; padding: 3px 7px; border-radius: 3px; text-transform: uppercase; }
  .tier.golden { color: var(--med); background: rgba(230,195,76,0.1); border: 1px solid rgba(230,195,76,0.35); }
  .tier.curated { color: var(--accent); background: var(--accent-glow); border: 1px solid var(--accent-deep); }
  .mem-txt { font-size: 12px; color: var(--text-dim); min-width: 0; }
  .mem-txt .m-tkt { font-family: var(--font-mono); font-size: 11px; color: var(--text); }
  .mem-txt .m-note { display: block; font-size: 11px; color: var(--text-faint); margin-top: 2px; }
  .mem-conf { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); text-align: right; }
  .mem-conf small { display: block; color: var(--text-faint); font-size: 9px; letter-spacing: 0.08em; }

  @media (prefers-reduced-motion: reduce) {
    * { animation: none !important; transition: none !important; }
    .meter-fill { transition: none; }
  }

  /* ---- topbar action buttons ---- */
  .tb-actions { display:flex; align-items:center; gap:7px; }
  .btn { display:inline-flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:11px; letter-spacing:0.03em; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); border-radius:5px; padding:6px 10px; transition:.15s; white-space:nowrap; }
  .btn svg { width:13px; height:13px; }
  .btn:hover { color:var(--text); border-color:var(--accent-deep); }
  .btn.primary { color:#06110F; background:var(--accent); border-color:var(--accent); font-weight:600; }
  .btn.primary:hover { filter:brightness(1.08); }
  .btn.danger { color:var(--crit); border-color:rgba(240,85,82,0.35); background:rgba(240,85,82,0.06); }
  .btn.danger:hover { background:rgba(240,85,82,0.12); }

  /* ---- queue sub-toolbar ---- */
  .subbar { display:flex; align-items:center; gap:9px; padding:9px 12px; border-bottom:1px solid var(--line); flex-wrap:wrap; }
  .seg { display:flex; background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:2px; gap:2px; }
  .seg button { font-family:var(--font-mono); font-size:10.5px; letter-spacing:0.02em; color:var(--text-dim); background:none; border:0; padding:4px 9px; border-radius:3px; transition:.13s; white-space:nowrap; }
  .seg button:hover { color:var(--text); }
  .seg button.on { background:var(--surface-3); color:var(--text); }
  .seg .cnt { color:var(--text-faint); margin-left:4px; }
  .seg button.on .cnt { color:var(--accent); }
  .search { display:flex; align-items:center; gap:7px; background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:5px 9px; min-width:150px; flex:1; }
  .search:focus-within { border-color:var(--accent-deep); }
  .search svg { width:13px; height:13px; color:var(--text-faint); flex:none; }
  .search input { background:none; border:0; outline:none; color:var(--text); font-size:12px; width:100%; font-family:var(--font-sans); }
  .search input::placeholder { color:var(--text-faint); }
  .tgl { display:inline-flex; align-items:center; gap:7px; font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:5px 9px; cursor:pointer; user-select:none; white-space:nowrap; }
  .tgl .sw { width:26px; height:15px; border-radius:20px; background:var(--surface-3); border:1px solid var(--line); position:relative; transition:.15s; flex:none; }
  .tgl .sw::before { content:""; position:absolute; left:2px; top:1.5px; width:10px; height:10px; border-radius:50%; background:var(--text-faint); transition:.15s; }
  .tgl.on { color:var(--text); }
  .tgl.on .sw { background:var(--accent-glow); border-color:var(--accent-deep); }
  .tgl.on .sw::before { transform:translateX(11px); background:var(--accent); }

  /* ---- pager ---- */
  .pager-bar { display:flex; align-items:center; justify-content:space-between; padding:9px 12px; border-top:1px solid var(--line); }
  .pager-bar .pi { font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); }
  .pager { display:flex; gap:6px; }
  .pager button { font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); padding:5px 10px; border-radius:4px; transition:.13s; }
  .pager button:hover:not(:disabled) { color:var(--text); border-color:var(--accent-deep); }
  .pager button:disabled { opacity:.35; }
  .pb { font-family:var(--font-mono); font-size:10.5px; color:var(--text-dim); }

  /* ---- detail: verdict / meta / VT / comments / reasoning ---- */
  .verdict-top { display:flex; align-items:center; gap:11px; padding:11px 13px; border-radius:7px; border:1px solid; }
  .verdict-top .vt-dot { width:9px; height:9px; border-radius:50%; flex:none; }
  .verdict-top .vt-name { font-family:var(--font-mono); font-size:14px; font-weight:600; letter-spacing:0.03em; }
  .verdict-top .vt-conf { margin-left:auto; font-family:var(--font-mono); font-size:11px; color:var(--text-dim); }
  .meta-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
  .meta { background:var(--surface-2); border:1px solid var(--line); border-radius:6px; padding:9px 11px; min-width:0; }
  .meta .mk { font-family:var(--font-sans); font-size:9.5px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:var(--text-faint); margin-bottom:4px; }
  .meta .mv { font-family:var(--font-mono); font-size:11.5px; color:var(--text); word-break:break-word; }
  .meta.full { grid-column:1 / -1; }
  .vt-card { display:flex; align-items:center; gap:12px; background:var(--surface-2); border:1px solid var(--line); border-radius:7px; padding:11px 13px; }
  .vt-ring { width:42px; height:42px; border-radius:50%; flex:none; display:grid; place-items:center; }
  .vt-ring b { width:32px; height:32px; border-radius:50%; background:var(--surface); display:grid; place-items:center; font-family:var(--font-mono); font-size:12px; font-weight:600; }
  .vt-info .a { font-size:12.5px; color:var(--text); }
  .vt-info .b { font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); margin-top:2px; }
  .cmd { background:var(--ground); border:1px solid var(--line); border-radius:6px; padding:11px 12px; font-family:var(--font-mono); font-size:11px; color:#b7c6d8; white-space:pre-wrap; word-break:break-word; line-height:1.6; }
  /* Mock Jira panel — the exact comment/transition/labels RAPTOR posts to the ticket */
  .jira-card { border:1px solid var(--line); border-radius:8px; overflow:hidden; background:var(--surface); }
  .jira-head { display:flex; align-items:center; gap:10px; padding:9px 12px; border-bottom:1px solid var(--line); background:var(--surface-2); }
  .jira-key { font-family:var(--font-mono); font-size:12px; font-weight:600; color:var(--accent); }
  .jira-mock { font-family:var(--font-mono); font-size:9px; letter-spacing:0.06em; text-transform:uppercase; color:var(--text-faint); border:1px solid var(--line); border-radius:3px; padding:2px 6px; }
  .jira-head .spacer { flex:1; }
  .jira-trans { font-family:var(--font-mono); font-size:10.5px; padding:3px 9px; border:1px solid; border-radius:20px; white-space:nowrap; }
  .jira-labels { display:flex; flex-wrap:wrap; gap:6px; padding:10px 12px 0; }
  .jira-chip { font-family:var(--font-mono); font-size:10px; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--line); border-radius:4px; padding:2px 8px; }
  .jira-comment { padding:11px 12px 12px; }
  .jira-comment-head { display:flex; align-items:center; gap:8px; font-size:11px; color:var(--text-dim); margin-bottom:9px; }
  .jira-avatar { width:20px; height:20px; border-radius:50%; background:var(--accent); color:#0b0d11; font-weight:700; font-size:11px; display:flex; align-items:center; justify-content:center; }
  .jira-comment-body { font-size:12.5px; color:var(--text); line-height:1.55; }
  .jira-comment-body .jira-h { font-weight:600; color:var(--text); margin:11px 0 5px; font-size:12.5px; }
  .jira-comment-body .jira-h:first-child { margin-top:0; }
  .jira-comment-body .jira-p { margin:4px 0; color:var(--text-dim); }
  .jira-comment-body .jira-ul { margin:4px 0 4px 2px; padding:0; list-style:none; }
  .jira-comment-body .jira-ul li { position:relative; padding-left:14px; margin:3px 0; color:var(--text-dim); }
  .jira-comment-body .jira-ul li::before { content:"\2022"; position:absolute; left:2px; color:var(--accent); }
  .jira-comment-body .jira-pre { background:var(--ground); border:1px solid var(--line); border-radius:5px; padding:8px 10px; font-family:var(--font-mono); font-size:10.5px; color:var(--text-faint); white-space:pre-wrap; margin:8px 0 0; }
  .ai-block { background:var(--accent-glow); border:1px solid var(--accent-deep); border-radius:7px; padding:12px 13px; }
  .ai-block .ah { display:flex; align-items:center; gap:7px; font-family:var(--font-mono); font-size:10px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; color:var(--accent); margin-bottom:8px; }
  .ai-block .ah svg { width:12px; height:12px; }
  .ai-block pre { margin:0; font-family:var(--font-mono); font-size:11px; line-height:1.65; color:#cdbff5; white-space:pre-wrap; word-break:break-word; }

  /* ---- shared preview head + entities + full-page (consistency with AI Memory) ---- */
  .prev-head { display: flex; align-items: center; gap: 10px; padding: 11px 14px; border-bottom: 1px solid var(--line); }
  .prev-head .pref { font-family: var(--font-mono); font-size: 13px; color: var(--accent); }
  .ents { display: flex; flex-wrap: wrap; gap: 7px; }
  .ent { display: inline-flex; align-items: center; gap: 6px; font-family: var(--font-mono); font-size: 10.5px; color: var(--text-dim); background: var(--surface-2); border: 1px solid var(--line); border-radius: 5px; padding: 4px 8px; }
  .ent svg { width: 11px; height: 11px; color: var(--accent); }
  .fullpage { position: fixed; inset: 0; z-index: 80; background: var(--ground); overflow: auto; display: none; }
  .fullpage.on { display: block; }
  .fp-bar { position: sticky; top: 0; z-index: 2; display: flex; align-items: center; gap: 14px; padding: 0 24px; height: 54px; border-bottom: 1px solid var(--line); background: rgba(11,13,17,0.85); backdrop-filter: blur(6px); }
  .fp-back { display: inline-flex; align-items: center; gap: 7px; font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); cursor: pointer; }
  .fp-back:hover { color: var(--text); }
  .fp-wrap { max-width: 1060px; margin: 0 auto; padding: 26px 24px 60px; }
  .fp-eyebrow { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .fp-title { font-size: 22px; font-weight: 650; letter-spacing: 0.01em; margin: 0 0 6px; }
  .fp-sub { font-family: var(--font-mono); font-size: 11.5px; color: var(--text-dim); }
  .fp-quote { border: 1px solid var(--line); border-left: 3px solid var(--accent); background: var(--surface); border-radius: 0 8px 8px 0; padding: 16px 18px; font-size: 14px; line-height: 1.65; color: var(--text); margin: 20px 0; }
  .fp-timeline { display: flex; align-items: stretch; gap: 0; margin: 18px 0; flex-wrap: wrap; }
  .tl-step { flex: 1; min-width: 150px; border: 1px solid var(--line); background: var(--surface); border-radius: 7px; padding: 12px 14px; position: relative; }
  .tl-step + .tl-step { margin-left: 22px; }
  .tl-step + .tl-step::before { content: "\2192"; position: absolute; left: -18px; top: 50%; transform: translateY(-50%); color: var(--text-faint); font-family: var(--font-mono); }
  .tl-step .ts-k { font-family: var(--font-mono); font-size: 9px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-faint); margin-bottom: 6px; }
  .tl-step .ts-v { font-family: var(--font-mono); font-size: 13px; font-weight: 600; }
  .tl-step .ts-note { font-size: 11px; color: var(--text-dim); margin-top: 4px; }
  .fp-cols { display: grid; grid-template-columns: 1.3fr 1fr; gap: 20px; align-items: start; margin-top: 8px; }
  @media (max-width: 900px) { .fp-cols { grid-template-columns: 1fr; } }
  .fp-actions { display: flex; gap: 9px; margin-top: 24px; flex-wrap: wrap; align-items: center; }
  .fp-sect { margin-top: 22px; }
  .fp-sect > .section-label { margin-bottom: 12px; }
  .trace-cmd { margin: 6px 0 2px 30px; }

  /* ---- investigation drawer (preview, ~560px slide-over) ---- */
  .overlay { position: fixed; inset: 0; background: rgba(4,7,11,0.6); backdrop-filter: blur(3px); opacity: 0; pointer-events: none; transition: .2s; z-index: 70; }
  .overlay.open { opacity: 1; pointer-events: auto; }
  .drawer { position: fixed; top: 0; right: 0; height: 100vh; width: min(560px, 94vw); background: var(--surface); border-left: 1px solid var(--line); transform: translateX(100%); transition: transform .26s cubic-bezier(.4,0,.2,1); z-index: 75; display: flex; flex-direction: column; box-shadow: -30px 0 60px rgba(0,0,0,.5); }
  .drawer.open { transform: translateX(0); }
  .dhead { padding: 15px 18px 13px; border-bottom: 1px solid var(--line); flex: 0 0 auto; }
  .dh-top { display: flex; align-items: center; justify-content: space-between; }
  .dx { cursor: pointer; color: var(--text-faint); font-size: 20px; line-height: 1; padding: 0 4px; }
  .dx:hover { color: var(--text); }
  .dstrip { display: flex; align-items: center; gap: 7px; margin-top: 11px; }
  .dbody { padding: 16px 18px 40px; overflow-y: auto; flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; gap: 15px; }
  .dbody > * { flex-shrink: 0; }
</style>
<style>
  .ro-pill{font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;text-transform:uppercase;color:var(--text-faint);border:1px solid var(--line);border-radius:20px;padding:2px 9px;display:inline-flex;align-items:center;gap:5px;}
  .ro-pill svg{width:10px;height:10px;}
  .lock-note{font-family:var(--font-mono);font-size:10.5px;color:var(--text-faint);display:flex;align-items:center;gap:6px;}
  .lock-note svg{width:12px;height:12px;}
  .sec-pad{padding:16px;}
  .stackgap{display:flex;flex-direction:column;gap:16px;max-width:1100px;}
  .spendrow{display:flex;align-items:baseline;gap:10px;margin-bottom:10px;}
  .spendrow .big{font-family:var(--font-sans);font-size:26px;font-weight:700;color:var(--text-bright);}
  .spendrow .cap{font-family:var(--font-mono);font-size:12px;color:var(--text-dim);}
  .bigtrack{height:7px;border-radius:5px;background:var(--surface-3);overflow:hidden;max-width:520px;}
  .bigtrack i{display:block;height:100%;border-radius:5px;width:0;background:var(--accent);transition:width .8s;}
  .addform{padding:14px 16px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;}
  .field label{display:block;font-family:var(--font-sans);font-size:9.5px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;color:var(--text-faint);margin-bottom:5px;}
  .field input,.field select{background:var(--ground);border:1px solid var(--line);border-radius:5px;padding:7px 10px;color:var(--text);font-size:12px;font-family:var(--font-sans);outline:none;}
  .field input:focus,.field select:focus{border-color:var(--accent-deep);}
  .iact{width:26px;height:26px;border-radius:5px;display:inline-grid;place-items:center;border:1px solid var(--line);background:var(--surface-2);color:var(--text-faint);}
  .iact svg{width:13px;height:13px;} .iact.no:hover{color:var(--crit);border-color:rgba(240,85,82,0.4);}
  .phasetag{font-family:var(--font-mono);font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;}
</style>
</head>
<body>
<div class="app">
  <aside class="rail">
    <div class="glyph"><svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 L20 7 L17 14 C15.5 18 12 22 12 22 C12 22 8.5 18 7 14 L4 7 Z"/><path d="M12 8 L12 15 M9 11 L12 8 L15 11"/></svg></div>
    <button class="navbtn" onclick="location.href='/edr-triage'"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"/></svg><span class="tip">Triage Console</span></button>
    <button class="navbtn" onclick="location.href='/memory/quarantine'"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg><span class="tip">AI Memory</span></button>
    <div class="spacer"></div>
    <button class="navbtn active" onclick="location.href='/settings'"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 100-6 3 3 0 000 6z"/><path d="M19 12a7 7 0 00-.1-1l2-1.6-2-3.4-2.4 1a7 7 0 00-1.7-1L14.5 2h-5l-.3 2.9a7 7 0 00-1.7 1l-2.4-1-2 3.4L3.1 11a7 7 0 000 2l-2 1.6 2 3.4 2.4-1a7 7 0 001.7 1L9.5 22h5l.3-2.9a7 7 0 001.7-1l2.4 1 2-3.4-2-1.6a7 7 0 00.1-1z"/></svg><span class="tip">Settings</span></button>
  </aside>
  <div class="main">
    <header class="topbar">
      <div class="title-block"><h1><span class="wm"><b>RAP</b>TOR</span></h1><span class="eyebrow">Settings · pipeline &amp; triage rules</span></div>
      <div class="topbar-spacer"></div>
      <div class="tb-actions"><button class="btn" onclick="loadAll()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></svg>Refresh</button></div>
    </header>
    <div class="content"><div class="stackgap">
      <section class="panel">
        <div class="panel-head"><h2>Triage pipeline</h2><span class="ro-pill"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>read-only</span><div class="spacer"></div><span class="lock-note"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>Environment-managed — these take effect via deployment config, not from this page.</span></div>
        <div class="sec-pad"><div class="meta-grid" id="cfg" style="grid-template-columns:repeat(3,1fr)"><div class="prev-empty" style="grid-column:1/-1">Loading…</div></div></div>
      </section>
      <section class="panel">
        <div class="panel-head"><h2>AI spend</h2><span class="ro-pill"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>read-only</span><div class="spacer"></div><span class="lock-note">Budget set by AGENT_MONTHLY_BUDGET_USD</span></div>
        <div class="sec-pad"><div class="spendrow"><span class="big" id="spendBig">—</span><span class="cap" id="spendCap"></span></div><div class="bigtrack"><i id="spendFill"></i></div></div>
      </section>
      <section class="panel">
        <div class="panel-head"><h2>Triage rules</h2><span class="count" id="rc">—</span><div class="spacer"></div><span class="lock-note">Custom rules matched before built-in patterns</span></div>
        <div class="addform">
          <div class="field"><label>Pattern</label><input id="r-pattern" placeholder="substring or regex" style="width:220px"/></div>
          <div class="field"><label>Match</label><select id="r-match"><option value="contains">contains</option><option value="regex">regex</option><option value="exact">exact</option></select></div>
          <div class="field"><label>Playbook</label><select id="r-playbook"><option>generic</option><option>malware</option><option>block_tool</option><option>reverse_shell</option><option>lateral_move</option><option>credential_access</option><option>privesc</option><option>encoded_powershell</option><option>lolbin</option></select></div>
          <div class="field"><label>Note (optional)</label><input id="r-note" placeholder="why" style="width:180px"/></div>
          <button class="btn primary" onclick="addRule()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Add rule</button>
        </div>
        <div class="q-wrap"><table class="queue"><thead><tr><th>Pattern</th><th>Match</th><th>Playbook</th><th>Note</th><th></th></tr></thead><tbody id="r-rows"></tbody></table></div>
      </section>
    </div></div>
  </div>
</div>
<script>
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function cell(k,v,color){return '<div class="meta"><div class="mk">'+esc(k)+'</div><div class="mv"'+(color?' style="color:'+color+'"':'')+'>'+esc(v)+'</div></div>';}
var PHASECOL={autonomous:'var(--crit)',copilot:'var(--accent)',shadow:'var(--text-dim)',advisory:'var(--accent)'};

function loadSettings(){
  fetch('/api/edr-triage/settings').then(function(r){return r.json();}).then(function(d){
    var ph=(d.agent_phase||'').toLowerCase();
    var cfg=document.getElementById('cfg');
    cfg.innerHTML=
       '<div class="meta"><div class="mk">Agent phase</div><div class="mv"><span class="phasetag" style="color:'+(PHASECOL[ph]||'var(--text)')+';background:var(--surface-3)">'+esc((d.agent_phase||'—').toUpperCase())+'</span></div></div>'
      +cell('Backend',d.agent_backend||'—')
      +cell('Agent loop',d.use_agent_loop?'on':'off',d.use_agent_loop?'var(--good)':'var(--text-faint)')
      +cell('Model',d.agent_model||'—')
      +cell('AWS region',d.aws_region||'—')
      +cell('Poll interval',(d.poll_interval!=null?d.poll_interval+' s':'—'))
      +cell('Dry run',d.dry_run?'yes':'no',d.dry_run?'var(--med)':'var(--text-faint)')
      +cell('Jira project',d.jira_project||'—')
      +cell('Jira email',d.jira_email||'—')
      +cell('LLM fallback URL',d.llm_url||'(none)');
    // spend
    var cap=d.budget_usd,mtd=d.month_to_date_usd||0;
    if(cap==null){document.getElementById('spendBig').textContent='—';document.getElementById('spendCap').textContent='no budget set';}
    else{document.getElementById('spendBig').textContent='$'+(+mtd).toFixed(2);document.getElementById('spendCap').textContent='of $'+(+cap).toFixed(0)+' this month';var p=cap>0?Math.min(100,(mtd/cap)*100):0;var f=document.getElementById('spendFill');f.style.width=p+'%';f.style.background=p>=100?'var(--crit)':p>=80?'var(--med)':'var(--accent)';}
  }).catch(function(){document.getElementById('cfg').innerHTML='<div class="prev-empty" style="grid-column:1/-1;color:var(--crit)">Failed to load settings</div>';});
}
function loadRules(){
  fetch('/api/edr-triage/rules').then(function(r){return r.json();}).then(function(d){
    var rules=(d&&d.rules)||[];document.getElementById('rc').textContent=rules.length+' rule'+(rules.length!==1?'s':'');
    var tb=document.getElementById('r-rows');
    if(!rules.length){tb.innerHTML='<tr><td colspan="5"><div class="prev-empty" style="padding:30px">No custom rules — built-in playbook patterns apply</div></td></tr>';return;}
    tb.innerHTML=rules.map(function(rl){
      return '<tr><td><span class="tkt">'+esc(rl.pattern||'')+'</span></td><td><span class="pb">'+esc(rl.match_type||'contains')+'</span></td><td><span class="verdict l2">'+esc(rl.playbook||'generic')+'</span></td><td class="c-usr">'+esc(rl.note||'')+'</td><td style="text-align:right"><span class="iact no" title="Delete rule" onclick="delRule('+JSON.stringify(rl.id||'')+')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V4h6v3M10 11v6M14 11v6M6 7l1 13h10l1-13"/></svg></span></td></tr>';
    }).join('');
  }).catch(function(){});
}
function addRule(){
  var pattern=document.getElementById('r-pattern').value.trim();
  if(pattern.length<2){alert('Pattern is required.');return;}
  var body={pattern:pattern,match_type:document.getElementById('r-match').value,playbook:document.getElementById('r-playbook').value,note:document.getElementById('r-note').value.trim()};
  fetch('/api/edr-triage/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(function(r){if(!r.ok)return r.json().then(function(e){throw new Error(e.detail||('HTTP '+r.status));});return r.json();})
    .then(function(){document.getElementById('r-pattern').value='';document.getElementById('r-note').value='';loadRules();})
    .catch(function(e){alert('Could not add rule: '+(e.message||e));});
}
function delRule(id){if(!id)return;if(!confirm('Delete this rule?'))return;fetch('/api/edr-triage/rules/'+encodeURIComponent(id),{method:'DELETE'}).then(function(r){return r.json();}).then(function(){loadRules();}).catch(function(){});}
function loadAll(){loadSettings();loadRules();}
loadAll();

</script>
</body>
</html>"""
