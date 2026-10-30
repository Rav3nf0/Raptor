"""Jira closure poller — polls terminal state transitions every 5 min.

Two-stage memory write:
  Stage 1 — L1 escalates: status = "L2 ANALYSIS REQUIRED"
    → records l1_handoff_at on ShadowResult, writes provisional quarantine memory
  Stage 2 — L2 resolves: status = "FALSE POSITIVE" / "RESOLVED" / "CLOSED"
    → enriches Stage-1 memory (or writes fresh if no prior escalation)
    → sets verdict_match against L2 verdict, not L1 escalation
  (unscored) — status = "AWAITING MORE INPUTS": refreshes a stale pending-quarantine
    caption if one already exists; never resolves, never touched otherwise

JQL: project = SIM AND status in ("FALSE POSITIVE","RESOLVED","CLOSED",
     "L2 ANALYSIS REQUIRED","AWAITING MORE INPUTS") AND updated >= -{lookback}m
     (lookback > interval on purpose — see run_forever)

Stage 2 does NOT depend on Stage 1 having been observed: whether a ticket went to L2
is also read back off the comment thread (`_thread_shows_l2`), so a poll that misses
the L2-status window costs a refresh, not the L2 provenance.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time

import httpx

from edr_triage.config import get_edr_config
from lib.comment_utils import verdict_aware_truncate

logger = logging.getLogger(__name__)

_TERMINAL_STATES = frozenset([
    "FALSE POSITIVE", "RESOLVED", "CLOSED", "L2 ANALYSIS REQUIRED",
])

# Page cap for the closed-ticket search (100 rows/page). 20 pages = 2000 tickets,
# far above any sane lookback, so it only guards against a runaway window.
_MAX_CLOSURE_PAGES = 20

_JIRA_TO_TRIAGE: dict[str, str] = {
    "FALSE POSITIVE": "AUTO_CLOSED_FP",
    "RESOLVED":       "AUTO_CLOSED_TP",
    "CLOSED":         "AUTO_CLOSED_TP",
}

_SKIP_STATES = frozenset(["NO RESPONSE"])

# A ticket an analyst closed as a duplicate of another. NOT in _TERMINAL_STATES and NOT
# in _JIRA_TO_TRIAGE: closing as Duplicate is not a verdict — the analyst never said
# false positive or true positive, they said "see the other ticket" — so it must never
# be scored as an AI hit or miss.
#
# But it DOES have to be stamped as resolved, and until now it was not polled at all.
# The consequence was a phantom open alert that manufactured misses in every OTHER
# alert family. check_concurrent_alerts (entity_graph/query.py) treats a sibling as
# still-open unless the poller stamped a resolution, so a Duplicate-closed ticket
# counted as an open concurrent alert for its full 24h window, forever. DEMO-111177
# (Netskope DLP, nico.bhatt, closed Duplicate, no stamps) is why DEMO-111178 — a Root
# Privilege Escalation whose commands the agent had correctly read as benign `id`
# queries with prior business justification — was escalated to L2 anyway on the
# concurrent-alert safety rule, and scored a miss when both L1 and L2 closed it FP.
#
# DLP fans out into many tickets and ~a third of them are closed Duplicate, so the
# phantom siblings cluster on exactly the high-volume actors who also appear in other
# families. Splitting DLP out of the headline does not touch this: the misses it causes
# land in the NON-DLP bucket.
_DUPLICATE_STATE = "DUPLICATE"

# AWAITING MORE INPUTS is L1's business-justification loop, not a resolution — a
# ticket can sit here for days (DEMO-108035: escalated, L2 asked the actor, waited
# 4 days for a reply) while its underlying shadow gets re-triaged and ai_triage_class
# moves on. It used to be a _SKIP_STATES entry, so the JQL below never even fetched
# it and the pending-quarantine caption froze at whatever the AI said the moment it
# first escalated — an L2 reviewing the queue saw "AI: NEEDS_L2" long after the AI's
# current read had moved to REQUEST_JUSTIFICATION. Fetched and refreshed (never
# scored — see _refresh_awaiting_inputs_memory) exactly like L2 ANALYSIS REQUIRED.
_AWAITING_INPUTS_STATE = "AWAITING MORE INPUTS"


def _thread_shows_l2(attributed_comment: str) -> bool:
    """True when the attributed comment thread contains an L2 analyst's comment.

    A DURABLE, retroactive L2 signal: it is re-derivable from the ticket at any time,
    unlike `l1_handoff_at`, which is only ever stamped while the ticket is SITTING in
    "L2 Analysis required" and a poll happens to catch it there. Miss that window and
    the fact that a ticket went to L2 is lost permanently — the status has moved on, so
    _handle_l2_handoff can never fire for it again.

    `_extract_all_comments` tags each human comment `[<role> — <name>]` from the analyst
    role registry, so an L2 who commented is recorded in the thread itself. Accepts the
    hyphen form too — the tag is written with an em dash, but a re-ingested/normalised
    thread can carry the ASCII one.
    """
    t = attributed_comment or ""
    return "[L2 —" in t or "[L2 -" in t


async def _alert_under_test(alert_name: str) -> bool:
    """True when this alert NAME is on the standing under-test exclusion list.

    Checked before scoring or quarantining a ticket — see AlertUnderTest's docstring.
    A tiny lookup per closed ticket; the list is expected to hold at most a handful of
    rows at once, so no caching layer is worth the staleness it would introduce.
    """
    from entity_graph.models import AlertUnderTest
    return await AlertUnderTest.find_one(AlertUnderTest.alert_name == (alert_name or "")) is not None


async def poll_once(lookback_minutes: int = 5) -> int:
    """Poll for recently-closed SIM tickets, cross-reference shadow results.

    Returns number of shadow results updated.
    """
    cfg = get_edr_config()
    if not all([cfg.jira_email, cfg.jira_token]):
        logger.warning("Jira credentials not configured — skipping closure poll")
        return 0
    if not cfg.jira_url:
        logger.error("JIRA_URL is not configured — closure poller cannot reach Jira; "
                     "shadow accuracy will not be scored. Set JIRA_URL.")
        return 0

    # Held Root Privesc tickets whose blocker is still open after the hold window → L2.
    try:
        from edr_triage.concurrency_hold import expire_holds
        await expire_holds(cfg)
    except Exception as exc:
        logger.error("closure_poller: expire_holds failed: %s", exc)

    tickets = await _fetch_recently_closed(cfg, lookback_minutes)
    if not tickets:
        return 0

    updated = 0
    for ticket in tickets:
        try:
            ok = await _process_closed_ticket(ticket)
            if ok:
                updated += 1
        except Exception as exc:
            logger.error("closure_poller: error processing %s: %s", ticket.get("key"), exc)

    logger.info("Closure poller: %d tickets checked, %d shadow results updated", len(tickets), updated)
    return updated


async def _fetch_recently_closed(cfg, lookback_minutes: int) -> list[dict]:
    states = list(_TERMINAL_STATES) + [_AWAITING_INPUTS_STATE, _DUPLICATE_STATE]
    jql = (
        f'project = {cfg.jira_project_key} '
        f'AND status in ({", ".join(repr(s) for s in states)}) '
        f'AND updated >= -{lookback_minutes}m'
    )
    try:
        async with httpx.AsyncClient(
            base_url=cfg.jira_url.rstrip("/"),
            auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=20.0,
            verify=cfg.jira_verify_ssl,
        ) as client:
            # Jira Cloud deprecated GET /rest/api/3/search — use POST /rest/api/3/search/jql
            #
            # Paginate: a single 50-row page silently truncated any wide lookback (a
            # backfill over 48h spans ~200 closures here), so accuracy was scored on
            # whatever happened to land in page 1. Page until isLast/no token, with a
            # hard page cap so a huge window can't spin forever.
            issues: list[dict] = []
            next_token: str | None = None
            for _ in range(_MAX_CLOSURE_PAGES):
                body: dict = {
                    "jql": jql,
                    "fields": ["summary", "status", "assignee", "comment", "updated", "labels"],
                    "maxResults": 100,
                }
                if next_token:
                    body["nextPageToken"] = next_token
                resp = await client.post("/rest/api/3/search/jql", json=body)
                resp.raise_for_status()
                page = resp.json()
                issues.extend(page.get("issues", []))
                next_token = page.get("nextPageToken")
                if page.get("isLast") or not next_token:
                    break
            else:
                logger.warning(
                    "closure_poller: hit the %d-page cap (%d tickets) for lookback=%dm — "
                    "results truncated; narrow the window to score the rest",
                    _MAX_CLOSURE_PAGES, len(issues), lookback_minutes,
                )
            return issues
    except Exception as exc:
        logger.error("closure_poller: Jira search failed: %s", exc)
        return []


async def rescore_one(jira_key: str) -> dict:
    """Re-score ONE ticket by key, fetched directly instead of through the JQL window.

    poll_once can only see tickets a `updated >= -Nm` search returns, capped at
    _MAX_CLOSURE_PAGES x 100. That makes an individual old ticket unreachable: any
    window wide enough to include it returns more than the cap and truncates before it.
    A re-triage clears verdict_match, so a row in that position drops OUT of the
    accuracy denominator and stays out — an exclusion, which is exactly the thing the
    metric must never do. DEMO-106604 needed a human to comment on the ticket just to
    drag its `updated` back into the window; DEMO-106078 and DEMO-108928 are still stuck
    there.

    Fetches the issue by key (no search, no window, no cap) and hands it to the SAME
    _process_closed_ticket the poller uses, with the SAME field set — so this re-scores
    by exactly the poller's rules and can never become a second, divergent scoring path.
    It re-reads what a HUMAN decided; it never re-runs the agent.
    """
    key = (jira_key or "").strip().upper()
    if not key:
        return {"ok": False, "jira_key": jira_key, "error": "no jira_key given"}
    cfg = get_edr_config()
    if not all([cfg.jira_email, cfg.jira_token, cfg.jira_url]):
        return {"ok": False, "jira_key": key, "error": "Jira not configured"}
    try:
        async with httpx.AsyncClient(
            base_url=cfg.jira_url.rstrip("/"),
            auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
            headers={"Accept": "application/json"},
            timeout=20.0,
            verify=cfg.jira_verify_ssl,
        ) as client:
            resp = await client.get(
                f"/rest/api/3/issue/{key}",
                # Same fields the search requests, so the handlers see identical input.
                params={"fields": "summary,status,assignee,comment,updated,labels"},
            )
            if resp.status_code == 404:
                return {"ok": False, "jira_key": key, "error": "no such Jira ticket"}
            resp.raise_for_status()
            issue = resp.json()
    except Exception as exc:
        logger.error("rescore_one: Jira fetch failed for %s: %s", key, exc)
        return {"ok": False, "jira_key": key, "error": str(exc)}

    status = ((issue.get("fields") or {}).get("status") or {}).get("name", "")
    updated = await _process_closed_ticket(issue)
    # Report the resulting score so the caller can tell "scored" from "the handler
    # declined" (not terminal yet, under test, already scored and unchanged) without
    # a second round trip.
    verdict_match = None
    try:
        from entity_graph.models import ShadowResult
        shadow = await (
            ShadowResult.find(ShadowResult.jira_key == key)
            .sort(-ShadowResult.created_at).first_or_none()
        )
        if shadow:
            verdict_match = shadow.verdict_match
    except Exception as exc:                       # reporting only — never fail the call
        logger.warning("rescore_one: could not read back %s: %s", key, exc)
    logger.info("rescore_one %s: status=%s processed=%s verdict_match=%s",
                key, status, updated, verdict_match)
    return {"ok": True, "jira_key": key, "jira_status": status,
            "processed": bool(updated), "verdict_match": verdict_match}


async def _process_closed_ticket(ticket: dict) -> bool:
    """Dispatch ticket to L2-handoff, final-resolution, or awaiting-inputs-refresh
    handler based on status."""
    jira_key = ticket.get("key", "")
    fields = ticket.get("fields", {})
    status_name = (fields.get("status") or {}).get("name", "").upper()

    if status_name == _AWAITING_INPUTS_STATE:
        try:
            return await _refresh_awaiting_inputs_memory(jira_key, fields)
        except Exception as exc:
            logger.error("closure_poller: _process_closed_ticket(%s) failed: %s", jira_key, exc)
            return False

    if status_name == _DUPLICATE_STATE:
        try:
            return await _mark_duplicate_resolved(jira_key, fields)
        except Exception as exc:
            logger.error("closure_poller: _mark_duplicate_resolved(%s) failed: %s", jira_key, exc)
            return False

    if status_name in _SKIP_STATES:
        return False
    if status_name not in _TERMINAL_STATES:
        return False

    assignee = fields.get("assignee") or {}
    analyst_id = assignee.get("accountId", "") or assignee.get("emailAddress", "")
    analyst_name = assignee.get("displayName", analyst_id)

    try:
        if status_name == "L2 ANALYSIS REQUIRED":
            return await _handle_l2_handoff(jira_key, fields, analyst_id, analyst_name)
        else:
            final_class = _JIRA_TO_TRIAGE.get(status_name)
            if not final_class:
                return False
            resolved = await _handle_l2_resolution(jira_key, fields, final_class, analyst_id, analyst_name)
            if resolved:
                # A human just reached a terminal verdict (FP or TP) on this ticket —
                # resolve any open page for it. Safe no-op if none was ever triggered
                # (see lib.pagerduty_client.resolve_event); best-effort, same as
                # _retrigger_dependents below, so a PagerDuty outage never masks this
                # ticket's own successful resolution.
                try:
                    from lib.pagerduty_client import resolve_event
                    await resolve_event(jira_key)
                except Exception as exc:
                    logger.error("closure_poller: resolve_event(%s) failed: %s", jira_key, exc)
                # This ticket just closed — anything the concurrency gate blocked
                # specifically because THIS one was open has nothing else watching for
                # that to change (DEMO-109502/DEMO-109453: a ticket blocked on a sibling's
                # still-open status sat at NEEDS_L2 with no mechanism to revisit it once
                # the sibling closed). Best-effort: never let a dependent failure mask
                # this ticket's own successful resolution.
                try:
                    await _retrigger_dependents(jira_key, final_class)
                except Exception as exc:
                    logger.error("closure_poller: _retrigger_dependents(%s) failed: %s", jira_key, exc)
            return resolved
    except Exception as exc:
        logger.error("closure_poller: _process_closed_ticket(%s) failed: %s", jira_key, exc)
        return False


async def _retrigger_dependents(jira_key: str, final_class: str = "") -> None:
    """A ticket just resolved — re-triage any OTHER ticket the concurrency gate blocked
    specifically because THIS one was open (ShadowResult.blocked_by_concurrent_keys
    contains jira_key).

    Full REAL re-triage (dry_run=False) — this is meant to behave exactly like the
    normal ingestion pipeline seeing the dependent ticket fresh, respecting whatever
    phase (shadow/copilot/autonomous) is currently configured, not a special-cased
    action. Clears the dedup record first (same as the manual force=true path) since
    the dependent's alert_id was already claimed on its original, blocked run.
    """
    from entity_graph.models import ShadowResult
    dependents = await ShadowResult.find(
        ShadowResult.blocked_by_concurrent_keys == jira_key,
    ).to_list()
    if not dependents:
        return
    import asyncio
    import httpx
    from edr_triage.config import get_edr_config
    from edr_triage.jira_poller import (
        parse_mde_alert_id, parse_description_fields,
        parse_sentinel_incident_url, parse_sentinel_alert_id, _adf_to_text,
        build_upwind_ticket,
    )
    from edr_triage.pipeline import _process_ticket
    from edr_triage.store import _col as _store_col
    from lib.mde_client import get_access_token

    cfg = get_edr_config()
    from edr_triage import concurrency_hold as _ch
    for dep in dependents:
        dep_key = dep.jira_key
        try:
            if final_class != "AUTO_CLOSED_FP" and await _ch.is_held(dep_key, cfg):
                # Held behind a ticket that did NOT close False Positive — possibly a true
                # positive, so this one goes to a person, never back through the model.
                logger.info("%s closed %s — held %s goes to L2", jira_key, final_class, dep_key)
                await _ch.release_to_l2(dep_key, f"{jira_key}, which it was held behind, was "
                                        f"closed as {final_class or 'something other than False Positive'}",
                                        cfg)
                continue
            logger.info(
                "%s closed — re-triaging %s (was blocked on it via the concurrent-alerts gate)",
                jira_key, dep_key,
            )
            await asyncio.to_thread(lambda k=dep_key: _store_col().delete_many(
                {"$or": [{"alert_id": k}, {"jira_key": k}]}
            ))
            async with httpx.AsyncClient(
                base_url=cfg.jira_url.rstrip("/"),
                auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
                headers={"Accept": "application/json"},
                timeout=20.0,
                verify=cfg.jira_verify_ssl,
            ) as client:
                resp = await client.get(
                    f"/rest/api/3/issue/{dep_key}",
                    params={"fields": "summary,description,created,priority,labels,comment"},
                )
                resp.raise_for_status()
                issue = resp.json()

            dep_fields = issue.get("fields", {})
            desc_raw = dep_fields.get("description") or {}
            description = _adf_to_text(desc_raw) if isinstance(desc_raw, dict) else str(desc_raw or "")
            alert_id = parse_mde_alert_id(description)
            parsed = parse_description_fields(description)
            sentinel_url = parse_sentinel_incident_url(description)
            alert_name = parsed.get("alert_name", dep_fields.get("summary", ""))
            existing_comments, _, _ = _extract_all_comments(dep_fields, bot_email=cfg.jira_email or "")
            upwind_ticket = None if alert_id else build_upwind_ticket(
                dep_key, dep_fields, description, existing_comments)

            if upwind_ticket:
                dep_ticket = upwind_ticket
            elif alert_id:
                dep_ticket = {
                    "jira_key": dep_key, "alert_id": alert_id, "alert_name": alert_name,
                    "description": description, "created_at": dep_fields.get("created", ""),
                    "severity": (dep_fields.get("priority") or {}).get("name", ""),
                    "tactics": parsed.get("tactics", ""), "device_name": parsed.get("device", ""),
                    "user_name": parsed.get("user", ""), "incident_url": parsed.get("incident_url", ""),
                    "is_sentinel": False, "observe_only": False, "existing_comments": existing_comments,
                }
            elif sentinel_url:
                dep_ticket = {
                    "jira_key": dep_key, "alert_id": dep_key, "alert_name": alert_name,
                    "description": description, "created_at": dep_fields.get("created", ""),
                    "severity": (dep_fields.get("priority") or {}).get("name", ""),
                    "tactics": parsed.get("tactics", ""), "device_name": parsed.get("device", ""),
                    "user_name": parsed.get("user", ""), "incident_url": sentinel_url,
                    "sentinel_alert_id": parse_sentinel_alert_id(description) or "",
                    "is_sentinel": True, "observe_only": False, "existing_comments": existing_comments,
                }
            else:
                logger.warning("dependent re-triage of %s skipped — no alert ID in description", dep_key)
                continue

            token = None
            try:
                token = await get_access_token()
            except Exception as exc:
                logger.warning("MDE token fetch failed for dependent %s: %s", dep_key, exc)
            await _process_ticket(dep_ticket, token=token, cfg=cfg, force_agent=True)
        except Exception as exc:
            logger.error("dependent re-triage of %s (unblocked by %s) failed: %s",
                        dep_key, jira_key, exc)


async def _refresh_awaiting_inputs_memory(jira_key: str, fields: dict) -> bool:
    """AWAITING MORE INPUTS is L1's loop, not a resolution — this NEVER sets
    verdict_match or l1/l2 fields going FORWARD, and NEVER writes a memory that
    doesn't already exist. It exists solely so a ticket sitting here for days
    doesn't leave its pending-quarantine caption frozen at whatever the AI said the
    moment it was first escalated, while the underlying shadow moves on underneath
    it (DEMO-108035: re-triaged from NEEDS_L2 to REQUEST_JUSTIFICATION, caption still
    read "AI: NEEDS_L2" because this status used to be skipped outright).

    REOPENED-AFTER-RESOLUTION is the other case handled here. A ticket can be
    resolved (verdict_match set, a memory written) and later moved BACK to
    AWAITING MORE INPUTS — not just via a genuine re-triage (which already clears
    verdict_match itself), but via a plain Jira reopen: DEMO-109508 was caught in a
    bulk close intended for an unrelated Netskope-alert burst (same copy-pasted
    "re-enablement of the CASB rule" comment and AUTO_CLOSED_FP verdict landed on
    it), then reopened once the mistake was caught — but nothing had ever cleared
    the stale verdict_match or the now-wrong memory, so both sat there permanently
    captioned with someone else's resolution. A resolved verdict is only ever valid
    while the ticket STAYS resolved; seeing it back in this state at all means that
    resolution no longer holds, regardless of why.
    """
    from entity_graph.models import ShadowResult
    shadow = await (
        ShadowResult.find(ShadowResult.jira_key == jira_key)
        .sort(-ShadowResult.created_at)
        .first_or_none()
    )
    if not shadow:
        return False

    # Record that L1 ASKED THE USER. Stamped once, never cleared, and set BEFORE every
    # early return below — including the `l1_handoff_at is None` one, because L1 asking
    # is a decision whether or not they later escalated.
    #
    # This was the one L1 decision nothing recorded. l1_triage_class is only ever set by
    # _handle_l2_handoff (-> NEEDS_L2) or by the terminal-close branch (-> final class),
    # so "L1 opened the business-justification loop" left no trace at all. The agent's
    # REQUEST_JUSTIFICATION verdict could therefore never be scored as agreeing with L1
    # even when both made the identical call — a systematic undercount landing entirely
    # on the RJ path (21 scored RJ misses; DLP alone had 31 of 264 rows at RJ).
    #
    # Still does NOT score anything: verdict_match and l1/l2 stay untouched here, exactly
    # as before. This is a timestamp, read later by the l1_agreement metric.
    from datetime import datetime as _dt
    if getattr(shadow, "l1_awaiting_inputs_at", None) is None:
        shadow.l1_awaiting_inputs_at = _dt.utcnow()
        await shadow.save()
        logger.info("AWAITING MORE INPUTS %s — recorded L1's justification request", jira_key)

    if shadow.verdict_match is not None:
        shadow.verdict_match = None
        await shadow.save()
        from app.database import get_collection
        col = get_collection("eg_memories")
        deleted = await col.delete_one({"jira_key": jira_key})
        logger.warning(
            "AWAITING MORE INPUTS %s — was already resolved (verdict_match set) but is "
            "back in this state; cleared the stale verdict and removed its memory "
            "(deleted=%s) rather than leave a reopened ticket's queue entry captioned "
            "with a resolution that no longer holds",
            jira_key, bool(deleted.deleted_count),
        )
    if shadow.l1_handoff_at is None:
        return False
    from edr_triage.classifier import memory_alert_type as _classify_hs
    cfg = get_edr_config()
    l1_comment, _, _ = _extract_all_comments(fields, bot_email=cfg.jira_email or "")
    alert_type = _classify_hs(shadow.alert_name)
    if alert_type == "skip":
        return False
    await _write_l2_handoff_memory(shadow, l1_comment, alert_type)
    logger.debug("AWAITING MORE INPUTS %s — refreshed pending memory", jira_key)
    return False


async def _handle_l2_handoff(jira_key: str, fields: dict, analyst_id: str, analyst_name: str) -> bool:
    """Stage 1: L1 escalated to L2. Record the handoff and write a provisional quarantine memory."""
    from datetime import datetime
    from entity_graph.models import ShadowResult

    # Newest-first: force=true reruns leave older rows behind, and an unsorted
    # find_one returns an arbitrary one — often a previously-scored row, which then
    # short-circuits as 'already resolved' and the NEW verdict is never scored.
    shadow = await (
        ShadowResult.find(ShadowResult.jira_key == jira_key)
        .sort(-ShadowResult.created_at)
        .first_or_none()
    )
    if not shadow:
        logger.debug("L2 handoff %s — no ShadowResult, skipping", jira_key)
        return False
    if await _alert_under_test(shadow.alert_name):
        logger.debug("L2 handoff %s — alert '%s' is under test, skipping quarantine write",
                     jira_key, shadow.alert_name)
        return False

    cfg = get_edr_config()
    l1_comment, _, _ = _extract_all_comments(fields, bot_email=cfg.jira_email or "")

    if shadow.l1_handoff_at is not None:
        # Handoff already stamped — do NOT re-stamp the timestamps (the escalation
        # happened once). But the AI verdict may have MOVED since, and the pending-L2
        # memory caption is built from it, so refresh that: DEMO-107770/107800 sat in
        # the review queue reading "AI: AUTO_CLOSED_FP" long after the agent had
        # re-triaged to NEEDS_L2. Stale provenance on a queue an analyst is using to
        # adjudicate AI-vs-human splits is worse than no provenance.
        from edr_triage.classifier import memory_alert_type as _classify_hs
        _at = _classify_hs(shadow.alert_name)
        if _at != "skip":
            await _write_l2_handoff_memory(shadow, l1_comment, _at)
        logger.debug("L2 handoff %s — already recorded; refreshed pending memory", jira_key)
        return False

    shadow.l1_triage_class = "NEEDS_L2"
    shadow.l1_analyst_id = analyst_id or "unknown"
    shadow.l1_resolved_at = datetime.utcnow()
    shadow.l1_handoff_at = datetime.utcnow()
    shadow.l1_handoff_comment = l1_comment
    await shadow.save()

    logger.info("L2 handoff %s: analyst=%s", jira_key, analyst_name)

    from edr_triage.classifier import memory_alert_type as classify
    alert_type = classify(shadow.alert_name)
    if alert_type == "skip":
        return True

    await _write_l2_handoff_memory(shadow, l1_comment, alert_type)
    return True


async def _mark_duplicate_resolved(jira_key: str, fields: dict) -> bool:
    """Stamp a Duplicate-closed ticket as resolved WITHOUT scoring it.

    Two things are deliberately separate here:

      * RESOLUTION is stamped, so check_concurrent_alerts stops counting this ticket as
        an open concurrent alert. That is the bug fix — see _DUPLICATE_STATE.
      * The VERDICT is left alone. l1_triage_class and verdict_match stay untouched, so
        the row is not added to the accuracy denominator and no existing score is
        altered. Closing as Duplicate is not a determination, and inventing one would
        put a verdict the analyst never gave into the metric.

    Idempotent: an already-stamped ticket is left as-is and reports no work done.
    """
    from datetime import datetime
    from entity_graph.models import ShadowResult

    shadow = await (
        ShadowResult.find(ShadowResult.jira_key == jira_key)
        .sort(-ShadowResult.created_at).first_or_none()
    )
    if shadow is None:
        # Closed as Duplicate before triage ever ran — there is no row to stamp, and
        # nothing counts it as concurrent either. Nothing to do.
        logger.debug("Duplicate %s: no shadow row (closed before triage)", jira_key)
        return False

    if shadow.l1_resolved_at is not None or shadow.l2_resolved_at is not None:
        return False

    assignee = fields.get("assignee") or {}
    analyst_id = assignee.get("accountId", "") or assignee.get("emailAddress", "")

    now = datetime.utcnow()
    shadow.l1_resolved_at = now
    shadow.l1_analyst_id = analyst_id or "unknown"
    # Why it resolved, not just that it did. l1_resolved_at alone is ambiguous: a row
    # carrying it with verdict_match still None is indistinguishable from one still
    # awaiting a human, so these were reported as "pending review" indefinitely. This
    # marker lets the report say "resolved as duplicate, never scoreable" instead —
    # transparency about what the denominator excludes, not a change to any score.
    shadow.duplicate_at = now
    # check_concurrent_alerts counts a sibling as open unless l2_resolved_at is set, OR
    # l1_resolved_at is set with NO l1_handoff_at. A ticket that reached L2 and was then
    # closed as Duplicate therefore needs the L2 stamp as well, or l1_resolved_at alone
    # would not exclude it and the phantom-open sibling would survive this fix.
    if shadow.l1_handoff_at is not None:
        shadow.l2_resolved_at = now
    await shadow.save()

    logger.info("Duplicate %s: stamped resolved (not scored) — analyst=%s, via_l2=%s",
                jira_key, analyst_id or "unknown", shadow.l1_handoff_at is not None)
    return True


async def _mark_autonomous_resolved(shadow, jira_key: str) -> bool:
    """A ticket RAPTOR closed itself: stamp it resolved, record NO verdict, write NO memory.

    Mirrors _mark_duplicate_resolved. Resolution is stamped so check_concurrent_alerts
    stops counting the ticket as open, and returning True lets the dispatcher re-trigger
    anything this ticket was blocking. The verdict is left alone: no human has decided
    anything, so there is nothing to score and nothing to learn — the autoclose report's
    reopen signal is what reviews these. If a human later reopens and closes it, that
    close is attributed to them and scored normally (l2_resolved_at stays unset here
    unless the ticket had already been handed to L2).

    Idempotent: an already-stamped ticket reports no work done.
    """
    from datetime import datetime

    if shadow.autonomous_closed_at is not None and shadow.l1_resolved_at is not None:
        return False
    now = datetime.utcnow()
    if shadow.autonomous_closed_at is None:
        shadow.autonomous_closed_at = now
    if shadow.l1_resolved_at is None:
        shadow.l1_resolved_at = now
    if shadow.l1_handoff_at is not None and shadow.l2_resolved_at is None:
        shadow.l2_resolved_at = now
    await shadow.save()
    logger.info("Autonomous close %s: stamped resolved (not scored, no memory) — ai=%s",
                jira_key, shadow.ai_triage_class)
    return True


_ZERO_RESULT_RE = re.compile(r"^\s*0\s+(?:rows?|events?)\b", re.I)


def _tool_call_corroborates(result: str) -> bool:
    """True when a STORED (already-summarized) tool-call result is an actual,
    informative answer rather than an error or a genuinely empty hunt/query.

    Conservative on purpose: entity-context and VT-style calls always corroborate
    once they complete — "not seen before" and "0/91 clean" are both real, definitive
    answers, not a failure to find something. A hunt/query returning literally "0
    rows"/"0 events" does not — there's nothing there to corroborate with. Anything
    unrecognized falls through to True as well UNLESS it starts with "ERROR" — the
    bias here is toward NOT flagging a close as thin on a false negative, since the
    two things that must never be silently missed are an actual error and a hunt that
    came back with nothing at all; everything else reads as it says.
    """
    r = (result or "").strip()
    if not r or r.upper().startswith("ERROR"):
        return False
    return not _ZERO_RESULT_RE.match(r)


def _rj_close_is_thin(shadow) -> str:
    """Why an RJ-verdict ticket's closure rests on thin evidence, or "" if it doesn't.

    Scope decision: L1 closing a WELL-EVIDENCED single-actor RJ ticket directly is
    fine (e.g. DEMO-109425 — 5 tool calls, several returning real data) — this is not
    a blanket "every RJ needs L2" rule. What must route to L2 is a close where the
    justification is the ONLY thing supporting it. Either prong below is sufficient:

      1. An actor on a multi-actor incident was never addressed by this ask — a
         justification from one actor cannot cover another's separate activity
         (DEMO-109720). Reuses agent_core.loop._unaddressed_actors against the
         persisted actor_hosts/reasoning; no `actor_justification_hits` is available
         at close time (that's only computed live, during the agent run), so this
         check is slightly more conservative here than at triage time — consistent
         with biasing toward L2 rather than away from it.
      2. Fewer than the same _CORROBORATING_HUNTS_REQUIRED tool calls the agent's own
         auto-close gate already requires returned real data.
    """
    from agent_core.loop import _unaddressed_actors, _CORROBORATING_HUNTS_REQUIRED

    _evidence_stub = {"actor_hosts": getattr(shadow, "actor_hosts", None) or []}
    _unaddressed = _unaddressed_actors(_evidence_stub, shadow.ai_reasoning or "")
    if _unaddressed:
        return (f"multi-actor incident — actor(s) {', '.join(_unaddressed)} were never "
                "addressed by this justification request")

    _calls = getattr(shadow, "ai_tool_calls", None) or []
    _corroborating = sum(
        1 for tc in _calls
        if isinstance(tc, dict) and _tool_call_corroborates(tc.get("result", ""))
    )
    if _corroborating < _CORROBORATING_HUNTS_REQUIRED:
        return (f"only {_corroborating} tool call(s) returned real data — the "
                "justification is the only thing actually supporting this close")
    return ""


async def _route_thin_rj_to_l2(jira_key: str, fields: dict, shadow, justification: str,
                               reason: str) -> None:
    """A REQUEST_JUSTIFICATION ticket closed on thin evidence — route to L2 instead of
    letting the close stand. Reuses chase_reply_poller's exact pattern (comment +
    allowlist-gated transition) rather than reimplementing it: same target status,
    same safety property — the transition is keyed on the DESTINATION status, not a
    transition name that could be silently repointed by an unrelated workflow edit.

    One-time ROUTING correction, not enforcement: _handle_l2_handoff stamps
    l1_handoff_at, so this cannot fire twice on the same ticket — an L1 who disagrees
    and closes it again will have that close stand. That is intentional under the
    "only when evidence is thin" scope decision: it forces the thin case to be SEEN by
    L2 once; it does not overrule a human twice.

    Note: this stamps shadow.l1_triage_class = "NEEDS_L2" via _handle_l2_handoff even
    though L1 actually attempted a direct FP/TP close, not a genuine escalation — a
    minor provenance inaccuracy (affects L1 analyst-quality scoring only, never
    verdict_match) accepted in exchange for reusing the existing, already-idempotent
    handoff path rather than duplicating its memory-writing/classification logic.
    """
    from edr_triage.chase_reply_poller import _transition_to
    from edr_triage.jira_handler import add_comment

    cfg = get_edr_config()
    packet = (
        "*RAPTOR — thin-evidence justification, routed to L2*\n\n"
        f"*Why this wasn't accepted as a direct close:* {reason}.\n\n"
        + (f"*Business justification on file:*\n{{quote}}{justification}{{quote}}\n\n"
           if justification else "")
        + "*Status of this evidence:* UNVERIFIED SELF-REPORT, and it is the ONLY thing "
        "supporting this close — there is no independent technical corroboration on "
        "record. Re-validate before closing.\n\n"
        f"*Ticket moved to L2 Analysis required.* RAPTOR has not closed or resolved "
        f"{jira_key} and cannot — it may only route. The verdict is L2's.\n\n"
        "[RAPTOR — automated thin-evidence RJ routing]"
    )
    await add_comment(jira_key, packet, cfg)
    moved = await _transition_to(jira_key, "L2 Analysis required", cfg)
    logger.info("thin-RJ routing %s: reason=%r transitioned=%s", jira_key, reason, moved)

    assignee = fields.get("assignee") or {}
    analyst_id = assignee.get("accountId", "") or assignee.get("emailAddress", "") or "unknown"
    analyst_name = assignee.get("displayName", analyst_id)
    await _handle_l2_handoff(jira_key, fields, analyst_id, analyst_name)


async def _handle_l2_resolution(
    jira_key: str, fields: dict, final_class: str, analyst_id: str, analyst_name: str
) -> bool:
    """Stage 2: Final close (FP / TP). Enrich Stage-1 memory or write fresh if no prior escalation."""
    from datetime import datetime
    from entity_graph.models import ShadowResult

    cfg = get_edr_config()
    comment, _, justification = _extract_all_comments(fields, bot_email=cfg.jira_email or "")

    # Newest-first: force=true reruns leave older rows behind, and an unsorted
    # find_one returns an arbitrary one — often a previously-scored row, which then
    # short-circuits as 'already resolved' and the NEW verdict is never scored.
    shadow = await (
        ShadowResult.find(ShadowResult.jira_key == jira_key)
        .sort(-ShadowResult.created_at)
        .first_or_none()
    )
    if shadow and await _alert_under_test(shadow.alert_name):
        # Deliberately does NOT touch verdict_match (leaves it None) or write any memory
        # — an already-resolved ticket with verdict_match=None reads as "needs rescoring"
        # to the block below (_rescoring), which would otherwise re-score and re-quarantine
        # it the next time this ticket's `updated` timestamp changes for any reason.
        logger.debug("L2 resolution %s — alert '%s' is under test, skipping scoring",
                     jira_key, shadow.alert_name)
        return False

    # Who made the terminal transition. RAPTOR's own closes land on False Positive just
    # like a human's, and this handler used to treat them identically: it recorded the
    # bot's FP as the L1 verdict, scored verdict_match=True (the AI agreeing with
    # itself), and wrote a CURATED "analyst" memory at ~0.80 confidence. That memory then
    # came back through entity recall as a prior verdict, so the next day's close cited
    # it — the self-reinforcing precedent in the AWS credential-abuse family (by DEMO-114642
    # every "prior occurrence" was a RAPTOR auto-close). `None` = could not be established:
    # proceed exactly as before, so a Jira hiccup never drops a real human verdict.
    from edr_triage.jira_handler import last_status_author
    _closer = await last_status_author(jira_key, ("false positive", "closed", "resolved"), cfg)
    if _closer and _closer == (cfg.jira_email or "").lower():
        if not shadow:
            # No row to stamp — and the no-shadow branch below would write an "L1-only"
            # memory from what is really RAPTOR's own close.
            return False
        return await _mark_autonomous_resolved(shadow, jira_key)
    # Same for a ticket Claude closed in bulk from an operator's account: an AI close,
    # not that operator's verdict, so it is stamped resolved but never scored or learned.
    from edr_triage.config import BULK_CLOSE_LABEL
    if BULK_CLOSE_LABEL in (fields.get("labels") or []):
        if not shadow:
            return False
        return await _mark_autonomous_resolved(shadow, jira_key)

    # A REQUEST_JUSTIFICATION ticket closing directly (never through L2) is fine when
    # well-evidenced — this is NOT a blanket "every RJ needs L2" rule, only ones that
    # rest on the justification alone. See _rj_close_is_thin.
    # `l1_handoff_at is None` is what makes this fire at most once — but that stamp is
    # lost whenever a poll misses the L2-status window (see went_through_l2 below), and
    # a lost stamp here does not just mis-label provenance: it transitions a ticket L2
    # has already closed back into "L2 Analysis required". The thread is checked too so
    # the one-shot guarantee rests on a signal that survives a missed poll.
    if (shadow and shadow.ai_triage_class == "REQUEST_JUSTIFICATION"
            and shadow.l1_handoff_at is None
            and not _thread_shows_l2(comment)
            and final_class in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP")):
        _thin = _rj_close_is_thin(shadow)
        if _thin:
            await _route_thin_rj_to_l2(jira_key, fields, shadow, justification, _thin)
            return False

    if shadow:
        # Re-score an already-resolved ticket ONLY when its verdict_match was cleared —
        # i.e. a re-triage overwrote the AI verdict and it needs comparing again. Without
        # this the row would sit resolved-but-unscored forever, silently dropping out of
        # the accuracy denominator (an exclusion, which is exactly what must not happen).
        # A human RECLASSIFYING a ticket must re-score it. Until now the only trigger was
        # verdict_match being cleared by a re-triage, so a status change after the first
        # scoring was invisible: DEMO-107629 was scored on 2026-08-07 while it sat in
        # False Positive, an analyst later re-closed it as Closed (= AUTO_CLOSED_TP), and
        # nothing re-read it. The AI had said NEEDS_L2, which against a confirmed TP is a
        # WARRANTED escalation — so a hit stayed recorded as a miss, and its memory sat in
        # the review queue as a conflict that no longer existed.
        # This only ever re-reads what a HUMAN actually decided; it never re-runs the
        # agent, so the AI verdict being scored is the original one.
        _reclassified = (
            shadow.l2_resolved_at is not None
            and shadow.verdict_match is not None
            and bool(final_class)
            and bool(shadow.l2_triage_class)
            and final_class != shadow.l2_triage_class
        )
        if _reclassified:
            logger.info(
                "L2 resolution %s — human RECLASSIFIED %s -> %s, re-scoring (AI verdict "
                "unchanged: %s)", jira_key, shadow.l2_triage_class, final_class,
                shadow.ai_triage_class,
            )
        _rescoring = shadow.l2_resolved_at is not None and shadow.verdict_match is None
        if shadow.l2_resolved_at is not None and not _rescoring and not _reclassified:
            # Before skipping, heal a memory left behind in quarantine. The quarantine
            # row is written at TRIAGE time from the verdict the AI held then; if a
            # re-triage later moved the AI onto the human's side, verdict_match becomes
            # True but nothing re-runs the tier calculation — this early return is where
            # it stops. The queue then shows a conflict that no longer exists: DEMO-107872
            # sits there captioned "AI said NEEDS_L2, L1 said AUTO_CLOSED_FP" while the
            # shadow reads AUTO_CLOSED_FP / verdict_match=True, a scored HIT (also
            # DEMO-106747, DEMO-106980 — 3 of 109 entries).
            # Strictly one-directional: only quarantine -> curated, and only when the
            # scored verdict says they agreed. It never moves a memory INTO quarantine
            # and never touches a human-promoted one (_refresh_verdict_memory keeps the
            # human's tier when resolved_by is set), so it cannot launder a real
            # disagreement out of the review queue.
            if shadow.verdict_match is True:
                await _heal_stale_quarantine(shadow)
            logger.debug("L2 resolution %s — already resolved, skipping", jira_key)
            return False

        # Fall back to the comment thread when the handoff stamp is missing. The stamp
        # requires a poll to land inside the (single, 5-minute) window in which the
        # ticket sat in "L2 ANALYSIS REQUIRED" with a fresh `updated`; the JQL lookback
        # equals the poll interval and the sleep runs AFTER the work, so every cycle
        # leaves an uncovered gap the width of its own processing time and a one-off
        # transition can fall straight through it. DEMO-111116 was escalated by L1 at
        # 17:07 on 2026-08-31, untouched until L2 closed it FP the next morning: with
        # the stamp missed, close-time took the no-L2 branch and wrote a memory reading
        # "L1: AUTO_CLOSED_FP" with no l2_comment, credited the L2 as the L1 analyst,
        # and scored no escalation precision for the L1 who actually escalated.
        # `_write_direct_memory` already reads L2 off the thread this way; this puts the
        # shadow path on the same durable signal.
        went_through_l2 = shadow.l1_handoff_at is not None or _thread_shows_l2(comment)

        shadow.l2_triage_class = final_class
        shadow.l2_analyst_id = analyst_id or "unknown"
        shadow.l2_resolved_at = datetime.utcnow()
        # Credit a WARRANTED escalation as agreement. An AI NEEDS_L2 is the correct
        # triage call in two cases:
        #  (a) a human confirmed a TRUE POSITIVE — the AI flagged a real threat and a
        #      human agreed it was real. ANY tier's confirmation counts: this used to
        #      require went_through_l2, on the assumption that L2 is the only place a TP
        #      gets confirmed. It isn't. L1 routinely resolves without escalating — they
        #      ask the user, get a business justification back, and close the ticket TP
        #      themselves. 4 of the 9 TP resolutions to date took that path and every one
        #      scored as a MISS while the AI had made the right call (DEMO-106747 dotnet
        #      -install.ps1 on a red-team box, DEMO-106100, DEMO-105606). The confirming
        #      tier says nothing about whether escalating was correct — the TP does; OR
        #  (b) the AI asked for a BUSINESS JUSTIFICATION (REQUEST_JUSTIFICATION) and the
        #      justification loop is exactly what resolved the ticket — the user explained
        #      the activity and it closed FP, or explaining it surfaced a real TP. The AI
        #      cannot see a future justification at triage time, so declining to close and
        #      asking was the correct call (DEMO-106406: Entra privileged-group add, closed
        #      FP once the granting admin explained it).
        # Clause (b) is deliberately scoped to REQUEST_JUSTIFICATION and NOT to NEEDS_L2.
        # Asking the acting user to explain themselves is the AWAITING MORE INPUTS loop
        # that L1 owns inside EVENT ANALYSIS — it is NOT an L2 technical escalation, so a
        # NEEDS_L2 that ended in a justified FP does not get credit for "predicting" a
        # workflow it never named. This matters now that justifications are also detected
        # INLINE (see _JUSTIFICATION_PROVIDED_RE): leaving clause (b) on NEEDS_L2 while
        # widening detection would have retro-credited a large batch of NEEDS_L2 verdicts
        # and inflated accuracy for a call the AI did not make.
        # The over-escalation signal is PRESERVED and is where it has always lived: an FP
        # reached by L1/L2 closing on review with NO justification has `justification`
        # empty → stays a miss. Escalating everything is still punished on the FP side.
        _justified = bool(justification.strip())
        _warranted_escalation = (
            (shadow.ai_triage_class == "NEEDS_L2" and final_class == "AUTO_CLOSED_TP")
            or (
                shadow.ai_triage_class == "REQUEST_JUSTIFICATION"
                and (
                    final_class == "AUTO_CLOSED_TP"
                    or (final_class == "AUTO_CLOSED_FP" and _justified)
                )
            )
        )
        # If the agent ERRORED (e.g. the Mantle/SCP outage), the shadow holds the
        # deterministic playbook's fallback verdict, not a real agent decision — leave
        # verdict_match unset so it never counts as an AI hit/miss in the accuracy metrics.
        if getattr(shadow, "ai_error", None):
            shadow.verdict_match = None
        else:
            shadow.verdict_match = (shadow.ai_triage_class == final_class) or _warranted_escalation

        if not went_through_l2:
            shadow.l1_triage_class = final_class
            shadow.l1_analyst_id = analyst_id or "unknown"
            shadow.l1_resolved_at = datetime.utcnow()

        await shadow.save()

        logger.info(
            "Shadow match %s: ai=%s final=%s match=%s via_l2=%s justified=%s analyst=%s",
            jira_key, shadow.ai_triage_class, final_class, shadow.verdict_match,
            went_through_l2, bool(justification.strip()), analyst_name,
        )

        # Analyst quality is only scoreable when an independent second opinion
        # exists — i.e. this ticket went L1 → L2. Score the L1 analyst's ESCALATION
        # PRECISION against the L2 ground truth: escalation was warranted when L2
        # confirmed a true positive, over-escalation when L2 closed it as an FP.
        # Direct L1 closes have no ground truth and are intentionally not recorded
        # (recording them was the bug that pinned accuracy at ~100%).
        # `not _rescoring` — on a re-score the analyst's verdict was already recorded the
        # first time round; recording it again would inflate their scored-decision count
        # for a decision they only made once.
        if (not _rescoring) and went_through_l2 and shadow.l1_analyst_id and shadow.l1_analyst_id != "unknown":
            from entity_graph.analyst_profile import record_verdict
            await record_verdict(
                shadow.l1_analyst_id,
                shadow.l1_analyst_id,
                was_correct=(final_class == "AUTO_CLOSED_TP"),
            )

        from edr_triage.classifier import memory_alert_type as classify
        alert_type = classify(shadow.alert_name)
        if alert_type == "skip":
            return False

        if went_through_l2:
            from entity_graph.memory import update_memory_l2_verdict
            updated = await update_memory_l2_verdict(
                jira_key=jira_key,
                l2_triage_class=final_class,
                l2_comment=comment,
                ai_triage_class=shadow.ai_triage_class,
                ai_confidence=shadow.ai_confidence,
                # Pass the SAME verdict_match just computed above — not recomputed
                # inside update_memory_l2_verdict — so the memory's tier can't drift
                # out of sync with the accuracy metric's own judgment (warranted
                # escalations, ai_error non-decisions) the way it did before.
                ai_agreed=shadow.verdict_match,
            )
            if not updated:
                await _write_verdict_memory(shadow, final_class, analyst_id,
                                            l1_comment=comment, alert_type=alert_type,
                                            justification=justification)
        else:
            await _write_verdict_memory(shadow, final_class, analyst_id,
                                        l1_comment=comment, alert_type=alert_type,
                                        justification=justification)

        # Reinforce / contradict existing memories — but only on a HUMAN verdict.
        # Status alone cannot say who closed it: RAPTOR's own autonomous closes land on
        # False Positive too, and feeding those back would let every close reinforce the
        # memory that produced it. Unknown closer -> skip; never assume human.
        try:
            from edr_triage.classifier import alert_subtype
            from entity_graph.memory import reconcile_human_verdict
            if _closer and _closer != (cfg.jira_email or "").lower():
                _rec = await reconcile_human_verdict(
                    [alert_type, alert_subtype(shadow.alert_name)],
                    shadow.user_name or "", shadow.device_name or "", final_class, jira_key)
                if _rec["refreshed"] or _rec["demoted"]:
                    logger.info("memory reconcile %s (%s by %s): %s",
                                jira_key, final_class, _closer, _rec)
        except Exception as exc:
            logger.warning("memory reconcile skipped for %s: %s", jira_key, exc)
    else:
        if not comment.strip():
            logger.debug("Skipping %s — no ShadowResult and no comment", jira_key)
            return False
        summary = (fields.get("summary") or "").strip()
        from edr_triage.classifier import memory_alert_type as classify
        alert_type = classify(summary)
        if alert_type in ("generic", "skip"):
            logger.debug("Skipping %s — no ShadowResult and alert_type=%s (%s)", jira_key, alert_type, summary[:60])
            return False
        logger.info("No shadow result for %s — writing L1-only memory (alert_type=%s)", jira_key, alert_type)
        await _write_direct_memory(jira_key, summary, final_class, comment, alert_type,
                                   justification=justification)

    return True


# A RELAYED user business justification (the Slack workflow posts it as a bot
# comment) vs the bot's OWN AI-analysis/triage output. We capture the former
# (ground truth) and skip the latter (re-ingesting our own verdict is circular).
_JUSTIFICATION_MARKERS = ("added a business justification", "business justification via slack")
_AI_ANALYSIS_MARKERS = ("ai analysis", "auto-analysed by deepintel", "auto-triaged by raptor")

# A justification supplied INLINE in the ticket rather than relayed by the Slack bot.
# The Slack-relay markers above only catch one workflow; in practice L1 asks in the
# ticket and the user answers in the ticket, then L1 closes FP citing it (DEMO-106406:
# "has provided a justification for this activity … User's justification: …"). Without
# this the justification loop was invisible to scoring.
# Deliberately keyed on PAST-TENSE "provided"/"justification:" wording so the ASK
# ("Please provide business justification for the observed activity") never counts as an
# answer — an FP closed on plain review with no justification must stay a miss, since
# that is the genuine over-escalation signal.
# Jira comments arrive with TYPOGRAPHIC punctuation — the Jira editor (and macOS,
# and Word paste) autocorrects ' to U+2019 and " to U+201C/D. DEMO-108107 is the case:
# L1 wrote "Based on the user’s justification, they have received the ticket for
# onboarding" — the justification loop had run exactly as designed, the user had
# answered in the ticket, and L1 recorded it in the precise wording this regex looks
# for — but `user’s` is not `user's`, so the match failed, `justification` stayed
# empty, clause (b) could not fire, and an FP the ask-the-user loop resolved scored as
# a miss. Normalise a COPY for matching only; the stored comment keeps its original
# characters.
_PUNCT_FOLD = str.maketrans({
    "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'",
    "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u2032": "'", "\u2033": '"',
    "\u2013": "-", "\u2014": "-", "\u2212": "-", "\u00a0": " ",
})


def _fold_punct(text: str) -> str:
    """ASCII-fold smart quotes/dashes so keyword matching is not defeated by them."""
    return (text or "").translate(_PUNCT_FOLD)


_JUSTIFICATION_PROVIDED_RE = re.compile(
    r"provided\s+(?:a|the|his|her|their)?\s*(?:business\s+)?justification"
    r"|(?:user|user's|users)\s+justification"
    r"|justification\s*(?:provided|received|shared)"
    r"|justification\s*:",
    re.I,
)


def _extract_all_comments(fields: dict, bot_email: str = "") -> tuple[str, str, str]:
    """Extract all human comments from a ticket with role attribution.

    Tags each human comment as [L1], [L2], or [user] via the analyst role
    registry. Bot comments are skipped EXCEPT a relayed user business
    justification, which is captured separately (context only). Returns:
      attributed_text — human conversation with role prefixes (stored in l1_comment)
      l1_only        — only L1 comments joined (for backwards-compat logging)
      justification  — relayed user business justification(s), if any (CONTEXT ONLY)
    """
    from edr_triage.jira_poller import _adf_to_text
    from edr_triage.analyst_store import get_analyst_role

    comment_block = fields.get("comment") or {}
    comments = comment_block.get("comments") or []

    parts: list[str] = []
    l1_parts: list[str] = []
    just_parts: list[str] = []

    for c in comments:
        author = c.get("author") or {}
        author_email = author.get("emailAddress", "").lower()

        body_raw = c.get("body") or ""
        text = _adf_to_text(body_raw) if isinstance(body_raw, dict) else str(body_raw)
        text = text.strip()
        if not text:
            continue

        if bot_email and author_email == bot_email.lower():
            # Skip the bot's own AI-analysis/triage + operational (notify/reminder)
            # comments — re-ingesting RAPTOR's own verdict is circular. BUT keep a
            # RELAYED user business justification (DEMO-106480: "…Percona MongoDB
            # Testing and Cert Rotation") — it's user ground truth. Captured as
            # CONTEXT ONLY (labelled re-validate/not-exculpatory downstream); it
            # never drives an auto-close.
            low = _fold_punct(text).lower()
            if (any(m in low for m in _JUSTIFICATION_MARKERS)
                    and not any(m in low for m in _AI_ANALYSIS_MARKERS)):
                just_parts.append(text)
            continue

        role = get_analyst_role(author_email)
        display = author.get("displayName", author_email) or author_email
        parts.append(f"[{role} — {display}]\n{text}")
        if role == "L1":
            l1_parts.append(text)
        # An inline justification — the acting user explaining the activity, or an
        # analyst recording that they did. Same CONTEXT-ONLY status as the Slack-relayed
        # one: it is evidence the justification loop ran, and never on its own a reason
        # to close anything.
        #
        # role == "user" alone counts, not just the keyword regex: DEMO-108035's actor
        # replied with a full explanation (a Microsoft Graph baseline-scope change that
        # broke an existing MFA bypass, requiring a second one) after L2 asked "can you
        # confirm this activity" — he never once said the word "justification", so the
        # regex alone missed it and a genuinely-settled REQUEST_JUSTIFICATION scored as
        # a miss. Anyone who isn't a registered L1/L2 analyst commenting on a ticket IS
        # the justification loop completing, by construction — the specific phrasing was
        # never the thing that mattered.
        if role == "user" or _JUSTIFICATION_PROVIDED_RE.search(_fold_punct(text)):
            just_parts.append(f"[{role} — {display}] {text}")

    attributed_text = "\n\n".join(parts)
    l1_only = "\n\n".join(l1_parts)
    justification = "\n".join(just_parts)
    return attributed_text, l1_only, justification


async def _memory_entity_ids(shadow, upsert_entity) -> list[str]:
    """Entity ids a memory for `shadow` should link: the device + EVERY user involved.

    get-or-create so the memory ALWAYS links to the device/user when a name is present.
    Previously used get-only, which silently dropped the link if triage-time extraction
    hadn't created the entity — leaving entity_ids=[] and making per-entity memory recall
    non-functional. risk_delta=0 → no score change.

    Every user, not just `shadow.user_name`: recall is entity-id scoped
    (memory.recall_memories), so a co-user who is not linked can never surface this
    memory. DEMO-107416's memory linked taylor.singh alone while the verdict was
    reached about toby.vohra. `actor` stays the primary user — it feeds the armed
    actor-allowlist (auto_fp), which must not widen as a side effect of entity linking.
    """
    entities: list[str] = []
    if shadow.device_name:
        e = await upsert_entity("device", shadow.device_name, source_system="mde", risk_delta=0.0)
        if e:
            entities.append(str(e.id))
    _users = [shadow.user_name, *(getattr(shadow, "additional_users", None) or [])]
    for _u in dict.fromkeys(u for u in _users if u):
        e = await upsert_entity("user", _u, source_system="mde", risk_delta=0.0)
        if e:
            entities.append(str(e.id))
    return entities


def pending_reason(ai_triage_class: str, ai_error: str | None = None) -> str:
    """Caption for a still-PENDING quarantine row, given the AI's current verdict.

    Encodes the AI-vs-L1 split at hand-off so the queue distinguishes "L1 escalated and
    the AI agreed it needed L2" from "the AI would have auto-closed this but L1 escalated
    anyway" — the latter is the high-value review case (either L1 over-escalated or the
    AI missed something). Kept under the "Pending L2 resolution" prefix (NOT "AI said …")
    so it doesn't double-count in the resolved AI-vs-L2 pollution metric; the split is
    provisional until L2 rules.

    Shared with the re-triage refresh in edr_triage.pipeline. It lived only here, and the
    refresh hardcoded "AI concurred" for every class — so a re-triage that moved the AI to
    AUTO_CLOSED_FP relabelled a genuine split as agreement (DEMO-107068, DEMO-108429 both
    read "AI concurred (AUTO_CLOSED_FP)" against an L1 escalation, which is the exact
    review case the caption exists to surface). One definition so the two cannot drift.
    """
    _ai = (ai_triage_class or "").upper()
    if ai_error:
        # A fallback verdict is not an AI opinion — don't caption it as agreement or
        # dissent (same non-decision the accuracy metric excludes via verdict_match=None).
        return "Pending L2 resolution — no real AI verdict (agent error)"
    if _ai in ("NEEDS_L2", "URGENT"):
        return f"Pending L2 resolution — AI concurred ({ai_triage_class})"
    if _ai:
        return f"Pending L2 resolution — AI/L1 split (AI: {ai_triage_class}, L1: escalated)"
    return "Pending L2 resolution"


async def _write_l2_handoff_memory(shadow, l1_comment: str, alert_type: str) -> None:
    """Write a provisional quarantine memory when L1 escalates to L2."""
    from entity_graph.memory import write_memory
    from entity_graph.graph import upsert_entity

    entities = await _memory_entity_ids(shadow, upsert_entity)

    # An ai_error shadow's triage_class is a deterministic FALLBACK, not a real AI
    # opinion — don't caption it "AI concurred"/"AI/L1 split" as if it were one
    # (DEMO-106643-adjacent: same non-decision the accuracy metric already excludes
    # via verdict_match=None, applied here to the provisional handoff label too).
    _ai_err = getattr(shadow, "ai_error", None)
    _ai_label = (f"verdict unavailable ({_ai_err})" if _ai_err
                 else f"{shadow.ai_triage_class} (conf={shadow.ai_confidence:.0%})")
    content = (
        f"[{alert_type}] '{shadow.alert_name}' escalated to L2 — AI: {_ai_label}"
        + (f"\n{verdict_aware_truncate(l1_comment, 400)}" if l1_comment else "")
        + "\n[Pending L2 resolution]"
    ).strip()

    # Encode the AI-vs-L1 split at handoff time so the quarantine queue distinguishes
    # "L1 escalated and the AI agreed it needed L2" from "the AI would have auto-closed
    # this but L1 escalated anyway" — the latter is the high-value review case (either
    # L1 over-escalated or the AI missed something). Kept under the "Pending L2 resolution"
    # prefix (NOT the "AI said …" prefix) so it doesn't double-count in the resolved
    # AI-vs-L2 pollution metric — this split is provisional until L2 rules.
    _reason = pending_reason(shadow.ai_triage_class, _ai_err)

    # Same create-only problem as the resolution path: a re-triage changes the AI
    # verdict but write_memory would return the stale row untouched, leaving the
    # review queue captioned with a verdict the agent no longer holds (DEMO-107770 /
    # DEMO-107800 both still read "AI: AUTO_CLOSED_FP" after the agent moved to
    # NEEDS_L2). Refresh in place; create only when absent.
    if not await _refresh_verdict_memory(
        shadow.jira_key, tier="quarantine", confidence=0.50,
        quarantine_reason=_reason, content=content, l1_comment=l1_comment,
    ):
        await write_memory(
            entity_ids=entities,
            memory_type="analyst_verdict",
            content=content,
            confidence=0.50,
            source="analyst",
            jira_key=shadow.jira_key,
            alert_ref=shadow.alert_id,
            tier="quarantine",
            quarantine_reason=_reason,
            alert_type=alert_type,
            l1_comment=l1_comment,
            actor=shadow.user_name or "",
            device=shadow.device_name or "",
            actors=[g.get("actor", "") for g in (getattr(shadow, "actor_hosts", None) or [])
                    if isinstance(g, dict) and g.get("actor")],
        )


async def _write_verdict_memory(shadow, l1_triage_class: str, analyst_id: str,
                                 l1_comment: str = "", alert_type: str = "",
                                 justification: str = "") -> None:
    """Write a memory from a confirmed L1 verdict, including analyst comment and alert type.

    ``justification`` (if present) is a RELAYED user business justification, stored
    as CONTEXT ONLY — labelled re-validate/not-exculpatory so recall surfaces it to
    inform the next investigation WITHOUT ever justifying an auto-close on its own
    (a prior justification doesn't validate a new privesc event — DEMO-106480)."""
    from entity_graph.memory import write_memory
    from entity_graph.graph import upsert_entity

    entities = await _memory_entity_ids(shadow, upsert_entity)

    # Write memory even without entity bindings — playbook-level memories
    # (alert_type tagged) are still useful for pattern recall even if the
    # specific device/user haven't been seen before.
    ai_agreed = shadow.verdict_match
    # verdict_match is None in exactly one situation at this point in the call chain:
    # _handle_l2_resolution just set it that way because the shadow carries an
    # ai_error (agent_exception, no_tool_calls, ...) — a deterministic FALLBACK
    # verdict, not a real agent opinion. `if ai_agreed:` treated None the same as
    # False, so an infra failure landed in the quarantine REVIEW queue captioned
    # "AI said NEEDS_L2, L1 said AUTO_CLOSED_FP" as if it were a genuine disagreement
    # (DEMO-106643: Mantle 500 mid-triage, fell back to NEEDS_L2 at 0% confidence with
    # zero tool calls; L1 closed FP off a Slack justification — there was never an AI
    # verdict to disagree with L1 in the first place). Route it like the no-shadow
    # human-only case (_write_direct_memory, cfcd5b4) instead: nothing to adjudicate,
    # so curated, not quarantine.
    _no_real_verdict = ai_agreed is None
    _ai_err = getattr(shadow, "ai_error", None)
    _ai_line = (
        (f"AI: verdict unavailable ({_ai_err}) — fell back to a default, not a real "
         "agent opinion" if _ai_err else "AI: verdict not scored")
        if _no_real_verdict else
        f"AI: {shadow.ai_triage_class} (conf={shadow.ai_confidence:.0%})"
    )
    # Context-only justification prefix — prepended (not appended) so it survives the
    # comment truncation below and is surfaced first on recall. The label makes clear
    # it is NOT a basis for auto-closing a future occurrence.
    #
    # 200 chars cut the substance out of most real justifications, keeping only a
    # head fragment plus the concluding verdict sentence (DEMO-108122: Sravan's actual
    # explanation — a SQL Server hardening audit script, config/logs only — was
    # replaced by "...we are required to provid … Therefore, we are classifying this
    # as a false positive", losing exactly the content a future similar alert needs).
    # This is the one piece of context specifically meant to inform reasoning on a
    # NEXT occurrence, so it gets real budget instead of the comment-log truncation.
    _just = (f"[PRIOR BUSINESS JUSTIFICATION — context only, re-validate each occurrence, "
             f"NOT exculpatory on its own]: {verdict_aware_truncate(justification, 800)}\n"
             if justification else "")
    verdict_summary = (
        _just
        + f"[{alert_type}] Alert '{shadow.alert_name}' — "
        f"L1: {l1_triage_class} | {_ai_line}. "
        + (f"L1 note: {verdict_aware_truncate(l1_comment, 300)}" if l1_comment else "")
    ).strip()

    if _no_real_verdict or ai_agreed:
        confidence = 0.50 if _no_real_verdict else (shadow.ai_confidence + 0.65) / 2
        tier = "curated"
        source = "analyst"
        _reason = ""
    else:
        confidence = 0.50
        tier = "quarantine"
        source = "analyst"
        _reason = f"AI said {shadow.ai_triage_class}, L1 said {l1_triage_class}"

    # write_memory is create-only: it finds an existing row for this jira_key and
    # returns it untouched, which silently drops a RE-SCORE. A re-triage that flips
    # agreement into disagreement then left the memory sitting in `curated` with no
    # quarantine_reason, so the conflict never reached the review queue (DEMO-107507:
    # AI moved AUTO_CLOSED_FP -> NEEDS_L2 against an FP closure, verdict_match went
    # true -> false, and the memory stayed curated). Refresh the verdict-derived
    # fields in place when the row already exists; only create when it doesn't.
    if not await _refresh_verdict_memory(
        shadow.jira_key, tier=tier, confidence=confidence,
        quarantine_reason=_reason, content=verdict_summary, l1_comment=l1_comment,
    ):
        await write_memory(
            entity_ids=entities,
            memory_type="analyst_verdict",
            content=verdict_summary,
            confidence=confidence,
            source=source,
            jira_key=shadow.jira_key,
            alert_ref=shadow.alert_id,
            tier=tier,
            quarantine_reason=_reason,
            alert_type=alert_type,
            l1_comment=l1_comment,
            actor=shadow.user_name or "",
            device=shadow.device_name or "",
            actors=[g.get("actor", "") for g in (getattr(shadow, "actor_hosts", None) or [])
                    if isinstance(g, dict) and g.get("actor")],
        )


async def _heal_stale_quarantine(shadow) -> bool:
    """Move a memory out of quarantine when the shadow it describes now AGREES.

    The quarantine caption is a snapshot of the AI verdict at triage time. A later
    re-triage can flip that verdict onto the human's side — verdict_match goes True and
    the ticket scores as a hit — but the memory keeps the old caption and the old tier,
    so the review queue accumulates conflicts that have already been settled.

    Only ever quarantine -> curated, and only on verdict_match True. Human-promoted rows
    are left alone entirely: their tier is the analyst's decision, and golden already
    outranks curated, so there is nothing to heal there.
    """
    try:
        from app.database import get_collection
        col = get_collection("eg_memories")
        existing = await col.find_one(
            {"jira_key": shadow.jira_key},
            {"_id": 1, "tier": 1, "resolved_by": 1, "content": 1},
        )
        if not existing or (existing.get("tier") or "") != "quarantine":
            return False
        if (existing.get("resolved_by") or "").strip():
            return False
        _conf = (getattr(shadow, "ai_confidence", None) or 0.0)
        await col.update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "tier": "curated",
                "quarantine_reason": "",
                "confidence": (_conf + 0.65) / 2,
                # The stored caption still names the pre-re-triage verdict. Correct it
                # to what the AI actually concluded, or the memory recalls a verdict the
                # agent no longer holds.
                "content": _re_caption(existing.get("content") or "", shadow),
            }},
        )
        logger.info(
            "Healed stale quarantine memory %s: AI now %s, human %s, verdict_match=True "
            "— moved quarantine -> curated",
            shadow.jira_key, shadow.ai_triage_class,
            shadow.l2_triage_class or shadow.l1_triage_class,
        )
        return True
    except Exception as exc:
        logger.error("_heal_stale_quarantine(%s) failed: %s", shadow.jira_key, exc)
        return False


def _re_caption(content: str, shadow) -> str:
    """Rewrite the stale 'AI: <old verdict>' fragment to the AI's current verdict."""
    import re as _re
    _new = f"AI: {shadow.ai_triage_class} (conf={(getattr(shadow, 'ai_confidence', None) or 0):.0%})"
    # [A-Z0-9_]+, not [A-Z_]+ — every class name that matters here ends in a digit
    # (NEEDS_L2), so a letters-only class silently never matched.
    _out, _n = _re.subn(r"AI: [A-Z0-9_]+ \(conf=\d+%\)", _new, content, count=1)
    return _out if _n else content


async def _refresh_verdict_memory(jira_key: str, tier: str, confidence: float,
                                  quarantine_reason: str, content: str,
                                  l1_comment: str = "") -> bool:
    """Update an EXISTING memory's verdict-derived fields. False if none exists.

    Deliberately narrow: only tier / confidence / quarantine_reason / content /
    l1_comment move. Scope, actor, device, commands, apps and auto_fp are human
    decisions (an L2 promote/arm) and must survive a re-score untouched.

    TIER IS ALSO A HUMAN DECISION once someone has promoted the memory, and it was
    missing from that list. `promote_memory` sets tier=golden alongside resolved_by /
    resolved_at; a later re-score recomputed the tier from AI-vs-human agreement and
    wrote it straight back to quarantine — reversing an L2 promotion silently, and
    taking the memory out of recall entirely (get_playbook_memories and
    recall_memories both filter on tier in [curated, golden]). DEMO-107947 was
    promoted to a golden playbook precedent and was back in the quarantine queue one
    poll later, with the promotion gone and nothing to show it had happened.

    So: when `resolved_by` is set, keep the human's tier and confidence. The verdict
    text still refreshes, and a re-score that DISAGREES marks the reason [FLAGGED] so
    the conflict is visible for review rather than either silently reversing the human
    or silently hiding that the AI now disagrees with them.
    """
    try:
        from app.database import get_collection
        col = get_collection("eg_memories")
        existing = await col.find_one({"jira_key": jira_key},
                                      {"_id": 1, "tier": 1, "resolved_by": 1})
        if not existing:
            return False
        _human = bool((existing.get("resolved_by") or "").strip())
        _set = {"quarantine_reason": quarantine_reason, "content": content}
        if l1_comment:
            _set["l1_comment"] = l1_comment
        if _human:
            if quarantine_reason and not quarantine_reason.startswith("[FLAGGED]"):
                _set["quarantine_reason"] = f"[FLAGGED] {quarantine_reason}"
            if (existing.get("tier") or "") != tier:
                logger.warning(
                    "Memory %s re-score would have re-tiered %s -> %s, but it was promoted "
                    "by %s — keeping the human tier and flagging instead (%s)",
                    jira_key, existing.get("tier"), tier,
                    existing.get("resolved_by"), quarantine_reason or "agreed",
                )
        else:
            _set["tier"] = tier
            _set["confidence"] = confidence
            if (existing.get("tier") or "") != tier:
                logger.info("Memory re-tiered on re-score %s: %s -> %s (%s)",
                            jira_key, existing.get("tier"), tier, quarantine_reason or "agreed")
        await col.update_one({"_id": existing["_id"]}, {"$set": _set})
        return True
    except Exception as exc:
        logger.error("_refresh_verdict_memory(%s) failed: %s", jira_key, exc)
        return False


async def _write_direct_memory(jira_key: str, summary: str, final_class: str,
                               attributed_comment: str, alert_type: str,
                               justification: str = "") -> None:
    """Write a memory for a ticket that was never triaged by DeepIntel (no ShadowResult).

    With no shadow there's no ``l1_handoff_at`` to tell whether the ticket went to
    L2, so the resolving tier is read from the attributed comment thread instead:
    ``_extract_all_comments`` tags each comment ``[L1 — …]`` / ``[L2 — …]``. If an
    L2 analyst is present, the final verdict is L2's (after an L1 escalation), so
    the memory is attributed to L2 — not blanket-labelled "L1" (the bug that
    mislabelled L2 FP closes like DEMO-46549 as L1 closes).

    Tier = ``curated`` (NOT quarantine): with no AI verdict there is nothing to
    adjudicate, so the quarantine REVIEW queue is the wrong home — it just clutters
    with un-actionable rows (DEMO-106942, closed while USE_AGENT_LOOP was off). The
    analyst's verdict is authoritative ground truth, so it goes straight to curated
    where it (a) stays out of the review queue and (b) informs future triage recall
    (recall reads curated+golden), same as an AI-agreed verdict. It's still
    distinguishable from AI-corroborated curated rows — those carry an "AI: …" line
    in their content; these don't.
    """
    from entity_graph.memory import write_memory
    from entity_graph.graph import upsert_entity
    from edr_triage.store import get_alert_by_jira_key

    went_l2 = _thread_shows_l2(attributed_comment)
    verdict_line = (
        f"L2: {final_class} (escalated by L1)" if went_l2 else f"L1: {final_class}"
    )
    # Context-only justification prefix (see _write_verdict_memory) — prepended so it
    # survives truncation and surfaces on recall, labelled so it never drives auto-close.
    # Same 800-char budget as _write_verdict_memory — this is the one field meant to
    # inform reasoning on a FUTURE similar alert, so it gets real room instead of the
    # comment-log truncation (DEMO-108122).
    _just = (f"[PRIOR BUSINESS JUSTIFICATION — context only, re-validate each occurrence, "
             f"NOT exculpatory on its own]: {verdict_aware_truncate(justification, 800)}\n"
             if justification else "")
    content = (
        _just
        + f"[{alert_type}] '{summary}' — {verdict_line}"
        + (f"\n{verdict_aware_truncate(attributed_comment, 400)}" if attributed_comment else "")
    ).strip()

    # Bind the device/user the ticket carried at triage time (recovered from the
    # store record — there's no shadow to read them from). recall_memories is
    # entity-scoped, so WITHOUT these bindings a curated memory is never recalled;
    # WITH them the analyst verdict actually informs future triage (DEMO-106942).
    entities: list[str] = []
    try:
        _rec = await asyncio.to_thread(get_alert_by_jira_key, jira_key) or {}
        _dev = (_rec.get("device_name") or "").strip()
        if _dev:
            e = await upsert_entity("device", _dev, source_system="mde", risk_delta=0.0)
            if e:
                entities.append(str(e.id))
        # Every user the ticket carried, same reason as _memory_entity_ids: an unlinked
        # co-user can never recall this memory.
        _usrs = [(_rec.get("user_name") or "").strip(),
                 *[(str(u) or "").strip() for u in (_rec.get("additional_users") or [])]]
        for _usr in dict.fromkeys(u for u in _usrs if u):
            e = await upsert_entity("user", _usr, source_system="mde", risk_delta=0.0)
            if e:
                entities.append(str(e.id))
    except Exception as exc:
        logger.debug("direct-memory entity bind failed for %s: %s", jira_key, exc)

    await write_memory(
        entity_ids=entities,
        memory_type="analyst_verdict",
        content=content,
        confidence=0.55,
        source="analyst",
        jira_key=jira_key,
        tier="curated",
        quarantine_reason="",
        alert_type=alert_type,
        l1_comment=attributed_comment,
    )


async def run_forever(interval_seconds: int = 300) -> None:
    """Run the closure poller in a loop. Called from main app startup.

    The lookback deliberately EXCEEDS the interval. `sleep` runs after `poll_once`, so
    consecutive polls are `interval + work` apart while each looks back a fixed window —
    with the two equal, every cycle leaves an uncovered gap as wide as its own
    processing time, and `_retrigger_dependents` runs full re-triages inside a cycle, so
    that is seconds to minutes, not milliseconds. A status transition landing in the gap
    is never seen, and for the L2 handoff that loss is permanent (DEMO-111116). Overlap
    is the cheap side of the trade and is safe: every handler is idempotent — the
    handoff re-stamp is guarded (`l1_handoff_at is not None` → refresh only), the
    resolution early-returns on an already-scored row, and the awaiting-inputs and
    duplicate paths only refresh/stamp.
    """
    lookback_minutes = max(5, (interval_seconds // 60) * 3)
    logger.info("Jira closure poller started (interval=%ds, lookback=%dm)",
                interval_seconds, lookback_minutes)
    while True:
        try:
            await poll_once(lookback_minutes=lookback_minutes)
        except Exception as exc:
            logger.error("Closure poller cycle failed: %s", exc)
        await asyncio.sleep(interval_seconds)
