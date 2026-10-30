"""Root Privesc held behind an open sibling instead of escalated beside it.

The concurrent-alert gate is the LAST agent gate (agent_core/loop.py), so when it is the
one that turned an AUTO_CLOSED_FP into NEEDS_L2, everything before it passed. For Root
Privesc that verdict then went to L2 as a second ticket on an incident L2 already had:
DEMO-118277 and DEMO-118281 (sage's routine `sudo tcpdump`) both escalated only
because the multi-host DEMO-118007 was still open with L2.

So when the open sibling is the ONLY thing in the way — the model said FP, every agent
gate passed, the privesc repeat rule and the session check pass, the family may close,
nothing is braked, not CRITICAL, not a test box — the ticket is HELD instead:

  * moved to Event Analysis (never Awaiting more inputs: entering that status fires the
    Acme Security Bot at whoever is named on the ticket),
  * assigned to the analyst who owns the blocking ticket, linked "is blocked by" it,
    labelled raptor-held, with a comment saying why.

Release (jira_closure_poller):
  * the blocker closes False Positive → the existing re-trigger re-triages the held
    ticket from scratch; it closes only if it passes every check on its own, and if
    another blocker is still open it is held again;
  * the blocker closes any other way (Resolved / Closed — may be a true positive) → the
    held ticket goes to L2 Analysis required, never re-triaged;
  * HOLD_HOURS without a release → L2 Analysis required.
It never closes anything the existing gates would not; it only waits for the incident
the gate is worried about to get a human answer.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

HOLD_LABEL = "raptor-held"
EXPIRED_LABEL = "raptor-held-expired"   # route to L2 failed once; never retried
HOLD_STATUS = "Event Analysis"
HOLD_HOURS = 24
_MARKER = "RAPTOR is holding this ticket"


def holdable(agent_result, alert_name: str, severity: str, is_test: bool,
             actor_ambiguous: bool) -> tuple[bool, str]:
    """(ok, why-not). Pure: the model-side preconditions only."""
    from edr_triage import privesc_guard
    if not privesc_guard.applies(alert_name):
        return False, "not Root Privilege Escalation"
    if agent_result is None:
        return False, "no agent verdict"
    if (getattr(agent_result, "pre_safety_class", "") or "") != "AUTO_CLOSED_FP":
        return False, "the model did not call it a false positive"
    if not (getattr(agent_result, "blocked_by_concurrent_keys", None) or []):
        return False, "not blocked by an open sibling"
    if not (getattr(agent_result, "safety_block_reason", "") or "").startswith("Concurrent open alerts"):
        return False, "another gate blocked it"
    if (severity or "").strip().upper() == "CRITICAL":
        return False, "CRITICAL severity"
    if is_test:
        return False, "test device"
    if actor_ambiguous:
        return False, "actor ambiguous"
    return True, ""


async def _issue(key: str, cfg, fields: str) -> dict:
    from edr_triage.jira_handler import _build_client
    async with _build_client(cfg) as c:
        r = await c.get(f"/rest/api/3/issue/{key}", params={"fields": fields})
        r.raise_for_status()
        return r.json().get("fields") or {}


async def blocker_owner(blockers: list[str], cfg) -> tuple[str, str]:
    """(accountId, displayName) of the first blocker assigned to a person; falls back to
    the configured L2 owner."""
    from edr_triage.jira_handler import _self_account_id
    me = await _self_account_id(cfg)
    for k in blockers:
        try:
            a = (await _issue(k, cfg, "assignee")).get("assignee") or {}
        except Exception as exc:
            logger.warning("concurrency_hold: assignee of %s unreadable: %s", k, exc)
            continue
        if a.get("accountId") and a["accountId"] != me:
            return a["accountId"], a.get("displayName") or k
    return (getattr(cfg, "l2_assignee_account_id", "") or "",
            getattr(cfg, "l2_assignee_name", "") or "the L2 owner")


async def may_hold_now(jira_key: str, cfg) -> tuple[bool, str]:
    """Ticket-state precondition: nobody has moved it on — Open/Assigned and unowned, or
    already one of OUR holds (a re-triage while another blocker is still open)."""
    try:
        f = await _issue(jira_key, cfg, "status,labels,assignee")
    except Exception as exc:
        return False, f"ticket unreadable ({exc})"
    st = ((f.get("status") or {}).get("name") or "").strip().lower()
    if HOLD_LABEL in (f.get("labels") or []) and st == HOLD_STATUS.lower():
        return True, ""
    if st not in ("open", "assigned"):
        return False, f"ticket already in {st or 'an unknown status'}"
    from edr_triage.jira_handler import owned_by_a_person
    owner = await owned_by_a_person(jira_key, cfg)
    if owner is None:
        return False, "could not read who owns the ticket"
    if owner:
        return False, f"{owner} has already picked this ticket up"
    return True, ""


async def link_blocked_by(jira_key: str, blocker: str, cfg) -> bool:
    from edr_triage.jira_handler import _build_client
    try:
        async with _build_client(cfg) as c:
            r = await c.post("/rest/api/3/issueLink", json={
                "type": {"name": "Blocks"},
                "outwardIssue": {"key": blocker},    # blocker "blocks" ...
                "inwardIssue": {"key": jira_key},    # ... this one ("is blocked by")
            })
            return r.status_code in (200, 201)
    except Exception as exc:
        logger.warning("concurrency_hold: link %s blocked-by %s failed: %s", jira_key, blocker, exc)
        return False


def hold_comment(blockers: list[str], owner: str) -> str:
    b = ", ".join(blockers)
    return (f"*{_MARKER}* behind {b}, which is still open with {owner}.\n\n"
            "RAPTOR found this alert benign and every close check passed except one: another "
            f"open alert on the same user or host ({b}). Rather than send a second ticket to "
            "L2 for the same incident, it waits here for that one:\n"
            f"* closed as False Positive → RAPTOR re-checks this ticket from scratch;\n"
            f"* closed any other way → this ticket moves to L2 Analysis required;\n"
            f"* still open after {HOLD_HOURS}h → this ticket moves to L2 Analysis required.\n\n"
            "Nobody was messaged.\n\n[Auto-triaged by RAPTOR]")


async def hold(jira_key: str, blockers: list[str], cfg, dry_run: bool = False) -> bool:
    """Move to Event Analysis, assign to the blocker's owner, link, label, comment.
    False (and nothing beyond a possible partial walk) when the walk fails."""
    from edr_triage.jira_handler import add_comment, add_labels, assign_issue, walk_to_status
    if not await walk_to_status(jira_key, ["Assigned", HOLD_STATUS], cfg,
                                forbidden=cfg.close_forbidden(), dry_run=dry_run):
        logger.error("[HOLD] %s: could not reach %s — not held", jira_key, HOLD_STATUS)
        return False
    acc, name = await blocker_owner(blockers, cfg)
    if not dry_run:
        await assign_issue(jira_key, acc, cfg)
        for b in blockers:
            await link_blocked_by(jira_key, b, cfg)
    await add_labels(jira_key, [HOLD_LABEL], cfg, dry_run=dry_run)
    await add_comment(jira_key, hold_comment(blockers, name), cfg, dry_run=dry_run)
    logger.info("[HOLD] %s: held behind %s, assigned to %s", jira_key, blockers, name)
    return True


async def is_held(jira_key: str, cfg) -> bool:
    try:
        f = await _issue(jira_key, cfg, "status,labels")
    except Exception:
        return False
    return (HOLD_LABEL in (f.get("labels") or [])
            and ((f.get("status") or {}).get("name") or "").strip().lower() == HOLD_STATUS.lower())


async def release_to_l2(jira_key: str, why: str, cfg) -> bool:
    """Send a held ticket to L2 Analysis required with the reason."""
    from types import SimpleNamespace
    from edr_triage.jira_handler import add_labels
    from edr_triage.pipeline import _execute_l2_route
    res = SimpleNamespace(labels=["needs-l2-review"])
    out = await _execute_l2_route(jira_key, cfg, res, False, why=why)
    if out != "routed_to_l2":
        res.labels.append(EXPIRED_LABEL)
    await add_labels(jira_key, res.labels, cfg)
    return out == "routed_to_l2"


async def expire_holds(cfg, now: datetime | None = None) -> int:
    """Held tickets past HOLD_HOURS → L2. Returns how many were routed."""
    from edr_triage.jira_handler import _build_client
    from edr_triage.jira_poller import _adf_to_text
    now = now or datetime.now(timezone.utc)
    jql = (f'project = {cfg.jira_project_key} AND labels = "{HOLD_LABEL}" '
           f'AND labels != "{EXPIRED_LABEL}" AND status = "{HOLD_STATUS}"')
    try:
        async with _build_client(cfg) as c:
            r = await c.post("/rest/api/3/search/jql",
                             json={"jql": jql, "maxResults": 50, "fields": ["comment"]})
            r.raise_for_status()
            issues = r.json().get("issues") or []
    except Exception as exc:
        logger.error("concurrency_hold: expiry search failed: %s", exc)
        return 0
    routed = 0
    for i in issues:
        held_at = None
        for cm in ((i.get("fields") or {}).get("comment") or {}).get("comments") or []:
            body = cm.get("body")
            text = _adf_to_text(body) if isinstance(body, dict) else str(body or "")
            if _MARKER in text:
                held_at = cm.get("created")
        from edr_triage.privesc_guard import parse_ts
        t = parse_ts(held_at)
        if t is None or now - t < timedelta(hours=HOLD_HOURS):
            continue
        if await release_to_l2(i["key"], f"it was held {HOLD_HOURS}h behind an open sibling "
                               "that is still unresolved", cfg):
            routed += 1
    if issues:
        logger.info("concurrency_hold: %d held, %d past %dh routed to L2", len(issues), routed, HOLD_HOURS)
    return routed
