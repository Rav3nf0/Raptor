"""Chase-reply poller — react to a user's Slack answer on a chased ticket.

The ExampleCorp Security Bot (Azure Logic App) DMs the involved user and mirrors their
answer back into Jira as a comment. Until now nothing read that answer: the closure
poller skips `AWAITING MORE INPUTS` entirely, so a justification could sit in the
ticket for days (DEMO-106747 sat 8) with no automation noticing.

This poller closes that half of the loop:

    reply present  -> post a verification packet, transition to L2 Analysis required
    no reply yet   -> leave the ticket alone, only RECORD how long it has waited

Deliberately NOT built in:
  * No verdict. RAPTOR never closes a chased ticket — a self-reported justification is
    not proof (the DM goes to the account that may itself be compromised, so accepting
    it as exculpatory would hand an attacker the off-switch). L2 verifies and closes.
  * No timeout transition. `No Response` is not currently reachable from
    `Awaiting more inputs`, and unanswered tickets are left in place by choice. Staleness
    is MEASURED (see `stale`) so a silent backlog stays visible without moving anything.
  * No LLM. Every decision here is a string match on the bot's own comments.

Work is found by JQL + the bot's notification comment rather than by our own chase
records, so it also covers the chases an L1 kicks off by hand — which today is all of them.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from edr_triage.config import get_edr_config

logger = logging.getLogger(__name__)

_WAITING_STATUS = "Awaiting more inputs"

# The ONLY status this poller may move a ticket to. Keyed on the TARGET status, not the
# transition name — the workflow's transition into L2 is confusingly called
# "Awaiting More Inputs_1", and it was silently repointed from `No Response` to
# `L2 Analysis required` once already. Matching on the destination means a rename or
# repoint can never send a ticket somewhere unintended, and `False Positive` / the IR
# chain stay permanently out of reach.
_ALLOWED_TARGET_STATUSES = frozenset({"l2 analysis required"})

# Bot comment fingerprints. The first two are verified against real bot output on
# DEMO-106747; `_REJECT_MARKERS` is a best guess — no "Reject & Escalate" click has been
# observed yet, so treat a hit as advisory until one is seen in the wild.
_NOTIFIED_MARKERS = ("notification dispatched",)
_JUSTIFIED_MARKERS = ("added a business justification",)
_ACK_MARKERS = ("acknowledged involvement",)
_REJECT_MARKERS = ("reject", "escalate to security", "did not perform")

# Idempotency: our own packet carries this, so a second pass neither re-posts nor
# re-transitions. Cheaper and more reliable than a claim row because it survives a
# database reset and covers tickets chased before this poller existed.
_PACKET_MARKER = "[RAPTOR chase-reply]"


async def poll_once(lookback_days: int = 14, dry_run: bool | None = None) -> dict:
    """Scan waiting tickets once. Returns a summary dict (never raises).

    `dry_run=True` forces report-only: no comment, no transition. Passed explicitly
    rather than read from config so a caller (the read-only API view) can guarantee
    inertness — this module binds get_edr_config at import, so patching the config
    module would NOT have taken effect here.
    """
    cfg = get_edr_config()
    _dry = cfg.dry_run if dry_run is None else bool(dry_run)
    if not all([cfg.jira_email, cfg.jira_token, cfg.jira_url]):
        logger.warning("chase_reply: Jira not configured — skipping")
        return {"scanned": 0, "handled": 0, "stale": [], "error": "jira_not_configured"}

    tickets = await _fetch_waiting(cfg, lookback_days)
    handled, stale, skipped = 0, [], 0

    for t in tickets:
        key = t.get("key", "")
        fields = t.get("fields") or {}
        try:
            outcome = await _process(key, fields, cfg, _dry)
        except Exception as exc:  # one bad ticket must not stop the sweep
            logger.error("chase_reply: %s failed: %s", key, exc)
            continue
        if outcome.get("handled"):
            handled += 1
        elif outcome.get("waiting_hours") is not None:
            stale.append({"jira_key": key, "waiting_hours": outcome["waiting_hours"]})
        else:
            skipped += 1

    stale.sort(key=lambda r: -r["waiting_hours"])
    # Surface the backlog we deliberately do NOT transition, so "left in Awaiting more
    # inputs" can't quietly become "forgotten".
    _breached = [s for s in stale if s["waiting_hours"] >= cfg.chase_stale_hours]
    if _breached:
        logger.warning(
            "chase_reply: %d chased ticket(s) unanswered beyond %dh — oldest %s (%.0fh)",
            len(_breached), cfg.chase_stale_hours,
            _breached[0]["jira_key"], _breached[0]["waiting_hours"],
        )
    logger.info("chase_reply: scanned=%d handled=%d awaiting=%d skipped=%d",
                len(tickets), handled, len(stale), skipped)
    return {
        "scanned": len(tickets), "handled": handled,
        "awaiting_reply": stale, "stale_beyond_threshold": _breached,
        "stale_threshold_hours": cfg.chase_stale_hours, "skipped": skipped,
        "dry_run": _dry,
    }


async def _fetch_waiting(cfg, lookback_days: int) -> list[dict]:
    jql = (
        f'project = {cfg.jira_project_key} '
        f'AND status = "{_WAITING_STATUS}" '
        f'AND updated >= -{lookback_days}d'
    )
    try:
        async with httpx.AsyncClient(
            base_url=cfg.jira_url.rstrip("/"),
            auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=20.0,
            verify=cfg.jira_verify_ssl,
        ) as client:
            issues: list[dict] = []
            token: str | None = None
            for _ in range(20):
                body: dict = {
                    "jql": jql,
                    "fields": ["summary", "status", "comment", "updated"],
                    "maxResults": 100,
                }
                if token:
                    body["nextPageToken"] = token
                resp = await client.post("/rest/api/3/search/jql", json=body)
                resp.raise_for_status()
                page = resp.json()
                issues.extend(page.get("issues", []))
                token = page.get("nextPageToken")
                if page.get("isLast") or not token:
                    break
            return issues
    except Exception as exc:
        logger.error("chase_reply: Jira search failed: %s", exc)
        return []


def _comments(fields: dict) -> list[tuple[str, str, str]]:
    """(created, author_email, text) for every comment, oldest first."""
    from edr_triage.jira_poller import _adf_to_text
    out = []
    for c in ((fields.get("comment") or {}).get("comments") or []):
        body = c.get("body") or ""
        text = _adf_to_text(body) if isinstance(body, dict) else str(body)
        author = (c.get("author") or {}).get("emailAddress", "") or ""
        out.append((c.get("created", ""), author.lower(), " ".join(text.split())))
    return out


def _parse_iso(ts: str):
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00"))
    except Exception:
        return None


async def _process(key: str, fields: dict, cfg, dry_run: bool = False) -> dict:
    """Handle one waiting ticket. Returns {handled|waiting_hours|skip_reason}."""
    comments = _comments(fields)
    if any(_PACKET_MARKER.lower() in txt.lower() for _, _, txt in comments):
        return {"skip_reason": "already_handled"}

    bot_email = (cfg.jira_email or "").lower()
    notified_at, justification, acked, rejected = None, "", False, False

    for created, author, text in comments:
        if bot_email and author != bot_email:
            continue  # only the bot/Logic App relays the user's Slack answer
        low = text.lower()
        if any(m in low for m in _NOTIFIED_MARKERS):
            notified_at = notified_at or _parse_iso(created)
        if any(m in low for m in _JUSTIFIED_MARKERS):
            justification = text
        elif any(m in low for m in _ACK_MARKERS):
            acked = True
        elif any(m in low for m in _REJECT_MARKERS):
            rejected = True

    if not notified_at:
        return {"skip_reason": "no_chase_on_this_ticket"}

    if not (justification or acked or rejected):
        waited = (datetime.now(timezone.utc) - notified_at).total_seconds() / 3600.0
        return {"waiting_hours": round(waited, 1)}

    packet = _build_packet(key, fields, justification, acked, rejected)
    from edr_triage.jira_handler import add_comment
    if not await add_comment(key, packet, cfg=cfg, dry_run=dry_run):
        return {"skip_reason": "comment_failed"}

    moved = await _transition_to(key, "L2 Analysis required", cfg, dry_run)
    logger.info("chase_reply: %s reply=%s ack=%s reject=%s transitioned=%s",
                key, bool(justification), acked, rejected, moved)
    return {"handled": True, "transitioned": moved}


def _build_packet(key: str, fields: dict, justification: str, acked: bool,
                  rejected: bool) -> str:
    """The verification packet L2 reads. Facts only — it recommends no verdict.

    Framing matters: the justification is the SUBJECT's own account of their activity,
    so it is presented as a claim to verify, never as clearance. Mirrors the wording
    already used on relayed justifications elsewhere (adf31b0).
    """
    summary = (fields.get("summary") or "").strip()
    lines = [
        f"*{_PACKET_MARKER} User responded — for L2 verification*",
        "",
        f"*Alert:* {summary}",
    ]
    if rejected:
        lines += [
            "",
            "*(!) USER DISOWNED THIS ACTIVITY* — they indicated it was not them. "
            "Treat as a possible account compromise and prioritise accordingly; do NOT "
            "close this without establishing who actually performed the activity.",
        ]
    if justification:
        lines += [
            "",
            "*Business justification supplied via Slack:*",
            f"{{quote}}{justification}{{quote}}",
        ]
    elif acked:
        lines += [
            "",
            "*User acknowledged involvement but supplied NO justification.* They confirm "
            "it was them, without saying why — the activity itself is still unexplained.",
        ]

    lines += [
        "",
        "*Status of this evidence:* UNVERIFIED SELF-REPORT. This is the subject's own "
        "account of their own activity and is NOT exculpatory on its own — a compromised "
        "account's owner would answer exactly the same way. Re-validate for this specific "
        "occurrence before closing.",
        "",
        "*To verify:*",
        "# Does the stated reason actually EXPLAIN the observed activity, or only restate it?",
        "# Was the actor ENTITLED to perform this action, independent of their claim?",
        "# Is there independent corroboration — change ticket, approval, or manager confirmation?",
        "",
        f"*Ticket moved to L2 Analysis required.* RAPTOR has not closed or resolved "
        f"{key} and cannot — it may only route. The verdict is L2's.",
        "",
        "[RAPTOR — automated chase reply handler]",
    ]
    return "\n".join(lines)


async def _transition_to(key: str, target_status: str, cfg, dry_run: bool = False) -> bool:
    """Transition by TARGET status, hard-limited to _ALLOWED_TARGET_STATUSES.

    Not jira_handler.transition_ticket: that matches on the transition NAME, and the
    name here ("Awaiting More Inputs_1") describes neither its source nor its
    destination — it was already repointed once from `No Response` to
    `L2 Analysis required`. Keying on where the ticket LANDS, behind an allowlist, means
    no rename or workflow edit can route a ticket somewhere RAPTOR must never send it.
    """
    if target_status.strip().lower() not in _ALLOWED_TARGET_STATUSES:
        logger.error("chase_reply: refusing to transition %s to '%s' — not allowlisted",
                     key, target_status)
        return False
    if dry_run:
        logger.info("[DRY-RUN] chase_reply would transition %s → %s", key, target_status)
        return True
    try:
        async with httpx.AsyncClient(
            base_url=cfg.jira_url.rstrip("/"),
            auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=20.0,
            verify=cfg.jira_verify_ssl,
        ) as client:
            r = await client.get(f"/rest/api/3/issue/{key}/transitions")
            r.raise_for_status()
            match = next(
                (t for t in r.json().get("transitions", [])
                 if ((t.get("to") or {}).get("name", "")).strip().lower()
                 == target_status.strip().lower()),
                None,
            )
            if not match:
                logger.warning("chase_reply: no transition to '%s' available on %s (have: %s)",
                               target_status, key,
                               [(t.get("to") or {}).get("name") for t in r.json().get("transitions", [])])
                return False
            p = await client.post(f"/rest/api/3/issue/{key}/transitions",
                                  json={"transition": {"id": match["id"]}})
            if p.status_code >= 300:
                logger.error("chase_reply: transition %s → %s failed HTTP %s: %s",
                             key, target_status, p.status_code, p.text[:200])
                return False
            logger.info("chase_reply: %s → %s", key, target_status)
            return True
    except Exception as exc:
        logger.error("chase_reply: transition %s → %s errored: %s", key, target_status, exc)
        return False


async def run_forever(interval_seconds: int = 600) -> None:
    import asyncio
    cfg = get_edr_config()
    if not cfg.chase_reply_enabled:
        logger.info("chase_reply poller disabled (EDR_CHASE_REPLY unset) — not starting")
        return
    logger.info("chase_reply poller started — every %ds", interval_seconds)
    while True:
        try:
            await poll_once()
        except Exception:
            logger.exception("chase_reply: poll failed")
        await asyncio.sleep(interval_seconds)
