"""Chase-reply poller — react to a user's Slack answer on a chased ticket.

The Acme Security Bot (Azure Logic App) DMs the involved user and mirrors their
answer back into Jira as a comment. Until now nothing read that answer: the closure
poller skips `AWAITING MORE INPUTS` entirely, so a justification could sit in the
ticket for days (DEMO-106747 sat 8) with no automation noticing.

This poller closes that half of the loop, for tickets RAPTOR itself chased
(label `raptor-chased`; chases an L1 starts by hand keep their existing workflow):

    every chased user answered      -> verification packet, route to L2 Analysis required
    anyone disowned the activity    -> route to L2 immediately (possible compromise)
    silence past EDR_CHASE_STALE_HOURS -> route to L2, naming who never answered
    otherwise                       -> leave it alone, only RECORD how long it has waited

Each round is handled on its own: when L2 sends a ticket back for another chase, the new
round's answers are routed again. And every ticket in Awaiting more inputs, an L1's hand
chase included, has a deadline (EDR_AWAITING_DEADLINE_DAYS, default 7) after which it is
routed to L2 with a note that nobody answered (_route_overdue).

That routing IS the "L2 approves any close" step of the Netskope bulk upload/download
workflow: RAPTOR asks, the users answer, L2 decides — and an L2-approved close is the
evidence edr_triage/uba_learner.py later learns from.

Deliberately NOT built in:
  * No verdict. RAPTOR never closes a chased ticket — a self-reported justification is
    not proof (the DM goes to the account that may itself be compromised, so accepting
    it as exculpatory would hand an attacker the off-switch). L2 verifies and closes.
  * No LLM. Every decision here is a string match on the bot's own comments.

Work is found by JQL + the bot's notification comment, scoped by the raptor-chased label.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import httpx

from edr_triage.config import get_edr_config
from edr_triage.jira_handler import assign_issue

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
# A Security Bot relay is one short line ("<user> rejected involvement via slack", 16 of 16
# rejects over 120 days). RAPTOR's own notes are bot-authored too and run to thousands of
# characters: DEMO-116804 was flagged "A USER DISOWNED THIS" a minute after the ask because
# its triage note named the file "Order Rejected - PAN-Aadhaar linking".
_RELAY_MAX_CHARS = 300

# Idempotency: our own packet carries this, so a second pass neither re-posts nor
# re-transitions. Cheaper and more reliable than a claim row because it survives a
# database reset and covers tickets chased before this poller existed.
_PACKET_MARKER = "[RAPTOR chase-reply]"

# Set by pipeline._execute_user_chase once all four chase steps have landed.
_CHASED_LABEL = "raptor-chased"

# "<username> acknowledged involvement via slack" /
# "<username> added a business justification via Slack: <text>" — verified on DEMO-106747.
_REPLY_RE = re.compile(r"^\s*(\S+)\s+(acknowledged involvement|added a business justification)"
                       r"(?:[^:]*:\s*(.*))?", re.IGNORECASE | re.DOTALL)


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

    try:
        overdue = await _route_overdue(cfg, _dry)
    except Exception as exc:  # the deadline must never break the reply sweep
        logger.error("chase_reply: deadline sweep failed: %s", exc)
        overdue = []

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
        "deadline_routed": overdue, "deadline_days": cfg.awaiting_deadline_days,
        "dry_run": _dry,
    }


async def _fetch_waiting(cfg, lookback_days: int) -> list[dict]:
    # Only tickets RAPTOR itself chased. Chases an L1 starts by hand keep their existing
    # workflow — L1 often closes those directly on the user's answer, and silently
    # re-routing all of them to L2 would change every team's process at once. Those are
    # covered instead by the much longer deadline (_route_overdue).
    jql = (
        f'project = {cfg.jira_project_key} '
        f'AND status = "{_WAITING_STATUS}" '
        f'AND labels = "{_CHASED_LABEL}" '
        f'AND updated >= -{lookback_days}d'
    )
    return await _search(cfg, jql, ["summary", "status", "comment", "updated", "description"])


async def _search(cfg, jql: str, fields: list[str], max_pages: int = 20) -> list[dict]:
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
            for _ in range(max_pages):
                body: dict = {"jql": jql, "fields": fields, "maxResults": 100}
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


def _chased_users(fields: dict) -> list[str]:
    """Local parts of the addresses in the Involved Users cell — who RAPTOR asked."""
    from edr_triage.jira_handler import _find_involved_users_row
    from edr_triage.jira_poller import _adf_to_text
    row = _find_involved_users_row(fields.get("description"))
    if not row:
        return []
    cells = row.get("content") or []
    text = _adf_to_text(cells[1]) if len(cells) > 1 else ""
    return list(dict.fromkeys(a.split("@")[0].lower()
                              for a in re.findall(r"[\w.+-]+@[\w.-]+", text)))


def _attribute(answers: dict[str, dict], expected: list[str]) -> dict[str, dict]:
    """Key each reply by the Involved Users address it answers for.

    The bot relays replies under the Slack handle, which is not always the address's local
    part: DEMO-116104 asked pratapsingh.c@example.com and the replies came from
    `pratapsingh.chaudhary`, so the user never counted as answered — every round waited out
    the stale timer and told L2 "no answer from pratapsingh.c" beside his own acknowledgement.
    A handle maps to an address when it is the only one either prefixes; with one user asked,
    the bot DMs nobody else, so its lone unmatched replier is that user."""
    out: dict[str, dict] = {}
    unmatched: list[str] = []

    def _merge(user, a):
        cur = out.setdefault(user, {"justification": "", "acked": False})
        cur["justification"] = cur["justification"] or a["justification"]
        cur["acked"] = cur["acked"] or a["acked"]
        if a.get("justification") and cur["justification"] == a["justification"]:
            cur["on_ticket"] = a.get("on_ticket", False)

    for who, a in answers.items():
        if who in expected:
            _merge(who, a)
            continue
        hits = [u for u in expected if who.startswith(u) or u.startswith(who)]
        if len(hits) == 1:
            _merge(hits[0], a)
        else:
            unmatched.append(who)
    if len(expected) == 1 and len(unmatched) == 1:
        _merge(expected[0], answers[unmatched.pop()])
    for who in unmatched:
        _merge(who, answers[who])
    return out


async def _process(key: str, fields: dict, cfg, dry_run: bool = False) -> dict:
    """Handle one waiting ticket. Returns {handled|waiting_hours|skip_reason}.

    Tracks EACH chased user, because every named user is now asked. Routes to L2 when:
      * anyone disowned the activity — immediately, it may be a compromised account;
      * every chased user has answered (a justification, or at least an acknowledgement);
      * or EDR_CHASE_STALE_HOURS have passed since the dispatch — L2 then decides with
        whatever answers exist, and the packet names who stayed silent.
    Routing on the FIRST reply would hand L2 a ticket while others were still answering,
    and a later "that wasn't me" would land on a ticket nobody was watching any more.
    """
    comments = _comments(fields)
    # Only the latest round counts. L2 can send a routed ticket back for another round
    # (Parker re-chased 8 on 2026-10-12 16:03-16:09: L2 Analysis required -> Event Analysis
    # -> Awaiting more inputs, which fires the bot again). A packet anywhere on the ticket
    # used to mean "handled", so the second round's answers were never routed back.
    _packets = [i for i, (_, _, txt) in enumerate(comments) if _PACKET_MARKER.lower() in txt.lower()]
    if _packets:
        comments = comments[_packets[-1] + 1:]
        if not any(m in txt.lower() for _, _, txt in comments for m in _NOTIFIED_MARKERS):
            return {"skip_reason": "already_handled"}
    # The first round keeps the bare key, so its claims are unchanged.
    claim_key = key if not _packets else f"{key}#round{len(_packets) + 1}"

    bot_email = (cfg.jira_email or "").lower()
    notified_at = None
    answers: dict[str, dict] = {}      # user -> {"justification": str, "acked": bool}
    rejected: list[str] = []
    unreachable_note = ""
    asked = _chased_users(fields)
    for created, author, text in comments:
        if bot_email and author != bot_email:
            # The asked person answering ON THE TICKET counts as their answer (DEMO-117308:
            # Swapnesh explained in a Jira comment and only clicked Acknowledge in Slack, so
            # L2 was told "NO justification" and re-chased him). Matched by the commenter's
            # own address, never by a name, and only after this round's dispatch.
            local = author.split("@")[0]
            if notified_at and author and local in asked and text.strip():
                a = answers.setdefault(local, {"justification": "", "acked": False})
                a["justification"] = a["justification"] or text.strip()
                a["on_ticket"] = a.get("on_ticket") or not a.get("slack_justified")
                a["acked"] = True
            continue
        low = text.lower()
        if "cannot be asked via slack" in low and not unreachable_note:
            unreachable_note = text[low.index("cannot be asked via slack"):][:400]
        if any(m in low for m in _NOTIFIED_MARKERS):
            notified_at = notified_at or _parse_iso(created)
        m = _REPLY_RE.match(text)
        if m and any(x in low for x in _JUSTIFIED_MARKERS + _ACK_MARKERS):
            who = m.group(1).split("@")[0].lower()
            a = answers.setdefault(who, {"justification": "", "acked": False})
            if "business justification" in m.group(2).lower():
                a["justification"] = (m.group(3) or "").strip() or text
                a["slack_justified"], a["on_ticket"] = True, False
            a["acked"] = True
        elif (len(text) < _RELAY_MAX_CHARS and any(r in low for r in _REJECT_MARKERS)
              and not any(n in low for n in _NOTIFIED_MARKERS)):
            rejected.append(text[:200])

    if not notified_at:
        return {"skip_reason": "no_chase_on_this_ticket"}

    expected = _chased_users(fields)
    answers = _attribute(answers, expected)
    silent = [u for u in expected if u not in answers]
    waited = (datetime.now(timezone.utc) - notified_at).total_seconds() / 3600.0
    all_answered = bool(answers) and not silent
    timed_out = waited >= cfg.chase_stale_hours
    if not (rejected or all_answered or timed_out):
        return {"waiting_hours": round(waited, 1), "answered": sorted(answers),
                "silent": silent}

    packet = _build_packet(key, fields, answers, rejected, silent, timed_out, unreachable_note,
                           stale_hours=cfg.chase_stale_hours)
    # One packet per ticket across pods: both run this poller (see store.claim_chase_reply).
    from edr_triage import store
    if not dry_run:
        try:
            if not store.claim_chase_reply(claim_key):
                return {"skip_reason": "claimed_by_another_worker"}
        except store.ChaseClaimUnavailable as exc:
            logger.error("chase_reply: %s — claim store unavailable (%s); not posting this "
                         "round", key, exc)
            return {"skip_reason": "claim_store_unavailable"}
    from edr_triage.jira_handler import add_comment
    if not await add_comment(key, packet, cfg=cfg, dry_run=dry_run):
        if not dry_run:
            store.release_chase_reply(claim_key)
        return {"skip_reason": "comment_failed"}

    moved = await _transition_to(key, "L2 Analysis required", cfg, dry_run)
    logger.info("chase_reply: %s answered=%s silent=%s rejected=%d timed_out=%s transitioned=%s",
                key, sorted(answers), silent, len(rejected), timed_out, moved)
    return {"handled": True, "transitioned": moved}


_DEADLINE_MARKER = "[RAPTOR awaiting-deadline]"


def _deadline_jql(cfg) -> str:
    """Tickets parked in Awaiting more inputs with no status change for the deadline,
    that entered it on/after the cut-off date (see EDR_AWAITING_DEADLINE_SINCE)."""
    return (
        f'project = {cfg.jira_project_key} '
        f'AND status = "{_WAITING_STATUS}" '
        f'AND status CHANGED TO "{_WAITING_STATUS}" AFTER "{cfg.awaiting_deadline_since}" '
        f'AND NOT status CHANGED AFTER -{cfg.awaiting_deadline_days}d '
        f'ORDER BY updated ASC'
    )


def _owned_by_reply_handler(fields: dict) -> bool:
    """A RAPTOR chase whose current round is still running belongs to _process, which
    routes it after EDR_CHASE_STALE_HOURS (far sooner than the deadline). Anything else
    in Awaiting more inputs (an L1's hand chase, an aborted chase) is the deadline's."""
    if _CHASED_LABEL not in (fields.get("labels") or []):
        return False
    comments = _comments(fields)
    _packets = [i for i, (_, _, t) in enumerate(comments) if _PACKET_MARKER.lower() in t.lower()]
    tail = comments[_packets[-1] + 1:] if _packets else comments
    return any(m in t.lower() for _, _, t in tail for m in _NOTIFIED_MARKERS)


def _deadline_note(key: str, days: int) -> str:
    return "\n".join([
        f"*{_DEADLINE_MARKER} No answer after {days} days in Awaiting more inputs — for L2*",
        "",
        f"This ticket has had no status change for {days} days while waiting on the user, "
        "so it is moved to L2 rather than left parked. Nothing here has been verified: "
        "any reply in the comments above is the user's own unverified account.",
        "",
        f"*Ticket moved to L2 Analysis required.* RAPTOR has not closed or resolved {key} "
        "and cannot — it may only route. Closing is L2's decision.",
        "",
        "[RAPTOR — automated chase reply handler]",
    ])


async def _route_overdue(cfg, dry_run: bool) -> list[str]:
    """Route tickets past the Awaiting more inputs deadline to L2. Returns the keys routed."""
    if cfg.awaiting_deadline_days <= 0 or cfg.awaiting_deadline_max_per_run <= 0:
        return []
    issues = await _search(cfg, _deadline_jql(cfg),
                           ["summary", "labels", "comment", "description"], max_pages=1)
    from edr_triage import store
    from edr_triage.jira_handler import add_comment
    routed: list[str] = []
    for t in issues:
        if len(routed) >= cfg.awaiting_deadline_max_per_run:
            break
        key, fields = t.get("key", ""), t.get("fields") or {}
        if not key or _owned_by_reply_handler(fields):
            continue
        # One note per stay in Awaiting: the claim is keyed on how many deadline notes
        # the ticket already carries, so a ticket that comes back later can be routed again.
        n = sum(1 for _, _, txt in _comments(fields) if _DEADLINE_MARKER.lower() in txt.lower())
        claim_key = f"{key}#deadline{n + 1}"
        if not dry_run:
            try:
                if not store.claim_chase_reply(claim_key):
                    continue
            except store.ChaseClaimUnavailable as exc:
                logger.error("chase_reply: deadline claim store unavailable (%s) — stopping", exc)
                break
        if not await add_comment(key, _deadline_note(key, cfg.awaiting_deadline_days),
                                 cfg=cfg, dry_run=dry_run):
            if not dry_run:
                store.release_chase_reply(claim_key)
            continue
        if await _transition_to(key, "L2 Analysis required", cfg, dry_run):
            routed.append(key)
    if routed:
        logger.info("chase_reply: routed %d ticket(s) past the %d-day deadline to L2: %s",
                    len(routed), cfg.awaiting_deadline_days, ", ".join(routed))
    return routed


def _packet_headline(answers: dict, rejected: list, silent: list, timed_out: bool,
                     stale_hours: int = 72) -> str:
    """What actually happened. It used to read "Users responded" on every packet — including
    DEMO-116071 (2026-10-10), where nobody had answered and the 72 hours had simply run out."""
    if rejected:
        return f"*{_PACKET_MARKER} A user says this was NOT them — for L2, treat as urgent*"
    if not answers:
        return f"*{_PACKET_MARKER} No reply after {stale_hours} hours — for L2*"
    if silent:
        return (f"*{_PACKET_MARKER} Partial replies"
                + (f" after {stale_hours} hours" if timed_out else "") + " — for L2 approval*")
    return f"*{_PACKET_MARKER} Users responded — for L2 approval*"


def _build_packet(key: str, fields: dict, answers: dict, rejected: list, silent: list,
                  timed_out: bool, unreachable_note: str = "", stale_hours: int = 72) -> str:
    """The verification packet L2 reads. Facts only — it recommends no verdict.

    Framing matters: each justification is the SUBJECT's own account of their activity,
    so it is presented as a claim to verify, never as clearance. Mirrors the wording
    already used on relayed justifications elsewhere (adf31b0).
    """
    summary = (fields.get("summary") or "").strip()
    lines = [_packet_headline(answers, rejected, silent, timed_out, stale_hours), "",
             f"*Alert:* {summary}"]
    if rejected:
        lines += ["", "*(!) A USER DISOWNED THIS ACTIVITY* — they indicated it was not them. "
                  "Treat as a possible account compromise and prioritise accordingly; do NOT "
                  "close this without establishing who actually performed the activity."]
    for user, a in sorted(answers.items()):
        lines.append("")
        if a["justification"]:
            lines += [f"*{user} — business justification "
                      f"{'written on this ticket' if a.get('on_ticket') else 'via Slack'}:*",
                      f"{{quote}}{a['justification']}{{quote}}"]
        else:
            lines.append(f"*{user} — acknowledged involvement but gave NO justification.* "
                         "The activity itself is still unexplained.")
    if silent:
        lines += ["", f"*No answer{' after the waiting period' if timed_out else ''} from:* "
                  + ", ".join(silent) + " — their part of this activity is unexplained."]
    if unreachable_note:
        lines += ["", f"*{unreachable_note}*"]
    lines += [
        "",
        "*Status of this evidence:* UNVERIFIED SELF-REPORTS. Each is the subject's own "
        "account of their own activity and is NOT exculpatory on its own — a compromised "
        "account's owner would answer exactly the same way. Re-validate for this specific "
        "occurrence before closing.",
        "",
        "*To verify:*",
        "# Does each stated reason actually EXPLAIN that user's activity, or only restate it?",
        "# Was the destination the COMPANY's instance of the app (e.g. corp.example.com Drive, the "
        "acme-in Slack workspace), not a personal one?",
        "# Is there independent corroboration — change ticket, approval, or manager confirmation?",
        "",
        f"*Ticket moved to L2 Analysis required.* RAPTOR has not closed or resolved "
        f"{key} and cannot — it may only route. Closing is L2's decision; an L2-approved "
        "close becomes evidence RAPTOR can later learn from.",
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
    moved = False
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
            moved = True
    except Exception as exc:
        logger.error("chase_reply: transition %s → %s errored: %s", key, target_status, exc)
        return False

    # Assign the named L2 owner, AFTER the transition and outside the client block.
    #
    # Order matters: assign-then-transition would leave a ticket assigned to L2 while
    # still sitting in its old status if the transition failed — a handoff that looks
    # done and is not. Transition-then-assign can only ever fail the other way, leaving
    # a correctly-routed ticket with a stale assignee, which is today's behaviour.
    #
    # Placed here rather than at the two call sites (chase_reply._process and
    # jira_closure_poller._route_thin_rj_to_l2) because THIS function is the one thing
    # they share, and it is hard-allowlisted to `l2 analysis required` — so "every route
    # to L2 gets an owner" holds for any future caller without it having to remember.
    # Never blocks the handoff: a failed assignment is logged, the transition stands.
    assigned = await assign_issue(key, cfg.l2_assignee_account_id, cfg, dry_run)
    if not assigned:
        logger.warning("chase_reply: %s routed to %s but assigning %s failed — "
                       "the ticket is at L2 and UNOWNED", key, target_status,
                       cfg.l2_assignee_name or cfg.l2_assignee_account_id)
    return moved


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
