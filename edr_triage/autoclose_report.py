"""Autonomous-close report — every ticket RAPTOR closed by itself, and whether it stuck.

This is the compensating control that autonomy rests on. The accepted safety position is
not "RAPTOR never closes anything wrongly" — it is "an occasional wrong close is tolerable
BECAUSE L2 sees every close". Nothing enforces the second half of that sentence except
this module, so it is a prerequisite for turning `AGENT_AUTONOMOUS_ALERTS` on, not a
follow-up to it.

Two things it does, both read-only against Jira:

  1. Stamps `autonomous_closed_at` on the ShadowResult for every close RAPTOR performed
     ITSELF. A close performed by a human is not reported here — the whole point is the
     subset nobody reviewed beforehand.
  2. Detects OVERTURNS by watching for the reopen. `False Positive -> Event Analysis` is
     transition 61 and is verified working (DEMO-112428), it is what an analyst would do on
     disagreeing anyway, and it therefore needs no new label, no new UI, and no new habit
     — an unpracticed habit produces silence that reads as approval.

Attribution is by changelog author, not by label: the `ai-fp` label says the AGENT said FP,
which in copilot phase is merely advice. The only evidence that RAPTOR *did* the closing is
a `-> False Positive` status change authored by the bot account. That is the same
bot-identity test `jira_closure_poller._extract_all_comments` already uses.

WHAT THIS DELIBERATELY DOES NOT DO
  * It never transitions, comments on, or closes anything. It is a reporter.
  * It does not treat "no reopen" as approval. A reopen detects DISAGREEMENT, not
    diligence — `reopened_at is None` cannot distinguish "checked and correct" from
    "nobody ever looked". Hence `age_hours` on every row and `unreviewed_beyond_threshold`
    in the summary: an unexamined backlog has to be visible AS a backlog.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from edr_triage.config import get_edr_config

logger = logging.getLogger(__name__)

# The label `_build_playbook_result_from_agent` attaches to an AUTO_CLOSED_FP verdict.
# Used only to NARROW the Jira search; attribution is decided by changelog author below.
_AI_FP_LABEL = "ai-fp"

# Every label that can mark a ticket RAPTOR closed. Searching on `ai-fp` alone missed
# every DETERMINISTIC close: that label is only added on the agent path, so an actor-
# allowlist close (`raptor-actor-allowlist`) or a DLP-Secret-key close (`dlp-secret-key`)
# would never have reached this report — the one thing that makes an occasional wrong
# close tolerable. `raptor-autoclosed` is now stamped on every close whatever produced it;
# the other two are kept so closes made before that label existed are still covered.
# Over-inclusion is harmless: attribution is still the changelog author, so a HUMAN close
# of a dlp-secret-key ticket is ignored exactly as before.
_CLOSE_LABELS = ("ai-fp", "raptor-autoclosed", "raptor-actor-allowlist", "dlp-secret-key",
                 "raptor-autoduplicate", "raptor-custom-block", "raptor-cyble-fp")
_CLOSE_LABELS_JQL = ", ".join(f'"{l}"' for l in _CLOSE_LABELS)
_ALLOWLIST_MEM_PREFIX = "allowlist-mem-"

_CLOSED_STATUS = "False Positive"
# duplicate_guard.py's exact-repeat duplicates are closes too: L2 sees them here, a reopen
# is an overturn, and the autonomy brake counts it.
_DUPLICATE_STATUS = "Duplicate"
# custom_block_guard.py closes as a true positive, to Closed.
_CLOSE_STATUSES = (_CLOSED_STATUS, _DUPLICATE_STATUS, "Closed")

# The L2 review marker. An analyst adds this label to an autonomous close once they have
# looked at it. Before this, "unreviewed" was purely age-based — every unreopened close
# older than the threshold counted, whether anyone had read it or not — so the number
# could only ever grow and said nothing about review. Counted only when a HUMAN added the
# label after the close (the changelog author is not RAPTOR's account).
REVIEWED_LABEL = "raptor-reviewed"

# Every autonomous close, one document per ticket (see _persist). Read by autonomy_brake.
CLOSES_COLLECTION = "edr_autonomous_closes"


async def poll_once(lookback_days: int = 30) -> dict:
    """Scan RAPTOR's autonomous closes once. Never raises; returns a summary dict."""
    cfg = get_edr_config()
    if not all([cfg.jira_email, cfg.jira_token, cfg.jira_url]):
        logger.warning("autoclose_report: Jira not configured — skipping")
        return {"scanned": 0, "closes": [], "error": "jira_not_configured"}

    issues = await _fetch_ai_fp_tickets(cfg, lookback_days)
    closes: list[dict] = []
    for issue in issues:
        try:
            row = _read_close(issue, (cfg.jira_email or "").lower())
        except Exception as exc:      # one malformed changelog must not stop the sweep
            logger.error("autoclose_report: %s failed: %s", issue.get("key"), exc)
            continue
        if row:
            closes.append(row)

    for row in closes:
        await _persist(row)
        # A human reopened a close an allowlist entry made. That is direct disagreement
        # with the entry's claim, so disarm it now; idempotent, so repeated sweeps over
        # the same overturned ticket are harmless.
        if row.get("reopened_at") and row.get("allowlist_memory_id"):
            try:
                from entity_graph.memory import demote_on_overturn
                await demote_on_overturn(row["allowlist_memory_id"], row["jira_key"],
                                         row.get("reopened_by") or "")
            except Exception as exc:
                logger.error("autoclose_report: demote for %s failed: %s", row["jira_key"], exc)

    overturned = [c for c in closes if c["reopened_at"]]
    standing = [c for c in closes if not c["reopened_at"]]
    reviewed = [c for c in standing if c.get("reviewed_at")]
    unreviewed = [c for c in standing if not c.get("reviewed_at")
                  and c["age_hours"] >= cfg.autoclose_review_hours]

    # Loud, because a silent backlog of unexamined autonomous closes is the exact failure
    # this module exists to prevent — and it looks identical to "everything is fine".
    if unreviewed:
        logger.warning(
            "autoclose_report: %d autonomous close(s) still unreviewed beyond %dh — "
            "oldest %s (%.0fh). No reopen is NOT evidence of agreement.",
            len(unreviewed), cfg.autoclose_review_hours,
            unreviewed[0]["jira_key"], unreviewed[0]["age_hours"],
        )
    logger.info("autoclose_report: scanned=%d autonomous_closes=%d overturned=%d",
                len(issues), len(closes), len(overturned))

    await _notify(cfg, closes, overturned, unreviewed)

    scored = len(closes)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_days": lookback_days,
        "scanned": len(issues),
        "autonomous_closes": len(closes),
        "overturned": len(overturned),
        "standing": len(standing),
        # Precision of RAPTOR's OWN closes. Distinct from the FP-precision endpoint, which
        # scores what the agent RECOMMENDED (mostly in copilot, where a human still closed
        # the ticket). This is the subset where the agent actually acted.
        "precision": round(1 - len(overturned) / scored, 4) if scored else None,
        "reviewed": len(reviewed),
        "reviewed_label": REVIEWED_LABEL,
        "unreviewed_beyond_threshold": len(unreviewed),
        "review_threshold_hours": cfg.autoclose_review_hours,
        "closes": sorted(closes, key=lambda c: c["closed_at"] or "", reverse=True),
    }


async def _fetch_ai_fp_tickets(cfg, lookback_days: int) -> list[dict]:
    """Every ai-fp-labelled ticket touched in the window, with its changelog."""
    jql = (
        f'project = {cfg.jira_project_key} '
        f'AND labels in ({_CLOSE_LABELS_JQL}) '
        f'AND updated >= -{lookback_days}d'
    )
    try:
        async with httpx.AsyncClient(
            base_url=cfg.jira_url.rstrip("/"),
            auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=30.0,
            verify=cfg.jira_verify_ssl,
        ) as client:
            issues: list[dict] = []
            token: str | None = None
            for _ in range(20):
                body: dict = {
                    "jql": jql,
                    "fields": ["summary", "status", "assignee", "labels", "updated"],
                    # A STRING, not a list: POST /search/jql rejects an array here with
                    # "Invalid request payload" (400) while accepting the same value as a
                    # scalar. The GET form tolerates both, which makes this easy to get
                    # wrong by analogy.
                    "expand": "changelog",
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
        logger.error("autoclose_report: Jira search failed: %s", exc)
        return []


def _parse(ts: str):
    """Jira timestamps ('2026-09-10T18:28:46.248+0530') -> aware datetime, or None."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _read_close(issue: dict, bot_email: str) -> dict | None:
    """Return a close row for this issue, or None if RAPTOR did not close it.

    Walks the status history once, oldest-first, and keeps the LAST bot-authored close —
    a ticket can be closed, reopened and closed again, and the live question is always
    about the most recent close.
    """
    key = issue.get("key", "")
    fields = issue.get("fields") or {}
    histories = (issue.get("changelog") or {}).get("histories") or []

    events: list[tuple[str, str, str, str, str]] = []
    for h in histories:
        author = h.get("author") or {}
        for item in h.get("items", []):
            if item.get("field") != "status":
                continue
            events.append((
                h.get("created", ""),
                (author.get("emailAddress") or "").lower(),
                author.get("displayName") or "",
                item.get("fromString") or "",
                item.get("toString") or "",
            ))
    events.sort(key=lambda e: e[0])

    closed_at = closed_to = None
    reopened_at = reopened_by = reopened_to = None
    for created, email, _display, _frm, to in events:
        if to in _CLOSE_STATUSES and bot_email and email == bot_email:
            # A later close supersedes an earlier one, and clears any reopen recorded
            # against the earlier close — otherwise a close→reopen→close cycle would
            # report as permanently overturned.
            closed_at, closed_to = created, to
            reopened_at = reopened_by = reopened_to = None
    if not closed_at:
        return None      # a human closed this, or nobody did — not ours to report

    for created, _email, display, frm, to in events:
        if created > closed_at and frm == closed_to:
            reopened_at, reopened_by, reopened_to = created, display, to
            break

    reviewed_at = reviewed_by = None
    for h in sorted(histories, key=lambda h: h.get("created", "")):
        author = h.get("author") or {}
        if (author.get("emailAddress") or "").lower() == bot_email or h.get("created", "") <= closed_at:
            continue
        for item in h.get("items", []):
            if (item.get("field") == "labels"
                    and REVIEWED_LABEL in (item.get("toString") or "").split()
                    and REVIEWED_LABEL not in (item.get("fromString") or "").split()):
                reviewed_at, reviewed_by = h.get("created", ""), author.get("displayName") or ""
                break
        if reviewed_at:
            break

    _closed_dt = _parse(closed_at)
    age_hours = (
        (datetime.now(timezone.utc) - _closed_dt).total_seconds() / 3600.0
        if _closed_dt else 0.0
    )
    return {
        "jira_key": key,
        "alert_name": fields.get("summary", ""),
        "status": ((fields.get("status") or {}).get("name", "")),
        "closed_at": closed_at,
        "age_hours": round(age_hours, 1),
        "reopened_at": reopened_at,
        "reopened_by": reopened_by,
        "reopened_to": reopened_to or "",
        "closed_to": closed_to,
        "reviewed_at": reviewed_at,
        "reviewed_by": reviewed_by,
        # The allowlist entry that caused this close, if one did — so a reopen can
        # disarm exactly that entry instead of leaving it to decay for months.
        "allowlist_memory_id": next(
            (l[len(_ALLOWLIST_MEM_PREFIX):] for l in (fields.get("labels") or [])
             if isinstance(l, str) and l.startswith(_ALLOWLIST_MEM_PREFIX)), ""),
    }


async def _persist(row: dict) -> None:
    """Write the close/overturn onto the ShadowResult. Best-effort; never blocks the report.

    Newest-first, matching every other writer in this codebase: a force=true rerun leaves
    older rows behind, and an unsorted find_one returns an arbitrary one.
    """
    # Every autonomous close is also recorded on its own, keyed by ticket. Families that run
    # playbook-only (Cyble) never get a ShadowResult, so without this the brake could not
    # see their reopens at all — it would fail OPEN for exactly those families.
    try:
        from lib.mongo import get_col
        get_col(CLOSES_COLLECTION).update_one(
            {"jira_key": row["jira_key"]},
            {"$set": {"alert_name": row.get("alert_name", ""),
                      "closed_at": _parse(row["closed_at"]),
                      "closed_to": row.get("closed_to"),
                      "reopened_at": _parse(row["reopened_at"]) if row["reopened_at"] else None,
                      "reopened_by": row["reopened_by"] or None}},
            upsert=True)
    except Exception as exc:
        logger.error("autoclose_report: recording close %s failed: %s", row["jira_key"], exc)
    try:
        from entity_graph.models import ShadowResult

        shadow = await (
            ShadowResult.find(ShadowResult.jira_key == row["jira_key"])
            .sort(-ShadowResult.created_at)
            .first_or_none()
        )
        if not shadow:
            return
        shadow.autonomous_closed_at = _parse(row["closed_at"])
        shadow.reopened_at = _parse(row["reopened_at"]) if row["reopened_at"] else None
        shadow.reopened_by = row["reopened_by"] or None
        shadow.reopened_to = row["reopened_to"]
        await shadow.save()
    except Exception as exc:
        logger.debug("autoclose_report: persist %s failed: %s", row["jira_key"], exc)


async def _notify(cfg, closes: list[dict], overturned: list[dict],
                  unreviewed: list[dict]) -> None:
    """Post the digest to Slack, if a webhook is configured.

    An INCOMING WEBHOOK, deliberately, not a bot token: a webhook is one URL with no
    OAuth, no app install, and no relationship to the Acme Security Bot Logic App —
    which is out of scope by decision and must not be touched. Empty webhook = silently
    disabled, so the dashboard half of this report ships without waiting on a credential.
    """
    if not cfg.slack_webhook or not closes:
        return
    lines = [
        f"*RAPTOR autonomous closes* — {len(closes)} in the last window, "
        f"{len(overturned)} overturned"
    ]
    if overturned:
        lines.append("*Overturned (reopened by a human):*")
        for c in overturned[:10]:
            lines.append(
                f"• <{cfg.jira_url.rstrip('/')}/browse/{c['jira_key']}|{c['jira_key']}> "
                f"{c['alert_name'][:70]} — reopened to {c['reopened_to']} "
                f"by {c['reopened_by']}"
            )
    if unreviewed:
        lines.append(
            f"*{len(unreviewed)} close(s) unreviewed beyond {cfg.autoclose_review_hours}h* "
            f"— no reopen is not evidence of agreement; oldest "
            f"{unreviewed[0]['jira_key']} ({unreviewed[0]['age_hours']:.0f}h). "
            f"Add the label `{REVIEWED_LABEL}` once checked; reopen it if wrong."
        )
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=cfg.jira_verify_ssl) as client:
            resp = await client.post(cfg.slack_webhook, json={"text": "\n".join(lines)})
            if resp.status_code >= 300:
                logger.error("autoclose_report: Slack webhook HTTP %s: %s",
                             resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.error("autoclose_report: Slack post failed: %s", exc)


async def run_forever(interval_seconds: int = 1800) -> None:
    import asyncio

    cfg = get_edr_config()
    if not cfg.autoclose_report_enabled:
        logger.info("autoclose_report disabled (EDR_AUTOCLOSE_REPORT unset) — not starting")
        return
    logger.info("autoclose_report started — every %ds", interval_seconds)
    while True:
        try:
            await poll_once()
        except Exception:
            logger.exception("autoclose_report: poll failed")
        await asyncio.sleep(interval_seconds)
