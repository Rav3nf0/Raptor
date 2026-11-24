"""Which /shadow findings and stories page (lib/paging.py does grouping, brake and lifecycle).

Replayed on 30 days (3 Oct - 2 Nov 2026): 71 high/critical true positives became 4 pages, all
real (AutoClaw/PayGuard, ATLAS on publisher02, the partner-onboarding SSRF, 198.51.100.44).

  high (phone)  a high/critical finding Claude called true positive at confidence >= 0.8,
                in-app Opus or a manual Claude Code pass alike (notify.is_tp), that no person
                had reviewed when the verdict landed. Its host, account and story join one
                incident, so later TPs on them fold in instead of ringing again.
  story         a story carrying such a TP joins the incident of its hosts; a story with none
                paged yet pages once (phone when high/critical, else a push).
  low (push)    until the in-app review runs on Claude (ai_review.enabled_review), a few
                detectors push on detection alone: ssh_backdoor, edge_attacks, Upwind high
                command execution, anything critical. Held until 09:00 IST at night.
  never         a person's own TP decision: they have seen it. It acknowledges the incident
                instead; FP or snooze closes the finding's part of it, and a closed story
                closes its own.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

MIN_CONFIDENCE = 0.8
LOOKBACK_HOURS = 24
EARLY_DETECTORS = ("ssh_backdoor", "edge_attacks")
_COMMAND = re.compile(r"command|shell|exec", re.I)


def ai_page(f) -> bool:
    from shadow_hunter.notify import is_tp
    return (f.severity in ("high", "critical") and is_tp(f) and (f.ai_confidence or 0) >= MIN_CONFIDENCE
            and not _seen_first(f))


def _seen_first(f) -> bool:
    """A person reviewed it before (or without) the AI verdict: they already know."""
    if not f.reviewed_at:
        return False
    return not f.ai_at or _utc(f.reviewed_at) <= _utc(f.ai_at)


def early_push(f) -> bool:
    if f.reviewed_at or f.ai_verdict == "false_positive":
        return False
    return (f.detector in EARLY_DETECTORS or f.severity == "critical"
            or (f.detector == "upwind_threats" and f.severity == "high" and bool(_COMMAND.search(f.summary or ""))))


def _utc(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _entities(f) -> list[str]:
    from lib import paging
    return [paging.entity("story", f.story_id or ""), paging.entity("host", f.device_name),
            paging.entity("acct", f.account_name)]


def _title(f) -> str:
    where = f.device_name or f.account_name or ""
    return (f"/shadow {f.severity} {f.detector}" + (f" on {where}" if where else "")
            + f": {(f.summary or f.indicator or '')[:140]} | Tribe: SecOps")


def _details(f, why: str) -> dict:
    return {"why_paged": why, "ai_verdict": f.ai_verdict, "ai_confidence": f.ai_confidence, "ai_by": f.ai_by,
            "ai_reasoning": (f.ai_reasoning or "")[:1500]}


async def run(now: datetime | None = None, early: bool | None = None) -> dict:
    from beanie.operators import In
    from lib import paging
    from shadow_hunter.models import Finding, Story
    from shadow_hunter.stories import clean
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(hours=LOOKBACK_HOURS)).replace(tzinfo=None)
    if paging.mode() == "off":
        return {"off": True, "tickets": await _tickets(now, since)}
    base = paging.base_url()
    out = {"findings": 0, "early": 0, "stories": 0, "closed": 0, "released": 0}
    live = {"legacy": {"$ne": True}, "allowlisted_by_rule": ""}

    for f in await Finding.find({**live, "severity": {"$in": ["high", "critical"]}, "ai_verdict": "true_positive",
                                 "ai_at": {"$gte": since}}).to_list():
        if ai_page(f):
            r = await paging.offer("shadow", f"shadow:finding:{f.id}", _entities(f), "high", clean(_title(f)),
                                   clean(_details(f, "Claude-verified true positive")), f"{base}/shadow?finding={f.id}",
                                   "Claude-verified TP", now=now, kind=f"shadow:{f.detector}")
            out["findings"] += r.get("action") not in ("member", "off")

    if early is None:
        from shadow_hunter.ai_review import enabled_review
        early = not enabled_review()
    if early:
        for f in await Finding.find({**live, "reviewed_at": None, "created_at": {"$gte": since},
                                     "$or": [{"detector": {"$in": list(EARLY_DETECTORS)}}, {"severity": "critical"},
                                             {"detector": "upwind_threats", "severity": "high"}]}).to_list():
            if early_push(f):
                r = await paging.offer("shadow", f"shadow:early:{f.id}", _entities(f), "low", clean(_title(f)),
                                       clean(_details(f, "detector pushes on detection until Claude review is on")),
                                       f"{base}/shadow?finding={f.id}", "early detector push", now=now,
                                       kind=f"shadow:{f.detector}")
                out["early"] += r.get("action") not in ("member", "off")

    for st in await Story.find({"status": "open"}).to_list():
        fs = await Finding.find(In(Finding.id, st.finding_ids)).to_list()
        tps = [f for f in fs if _story_tp(f)]
        fresh = any(_utc(f.ai_at) and _utc(f.ai_at) >= now - timedelta(hours=LOOKBACK_HOURS) for f in tps)
        if not tps or not fresh:
            continue
        ents = [paging.entity("story", st.id)] + [e for f in fs for e in _entities(f)[1:]]
        urg = "high" if st.severity in ("high", "critical") else "low"
        r = await paging.offer("shadow", f"shadow:story:{st.id}", ents, urg,
                               clean(f"/shadow {st.severity} story: {st.title} ({len(tps)} TP) | Tribe: SecOps"),
                               {"why_paged": "story with a Claude-verified true positive"},
                               f"{base}/shadow/stories/{st.id}", "TP story", now=now)
        out["stories"] += r.get("action") not in ("member", "off")

    out["tickets"] = await _tickets(now, since)      # after the pages, so each ticket joins its incident
    out["closed"] = await lifecycle()
    out["released"] = await paging.flush_held(now)
    if paging.digest_due(now):
        await _digest(now)
        try:                                   # same daily slot: confirmed TPs that never paged
            text = missed_text(await missed(7, now))
            url = __import__("os").getenv("SHADOW_SLACK_WEBHOOK", "").strip()
            if text and url:
                from shadow_hunter.notify import _post
                await _post(url, text)
        except Exception:
            logger.exception("[paging] missed-TP check failed")
    return out


async def _tickets(now: datetime, since) -> dict:
    """Jira tickets for Claude-confirmed TPs (shadow_hunter/tickets.py): the same findings that
    page, plus Claude TPs inside a story. Each failure is retried next run."""
    from shadow_hunter import tickets
    from shadow_hunter.models import Finding, Story
    out = {"created": 0, "commented": 0, "failed": 0, "closed": 0}
    if not tickets.enabled():
        return out
    live = {"legacy": {"$ne": True}, "allowlisted_by_rule": ""}
    stories = {st.id: st for st in await Story.find({"status": "open"}).to_list()}
    todo = []
    for f in await Finding.find({**live, "ai_verdict": "true_positive", "ai_at": {"$gte": since}}).to_list():
        st = stories.get(f.story_id) if f.story_id else None
        if ai_page(f) or (st and _story_tp(f)):
            todo.append((f, st))
    for f, st in sorted(todo, key=lambda x: _utc(x[0].ai_at) or now):
        try:
            r = await tickets.ticket_for(f, st, now=now)
            out["created"] += r["action"] == "created"
            out["commented"] += r["action"] == "comment"
        except Exception:
            logger.exception("[shadow-tickets] finding %s", f.id)
            out["failed"] += 1
    try:
        out["closed"] = await tickets.sync_closed()
    except Exception:
        logger.exception("[shadow-tickets] close sync failed")
    return out


def _story_tp(f) -> bool:
    from shadow_hunter.notify import is_tp
    return is_tp(f) and (f.ai_confidence or 0) >= MIN_CONFIDENCE and not _seen_first(f)


async def lifecycle() -> int:
    """Close the /shadow members whose finding a person decided or whose story closed."""
    from lib import paging
    from shadow_hunter.models import Finding, Story
    n = 0
    for inc in paging._col("pd_incidents").find({"status": {"$ne": "resolved"}, "members.source": "shadow"}):
        for m in inc.get("members", []):
            if m.get("closed") or m.get("source") != "shadow":
                continue
            _, kind, oid = m["id"].split(":", 2)
            if kind == "story":
                st = await Story.get(oid)
                if not st or st.status != "open":
                    n += await paging.close_member(m["id"])
                continue
            f = await Finding.get(oid)
            if not f or f.decision in ("false_positive", "snooze"):
                n += await paging.close_member(m["id"])
            elif f.decision == "true_positive":
                await paging.acknowledge(m["id"])
                st = await Story.get(f.story_id) if f.story_id else None
                if not st or st.status != "open":
                    n += await paging.close_member(m["id"])
    return n


async def on_decision(f) -> None:
    """Right after a person's decision in the portal (best-effort; lifecycle() also catches it)."""
    from lib import paging
    for member in (f"shadow:finding:{f.id}", f"shadow:early:{f.id}"):
        if f.decision == "true_positive":
            await paging.acknowledge(member)
            if not f.story_id:
                await paging.close_member(member)
        elif f.decision in ("false_positive", "snooze"):
            await paging.close_member(member)


async def _digest(now: datetime) -> None:
    import os
    from lib import paging
    from shadow_hunter.notify import _post
    text = paging.digest_text(paging.stale(now), now)
    url = os.getenv("SHADOW_SLACK_WEBHOOK", "").strip()
    if text and url:
        await _post(url, text)


# ── missed-TP check (2026-11-05) ───────────────────────────────────────────────
# A real attack that never phoned looks exactly like a quiet week. This lists every true
# positive a person confirmed in the window that did not page, with the reason, so the rules
# can be tuned, and so the CrowdStrike switch (~May 2027; every alert name changes) shows up as
# a number instead of silence. L2's "True Positive" often means "it happened, and it was
# authorised" (TP-benign), so each row is a question for a person, not proof of a miss.

def _member_paged(members: list[str]) -> bool:
    from lib import paging
    return any(paging._member_incident(m) for m in members)


def _raptor_reason(rec: dict | None) -> str:
    from edr_triage import paging_rules as R
    from lib import paging
    if not rec:
        return "no RAPTOR record for this ticket"
    name = rec.get("alert_name", "")
    urg, why = R.decide(name, rec.get("triage_class", ""), rec.get("action_taken", ""),
                        paging.type_rule(paging.type_key(name)), False, rec.get("mitre_tactics") or ())
    if urg == "high" and why.startswith("MITRE"):
        return f"tactic rule is observe-only ({why})"
    if urg:
        return f"rule says page ({why}) but no page was recorded (before paging was live, or a send failure)"
    if rec.get("triage_class") != "NEEDS_L2" and rec.get("triage_class") != "URGENT":
        return f"RAPTOR verdict {rec.get('triage_class') or '?'}"
    if rec.get("action_taken") in R.QUIET_ACTIONS:
        return f"RAPTOR action {rec.get('action_taken')}"
    return "alert name not on the paging list and no high-risk MITRE tactic"


def _shadow_reason(f) -> str:
    from shadow_hunter.notify import is_tp
    if f.severity not in ("high", "critical") and not f.story_id:
        return f"severity {f.severity or '?'} and in no story"
    if not is_tp(f):
        return "no Claude true-positive verdict"
    if (f.ai_confidence or 0) < MIN_CONFIDENCE:
        return f"Claude confidence {f.ai_confidence} below {MIN_CONFIDENCE}"
    if _seen_first(f):
        return "a person reviewed it before Claude's verdict"
    return "qualified, but no page was recorded (before paging was live, or a send failure)"


async def missed(days: int = 7, now: datetime | None = None) -> dict:
    """Confirmed TPs in the last `days` that never paged. Counted only from when paging first
    recorded anything, so the window before it existed is not reported as misses."""
    from beanie.operators import In
    from edr_triage.store import get_alert_by_jira_key
    from entity_graph.models import ShadowResult
    from lib import paging
    from shadow_hunter.models import Finding
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    first = paging._col("pd_events").find_one({}, sort=[("at", 1)])
    if first:
        since = max(since, paging._aware(first["at"]))
    else:
        return {"since": since.isoformat(), "raptor": [], "shadow": [], "note": "paging has not recorded anything yet"}
    naive = since.replace(tzinfo=None)

    raptor = []
    rows = await ShadowResult.find({"$or": [
        {"l2_triage_class": "AUTO_CLOSED_TP", "l2_resolved_at": {"$gte": naive}},
        {"l1_triage_class": "AUTO_CLOSED_TP", "l1_resolved_at": {"$gte": naive}}],
        "autonomous_closed_at": None}).to_list()
    for r in {r.jira_key: r for r in rows}.values():
        if _member_paged([f"raptor:{r.jira_key}"]):
            continue
        rec = get_alert_by_jira_key(r.jira_key)
        raptor.append({"jira_key": r.jira_key, "alert_name": r.alert_name, "device": r.device_name or r.user_name,
                       "tactics": (rec or {}).get("mitre_tactics") or [], "reason": _raptor_reason(rec)})

    shadow = []
    for f in await Finding.find({"decision": "true_positive", "reviewed_at": {"$gte": naive}}).to_list():
        ids = [f"shadow:finding:{f.id}", f"shadow:early:{f.id}"] + ([f"shadow:story:{f.story_id}"] if f.story_id else [])
        if _member_paged(ids):
            continue
        shadow.append({"finding": f.id, "detector": f.detector, "severity": f.severity, "device": f.device_name,
                       "summary": (f.summary or f.indicator or "")[:140], "reason": _shadow_reason(f)})
    return {"since": since.isoformat(), "raptor": sorted(raptor, key=lambda x: x["jira_key"]), "shadow": shadow}


def missed_text(rep: dict) -> str:
    n = len(rep.get("raptor", [])) + len(rep.get("shadow", []))
    if not n:
        return ""
    lines = [f":mag: *{n} confirmed true positive{'s' if n > 1 else ''} did not page* (since "
             f"{rep['since'][:10]}). Check each: a real miss means a paging rule to add; "
             "L2's TP is often an authorised action."]
    for r in rep["raptor"][:15]:
        lines.append(f"• {r['jira_key']} {r['alert_name'][:80]} · {r['device'][:30]} — _{r['reason']}_")
    for f in rep["shadow"][:10]:
        lines.append(f"• /shadow {f['severity']} {f['detector']} · {f['device'][:30]} — _{f['reason']}_")
    return "\n".join(lines)
