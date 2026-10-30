"""Slack alerts for /shadow stories that contain a true positive.

The partner-onboarding SSRF (22 Oct 2026) was in /shadow at 23:12 IST and its story was built
within the hour, but nothing told anyone: the SOC ticket came from GuardDuty at 01:10 and the
analyst found the story the next afternoon.

Only Claude-verified true positives are announced: ai_verdict true_positive set by Claude
(ai_by names Claude), not dismissed or snoozed by a person. Other models' TPs, unverified
findings and a person's TP decision alone never alert. Posted to a Slack
incoming webhook (#claude-notifier, the channel the September Claude Code sweep used) when

  new        a story first carries a Claude-verified TP
  escalated  a TP story's severity went up after it was announced
  ticket     a Jira ticket is newly linked to a TP story (story_context)
  finding    a high/critical Claude-verified TP finding that is in no story (one in a story rides on its story)

Each is announced once (Story.notified, Finding.notified_at). Only a successful post is recorded, so a Slack
outage is retried next run. A story whose last change and TPs are all older than
LOOKBACK_HOURS is not announced, so turning this on does not replay history. Advisory only:
it never decides, snoozes or edits findings or a story's grouping.

SHADOW_SLACK_WEBHOOK   incoming webhook URL (empty = disabled)
SHADOW_PUBLIC_URL      base for story links (default: UAT)
SHADOW_SLACK_MENTION   optional, e.g. "<@U0123>" or "<!subteam^S0123>", prefixed on critical
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

LOOKBACK_HOURS = 24
FINDING_SEVERITIES = ("high", "critical")
MAX_FINDINGS = 10
IST = timezone(timedelta(hours=5, minutes=30))
DEFAULT_BASE = "https://deepintel.uat.example.com"


def _webhook() -> str:
    return os.getenv("SHADOW_SLACK_WEBHOOK", "").strip()


def _base() -> str:
    return (os.getenv("SHADOW_PUBLIC_URL", "") or DEFAULT_BASE).strip().rstrip("/")


def _aware(dt):
    from shadow_hunter.stories import _parse
    return _parse(dt)


def _ist(dt) -> str:
    d = _aware(dt)
    return d.astimezone(IST).strftime("%d %b %H:%M IST") if d else "?"


def _esc(s) -> str:
    """Slack mrkdwn: & < > are control characters."""
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def is_tp(f) -> bool:
    """Claude verified it as a true positive (ai_by names Claude: the manual Claude Code
    pass, or Claude triage in-app) and no person has dismissed or snoozed it. Other models'
    TPs and unverified findings never alert; a person's TP alone does not either (they know)."""
    return (f.ai_verdict == "true_positive" and "claude" in (getattr(f, "ai_by", "") or "").lower()
            and f.decision not in ("false_positive", "snooze"))


# ── what to say ────────────────────────────────────────────────────────────────

def story_events(st, findings: list, now: datetime) -> dict:
    """{'kind': 'new'|'escalated'|None, 'alerts': [newly linked tickets], 'tps': [...]}."""
    from shadow_hunter.stories import SEV_RANK
    tps = [f for f in findings if is_tp(f)]
    if not tps:
        return {"kind": None, "alerts": [], "tps": []}
    told = st.notified or {}
    recent = now - timedelta(hours=LOOKBACK_HOURS)
    fresh = (_aware(st.updated_at) or now) >= recent or any((_aware(f.created_at) or now) >= recent for f in tps)
    kind = None
    if not told.get("severity"):
        kind = "new" if fresh else None
    elif SEV_RANK.get(st.severity, 0) > SEV_RANK.get(told["severity"], 0):
        kind = "escalated"
    known = set(told.get("alerts") or [])
    alerts = []
    if told.get("severity") or kind:          # tickets only on a story we have announced
        alerts = [a for a in (st.context or {}).get("alerts", [])
                  if a.get("jira_key") and a["jira_key"] not in known
                  and (_aware(a.get("created_at")) or now) >= recent]
    return {"kind": kind, "alerts": alerts, "tps": tps}


def story_message(st, ev: dict) -> str:
    from shadow_hunter.stories import clean
    url = f"{_base()}/shadow/stories/{st.id}"
    hosts = ", ".join(h.get("name", "") for h in (st.entities or {}).get("hosts", [])[:4])
    sev = (st.severity or "").upper()
    lines = []
    if ev["kind"]:
        head = (f"{sev} story with a Claude-verified true positive" if ev["kind"] == "new"
                else f"TP story escalated to {sev}")
        mention = os.getenv("SHADOW_SLACK_MENTION", "").strip() if st.severity == "critical" else ""
        lines.append(f"{mention + ' ' if mention else ''}:rotating_light: *{head}* <{url}|{_esc(st.title)}>")
        lines.append(f"First seen {_ist(st.first_seen)} · last {_ist(st.last_seen)} · "
                     f"{len(ev['tps'])} TP of {len(st.finding_ids)} findings" + (f" · {_esc(hosts)}" if hosts else ""))
        for f in sorted(ev["tps"], key=lambda f: (f.decision != "true_positive", f.severity != "critical"))[:3]:
            who = "Claude TP, analyst confirmed" if f.decision == "true_positive" else "Claude TP"
            lines.append(f"• {_esc(f.severity)} · {_esc(f.device_name)} · {_esc((f.summary or f.indicator)[:110])} _({who})_")
    if ev["alerts"]:
        if not ev["kind"]:
            lines.append(f":link: *Ticket linked to TP story* <{url}|{_esc(st.title)}> ({_esc(st.severity)})")
        for a in ev["alerts"][:5]:
            lines.append(f"• {_esc(a['jira_key'])} {_esc((a.get('alert_name') or '')[:90])}"
                         + (f" — _{_esc(a.get('matched_on', '')[:90])}_" if a.get("matched_on") else ""))
    return clean("\n".join(lines))


def finding_message(findings: list) -> str:
    from shadow_hunter.stories import clean
    crit = any(f.severity == "critical" for f in findings)
    mention = os.getenv("SHADOW_SLACK_MENTION", "").strip() if crit else ""
    lines = [f"{mention + ' ' if mention else ''}:warning: *{len(findings)} Claude-verified true-positive "
             f"detection{'s' if len(findings) > 1 else ''}* (high/critical, not part of a story)"]
    for f in findings[:MAX_FINDINGS]:
        who = "Claude TP, analyst confirmed" if f.decision == "true_positive" else "Claude TP"
        lines.append(f"• <{_base()}/shadow?finding={f.id}|{_esc(f.severity)} · {_esc(f.detector)} · {_esc(f.device_name)}> "
                     f"{_esc((f.summary or f.indicator)[:110])} _({who})_")
    if len(findings) > MAX_FINDINGS:
        lines.append(f"…and {len(findings) - MAX_FINDINGS} more in <{_base()}/shadow|/shadow>")
    return clean("\n".join(lines))


# ── run ────────────────────────────────────────────────────────────────────────

async def _post(url: str, text: str) -> bool:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, json={"text": text})
        if resp.status_code >= 300:
            logger.error("[notify] Slack webhook HTTP %s: %s", resp.status_code, resp.text[:200])
            return False
        return True
    except Exception as exc:
        logger.error("[notify] Slack post failed: %s", exc)
        return False


async def run(post=None, now: datetime | None = None) -> dict:
    """One pass. post: async (text) -> bool, for tests; None = the configured webhook."""
    from beanie.operators import In
    from shadow_hunter.models import Finding, Story
    url = _webhook()
    if post is None:
        if not url:
            return {"disabled": True}
        post = lambda text: _post(url, text)  # noqa: E731
    now = now or datetime.now(timezone.utc)
    sent = {"stories": 0, "tickets": 0, "findings": 0, "failed": 0}
    for st in await Story.find({"status": "open"}).to_list():
        fs = await Finding.find(In(Finding.id, st.finding_ids)).to_list()
        ev = story_events(st, fs, now)
        if not ev["kind"] and not ev["alerts"]:
            continue
        if not await post(story_message(st, ev)):
            sent["failed"] += 1
            continue
        told = dict(st.notified or {})
        if ev["kind"]:
            told["severity"] = st.severity
            sent["stories"] += 1
        if ev["alerts"]:
            told["alerts"] = list(dict.fromkeys((told.get("alerts") or []) + [a["jira_key"] for a in ev["alerts"]]))
            sent["tickets"] += len(ev["alerts"])
        told["at"] = now.isoformat()
        st.notified = told
        await st.save()

    recent = (now - timedelta(hours=LOOKBACK_HOURS)).replace(tzinfo=None)
    loose = [f for f in await Finding.find({
        "severity": {"$in": list(FINDING_SEVERITIES)}, "story_id": {"$in": ["", None]}, "notified_at": None,
        "legacy": {"$ne": True}, "allowlisted_by_rule": "", "created_at": {"$gte": recent},
        "ai_verdict": "true_positive", "decision": {"$nin": ["false_positive", "snooze"]},
    }).sort("-created_at").to_list() if is_tp(f)]
    if loose:
        if await post(finding_message(loose)):
            sent["findings"] = len(loose)
            for f in loose:
                f.notified_at = now
                await f.save()
        else:
            sent["failed"] += 1
    return sent


async def run_logged() -> dict:
    out = await run()
    if not out.get("disabled") and any(out.values()):
        logger.info("[notify] %s", out)
    return out
