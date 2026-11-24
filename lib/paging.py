"""PagerDuty paging for RAPTOR and /shadow: one incident per host or story, quiet by default.

Designed 2026-11-02 against 30 days of real traffic. A severity floor does not work here (96%
of tickets arrive as Medium, and the ATLAS webshell ticket was one of them), and a broad
attack-type list phoned ~4.6 times a day. What decides a page lives with each source
(edr_triage/paging_rules.py, shadow_hunter/paging.py); this module only does what happens
after "this should page":

  grouping   anything that shares a host, account or story with an incident still open and
             active in the last 24h joins it as a member: a PagerDuty trigger on the same
             dedup_key, which PagerDuty folds into the open incident without notifying again.
             ATLAS's 60 /shadow true positives were one incident.
  brake      at most BRAKE_PER_HOUR new phone pages an hour; the rest join one burst incident.
  urgency    "high" phones (PagerDuty severity critical); "low" is a push, off unless
             PAGERDUTY_PUSHES=1 (severity warning;
             the service's urgency must be set to "based on alert severity"). A low-urgency
             push raised at night is held until 09:00 IST (flush_held).
  lifecycle  each member closes with its ticket, finding or story; the incident resolves when
             every member has. A person's TP decision acknowledges it. Nothing re-alerts after
             an acknowledgement; digest() lists incidents still open after 48h, for Slack.

PAGERDUTY_MODE  live (default since 2026-11-03: L1 is paged while their contract runs) | trial |
                off. Live needs EDR_PAGERDUTY_ROUTING_KEY (Events API v2, service secops-urgent);
                without it nothing is sent. Trial records every decision as "would page" and
                calls nothing.

Collections: pd_incidents (one per incident), pd_events (every decision, for the trial
report), pd_type_rules (an analyst's always/never per RAPTOR alert type), pd_seen_types
(when each alert type was last seen, for first-occurrence pushes), pd_meta.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))
JOIN_HOURS = 24
BRAKE_PER_HOUR = 3
DAY_START_IST, DAY_END_IST = 9, 21          # low-urgency pushes outside these hours are held
STALE_HOURS = 48
NEW_TYPE_DAYS = 30
PD_SEVERITY = {"high": "critical", "low": "warning"}


def mode() -> str:
    m = os.getenv("PAGERDUTY_MODE", "live").strip().lower()
    return m if m in ("off", "trial", "live") else "live"


def pushes_on() -> bool:
    """Low-urgency pushes (new alert types, /shadow early detectors, medium stories). Off by
    default since 2026-11-03: the team gets those through Jira and mail; only phone pages go out."""
    return os.getenv("PAGERDUTY_PUSHES", "").strip().lower() in ("1", "true", "on", "yes")


def _routing_key() -> str:
    return os.getenv("EDR_PAGERDUTY_ROUTING_KEY", "").strip()


def base_url() -> str:
    return (os.getenv("SHADOW_PUBLIC_URL", "") or "https://deepintel.uat.example.com").strip().rstrip("/")


def _col(name: str):
    from lib.mongo import get_col
    return get_col(name)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt):
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def entity(kind: str, value: str) -> str:
    """host:name / acct:name / story:id, lower-cased; '' for an empty value."""
    v = (value or "").strip().lower()
    if not v:
        return ""
    if kind == "host":
        v = v.split(".")[0] if not re.match(r"^\d+\.\d+\.\d+\.\d+$", v) else v
    return f"{kind}:{v}"


def next_day_start(now: datetime) -> datetime:
    """The next 09:00 IST at or after now (now itself when it is daytime)."""
    local = now.astimezone(IST)
    if DAY_START_IST <= local.hour < DAY_END_IST:
        return now
    day = local.date() + (timedelta(days=1) if local.hour >= DAY_END_IST else timedelta(0))
    return datetime(day.year, day.month, day.day, DAY_START_IST, tzinfo=IST).astimezone(timezone.utc)


# ── PagerDuty Events API v2 ────────────────────────────────────────────────────

async def _send(action: str, dedup_key: str, title: str = "", urgency: str = "high", details: dict | None = None,
                link: str = "") -> bool:
    """trigger | acknowledge | resolve. Only in live mode with a routing key; never raises."""
    key = _routing_key()
    if mode() != "live" or not key:
        return False
    import httpx
    body: dict = {"routing_key": key, "event_action": action, "dedup_key": dedup_key}
    if action == "trigger":
        body["payload"] = {"summary": title[:1000], "source": "deepintel", "severity": PD_SEVERITY[urgency],
                           "custom_details": details or {}}
        if link:
            body["links"] = [{"href": link, "text": "Open in DeepIntel"}]
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post("https://events.pagerduty.com/v2/enqueue", json=body)
            resp.raise_for_status()
        return True
    except Exception as exc:
        logger.error("[paging] PagerDuty %s for %s failed: %s", action, dedup_key, exc)
        return False


def _log(action: str, source: str, member: str, reason: str, incident: str = "", urgency: str = "", **kw) -> None:
    try:
        _col("pd_events").insert_one({"at": _now(), "action": action, "source": source, "member": member,
                                      "reason": reason, "incident": incident, "urgency": urgency,
                                      "mode": mode(), **kw})
    except Exception as exc:
        logger.error("[paging] event log failed: %s", exc)


# ── offer: "this should page" ──────────────────────────────────────────────────

def _member_incident(member: str):
    return _col("pd_incidents").find_one({"members.id": member})


def _open_for(entities: list[str], now: datetime):
    since = now - timedelta(hours=JOIN_HOURS)
    return _col("pd_incidents").find_one({"status": {"$ne": "resolved"}, "entities": {"$in": entities},
                                          "last_at": {"$gte": since}}, sort=[("opened_at", -1)])


async def offer(source: str, member: str, entities: list[str], urgency: str, title: str,
                details: dict | None = None, link: str = "", reason: str = "", now: datetime | None = None,
                kind: str = "") -> dict:
    """Page (or record that it would page) for one ticket / finding / story. Idempotent per
    member. Returns {"action": "page"|"join"|"held"|"burst"|"member"|"off", "incident": key}.

    kind names what fired (an alert type, a detector). A phone-worthy alert of a kind the
    incident has not seen does not fold into an incident someone already acknowledged: they
    acknowledged something else, so it pages afresh (2026-11-05)."""
    if mode() == "off":
        return {"action": "off"}
    now = now or _now()
    if urgency == "low" and not pushes_on():        # Jira and mail already carry these
        if not _col("pd_events").find_one({"member": member, "action": "push_skipped"}):
            _log("push_skipped", source, member, reason, "", urgency, title=title[:200])
        return {"action": "push_skipped"}
    entities = [e for e in dict.fromkeys(entities) if e]
    col = _col("pd_incidents")
    if _member_incident(member):
        return {"action": "member"}
    m = {"id": member, "source": source, "closed": False, "title": title[:200], "at": now, "urgency": urgency,
         "kind": kind}

    inc = _open_for(entities, now) if entities else None
    new_kind_after_ack = bool(inc and urgency == "high" and kind and inc.get("status") == "acknowledged"
                              and kind not in {x.get("kind") for x in inc.get("members", [])})
    if inc and not (urgency == "high" and inc.get("urgency") == "low") and not new_kind_after_ack:
        col.update_one({"_id": inc["_id"]}, {"$push": {"members": m}, "$addToSet": {"entities": {"$each": entities}},
                                              "$set": {"last_at": now}})
        if inc.get("sent"):
            await _send("trigger", inc["_id"], title, inc.get("urgency", "high"), details, link)
        _log("join", source, member, reason, inc["_id"], urgency)
        return {"action": "join", "incident": inc["_id"]}

    action = "page"
    if urgency == "high":
        hour_ago = now - timedelta(hours=1)
        recent = col.count_documents({"urgency": "high", "opened_at": {"$gte": hour_ago}, "burst": {"$ne": True}})
        if recent >= BRAKE_PER_HOUR:
            key = f"burst-{now.astimezone(IST):%Y%m%d%H}"
            col.update_one({"_id": key}, {"$setOnInsert": {"opened_at": now, "urgency": "high", "burst": True,
                                                            "status": "open", "title": "Burst: more than "
                                                            f"{BRAKE_PER_HOUR} pages in an hour", "sent": False},
                                           "$push": {"members": m}, "$addToSet": {"entities": {"$each": entities}},
                                           "$set": {"last_at": now}}, upsert=True)
            burst = col.find_one({"_id": key})
            if not burst.get("sent"):
                sent = await _send("trigger", key, f"[burst] {burst['title']} — first: {title}", "high", details, link)
                col.update_one({"_id": key}, {"$set": {"sent": sent or mode() == "trial"}})
            _log("burst", source, member, reason, key, urgency)
            return {"action": "burst", "incident": key}

    key = f"{source}-{re.sub(r'[^A-Za-z0-9_.:-]', '_', member)[:80]}-{now:%Y%m%d%H%M}"
    hold = urgency == "low" and next_day_start(now) > now
    doc = {"_id": key, "title": title[:300], "urgency": urgency, "status": "open", "opened_at": now, "last_at": now,
           "entities": entities, "members": [m], "source": source, "details": details or {}, "link": link,
           "held_until": next_day_start(now) if hold else None, "sent": False}
    col.insert_one(doc)
    if inc and not new_kind_after_ack:        # a phone page outranks the push it supersedes
        col.update_one({"_id": inc["_id"]}, {"$set": {"superseded_by": key}})
    if new_kind_after_ack:
        reason = f"{reason}; new kind of alert on an incident already acknowledged ({inc['_id']})"
    if hold:
        action = "held"
    else:
        sent = await _send("trigger", key, title, urgency, details, link)
        col.update_one({"_id": key}, {"$set": {"sent": sent or mode() == "trial"}})
    _log(action, source, member, reason, key, urgency, title=title[:200], night=_night(now))
    return {"action": action, "incident": key}


def _night(now: datetime) -> bool:
    h = now.astimezone(IST).hour
    return h >= 22 or h < 8


def observe(source: str, member: str, reason: str, title: str = "") -> None:
    """A rule still being measured: record that it would page, once per member, page nothing."""
    try:
        if not _col("pd_events").find_one({"member": member, "action": "observed"}):
            _log("observed", source, member, reason, "", "high", title=title[:200], night=_night(_now()))
    except Exception as exc:
        logger.error("[paging] observe failed: %s", exc)


# ── lifecycle ──────────────────────────────────────────────────────────────────

async def acknowledge(member: str) -> bool:
    """A person decided TP on this member: stop the escalation, keep the incident open."""
    inc = _member_incident(member)
    if not inc or inc.get("status") != "open":
        return False
    _col("pd_incidents").update_one({"_id": inc["_id"]}, {"$set": {"status": "acknowledged", "acked_at": _now(),
                                                                     "acked_by_member": member}})
    if inc.get("sent"):
        await _send("acknowledge", inc["_id"])
    _log("ack", inc.get("source", ""), member, "person decided true positive", inc["_id"])
    return True


async def close_member(member: str) -> bool:
    """This ticket / finding / story is closed. Resolves the incident once every member is."""
    col = _col("pd_incidents")
    inc = _member_incident(member)
    if not inc or inc.get("status") == "resolved":
        return False
    col.update_one({"_id": inc["_id"], "members.id": member}, {"$set": {"members.$.closed": True}})
    inc = col.find_one({"_id": inc["_id"]})
    if all(m.get("closed") for m in inc.get("members", [])):
        col.update_one({"_id": inc["_id"]}, {"$set": {"status": "resolved", "resolved_at": _now()}})
        if inc.get("sent"):
            await _send("resolve", inc["_id"])
        _log("resolve", inc.get("source", ""), member, "every member closed", inc["_id"])
    return True


def link_entities(entities: list[str], extra: list[str]) -> str:
    """A story formed around hosts that already paged: its key joins their incident, so its
    later findings fold in instead of ringing again. Returns the incident key or ''."""
    inc = _open_for([e for e in entities if e], _now())
    if not inc:
        return ""
    _col("pd_incidents").update_one({"_id": inc["_id"]}, {"$addToSet": {"entities": {"$each": [e for e in extra if e]}}})
    return inc["_id"]


async def flush_held(now: datetime | None = None) -> int:
    """Send night-held pushes once the day starts, unless resolved meanwhile."""
    now = now or _now()
    col = _col("pd_incidents")
    n = 0
    for inc in col.find({"held_until": {"$ne": None, "$lte": now}, "sent": False, "status": {"$ne": "resolved"}}):
        sent = await _send("trigger", inc["_id"], inc.get("title", ""), inc.get("urgency", "low"),
                           inc.get("details"), inc.get("link", ""))
        col.update_one({"_id": inc["_id"]}, {"$set": {"sent": sent or mode() == "trial", "held_until": None}})
        _log("released", inc.get("source", ""), "", "held overnight", inc["_id"], inc.get("urgency", ""))
        n += 1
    return n


def stale(now: datetime | None = None) -> list[dict]:
    """Incidents open or acknowledged for more than STALE_HOURS (the daily Slack digest)."""
    now = now or _now()
    return list(_col("pd_incidents").find({"status": {"$ne": "resolved"},
                                           "opened_at": {"$lte": now - timedelta(hours=STALE_HOURS)}},
                                          {"title": 1, "status": 1, "opened_at": 1, "members": 1, "link": 1})
                .sort("opened_at", 1).limit(30))


def digest_text(rows: list[dict], now: datetime) -> str:
    if not rows:
        return ""
    lines = [f":hourglass: *{len(rows)} PagerDuty incident{'s' if len(rows) > 1 else ''} open for more than "
             f"{STALE_HOURS}h* (nothing re-alerts; this is the reminder)"]
    for r in rows:
        age = (now - _aware(r["opened_at"])).total_seconds() / 3600
        open_m = sum(1 for m in r.get("members", []) if not m.get("closed"))
        lines.append(f"• {r.get('title', '')[:110]} · {r.get('status')} · {age / 24:.1f}d · {open_m} open item(s)")
    return "\n".join(lines)


def digest_due(now: datetime) -> bool:
    """Once a day, from 10:00 IST."""
    local = now.astimezone(IST)
    if local.hour < 10:
        return False
    meta = _col("pd_meta")
    day = local.strftime("%Y-%m-%d")
    if (meta.find_one({"_id": "digest"}) or {}).get("day") == day:
        return False
    meta.update_one({"_id": "digest"}, {"$set": {"day": day}}, upsert=True)
    return True


# ── alert types (RAPTOR): first occurrence and an analyst's always/never ──────

_TYPE_NOISE = re.compile(r"\bi-[0-9a-f]{6,}\b|\b\d[\d.:,/-]*\b|\S+@\S+")


def type_key(alert_name: str) -> str:
    return re.sub(r"\s+", " ", _TYPE_NOISE.sub("#", (alert_name or "").lower())).strip()[:120]


def type_rule(key: str) -> str:
    row = _col("pd_type_rules").find_one({"_id": key})
    return (row or {}).get("rule", "")


def set_type_rule(key: str, rule: str, by: str) -> None:
    if rule not in ("always", "never", ""):
        raise ValueError("rule must be always, never or empty")
    col = _col("pd_type_rules")
    if not rule:
        col.delete_one({"_id": key})
    else:
        col.update_one({"_id": key}, {"$set": {"rule": rule, "by": by, "at": _now()}}, upsert=True)


def list_type_rules() -> list[dict]:
    return [{"type": r["_id"], "rule": r.get("rule"), "by": r.get("by", ""),
             "at": _aware(r.get("at")).isoformat() if r.get("at") else ""}
            for r in _col("pd_type_rules").find().sort("at", -1)]


def _seed_seen_types(now: datetime) -> None:
    """First use: everything RAPTOR saw in the last NEW_TYPE_DAYS counts as known, so turning
    this on does not push every existing alert type as new."""
    seen = _col("pd_seen_types")
    if seen.estimated_document_count():
        return
    since = now.timestamp() - NEW_TYPE_DAYS * 86400
    last: dict = {}
    for r in _col("edr_triage_processed").find({"processed_at": {"$gte": since}}, {"alert_name": 1, "processed_at": 1}):
        k = type_key(r.get("alert_name", ""))
        if k:
            last[k] = max(last.get(k, 0), r.get("processed_at") or 0)
    for k, ts in last.items():
        seen.update_one({"_id": k}, {"$set": {"last": datetime.fromtimestamp(ts, timezone.utc)}}, upsert=True)
    seen.update_one({"_id": "__seeded__"}, {"$set": {"last": now}}, upsert=True)


def first_occurrence(key: str, now: datetime | None = None) -> bool:
    """True when this alert type was not seen in the previous NEW_TYPE_DAYS. Records it as seen."""
    now = now or _now()
    if not key:
        return False
    try:
        _seed_seen_types(now)
    except Exception as exc:
        logger.error("[paging] seeding seen types failed: %s", exc)
    seen = _col("pd_seen_types")
    row = seen.find_one({"_id": key})
    seen.update_one({"_id": key}, {"$set": {"last": now}}, upsert=True)
    return not row or _aware(row["last"]) < now - timedelta(days=NEW_TYPE_DAYS)


# ── trial report ───────────────────────────────────────────────────────────────

def report(days: int = 14, now: datetime | None = None) -> dict:
    now = now or _now()
    since = now - timedelta(days=days)
    ev = list(_col("pd_events").find({"at": {"$gte": since}}).sort("at", 1))
    phone = [e for e in ev if e["action"] in ("page", "burst") and e.get("urgency") == "high"]
    push = [e for e in ev if e["action"] in ("page", "held") and e.get("urgency") == "low"]
    per_day: dict = {}
    for e in phone:
        d = _aware(e["at"]).astimezone(IST).strftime("%Y-%m-%d")
        per_day[d] = per_day.get(d, 0) + 1
    by_source: dict = {}
    for e in phone + push:
        k = f"{e['source']}:{e.get('urgency')}"
        by_source[k] = by_source.get(k, 0) + 1
    return {
        "mode": mode(), "live_ready": bool(_routing_key()), "days": days,
        "phone_pages": len(phone), "phone_per_week": round(len(phone) * 7 / max(days, 1), 1),
        "phone_at_night": sum(1 for e in phone if e.get("night")),
        "pushes": len(push), "pushes_on": pushes_on(),
        "pushes_skipped": sum(1 for e in ev if e["action"] == "push_skipped"), "joined": sum(1 for e in ev if e["action"] == "join"),
        "bursts": sum(1 for e in ev if e["action"] == "burst"),
        "observed": sum(1 for e in ev if e["action"] == "observed"),
        "observed_recent": [{"at": _aware(e["at"]).astimezone(IST).strftime("%d %b %H:%M IST"), "member": e["member"],
                             "title": e.get("title", ""), "reason": e.get("reason", "")}
                            for e in reversed(ev) if e["action"] == "observed"][:40],
        "worst_day": max(per_day.values()) if per_day else 0, "by_source": by_source,
        "recent": [{"at": _aware(e["at"]).astimezone(IST).strftime("%d %b %H:%M IST"), "action": e["action"],
                    "urgency": e.get("urgency", ""), "source": e["source"], "member": e["member"],
                    "title": e.get("title", ""), "reason": e.get("reason", "")}
                   for e in reversed(ev) if e["action"] in ("page", "held", "burst")][:40],
    }
