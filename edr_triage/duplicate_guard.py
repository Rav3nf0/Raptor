"""Mark a Netskope DLP ticket Duplicate only when it is the SAME event ticketed twice.

Why so narrow. 43% of SIM tickets end as Duplicate (1,713 of 3,971 over 30 days to
2026-10-05), 70% of them DLP. But humans mark DLP duplicates by SENTINEL INCIDENT, and a
DLP Sentinel incident is grouped by DLP PROFILE — its only entity is the profile name, and
one incident collects every DLP-Secret-key hit for weeks. So 536 of the 1,158 human-marked
DLP duplicates carried a DIFFERENT user from every earlier ticket of their incident
(DEMO-111945 skyler.rao closed as a duplicate of reese.iyer's DEMO-111944 — a different
person sending a different file). Copying that practice would swallow distinct events.

What is safe is the exact repeat: the same Netskope event set — user, file, DLP rule, app,
activity and profile, read from each alert's own compressedRec — ticketed again within
WINDOW_SECONDS of the first. Measured over the same 30 days: 526 such tickets in 316
groups, and humans gave all 316 groups ONE outcome. At a 1-hour window one group already
splits (DEMO-113799 False Positive vs DEMO-113808 Awaiting more inputs); at 24h, 15 do.

The earliest ticket of a group is never marked: it carries the triage. An original that is
itself in Duplicate is skipped — a ticket humans folded into some OTHER ticket says nothing
about this event — so if no live original remains, this ticket is triaged as normal.
Fails closed: anything unreadable means "not a duplicate".
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

FAMILY = "Netskope DLP Alerts"
# Cyble threat-intel digests ("Found 22 alerts for Social Media Monitoring across 2 entities")
# arrive as exact twins: the same summary and description, ticketed again within seconds.
# 456 such twins in the 30 days to 2026-10-06, every one within 9 s of the first; humans
# marked 439 Duplicate and closed 16 the same way as the original (1 split decision).
CYBLE_RE = re.compile(r"^\s*found\s+\d+\s+alerts?\s+for\s+.+\s+across\s+\d+\s+entit", re.I)
CYBLE_WINDOW_SECONDS = 60
# The brake must judge Cyble as ONE family: its alert name changes with every digest.
CYBLE_BRAKE_PATTERN = r"^\s*[Ff]ound\s+\d+\s+alerts?\s+for\s"
WINDOW_SECONDS = 120
LABEL = "raptor-autoduplicate"
REC_LABEL = "raptor-rec-duplicate"
_FIELDS = ("user", "dlp_file", "dlp_rule", "app", "activity", "dlp_profile")


def applies(alert_name: str) -> bool:
    return (alert_name or "").strip() == FAMILY


def fingerprint(events: list[dict]) -> frozenset | None:
    """The event set as comparable tuples — None unless every event has every field."""
    out = set()
    for e in events or []:
        t = tuple(str(e.get(f) or "").strip().casefold() for f in _FIELDS)
        if not all(t):
            return None
        out.add(t)
    return frozenset(out) or None


def _ts(s: str) -> datetime | None:
    """Jira '2026-10-05T16:20:01.123+0530' -> aware datetime."""
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", (s or "").strip().replace("Z", "+00:00"))
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo else None


def _num(key: str) -> int:
    m = re.search(r"(\d+)$", key or "")
    return int(m.group(1)) if m else 0


def is_earlier(cand_key: str, cand_t: datetime, key: str, t: datetime) -> bool:
    """Strictly before this ticket, ties broken by key, so one group has one original."""
    return cand_t < t or (cand_t == t and _num(cand_key) < _num(key))


async def _candidates(jira_key: str, t: datetime, cfg) -> list[dict]:
    """Same-family tickets created up to WINDOW_SECONDS before this one, earliest first."""
    from edr_triage.jira_handler import _build_client
    lo, hi = (t - timedelta(days=1)).date().isoformat(), (t + timedelta(days=2)).date().isoformat()
    jql = (f'project = {cfg.jira_project_key} AND summary ~ "\\"{FAMILY}\\"" '
           f'AND created >= "{lo}" AND created < "{hi}" AND key != {jira_key} ORDER BY created ASC')
    out, token = [], None
    async with _build_client(cfg) as c:
        for _ in range(10):
            body = {"jql": jql, "maxResults": 100,
                    "fields": ["summary", "status", "created", "description"]}
            if token:
                body["nextPageToken"] = token
            r = await c.post("/rest/api/3/search/jql", json=body)
            r.raise_for_status()
            page = r.json()
            for i in page.get("issues", []):
                f = i.get("fields") or {}
                ct = _ts(f.get("created", ""))
                if (ct and (f.get("summary") or "").strip() == FAMILY
                        and timedelta(0) <= t - ct <= timedelta(seconds=WINDOW_SECONDS)
                        and is_earlier(i["key"], ct, jira_key, t)):
                    out.append({"key": i["key"], "created": ct,
                                "status": ((f.get("status") or {}).get("name") or ""),
                                "description": f.get("description")})
            token = page.get("nextPageToken")
            if page.get("isLast") or not token:
                break
    return sorted(out, key=lambda x: (x["created"], _num(x["key"])))


async def find_original(jira_key: str, created_at: str, dlp: dict, cfg) -> dict | None:
    """{"key", "status"} of the earliest live ticket carrying exactly this event set, or
    None. `dlp` is query_netskope_dlp's result for THIS ticket. Never raises."""
    try:
        dlp = dlp or {}
        if (dlp.get("bind_source") != "alert" or dlp.get("truncated")
                or dlp.get("event_count", 0) != len(dlp.get("events") or [])):
            return None      # only a complete, alert-bound event set compares (events cap at 15)
        fp = fingerprint(dlp.get("events") or [])
        t = _ts(created_at)
        if not fp or not t:
            return None
        from edr_triage.jira_poller import (_adf_to_text, parse_sentinel_alert_id,
                                            parse_sentinel_incident_url)
        from edr_triage.sentinel_client import _dlp_rows_from_alert
        for cand in await _candidates(jira_key, t, cfg):
            if cand["status"].strip().lower() == "duplicate":
                continue
            d = cand["description"]
            text = _adf_to_text(d) if isinstance(d, dict) else str(d or "")
            url, aid = parse_sentinel_incident_url(text), parse_sentinel_alert_id(text)
            if not (url and aid):
                continue
            if fingerprint(await _dlp_rows_from_alert(url, aid)) == fp:
                return {"key": cand["key"], "status": cand["status"]}
    except Exception as exc:
        logger.warning("duplicate_guard: lookup for %s failed — treating as not a duplicate: %s",
                       jira_key, exc)
    return None


# Files at rest are re-scanned: a CASB API scan finds the same file of the same user again
# hours or days later and every finding is a new ticket (v-aayush.bhapkar1's "RA Payment
# Done Data" was ticketed 7 times 2026-10-07..09; wren.pillai's "Bank Transaction Summary" 4).
# Analysts mark each re-find Duplicate of the ticket already being worked ("a similar alert
# has already been raised to L2"). Narrower than their practice — they also fold a DIFFERENT
# file of the same user — this matches only the identical event set, only for at-rest scans,
# and only onto an original that is still OPEN: someone is handling exactly this finding.
OPEN_REPEAT_DAYS = 7
_AT_REST = "casb api scan"
_DONE = ("False Positive", "Duplicate", "Closed", "Resolved")


async def find_open_repeat(jira_key: str, created_at: str, dlp: dict, cfg) -> dict | None:
    """{"key", "status"} of the earliest still-open DLP ticket, up to OPEN_REPEAT_DAYS older,
    carrying exactly this at-rest event set, or None. Never raises."""
    try:
        dlp = dlp or {}
        events = dlp.get("events") or []
        if (dlp.get("bind_source") != "alert" or dlp.get("truncated")
                or dlp.get("event_count", 0) != len(events)):
            return None
        if not events or any(str(e.get("activity") or "").strip().casefold() != _AT_REST
                             for e in events):
            return None
        fp = fingerprint(events)
        t = _ts(created_at)
        users = sorted({str(e.get("user") or "").strip() for e in events})
        if not fp or not t or len(users) != 1 or '"' in users[0] or "\\" in users[0]:
            return None
        from edr_triage.jira_handler import _build_client
        from edr_triage.jira_poller import (_adf_to_text, parse_sentinel_alert_id,
                                            parse_sentinel_incident_url)
        from edr_triage.sentinel_client import _dlp_rows_from_alert
        lo = (t - timedelta(days=OPEN_REPEAT_DAYS)).date().isoformat()
        hi = (t + timedelta(days=1)).date().isoformat()
        done = ", ".join(f'"{s}"' for s in _DONE)
        # The user's address is in RAPTOR's own triage comment on every DLP ticket, so a text
        # search narrows the candidates; the Sentinel event set below is what decides.
        jql = (f'project = {cfg.jira_project_key} AND summary ~ "\\"{FAMILY}\\"" '
               f'AND created >= "{lo}" AND created < "{hi}" AND status not in ({done}) '
               f'AND text ~ "\\"{users[0]}\\"" AND key != {jira_key} ORDER BY created ASC')
        async with _build_client(cfg) as c:
            r = await c.post("/rest/api/3/search/jql", json={
                "jql": jql, "maxResults": 50, "fields": ["summary", "status", "created", "description"]})
            r.raise_for_status()
            issues = r.json().get("issues", [])
        cands = []
        for i in issues:
            f = i.get("fields") or {}
            ct = _ts(f.get("created", ""))
            st = ((f.get("status") or {}).get("name") or "")
            if (ct and (f.get("summary") or "").strip() == FAMILY and is_earlier(i["key"], ct, jira_key, t)
                    and t - ct <= timedelta(days=OPEN_REPEAT_DAYS) and st not in _DONE):
                cands.append((ct, _num(i["key"]), i["key"], st, f.get("description")))
        for _, _, key, st, d in sorted(cands)[:20]:
            text = _adf_to_text(d) if isinstance(d, dict) else str(d or "")
            url, aid = parse_sentinel_incident_url(text), parse_sentinel_alert_id(text)
            if url and aid and fingerprint(await _dlp_rows_from_alert(url, aid)) == fp:
                return {"key": key, "status": st}
    except Exception as exc:
        logger.warning("duplicate_guard: open-repeat lookup for %s failed — treating as not a "
                       "duplicate: %s", jira_key, exc)
    return None


def open_repeat_comment(original: str, status: str, dlp: dict, closed: bool) -> str:
    ev = (dlp.get("events") or [{}])[0]
    head = (f"*RAPTOR closed this as a Duplicate of {original}.*" if closed
            else f"*RAPTOR: this is a repeat of {original}, which is still open.*")
    return (f"{head}\n\n"
            f"The CASB scan found the same file again: user {ev.get('user')}, file "
            f"\"{ev.get('dlp_file')}\", rule {ev.get('dlp_rule')}, on {ev.get('app')}"
            + (f" (+{len(dlp.get('events')) - 1} more file(s), the same set as on {original})"
               if len(dlp.get("events") or []) > 1 else "")
            + f". {original} is still open ({status}), so this finding is already being handled "
            "there.\n\n"
            + (f"Reopen this ticket only if it is about a DIFFERENT user or file than the one "
               "named above." if closed else "Not closed: recommendation only.")
            + "\n\n[Auto-triaged by RAPTOR]")


def comment(original: str, dlp: dict, closed: bool) -> str:
    ev = (dlp.get("events") or [{}])[0]
    head = (f"*RAPTOR closed this as a Duplicate of {original}.*" if closed
            else f"*RAPTOR: this looks like an exact duplicate of {original}.*")
    return (f"{head}\n\n"
            f"Same file, user and DLP rule, ticketed again within {WINDOW_SECONDS // 60} minutes: user "
            f"{ev.get('user')}, file \"{ev.get('dlp_file')}\", rule {ev.get('dlp_rule')}, "
            f"{ev.get('activity')} on {ev.get('app')}"
            + (f" (+{len(dlp.get('events')) - 1} more event(s), the same set as on {original})"
               if len(dlp.get("events") or []) > 1 else "") + ".\n\n"
            + (f"Triage happens on {original}. Reopen this ticket only if it is about a "
               f"DIFFERENT user or file than the one named above."
               if closed else "Not closed: recommendation only.")
            + "\n\n[Auto-triaged by RAPTOR]")


def applies_cyble(alert_name: str) -> bool:
    return bool(CYBLE_RE.match(alert_name or ""))


def _norm_text(t: str) -> str:
    return " ".join((t or "").split())


async def find_cyble_twin(jira_key: str, created_at: str, alert_name: str, description: str,
                          cfg) -> dict | None:
    """{"key", "status"} of the earliest live ticket with the SAME summary and description
    created up to CYBLE_WINDOW_SECONDS before this one, or None. Never raises."""
    try:
        t, want = _ts(created_at), _norm_text(description)
        if not (t and want and applies_cyble(alert_name)):
            return None
        from edr_triage.jira_handler import _build_client
        from edr_triage.jira_poller import _adf_to_text
        lo, hi = (t - timedelta(days=1)).date().isoformat(), (t + timedelta(days=2)).date().isoformat()
        jql = (f'project = {cfg.jira_project_key} AND summary ~ "\\"Found\\"" '
               f'AND created >= "{lo}" AND created < "{hi}" AND key != {jira_key} ORDER BY created ASC')
        best, token = None, None
        async with _build_client(cfg) as c:
            for _ in range(10):
                body = {"jql": jql, "maxResults": 100,
                        "fields": ["summary", "status", "created", "description"]}
                if token:
                    body["nextPageToken"] = token
                r = await c.post("/rest/api/3/search/jql", json=body)
                r.raise_for_status()
                page = r.json()
                for i in page.get("issues", []):
                    f = i.get("fields") or {}
                    ct = _ts(f.get("created", ""))
                    st = ((f.get("status") or {}).get("name") or "")
                    d = f.get("description")
                    if not (ct and (f.get("summary") or "").strip() == alert_name.strip()
                            and timedelta(0) <= t - ct <= timedelta(seconds=CYBLE_WINDOW_SECONDS)
                            and is_earlier(i["key"], ct, jira_key, t)
                            and st.strip().lower() != "duplicate"):
                        continue
                    if _norm_text(_adf_to_text(d) if isinstance(d, dict) else str(d or "")) != want:
                        continue
                    if best is None or (ct, _num(i["key"])) < (best[0], _num(best[1])):
                        best = (ct, i["key"], st)
                token = page.get("nextPageToken")
                if page.get("isLast") or not token:
                    break
        return {"key": best[1], "status": best[2]} if best else None
    except Exception as exc:
        logger.warning("duplicate_guard: Cyble twin lookup for %s failed — not a duplicate: %s",
                       jira_key, exc)
        return None


def cyble_comment(original: str, closed: bool) -> str:
    head = (f"*RAPTOR closed this as a Duplicate of {original}.*" if closed
            else f"*RAPTOR: this is an exact duplicate of {original}.*")
    return (f"{head}\n\nSame Cyble digest — identical summary and alert breakdown — ticketed "
            f"again within {CYBLE_WINDOW_SECONDS} seconds.\n\n"
            + (f"Triage happens on {original}. Reopen this ticket if it is not the same digest."
               if closed else "Not closed: recommendation only.")
            + "\n\n[Auto-triaged by RAPTOR]")


# ── MS SQL "Suspicious Alter command" re-fires ───────────────────────────────────────────
# The rule runs every 30 minutes over a window that keeps catching the SAME audit event, so
# one ALTER becomes a ticket every half hour while it stays in the window (DEMO-118389 ..
# DEMO-118416: 8 tickets, one eventtime_s 2026-10-23 18:31:43.2367292). L1 sends the first to
# L2 and closes the rest as "a similar alert has already been raised to L2" — 32 of 37 in 60
# days. Folded ONLY on the event's own audit timestamp (7 fractional digits — an identity,
# not a time window): an earlier ticket for this alert whose comments carry that exact
# string is the same event. No timestamp read = nothing folded.
SQLALTER_RE = re.compile(r"^\s*Suspicious Alter command executed on MS SQL server\s*$", re.I)
SQLALTER_WINDOW = timedelta(hours=24)
SQLALTER_BRAKE_PATTERN = r"^\s*Suspicious Alter command executed on MS SQL server"


def applies_sqlalter(alert_name: str) -> bool:
    return bool(SQLALTER_RE.match(alert_name or ""))


def sqlalter_event_time(rule_replay: dict | None) -> str:
    """The audit event's own timestamp from the replayed rule row, or "" — only a value
    precise enough to identify one event (sub-second digits) counts."""
    for k, v in ((rule_replay or {}).get("fields") or {}).items():
        if str(k).lower().startswith("eventtime"):
            v = str(v or "").strip()
            if re.match(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\.\d{4,}", v):
                return v
    return ""


async def find_sqlalter_original(jira_key: str, created_at: str, event_time: str, cfg) -> dict | None:
    """{"key", "status"} of the EARLIEST ticket for this alert in the last 24h whose comments
    carry the same audit event timestamp, or None. Never raises."""
    try:
        t = _ts(created_at)
        if not (t and event_time):
            return None
        from edr_triage.jira_handler import _build_client
        from edr_triage.jira_poller import _adf_to_text
        lo = (t - SQLALTER_WINDOW - timedelta(days=1)).date().isoformat()
        jql = (f'project = {cfg.jira_project_key} AND summary ~ "\\"Suspicious Alter command\\"" '
               f'AND created >= "{lo}" AND key != {jira_key} ORDER BY created ASC')
        best = None
        async with _build_client(cfg) as c:
            r = await c.post("/rest/api/3/search/jql", json={
                "jql": jql, "maxResults": 100, "fields": ["summary", "status", "created", "comment"]})
            r.raise_for_status()
            for i in r.json().get("issues", []):
                f = i.get("fields") or {}
                ct = _ts(f.get("created", ""))
                st = ((f.get("status") or {}).get("name") or "")
                if not (ct and applies_sqlalter(f.get("summary") or "")
                        and timedelta(0) <= t - ct <= SQLALTER_WINDOW
                        and is_earlier(i["key"], ct, jira_key, t)
                        and st.strip().lower() != "duplicate"):
                    continue
                text = " ".join(_adf_to_text(cm.get("body")) if isinstance(cm.get("body"), dict)
                                else str(cm.get("body") or "")
                                for cm in ((f.get("comment") or {}).get("comments") or []))
                if event_time not in text:
                    continue
                if best is None or (ct, _num(i["key"])) < (best[0], _num(best[1])):
                    best = (ct, i["key"], st)
        return {"key": best[1], "status": best[2]} if best else None
    except Exception as exc:
        logger.warning("duplicate_guard: SQL Alter lookup for %s failed — not a duplicate: %s",
                       jira_key, exc)
        return None


def sqlalter_comment(original: str, status: str, event_time: str, command: str, closed: bool) -> str:
    head = (f"*RAPTOR closed this as a Duplicate of {original}.*" if closed
            else f"*RAPTOR: this is the same SQL audit event as {original}.*")
    return (f"{head}\n\nThe MS SQL Alter rule runs every 30 minutes and caught the SAME audit "
            f"event again — event time {event_time}"
            + (f", command `{command[:200]}`" if command else "") + f" — which {original} "
            f"already carries ({status}).\n\n"
            + (f"Review the event on {original}. Reopen this ticket if it is a separate change."
               if closed else "Not closed: recommendation only.")
            + "\n\n[Auto-triaged by RAPTOR]")


# ── Port Sweep hourly re-fires ───────────────────────────────────────────────────────────
# "Network Port Sweep detected on <port>" is an hourly rule: distinct internal hosts that
# received connections on one port in the last hour, over a threshold. While the condition
# lasts it re-fires every hour with a slightly different destination set (7680 from
# 2026-10-13 19:42 UTC: 11 tickets in a day, L1 sent the first to L2 and closed the rest
# as Duplicate by hand — DEMO-116911 of DEMO-116878). Folded in ONLY while an earlier ticket
# for the same port, from the last 24 hours, is still with L2: a person is already looking
# at that condition, and this ticket's destinations are named on it. A new port, or one
# whose earlier ticket is closed or not yet escalated, is triaged on its own.
PORTSWEEP_RE = re.compile(r"^\s*Network Port Sweep detected on (\d{1,5})\s*$", re.I)
PORTSWEEP_WINDOW = timedelta(hours=24)
PORTSWEEP_BRAKE_PATTERN = r"^\s*Network Port Sweep detected on"
_L2 = "l2 analysis required"


def applies_portsweep(alert_name: str) -> bool:
    return bool(PORTSWEEP_RE.match(alert_name or ""))


def _with_l2(issue: dict) -> bool:
    """Reached L2 Analysis required and not finished — wherever L2 has moved it since."""
    f = issue.get("fields") or {}
    st = ((f.get("status") or {}).get("name") or "").strip()
    if st in _DONE:
        return False
    if st.lower() == _L2:
        return True
    return any(it.get("field") == "status" and (it.get("toString") or "").strip().lower() == _L2
               for h in (issue.get("changelog") or {}).get("histories") or []
               for it in h.get("items") or [])


async def find_portsweep_open(jira_key: str, created_at: str, alert_name: str, cfg) -> dict | None:
    """{"key", "status"} of the EARLIEST ticket for the same port, created in the 24 hours
    before this one and still with L2, or None. Never raises."""
    try:
        t = _ts(created_at)
        if not (t and applies_portsweep(alert_name)):
            return None
        from edr_triage.jira_handler import _build_client
        lo = (t - PORTSWEEP_WINDOW - timedelta(days=1)).date().isoformat()
        jql = (f'project = {cfg.jira_project_key} AND summary ~ "\\"Network Port Sweep detected\\"" '
               f'AND created >= "{lo}" AND key != {jira_key} ORDER BY created ASC')
        best = None
        async with _build_client(cfg) as c:
            body = {"jql": jql, "maxResults": 100, "fields": ["summary", "status", "created"],
                    "expand": "changelog"}
            r = await c.post("/rest/api/3/search/jql", json=body)
            r.raise_for_status()
            for i in r.json().get("issues", []):
                f = i.get("fields") or {}
                ct = _ts(f.get("created", ""))
                if not (ct and (f.get("summary") or "").strip().lower() == alert_name.strip().lower()
                        and timedelta(0) <= t - ct <= PORTSWEEP_WINDOW
                        and is_earlier(i["key"], ct, jira_key, t) and _with_l2(i)):
                    continue
                if best is None or (ct, _num(i["key"])) < (best[0], _num(best[1])):
                    best = (ct, i["key"], ((f.get("status") or {}).get("name") or ""))
        return {"key": best[1], "status": best[2]} if best else None
    except Exception as exc:
        logger.warning("duplicate_guard: port-sweep lookup for %s failed — not a duplicate: %s",
                       jira_key, exc)
        return None


def portsweep_comment(original: str, status: str, port: str, dests: list[str], closed: bool) -> str:
    head = (f"*RAPTOR closed this as a Duplicate of {original}.*" if closed
            else f"*RAPTOR: this is the same ongoing sweep as {original}.*")
    d = (f"\n\nThis hour's destinations on port {port} ({len(dests)}): " + ", ".join(dests[:60])
         + (f" … and {len(dests) - 60} more" if len(dests) > 60 else "")) if dests else (
        "\n\nThis hour's destination list could not be read from the alert — see the Sentinel "
        "incident linked in the description.")
    return (f"{head}\n\nThe hourly Port Sweep rule fired again on port {port} while {original} "
            f"is still with L2 ({status}). One ticket per ongoing sweep"
            + ("; this hour's hosts are listed here so they are not lost." if dests else ".")
            + f"{d}\n\n"
            + (f"Review the sweep on {original}. Reopen this ticket if it is a separate event."
               if closed else "Not closed: recommendation only.")
            + "\n\n[Auto-triaged by RAPTOR]")
