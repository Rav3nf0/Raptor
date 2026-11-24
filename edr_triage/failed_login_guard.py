"""Netskope - Failed Login: take re-fires and person-cleared repeats off L2's queue.

The rule is an aggregate over a 24h lookback (`count_ > 2` per user/app/device/IP), and it
runs every ~5 hours. So ONE burst of failures is ticketed about five times: v-elena.rossi's
4 Seva Sindhu failures at 08:56 UTC on 2026-11-12 became DEMO-121981, -122017, -122049,
-122077 and -122126, each re-reporting the same 4. Of the 17 such tickets with L2 on
2026-11-13, 15 were re-fires of three bursts. Every one went to L2, because analysts have
always raised this alert there (pipeline._L2_DIRECT).

Two rules, both fail closed (anything unreadable means "leave it with L2"):

  * RE-FIRE -> Duplicate. An earlier ticket of this alert, raised within 24h and not
    itself a Duplicate, named the same users, apps and source IPs; every failure behind
    this ticket happened at least REFIRE_MARGIN before that ticket was raised, and inside
    its lookback; and this ticket counts no more failures than it did. Nothing happened
    after the earlier ticket, so it already carries the triage. A single new failure
    breaks the match.

  * EXACT REPEAT a person cleared -> False Positive. One user only; every (app, source IP)
    pair in this ticket was on a ticket a PERSON closed False Positive for that same user
    within PRECEDENT_DAYS (a RAPTOR or bulk close is not a clearance); no more than
    max(FAILURE_FLOOR, 2x) the failures of that clearance; no other open alert on the user;
    Netskope shows no successful login by the user to those apps after the first failure;
    and the agent did not call it URGENT.

Neither decides a verdict the humans have not already given: the duplicate defers to an
earlier ticket, the close repeats a person's call on the same user, app and source.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

FAMILY_RE = re.compile(r"^\s*Netskope - Failed Login(?: involving (?:one user|multiple users))?\s*$",
                       re.I)
BRAKE_PATTERN = r"^\s*Netskope - Failed Login"
SUMMARY = "Netskope - Failed Login"
REFIRE_WINDOW = timedelta(hours=24)
REFIRE_MARGIN = timedelta(hours=1)    # ingestion lag: a failure just before the rule ran may be missing from it
LOOKBACK = timedelta(hours=25)        # the rule's 24h lookback plus the bind's forward margin
PRECEDENT_DAYS = 30
FAILURE_FLOOR = 10
CLOSE_LABEL = "raptor-failed-login-repeat"
REC_LABEL = "raptor-rec-failed-login-fp"
_NOT_LIVE = ("Duplicate",)


def applies(alert_name: str) -> bool:
    return bool(FAMILY_RE.match(alert_name or ""))


def _ts(s) -> datetime | None:
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", str(s or "").strip().replace("Z", "+00:00"))
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)          # Log Analytics gives 7 fractional digits
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def shape(fl: dict | None) -> dict | None:
    """The bound failure groups as sets plus the failure time span. None when any group is
    missing its user, app, source IP or times: such a ticket cannot be compared."""
    groups = (fl or {}).get("groups") or []
    if not groups or (fl or {}).get("truncated"):
        return None
    users, apps, ips, pairs, t0s, t1s = set(), set(), set(), set(), [], []
    for g in groups:
        u = str(g.get("user") or g.get("from_user") or "").strip().lower()
        a = str(g.get("app") or "").strip()
        ip = str(g.get("src_ip") or "").strip()
        t0, t1 = _ts(g.get("first_failure")), _ts(g.get("last_failure"))
        if not (u and a and ip and t0 and t1):
            return None
        users.add(u), apps.add(a.lower()), ips.add(ip), pairs.add((u, a.lower(), ip))
        t0s.append(t0), t1s.append(t1)
    return {"users": users, "apps": apps, "ips": ips, "pairs": pairs,
            "first": min(t0s), "last": max(t1s),
            "total": int(fl.get("total_failures") or 0),
            "max": int(fl.get("max_failures") or 0)}


_LINE = lambda label: re.compile(r"\*?" + label + r":\*?[ \t]*([^\n]*)")
_USERS, _APPS, _IPS = _LINE("Users"), _LINE("Apps"), _LINE("Source IPs")
_TOTAL = re.compile(r"\*?(\d+) failed logins\*?")


def parse_playbook_comment(text: str) -> dict | None:
    """Users / Apps / Source IPs / failure total from RAPTOR's failed-login comment
    (playbooks/netskope.py). None when it is not that comment or a line is unresolved."""
    if "failed-login" not in (text or "") or not _TOTAL.search(text):
        return None
    out = {}
    for k, rx in (("users", _USERS), ("apps", _APPS), ("ips", _IPS)):
        m = rx.search(text)
        raw = (m.group(1) if m else "").strip()
        if not raw or raw == "not resolved":
            return None
        vals = {v.strip().strip("*`").lower() for v in raw.split(",") if v.strip()}
        out[k] = {v for v in vals if v}
    out["total"] = int(_TOTAL.search(text).group(1))
    return out


def _bot_record(issue: dict, bot: str) -> dict | None:
    from edr_triage.jira_poller import _adf_to_text, adf_to_marked_text
    for c in ((issue.get("fields") or {}).get("comment") or {}).get("comments") or []:
        if ((c.get("author") or {}).get("emailAddress") or "").lower() != bot:
            continue
        b = c.get("body")
        if not isinstance(b, dict):
            continue
        p = parse_playbook_comment(adf_to_marked_text(b)) or parse_playbook_comment(_adf_to_text(b))
        if p:
            return p
    return None


async def _search(cfg, jql: str, fields: list[str], pages: int = 5) -> list[dict]:
    from edr_triage.jira_handler import _build_client
    out, tok = [], None
    async with _build_client(cfg) as client:
        for _ in range(pages):
            body = {"jql": jql, "maxResults": 100, "fields": fields}
            if tok:
                body["nextPageToken"] = tok
            r = await client.post("/rest/api/3/search/jql", json=body)
            r.raise_for_status()
            d = r.json()
            out += d.get("issues", [])
            tok = d.get("nextPageToken")
            if not tok or d.get("isLast"):
                break
    return out


def is_refire_of(cur: dict, cur_t: datetime, cand: dict, cand_t: datetime) -> bool:
    """Pure: may this ticket (shape `cur`, created `cur_t`) be folded into the earlier one
    (parsed record `cand`, created `cand_t`)?"""
    if not (cur and cand and cand_t < cur_t and cur_t - cand_t <= REFIRE_WINDOW):
        return False
    if (cand["users"], cand["apps"], cand["ips"]) != (cur["users"], cur["apps"], cur["ips"]):
        return False
    if cur["last"] > cand_t - REFIRE_MARGIN:       # a failure after (or at) the earlier ticket
        return False
    if cur["first"] < cand_t - LOOKBACK:           # outside what the earlier ticket could see
        return False
    return cur["total"] <= cand["total"]


async def find_refire(jira_key: str, created_at: str, fl: dict, cfg) -> dict | None:
    """{"key", "status"} of the earliest live ticket this one re-fires, or None. Never raises."""
    try:
        cur, t = shape(fl), _ts(created_at)
        if not (cur and t):
            return None
        bot = (cfg.jira_email or "").lower()
        lo = (t - REFIRE_WINDOW - timedelta(days=1)).date().isoformat()
        jql = (f'project = {cfg.jira_project_key} AND summary ~ "\\"{SUMMARY}\\"" '
               f'AND created >= "{lo}" AND key != {jira_key} ORDER BY created ASC')
        best = None
        for i in await _search(cfg, jql, ["summary", "status", "created", "comment"]):
            f = i.get("fields") or {}
            ct = _ts(f.get("created", ""))
            st = ((f.get("status") or {}).get("name") or "").strip()
            if not (ct and applies(f.get("summary") or "") and st not in _NOT_LIVE):
                continue
            if is_refire_of(cur, t, _bot_record(i, bot), ct) and (best is None or ct < best[0]):
                best = (ct, i["key"], st)
        return {"key": best[1], "status": best[2]} if best else None
    except Exception as exc:
        logger.warning("failed_login_guard: re-fire lookup for %s failed — not a duplicate: %s",
                       jira_key, exc)
        return None


def refire_comment(original: str, status: str, fl: dict, closed: bool) -> str:
    cur = shape(fl) or {}
    head = (f"*RAPTOR closed this as a Duplicate of {original}.*" if closed
            else f"*RAPTOR: this re-reports the same failed logins as {original}.*")
    return (f"{head}\n\nThe Netskope Failed Login rule looks back 24 hours and runs every few "
            f"hours, so one burst of failures is ticketed several times. These "
            f"{cur.get('total', '?')} failure(s) by {', '.join(sorted(cur.get('users') or [])) or '?'} "
            f"on {', '.join(sorted(cur.get('apps') or [])) or '?'} from "
            f"{', '.join(sorted(cur.get('ips') or [])) or '?'} all happened before {original} was "
            f"raised ({status}); there has been no failure since.\n\n"
            + (f"Review the failures on {original}. Reopen this ticket if they are new."
               if closed else "Not closed: recommendation only.")
            + "\n\n[Auto-triaged by RAPTOR]")


async def cleared_precedents(user: str, jira_key: str, cfg) -> list[dict]:
    """Tickets of this alert a PERSON closed False Positive for exactly this one user within
    PRECEDENT_DAYS, with their apps, IPs and failure total. Raises on a Jira failure."""
    from edr_triage.config import NOT_BULK_CLOSED_JQL
    from edr_triage.powershell_guard import _last_fp_close
    bot = (cfg.jira_email or "").lower()
    since = datetime.now(timezone.utc) - timedelta(days=PRECEDENT_DAYS)
    jql = (f'project = {cfg.jira_project_key} AND summary ~ "\\"{SUMMARY}\\"" '
           f'AND status = "False Positive" AND updated >= -{PRECEDENT_DAYS + 1}d '
           f'AND {NOT_BULK_CLOSED_JQL} AND key != {jira_key} ORDER BY created DESC')
    out = []
    for i in await _search(cfg, jql, ["comment"]):
        p = _bot_record(i, bot)
        if not (p and p["users"] == {user}):
            continue
        closer, at = await _last_fp_close(i["key"], cfg)
        if closer and closer != bot and at and at >= since:
            out.append({**p, "key": i["key"], "cleared_by": closer, "cleared_at": at.isoformat()})
    return out


def precedent_decision(cur: dict, prec: list[dict]) -> tuple[bool, str, list[dict]]:
    """Pure: (allow, reason, precedents used) for the exact-repeat close."""
    if not cur:
        return False, "the failure groups could not be read in full", []
    if len(cur["users"]) != 1:
        return False, f"{len(cur['users'])} users failing — not one person's repeat", []
    used, uncovered = [], []
    for (_u, app, ip) in sorted(cur["pairs"]):
        hit = [p for p in prec if app in p["apps"] and ip in p["ips"]]
        if not hit:
            uncovered.append(f"{app} from {ip}")
        used += [p for p in hit if p not in used]
    if uncovered:
        return False, ("no person has cleared this user's failures on " + ", ".join(uncovered)
                       + f" in the last {PRECEDENT_DAYS} days"), []
    cap = max(FAILURE_FLOOR, 2 * max(p["total"] for p in used))
    if cur["max"] > cap:
        return False, f"{cur['max']} failures in one group, above the cleared runs' {cap}", []
    return True, "exact repeat of a person-cleared failed login", used


async def later_success(incident_url: str, user: str, apps: set, since: datetime) -> bool | None:
    """True if Netskope logged a successful login by `user` to any of `apps` at or after
    `since`; None when the query could not run (the caller then refuses)."""
    from edr_triage.sentinel_client import _run_la_query, parse_incident_url
    parts = parse_incident_url(incident_url)
    if not parts:
        return None
    esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
    app_list = ", ".join(f'"{esc(a)}"' for a in sorted(apps))
    kql = ("Netskope_Alerts_CL\n"
           f"| where TimeGenerated >= datetime({since:%Y-%m-%dT%H:%M:%S}Z)\n"
           f'| where user_s =~ "{esc(user)}" or from_user_s =~ "{esc(user)}"\n'
           f"| where tolower(app_s) in ({app_list})\n"
           '| where activity_s == "Login Successful"\n'
           "| summarize n=count()")
    try:
        rows = await _run_la_query(parts, kql)
    except Exception as exc:
        logger.warning("failed_login_guard: success lookup failed: %s", exc)
        return None
    if not rows:            # _run_la_query returns [] on an error as well as on no data
        return None
    return int((rows[0] or {}).get("n") or 0) > 0


def close_comment(cur: dict, used: list[dict]) -> str:
    user = next(iter(cur["users"]))
    refs = "; ".join(f"{p['key']} (cleared by {p['cleared_by'].split('@')[0]}, "
                     f"{p['cleared_at'][:10]})" for p in used[:5])
    pairs = ", ".join(f"{a} from {ip}" for (_u, a, ip) in sorted(cur["pairs"]))
    return ("*RAPTOR closed this as a False Positive: an exact repeat of failed logins a person "
            "already cleared.*\n\n"
            f"{cur['total']} failed login(s) by {user} on {pairs}. The same user, app and source "
            f"IP were closed False Positive by an analyst: {refs}.\n\n"
            "Checked before closing: Netskope shows no successful login by this user to these "
            "apps since the first failure; no other open alert on this user; the failure count "
            "is within twice the cleared run's.\n\n"
            "Reopen this ticket if these logins were not the user's own."
            "\n\n[Auto-triaged by RAPTOR]")
