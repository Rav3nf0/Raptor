"""Which open L2 ticket to read first.

Jira's own priority cannot answer that: on 2026-11-13 the L2 queue held 1,148 tickets and
1,141 of them were "Medium". Nine carried a RAPTOR True Positive or URGENT call or a High
priority, some open for four weeks, among 469 DLP tickets and 57 copies of one nightly job.

This is a hand-written score, not a model, and it decides nothing: no ticket is closed,
moved or hidden by it. It only orders the queue, from facts already on each ticket:

  * RAPTOR's own call (URGENT, True Positive, needs L2, False Positive held by a rule);
  * Jira priority High or above — 4% of tickets, set by the source or an analyst;
  * an attack type on the paging list, or a high-risk MITRE tactic (paging_rules.py) —
    unless every ticket of that alert type carries the tactic. The DLP, USB and bulk-download
    rules stamp "Exfiltration" on all their tickets (528 of the queue), which says what the
    rule is about and nothing about this ticket;
  * a canary token — a tripwire has no legitimate use;
  * the same person or host as another queue ticket that is URGENT or a True Positive;
  * age, one point a day up to AGE_CAP, so nothing starves — never enough to change tier.

Every point carries its reason, so a rank can be read and argued with.

Backtest, scored as each ticket arrived, over the 192 tickets L2 closed itself in the 30 days
to 2026-11-13: 10 of the 15 it closed as true positives were P1 or P2 (8 in P1), against 1 of
the 177 false positives. Four of the five it ranked lower are block-rule and Netskope-malware
tickets L2 closes "true positive, no action"; the fifth (DEMO-117319, a masqueraded service)
RAPTOR had recommended asking the user about, so the score inherits RAPTOR's own misreads.
Fifteen is a small number: treat the weights as a starting point and re-run the backtest
before changing one.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

URGENT, TP, HIGH_PRIORITY, ATTACK_TYPE, HOT_ENTITY = 100, 80, 70, 60, 40
TACTIC, CANARY, RAPTOR_L2, DUPLICATE, REPEAT = 30, 30, 15, -10, -10
AGE_CAP = 14
FLAT_MIN = 10       # an alert type with this many queue tickets, all carrying a tactic: no points for it
TIERS = ((70, "P1"), (40, "P2"), (15, "P3"))      # below the last: P4
_CANARY_RX = re.compile(r"canary", re.I)
_HIGH_PRIORITIES = {"high", "highest", "critical", "blocker"}


def verdict_of(labels) -> str:
    """RAPTOR's call as the ticket's labels record it: URGENT, TP, L2, ASK, FP, DUP or ""."""
    labs = {str(l).lower() for l in labels or []}
    if "urgent" in labs or "raptor-rec-urgent" in labs:
        return "URGENT"
    if "raptor-rec-tp" in labs:
        return "TP"
    if "raptor-rec-l2" in labs:
        return "L2"
    if "raptor-rec-duplicate" in labs:
        return "DUP"
    if "raptor-rec-justify" in labs:
        return "ASK"
    if "ai-fp" in labs or any(l.startswith("raptor-rec-") and l.endswith("-fp") for l in labs):
        return "FP"
    # No recommendation label (autonomous tickets carry none), but RAPTOR's routing label
    # or a rule's "review" call: it decided the ticket needs a person.
    if "needs-l2-review" in labs or any(l.startswith("raptor-rec-") and l.endswith("-review") for l in labs):
        return "L2"
    return ""


def _age_days(created, now: datetime) -> int:
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", str(created or "").strip().replace("Z", "+00:00"))
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return 0
    if not t.tzinfo:
        t = t.replace(tzinfo=timezone.utc)
    return max(0, (now - t).days)


def score(ticket: dict, now: datetime | None = None, hot: dict | None = None,
          flat: set | None = None) -> dict:
    """Points, tier and the reason for every point. Pure.

    `ticket`: key, summary, labels, priority, created, tactics, device, user.
    `hot`: {entity: key of the URGENT/TP queue ticket on it} — see hot_entities().
    `flat`: alert families whose tactic is on every ticket — see flat_tactic_families()."""
    from edr_triage.paging_rules import HIGH_TACTICS, NEVER_RX, PAGE_RX, tactics_of
    now = now or datetime.now(timezone.utc)
    name = ticket.get("summary") or ""
    why: list[tuple[int, str]] = []
    v = verdict_of(ticket.get("labels"))
    if v == "URGENT":
        why.append((URGENT, "RAPTOR called it URGENT"))
    elif v == "TP":
        why.append((TP, "RAPTOR recommends True Positive"))
    elif v == "L2":
        why.append((RAPTOR_L2, "RAPTOR could not clear it"))
    elif v == "DUP":
        why.append((DUPLICATE, "RAPTOR matched it to an earlier ticket"))
    elif not v:
        why.append((RAPTOR_L2, "no RAPTOR verdict on the ticket"))     # unknown is not cleared
    if str(ticket.get("priority") or "").strip().lower() in _HIGH_PRIORITIES:
        why.append((HIGH_PRIORITY, f"Jira priority {ticket.get('priority')}"))
    if PAGE_RX.search(name):
        why.append((ATTACK_TYPE, "attack type on the paging list"))
    hit = sorted(set(tactics_of(ticket.get("tactics") or "")) & HIGH_TACTICS)
    if hit and _family(name) not in (flat or ()):
        why.append((TACTIC, "MITRE tactic: " + ", ".join(hit)))
    if _CANARY_RX.search(name):
        why.append((CANARY, "canary token"))
    if NEVER_RX.search(name) and not PAGE_RX.search(name):
        why.append((REPEAT, "known repeating alert or intel digest"))
    for ent in _entities(ticket):
        other = (hot or {}).get(ent)
        if other and other != ticket.get("key"):
            why.append((HOT_ENTITY, f"same user or host as {other}"))
            break
    age = min(_age_days(ticket.get("created"), now), AGE_CAP)
    if age:
        why.append((age, f"waiting {_age_days(ticket.get('created'), now)} day(s)"))
    pts = sum(p for p, _ in why)
    tier = next((t for floor, t in TIERS if pts >= floor), "P4")
    return {"points": pts, "tier": tier, "reasons": [f"{'+' if p > 0 else ''}{p} {r}" for p, r in why]}


def _family(name: str) -> str:
    from edr_triage.replay_corpus import family
    return family(name)


def flat_tactic_families(tickets: list[dict]) -> set:
    """Alert families with FLAT_MIN or more tickets in the queue, every one carrying a
    high-risk tactic. Pure."""
    from collections import Counter
    from edr_triage.paging_rules import HIGH_TACTICS, tactics_of
    n, with_tactic = Counter(), Counter()
    for t in tickets:
        f = _family(t.get("summary") or "")
        n[f] += 1
        with_tactic[f] += bool(set(tactics_of(t.get("tactics") or "")) & HIGH_TACTICS)
    return {f for f, c in n.items() if c >= FLAT_MIN and with_tactic[f] == c}


def _entities(ticket: dict) -> list[str]:
    """The ticket's host (short name) and named user, lower-cased. Shared accounts are left
    out: every host has an administrator."""
    from entity_graph.query import _is_generic_account
    out = []
    host = str(ticket.get("device") or "").strip().lower().split(".")[0]
    if host and host not in ("unknown", "unknown device"):
        out.append("host:" + host)
    user = str(ticket.get("user") or "").strip().lower()
    if user and not _is_generic_account(user):
        out.append("user:" + user)
    return out


def hot_entities(tickets: list[dict]) -> dict:
    """{entity: ticket key} for every user and host on a queue ticket RAPTOR called URGENT
    or True Positive. Pure."""
    hot: dict = {}
    for t in tickets:
        if verdict_of(t.get("labels")) in ("URGENT", "TP"):
            for ent in _entities(t):
                hot.setdefault(ent, t.get("key"))
    return hot


def rank(tickets: list[dict], now: datetime | None = None) -> list[dict]:
    """The queue, most urgent first; ties go to the older ticket. Pure."""
    now = now or datetime.now(timezone.utc)
    hot, flat = hot_entities(tickets), flat_tactic_families(tickets)
    out = [{**t, **score(t, now, hot, flat)} for t in tickets]
    out.sort(key=lambda t: (-t["points"], str(t.get("created") or "")))
    return out


async def fetch_queue(cfg, jql: str = "") -> list[dict]:
    """Every ticket now in L2 Analysis required (or matching `jql`, for a backtest), with the
    facts score() reads. Raises on a
    Jira failure. Host and user come only from RAPTOR's own triage record: the description's
    "Device Name" is a table header on intel tickets ("Timestamp" on DEMO-120184 and -120976,
    which made them the same host)."""
    from edr_triage.jira_poller import _adf_to_text, _build_client, parse_description_fields
    jql = jql or (f'project = {cfg.jira_project_key} AND status = "L2 Analysis required" '
                  'ORDER BY created ASC')
    out, tok = [], None
    async with _build_client(cfg) as client:
        for _ in range(40):                              # 4,000 tickets; the queue is ~1,100
            body = {"jql": jql, "maxResults": 100,
                    "fields": ["summary", "labels", "priority", "created", "assignee", "description"]}
            if tok:
                body["nextPageToken"] = tok
            r = await client.post("/rest/api/3/search/jql", json=body, timeout=120.0)
            r.raise_for_status()
            d = r.json()
            for i in d.get("issues", []):
                f = i.get("fields") or {}
                desc = f.get("description")
                parsed = parse_description_fields(_adf_to_text(desc) if isinstance(desc, dict) else (desc or ""))
                tactics = parsed.get("tactics") or ""
                out.append({"key": i["key"], "summary": f.get("summary") or "",
                            "labels": f.get("labels") or [],
                            "priority": (f.get("priority") or {}).get("name") or "",
                            "created": f.get("created") or "",
                            "assignee": (f.get("assignee") or {}).get("displayName") or "",
                            "tactics": "" if tactics.strip() in ("[]", "") else tactics,
                            "device": "", "user": ""})
            tok = d.get("nextPageToken")
            if not tok or d.get("isLast"):
                break
    await _add_entities(out)
    return out


async def _add_entities(tickets: list[dict]) -> None:
    """Fill device and user from each ticket's ShadowResult. Never raises: without the
    store the queue is still ranked, only the same-user-or-host signal is missing."""
    try:
        from beanie.operators import In
        from entity_graph.models import ShadowResult
        by_key = {t["key"]: t for t in tickets}
        keys = list(by_key)
        for n in range(0, len(keys), 500):
            rows = await ShadowResult.find(In(ShadowResult.jira_key, keys[n:n + 500])) \
                .sort(-ShadowResult.created_at).to_list()
            seen: set = set()
            for r in rows:
                if r.jira_key in seen:
                    continue
                seen.add(r.jira_key)
                t = by_key[r.jira_key]
                t["device"], t["user"] = r.device_name or "", r.user_name or ""
    except Exception as exc:
        logger.warning("l2_priority: entities unavailable, ranking without them: %s", exc)


async def report(cfg, limit: int = 100) -> dict:
    """The ranked queue: counts per tier and the first `limit` tickets."""
    from collections import Counter
    ranked = rank(await fetch_queue(cfg))
    base = (cfg.jira_url or "").rstrip("/")
    tiers = Counter(t["tier"] for t in ranked)
    return {"total": len(ranked), "by_tier": {k: tiers.get(k, 0) for k in ("P1", "P2", "P3", "P4")},
            "tickets": [{"key": t["key"], "url": f"{base}/browse/{t['key']}", "tier": t["tier"],
                         "points": t["points"], "summary": t["summary"], "created": t["created"],
                         "assignee": t["assignee"], "reasons": t["reasons"]}
                        for t in ranked[:max(1, min(int(limit or 100), 2000))]]}
