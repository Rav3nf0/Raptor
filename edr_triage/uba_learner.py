"""Learn L2-approved Netskope bulk upload/download patterns, and PROPOSE them for arming.

Stage three of the UBA workflow. Stages one and two ask every named user to explain the
activity (the chase) and route the answers to L2, who approves any close. This stage
turns those approvals into context RAPTOR can act on later — but only through an L2's
hand again: it never arms anything itself. It queues an AllowlistSuggestion, an L2 clicks
Arm in the AI Memory UI, and only then does a repeat of that exact pattern auto-close
(still gated by uba_guard at the close gate).

What counts as evidence — every condition must hold for a user on a ticket:
  * the ticket was chased by RAPTOR (label raptor-chased), its answers were routed to L2
    (RAPTOR's chase-reply packet is on it), and a HUMAN then closed it False Positive
    AFTER that routing — i.e. the close is L2's decision on the answers, not an L1
    closing before L2 ever saw it, and never RAPTOR's own close;
  * that user gave a business justification (named in the packet) — a user who stayed
    silent or only acknowledged is not a pattern anyone approved;
  * every app and account for that user is known and is a COMPANY account (uba_guard's
    non-company test) — a personal, public or unrecorded account is never learned;
  * no Amazon S3 — an S3 transfer needs the user's justification every time, so it is
    never turned into a standing approval (see uba_guard);
  * the device is recorded — the approval pins the machines it came from.

Each suggestion also carries a baseline (the devices and the largest volume seen across
its approved tickets). uba_guard refuses a learned close from another device or at more
than twice that volume, so an insider or an attacker repeating the approved shape from a
new machine, or at a new scale, still goes to L2.

Clustered per (actor, direction, apps, accounts). MIN_APPROVALS separate L2-approved
tickets within LOOKBACK_DAYS are needed before a suggestion is queued. A suggestion L2
has dismissed is never re-proposed.

Evidence is read from Jira — RAPTOR's own UBA comment on each ticket (User / App /
Account lines) and its chase-reply packet — the same way powershell_guard reads its
history, so it survives a database reset and needs no second store.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

MIN_APPROVALS = 2
LOOKBACK_DAYS = 90
_PACKET_MARKER = "[RAPTOR chase-reply]"

_USER_RE = re.compile(r"^\s*\*?User:\*?\s*(\S+)\s+—\s+(\d+)\s+(upload|download)\(s\)", re.I)
_HOST_RE = re.compile(r"^\s*\*?Host:\*?\s*(.+?)(?:\s+\([^)]*\))?(?:\s+—.*)?\s*$", re.I)
_SIZE_RE = re.compile(r"^\s*\*?Total size:\*?\s*([\d,]+)\s+bytes", re.I)
_APP_RE = re.compile(r"^\s*\*?App:\*?\s*(.+?)(?:\s{2,}\(CCL[^)]*\))?\s*$", re.I)
_ACCT_RE = re.compile(r"^\s*\*?Account:\*?\s*(.+?)(?:\s+\(\+\d+ more\))?\s*$", re.I)
_JUSTIFIED_RE = re.compile(r"(\S+)\s+—\s+business justification via Slack", re.I)


def parse_uba_comment(text: str) -> list[dict]:
    """Per-user {actor, direction, apps, instances} from RAPTOR's UBA playbook comment.

    A user whose account list was truncated ("+N more") or missing gets `complete=False`
    and is never learned — a partial list would approve less than was actually shown.
    """
    out: list[dict] = []
    cur: dict | None = None
    for line in (text or "").splitlines():
        m = _USER_RE.match(line)
        if m:
            cur = {"actor": m.group(1).strip().lower(), "direction": m.group(3).lower(),
                   "events": int(m.group(2)), "bytes": 0, "hosts": [],
                   "apps": [], "instances": [], "complete": True}
            out.append(cur)
            continue
        if cur is None:
            continue
        m = _HOST_RE.match(line)
        if m and not cur["hosts"]:
            cur["hosts"] = [h.strip().lower() for h in m.group(1).split(",") if h.strip()]
            continue
        m = _SIZE_RE.match(line)
        if m and not cur["bytes"]:
            cur["bytes"] = int(m.group(1).replace(",", ""))
            continue
        m = _APP_RE.match(line)
        if m and not cur["apps"]:
            cur["apps"] = [a.strip().lower() for a in m.group(1).split(",") if a.strip()]
            continue
        m = _ACCT_RE.match(line)
        if m and not cur["instances"]:
            if "more)" in line:
                cur["complete"] = False
            cur["instances"] = [a.strip().lower() for a in m.group(1).split(",") if a.strip()]
    for u in out:
        if not u["apps"] or not u["instances"]:
            u["complete"] = False
    return out


def justified_users(packet_text: str) -> set[str]:
    return {m.group(1).lower() for m in _JUSTIFIED_RE.finditer(packet_text or "")}


def learnable(entry: dict, justified: set[str]) -> str:
    """"" if this user's activity on an L2-approved ticket may be learned, else why not."""
    from edr_triage.uba_guard import always_justify, non_company
    if not entry.get("complete"):
        return "apps or accounts incomplete"
    if always_justify(entry["apps"]):
        return "Amazon S3 needs a justification every time"
    if not entry.get("hosts"):
        return "no device recorded"
    if entry["actor"].split("@")[0] not in justified and entry["actor"] not in justified:
        return "user gave no justification"
    bad = non_company(entry["instances"])
    if bad:
        return f"non-company account(s): {', '.join(bad)}"
    return ""


def cluster_key(e: dict) -> str:
    return (f"uba|{e['actor']}|{e['direction']}|{','.join(sorted(e['apps']))}"
            f"|{','.join(sorted(e['instances']))}")


def cluster(approved: list[dict]) -> list[dict]:
    """approved: [{key, closed_at, entries:[...], justified:set}] -> suggestion candidates."""
    groups: dict[str, list] = defaultdict(list)
    sample: dict[str, dict] = {}
    for t in approved:
        for e in t["entries"]:
            if learnable(e, t["justified"]):
                continue
            k = cluster_key(e)
            if t["key"] not in [x["key"] for x in groups[k]]:
                groups[k].append(t)
                sample[k] = e
    out = []
    for k, ts in groups.items():
        if len(ts) < MIN_APPROVALS:
            continue
        mine = [e for t in ts for e in t["entries"] if cluster_key(e) == k]
        out.append({"cluster_key": k, **sample[k], "tickets": [t["key"] for t in ts],
                    "baseline": {"hosts": sorted({h for e in mine for h in e["hosts"]}),
                                 "max_events": max(e.get("events", 0) for e in mine),
                                 "max_bytes": max(e.get("bytes", 0) for e in mine)}})
    return out


async def _approved_tickets(cfg) -> list[dict]:
    """Chased UBA tickets that L2 closed False Positive after RAPTOR routed the answers."""
    from edr_triage.jira_handler import _build_client
    from edr_triage.jira_poller import _adf_to_text
    bot = (cfg.jira_email or "").lower()
    from edr_triage.config import BULK_CLOSE_LABEL
    # A bulk close by Claude is not an L2 approval (see BULK_CLOSE_LABEL).
    jql = (f'project = {cfg.jira_project_key} AND labels = "raptor-chased" AND '
           f'labels != "{BULK_CLOSE_LABEL}" AND '
           f'status = "False Positive" AND updated >= -{LOOKBACK_DAYS}d')
    out: list[dict] = []
    async with _build_client(cfg) as client:
        issues, tok = [], None
        for _ in range(10):
            body = {"jql": jql, "maxResults": 100, "fields": ["comment", "summary"]}
            if tok:
                body["nextPageToken"] = tok
            r = await client.post("/rest/api/3/search/jql", json=body)
            r.raise_for_status()
            d = r.json()
            issues += d.get("issues", [])
            tok = d.get("nextPageToken")
            if not tok or d.get("isLast"):
                break
        for iss in issues:
            comments = ((iss.get("fields") or {}).get("comment") or {}).get("comments") or []
            uba_text, packet_text, packet_at = "", "", ""
            for c in comments:
                if ((c.get("author") or {}).get("emailAddress") or "").lower() != bot:
                    continue
                t = _adf_to_text(c.get("body")) if isinstance(c.get("body"), dict) else ""
                if _PACKET_MARKER in t and not packet_text:
                    packet_text, packet_at = t, c.get("created", "")
                elif not uba_text and parse_uba_comment(t):
                    uba_text = t
            if not (uba_text and packet_text):
                continue
            ch = await client.get(f"/rest/api/3/issue/{iss['key']}",
                                  params={"fields": "status", "expand": "changelog"})
            ch.raise_for_status()
            closes = [(h.get("created", ""), ((h.get("author") or {}).get("emailAddress") or "").lower())
                      for h in (ch.json().get("changelog") or {}).get("histories") or []
                      for it in h.get("items", [])
                      if it.get("field") == "status" and it.get("toString") == "False Positive"]
            if not closes:
                continue
            closed_at, closer = max(closes)
            if not closer or closer == bot or closed_at <= packet_at:
                continue      # RAPTOR's own close, or closed before L2 ever saw the answers
            out.append({"key": iss["key"], "closed_at": closed_at, "closed_by": closer,
                        "alert_name": (iss.get("fields") or {}).get("summary", ""),
                        "entries": parse_uba_comment(uba_text),
                        "justified": justified_users(packet_text)})
    return out


async def run_once(cfg=None) -> dict:
    """Mine L2-approved patterns and queue suggestions. Never arms anything. Never raises."""
    from edr_triage.config import get_edr_config
    cfg = cfg or get_edr_config()
    try:
        approved = await _approved_tickets(cfg)
    except Exception as exc:
        logger.warning("uba_learner: Jira read failed: %s", exc)
        return {"error": str(exc)[:200], "queued": 0}
    candidates = cluster(approved)
    queued, skipped = [], []
    try:
        from entity_graph.models import AllowlistSuggestion
        from edr_triage.classifier import alert_subtype
        for c in candidates:
            # Any status — a pattern L2 dismissed is never re-proposed.
            if await AllowlistSuggestion.find_one(AllowlistSuggestion.cluster_key == c["cluster_key"]):
                skipped.append(c["cluster_key"])
                continue
            name = next((t["alert_name"] for t in approved if t["key"] in c["tickets"]),
                        "Netskope - Bulk Upload detection")
            await AllowlistSuggestion(
                alert_type=alert_subtype(name), alert_name=name, actor=c["actor"], device="",
                commands=[], apps=c["apps"], app_instances=c["instances"],
                uba_direction=c["direction"], uba_baseline=c["baseline"],
                source="uba_learner",
                fp_count=len(c["tickets"]), evidence_jira_keys=c["tickets"][:20],
                cluster_key=c["cluster_key"],
            ).insert()
            queued.append(c["cluster_key"])
            logger.info("[UBA-LEARN] queued %s — %d L2-approved closes", c["cluster_key"],
                        len(c["tickets"]))
    except Exception as exc:
        logger.warning("uba_learner: queueing failed: %s", exc)
    return {"approved_tickets": len(approved), "candidates": len(candidates),
            "queued": len(queued), "already_known": len(skipped)}
