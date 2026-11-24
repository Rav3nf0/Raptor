"""Where a close rule might be worth writing: shapes people always close False Positive.

Every close rule RAPTOR has was found the same way — count what analysts did with one kind
of ticket, and when it was the same answer every time, read the tickets and write the rule.
This does the counting. It is a group-by, not a model, and it changes nothing: its output
is a list for a person to read.

A shape is an alert family, alone or narrowed by RAPTOR's own call, by host or by named
user. A shape is a candidate when, among the tickets RAPTOR did not close itself, people
gave at least `min_n` verdicts and none was a True Positive. Duplicates are not verdicts
and are counted beside them. A narrower shape is listed only when its family does not
already qualify.

A long window re-finds rules RAPTOR already has: over 90 days "Log injestion stopped" is 46
of 46, from before its rule shipped. So each candidate also shows the last RECENT_DAYS days —
how many tickets people still closed by hand and how many RAPTOR closed itself — and the
list is ordered by that hand-closed count, which is what a new rule would actually save.

What it cannot tell you, and why a candidate is not a rule:
  * "L1 closed it" is not independent evidence the activity was benign; the L2 count is
    shown separately for that reason.
  * It counts outcomes, not reasons. The rule still needs a condition RAPTOR can check
    (the same commands, the same file, the same source) — that comes from reading the
    tickets, which is why each candidate carries examples.
  * A shape nobody has closed (57 PowerShell tickets on one server, all still with L2)
    has no verdicts and so is never a candidate; it is listed under `unanswered` instead.

Verdicts come from the ShadowResult store, through replay_corpus.verdict_fields: a RAPTOR
close nobody reviewed and a bulk close are not human verdicts there.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

MIN_N = 20
RECENT_DAYS = 30
UNANSWERED_MIN = 15


def _shapes(r: dict) -> list[tuple]:
    from entity_graph.query import _is_generic_account
    fam = r.get("family") or "?"
    out = [("family", fam, "")]
    if r.get("raptor"):
        out.append(("family + RAPTOR's call", fam, r["raptor"]))
    host = str(r.get("device") or "").strip().lower().split(".")[0]
    if host and host not in ("unknown", "unknown device"):
        out.append(("family + host", fam, host))
    user = str(r.get("user") or "").strip().lower()
    if user and not _is_generic_account(user):
        out.append(("family + user", fam, user))
    return out


def mine(rows: list[dict], min_n: int = MIN_N, days: int = 0,
         recent_since: datetime | None = None) -> dict:
    """Candidates and unanswered shapes from one row per ticket. Pure.

    Row: key, family, raptor (its call), device, user, raptor_closed (bool),
    human ("FP", "TP", "DUP" or "" while open), tier ("L1" or "L2"), created (datetime).
    `recent_since`: rows created at or after it count as recent."""
    g: dict = defaultdict(lambda: {"fp": 0, "fp_l2": 0, "tp": 0, "dup": 0, "open": 0, "n": 0,
                                   "fp_recent": 0, "n_recent": 0, "examples": [], "tp_keys": []})
    raptor_recent: dict = defaultdict(int)       # shape -> RAPTOR's own closes, recent
    for r in rows:
        recent = bool(recent_since and r.get("created") and r["created"] >= recent_since)
        if r.get("raptor_closed"):
            for shape in _shapes(r):
                raptor_recent[shape] += recent
            continue
        for shape in _shapes(r):
            s = g[shape]
            s["n"] += 1
            s["n_recent"] += recent
            h = r.get("human") or ""
            if h == "FP":
                s["fp"] += 1
                s["fp_recent"] += recent
                s["fp_l2"] += r.get("tier") == "L2"
                if len(s["examples"]) < 5:
                    s["examples"].append(r.get("key"))
            elif h == "TP":
                s["tp"] += 1
                s["tp_keys"].append(r.get("key"))
            elif h == "DUP":
                s["dup"] += 1
            else:
                s["open"] += 1
    weeks = max(days / 7.0, 1.0) if days else 0

    def _row(shape, s):
        kind, fam, val = shape
        return {"shape": kind, "family": fam, "value": val, "tickets": s["n"],
                "per_week": round(s["n"] / weeks, 1) if weeks else None,
                "closed_fp": s["fp"], "closed_fp_by_l2": s["fp_l2"], "closed_tp": s["tp"],
                "duplicates": s["dup"], "still_open": s["open"],
                "recent": {"days": RECENT_DAYS, "left_for_people": s["n_recent"],
                           "people_closed_fp": s["fp_recent"],
                           "raptor_closed": raptor_recent.get(shape, 0)},
                "examples": s["examples"], "tp_tickets": s["tp_keys"][:5]}

    ok = {shape for shape, s in g.items() if s["fp"] >= min_n and s["tp"] == 0}
    fam_ok = {shape[1] for shape in ok if shape[0] == "family"}
    cands = [_row(shape, g[shape]) for shape in ok
             if shape[0] == "family" or shape[1] not in fam_ok]
    cands.sort(key=lambda c: (-c["recent"]["people_closed_fp"], -c["tickets"], c["family"], c["value"]))
    # One True Positive in a long run of False Positives: the ticket that breaks the
    # pattern is the first thing to read before writing any rule near it.
    near = [_row(shape, s) for shape, s in g.items()
            if shape[0] == "family" and s["tp"] and s["fp"] >= min_n and s["tp"] / (s["fp"] + s["tp"]) <= 0.05]
    near.sort(key=lambda c: -c["tickets"])
    unanswered = [_row(shape, s) for shape, s in g.items()
                  if shape[0] in ("family + host", "family + user")
                  and s["open"] >= UNANSWERED_MIN and s["fp"] + s["tp"] == 0]
    unanswered.sort(key=lambda c: -c["still_open"])
    return {"min_n": min_n, "days": days, "tickets_read": len(rows),
            "candidates": cands, "one_true_positive_in_a_long_run": near, "unanswered": unanswered}


def row_of(shadow) -> dict:
    """One ticket's ShadowResult as a mine() row. Pure."""
    from edr_triage.replay_corpus import family, verdict_fields
    f = verdict_fields(shadow)
    final = f["human_class"]
    if getattr(shadow, "reopened_at", None):
        human = "TP"                  # a person overturned RAPTOR's close: never a clean FP
    elif f["labelled"] and final == "AUTO_CLOSED_FP":
        human = "FP"
    elif f["labelled"] and final in ("AUTO_CLOSED_TP", "URGENT"):
        human = "TP"
    elif getattr(shadow, "duplicate_at", None) and not f["closed_by_raptor"]:
        human = "DUP"
    else:
        human = ""
    return {"key": shadow.jira_key, "family": family(shadow.alert_name),
            "raptor": getattr(shadow, "pre_safety_class", "") or shadow.ai_triage_class or "",
            "device": shadow.device_name or "", "user": shadow.user_name or "",
            "created": getattr(shadow, "created_at", None),
            "raptor_closed": f["closed_by_raptor"] and not getattr(shadow, "reopened_at", None),
            "human": human, "tier": "L2" if f["handled_by_l2"] else "L1"}


async def report(days: int = 90, min_n: int = MIN_N) -> dict:
    """mine() over every ticket triaged in the last `days` (newest record per ticket)."""
    from entity_graph.models import ShadowResult
    days = max(7, min(int(days or 90), 365))
    since = datetime.utcnow() - timedelta(days=days)
    rows: dict = {}                 # only the small row is kept: a record carries every tool call
    async for sr in ShadowResult.find(ShadowResult.created_at >= since).sort(-ShadowResult.created_at):
        if sr.jira_key not in rows and not getattr(sr, "ai_error", None):
            rows[sr.jira_key] = row_of(sr)
    return mine(list(rows.values()), max(5, int(min_n or MIN_N)), days,
                recent_since=datetime.utcnow() - timedelta(days=RECENT_DAYS))
