"""A few random autonomous closes a day, put in front of L2, and the answer counted.

Why: the autonomy brake and the autonomous-close report learn about a wrong close only when
someone happens to reopen it. While L1 still reads every ticket that is close enough; from
the cutover nobody reads an auto-closed ticket, reopens fall to zero, and precision reads
100% while measuring nothing. A reopen detects disagreement, not diligence (see
autoclose_report). Reviewing every close costs more than not closing; a small random
sample, spread across families, gives a real error rate for about three minutes of L2
time a day. Idea from AiSOC's closure QA sampling (services/agents/app/closure).

How it is answered needs no new habit: L2 adds `raptor-reviewed` if the close was right
(already counted by autoclose_report) or reopens it if wrong (already an overturn, and it
feeds the brake). This module only picks, asks and counts.

Picks: standing closes (not reopened, not reviewed, not sampled before) made in the last
SAMPLE_WINDOW_HOURS, at most one per alert family before any family gets a second, at
random. Once per IST day after SAMPLE_HOUR_IST, claimed in the store so two pods never
both ask.
"""
from __future__ import annotations

import logging
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

SAMPLE_LABEL = "raptor-qa-sample"
SAMPLE_WINDOW_HOURS = 24
SAMPLE_HOUR_IST = 10
_IST = timezone(timedelta(hours=5, minutes=30))


def family(alert_name: str) -> str:
    """Alert family: the summary with digits folded (Port Sweep 7680 and 443 are one)."""
    import re
    return re.sub(r"\d+", "#", (alert_name or "").strip()).casefold()


def pick(closes: list[dict], n: int, rng: random.Random | None = None) -> list[dict]:
    """Up to `n` eligible closes, one per family before any family repeats. Pure."""
    rng = rng or random.Random()
    ok = [c for c in closes
          if not c.get("reopened_at") and not c.get("reviewed_at") and not c.get("qa_sampled")
          and c.get("age_hours", 1e9) <= SAMPLE_WINDOW_HOURS]
    by_fam: dict[str, list[dict]] = defaultdict(list)
    for c in ok:
        by_fam[family(c.get("alert_name", ""))].append(c)
    for v in by_fam.values():
        rng.shuffle(v)
    fams = list(by_fam)
    rng.shuffle(fams)
    out: list[dict] = []
    while len(out) < n and any(by_fam.values()):
        for f in fams:
            if by_fam[f] and len(out) < n:
                out.append(by_fam[f].pop())
    return out


def ask_comment(n: int) -> str:
    return (f"*RAPTOR QA check* — this is one of {n} autonomous close(s) picked at random "
            "today for an L2 look. Nobody else reviews RAPTOR's closes, so this sample is "
            "how its error rate is measured.\n\n"
            "Was this close right?\n"
            "• *Yes:* add the label `raptor-reviewed`.\n"
            "• *No:* reopen it (False Positive → Event Analysis). That counts against this "
            "alert family and can brake its autonomy.\n\n"
            "[RAPTOR QA sample]")


def due(now: datetime | None = None) -> str:
    """Today's IST date if the sample is due (past SAMPLE_HOUR_IST), else ""."""
    now = (now or datetime.now(timezone.utc)).astimezone(_IST)
    return now.date().isoformat() if now.hour >= SAMPLE_HOUR_IST else ""


def summary(closes: list[dict]) -> dict:
    """Outcome of every sampled close: right (reviewed), wrong (reopened) or pending,
    overall and per family. The error rate is wrong / answered, never wrong / sampled —
    an unanswered sample is not a correct one."""
    fams: dict[str, dict] = defaultdict(lambda: {"right": 0, "wrong": 0, "pending": 0})
    for c in closes:
        if not c.get("qa_sampled"):
            continue
        k = "wrong" if c.get("reopened_at") else "right" if c.get("reviewed_at") else "pending"
        fams[family(c.get("alert_name", ""))][k] += 1
    tot = {k: sum(f[k] for f in fams.values()) for k in ("right", "wrong", "pending")}
    answered = tot["right"] + tot["wrong"]
    return {**tot, "sampled": answered + tot["pending"],
            "error_rate": round(tot["wrong"] / answered, 4) if answered else None,
            "per_family": dict(fams)}


async def maybe_sample(closes: list[dict], cfg, now: datetime | None = None,
                       dry_run: bool = False) -> list[str]:
    """Ask L2 about today's sample if it is due and not yet taken. Returns the keys asked."""
    n = int(getattr(cfg, "qa_sample_per_day", 3) or 0)
    day = due(now)
    if n <= 0 or not day:
        return []
    picked = pick(closes, n)
    if not picked:
        return []
    from edr_triage import store
    if not dry_run:
        try:
            # One sample per IST day across pods; the chase-claim store's unique key.
            if not store.claim_user_chase(f"qa-sample:{day}"):
                return []
        except store.ChaseClaimUnavailable as exc:
            logger.error("qa_sample: claim store unavailable (%s) — not sampling", exc)
            return []
    from edr_triage.jira_handler import add_comment, add_labels, assign_issue
    asked = []
    for c in picked:
        key = c["jira_key"]
        if not await add_labels(key, [SAMPLE_LABEL], cfg, dry_run=dry_run):
            logger.error("qa_sample: could not label %s — skipped", key)
            continue
        await add_comment(key, ask_comment(len(picked)), cfg, dry_run=dry_run)
        if cfg.l2_assignee_account_id:
            await assign_issue(key, cfg.l2_assignee_account_id, cfg, dry_run=dry_run)
        asked.append(key)
    logger.info("qa_sample: %s asked L2 about %s", day, asked)
    return asked
