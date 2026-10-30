"""Automatic brake: a family whose autonomous closes humans have started reopening stops closing.

Every gate in front of an autonomous close predicts. This one reacts. A family enrolled on
a measured precision can still drift: a new kind of activity starts arriving that the
measurement never contained (Root Privesc's DEMO-115542 — a new systemd service closed on
"similar alerts were justified before"). Waiting for someone to notice the overturns in
the report is exactly the kind of habit this design is meant not to depend on.

The rule: look at the family's last WINDOW_CLOSES autonomous closes (made after its re-arm
time, if any). If MAX_OVERTURNS or more of them were reopened by a human — the overturn
signal autoclose_report already records on ShadowResult — the family is braked: no
autonomous close until a person re-arms it with EDR_BRAKE_REARM="<family>=<ISO time>",
which makes only closes after that time count.

Fails CLOSED: if the close history cannot be read, the family does not close.
Chases are untouched — a brake stops closing, never asking.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

WINDOW_CLOSES = 20
MAX_OVERTURNS = 1
BLOCK_LABELS = ("needs-l2-review", "autonomy-braked")

# Root Privesc's only overturn (DEMO-115542) came from closing on the model's verdict, the
# rule withdrawn on 2026-10-05. It re-entered as repeat-or-ask (548040c, live 08:06 UTC),
# so the brake judges only closes made by the new rule. Override or extend with
# EDR_BRAKE_REARM.
DEFAULT_REARM = {
    "root privilege escalation": "2026-10-05T08:06:00+00:00",
    # DEMO-115961's "overturn" (2026-10-06 17:47 UTC) was not a wrong close: RAPTOR's Duplicate
    # was right, and the L1 reopened it to escalate a DIFFERENT alert from the same per-profile
    # Sentinel incident (ellis.rana, "Main Employee Sheet"). Re-armed just after it.
    #
    # DEMO-118679 (2026-10-26 07:53 UTC): RAPTOR closed vera.sinha's at-rest secret-key
    # file False Positive and an L1 re-filed it as Duplicate of DEMO-118678 the same minute.
    # 118678 is a different user and file from the same CASB scan wave, which the L1 closed
    # False Positive himself — a bulk-close habit, not a dispute that the file was benign.
    # Re-armed just after it.
    "netskope dlp alerts": "2026-10-26T07:54:00+00:00",
    # DEMO-116082 (2026-10-07 10:35 UTC): an L1 reopened a correct close that listed only
    # retired tables, after RAPTOR's own comments wrongly said "escalate to L2" (fixed in the
    # same change). Re-armed just after it.
    "log injestion stopped": "2026-10-07T10:36:00+00:00",
    # Port Sweep re-fire duplicates are braked by their regex (duplicate_guard
    # .PORTSWEEP_BRAKE_PATTERN), so the key is that pattern. DEMO-117045 (2026-10-15 05:06
    # UTC): an L1 reopened a port-443 re-fire RAPTOR folded into DEMO-117010, already with
    # L2, only to raise it to L2 again — the redundant escalation the rule exists to save,
    # not a wrong fold. Re-armed just after it (L2 decision).
    # DEMO-118428 (2026-10-23 21:55 UTC): a 7680 re-fire RAPTOR folded as Duplicate, re-filed
    # False Positive by an L1 an hour later — agreement, not an overturn. Re-armed after it.
    r"^\s*network port sweep detected on": "2026-10-23T21:56:00+00:00",
    # Cyble digests (duplicate_guard.CYBLE_BRAKE_PATTERN, all services).
    # DEMO-118854 (2026-10-27 06:02 UTC): RAPTOR
    # closed a twin copy Duplicate and an L1 re-filed it False Positive the next minute —
    # agreement, not an overturn — which stopped every Cyble twin and close. Re-armed after it.
    r"^\s*[Ff]ound\s+\d+\s+alerts?\s+for\s": "2026-10-27T06:03:00+00:00",
    r"^\s*[Ff]ound\s+\d+\s+alerts?\s+for\s+[Ss]ocial\s+[Mm]edia\s+[Mm]onitoring\s":
        "2026-10-27T06:03:00+00:00",
}


def _parse_rearm(raw: str) -> dict[str, datetime]:
    out: dict[str, datetime] = {}
    for part in (raw or "").split(","):
        if "=" not in part:
            continue
        fam, ts = part.rsplit("=", 1)
        try:
            t = datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
        except ValueError:
            logger.error("autonomy_brake: unparseable EDR_BRAKE_REARM entry %r — ignored", part)
            continue
        out[fam.strip().casefold()] = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return out


def rearm_times() -> dict[str, datetime]:
    out = _parse_rearm(",".join(f"{k}={v}" for k, v in DEFAULT_REARM.items()))
    out.update(_parse_rearm(os.getenv("EDR_BRAKE_REARM", "")))
    return out


def _aware(t):
    if t is None:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def decide(closes: list[dict], rearm: datetime | None) -> tuple[bool, str]:
    """(braked, reason) from the family's closes, newest first. Pure.

    `closes`: [{"jira_key", "closed_at", "reopened_at"}], datetimes or None.
    """
    recent = [c for c in closes if c.get("closed_at")
              and (rearm is None or _aware(c["closed_at"]) >= rearm)][:WINDOW_CLOSES]
    over = [c for c in recent if c.get("reopened_at")]
    if len(over) >= MAX_OVERTURNS:
        return True, (f"{len(over)} of this family's last {len(recent)} autonomous closes were "
                      f"reopened by a person ({', '.join(c['jira_key'] for c in over[:5])})")
    return False, ""


async def check(alert_name: str, pattern: str = "") -> tuple[bool, str]:
    """(braked, reason) for this family. Fails closed.

    `pattern`: a regex over alert_name for a family whose name embeds per-alert data (Cyble
    digests carry their alert count), so its closes are judged together, not one name each.
    """
    fam = (alert_name or "").strip()
    if not fam:
        return True, "no alert family identified"
    _name = {"$regex": pattern} if pattern else fam
    try:
        from entity_graph.models import ShadowResult
        rows = await (ShadowResult.find({"alert_name": _name,
                                         "autonomous_closed_at": {"$ne": None}})
                      .sort(-ShadowResult.autonomous_closed_at)
                      .limit(WINDOW_CLOSES * 3).to_list())
        # Closes recorded by autoclose_report — the only record for playbook-only families
        # (Cyble), which never get a ShadowResult.
        from lib.mongo import get_col
        from edr_triage.autoclose_report import CLOSES_COLLECTION
        recorded = list(get_col(CLOSES_COLLECTION)
                        .find({"alert_name": _name, "closed_at": {"$ne": None}})
                        .sort("closed_at", -1).limit(WINDOW_CLOSES * 3))
    except Exception as exc:
        logger.error("autonomy_brake: close history unreadable for %r: %s", fam, exc)
        return True, f"the family's close history could not be read ({str(exc)[:100]})"
    by_key: dict[str, dict] = {}
    for key, closed_at, reopened_at in (
            [(r.jira_key, r.autonomous_closed_at, r.reopened_at) for r in rows]
            + [(d.get("jira_key"), d.get("closed_at"), d.get("reopened_at")) for d in recorded]):
        if not key:
            continue
        c = by_key.setdefault(key, {"jira_key": key, "closed_at": closed_at, "reopened_at": None})
        c["reopened_at"] = c["reopened_at"] or reopened_at   # one row per ticket; a reopen anywhere counts
    closes = sorted(by_key.values(), key=lambda c: _aware(c["closed_at"]), reverse=True)
    braked, why = decide(closes, rearm_times().get((pattern or fam).casefold()))
    if braked:
        logger.warning("[BRAKE] %r is braked — %s", fam, why)
    return braked, why


async def enforce_at_close(alert_name: str, labels: list, jira_key: str, cfg,
                           dry_run: bool = False) -> tuple[bool, str]:
    braked, why = await check(alert_name)
    if not braked:
        return False, ""
    for lab in BLOCK_LABELS:
        if lab not in labels:
            labels.append(lab)
    from edr_triage.jira_handler import add_comment
    try:
        await add_comment(jira_key, (
            "*RAPTOR did not auto-close this ticket: autonomy is braked for this alert "
            "family.*\n\n"
            f"Reason: {why}.\n\n"
            "When people start reopening a family's automatic closes, RAPTOR stops closing "
            "that family until someone re-arms it (EDR_BRAKE_REARM). Please triage this "
            "ticket as usual.\n\n[Auto-triaged by RAPTOR]"), cfg, dry_run=dry_run)
    except Exception as exc:
        logger.error("autonomy_brake: comment on %s failed: %s", jira_key, exc)
    return True, why
