"""EDR Triage MongoDB store — dedup + triaged alert persistence."""
from __future__ import annotations

import logging
import re
import time
from typing import Optional

from edr_triage.models import TriagedAlert

logger = logging.getLogger(__name__)


def _col():
    from lib.mongo import get_col
    col = get_col("edr_triage_processed")
    col.create_index("alert_id", unique=True)
    col.create_index("jira_key")
    col.create_index("processed_at")
    col.create_index("triage_class")
    return col


# A claim still PROCESSING this long after it was taken belongs to a run that died —
# the pod was killed (OOM, restart, deploy) or the run raised. Well past the agent's
# 12-minute wall clock (AGENT_LOOP_WALL_TIMEOUT) plus enrichment.
STALE_CLAIM_SECONDS = 30 * 60
# Runs per ticket before RAPTOR gives up and says so on the ticket.
MAX_CLAIM_ATTEMPTS = 2


def claim_alert(alert_id: str) -> bool:
    """Atomically claim an alert for processing. Returns True if this caller owns it, False if already claimed."""
    try:
        _col().insert_one({"alert_id": alert_id, "claimed_at": time.time(),
                           "triage_class": "PROCESSING", "attempts": 1})
        return True  # we inserted — we own it
    except Exception:
        # Duplicate key error (or any other failure) → already claimed
        return False


def claim_alert_with_retry(alert_id: str) -> str:
    """Claim an alert, recovering one whose earlier run died. Returns:

      "new"      — first claim; process it.
      "retry"    — an earlier run never finished (still PROCESSING past
                   STALE_CLAIM_SECONDS, or released by the poll loop after it raised);
                   this caller now owns it; process it again.
      "give_up"  — that has already happened MAX_CLAIM_ATTEMPTS times; the record is now
                   FAILED and the caller must tell the ticket, once.
      "taken"    — processed, being processed, or unreadable; do nothing.

    Before this, a run that died after claiming left the ticket PROCESSING forever: never
    retried, and no comment, so it looked exactly like RAPTOR had never seen it. Five
    Root Privilege Escalation tickets on nerve-engine-0101/-0102 went that way on
    2026-09-30 (DEMO-115156 .. DEMO-115282). Both updates are conditional on the
    claimed_at that was read, so two pollers cannot both win the same recovery.
    """
    if claim_alert(alert_id):
        return "new"
    try:
        col = _col()
        doc = col.find_one({"alert_id": alert_id})
        if not doc or doc.get("triage_class") != "PROCESSING":
            return "taken"
        seen = doc.get("claimed_at", 0)
        if seen > time.time() - STALE_CLAIM_SECONDS:
            return "taken"                        # a live run owns it
        attempts = int(doc.get("attempts") or 1)
        guard = {"alert_id": alert_id, "triage_class": "PROCESSING", "claimed_at": seen}
        if attempts >= MAX_CLAIM_ATTEMPTS:
            res = col.update_one(guard, {"$set": {"triage_class": "FAILED",
                                                  "failed_at": time.time()}})
            return "give_up" if res.modified_count else "taken"
        res = col.update_one(guard, {"$set": {"claimed_at": time.time(),
                                              "attempts": attempts + 1}})
        return "retry" if res.modified_count else "taken"
    except Exception as exc:
        logger.warning("claim recovery failed for %s: %s", alert_id, exc)
        return "taken"


def release_claim_for_retry(alert_id: str, error: str = "") -> None:
    """Mark a claim whose run raised as immediately stale, so the next poll cycle retries
    it instead of waiting out STALE_CLAIM_SECONDS. Only touches a claim still PROCESSING."""
    try:
        _col().update_one({"alert_id": alert_id, "triage_class": "PROCESSING"},
                          {"$set": {"claimed_at": 0, "last_error": (error or "")[:500]}})
    except Exception as exc:
        logger.warning("could not release claim %s: %s", alert_id, exc)


def last_claim_error(alert_id: str) -> str:
    try:
        return (_col().find_one({"alert_id": alert_id}) or {}).get("last_error", "") or ""
    except Exception:
        return ""


def is_processed(alert_id: str) -> bool:
    """Return True if this MDE alert ID has already been triaged."""
    try:
        return _col().count_documents({"alert_id": alert_id}, limit=1) > 0
    except Exception as exc:
        logger.warning("Dedup check failed for %s: %s", alert_id, exc)
        return False


def _chase_col():
    from lib.mongo import get_col
    col = get_col("edr_user_chase")
    col.create_index("jira_key", unique=True)
    return col


class ChaseClaimUnavailable(RuntimeError):
    """The claim store could not be reached, so ownership is UNKNOWN.

    Distinct from "already claimed" on purpose. Both must stop the chase — sending a DM
    without a durable claim risks the duplicate the claim exists to prevent — but they
    are opposite situations: one is the system working, the other is the system down.
    Collapsing them into a single False is what made the 2026-09-17 pilot's first run
    look like a no-op "already chased" when the real cause was an unreachable Mongo.
    """


def claim_user_chase(jira_key: str) -> bool:
    """Atomically claim JIRA_KEY for a user-chase attempt. True iff this caller owns it.

    Own idempotency layer, deliberately not relying on the bot's dedup — DEMO-106747 got
    a duplicate DM because the L1 re-entered `Awaiting more inputs` a second time, so the
    Logic App's own de-dup (if any) is not trustworthy. A unique index on `jira_key`
    means a poller overlap or a forced re-triage can insert at most once; every caller
    after the first gets False and must not repeat the sequence.

    Returns False ONLY for a genuine duplicate. Raises ChaseClaimUnavailable if the store
    itself is unreachable, so the caller can say which of the two happened.
    """
    try:
        _chase_col().insert_one({"jira_key": jira_key, "claimed_at": time.time()})
        return True
    except Exception as exc:
        if _is_duplicate_key(exc):
            return False
        raise ChaseClaimUnavailable(str(exc)) from exc


def _is_duplicate_key(exc: Exception) -> bool:
    """True for a unique-index violation, by pymongo type where available and by message
    otherwise — the tests' in-memory fake raises a plain Exception, and a claim store
    that changes driver must not silently start reading outages as duplicates."""
    try:
        from pymongo.errors import DuplicateKeyError
        if isinstance(exc, DuplicateKeyError):
            return True
    except Exception:
        pass
    return "duplicate key" in str(exc).lower()


def _reply_col():
    from lib.mongo import get_col
    col = get_col("edr_chase_reply")
    col.create_index("jira_key", unique=True)
    return col


def claim_chase_reply(jira_key: str) -> bool:
    """Atomically claim JIRA_KEY for posting its chase-reply packet. True iff this caller owns it.

    Both pods run chase_reply_poller; each read the ticket, saw no packet yet, and posted one
    — DEMO-116253/116255/116259/116260 got two identical packets in the same second
    (2026-10-11), and the second pod's move to L2 then failed. Raises ChaseClaimUnavailable
    when the store cannot be reached, so the caller skips this round instead of posting.
    """
    try:
        _reply_col().insert_one({"jira_key": jira_key, "claimed_at": time.time()})
        return True
    except Exception as exc:
        if _is_duplicate_key(exc):
            return False
        raise ChaseClaimUnavailable(str(exc)) from exc


def release_chase_reply(jira_key: str) -> None:
    """Give a claim back when its packet could not be posted, so a later round retries."""
    try:
        _reply_col().delete_one({"jira_key": jira_key})
    except Exception as exc:
        logger.warning("release_chase_reply(%s) failed: %s", jira_key, exc)


def _sentinel_close_col():
    from lib.mongo import get_col
    col = get_col("edr_sentinel_close")
    col.create_index("incident_id", unique=True)
    return col


SENTINEL_CLAIM_STALE_SECONDS = 3600


def claim_sentinel_close(incident_id: str) -> bool:
    """Atomically claim a Sentinel incident for closing. True iff this caller owns it.

    Every pod runs sentinel_sync; without a claim they race to close the same incident and
    all but one get a rejected write. A claim left by a pod that died before finishing
    (no `done`, older than an hour) is taken over. Raises ChaseClaimUnavailable when the
    store cannot be reached, so the caller skips the incident this round."""
    col = _sentinel_close_col()
    now = time.time()
    try:
        col.insert_one({"incident_id": incident_id, "claimed_at": now})
        return True
    except Exception as exc:
        if not _is_duplicate_key(exc):
            raise ChaseClaimUnavailable(str(exc)) from exc
    try:
        res = col.update_one({"incident_id": incident_id, "done": {"$ne": True},
                              "claimed_at": {"$lt": now - SENTINEL_CLAIM_STALE_SECONDS}},
                             {"$set": {"claimed_at": now}})
    except Exception as exc:
        raise ChaseClaimUnavailable(str(exc)) from exc
    return getattr(res, "modified_count", 0) == 1


def finish_sentinel_close(incident_id: str, result: str) -> None:
    try:
        _sentinel_close_col().update_one({"incident_id": incident_id},
                                         {"$set": {"done": True, "result": result,
                                                   "done_at": time.time()}})
    except Exception as exc:
        logger.warning("finish_sentinel_close(%s) failed: %s", incident_id, exc)


def release_sentinel_close(incident_id: str) -> None:
    """Give a claim back when the close did not happen, so a later sweep retries."""
    try:
        _sentinel_close_col().delete_one({"incident_id": incident_id})
    except Exception as exc:
        logger.warning("release_sentinel_close(%s) failed: %s", incident_id, exc)


def _residual_col():
    from lib.mongo import get_col
    col = get_col("edr_residual")
    col.create_index("jira_key", unique=True)
    col.create_index("noted_at")
    return col


def record_residual(doc: dict) -> None:
    """One row per ticket RAPTOR left for an analyst (no close, ask or route). Upserted on
    jira_key so a re-triage does not count twice. Never raises: this is measurement."""
    try:
        _residual_col().update_one({"jira_key": doc["jira_key"]},
                                   {"$set": doc, "$setOnInsert": {"noted_at": time.time()}},
                                   upsert=True)
    except Exception as exc:
        logger.warning("record_residual(%s) failed: %s", doc.get("jira_key"), exc)


def list_residual(since_epoch: float) -> list[dict]:
    try:
        return list(_residual_col().find({"noted_at": {"$gte": since_epoch}}, {"_id": 0}))
    except Exception as exc:
        logger.warning("list_residual failed: %s", exc)
        return []


def record_user_chase(jira_key: str, recipients: list[str], trigger_reason: str,
                      dry_run: bool) -> None:
    """Attach the outcome to an already-claimed chase row. Never raises — a failure to
    record must not be treated as a failure to chase; the chase itself already happened
    (or was correctly dry-run) by the time this is called."""
    try:
        _chase_col().update_one(
            {"jira_key": jira_key},
            {"$set": {
                "recipients": recipients,
                "trigger_reason": trigger_reason,
                "dry_run": dry_run,
                "notified_at": time.time(),
            }},
        )
    except Exception as exc:
        logger.warning("record_user_chase(%s) failed: %s", jira_key, exc)


def save_triaged_alert(alert: TriagedAlert) -> None:
    """Upsert a triaged alert record."""
    try:
        doc = alert.model_dump()
        doc.setdefault("processed_at", time.time())
        _col().update_one(
            {"alert_id": alert.alert_id},
            {"$set": doc, "$setOnInsert": {"created_at": time.time()}},
            upsert=True,
        )
    except Exception as exc:
        logger.warning("Failed to save triaged alert %s: %s", alert.alert_id, exc)


def get_recent_alerts(
    limit: int = 20,
    offset: int = 0,
    triage_class: str = "",
    severity: str = "",
    hide_observed: bool = False,
    search: str = "",
) -> dict:
    """List triaged alerts, newest first.

    `search` matches jira_key / alert_id / alert_name / device_name / user_name
    server-side. It has to be server-side: the console's filter box used to sift
    only the rows already loaded (one 25-row page), so looking up a specific ticket
    reported "no alerts match" whenever it sat on any other page — and jira_key
    wasn't even in the filtered fields, so a ticket key never matched at all.
    """
    # PROCESSING is always hidden (in-flight). When hide_observed is set, also drop
    # OBSERVED / SKIPPED records AND the observe-only alert FAMILIES.
    #
    # The triage_class exclusion alone is no longer sufficient. It still earns its keep —
    # it removes ~5,200 historical OBSERVED/SKIPPED rows — but Netskope DLP and the Cyble
    # digests now receive real verdicts, so they stopped matching it and the toggle went
    # from hiding them to hiding nothing that mattered: 82% of what remained visible was
    # exactly those two families (measured 2026-09-02).
    #
    # Applied to the verdict-filtered branch too, deliberately: without it "show me every
    # NEEDS_L2" comes back 61% Netskope DLP, which is the same complaint one level down.
    from edr_triage.classifier import OBSERVE_ONLY_FAMILY_RE
    _observe_only = {"alert_name": {"$not": OBSERVE_ONLY_FAMILY_RE}}
    if triage_class:
        query: dict = {"triage_class": triage_class}
        if hide_observed:
            query.update(_observe_only)
    else:
        excluded = ["PROCESSING"]
        if hide_observed:
            excluded += ["OBSERVED", "SKIPPED"]
        query = {"triage_class": {"$nin": excluded}}
        if hide_observed:
            query.update(_observe_only)
    if severity:
        query["severity"] = severity
    if search and search.strip():
        # Escaped: a ticket key contains no regex metacharacters, but a user pasting
        # a command or path into the box must not be interpreted as a pattern.
        _rx = {"$regex": re.escape(search.strip()), "$options": "i"}
        query["$or"] = [
            {"jira_key": _rx}, {"alert_id": _rx}, {"alert_name": _rx},
            {"device_name": _rx}, {"user_name": _rx},
        ]
    try:
        col = _col()
        total = col.count_documents(query)
        docs = list(
            col.find(query)
            .sort("processed_at", -1)
            .skip(offset)
            .limit(limit)
        )
        # How many rows the family filter suppressed, so the console can SAY it is
        # filtered. A hidden queue that looks like the whole queue is how "why am I not
        # seeing DLP tickets?" becomes a bug report instead of a setting.
        observed_hidden = 0
        if hide_observed:
            _unfiltered = {k: v for k, v in query.items() if k != "alert_name"}
            if not triage_class:
                _unfiltered["triage_class"] = {"$nin": ["PROCESSING"]}
            observed_hidden = max(0, col.count_documents(_unfiltered) - total)
    except Exception as exc:
        logger.warning("Failed to read triaged alerts: %s", exc)
        return {"alerts": [], "total": 0, "observed_hidden": 0}

    results = []
    for doc in docs:
        doc.pop("_id", None)
        results.append(doc)
    return {"alerts": results, "total": total, "observed_hidden": observed_hidden}


def get_precedents(
    alert_name: str,
    current_device: str = "",
    current_user: str = "",
    limit: int = 5,
) -> list[dict]:
    """Return previous processed alerts with the same alert name, scoped to
    this specific (device, user) entity.

    Requires BOTH device and user to match when both are known — an OR match
    let generic/shared accounts (root, svc-*, administrator) pull in unrelated
    hosts that just happen to run under the same account (DEMO-106632: root@
    five different boxes showing up as "precedent" for each other). Falls back
    to matching on whichever single field is known if only one is available.
    Excludes in-flight (PROCESSING) and passive (OBSERVED/SKIPPED) records.
    """
    skip_classes = {"PROCESSING", "OBSERVED", "SKIPPED"}
    query = {
        "alert_name": alert_name,
        "triage_class": {"$nin": list(skip_classes)},
    }

    if current_device:
        query["device_name"] = {"$regex": f"^{re.escape(current_device)}$", "$options": "i"}
    if current_user:
        query["user_name"] = {"$regex": f"^{re.escape(current_user)}$", "$options": "i"}
    # else (neither known): nothing to scope by — falls back to alert-type-only matching.

    try:
        docs = list(
            _col()
            .find(query)
            .sort("processed_at", -1)
            .limit(limit)
        )
    except Exception as exc:
        logger.warning("get_precedents failed for '%s': %s", alert_name, exc)
        return []

    results = []
    dev_lower  = (current_device or "").lower()
    user_lower = (current_user or "").lower()

    for doc in docs:
        doc.pop("_id", None)
        prev_device = (doc.get("device_name") or "").lower()
        prev_user   = (doc.get("user_name") or "").lower()
        doc["same_device"] = bool(dev_lower and prev_device and dev_lower == prev_device)
        doc["same_user"]   = bool(user_lower and prev_user   and user_lower == prev_user)
        results.append(doc)

    return results


_HUMAN_CLASS = {"AUTO_CLOSED_FP": "False Positive", "AUTO_CLOSED_TP": "True Positive"}


def human_outcome(shadow) -> str:
    """What a HUMAN decided on a ticket, from its ShadowResult — or that nobody has.

    get_precedents() reads edr_triage_processed, whose triage_class is RAPTOR's own
    ROUTING. Rendered alone as "Outcome", it showed "Needs L2 Review" for tickets L1/L2
    had long since closed FP (DEMO-113488, 113220, 112942 …), and showed RAPTOR's own
    auto-closes as settled precedent. A RAPTOR close is labelled as such, never as a
    human verdict: it is exactly the kind of close nobody reviewed.
    """
    if shadow is None:
        return ""
    if (getattr(shadow, "autonomous_closed_at", None)
            and getattr(shadow, "l2_triage_class", None) == "AUTO_CLOSED_TP"):
        return "auto-closed by RAPTOR, later marked True Positive by a human"
    if getattr(shadow, "reopened_at", None):
        return "auto-closed by RAPTOR, then REOPENED by a human"
    if getattr(shadow, "autonomous_closed_at", None):
        return "auto-closed by RAPTOR — no human review"
    final = getattr(shadow, "l2_triage_class", None)
    if final and getattr(shadow, "l2_resolved_at", None):
        tier = "L2" if getattr(shadow, "l1_handoff_at", None) else "L1"
        return f"{tier}: {_HUMAN_CLASS.get(final, final)}"
    if getattr(shadow, "l1_handoff_at", None):
        return "with L2 — not yet resolved"
    if getattr(shadow, "l1_awaiting_inputs_at", None):
        return "awaiting user input — not yet resolved"
    return "no human verdict yet"


async def attach_human_outcomes(precedents: list[dict]) -> list[dict]:
    """Add `human_outcome` to each precedent in place. Never raises — the section is
    informational, and a lookup failure just leaves the routing-only line as before."""
    keys = [p.get("jira_key") for p in precedents or [] if p.get("jira_key")]
    if not keys:
        return precedents
    try:
        from beanie.operators import In
        from entity_graph.models import ShadowResult
        rows = await ShadowResult.find(In(ShadowResult.jira_key, keys)) \
            .sort(-ShadowResult.created_at).to_list()
    except Exception as exc:
        logger.warning("attach_human_outcomes failed: %s", exc)
        return precedents
    newest: dict = {}
    for r in rows:                      # newest-first, so the first row per key wins
        newest.setdefault(r.jira_key, r)
    for p in precedents:
        if p.get("jira_key") in newest:
            p["human_outcome"] = human_outcome(newest[p["jira_key"]])
    return precedents


def get_occurrence_history(
    alert_name: str,
    user_name: str = "",
    device_name: str = "",
    days: int = 90,
    exclude_alert_id: str = "",
) -> dict:
    """How often this alert family has fired for THIS actor and THIS device before.

    A novelty signal, deliberately separate from get_precedents(). Precedents answer
    "what happened last time and what did we decide" and are scoped to device AND user
    together; this answers only "is this routine for them, or the first time", per
    actor and per device INDEPENDENTLY — because "the host does this constantly but
    this user never has" is exactly the shape that distinguishes a compromised account
    from its owner, and an AND-scoped lookup cannot express it.

    Counts occurrences, NOT outcomes, on purpose. Folding in "and they were all closed
    FP" would rebuild the very thing that makes this class of alert dangerous to
    auto-close: an argument from history that a compromised account inherits wholesale
    from its legitimate owner. Frequency is context for the model to weigh; it is not
    evidence of benignity, and oscar.py says so in the prompt.

    Returns {} when the history cannot be read — an unknown history must never render
    as "never seen before" (falsely alarming) or as "seen often" (falsely reassuring).
    """
    if not (alert_name or "").strip():
        return {}
    since = time.time() - days * 86400
    base: dict = {"alert_name": alert_name,
                  "triage_class": {"$nin": ["PROCESSING", "OBSERVED", "SKIPPED"]}}

    def _count(extra: dict) -> Optional[int]:
        q = dict(base); q.update(extra)
        if exclude_alert_id:
            q["alert_id"] = {"$ne": exclude_alert_id}
        try:
            return _col().count_documents(q)
        except Exception as exc:
            logger.warning("get_occurrence_history count failed for %r: %s", alert_name, exc)
            return None

    out: dict = {"window_days": days, "alert_name": alert_name}
    if (user_name or "").strip():
        n = _count({"user_name": {"$regex": f"^{re.escape(user_name)}$", "$options": "i"},
                    "processed_at": {"$gte": since}})
        if n is None:
            return {}
        out["actor"] = user_name
        out["actor_prior"] = n
        out["actor_first_seen"] = (n == 0)
    if (device_name or "").strip() and device_name != "Unknown Device":
        n = _count({"device_name": {"$regex": f"^{re.escape(device_name)}$", "$options": "i"},
                    "processed_at": {"$gte": since}})
        if n is None:
            return {}
        out["device"] = device_name
        out["device_prior"] = n
        out["device_first_seen"] = (n == 0)
    # Nothing to say if neither an actor nor a device could be scoped.
    if "actor_prior" not in out and "device_prior" not in out:
        return {}
    return out


def clear_all_alerts() -> int:
    """Delete all records from edr_triage_processed. Rules and observations are untouched."""
    try:
        result = _col().delete_many({})
        return result.deleted_count
    except Exception as exc:
        logger.warning("Failed to clear triaged alerts: %s", exc)
        return 0


def get_alert_by_id(alert_id: str) -> dict | None:
    try:
        doc = _col().find_one({"alert_id": alert_id})
        if doc:
            doc.pop("_id", None)
        return doc
    except Exception as exc:
        logger.warning("Failed to look up alert %s: %s", alert_id, exc)
        return None


def get_alert_by_jira_key(jira_key: str) -> dict | None:
    """Look up the triaged-alert record by Jira key (alert_id differs from jira_key
    for MDE tickets). Used by the closure poller to recover the device/user a
    no-shadow ticket bound at triage time, so its human-only memory can link to
    those entities and be recalled."""
    try:
        doc = _col().find_one({"jira_key": jira_key})
        if doc:
            doc.pop("_id", None)
        return doc
    except Exception as exc:
        logger.warning("Failed to look up alert by jira_key %s: %s", jira_key, exc)
        return None


def get_stats() -> dict:
    try:
        col = _col()
        total = col.count_documents({})
        pipeline = [{"$group": {"_id": "$triage_class", "count": {"$sum": 1}}}]
        class_counts: dict[str, int] = {}
        for row in col.aggregate(pipeline):
            class_counts[row["_id"] or "UNKNOWN"] = row["count"]
        return {
            "total": total,
            "auto_closed": class_counts.get("AUTO_CLOSED_TP", 0) + class_counts.get("AUTO_CLOSED_FP", 0),
            "needs_l2": class_counts.get("NEEDS_L2", 0),
            "urgent": class_counts.get("URGENT", 0),
            "pending": class_counts.get("PENDING", 0),
            "by_class": class_counts,
        }
    except Exception as exc:
        logger.warning("Failed to read triage stats: %s", exc)
        return {"total": 0, "auto_closed": 0, "needs_l2": 0, "urgent": 0, "pending": 0, "by_class": {}}
