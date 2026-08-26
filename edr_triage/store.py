"""EDR Triage MongoDB store — dedup + triaged alert persistence."""
from __future__ import annotations

import logging
import re
import time

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


def claim_alert(alert_id: str) -> bool:
    """Atomically claim an alert for processing. Returns True if this caller owns it, False if already claimed."""
    try:
        _col().insert_one({"alert_id": alert_id, "claimed_at": time.time(), "triage_class": "PROCESSING"})
        return True  # we inserted — we own it
    except Exception:
        # Duplicate key error (or any other failure) → already claimed
        return False


def is_processed(alert_id: str) -> bool:
    """Return True if this MDE alert ID has already been triaged."""
    try:
        return _col().count_documents({"alert_id": alert_id}, limit=1) > 0
    except Exception as exc:
        logger.warning("Dedup check failed for %s: %s", alert_id, exc)
        return False


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
    # PROCESSING is always hidden (in-flight). When hide_observed is set, also
    # drop OBSERVED / SKIPPED records (observe-only noise, e.g. Netskope DLP).
    if triage_class:
        query: dict = {"triage_class": triage_class}
    else:
        excluded = ["PROCESSING"]
        if hide_observed:
            excluded += ["OBSERVED", "SKIPPED"]
        query = {"triage_class": {"$nin": excluded}}
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
    except Exception as exc:
        logger.warning("Failed to read triaged alerts: %s", exc)
        return {"alerts": [], "total": 0}

    results = []
    for doc in docs:
        doc.pop("_id", None)
        results.append(doc)
    return {"alerts": results, "total": total}


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
