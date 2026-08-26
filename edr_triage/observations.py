"""Ticket observatory — logs every SIM ticket type seen, regardless of whether it was acted on.

Tracks at the alert-name level (one doc per unique alert name), so you can see
frequency, source, and classifier decision across all incoming ticket types.
"""
from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)

_SOURCE_LABELS = {
    "mde":          "MDE Endpoint",
    "sentinel":     "Sentinel",
    "netskope":     "Netskope",
    "aws_guardduty":"AWS GuardDuty",
    "entra_pim":    "Entra PIM",
    "unknown":      "Unknown",
}


def _col():
    from lib.mongo import get_col
    col = get_col("edr_triage_observations")
    col.create_index("alert_name_key", unique=True)
    col.create_index("source")
    col.create_index("last_seen")
    col.create_index("reviewed")
    return col


def _name_key(alert_name: str) -> str:
    """Normalised key for dedup — lowercase, strip punctuation."""
    import re
    return re.sub(r"[^a-z0-9 ]", "", (alert_name or "").lower()).strip()


def detect_source(description: str, alert_name: str) -> str:
    """Infer ticket source from description + alert name."""
    import re
    if re.search(r'security\.microsoft\.com/alerts/', description or ""):
        return "mde"
    if re.search(r'Microsoft\.SecurityInsights/Incidents/', description or ""):
        return "sentinel"
    name = (alert_name or "").lower()
    if any(k in name for k in ("netskope", " dlp", "dlp ")):
        return "netskope"
    if any(k in name for k in ("ec2 instance", "guardduty", "assumedrole", "aws credential",
                                "monitor aws", "drive-by so")):
        return "aws_guardduty"
    if any(k in name for k in ("pim", "privileged role", "entra id")):
        return "entra_pim"
    return "unknown"


def record_observation(
    jira_key: str,
    alert_name: str,
    source: str,
    classifier_decision: str,
    description: str = "",
) -> None:
    """Upsert an observation record for this alert name. Called for every ticket seen."""
    try:
        key = _name_key(alert_name)
        if not key:
            return
        col = _col()
        col.update_one(
            {"alert_name_key": key},
            {
                "$set": {
                    "alert_name":           alert_name,
                    "source":               source,
                    "source_label":         _SOURCE_LABELS.get(source, source),
                    "classifier_decision":  classifier_decision,
                    "last_seen":            time.time(),
                    "last_jira_key":        jira_key,
                },
                "$setOnInsert": {
                    "alert_name_key": key,
                    "first_seen":     time.time(),
                    "reviewed":       False,
                    "review_action":  None,
                    "review_note":    None,
                },
                "$inc": {"count": 1},   # creates `count`=1 on insert (never in $setOnInsert — conflict)
            },
            upsert=True,
        )
    except Exception as exc:
        logger.warning("Failed to record observation for %s: %s", alert_name, exc)


def get_observations(
    limit: int = 50,
    offset: int = 0,
    source: str = "",
    reviewed: str = "",   # "yes" | "no" | ""
) -> dict:
    query: dict = {}
    if source:
        query["source"] = source
    if reviewed == "yes":
        query["reviewed"] = True
    elif reviewed == "no":
        query["reviewed"] = False
    try:
        col = _col()
        total = col.count_documents(query)
        docs = list(col.find(query).sort("last_seen", -1).skip(offset).limit(limit))
        for d in docs:
            d.pop("_id", None)
        return {"observations": docs, "total": total}
    except Exception as exc:
        logger.warning("Failed to get observations: %s", exc)
        return {"observations": [], "total": 0}


def get_observation_stats() -> dict:
    try:
        col = _col()
        total = col.count_documents({})
        unreviewed = col.count_documents({"reviewed": False, "classifier_decision": {"$in": ["skip", "generic"]}})
        pipeline = [{"$group": {"_id": "$source", "count": {"$sum": 1}, "tickets": {"$sum": "$count"}}}]
        by_source = {}
        for row in col.aggregate(pipeline):
            by_source[row["_id"]] = {"types": row["count"], "tickets": row["tickets"]}
        decision_pipeline = [{"$group": {"_id": "$classifier_decision", "count": {"$sum": "$count"}}}]
        by_decision = {}
        for row in col.aggregate(decision_pipeline):
            by_decision[row["_id"] or "unknown"] = row["count"]
        return {
            "total_types": total,
            "unreviewed":  unreviewed,
            "by_source":   by_source,
            "by_decision": by_decision,
        }
    except Exception as exc:
        logger.warning("Failed to get observation stats: %s", exc)
        return {"total_types": 0, "unreviewed": 0, "by_source": {}, "by_decision": {}}


def mark_reviewed(alert_name_key: str, review_action: str, review_note: str = "") -> bool:
    try:
        _col().update_one(
            {"alert_name_key": alert_name_key},
            {"$set": {"reviewed": True, "review_action": review_action, "review_note": review_note}},
        )
        return True
    except Exception as exc:
        logger.warning("Failed to mark reviewed: %s", exc)
        return False
