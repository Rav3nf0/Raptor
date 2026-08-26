"""User-defined triage rules — stored in MongoDB, checked by classifier before hardcoded patterns.

Rules are simple: if alert_name matches pattern → route to this playbook/action.
Pattern matching: substring (default) or regex.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Optional

logger = logging.getLogger(__name__)

_VALID_PLAYBOOKS = {
    "skip", "block_tool", "malware", "reverse_shell", "lateral_move",
    "credential_access", "privesc", "generic", "no_threat",
}

# In-memory cache — reloaded when TTL expires or after a write
_rules_cache: list[dict] = []
_cache_at: float = 0.0
_CACHE_TTL = 60.0  # seconds


def _col():
    from lib.mongo import get_col
    col = get_col("edr_triage_rules")
    col.create_index("created_at")
    col.create_index("active")
    return col


def _load_rules() -> list[dict]:
    global _rules_cache, _cache_at
    now = time.time()
    if _rules_cache and now - _cache_at < _CACHE_TTL:
        return _rules_cache
    try:
        docs = list(_col().find({"active": True}).sort("created_at", 1))
        for d in docs:
            d["_id"] = str(d["_id"])
        _rules_cache = docs
        _cache_at = now
        return docs
    except Exception as exc:
        logger.warning("Failed to load triage rules: %s", exc)
        return _rules_cache  # return stale cache on error


def _invalidate_cache() -> None:
    global _cache_at
    _cache_at = 0.0


def classify_by_rules(alert_name: str) -> Optional[str]:
    """Return playbook name if any user rule matches, else None."""
    rules = _load_rules()
    name = (alert_name or "").strip()
    for rule in rules:
        pattern = rule.get("pattern", "")
        match_type = rule.get("match_type", "contains")
        try:
            if match_type == "regex":
                if re.search(pattern, name, re.IGNORECASE):
                    return rule.get("playbook", "generic")
            else:  # contains (case-insensitive substring)
                if pattern.lower() in name.lower():
                    return rule.get("playbook", "generic")
        except re.error:
            continue
    return None


def get_rules() -> list[dict]:
    try:
        docs = list(_col().find({}).sort("created_at", -1))
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
    except Exception as exc:
        logger.warning("Failed to get rules: %s", exc)
        return []


def create_rule(
    pattern: str,
    playbook: str,
    match_type: str = "contains",
    example_alert: str = "",
    note: str = "",
) -> Optional[dict]:
    if playbook not in _VALID_PLAYBOOKS:
        raise ValueError(f"Invalid playbook '{playbook}'. Valid: {sorted(_VALID_PLAYBOOKS)}")
    if match_type not in ("contains", "regex"):
        raise ValueError("match_type must be 'contains' or 'regex'")
    if match_type == "regex":
        re.compile(pattern)  # validate — raises re.error if invalid
    doc = {
        "pattern":       pattern,
        "match_type":    match_type,
        "playbook":      playbook,
        "example_alert": example_alert,
        "note":          note,
        "active":        True,
        "created_at":    time.time(),
    }
    try:
        result = _col().insert_one(doc)
        doc["_id"] = str(result.inserted_id)
        _invalidate_cache()
        return doc
    except Exception as exc:
        logger.warning("Failed to create rule: %s", exc)
        return None


def delete_rule(rule_id: str) -> bool:
    try:
        from bson import ObjectId
        result = _col().delete_one({"_id": ObjectId(rule_id)})
        _invalidate_cache()
        return result.deleted_count > 0
    except Exception as exc:
        logger.warning("Failed to delete rule %s: %s", rule_id, exc)
        return False


def toggle_rule(rule_id: str, active: bool) -> bool:
    try:
        from bson import ObjectId
        result = _col().update_one({"_id": ObjectId(rule_id)}, {"$set": {"active": active}})
        _invalidate_cache()
        return result.modified_count > 0
    except Exception as exc:
        logger.warning("Failed to toggle rule %s: %s", rule_id, exc)
        return False
