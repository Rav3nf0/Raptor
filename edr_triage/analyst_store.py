"""Analyst role registry — maps Jira commenter email to L1/L2 role.

Used by the closure poller to attribute comments and by the memory system
to tag memories with who said what. Managed via /memory/quarantine Analysts tab.

Collection: edr_analyst_roles
Doc shape:  { email, display_name, role: "L1"|"L2", active: bool }
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_col_cache = None


def _col():
    global _col_cache
    if _col_cache is not None:
        return _col_cache
    from lib.mongo import get_col
    col = get_col("edr_analyst_roles")
    col.create_index("email", unique=True)
    _col_cache = col
    return _col_cache


def get_analyst_role(email: str) -> str:
    """Return "L1", "L2", or "user" (unknown / business stakeholder)."""
    if not email:
        return "user"
    try:
        doc = _col().find_one({"email": email.lower(), "active": True}, {"role": 1})
        if doc:
            return doc.get("role", "user")
    except Exception as exc:
        logger.warning("analyst_store.get_analyst_role failed: %s", exc)
    return "user"


def upsert_analyst(email: str, display_name: str, role: str) -> None:
    """Add or update an analyst. role must be 'L1' or 'L2'."""
    if role not in ("L1", "L2"):
        raise ValueError(f"Invalid role '{role}': must be L1 or L2")
    _col().update_one(
        {"email": email.lower()},
        {"$set": {"email": email.lower(), "display_name": display_name, "role": role, "active": True}},
        upsert=True,
    )


def remove_analyst(email: str) -> None:
    """Deactivate an analyst (soft delete)."""
    _col().update_one({"email": email.lower()}, {"$set": {"active": False}})


def list_analysts() -> list[dict]:
    """Return all active analysts sorted by role then email."""
    try:
        docs = list(_col().find({"active": True}, {"_id": 0}).sort([("role", 1), ("email", 1)]))
        return docs
    except Exception as exc:
        logger.warning("analyst_store.list_analysts failed: %s", exc)
        return []
