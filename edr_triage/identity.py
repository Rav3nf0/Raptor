"""IdentityInfo resolution + reachability, for the deterministic user-chase (Phase 1).

Scope note (2026-09-16): built to unblock exactly one family — `Netskope - Suspicious
Bulk Download Detection` — which is RAPTOR's highest-RATE REQUEST_JUSTIFICATION family
(19 of 27 tickets in 90 days) and the one where the human-driven chase is demonstrably
not happening: of 27 tickets, only 2 ever got `Notification dispatched`, 1 acked, 0
justified. The gap is not that L1 disagrees with RAPTOR — it is that nobody asks.

Kept deliberately general (`resolve_identity` / `reachability` / `eligible_recipients`
take a bare account name, nothing Netskope-specific) so a second family can opt in later
by calling the same functions — see the (currently parked) plan at
`.claude/plans/ok-so-we-need-idempotent-sundae.md`.

The Acme Security Bot Logic App is NOT modified by anything here (constraint decided
2026-09-09) — this module only resolves who to name and whether the bot's own channel
(Slack) can reach them; the trigger sequence lives in edr_triage/jira_handler.py and its
gating in edr_triage/pipeline.py.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from edr_triage.config import EDRTriageConfig, get_edr_config

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 24 * 3600   # IdentityInfo is a daily Entra sync; re-querying per
                                 # alert is waste, not freshness.


def _cache_col():
    from lib.mongo import get_col
    col = get_col("edr_identity_cache")
    col.create_index("key")
    return col


def _cache_get(key: str) -> tuple[bool, Optional[dict]]:
    """(found, identity). found=False means "query Sentinel"; found=True with
    identity=None means a cached NEGATIVE result — do not re-query, and treat as
    unresolved. Collapsing "not cached" and "cached miss" into one None, as an earlier
    version of this function did, made a cached negative indistinguishable from an
    expired/absent entry and forced a second read to tell them apart."""
    try:
        doc = _cache_col().find_one({"key": key})
    except Exception as exc:
        logger.warning("identity cache read failed for %r: %s", key, exc)
        return False, None
    if not doc:
        return False, None
    if time.time() - doc.get("cached_at", 0) > _CACHE_TTL_SECONDS:
        return False, None
    return True, doc.get("identity")


def _cache_put(key: str, identity: Optional[dict]) -> None:
    try:
        _cache_col().update_one(
            {"key": key},
            {"$set": {"key": key, "identity": identity, "cached_at": time.time()}},
            upsert=True,
        )
    except Exception as exc:
        logger.warning("identity cache write failed for %r: %s", key, exc)


def _strip_domain_prefix(name: str) -> str:
    """'DOMAIN\\user' -> 'user'. IdentityInfo rows are never stored with the prefix."""
    return name.split("\\", 1)[1] if "\\" in name else name


def _escape_kql_literal(s: str) -> str:
    return s.replace("'", "''")


async def resolve_identity(account_name: str, cfg: Optional[EDRTriageConfig] = None) -> Optional[dict]:
    """Resolve a bare account name / UPN / email against Sentinel's IdentityInfo table.

    Returns the latest row as a dict (AccountName, AccountUPN, MailAddress,
    AccountDisplayName, Manager, Department, JobTitle, IsAccountEnabled, UserType,
    GroupMembership), or None if nothing matches. GroupMembership is what
    `reachability()` below reads — it must stay in the projection.

    Uses `lib.mde_client.run_sentinel_query`, not `sentinel_client._run_la_query`: the
    latter needs workspace parts parsed out of an incident URL, which a bare username
    does not carry.
    """
    key = (account_name or "").strip().casefold()
    if not key:
        return None
    key = _strip_domain_prefix(key)
    found, cached = _cache_get(key)
    if found:
        return cached

    from lib.mde_client import run_sentinel_query

    lit = _escape_kql_literal(key)
    kql = (
        "IdentityInfo\n"
        f"| where tolower(AccountName) == '{lit}' or tolower(AccountUPN) == '{lit}' "
        f"or tolower(MailAddress) == '{lit}'\n"
        "| summarize arg_max(TimeGenerated, *) by AccountName\n"
        "| project AccountName, AccountUPN, MailAddress, AccountDisplayName, Manager,\n"
        "    Department, JobTitle, IsAccountEnabled, UserType, GroupMembership\n"
        "| take 1"
    )
    rows, err = await run_sentinel_query(kql)
    if err:
        logger.warning("resolve_identity(%r) query failed: %s", account_name, err)
        return None   # fail closed — caller must not treat a query error as "resolved"
    identity = rows[0] if rows else None
    _cache_put(key, identity)
    return identity


def reachability(identity: Optional[dict], cfg: Optional[EDRTriageConfig] = None) -> tuple[str, str]:
    """(status, reason). status is "reachable" | "unreachable".

    The predicate is `slack-acme` GROUP MEMBERSHIP, not an OU or a `v-` prefix —
    verified 2026-09-09 against real dispatch history: `v-` ranges from 0.1% to 64%
    membership depending on OU, and the one production case where a `v-` account (BPO,
    OU=Eos) was dispatched to and never replied (DEMO-107682) is exactly the case this
    predicate flags. Fails closed: no identity, no GroupMembership field, or the group
    absent are all "unreachable".
    """
    cfg = cfg or get_edr_config()
    group = (cfg.slack_group or "slack-acme").strip().casefold()
    if identity is None:
        return "unreachable", "not found in IdentityInfo"
    if not identity.get("IsAccountEnabled"):
        return "unreachable", "account is disabled"
    if (identity.get("UserType") or "").strip().casefold() != "member":
        return "unreachable", f"UserType={identity.get('UserType')!r}, not Member"
    groups = identity.get("GroupMembership") or []
    if isinstance(groups, str):
        # KQL can return a dynamic column as a JSON string depending on projection.
        import json
        try:
            groups = json.loads(groups)
        except Exception:
            groups = [groups]
    membership = {str(g).strip().casefold() for g in groups}
    if group in membership:
        return "reachable", ""
    return "unreachable", f"not in {cfg.slack_group!r}"


async def eligible_recipients(
    users: list[str], cfg: Optional[EDRTriageConfig] = None,
) -> tuple[list[dict], list[str]]:
    """Resolve + gate a list of raw usernames. Returns (eligible, rejected_with_reason).

    Each eligible entry: {"raw", "email", "display_name", "identity"}. Never synthesises
    an address by appending a domain — an unresolved name is rejected, not guessed at.
    """
    from entity_graph.query import _is_generic_account

    cfg = cfg or get_edr_config()
    eligible: list[dict] = []
    rejected: list[str] = []
    for raw in users:
        raw = (raw or "").strip()
        if not raw:
            continue
        if _is_generic_account(raw):
            rejected.append(f"{raw} — service/generic account")
            continue
        identity = await resolve_identity(raw, cfg)
        if identity is None:
            rejected.append(f"{raw} — not found in IdentityInfo")
            continue
        email = identity.get("MailAddress") or identity.get("AccountUPN") or ""
        if not email:
            rejected.append(f"{raw} — no email/UPN on record")
            continue
        status, reason = reachability(identity, cfg)
        if status != "reachable":
            rejected.append(f"{raw} — {reason}")
            continue
        eligible.append({
            "raw": raw,
            "email": email,
            "display_name": identity.get("AccountDisplayName") or raw,
            "identity": identity,
        })
    return eligible, rejected
