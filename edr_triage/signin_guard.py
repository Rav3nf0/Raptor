"""Never auto-close a sign-in failure spike when a success FOLLOWS invalid-password failures.

"Privileged Accounts - Sign in Failure Spikes" is benign almost every time — the dominant
cause here is ResultType 70044, Conditional Access sign-in-frequency expiry (DEMO-107545:
608 of them) — and that is why it scores 10/10. Its dangerous twin is the same alert
produced by a password spray that got in: wrong-password failures, then a success. A
model can see that shape, but nothing forced it away from a close. This does.

Enforced at the pipeline's single auto-close gate, so it covers every route to a close:
an agent verdict, an actor-allowlist match (no LLM involved), a playbook fallback.

FAILS CLOSED. If the check cannot run — no account to check, Sentinel unreachable, a
query error — the answer is "not safe to close", never "no success found". The only
cost of failing closed is that a ticket goes to L2, which is what happened before this
family was autonomous at all.

Measured before shipping, replaying 22 tickets of this family at triage time: it would
have blocked 4, all later closed FP by humans (1-5 mistyped passwords, then normal
logins) — 3 of them FP recommendations, so roughly 3 in 10 of this family's closes route
to L2 instead. No real spray appears in the window, so none of the 4 was a rescue.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def check(users: list[str], anchor_iso: str = "") -> dict:
    """Run the spray check for these accounts. Never raises.

    Returns {"ok": True, "rows": [...], "blocking": [upn, ...]} or
    {"ok": False, "error": "..."}. `blocking` lists accounts with a success after their
    first invalid-password failure.
    """
    accts = [u for u in dict.fromkeys((u or "").strip() for u in (users or [])) if u]
    if not accts:
        return {"ok": False, "error": "no account on the alert to check"}
    try:
        from lib.kql_templates import sentinel_signin_spray_check
        from lib.mde_client import run_sentinel_query
        rows, err = await run_sentinel_query(sentinel_signin_spray_check(accts, anchor_iso))
    except Exception as exc:
        logger.warning("signin_guard: check failed for %s: %s", accts, exc)
        return {"ok": False, "error": str(exc)[:200]}
    if err:
        return {"ok": False, "error": str(err)[:200]}
    rows = rows or []
    blocking = [str(r.get("UserPrincipalName") or "?") for r in rows
                if int(r.get("SuccessAfterBadPw") or 0) > 0]
    return {"ok": True, "rows": rows, "blocking": blocking, "accounts": accts}


def _as_list(v) -> list:
    """Log Analytics returns a dynamic column (make_set) as a JSON STRING, not a list —
    slicing it directly yields characters ("[", "\"", "1", ...). Found on the first live
    run; accept either shape."""
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v.strip():
        import json
        try:
            out = json.loads(v)
            return out if isinstance(out, list) else [out]
        except ValueError:
            return [v]
    return []


def no_failures_found(result: dict | None) -> bool:
    """True when the check ran and found NO failed sign-in for any account on the alert.

    The alert is a failure SPIKE; if the failures cannot be found in either sign-in table,
    what fired it is unaccounted for and a close would rest on absence of evidence
    (DEMO-115064). Rows from before `Failures` existed carry no count — read as zero, so an
    unknown fails closed like everything else here.
    """
    if not result or not result.get("ok"):
        return False
    return not any(int(r.get("Failures") or 0) > 0 for r in (result.get("rows") or []))


# Wrong-password/lockout failures (50126, 50053) at or above this are someone hammering the
# account, success or not. DEMO-117459 closed theo.malik's spike with 89 x 50126 and
# 124 x 50053 lockouts, the model calling them "token expiry"; the next day DEMO-117523 saw
# wrong passwords then a success from a new IP. The benign shape this family closes on is
# 1-5 mistypes (measured at shipping), or session expiries, which are not counted here.
MANY_BAD_PW = 10


def blocks_close(result: dict | None) -> tuple[bool, str]:
    """(block, reason). Anything other than a clean, successful check blocks."""
    if not result:
        return True, "sign-in spray check did not run"
    if not result.get("ok"):
        return True, f"sign-in spray check unavailable ({result.get('error') or 'unknown'})"
    if result.get("blocking"):
        detail = []
        for r in result.get("rows") or []:
            if str(r.get("UserPrincipalName")) in result["blocking"]:
                ips = _as_list(r.get("SuccessIPs"))
                detail.append(f"{r.get('UserPrincipalName')}: {r.get('BadPw')} invalid-password "
                              f"failure(s), then {r.get('SuccessAfterBadPw')} successful sign-in(s)"
                              + (f" from {', '.join(map(str, ips[:5]))}" if ips else ""))
        return True, "a successful sign-in followed invalid-password failures — " + "; ".join(detail)
    hammered = [r for r in result.get("rows") or [] if int(r.get("BadPw") or 0) >= MANY_BAD_PW]
    if hammered:
        return True, ("repeated wrong-password or lockout failures — "
                      + "; ".join(f"{r.get('UserPrincipalName')}: {r.get('BadPw')} invalid-password/"
                                  "locked-out failure(s)" for r in hammered[:5]))
    if no_failures_found(result):
        accts = ", ".join(result.get("accounts") or []) or "the alert's account(s)"
        return True, (f"no failed sign-in could be found for {accts} in SigninLogs or "
                      "AADNonInteractiveUserSignInLogs, so the failures this alert reports "
                      "are unaccounted for")
    return False, ""


BLOCK_LABELS = ("needs-l2-review", "signin-spray-guard")


async def enforce_at_close(alert_name: str, labels: list, spray_check: dict | None,
                           users: list[str], anchor_iso: str, jira_key: str, cfg,
                           dry_run: bool = False) -> tuple[bool, str, dict | None]:
    """The close-gate step, as one unit so it can be tested by RUNNING it.

    Called by the pipeline only after may_autoclose() has already said yes. Returns
    (block, reason, spray_check): `spray_check` is handed back so the pipeline keeps the
    result it now holds. For a family the guard does not cover, it returns immediately
    without querying anything.

    `spray_check is None` means the agent prefetch never ran — the actor-allowlist
    short-circuit and the playbook fallback both skip it — so the check is run here.
    Without that, an allowlist entry would bypass the guard entirely.

    On a block it mutates `labels` in place (the pipeline writes them to Jira after the
    gate) and posts the explanatory comment.
    """
    from edr_triage.classifier import signin_spray_guard_applies
    if not signin_spray_guard_applies(alert_name):
        return False, "", spray_check
    if spray_check is None:
        spray_check = await check(users, anchor_iso)
    block, why = blocks_close(spray_check)
    if not block:
        return False, "", spray_check
    for lab in BLOCK_LABELS:
        if lab not in labels:
            labels.append(lab)
    from edr_triage.jira_handler import add_comment
    if why.startswith("repeated wrong-password"):
        _explain = ("This many wrong passwords or lockouts on a privileged account is someone "
                    "guessing at it, whether or not they got in. Please find where the attempts "
                    "came from and confirm with the account owner.")
    elif no_failures_found(spray_check):
        _explain = ("RAPTOR searched both interactive and non-interactive sign-ins and "
                    "found no failure to explain the spike, so it cannot say what fired "
                    "this alert. Please check the incident's own evidence for the failing "
                    "account and sign-ins.")
    else:
        _explain = ("A sign-in failure spike is usually benign, but when a successful "
                    "sign-in comes AFTER wrong-password failures it has the shape of a "
                    "password spray that got in, so it needs a human. Please confirm the "
                    "successful sign-in(s) were the account owner.")
    try:
        await add_comment(jira_key, (
            "*RAPTOR did not auto-close this ticket.*\n\n"
            f"Reason: {why}.\n\n"
            f"{_explain}\n\n[Auto-triaged by RAPTOR]"), cfg, dry_run=dry_run)
    except Exception as exc:
        # The block stands even if the comment fails — the comment explains the
        # decision, it is not what enforces it.
        logger.error("signin_guard: comment on %s failed: %s", jira_key, exc)
    return True, why, spray_check
