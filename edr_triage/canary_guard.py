"""Canary token was accessed: say WHICH tripwire fired and whether one of ours walked into it.

A canary has no legitimate use, so a hit is never closed by RAPTOR. What L2 needs is what the
alert means, and that depends on the token TYPE, which the generic rule-replay path never
said. On DEMO-121175 (2026-11-08) the agent took the "Phishing_EntraID login" token — a
cloned-site token: our Microsoft sign-in branding rendered on a non-Microsoft domain, i.e. a
phishing kit — for a document canary, reasoned about an unrelated busy SharePoint
spreadsheet, called the hit "authorized access" and recommended a False Positive close. Only
an unrelated hunt error blocked the close.

The source IP of a cloned-site hit is the BROWSER that viewed the phishing page. So the check
that matters is whether that browser was one of ours: an IP our users signed in from in the
week before the hit. If it was, those users may have typed their password into the kit, and
any successful sign-in for them from an IP they had not used in the prior 14 days, in the 24
hours after the hit, is listed for L2. No match means the visitors were outsiders (scanners,
the phisher testing, other targets) — still a live kit on our branding, never benign.

check() fails closed: a query that cannot run is reported as such, never as "no match".
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

LABEL = "raptor-canary"
TABLE = "CanaryTokens_CL"
_NAME_RE = re.compile(r"canary\s*token", re.IGNORECASE)

# canarytokens.org token_type -> what a hit means. Unknown types fall back to _DEFAULT.
TOKEN_MEANING = {
    "cssclonedsite": "a cloned-site token: our Microsoft sign-in page branding was displayed "
                     "on a domain that is not Microsoft's — someone is running a phishing "
                     "(likely adversary-in-the-middle) page built on our login. The source IP "
                     "is the browser that VIEWED that page",
    "clonedsite": "a cloned-site token: a copy of one of our web pages was loaded on a domain "
                  "that is not ours — a phishing page built on our site. The source IP is the "
                  "browser that viewed it",
    "idp_app": "a fake app tile in our identity-provider portal was opened — someone with "
               "access to our app portal clicked an app that exists only as a tripwire",
    "ms_word": "a decoy Word document was opened; the source IP is where it was opened",
    "ms_excel": "a decoy Excel document was opened; the source IP is where it was opened",
    "adobe_pdf": "a decoy PDF was opened; the source IP is where it was opened",
    "aws_keys": "decoy AWS keys were used — whoever used them has a copy of the place they "
                "were planted",
    "dns": "a decoy hostname was resolved — something read the place it was planted",
    "web": "a decoy URL was fetched — something read the place it was planted",
}
_DEFAULT = "a canary token fired — a tripwire that nothing legitimate should touch"
_PHISH_TYPES = {"cssclonedsite", "clonedsite"}

# Query-string values that are credentials: canarytokens.org manage/history/download links
# carry `auth=` — whoever holds one can disable the token. Never into Jira or a prompt.
_URL_SECRET_RE = re.compile(r"([?&](?:auth|token|key|sig|signature|code)=)[^&\s\"'<>]+",
                            re.IGNORECASE)


def applies(alert_name: str) -> bool:
    return bool(_NAME_RE.search(alert_name or ""))


def redact_url_secrets(s: str) -> str:
    return _URL_SECRET_RE.sub(r"\1[redacted]", s or "")


def meaning(token_type: str) -> str:
    return TOKEN_MEANING.get((token_type or "").strip().lower(), _DEFAULT)


def _kq(s: str) -> str:
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parse(ts: str):
    try:
        t = datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00").replace(" ", "T"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


async def _query(kql: str) -> list[dict] | None:
    try:
        from lib.mde_client import run_sentinel_query
        rows, err = await run_sentinel_query(kql, autofix=False)
        if err:
            logger.warning("canary_guard: query failed: %s", str(err)[:200])
            return None
        return rows or []
    except Exception as exc:
        logger.warning("canary_guard: query failed: %s", exc)
        return None


_cache: dict[str, dict] = {}


async def check(anchor: str) -> dict:
    """What fired and whether an Acme browser was the visitor. Cached per anchor: the
    playbook comment and the agent prefetch both ask for the same alert."""
    if anchor in _cache:
        return _cache[anchor]
    out = await _check(anchor)
    if len(_cache) > 200:
        _cache.clear()
    _cache[anchor] = out
    return out


async def _check(anchor: str) -> dict:
    t = _parse(anchor)
    if not t:
        return {"ok": False, "error": "no alert time to anchor the check"}
    a = t.strftime("%Y-%m-%dT%H:%M:%SZ")
    hits = await _query(f"""{TABLE}
| where TimeGenerated between (datetime({a}) - 3h .. datetime({a}) + 15m)
| extend d = abs(datetime_diff('second', TimeGenerated, datetime({a})))
| top 1 by d asc
| project TimeGenerated, memo_s, token_type_s, src_ip_s, org_s, city_s, country_s, useragent_s""")
    if hits is None:
        return {"ok": False, "error": f"{TABLE} could not be read"}
    if not hits:
        return {"ok": False, "error": f"no {TABLE} hit within 3h before the alert"}
    h = hits[0]
    memo, ttype = str(h.get("memo_s") or ""), str(h.get("token_type_s") or "")
    out = {"ok": True, "memo": memo, "token_type": ttype, "meaning": meaning(ttype),
           "phishing": ttype.lower() in _PHISH_TYPES,
           "hit": {k: str(h.get(k) or "") for k in
                   ("TimeGenerated", "src_ip_s", "org_s", "city_s", "country_s", "useragent_s")}}

    recent = await _query(f"""{TABLE}
| where TimeGenerated between (datetime({a}) - 7d .. datetime({a}) + 15m)
| where memo_s == {_kq(memo)} and token_type_s == {_kq(ttype)}
| summarize hits = count(), first_hit = min(TimeGenerated), last_hit = max(TimeGenerated),
            ips = make_set(src_ip_s, 50), orgs = make_set(org_s, 8)""")
    if recent is None or not recent:
        out.update(ok=False, error="the token's 7-day history could not be read")
        return out
    r = recent[0]
    ips = [str(x) for x in (r.get("ips") or []) if x]
    if isinstance(r.get("ips"), str):
        import json
        ips = [str(x) for x in json.loads(r["ips"]) if x]
    out["recent"] = {"hits": int(r.get("hits") or 0), "first": str(r.get("first_hit") or ""),
                     "last": str(r.get("last_hit") or ""), "ips": ips[:50],
                     "orgs": r.get("orgs") if isinstance(r.get("orgs"), list) else str(r.get("orgs") or "")}
    if not ips:
        out["ours"] = []
        return out

    # Was any visitor one of ours? An IP our users signed in from in the week before.
    ip_list = ", ".join(_kq(i) for i in ips[:50])
    ours = await _query(f"""union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime({a}) - 7d .. datetime({a}) + 1h)
| where IPAddress in ({ip_list})
| summarize users = make_set(UserPrincipalName, 10) by IPAddress""")
    if ours is None:
        out.update(ok=False, error="sign-in logs could not be read for the visitor IPs")
        return out
    matched = []
    for row in ours:
        us = row.get("users")
        if isinstance(us, str):
            import json
            us = json.loads(us)
        matched.append({"ip": str(row.get("IPAddress") or ""), "users": [str(u) for u in us or []]})
    out["ours"] = matched
    users = sorted({u for m in matched for u in m["users"]})
    if not users:
        return out

    # Those users: successful sign-ins in the 24h after the first hit from an IP they had not
    # used in the 14 days before it — where a phished password or session would show up.
    first = _parse(out["recent"]["first"]) or t
    f = first.strftime("%Y-%m-%dT%H:%M:%SZ")
    ul = ", ".join(_kq(u) for u in users[:10])
    new = await _query(f"""let known = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (datetime({f}) - 14d .. datetime({f}))
    | where UserPrincipalName in ({ul}) | distinct UserPrincipalName, IPAddress;
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime({f}) .. datetime({f}) + 24h)
| where UserPrincipalName in ({ul}) and tostring(ResultType) == "0"
| join kind=leftanti known on UserPrincipalName, IPAddress
| summarize n = count(), first_seen = min(TimeGenerated), apps = make_set(AppDisplayName, 4)
    by UserPrincipalName, IPAddress, AutonomousSystemNumber""")
    if new is None:
        out.update(ok=False, error="follow-up sign-ins could not be read for the matched users")
        return out
    out["new_ip_success"] = [{"user": str(x.get("UserPrincipalName") or ""),
                              "ip": str(x.get("IPAddress") or ""),
                              "asn": str(x.get("AutonomousSystemNumber") or ""),
                              "first": str(x.get("first_seen") or ""), "n": int(x.get("n") or 0)}
                             for x in new]
    return out


def _hit_line(chk: dict) -> str:
    h = chk.get("hit") or {}
    where = ", ".join(x for x in (h.get("city_s"), h.get("country_s")) if x)
    return (f"{h.get('src_ip_s') or '?'} ({h.get('org_s') or 'unknown network'}"
            + (f", {where}" if where else "") + ")"
            + (f", user agent {h['useragent_s'][:110]}" if h.get("useragent_s") else ""))


def summary_lines(chk: dict) -> list[str]:
    """The canary facts, for the L1 comment and the agent prompt alike."""
    if not chk or not chk.get("memo"):
        return ["Canary check could not run" + (f" ({chk.get('error')})" if chk and chk.get("error") else "")
                + " — which token fired and who triggered it are UNKNOWN; treat as unexplained."]
    lines = [f"Token: '{chk['memo']}' (type {chk.get('token_type') or '?'}) — {chk['meaning']}.",
             f"This hit: {_hit_line(chk)}."]
    rec = chk.get("recent") or {}
    if rec:
        lines.append(f"Same token, last 7 days: {rec.get('hits', 0)} hit(s) from "
                     f"{len(rec.get('ips') or [])} IP(s), first {rec.get('first', '')[:16]} UTC.")
    if not chk.get("ok"):
        lines.append(f"Check incomplete: {chk.get('error')} — do not read the missing part as clean.")
        return lines
    ours = chk.get("ours") or []
    if ours:
        lines.append("A VISITOR WAS ONE OF OURS: " + "; ".join(
            f"{m['ip']} — signed in from by {', '.join(m['users'][:5])}" for m in ours[:5]) + ".")
        news = chk.get("new_ip_success") or []
        if news:
            lines.append("Successful sign-ins for those users from an IP new to them, within 24h: " + "; ".join(
                f"{x['user']} from {x['ip']} (AS{x['asn']}) at {x['first'][:16]}" for x in news[:6])
                + " — possible stolen credentials or session.")
        else:
            lines.append("No successful sign-in for those users from a new IP in the 24h after the first hit.")
    else:
        lines.append("No visitor IP was used by any Acme account in the week before: the "
                     "visitors were outsiders (scanners, the operator testing, or other targets).")
    return lines


def l1_comment_lines(chk: dict) -> list[str]:
    lines = ["*Canary check:*"] + [f"  • {x}" for x in summary_lines(chk)]
    if chk and chk.get("phishing"):
        lines += ["", "Recommendation: TRUE POSITIVE — phishing infrastructure is using our "
                  "login branding. L2: get the cloned page's domain from the token's history "
                  "on canarytokens.org, block it in Netskope and request a takedown"
                  + ("; contact the matched users and revoke their sessions if a new-IP "
                     "sign-in is listed above" if chk.get("ours") else "") + "."]
    else:
        lines += ["", "Recommendation: a canary has no legitimate use — L2 should establish who "
                  "triggered it before any close. RAPTOR never closes a canary alert."]
    return lines


def prompt_lines(chk: dict) -> list[str]:
    return (["\nCanary check (KEY EVIDENCE — bound from CanaryTokens_CL and the Entra sign-in "
             "logs, do NOT re-query them):"]
            + [f"  {x}" for x in summary_lines(chk)]
            + ["  How to judge: a canary token is a tripwire with no legitimate use, so a hit is "
               "never 'expected access' and never a False Positive. Judge it by the TOKEN TYPE "
               "above, not by unrelated file or mailbox activity: a cloned-site hit means a "
               "phishing page is serving our login, and the source IP is whoever VIEWED it. "
               "What matters is whether that viewer was one of ours and whether their account "
               "then signed in from somewhere new. Escalate to L2 either way."])


def close_block_reason(alert_name: str) -> str:
    """Non-empty for every canary alert: RAPTOR never closes one."""
    if not applies(alert_name):
        return ""
    return ("Auto-close blocked: canary token alert — a tripwire has no legitimate use; "
            "a person must establish who triggered it")
