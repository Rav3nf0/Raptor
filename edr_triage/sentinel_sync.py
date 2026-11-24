"""Close the Sentinel incident once its SIM tickets are decided — the step L1 does by hand.

L1 closes the Sentinel incident behind almost every SIM ticket (1,456 of 1,630 in the 30
days to 2026-10-13) and classifies it from the Jira outcome, pasting the SIM link as the
comment. RAPTOR never did: 124 of the 267 tickets it closed, and 47 of the 123 it routed
to L2, still had an open incident, and with no L1 every one would stay open.

L1's convention, copied as is (L2 decision 2026-10-13 — "easier, it doesn't matter much"):

  Jira outcome                          Sentinel close
  ever reached L2 Analysis required  →  TruePositive / SuspiciousActivity  ("escalated to L2")
  Closed / Resolved / IR stages      →  TruePositive / SuspiciousActivity
  False Positive                     →  FalsePositive / IncorrectAlertLogic
  Duplicate                          →  whatever the ticket it duplicates got; Undetermined
                                        when that cannot be found

One incident can carry several tickets (grouped alerts: ~300 of 1,630 had 2–6), so the
incident closes only when EVERY ticket naming it is decided, as TruePositive if any of
them is, else FalsePositive if any is, else the duplicates' classification. A ticket still
being worked (Open, Event Analysis, Awaiting more inputs never escalated) holds it open.

Scope: "raptor" (default) syncs incidents behind tickets RAPTOR acted on — the ones L1 no
longer touches. "all" also takes the ones L1 closes today, for when there is no L1.
Mode: off | dry (log what would close) | on (default). Writing needs the Microsoft
Sentinel Responder role for RAPTOR's service principal; without it the first 403 stops the
sweep with one error, nothing half-done.

Never reopens, never changes an incident that is already Closed, never touches Jira.
"""
from __future__ import annotations

import json
import logging
import re

import httpx

from edr_triage.config import get_edr_config

logger = logging.getLogger(__name__)

_RAPTOR_LABELS = ("raptor-autoclosed", "raptor-autoduplicate", "raptor-custom-block",
                  "raptor-routed-l2", "raptor-chased", "ai-fp", "dlp-secret-key",
                  "raptor-actor-allowlist")
_TP_STATUSES = {"closed", "resolved", "in progress", "containment", "eradication",
                "recovery", "rca"}
_L2 = "l2 analysis required"
_INCIDENT_RE = re.compile(r"Incidents/([0-9a-fA-F-]{36})")
_DUP_OF_RE = re.compile(r"Duplicate of (DEMO-\d+)")


def _adf_text(node) -> str:
    if isinstance(node, dict):
        return (node.get("text") or "") + "".join(_adf_text(x) for x in node.get("content") or [])
    if isinstance(node, list):
        return "".join(_adf_text(x) for x in node)
    return node if isinstance(node, str) else ""

TP = ("TruePositive", "SuspiciousActivity")
FP = ("FalsePositive", "IncorrectAlertLogic")
UNDETERMINED = ("Undetermined", "")


def incident_id(description) -> str:
    m = _INCIDENT_RE.search(json.dumps(description or ""))
    return m.group(1).lower() if m else ""


def ticket_outcome(issue: dict) -> str:
    """'tp' | 'fp' | 'dup' | 'open' for one SIM ticket, from its status and changelog."""
    f = issue.get("fields") or {}
    status = ((f.get("status") or {}).get("name") or "").strip().lower()
    hist = (issue.get("changelog") or {}).get("histories") or []
    reached_l2 = status == _L2 or any(
        (it.get("field") == "status" and (it.get("toString") or "").strip().lower() == _L2)
        for h in hist for it in h.get("items") or [])
    if reached_l2 or status in _TP_STATUSES:
        return "tp"
    if status == "false positive":
        return "fp"
    if status == "duplicate":
        return "dup"
    return "open"


def decide(outcomes: dict[str, str], dup_classes: dict[str, tuple] | None = None) -> tuple | None:
    """Classification for an incident from its tickets' outcomes, or None to wait.

    outcomes: {SIM key: tp|fp|dup|open}. dup_classes: {SIM key: classification of the
    ticket it duplicates, or None if that one is not decided yet}."""
    if not outcomes or "open" in outcomes.values():
        return None
    if "tp" in outcomes.values():
        return TP
    if "fp" in outcomes.values():
        return FP
    found = [c for c in (dup_classes or {}).values()]
    if any(c is None for c in found):
        return None                       # an original is still being worked
    if TP in found:
        return TP
    if FP in found:
        return FP
    return UNDETERMINED


def comment(cls: tuple, outcomes: dict[str, str], jira_url: str) -> str:
    links = ", ".join(f"{jira_url.rstrip('/')}/browse/{k}" for k in sorted(outcomes))
    if cls == TP and any(v == "tp" for v in outcomes.values()):
        return f"Closed by RAPTOR: escalated to L2 for further investigation / closed as true positive in Jira: {links}"
    if cls == FP and any(v == "fp" for v in outcomes.values()):
        return f"Closed by RAPTOR: closed as False Positive in Jira: {links}"
    return f"Closed by RAPTOR: duplicate ticket(s) in Jira: {links}"


# Incidents this process has seen Closed (by us or by a person). Never re-checked: a
# closed incident is never reopened here, so the sweep stops costing a Jira search and a
# Sentinel read per incident every 15 minutes.
_SEEN_CLOSED: set[str] = set()


class SentinelWriteForbidden(Exception):
    pass


async def _jira_search(client: httpx.AsyncClient, jql: str, fields: list[str],
                       changelog: bool = True, pages: int = 20) -> list[dict]:
    out: list[dict] = []
    token = None
    for _ in range(pages):
        body: dict = {"jql": jql, "fields": fields, "maxResults": 100}
        if changelog:
            body["expand"] = "changelog"          # a string: an array is a 400 here
        if token:
            body["nextPageToken"] = token
        resp = await client.post("/rest/api/3/search/jql", json=body)
        resp.raise_for_status()
        page = resp.json()
        out.extend(page.get("issues", []))
        token = page.get("nextPageToken")
        if page.get("isLast") or not token:
            break
    return out


async def _dup_original_class(client: httpx.AsyncClient, key: str) -> tuple | None:
    """Classification of the ticket a Duplicate points at (RAPTOR's 'Duplicate of DEMO-X'
    comment), UNDETERMINED when none is named, None while the original is undecided."""
    try:
        resp = await client.get(f"/rest/api/3/issue/{key}/comment", params={"maxResults": 50})
        resp.raise_for_status()
        # Plain text, not the raw ADF: the key is a separate link node after "Duplicate of ".
        text = " ".join(_adf_text(c.get("body")) for c in resp.json().get("comments") or [])
        m = _DUP_OF_RE.search(" ".join(text.split()))
        if not m or m.group(1) == key:
            return UNDETERMINED
        resp = await client.get(f"/rest/api/3/issue/{m.group(1)}",
                                params={"fields": "status", "expand": "changelog"})
        resp.raise_for_status()
        o = ticket_outcome(resp.json())
    except Exception as exc:
        logger.warning("sentinel_sync: duplicate lookup for %s failed: %s", key, exc)
        return None
    return {"tp": TP, "fp": FP, "open": None}.get(o, UNDETERMINED)


def _incident_url(parts_base: str, iid: str, api: str) -> str:
    return f"{parts_base}/providers/Microsoft.SecurityInsights/incidents/{iid}?api-version={api}"


async def close_incident(ws_base: str, iid: str, cls: tuple, text: str, dry_run: bool) -> str:
    """'closed' | 'already-closed' | 'would-close' | 'missing'. Raises SentinelWriteForbidden."""
    from edr_triage.sentinel_client import _API_VERSION, _MGMT_API, _VERIFY_SSL, get_management_token
    token = await get_management_token()
    if not token:
        raise RuntimeError("no management token")
    url = _MGMT_API + _incident_url(ws_base, iid, _API_VERSION)
    hdr = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(verify=_VERIFY_SSL, timeout=30.0) as c:
        r = await c.get(url, headers=hdr)
        if r.status_code == 404:
            return "missing"
        r.raise_for_status()
        inc = r.json()
        props = inc.get("properties") or {}
        if (props.get("status") or "") == "Closed":
            return "already-closed"
        if dry_run:
            return "would-close"
        new = {k: props[k] for k in ("title", "severity", "owner", "labels", "description")
               if props.get(k) is not None}
        new.update({"status": "Closed", "classification": cls[0],
                    "classificationComment": text[:1000]})
        if cls[1]:
            new["classificationReason"] = cls[1]
        body = {"properties": new}
        if inc.get("etag"):
            body["etag"] = inc["etag"]
        r = await c.put(url, headers=hdr, json=body)
        if r.status_code == 403:
            raise SentinelWriteForbidden(r.text[:300])
        r.raise_for_status()
        return "closed"


def _ws_base(sample_description) -> str:
    m = re.search(r"(/subscriptions/[^/\s\"]+/resourceGroups/[^/\s\"]+/providers/"
                  r"Microsoft\.OperationalInsights/workspaces/[^/\s\"]+)",
                  json.dumps(sample_description or ""))
    return m.group(1) if m else ""


async def poll_once(mode: str | None = None, days: int | None = None) -> dict:
    cfg = get_edr_config()
    mode = (mode or cfg.sentinel_close_mode or "off").lower()
    if mode not in ("dry", "on"):
        return {"mode": mode, "skipped": True}
    scope = (cfg.sentinel_close_scope or "raptor").lower()
    days = max(1, int(days or cfg.sentinel_close_days or 3))
    jql = f"project = {cfg.jira_project_key} AND updated >= -{days}d"
    if scope != "all":
        jql += " AND labels in (" + ", ".join(f'"{l}"' for l in _RAPTOR_LABELS) + ")"
    summary = {"mode": mode, "scope": scope, "incidents": 0, "closed": 0, "would_close": 0,
               "already_closed": 0, "waiting": 0, "errors": 0}
    async with httpx.AsyncClient(
        base_url=cfg.jira_url.rstrip("/"),
        auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30.0, verify=cfg.jira_verify_ssl,
    ) as jc:
        seeds = await _jira_search(jc, jql, ["description"], changelog=False)
        incidents: dict[str, object] = {}
        for s in seeds:
            iid = incident_id((s.get("fields") or {}).get("description"))
            if iid:
                incidents.setdefault(iid, (s.get("fields") or {}).get("description"))
        summary["incidents"] = len(incidents)
        for iid, desc in incidents.items():
            if iid in _SEEN_CLOSED:
                summary["already_closed"] += 1
                continue
            try:
                sibs = await _jira_search(
                    jc, f'project = {cfg.jira_project_key} AND description ~ "\\"{iid}\\""',
                    ["status"])
                outcomes = {i["key"]: ticket_outcome(i) for i in sibs}
                dups = {k: await _dup_original_class(jc, k) for k, v in outcomes.items() if v == "dup"} \
                    if outcomes and set(outcomes.values()) <= {"dup"} else {}
                cls = decide(outcomes, dups)
                if cls is None:
                    summary["waiting"] += 1
                    continue
                # One pod per incident (every pod runs this sweep). Dry runs never claim:
                # a dry claim would block the real close later.
                claimed = False
                if mode == "on":
                    from edr_triage import store
                    try:
                        claimed = store.claim_sentinel_close(iid)
                    except store.ChaseClaimUnavailable as exc:
                        logger.warning("sentinel_sync: claim store unavailable, skipping %s: %s", iid, exc)
                        summary["errors"] += 1
                        continue
                    if not claimed:
                        summary["claimed_elsewhere"] = summary.get("claimed_elsewhere", 0) + 1
                        continue
                try:
                    res = await close_incident(_ws_base(desc), iid, cls,
                                               comment(cls, outcomes, cfg.jira_url), mode == "dry")
                except BaseException:
                    if claimed:
                        store.release_sentinel_close(iid)
                    raise
                if claimed:
                    if res in ("closed", "already-closed", "missing"):
                        store.finish_sentinel_close(iid, res)
                    else:
                        store.release_sentinel_close(iid)
                key = {"closed": "closed", "would-close": "would_close",
                       "already-closed": "already_closed"}.get(res)
                if key:
                    summary[key] += 1
                if res in ("closed", "already-closed"):
                    _SEEN_CLOSED.add(iid)
                if res in ("closed", "would-close"):
                    logger.info("sentinel_sync %s incident %s as %s/%s — tickets %s",
                                "CLOSED" if res == "closed" else "would close", iid, cls[0],
                                cls[1] or "-", sorted(outcomes))
            except SentinelWriteForbidden as exc:
                logger.error("sentinel_sync: Sentinel refused the close (403) — RAPTOR's service "
                             "principal needs the Microsoft Sentinel Responder role. Stopping "
                             "this sweep. %s", exc)
                summary["errors"] += 1
                summary["forbidden"] = True
                break
            except Exception as exc:
                summary["errors"] += 1
                logger.warning("sentinel_sync: incident %s failed: %s", iid, exc)
    logger.info("sentinel_sync: %s", summary)
    return summary


async def run_forever(interval_seconds: int = 900) -> None:
    import asyncio

    cfg = get_edr_config()
    if (cfg.sentinel_close_mode or "off").lower() not in ("dry", "on"):
        logger.info("sentinel_sync off (EDR_SENTINEL_CLOSE) — not starting")
        return
    logger.info("sentinel_sync started — mode=%s scope=%s every %ds",
                cfg.sentinel_close_mode, cfg.sentinel_close_scope, interval_seconds)
    # The first sweep after a start looks back further, so incidents left open while the
    # sync was off or dry (or the pod was down) are caught up without anyone touching it.
    first = max(int(cfg.sentinel_close_backfill_days or 0), int(cfg.sentinel_close_days or 3))
    while True:
        try:
            await poll_once(days=first)
        except Exception:
            logger.exception("sentinel_sync: poll failed")
        first = None
        await asyncio.sleep(interval_seconds)
