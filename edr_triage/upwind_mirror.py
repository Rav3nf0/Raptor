"""Local mirror of the Upwind data RAPTOR and /shadow need, refreshed on a schedule.

Upwind's list endpoints ignore per-resource filters (resource-name, host-id and asset-id all
return the same rows, checked 2026-10-06), so an alert can't ask Upwind "what do you know
about this host". Instead a scheduled sync pages through the lists and keeps, in Mongo:

  upwind_detections   threat detections + runtime events, one row each (kind = detection|event)
  upwind_assets       one doc per resource: lookup keys (name, short host, instance id),
                      internet exposure, owner tags, and summaries of its critical/exploitable
                      vulnerabilities, critical/high misconfigurations and open threats

Readers (RAPTOR alert context, the agent's upwind_* tools, /shadow's upwind detector and
behaviour signal) only ever query these collections — never Upwind — so an Upwind outage costs
freshness, not triage. The sync is GET-only, one page in memory at a time (256 MiB pods), and
12-digit account ids are masked before storage.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Iterable

logger = logging.getLogger(__name__)

DETECTIONS_COLL = "upwind_detections"
ASSETS_COLL = "upwind_assets"
RUNS_COLL = "upwind_sync_runs"

# Volume measured 2026-10-07: CRITICAL vulnerabilities > 30,000 rows; CRITICAL AND exploitable
# > 20,000 rows on > 3,155 resources; HIGH misconfigurations > 10,000 rows on > 8,500 mostly
# non-host resources (S3, CloudFront); CRITICAL misconfigurations 136. Keep what changes a
# triage decision about a host: critical-and-exploitable vulnerabilities and critical
# misconfigurations. ~0.46 s a 100-row page, so 800 pages is ~6 min, twice a day. A query that
# hits its cap is recorded (its counts are then lower bounds).
VULN_QUERIES = ("severity=CRITICAL&exploitable=true",)
CONFIG_QUERIES = ("severity=CRITICAL",)
MAX_PAGES_VULN = 800
MAX_PAGES_CONFIG = 20
TOP_PER_ASSET = 8
STALE_AFTER = timedelta(days=3)       # an asset unseen by three days of syncs is dropped


def _db():
    from shadow_hunter.models import Finding
    return Finding.get_pymongo_collection().database


def _mask(s):
    from shadow_hunter.detectors.base import mask_ids
    return mask_ids(s) if isinstance(s, str) else s


def host_keys(*names: str) -> list[str]:
    """Lookup keys for a host name or id: lowercased, with and without the domain. An MDE
    device 'genai-vector-store-0102.corp.example.com' and Upwind's EC2 Name tag 'genai-vector-store-0102'
    must meet; an instance id 'i-0abc…' is a key as itself."""
    out: list[str] = []
    for n in names:
        n = (n or "").strip().lower()
        if not n or n in ("unknown device", "unknown"):
            continue
        for k in (n, n.split(".")[0]):
            if k and k not in out:
                out.append(k)
    return out


def _num(v) -> float | None:
    """Upwind sends some scores as strings (epss_score '0.94', 2026-10-07)."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _exposed(res: dict) -> bool:
    return bool((((res or {}).get("internet_exposure") or {}).get("ingress") or {}).get("exposed"))


def _resource(res: dict) -> dict:
    res = res or {}
    return {
        "name": res.get("name", ""),
        "type": res.get("type", ""),
        "host_id": res.get("host_id") or (res.get("external_id") if str(res.get("external_id", "")).startswith("i-") else ""),
        "upwind_asset_id": res.get("upwind_asset_id", ""),
        "cloud_provider": res.get("cloud_provider", ""),
        "cloud_account_id": _mask(str(res.get("cloud_account_id", ""))),
        "cloud_account_name": res.get("cloud_account_name", ""),
        "region": res.get("region", ""),
        "namespace": res.get("namespace", ""),
        "exposed": _exposed(res),
    }


def _asset_key(res: dict) -> str:
    return res.get("upwind_asset_id") or f"{res.get('type', '')}:{(res.get('name') or '').lower()}"


def detection_doc(row: dict, kind: str, now: datetime) -> dict:
    res = _resource(row.get("resource") or {})
    return {
        "_id": row.get("id"),
        "kind": kind,
        "type": row.get("type", ""),
        "category": row.get("category", ""),
        "severity": row.get("severity", ""),
        "status": row.get("status", ""),
        "title": _mask(row.get("title", ""))[:300],
        "description": _mask(row.get("description", "") or "")[:600],
        "first_seen": row.get("first_seen_time", ""),
        "last_seen": row.get("last_seen_time", ""),
        "occurrence_count": row.get("occurrence_count"),
        "mitre": [f"{m.get('tactic_name', '')}" + (f" / {m['technique_name']}" if m.get("technique_name") else "")
                  for m in row.get("mitre_attacks") or []][:5],
        "resource": res,
        "keys": host_keys(res["name"], res["host_id"]),
        "synced_at": now,
    }


class _Assets:
    """Per-asset accumulator across one sync's pages. Thousands of assets at most, each a
    few hundred bytes — the pages themselves are what must not be held."""

    def __init__(self):
        self.by: dict[str, dict] = {}

    def _get(self, res: dict) -> dict:
        r = _resource(res)
        key = _asset_key(r)
        a = self.by.get(key)
        if a is None:
            a = self.by[key] = {
                "_id": key, "name": r["name"], "type": r["type"], "host_id": r["host_id"],
                "cloud_provider": r["cloud_provider"], "cloud_account_name": r["cloud_account_name"],
                "cloud_account_id": r["cloud_account_id"], "region": r["region"], "exposed": r["exposed"],
                "tags": {}, "keys": host_keys(r["name"], r["host_id"]),
                "vulns": {"critical": 0, "exploitable": 0, "top": [], "_seen": set()},
                "config": {"critical": 0, "high": 0, "top": [], "_seen": set()},
                "threats": {"open": 0, "top": []},
            }
        a["exposed"] = a["exposed"] or r["exposed"]
        for t in (res or {}).get("resource_tags") or []:
            k = str(t.get("key", "")).lower()
            if k in ("tribe", "person", "product", "environment", "name", "team", "owner"):
                a["tags"][k] = str(t.get("value", ""))[:80]
        return a

    def add_vuln(self, row: dict) -> None:
        a = self._get(row.get("resource") or {})
        v = row.get("vulnerability") or {}
        if row.get("id") in a["vulns"]["_seen"]:
            return
        a["vulns"]["_seen"].add(row.get("id"))
        sev = str(v.get("nvd_cvss_v3_severity") or "").upper()
        expl = bool(v.get("exploitable"))
        a["vulns"]["critical"] += sev == "CRITICAL"
        a["vulns"]["exploitable"] += expl
        top = a["vulns"]["top"]
        item = {"cve": v.get("nvd_cve_id") or v.get("name", ""), "severity": sev,
                "cvss": _num(v.get("nvd_cvss_v3_score")), "epss": _num(v.get("epss_score")), "exploitable": expl,
                "in_use": bool(v.get("exploitable_functions_in_use")),
                "package": ((row.get("package") or {}).get("name") or "")[:60]}
        top.append(item)
        top.sort(key=lambda x: (not x["exploitable"], -(x["epss"] or 0), -(x["cvss"] or 0)))
        del top[TOP_PER_ASSET:]

    def add_config(self, row: dict) -> None:
        a = self._get(row.get("resource") or {})
        if row.get("id") in a["config"]["_seen"]:
            return
        a["config"]["_seen"].add(row.get("id"))
        sev = str(row.get("severity") or "").upper()
        a["config"]["critical"] += sev == "CRITICAL"
        a["config"]["high"] += sev == "HIGH"
        title = _mask(row.get("title") or (row.get("check") or {}).get("title") or "")[:160]
        if len(a["config"]["top"]) < TOP_PER_ASSET and title not in a["config"]["top"]:
            a["config"]["top"].append(title)

    def add_threat(self, doc: dict, res: dict) -> None:
        a = self._get(res)
        if doc["status"] in ("OPEN", "PENDING"):
            a["threats"]["open"] += 1
            if len(a["threats"]["top"]) < TOP_PER_ASSET:
                a["threats"]["top"].append({"id": doc["_id"], "kind": doc["kind"], "severity": doc["severity"],
                                            "category": doc["category"], "title": doc["title"][:160],
                                            "first_seen": doc["first_seen"]})

    def docs(self, now: datetime) -> Iterable[dict]:
        for a in self.by.values():
            a["vulns"].pop("_seen", None)
            a["config"].pop("_seen", None)
            a["synced_at"] = now
            yield a


async def ensure_indexes() -> None:
    db = _db()
    await db[DETECTIONS_COLL].create_index("keys")
    await db[DETECTIONS_COLL].create_index("first_seen")
    await db[ASSETS_COLL].create_index("keys")


async def sync(full: bool = True) -> dict:
    """Refresh the mirror. full=False syncs detections and events only (one cheap call each),
    for the frequent schedule; full=True also rebuilds the per-asset vulnerability and
    misconfiguration summaries."""
    from edr_triage import upwind_client as uc
    if not uc.configured():
        return {"skipped": "upwind not configured"}
    db = _db()
    now = datetime.now(timezone.utc)
    await ensure_indexes()
    out = {"started": now.isoformat(), "full": full}
    assets = _Assets()

    for endpoint, kind in (("threat-detections", "detection"), ("threat-events", "event")):
        n = 0
        async for page in uc.iter_pages(endpoint, max_pages=20):
            for row in page:
                if not row.get("id"):
                    continue
                d = detection_doc(row, kind, now)
                await db[DETECTIONS_COLL].replace_one({"_id": d["_id"]}, d, upsert=True)
                assets.add_threat(d, row.get("resource") or {})
                n += 1
        out[kind + "s"] = n

    if full:
        # One query failing part-way (a stalled page after retries) keeps what it already read
        # and is recorded; it must not cost the detections or the other queries.
        out["errors"] = []
        for endpoint, queries, cap, add in (
                ("vulnerability-findings", VULN_QUERIES, MAX_PAGES_VULN, assets.add_vuln),
                ("configuration-findings", CONFIG_QUERIES, MAX_PAGES_CONFIG, assets.add_config)):
            for q in queries:
                rows = 0
                try:
                    async for page in uc.iter_pages(endpoint, q, max_pages=cap):
                        for row in page:
                            add(row)
                        rows += len(page)
                except Exception as exc:
                    out["errors"].append(f"{endpoint}?{q} after {rows} rows: {type(exc).__name__}: {str(exc)[:120]}")
                    logger.warning("[upwind] %s?%s stopped after %d rows: %s", endpoint, q, rows, exc)
                out[f"{endpoint}?{q}"] = rows
                if rows >= cap * 100:
                    out.setdefault("capped", []).append(f"{endpoint}?{q}")
        written = 0
        for a in assets.docs(now):
            await db[ASSETS_COLL].replace_one({"_id": a["_id"]}, a, upsert=True)
            written += 1
        await db[ASSETS_COLL].delete_many({"synced_at": {"$lt": now - STALE_AFTER}})
        out["assets"] = written
    else:
        # refresh only the threat summaries of assets already mirrored
        for a in assets.docs(now):
            await db[ASSETS_COLL].update_one({"_id": a["_id"]}, {"$set": {"threats": a["threats"]}})
    out["finished"] = datetime.now(timezone.utc).isoformat()
    await db[RUNS_COLL].insert_one({**out, "ok": True})
    return out


async def record_failure(full: bool, exc: Exception) -> None:
    now = datetime.now(timezone.utc).isoformat()
    await _db()[RUNS_COLL].insert_one({"full": full, "ok": False, "finished": now,
                                       "error": f"{type(exc).__name__}: {str(exc)[:300]}"})


async def last_full_sync() -> datetime | None:
    r = await _db()[RUNS_COLL].find_one({"full": True, "ok": True}, sort=[("finished", -1)])
    if not r:
        return None
    try:
        return datetime.fromisoformat(r["finished"])
    except (KeyError, ValueError):
        return None


async def status() -> dict:
    db = _db()
    runs = await db[RUNS_COLL].find({}, {"_id": 0}).sort("finished", -1).limit(5).to_list(5)
    return {"detections": await db[DETECTIONS_COLL].count_documents({"kind": "detection"}),
            "events": await db[DETECTIONS_COLL].count_documents({"kind": "event"}),
            "assets": await db[ASSETS_COLL].count_documents({}),
            "exposed_assets": await db[ASSETS_COLL].count_documents({"exposed": True}),
            "recent_runs": runs}


# ── readers ─────────────────────────────────────────────────────────────────────

async def lookup_asset(*names: str) -> dict | None:
    """The mirrored Upwind picture of a host, by any of its names or its instance id.
    None when nothing matches (a host Upwind doesn't cover is not a finding)."""
    keys = host_keys(*names)
    if not keys:
        return None
    try:
        doc = await _db()[ASSETS_COLL].find_one({"keys": {"$in": keys}}, {"_id": 0})
    except Exception as exc:          # a mirror read must never stop triage
        logger.debug("[upwind] asset lookup failed: %s", exc)
        return None
    return doc


async def threats_for(*names: str, days: int = 30, limit: int = 20) -> list[dict]:
    keys = host_keys(*names)
    if not keys:
        return []
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    cur = _db()[DETECTIONS_COLL].find(
        {"keys": {"$in": keys}, "last_seen": {"$gte": since}},
        {"_id": 1, "kind": 1, "severity": 1, "category": 1, "status": 1, "title": 1, "first_seen": 1,
         "last_seen": 1, "occurrence_count": 1, "mitre": 1}).sort("last_seen", -1).limit(limit)
    return await cur.to_list(length=limit)


async def new_runtime_detections(start: datetime, end: datetime, *, min_severity: str = "MEDIUM",
                                 exclude_critical_detections: bool = False) -> list[dict]:
    """Detections and runtime events first seen in [start, end): the /shadow detector's and
    the behaviour signal's input. API-security pattern matches (OWASP request heuristics, over
    half of all events) and LOW severity are left out."""
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    keep = sevs[:sevs.index(min_severity) + 1]
    q = {"first_seen": {"$gte": start.strftime("%Y-%m-%dT%H:%M:%S"), "$lt": end.strftime("%Y-%m-%dT%H:%M:%S")},
         "severity": {"$in": keep}, "category": {"$ne": "API_SECURITY"}}
    rows = await _db()[DETECTIONS_COLL].find(q).to_list(length=2000)
    if exclude_critical_detections:
        rows = [r for r in rows if not (r["kind"] == "detection" and r["severity"] == "CRITICAL")]
    return rows


def format_asset(a: dict) -> str:
    """One compact block for a prompt or comment. Facts only; no verdict."""
    if not a:
        return ""
    t = a.get("tags") or {}
    v, c, th = a.get("vulns") or {}, a.get("config") or {}, a.get("threats") or {}
    parts = [f"{a.get('type', '')} '{a.get('name', '')}'"
             + (f" ({a['host_id']})" if a.get("host_id") else "")
             + (f", account {a['cloud_account_name']}" if a.get("cloud_account_name") else ""),
             f"internet-exposed: {'YES' if a.get('exposed') else 'no'}"]
    if t:
        parts.append("tags: " + ", ".join(f"{k}={val}" for k, val in sorted(t.items()) if k != "name"))
    parts.append(f"open Upwind threats: {th.get('open', 0)}"
                 + (" — " + "; ".join(f"[{x['severity']}] {x['title']}" for x in th.get("top", [])[:4])
                    if th.get("top") else ""))
    if v.get("critical") or v.get("exploitable"):
        top = ", ".join(f"{x['cve']}{' (exploitable' + (', in use' if x.get('in_use') else '') + ')' if x['exploitable'] else ''}"
                        for x in v.get("top", [])[:5])
        parts.append(f"critical exploitable vulnerabilities: {v.get('exploitable', 0)}"
                     + (f" — {top}" if top else ""))
    if c.get("critical") or c.get("high"):
        parts.append(f"critical misconfigurations: {c.get('critical', 0)}"
                     + (" — " + "; ".join(c.get("top", [])[:3]) if c.get("top") else ""))
    return " | ".join(parts)
