"""Upwind CNAPP read client — the evidence behind an Upwind detection ticket.

Upwind's Jira tickets carry only a title and the affected resource. The detection itself
(GET /v1/organizations/{org}/threat-detections/{uwd-id}) carries the file hashes, paths,
instance id, first/last seen and occurrence count — verified live on uwd-3e95ace03721d158
(DEMO-115057), 2026-09-29.

Read-only by construction: this module only issues GETs. Never raises and never blocks
triage — every failure returns a status dict and logs; an Upwind outage must not stop an
alert being triaged. Outcomes kept distinct, like lib/tribe_client:

    found      the detection was fetched; `detection` holds the summary
    not_found  Upwind has no such detection (404)
    error      the lookup failed (auth, network, 5xx) — says nothing about the detection
"""
from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Optional

import httpx

from edr_triage.config import get_edr_config

logger = logging.getLogger("upwind_client")

_token: dict[str, Any] = {"value": "", "expires_at": 0.0, "org_id": ""}

_MAX_FILES = 10
_MAX_PATHS_PER_FILE = 5
_MAX_OTHER_EVENTS = 5


def _jwt_claim(token: str, claim: str) -> str:
    """Read one claim from our own access token's payload (no verification needed —
    it is only used to learn which org the credential belongs to)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get(claim) or "")
    except Exception:
        return ""


async def _get_token(client: httpx.AsyncClient, cfg) -> Optional[str]:
    now = time.monotonic()
    if _token["value"] and now < _token["expires_at"] - 60:
        return _token["value"]
    resp = await client.post(cfg.upwind_auth_url, data={
        "grant_type": "client_credentials",
        "client_id": cfg.upwind_client_id,
        "client_secret": cfg.upwind_client_secret,
        # The audience must be the regional API host the token will be used against.
        "audience": cfg.upwind_api_base.rstrip("/"),
    })
    resp.raise_for_status()
    body = resp.json()
    _token["value"] = body["access_token"]
    _token["expires_at"] = now + int(body.get("expires_in", 3600))
    _token["org_id"] = _jwt_claim(_token["value"], "org_id")
    return _token["value"]


def summarize_detection(raw: dict) -> dict:
    """Compact, prompt-sized view of a detection. File events are grouped by hash, since
    the same binary routinely appears at several paths (uwd-3e95ace03721d158: 6 events,
    fewer distinct hashes)."""
    raw = raw or {}
    res = raw.get("resource") or {}
    files: dict[str, dict] = {}
    event_types: dict[str, int] = {}
    other_events: list[dict] = []
    for trig in raw.get("triggers") or []:
        for ev in trig.get("events") or []:
            etype = ev.get("type") or "UNKNOWN"
            event_types[etype] = event_types.get(etype, 0) + 1
            data = ev.get("data") or {}
            h = data.get("file_hash")
            if h:
                f = files.setdefault(h, {
                    "hash": h, "hash_type": data.get("file_hash_type", ""),
                    "name": data.get("file_name", ""), "paths": [],
                    "image": data.get("image_name", ""),
                })
                p = data.get("file_path")
                if p and p not in f["paths"] and len(f["paths"]) < _MAX_PATHS_PER_FILE:
                    f["paths"].append(p)
            elif len(other_events) < _MAX_OTHER_EVENTS:
                other_events.append({
                    "type": etype,
                    "description": ev.get("description", ""),
                    "data": {k: (v[:300] if isinstance(v, str) else v) for k, v in data.items()},
                })
    return {
        "id": raw.get("id", ""),
        "type": raw.get("type", ""),
        "category": raw.get("category", ""),
        "severity": raw.get("severity", ""),
        "status": raw.get("status", ""),
        "title": raw.get("title", ""),
        "first_seen": raw.get("first_seen_time", ""),
        "last_seen": raw.get("last_seen_time", ""),
        "occurrence_count": raw.get("occurrence_count"),
        "mitre": [f"{m.get('tactic_id', '')} {m.get('tactic_name', '')}".strip()
                  + (f" / {m['technique_name']}" if m.get("technique_name") else "")
                  for m in raw.get("mitre_attacks") or []],
        "policies": sorted({t.get("policy_name", "") for t in raw.get("triggers") or []
                            if t.get("policy_name")}),
        "resource": {
            "name": res.get("name", ""),
            "type": res.get("type", ""),
            "instance_id": res.get("external_id", ""),
            "region": res.get("region", ""),
            "cloud_provider": res.get("cloud_provider", ""),
            "cloud_account_id": res.get("cloud_account_id", ""),
            "upwind_asset_id": res.get("upwind_asset_id", ""),
        },
        "event_types": event_types,
        "files": list(files.values())[:_MAX_FILES],
        "files_truncated": max(0, len(files) - _MAX_FILES),
        "other_events": other_events,
    }


_NEXT_RE = __import__("re").compile(r'<([^>]+)>;\s*rel="next"')


def configured() -> bool:
    cfg = get_edr_config()
    return bool(cfg.upwind_client_id and cfg.upwind_client_secret) and not cfg.upwind_lookup_disabled


async def iter_pages(endpoint: str, params: str = "", *, per_page: int = 100, max_pages: int = 200,
                     timeout: float = 120.0):
    """Yield one page (a list of rows) at a time from a list endpoint, following the Link
    rel="next" header, or `page=N` where the endpoint pages without one. GET only. One page in memory at a time: the pods run in 256 MiB and a
    100-row vulnerability page alone is ~1 MB. The API ignores per-resource filters
    (resource-name, host-id, asset-id all return the same rows, 2026-10-06), so callers mirror
    and index locally instead of querying per host. Raises on failure — the caller (a
    scheduled sync) records it; nothing on the triage path calls this."""
    cfg = get_edr_config()
    async with httpx.AsyncClient(timeout=timeout, verify=cfg.upwind_verify_ssl) as client:
        token = await _get_token(client, cfg)
        org = cfg.upwind_org_id or _token["org_id"]
        if not org:
            raise RuntimeError("no Upwind org id (not configured, not in token)")
        base = f"{cfg.upwind_api_base.rstrip('/')}/v1/organizations/{org}/{endpoint}"
        sep = "&" if params else ""
        first = f"{base}?{params}{sep}per-page={per_page}"
        url: Optional[str] = first
        pages = 0
        # Some endpoints page with `page=N` and send no Link header (threat-events: 669
        # events, but only the first 100 ever arrived while this followed Link alone).
        # Ids already yielded tell a real next page from a server that ignores `page`.
        seen: set = set()
        while url and pages < max_pages:
            # A page occasionally stalls past the read timeout (a vulnerability page, 2026-10-06)
            # and a deep page token is the only way back to where we were: retry it, don't restart.
            for attempt in range(3):
                try:
                    resp = await client.get(url, headers={"Authorization": f"Bearer {token}",
                                                          "Accept": "application/json"})
                    if resp.status_code < 500:
                        break
                except (httpx.TimeoutException, httpx.TransportError):
                    if attempt == 2:
                        raise
                logger.info("[upwind] retrying %s page %d (attempt %d)", endpoint, pages + 1, attempt + 2)
            if resp.status_code == 401:
                _token["value"] = ""
            resp.raise_for_status()
            rows = resp.json()
            rows = rows if isinstance(rows, list) else []
            pages += 1
            m = _NEXT_RE.search(resp.headers.get("link", ""))
            if m:
                yield rows
                url = m.group(1)
                continue
            ids = {r.get("id") for r in rows if isinstance(r, dict)}
            fresh = [r for r in rows if not isinstance(r, dict) or r.get("id") not in seen]
            if pages > 1 and not fresh:
                break                      # server ignores `page`: nothing new, stop
            seen |= ids
            yield fresh
            # A full page with no Link may have more behind it; a short page is the last.
            url = f"{first}&page={pages + 1}" if len(rows) >= per_page else None


async def get_detection(detection_id: str) -> Optional[dict]:
    """Fetch and summarize one detection. None when the lookup is disabled or
    unconfigured (nothing to say); otherwise a status dict."""
    cfg = get_edr_config()
    if cfg.upwind_lookup_disabled or not (cfg.upwind_client_id and cfg.upwind_client_secret):
        return None
    if not (detection_id or "").startswith("uwd-"):
        return None
    try:
        async with httpx.AsyncClient(timeout=15, verify=cfg.upwind_verify_ssl) as client:
            token = await _get_token(client, cfg)
            org = cfg.upwind_org_id or _token["org_id"]
            if not org:
                return {"status": "error", "error": "no Upwind org id (not configured, not in token)"}
            resp = await client.get(
                f"{cfg.upwind_api_base.rstrip('/')}/v1/organizations/{org}/threat-detections/{detection_id}",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
            if resp.status_code == 404:
                return {"status": "not_found"}
            if resp.status_code == 401:
                _token["value"] = ""  # force a fresh token next call
            resp.raise_for_status()
            return {"status": "found", "detection": summarize_detection(resp.json())}
    except Exception as exc:
        logger.warning("Upwind detection lookup %s failed: %s", detection_id, exc)
        return {"status": "error", "error": str(exc)[:200]}


# Kubernetes resolver search-domain expansions of one real lookup ("x.oast.live.svc.cluster.local").
_K8S_EXPANSION = __import__("re").compile(r"\.(?:cluster\.local|compute\.internal|svc|local)\.?$", __import__("re").I)
_DOMAIN = __import__("re").compile(r"^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$")


def detection_domains(raw: dict) -> list[str]:
    """The DNS names a network detection's evidence queried, without the cluster-local
    expansions. Network detections carry them in triggers[].events[].rawLog (a JSON string),
    which summarize_detection does not read."""
    names: list[str] = []
    logs = [ev.get("rawLog") for t in (raw or {}).get("triggers") or [] for ev in t.get("events") or []]
    logs += list((raw or {}).get("evidences") or [])
    for s in logs:
        try:
            d = json.loads(s) if isinstance(s, str) else (s or {})
        except ValueError:
            continue
        d = d.get("evidence", d) if isinstance(d, dict) else {}
        labels = d.get("labels") or {}
        for v in (d.get("reqDomain"), d.get("destDomain"), labels.get("dns.reqDomain")):
            v = str(v or "").strip().rstrip(".").lower()
            if v and _DOMAIN.match(v) and not _K8S_EXPANSION.search(v):
                names.append(v)
    return list(dict.fromkeys(names))


async def get_detection_raw(detection_id: str) -> Optional[dict]:
    """One detection as Upwind returns it, threat (uwd-) or network (uwnd-). None when the
    lookup is off, unconfigured, not found or failing: callers treat it as 'no evidence'."""
    cfg = get_edr_config()
    if cfg.upwind_lookup_disabled or not (cfg.upwind_client_id and cfg.upwind_client_secret):
        return None
    if not (detection_id or "").startswith(("uwd-", "uwnd-")):
        return None
    try:
        async with httpx.AsyncClient(timeout=15, verify=cfg.upwind_verify_ssl) as client:
            token = await _get_token(client, cfg)
            org = cfg.upwind_org_id or _token["org_id"]
            if not org:
                return None
            resp = await client.get(
                f"{cfg.upwind_api_base.rstrip('/')}/v1/organizations/{org}/threat-detections/{detection_id}",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
            if resp.status_code == 401:
                _token["value"] = ""
            if resp.status_code != 200:
                return None
            return resp.json()
    except Exception as exc:
        logger.warning("Upwind detection fetch %s failed: %s", detection_id, exc)
        return None
