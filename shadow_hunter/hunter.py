"""Runs all detectors, applies the allowlist, persists findings."""
from __future__ import annotations

import logging

from shadow_hunter.allowlist import AllowlistEngine
from shadow_hunter.clients import DefenderClient, MockDefenderClient
from shadow_hunter.config import get_shadow_config
from shadow_hunter.detectors import DETECTORS, Detector
from shadow_hunter.models import Finding

logger = logging.getLogger(__name__)


def _s(v: object) -> str:
    """Coerce any value to a plain string (mock CSV arrays may be lists)."""
    if isinstance(v, list):
        return v[0] if v else ""
    return str(v) if v is not None else ""


RUNS_COLL = "shadow_detector_runs"
_EMPTY = {"inserted": 0, "allowlisted": 0, "skipped_existing": 0}


async def run_detector(detector: Detector) -> dict:
    """Run a single detector, apply allowlist, persist findings, and record how the run went.

    Returns counters: inserted, allowlisted, skipped_existing.
    Never raises — errors are logged and empty counters are returned. A failed run is also
    recorded in shadow_detector_runs: a detector that cannot reach its source (MDE quota, an
    egress proxy blocking OSV, an expired credential) otherwise looks exactly like a quiet day.
    """
    from datetime import datetime, timezone
    started = datetime.now(timezone.utc)
    result = await _run_detector(detector)
    await _record_run(detector.name, started, result)
    return {k: result.get(k, 0) for k in _EMPTY}


async def _record_run(name: str, started, result: dict) -> None:
    from datetime import datetime, timezone
    try:
        now = datetime.now(timezone.utc)
        doc = {"detector": name, "last_run": now.isoformat(), "duration_s": round((now - started).total_seconds(), 1),
               "ok": not result.get("error"), "error": (result.get("error") or "")[:300],
               "rows": result.get("rows", 0), "inserted": result.get("inserted", 0)}
        doc["warning"] = (result.get("warning") or "")[:300]
        if result.get("phases"):
            doc["phases"] = result["phases"]
        update = {"$set": doc}
        if doc["ok"]:
            update["$set"]["last_ok"] = doc["last_run"]
        await Finding.get_pymongo_collection().database[RUNS_COLL].update_one({"detector": name}, update, upsert=True)
    except Exception:
        logger.debug("[hunter] %s: could not record run status", name, exc_info=True)


def _err(stage: str, exc: Exception | None = None) -> dict:
    return {**_EMPTY, "error": f"{stage}: {type(exc).__name__}: {exc}" if exc else stage}


async def _run_detector(detector: Detector) -> dict:
    cfg = get_shadow_config()

    if cfg.mode == "live" and not cfg.tenant_id:
        logger.warning("[hunter] %s: live mode but SHADOW_TENANT_ID not set — skipping", detector.name)
        return _err("SHADOW_TENANT_ID not set")

    try:
        defender = DefenderClient() if cfg.mode == "live" else MockDefenderClient()
    except Exception as exc:
        logger.exception("[hunter] %s: failed to create Defender client", detector.name)
        return _err("client", exc)

    allowlist = await AllowlistEngine.load_all(cfg.allowlist_path)

    inserted = allowlisted = skipped_existing = 0

    try:
        rows = await detector.fetch(defender, lookback_hours=24)
    except Exception as exc:
        logger.exception("[hunter] %s: failed to fetch rows", detector.name)
        return {**_err("fetch", exc), "phases": getattr(detector, "run_phases", None) or {}}

    warning = getattr(detector, "run_warning", "") or ""
    phases = getattr(detector, "run_phases", None) or {}
    if not rows:
        logger.debug("[hunter] %s: no rows returned", detector.name)
        return {**_EMPTY, "warning": warning, "phases": phases}

    try:
        findings = detector.to_findings(rows)
    except Exception as exc:
        logger.exception("[hunter] %s: to_findings() failed", detector.name)
        return _err("to_findings", exc)

    findings = allowlist.annotate([f for f in findings if detector.should_persist(f)])

    try:
        for f in findings:
            indicator   = _s(f.get("indicator"))
            device_name = _s(f.get("device_name"))

            # Legacy rows are excluded: the retired backlog must not suppress a finding
            # the revamped detectors raise today.
            existing = await Finding.find_one(
                Finding.detector == f["detector"],
                Finding.indicator == indicator,
                Finding.device_name == device_name,
                Finding.legacy != True,  # noqa: E712 — also matches rows without the field
            )
            if existing:
                skipped_existing += 1
                continue

            await Finding(
                detector=f["detector"],
                severity=f["severity"],
                device_id=_s(f.get("device_id")),
                device_name=device_name,
                account_name=_s(f.get("account_name")),
                indicator=indicator,
                summary=_s(f.get("summary")),
                raw=f.get("raw", {}),
                mitre_techniques=f.get("mitre_techniques", []),
                allowlisted_by_rule=f.get("allowlisted_by_rule", ""),
            ).insert()

            if f.get("allowlisted_by_rule"):
                allowlisted += 1
            inserted += 1
    except Exception as exc:
        logger.exception("[hunter] %s: DB write failed", detector.name)
        return {**_err("db write", exc), "inserted": inserted, "rows": len(rows)}

    return {
        "inserted": inserted,
        "allowlisted": allowlisted,
        "skipped_existing": skipped_existing,
        "rows": len(rows),
        "warning": warning,
        "phases": phases,
    }


async def run_all() -> dict:
    """Run every registered detector and return combined counters."""
    totals = {"inserted": 0, "allowlisted": 0, "skipped_existing": 0}
    for detector in DETECTORS:
        result = await run_detector(detector)
        for key in totals:
            totals[key] += result[key]
    return totals
