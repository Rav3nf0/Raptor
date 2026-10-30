"""APScheduler wiring — runs each detector on its own cadence."""
from __future__ import annotations

import logging
import os
import socket
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from shadow_hunter.detectors import DETECTORS, Detector
from shadow_hunter.hunter import run_detector

logger = logging.getLogger(__name__)

# The app runs as several replicas and every replica starts this scheduler, so without a
# lease each hunt ran once PER REPLICA — multiplying MDE hunting-quota use (shared with
# RAPTOR's own hunts) and racing on the same inserts. Each run first takes a short Mongo
# lease keyed by job; replicas that don't get it skip that cycle.
_HOLDER = f"{socket.gethostname()}:{os.getpid()}"
LOCK_COLL = "shadow_job_locks"


async def acquire_lease(job_id: str, ttl_s: int) -> bool:
    """True if this process may run `job_id` now. Atomic: the filter only matches an expired
    lease or one we already hold, so a live lease held by another replica makes the upsert
    collide on _id and we back off."""
    from pymongo.errors import DuplicateKeyError
    from shadow_hunter.models import Finding
    coll = Finding.get_pymongo_collection().database[LOCK_COLL]
    now = datetime.now(timezone.utc)
    try:
        await coll.update_one(
            {"_id": job_id, "$or": [{"expires_at": {"$lt": now}}, {"holder": _HOLDER}]},
            {"$set": {"holder": _HOLDER, "expires_at": now + timedelta(seconds=ttl_s),
                      "acquired_at": now}},
            upsert=True,
        )
        return True
    except DuplicateKeyError:
        return False


async def _job(detector: Detector) -> None:
    # Lease for most of one cadence: long enough that no other replica starts the same
    # hunt this cycle, short enough that a dead holder does not block the next one.
    if not await acquire_lease(f"detector:{detector.name}", int(detector.cadence_minutes * 60 * 0.8)):
        logger.debug("[scheduler] %s: another replica holds this cycle", detector.name)
        return
    try:
        result = await run_detector(detector)
        logger.info(
            "[scheduler] %s: inserted=%d allowlisted=%d skipped=%d",
            detector.name,
            result["inserted"],
            result["allowlisted"],
            result["skipped_existing"],
        )
    except Exception:
        logger.exception("[scheduler] %s: hunt failed", detector.name)


async def _behavior_job() -> None:
    if not await acquire_lease("behavior_daily", 6 * 3600):
        logger.info("[scheduler] behavior: another replica holds today's run")
        return
    try:
        from shadow_hunter.behavior import run_daily
        logger.info("[scheduler] behavior: %s", await run_daily())
    except Exception:
        logger.exception("[scheduler] behavior: daily build/score failed")
    finally:
        await release_lease("behavior_daily")


async def _behavior_recover_job() -> None:
    from shadow_hunter import behavior
    try:
        if not await behavior.recovery_plans():
            return
        # A pod killed mid-run leaves its 6 h lease behind. A plan exists only when no run is
        # alive (failed, no heartbeat for STALE_AFTER, or never started), so a lease older than
        # that is a dead holder's. A fresh one is a live replica's and is left alone.
        await clear_lease_older_than("behavior_daily", behavior.STALE_AFTER)
    except Exception:
        logger.exception("[scheduler] behavior: recovery check failed")
        return
    # Same lease as the nightly run, so a recovery can never overlap it (or another replica's).
    if not await acquire_lease("behavior_daily", 6 * 3600):
        return
    try:
        for r in await behavior.recover_missed():
            logger.info("[scheduler] behavior recovery: %s", r)
    except Exception:
        logger.exception("[scheduler] behavior: recovery failed")
    finally:
        await release_lease("behavior_daily")


async def clear_lease_older_than(job_id: str, age: timedelta) -> None:
    from shadow_hunter.models import Finding
    coll = Finding.get_pymongo_collection().database[LOCK_COLL]
    await coll.delete_one({"_id": job_id, "acquired_at": {"$lt": datetime.now(timezone.utc) - age}})


async def _ai_triage_job() -> None:
    """AI suggestions every 30 min (SHADOW_AI_TRIAGE=1). On Claude: the grouped review —
    high/critical every run, medium/low at the twice-daily batch (shadow_hunter/ai_review.py)."""
    from shadow_hunter import ai_review, ai_triage
    if not ai_triage.enabled():
        return
    if not await acquire_lease("ai_triage", 25 * 60):
        return
    try:
        if ai_review.enabled_review():
            logger.info("[scheduler] ai_review: %s", await ai_review.run())
        else:
            logger.info("[scheduler] ai_triage: %s", await ai_triage.run_batch(limit=10))
    except Exception:
        logger.exception("[scheduler] ai_triage failed")
    finally:
        await release_lease("ai_triage")


async def _upwind_sync_job(full: bool, force: bool = False) -> None:
    job = "upwind_sync_full" if full else "upwind_sync"
    if not await acquire_lease(job, 60 * 60 if full else 25 * 60):
        logger.info("[scheduler] %s: another replica holds this run", job)
        return
    try:
        from edr_triage.upwind_mirror import last_full_sync, record_failure, sync
        # Pods are replaced several times a day and each new one schedules a full sync a few
        # minutes after start: skip it unless the last full one is old.
        if full and not force and (last := await last_full_sync()) and datetime.now(timezone.utc) - last < timedelta(hours=11):
            logger.info("[scheduler] %s: skipped, last full sync %s", job, last.isoformat())
            return
        logger.info("[scheduler] %s: %s", job, await sync(full=full))
    except Exception as exc:
        logger.exception("[scheduler] %s failed", job)
        try:
            await record_failure(full, exc)
        except Exception:
            pass
    finally:
        await release_lease(job)


async def _person_job() -> None:
    """Person cases for yesterday (UTC). After the behaviour run, whose device scores it reads."""
    if not await acquire_lease("person_daily", 3 * 3600):
        logger.info("[scheduler] person: another replica holds today's run")
        return
    try:
        from shadow_hunter.person import run_logged
        day = datetime.now(timezone.utc).date() - timedelta(days=1)
        logger.info("[scheduler] person: %s", await run_logged(day))
    except Exception:
        logger.exception("[scheduler] person: daily run failed")
    finally:
        await release_lease("person_daily")


async def _story_job() -> None:
    """Regroup recent findings into incident stories (shadow_hunter/stories.py). Its Sentinel
    lookups are Log Analytics queries, whose limits are separate from the MDE hunting quota."""
    if not await acquire_lease("story_build", 25 * 60):
        return
    try:
        from shadow_hunter.clients.sentinel_logs import SentinelLogsClient
        from shadow_hunter.stories import run_logged
        logger.info("[scheduler] stories: %s", await run_logged(client=SentinelLogsClient()))
    except Exception:
        logger.exception("[scheduler] stories: build failed")
    finally:
        await release_lease("story_build")


async def _story_context_job() -> None:
    """Snapshot related Jira alerts and VictoriaLogs context onto the open stories that need it
    (shadow_hunter/story_context.py). Its own lease: a slow VictoriaLogs never delays grouping."""
    if not await acquire_lease("story_context", 25 * 60):
        return
    try:
        from shadow_hunter.story_context import run_due
        logger.info("[scheduler] story context: %s", await run_due())
    except Exception:
        logger.exception("[scheduler] story context: refresh failed")
    finally:
        await release_lease("story_context")


async def _notify_job() -> None:
    """Slack alerts for true positives only: TP stories (first TP, severity up, newly linked
    ticket) and high/critical TP detections in no story (shadow_hunter/notify.py). Off
    without a webhook."""
    if not await acquire_lease("shadow_notify", 9 * 60):
        return
    try:
        from shadow_hunter.notify import run_logged
        await run_logged()
    except Exception:
        logger.exception("[scheduler] notify: failed")
    finally:
        await release_lease("shadow_notify")


async def release_lease(job_id: str) -> None:
    """Drop a lease we hold, so the next job using it is not blocked for its whole TTL."""
    from shadow_hunter.models import Finding
    coll = Finding.get_pymongo_collection().database[LOCK_COLL]
    try:
        await coll.delete_one({"_id": job_id, "holder": _HOLDER})
    except Exception:
        logger.debug("[scheduler] could not release %s", job_id, exc_info=True)


def build_scheduler() -> AsyncIOScheduler:
    """Create and configure the scheduler (does not start it)."""
    scheduler = AsyncIOScheduler()

    # Once a day, off-peak (02:30 IST): the MDE hunting CPU quota is per tenant and shared
    # with RAPTOR's own hunts, so the one fleet-day scan runs when triage is quietest.
    scheduler.add_job(
        _behavior_job, trigger="cron", hour=21, minute=0, timezone="UTC",
        id="behavior_daily", name="Behaviour profile + entity scoring (daily)",
        replace_existing=True, misfire_grace_time=3600,
    )
    # Pods are replaced by the autoscaler mid-run; this finishes a night that failed, stalled
    # or never started (behavior.recover_missed), without a human re-running it.
    scheduler.add_job(
        _behavior_recover_job, trigger="interval", minutes=30,
        id="behavior_recover", name="Behaviour: finish failed/stalled nights (every 30m)",
        replace_existing=True, misfire_grace_time=600,
    )
    # Person cases (shadow_hunter/person.py): EDR + Netskope + Entra + CloudTrail per person,
    # 14-day rolling. 22:30 UTC, after the 21:00 behaviour run whose device scores it reads.
    scheduler.add_job(
        _person_job, trigger="cron", hour=22, minute=30, timezone="UTC",
        id="person_daily", name="Person cases across EDR/Netskope/Entra/CloudTrail (daily)",
        replace_existing=True, misfire_grace_time=3 * 3600,
    )
    # Upwind mirror (edr_triage/upwind_mirror.py): detections + events every 30 min feed the
    # upwind_threats detector and the behaviour signal; the per-host vulnerability and
    # misconfiguration summaries (RAPTOR context, agent tools) rebuild twice a day.
    scheduler.add_job(
        _upwind_sync_job, trigger="interval", minutes=30, args=[False],
        id="upwind_sync", name="Upwind mirror: detections + events (every 30m)",
        replace_existing=True, misfire_grace_time=600, next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2),
    )
    scheduler.add_job(
        _upwind_sync_job, trigger="interval", hours=12, args=[True],
        id="upwind_sync_full", name="Upwind mirror: full incl. vulnerabilities (every 12h)",
        replace_existing=True, misfire_grace_time=3600, next_run_time=datetime.now(timezone.utc) + timedelta(minutes=6),
    )
    # Incident stories: related findings grouped with link reasons and a timeline (advisory).
    scheduler.add_job(
        _story_job, trigger="interval", minutes=30,
        id="story_build", name="Incident stories: group related findings (every 30m)",
        replace_existing=True, misfire_grace_time=600, next_run_time=datetime.now(timezone.utc) + timedelta(minutes=8),
    )
    # Story context: related Jira alerts + VictoriaLogs (edge, EKS, RDS, other logs), snapshotted.
    scheduler.add_job(
        _story_context_job, trigger="interval", minutes=30,
        id="story_context", name="Incident stories: Jira + VictoriaLogs context (every 30m)",
        replace_existing=True, misfire_grace_time=600, next_run_time=datetime.now(timezone.utc) + timedelta(minutes=12),
    )
    # Slack: TP stories + high/critical TP detections (no-op unless SHADOW_SLACK_WEBHOOK is set).
    scheduler.add_job(
        _notify_job, trigger="interval", hours=2,
        id="shadow_notify", name="Slack alerts: TP stories and high/critical TP detections (every 2h)",
        replace_existing=True, misfire_grace_time=300, next_run_time=datetime.now(timezone.utc) + timedelta(minutes=3),
    )
    # AI suggestions on new findings (advisory; paused unless SHADOW_AI_TRIAGE=1).
    scheduler.add_job(
        _ai_triage_job, trigger="interval", minutes=30,
        id="ai_triage", name="AI triage suggestions (every 30m)",
        replace_existing=True, misfire_grace_time=600,
    )

    for detector in DETECTORS:
        scheduler.add_job(
            _job,
            trigger="interval",
            minutes=detector.cadence_minutes,
            args=[detector],
            id=f"detector_{detector.name}",
            name=f"Hunt: {detector.name} (every {detector.cadence_minutes}m)",
            replace_existing=True,
            misfire_grace_time=60,
        )
        logger.info(
            "[scheduler] registered %s — every %dm",
            detector.name,
            detector.cadence_minutes,
        )

    return scheduler
