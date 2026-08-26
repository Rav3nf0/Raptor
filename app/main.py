"""
RAPTOR — MVC entrypoint (open-source edition).

Autonomous L1 alert triage: polls a ticketing source, classifies alerts, runs a
ReAct agent loop behind a data-sovereignty boundary, and records verdicts + a
tiered institutional memory (SCG). Config from env; MongoDB via Beanie.
"""
import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI

from lib.config import get_config, reset_config
from app.database import init_db, close_db
from app.views.auth_views import router as auth_router
from app.views.edr_triage_views import router as edr_triage_router
from app.views.memory_views import router as memory_router


# Set to True once config + DB init have completed.
_ready: bool = False


def _demo_mode() -> bool:
    return os.getenv("DEMO_MODE", "false").lower() == "true"


async def _run_edr_triage() -> None:
    """EDR triage background service — polls the ticketing source every N minutes.

    With no credentials configured the poller returns no tickets and idles, so a
    credential-free demo is inert here (drive triage via /api/edr-triage/run-synthetic).
    """
    while not _ready:
        await asyncio.sleep(0.5)
    try:
        from edr_triage.pipeline import run_once
        from edr_triage.config import get_edr_config
        cfg = get_edr_config()
        logging.getLogger("edr_triage.service").info(
            "EDR triage service started — poll_interval=%ds dry_run=%s",
            cfg.poll_interval_seconds, cfg.dry_run,
        )
        while True:
            try:
                await run_once(cfg)
            except Exception:
                logging.getLogger("edr_triage.service").exception("EDR triage cycle error")
            await asyncio.sleep(cfg.poll_interval_seconds)
    except asyncio.CancelledError:
        pass
    except Exception:
        logging.getLogger("edr_triage.service").exception("EDR triage service crashed")


async def _run_jira_closure_poller() -> None:
    """Closure poller — compares AI shadow verdicts against L1 outcomes on close."""
    while not _ready:
        await asyncio.sleep(0.5)
    try:
        from edr_triage.jira_closure_poller import run_forever
        await run_forever(interval_seconds=300)
    except asyncio.CancelledError:
        pass
    except Exception:
        logging.getLogger("edr_triage.closure_poller").exception("Closure poller crashed")


async def _run_scg_decay() -> None:
    """Daily SCG memory decay — ages out stale institutional memory. Idempotent.

    Disable via SCG_DECAY_ENABLED=false.
    """
    _log = logging.getLogger(__name__)
    if os.getenv("SCG_DECAY_ENABLED", "true").lower() != "true":
        _log.info("SCG decay disabled (SCG_DECAY_ENABLED=false)")
        return
    while not _ready:
        await asyncio.sleep(0.5)
    while True:
        try:
            from entity_graph.memory import apply_decay
            updated = await apply_decay()
            _log.info("SCG decay: %d memories decayed/expired", updated)
        except Exception:
            _log.warning("SCG decay failed", exc_info=True)
        await asyncio.sleep(24 * 3600)


async def _run_scg_drift() -> None:
    """Daily drift detection — surface AI-vs-human divergence as propose-only
    playbook/allowlist suggestions (never auto-applied). Disable via SCG_DRIFT_ENABLED=false.
    """
    _log = logging.getLogger(__name__)
    if os.getenv("SCG_DRIFT_ENABLED", "true").lower() != "true":
        _log.info("SCG drift detection disabled (SCG_DRIFT_ENABLED=false)")
        return
    while not _ready:
        await asyncio.sleep(0.5)
    while True:
        try:
            from edr_triage.playbook_suggester import analyze_divergences
            summary = await analyze_divergences(lookback_days=14, min_mismatches=3)
            _log.info(
                "SCG drift: scanned %d mismatches, queued %d suggestions",
                summary.get("mismatches_scanned", 0), summary.get("suggestions_created", 0),
            )
        except Exception:
            _log.warning("SCG drift detection failed", exc_info=True)
        try:
            from edr_triage.allowlist_suggester import analyze_fp_clusters
            al = await analyze_fp_clusters(lookback_days=30, min_count=3)
            _log.info(
                "Allowlist suggest: scanned %d mismatches, queued %d suggestions",
                al.get("mismatches_scanned", 0), al.get("suggestions_created", 0),
            )
        except Exception:
            _log.warning("Allowlist suggestion mining failed", exc_info=True)
        await asyncio.sleep(24 * 3600)


async def _do_startup() -> None:
    """Config + DB init, off the lifespan critical path so /health responds fast."""
    _log = logging.getLogger(__name__)
    try:
        reset_config()
        await asyncio.to_thread(get_config)
        try:
            await init_db()
        except Exception as e:
            _log.warning("MongoDB unavailable at startup: %s", e)
    except Exception as e:
        _log.error("Startup init failed: %s", e)
    finally:
        global _ready
        _ready = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    for _name in ("edr_triage", "edr_triage.service", "edr_triage.closure_poller", "app.main"):
        _lg = logging.getLogger(_name)
        _lg.setLevel(logging.INFO)
        _lg.addHandler(_handler)
        _lg.propagate = False

    tasks = [asyncio.create_task(_do_startup(), name="startup")]
    # In demo mode the poller/pollers add only log noise (no creds) — skip them so a
    # credential-free run is quiet. Drive triage via /api/edr-triage/run-synthetic.
    if not _demo_mode():
        tasks += [
            asyncio.create_task(_run_edr_triage(),          name="edr-triage"),
            asyncio.create_task(_run_jira_closure_poller(), name="jira-closure-poller"),
        ]
    tasks += [
        asyncio.create_task(_run_scg_decay(), name="scg-decay"),
        asyncio.create_task(_run_scg_drift(), name="scg-drift"),
    ]

    yield

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await close_db()


app = FastAPI(
    title="RAPTOR",
    description="Autonomous L1 alert triage with a data-sovereignty boundary and institutional memory",
    lifespan=lifespan,
)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import RedirectResponse as StarletteRedirect

_PUBLIC_PATHS = {"/login", "/health", "/health-check", "/metrics"}


class _AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        path = request.url.path
        if request.method == "OPTIONS" or path in _PUBLIC_PATHS:
            return await call_next(request)
        from app.auth import verify_token, refresh_session_cookie, _COOKIE_NAME
        token = request.cookies.get(_COOKIE_NAME)
        username = verify_token(token) if token else None
        if not username:
            return StarletteRedirect(url="/login", status_code=302)
        response = await call_next(request)
        refresh_session_cookie(response, username)
        return response


app.add_middleware(_AuthMiddleware)

app.include_router(auth_router)
app.include_router(edr_triage_router)
app.include_router(memory_router)


@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/edr-triage", status_code=302)


@app.get("/health")
async def health():
    return {"status": "ok", "app": "raptor"}


@app.api_route("/health-check", methods=["GET", "OPTIONS"])
async def health_check():
    return {"status": "ok", "app": "raptor"}
