"""Live Microsoft Defender for Endpoint client.

Authenticates via Azure AD client-credentials flow (msal) and runs
Advanced Hunting KQL queries against the Defender API.
"""
from __future__ import annotations

import asyncio
import logging

import httpx
import msal
import requests

from shadow_hunter.config import get_shadow_config

logger = logging.getLogger(__name__)

_MDE_SCOPE = ["https://api.security.microsoft.com/.default"]
_MDE_URL = "https://api.security.microsoft.com/api/advancedhunting/run"


# One msal app per credential set, so its in-memory token cache is reused. Building a new app
# per DefenderClient (every hunt did) meant a fresh token request to login.microsoftonline.com
# on every single query.
_APPS: dict[tuple, msal.ConfidentialClientApplication] = {}
_MSAL_TIMEOUT_S = 30
_TOKEN_TIMEOUT_S = 40


def _msal_app(tenant_id: str, client_id: str, client_secret: str, ssl_verify: bool):
    key = (tenant_id, client_id, ssl_verify)
    if key not in _APPS:
        # MSAL uses `requests` internally; pass a custom session when SSL
        # verification is disabled (e.g. corporate SSL-inspection proxy).
        http_client: requests.Session | None = None
        if not ssl_verify:
            http_client = requests.Session()
            http_client.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _APPS[key] = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            http_client=http_client,
            # requests has NO default timeout: a stalled token request waited forever.
            timeout=_MSAL_TIMEOUT_S,
        )
    return _APPS[key]


_RATE_LIMIT_RETRIES = 2


def _retry_after(value: str | None, default: float) -> float:
    try:
        return min(max(float(value), 1.0), 90.0)
    except (TypeError, ValueError):
        return default


class DefenderClient:
    def __init__(self) -> None:
        cfg = get_shadow_config()
        self._ssl_verify = cfg.ssl_verify
        self._app = _msal_app(cfg.tenant_id, cfg.client_id, cfg.client_secret, cfg.ssl_verify)

    def _get_token(self) -> str:
        result = self._app.acquire_token_for_client(scopes=_MDE_SCOPE)
        if "access_token" not in result:
            error = result.get("error_description") or result.get("error")
            raise RuntimeError(f"Defender auth failed: {error}")
        return result["access_token"]

    async def _get_token_async(self) -> str:
        # msal is synchronous. Called directly from a coroutine it blocked the replica's whole
        # event loop while it waited — RAPTOR's triage included — and with no timeout a stalled
        # login froze the replica until it was restarted (behaviour runs hung at their MDE query
        # and went stale, 2026-09-30). Off the loop, and capped.
        return await asyncio.wait_for(asyncio.to_thread(self._get_token), timeout=_TOKEN_TIMEOUT_S)

    async def hunt(self, query_name: str, kql: str = "", lookback_hours: int = 24,
                   timeout: float = 60) -> list[dict]:
        """Run a KQL query against Defender Advanced Hunting.

        query_name is ignored in live mode (it's only used by the mock).
        kql must be provided; lookback_hours is already baked into the kql string.
        """
        if not kql:
            logger.warning("[defender] no KQL provided for %s — skipping", query_name)
            return []

        token = await self._get_token_async()

        async def _post() -> httpx.Response:
            async with httpx.AsyncClient(timeout=timeout, verify=self._ssl_verify) as client:
                return await client.post(
                    _MDE_URL,
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    json={"Query": kql},
                )

        # Advanced hunting allows ~45 calls a minute per tenant, shared with RAPTOR's hunts; a
        # burst (every detector at pod start, 2026-09-30) came back 429. Wait as told and retry.
        for attempt in range(_RATE_LIMIT_RETRIES + 1):
            # httpx's timeout is per phase (connect/read/write/pool); this is the whole-call ceiling.
            resp = await asyncio.wait_for(_post(), timeout=timeout + 30)
            if resp.status_code != 429 or attempt == _RATE_LIMIT_RETRIES:
                break
            wait = _retry_after(resp.headers.get("Retry-After"), default=15 * (attempt + 1))
            logger.warning("[defender] %s: rate limited, retrying in %ss", query_name, wait)
            await asyncio.sleep(wait)
        resp.raise_for_status()
        data = resp.json()

        results = data.get("Results", [])
        logger.info("[defender] %s: %d rows returned", query_name, len(results))
        return results
