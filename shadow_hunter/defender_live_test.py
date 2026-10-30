"""The live MDE client must never let a stalled login hang (or freeze) its replica.

2026-09-30: msal's synchronous token call, made directly from a coroutine with no timeout,
stalled and froze the replica's event loop — behaviour runs hung at their MDE query and went
stale. Token acquisition now runs off the loop with a hard cap.

Run: python -m pytest shadow_hunter/defender_live_test.py -q
"""
from __future__ import annotations

import asyncio
import time

import pytest

from shadow_hunter.clients import defender_live


class _Stub(defender_live.DefenderClient):
    def __init__(self, token_delay: float):
        self._ssl_verify = True
        self._delay = token_delay

    def _get_token(self) -> str:
        time.sleep(self._delay)   # a blocking, stalled msal call
        return "t"


def test_a_stalled_token_request_fails_fast(monkeypatch):
    monkeypatch.setattr(defender_live, "_TOKEN_TIMEOUT_S", 0.3)
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(_Stub(token_delay=2).hunt("q", kql="DeviceInfo | take 1"))


def test_the_event_loop_keeps_running_while_a_token_is_fetched(monkeypatch):
    monkeypatch.setattr(defender_live, "_TOKEN_TIMEOUT_S", 0.5)
    ticks = []

    async def ticker():
        for _ in range(5):
            ticks.append(1)
            await asyncio.sleep(0.05)

    async def main():
        t = asyncio.create_task(ticker())
        with pytest.raises(asyncio.TimeoutError):
            await _Stub(token_delay=2).hunt("q", kql="x")
        await t

    asyncio.run(main())
    assert len(ticks) == 5    # the loop was not blocked by the synchronous token call


def test_msal_apps_are_shared_per_credential_set(monkeypatch):
    monkeypatch.setattr(defender_live.msal, "ConfidentialClientApplication",
                        lambda **kw: object())   # no network for a fake tenant
    monkeypatch.setattr(defender_live, "_APPS", {})
    a = defender_live._msal_app("t1", "c1", "s", True)
    assert defender_live._msal_app("t1", "c1", "s", True) is a
    assert defender_live._msal_app("t2", "c1", "s", True) is not a


# ── rate limiting ───────────────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError(f"{self.status_code}", request=None, response=None)


def _patch_post(monkeypatch, responses):
    import httpx
    calls = []

    async def fake_post(self, url, **kw):
        calls.append(url)
        return responses[min(len(calls) - 1, len(responses) - 1)]
    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    return calls


def test_a_429_is_retried_after_the_advised_wait(monkeypatch):
    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)
    monkeypatch.setattr(defender_live.asyncio, "sleep", fake_sleep)
    calls = _patch_post(monkeypatch, [_Resp(429, headers={"Retry-After": "7"}), _Resp(200, {"Results": [{"a": 1}]})])
    rows = asyncio.run(_Stub(token_delay=0).hunt("q", kql="DeviceInfo | take 1"))
    assert rows == [{"a": 1}] and len(calls) == 2 and sleeps == [7.0]


def test_persistent_429_still_fails_after_the_retries(monkeypatch):
    import httpx

    async def fake_sleep(s):
        return None
    monkeypatch.setattr(defender_live.asyncio, "sleep", fake_sleep)
    calls = _patch_post(monkeypatch, [_Resp(429)])
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(_Stub(token_delay=0).hunt("q", kql="DeviceInfo | take 1"))
    assert len(calls) == defender_live._RATE_LIMIT_RETRIES + 1
