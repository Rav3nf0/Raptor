"""Edge attacks via VictoriaLogs: the MCP client and the 2xx-on-attack-path detector."""
from __future__ import annotations

import asyncio
import json
import re

import pytest

from shadow_hunter.clients import victorialogs as VL
from shadow_hunter.detectors import DETECTORS
from shadow_hunter.detectors.edge_attacks import ATTACK_PATH_RE, EdgeAttacksDetector, logsql


# ── the path pattern ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/order-api/open/..%2fv0/order",                                  # ATLAS 2026-10-19
    "/pledge-margins/v1/open/..%2F..%2Fv2/pledge-unpledge-request",
    "/mutual-funds/open/actuato%72;%2f%2e%2e/gateway/routes/x",       # Oct 14 actuator bypass
    "/mutual-funds/open/actuator/gateway/routes/x",
    "/static/../../etc/passwd", "/app/.env", "/repo/.git/config", "/a%00.jsp",
    "/search/<script>alert(1)</script>", "/items/1%20union%20select%201",
])
def test_attack_paths_match(path):
    assert re.search(ATTACK_PATH_RE, path)


@pytest.mark.parametrize("path", [
    "/order-api/v1/order", "/pledge-margins/v1/pledge-timing", "/market-quote/ltp",
    "/environment/settings", "/github/oauth", "/v2/login/authorization/token",
])
def test_ordinary_paths_do_not_match(path):
    assert not re.search(ATTACK_PATH_RE, path)


def test_the_logsql_literal_round_trips_to_the_same_regex():
    q = logsql()
    lit = re.search(r'ClientRequestPath:~"((?:[^"\\]|\\.)*)"', q).group(1)
    assert json.loads(f'"{lit}"') == ATTACK_PATH_RE      # LogsQL and JSON share this escaping
    assert 'OriginResponseStatus:~"^2"' in q and "source_type:cloudflare" in q


# ── findings ───────────────────────────────────────────────────────────────────

def _row(method, ip="203.0.113.10", hits="263", sample=None):
    return {"ClientIP": ip, "ClientCountry": "in", "ClientRequestHost": "service.example.com",
            "ClientRequestMethod": method, "hits": hits, "paths": "3",
            "sample": sample if sample is not None else json.dumps(["/order-api/open/..%2fv0/order"]),
            "statuses": '["200"]', "first": "2026-10-19T00:38:48Z", "last": "2026-10-19T02:45:33Z"}


def test_a_write_answered_2xx_is_critical_and_a_read_is_high():
    f = EdgeAttacksDetector().to_findings([_row("POST"), _row("GET", hits="10")])
    assert [x["severity"] for x in f] == ["critical", "high"]
    assert f[0]["indicator"] == "203.0.113.10|service.example.com|POST|2026-10-19"
    assert f[0]["device_name"] == "service.example.com" and f[0]["device_id"] == "203.0.113.10"
    assert "/order-api/open/..%2fv0/order" in f[0]["summary"] and "WRITE" in f[0]["summary"]
    assert f[0]["raw"]["sample_paths"] == ["/order-api/open/..%2fv0/order"]
    assert f[0]["mitre_techniques"] == ["T1190"]


def test_sample_may_arrive_as_a_list_or_a_plain_string():
    f = EdgeAttacksDetector().to_findings([_row("PUT", sample=["/x/..%2fy"]), _row("DELETE", sample="/z/..%2f")])
    assert f[0]["raw"]["sample_paths"] == ["/x/..%2fy"] and f[1]["raw"]["sample_paths"] == ["/z/..%2f"]


def test_mock_mode_never_calls_out():
    from shadow_hunter.clients import MockDefenderClient
    assert asyncio.run(EdgeAttacksDetector().fetch(MockDefenderClient())) == []


def test_registered_everywhere():
    assert any(d.name == "edge_attacks" for d in DETECTORS)
    import inspect
    from app.views import shadow_views
    assert "edge_attacks:" in inspect.getsource(shadow_views)
    from shadow_hunter.ai_triage import DETECTOR_GUIDE
    assert "edge_attacks" in DETECTOR_GUIDE


# ── the MCP client ─────────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, body, headers=None, sse=False):
        self.headers = headers or {}
        self.text = ("event: message\ndata: " + json.dumps(body)) if sse else json.dumps(body)
    def raise_for_status(self): pass


def _patch(monkeypatch, final_body, sse=False):
    calls = []

    class _Client:
        def __init__(self, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, headers=None, json=None):
            calls.append((json or {}).get("method"))
            if json.get("method") == "initialize":
                return _Resp({"jsonrpc": "2.0", "id": 1, "result": {}}, {"mcp-session-id": "s1"})
            if json.get("method") == "tools/call":
                assert headers.get("Mcp-Session-Id") == "s1"
                assert json["params"]["name"] == "query"
                return _Resp(final_body, sse=sse)
            return _Resp({})
    monkeypatch.setattr(VL.httpx, "AsyncClient", _Client)
    return calls


@pytest.mark.parametrize("sse", [False, True])
def test_query_returns_rows_from_json_lines(monkeypatch, sse):
    text = '{"hits":"3","ClientIP":"1.2.3.4"}\n{"hits":"1","ClientIP":"5.6.7.8"}\n'
    calls = _patch(monkeypatch, {"jsonrpc": "2.0", "id": 2,
                                 "result": {"content": [{"type": "text", "text": text}]}}, sse=sse)
    rows = asyncio.run(VL.VictoriaLogsClient(url="https://x/mcp").query("q", "a", "b"))
    assert [r["ClientIP"] for r in rows] == ["1.2.3.4", "5.6.7.8"]
    assert calls == ["initialize", "notifications/initialized", "tools/call"]


@pytest.mark.parametrize("body", [
    {"jsonrpc": "2.0", "id": 2, "error": {"code": -1, "message": "bad"}},
    {"jsonrpc": "2.0", "id": 2, "result": {"isError": True, "content": [{"type": "text", "text": "parse error"}]}},
])
def test_errors_raise_so_the_run_is_recorded_as_failed(monkeypatch, body):
    _patch(monkeypatch, body)
    with pytest.raises(RuntimeError):
        asyncio.run(VL.VictoriaLogsClient(url="https://x/mcp").query("q", "a", "b"))
