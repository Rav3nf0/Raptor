"""Read-only LogsQL queries against VictoriaLogs, for /shadow's edge and app detectors.

VictoriaLogs holds the Cloudflare Logpush stream (source_type:cloudflare, ~30 days), service
logs (ngav1), EKS control-plane and RDS audit logs (cloudwatch), MongoDB Atlas and Kubernetes
events. Nothing is copied into Sentinel: detectors query it in place.

The only reachable endpoint is the internal VictoriaLogs MCP server (streamable-HTTP JSON-RPC);
the raw /select/logsql API isn't exposed. So this speaks just enough MCP: initialize, then
tools/call on its `query` tool, which wraps /select/logsql/query and returns JSON lines.
"""
from __future__ import annotations

import json
import logging
import os

import httpx

logger = logging.getLogger(__name__)

_PROTOCOL = "2025-03-26"


def mcp_url() -> str:
    return os.getenv("VICTORIALOGS_MCP_URL", "https://victoria-logs-mcp.example.com/mcp").strip()


def _decode(resp: httpx.Response) -> dict:
    """A JSON-RPC reply, whether sent as plain JSON or as one SSE `data:` event."""
    text = resp.text.strip()
    if text.startswith(("event:", "data:")):
        text = "\n".join(line[5:].strip() for line in text.splitlines() if line.startswith("data:"))
    return json.loads(text) if text else {}


def parse_lines(text: str) -> list[dict]:
    """The query tool answers with one JSON object per line."""
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


class VictoriaLogsClient:
    def __init__(self, url: str | None = None, timeout: float = 120.0):
        self.url = url or mcp_url()
        self.timeout = timeout

    async def query(self, logsql: str, start: str, end: str, limit: int = 1000) -> list[dict]:
        """Rows of one LogsQL query over [start, end] (RFC3339). Raises on failure — the
        hunter records the error and skips the run, so an unreachable source shows up in
        detector status rather than as a quiet zero."""
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        verify = os.getenv("VICTORIALOGS_VERIFY_SSL", "true").lower() != "false"
        async with httpx.AsyncClient(timeout=self.timeout, verify=verify) as client:
            r = await client.post(self.url, headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": _PROTOCOL, "capabilities": {},
                           "clientInfo": {"name": "deepintel-shadow", "version": "1"}}})
            r.raise_for_status()
            sid = r.headers.get("mcp-session-id")
            if sid:
                headers["Mcp-Session-Id"] = sid
            await client.post(self.url, headers=headers,
                              json={"jsonrpc": "2.0", "method": "notifications/initialized"})
            r = await client.post(self.url, headers=headers, json={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "query", "arguments": {
                    "query": logsql, "start": start, "end": end, "limit": limit}}})
            r.raise_for_status()
        body = _decode(r)
        if body.get("error"):
            raise RuntimeError(f"VictoriaLogs error: {json.dumps(body['error'])[:300]}")
        result = body.get("result") or {}
        text = "\n".join(c.get("text", "") for c in result.get("content") or [] if c.get("type") == "text")
        if result.get("isError"):
            raise RuntimeError(f"VictoriaLogs query failed: {text[:300]}")
        return parse_lines(text)


def literal(pattern: str) -> str:
    """A LogsQL double-quoted string literal (regex or phrase)."""
    return '"' + pattern.replace("\\", "\\\\").replace('"', '\\"') + '"'


def iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def as_list(v) -> list:
    """uniq_values() arrives as a JSON-array string; accept a list or a bare string too."""
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v.strip():
        try:
            out = json.loads(v)
            return out if isinstance(out, list) else [out]
        except ValueError:
            return [v]
    return []


def as_int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0
