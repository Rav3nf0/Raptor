"""Read-only Log Analytics queries against the Sentinel workspace, for /shadow's cloud detectors.

Uses the workspace config and management token RAPTOR's Sentinel enrichment already queries
with (lib.mde_client). Deliberately not lib.mde_client.run_sentinel_query: that one sends a
failing query to an LLM to auto-fix it, which a scheduled detector must never do. Log Analytics
has its own limits, separate from the MDE advanced-hunting CPU quota shared with RAPTOR.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger(__name__)


def parse_tables(body: dict) -> list[dict]:
    """First result table as dicts. The management-API endpoint answers in PascalCase
    (Tables/Columns/ColumnName/Rows), the direct Log Analytics API in camelCase."""
    tables = body.get("tables") or body.get("Tables") or []
    if not tables:
        return []
    t = tables[0]
    cols = [c.get("name") or c.get("ColumnName") for c in (t.get("columns") or t.get("Columns") or [])]
    return [dict(zip(cols, row)) for row in (t.get("rows") or t.get("Rows") or [])]


class SentinelLogsClient:
    async def query(self, kql: str, timeout: int = 180) -> list[dict]:
        """Rows of one KQL query. Raises on failure — the hunter logs and skips the run."""
        return await asyncio.wait_for(self._query(kql, timeout), timeout=timeout + 30)

    async def _query(self, kql: str, timeout: int) -> list[dict]:
        from lib.mde_client import MDE_VERIFY_SSL, _sentinel_query_url, get_management_token
        url = _sentinel_query_url()
        if not url:
            raise RuntimeError("Sentinel workspace not configured")
        token = await get_management_token()
        if not token:
            raise RuntimeError("management token acquisition failed")
        async with httpx.AsyncClient(timeout=timeout, verify=MDE_VERIFY_SSL) as client:
            resp = await client.post(url, json={"query": kql},
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        if resp.status_code >= 400:
            raise RuntimeError(f"Log Analytics {resp.status_code}: {resp.text[:300]}")
        return parse_tables(resp.json())
