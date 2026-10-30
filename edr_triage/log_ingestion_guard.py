"""'Log injestion stopped': close only when every silent table is one humans already retired.

The analytics rule lists Log Analytics tables with no records for 3+ days. Over the 120
days to 2026-10-06 that produced 97 tickets, and every table it ever named was closed False
Positive by analysts — "these tables are not in use", "logs only flow to this table if the
canary token is accessed" — each between 3 and 45 times. None was ever a real outage.

The real outage would be a table that MATTERS going quiet (SigninLogs, DeviceEvents …).
So RAPTOR re-runs the rule's own query at triage time and closes only if every stale table
is on RETIRED_TABLES; any other table — or a query that cannot run — goes to a person,
with the table named. Extend with EDR_RETIRED_TABLES="A,B" once analysts retire another.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

FAMILY = "log injestion stopped"
LABEL = "raptor-log-ingestion"
# Every table analysts closed as unused / canary-only, 120 days to 2026-10-06 (closes).
RETIRED_TABLES = frozenset({
    "SentinelAudit",                     # 45
    "SecureScores",                      # 19
    "CanaryTokens_CL",                   # 18 — canary: silent unless a token is touched
    "Anomalies",                         # 17
    "MDCFileIntegrityMonitoringEvents",  # 11
    "Operation",                         # 11
    "Watchlist",                         # 10
    "SecureScoreControls",               # 10
    "TI_Map_IP_CSL_CL",                  # 7
    "ALB_Forensic_Logs_CL",              # 6
    "AADRiskyUsers",                     # 3
})

QUERY = """Usage
| where TimeGenerated > ago(14d)
| summarize LastRecordReceived = max(TimeGenerated) by DataType
| where LastRecordReceived < ago(3d)
| project TableName = DataType, LastRecordReceived"""


def applies(alert_name: str) -> bool:
    return (alert_name or "").strip().casefold() == FAMILY


def retired() -> frozenset:
    extra = {t.strip() for t in os.getenv("EDR_RETIRED_TABLES", "").split(",") if t.strip()}
    return RETIRED_TABLES | extra


def decide(stale: list[str] | None) -> tuple[bool, str]:
    """(close, reason). Pure."""
    if stale is None:
        return False, "the ingestion check could not run"
    if not stale:
        return False, "no table is silent now — the alert's cause could not be confirmed"
    live = sorted(t for t in stale if t not in retired())
    if live:
        return False, "these tables have stopped and are NOT known to be retired: " + ", ".join(live)
    return True, f"every silent table is one analysts retired: {', '.join(sorted(stale))}"


async def stale_tables() -> list[str] | None:
    """Tables with no records for 3+ days, from the rule's own query. None on failure."""
    try:
        from lib.mde_client import run_sentinel_query
        res = run_sentinel_query(QUERY)
        if hasattr(res, "__await__"):
            res = await res
        rows, err = res
        if err:
            logger.warning("log_ingestion_guard: query failed: %s", err)
            return None
        return sorted({str(r.get("TableName") or "") for r in rows or []} - {""})
    except Exception as exc:
        logger.warning("log_ingestion_guard: query failed: %s", exc)
        return None


def comment(closed: bool, reason: str, stale: list[str] | None) -> str:
    head = ("*RAPTOR closed this as a False Positive.*" if closed
            else "*RAPTOR did not close this: a person should check it.*")
    return (f"{head}\n\n{reason[0].upper() + reason[1:]}.\n\n"
            + ("Analysts have closed every one of these tables as not in use or canary-only. "
               "Reopen this ticket if one of them should be sending data."
               if closed else
               "A table that is not on RAPTOR's retired list has stopped sending data — that "
               "may be a real collection outage.")
            + "\n\n[Auto-triaged by RAPTOR]")
