"""Mock Defender client — reads CSVs from shadow_hunter/data/.

In live mode this would be replaced with a real httpx client hitting
https://api.security.microsoft.com/api/advancedhunting/run
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from shadow_hunter.config import get_shadow_config


def _parse_array(value: str) -> list[str]:
    """CSV arrays look like ["192.168.75.11"] but may be double-quoted."""
    if not value:
        return []
    cleaned = value.replace('""', '"').strip()
    if not cleaned or cleaned in ('""', "''"):
        return []
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            return [str(x) for x in parsed if x]
    except (json.JSONDecodeError, ValueError):
        pass
    return [cleaned.strip('[]"\'').strip()]


class MockDefenderClient:
    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or get_shadow_config().data_dir

    async def hunt(self, query_name: str, kql: str = "", lookback_hours: int = 24,
                   timeout: float = 60) -> list[dict]:
        """Resolve a query name to a CSV file under data/."""
        path = self.data_dir / f"{query_name}.csv"
        if not path.exists():
            return []
        # utf-8-sig strips the BOM that Excel / PowerQuery love adding
        with path.open("r", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            rows = []
            for row in reader:
                for key, value in list(row.items()):
                    if key is None or not isinstance(value, str):
                        continue
                    if value.startswith('"[') or value.startswith("["):
                        row[key] = _parse_array(value)
                row.pop(None, None)
                rows.append(row)
            return rows
