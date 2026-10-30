"""Mock Sentinel client.

In live mode this would POST to:
https://management.azure.com/subscriptions/.../Microsoft.SecurityInsights/incidents/{id}
"""
from __future__ import annotations

from uuid import uuid4


class MockSentinelClient:
    def __init__(self) -> None:
        self._incidents: dict[str, dict] = {}

    async def create_incident_from_finding(self, finding: dict) -> str:
        incident_id = f"INC-{uuid4().hex[:8].upper()}"
        self._incidents[incident_id] = {
            "id": incident_id,
            "title": f"[SentinelShadow] {finding.get('summary', '')}",
            "severity": finding.get("severity", "Low").capitalize(),
            "status": "New",
            "source_finding": finding.get("id"),
        }
        return incident_id

    async def find_by_device(self, device_id: str) -> list[dict]:
        return [i for i in self._incidents.values() if device_id in str(i)]
