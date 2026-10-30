"""Upwind CNAPP threats new to the hunt window — cloud workloads, Kubernetes, IAM and the
on-prem hosts Upwind's sensors cover, which MDE either can't see or sees differently.

Reads the local Upwind mirror (edr_triage/upwind_mirror.py), never Upwind itself. Profile on
2026-10-06: 590 open detections (Jul 28 onward, 2-4 new a day) and 100 runtime events.
  * CRITICAL detections are left out: Upwind's own Jira integration tickets them and RAPTOR
    triages those tickets with the detection fetched.
  * API-security events (OWASP request-pattern matches, 55 of 100) and LOW severity are left
    out: heuristic and noisy.
  * Only items FIRST SEEN in the window, so the open backlog does not flood the queue; one
    finding per rule title, resource and day, however many events Upwind raised for it.
Upwind's severity carries over (HIGH -> high, MEDIUM -> medium). A resource exposed to the
internet is named in the summary.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shadow_hunter.detectors.base import Detector, mask_ids

_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class UpwindThreatsDetector(Detector):
    name = "upwind_threats"
    mitre_techniques: list[str] = []
    severity = "medium"
    cadence_minutes = 60
    query_name = "upwind_threats"

    def kql(self, lookback_hours: int) -> str:  # not an MDE query; see fetch
        return ""

    async def fetch(self, defender, lookback_hours: int = 24) -> list[dict]:
        from shadow_hunter.clients import MockDefenderClient
        if isinstance(defender, MockDefenderClient):
            return []
        from edr_triage.upwind_mirror import new_runtime_detections
        end = datetime.now(timezone.utc)
        return await new_runtime_detections(end - timedelta(hours=lookback_hours), end,
                                            min_severity="MEDIUM", exclude_critical_detections=True)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        """One finding per (rule title, resource, day). Upwind raises a separate event for each
        occurrence — the same security-group change on one Jenkins role arrived as two events
        (2026-10-07) — and a reviewer needs it once. The finding carries every Upwind id it covers."""
        groups: dict[str, list[dict]] = {}
        for r in rows:
            res = r.get("resource") or {}
            key = "|".join((str(r.get("title", "")).strip().lower(), (res.get("name") or "?").lower(),
                            str(r.get("first_seen", ""))[:10]))
            groups.setdefault(key, []).append(r)
        out = []
        for key, grp in groups.items():
            r = max(grp, key=lambda x: _RANK.get(str(x.get("severity", "")).upper(), 0))
            res = r.get("resource") or {}
            name = res.get("name") or "?"
            kind = "detection" if r.get("kind") == "detection" else "runtime event"
            where = " ".join(x for x in (res.get("type", ""), f"'{name}'") if x) + (
                f" ({res['host_id']})" if res.get("host_id") else "")
            exposed = " — the resource is EXPOSED TO THE INTERNET" if res.get("exposed") else ""
            times = f" ({len(grp)}x)" if len(grp) > 1 else ""
            out.append({
                "detector": self.name,
                "severity": _SEV.get(str(r.get("severity", "")).upper(), "medium"),
                "device_id": res.get("host_id") or res.get("upwind_asset_id") or name,
                "device_name": name,
                "account_name": res.get("cloud_account_name", ""),
                "indicator": key[:300],
                "summary": mask_ids(f"Upwind {kind} [{r.get('severity', '')}/{r.get('category', '')}]: "
                                    f"{r.get('title', '')}{times} on {where}{exposed}")[:400],
                "raw": {k: (str(v) if k == "synced_at" else v) for k, v in r.items() if k != "_id"}
                       | {"upwind_id": str(r.get("_id") or ""),
                          "upwind_ids": [str(x.get("_id") or x.get("id") or "") for x in grp][:50],
                          "occurrences": len(grp)},
                "mitre_techniques": list(r.get("mitre") or [])[:3],
            })
        return out
