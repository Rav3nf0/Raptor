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
internet is named in the summary. Each new finding carries what Upwind saw (the request, client
IP, process) from the detection's own record: raw["evidence"] and a "seen:" line in the summary.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from urllib.parse import unquote
from datetime import datetime, timedelta, timezone

from shadow_hunter.detectors.base import Detector, mask_ids

logger = logging.getLogger(__name__)

_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# IronWatch's weekly CIS compliance run reads the login banner and local group database on the
# UAT exchange-connectivity hosts every Saturday ~20:30 UTC: 66 of the 69 such Upwind findings
# to 2026-11-08 fell in Sat 20:30-20:39 on exactly these hosts (the other 3 were two other
# hosts at other times). These are attacker recon techniques too, so the suppression needs all
# three: the title, these hosts, and the Saturday 20:25-20:50 UTC window. Anything else reports.
IRONWATCH_RULE = "ironwatch-weekly-cis"
IRONWATCH_TITLES = {"login banner inspection", "local group database inspection"}
IRONWATCH_HOSTS = {"uat-kambala-grpc", "uta-kambala-bse-sap", "uat-interop-prms", "uat-kambala-filednwld",
                   "uta-kambala-nse-dc", "uat-mcxvpn-filednwld", "uat-sify-interop", "uat-sify-nsedc",
                   "kambala-uat-com", "kambala-oms-uat", "uat-bse-sap"}


def ironwatch_window(r: dict) -> bool:
    if str(r.get("title", "")).strip().lower() not in IRONWATCH_TITLES:
        return False
    if str((r.get("resource") or {}).get("name", "")).strip().lower() not in IRONWATCH_HOSTS:
        return False
    try:
        t = datetime.fromisoformat(str(r.get("first_seen", "")).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return False
    return t.weekday() == 5 and t.hour == 20 and 25 <= t.minute <= 50


# Argo CI build nodes: build containers add apt/yum sources, which Upwind raises as "Package
# repository configuration modification" (31 findings in 30 days to 2026-11-13: 28 judged FP,
# 3 unsure, no TP). The 10.193 node subnets are shared with prod (an IP launched by prod-karpenter one day was
# an argo node the next), so the host name proves nothing: CloudTrail must show that the LAST
# launch of that private IP before the event was by the argo-cluster autoscaler, within 24 h.
# A failed CloudTrail lookup suppresses nothing. Replay 14 Oct - 13 Nov: 31 of 31 such findings
# were on argo nodes (launched 3 min to 19.5 h before the event). Other titles seen on
# argo nodes (tooling installed via package manager, Python history overwrite, scanner executed)
# still report.
ARGO_CI_RULE = "argo-ci-package-repo"
ARGO_CI_TITLES = {"package repository configuration modification"}
ARGO_CI_ROLE = "argo-cluster-karpenter"
ARGO_CI_MAX_AGE = timedelta(hours=24)
_NODE_IP = re.compile(r"^ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(\.|$)")


def node_ip(name: str) -> str:
    """10.193.85.69 from an EC2 private DNS name (ip-10-193-85-69.ap-south-1.compute.internal)."""
    m = _NODE_IP.match(str(name or "").strip().lower())
    return ".".join(m.group(i) for i in range(1, 5)) if m else ""


def _ts(s) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def ci_launch_kql(ips: list[str], start: datetime, end: datetime) -> str:
    """Every RunInstances in [start, end] that handed out one of `ips`, with the launching role
    (the role NAME only: the ARN carries the account id)."""
    lst = ", ".join(f'"{ip}"' for ip in ips)
    return f"""AWSCloudTrail
        | where TimeGenerated between (datetime({start:%Y-%m-%dT%H:%M:%SZ}) .. datetime({end:%Y-%m-%dT%H:%M:%SZ}))
        | where EventName == "RunInstances" and ResponseElements has_any ({lst})
        | extend Ips = extract_all(@'privateIpAddress":"([0-9.]+)', ResponseElements)
        | mv-expand Ip = Ips to typeof(string)
        | where Ip in ({lst})
        | project At = TimeGenerated, Ip, Role = extract(@'assumed-role/([^/]+)/', 1, UserIdentityArn)
        | take 2000"""


def attach_ci_launch(rows: list[dict], launches: list[dict]) -> None:
    """Puts on each candidate row the LAST launch of its node IP at or before the event:
    r["ci_launch"] = {"ip", "at", "role"}. Rows with no launch found get nothing."""
    by_ip: dict[str, list[tuple[datetime, str]]] = {}
    for x in launches:
        at = _ts(x.get("At"))
        if at and x.get("Ip"):
            by_ip.setdefault(str(x["Ip"]), []).append((at, str(x.get("Role") or "")))
    for r in rows:
        ip, seen = node_ip((r.get("resource") or {}).get("name", "")), _ts(r.get("first_seen"))
        before = [l for l in by_ip.get(ip, []) if seen and l[0] <= seen]
        if before:
            at, role = max(before)
            r["ci_launch"] = {"ip": ip, "at": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "role": role}


def argo_ci_node(r: dict) -> bool:
    if str(r.get("title", "")).strip().lower() not in ARGO_CI_TITLES:
        return False
    launch, seen = r.get("ci_launch") or {}, _ts(r.get("first_seen"))
    at = _ts(launch.get("at"))
    if not (seen and at) or launch.get("role") != ARGO_CI_ROLE:
        return False
    if launch.get("ip") != node_ip((r.get("resource") or {}).get("name", "")):
        return False
    return timedelta(0) <= seen - at <= ARGO_CI_MAX_AGE


# What Upwind saw, from the detection itself. The mirrored list rows carry only a title, time
# and workload; GET threat-detections/{id} carries triggers[].events[].rawLog with the HTTP
# request, client IP and process (2026-11-24: a "callback receiver" on UAT uplink that the list
# could not explain was, in the evidence, an employee's browser hitting firewall/check?url=
# webhook.site from our NAT). One call per new finding, a handful a day; a failed lookup leaves
# the finding as it was.
EVIDENCE_MAX_ROWS = 30
EVIDENCE_EVENTS = 4
EVIDENCE_CONCURRENCY = 4
_EV_KEY = re.compile(r"^(http\.(method|host|uri|status-code|header\.user-agent|header\.referer)|cf-connecting-ip"
                     r"|http\.x-forwarded-for|dns\..*|.*domain.*|.*query.*|src\.comm|.*cmdline.*|.*command.*"
                     r"|process\..*|.*exe.*|.*file.*|.*path.*|dst\.(ip|port|nat-ip))$", re.I)
_EV_TOP = ("timestamp", "direction", "protocol", "srcIp", "destIp", "destPort")


def _clean(text: str) -> str:
    from shadow_hunter.stories import redact_secrets
    return mask_ids(redact_secrets(str(text)))


def evidence_from(detection: dict | None) -> list[dict]:
    """Up to EVIDENCE_EVENTS distinct evidence events: the labels worth reading (request,
    client, process, domain), secrets redacted and account ids masked."""
    out, seen = [], set()
    for trig in (detection or {}).get("triggers") or []:
        for ev in trig.get("events") or []:
            raw = ev.get("rawLog")
            try:
                log = json.loads(raw) if isinstance(raw, str) else (raw or {})
            except ValueError:
                log = {"message": str(raw)[:300]}
            if not isinstance(log, dict):
                continue
            labels = log.get("labels") if isinstance(log.get("labels"), dict) else {}
            item = {k: log[k] for k in _EV_TOP if log.get(k) not in (None, "")}
            item |= {k: v for k, v in labels.items() if _EV_KEY.match(k) and v not in (None, "")}
            if "message" in log and not labels:
                item["message"] = log["message"]
            item = {k: _clean(unquote(str(v)) if k == "http.uri" else v)[:300] for k, v in item.items()}
            key = json.dumps({k: v for k, v in item.items() if k != "timestamp"}, sort_keys=True)
            if item and key not in seen:
                seen.add(key)
                out.append(item)
            if len(out) >= EVIDENCE_EVENTS:
                return out
    return out


def evidence_line(evidence: list[dict]) -> str:
    """One readable line from the first evidence event, for the finding summary."""
    if not evidence:
        return ""
    e = evidence[0]
    if e.get("http.uri") or e.get("http.host"):
        who = e.get("cf-connecting-ip") or e.get("srcIp", "")
        return " ".join(x for x in (e.get("http.method", ""), e.get("http.status-code", ""),
                                    f"{e.get('http.host', '')}{e.get('http.uri', '')}"[:180],
                                    f"from {who}" if who else "") if x)
    rest = [f"{k}={v}" for k, v in e.items() if k not in ("timestamp", "direction", "protocol")]
    return "; ".join(rest)[:200]


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
        rows = await new_runtime_detections(end - timedelta(hours=lookback_hours), end,
                                            min_severity="MEDIUM", exclude_critical_detections=True)
        await self._add_ci_launches(rows)
        await self._add_evidence(rows)
        return rows

    @staticmethod
    async def _add_evidence(rows: list[dict], fetch=None) -> None:
        """r["evidence"] from each detection's own record, highest severity first, at most
        EVIDENCE_MAX_ROWS per run. No evidence on any failure: nothing is suppressed by it."""
        if fetch is None:
            from edr_triage.upwind_client import get_detection_raw as fetch
        todo = sorted((r for r in rows if not r.get("evidence") and str(r.get("_id") or r.get("id") or "")
                       .startswith(("uwd-", "uwnd-"))),
                      key=lambda r: -_RANK.get(str(r.get("severity", "")).upper(), 0))[:EVIDENCE_MAX_ROWS]
        sem = asyncio.Semaphore(EVIDENCE_CONCURRENCY)

        async def one(r):
            async with sem:
                try:
                    ev = evidence_from(await fetch(str(r.get("_id") or r.get("id"))))
                except Exception as exc:
                    logger.warning("[upwind_threats] evidence lookup failed: %s", exc)
                    return
                if ev:
                    r["evidence"] = ev
        await asyncio.gather(*(one(r) for r in todo))

    @staticmethod
    async def _add_ci_launches(rows: list[dict]) -> None:
        cand = [r for r in rows if str(r.get("title", "")).strip().lower() in ARGO_CI_TITLES
                and node_ip((r.get("resource") or {}).get("name", ""))]
        seen = [t for t in (_ts(r.get("first_seen")) for r in cand) if t]
        if not seen:
            return
        ips = sorted({node_ip(r["resource"]["name"]) for r in cand})[:200]
        try:
            from shadow_hunter.clients import SentinelLogsClient
            launches = await SentinelLogsClient().query(
                ci_launch_kql(ips, min(seen) - ARGO_CI_MAX_AGE, max(seen)), timeout=120)
        except Exception as exc:          # no proof, no suppression: the findings report as usual
            logger.warning("[upwind_threats] CloudTrail launch lookup failed: %s", exc)
            return
        attach_ci_launch(cand, launches)

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
            evidence = next((x["evidence"] for x in [r] + grp if x.get("evidence")), [])
            seen_line = evidence_line(evidence)
            out.append({
                "detector": self.name,
                "severity": _SEV.get(str(r.get("severity", "")).upper(), "medium"),
                "device_id": res.get("host_id") or res.get("upwind_asset_id") or name,
                "device_name": name,
                "account_name": res.get("cloud_account_name", ""),
                "indicator": key[:300],
                "summary": mask_ids(f"Upwind {kind} [{r.get('severity', '')}/{r.get('category', '')}]: "
                                    f"{r.get('title', '')}{times} on {where}{exposed}"
                                    + (f" — seen: {seen_line}" if seen_line else ""))[:400],
                # evidence first: the AI reviewer reads raw clipped to its first few thousand characters
                "raw": {"evidence": evidence}
                       | {k: (str(v) if k == "synced_at" else v) for k, v in r.items() if k not in ("_id", "evidence")}
                       | {"upwind_id": str(r.get("_id") or ""),
                          "upwind_ids": [str(x.get("_id") or x.get("id") or "") for x in grp][:50],
                          "occurrences": len(grp)},
                "mitre_techniques": list(r.get("mitre") or [])[:3],
                "allowlisted_by_rule": (IRONWATCH_RULE if all(ironwatch_window(x) for x in grp)
                                        else ARGO_CI_RULE if all(argo_ci_node(x) for x in grp) else ""),
            })
        return out
