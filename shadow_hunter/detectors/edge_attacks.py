"""Attack-shaped requests at the Cloudflare edge that the ORIGIN answered 2xx.

The WAF blocks most probing (3,205 traversal attempts on api.example.com got 403 during the
DART intrusion). What matters is the request that got through: an attack pattern in the
path that our own service accepted. On 2026-10-19 00:37-02:45 UTC two IPs used the gateway
bypass `/order-api/open/..%2fv0/order` on service.example.com and got 200 on POST x263, PUT,
PATCH and DELETE — nothing in Defender, Sentinel or Upwind saw it.

Reads VictoriaLogs (source_type:cloudflare) in place, through shadow_hunter.clients.victorialogs.
The Cloudflare feed carries path, method and statuses but no query string, user agent, WAF
action or request headers, so this matches on the PATH only.

Replay on 2026-10-19 data: the last 24 h had only the DART requests (10 groups); busy
weekday windows had 0-1 (a /blog/phpmyadmin/ hit on algoverse), plus Oct 14's Spring Cloud
Gateway actuator route-injection POSTs on mutual-funds that came back 2xx.

One finding per client IP, host, method and day. A write method answered 2xx is critical.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shadow_hunter.detectors.base import Detector, mask_ids

# Traversal (plain, encoded, double-encoded), null bytes, secrets and repo files, script or
# SQL injection, management endpoints and common admin panels.
ATTACK_PATH_RE = (
    r"(?i)(\.\.(%2f|%5c|/|\\)|%2e%2e|%252e|%00|/etc/passwd|win\.ini|/\.env($|[./])|/\.git/"
    r"|<script|%3cscript|union(%20|\+)+select|/actuator/|/wp-admin|/phpmyadmin|/cgi-bin/)"
)
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
WINDOW_HOURS = 2          # every 30 min over the last 2 h: a missed run or two is still covered


def _lit(pattern: str) -> str:
    """A LogsQL double-quoted string literal."""
    return '"' + pattern.replace("\\", "\\\\").replace('"', '\\"') + '"'


def logsql() -> str:
    return (f"source_type:cloudflare ClientRequestPath:~{_lit(ATTACK_PATH_RE)} OriginResponseStatus:~\"^2\" "
            "| stats by (ClientIP, ClientCountry, ClientRequestHost, ClientRequestMethod) count() hits, "
            "count_uniq(ClientRequestPath) paths, uniq_values(ClientRequestPath) limit 5 sample, "
            "uniq_values(OriginResponseStatus) limit 5 statuses, min(_time) first, max(_time) last "
            "| sort by (hits desc) | limit 500")


class EdgeAttacksDetector(Detector):
    name = "edge_attacks"
    mitre_techniques = ["T1190"]       # Exploit Public-Facing Application
    severity = "high"
    cadence_minutes = 30
    query_name = "edge_attacks"

    def kql(self, lookback_hours: int) -> str:  # not an MDE query; see fetch
        return ""

    async def fetch(self, defender, lookback_hours: int = 24) -> list[dict]:
        from shadow_hunter.clients import MockDefenderClient
        if isinstance(defender, MockDefenderClient):
            return []
        from shadow_hunter.clients.victorialogs import VictoriaLogsClient
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=WINDOW_HOURS)
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        return await VictoriaLogsClient().query(logsql(), start.strftime(fmt), end.strftime(fmt), limit=500)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            ip, host = str(r.get("ClientIP") or "?"), str(r.get("ClientRequestHost") or "?")
            method = str(r.get("ClientRequestMethod") or "?").upper()
            day = str(r.get("first") or "")[:10]
            try:
                hits = int(r.get("hits") or 0)
            except (TypeError, ValueError):
                hits = 0
            sample = r.get("sample") or []
            if isinstance(sample, str):
                import json
                try:
                    sample = json.loads(sample)
                except ValueError:
                    sample = [sample]
            write = method in WRITE_METHODS
            what = "WRITE request(s)" if write else "request(s)"
            out.append({
                "detector": self.name,
                "severity": "critical" if write else "high",
                "device_id": ip,
                "device_name": host,
                "account_name": "",
                "indicator": f"{ip}|{host}|{method}|{day}",
                "summary": mask_ids(
                    f"{hits} attack-shaped {method} {what} from {ip} ({str(r.get('ClientCountry') or '?').upper()}) "
                    f"to {host} were ANSWERED 2xx by the origin — e.g. {sample[0] if sample else '?'}")[:400],
                "raw": {"client_ip": ip, "country": r.get("ClientCountry"), "host": host, "method": method,
                        "hits": hits, "distinct_paths": r.get("paths"), "sample_paths": sample[:5],
                        "origin_statuses": r.get("statuses"), "first": r.get("first"), "last": r.get("last"),
                        "source": "victorialogs:cloudflare"},
                "mitre_techniques": list(self.mitre_techniques),
            })
        return out
