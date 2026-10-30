"""hunt_vlogs — edge, Kubernetes and database context from VictoriaLogs for one alert.

Read-only, summarised. VictoriaLogs holds what Sentinel and Defender don't: every Cloudflare
request at the edge (~30 days), the EKS prod API audit trail and the Aurora audit logs of
every prod database. Queried in place through the internal VictoriaLogs MCP; nothing is
copied anywhere. The window is centred on the alert (alert_time is injected by the loop).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from agent_tools.registry import register

_IP_RE = re.compile(r"^[0-9a-fA-F:.]{3,45}$")
_SAFE_RE = re.compile(r"^[A-Za-z0-9@._:/+=-]{1,200}$")
_MAX_WINDOW_H = 72


def _window(alert_time: str, window_hours) -> tuple[str, str]:
    from shadow_hunter.clients.victorialogs import iso
    try:
        w = max(1, min(int(window_hours or 24), _MAX_WINDOW_H))
    except (TypeError, ValueError):
        w = 24
    try:
        anchor = datetime.fromisoformat(str(alert_time).replace("Z", "+00:00")) if alert_time else None
    except ValueError:
        anchor = None
    if anchor is None:
        end = datetime.now(timezone.utc)
        return iso(end - timedelta(hours=w)), iso(end)
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    return iso(anchor - timedelta(hours=w)), iso(min(anchor + timedelta(hours=w), datetime.now(timezone.utc)))


def _edge_query(ip: str, host: str) -> str:
    from shadow_hunter.clients.victorialogs import literal
    from shadow_hunter.detectors.edge_attacks import ATTACK_PATH_RE
    f = ["source_type:cloudflare"]
    if ip:
        f.append(f"ClientIP:={literal(ip)}")
    if host:
        f.append(f"ClientRequestHost:={literal(host)}")
    return (" ".join(f) + " | stats by (ClientRequestHost, ClientRequestMethod, EdgeResponseStatus, OriginResponseStatus) "
            f"count() n, count() if (ClientRequestPath:~{literal(ATTACK_PATH_RE)}) attack_paths, "
            "uniq_values(ClientRequestPath) limit 5 sample_paths, uniq_values(ClientIP) limit 5 client_ips, "
            "uniq_values(ClientCountry) limit 3 countries, min(_time) first, max(_time) last "
            "| sort by (n desc) | limit 40")


def _eks_query(ip: str, user: str) -> str:
    from shadow_hunter.clients.victorialogs import literal
    from shadow_hunter.detectors.eks_audit import BASE, UNPACK
    f = [BASE] + [f"_msg:{literal(v)}" for v in (user, ip) if v]
    return (" ".join(f) + f" {UNPACK} "
            "| stats by (user.username, verb, objectRef.resource, objectRef.subresource, responseStatus.code) count() n, "
            "uniq_values(objectRef.namespace) limit 5 namespaces, uniq_values(objectRef.name) limit 5 names, "
            "uniq_values(sourceIPs) limit 3 ips, uniq_values(userAgent) limit 2 agents, min(_time) first, max(_time) last "
            "| sort by (n desc) | limit 40")


def _rds_query(ip: str, user: str, host: str) -> str:
    from shadow_hunter.clients.victorialogs import literal
    from shadow_hunter.detectors.rds_audit import BASE, EXTRACT
    f = [BASE]
    if host:
        f.append(f"log_group:~{literal('/' + re.escape(host) + '/')}")
    f += [f"_msg:{literal(v)}" for v in (user, ip) if v]
    post = []
    if user:
        post.append(f"dbuser:={literal(user)}")
    if ip:
        post.append(f"client:={literal(ip)}")
    return (" ".join(f) + f" {EXTRACT} " + (f"| filter {' '.join(post)} " if post else "")
            + "| stats by (log_group, dbuser, client, op) count() n, uniq_values(_msg) limit 3 sample, "
            "min(_time) first, max(_time) last | sort by (n desc) | limit 40")


@register(
    name="hunt_vlogs",
    description=(
        "Edge, Kubernetes and database activity around this alert from VictoriaLogs — data Defender and "
        "Sentinel do not have. source='edge': every Cloudflare request by client `ip` and/or `host` (method, "
        "edge/origin status, attack-shaped paths, sample paths) — use for an external IP, an API host, or "
        "'did this IP reach our public apps and get a 2xx?'. source='eks': the EKS prod API audit for a "
        "`user` (email/IAM principal) or source `ip` (verbs, resources, exec/secrets/RBAC, HTTP codes). "
        "source='rds': Aurora audit for a database `user`, client `ip` and/or cluster `host` (connects, "
        "failed logins, DDL/DCL statements, passwords redacted). Returns grouped counts, not raw logs. "
        "Zero rows means no matching activity in the window — inconclusive for an IP that never touches "
        "these systems, not proof of benign."
    ),
    parameters={
        "type": "object",
        "properties": {
            "source": {"type": "string", "enum": ["edge", "eks", "rds"]},
            "ip": {"type": "string", "description": "Client/source IP"},
            "user": {"type": "string", "description": "User email, IAM principal or database user"},
            "host": {"type": "string", "description": "edge: request host (e.g. service.example.com); rds: cluster name"},
            "window_hours": {"type": "integer", "description": "Hours either side of the alert (default 24, max 72)",
                             "default": 24},
        },
        "required": ["source"],
    },
)
async def hunt_vlogs(source: str = "", ip: str = "", user: str = "", host: str = "",
                     window_hours: int = 24, alert_time: str = "") -> dict:
    ip, user, host = (ip or "").strip(), (user or "").strip(), (host or "").strip()
    if ip and not _IP_RE.match(ip):
        return {"error": f"'{ip}' is not an IP address", "rows": []}
    for name, v in (("user", user), ("host", host)):
        if v and not _SAFE_RE.match(v):
            return {"error": f"{name} contains characters this tool does not accept", "rows": []}
    if source == "edge":
        if not (ip or host):
            return {"error": "edge needs an ip or a host", "rows": []}
        if host and not ip:
            return {"error": "edge by host alone is the whole site's traffic — pass the client ip too", "rows": []}
        q = _edge_query(ip, host)
    elif source == "eks":
        if not (ip or user):
            return {"error": "eks needs a user or an ip", "rows": []}
        q = _eks_query(ip, user)
    elif source == "rds":
        if not (ip or user or host):
            return {"error": "rds needs a user, an ip or a cluster host", "rows": []}
        q = _rds_query(ip, user, host)
    else:
        return {"error": "source must be edge, eks or rds", "rows": []}
    start, end = _window(alert_time, window_hours)
    try:
        from shadow_hunter.clients.victorialogs import VictoriaLogsClient
        rows = await VictoriaLogsClient(timeout=90).query(q, start, end, limit=40)
    except Exception as exc:
        return {"error": f"VictoriaLogs unavailable: {str(exc)[:200]}", "rows": [], "window": [start, end]}
    if source == "rds":
        from shadow_hunter.clients.victorialogs import as_list
        from shadow_hunter.detectors.rds_audit import redact, statement
        for r in rows:
            r["sample"] = [redact(statement(s))[:240] for s in as_list(r.get("sample"))]
    from shadow_hunter.detectors.base import mask_ids
    return {"source": source, "window": [start, end], "count": len(rows), "rows": mask_ids(rows)}
