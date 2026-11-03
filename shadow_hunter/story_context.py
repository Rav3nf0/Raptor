"""Everything else we know about an incident story: RAPTOR/Jira alerts and VictoriaLogs.

A story (shadow_hunter/stories.py) groups /shadow findings. The rest of the picture lives
elsewhere: the Jira alerts RAPTOR triaged on the same hosts and accounts, and the edge,
Kubernetes, database and application logs in VictoriaLogs. The ATLAS intrusion showed the
cost of leaving those out: the order attempts, the gateway bypass and 116 S3 access-log
lines from the attacker IP were each found by hand, in a different place.

This module snapshots that context onto the story (Story.context), so it is on the story
page and in the report bundle, and it outlives VictoriaLogs retention (Cloudflare ~30 days).

  alerts    ShadowResult rows (RAPTOR tickets) on a story host or account, ±48 h, and on the
            EKS nodes its workloads ran on (GuardDuty names the node, Upwind the deployment)
  infra     workload -> nodes (pod logs), the domains its Upwind network detections queried,
            and the GuardDuty instances on those nodes or for those domains (Sentinel)
  edge      Cloudflare requests per public IP in the story (method, host, edge/origin status,
            attack-shaped paths)
  eks       EKS prod API audit per account that looks like a person (an email)
  rds       Aurora audit per private host IP (did a compromised host touch a database?)
  mentions  any other log source (S3 access logs, app namespaces, CloudWatch) that contains
            one of the story's indicators: a public IP or a webshell-style file stem

Read-only and bounded: at most MAX_EDGE_IPS / MAX_TERMS / ... lookups, 6 h chunks for
full-text search (a multi-day phrase search times out at the gateway), and a time budget
per story. Every lookup records its window and any error instead of failing the refresh.
Everything stored goes through stories.clean() (secrets out, 12-digit ids masked).
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

ALERT_PAD_HOURS = 48
EDGE_PAD_HOURS = 24
EDGE_CHUNK_HOURS = 72
MENTION_PAD_HOURS = 24
MENTION_CHUNK_HOURS = 6
MENTION_MAX_HOURS = 72
MAX_EDGE_IPS, MAX_EKS_USERS, MAX_RDS_IPS, MAX_TERMS = 6, 3, 4, 4
MAX_ALERTS = 100
BUDGET_SECONDS = 420
STALE_HOURS = 12
STORIES_PER_RUN = 2
MAX_INDICATORS = 20
# Shared Acme egress (corporate NAT, ~13M requests a day): a phrase search for it matches
# everything and times out, and "this IP appears in the logs" says nothing.
SKIP_TERMS = {"203.0.113.10"}

_PRIVATE = re.compile(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HOSTLIKE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$", re.I)
_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$")

MENTIONS_STATS = ("| stats by (source_type, kubernetes.namespace_name, log_group) count() n, "
                  "min(_time) first, max(_time) last | sort by (n desc) | limit 20")


# ── what to look up ────────────────────────────────────────────────────────────

def _window(st) -> tuple[datetime, datetime]:
    from shadow_hunter.stories import _parse
    now = datetime.now(timezone.utc)
    a = _parse(st.first_seen) or now
    b = _parse(st.last_seen) or a
    return a, b


def _counted(findings, prefix: str) -> list[str]:
    """Tokens of one kind, most-mentioned first (ties by name, so a refresh is stable)."""
    from shadow_hunter.stories import tokens
    n: dict[str, int] = {}
    for f in findings:
        for t in tokens(f):
            if t.startswith(prefix):
                n[t[len(prefix):]] = n.get(t[len(prefix):], 0) + 1
    return [t for t, _ in sorted(n.items(), key=lambda kv: (-kv[1], kv[0]))]


_TERM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:/+=-]{2,99}$")


def indicator_kind(value: str) -> str | None:
    """'ip' for a public IPv4, 'term' for a searchable token, None for anything else (private
    IPs say nothing at the edge; free text cannot be searched safely)."""
    v = (value or "").strip()
    if _IPV4.match(v):
        return None if _PRIVATE.match(v) or v.startswith(("0.", "255.")) else "ip"
    return "term" if _TERM.match(v) else None


def analyst(st, kind: str) -> list[str]:
    return [i["value"] for i in (st.indicators or []) if i.get("kind") == kind]


def public_ips(st, findings) -> list[str]:
    """Public IPs in the story: an analyst's first, then the findings', then its hosts'."""
    out = analyst(st, "ip") + _counted(findings, "ip:")
    for h in (st.entities or {}).get("hosts", []):
        out += [ip for ip in h.get("ips", []) if not _PRIVATE.match(ip)]
    return list(dict.fromkeys(out))


def private_host_ips(st) -> list[str]:
    return list(dict.fromkeys(ip for h in (st.entities or {}).get("hosts", [])
                              for ip in h.get("ips", []) if _PRIVATE.match(ip)))


def people(st) -> list[str]:
    return [a for a in (st.entities or {}).get("accounts", []) if _EMAIL.match(a or "")]


def mention_terms(st, findings) -> list[str]:
    """Indicators worth a full-text search: attacker-side public IPs, then webshell-style file
    stems and script names. Never the shared NAT."""
    ips = [ip for ip in public_ips(st, findings) if ip not in SKIP_TERMS]
    files = [f for f in _counted(findings, "file:")
             if re.search(r"\.(ashx|aspx|asmx|jsp|php|ps1|bat|cmd|vbs|hta|sh)$", f)]
    mine = analyst(st, "ip") + analyst(st, "term")      # an analyst's always make the cut
    rest = [t for t in ips + _counted(findings, "stem:") + files if t not in mine]
    return list(dict.fromkeys(mine + rest))[:max(MAX_TERMS, len(mine))]


def host_names(st) -> list[str]:
    """Short host names a Jira alert could carry (no BYOC addresses, no bare IPs)."""
    out = []
    for h in (st.entities or {}).get("hosts", []):
        for n in [h.get("name", "")] + list(h.get("aliases", [])):
            s = (n or "").strip().lower().split(".")[0]
            if s and not _IPV4.match(n or "") and _HOSTLIKE.match(s):
                out.append(s)
    return list(dict.fromkeys(out))


# ── RAPTOR / Jira alerts ───────────────────────────────────────────────────────

def _account_regex(acct: str) -> str | None:
    """'CORP\\jdoe', 'jdoe@corp.com' and 'jdoe' are the same person in different alerts."""
    from entity_graph.query import _is_generic_account
    local = (acct or "").split("\\")[-1].split("@")[0].strip().lower()
    if len(local) < 3 or _is_generic_account(local):
        return None
    return rf"(^|\\){re.escape(local)}(@|$)"


async def related_alerts(st) -> list[dict]:
    from entity_graph.models import ShadowResult
    a, b = _window(st)
    ors, why = [], {}
    for h in host_names(st):
        ors.append({"device_name": {"$regex": rf"^{re.escape(h)}(\.|$)", "$options": "i"}})
    for acct in (st.entities or {}).get("accounts", []):
        rx = _account_regex(acct)
        if rx:
            ors.append({"user_name": {"$regex": rx, "$options": "i"}})
            why[rx] = acct
    if not ors:
        return []
    pad = timedelta(hours=ALERT_PAD_HOURS)
    lo, hi = (a - pad).replace(tzinfo=None), (b + pad).replace(tzinfo=None)  # stored naive UTC
    rows = await ShadowResult.find({"$or": ors, "created_at": {"$gte": lo, "$lte": hi}}) \
        .sort("created_at").limit(MAX_ALERTS).to_list()
    hosts = set(host_names(st))
    out = []
    for r in rows:
        short = (r.device_name or "").lower().split(".")[0]
        matched = (f"host {short}" if short in hosts else
                   f"account {next((v for k, v in why.items() if re.search(k, r.user_name or '', re.I)), r.user_name)}")
        out.append(_alert_row(r, matched))
    return out


def _alert_row(r, matched: str) -> dict:
    return {"jira_key": r.jira_key, "alert_name": r.alert_name, "severity": r.severity,
            "device_name": r.device_name, "user_name": r.user_name,
            "created_at": (r.created_at.replace(tzinfo=timezone.utc).isoformat() if r.created_at else ""),
            "ai_triage_class": r.ai_triage_class, "ai_confidence": r.ai_confidence,
            "ai_reasoning": (r.ai_reasoning or "")[:400],
            "l1_triage_class": r.l1_triage_class or "", "l2_triage_class": r.l2_triage_class or "",
            "matched_on": matched}


async def node_alerts(st, infra: dict) -> list[dict]:
    """Tickets on the EKS nodes a story's workloads ran on. GuardDuty names the node (its
    instance id in the alert title, no device), Upwind names the deployment, so the two
    never shared a host name (DEMO-118243 vs the partner-onboarding SSRF story)."""
    from entity_graph.models import ShadowResult
    nodes = [n for n in (infra or {}).get("nodes", []) if n.get("instance_id") or n.get("node")]
    if not nodes:
        return []
    ors, why = [], []
    for n in nodes:
        label = f"node {n.get('node') or n.get('ip')}" + (f" ({', '.join(n['workloads'])})" if n.get("workloads") else "") \
            + (f", GuardDuty {', '.join(n['domains'][:2])}" if n.get("domains") else "")
        if _INSTANCE.match(n.get("instance_id", "")):
            ors.append({"alert_name": {"$regex": re.escape(n["instance_id"])}})
            why.append((n["instance_id"], label))
        if n.get("node"):
            short = n["node"].lower().split(".")[0]
            ors.append({"device_name": {"$regex": rf"^{re.escape(short)}(\.|$)", "$options": "i"}})
            why.append((short, label))
    if not ors:
        return []
    a, b = _window(st)
    pad = timedelta(hours=ALERT_PAD_HOURS)
    rows = await ShadowResult.find({"$or": ors, "created_at": {"$gte": (a - pad).replace(tzinfo=None),
                                                               "$lte": (b + pad).replace(tzinfo=None)}}) \
        .sort("created_at").limit(MAX_ALERTS).to_list()
    out = []
    for r in rows:
        hay = f"{r.alert_name or ''} {(r.device_name or '').lower()}"
        key, label = next(((k, l) for k, l in why if k in hay), ("", "node"))
        out.append(_alert_row(r, f"{key}: {label}" if key else label))
    return out


# ── EKS nodes behind a story's workloads ───────────────────────────────────────

NODE_PAD_HOURS = 1
MAX_WORKLOADS, MAX_NODES_PER_WORKLOAD, MAX_DETECTIONS, MAX_DOMAINS = 4, 12, 6, 10
INFRA_BUDGET_SECONDS = 120
_NODE = re.compile(r"^ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(?:\.|$)", re.I)
_INSTANCE = re.compile(r"^i-[0-9a-f]{8,17}$")
_DNS = re.compile(r"^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$")


def node_ip(name: str) -> str:
    """10.193.86.192 from ip-10-193-86-192.ap-south-1.compute.internal, else ''."""
    m = _NODE.match(name or "")
    return ".".join(m.groups()) if m else ""


async def workload_nodes(st, c, budget) -> dict:
    """Which nodes each story workload's pods logged from (kubernetes.host). A workload on
    more than MAX_NODES_PER_WORKLOAD nodes is a DaemonSet (node-local-dns runs on every
    node), which would tie the story to the whole cluster: recorded as skipped."""
    from shadow_hunter.clients.victorialogs import literal
    a, b = _window(st)
    s, e = a - timedelta(hours=NODE_PAD_HOURS), min(b + timedelta(hours=NODE_PAD_HOURS), datetime.now(timezone.utc))
    out: dict = {}
    for w in [h for h in host_names(st) if not node_ip(h)][:MAX_WORKLOADS]:
        q = f"kubernetes.container_name:{literal(w)} | stats by (kubernetes.host, kubernetes.namespace_name) count() n"
        res = await _run(c, q, s, e, 24, ("kubernetes.host", "kubernetes.namespace_name"), budget, limit=200)
        nodes = sorted({r.get("kubernetes.host", "") for r in res["rows"] if node_ip(r.get("kubernetes.host", ""))})
        if not nodes:
            continue
        ns = sorted({r.get("kubernetes.namespace_name", "") for r in res["rows"]} - {""})
        out[w] = ({"skipped": f"runs on {len(nodes)} nodes (DaemonSet-like)", "namespaces": ns}
                  if len(nodes) > MAX_NODES_PER_WORKLOAD else {"nodes": nodes, "namespaces": ns})
        if res.get("errors"):
            out[w]["errors"] = res["errors"]
    return out


def _upwind_ids(findings) -> list[str]:
    """Network detection ids, one per distinct title first (round robin), so the
    MAX_DETECTIONS cap samples every kind. Story 3fbe2e00 loaded its six OAST
    detections ahead of the IMDS-rebind ones and the cap kept only the OAST domain."""
    by_title: dict[str, list[str]] = {}
    for f in findings:
        raw = f.raw if isinstance(f.raw, dict) else {}
        if f.detector != "upwind_threats" or str(raw.get("category", "")).upper() != "NETWORK":
            continue
        title = str(raw.get("title") or f.summary or "")
        by_title.setdefault(title, []).extend(str(i) for i in (raw.get("upwind_ids") or [raw.get("upwind_id")]) if i)
    ordered, queues = [], [list(dict.fromkeys(v)) for v in by_title.values()]
    while any(queues):
        ordered += [q.pop(0) for q in queues if q]
    return list(dict.fromkeys(ordered))


async def story_domains(findings, fetch=None, budget=None) -> list[str]:
    """DNS names the story's Upwind network detections queried (IMDS rebinding names,
    OAST callbacks). The finding rows only keep a title; the names are in the detection."""
    from edr_triage.upwind_client import detection_domains
    if fetch is None:
        from edr_triage.upwind_client import get_detection_raw as fetch
    out: list[str] = []
    for i in _upwind_ids(findings)[:MAX_DETECTIONS]:
        if budget is not None and not budget.left():
            break
        out += detection_domains(await fetch(i) or {})
    return list(dict.fromkeys(out))[:MAX_DOMAINS]


async def guardduty_instances(ips: list[str], domains: list[str], start: datetime, end: datetime,
                              sentinel=None) -> list[dict]:
    """GuardDuty findings on these node IPs or for these domains: instance id, IP, finding
    types and domains per instance. Inputs are validated before they go into KQL."""
    ips = [i for i in ips if _IPV4.match(i) and _PRIVATE.match(i)][:40]
    domains = [d for d in domains if _DNS.match(d)][:MAX_DOMAINS]
    if not ips and not domains:
        return []
    if sentinel is None:
        from shadow_hunter.clients.sentinel_logs import SentinelLogsClient
        sentinel = SentinelLogsClient()
    lst = lambda xs: "dynamic([" + ",".join(f"'{x}'" for x in xs) + "])"
    kql = (f"AWSGuardDuty | where TimeGenerated between (datetime({start:%Y-%m-%dT%H:%M:%SZ}) .. "
           f"datetime({end:%Y-%m-%dT%H:%M:%SZ}))"
           " | extend rd = todynamic(ResourceDetails), sd = todynamic(ServiceDetails)"
           " | extend iid = tostring(rd.instanceDetails.instanceId),"
           " pip = tostring(rd.instanceDetails.networkInterfaces[0].privateIpAddress),"
           " dom = tostring(sd.action.dnsRequestAction.domain)"
           f" | where pip in ({lst(ips)}) or dom in ({lst(domains)})"
           " | summarize findings = count(), types = make_set(ActivityType, 8), doms = make_set(dom, 8),"
           " t0 = min(TimeGenerated), t1 = max(TimeGenerated) by iid, pip")
    from shadow_hunter.clients.victorialogs import as_list
    return [{"instance_id": r.get("iid", ""), "ip": r.get("pip", ""), "findings": r.get("findings", 0),
             "types": as_list(r.get("types")), "domains": [d for d in as_list(r.get("doms")) if d],
             "first": str(r.get("t0", "")), "last": str(r.get("t1", ""))}
            for r in await sentinel.query(kql) if _INSTANCE.match(r.get("iid") or "")]


async def infra_context(st, findings, c, sentinel=None, fetch=None,
                        budget_seconds: float = INFRA_BUDGET_SECONDS) -> dict:
    """Workloads → the nodes they ran on (pod logs), the domains their detections queried
    (Upwind), and the GuardDuty instances on those nodes or for those domains (Sentinel).
    Never raises: each step records its error and the rest still run."""
    budget = _Budget(budget_seconds)
    out: dict = {"workloads": {}, "domains": [], "nodes": []}
    errors = []
    try:
        out["workloads"] = await workload_nodes(st, c, budget)
    except Exception as exc:
        errors.append(f"pod nodes: {str(exc)[:160]}")
    try:
        out["domains"] = await story_domains(findings, fetch, budget)
    except Exception as exc:
        errors.append(f"detection domains: {str(exc)[:160]}")
    by_node: dict[str, dict] = {}
    for w, v in out["workloads"].items():
        for n in v.get("nodes", []):
            by_node.setdefault(n, {"node": n, "ip": node_ip(n), "workloads": []})["workloads"].append(w)
    a, b = _window(st)
    gd = []
    try:
        gd = await guardduty_instances([n["ip"] for n in by_node.values()], out["domains"],
                                       a - timedelta(hours=ALERT_PAD_HOURS), b + timedelta(hours=ALERT_PAD_HOURS),
                                       sentinel)
    except Exception as exc:
        errors.append(f"GuardDuty: {str(exc)[:160]}")
    for g in gd:
        node = next((n for n in by_node.values() if n["ip"] == g["ip"]), None)
        if node is None:   # reached through a shared domain only
            node = by_node.setdefault(f"ip-{g['ip'].replace('.', '-')}",
                                      {"node": f"ip-{g['ip'].replace('.', '-')}", "ip": g["ip"], "workloads": [],
                                       "via": "GuardDuty domain"})
        node.update({"instance_id": g["instance_id"], "guardduty_types": g["types"], "domains": g["domains"],
                     "guardduty_findings": g["findings"]})
    for n in by_node.values():
        if not n.get("instance_id"):
            n["background"] = True    # the workload ran here; nothing was flagged on it
    out["nodes"] = sorted(by_node.values(), key=lambda n: (not n.get("instance_id"), n["node"]))
    if errors:
        out["errors"] = errors
    return out


# ── VictoriaLogs ───────────────────────────────────────────────────────────────

_SUMS = ("n", "attack_paths")


def merge_rows(rows: list[dict], by: tuple[str, ...]) -> list[dict]:
    """Merge grouped stats rows from several time chunks: counts add up, first/last widen,
    uniq_values lists union. Rows sort by count, largest first."""
    from shadow_hunter.clients.victorialogs import as_int, as_list
    out: dict[tuple, dict] = {}
    for r in rows:
        k = tuple(r.get(f) or "" for f in by)
        cur = out.get(k)
        if cur is None:
            out[k] = {**r, **{s: as_int(r.get(s)) for s in _SUMS if s in r}}
            continue
        for f, v in r.items():
            if f in by:
                continue
            if f in _SUMS:
                cur[f] = as_int(cur.get(f)) + as_int(v)
            elif f == "first":
                cur[f] = min(x for x in (cur.get(f), v) if x) if (cur.get(f) or v) else ""
            elif f == "last":
                cur[f] = max(x for x in (cur.get(f), v) if x) if (cur.get(f) or v) else ""
            else:
                cur[f] = list(dict.fromkeys(as_list(cur.get(f)) + as_list(v)))[:10]
    return sorted(out.values(), key=lambda r: -as_int(r.get("n")))


def chunks(start: datetime, end: datetime, hours: int) -> list[tuple[datetime, datetime]]:
    out, t = [], start
    while t < end:
        out.append((t, min(t + timedelta(hours=hours), end)))
        t += timedelta(hours=hours)
    return out


class _Budget:
    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + seconds

    def left(self) -> bool:
        return time.monotonic() < self.deadline


async def _run(c, q: str, start: datetime, end: datetime, chunk_h: int, by: tuple, budget: _Budget,
               limit: int = 40) -> dict:
    """One lookup over [start, end] in chunks. Never raises: errors are recorded."""
    from shadow_hunter.clients.victorialogs import iso
    rows, errors, done = [], [], 0
    parts = chunks(start, end, chunk_h)
    for s, e in parts:
        if not budget.left():
            errors.append("time budget reached; later chunks skipped")
            break
        try:
            rows += await c.query(q, iso(s), iso(e), limit)
            done += 1
        except Exception as exc:
            errors.append(f"{iso(s)}..{iso(e)}: {str(exc)[:160]}")
            if len(errors) >= 2 and not done:
                break
    return {"window": [iso(start), iso(end)], "chunks": f"{done}/{len(parts)}",
            "rows": merge_rows(rows, by)[:limit], **({"errors": errors} if errors else {})}


async def vlogs_context(st, findings, c, budget_seconds: float = BUDGET_SECONDS) -> dict:
    from agent_tools.vlogs import _edge_query, _eks_query, _rds_query
    from shadow_hunter.clients.victorialogs import literal
    a, b = _window(st)
    now = datetime.now(timezone.utc)
    budget = _Budget(budget_seconds)
    out: dict = {"edge": {}, "eks": {}, "rds": {}, "mentions": {}}

    e0, e1 = a - timedelta(hours=EDGE_PAD_HOURS), min(b + timedelta(hours=EDGE_PAD_HOURS), now)
    edge_by = ("ClientRequestHost", "ClientRequestMethod", "EdgeResponseStatus", "OriginResponseStatus")
    for ip in public_ips(st, findings)[:MAX_EDGE_IPS]:
        out["edge"][ip] = await _run(c, _edge_query(ip, ""), e0, e1, EDGE_CHUNK_HOURS, edge_by, budget)

    eks_by = ("user.username", "verb", "objectRef.resource", "objectRef.subresource", "responseStatus.code")
    for user in people(st)[:MAX_EKS_USERS]:
        out["eks"][user] = await _run(c, _eks_query("", user), e0, e1, 24, eks_by, budget)

    rds_by = ("log_group", "dbuser", "client", "op")
    for ip in private_host_ips(st)[:MAX_RDS_IPS]:
        out["rds"][ip] = await _run(c, _rds_query(ip, "", ""), e0, e1, 24, rds_by, budget)
        for r in out["rds"][ip]["rows"]:
            from shadow_hunter.detectors.rds_audit import redact, statement
            from shadow_hunter.clients.victorialogs import as_list
            r["sample"] = [redact(statement(s))[:240] for s in as_list(r.get("sample"))]

    m1 = min(b + timedelta(hours=MENTION_PAD_HOURS), now)
    m0 = max(a - timedelta(hours=MENTION_PAD_HOURS), m1 - timedelta(hours=MENTION_MAX_HOURS))
    for term in mention_terms(st, findings):
        q = f"-source_type:cloudflare {literal(term)} {MENTIONS_STATS}"
        out["mentions"][term] = await _run(c, q, m0, m1, MENTION_CHUNK_HOURS,
                                           ("source_type", "kubernetes.namespace_name", "log_group"), budget, limit=20)
        if m0 > a - timedelta(hours=MENTION_PAD_HOURS):
            out["mentions"][term]["note"] = f"searched the last {MENTION_MAX_HOURS} h of the story only"
    return out


# ── refresh ────────────────────────────────────────────────────────────────────

async def refresh(story_id: str, client=None, vlogs: bool = True, sentinel=None, fetch=None) -> dict:
    """Recompute and store a story's context. client: a VictoriaLogsClient, sentinel: a
    SentinelLogsClient, fetch: an Upwind detection fetcher (None = the defaults)."""
    from beanie.operators import In
    from shadow_hunter.models import Finding, Story
    from shadow_hunter.stories import clean
    st = await Story.get(story_id)
    if not st:
        raise LookupError("story not found")
    findings = await Finding.find(In(Finding.id, st.finding_ids)).to_list()
    ctx: dict = {}
    if vlogs and client is None:
        from shadow_hunter.clients.victorialogs import VictoriaLogsClient
        client = VictoriaLogsClient(timeout=90)
    ctx["infra"] = (await infra_context(st, findings, client, sentinel=sentinel, fetch=fetch) if vlogs
                    else (st.context or {}).get("infra", {}))
    try:
        ctx["alerts"] = await related_alerts(st)
        seen = {x["jira_key"] for x in ctx["alerts"]}
        ctx["alerts"] += [x for x in await node_alerts(st, ctx["infra"]) if x["jira_key"] not in seen]
    except Exception as exc:
        logger.warning("[story_context] alerts for %s failed: %s", st.id, exc)
        ctx["alerts_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        ctx["alerts"] = (st.context or {}).get("alerts", [])
    if vlogs:
        ctx["vlogs"] = await vlogs_context(st, findings, client)
    elif (st.context or {}).get("vlogs"):
        ctx["vlogs"] = st.context["vlogs"]
    now = datetime.now(timezone.utc)
    ctx["fetched_at"] = now.isoformat()
    st.context, st.context_at = clean(ctx), now
    await st.save()
    return {"story": st.id, "alerts": len(ctx["alerts"]), "nodes": len(ctx["infra"].get("nodes", [])),
            **({k: len(v) for k, v in ctx["vlogs"].items()} if ctx.get("vlogs") else {})}


def _due(st, now: datetime) -> bool:
    from shadow_hunter.stories import _parse
    at = _parse(st.context_at)
    upd = _parse(st.updated_at)
    return at is None or (upd is not None and upd > at) or at < now - timedelta(hours=STALE_HOURS)


async def run_due(limit: int = STORIES_PER_RUN) -> dict:
    """Refresh the open stories whose context is missing, older than their last change, or
    STALE_HOURS old: most severe first, then most recently changed."""
    from shadow_hunter.models import Story
    from shadow_hunter.stories import SEV_RANK
    now = datetime.now(timezone.utc)
    open_ = await Story.find({"status": "open"}).to_list()
    due = sorted((s for s in open_ if _due(s, now)),
                 key=lambda s: (-SEV_RANK.get(s.severity, 0), -(s.updated_at.timestamp() if s.updated_at else 0)))
    done = []
    for st in due[:limit]:
        try:
            done.append(await refresh(st.id))
        except Exception as exc:
            logger.exception("[story_context] refresh %s failed", st.id)
            done.append({"story": st.id, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
    return {"due": len(due), "refreshed": done}


# ── one view of everything ─────────────────────────────────────────────────────

def merged_timeline(st) -> list[dict]:
    """Findings, Jira alerts, first/last edge requests per IP and first mentions in other
    logs, in one time order. kind: finding | alert | edge | logs."""
    from shadow_hunter.clients.victorialogs import as_int
    items = [{"ts": t.get("ts", ""), "kind": "finding", "host": t.get("host", ""), "severity": t.get("severity", ""),
              "source": t.get("source", ""), "event": t.get("event", ""), "ref": t.get("finding_id", "")}
             for t in st.timeline or []]
    ctx = st.context or {}
    for al in ctx.get("alerts", []):
        items.append({"ts": al.get("created_at", ""), "kind": "alert", "host": al.get("device_name") or al.get("user_name", ""),
                      "severity": al.get("severity", ""), "source": "jira",
                      "event": f"{al.get('jira_key')}: {al.get('alert_name')} (RAPTOR {al.get('ai_triage_class') or '—'})",
                      "ref": al.get("jira_key", "")})
    vl = ctx.get("vlogs") or {}
    for ip, res in (vl.get("edge") or {}).items():
        rows = res.get("rows") or []
        if not rows or ip in SKIP_TERMS:      # the shared NAT's first request is everyone's
            continue
        n = sum(as_int(r.get("n")) for r in rows)
        bad = sum(as_int(r.get("attack_paths")) for r in rows
                  if str(r.get("OriginResponseStatus") or "").startswith("2"))
        hosts = sorted({r.get("ClientRequestHost") for r in rows if r.get("ClientRequestHost")})
        first = min((r.get("first") for r in rows if r.get("first")), default="")
        last = max((r.get("last") for r in rows if r.get("last")), default="")
        detail = f"{n:,} requests to {', '.join(hosts[:3])}" + (f"; {bad} attack-shaped answered 2xx by origin" if bad else "")
        items.append({"ts": first, "kind": "edge", "host": ip, "severity": "", "source": "cloudflare",
                      "event": f"First request from {ip} at the edge ({detail})", "ref": ip})
        if last and last != first:
            items.append({"ts": last, "kind": "edge", "host": ip, "severity": "", "source": "cloudflare",
                          "event": f"Last request from {ip} at the edge", "ref": ip})
    for term, res in (vl.get("mentions") or {}).items():
        for r in res.get("rows") or []:
            where = r.get("kubernetes.namespace_name") or r.get("log_group") or r.get("source_type") or "logs"
            items.append({"ts": r.get("first", ""), "kind": "logs", "host": where, "severity": "", "source": r.get("source_type") or "logs",
                          "event": f"'{term}' first appears in {where} ({as_int(r.get('n')):,} lines)", "ref": term})
    return sorted((i for i in items if i["ts"]), key=lambda i: i["ts"])


_NAMESPACE = re.compile(r"^(system|microsoft|windows)\.[a-z]+$")   # .NET namespaces, not domains
_UW_ID = re.compile(r"\buw[a-z]{0,3}-([0-9a-f]{16,40})\b", re.I)            # Upwind ids: uwd-, uwnd-, uwr-
_CLUSTER_DNS = {"node-local-dns", "coredns", "kube-dns"}


def iocs(st, findings) -> list[dict]:
    """Indicators of compromise: the analyst's, then those taken from the story itself:
    {value, type, note}. Ids that only name our own assets (the Upwind asset id inside
    'uwr-<hash>', an MDE device id) are not indicators."""
    import json as _json
    in_findings = set(_counted(findings, "ip:"))
    added = {i["value"]: i for i in st.indicators or []}
    raws = [f.raw if isinstance(f.raw, dict) else {} for f in findings]
    own = " ".join([f.device_id or "" for f in findings]
                   + [a for h in (st.entities or {}).get("hosts", []) for a in h.get("asset_ids", []) + h.get("device_ids", [])]
                   # our own Upwind detection/event ids (uwnd-<hash>): 9 of 3fbe2e00's "hashes"
                   + _UW_ID.findall(_json.dumps(raws, default=str))).lower()
    # A domain only in a detection's description ("…interactsh, Burp Collaborator and
    # webhook.site") is the vendor explaining the rule, not something the attack touched.
    desc = " ".join(str(r.get("description") or "") for r in raws).lower()
    said = " ".join([_json.dumps({k: v for k, v in r.items() if k != "description"}, default=str) for r in raws]
                    + [f"{f.summary} {f.indicator}" for f in findings]).lower()
    infra = (st.context or {}).get("infra") or {}
    out = [{"value": i["value"], "type": "IP" if i.get("kind") == "ip" else "Indicator",
            "note": " · ".join(x for x in (i.get("note", ""), f"added by {i.get('by', 'analyst')}") if x)}
           for i in st.indicators or []]
    out += [{"value": ip, "type": "IP", "note": "in the findings" if ip in in_findings else "a story host's IP"}
            for ip in public_ips(st, findings)[:20] if ip not in added]
    kinds = {"stem:": "File stem", "file:": "File", "domain:": "Domain", "hash:": "Hash"}
    for prefix, label in kinds.items():
        vals = [v for v in _counted(findings, prefix) if v not in added
                and not (prefix == "hash:" and v in own) and not (prefix == "domain:" and _NAMESPACE.match(v))
                and not (prefix == "domain:" and v in desc and v not in said)]
        out += [{"value": v, "type": label, "note": ""} for v in vals[:15]]
    seen = {o["value"] for o in out}
    out += [{"value": d, "type": "Domain", "note": "queried by the workload (Upwind network detection)"}
            for d in infra.get("domains", []) if d not in seen and d not in added]
    out += [{"value": n["instance_id"], "type": "Instance",
             "note": " · ".join(x for x in (n.get("ip", ""), ", ".join(n.get("guardduty_types", [])[:3]),
                                            n.get("via", "") or ("runs " + ", ".join(n["workloads"]) if n.get("workloads") else ""))
                                if x)}
            for n in infra.get("nodes", []) if n.get("instance_id")]
    for h in (st.entities or {}).get("hosts", []):
        note = ", ".join(h.get("ips", [])[:4])
        if h.get("name", "").lower() in _CLUSTER_DNS:
            note = "cluster DNS resolver: sees the same lookups as the workloads, not a separate host"
        out.append({"value": h.get("name", ""), "type": "Host", "note": note})
    for a in (st.entities or {}).get("accounts", [])[:15]:
        out.append({"value": a, "type": "Account", "note": ""})
    return out
