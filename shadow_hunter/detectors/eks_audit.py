"""EKS prod API audit — human hands on the cluster, and anything anonymous getting through.

Reads VictoriaLogs in place: source_type:cloudwatch, log_group /aws/eks/prod/cluster, streams
kube-apiserver-audit-* (~2M events/h, one Kubernetes audit event per line in _msg).
Profile on Oct 12-19: humans (an email via aws-iam-authenticator) make ~1 read a day; the only
pod port-forwarding is Kiali; anonymous traffic is the default /healthz /livez /readyz probes;
secrets are read only by controllers. So each signal below is near-silent normally:

  * exec / attach / portforward into a pod by anyone but Kiali (high; medium for a service
    account) — an interactive shell in a prod workload.
  * Secrets read (get/list/watch) by a human — credentials out of the cluster.
  * RBAC create/update/patch/delete by a human — critical when the request names cluster-admin.
  * Service-account token minted by a human — a credential that outlives the session.
  * Any anonymous request other than the health/version probes answered < 400 — critical.

A refused attempt (HTTP >= 400) is one severity lower. Replay Oct 12-19: one finding, a human
listing secrets in kube-system and getting 403.

Phrase pre-filters keep the scan to a few seconds; JSON is unpacked only for what's left.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shadow_hunter.detectors.base import Detector, mask_ids

BASE = 'source_type:cloudwatch log_group:="/aws/eks/prod/cluster" log_stream:~"^kube-apiserver-audit"'
PRE = ('(_msg:"\\"subresource\\":\\"exec\\"" or _msg:"\\"subresource\\":\\"attach\\"" '
       'or _msg:"\\"subresource\\":\\"portforward\\"" or _msg:"\\"subresource\\":\\"token\\"" '
       'or _msg:"rbac.authorization.k8s.io" or _msg:"system:anonymous" '
       'or (_msg:"\\"resource\\":\\"secrets\\"" -_msg:"system:serviceaccount" -_msg:"system:node"))')
UNPACK = ('| unpack_json from _msg fields (verb, user.username, objectRef.resource, objectRef.subresource, '
          'objectRef.namespace, objectRef.name, responseStatus.code, requestURI, userAgent, sourceIPs)')
WINDOW_HOURS = 2
ALLOWED_PORTFORWARD = {"system:serviceaccount:istio-system:kiali"}
RBAC = {"roles", "rolebindings", "clusterroles", "clusterrolebindings"}
WRITES = {"create", "update", "patch", "delete", "deletecollection"}
HEALTH_URI = ("/healthz", "/livez", "/readyz", "/version", "/openapi")


def logsql() -> str:
    return (f"{BASE} {PRE} {UNPACK} "
            '| filter -user.username:~"^(system:node:|system:apiserver|system:kube-|eks:)" -user.username:~"AWSServiceRole" '
            '| stats by (user.username, verb, objectRef.resource, objectRef.subresource, responseStatus.code) count() n, '
            "uniq_values(objectRef.namespace) limit 5 namespaces, uniq_values(objectRef.name) limit 5 names, "
            "uniq_values(requestURI) limit 3 uris, uniq_values(userAgent) limit 2 agents, uniq_values(sourceIPs) limit 3 ips, "
            'count() if (_msg:"cluster-admin") admin_refs, min(_time) first | limit 500')


def is_human(user: str) -> bool:
    return bool(user) and not user.startswith(("system:", "eks:")) and "AWSServiceRole" not in user


def classify(r: dict) -> tuple[str, str] | None:
    """(kind, severity) for one grouped row, or None when it's routine."""
    from shadow_hunter.clients.victorialogs import as_int, as_list
    user = r.get("user.username") or ""
    verb, res, sub = r.get("verb") or "", r.get("objectRef.resource") or "", r.get("objectRef.subresource") or ""
    code = as_int(r.get("responseStatus.code"))
    if user == "system:anonymous":
        uris = [u for u in as_list(r.get("uris")) if not str(u).startswith(HEALTH_URI)]
        return ("anonymous_allowed", "critical") if uris and 0 < code < 400 else None
    if sub in ("exec", "attach", "portforward") and res == "pods":
        if user in ALLOWED_PORTFORWARD:
            return None
        return ("pod_shell", "high" if is_human(user) else "medium")
    if not is_human(user):
        return None
    if res == "secrets" and verb in ("get", "list", "watch"):
        return ("secret_read", "high")
    if res in RBAC and verb in WRITES:
        return ("rbac_change", "critical" if as_int(r.get("admin_refs")) else "high")
    if res == "serviceaccounts" and sub == "token" and verb == "create":
        return ("token_minted", "high")
    return None


def refused(sev: str, r: dict) -> str:
    """A refused attempt (HTTP >= 400) is still worth asking about, one level lower."""
    from shadow_hunter.clients.victorialogs import as_int
    if as_int(r.get("responseStatus.code")) >= 400:
        return {"critical": "high", "high": "medium"}.get(sev, sev)
    return sev


_WHAT = {"anonymous_allowed": "ANONYMOUS request(s) answered", "pod_shell": "interactive pod access",
         "secret_read": "secret read(s)", "rbac_change": "RBAC change(s)", "token_minted": "service-account token(s) minted"}


class EksAuditDetector(Detector):
    name = "eks_audit"
    mitre_techniques = ["T1609", "T1552.007", "T1098", "T1078"]
    severity = "high"
    cadence_minutes = 30
    query_name = "eks_audit"

    def kql(self, lookback_hours: int) -> str:  # not an MDE query; see fetch
        return ""

    async def fetch(self, defender, lookback_hours: int = 24) -> list[dict]:
        from shadow_hunter.clients import MockDefenderClient
        if isinstance(defender, MockDefenderClient):
            return []
        from shadow_hunter.clients.victorialogs import VictoriaLogsClient
        return await self.collect(VictoriaLogsClient(), datetime.now(timezone.utc))

    async def collect(self, c, end: datetime) -> list[dict]:
        from shadow_hunter.clients.victorialogs import iso
        start = end - timedelta(hours=WINDOW_HOURS)
        out = []
        for r in await c.query(logsql(), iso(start), iso(end), 500):
            k = classify(r)
            if k:
                out.append({**r, "_kind": k[0], "_sev": refused(k[1], r)})
        return out

    def to_findings(self, rows: list[dict]) -> list[dict]:
        from shadow_hunter.clients.victorialogs import as_int, as_list
        out = []
        for r in rows:
            user, kind = r.get("user.username") or "?", r.get("_kind")
            ns = [str(x) for x in as_list(r.get("namespaces")) if x]
            names = [str(x) for x in as_list(r.get("names")) if x]
            day = str(r.get("first") or "")[:10]
            target = (f"{r.get('objectRef.resource') or ''}"
                      + (f"/{r.get('objectRef.subresource')}" if r.get("objectRef.subresource") else "")
                      + (f" in {', '.join(ns[:3])}" if ns else "")
                      + (f" ({', '.join(names[:3])})" if names else ""))
            out.append({
                "detector": self.name,
                "severity": r.get("_sev") or "high",
                "device_id": "eks:prod",
                "device_name": "eks-prod",
                "account_name": user,
                "indicator": f"{kind}|{user}|{r.get('verb')}|{r.get('objectRef.resource')}|{','.join(ns[:3])}|{day}",
                "summary": mask_ids(f"EKS prod: {as_int(r.get('n'))} {_WHAT.get(kind, kind)} by {user}: "
                                    f"{r.get('verb')} {target} → HTTP {r.get('responseStatus.code')}")[:400],
                "raw": {"kind": kind, "user": user, "verb": r.get("verb"),
                        "resource": r.get("objectRef.resource"), "subresource": r.get("objectRef.subresource"),
                        "namespaces": ns, "names": names, "status": r.get("responseStatus.code"),
                        "uris": as_list(r.get("uris")), "user_agents": as_list(r.get("agents")),
                        "source_ips": as_list(r.get("ips")), "count": as_int(r.get("n")),
                        "first": r.get("first"), "source": "victorialogs:eks_audit"},
                "mitre_techniques": {"pod_shell": ["T1609"], "secret_read": ["T1552.007"],
                                     "rbac_change": ["T1098"], "token_minted": ["T1528"],
                                     "anonymous_allowed": ["T1078"]}.get(kind, []),
            })
        return mask_ids(out)
