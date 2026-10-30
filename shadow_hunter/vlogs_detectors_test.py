"""RDS audit + EKS audit detectors and the hunt_vlogs tool (VictoriaLogs, queried in place)."""
from __future__ import annotations

import asyncio
import inspect
import json
from datetime import datetime, timezone

import pytest

from shadow_hunter.detectors import DETECTORS
from shadow_hunter.detectors import eks_audit as EKS
from shadow_hunter.detectors import rds_audit as RDS


class _Fake:
    """A VictoriaLogsClient stand-in that answers by matching a substring of the query."""
    def __init__(self, answers):
        self.answers, self.seen = answers, []

    async def query(self, q, start, end, limit=1000):
        self.seen.append((q, start, end))
        for needle, rows in self.answers:
            if needle(q, start):
                return rows
        return []


END = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)


# ── RDS: passwords never leave the detector ────────────────────────────────────

@pytest.mark.parametrize("sql", [
    "CREATE USER 'app'@'%' IDENTIFIED BY 'Sup3r$ecret'",
    "ALTER USER \\'callout_core_user\\'@\\'%\\' IDENTIFIED BY \\'Sup3r$ecret\\'",
    "CREATE USER 'x'@'%' IDENTIFIED WITH mysql_native_password BY 'Sup3r$ecret'",
    "SET PASSWORD FOR 'x'@'%' = 'Sup3r$ecret'",
    "SET PASSWORD = PASSWORD('Sup3r$ecret')",
])
def test_passwords_are_redacted(sql):
    out = RDS.redact(sql)
    assert "Sup3r$ecret" not in out and "***" in out


def test_statement_and_cluster_are_parsed_from_the_audit_line():
    line = ("1760848800123,prod-website-services-0,root,10.219.47.227,758600,56373452,QUERY,ai_news,"
            "'CREATE USER \\'ai_news_user\\'@\\'%\\' IDENTIFIED BY \\'pw,with,commas\\' REQUIRE SSL',0")
    sql = RDS.statement(line)
    assert sql.startswith("CREATE USER 'ai_news_user'") and "REQUIRE SSL" in sql
    assert "pw,with,commas" not in RDS.redact(sql)
    assert RDS.cluster_of("/aws/rds/cluster/prod-loan-service/audit") == "prod-loan-service"


def _dcl_row(stmt, user="root", client="10.219.95.112"):
    return {"log_group": "/aws/rds/cluster/prod-trade-preset-service/audit", "dbuser": user, "client": client,
            "n": "2", "first": "2026-10-16T14:05:00Z",
            "sample": json.dumps([f"1,srv,{user},{client},1,1,QUERY,db,'{stmt}',0"])}


def test_account_changes_medium_strong_grants_high_and_secret_free():
    f = RDS.RdsAuditDetector().to_findings([
        {**_dcl_row("CREATE USER 'a'@'%' IDENTIFIED BY 'hunter2'"), "_kind": "account_change"},
        {**_dcl_row("GRANT ALL PRIVILEGES ON *.* TO 'a'@'%' WITH GRANT OPTION"), "_kind": "account_change"},
    ])
    assert [x["severity"] for x in f] == ["medium", "high"]
    assert "hunter2" not in json.dumps(f)
    assert f[0]["indicator"].startswith("account_change|prod-trade-preset-service|root|10.219.95.112|2026-10-16")


def test_destructive_only_new_pairs_and_drop_database_always():
    window = [{**_dcl_row("TRUNCATE TABLE summary_db.orders", user="summary_db_user"), "n": "5"},
              {**_dcl_row("DROP TABLE IF EXISTS event_outbox", user="root"), "n": "5"},
              {**_dcl_row("DROP DATABASE payments", user="summary_db_user"), "n": "1"}]
    baseline = [{"log_group": "/aws/rds/cluster/prod-trade-preset-service/audit", "dbuser": "summary_db_user"}]
    c = _Fake([(lambda q, s: "drop\\\\s+(database" in q and s.startswith("2026-10-19T08"), window),
               (lambda q, s: "drop\\\\s+(database" in q, baseline)])
    rows = asyncio.run(RDS.RdsAuditDetector().collect(c, END))
    kinds = [(r["dbuser"], r["_kind"], r.get("_drops_db")) for r in rows]
    assert ("root", "destructive", False) in kinds                     # first time for root
    assert ("summary_db_user", "destructive", True) in kinds           # DROP DATABASE despite baseline
    assert sum(1 for k in kinds if k[0] == "summary_db_user") == 1     # its usual TRUNCATE stays quiet


def test_wrong_password_new_user_medium_guessed_high_chronic_quiet():
    win = [{"log_group": "/aws/rds/cluster/c1/audit", "dbuser": "root", "client": "10.219.1.1", "fails": "1", "ok": "3"},
           {"log_group": "/aws/rds/cluster/c2/audit", "dbuser": "cch_user", "client": "10.193.9.9", "fails": "13", "ok": "0"},
           {"log_group": "/aws/rds/cluster/c3/audit", "dbuser": "svc", "client": "10.5.5.5", "fails": "4", "ok": "2"}]
    hist = [{"log_group": "/aws/rds/cluster/c2/audit", "dbuser": "cch_user", "client": "10.193.1.1"},
            {"log_group": "/aws/rds/cluster/c3/audit", "dbuser": "svc", "client": "10.9.9.9"}]
    c = _Fake([(lambda q, s: "count() if" in q, win), (lambda q, s: ",1045" in q and "count() n" in q, hist)])
    rows = asyncio.run(RDS.RdsAuditDetector().collect(c, END))
    f = {r["dbuser"]: r for r in rows}
    assert "cch_user" not in f                                 # chronic failer, new pod IP
    assert f["root"]["_guessed"] is False                      # new failing user, 1 typo
    assert f["svc"]["_guessed"] is True                        # 4 fails then success from a new client
    sev = {x["account_name"]: x["severity"] for x in RDS.RdsAuditDetector().to_findings(rows)}
    assert sev == {"root": "medium", "svc": "high"}


# ── EKS: rules ─────────────────────────────────────────────────────────────────

def _k(user, verb, res="", sub="", code="200", **kw):
    return {"user.username": user, "verb": verb, "objectRef.resource": res, "objectRef.subresource": sub,
            "responseStatus.code": code, **kw}


@pytest.mark.parametrize("row,expect", [
    (_k("system:anonymous", "get", uris='["/healthz?exclude=kms"]'), None),
    (_k("system:anonymous", "get", uris='["/api/v1/secrets"]'), ("anonymous_allowed", "critical")),
    (_k("system:anonymous", "get", code="403", uris='["/api/v1/secrets"]'), None),
    (_k("system:serviceaccount:istio-system:kiali", "create", "pods", "portforward"), None),
    (_k("someone@example.com", "create", "pods", "exec"), ("pod_shell", "high")),
    (_k("system:serviceaccount:ci:runner", "create", "pods", "exec"), ("pod_shell", "medium")),
    (_k("someone@example.com", "list", "secrets"), ("secret_read", "high")),
    (_k("system:serviceaccount:kyverno:kyverno", "get", "secrets"), None),
    (_k("someone@example.com", "create", "clusterrolebindings", admin_refs="1"), ("rbac_change", "critical")),
    (_k("someone@example.com", "patch", "rolebindings"), ("rbac_change", "high")),
    (_k("someone@example.com", "get", "rolebindings"), None),
    (_k("system:serviceaccount:argocd:argocd-application-controller", "create", "clusterrolebindings"), None),
    (_k("someone@example.com", "create", "serviceaccounts", "token"), ("token_minted", "high")),
    (_k("someone@example.com", "get", "pods"), None),
])
def test_eks_rules(row, expect):
    assert EKS.classify(row) == expect


def test_a_refused_attempt_is_one_level_lower():
    assert EKS.refused("high", {"responseStatus.code": "403"}) == "medium"
    assert EKS.refused("critical", {"responseStatus.code": "401"}) == "high"
    assert EKS.refused("high", {"responseStatus.code": "200"}) == "high"


def test_eks_collect_and_findings():
    c = _Fake([(lambda q, s: True, [_k("jeremy@example.com", "list", "secrets", code="403",
                                       namespaces='["kube-system"]', n="1", first="2026-10-16T14:10:00Z")])])
    rows = asyncio.run(EKS.EksAuditDetector().collect(c, END))
    f = EKS.EksAuditDetector().to_findings(rows)
    assert len(f) == 1 and f[0]["severity"] == "medium"
    assert "secret read" in f[0]["summary"] and "kube-system" in f[0]["summary"]
    assert f[0]["indicator"] == "secret_read|jeremy@example.com|list|secrets|kube-system|2026-10-16"


# ── registration ───────────────────────────────────────────────────────────────

def test_registered_everywhere():
    names = {d.name for d in DETECTORS}
    assert {"rds_audit", "eks_audit", "edge_attacks"} <= names
    from app.views import shadow_views
    src = inspect.getsource(shadow_views)
    assert "eks_audit:" in src and "rds_audit:" in src
    from shadow_hunter.ai_triage import DETECTOR_GUIDE
    assert {"eks_audit", "rds_audit"} <= set(DETECTOR_GUIDE)


def test_mock_mode_never_calls_out():
    from shadow_hunter.clients import MockDefenderClient
    assert asyncio.run(RDS.RdsAuditDetector().fetch(MockDefenderClient())) == []
    assert asyncio.run(EKS.EksAuditDetector().fetch(MockDefenderClient())) == []


# ── hunt_vlogs ─────────────────────────────────────────────────────────────────

from agent_tools import vlogs as HV  # noqa: E402


@pytest.mark.parametrize("kw,err", [
    ({"source": "edge", "host": "service.example.com"}, "pass the client ip"),
    ({"source": "edge", "ip": "1.2.3.4; drop"}, "not an IP"),
    ({"source": "eks"}, "needs a user or an ip"),
    ({"source": "rds", "user": "a\"b"}, "characters"),
    ({"source": "splunk", "ip": "1.2.3.4"}, "source must be"),
])
def test_hunt_vlogs_rejects_bad_input(kw, err):
    assert err in asyncio.run(HV.hunt_vlogs(**kw))["error"]


def test_hunt_vlogs_anchors_on_the_alert_and_redacts(monkeypatch):
    seen = {}

    class _C:
        def __init__(self, **kw): pass
        async def query(self, q, start, end, limit=1000):
            seen.update(q=q, start=start, end=end)
            return [{"op": "QUERY", "sample": json.dumps(["1,s,root,10.1.1.1,1,1,QUERY,db,'CREATE USER \\'u\\'@\\'%\\' IDENTIFIED BY \\'pw123\\'',0"])}]
    monkeypatch.setattr("shadow_hunter.clients.victorialogs.VictoriaLogsClient", _C)
    r = asyncio.run(HV.hunt_vlogs(source="rds", user="root", host="prod-loan-service",
                                  window_hours=6, alert_time="2026-10-16T14:30:00Z"))
    assert (seen["start"], seen["end"]) == ("2026-10-16T08:30:00Z", "2026-10-16T20:30:00Z")
    assert 'dbuser:="root"' in seen["q"] and "prod\\\\-loan\\\\-service" in seen["q"]
    assert "pw123" not in json.dumps(r) and "***" in json.dumps(r)


def test_hunt_vlogs_is_loop_anchored_and_alert_time_is_hidden():
    import agent_tools.vlogs  # noqa: F401 — registers the tool
    from agent_core.loop import _ALERT_ANCHORED_HUNTS
    from agent_tools.registry import _REGISTRY
    assert "hunt_vlogs" in _ALERT_ANCHORED_HUNTS
    assert "alert_time" in inspect.signature(_REGISTRY["hunt_vlogs"].fn).parameters
    assert "alert_time" not in (_REGISTRY["hunt_vlogs"].parameters or {}).get("properties", {})


def test_unreachable_victorialogs_is_an_error_not_an_empty_answer(monkeypatch):
    class _C:
        def __init__(self, **kw): pass
        async def query(self, *a, **kw): raise RuntimeError("502")
    monkeypatch.setattr("shadow_hunter.clients.victorialogs.VictoriaLogsClient", _C)
    r = asyncio.run(HV.hunt_vlogs(source="edge", ip="1.2.3.4"))
    assert "unavailable" in r["error"] and r["rows"] == []
