"""Story context (Jira alerts + VictoriaLogs), the story page and the v5-style report.
Fixtures follow the DART intrusion of 17-19 Oct 2026."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.views import story_page as P
from shadow_hunter import stories as S
from shadow_hunter import story_context as C
from shadow_hunter.models import AuditLog, Finding, Story

T = datetime(2026, 10, 19, 1, 46, tzinfo=timezone.utc)
ATTACKER, NAT = "43.153.133.154", "65.2.96.12"


def finding(name, summary, at, detector="upwind_threats", raw=None, account=""):
    return Finding.model_construct(detector=detector, severity="high", device_name=name, device_id="",
                                   account_name=account, indicator=summary[:80], summary=summary,
                                   raw={"first_seen": at.isoformat(), **(raw or {})}, created_at=at,
                                   decision="", ai_verdict="", story_id="")


def story(**kw):
    base = dict(title="2 hosts · Upwind · 17-19 Oct", severity="critical", first_seen=T - timedelta(hours=30), last_seen=T,
                entities={"hosts": [{"name": "idart-publisher01", "aliases": ["BYOC::byoc-acme-dc::::ffff:10.0.0.76"],
                                     "ips": ["10.0.0.76"]},
                                    {"name": "publisher02", "aliases": [], "ips": []}],
                          "accounts": ["devon.rao@example.com", "system"]},
                timeline=[{"ts": T.isoformat(), "host": "idart-publisher01", "event": "webshell zz60770.ashx ran whoami",
                           "source": "upwind_threats", "severity": "critical", "finding_id": "f1"}])
    base.update(kw)
    defaults = {k: (f.default_factory() if f.default_factory else f.default) for k, f in Story.model_fields.items()}
    return Story.model_construct(**{**defaults, **base})


DART = [finding("idart-publisher01", f"POST from {ATTACKER} to /DataService/zz60770.ashx", T,
                raw={"ip": ATTACKER, "path": "c:\\inetpub\\zz60770.ashx"}),
        finding("publisher02", f"relay via {NAT} k6123456 upload", T + timedelta(minutes=5), raw={"ip": NAT}),
        finding("publisher02", f"{ATTACKER} again, cmd.exe /c whoami", T + timedelta(minutes=9))]


# ── what gets looked up ──────────────────────────────────────────────────────

def test_terms_put_attacker_ip_first_never_search_the_shared_nat_and_cap():
    st = story()
    terms = C.mention_terms(st, DART)
    assert terms[0] == ATTACKER
    assert NAT not in terms
    assert "zz60770" in terms and len(terms) <= C.MAX_TERMS
    assert NAT in C.public_ips(st, DART)          # still looked up at the edge, just not full-text
    assert C.private_host_ips(st) == ["10.0.0.76"]
    assert C.people(st) == ["devon.rao@example.com"]
    assert C.host_names(st) == ["idart-publisher01", "publisher02"]   # BYOC address is not a host name


def test_merge_rows_adds_counts_widens_times_and_unions_values():
    rows = [{"h": "a", "n": "3", "attack_paths": "1", "first": "2026-10-19T01:00:00Z", "last": "2026-10-19T02:00:00Z", "ips": '["x"]'},
            {"h": "a", "n": "4", "attack_paths": "0", "first": "2026-10-18T23:00:00Z", "last": "2026-10-19T05:00:00Z", "ips": '["y"]'},
            {"h": "b", "n": "10", "first": "2026-10-19T00:00:00Z", "last": "2026-10-19T00:00:00Z"}]
    out = C.merge_rows(rows, ("h",))
    assert [r["h"] for r in out] == ["b", "a"]
    a = out[1]
    assert (a["n"], a["attack_paths"]) == (7, 1)
    assert (a["first"], a["last"]) == ("2026-10-18T23:00:00Z", "2026-10-19T05:00:00Z")
    assert a["ips"] == ["x", "y"]


def test_chunks_cover_the_window_exactly():
    parts = C.chunks(T, T + timedelta(hours=13), 6)
    assert [p[1] - p[0] for p in parts] == [timedelta(hours=6), timedelta(hours=6), timedelta(hours=1)]


class FakeVL:
    """Answers by query shape; can fail or be slow."""
    def __init__(self, fail=lambda q: False):
        self.calls, self.fail = [], fail

    async def query(self, q, start, end, limit=40):
        self.calls.append((q, start, end))
        if self.fail(q):
            raise RuntimeError("504 Gateway Time-out")
        if "source_type:cloudflare" in q and q.startswith("source_type"):
            return [{"ClientRequestHost": "service.example.com", "ClientRequestMethod": "POST", "EdgeResponseStatus": "200",
                     "OriginResponseStatus": "200", "n": "263", "attack_paths": "263",
                     "sample_paths": '["/order-api/open/..%2fv0/order"]', "first": start, "last": end}]
        if "/aws/rds/" in q:
            return [{"log_group": "/aws/rds/cluster/dart-db/audit", "dbuser": "sa", "client": "10.0.0.76", "op": "QUERY", "n": "2",
                     "sample": '["1,srv,sa,10.0.0.76,1,2,QUERY,db,\'CREATE USER x IDENTIFIED BY \\\\\'hunter2pass\\\\\'\',0"]',
                     "first": start, "last": end}]
        if "-source_type:cloudflare" in q:
            return [{"source_type": "aws_s3", "n": "116", "first": start, "last": start}]
        return []


def test_vlogs_context_queries_each_source_and_redacts_database_passwords():
    st, vl = story(), FakeVL()
    out = asyncio.run(C.vlogs_context(st, DART, vl))
    assert set(out["edge"]) == {ATTACKER, NAT}
    assert out["edge"][ATTACKER]["rows"][0]["n"] == 263 * len(C.chunks(*_edge_window(st), C.EDGE_CHUNK_HOURS))
    assert list(out["eks"]) == ["devon.rao@example.com"]
    assert "hunter2pass" not in str(out["rds"]) and "***" in str(out["rds"])
    assert out["mentions"][ATTACKER]["rows"][0]["source_type"] == "aws_s3"
    # full-text search runs in 6 h chunks: a multi-day phrase search times out at the gateway
    mention_calls = [c for c in vl.calls if c[0].startswith("-source_type:cloudflare")]
    assert mention_calls and all(_hours(c) <= C.MENTION_CHUNK_HOURS for c in mention_calls)


def _edge_window(st):
    return st.first_seen - timedelta(hours=C.EDGE_PAD_HOURS), min(st.last_seen + timedelta(hours=C.EDGE_PAD_HOURS),
                                                                   datetime.now(timezone.utc))


def _hours(call):
    a, b = (datetime.fromisoformat(x.replace("Z", "+00:00")) for x in call[1:3])
    return (b - a).total_seconds() / 3600


def test_vlogs_errors_are_recorded_not_raised_and_a_dead_lookup_stops_early():
    st = story()
    vl = FakeVL(fail=lambda q: "-source_type:cloudflare" in q)
    out = asyncio.run(C.vlogs_context(st, DART, vl))
    m = out["mentions"][ATTACKER]
    assert m["rows"] == [] and len(m["errors"]) == 2 and m["chunks"].startswith("0/")
    assert out["edge"][ATTACKER]["rows"]                       # the other sources still answered


def test_time_budget_skips_the_rest_and_says_so():
    out = asyncio.run(C.vlogs_context(story(), DART, FakeVL(), budget_seconds=0))
    res = out["edge"][ATTACKER]
    assert res["rows"] == [] and "time budget" in res["errors"][0]


# ── Jira alerts, timeline, report flow (Mongo) ───────────────────────────────

async def _db(name):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    from entity_graph.models import ShadowResult
    await init_beanie(database=mm.AsyncMongoMockClient()[name], document_models=[Finding, AuditLog, Story, ShadowResult])


def _sr(key, device, user, at):
    from entity_graph.models import ShadowResult
    return ShadowResult(jira_key=key, alert_id=key, alert_name="Suspicious web shell", device_name=device, user_name=user,
                        ai_triage_class="NEEDS_L2", ai_confidence=0.9, created_at=at.replace(tzinfo=None))


def test_related_alerts_match_host_or_person_in_the_window_only():
    async def go():
        await _db("ctx_alerts")
        st = story()
        await _sr("DEMO-1", "IDART-PUBLISHER01.corp.local", "", T).insert()               # host, FQDN form
        await _sr("DEMO-2", "laptop-9", "CORP\\devon.rao", T - timedelta(hours=10)).insert()  # same person
        await _sr("DEMO-3", "laptop-9", "system", T).insert()                               # generic account: never
        await _sr("DEMO-4", "publisher02", "", T + timedelta(days=5)).insert()              # outside ±48 h
        await _sr("DEMO-5", "idart-publisher011", "", T).insert()                           # prefix lookalike
        return await C.related_alerts(st)
    out = asyncio.run(go())
    assert [a["jira_key"] for a in out] == ["DEMO-2", "DEMO-1"]
    assert out[1]["matched_on"] == "host idart-publisher01"
    assert out[0]["matched_on"] == "account devon.rao@example.com"


def test_merged_timeline_orders_findings_alerts_edge_and_logs():
    st = story(context={"alerts": [{"jira_key": "DEMO-9", "alert_name": "Webshell", "created_at": (T - timedelta(hours=1)).isoformat(),
                                    "device_name": "publisher02", "ai_triage_class": "NEEDS_L2"}],
                        "vlogs": {"edge": {ATTACKER: {"rows": [{"ClientRequestHost": "service.example.com", "n": "5", "attack_paths": "3",
                                                                "OriginResponseStatus": "200", "first": "2026-10-17T02:06:00Z",
                                                                "last": "2026-10-19T02:44:00Z"}]}},
                                  "mentions": {ATTACKER: {"rows": [{"source_type": "aws_s3", "n": "116",
                                                                    "first": "2026-10-18T19:45:15Z"}]}}}})
    tl = C.merged_timeline(st)
    assert [t["kind"] for t in tl] == ["edge", "logs", "alert", "finding", "edge"]
    assert "3 attack-shaped answered 2xx" in tl[0]["event"]
    assert "aws_s3" in tl[1]["event"] and "116" in tl[1]["event"]
    st.context["vlogs"]["edge"][NAT] = st.context["vlogs"]["edge"][ATTACKER]
    assert not any(t["ref"] == NAT for t in C.merged_timeline(st))   # the shared NAT is not an event


def test_request_report_queues_a_claude_pass_and_posting_the_report_clears_it():
    async def go():
        await _db("ctx_report")
        st = Story(title="t", finding_ids=[])
        await st.insert()
        req = await S.request_report(st.id, "riley", "https://uat.example/")
        queued = await Story.find({"report_requested_at": {"$ne": None}}).count()
        b = await S.bundle(st.id)
        await S.set_report(st.id, [{"heading": "Status and summary", "body": "Contained."}], "claude-code-manual",
                           S.REPORT_PROMPT_VERSION)
        return req, queued, b, await Story.get(st.id)
    req, queued, b, st = asyncio.run(go())
    assert req["requested"] and not req["written"] and queued == 1
    assert f"https://uat.example/api/shadow/stories/{st.id}/bundle" in req["prompt"]
    assert '"by": "claude-code-manual"' in req["prompt"]
    assert [s["heading"] for s in b["report_template"]][0] == "Status and summary"
    assert {"related_alerts", "vlogs", "iocs", "previous_report", "report_guide"} <= set(b)
    assert st.report_requested_at is None and st.report["version"] == 1


def test_refresh_keeps_old_alerts_when_the_lookup_fails_and_stores_redacted_context(monkeypatch):
    async def go():
        await _db("ctx_refresh")
        st = Story(title="t", finding_ids=[], first_seen=T, last_seen=T,
                   context={"alerts": [{"jira_key": "SIM-OLD"}]})
        await st.insert()

        async def boom(_):
            raise RuntimeError("mongo down")
        monkeypatch.setattr(C, "related_alerts", boom)

        class VL(FakeVL):
            async def query(self, q, start, end, limit=40):
                return [{"source_type": "aws_s3", "n": "1", "first": start, "note": "password=Sup3rS3cretValue!"}]
        await C.refresh(st.id, client=VL())
        return await Story.get(st.id)
    st = asyncio.run(go())
    assert st.context["alerts"] == [{"jira_key": "SIM-OLD"}] and "mongo down" in st.context["alerts_error"]
    assert "Sup3rS3cretValue" not in str(st.context) and st.context_at is not None


# ── rendering ────────────────────────────────────────────────────────────────

def test_markdown_subset_renders_tables_and_never_passes_html_or_script_links():
    html = P.md("**Exposed:** `562211`\n\n| Time | Outcome |\n| --- | --- |\n| 07:16 | rejected, code 108 |\n\n"
                "- one\n- two <script>alert(1)</script>\n\n[ok](https://x.example/a) [bad](javascript:alert(1))")
    assert "<b>Exposed:</b> <code>562211</code>" in html
    assert "<th>Time</th>" in html and "<td>rejected, code 108</td>" in html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert '<a href="https://x.example/a"' in html and 'href="javascript' not in html
    assert "<ul><li>one</li>" in html


def test_story_page_and_report_render_everything_escaped_in_ist():
    st = story(title="<img src=x onerror=alert(1)>", id="s1",
               report={"version": 2, "by": "claude-code-manual", "at": T.isoformat(),
                       "sections": [{"heading": "Status and summary", "body": "No order was placed."},
                                    {"heading": "Containment and remediation tracker",
                                     "body": "| # | Action | Status |\n| --- | --- | --- |\n| 1 | Block IP | Done |"}]},
               context={"alerts": [{"jira_key": "DEMO-9", "alert_name": "Webshell", "created_at": T.isoformat(),
                                    "device_name": "publisher02", "matched_on": "host publisher02"}],
                        "vlogs": {"mentions": {ATTACKER: {"window": [T.isoformat(), T.isoformat()], "chunks": "1/1",
                                                          "rows": [{"source_type": "aws_s3", "n": "116", "first": T.isoformat()}]}}},
                        "fetched_at": T.isoformat()})
    page = P.render_story_page(st, DART)
    rep = P.render_story_report(st, DART)
    for html in (page, rep):
        assert "<img src=x" not in html and "&lt;img" in html
        assert "jira.example.com/browse/DEMO-9" in html and "aws_s3" in html
        assert "19 Oct 07:16" in html                       # 01:46 UTC shown in IST
        assert ATTACKER in html                             # IOC table
    assert "No order was placed." in page                   # lead = first section
    assert "Incident Report v2" in rep and "supersedes v1" in rep and "<td>Block IP</td>" in rep
    assert "/shadow?finding=" in page


# ── analyst indicators ───────────────────────────────────────────────────────

def test_indicator_kinds_accept_public_ips_and_tokens_only():
    assert C.indicator_kind(ATTACKER) == "ip"
    assert C.indicator_kind("zz60770") == "term" and C.indicator_kind("62.2.96.0/24") == "term"
    assert C.indicator_kind("10.0.0.76") is None          # private: nothing to see at the edge
    assert C.indicator_kind('x" or 1=1') is None and C.indicator_kind("ab") is None


def test_an_analysts_indicator_is_searched_first_even_when_the_findings_carry_none():
    # the DART story's 91 findings held no public IP; the attacker IP came from IIS logs
    st = story(indicators=[{"value": ATTACKER, "kind": "ip", "note": "IIS logs", "by": "riley"},
                           {"value": "atex", "kind": "term"}])
    bare = [finding("publisher02", "encoded powershell", T, detector="encoded_powershell")]
    assert C.public_ips(st, bare) == [ATTACKER]
    assert C.mention_terms(st, bare)[:2] == [ATTACKER, "atex"]
    out = asyncio.run(C.vlogs_context(st, bare, FakeVL()))
    assert ATTACKER in out["edge"] and ATTACKER in out["mentions"]
    ioc = C.iocs(st, bare)
    assert ioc[0] == {"value": ATTACKER, "type": "IP", "note": "IIS logs · added by riley"}


def test_iocs_leave_out_our_own_asset_ids_and_dotnet_namespaces():
    f = finding("idart-publisher01", "Upwind on uwr-bb8b0a1fe961b510280d5b517123eb73 using System.Net "
                "dropped f2628a993b00596247d6da2858c6538a169089cc", T)
    f.device_id = "uwr-bb8b0a1fe961b510280d5b517123eb73"
    vals = {i["value"] for i in C.iocs(story(), [f])}
    assert "f2628a993b00596247d6da2858c6538a169089cc" in vals
    assert "bb8b0a1fe961b510280d5b517123eb73" not in vals and "system.net" not in vals


def test_add_and_remove_indicator_validates_dedups_audits_and_marks_context_due():
    async def go():
        await _db("ctx_ind")
        st = Story(title="t", finding_ids=[], context_at=T)
        await st.insert()
        a = await S.add_indicator(st.id, f" {ATTACKER} ", "IIS logs", "riley")
        again = await S.add_indicator(st.id, ATTACKER, "", "riley")
        with pytest.raises(ValueError):
            await S.add_indicator(st.id, "10.0.0.1", "", "riley")
        due = (await Story.get(st.id)).context_at
        r = await S.remove_indicator(st.id, ATTACKER, "riley")
        acts = [x.action for x in await AuditLog.find_all().to_list()]
        return a, again, due, r, acts
    a, again, due, r, acts = asyncio.run(go())
    assert a["added"] and a["indicators"][0]["value"] == ATTACKER and not again["added"]
    assert due is None and r["indicators"] == []
    assert acts.count("story.indicator_added") == 1 and "story.indicator_removed" in acts


def test_story_page_has_the_add_indicator_form_and_chips():
    html = P.render_story_page(story(id="s2", indicators=[{"value": ATTACKER, "kind": "ip", "note": "IIS"}]), DART)
    assert 'id="add-ind"' in html and f"data-rm='{ATTACKER}'" in html


# ── EKS nodes behind a story's workloads (partner-onboarding SSRF, 22-23 Oct) ─

PO_T = datetime(2026, 10, 22, 17, 30, tzinfo=timezone.utc)
NODE_A, NODE_B = "ip-10-193-125-65.ap-south-1.compute.internal", "ip-10-193-86-192.ap-south-1.compute.internal"
REBIND, OAST = "169.254.169.254.nip.io", "dbd5g69ft4rf6h7dl7g06frnfqcppbngq.oast.live"
UPWIND_NET = {"triggers": [{"events": [
    {"rawLog": '{"reqDomain": "%s", "destDomain": "%s"}' % (REBIND, REBIND)},
    {"rawLog": '{"reqDomain": "%s.svc.cluster.local"}' % OAST},           # resolver expansion: dropped
    {"rawLog": '{"labels": {"dns.reqDomain": "%s"}}' % OAST},
    {"rawLog": "not json"}]}]}


def po_story(**kw):
    return story(**kw, title="2 hosts · Upwind · 22 Oct", first_seen=PO_T - timedelta(minutes=45), last_seen=PO_T + timedelta(hours=1),
                 entities={"hosts": [{"name": "partner-onboarding-service", "aliases": [], "ips": []},
                                     {"name": "node-local-dns", "aliases": [], "ips": []}], "accounts": []})


PO_FINDINGS = [finding("partner-onboarding-service", "Cloud Metadata (IMDS) DNS Rebinding Attempt", PO_T,
                       raw={"category": "NETWORK", "upwind_ids": ["uwnd-1", "uwnd-2"]}),
               finding("partner-onboarding-service", "Python History Overwrite", PO_T,
                       raw={"category": "FILE_EVENTS", "upwind_ids": ["uwnd-3"]})]


class NodeVL(FakeVL):
    async def query(self, q, start, end, limit=40):
        self.calls.append((q, start, end))
        if q.startswith('kubernetes.container_name:"partner-onboarding-service"'):
            return [{"kubernetes.host": NODE_A, "kubernetes.namespace_name": "partner-onboarding-service", "n": "40"},
                    {"kubernetes.host": NODE_B, "kubernetes.namespace_name": "partner-onboarding-service", "n": "9"}]
        if q.startswith('kubernetes.container_name:"node-local-dns"'):    # a DaemonSet: every node
            return [{"kubernetes.host": f"ip-10-193-0-{i}.ap-south-1.compute.internal", "n": "1"} for i in range(30)]
        return []


class FakeSentinel:
    def __init__(self, rows):
        self.rows, self.kql = rows, []

    async def query(self, kql):
        self.kql.append(kql)
        return self.rows


GD_ROWS = [{"iid": "i-03b20b3d6f4b473ea", "pip": "10.193.125.65", "findings": 7, "types": '["UnauthorizedAccess:EC2/MetadataDNSRebind"]',
            "doms": f'["{REBIND}"]', "t0": "2026-10-22T16:47:42Z", "t1": "2026-10-22T17:51:31Z"},
           {"iid": "i-0782e7125b7ce3e8b", "pip": "10.193.115.160", "findings": 3,
            "types": '["Impact:EC2/SuspiciousDomainRequest.Reputation"]', "doms": f'["{OAST}"]', "t0": "", "t1": ""},
           {"iid": "", "pip": "10.193.1.1", "findings": 1, "types": "[]", "doms": "[]"}]        # no instance: dropped


async def _fetch(i):
    return UPWIND_NET if i in ("uwnd-1", "uwnd-2") else {"triggers": []}


def test_detection_domains_reads_raw_logs_and_drops_cluster_expansions():
    from edr_triage.upwind_client import detection_domains
    assert detection_domains(UPWIND_NET) == [REBIND, OAST]
    assert detection_domains({}) == [] and detection_domains({"evidences": ['{"evidence": {"reqDomain": "a.b.oast.fun"}}']}) == ["a.b.oast.fun"]


def test_story_domains_read_network_detections_only_and_cap():
    calls = []

    async def fetch(i):
        calls.append(i)
        return await _fetch(i)
    assert asyncio.run(C.story_domains(PO_FINDINGS, fetch)) == [REBIND, OAST]
    assert calls == ["uwnd-1", "uwnd-2"]                         # the FILE_EVENTS detection is not fetched


def test_workload_nodes_maps_pods_to_nodes_and_skips_daemonsets():
    out = asyncio.run(C.workload_nodes(po_story(), NodeVL(), C._Budget(30)))
    assert out["partner-onboarding-service"] == {"nodes": [NODE_A, NODE_B], "namespaces": ["partner-onboarding-service"]}
    assert "DaemonSet" in out["node-local-dns"]["skipped"] and "nodes" not in out["node-local-dns"]
    assert C.node_ip(NODE_A) == "10.193.125.65" and C.node_ip("partner-onboarding-service") == ""


def test_guardduty_lookup_validates_everything_it_puts_in_kql():
    sen = FakeSentinel(GD_ROWS)
    got = asyncio.run(C.guardduty_instances(["10.193.125.65", "8.8.8.8", "10.0.0.1') or 1==1 //"],
                                            [REBIND, "evil'); drop", "x"], PO_T, PO_T, sen))
    kql = sen.kql[0]
    assert "'10.193.125.65'" in kql and "8.8.8.8" not in kql and "1==1" not in kql
    assert f"'{REBIND}'" in kql and "drop" not in kql
    assert [g["instance_id"] for g in got] == ["i-03b20b3d6f4b473ea", "i-0782e7125b7ce3e8b"]
    assert got[0]["types"] == ["UnauthorizedAccess:EC2/MetadataDNSRebind"]
    assert asyncio.run(C.guardduty_instances([], [], PO_T, PO_T, FakeSentinel([]))) == []


def test_infra_context_joins_pod_nodes_and_domain_only_nodes():
    out = asyncio.run(C.infra_context(po_story(), PO_FINDINGS, NodeVL(), sentinel=FakeSentinel(GD_ROWS), fetch=_fetch))
    by_iid = {n.get("instance_id"): n for n in out["nodes"]}
    assert by_iid["i-03b20b3d6f4b473ea"]["workloads"] == ["partner-onboarding-service"]
    assert by_iid["i-0782e7125b7ce3e8b"]["via"] == "GuardDuty domain" and by_iid["i-0782e7125b7ce3e8b"]["workloads"] == []
    assert any(n["node"] == NODE_B and not n.get("instance_id") for n in out["nodes"])   # pods there, no GuardDuty
    assert out["domains"] == [REBIND, OAST] and "errors" not in out


def test_infra_errors_are_recorded_and_the_rest_still_runs():
    class Down:
        async def query(self, kql):
            raise RuntimeError("Log Analytics 504")
    out = asyncio.run(C.infra_context(po_story(), PO_FINDINGS, NodeVL(), sentinel=Down(), fetch=_fetch))
    assert out["domains"] == [REBIND, OAST] and any("GuardDuty" in e for e in out["errors"])
    assert {n["node"] for n in out["nodes"]} == {NODE_A, NODE_B}


def _gd_ticket(key, iid, at, device=""):
    from entity_graph.models import ShadowResult
    return ShadowResult(jira_key=key, alert_id=key, alert_name=f"The EC2 instance {iid} may be the target of a DNS rebinding attack.",
                        device_name=device, user_name="", ai_triage_class="NEEDS_L2", ai_confidence=0.6,
                        created_at=at.replace(tzinfo=None))


def test_refresh_links_the_guardduty_ticket_on_the_node_the_story_ran_on():
    """DEMO-118243: the ticket names the node (no device), the story names the deployment."""
    async def go():
        await _db("ctx_nodes")
        st = po_story()
        st.finding_ids = []
        await st.insert()
        for f in PO_FINDINGS:
            f.story_id = st.id
            await f.insert()
            st.finding_ids.append(f.id)
        await st.save()
        await _gd_ticket("DEMO-118243", "i-03b20b3d6f4b473ea", PO_T + timedelta(hours=2)).insert()
        await _gd_ticket("SIM-OTHER", "i-0ffffffffffffffff", PO_T).insert()               # another node
        await _gd_ticket("SIM-OLD", "i-03b20b3d6f4b473ea", PO_T - timedelta(days=5)).insert()  # outside ±48 h
        await _gd_ticket("SIM-DEV", "", PO_T, device="IP-10-193-86-192.ap-south-1.compute.internal").insert()
        await C.refresh(st.id, client=NodeVL(), sentinel=FakeSentinel(GD_ROWS), fetch=_fetch)
        return await Story.get(st.id)
    st = asyncio.run(go())
    alerts = {a["jira_key"]: a for a in st.context["alerts"]}
    assert set(alerts) == {"DEMO-118243", "SIM-DEV"}
    assert alerts["DEMO-118243"]["matched_on"].startswith("i-03b20b3d6f4b473ea: node ip-10-193-125-65")
    assert "partner-onboarding-service" in alerts["DEMO-118243"]["matched_on"]
    assert alerts["SIM-DEV"]["matched_on"].startswith("ip-10-193-86-192")
    assert st.context["infra"]["domains"] == [REBIND, OAST]


def test_detection_cap_samples_every_kind_of_network_detection():
    """3fbe2e00 on UAT: six OAST detections loaded first and the cap of 6 dropped the rebind ones."""
    oast = [finding("partner-onboarding-service", "x", PO_T,
                    raw={"category": "NETWORK", "title": "Workload Resolved an OAST Domain", "upwind_ids": [f"uwnd-o{i}"]})
            for i in range(6)]
    rebind = [finding("partner-onboarding-service", "x", PO_T,
                      raw={"category": "NETWORK", "title": "Cloud Metadata (IMDS) DNS Rebinding Attempt",
                           "upwind_ids": ["uwnd-r1", "uwnd-r2"]})]
    ids = C._upwind_ids(oast + rebind)
    assert ids[:2] == ["uwnd-o0", "uwnd-r1"] and "uwnd-r2" in ids[:C.MAX_DETECTIONS]
    assert len(ids) == 8 and len(set(ids)) == 8


def test_iocs_drop_our_upwind_ids_and_vendor_description_domains_and_add_observed_ones():
    """3fbe2e00: 9 of its 'hashes' were our own uwnd- ids, webhook.site came from Upwind's rule
    description, and none of the domains the pods actually resolved were listed."""
    f = finding("partner-onboarding-service", "Upwind detection [HIGH/NETWORK]: Workload Resolved an OAST Domain", PO_T,
                raw={"category": "NETWORK", "upwind_id": "uwnd-7b2cf0cd92771e2d60a675051d983fd6",
                     "description": "callback infrastructure used by interactsh, Burp Collaborator and webhook.site",
                     "note": "dropped c0ffee0123456789abcdef0123456789abcdef01"})
    infra = {"domains": [OAST, REBIND],
             "nodes": [{"node": NODE_A, "ip": "10.193.125.65", "instance_id": "i-03b20b3d6f4b473ea",
                        "guardduty_types": ["UnauthorizedAccess:EC2/MetadataDNSRebind"], "workloads": ["partner-onboarding-service"]},
                       {"node": NODE_B, "ip": "10.193.86.192", "workloads": ["partner-onboarding-service"], "background": True}]}
    st = po_story(context={"infra": infra})
    rows = C.iocs(st, [f])
    vals = {r["value"]: r for r in rows}
    assert "7b2cf0cd92771e2d60a675051d983fd6" not in vals and "webhook.site" not in vals
    assert "c0ffee0123456789abcdef0123456789abcdef01" in vals            # a real hash still listed
    assert vals[OAST]["type"] == "Domain" and vals[REBIND]["note"].startswith("queried by the workload")
    assert vals["i-03b20b3d6f4b473ea"]["type"] == "Instance" and "10.193.125.65" in vals["i-03b20b3d6f4b473ea"]["note"]
    assert "cluster DNS resolver" in vals["node-local-dns"]["note"]
    assert not any(r["value"].startswith("ip-10-193-86-192") for r in rows)  # background node: not an IOC


def test_a_domain_the_attack_touched_stays_even_if_the_description_also_names_it():
    f = finding("web01", "beacon to evil.example.org", PO_T,
                raw={"description": "resolves evil.example.org", "dns": "evil.example.org"})
    assert "evil.example.org" in {r["value"] for r in C.iocs(po_story(), [f])}
