"""Incident stories: grouping, link reasons, safety rules and redaction (shadow_hunter/stories.py).
Fixtures follow the DART intrusion of 17-19 Oct 2026."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from shadow_hunter import stories as S
from shadow_hunter.models import AuditLog, Finding, Story

NOW = datetime(2026, 10, 19, 6, 0, tzinfo=timezone.utc)
T = datetime(2026, 10, 18, 19, 39, tzinfo=timezone.utc)
BYOC = "BYOC::byoc-acme-dc::::ffff:10.0.0.76"
ASSET = "uwr-bb8b0a1fe961b510280d5b517123eb73"


def upwind(name, title, at, asset=ASSET, sev="high", typ="", ai=""):
    return Finding.model_construct(detector="upwind_threats", severity=sev, device_name=name, device_id=asset, ai_verdict=ai,
                   indicator=f"{title}|{name}|{at:%Y-%m-%d}".lower(), summary=f"Upwind detection: {title} on '{name}'",
                   raw={"title": title, "first_seen": at.isoformat(), "resource": {"name": name, "upwind_asset_id": asset, "type": typ}},
                   created_at=NOW - timedelta(hours=1))


def mde(name, detector, summary, at, sev="medium", device_id="a" * 40, raw=None):
    return Finding.model_construct(detector=detector, severity=sev, device_name=name, device_id=device_id,
                   indicator=summary[:80], summary=summary,
                   raw={"FirstSeen": at.isoformat(), **(raw or {})}, created_at=NOW - timedelta(hours=2))


async def _db(name):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    await init_beanie(database=mm.AsyncMongoMockClient()[name], document_models=[Finding, AuditLog, Story])


async def _insert(*fs):
    out = []
    for f in fs:
        d = Finding(**f.model_dump())
        await d.insert()
        out.append(d)
    return out


def test_byoc_address_name_and_hostname_resolve_to_one_host():
    a = upwind(BYOC, "A host is retrieving its system hostname", T, typ="INTERNAL_VPC")
    b = upwind("idart-publisher01", "A host is retrieving the current user identity", T + timedelta(minutes=10), typ="BYOC_HOST")
    f2e, ents = S.resolve_entities([a, b])
    assert f2e[a.id] == f2e[b.id] == "idart-publisher01"
    assert ents["idart-publisher01"]["ips"] == ["10.0.0.76"]


def test_same_rare_title_links_two_hosts_but_an_everyday_title_on_many_hosts_does_not():
    rare = [upwind("publisher02", "A host is searching files recursively for credential-related strings", T, asset="uwr-p2"),
            upwind("idart-publisher01", "A host is searching files recursively for credential-related strings", T + timedelta(minutes=5))]
    common = [upwind(f"uat-host-{i}", "Login Banner Inspection", T, asset=f"uwr-{i}") for i in range(7)]
    fs = rare + common
    f2e, _ = S.resolve_entities(fs)
    edges = S.shared_indicator_edges(fs, f2e, {f.id: S.tokens(f) for f in fs})
    assert len(edges) == 1 and edges[0]["kind"] == "shared_indicator"
    assert "publisher02" in edges[0]["reason"] and "idart-publisher01" in edges[0]["reason"]


def test_shared_file_stem_links_hosts_but_cmd_exe_never_does():
    x = mde("uat-dart-pubsr", "encoded_powershell", "w3wp > cmd > powershell writes DataService\\zz60770.ashx", T)
    y = upwind("publisher02", "Batch script via nested shells D:\\IDartswwwroot\\DataService\\zz60770.ashx", T + timedelta(minutes=8), asset="uwr-p2")
    z = mde("laptop-1", "suspicious_parent_child", "excel.exe started cmd.exe", T, device_id="b" * 40)
    w = mde("laptop-2", "suspicious_parent_child", "word.exe started cmd.exe", T, device_id="c" * 40)
    fs = [x, y, z, w]
    f2e, _ = S.resolve_entities(fs)
    edges = S.shared_indicator_edges(fs, f2e, {f.id: S.tokens(f) for f in fs})
    linked = {frozenset((e["a"], e["b"])) for e in edges}
    assert frozenset((x.id, y.id)) in linked
    assert not any(z.id in p or w.id in p for p in linked)


def test_network_touch_only_inside_the_60_minute_window():
    src = mde("uat-dart-pubsr.corp.example.com", "encoded_powershell", "w3wp > cmd", T - timedelta(minutes=30))
    dst = upwind(BYOC, "A host is retrieving its system hostname", T + timedelta(minutes=10))
    fs = [src, dst]
    f2e, ents = S.resolve_entities(fs)
    inside = [{"DeviceName": "uat-dart-pubsr.corp.example.com", "RemoteIP": "10.0.0.76", "Times": [T.isoformat()]}]
    outside = [{"DeviceName": "uat-dart-pubsr.corp.example.com", "RemoteIP": "10.0.0.76", "Times": [(T - timedelta(hours=3)).isoformat()]}]
    after = [{"DeviceName": "uat-dart-pubsr.corp.example.com", "RemoteIP": "10.0.0.76", "Times": [(T + timedelta(hours=1)).isoformat()]}]
    e = S.network_touch_edges(fs, f2e, ents, inside)
    assert len(e) == 1 and "10 min later" in e[0]["reason"]
    assert S.network_touch_edges(fs, f2e, ents, outside) == []
    assert S.network_touch_edges(fs, f2e, ents, after) == []


def test_a_lone_finding_or_a_quiet_pair_on_one_host_is_not_a_story():
    lone = [mde("laptop-1", "rare_persistence", "task A", T)]
    pair = [mde("laptop-2", "rare_persistence", "task A", T, device_id="b" * 40),
            mde("laptop-2", "rare_persistence", "task B", T + timedelta(minutes=5), device_id="b" * 40)]
    for comp in (lone, pair):
        f2e, _ = S.resolve_entities(comp)
        assert not S.qualifies(comp, f2e)
    trio = pair + [mde("laptop-2", "encoded_powershell", "enc ps", T + timedelta(minutes=9), sev="high", device_id="b" * 40)]
    f2e, _ = S.resolve_entities(trio)
    assert S.qualifies(trio, f2e)


def test_build_groups_the_dart_shape_and_is_idempotent():
    async def go():
        await _db("stories_build")
        fs = await _insert(
            mde("uat-dart-pubsr", "encoded_powershell", "w3wp writes DataService\\zz60770.ashx", T, sev="medium"),
            mde("uat-dart-pubsr", "unusual_remote_logons", "RDP by administrator", T + timedelta(hours=1)),
            upwind(BYOC, "A host is searching files recursively for credential-related strings DataService\\zz60770.ashx", T + timedelta(minutes=10),
                   ai="true_positive"),
            upwind("idart-publisher01", "A host is retrieving the current user identity", T + timedelta(minutes=20), typ="BYOC_HOST"),
            upwind("publisher02", "A host is retrieving the current user identity", T + timedelta(minutes=21), asset="uwr-p2"),
            mde("laptop-9", "rare_persistence", "WPS update task", T, device_id="9" * 40),
        )
        r1 = await S.build(now=NOW)
        r2 = await S.build(now=NOW)
        sts = await Story.find_all().to_list()
        laptop = await Finding.get(fs[-1].id)
        return r1, r2, sts, laptop
    r1, r2, sts, laptop = asyncio.run(go())
    assert r1["created"] == 1 and r2["created"] == 0 and r2["updated"] == 0
    assert len(sts) == 1
    st = sts[0]
    assert len(st.finding_ids) == 5 and st.severity == "high"
    hosts = {h["name"] for h in st.entities["hosts"]}
    assert hosts == {"uat-dart-pubsr", "idart-publisher01", "publisher02"}
    assert {e["kind"] for e in st.edges} >= {"same_entity", "shared_indicator"}
    assert all(e["reason"] for e in st.edges)
    assert [t["ts"] for t in st.timeline] == sorted(t["ts"] for t in st.timeline)
    assert laptop.story_id == ""


def test_detached_finding_never_rejoins_closed_story_never_reopens_severity_never_drops():
    async def go():
        await _db("stories_rules")
        a = upwind("publisher02", "A host is retrieving the current user identity", T, asset="uwr-p2", ai="true_positive")
        b = upwind("idart-publisher01", "A host is retrieving the current user identity", T + timedelta(minutes=3))
        c = mde("idart-publisher01", "encoded_powershell", "enc", T + timedelta(minutes=30), sev="low")
        await _insert(a, b, c)
        await S.build(now=NOW)
        st = (await Story.find_all().to_list())[0]
        await S.detach(st.id, c.id, "analyst")
        await S.build(now=NOW)
        st = await Story.get(st.id)
        detached_ok = c.id not in st.finding_ids and (await Finding.get(c.id)).story_id == ""
        sev_ok = st.severity == "high"
        await S.set_status(st.id, "closed", "analyst")
        d = upwind("publisher02", "A host is retrieving the current user identity", T + timedelta(hours=2), asset="uwr-p2",
                   ai="true_positive")
        e = upwind("idart-publisher01", "A host is retrieving the current user identity", T + timedelta(hours=2, minutes=1))
        await _insert(d, e)
        await S.build(now=NOW)
        all_st = await Story.find_all().to_list()
        old = await Story.get(st.id)
        return detached_ok, sev_ok, old, all_st
    detached_ok, sev_ok, old, all_st = asyncio.run(go())
    assert detached_ok and sev_ok
    assert old.status == "closed" and len(old.finding_ids) == 2
    new = [s for s in all_st if s.id != old.id]
    assert len(new) == 1 and new[0].related == [old.id] and len(new[0].finding_ids) == 2


def test_report_is_redacted_versioned_and_audited():
    async def go():
        await _db("stories_report")
        st = Story(title="t", finding_ids=[])
        await st.insert()
        secret = ("Token eyJhbGciOiJIUzI1NiJ9.eyJ1bmlxdWVfbmFtZSI6ImFjbWVsaXZlIn0.sig Authorization: Bearer abcDEF123456789 "
                  "client_secret=as2rporyyp pwd=Passw0rd!23 key AKIAABCDEFGHIJKLMNOP account 111122223333")
        r1 = await S.set_report(st.id, [{"heading": "Summary", "body": secret}], "claude-code-manual", "v1")
        r2 = await S.set_report(st.id, [{"heading": "Summary", "body": "second"}], "claude-code-manual", "v1")
        st = await Story.get(st.id)
        audits = await AuditLog.find(AuditLog.action == "story.report").count()
        return r1, r2, st, audits
    r1, r2, st, audits = asyncio.run(go())
    body = r1["sections"][0]["body"]
    for leak in ("eyJhbGci", "abcDEF123456789", "as2rporyyp", "Passw0rd!23", "AKIAABCDEFGHIJKLMNOP", "111122223333"):
        assert leak not in body
    assert "11…333" in body
    assert r2["version"] == 2 and st.report_history[0]["version"] == 1 and audits == 2
    with pytest.raises(ValueError):
        asyncio.run(S.set_report(st.id, [], "x"))


def test_enrichment_failure_still_groups():
    class Broken:
        async def query(self, kql):
            raise RuntimeError("Log Analytics 429")

    async def go():
        await _db("stories_enrich_fail")
        await _insert(upwind("publisher02", "A host is retrieving the current user identity", T, asset="uwr-p2", ai="true_positive"),
                      upwind("idart-publisher01", "A host is retrieving the current user identity", T + timedelta(minutes=2)))
        return await S.build(now=NOW, client=Broken())
    r = asyncio.run(go())
    assert r["created"] == 1 and "429" in r["enrichment_error"]


def test_vendor_installed_binaries_never_link_hosts_but_app_files_do():
    a = mde("pc-1", "rare_persistence", r"task runs C:\Windows\System32\DriverStore\FileRepository\cui.inf\igfxEM.exe", T, device_id="1" * 40)
    b = mde("pc-2", "rare_persistence", r"task runs C:\Windows\System32\DriverStore\FileRepository\cui.inf\igfxEM.exe", T, device_id="2" * 40)
    c = mde("uat-dart-pubsr", "encoded_powershell", r"ReadAllBytes('C:\IDarts Services\DIPL API Services\ApiServices.dll.config')", T)
    d = upwind("publisher02", r"findstr acme D:\ApiServices.dll.con*", T + timedelta(minutes=5), asset="uwr-p2")
    fs = [a, b, c, d]
    f2e, _ = S.resolve_entities(fs)
    pairs = {frozenset((e["a"], e["b"])) for e in S.shared_indicator_edges(fs, f2e, {f.id: S.tokens(f) for f in fs})}
    assert frozenset((a.id, b.id)) not in pairs and frozenset((c.id, d.id)) in pairs


def test_attacker_drops_in_windows_temp_still_count_and_unrelated_paths_do_not_hide_a_file():
    assert not S._installed_binary("evil.exe", r'value "C:\Windows\Temp\evil.exe"')
    assert not S._installed_binary("x-lite.exe", r'RunOnce = "C:\WINDOWS\is-AB.exe" /REG "C:\Users\s\Downloads\X-Lite.exe"')
    assert S._installed_binary("igfxem.exe", r"C:\WINDOWS\System32\DriverStore\x\igfxEM.exe")


def test_redaction_keeps_the_last_four_of_long_secrets_only_and_is_stable():
    assert S.clean("client_secret=Zx9QwErTyUiOp1234") == "client_secret=<redacted …1234>"
    assert S.clean("pwd=Passw0rd!23") == "pwd=<redacted>"                     # short: hidden whole
    assert S.clean("Bearer abcDEF123456789") == "Bearer <redacted …6789>"
    assert S.clean("AKIAABCDEFGHIJKLMNOP") == "AKIA<redacted …MNOP>"
    assert S.clean("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sigXYZ9") == "<jwt …XYZ9>"
    for s in ("client_secret=Zx9QwErTyUiOp1234 Bearer abcDEF123456789 pwd=Passw0rd!23", "password reset flow"):
        assert S.clean(S.clean(s)) == S.clean(s)


# ── AI false-positive suggestions and dismissed findings (2026-10-20) ─────────

RARE = "A host is searching files recursively for credential-related strings"


def _three(ai):
    fs = [upwind(f"host-{i}", RARE, T + timedelta(minutes=i), asset=f"uwr-{i}") for i in range(3)]
    for f in fs:
        f.ai_verdict = ai
    return fs


def test_ai_false_positives_alone_never_make_a_story_but_join_one_that_qualifies():
    fs = _three("false_positive")
    f2e, _ = S.resolve_entities(fs)
    assert not S.qualifies(fs, f2e)
    real = upwind("host-9", RARE, T + timedelta(minutes=9), asset="uwr-9")
    real.ai_verdict = "unsure"
    f2e, _ = S.resolve_entities(fs + [real])
    assert not S.qualifies(fs + [real], f2e)          # one real finding on one host is not a story
    real2 = upwind("host-8", RARE, T + timedelta(minutes=8), asset="uwr-8")
    f2e, _ = S.resolve_entities(fs + [real, real2])
    assert S.qualifies(fs + [real, real2], f2e)       # two hosts with real signal: the AI-FP ones come along
    tp = fs[0].model_copy()
    tp.decision = "true_positive"
    assert not S.ai_dismissed(tp)                      # a human confirmation outranks the AI


def test_prune_drops_dismissed_findings_and_closes_stories_left_with_ai_noise():
    async def go():
        await _db("stories_prune")
        noisy = await _insert(*_three("false_positive"))
        real = await _insert(*_three("unsure"))
        s1 = Story(status="open", finding_ids=[f.id for f in noisy], timeline=[{"finding_id": f.id} for f in noisy])
        s2 = Story(status="open", finding_ids=[f.id for f in real])
        await s1.insert(); await s2.insert()
        for f in noisy:
            await Finding.find_one(Finding.id == f.id).update({"$set": {"story_id": s1.id}})
        # analyst snoozes one of the real story's findings: it leaves, the story stays (2 hosts left)
        await Finding.find_one(Finding.id == real[0].id).update({"$set": {"decision": "snooze"}})
        out = await S.prune(NOW)
        return out, await Story.get(s1.id), await Story.get(s2.id), await Finding.get(noisy[0].id), \
            [a.action for a in await AuditLog.find_all().to_list()]
    out, s1, s2, f0, acts = asyncio.run(go())
    assert out == (1, 1)
    assert s1.status == "closed" and s1.closed_by == "stories:auto"
    assert s2.status == "open" and len(s2.finding_ids) == 2 and s2.detached
    assert f0.story_id                                  # AI-FP members keep their link to the closed story
    assert "story.auto_closed" in acts and "story.pruned" in acts


def test_prune_never_drops_a_confirmed_threat():
    async def go():
        await _db("stories_prune_tp")
        fs = await _insert(*_three("false_positive"))
        await Finding.find_one(Finding.id == fs[0].id).update({"$set": {"decision": "true_positive"}})
        await Finding.find_one(Finding.id == fs[1].id).update({"$set": {"decision": "true_positive"}})
        st = Story(status="open", finding_ids=[f.id for f in fs])
        await st.insert()
        await S.prune(NOW)
        return await Story.get(st.id)
    st = asyncio.run(go())
    assert st.status == "open" and len(st.finding_ids) == 3


def test_a_finding_whose_raw_resource_is_a_string_does_not_break_grouping():
    # eks_audit stores raw.resource = "secrets"; the build failed on it from 19 Oct 19:38 UTC
    eks = Finding.model_construct(detector="eks_audit", severity="high", device_name="eks-prod", device_id="eks:prod",
                                  indicator="secret_read|a@b.com|list|secrets", summary="EKS prod: secret reads",
                                  raw={"resource": "secrets", "first": T.isoformat()}, created_at=NOW)
    f2e, ents = S.resolve_entities([eks, upwind("publisher02", RARE, T)])
    assert f2e[eks.id] and S.identifiers(eks)


def test_a_new_story_needs_a_true_positive_but_an_open_story_still_grows():
    """No AI or analyst TP behind a grouping: no story. Once one exists, untriaged findings
    that link to it still join (they are part of what happened)."""
    async def go():
        await _db("stories_tp_gate")
        a = upwind("publisher02", "A host is retrieving the current user identity", T, asset="uwr-p2")
        b = upwind("idart-publisher01", "A host is retrieving the current user identity", T + timedelta(minutes=3))
        await _insert(a, b)
        r0 = await S.build(now=NOW)                                   # untriaged: nothing
        ov = await Finding.get(a.id)
        ov.ai_verdict, ov.decision = "true_positive", "false_positive"   # AI TP overruled by a person
        await ov.save()
        r1 = await S.build(now=NOW)
        ov.decision = ""                                              # AI TP, undisputed
        await ov.save()
        r2 = await S.build(now=NOW)
        c = upwind("publisher02", "A host is retrieving the current user identity", T + timedelta(minutes=40), asset="uwr-p2")
        await _insert(c)                                              # untriaged, links to the open story
        r3 = await S.build(now=NOW)
        st = (await Story.find_all().to_list())
        return r0, r1, r2, r3, st, c.id
    r0, r1, r2, r3, st, cid = asyncio.run(go())
    assert r0["created"] == 0 and r1["created"] == 0 and r2["created"] == 1
    assert r3["created"] == 0 and len(st) == 1 and cid in st[0].finding_ids


def test_a_confirmed_true_positive_backs_a_story_without_any_ai_verdict():
    async def go():
        await _db("stories_tp_human")
        a = upwind("publisher02", "A host is retrieving the current user identity", T, asset="uwr-p2")
        b = upwind("idart-publisher01", "A host is retrieving the current user identity", T + timedelta(minutes=3))
        fs = await _insert(a, b)
        fs[0].decision, fs[0].reviewed_at = "true_positive", NOW
        await fs[0].save()
        return await S.build(now=NOW)
    assert asyncio.run(go())["created"] == 1
