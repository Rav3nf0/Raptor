"""Canary token was accessed: name the tripwire, check whether one of ours tripped it, never close.

Run: python -m pytest edr_triage/canary_guard_test.py -q
"""
from __future__ import annotations

import asyncio

from edr_triage import canary_guard as C

_HIT = {"TimeGenerated": "2026-11-08T22:54:51Z", "memo_s": "Phishing_EntraID login",
        "token_type_s": "cssclonedsite", "src_ip_s": "142.147.142.182",
        "org_s": "AS62874 Web2Objects LLC", "city_s": "Dallas", "country_s": "US",
        "useragent_s": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/146.0.0.0"}
_RECENT = {"hits": 9, "first_hit": "2026-11-08T10:38:53Z", "last_hit": "2026-11-08T22:54:51Z",
           "ips": ["142.147.142.182", "31.76.154.227"], "orgs": ["AS62874 Web2Objects LLC"]}


def _run(monkeypatch, answers):
    """answers: one per query in order; None = that query failed."""
    seen = []

    async def fake(kql):
        seen.append(kql)
        return answers[len(seen) - 1]
    monkeypatch.setattr(C, "_query", fake)
    C._cache.clear()
    return asyncio.run(C.check("2026-11-08T23:04:52Z")), seen


def test_applies_to_the_canary_family_only():
    assert C.applies("Canary token was accessed")
    assert not C.applies("Log injestion stopped")


def test_the_auth_key_in_a_canarytokens_link_never_reaches_jira():
    url = "https://canarytokens.org/manage?token=ttqm5hbslyn6v0qhlgjijhcm8&auth=486b9fbd4e6b6530"
    out = C.redact_url_secrets(url)
    assert "486b9fbd" not in out and "ttqm5hbs" not in out and out.startswith("https://canarytokens.org/manage?")


def test_rule_replay_redacts_link_credentials_in_urls_and_fields():
    from edr_triage.rule_replay import summarize_rows
    rr = summarize_rows([{"manage_url_s": "https://canarytokens.org/manage?token=abc&auth=SECRET1",
                          "useragent_s": "x", "agent_link_s": "https://canarytokens.org/history?auth=SECRET2"}])
    blob = repr(rr)
    assert "SECRET1" not in blob and "SECRET2" not in blob


def test_outside_visitors_mean_a_live_kit_not_a_compromise(monkeypatch):
    chk, seen = _run(monkeypatch, [[_HIT], [_RECENT], []])
    assert chk["ok"] and chk["phishing"] and chk["ours"] == []
    assert len(seen) == 3                       # no follow-up query without a matched user
    text = "\n".join(C.l1_comment_lines(chk))
    assert "phishing" in text and "Web2Objects" in text and "outsiders" in text
    assert "TRUE POSITIVE" in text and "takedown" in text


def test_a_visitor_ip_of_ours_names_the_users_and_their_new_ip_sign_ins(monkeypatch):
    ours = [{"IPAddress": "142.147.142.182", "users": ["a.b@example.com"]}]
    new = [{"UserPrincipalName": "a.b@example.com", "IPAddress": "5.6.7.8",
            "AutonomousSystemNumber": "9009", "first_seen": "2026-11-08T23:30:00Z", "n": 2}]
    chk, seen = _run(monkeypatch, [[_HIT], [_RECENT], ours, new])
    assert '"a.b@example.com"' in seen[3] and "leftanti" in seen[3]
    text = "\n".join(C.summary_lines(chk))
    assert "ONE OF OURS" in text and "a.b@example.com" in text and "5.6.7.8" in text
    assert "stolen" in text


def test_a_failed_query_is_never_read_as_clean(monkeypatch):
    chk, _ = _run(monkeypatch, [[_HIT], [_RECENT], None])
    assert not chk["ok"]
    text = "\n".join(C.summary_lines(chk))
    assert "incomplete" in text and "outsiders" not in text
    chk, _ = _run(monkeypatch, [None])
    assert "UNKNOWN" in "\n".join(C.summary_lines(chk))


def test_each_token_type_is_explained():
    assert "phishing" in C.meaning("cssclonedsite")
    assert "app" in C.meaning("idp_app")
    assert "tripwire" in C.meaning("something_new")


def test_the_agent_is_told_how_to_judge_it():
    text = "\n".join(C.prompt_lines({"ok": False, "error": "x"}))
    assert "never 'expected access'" in text and "TOKEN TYPE" in text


def test_a_canary_is_never_auto_closed():
    assert C.close_block_reason("Canary token was accessed").startswith("Auto-close blocked")
    assert C.close_block_reason("Netskope DLP Alerts") == ""


def test_the_agent_gate_turns_a_canary_fp_into_l2():
    import inspect
    from agent_core import loop
    src = inspect.getsource(loop)
    assert "close_block_reason(alert_name)" in src


def test_the_prompt_renders_the_canary_check():
    from agent_core.oscar import format_alert
    p = format_alert({}, "DEMO-1", "Canary token was accessed", "High", "", "",
                     evidence={"canary_check": {"ok": True, "memo": "Phishing_EntraID login",
                                                "token_type": "cssclonedsite",
                                                "meaning": C.meaning("cssclonedsite"),
                                                "phishing": True, "hit": _HIT, "ours": []}})
    assert "Canary check (KEY EVIDENCE" in p and "Phishing_EntraID login" in p
