"""Slack alerts for /shadow stories that carry a true positive (shadow_hunter/notify.py).
Fixtures follow the partner-onboarding SSRF of 22-23 Oct 2026: story 3fbe2e00, DEMO-118243.
Run: python -m pytest shadow_hunter/notify_test.py -q
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from shadow_hunter import notify as N
from shadow_hunter.models import AuditLog, Finding, Story

NOW = datetime(2026, 10, 23, 13, 0, tzinfo=timezone.utc)
TICKET = {"jira_key": "DEMO-118243", "alert_name": "The EC2 instance i-03b20b3d6f4b473ea may be the target of a DNS rebinding attack.",
          "created_at": (NOW - timedelta(hours=3)).isoformat(),
          "matched_on": "i-03b20b3d6f4b473ea: node ip-10-193-125-65 (partner-onboarding-service)"}


async def _db(name):
    mm = pytest.importorskip("mongomock_motor")
    from beanie import init_beanie
    await init_beanie(database=mm.AsyncMongoMockClient()[name], document_models=[Finding, Story, AuditLog])


class Slack:
    def __init__(self, ok=True):
        self.ok, self.posts = ok, []

    async def __call__(self, text):
        self.posts.append(text)
        return self.ok


async def _story(findings, sev="high", age_h=2, **kw):
    """A story with these findings: (ai_verdict, decision, age_hours[, ai_by]) tuples; ai_by
    defaults to the manual Claude pass."""
    st = Story(title="2 hosts · Upwind · 22 Oct", severity=sev, first_seen=NOW - timedelta(hours=20),
               last_seen=NOW - timedelta(hours=18), updated_at=NOW - timedelta(hours=age_h),
               entities={"hosts": [{"name": "partner-onboarding-service"}]}, **kw)
    await st.insert()
    for ai, decision, f_age, *by in findings:
        f = Finding(detector="upwind_threats", severity="high", device_name="partner-onboarding-service",
                    summary="Cloud Metadata (IMDS) DNS Rebinding Attempt, account 123456789012",
                    ai_verdict=ai, decision=decision, story_id=st.id, ai_by=(by or ["claude-code-manual"])[0] if ai else "",
                    created_at=(NOW - timedelta(hours=f_age)).replace(tzinfo=None))
        await f.insert()
        st.finding_ids.append(f.id)
    await st.save()
    return st


def _run(name, setup, slack, runs=1):
    async def go():
        await _db(name)
        await setup()
        return [await N.run(post=slack, now=NOW) for _ in range(runs)]
    return asyncio.run(go())


def test_disabled_without_a_webhook(monkeypatch):
    monkeypatch.delenv("SHADOW_SLACK_WEBHOOK", raising=False)
    assert asyncio.run(N.run()) == {"disabled": True}


def test_only_a_claude_verified_tp_counts():
    f = lambda ai, d, by="claude-code-manual": Finding.model_construct(ai_verdict=ai, decision=d, ai_by=by)  # noqa: E731
    assert N.is_tp(f("true_positive", "")) and N.is_tp(f("true_positive", "true_positive"))
    assert N.is_tp(f("true_positive", "", "ai:claude-sonnet"))                       # Claude triage in-app later
    assert not N.is_tp(f("true_positive", "", "ai:mistral.mistral-large-3"))          # another model
    assert not N.is_tp(f("", "true_positive", ""))                                     # a person's TP alone
    assert not N.is_tp(f("true_positive", "false_positive")) and not N.is_tp(f("true_positive", "snooze"))
    assert not N.is_tp(f("unsure", "")) and not N.is_tp(f("false_positive", ""))


def test_a_story_with_a_tp_is_announced_once():
    slack = Slack()
    out = _run("n_tp", lambda: _story([("true_positive", "", 2), ("false_positive", "", 2)]), slack, runs=2)
    assert out[0]["stories"] == 1 and out[1] == {"stories": 0, "tickets": 0, "findings": 0, "failed": 0}
    text = slack.posts[0]
    assert "HIGH story with a Claude-verified true positive" in text and "1 TP of 2 findings" in text
    assert "/shadow/stories/" in text and "IST" in text and "123456789012" not in text


def test_stories_without_a_tp_are_never_announced_whatever_their_severity():
    slack = Slack()

    async def setup():
        await _story([("false_positive", "", 2), ("unsure", "", 2)], sev="critical")
        await _story([("true_positive", "false_positive", 2)], sev="critical")      # a person overruled the AI
        await _story([("true_positive", "snooze", 2)])
        await _story([], sev="critical", context={"alerts": [TICKET]})              # a ticket alone is not enough
    out = _run("n_quiet", setup, slack)
    assert out[0] == {"stories": 0, "tickets": 0, "findings": 0, "failed": 0} and slack.posts == []


def test_tps_from_another_model_or_only_a_person_stay_quiet():
    slack = Slack()

    async def setup():
        await _story([("true_positive", "", 2, "ai:mistral.mistral-large-3")])
        await _story([("", "true_positive", 2)])
    out = _run("n_notclaude", setup, slack)
    assert out[0]["stories"] == 0 and slack.posts == []


def test_an_analyst_confirmed_claude_tp_is_labelled_so():
    slack = Slack()
    _run("n_conf", lambda: _story([("true_positive", "true_positive", 2)]), slack)
    assert "_(Claude TP, analyst confirmed)_" in slack.posts[0]


def test_old_tp_stories_are_not_replayed_when_this_is_switched_on():
    slack = Slack()
    out = _run("n_old", lambda: _story([("true_positive", "", 40)], age_h=40), slack)
    assert out[0]["stories"] == 0 and slack.posts == []


def test_escalation_after_announcement_is_announced():
    slack = Slack()
    _run("n_esc", lambda: _story([("true_positive", "", 30)], sev="critical", age_h=30,
                                 notified={"severity": "high"}), slack)
    assert "TP story escalated to CRITICAL" in slack.posts[0]


def test_critical_story_mentions_the_configured_handle(monkeypatch):
    monkeypatch.setenv("SHADOW_SLACK_MENTION", "<@U0SEC>")
    slack = Slack()
    _run("n_mention", lambda: _story([("true_positive", "", 2)], sev="critical"), slack)
    assert slack.posts[0].startswith("<@U0SEC>")


def test_a_ticket_linked_to_an_announced_tp_story_is_announced_once():
    slack = Slack()
    out = _run("n_ticket", lambda: _story([("true_positive", "", 30)], age_h=30, notified={"severity": "high"},
                                          context={"alerts": [TICKET]}), slack, runs=2)
    assert out[0]["tickets"] == 1 and out[1]["tickets"] == 0
    assert "Ticket linked to TP story" in slack.posts[0] and "DEMO-118243" in slack.posts[0]


def test_a_new_tp_story_carries_its_ticket_in_the_same_message():
    slack = Slack()
    out = _run("n_both", lambda: _story([("true_positive", "", 2)], context={"alerts": [TICKET]}), slack)
    assert out[0] == {"stories": 1, "tickets": 1, "findings": 0, "failed": 0} and len(slack.posts) == 1
    assert "DEMO-118243" in slack.posts[0]


def test_a_failed_post_is_retried_next_run():
    slack = Slack(ok=False)

    async def go():
        await _db("n_retry")
        await _story([("true_positive", "", 2)])
        first = await N.run(post=slack, now=NOW)
        slack.ok = True
        return first, await N.run(post=slack, now=NOW)
    first, second = asyncio.run(go())
    assert first == {"stories": 0, "tickets": 0, "findings": 0, "failed": 1} and second["stories"] == 1


def test_slack_control_characters_in_titles_are_escaped():
    st = Story(title="<!channel> & friends", severity="high", entities={})
    text = N.story_message(st, {"kind": "new", "alerts": [], "tps": []})
    assert "<!channel>" not in text and "&lt;!channel&gt; &amp; friends" in text


def _loose(sev="high", ai="true_positive", decision="", age_h=2, story_id="", by="claude-code-manual", **kw):
    return Finding(detector="rare_persistence", severity=sev, device_name="mac-1", summary="launchd plist com.evil.agent",
                   ai_verdict=ai, decision=decision, story_id=story_id, ai_by=by,
                   created_at=(NOW - timedelta(hours=age_h)).replace(tzinfo=None), **kw)


def test_high_or_critical_tp_detections_outside_a_story_are_announced_once():
    slack = Slack()

    async def setup():
        await _loose().insert()                                            # AI TP, high: yes
        await _loose(sev="critical", decision="true_positive").insert()    # Claude TP, analyst confirmed, critical: yes
        await _loose(ai="", decision="true_positive").insert()             # a person's TP alone: no
        await _loose(by="ai:mistral.mistral-large-3").insert()             # another model: no
        await _loose(sev="medium").insert()                                # medium: no
        await _loose(ai="true_positive", decision="false_positive").insert()     # a person overruled: no
        await _loose(ai="unsure").insert()                                 # not TP: no
        await _loose(age_h=30).insert()                                    # before the lookback: no
        await _loose(legacy=True).insert()                                 # legacy: no
        await _loose(allowlisted_by_rule="r1").insert()                    # allowlisted: no
    out = _run("n_loose", setup, slack, runs=2)
    assert out[0]["findings"] == 2 and out[1]["findings"] == 0 and len(slack.posts) == 1
    assert "2 Claude-verified true-positive detections" in slack.posts[0] and "shadow?finding=" in slack.posts[0]


def test_a_tp_detection_in_a_story_rides_on_the_story_alert_not_its_own():
    slack = Slack()
    out = _run("n_instory", lambda: _story([("true_positive", "", 2)]), slack)
    assert out[0]["stories"] == 1 and out[0]["findings"] == 0 and len(slack.posts) == 1


def test_critical_tp_detection_mentions_the_configured_handle(monkeypatch):
    monkeypatch.setenv("SHADOW_SLACK_MENTION", "<@U0SEC>")
    slack = Slack()

    async def setup():
        await _loose(sev="critical").insert()
    _run("n_loose_crit", setup, slack)
    assert slack.posts[0].startswith("<@U0SEC>")
