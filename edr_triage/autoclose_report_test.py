"""Autonomous-close report: whose close was it, and did a human overturn it.

The attribution question is the one that matters. The `ai-fp` label only says the AGENT
said False Positive — in copilot phase that is advice and a human did the closing. The
only evidence RAPTOR *closed* anything is a `-> False Positive` status change authored by
the bot account, so these tests attack that distinction from both sides.

Changelog shapes below are copied from real SIM tickets (DEMO-112428's walk, DEMO-112105's
copilot breach), including Jira's `+0530` offsets, because a naive `datetime.fromisoformat`
on a `Z`-suffixed or offset-bearing stamp is exactly the kind of thing that silently
returns None and makes every close look un-aged.
"""
from __future__ import annotations

from edr_triage.autoclose_report import _read_close

BOT = "purple.phantom@example.com"
HUMAN = "v-arjun.okafor@example.com"


def _issue(key: str, events: list[tuple[str, str, str, str]], summary: str = "Alert",
           status: str = "False Positive") -> dict:
    """events = [(created, author_email, fromString, toString)]"""
    return {
        "key": key,
        "fields": {"summary": summary, "status": {"name": status}},
        "changelog": {
            "histories": [
                {
                    "created": created,
                    "author": {"emailAddress": email, "displayName": email.split("@")[0]},
                    "items": [{"field": "status", "fromString": frm, "toString": to}],
                }
                for created, email, frm, to in events
            ]
        },
    }


# --- attribution -------------------------------------------------------------

def test_a_close_by_the_bot_is_reported():
    row = _read_close(_issue("DEMO-1", [
        ("2026-09-10T18:28:43.994+0530", BOT, "Open", "Assigned"),
        ("2026-09-10T18:28:45.170+0530", BOT, "Assigned", "Event Analysis"),
        ("2026-09-10T18:28:46.248+0530", BOT, "Event Analysis", "False Positive"),
    ]), BOT)
    assert row is not None
    assert row["closed_at"] == "2026-09-10T18:28:46.248+0530"
    assert row["reopened_at"] is None


def test_a_close_by_a_human_is_not_ours_to_report():
    """The ai-fp label is on plenty of tickets a human closed — copilot phase only
    recommends. Reporting those as autonomous closes would overstate what RAPTOR did."""
    assert _read_close(_issue("DEMO-2", [
        ("2026-09-08T18:15:04.000+0530", HUMAN, "Event Analysis", "False Positive"),
    ]), BOT) is None


def test_a_ticket_the_bot_touched_but_did_not_close_is_not_reported():
    """DEMO-112105's shape: the bot transitioned it, a human closed it."""
    assert _read_close(_issue("DEMO-112105", [
        ("2026-09-08T18:04:12.000+0530", BOT, "Assigned", "Event Analysis"),
        ("2026-09-08T18:15:04.000+0530", HUMAN, "Event Analysis", "False Positive"),
    ]), BOT) is None


def test_no_status_history_at_all_is_not_a_close():
    assert _read_close(_issue("DEMO-3", []), BOT) is None


# --- the overturn ------------------------------------------------------------

def test_a_reopen_after_our_close_is_an_overturn():
    row = _read_close(_issue("DEMO-4", [
        ("2026-09-10T18:28:46.248+0530", BOT, "Event Analysis", "False Positive"),
        ("2026-09-10T19:00:00.000+0530", HUMAN, "False Positive", "Event Analysis"),
    ], status="Event Analysis"), BOT)
    assert row["reopened_at"] == "2026-09-10T19:00:00.000+0530"
    assert row["reopened_to"] == "Event Analysis"
    assert row["reopened_by"] == "v-arjun.okafor"


def test_a_reopen_straight_to_l2_is_captured_as_such():
    """Reopening to `L2 Analysis required` is a stronger disagreement than parking it
    back in Event Analysis, so the destination is recorded, not just the fact."""
    row = _read_close(_issue("DEMO-5", [
        ("2026-09-10T10:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
        ("2026-09-10T11:00:00.000+0530", HUMAN, "False Positive", "L2 Analysis required"),
    ], status="L2 Analysis required"), BOT)
    assert row["reopened_to"] == "L2 Analysis required"


def test_a_reopen_BEFORE_our_close_is_not_an_overturn():
    """A ticket can be closed by a human, reopened, and only then closed by RAPTOR. The
    earlier reopen says nothing about our close."""
    row = _read_close(_issue("DEMO-6", [
        ("2026-09-01T10:00:00.000+0530", HUMAN, "Event Analysis", "False Positive"),
        ("2026-09-01T11:00:00.000+0530", HUMAN, "False Positive", "Event Analysis"),
        ("2026-09-02T10:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
    ]), BOT)
    assert row["closed_at"] == "2026-09-02T10:00:00.000+0530"
    assert row["reopened_at"] is None


def test_close_reopen_close_reports_the_LATEST_close_and_clears_the_overturn():
    """Otherwise a ticket RAPTOR successfully re-closed would report as permanently
    overturned, and the precision figure would never recover."""
    row = _read_close(_issue("DEMO-7", [
        ("2026-09-01T10:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
        ("2026-09-01T11:00:00.000+0530", HUMAN, "False Positive", "Event Analysis"),
        ("2026-09-03T10:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
    ]), BOT)
    assert row["closed_at"] == "2026-09-03T10:00:00.000+0530"
    assert row["reopened_at"] is None


def test_refiling_our_close_as_duplicate_is_agreement_not_a_reopen():
    """False Positive <-> Duplicate both say "not a threat". Read as an overturn it braked a
    family four times, each re-armed by hand (DEMO-118679, 118428, 118854, 120563)."""
    row = _read_close(_issue("DEMO-8", [
        ("2026-09-10T10:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
        ("2026-09-10T12:00:00.000+0530", HUMAN, "False Positive", "Duplicate"),
    ], status="Duplicate"), BOT)
    assert not row["reopened_to"] and not row["reopened_at"]


def test_a_reopen_after_a_refile_still_counts():
    row = _read_close(_issue("DEMO-9", [
        ("2026-09-10T10:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
        ("2026-09-10T12:00:00.000+0530", HUMAN, "False Positive", "Duplicate"),
        ("2026-09-10T13:00:00.000+0530", HUMAN, "Duplicate", "L2 Analysis required"),
    ], status="L2 Analysis required"), BOT)
    assert row["reopened_to"] == "L2 Analysis required"


def test_moving_our_false_positive_to_closed_is_still_an_overturn():
    row = _read_close(_issue("DEMO-10", [
        ("2026-09-10T10:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
        ("2026-09-10T12:00:00.000+0530", HUMAN, "False Positive", "Closed"),
    ], status="Closed"), BOT)
    assert row["reopened_to"] == "Closed"


# --- robustness --------------------------------------------------------------

def test_events_are_ordered_by_time_not_by_changelog_order():
    """Jira does not guarantee history order, and an out-of-order pair would otherwise
    make a reopen look like it preceded the close."""
    row = _read_close(_issue("DEMO-9", [
        ("2026-09-10T19:00:00.000+0530", HUMAN, "False Positive", "Event Analysis"),
        ("2026-09-10T18:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
    ], status="Event Analysis"), BOT)
    assert row["closed_at"] == "2026-09-10T18:00:00.000+0530"
    assert row["reopened_at"] == "2026-09-10T19:00:00.000+0530"


def test_offset_bearing_timestamps_produce_a_real_age():
    """Jira stamps carry +0530. If parsing failed, age would silently be 0.0 and an
    unreviewed backlog would never breach the threshold."""
    row = _read_close(_issue("DEMO-10", [
        ("2026-01-01T10:00:00.000+0530", BOT, "Event Analysis", "False Positive"),
    ]), BOT)
    assert row["age_hours"] > 1000


def test_a_missing_bot_email_reports_nothing_rather_than_everything():
    """Config with no JIRA_EMAIL must not make every human close look autonomous."""
    assert _read_close(_issue("DEMO-11", [
        ("2026-09-10T10:00:00.000+0530", HUMAN, "Event Analysis", "False Positive"),
    ]), "") is None


def test_author_email_comparison_is_case_insensitive():
    row = _read_close(_issue("DEMO-12", [
        ("2026-09-10T10:00:00.000+0530", "Purple.Phantom@Example.Com", "Event Analysis",
         "False Positive"),
    ]), BOT)
    assert row is not None


# --- the fields the report reads --------------------------------------------
#
# These are read by the report and by /api/edr-triage/fp-report's bucketing. A refactor
# that drops one would not break any import — it would silently send every duplicate-
# closed ticket back into "awaiting human review", which is the exact misreport this
# work removed. So assert they are declared.

def test_shadowresult_carries_the_fields_the_report_depends_on():
    from entity_graph.models import ShadowResult

    for field in ("duplicate_at", "autonomous_closed_at", "reopened_at",
                  "reopened_by", "reopened_to"):
        assert field in ShadowResult.model_fields, field


def test_duplicate_and_autonomous_close_default_to_unset():
    """Every existing row predates these fields; none may read as closed-by-RAPTOR or
    resolved-as-duplicate by default, or the first report would be pure fiction."""
    from entity_graph.models import ShadowResult

    for field in ("duplicate_at", "autonomous_closed_at", "reopened_at", "reopened_by"):
        assert ShadowResult.model_fields[field].default is None, field
    assert ShadowResult.model_fields["reopened_to"].default == ""
