"""Alert time is UTC whatever the source: a Jira `created` (+0530) must not be shown as UTC.

Run: python -m pytest edr_triage/alert_time_utc_test.py -q
"""
from __future__ import annotations

from edr_triage.normalized import normalize_alert, utc_seconds


def test_jira_created_time_is_converted_not_truncated():
    # DEMO-121175: '2026-11-08 23:04:52' was printed as UTC; the alert was 17:34:52 UTC.
    assert utc_seconds("2026-11-08T23:04:52.743+0530") == "2026-11-08T17:34:52"


def test_mde_utc_times_are_unchanged():
    assert utc_seconds("2026-11-08T17:34:52.1234567Z") == "2026-11-08T17:34:52"
    assert utc_seconds("2026-11-08T17:34:52") == "2026-11-08T17:34:52"


def test_unparseable_falls_back_to_the_old_slice():
    assert utc_seconds("not a time at all, really") == "not a time at all, "
    assert utc_seconds("") == ""


def test_the_normalized_alert_carries_utc():
    n = normalize_alert({"alertDisplayName": "Canary token was accessed",
                         "alertCreationTime": "2026-11-08T23:04:52.743+0530"}, {}, None)
    assert n.alert_time == "2026-11-08 17:34:52"
