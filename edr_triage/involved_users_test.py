"""Editing the description's "Involved Users" cell — the mechanism that lets RAPTOR fire
the Acme Security Bot (re-entry into `Awaiting more inputs`, with that cell populated).

Fixture (`testdata_involved_users_adf.json`) mirrors the real ADF shape: one `table` node
of `tableHeader` row pairs, each holding one `paragraph`. The property that matters most
is that editing the "Involved Users" cell leaves every OTHER row byte-identical — an L1
may have hand-formatted the rest of the table, and a diff there would be a silent
corruption of their work.
"""
from __future__ import annotations

import asyncio
import copy
import json
import pathlib

import httpx
import pytest

from edr_triage.config import EDRTriageConfig
from edr_triage import jira_handler as J

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "testdata_involved_users_adf.json").read_text()
)


def _cfg(**kw) -> EDRTriageConfig:
    return EDRTriageConfig(_env_file=None, **kw)


def _client_for(handler):
    def _factory(cfg):
        return httpx.AsyncClient(base_url="https://jira.test",
                                 transport=httpx.MockTransport(handler))
    return _factory


def _with_client(handler, coro_factory):
    real = J._build_client
    J._build_client = _client_for(handler)
    try:
        return asyncio.run(coro_factory())
    finally:
        J._build_client = real


# --- _find_involved_users_row -------------------------------------------------

def test_finds_the_row_by_label_not_position():
    row = J._find_involved_users_row(FIXTURE)
    assert row is not None
    label_text = row["content"][0]["content"][0]["content"][0]["text"]
    assert label_text == "Involved Users"


def test_returns_none_when_the_table_has_no_such_row():
    doc = {"type": "doc", "content": [{"type": "table", "content": [
        {"type": "tableRow", "content": [
            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Severity"}]}]},
            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "High"}]}]},
        ]},
    ]}]}
    assert J._find_involved_users_row(doc) is None


def _hdr(t):
    return {"type": "tableHeader", "attrs": {}, "content": [{"type": "paragraph", "content": (
        [{"type": "text", "text": t, "marks": [{"type": "strong"}]}] if t else [])}]}


# DEMO-121856: a multi-paragraph Incident description splits the source table in two; the
# empty Involved Users row (label only) sits in the SECOND table, after loose paragraphs.
SPLIT = {"type": "doc", "version": 1, "content": [
    {"type": "table", "content": [{"type": "tableRow", "content": [
        _hdr("Incident description "), _hdr("Malware and unwanted software ...")]}]},
    {"type": "paragraph", "content": [{"type": "text", "text": "A malware is considered active ..."}]},
    {"type": "table", "content": [
        {"type": "tableRow", "content": [_hdr("Severity "), _hdr("Low ")]},
        {"type": "tableRow", "content": [_hdr("Involved Users ")]},
        {"type": "tableRow", "content": [_hdr("DLP Profile "), _hdr("")]},
    ]},
]}


def test_finds_the_row_in_a_later_table_when_the_description_split_the_table():
    row = J._find_involved_users_row(SPLIT)
    assert row is not None and len(row["content"]) == 1
    assert J._find_involved_users_row({"type": "doc", "content": SPLIT["content"][:2]}) is None


def test_get_cell_reads_empty_for_the_split_table_row(monkeypatch):
    async def _adf(key, cfg=None):
        return copy.deepcopy(SPLIT)
    monkeypatch.setattr(J, "get_description_adf", _adf)
    assert asyncio.run(J.get_involved_users_cell("DEMO-121856", _cfg())) == ""


def test_returns_none_when_there_is_no_table_at_all():
    assert J._find_involved_users_row({"type": "doc", "content": []}) is None
    assert J._find_involved_users_row(None) is None


@pytest.mark.parametrize("label", ["Involved User", "involved users", "  Involved Users  "])
def test_label_match_is_case_and_plural_forgiving(label):
    doc = copy.deepcopy(FIXTURE)
    doc["content"][0]["content"][6]["content"][0]["content"][0]["content"][0]["text"] = label
    assert J._find_involved_users_row(doc) is not None


# --- get_involved_users_cell --------------------------------------------------

def test_get_cell_returns_empty_string_for_an_empty_but_present_row():
    def handler(request):
        return httpx.Response(200, json={"fields": {"description": FIXTURE}})
    result = _with_client(handler, lambda: J.get_involved_users_cell("DEMO-1", _cfg()))
    assert result == ""


def test_get_cell_returns_none_when_no_such_row_exists():
    def handler(request):
        return httpx.Response(200, json={"fields": {"description": {"type": "doc", "content": []}}})
    result = _with_client(handler, lambda: J.get_involved_users_cell("DEMO-1", _cfg()))
    assert result is None


def test_get_cell_reads_back_existing_text():
    doc = copy.deepcopy(FIXTURE)
    doc["content"][0]["content"][6]["content"][1]["content"][0]["content"] = [
        {"type": "text", "text": "someone@example.com"}
    ]
    def handler(request):
        return httpx.Response(200, json={"fields": {"description": doc}})
    result = _with_client(handler, lambda: J.get_involved_users_cell("DEMO-1", _cfg()))
    assert result == "someone@example.com"


# --- set_involved_users --------------------------------------------------------

def test_set_involved_users_edits_only_the_target_cell():
    seen = {}
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"fields": {"description": FIXTURE}})
        seen["body"] = json.loads(request.content)
        return httpx.Response(204)

    ok = _with_client(handler, lambda: J.set_involved_users(
        "DEMO-1", [{"email": "riley.patel@example.com", "display_name": "riley Rajeev"}],
        _cfg()))
    assert ok is True

    put_doc = seen["body"]["fields"]["description"]
    rows = put_doc["content"][0]["content"]
    # Every OTHER row is byte-identical to the fixture.
    for i, row in enumerate(rows):
        if i == 6:
            continue
        assert row == FIXTURE["content"][0]["content"][i], f"row {i} was modified"

    value_content = rows[6]["content"][1]["content"][0]["content"]
    assert value_content == [{
        "type": "text", "text": "riley.patel@example.com",
        "marks": [{"type": "link", "attrs": {"href": "mailto:riley.patel@example.com"}}],
    }]


def test_set_involved_users_joins_multiple_recipients_with_comma_space():
    seen = {}
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"fields": {"description": FIXTURE}})
        seen["body"] = json.loads(request.content)
        return httpx.Response(204)

    _with_client(handler, lambda: J.set_involved_users(
        "DEMO-1",
        [{"email": "a@example.com", "display_name": "A"}, {"email": "b@example.com", "display_name": "B"}],
        _cfg()))
    value_content = seen["body"]["fields"]["description"]["content"][0]["content"][6]["content"][1]["content"][0]["content"]
    texts = [n["text"] for n in value_content]
    assert texts == ["a@example.com", ", ", "b@example.com"]


def test_set_involved_users_refuses_when_no_such_row(monkeypatch):
    async def _get_adf(key, cfg=None):
        return {"type": "doc", "content": []}
    monkeypatch.setattr(J, "get_description_adf", _get_adf)
    ok = asyncio.run(J.set_involved_users("DEMO-1", [{"email": "a@example.com"}], _cfg()))
    assert ok is False


def test_set_involved_users_fails_closed_when_description_unreadable(monkeypatch):
    async def _get_adf(key, cfg=None):
        return None
    monkeypatch.setattr(J, "get_description_adf", _get_adf)
    ok = asyncio.run(J.set_involved_users("DEMO-1", [{"email": "a@example.com"}], _cfg()))
    assert ok is False


def test_set_involved_users_dry_run_makes_no_request():
    def handler(request):
        raise AssertionError("dry_run must not make any HTTP request")
    ok = _with_client(handler, lambda: J.set_involved_users(
        "DEMO-1", [{"email": "a@example.com"}], _cfg(), dry_run=True))
    assert ok is True


def test_set_involved_users_reports_failure_on_bad_http_status():
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"fields": {"description": FIXTURE}})
        return httpx.Response(400, text="bad request")
    ok = _with_client(handler, lambda: J.set_involved_users(
        "DEMO-1", [{"email": "a@example.com"}], _cfg()))
    assert ok is False


# --- set_category: field ID + option value, not the broken "category" field ---

def test_set_category_puts_the_real_field_id_and_option():
    seen = {}
    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(204)
    ok = _with_client(handler, lambda: J.set_category("DEMO-1", "No Repsonse", _cfg()))
    assert ok is True
    assert seen["body"] == {"fields": {"customfield_10335": {"value": "No Repsonse"}}}


def test_set_category_never_falls_back_to_the_broken_plain_field():
    """The old implementation retried with a bare 'category' string field on failure —
    which has never once worked in 30 days of live traffic. A failure must be reported,
    not silently retried against a field known not to exist."""
    calls = []
    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(400, text="no such field")
    ok = _with_client(handler, lambda: J.set_category("DEMO-1", "No Repsonse", _cfg()))
    assert ok is False
    assert len(calls) == 1
    assert "category" not in calls[0]["fields"]


# --- the FRESH-ticket shape: a label-only "Involved Users" row ----------------------
# Live SIM tickets arrive with the row carrying ONLY its label cell; the value cell only
# exists once an L1 types an address (DEMO-115190 vs DEMO-114766). Until 2026-10-01 the
# finder required two cells, so every live RAPTOR chase aborted with "description has no
# 'Involved Users' row" and nobody was asked.

def _fresh():
    doc = copy.deepcopy(FIXTURE)
    row = doc["content"][0]["content"][6]
    row["content"] = row["content"][:1]
    return doc


def test_a_label_only_row_is_found():
    assert J._find_involved_users_row(_fresh()) is not None


def test_a_label_only_row_reads_as_empty_so_a_chase_may_proceed():
    def handler(request):
        return httpx.Response(200, json={"fields": {"description": _fresh()}})
    assert _with_client(handler, lambda: J.get_involved_users_cell("DEMO-1", _cfg())) == ""


def test_writing_a_label_only_row_adds_the_value_cell_in_the_l1_shape():
    fresh, seen = _fresh(), {}

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"fields": {"description": copy.deepcopy(fresh)}})
        seen["body"] = json.loads(request.content)
        return httpx.Response(204)
    ok = _with_client(handler, lambda: J.set_involved_users(
        "DEMO-1", [{"email": "marco.silva@example.com", "display_name": "Marco Silva"}], _cfg()))
    assert ok is True
    rows = seen["body"]["fields"]["description"]["content"][0]["content"]
    for i, row in enumerate(rows):
        if i != 6:
            assert row == fresh["content"][0]["content"][i], f"row {i} was modified"
    label, value = rows[6]["content"]
    assert label == fresh["content"][0]["content"][6]["content"][0]      # label untouched
    assert value["type"] == label["type"] == "tableHeader"
    assert value["content"] == [{"type": "paragraph", "content": [{
        "type": "text", "text": "marco.silva@example.com",
        "marks": [{"type": "link", "attrs": {"href": "mailto:marco.silva@example.com"}}]}]}]
