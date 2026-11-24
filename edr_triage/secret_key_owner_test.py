"""The DLP-Secret-key close covers only owners who have explained such data before.

L2 on the 2026-10-14 review: kai.verma (DEMO-116210) and ira.chopra (DEMO-115919, cleared on
L1's bulk-template closes) were new users and should have been asked; rhys.kohli and
pia.gandhi (DEMO-116205/116214) had given justifications, which the close should cite.

Run: python -m pytest edr_triage/secret_key_owner_test.py -q
"""
from __future__ import annotations

import asyncio

import pytest

from edr_triage.playbooks import netskope as N

_REAL = N._secret_key_owners   # bound at import, before conftest's autouse stub runs

SAGAR = {"user": "ira.chopra@example.com", "dlp_profile": "DLP-Secret-key",
         "dlp_rule": "Security - API Secret Keys", "dlp_file": "Java - Payments Secret Manager",
         "activity": "CASB API Scan", "app": "Google Drive"}
RHYS = {**SAGAR, "user": "rhys.kohli@example.com", "dlp_rule": "Security - Passwords",
          "dlp_file": "Investor Grievance Register.xlsx"}


@pytest.fixture
def real_owner_check(monkeypatch):
    """Undo the conftest default; dlpcontext.txt is real, the memory lookup is stubbed."""
    monkeypatch.setattr(N, "_secret_key_owners", _REAL)
    memories: dict = {}

    async def fake_lookup(u):
        return memories.get(u, {})
    import entity_graph.query as Q
    monkeypatch.setattr(Q, "dlp_user_justification", fake_lookup)
    import edr_triage.identity as I

    async def fake_elig(us):
        return [{"raw": u, "email": u, "display_name": u.split("@")[0], "identity": {}}
                for u in us], []
    monkeypatch.setattr(I, "eligible_recipients", fake_elig)
    return memories




def _run(events):
    return asyncio.run(N.NetskopePlaybook().run(
        jira_key="DEMO-TEST", alert={"alertName": "Netskope DLP Alerts"}, evidence={}, vt=None,
        timeline=[], is_test_device=False, normalized={},
        sentinel_entities={"netskope_dlp": {"users": [e["user"] for e in events],
                                            "events": events, "bind_source": "alert"}}))


def _ask(monkeypatch, on: bool):
    cfg = N.get_edr_config()
    monkeypatch.setattr(cfg, "dlp_secret_key_ask", on)


UPLOAD = {**SAGAR, "activity": "Upload", "app": "Slack"}


def test_at_rest_closes_even_for_a_new_owner(real_owner_check, monkeypatch):
    """2026-10-26 (user's call on 60 days: 1,152/1,152 at-rest decisions were closes, 0 TP):
    a file at rest in a company account closes whatever the owner's history."""
    r = _run([SAGAR])
    assert r.auto_close is True and "No earlier answer on file for ira.chopra@example.com" in r.l1_comment


def test_sim_115919_a_new_owner_is_asked_not_closed(real_owner_check, monkeypatch):
    _ask(monkeypatch, True)
    r = _run([UPLOAD])
    assert r.auto_close is False and r.action == "user_confirmation"
    assert "ira.chopra@example.com has never explained" in r.l1_comment


def test_asking_is_off_by_default_and_nobody_is_messaged(real_owner_check, monkeypatch):
    """2026-10-23: the user switched the secret-key ask off until RAPTOR matures."""
    assert type(N.get_edr_config()).model_fields["dlp_secret_key_ask"].default is False
    _ask(monkeypatch, False)
    r = _run([UPLOAD])
    assert r.auto_close is False and r.action != "user_confirmation"
    assert not r.chase_recipients and "user-chase-pending" not in r.labels
    assert "switched off" in r.l1_comment and "needs-l2-review" in r.labels


def test_a_national_id_finding_is_still_asked_with_the_switch_off(real_owner_check, monkeypatch):
    _ask(monkeypatch, False)
    r = _run([{**SAGAR, "dlp_profile": "DLP-National-ID", "dlp_rule": "Aadhaar"}])
    assert r.action == "user_confirmation"


def test_sim_116205_a_justified_owner_closes_citing_their_answer(real_owner_check):
    r = _run([RHYS])
    assert r.auto_close is True and r.triage_class == "AUTO_CLOSED_FP"
    assert "Investor grievances" in r.l1_comment and "their own earlier answer" in r.l1_comment


def test_an_answer_on_an_earlier_ticket_counts(real_owner_check):
    real_owner_check["ira.chopra@example.com"] = {
        "jira_key": "DEMO-120001", "text": "As per confirmation from user, payments config docs"}
    r = _run([SAGAR])
    assert r.auto_close is True and "DEMO-120001" in r.l1_comment


def test_one_new_owner_in_an_upload_bundle_keeps_it_open(real_owner_check):
    r = _run([{**RHYS, "activity": "Upload", "app": "Slack"}, UPLOAD])
    assert r.auto_close is False


def test_an_at_rest_bundle_closes_with_a_new_owner_in_it(real_owner_check):
    r = _run([RHYS, SAGAR])
    assert r.auto_close is True and "Investor grievances" in r.l1_comment


def test_bulk_template_closes_are_not_an_answer():
    from entity_graph.query import _USER_ANSWER_RE
    template = ("The Netskope DLP alert tickets were generated after the re-enablement of the "
                "CASB rule ... No suspicious or malicious user activity was identified.")
    assert not _USER_ANSWER_RE.search(template)
    assert _USER_ANSWER_RE.search("As per the confirmation from user, the data is IG complaints")
    assert _USER_ANSWER_RE.search("[PRIOR BUSINESS JUSTIFICATION — context only]: ...")
    # an ASK is not an answer
    assert not _USER_ANSWER_RE.search("We request the user's business justification for this")
    assert not _USER_ANSWER_RE.search("Please provide user justification for the upload")
    assert not _USER_ANSWER_RE.search("Please obtain confirmation from the user regarding the activity")
    assert _USER_ANSWER_RE.search("Based on the confirmation received from the user, closing")


def test_the_citation_quotes_the_answer_not_the_header(monkeypatch):
    import entity_graph.query as Q

    class M:
        jira_key = "DEMO-112389"; l1_comment = ""; l2_comment = ""; quarantine_reason = ""
        content = ("[netskope_dlp] escalated to L2 — The user 'vera.sinha@example.com' did a CASB "
                   "scan. [L2] As per the confirmation from user, the sheet is their Fixed Deposit "
                   "Revenue Tracker. Hence marking this as false positive.")

    class F:
        def sort(self, *a): return self
        def limit(self, *a): return self
        async def to_list(self): return [M()]
    monkeypatch.setattr(Q.SCGMemory, "find", lambda *a, **k: F())
    rec = asyncio.run(Q.dlp_user_justification("vera.sinha@example.com"))
    assert rec["text"].startswith("As per the confirmation from user, the sheet is their Fixed")
