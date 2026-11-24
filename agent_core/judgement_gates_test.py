"""Three ways RAPTOR got a verdict wrong in the 2026-10-15 quarantine review, each now a gate.

USB copy (DEMO-116268/116658): FP because "the same SanDisk SSD" was cleared before.
Office operations (DEMO-113070/108455): judged the Exchange service account, called the
person who created an inbox rule a "misgrouping" — the rules were benign sorting rules,
but it never read them, so a close now needs the rule itself. Garbled output (DEMO-116237):
a close whose reasoning had degraded into stray Korean and invented words.

Run: python -m pytest agent_core/judgement_gates_test.py -q
"""
from __future__ import annotations

from agent_core.loop import _apply_safety_gates, _garbled_reasoning
from agent_core.result import AgentResult, ToolCallRecord
from lib.kql_templates import sentinel_office_activity

_CALLS = [ToolCallRecord(name="scg_check_concurrent_alerts", args={}, result={"concurrent_count": 0}),
          ToolCallRecord(name="hunt_events", args={}, result={"rows": [{"ActionType": "x"}]})]
OFFICE = "Rare and potentially high-risk Office operations"
EXCH = "nt service\\msexchangeadminapinetcore (microsoft.exchange.adminapi.netcore)"


def _gate(alert, user, evidence=None, reasoning="Routine.", cls="AUTO_CLOSED_FP", calls=_CALLS):
    return _apply_safety_gates(
        AgentResult(triage_class=cls, confidence=0.95, reasoning=reasoning),
        severity="MEDIUM", is_test_device=False, tool_calls=calls, device_name="",
        user_name=user, evidence={"actor_reachable": True, **(evidence or {})}, alert_name=alert)


def test_usb_copy_fp_asks_the_named_person():
    r = _gate("Files Copied to USB Drives", "v-uma.grover@example.com")
    assert r.triage_class == "REQUEST_JUSTIFICATION"
    assert r.safety_gate_kind == "usb_copy_needs_reason"


def test_usb_copy_bound_to_root_goes_to_l2():
    assert _gate("Files Copied to USB Drives", "root").triage_class == "NEEDS_L2"


def test_usb_copy_escalation_is_untouched():
    assert _gate("Files Copied to USB Drives", "root", cls="NEEDS_L2").triage_class == "NEEDS_L2"


def test_office_service_account_housekeeping_still_closes():
    r = _gate(OFFICE, EXCH, {"additional_users": []})
    assert r.triage_class == "AUTO_CLOSED_FP"


DREW = "v-drew.calder@acme.net"


def _office_hunt(*rows):
    return _CALLS + [ToolCallRecord(name="hunt_office", args={}, result={"rows": [
        {"UserId": DREW, "ExternalAccess": "False", **r} for r in rows]})]


def _ranjay(calls, user=EXCH):
    return _gate(OFFICE, user, {"additional_users": [DREW]}, calls=calls)


def test_person_whose_operation_was_never_looked_at_is_not_closed():
    """DEMO-113070: only the service account's Set-Mailbox was hunted."""
    r = _ranjay(_CALLS)
    assert r.triage_class == "NEEDS_L2" and r.safety_gate_kind == "office_person_actor"
    assert "never retrieved" in r.safety_block_reason


def test_sim_108455_sorting_rule_closes():
    """The real rules: "Move all messages from v-leah.grant@acme.net to QA"."""
    calls = _office_hunt({"Operation": "New-InboxRule", "KeySettings": "MoveToFolder=QA"},
                         {"Operation": "New-InboxRule", "KeySettings": "MoveToFolder=OPS"},
                         {"Operation": "MailItemsAccessed", "KeySettings": ""})
    assert _ranjay(calls).triage_class == "AUTO_CLOSED_FP"


def test_rule_that_forwards_deletes_or_hides_is_not_closed():
    for ks in ("ForwardTo=evil@gmail.com", "RedirectTo=x@y.com", "DeleteMessage=True",
               "MoveToFolder=RSS Feeds", "MoveToFolder=:\\Conversation History",
               "MoveToFolder=QA, MarkAsRead=True",
               "MoveToFolder=LgAAAAAVyO4n2XzXSZwqdNtmD6oRAQB"):
        r = _ranjay(_office_hunt({"Operation": "New-InboxRule", "KeySettings": ks}))
        assert r.triage_class == "NEEDS_L2", ks


def test_a_person_granting_mailbox_permission_is_not_closed():
    r = _ranjay(_office_hunt({"Operation": "Add-MailboxPermission", "KeySettings": ""}))
    assert r.triage_class == "NEEDS_L2" and "not an inbox rule" in r.safety_block_reason


def test_office_single_person_primary_unchecked_is_asked():
    r = _gate(OFFICE, DREW, {"additional_users": []})
    assert r.triage_class == "REQUEST_JUSTIFICATION"


def test_sim_116237_garbled_close_is_escalated():
    text = ("These chillains Sha256 hashes were checked, and all returned Egyes were clean. "
            "The `root` account is a shared/built-in었으며 account.")
    r = _gate("Root Privilege Escalation", "root", reasoning=text)
    assert r.triage_class == "NEEDS_L2" and r.safety_gate_kind == "garbled_output"


def test_non_latin_text_quoted_from_a_tool_result_is_not_garbled():
    calls = [ToolCallRecord(name="hunt_file", args={}, result={"rows": [{"FileName": "वेतन.xlsx"}]})]
    assert _garbled_reasoning("The file वेतन.xlsx was opened.", calls, {}) == ""
    assert _garbled_reasoning("Plain English reasoning, café résumé naïve.", [], {}) == ""


def test_operation_less_office_hunt_drops_read_noise_only():
    q = sentinel_office_activity(user="v-drew.calder@acme.net")
    assert "!in~" in q and "MailItemsAccessed" in q
    q = sentinel_office_activity(operation="MailItemsAccessed", user="x")
    assert "!in~" not in q


def _urgent(open_urgent, cls="AUTO_CLOSED_FP"):
    return _apply_safety_gates(
        AgentResult(triage_class=cls, confidence=0.95, reasoning="Session expiries."),
        severity="MEDIUM", is_test_device=False, tool_calls=_CALLS, device_name="",
        user_name="theo.malik@example.com", evidence={}, open_urgent=open_urgent,
        alert_name="Privileged Accounts - Sign in Failure Spikes involving one user")


def test_sim_117913_open_urgent_on_the_same_user_blocks_the_close():
    r = _urgent([{"jira_key": "DEMO-117523", "alert_name": "Privileged Accounts - Sign in"}])
    assert r.triage_class == "NEEDS_L2" and r.safety_gate_kind == "open_urgent_on_entity"
    assert "DEMO-117523" in r.safety_block_reason


def test_open_urgent_lookup_failure_blocks_and_none_open_allows():
    assert _urgent([{"error": "x"}]).triage_class == "NEEDS_L2"
    assert _urgent([]).triage_class == "AUTO_CLOSED_FP"
    assert _urgent(None).triage_class == "AUTO_CLOSED_FP"


def test_sim_117622_signed_ultraviewer_service_is_not_closed():
    calls = _CALLS + [ToolCallRecord(name="hunt_service", args={}, result={"rows": [
        {"FileName": "ultraviewer_service.exe", "Signer": "DUC FABULOUS CO.,LTD", "Verdict": "TRUSTED"}]})]
    r = _gate("Rare Process as a Service", "", calls=calls)
    assert r.triage_class == "NEEDS_L2" and r.safety_gate_kind == "remote_access_tool"


def test_asking_about_a_remote_tool_is_not_finding_one():
    calls = _CALLS + [ToolCallRecord(name="hunt_process", args={"process_name": "anydesk.exe"},
                                     result={"rows": [], "kql": "where FileName =~ 'anydesk.exe'"})]
    assert _gate("Rare Process as a Service", "", calls=calls).triage_class == "AUTO_CLOSED_FP"


def test_sim_116333_office_close_shows_the_exact_activity():
    from agent_core.result import AgentResult
    rows = [{"TimeGenerated": "2026-10-09T06:10:00Z", "Operation": "Set-AdminAuditLogConfig",
             "UserId": "NT SERVICE\\MSExchangeAdminApiNetCore", "Target": "Admin Audit Log Settings",
             "KeySettings": "AdminAuditLogEnabled=True", "ExternalAccess": "False",
             "ResultStatus": "True", "ChangedParams": "AdminAuditLogEnabled"},
            {"TimeGenerated": "2026-10-09T06:12:00Z", "Operation": "Remove-StoreMailbox",
             "UserId": "NT SERVICE\\MSExchangeAdminApiNetCore", "Target": "Soft Deleted Objects\\ab12",
             "KeySettings": "", "ExternalAccess": "False", "ResultStatus": "True",
             "ChangedParams": "Identity, Database, MailboxState"}]
    r = AgentResult(triage_class="AUTO_CLOSED_FP", confidence=0.95, reasoning="Routine.",
                    tool_calls=[ToolCallRecord(name="hunt_office", args={}, result={"rows": rows})])
    for text in (r.to_jira_comment("DEMO-1", OFFICE), r.to_jira_recommendation(OFFICE)):
        assert "*Set-AdminAuditLogConfig* by NT SERVICE" in text
        assert "AdminAuditLogEnabled=True" in text
        assert "Soft Deleted Objects" in text and "Identity, Database, MailboxState" in text


def test_sim_118344_a_close_whose_hunts_all_came_back_empty_is_blocked():
    calls = [ToolCallRecord(name="scg_check_concurrent_alerts", args={}, result={"concurrent_count": 0}),
             ToolCallRecord(name="hunt_query", args={}, result={"rows": [], "count": 0, "kql": "x"})]
    r = _gate("Monitor AWS Credential abuse or hijacking", "EKS", calls=calls)
    assert r.triage_class == "NEEDS_L2" and r.safety_gate_kind == "no_hunt_data"


def test_sim_119923_a_close_with_no_hunt_at_all_is_blocked():
    calls = [ToolCallRecord(name="scg_check_concurrent_alerts", args={}, result={"concurrent_count": 0}),
             ToolCallRecord(name="scg_get_entity_context", args={}, result={"alert_count": 634})]
    r = _gate("Monitor AWS Credential abuse or hijacking", "EKS", calls=calls)
    assert r.triage_class == "NEEDS_L2" and "no telemetry was hunted" in r.safety_block_reason


def test_sim_121888_rule_upgrade_does_not_leave_an_escalation_text_under_a_close():
    rows = [{"FileName": "wavessyssvc64.exe", "TrustedHashes": 3, "UntrustedHashes": 0,
             "OddUnverifiedHashes": 0, "Paths": ["C:\\\\Program Files\\\\Waves\\\\MaxxAudio"]}]
    calls = _CALLS + [ToolCallRecord(name="hunt_service", args={}, result={"rows": rows})]
    r = _apply_safety_gates(
        AgentResult(triage_class="NEEDS_L2", confidence=0.6, reasoning="Inconclusive, needs L2.",
                    recommended_actions=["Escalate to L2 for deeper analysis."]),
        severity="MEDIUM", is_test_device=False, tool_calls=calls, device_name="pc.corp.example.com",
        user_name="", evidence={"process_check": {"distinct": ["wavessyssvc64.exe"]}},
        alert_name="Rare Process as a Service")
    assert r.triage_class == "AUTO_CLOSED_FP", r.safety_block_reason
    assert r.reasoning.startswith("Closed by RAPTOR's service-identity rule")
    assert "Inconclusive, needs L2." in r.reasoning
    assert not any("Escalate" in a for a in r.recommended_actions)
