"""A close resting on a specific grant must rest on one the model was shown.

DEMO-119919: "the user was explicitly granted an exception" looked invented and was not —
parker wrote it on DEMO-115148/115090 and the precedents carried it into the prompt.
"""
from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from agent_core import claim_check as C
from agent_core import oscar


def _seen(user="", system_ctx="", tools=()):
    msgs = [{"role": "system", "content": oscar.OSCAR_SYSTEM + system_ctx},
            {"role": "user", "content": user}]
    return C.seen_text(msgs, [SimpleNamespace(result=r) for r in tools],
                       static_prompt=oscar.OSCAR_SYSTEM)


R_119919 = ("All prior alerts were closed as false positives after an exception was granted "
            "for the user (blair.ahuja). The files are part of an approved workflow.")


def test_sim_119919_a_grant_the_precedents_carried_is_backed():
    ctx = ("DEMO-115148 L2: False Positive — User has been given an exception to copy files "
           "into USB drive/external storage devices as part of their daily activities")
    assert C.unbacked_grants(R_119919, _seen(system_ctx=ctx)) == []


def test_the_same_claim_with_nothing_behind_it_is_unbacked():
    assert C.unbacked_grants(R_119919, _seen(user="Files Copied to USB Drives")) == [
        "an exception granted"]


def test_the_fixed_guidance_never_backs_a_claim():
    # OSCAR_SYSTEM itself says "exception", "allowlist", "confirm" in general terms.
    assert "exception" in oscar.OSCAR_SYSTEM.lower()
    assert C.unbacked_grants("An exception was granted under a change ticket.", _seen()) == [
        "an exception granted", "a change ticket"]


@pytest.mark.parametrize("reasoning,label,backing", [
    ("Covered by change request CHG1234.", "a change ticket", "CHG1234 approved"),
    ("Port 9182 is allowlisted.", "an allowlist entry", "port_sweep_check known_good: true"),
    ("This ran in a planned maintenance window.", "a planned window", "maintenance 02:00-04:00"),
    ("The script was approved by the platform team.", "a named approval", "approved"),
    ("The user confirmed this was a backup.", "a person's confirmation",
     "As per the confirmation from user, backup"),
])
def test_each_grant_needs_its_backing(reasoning, label, backing):
    assert C.unbacked_grants(reasoning, _seen()) == [label]
    assert C.unbacked_grants(reasoning, _seen(tools=[{"note": backing}])) == []


@pytest.mark.parametrize("reasoning", [
    "Prior analyst verdicts confirm this activity is routine and authorized.",
    "rm of dated files in approved folders.",
    "No change ticket was found for this activity.",
    "There is no exception on file.",
    "The script raised an exception error and exited.",
])
def test_paraphrase_negation_and_errors_are_not_grants(reasoning):
    assert C.unbacked_grants(reasoning, _seen()) == []


def test_its_own_nudge_cannot_back_the_claim():
    nudge = {"role": "user", "content": "Your reasoning relies on an exception granted"}
    msgs = [{"role": "system", "content": oscar.OSCAR_SYSTEM}, nudge]
    seen = C.seen_text(msgs, [], static_prompt=oscar.OSCAR_SYSTEM, skip=(nudge,))
    assert C.unbacked_grants(R_119919, seen) == ["an exception granted"]


def test_the_loop_nudges_then_blocks():
    from agent_core import loop as L
    src = inspect.getsource(L.run)
    assert src.count("unbacked_grants") >= 2 and "Unbacked grant" in src
    assert "skip=tuple(_gate_msgs)" in src and "static_prompt=oscar_module.OSCAR_SYSTEM" in src


@pytest.mark.parametrize("reasoning", [
    "The precedents are analyst-verified and meet the EXACT COMMAND MATCH exception for auto-closing.",
    "The exception for this alert type applies: hunt_service already resolved the binaries.",
    "Update the whitelist for this rule to include `CxAudioSvc.exe`.",
    "Add `x.exe` to the whitelist for this alert rule to prevent recurrence.",
])
def test_raptors_own_policy_exceptions_and_advice_are_not_grants(reasoning):
    """DEMO-118578, 119093, 121040: would have blocked correct closes."""
    assert C.unbacked_grants(reasoning, _seen()) == []


def test_port_sweep_allowlist_is_backed_by_the_known_good_check():
    seen = C.seen_text([], [], evidence={"port_sweep_check": {"known_good": True, "port": 9182}})
    assert C.unbacked_grants("Port 9182 is on the SOC's known-good port-sweep allowlist.", seen) == []
