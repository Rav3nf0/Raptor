"""Verification agent — second R1 call post-verdict to check before writing to SCG.

Uses a hard rule table per verdict type — does NOT rely on LLM judgment for conflict detection.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from agent_core.result import AgentResult, ToolCallRecord

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    consistent: bool
    reason: str
    tier: str  # "quarantine" | "curated" | "golden"
    trust_override: float | None = None


def verify(result: AgentResult) -> VerificationResult:
    """Apply rule-based verification. Returns whether memory should be quarantined."""
    tc = result.triage_class
    tool_calls = result.tool_calls

    if tc == "AUTO_CLOSED_FP":
        return _verify_fp(result, tool_calls)
    elif tc in ("AUTO_CLOSED_TP", "URGENT"):
        return _verify_tp(result, tool_calls)
    elif tc == "NEEDS_L2":
        return VerificationResult(consistent=True, reason="NEEDS_L2 is always consistent", tier="curated")
    elif tc == "REQUEST_JUSTIFICATION":
        # Like NEEDS_L2: closes nothing and suppresses nothing, so there is no verdict
        # to contradict. Without this it fell through to "Unknown triage class" and every
        # justification request was quarantined as if it were malformed.
        return VerificationResult(consistent=True,
                                  reason="REQUEST_JUSTIFICATION closes nothing — always consistent",
                                  tier="curated")
    return VerificationResult(consistent=True, reason="Unknown triage class", tier="quarantine")


def _verify_fp(result: AgentResult, tool_calls: list[ToolCallRecord]) -> VerificationResult:
    """FP verification rules — any of these makes the verdict conflicting."""

    # Rule 1: Any VT detections > 0
    for tc in tool_calls:
        if tc.name.startswith("vt_lookup"):
            detections = tc.result.get("detections", 0)
            if detections > 0:
                return VerificationResult(
                    consistent=False,
                    reason=f"VT returned {detections}/{tc.result.get('total', '?')} detections but verdict is AUTO_CLOSED_FP",
                    tier="quarantine",
                )

    # Rule 2: Safety gate was triggered (should never happen, but guard)
    if result.blocked_by_safety:
        return VerificationResult(
            consistent=False,
            reason=f"Safety gate triggered but verdict is AUTO_CLOSED_FP: {result.safety_block_reason}",
            tier="quarantine",
        )

    # Rule 3: MDE timeline contains known-malicious process names
    for tc in tool_calls:
        if tc.name == "mde_get_timeline":
            events = tc.result.get("events", [])
            for event in events:
                proc = (event.get("ProcessCommandLine") or event.get("FileName") or "").lower()
                if any(bad in proc for bad in _MALICIOUS_PROCESS_INDICATORS):
                    return VerificationResult(
                        consistent=False,
                        reason=f"MDE timeline contains suspicious process: {proc[:60]}",
                        tier="quarantine",
                    )

    # Rule 4: Confidence below acceptable threshold for the tier
    if result.confidence < 0.65:
        return VerificationResult(
            consistent=False,
            reason=f"AUTO_CLOSED_FP confidence {result.confidence:.0%} is below minimum 0.65 for curated memory",
            tier="quarantine",
        )

    # Passed all checks
    tier = "golden" if result.confidence >= 0.90 else "curated"
    return VerificationResult(consistent=True, reason="All FP verification rules passed", tier=tier)


def _verify_tp(result: AgentResult, tool_calls: list[ToolCallRecord]) -> VerificationResult:
    """TP verification — a TP verdict with no VT or MDE evidence needs quarantine."""
    has_evidence = False
    for tc in tool_calls:
        if tc.name.startswith("vt_lookup") and tc.result.get("detections", 0) > 0:
            has_evidence = True
        if tc.name == "mde_get_timeline" and tc.result.get("count", 0) > 0:
            has_evidence = True
        if tc.name in ("mde_advanced_hunt", "sentinel_run_kql") and tc.result.get("count", 0) > 0:
            has_evidence = True

    if not has_evidence:
        return VerificationResult(
            consistent=False,
            reason="AUTO_CLOSED_TP verdict with no supporting VT/MDE/Sentinel evidence",
            tier="quarantine",
        )
    tier = "golden" if result.confidence >= 0.90 else "curated"
    return VerificationResult(consistent=True, reason="TP verdict supported by evidence", tier=tier)


_MALICIOUS_PROCESS_INDICATORS = frozenset([
    "mimikatz", "procdump", "meterpreter", "cobalt", "beacon",
    "empire", "powersploit", "invoke-obfuscation", "invoke-mimikatz",
    "wce.exe", "gsecdump", "cachedump", "fgdump", "pwdump",
    "lsass.exe -dump", "tasklist /v", "net user /domain",
    "whoami /all", "nltest", "bloodhound", "sharphound",
    "psexec", "wmiexec", "dcsync",
])
