#!/usr/bin/env python3
"""Prove the data-sovereignty boundary — for real, with no LLM and no network.

This imports the SHIPPED sanitizer (`agent_core.sanitize.AlertSanitizer`) — the exact
class the agent loop uses — and runs a full round trip on a realistic alert:

    raw alert  --sanitize-->  what crosses to the cloud LLM  (tokens; IOCs preserved)
                                        |
    real tool args  <--desanitize--  the LLM's tool call (referring to tokens)

It then asserts that NO sensitive value appears in the outbound text (zero-leakage),
and exits non-zero if any does — so it's both a live demo and a regression test.

    python demo/show_boundary.py
"""
from __future__ import annotations

import json
import sys

from agent_core.sanitize import AlertSanitizer

# ── ANSI (skip if not a TTY) ────────────────────────────────────────────────
_tty = sys.stdout.isatty()
def c(s, code): return f"\033[{code}m{s}\033[0m" if _tty else s
def red(s):    return c(s, "38;5;203")
def green(s):  return c(s, "38;5;114")
def purple(s): return c(s, "38;5;141")
def dim(s):    return c(s, "38;5;244")
def bold(s):   return c(s, "1")


# ── A realistic alert: sensitive infra identifiers + public IOCs mixed together ──
DEVICE = "WKSTN-FIN-4471"
USER = "alice.chen@example.com"
ARN = "arn:aws:sts::123456789012:assumed-role/finance-admin/alice.chen"

# Sensitive (must NOT leave on-prem): device, user, ARN, instance-id, internal IP,
#   SID, and the command line.
# Public IOCs (MUST be preserved as evidence): the SHA-256, the external C2 domain,
#   and the external IP.
RAW_PROMPT = (
    f"Alert: Suspicious encoded PowerShell on {DEVICE} ({DEVICE}.corp.example.com).\n"
    f"User: {USER}  (bare form: alice.chen)\n"
    f"AWS principal: {ARN}\n"
    f"Instance: i-04a2ce810d6b72956   Internal IP: 10.0.4.17\n"
    f"SID: S-1-5-21-1004336348-1177238915-682003330-1234\n"
    f"Command line: powershell.exe -enc SQEXAGkAdABlAGMAaABvAA==  "
    f"downloading from https://c2-panel.redteam-bad.io (45.33.32.156)\n"
    f"File SHA-256: 9f2a1c4e8b7d6f5039a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8"
)

# What the LLM decides to do — it refers to entities by the TOKENS it was shown.
# (In the real loop this comes back from the model; here we template it so the
#  round trip is deterministic and reviewable.)
def llm_tool_call(dev_token: str, user_token: str) -> dict:
    return {
        "tool": "mde_advanced_hunt",
        "args": {
            "device": dev_token,
            "account": user_token,
            "lookback_hours": 24,
        },
    }


# The public IOCs that must survive the boundary untouched.
PUBLIC_IOCS = [
    "9f2a1c4e8b7d6f5039a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8",  # sha256
    "c2-panel.redteam-bad.io",  # external domain
    "45.33.32.156",             # external IP
]

# The sensitive values that must NEVER appear in outbound text.
SENSITIVE = [DEVICE, "alice.chen", "arn:aws:sts::123456789012",
             "i-04a2ce810d6b72956", "10.0.4.17", "S-1-5-21-1004336348"]


def rule(title=""):
    bar = "─" * 74
    print(f"\n{dim(bar)}")
    if title:
        print(bold(title))


def main() -> int:
    # This is exactly how agent_core/loop.py constructs the sanitizer per run.
    san = AlertSanitizer(device_name=DEVICE, user_name=USER)

    rule("1 · RAW ALERT  (regulated zone — never leaves on-prem)")
    print(RAW_PROMPT)

    outbound = san.sanitize(RAW_PROMPT)
    rule("2 · WHAT CROSSES THE BOUNDARY  →  cloud LLM  (sanitized)")
    print(outbound)

    dev_token = san.sanitize(DEVICE)
    user_token = san.sanitize("alice.chen")
    call = llm_tool_call(dev_token, user_token)
    rule("3 · LLM RESPONSE  —  a tool call, referring only to tokens")
    print(json.dumps(call, indent=2))

    restored = san.desanitize_obj(call["args"])
    rule("4 · RESTORED BEFORE EXECUTION  —  real values, on-prem only")
    print(json.dumps(restored, indent=2))

    # ── Assertions ──────────────────────────────────────────────────────────
    rule("LEAK CHECK")
    leaked = [v for v in SENSITIVE if v.lower() in outbound.lower()]
    preserved = [ioc for ioc in PUBLIC_IOCS if ioc in outbound]
    restored_ok = (restored["device"] == DEVICE and restored["account"] == USER)

    ok = True
    if leaked:
        print(red(f"✗ LEAKED {len(leaked)} sensitive value(s): {leaked}")); ok = False
    else:
        print(green("✓ zero sensitive identifiers crossed the boundary"))

    if len(preserved) == len(PUBLIC_IOCS):
        print(green(f"✓ all {len(PUBLIC_IOCS)} public IOCs preserved as evidence"))
    else:
        missing = [i for i in PUBLIC_IOCS if i not in preserved]
        print(red(f"✗ public IOC(s) wrongly stripped: {missing}")); ok = False

    if restored_ok:
        print(green(f"✓ tokens restored to real values before tool execution"))
        print(dim(f"    {dev_token} → {DEVICE}"))
        print(dim(f"    {user_token} → {USER}"))
    else:
        print(red("✗ round-trip restore mismatch")); ok = False

    rule()
    if ok:
        print(green(bold("BOUNDARY HOLDS")) + dim("  — the LLM reasoned over tokens; the tools ran on real values."))
        return 0
    print(red(bold("BOUNDARY FAILED")))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
