#!/usr/bin/env python3
"""Round-trip + zero-leakage test for the data-sovereignty boundary.

Runs two ways:

    python tests/test_boundary.py      # plain-python, exits non-zero on any failure
    pytest tests/test_boundary.py      # if pytest is installed

Asserts, against the SHIPPED AlertSanitizer (the exact class the agent loop uses):
  - seeded device/user (incl. FQDN and bare local-part forms) never appear in outbound text
  - infra identifiers (ARN, instance id, RFC1918 IP, SID, MAC, access key) are redacted
  - public IOCs (file hash, external domain, external IP) are preserved as evidence
  - a token-only tool call round-trips back to real values before execution
  - sanitize_obj drops known-sensitive columns wholesale
"""
from __future__ import annotations

import sys
from agent_core.sanitize import AlertSanitizer

DEVICE = "WKSTN-FIN-4471"
USER = "alice.chen@example.com"
ARN = "arn:aws:sts::123456789012:assumed-role/finance-admin/alice.chen"
INSTANCE = "i-04a2ce810d6b72956"
INTERNAL_IP = "10.0.4.17"
SID = "S-1-5-21-1004336348-1177238915-682003330-1234"
MAC = "aa:bb:cc:dd:ee:ff"
ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

HASH = "9f2a1c4e8b7d6f5039a2b1c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8"
C2_DOMAIN = "c2-panel.redteam-bad.io"
EXTERNAL_IP = "45.33.32.156"


def _s() -> AlertSanitizer:
    return AlertSanitizer(device_name=DEVICE, user_name=USER)


def test_seeded_identifiers_never_leak():
    s = _s()
    raw = (
        f"Alert on {DEVICE} ({DEVICE}.corp.example.com). User {USER} (bare: alice.chen). "
        f"Principal {ARN}. Instance {INSTANCE}. Internal IP {INTERNAL_IP}. "
        f"SID {SID}. NIC {MAC}. Key {ACCESS_KEY}."
    )
    out = s.sanitize(raw)
    for secret in (
        DEVICE, DEVICE.lower(), f"{DEVICE}.corp.example.com".lower(),
        USER, "alice.chen", ARN, INSTANCE, INTERNAL_IP, SID, MAC, ACCESS_KEY,
    ):
        assert secret.lower() not in out.lower(), f"LEAK: {secret!r} survived sanitize()"


def test_public_iocs_preserved():
    s = _s()
    out = s.sanitize(f"SHA256 {HASH}; beacon to {C2_DOMAIN} ({EXTERNAL_IP}).")
    for ioc in (HASH, C2_DOMAIN, EXTERNAL_IP):
        assert ioc in out, f"IOC dropped: {ioc!r} — public evidence must be preserved"


def test_round_trip_restores_real_values():
    s = _s()
    # The cloud model only ever saw tokens; it replies with a tool call referring to them.
    dev_token = s.sanitize(DEVICE)          # -> [DEVICE-xxxx]
    user_token = s.sanitize(USER)           # -> [USER-yyyy]
    assert dev_token != DEVICE and user_token != USER, "sanitize did not tokenize"
    tool_call = {"tool": "hunt_process", "args": {"device": dev_token, "user": user_token}}
    restored = s.desanitize_obj(tool_call)
    assert restored["args"]["device"] == DEVICE, "device token did not restore"
    assert restored["args"]["user"] == USER, "user token did not restore"


def test_sensitive_columns_stripped():
    s = _s()
    row = {
        "DeviceName": DEVICE,
        "ProcessCommandLine": "powershell.exe -enc SQBFAFgA...",
        "AccountName": "alice.chen",
        "sha256": HASH,           # not a stripped column, and a public IOC
        "note": f"talked to {C2_DOMAIN}",
    }
    clean = s.sanitize_obj(row)
    assert clean["DeviceName"] == "[REDACTED]"
    assert clean["ProcessCommandLine"] == "[REDACTED]"
    assert clean["AccountName"] == "[REDACTED]"
    assert clean["sha256"] == HASH, "public IOC must survive"
    assert C2_DOMAIN in clean["note"], "external domain must survive"


def _run() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
