#!/usr/bin/env python3
"""Adversarial finding — demonstrated boundary bypasses.

This is the honest counterpart to `demo/show_boundary.py`. The sanitizer seeds only the
alert's PRIMARY device and user and matches infra identifiers by regex, so any OTHER
sensitive identifier in free text can slip through. Here are two documented gaps with a
concrete, runnable repro and the mitigation for each. Both map to
docs/attacking-the-boundary.md (classes A and B).

    python demo/attack_boundary.py

Exit code is the number of identifiers that crossed the boundary — expected to be > 0.
These are known, documented gaps, not a regression: the point of an Arsenal tool is to
show where it breaks, not to pretend it doesn't.
"""
from __future__ import annotations

import sys
from agent_core.sanitize import AlertSanitizer

_tty = sys.stdout.isatty()
def c(s, code): return f"\033[{code}m{s}\033[0m" if _tty else s
def red(s):   return c(s, "38;5;203")
def green(s): return c(s, "38;5;114")
def dim(s):   return c(s, "38;5;244")
def bold(s):  return c(s, "1")

# The sanitizer is seeded with the alert's primary device + user only — exactly as the
# pipeline seeds it in production.
PRIMARY_DEVICE = "WKSTN-FIN-4471"
PRIMARY_USER = "alice.chen@example.com"
s = AlertSanitizer(device_name=PRIMARY_DEVICE, user_name=PRIMARY_USER)

# (label, sensitive value, text that carries it, threat-model class, mitigation)
CASES = [
    (
        "lateral-movement target host (a SECOND internal host, never seeded)",
        "JUMPBOX-DB-02",
        r"ProcessCommandLine: psexec.exe \\JUMPBOX-DB-02 -u svc-backup cmd /c whoami",
        "A — unenumerated entity",
        "seed EVERY entity the extractor finds (all hosts/users in the alert), not just the primary two",
    ),
    (
        "second user named in evidence (bare, not an internal-domain email)",
        "bob.finance",
        "Prior comment: bob.finance confirmed he ran the script on the DBA's behalf.",
        "A — unenumerated entity",
        "seed all extracted principals; the internal-email regex only catches user@company-domain",
    ),
    (
        "internal IPv6 (unique-local fd00::/8)",
        "fd00:abcd:1234::1",
        "Session opened from internal host fd00:abcd:1234::1 to the alerted device.",
        "B — regex format-evasion",
        "extend the internal-IP regex beyond RFC1918 IPv4 to fd00::/8 and fe80::/10",
    ),
    (
        "device name hidden in a base64 command-line arg",
        "V0tTVE4tRklOLTQ0NzE=",  # base64('WKSTN-FIN-4471')
        "powershell.exe -enc V0tTVE4tRklOLTQ0NzE=  # decodes to the device name",
        "B — encoded identifier in free text",
        "decode common encodings (base64/hex) before scanning, or strip the command line in text too",
    ),
]


def main() -> int:
    print(bold("\nAdversarial test — crafting identifiers past the sanitizer\n"))
    print(dim(f"seeded (protected): device={PRIMARY_DEVICE}  user={PRIMARY_USER}\n"))
    leaked = 0
    for label, secret, text, klass, fix in CASES:
        out = s.sanitize(text)
        crossed = secret in out
        tag = red("LEAKED  ") if crossed else green("contained")
        leaked += 1 if crossed else 0
        print(f"  {tag}  {label}")
        print(dim(f"            value    : {secret}"))
        print(dim(f"            outbound : {out}"))
        print(dim(f"            class    : {klass}"))
        print(dim(f"            mitigation: {fix}\n"))
    print(bold(f"{leaked}/{len(CASES)} crafted identifiers crossed the boundary."))
    print(dim("All are documented gaps (docs/attacking-the-boundary.md). The sanitizer is "
              "defense-in-depth, not a\ncryptographic guarantee — deploy it with an egress DLP "
              "control. See the hardening roadmap for fixes.\n"))
    return leaked


if __name__ == "__main__":
    sys.exit(main())
