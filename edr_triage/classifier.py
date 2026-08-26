"""Alert classifier — maps alert name / investigation state to a playbook name.

Classification is done in priority order:
  1. Exact / substring match on alert name (case-insensitive)
  2. Investigation state (e.g. "No threats found" → generic FP)
  3. Fallback → generic playbook
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Pattern tables — order matters: first match wins
# ---------------------------------------------------------------------------

_BLOCK_TOOL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"block\s+anydesk",
        r"anydesk",
        r"custom\s+enterprise\s+block",
        r"enterprise\s+block",
        r"block\s+teamviewer",
        r"teamviewer",
        r"block\s+ammyy",
        r"block\s+ultraviewer",
    ]
]

_PORT_SWEEP_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"port\s+sweep",
        r"network\s+scan",
        r"port\s+scan",
    ]
]

_MALWARE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"stealer",
        r"infostealer",
        r"clickfix",
        r"ransomware",
        r"trojan",
        r"backdoor",
        r"downloader",
        r"dropper",
        r"malware",
        r"lumma",
        r"redline",
        r"vidar",
        r"raccoon",
        r"formbook",
        r"agent\s+tesla",
        r"njrat",
        r"asyncrat",
        # Defender behavior detections (Impact/ransomware family) — MDE endpoint
        # alerts that must use the malware playbook (MDE evidence), not the
        # generic → Sentinel CloudTrail parse.
        r"encryption'?\s+behaviou?r",
        r"ransomware\s+behaviou?r",
        r"suspicious\s+.{0,3}encryption",
    ]
]

_REVERSE_SHELL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"reverse\s+shell",
        r"linpeas",
        r"winpeas",
        r"mimikatz",
        r"hacktool",
        r"metasploit",
        r"meterpreter",
        r"cobalt\s+strike",
        r"sliver",
        r"powersploit",
        r"invoke-mimikatz",
        r"invoke-bloodhound",
        r"sharphound",
        r"bloodhound",
        r"pentest",
        r"exploit",
    ]
]

_LATERAL_MOVE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"lateral\s+move",
        r"hands.on.keyboard",
        r"compromised\s+account",
        r"credential\s+theft",
        r"pass.the.hash",
        r"kerberoast",
        r"dcsync",
        r"golden\s+ticket",
        r"silver\s+ticket",
        r"impacket",
        r"psexec",
        r"wmiexec",
        r"smbexec",
    ]
]

_SKIP_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"netskope\s+dlp",
        r"dlp\s+alert",
        r"log\s+ingestion\s+stopped",
        r"log\s+injestion\s+stopped",     # common MDE typo
        r"data\s+loss\s+prevention",
        r"shadow\s+it",
        # AWS GuardDuty — not endpoint EDR alerts
        r"ec2\s+instance\s+i-[0-9a-f]+",
        r"monitor\s+aws\s+credential",
        r"aws\s+credential\s+abuse",
        r"assumedrole\s*:",
        r"the\s+user\s+assumedrole",
        # Entra ID PIM / privileged access management — not endpoint alerts
        r"privileged\s+role\s+assigned\s+outside\s+pim",
        r"pim\s+role\s+assigned",
    ]
]

_PRIVESC_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"privilege\s+escalation",
        r"privesc",
        r"uac\s+bypass",
        r"token\s+impersonation",
        r"suspicious\s+powershell",
        r"obfuscated\s+powershell",
        r"encoded\s+powershell",
        r"malicious\s+powershell",
    ]
]

_ENDPOINT_PROCESS_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"suspicious\s+curl",
        r"suspicious\s+wget",
        r"\bcurl\b.*(?:behavior|download)",
        r"\bwget\b.*(?:behavior|download)",
        r"certutil",
        r"bitsadmin",
        r"suspicious\s+download",
        r"file\s+download.*curl",
        # LOLBin / living-off-the-land script execution (Sentinel NRT). Evidence
        # lives in DeviceEvents PowerShellCommand telemetry, enriched in the pipeline.
        r"powershell\s+script\s+.*loaded\s+in\s+memory",
        r"script\s+was\s+loaded\s+in\s+memory",
        r"living\s+off\s+the\s+land",
    ]
]

_NETSKOPE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"netskope\s*-?\s*failed\s+login",
        r"netskope.*failed\s+login",
        r"netskope.*sign.?in\s+fail",
        # Netskope cloud-malware alerts — evidence lives in Netskope_Alerts_CL,
        # NOT MDE. Route here (before the bare 'malware' pattern) so they don't hit the
        # MDE malware playbook and render Unknown/Unknown (DEMO-104584).
        r"netskope\s*-?\s*malware",
        r"netskope.*malware",
        # Netskope UBA anomaly alerts (Bulk Upload / Bulk Download). Evidence lives in
        # Netskope_Alerts_CL under alert_type_s == "uba", and the rule aggregates with
        # SingleAlert — so ONE incident routinely spans SEVERAL users. Route here: the
        # Netskope playbook is the only one that renders every affected user, whereas
        # generic collapses the account entities to accounts[0] and reports a single
        # user (DEMO-107416 named taylor.singh and never mentioned the second user
        # sachin.khodpia, who is the one L1 actually investigated).
        r"netskope.*bulk\s+(?:upload|download)",
        r"bulk\s+(?:upload|download)\s+detection",
    ]
]

_CREDENTIAL_ACCESS_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"password\s+cracking",
        r"password\s+spray",
        r"brute\s+force",
        r"credential\s+access",
        r"sign.in.*failure",
        r"failed.*sign.in",
        r"multiple.*failed.*password",
        r"distributed.*password",
        r"entra.*id.*password",
        r"anomalous.*sign.in",
        r"failed.*login",
        r"login.*failed",
        r"multiple.*failed.*login",
    ]
]


def classify(alert_name: str, investigation_state: str = "") -> str:
    """Return a playbook name for the given alert.

    Playbook names: block_tool | malware | reverse_shell | lateral_move | netskope | credential_access | privesc | endpoint_process | port_sweep | generic | skip
    Checks user-defined rules (MongoDB) before hardcoded patterns.
    """
    name = (alert_name or "").strip()

    # User-defined rules take priority over hardcoded patterns
    try:
        from edr_triage.rules import classify_by_rules
        user_result = classify_by_rules(name)
        if user_result is not None:
            return user_result
    except Exception:
        pass  # never crash classification due to rule load failure

    for pat in _SKIP_PATTERNS:
        if pat.search(name):
            return "skip"

    for pat in _BLOCK_TOOL_PATTERNS:
        if pat.search(name):
            return "block_tool"

    for pat in _LATERAL_MOVE_PATTERNS:
        if pat.search(name):
            return "lateral_move"

    # Netskope web-proxy "failed login" events are policy/category blocks, NOT
    # Azure AD credential attacks — route to their own playbook before the
    # generic credential_access sign-in patterns below can claim them.
    for pat in _NETSKOPE_PATTERNS:
        if pat.search(name):
            return "netskope"

    for pat in _CREDENTIAL_ACCESS_PATTERNS:
        if pat.search(name):
            return "credential_access"

    for pat in _REVERSE_SHELL_PATTERNS:
        if pat.search(name):
            return "reverse_shell"

    for pat in _PRIVESC_PATTERNS:
        if pat.search(name):
            return "privesc"

    # Network Port Sweep (Sentinel Discovery alerts) — decided by a destination-port
    # allowlist in the SOC runbook, so route to its own playbook before generic.
    for pat in _PORT_SWEEP_PATTERNS:
        if pat.search(name):
            return "port_sweep"

    for pat in _MALWARE_PATTERNS:
        if pat.search(name):
            return "malware"

    # Endpoint download-tool / LOLBin process alerts (suspicious curl/wget/certutil):
    # these are MDE endpoint process events — keep them OUT of the Sentinel CloudTrail
    # parse (which reads the wrong host's data) so the real command line + correct
    # device/user come from MDE evidence.
    for pat in _ENDPOINT_PROCESS_PATTERNS:
        if pat.search(name):
            return "endpoint_process"

    # Investigation state fallback
    if investigation_state.lower() in ("no threats found", "benign positive"):
        return "no_threat"

    return "generic"


# ---------------------------------------------------------------------------
# Learning subtype — FINER than the playbook name, used ONLY for pattern scoping
# (actor-allowlist clustering / arming / matching), never for playbook routing.
# ---------------------------------------------------------------------------
#
# Identity alerts all fall through to the `generic` playbook, which is correct for
# INVESTIGATION (they share one enrichment path) but far too coarse for LEARNING.
# Measured on real tickets: one admin actor has 5 Conditional-Access FP closures over
# months, but the same actor's CA *exclusion* alert (DEMO-108099) went to L2, and their
# Entra privileged-group add (DEMO-106406) is a different risk class again. All three
# classify as `generic`, so arming the FP pattern on the playbook name would also
# auto-close the two that must NOT be — the exact "not all admin alerts are the same"
# problem. These subtypes give the allowlist a key fine enough to arm safely.
_IDENTITY_SUBTYPE_PATTERNS = [
    # Order matters: exclusion is checked BEFORE the general policy pattern, because
    # "a user/group was excluded from a policy" also contains the word "policy" and is
    # a materially riskier event (it removes someone from an enforcement control).
    (r"conditional\s+access.*(exclud|exempt)|(exclud|exempt).*conditional\s+access",
     "conditional_access_exclusion"),
    (r"conditional\s+access", "conditional_access_policy"),
    # Local Windows group membership change (e.g. "Local Admin Group Changes") — endpoint
    # plane, MDE DeviceEvents (UserAccountAddedToLocalGroup), a different risk class and a
    # different data source from the Entra/cloud grant below. Checked FIRST: "added to
    # local Administrator group" would otherwise also satisfy the broader admin/administrator
    # wording of privileged_group_add. Two principals here too — RECIPIENT (bare AccountName,
    # who the change is ABOUT) vs GRANTOR (InitiatingProcessAccountName, who ran it) — see
    # rule_replay.local_group_row_to_dict.
    (r"local\s+admin(?:istrator)?s?\s+group", "local_admin_group_change"),
    # Privileged role/group membership GRANT — two principals, and the alert names the
    # RECIPIENT not the grantor (see agent_core.oscar.is_privilege_grant_alert).
    (r"add(?:ed)?\s+(?:member\s+)?to\s+[^.]{0,60}?\b(?:privileged|admin|administrator)\b"
     r"|add(?:ed)?\s+member\s+to\s+role|\brole\s+assignment\b|added\s+to\s+microsoft\s+entra",
     "privileged_group_add"),
]
_IDENTITY_SUBTYPE_RE = [(re.compile(p, re.IGNORECASE), t) for p, t in _IDENTITY_SUBTYPE_PATTERNS]


def alert_subtype(alert_name: str, investigation_state: str = "") -> str:
    """Fine-grained pattern key for LEARNING (allowlist scoping), not routing.

    Falls back to `classify()` whenever no finer pattern applies, so for every alert
    class that already worked the subtype IS the playbook name — existing armed
    allowlist entries keep matching unchanged. Only alerts that were being lumped into
    an over-broad bucket gain a narrower key.
    """
    name = (alert_name or "").strip()
    for pat, subtype in _IDENTITY_SUBTYPE_RE:
        if pat.search(name):
            return subtype
    return classify(name, investigation_state)
