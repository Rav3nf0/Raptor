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
        r"log\s+ingestion\s+stopped",
        r"log\s+injestion\s+stopped",     # common MDE typo
        r"data\s+loss\s+prevention",
        r"shadow\s+it",
        # AWS GuardDuty EC2-DNS findings (phishing-domain / drive-by-source-domain)
        # have their own dedicated playbook — routed via _GUARDDUTY_PATTERNS below,
        # checked before this list even runs. "Monitor AWS Credential abuse" and
        # "AssumedRole ... anomalously invoking APIs" (also GuardDuty-sourced, the
        # AWS-API-call finding shape) fall through to "generic" instead of a skip
        # pattern now: extract_cloudtrail_details_async already auto-detects a
        # GuardDuty FindingLink and calls query_guardduty_details, and generic.py
        # already renders IAM Role, Access Key ID, IP Geolocation and MFA Status —
        # this enrichment was already built and working, the alert names were just
        # never allowed to reach it.
    ]
]

# AWS GuardDuty EC2-DNS findings — "The EC2 instance i-... queried a phishing/
# drive-by domain name." Previously in _SKIP_PATTERNS (never triaged at all);
# evidence lives in the AWSGuardDuty Sentinel table (see
# sentinel_client.query_guardduty_dns_finding), the Jira description carries
# nothing. Checked ahead of the generic _SKIP_PATTERNS list.
_GUARDDUTY_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ec2\s+instance.*queried\s+a\s+phishing\s+domain",
        r"ec2\s+instance.*queried\s+a\s+drive-by\s+source\s+domain",
        # Same DNS-lookup shape, different meaning (playbooks/guardduty.py words each
        # one). DEMO-118243 "may be the target of a DNS rebinding attack" fell to
        # generic, so the agent never saw the instance, IP or domain.
        r"ec2\s+instance.*target\s+of\s+a\s+dns\s+rebinding\s+attack",
        r"ec2\s+instance.*queried\s+a\s+known\s+command\s*(?:&|and)\s*control\s+server\s+domain",
        r"ec2\s+instance.*queried\s+a\s+low\s+reputation\s+domain",
        r"ec2\s+instance.*querying\s+algorithmically\s+generated\s+domains",
    ]
]

# Upwind CNAPP detections — raised by Upwind's own Jira integration and named
# "Upwind Detection | <title>" by jira_poller.build_upwind_ticket (the raw summary carries
# a "<Severity> Severity " prefix, accepted too). Checked before every content pattern:
# a title like "An AWS host contains a suspicious/malicious file" must not be claimed
# by the MDE-shaped malware playbook, whose evidence (timeline, hashes) Upwind doesn't carry.
_UPWIND_PATTERNS = [
    re.compile(r"^\s*(?:\w+\s+severity\s+)?upwind\s+detection\s*\|", re.IGNORECASE),
]

# Entra ID PIM — "Privileged Role Assigned Outside PIM". Previously in
# _SKIP_PATTERNS (never triaged at all); the grantor is resolved via
# lib.kql_templates.sentinel_identity_grant, the same query already proven live
# on DEMO-106406 through the agent loop's hunt_identity_grant tool.
_PIM_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
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

# The UBA-anomaly (Bulk Upload/Download) test, in ONE place so the classifier and the
# pipeline's evidence-binding gate cannot drift apart. They had drifted: both spelled it
# `download`, but the live alert is named "Netskope - Bulk Downnload detection" — a typo
# in the vendor rule name. So that family matched NEITHER, fell through to `generic`
# (the AWS/CloudTrail-shaped playbook) AND never got its Netskope_Alerts_CL binding.
# It sits at 10 resolved / 1 correct = 0.100 accuracy.
#
# `down+load` puts the `+` on the `n`, so "download", "downnload" and "downnnload" all
# match — which is what a hand-typed vendor rule name needs. Do not tighten this back to
# `download` without checking the live alert names first.
NETSKOPE_UBA_RE = re.compile(r"bulk\s+(?:upload|down+load)", re.IGNORECASE)

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
        # toby.vohra, who is the one L1 actually investigated).
        r"netskope.*bulk\s+(?:upload|down+load)",
        r"bulk\s+(?:upload|down+load)\s+detection",
        # Netskope DLP alerts — previously in _SKIP_PATTERNS (never triaged at all).
        # Evidence lives in Netskope_Alerts_CL under alert_type_s == "DLP"; the Jira
        # description only ever carries the profile name, never the rest, so L1 has
        # been retyping user/access-method/rule/severity/file-size by hand every time.
        r"netskope.*dlp",
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


# Cyble digests ("Found 216 alerts for stealer_logs across 2 entities") are intel, read by
# their own threat-intel guards, not by an endpoint playbook. "stealer"
# sent them to the MDE malware playbook, which wrote "Unknown Device ... notifying affected
# user via Slack" on every stealer_logs digest (DEMO-122951).
_CYBLE_DIGEST = re.compile(r"^\s*found\s+\d+\s+alerts?\s+for\s+\S+.*\sacross\s+\d+\s+entit", re.I)


def classify(alert_name: str, investigation_state: str = "") -> str:
    """Return a playbook name for the given alert.

    Playbook names: block_tool | malware | reverse_shell | lateral_move | netskope | credential_access | guardduty | pim | upwind | privesc | endpoint_process | port_sweep | generic | skip
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

    if _CYBLE_DIGEST.match(name):
        return "generic"

    for pat in _UPWIND_PATTERNS:
        if pat.search(name):
            return "upwind"

    for pat in _GUARDDUTY_PATTERNS:
        if pat.search(name):
            return "guardduty"

    for pat in _PIM_PATTERNS:
        if pat.search(name):
            return "pim"

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
# Measured on real tickets: `tatum.shah` has 5 Conditional-Access FP closures
# (Apr–Aug), but the same actor's CA *exclusion* alert (DEMO-108099) went to L2, and his
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


# Alert families whose MEMORY bucket must be narrower than their playbook name.
# `classify()` sends every Netskope variant to one "netskope" playbook, which is right
# for INVESTIGATION (one enrichment path) but wrong for MEMORY: a DLP false-positive
# precedent ("finance team keeps vendor PAN details for GST work") must never surface as
# context on a Netskope MALWARE alert, and "how is DLP doing" is unanswerable while both
# share a bucket. DLP also runs at far higher volume than its siblings, so a shared
# bucket means DLP crowds them out of the L2 review queue.
#
# Deliberately DLP-only for now. Widening this to every alert family (e.g. routing all
# memory writes through `alert_subtype`) would re-key existing conditional-access /
# local-group memories from "generic" to their subtype and orphan them from the
# `get_playbook_memories(alert_type)` lookups that currently find them — a live
# regression. DLP was skipped entirely until 2026-08-27, so it has NO stored memories
# to orphan: this refinement is free of that risk by construction.
_MEMORY_TYPE_PATTERNS = [
    (re.compile(r"netskope.*dlp|dlp.*netskope", re.IGNORECASE), "netskope_dlp"),
    # Netskope UBA anomalies (Bulk Upload / Bulk Download) get their own bucket for the
    # same reason DLP did: the shared "netskope" bucket mixes them with Failed Login and
    # cloud-Malware, three families with nothing in common, so type-wide precedent for one
    # is noise for the others. Measured 2026-09-01: Bulk Upload 1/15 correct, Suspicious
    # Bulk Download 1/3, Failed Login 2/10 — while DLP, which was split out on 2026-08-27
    # and has since accumulated 109 golden memories against netskope's 6, sits at 0.794.
    #
    # This is an ENABLER, not a fix. It lets UBA precedent accumulate separately; it does
    # not by itself change a verdict.
    #
    # Verified before making the change (the DLP split was safe only because DLP had no
    # stored memories to orphan, which is NOT true here):
    #   * get_playbook_memories filters scope=="playbook"; the "netskope" bucket has SIX
    #     memories and all six are scope=="entity", so nothing is orphaned. The only
    #     playbook-scope memory in the whole store is netskope_dlp.
    #   * _justification_applies requires a non-empty device, and every Netskope UBA/DLP
    #     alert is device-less, so it can never fire for this family either way.
    #   * entity recall (recall_memories) keys on entity ids, not alert_type, so
    #     per-user precedent keeps surfacing exactly as it does today — which is how
    #     DEMO-110811 already saw "a prior alert for casey.brooks involving Slack".
    (NETSKOPE_UBA_RE, "netskope_uba"),
    # Failed Login, split for the same reason plus a practical one: the quarantine
    # review queue filters BY BUCKET, so its 5 memories were unfindable among the 32 in
    # the shared "netskope" bucket (11 Malware + 10 Suspicious Bulk Download + 6 Bulk
    # Upload + these 5). "I don't see any failed logins in the quarantine memory" was
    # exactly right — they were there, just not filterable.
    #
    # Same orphaning check as netskope_uba: all 32 netskope-bucket memories are
    # scope=="entity", so no playbook-scope precedent is stranded, and Failed Login
    # alerts are device-less so _justification_applies could never fire for them anyway.
    (re.compile(r"netskope.*(?:failed\s+login|sign.?in\s+fail)", re.IGNORECASE),
     "netskope_failed_login"),
    # Log-ingestion health alerts. These still classify() as "skip" — that is their
    # PLAYBOOK routing and it is deliberately unchanged (FallbackPlaybook, which is what
    # they get today). This entry only changes their MEMORY bucket, which is the entire
    # reason memory_alert_type exists as a separate function.
    #
    # The bug it fixes: all three memory-write paths in jira_closure_poller bail on
    # `memory_alert_type(...) == "skip"`, so these alerts were triaged, given a shadow
    # row, and SCORED into the accuracy metric — 7 rows, 4 of them misses — while never
    # writing a memory, so they could not appear in the quarantine review queue at all.
    # Counted against the metric and impossible to review. That combination made sense
    # when "skip" meant the pipeline early-returned and no shadow row existed either;
    # those early returns were removed when the never-skip work landed, and this guard
    # was not revisited.
    #
    # Its own bucket rather than "generic": an ingestion-pipeline health alert has
    # nothing in common with the 133 rows already in generic, and burying it there is the
    # same dilution that made the Netskope Failed Login memories unfindable. No orphaning
    # risk by construction — no memory has ever been written under "skip", so there is
    # nothing stored to strand.
    (re.compile(r"log\s+in(?:je|ge)stion\s+stopped", re.IGNORECASE), "log_ingestion"),
]


def memory_alert_type(alert_name: str, investigation_state: str = "") -> str:
    """The alert_type key a MEMORY about this alert should be filed under.

    Same contract as `alert_subtype`: falls back to `classify()` so every alert family
    that already worked keeps the exact key it has today. Only the families listed in
    `_MEMORY_TYPE_PATTERNS` get a narrower one.
    """
    name = (alert_name or "").strip()
    for pat, mem_type in _MEMORY_TYPE_PATTERNS:
        if pat.search(name):
            return mem_type
    return classify(name, investigation_state)


# Families that must be triaged by the DETERMINISTIC PLAYBOOK ONLY — the agent loop
# is not run for them, so they cost nothing in Bedrock spend and produce no AI
# verdict to score.
#
# This is not "skip": these alerts are still triaged and still get a full L2-facing
# comment. The difference is that the comment comes from the playbook rather than the
# model. That is the right trade while a family's playbook is still being shaped —
# paying for model reasoning on an alert family whose ground truth we have not yet
# characterised buys inconsistent verdicts and burns credits that the families under
# active work (DLP) need.
#
# Cyble threat-intel digests are the current occupant. They arrive in one distinctive
# shape — "Found <n> alerts for <topic> across <m> entities" — across every topic
# (Social Media Monitoring, Suspicious Domains, mobile_apps, darkweb_marketplaces,
# postman), so the structural pattern covers topics we have not seen yet without
# needing a keyword per topic. They classify as `generic`, so gating on alert NAME
# rather than on the classified type is required: `generic` also catches genuine
# endpoint alerts that must keep their agent triage.
_DETERMINISTIC_ONLY_PATTERNS = [
    # Cyble digest shape. Anchored at the start and requiring both the "for <topic>"
    # and "across <n> entit" halves so it cannot match a free-text alert name that
    # merely happens to contain the word "found".
    re.compile(r"^\s*found\s+\d+\s+alerts?\s+for\s+.+\s+across\s+\d+\s+entit",
               re.IGNORECASE),
]


# Families the /edr-triage console hides when its observe-only toggle is ON.
#
# The toggle used to work by excluding `triage_class in ("OBSERVED", "SKIPPED")`, which was
# right while these families were skipped outright. Since DLP was un-skipped (2026-08-27)
# it gets a REAL verdict — NEEDS_L2 / AUTO_CLOSED_FP / REQUEST_JUSTIFICATION — so it stopped
# matching that filter and became permanently visible; the same happened to the Cyble
# digests. Measured 2026-09-02 with the toggle ON: of a 300-row sample, 183 were Netskope
# DLP and 66 were Cyble digests — 82% observe-only, leaving ~51 actual threat alerts.
#
# So the console has to filter on the FAMILY, not on the verdict. This is a VIEW filter
# only: these rows are still triaged, still stored and still scored in the accuracy metric.
# Hiding them from the queue changes nothing about the headline number.
# NOT a blanket `netskope` match. `Netskope -Malware alert` is a real malware detection —
# threat triage, not a business-justification workflow — and it stays visible by request.
# It is also the healthiest family in the store (25 scored rows, 1.000 accuracy), so there
# was never a noise argument for hiding it.
#
# Listing the families explicitly also fails in the safer direction: a NEW Netskope family
# nobody has classified yet stays VISIBLE rather than being silently swallowed. An unknown
# alert should be seen.
OBSERVE_ONLY_FAMILY_RE = re.compile(
    "|".join([
        r"netskope.*dlp|dlp.*netskope",                          # DLP
        NETSKOPE_UBA_RE.pattern,                                 # Bulk Upload / Download
        r"netskope.*(?:failed\s+login|sign.?in\s+fail)",         # Failed Login
        r"^\s*found\s+\d+\s+alerts?\s+for\s+.+\s+across\s+\d+\s+entit",   # Cyble digests
        r"cyble",
    ]),
    re.IGNORECASE,
)


# Entra sign-in failure families that the success-after-failures guard protects
# (edr_triage/signin_guard.py). Netskope "Failed Login" is a web-proxy block, not an Entra
# sign-in, so it is excluded explicitly.
SIGNIN_FAILURE_FAMILY_RE = re.compile(r"sign.?in\s+failure", re.IGNORECASE)


def signin_spray_guard_applies(alert_name: str) -> bool:
    n = alert_name or ""
    return bool(SIGNIN_FAILURE_FAMILY_RE.search(n)) and "netskope" not in n.lower()


# Identifiers embedded in an alert NAME that fragment one detection into many
# "families". Used ONLY for grouping the accuracy-by-type table — never for
# classification, routing or memory buckets, which key on the real name.
#
# Measured 2026-09-06 across 1,435 rows: 78 distinct alert_name values, of which 22 are
# really two detections. `The EC2 instance i-<id> queried a drive-by source domain name`
# appears as 11 separate families totalling 18 rows — mostly rows of ONE — so the family's
# real accuracy is unreadable, and a family with 1 scored row tells you nothing. Cyble
# digests fragment the same way on their two counts: 11 families, 32 rows.
#
# All "The EC2 instance i-<id> ..." names collapse to a SINGLE family, finding type
# included — see the second normaliser for why and for what that costs.
#
# Deliberately NOT collapsed: the port in "Network Port Sweep detected on 9182" and the
# addresses in "Potential beaconing from A to B". Those have 21 and 19 rows on their own —
# viable samples — and a port arguably IS part of what was detected, so merging them could
# hide one port degrading. Only identifiers that name an ENTITY rather than a behaviour
# are collapsed here.
_DISPLAY_NORMALISERS = [
    # AWS instance ids: i-0e70479780d1af6ff -> i-<instance>
    (re.compile(r"\bi-[0-9a-f]{8,}\b", re.IGNORECASE), "i-<instance>"),
    # Every GuardDuty EC2 finding is ONE reporting family. Collapsing only the instance id
    # still left three rows ("queried a drive-by source domain name", "queried a phishing
    # domain name", "is communicating with an unusual DNS resolver <ip>") at 33, 2 and 1
    # rows — and the last two are unreadable on their own. Requested 2026-09-08; it
    # reverses the earlier call to keep finding types apart, which was made when the
    # fragmentation looked like it was only the instance id.
    #
    # The trade-off, stated: the finding TYPE no longer has its own row, so one type
    # degrading while the others hold would not be visible here. Acceptable today because
    # all three sit at 0% and are closed by L2; the raw alert_name is still on every row
    # and `merged_from` prints how many names were folded in. Runs AFTER the rule above,
    # so it matches the already-normalised i-<instance>.
    (re.compile(r"^\s*the\s+ec2\s+instance\s+i-\S+\s+.+$", re.IGNORECASE),
     "The EC2 instance i-<instance> (all GuardDuty findings)"),
    # Cyble digest counts: "Found 22 alerts for X across 2 entities" -> N / N
    (re.compile(r"^(\s*found\s+)\d+(\s+alerts?\s+for\s+)", re.IGNORECASE), r"\1N\2"),
    (re.compile(r"(\s+across\s+)\d+(\s+entit)", re.IGNORECASE), r"\1N\2"),
]


def display_alert_family(alert_name: str) -> str:
    """The alert name with entity identifiers collapsed, for per-family REPORTING.

    Never use this for routing or memory bucketing — those must see the real name.
    """
    name = (alert_name or "").strip()
    if not name:
        return "(unknown)"
    for pat, repl in _DISPLAY_NORMALISERS:
        name = pat.sub(repl, name)
    return name


def is_observe_only_family(alert_name: str) -> bool:
    """True when this alert belongs to a family the console hides by default."""
    return bool(OBSERVE_ONLY_FAMILY_RE.search((alert_name or "").strip()))


def is_deterministic_only(alert_name: str) -> bool:
    """True when this alert family should bypass the agent loop entirely.

    Env escape hatches, so this can be changed without a deploy:
      DETERMINISTIC_ONLY_DISABLED=true   ignore the list (agent runs on everything)
      DETERMINISTIC_ONLY_EXTRA=a,b       extra case-insensitive substrings to match
    """
    import os

    name = (alert_name or "").strip()
    if not name:
        return False
    if os.getenv("DETERMINISTIC_ONLY_DISABLED", "").lower() == "true":
        return False
    for extra in (os.getenv("DETERMINISTIC_ONLY_EXTRA", "") or "").split(","):
        extra = extra.strip()
        if extra and extra.lower() in name.lower():
            return True
    return any(pat.search(name) for pat in _DETERMINISTIC_ONLY_PATTERNS)
