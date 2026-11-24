"""Which RAPTOR verdicts page (lib/paging.py does the grouping, brake and lifecycle).

Replayed on 4,467 tickets (3 Oct - 2 Nov 2026): ~11 phone pages a month. Severity is not used:
96% of tickets arrive as Medium, including the ATLAS webshell (DEMO-117541).

  high (phone)  RAPTOR's verdict is URGENT; or it needs L2 and the alert is one of the attack
                types below (or an analyst set the type to "always" in Settings).
  low (push)    the first ticket of an alert type not seen in the previous 30 days, unless
                RAPTOR closed it. Held until 09:00 IST at night. The push links to Settings,
                where an analyst marks the type always or never, once.
  nothing       closed or de-duplicated by RAPTOR, waiting on a user (chase, justification,
                concurrency hold), types set to "never", and the noise below.

MITRE tactics (2026-11-05): names change when a rule is reworded, and every name changes with
the CrowdStrike move (~May 2027). So a ticket that needs L2 and carries a high-risk MITRE
tactic (credential access, exfiltration, command and control, impact) also qualifies, from the
ticket's Tactics line, the EDR alert's category and its technique ids, which both EDRs give.
Until its volume is measured this rule only records "would page" (PAGERDUTY_TACTICS=observe,
the default); PAGERDUTY_TACTICS=live makes it phone.
"""
from __future__ import annotations

import os
import re

PAGE_RX = re.compile(
    r"web ?shell|post-exploitation|suspicious (behavior|commands?).{0,20}web ?server"
    r"|information stealing malware|theft of passwords|remote exfiltration"
    r"|credentials for instance role|used from an external ip|critical guardduty|dns rebinding"
    r"|gatekeeper bypass|ransomware|reverse ?shell|revshell|lsass|mimikatz", re.I)

# Never pages, whatever else matches: intel digests, advisories, tasks and known-noisy repeats
# (the CloudTrail ticket fires daily at 17:06 IST from a scheduled job; drive-by DNS repeats
# on the same few EC2 instances).
NEVER_RX = re.compile(
    r"\[cyble intel\]|threat advisory|^cve-|block ioc|^found \d+ alerts for|stealer_logs"
    r"|changes made to aws cloudtrail logs|drive-by source domain", re.I)

HIGH_TACTICS = {"credentialaccess", "exfiltration", "commandandcontrol", "impact"}

# Technique id -> tactic, for the techniques whose tactic is in HIGH_TACTICS (an EDR alert often
# carries technique ids without tactic names). ATT&CK enterprise, parent ids.
TECHNIQUE_TACTIC = {
    **{t: "credentialaccess" for t in ("T1003", "T1110", "T1555", "T1552", "T1558", "T1539", "T1528",
                                       "T1556", "T1606", "T1649", "T1212", "T1187", "T1557", "T1040")},
    **{t: "exfiltration" for t in ("T1041", "T1048", "T1567", "T1020", "T1030", "T1537", "T1052", "T1011", "T1029")},
    **{t: "commandandcontrol" for t in ("T1071", "T1095", "T1105", "T1572", "T1090", "T1219", "T1102",
                                        "T1568", "T1573", "T1571", "T1132", "T1001", "T1008", "T1104")},
    **{t: "impact" for t in ("T1486", "T1485", "T1490", "T1489", "T1529", "T1561", "T1491", "T1496",
                             "T1531", "T1565", "T1499", "T1498")},
}


def tactics_of(ticket_tactics: str = "", category: str = "", techniques=None) -> list[str]:
    """Canonical tactic names ('credentialaccess', ...) from the ticket's Tactics line, the EDR
    alert's category and its technique ids. Vendor-neutral by construction."""
    out: set[str] = set()
    for part in re.split(r"[,;|/\n]+", f"{ticket_tactics or ''},{category or ''}"):
        k = re.sub(r"[^a-z]", "", part.lower())
        if k:
            out.add(k)
    for t in techniques or []:
        m = re.match(r"(T\d{4})", str(t).strip().upper())
        if m and m.group(1) in TECHNIQUE_TACTIC:
            out.add(TECHNIQUE_TACTIC[m.group(1)])
    return sorted(out)


QUIET_ACTIONS = {"auto_closed", "auto_closed_tp", "auto_duplicate", "close_failed",
                 "user_chase_dispatched", "held"}


def decide(alert_name: str, triage_class: str, action_taken: str, rule: str, new_type: bool,
           tactics=()) -> tuple[str, str]:
    """(urgency, reason): urgency "high", "low" or "" for no page. A reason starting "MITRE"
    is the tactic rule, which maybe_page only records unless PAGERDUTY_TACTICS=live."""
    if triage_class == "URGENT":
        return "high", "RAPTOR verdict URGENT"
    if triage_class != "NEEDS_L2" or action_taken in QUIET_ACTIONS:
        return "", ""
    if rule == "never" or NEVER_RX.search(alert_name or ""):
        return "", ""
    if rule == "always":
        return "high", "alert type set to always page"
    if PAGE_RX.search(alert_name or ""):
        return "high", "attack type on the paging list"
    hit = sorted(set(tactics or ()) & HIGH_TACTICS)
    if hit:
        return "high", f"MITRE tactic: {', '.join(hit)}"
    if new_type:
        return "low", "first alert of this type in 30 days"
    return "", ""


_GATEKEEPER_RX = re.compile(r"gatekeeper bypass", re.I)
_SHELL_RX = re.compile(r"^-?/?(?:bin/)?(?:zsh|bash|sh)$")
_XATTR_RX = re.compile(r"^xattr\s+-[a-z]*[dc][a-z]*\s+(?:com\.apple\.quarantine\s+)?(?P<f>\S+)$")
_CHMOD_RX = re.compile(r"^chmod\s+(?:\+x|u\+x|a\+x|[0-7]{3,4})\s+(?P<f>\S+)$")


def internal_install_quiet(alert_name: str, evidence: dict | None) -> str:
    """Reason not to phone for a Gatekeeper bypass that is only the install step of one of our
    own tools, or "" to page as usual. The ticket still goes to L2; only the phone call is
    skipped, and it is recorded as observed.

    DEMO-121950 (2026-11-12) paged for `xattr -d com.apple.quarantine jit-cli-s3` + `chmod +x`
    on our unsigned JIT CLI. Deterministic, never the model's verdict: the 30-day file-origin
    check must say this device's copy came only from an internal source and no device got the
    hash anywhere else, and EVERY command on the alert must be quarantine removal, chmod or a
    bare shell, aimed at a file this device holds with that hash.
    """
    if not _GATEKEEPER_RX.search(alert_name or ""):
        return ""
    ev = evidence or {}
    fo = ev.get("file_origin") or {}
    if not (fo.get("ok") and fo.get("internal_origin")):
        return ""
    names = {str(p).rstrip("/").rsplit("/", 1)[-1] for p in ((fo.get("alert_device") or {}).get("paths") or [])}
    names.discard("")
    cmds = [str(c).strip() for c in (ev.get("command_lines") or []) if str(c).strip()]
    if not names or not cmds:
        return ""
    touched = 0
    for c in cmds:
        if _SHELL_RX.match(c):
            continue
        m = _XATTR_RX.match(c) or _CHMOD_RX.match(c)
        if not m or m.group("f").rstrip("/").rsplit("/", 1)[-1] not in names:
            return ""
        touched += 1
    if not touched:
        return ""
    return f"internal tool install step ({fo.get('internal_label') or 'internal source'})"


async def maybe_page(triaged, jira_url: str, evidence: dict | None = None) -> dict:
    """Called after a ticket is triaged and saved. Best-effort: callers swallow errors."""
    from lib import paging
    key = paging.type_key(triaged.alert_name)
    rule = paging.type_rule(key)
    quiet = triaged.triage_class != "NEEDS_L2" or triaged.action_taken in QUIET_ACTIONS
    new_type = False if quiet else paging.first_occurrence(key)
    urgency, reason = decide(triaged.alert_name, triaged.triage_class, triaged.action_taken, rule, new_type,
                             getattr(triaged, "mitre_tactics", None) or ())
    if not urgency:
        return {"action": "none"}
    if triaged.triage_class != "URGENT":
        quiet = internal_install_quiet(triaged.alert_name, evidence)
        if quiet:
            paging.observe("raptor", f"raptor:{triaged.jira_key}", f"not paged: {quiet}", triaged.alert_name)
            return {"action": "observed", "quiet": quiet}
    if reason.startswith("MITRE") and os.getenv("PAGERDUTY_TACTICS", "observe").strip().lower() != "live":
        paging.observe("raptor", f"raptor:{triaged.jira_key}", reason, triaged.alert_name)
        return {"action": "observed"}
    who = triaged.device_name or triaged.user_name or ""
    title = f"SecOps-{triaged.jira_key} {triaged.alert_name}" + (f" on {who}" if who else "") + " | Tribe: SecOps"
    details = {"jira": f"{jira_url}/browse/{triaged.jira_key}", "verdict": triaged.triage_class,
               "why_paged": reason, "raptor_reasoning": (triaged.llm_reasoning or "")[:1500]}
    if urgency == "low":
        details["decide_this_type"] = f"{paging.base_url()}/settings?pd_type={key}"
    return await paging.offer("raptor", f"raptor:{triaged.jira_key}",
                              [paging.entity("host", triaged.device_name), paging.entity("acct", triaged.user_name)],
                              urgency, title, details, details["jira"], reason, kind=f"raptor:{key}")
