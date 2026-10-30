"""PowerShell-in-memory: auto-close ONLY an exact repeat of something a human already cleared.

Why this family needs more than the confidence floor. "Powershell script was loaded in
memory" scores 21/21 on FP recommendations, but its human ground truth is almost never
technical — it is a person vouching. DEMO-113945 closed FP because the user replied "yes,
this is run by me"; DEMO-111992 because the DBA team confirmed the script kills long-running
Redash queries. The model's stated reasons for the same verdicts were "destinations are
benign, there is a prior memory, no malicious indicators" — and an attacker's
`Invoke-RestMethod` to a webhook reads exactly the same on those grounds. So the 21/21 is
agreement with justifications the model never saw, not evidence that it separates benign
from malicious. The only close that does not depend on that is: this exact command, on this
exact machine, under this exact account, was already cleared by a human, recently.

So an auto-close is permitted ONLY when every one of these holds:

  1. the alert's command lines were recorded, and not truncated;
  2. none carries a known-malicious PowerShell tradecraft marker (RED_FLAGS);
  3. the device is known;
  4. every command line is an exact (whitespace/case-normalised) repeat of one that a
     HUMAN closed as False Positive on the SAME device under the SAME account within the
     last PRECEDENT_DAYS. RAPTOR's own closes never count as clearance — that would let
     every close manufacture the precedent for the next one.

Anything else goes to a human, exactly as before this family was autonomous. It is
enforced at the pipeline's single close gate, so it also constrains an actor-allowlist
match — whose command pinning for this family reduces to a first token such as
`powershell.exe`, i.e. "any PowerShell by this account on this host". It FAILS CLOSED: a
Jira error, an unparseable history or anything unexpected means "not safe to close".

Precedent history comes from Jira, from the comment RAPTOR's endpoint_process playbook
posts on every ticket of this family ("*Device:* … *User:* … *Command line(s) (N):* `…`").
The live side uses the same NormalizedAlert fields that comment is rendered from, so a
repeat compares like with like.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

FAMILY = "powershell script was loaded in memory"
BLOCK_LABELS = ("needs-l2-review", "powershell-guard")
MAX_CMDS = 10   # the playbook comment renders at most 10; more means we cannot compare all


def precedent_days() -> int:
    """How recent a human clearance must be. 30, not 90: DEMO-113706 repeated a command
    cleared ~60 days earlier and the analysts chose to ask for a fresh justification
    rather than close it — a stale clearance is not one they would lean on either."""
    import os
    try:
        return max(1, int(os.getenv("POWERSHELL_PRECEDENT_DAYS", "30")))
    except ValueError:
        return 30


def applies(alert_name: str) -> bool:
    return (alert_name or "").strip().casefold() == FAMILY


# Known-malicious PowerShell tradecraft. Deliberately broad: a hit only means "a human
# looks", never "malicious", so a false match costs an L2 read and a miss costs a close.
# `-ExecutionPolicy Bypass` is NOT here on purpose — the benign Redash cleanup script runs
# with it, and on its own it says nothing.
RED_FLAGS: tuple[tuple[str, re.Pattern], ...] = tuple(
    (label, re.compile(rx, re.IGNORECASE)) for label, rx in (
        ("encoded command", r"(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s"),
        ("base64 decode", r"frombase64string"),
        ("Invoke-Expression", r"\biex\b|invoke-expression"),
        ("download cradle", r"downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer"),
        ("AMSI bypass", r"amsiutils|amsiinitfailed|amsiscanbuffer"),
        ("Defender tampering", r"add-mppreference|set-mppreference|disablerealtimemonitoring"),
        ("credential theft tooling", r"mimikatz|sekurlsa|lsass|procdump|out-minidump"),
        ("reflective loading", r"reflection\.assembly|\[system\.reflection|::load\("),
        ("hidden window", r"-w(?:indowstyle)?\s+h(?:idden)?\b"),
        ("persistence", r"new-service|sc(?:\.exe)?\s+create|schtasks|register-scheduledtask|"
                        r"currentversion\\run|new-itemproperty.*\\run\b|__eventfilter|"
                        r"commandlineeventconsumer"),
        ("remote execution", r"invoke-command\s+.*-computername|enter-pssession|new-pssession|"
                             r"invoke-wmimethod|win32_process.*create"),
        ("credential handling", r"get-credential|convertto-securestring\s.*-asplaintext|"
                                r"get-storedcredential"),
        ("archive staging", r"compress-archive"),
        ("raw-IP destination", r"https?://\d{1,3}(?:\.\d{1,3}){3}"),
        ("living-off-the-land binary", r"\b(?:certutil|bitsadmin|rundll32|regsvr32|mshta|"
                                       r"wmic|cscript|wscript)(?:\.exe)?\b"),
        ("security log clearing", r"clear-eventlog|wevtutil\s+cl|remove-eventlog"),
    )
)


def fingerprint(cmd: str) -> str:
    """Case- and whitespace-normalised command text. Nothing else is abstracted away:
    a changed URL, path, parameter or variable makes it a different command."""
    return " ".join((cmd or "").strip().lower().split())


def red_flags(cmds: list[str]) -> list[str]:
    return sorted({label for c in cmds for label, rx in RED_FLAGS if rx.search(c or "")})


def _norm_actor(u: str) -> str:
    u = (u or "").strip().lower()
    if "\\" in u:
        u = u.rsplit("\\", 1)[-1]
    return u or "unknown"


def _norm_device(d: str) -> str:
    return (d or "").strip().lower()


_DEV_RE = re.compile(r"\*?Device:\*?[ \t]*([^\s*]\S*)")
_USR_RE = re.compile(r"\*?User:\*?[ \t]*([^\s*]\S*)")  # same line only: an empty User must not swallow the next line
_CMDS_RE = re.compile(r"Command lines? \((\d+)\):\*?\s*\n((?:[ \t]+`.*`[ \t]*\n?)+)")


def parse_playbook_comment(text: str) -> dict | None:
    """Device, account and command lines from RAPTOR's endpoint_process comment.

    Returns None unless the comment is complete enough to compare against: a device, and
    exactly as many backtick-quoted command lines as its "(N)" header announces. A partial
    parse must never become a smaller set that makes a live alert look like a repeat.
    """
    dev, usr, m = _DEV_RE.search(text or ""), _USR_RE.search(text or ""), _CMDS_RE.search(text or "")
    if not (dev and m) or "more suppressed" in (text or ""):
        return None
    cmds = []
    for ln in m.group(2).splitlines():
        ln = ln.strip()
        if len(ln) >= 2 and ln.startswith("`") and ln.endswith("`"):
            cmds.append(ln[1:-1])
    if len(cmds) != int(m.group(1)) or not cmds:
        return None
    return {"device": _norm_device(dev.group(1)),
            "actor": _norm_actor(usr.group(1) if usr else ""), "cmds": cmds}


def evidence_record(device: str, actor: str, cmds: list[str]) -> str:
    """The Device / User / Command-lines block, in exactly the format parse_playbook_comment
    reads — so every ticket of this family carries its own history record.

    Needed because in AUTONOMOUS phase the agent's result replaces the playbook entirely,
    so endpoint_process never posts the comment this guard learns from. Without this the
    guard starves: new tickets leave no precedent, the copilot-era ones age past the
    window, and within a month it could never permit a close again.
    """
    cmds = [c for c in (cmds or []) if (c or "").strip()]
    lines = ["*RAPTOR evidence record (PowerShell guard):*",
             f"*Device:* {device or 'Unknown Device'}",
             f"*User:* {actor or 'Unknown'}"]
    if cmds:
        lines.append(f"*Command line{'s' if len(cmds) > 1 else ''} ({len(cmds)}):*")
        lines += [f"  `{c}`" for c in cmds[:MAX_CMDS]]
        if len(cmds) > MAX_CMDS:
            lines.append(f"  _… {len(cmds) - MAX_CMDS} more suppressed_")
    return "\n".join(lines)


MAX_CANDIDATES = 50   # bounds the changelog reads per alert; a burst host can have 60+


async def cleared_precedents(device: str, actor: str, exclude_key: str, cfg,
                             days: int | None = None, needed: set | None = None,
                             summary: str = "Powershell script was loaded in memory",
                             parser=None) -> list[dict]:
    """Tickets of this family that a HUMAN closed False Positive on this device, under this
    account, within `days`. Raises on any Jira failure — the caller fails closed.

    `needed` (fingerprints of the live commands) lets the scan stop as soon as every one
    is covered by a human clearance: candidates arrive newest-first, and a burst host can
    carry dozens of identical precedents that would each cost a changelog read."""
    from edr_triage.jira_handler import _build_client
    from edr_triage.jira_poller import _adf_to_text, adf_to_marked_text

    days = days or precedent_days()
    want_dev, want_actor = _norm_device(device), _norm_actor(actor)
    bot = (cfg.jira_email or "").lower()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    parser = parser or parse_playbook_comment
    from edr_triage.config import NOT_BULK_CLOSED_JQL
    # A bulk close by Claude is not a human clearance (see BULK_CLOSE_LABEL).
    jql = (f'project = {cfg.jira_project_key} AND summary ~ "\\"{summary}\\"" '
           f'AND status = "False Positive" AND updated >= -{days + 1}d '
           f'AND {NOT_BULK_CLOSED_JQL} ORDER BY created DESC')
    out: list[dict] = []
    tok = None
    async with _build_client(cfg) as client:
        for _page in range(10):                     # ≤1000 tickets; far above real volume
            body = {"jql": jql, "maxResults": 100, "fields": ["comment"]}
            if tok:
                body["nextPageToken"] = tok
            r = await client.post("/rest/api/3/search/jql", json=body)
            r.raise_for_status()
            d = r.json()
            for iss in d.get("issues", []):
                if iss.get("key") == exclude_key:
                    continue
                for c in ((iss.get("fields") or {}).get("comment") or {}).get("comments") or []:
                    if ((c.get("author") or {}).get("emailAddress") or "").lower() != bot:
                        continue
                    body_ = c.get("body")
                    # Read with the formatting restored first: since mid-October records
                    # arrive as real code/bold marks, which the plain reading drops.
                    p = ((parser(adf_to_marked_text(body_)) or parser(_adf_to_text(body_)))
                         if isinstance(body_, dict) else None)
                    if p and p["device"] == want_dev and p["actor"] == want_actor:
                        p["key"] = iss["key"]
                        out.append(p)
                        break
            tok = d.get("nextPageToken")
            if not tok or d.get("isLast"):
                break
    # Who made the close, and when. Only a human's close is a clearance.
    cleared, covered = [], set()
    for p in out[:MAX_CANDIDATES]:
        if needed is not None and not ({fingerprint(c) for c in p["cmds"]} & (needed - covered)):
            continue            # adds nothing we still need; skip the changelog read
        closer, at = await _last_fp_close(p["key"], cfg)
        if closer and closer != bot and at and at >= since:
            p["cleared_by"], p["cleared_at"] = closer, at.isoformat()
            cleared.append(p)
            covered |= {fingerprint(c) for c in p["cmds"]}
            if needed is not None and needed <= covered:
                break
    return cleared


async def _last_fp_close(key: str, cfg) -> tuple[str | None, datetime | None]:
    from edr_triage.jira_handler import _build_client
    async with _build_client(cfg) as client:
        r = await client.get(f"/rest/api/3/issue/{key}",
                             params={"fields": "status", "expand": "changelog"})
        r.raise_for_status()
        hist = (r.json().get("changelog") or {}).get("histories") or []
    last = None
    for h in hist:
        for it in h.get("items", []):
            if it.get("field") == "status" and (it.get("toString") or "") == "False Positive":
                if last is None or h.get("created", "") > last[0]:
                    last = (h.get("created", ""),
                            ((h.get("author") or {}).get("emailAddress") or "").lower())
    if not last:
        return None, None
    try:
        at = datetime.fromisoformat(last[0].replace("Z", "+00:00"))
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
    except ValueError:
        at = None
    return last[1], at


async def check(jira_key: str, device: str, actor: str, cmds: list[str], cfg) -> dict:
    """Decide whether this alert may auto-close. Never raises.

    Returns {"allow": bool, "reason": str, "precedents": [...]}.
    """
    cmds = [c for c in (cmds or []) if (c or "").strip()]
    if not cmds:
        return {"allow": False, "reason": "no command line was recorded for this alert"}
    if len(cmds) > MAX_CMDS:
        return {"allow": False, "reason": f"{len(cmds)} command lines — too many to verify"}
    flags = red_flags(cmds)
    if flags:
        return {"allow": False, "reason": "PowerShell tradecraft marker(s): " + ", ".join(flags)}
    dev = _norm_device(device)
    if not dev or dev in ("unknown", "unknown device"):
        return {"allow": False, "reason": "device unknown"}
    try:
        prec = await cleared_precedents(dev, actor, jira_key, cfg,
                                        needed={fingerprint(c) for c in cmds})
    except Exception as exc:
        logger.warning("powershell_guard: precedent lookup failed for %s: %s", jira_key, exc)
        return {"allow": False, "reason": f"precedent lookup failed ({str(exc)[:120]})"}
    if not prec:
        return {"allow": False, "reason": (
            f"no human-cleared precedent for {_norm_actor(actor)} on {dev} in the last "
            f"{precedent_days()} days")}
    cleared = {fingerprint(c) for p in prec for c in p["cmds"]}
    new = [c for c in cmds if fingerprint(c) not in cleared]
    if new:
        return {"allow": False, "reason": (
            f"{len(new)} command line(s) not previously cleared on this device — e.g. "
            f"`{new[0][:160]}`"), "precedents": [p["key"] for p in prec]}
    used = [p for p in prec if {fingerprint(c) for c in p["cmds"]} & {fingerprint(c) for c in cmds}]
    return {"allow": True, "reason": "exact repeat of a human-cleared run",
            "precedents": [{"key": p["key"], "cleared_by": p["cleared_by"],
                            "cleared_at": p["cleared_at"]} for p in used]}


async def enforce_at_close(alert_name: str, labels: list, jira_key: str, device: str,
                           actor: str, cmds: list[str], cfg,
                           dry_run: bool = False) -> tuple[bool, str]:
    """The close-gate step. Returns (block, reason). Called only after may_autoclose() agreed.

    On a block: adds BLOCK_LABELS and a comment saying why. On an allow: a comment naming
    the precedent the close rests on, so the L2 reading the autoclose report can see what
    clearance it inherited instead of taking the close on trust.
    """
    if not applies(alert_name):
        return False, ""
    res = await check(jira_key, device, actor, cmds, cfg)
    from edr_triage.jira_handler import add_comment
    if res["allow"]:
        p = res["precedents"][0]
        # Worded as a permission, not a result: this is posted before the close walk,
        # and a walk can still fail (it is then logged as close_failed).
        text = ("*Auto-close permitted: exact repeat of a human-cleared run.*\n\n"
                f"Same command line(s), same device and account as {p['key']}, which "
                f"{p['cleared_by']} closed as False Positive on {p['cleared_at'][:10]}."
                + (f" Also matches {', '.join(x['key'] for x in res['precedents'][1:4])}."
                   if len(res["precedents"]) > 1 else "")
                + "\n\nReopen this ticket if that clearance should not carry over.\n\n"
                "[Auto-triaged by RAPTOR]")
        blocked = False
    else:
        for lab in BLOCK_LABELS:
            if lab not in labels:
                labels.append(lab)
        text = ("*RAPTOR did not auto-close this ticket.*\n\n"
                f"Reason: {res['reason']}.\n\n"
                "For PowerShell loaded in memory, RAPTOR only closes an exact repeat of a "
                "command a human already cleared on this same device and account in the last "
                f"{precedent_days()} days. Anything new needs a person to confirm it is "
                "expected.\n\n[Auto-triaged by RAPTOR]")
        blocked = True
    try:
        await add_comment(jira_key, text, cfg, dry_run=dry_run)
    except Exception as exc:
        logger.error("powershell_guard: comment on %s failed: %s", jira_key, exc)
    return blocked, ("" if not blocked else res["reason"])


# ── ASK (2026-10-07) ─────────────────────────────────────────────────────────────────────
# When this guard refuses a close (not an exact repeat), what humans do is ask the person:
# on a workstation with a named user, analysts asked on 39 of 42 PowerShell tickets in the
# 90 days to 2026-10-07 and closed on the answer ("as confirmed by the user, he is using
# Claude Code to …"). So RAPTOR asks the logged-on user through the Security Bot, under the
# same rules as Root Privesc (privesc_guard.may_ask): only when the agent leaned benign or
# wanted a justification, exactly one reachable named person, never a test device or
# CRITICAL. Their answer goes to L2; an L2 FP close on it is the precedent the next exact
# repeat closes on. Shared admin accounts on servers fail eligibility and stay with L2.
ASK_LABEL = "powershell-ask"


def ask_comment(who: str, reason: str) -> str:
    return ("*RAPTOR is asking the user instead of auto-closing.*\n\n"
            f"Why not closed: {reason}.\n\n"
            "For PowerShell-in-memory RAPTOR closes only an exact repeat of a command a person "
            "already cleared for this user on this device. Anything new goes to the user — "
            f"{who} — via the Acme Security Bot; their answer comes back to L2, who decides."
            "\n\n[Auto-triaged by RAPTOR]")
