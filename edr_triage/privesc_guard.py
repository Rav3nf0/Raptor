"""Root Privilege Escalation: close an exact repeat of what a human cleared; ASK about the rest.

Why. Root Privesc was enrolled in autonomy on 113/113 FP recommendations confirmed — but
that counted terminal outcomes only. 23 more FP calls in the same window were PARKED by
humans in `Awaiting more inputs` to ask the user (`sudo su`, `sudo -l`, editing a service
file, `crontab -l`). Counting those, RAPTOR's closes matched what humans did ~83% of the
time, and the first autonomous overturn (DEMO-115542: a NEW systemd service + timer, closed
on "similar alerts were justified before") was exactly that shape. For this family the
human answer is often not "close" but "ask the person". So:

  * REPEAT — an auto-close is permitted only when every command on the ticket is an exact
    (case/whitespace-normalised) repeat of commands a HUMAN closed as False Positive on the
    same host under the same session principal within PRECEDENT_DAYS, and none carries a
    RED_FLAG. RAPTOR's own closes never count, so a close cannot manufacture the precedent
    for the next one.
  * ASK — anything else the agent would have closed (or wanted justified) goes to the
    session principal through the user chase, when exactly one verified, reachable person
    is involved. Their answer routes to L2 (chase_reply_poller), and an L2 FP close on it is
    precisely the precedent the next exact repeat closes on.

Red flags are never closed on precedent: persistence, download-and-execute, reverse
shells, setuid, credential stores, history clearing and kernel modules always need a
person, however often they have been seen — repeating a backdoor does not make it benign.

Precedent history is read from Jira, from RAPTOR's own Root Privesc comment (generic.py's
CloudTrail block: *Device Name:* / *Session Principal:* / *Initiating Commands (N):*). In
autonomous phase that comment is not posted, so the pipeline appends evidence_record() in
the same format — otherwise the guard would starve, as powershell_guard once nearly did.
Fails closed throughout.
"""
from __future__ import annotations

import logging
import re

from edr_triage.powershell_guard import _last_fp_close, cleared_precedents, fingerprint  # noqa: F401

logger = logging.getLogger(__name__)

FAMILY = "root privilege escalation"
SUMMARY = "Root Privilege Escalation"
BLOCK_LABELS = ("needs-l2-review", "privesc-guard")
ASK_LABEL = "privesc-ask"
MAX_CMDS = 12          # generic.py's _MAX_CMDS: the comment lists at most this many
PRECEDENT_DAYS = 30

RED_FLAGS: tuple[tuple[str, re.Pattern], ...] = tuple(
    (label, re.compile(rx, re.IGNORECASE)) for label, rx in (
        ("persistence", r"systemctl\s+(?:enable|link|edit)\b|enable\s+--now|/etc/systemd/|"
                        r"\.timer\b|crontab\s+(?!-l\b)|/etc/cron|/var/spool/cron|"
                        r"/etc/rc\.local|/etc/init\.d|update-rc\.d|chkconfig|/etc/profile|\.bashrc"),
        ("account change", r"\b(?:useradd|adduser|usermod|userdel|groupadd|gpasswd|chpasswd)\b|"
                           r"\bpasswd\s+\S|/etc/sudoers|visudo|authorized_keys"),
        ("credential store", r"/etc/shadow|/etc/gshadow|\.aws/credentials|\.ssh/id_"),
        ("download and execute", r"(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
                                 r"base64\s+(?:-d|--decode)[^|;]*\|\s*(?:ba)?sh"),
        ("reverse shell", r"/dev/tcp/|\bnc(?:at)?\b[^;|]*\s-[a-z]*e\b|socat\b.*exec|"
                          r"bash\s+-i\s*>&|python[0-9.]*\s+-c\s+.*socket"),
        ("setuid", r"chmod\s+(?:[ugo]*\+s|[2467][0-7]{3})\b"),
        ("history clearing", r"history\s+-c|unset\s+histfile|/dev/null\s*>\s*\S*_history|"
                             r"rm\s+[^;]*\.bash_history"),
        ("kernel module", r"\b(?:insmod|modprobe)\b"),
        ("audit or EDR tampering", r"auditctl\s+-D|systemctl\s+(?:stop|disable|mask)\s+"
                                   r"(?:auditd|mdatp|falcon|ssm|amazon-ssm)"),
    )
)


def applies(alert_name: str) -> bool:
    return (alert_name or "").strip().casefold() == FAMILY


def red_flags(cmds: list[str]) -> list[str]:
    return sorted({label for c in cmds for label, rx in RED_FLAGS if rx.search(c or "")})


def _norm(v: str) -> str:
    return (v or "").strip().lower()


def canon(cmd: str) -> str:
    """The rule joins one session's commands with ", ", so `su - netra` run twice arrives
    as "su - netra, su - netra" and three times as a different string — each a "new"
    command against the other's clearance. Collapse ONLY a run of identical commands to
    one; anything with a different command in it is left exactly as it is."""
    c = (cmd or "").strip()
    parts = [x.strip() for x in c.split(", ")]
    if len(parts) > 1 and len({fingerprint(x) for x in parts}) == 1 and parts[0]:
        return parts[0]
    return c


def canon_list(cmds: list[str]) -> list[str]:
    out: list[str] = []
    for c in cmds or []:
        c = canon(c)
        if c and fingerprint(c) not in {fingerprint(x) for x in out}:
            out.append(c)
    return out


_DEV_RE = re.compile(r"\*?Device Name:\*?[ \t]*([^\s*]\S*)")
_PRINC_RE = re.compile(r"\*?Session Principal:\*?[ \t]*([^\s*]\S*)")
_CMDS_RE = re.compile(r"Initiating Commands \((\d+)\):\*?\s*\n((?:[ \t]+`.*`[ \t]*\n?)+)")


def parse_comment(text: str) -> dict | None:
    """Device, session principal and commands from a Root Privesc comment — None unless it
    is complete: a device, a principal, and exactly as many quoted commands as the "(N)"
    header announces (a suppressed tail would make a partial set look like a repeat)."""
    t = text or ""
    if "more routine commands suppressed" in t or "more suppressed" in t:
        return None
    dev, pr, m = _DEV_RE.search(t), _PRINC_RE.search(t), _CMDS_RE.search(t)
    if not (dev and pr and m):
        return _parse_rendered(t)
    cmds = []
    for ln in m.group(2).splitlines():
        ln = ln.strip()
        if len(ln) >= 2 and ln.startswith("`") and ln.endswith("`"):
            cmds.append(ln[1:-1])
    if not cmds or len(cmds) != int(m.group(1)):
        return None
    return {"device": _norm(dev.group(1)), "actor": _norm(pr.group(1)), "cmds": canon_list(cmds)}


# The same block as Jira hands it back. The record is POSTED as wiki markup, stored as
# ADF, and _adf_to_text drops the bold/code marks — so from mid-October every record read
# back as "Device Name:\n host\nSession Principal:\n \nuser\nInitiating Commands (1):\ncmd"
# and none parsed (DEMO-117219 onward): human FP closes stopped becoming precedents, and the
# repeat closes were living on early-October clearances that age out after PRECEDENT_DAYS.
_DEV_RENDERED = re.compile(r"Device Name:[ \t]*\n\s*([^\s*]\S*)[ \t]*\n")
_PRINC_RENDERED = re.compile(r"Session Principal:[ \t]*\n\s*([^\s*]\S*)[ \t]*\n")
_CMDS_RENDERED = re.compile(r"Initiating Commands \((\d+)\):[ \t]*\n")


def _parse_rendered(t: str) -> dict | None:
    """parse_comment for the rendered form: the N lines after the header are the
    commands, all present and none a label. Same completeness rule as the marked form."""
    dev, pr, m = _DEV_RENDERED.search(t), _PRINC_RENDERED.search(t), _CMDS_RENDERED.search(t)
    if not (dev and pr and m):
        return None
    if dev.group(1).endswith(":") or pr.group(1).endswith(":"):
        return None                     # an empty value followed by the next label
    n = int(m.group(1))
    rest = t[m.end():].split("\n")
    cmds = [ln.strip() for ln in rest[:n]]
    if n < 1 or len(cmds) != n or any(not c or c.endswith(":") for c in cmds):
        return None
    # The block must END after N lines — at a blank line, the next "Label:", or the end. A
    # command with a newline inside it (DEMO-118222: `mysql -e "…"` over several lines)
    # would otherwise be cut into fragments that each read as a cleared command.
    nxt = rest[n].strip() if len(rest) > n else ""
    if nxt and not nxt.endswith(":"):
        return None
    if any(c.endswith(",") for c in cmds):
        return None                     # a line break inside a command list — a fragment
    return {"device": _norm(dev.group(1)), "actor": _norm(pr.group(1)), "cmds": canon_list(cmds)}


def evidence_record(device: str, actor: str, cmds: list[str]) -> str:
    """The same Device Name / Session Principal / Initiating Commands block parse_comment
    reads, appended to every autonomous-phase ticket so history keeps accruing."""
    cmds = [c for c in (cmds or []) if (c or "").strip()]
    lines = ["*RAPTOR evidence record (Root Privesc guard):*",
             f"*Device Name:* {device or 'Unknown Device'}",
             f"*Session Principal:* {actor or 'Unknown'}"]
    if cmds:
        lines.append(f"*Initiating Commands ({len(cmds)}):*")
        lines += [f"  `{c}`" for c in cmds[:MAX_CMDS]]
        if len(cmds) > MAX_CMDS:
            lines.append(f"  _… {len(cmds) - MAX_CMDS} more suppressed_")
    return "\n".join(lines)


def _match_actor(actor: str):
    want = _norm(actor)
    return lambda p: p.get("actor") == want


async def check(jira_key: str, device: str, actor: str, cmds: list[str], cfg) -> dict:
    """{"allow", "reason", "new", "precedents"} — never raises."""
    cmds = canon_list([c for c in (cmds or []) if (c or "").strip()])
    if not cmds:
        return {"allow": False, "reason": "no command was recorded for this alert", "new": []}
    if len(cmds) > MAX_CMDS:
        return {"allow": False, "reason": f"{len(cmds)} commands — too many to verify", "new": cmds}
    flags = red_flags(cmds)
    if flags:
        return {"allow": False, "reason": "needs a person whatever the history: " + ", ".join(flags),
                "new": cmds, "red_flags": flags}
    dev, who = _norm(device), _norm(actor)
    if not dev or dev in ("unknown", "unknown device"):
        return {"allow": False, "reason": "device unknown", "new": cmds}
    if not who or who in ("unknown", "root"):
        return {"allow": False, "reason": "no session principal — nobody the clearance could belong to",
                "new": cmds}
    try:
        prec = await cleared_precedents(dev, who, jira_key, cfg, days=PRECEDENT_DAYS,
                                        needed={fingerprint(c) for c in cmds},
                                        summary=SUMMARY, parser=parse_comment)
    except Exception as exc:
        logger.warning("privesc_guard: precedent lookup failed for %s: %s", jira_key, exc)
        return {"allow": False, "reason": f"precedent lookup failed ({str(exc)[:120]})", "new": cmds}
    cleared = {fingerprint(c) for p in prec for c in p["cmds"]}
    new = [c for c in cmds if fingerprint(c) not in cleared]
    if new:
        return {"allow": False, "new": new, "precedents": [p["key"] for p in prec],
                "reason": (f"{len(new)} command(s) {who} has not had cleared on {dev} in the last "
                           f"{PRECEDENT_DAYS} days — e.g. `{new[0][:160]}`")}
    used = [p for p in prec if {fingerprint(c) for c in p["cmds"]} & {fingerprint(c) for c in cmds}]
    return {"allow": True, "reason": "exact repeat of a human-cleared session", "new": [],
            "precedents": [{"key": p["key"], "cleared_by": p["cleared_by"],
                            "cleared_at": p["cleared_at"]} for p in used]}


# ── Session check ─────────────────────────────────────────────────────────────────────
# The repeat rule asks "has a person cleared these commands for this user on this host?".
# It cannot tell the person from someone replaying their stolen session with the same
# routine command (INC-2026-0001-KB: a stolen ReadOnly session replayed from
# 198.51.100.0/24). So a repeat closes only when the SSM session itself looks like this
# person's usual ones: every StartSession behind the alert came from a source IP they used
# on at least SESSION_MIN_DAYS earlier days, through a role and a kind of client they have
# used before. Anything unfamiliar is asked about or escalated instead. Fails closed.
SESSION_LOOKBACK_DAYS = 30
SESSION_MIN_DAYS = 2
SESSION_WINDOW_HOURS = 3     # the rule matches processes from the last hour, sessions from the last two


def parse_ts(v):
    """Aware datetime from a Sentinel / Jira / ISO timestamp, or None. Sentinel writes 7
    fractional digits ("…19.5578336Z") and Jira "+0530"; slicing the string to a fixed
    length cut "+00:00" to "+00:0", so every session check failed to anchor (DEMO-117030)."""
    import re as _re
    from datetime import datetime, timezone
    s = str(v or "").strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    s = _re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)                  # +0530 -> +05:30
    s = _re.sub(r"(\.\d{6})\d+", r"\1", s)                             # 7+ digits -> 6
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def session_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if arn and "assumed-role/" in arn else ""


def _role(arn: str) -> str:
    parts = (arn or "").split("/")
    return parts[1] if "assumed-role/" in (arn or "") and len(parts) >= 3 else ""


def client_family(ua: str) -> str:
    u = (ua or "").lower()
    if u.startswith("aws-cli") or "botocore" in u or "boto3" in u:
        return "aws-cli/sdk"
    for key, fam in (("windows", "browser-windows"), ("macintosh", "browser-mac"),
                     ("mac os", "browser-mac"), ("linux", "browser-linux")):
        if key in u:
            return fam
    return (u.split("/")[0] or "unknown")[:30]


def judge_sessions(current: list[dict], history: list[dict]) -> tuple[bool, str]:
    """Pure. current/history: rows with TimeGenerated, SourceIpAddress, UserAgent, UserIdentityArn."""
    if not current:
        return False, "no SSM StartSession by this person was found for the alert"
    ip_days: dict[str, set] = {}
    roles, clients = set(), set()
    for r in history:
        ip_days.setdefault(r.get("SourceIpAddress") or "", set()).add(str(r.get("TimeGenerated"))[:10])
        roles.add(_role(r.get("UserIdentityArn") or ""))
        clients.add(client_family(r.get("UserAgent") or ""))
    for r in current:
        ip = r.get("SourceIpAddress") or ""
        if len(ip_days.get(ip, ())) < SESSION_MIN_DAYS:
            return False, (f"session from {ip or 'an unknown address'}, which this person used on "
                           f"{len(ip_days.get(ip, ()))} earlier day(s) in {SESSION_LOOKBACK_DAYS} days")
        role = _role(r.get("UserIdentityArn") or "")
        if role not in roles:
            return False, f"session through role {role or '?'}, which this person has not used before"
        cf = client_family(r.get("UserAgent") or "")
        if cf not in clients:
            return False, f"session from a {cf} client, which this person has not used before"
    ips = sorted({r.get("SourceIpAddress") or "" for r in current})
    return True, (f"session from {', '.join(ips)}, used by this person on "
                  f"{min(len(ip_days[i]) for i in ips)}+ earlier days, usual role and client")


async def session_check(arn: str, anchor: str, incident_url: str) -> tuple[bool, str]:
    """(familiar, why). Fails closed on anything missing or any query error."""
    from datetime import datetime, timedelta
    who = session_name(arn)
    if not who or not incident_url:
        return False, "no SSM session to check"
    t = parse_ts(anchor)
    if t is None:
        return False, "no time to anchor the session check"
    lo = t - timedelta(days=SESSION_LOOKBACK_DAYS)
    win = t - timedelta(hours=SESSION_WINDOW_HOURS)
    hi = t + timedelta(minutes=10)
    f = "%Y-%m-%dT%H:%M:%SZ"
    who_q = who.replace("\\", "").replace('"', "")
    kql = (f'AWSCloudTrail\n| where TimeGenerated between (datetime({lo.strftime(f)}) .. datetime({hi.strftime(f)}))\n'
           f'| where EventName == "StartSession" and EventSource has "ssm" and isempty(ErrorCode)\n'
           f'| where UserIdentityArn endswith "/{who_q}"\n'
           f'| project TimeGenerated, SourceIpAddress, UserAgent, UserIdentityArn')
    try:
        from edr_triage.sentinel_client import _run_la_query, parse_incident_url
        rows = await _run_la_query(parse_incident_url(incident_url), kql,
                                   timespan=f"{lo.strftime(f)}/{hi.strftime(f)}")
    except Exception as exc:
        return False, f"session lookup failed ({str(exc)[:100]})"
    def _ts(r):
        return parse_ts(r.get("TimeGenerated"))
    current = [r for r in rows or [] if _ts(r) and _ts(r) >= win]
    history = [r for r in rows or [] if _ts(r) and _ts(r) < win]
    return judge_sessions(current, history)


# ── Ambiguous actor, every candidate cleared ──────────────────────────────────────────
# Two operators with SSM sessions on the host in the window (actor_ambiguous) leave WHO
# ran the command unknown, so the close gate refuses it. On kam-margin-calc-eq-prod two
# BOD operators overlap most mornings and every such `su - netra` went to L2 (DEMO-117843,
# DEMO-118003). Who ran it still cannot be told — but when EACH overlapping principal would
# pass the repeat rule and the session check on their own, whoever it was is a cleared
# operator in their usual session. One unfamiliar or uncleared session keeps it ambiguous.
async def resolve_ambiguity(jira_key: str, device: str, cmds: list[str], ct: dict,
                            anchor: str, incident_url: str, cfg) -> tuple[bool, str]:
    """(cleared, why). ct is the CloudTrail entity carrying actor_ambiguous,
    session_principals and session_arns. Fails closed."""
    if not ct.get("actor_ambiguous"):
        return False, "actor not ambiguous"
    if ct.get("candidate_devices"):
        return False, "several hosts matched — the host itself is unknown"
    if cfg is None or not getattr(cfg, "privesc_session_check", True):
        return False, "session check is off"
    from edr_triage.sentinel_client import _principal
    by_arn = {a: _norm(_principal(a)) for a in (ct.get("session_arns") or []) if a}
    princ = sorted({_norm(p) for p in (ct.get("session_principals") or []) if p})
    if len(princ) < 2 or set(by_arn.values()) != set(princ):
        return False, "the session ARNs do not account for every principal"
    cleared = []
    for who in princ:
        res = await check(jira_key, device, who, cmds, cfg)
        if not res["allow"]:
            return False, f"{who}: {res['reason']}"
        for arn in sorted(a for a, p in by_arn.items() if p == who):
            ok, why = await session_check(arn, anchor, incident_url)
            if not ok:
                return False, f"{who}: session not familiar — {why}"
        cleared.append(f"{who} (cleared on {res['precedents'][0]['key']})")
    return True, ("every overlapping session is a cleared operator in a familiar session: "
                  + "; ".join(cleared))


async def enforce_at_close(alert_name: str, labels: list, jira_key: str, device: str,
                           actor: str, cmds: list[str], cfg, dry_run: bool = False,
                           session: dict | None = None) -> tuple[bool, str]:
    """Close-gate step. (block, reason). On allow, names the precedent the close rests on;
    on block, labels the ticket — the ASK step afterwards decides whether to chase.

    session = {"arn", "anchor", "incident_url"}: with cfg set and EDR_PRIVESC_SESSION_CHECK on,
    an exact repeat also needs a familiar session (see session_check)."""
    if not applies(alert_name):
        return False, ""
    res = await check(jira_key, device, actor, cmds, cfg)
    from edr_triage.jira_handler import add_comment
    sess_why = ""
    if res["allow"] and cfg is not None and getattr(cfg, "privesc_session_check", True):
        s = session or {}
        ok, sess_why = await session_check(s.get("arn", ""), s.get("anchor", ""),
                                           s.get("incident_url", ""))
        if not ok:
            res = {"allow": False, "reason": f"exact repeat, but the session is not familiar: {sess_why}"}
            if "privesc-session-unfamiliar" not in labels:
                labels.append("privesc-session-unfamiliar")
    if res["allow"]:
        p = res["precedents"][0]
        text = ("*Auto-close permitted: exact repeat of a human-cleared session.*\n\n"
                f"Same commands, host and session principal as {p['key']}, which "
                f"{p['cleared_by']} closed as False Positive on {p['cleared_at'][:10]}."
                + (f"\nSession check: {sess_why}." if sess_why else "")
                + (f"\nSeveral people had sessions on the host — {(session or {})['ambiguity_cleared']}."
                   if (session or {}).get("ambiguity_cleared") else "") +
                "\n\nReopen this ticket if that clearance should not carry over.\n\n"
                "[Auto-triaged by RAPTOR]")
        try:
            await add_comment(jira_key, text, cfg, dry_run=dry_run)
        except Exception as exc:
            logger.error("privesc_guard: comment on %s failed: %s", jira_key, exc)
        return False, ""
    for lab in BLOCK_LABELS:
        if lab not in labels:
            labels.append(lab)
    return True, res["reason"]


def may_ask(triage_class: str, ambiguous: bool, is_test_device: bool, severity: str) -> tuple[bool, str]:
    """Whether a not-closed Root Privesc ticket goes to the session principal. Pure.

    Only when the agent leaned benign (FP) or asked for a justification itself — an agent
    escalation stays an escalation, and asking never replaces one: every answer still
    routes to L2. Never when the actor is ambiguous (asking one of several people cannot
    settle whose command it was), on a red-team box, or at CRITICAL severity."""
    if triage_class not in ("AUTO_CLOSED_FP", "REQUEST_JUSTIFICATION"):
        return False, f"the agent escalated ({triage_class})"
    if ambiguous:
        return False, "the actor is ambiguous"
    if is_test_device:
        return False, "known test/red-team device"
    if (severity or "").upper() == "CRITICAL":
        return False, "CRITICAL severity"
    return True, ""


def ask_comment(who: str, reason: str) -> str:
    return ("*RAPTOR is asking the user instead of auto-closing.*\n\n"
            f"Why not closed: {reason}.\n\n"
            f"For Root Privilege Escalation RAPTOR closes only an exact repeat of what a person "
            f"already cleared for this user on this host. Anything new goes to the user — "
            f"{who} — via the Acme Security Bot; their answer comes back to L2, who decides."
            "\n\n[Auto-triaged by RAPTOR]")
