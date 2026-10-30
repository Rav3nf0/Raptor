"""Netskope Bulk Upload / Bulk Download: RAPTOR closes ONLY through an L2-approved pattern.

The workflow for these families (decided 2026-09-30) is: chase every named user, route
their answers to L2, and let L2 approve any close. RAPTOR's own verdict never closes one.
The only close RAPTOR may perform is a repeat of a pattern L2 has explicitly approved —
an armed actor-allowlist entry proposed by uba_learner from L2-approved closes — and even
that only when the pattern is pinned to the COMPANY account of the app.

Why the account matters more than the app. L1 today closes most of these because "the
user accessed approved applications such as Slack, S3, Cursor". But a bulk upload to an
approved app in a PERSONAL workspace is exactly what data exfiltration looks like, and
"approved app" cannot tell the two apart. Netskope records the account (instance_id:
example.onmicrosoft.com, acme, a personal gmail.com, ...), so an approval here is
scoped to it, and anything personal, public or unrecorded never auto-closes.

A close is permitted only when ALL of these hold:
  1. it came from an armed allowlist entry, not from a model verdict;
  2. that entry pins both the apps AND the accounts (instances), none of them personal,
     public or unrecorded;
  3. the users came from the alert itself (alert-bound), not a time-window sweep;
  4. the approval covers this DIRECTION — a download approval never clears an upload;
  5. there is exactly one user — an entry is scoped to ONE actor, and a multi-user ticket
     matched on its primary actor would close everyone else's activity with it;
  6. no Amazon S3 is involved — see below;
  7. the activity still looks like the person L2 approved, not someone using their account.

Amazon S3 always needs the user's own justification (decided 2026-09-30). Netskope
records an S3 "account" as an AWS account id, and nothing here can prove a given id is
Acme's. A bucket in someone else's AWS account is the cheapest exfiltration path
there is, and it looks identical to a company bucket in the alert. So an S3 pattern is
never learned and never auto-closed: every S3 transfer is chased and L2 closes it.

Why (7). An approval says "this person moves these files to this company account".
An insider, or an attacker on a compromised laptop, can repeat exactly that shape, so
the approval alone is not enough. A learned close also requires, at the moment of
closing:
  * the SAME device(s) seen in the approved tickets — stolen credentials used from
    another machine fail here;
  * a device Netskope does not classify as unmanaged;
  * a volume no more than VOLUME_FACTOR times the largest approved one — staging data
    before exfiltration, or a leaver's last-week sweep, shows up as volume;
  * the account still enabled in IdentityInfo;
  * no other open alert on the same user or device (EDR, sign-in, DLP ...) — a
    compromised laptop rarely raises only a Netskope alert. An unreadable history
    blocks, unlike the agent's concurrency gate;
  * the ticket not drawn for L2 spot-check (EDR_UBA_SPOTCHECK_PERCENT of learned closes
    go to L2 anyway, so a slowly drifting pattern still gets human eyes).

Enforced at the pipeline's single close gate. Fails closed.
"""
from __future__ import annotations

import hashlib
import logging
import re

logger = logging.getLogger(__name__)

BLOCK_LABELS = ("needs-l2-review", "uba-guard")
VOLUME_FACTOR = 2.0

# Apps whose account cannot be shown to be a company one, so every transfer is justified.
_ALWAYS_JUSTIFY_RE = re.compile(r"\bs3\b|simple storage service", re.IGNORECASE)

# Accounts that are never a company workspace. "public-*" covers Netskope's
# public-download / public-link instances, which say where a file came from, not whose.
_NOT_COMPANY_RE = re.compile(
    r"^$|\(not recorded\)|^public-|gmail\.com|googlemail\.com|outlook\.com|hotmail\.|"
    r"live\.com|yahoo\.|icloud\.com|me\.com|proton(mail)?\.|aol\.com|gmx\.|yandex\.",
    re.IGNORECASE)


def applies(alert_name: str) -> bool:
    from edr_triage.classifier import NETSKOPE_UBA_RE
    return bool(NETSKOPE_UBA_RE.search(alert_name or ""))


def non_company(instances: list[str]) -> list[str]:
    """The pinned or live accounts that are not a company workspace."""
    return [i for i in (instances or [""]) if _NOT_COMPANY_RE.search((i or "").strip())]


def always_justify(apps: list[str]) -> list[str]:
    """The apps on which every transfer needs the user's own justification (Amazon S3)."""
    return [a for a in (apps or []) if _ALWAYS_JUSTIFY_RE.search(a or "")]


def _live_apps(uba: dict | None) -> list[str]:
    return sorted({str(a).strip().lower() for b in ((uba or {}).get("by_user") or {}).values()
                   for a in (b.get("apps") or []) if str(a).strip()})


def check(labels: list, allow_entry: dict | None, uba: dict | None) -> tuple[bool, str]:
    """(allow, reason) for the approval and this ticket's own evidence — pure, no I/O."""
    s3 = always_justify(_live_apps(uba) + list((allow_entry or {}).get("apps") or []))
    if s3:
        return False, ("Amazon S3 is involved — Netskope cannot show whose AWS account a "
                       "bucket belongs to, so every S3 transfer needs the user's own "
                       "justification and L2's approval")
    if not allow_entry or "raptor-actor-allowlist" not in (labels or []):
        return False, ("closing needs L2 approval — RAPTOR only closes a repeat of a pattern "
                       "L2 has approved, and none matched this ticket")
    apps = allow_entry.get("apps") or []
    insts = allow_entry.get("app_instances") or []
    if not apps or not insts:
        return False, ("the matched approval is not pinned to both the app and the company "
                       "account, so it cannot tell a personal workspace from the company one")
    bad = non_company(insts)
    if bad:
        return False, f"the approval covers non-company account(s): {', '.join(bad)}"
    u = uba or {}
    want = (u.get("kind") or "").strip().lower()
    if (allow_entry.get("uba_direction") or "").strip().lower() != want or not want:
        return False, (f"the matched approval covers {allow_entry.get('uba_direction') or 'no'} "
                       f"direction, not {want or 'an unknown one'} — a download approval never "
                       "clears an upload")
    if u.get("bind_source") != "alert":
        return False, "the users come from a time-window sweep, not the alert itself"
    users = u.get("users") or []
    if len(users) != 1:
        return False, (f"{len(users)} users on this ticket — an approval covers one person, "
                       "so each user's part still needs L2")
    return _check_behaviour(allow_entry.get("uba_baseline") or {},
                            (u.get("by_user") or {}).get(users[0]) or {})


def _check_behaviour(base: dict, live: dict) -> tuple[bool, str]:
    """Does this activity still look like the person L2 approved? Pure."""
    pinned = {h.strip().lower() for h in (base.get("hosts") or []) if h and h.strip()}
    hosts = {h.strip().lower() for h in (live.get("hosts") or []) if h and h.strip()}
    if not pinned:
        return False, "the approval records no device, so a different machine cannot be ruled out"
    if not hosts or not hosts <= pinned:
        return False, (f"device {', '.join(sorted(hosts)) or '(not recorded)'} is not one the "
                       f"approved activity came from ({', '.join(sorted(pinned))}) — the "
                       "account may be in use on another machine")
    if "unmanaged" in str(live.get("device_classification") or "").lower():
        return False, "Netskope classifies the device as unmanaged"
    for field, what in (("events", "max_events"), ("total_bytes", "max_bytes")):
        ceiling = int(base.get(what) or 0)
        seen = int(live.get(field) or 0)
        if ceiling <= 0:
            if field == "total_bytes" and seen <= 0:
                continue    # size never recorded on either side; the event count still bounds it
            return False, f"the approval records no {field.replace('_', ' ')} baseline"
        if seen > VOLUME_FACTOR * ceiling:
            return False, (f"{field.replace('_', ' ')} {seen:,} is more than "
                           f"{VOLUME_FACTOR:g}x the largest approved ({ceiling:,}) — "
                           "a volume jump is what staging data looks like")
    return True, ""


def check_context(identity: dict | None, other_alerts: list | None, jira_key: str,
                  spotcheck_percent: int) -> tuple[bool, str]:
    """Signals from outside the ticket. None means the lookup failed — that blocks. Pure."""
    if identity is None:
        return False, "the user could not be looked up in IdentityInfo"
    if str(identity.get("IsAccountEnabled", "")).lower() != "true":
        return False, "the user's account is not enabled in IdentityInfo"
    if other_alerts is None:
        return False, "other open alerts on this user or device could not be checked"
    if other_alerts:
        return False, (f"other open alert(s) on this user or device: "
                       f"{', '.join(other_alerts[:5])} — a compromised laptop rarely raises "
                       "only a Netskope alert")
    if spotcheck_percent > 0 and (
            int(hashlib.sha256((jira_key or "").encode()).hexdigest(), 16) % 100
            < spotcheck_percent):
        return False, (f"drawn for L2 spot-check ({spotcheck_percent}% of learned closes "
                       "are reviewed anyway)")
    return True, ""


async def _gather_context(uba: dict, jira_key: str, reference_time: str):
    user = ((uba or {}).get("users") or [""])[0]
    live = ((uba or {}).get("by_user") or {}).get(user) or {}
    identity = None
    try:
        from edr_triage.identity import resolve_identity
        identity = await resolve_identity(user)
    except Exception as exc:
        logger.warning("uba_guard: identity lookup for %s failed: %s", user, exc)
    others: list | None = []
    try:
        from entity_graph.query import check_concurrent_alerts
        # Other detections may name the person by bare account or by email.
        names = {user.lower(), user.split("@")[0].lower()} - {""}
        probes = [("", n) for n in names] + [(h, "") for h in (live.get("hosts") or []) if h]
        seen: set[str] = set()
        for dev, name in probes:
            r = await check_concurrent_alerts(device_name=dev, user_name=name,
                                              exclude_jira_key=jira_key,
                                              reference_time=reference_time)
            for d in r.get("open_alert_details") or []:
                # Another bulk-transfer ticket for the same person is the same story,
                # not corroboration of a compromise.
                if applies(d.get("alert_name", "")):
                    continue
                if d.get("jira_key") and d["jira_key"] not in seen:
                    seen.add(d["jira_key"])
                    others.append(d["jira_key"])
    except Exception as exc:
        logger.warning("uba_guard: concurrent-alert check for %s failed: %s", jira_key, exc)
        others = None
    return identity, others


async def evaluate(labels: list, allow_entry: dict | None, uba: dict | None, jira_key: str,
                   cfg, reference_time: str = "") -> tuple[bool, str]:
    """Every check a learned close must pass: the ticket's own evidence, then the outside
    signals (looked up only if the first part passes). Returns (allow, reason).

    Called twice. At the allowlist match, so a repeat that fails any check drops the
    match and goes through the normal chase — the user is still asked, which matters most
    on exactly the tickets where something looks off. And again at the close gate, as
    the backstop.
    """
    ok, why = check(labels, allow_entry, uba)
    if ok:
        identity, others = await _gather_context(uba or {}, jira_key, reference_time)
        ok, why = check_context(identity, others, jira_key,
                                int(getattr(cfg, "uba_spotcheck_percent", 10)))
    return ok, why


async def enforce_at_close(alert_name: str, labels: list, jira_key: str,
                           allow_entry: dict | None, uba: dict | None, cfg,
                           dry_run: bool = False,
                           reference_time: str = "") -> tuple[bool, str]:
    """The close-gate step. Returns (block, reason). Only runs for UBA families."""
    if not applies(alert_name):
        return False, ""
    ok, why = await evaluate(labels, allow_entry, uba, jira_key, cfg, reference_time)
    if ok:
        return False, ""
    for lab in BLOCK_LABELS:
        if lab not in labels:
            labels.append(lab)
    from edr_triage.jira_handler import add_comment
    try:
        await add_comment(jira_key, (
            "*RAPTOR did not auto-close this ticket.*\n\n"
            f"Reason: {why}.\n\n"
            "For Netskope bulk upload/download, each named user is asked to explain the "
            "activity and L2 approves any close. RAPTOR closes one itself only when it "
            "repeats a pattern L2 already approved for the same person, app, COMPANY "
            "account and device, at a similar volume, with nothing else open on that "
            "person — and never for Amazon S3.\n\n[Auto-triaged by RAPTOR]"), cfg,
            dry_run=dry_run)
    except Exception as exc:
        logger.error("uba_guard: comment on %s failed: %s", jira_key, exc)
    return True, why
