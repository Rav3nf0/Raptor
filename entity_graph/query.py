"""High-level context API — trust-filtered entity context for agent OSCAR O-step."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta

from beanie.odm.operators.find.comparison import In

from entity_graph.graph import get_entity
from entity_graph.models import SCGEntity, SCGMemory, MemoryTier, ShadowResult

logger = logging.getLogger(__name__)


def _cap(text: str, limit: int = 500) -> str:
    """Cap text near `limit` on a sentence/line boundary (no mid-word cuts).

    Replaces the old naive content[:300] slice that chopped reasoning mid-word.
    """
    if not text:
        return ""
    t = " ".join(text.split())  # collapse whitespace/newlines
    if len(t) <= limit:
        return t
    cut = t[:limit]
    for sep in (". ", "! ", "? ", "; "):
        idx = cut.rfind(sep)
        if idx > limit * 0.5:
            return cut[:idx + 1].strip() + " …"
    sp = cut.rfind(" ")
    return (cut[:sp] if sp > 0 else cut).strip() + " …"


_JUSTIFICATION_MARK = "[PRIOR BUSINESS JUSTIFICATION"


# How recent a prior justification must be to count as APPLICABLE to the alert in
# hand rather than as background. Short on purpose: a justification is a statement
# about what someone was doing THAT WEEK, not a standing permission.
_JUSTIFICATION_WINDOW_DAYS = 7


def _justification_applies(m, alert_type: str, device_name: str, user_name: str) -> bool:
    """True when a stored justification covers the alert being triaged right now.

    Requires the SAME actor, the SAME device, the SAME alert type, and a justification
    given within the last `_JUSTIFICATION_WINDOW_DAYS`. Actor and device must both be
    present on the memory — 2 of the 8 justification-bearing keys in the store are
    ('', '', 'privesc') / ('', '', 'netskope'), and an empty side would otherwise match
    every host-less alert.

    Deliberately NOT command-aware, because verdict memories carry no commands:
    `commands` is only ever populated by create_allowlist_memory (the L2-armed
    allowlist), so every memory written by the closure poller has an empty list. That
    makes this "same person, same box, same alert type" — looser than it should be, and
    the reason this only RELABELS the recall line rather than auto-closing anything.
    Storing the pipeline's extracted commands on verdict memories is what would let the
    match tighten to the command shape.

    Sized before shipping: 74 shadows match one of these actor+device keys — 54 already
    closed FP by a human, 18 pending, and ZERO true positives. (Weak evidence rather
    than proof: the dataset holds only 9 TPs in total, all on other hosts.)
    """
    m_actor = (getattr(m, "actor", "") or "").strip().lower()
    m_actors = {(a or "").strip().lower() for a in (getattr(m, "actors", None) or [])}
    m_device = (getattr(m, "device", "") or "").strip().lower()
    m_type = (getattr(m, "alert_type", "") or "").strip().lower()
    if not ((m_actor or m_actors) and m_type):
        return False
    _u = (user_name or "").strip().lower()
    if m_actor != _u and _u not in m_actors:
        return False
    # Device must MATCH — which for a device-less alert family means both sides absent,
    # not "one side present". Requiring m_device to be non-empty made this unreachable
    # for Netskope DLP: measured 2026-09-01, 0 of 264 DLP shadow rows carry a
    # device_name at all, because a DLP hit is CASB activity on a cloud app, not
    # something that happens on a host.
    #
    # The cost of that was not neutral. The justification itself was still surfaced by
    # entity recall, but it rendered with the stored "re-validate each occurrence"
    # caption — and per the note in _memory_summary the model obeys that caption and
    # asks the person to re-explain. So every DLP alert by someone who had ALREADY
    # given a business justification was told to go and ask again: 31 of those 264 rows
    # are REQUEST_JUSTIFICATION, and 7 of the 40 scored DLP misses are the agent asking
    # for a justification on a ticket a human then closed FP.
    #
    # The empty-side hazard the old guard was written for is handled by the actor and
    # type checks above, which are unchanged and strict: a ('', '', 'netskope') memory
    # has no actor and is already rejected, so it cannot match anything. What passes
    # here is still only the SAME named person on the SAME alert type inside the window.
    _d = (device_name or "").strip().lower()
    if m_device != _d:
        return False
    if m_type != (alert_type or "").strip().lower():
        return False
    created = getattr(m, "created_at", None)
    if not created:
        return False
    try:
        return (datetime.utcnow() - created) <= timedelta(days=_JUSTIFICATION_WINDOW_DAYS)
    except TypeError:
        return False


def _memory_summary(m, limit: int = 500, justification_applies: bool = False) -> str:
    """Render one memory for the agent's opening context.

    Two things have to survive, and neither did:

    1. THE USER'S JUSTIFICATION. `_write_verdict_memory` PREPENDS the relayed
       business justification to `content`. This rendered `l1_comment or content`,
       and l1_comment is essentially always populated (the L1 thread), so `content`
       was never reached and the justification was never shown — on any alert, for
       any entity. DEMO-108171 asked morgan.diaz for a justification he had already
       given on DEMO-105519/106643: seven memories were recalled for that host and
       user, two of them carrying his answer, and the agent saw none of it. It is
       pulled out and rendered FIRST so it also survives the character cap.

    2. THE RESOLUTION rather than the escalation. On a ticket that went to L2 the
       l1_comment is the hand-off ("escalating for further analysis") and carries no
       verdict; the answer is in l2_comment. Same fix as get_playbook_precedents_block.

    The justification stays labelled CONTEXT-ONLY by the stored prefix itself — this
    surfaces it, it does not promote it to exculpatory evidence.
    """
    content = getattr(m, "content", "") or ""
    just = ""
    if _JUSTIFICATION_MARK in content:
        _start = content.index(_JUSTIFICATION_MARK)
        # The prefix is written as one block ending at the first blank-line/verdict
        # marker "[<alert_type>]"; take up to that, else the rest of the field.
        _rest = content[_start:]
        _end = _rest.find("\n[")
        just = _cap(_rest[:_end] if _end > 0 else _rest, 260)
        if justification_applies:
            # Same actor, same device, same alert type, inside the window — so the
            # stored "re-validate each occurrence" caption is answering a question the
            # match has already settled, and the model obeys it: DEMO-108171 read the
            # caption and asked morgan.diaz to re-justify work he had justified on
            # the same host, for the same alert, that same day. Swap the caption for
            # what the match actually establishes. Still evidence the model weighs,
            # not an instruction to close — every gate downstream is unchanged.
            _body = just.split("]:", 1)[1].strip() if "]:" in just else just
            _days = max(0, (datetime.utcnow() - m.created_at).days)
            _when = "today" if _days == 0 else f"{_days}d ago"
            # Name only what the match actually established. On a device-less family
            # (Netskope DLP carries no host at all) claiming "SAME device" would be
            # asserting a correspondence that was never checked, in the one line the
            # model is most likely to lean on.
            _same = ("SAME actor, SAME device, SAME alert type"
                     if (getattr(m, "device", "") or "").strip()
                     else "SAME actor, SAME alert type (this alert family has no host)")
            just = (
                f"[APPLICABLE PRIOR JUSTIFICATION — {_same}, given {_when}"
                + (f" on {m.jira_key}" if getattr(m, "jira_key", "") else "")
                + f", within the {_JUSTIFICATION_WINDOW_DAYS}d window. This covers the "
                  "activity in hand: do NOT ask this user to justify it again. Weigh it "
                  f"as evidence and decide]: {_cap(_body, 260)}"
            )
    verdict = _cap(getattr(m, "l2_comment", "") or getattr(m, "l1_comment", "") or content, limit)
    return f"{just}\n{verdict}".strip() if just else verdict


_MEM_ALERT_NAME_RE = re.compile(r"Alert '([^']+)'|'([^']+)' escalated")
_INVOLVING_RE = re.compile(r"\s+involving\s+(one user|multiple users)\s*$", re.I)


def _memory_alert_name(m) -> str:
    """The alert name a memory was written about, from its caption ("" if absent)."""
    hit = _MEM_ALERT_NAME_RE.search(getattr(m, "content", "") or "")
    return (hit.group(1) or hit.group(2)).strip() if hit else ""


def _same_alert(m, alert_name: str) -> bool | None:
    """True/False when both alert names are known, None when it cannot be told."""
    mine = _INVOLVING_RE.sub("", (alert_name or "").strip()).lower()
    theirs = _INVOLVING_RE.sub("", _memory_alert_name(m)).lower()
    if not mine or not theirs:
        return None
    return mine == theirs


def _relevance_label(m, alert_name: str) -> str:
    """Say whether a recalled memory is about THIS alert or only about the same entity.

    DEMO-116466 (a privileged sign-in failure spike) leaned on "DLP/CASB alerts for
    sana.bedi were closed as FP" — a verdict about a different kind of alert
    recalled because it shared a user. It tells you something about the person, nothing
    about whether this alert is benign.
    """
    same = _same_alert(m, alert_name)
    if same is True:
        return "[SAME alert as this one] "
    if same is False:
        return (f"[DIFFERENT alert: '{_cap(_memory_alert_name(m), 70)}' — about this entity, "
                "says nothing about whether THIS alert is benign] ")
    return ""


async def get_entity_context(entity_type: str, value: str, alert_type: str = "",
                             device_name: str = "", user_name: str = "", alert_name: str = "") -> dict:
    """Return full context for an entity: history, tags, memories, related alerts."""
    entity = await get_entity(entity_type, value)
    if not entity:
        return {
            "entity_type": entity_type,
            "value": value,
            "found": False,
            "alert_count": 0,
            "risk_score": 0.0,
            "tags": [],
            "memories": [],
        }

    entity_id = str(entity.id)
    try:
        memories = await SCGMemory.find(
            In(SCGMemory.entity_ids, [entity_id]),
            SCGMemory.confidence >= 0.5,
            In(SCGMemory.tier, [MemoryTier.curated, MemoryTier.golden]),
        ).sort(-SCGMemory.confidence, -SCGMemory.created_at).limit(12).to_list()
        # Memories about THIS alert first: the top 3 by confidence alone were often other
        # alert families entirely (a DLP close recalled for a sign-in spike). Stable sort,
        # so confidence order holds within each group.
        memories = sorted(memories, key=lambda m: 0 if _same_alert(m, alert_name) else 1)[:3]
        memory_summaries = [
            f"[{m.tier.value}|{m.source}] {_relevance_label(m, alert_name)}"
            f"{_memory_summary(m, justification_applies=_justification_applies(m, alert_type, device_name, user_name))} "
            f"(conf={m.confidence:.2f})"
            for m in memories
        ]
    except Exception:
        memory_summaries = []

    # A SHARED account's history is the fleet's history, not this actor's. `root`,
    # SYSTEM, svc-* and friends appear on every host, so their alert_count and
    # risk_score are the sum of every unrelated event that ever ran under that name —
    # presenting them as this entity's record hands the model a maximum-risk actor for
    # what is really "a daemon did something somewhere".
    #
    # DEMO-109417 is the cost: a macOS "Files Copied to USB Drives" alert whose user field
    # carried the PROCESS account. The agent made two tool calls — the device came back
    # risk 10.0 / 2 alerts, and `root` came back **risk 100.0 / 176 alerts**. It escalated
    # at 0.75 on a low-risk device with a maximum-risk actor. Both L1 and L2 closed it FP.
    #
    # This is the THIRD time the same lesson has been learned. get_precedents already
    # guards it (DEMO-106632: "root@ five different boxes showing up as precedent for each
    # other"), and the concurrency gate was fixed for it later — entity recall never was.
    # _is_generic_account already exists and `root` is the first name in its list; this
    # just applies it at the remaining call site.
    #
    # The numbers are NOT hidden — the model still needs to know the alert names a
    # service account, and suppressing the row entirely would replace a misleading
    # signal with a missing one. They are relabelled so they cannot be read as this
    # actor's track record, and the caption says why.
    _shared = entity_type == "user" and _is_generic_account(value)
    out = {
        "entity_type": entity_type,
        "value": value,
        "found": True,
        "first_seen": entity.first_seen.isoformat(),
        "last_seen": entity.last_seen.isoformat(),
        "alert_count": entity.alert_count,
        "risk_score": round(entity.risk_score, 1),
        "tags": entity.tags,
        "source_systems": entity.source_systems,
        "memories": memory_summaries,
    }
    if _shared:
        out["shared_account"] = True
        out["fleet_alert_count"] = entity.alert_count
        out["fleet_risk_score"] = round(entity.risk_score, 1)
        # Zeroed for THIS entity, because none of that history is attributable to it.
        out["alert_count"] = 0
        out["risk_score"] = 0.0
        out["note"] = (
            f"'{value}' is a SHARED/built-in account, not a person. Its "
            f"{entity.alert_count} prior alerts and risk score of "
            f"{round(entity.risk_score, 1)} are the FLEET-WIDE totals for everything that "
            "has ever run under that name on any host — they say nothing about this event "
            "and are not evidence of risk here. Identify the actual acting principal "
            "(the device's user, the session owner) before weighing actor history."
        )
    return out


async def get_multi_entity_context(entities: list[tuple[str, str]], alert_type: str = "",
                                   device_name: str = "", user_name: str = "",
                                   alert_name: str = "") -> str:
    """Return a formatted context block for multiple entities (for OSCAR O-step prompt).

    `alert_type`/`device_name`/`user_name` describe the alert being triaged RIGHT NOW —
    they are only used to decide whether a stored business justification still applies
    to it (see _justification_applies). Omitted, every justification renders with its
    original re-validate-each-occurrence caption, which is the pre-existing behaviour.
    """
    sections = []
    for entity_type, value in entities:
        if not value:
            continue
        ctx = await get_entity_context(entity_type, value, alert_type=alert_type,
                                       device_name=device_name, user_name=user_name,
                                       alert_name=alert_name)
        if not ctx.get("found"):
            sections.append(f"- {entity_type} {value!r}: first seen, no prior history")
            continue
        if ctx.get("shared_account"):
            # Never render a shared account's fleet totals as this actor's history — see
            # get_entity_context. Say what it is instead, so the model looks for the real
            # acting principal rather than reading risk=100 off a daemon.
            parts = [f"- {entity_type} {value!r}: SHARED/built-in account — no actor "
                     f"history applies. {ctx.get('note', '')}"]
        else:
            parts = [f"- {entity_type} {value!r}: {ctx['alert_count']} prior alerts, risk={ctx['risk_score']}"]
        if ctx.get("tags"):
            parts.append(f"  tags: {', '.join(ctx['tags'])}")
        for m in ctx.get("memories", []):
            parts.append(f"  memory: {m}")
        sections.append("\n".join(parts))
    return "\n".join(sections) if sections else "No prior context found for entities in this alert."


async def get_multi_actor_justification_status(actor_hosts: list[dict], alert_type: str) -> dict[str, dict]:
    """For a multi-actor incident, which actors already have an applicable justification.

    `actor_hosts` is the paired [{"actor","hosts","commands"}] structure built in
    edr_triage/pipeline.py — one group per distinct actor on the incident. Reuses the
    exact same entity fetch and `_justification_applies` matching `get_entity_context`
    already does for the single primary actor; the only difference is this checks
    EACH of the actor's OWN hosts (not just one device_name) and loops over multiple
    actors instead of one. No new matching logic, no auto-close — same as
    `_justification_applies`, this only tells the caller a precedent EXISTS; it never
    authorizes skipping the ask on its own.

    Returns {actor.lower(): {"jira_key": ..., "device": <matched host>, "summary": ...}}
    for actors with an applicable hit. Actors with none are simply absent from the
    dict — DEMO-109720's insufficient-context case (an unresolved actor) is also just
    absent, since there is nothing to look up.
    """
    hits: dict[str, dict] = {}
    for group in (actor_hosts or []):
        if not isinstance(group, dict):
            continue
        actor = (group.get("actor") or "").strip()
        hosts = [h for h in (group.get("hosts") or []) if h]
        if not actor or not hosts:
            continue
        try:
            entity = await get_entity("user", actor)
        except Exception:
            entity = None
        if not entity:
            continue
        try:
            memories = await SCGMemory.find(
                In(SCGMemory.entity_ids, [str(entity.id)]),
                SCGMemory.confidence >= 0.5,
                In(SCGMemory.tier, [MemoryTier.curated, MemoryTier.golden]),
            ).sort(-SCGMemory.confidence, -SCGMemory.created_at).to_list()
        except Exception:
            continue
        for m in memories:
            matched_host = next(
                (h for h in hosts if _justification_applies(m, alert_type, h, actor)), None,
            )
            if matched_host:
                hits[actor.lower()] = {
                    "jira_key": getattr(m, "jira_key", ""),
                    "device": matched_host,
                    "summary": _memory_summary(m, justification_applies=True),
                }
                break
    return hits


async def get_playbook_memories(alert_type: str, limit: int = 5) -> list[dict]:
    """Return curated/golden memories for a given alert type — playbook-level patterns.

    These are lessons learned from L1 analyst decisions on similar alert types,
    not tied to a specific entity. Used to teach the LLM how L1 handles this class
    of alert before it makes a verdict.

    ONLY returns scope=="playbook" memories. Entity-scoped memories (the default)
    are deliberately excluded here — they are actor/device-specific verdicts and
    must surface ONLY via entity recall (recall_memories), never type-wide. Letting
    an entity-scoped FP leak into this type-wide path is exactly what taught the LLM
    "all privesc is benign" in DEMO-104192.
    """
    if not alert_type:
        return []
    try:
        memories = await SCGMemory.find(
            SCGMemory.alert_type == alert_type,
            SCGMemory.scope == "playbook",
            SCGMemory.confidence >= 0.5,
            In(SCGMemory.tier, [MemoryTier.curated, MemoryTier.golden]),
        ).sort(-SCGMemory.confidence, -SCGMemory.created_at).limit(limit).to_list()
        return [
            {
                "content": m.content,
                "l1_comment": m.l1_comment,
                # The L2 resolution — the AUTHORITATIVE verdict, and on an escalated
                # ticket the only place the answer lives. recall_memories already
                # surfaces it for the same reason; this path did not, so a playbook
                # precedent rendered the L1 ESCALATION and dropped the resolution
                # (DEMO-107947: l1_comment ends "escalating this alert to L2", while
                # "run as part of IronWatch → false positive" sits only in l2_comment).
                "l2_comment": (getattr(m, "l2_comment", "") or "")[:400],
                "confidence": round(m.confidence, 2),
                "tier": m.tier.value,
                "jira_key": m.jira_key,
                "source": m.source,
            }
            for m in memories
        ]
    except Exception as exc:
        logger.error("get_playbook_memories(%s) failed: %s", alert_type, exc)
        return []


def _norm_cmd(s: str) -> str:
    """Whitespace/case-normalised command text for comparison."""
    import re as _re
    return _re.sub(r"\s+", " ", (s or "")).strip().lower()


# A command has to be substantial before a substring hit means anything — short
# fragments ("powershell.exe", "-Method Post") appear in benign and malicious lines
# alike, so matching on them would turn any precedent into a free pass.
_CMD_MATCH_MIN_LEN = 40


def _matching_command(precedent_text: str, command_lines: list | None) -> str:
    """Return the alert command that appears VERBATIM in this precedent, if any.

    The point is to separate two very different things the model currently sees as
    one: 'an alert of this TYPE was closed FP before' (weak, and rightly not grounds
    to close), versus 'THIS EXACT COMMAND was adjudicated FP by a named L2' (direct
    evidence about the activity in hand).
    """
    if not command_lines:
        return ""
    hay = _norm_cmd(precedent_text)
    if not hay:
        return ""
    for c in command_lines:
        n = _norm_cmd(c)
        if len(n) >= _CMD_MATCH_MIN_LEN and n in hay:
            return str(c).strip()
    return ""


STANDING_CONTEXT_SOURCE = "admin_context_import"
_STANDING_CONTEXT_CAP = 3000


async def get_standing_context(alert_type: str) -> str:
    """The security team's own written context for an alert type (POST
    /api/memory/playbook-context), or "". Shown whole: it is a curated note, not a
    precedent, and the precedent cap of 500 characters cut its exclusions off."""
    if not alert_type:
        return ""
    try:
        m = await SCGMemory.find_one(
            SCGMemory.alert_type == alert_type,
            SCGMemory.scope == "playbook",
            SCGMemory.source == STANDING_CONTEXT_SOURCE,
        )
    except Exception as exc:
        logger.error("get_standing_context(%s) failed: %s", alert_type, exc)
        return ""
    return _cap((m.content or "") if m else "", _STANDING_CONTEXT_CAP)


async def get_playbook_precedents_block(alert_type: str, exclude_jira: str = "",
                                        limit: int = 3, command_lines: list | None = None) -> str:
    """Bounded, curated-only precedent block for the agent's opening context.

    Surfaces how L1 handled this ALERT TYPE before — including memories with no
    entity link (which entity recall can't reach) — with the full reasoning capped
    on a boundary. Deliberately small (top `limit`, curated/golden only) to bound
    token cost and limit anchoring/poisoning; the accompanying prompt marks it
    CONTEXT ONLY.
    """
    standing = await get_standing_context(alert_type)
    mems = await get_playbook_memories(alert_type, limit=limit + 3)
    mems = [m for m in mems if m.get("jira_key") != exclude_jira
            and m.get("source") != STANDING_CONTEXT_SOURCE][:limit]
    head = ([f"Standing context for '{alert_type}' written by the security team "
             "(CONTEXT ONLY — it never clears an alert by itself; anything it lists as NOT "
             f"routine still escalates):\n{standing}"] if standing else [])
    if not mems:
        return "\n".join(head)
    lines = head + [
        f"How analysts have previously RESOLVED '{alert_type}' alerts "
        "(curated precedents — CONTEXT ONLY; do NOT let these shortcut your own investigation):"
    ]
    _exact = False
    for m in mems:
        # Prefer the RESOLUTION over the escalation. On a ticket that went to L2 the
        # l1_comment is the hand-off ("escalating for further analysis") and carries no
        # verdict at all — rendering it as the precedent teaches the model that this
        # class of alert gets escalated, which is the opposite of the lesson.
        note = _cap(m.get("l2_comment") or m.get("l1_comment") or m.get("content") or "", 500)
        # Does this precedent record the SAME command the current alert carries?
        _hit = _matching_command(
            " ".join([m.get("l2_comment") or "", m.get("l1_comment") or "", m.get("content") or ""]),
            command_lines,
        )
        _tag = ""
        if _hit:
            _exact = True
            _tag = " **EXACT COMMAND MATCH**"
        lines.append(f"- [{m['tier']} conf={m['confidence']}]{_tag} {m.get('jira_key','')}: {note}")
    if _exact:
        # Without this the block is read under the blanket "memory never justifies an
        # auto-close" rule, which is correct for a same-TYPE precedent and wrong here:
        # a byte-identical command already adjudicated by a named L2 is evidence about
        # THIS activity, not a loose analogy. It is also the only evidence some alert
        # classes can ever produce — 'Powershell script was loaded in memory' carries no
        # hash and no file, so under the blanket rule it is unclosable by construction,
        # which is why the family sits at 18 scored misses with the AI escalating every
        # one and a human closing every one FP.
        lines.append(
            "  NOTE — one precedent above records the SAME command line as this alert, "
            "already adjudicated by a named analyst. That is DIRECT evidence about this "
            "specific activity, not a same-alert-type analogy: you may treat it as "
            "positive exculpatory evidence and auto-close, PROVIDED the rest of this "
            "alert is clean. It does not waive anything else — a VirusTotal detection, a "
            "named EDR threat, a concurrent open alert or any other danger signal still "
            "forces escalation, and the safety gates are unchanged."
        )
    return "\n".join(lines)


# Accounts that exist on EVERY host and therefore identify no one. Matching
# concurrency on these correlates unrelated machines: DEMO-107887 (beaconing on
# u1419kgupdsgmac-2) was blocked as "concurrent" with DEMO-107812 (USB file copy on
# u1423awanoprmac) — a different alert on a different device, linked only by both
# running as `root`. The precedents path already learned this (edr_triage.store
# .get_precedents, DEMO-106632: "root@ five different boxes showing up as precedent
# for each other"); the concurrency gate had not.
_GENERIC_ACCOUNTS = frozenset({
    "root", "admin", "administrator", "system", "localsystem", "local system",
    "network service", "local service", "nt authority\\system", "daemon",
    "nobody", "_mbsetupuser", "unknown", "n/a",
})
_GENERIC_ACCOUNT_PREFIXES = ("nt service\\", "nt authority\\", "svc-", "svc_")


def _is_generic_account(user: str) -> bool:
    """True when a username is a shared/built-in account that identifies no host."""
    u = (user or "").strip().lower()
    if not u:
        return True
    return u in _GENERIC_ACCOUNTS or u.startswith(_GENERIC_ACCOUNT_PREFIXES)


_CONCURRENT_WINDOW_HOURS = 24
# A sibling that lands slightly AFTER this alert can still be part of the same burst
# (ingestion/clock skew, an incident unfolding over minutes), so the window extends a
# little past the reference. A sibling a day later is a separate event, not concurrent.
_CONCURRENT_FORWARD_GRACE_HOURS = 1


# Block reasons written by the concurrency gate itself (agent_core.loop). Matched as a
# prefix so a reason that merely MENTIONS concurrency further in is not caught.
_CONCURRENCY_BLOCK_RE = re.compile(r"^Concurrent open alerts")


async def check_concurrent_alerts(device_name: str = "", user_name: str = "",
                                  exclude_jira_key: str = "",
                                  reference_time: str = "") -> dict:
    """Check for other open alerts on the same device or user within 24h of this alert.

    Returns `open_alerts` (jira_key list, for back-compat) plus `open_alert_details`
    — each sibling's jira_key + alert_name + ai_triage_class + created_at. The
    details let a caller distinguish a true DUPLICATE (same alert_name, same entity,
    near-same time) from merely-concurrent distinct alerts (possible attack chain).

    Excluded from the count (a sibling only corroborates concurrency if it is a
    *distinct, un-triaged-away, still-open* alert):
      * agent-failure shadows (`ai_error` set — an outage/agent_exception that only
        fell back to NEEDS_L2 without ever being triaged) — no incident signal;
      * terminally-resolved siblings — L2 closed (`l2_resolved_at`) or L1 closed
        directly (`l1_resolved_at` with no L2 handoff). The poller stamps these on
        close but never rewrites `ai_triage_class`, so a closed-FP ticket would
        otherwise keep counting as "open" until it aged out of the 24h window. A
        ticket escalated to L2 and still pending review stays counted (genuinely open);
      * `exclude_jira_key` — the current ticket's own shadow(s), which otherwise
        self-count on any re-triage/re-run (a ticket is not its own concurrent alert);
      * anything outside the window around `reference_time` (see below).

    `reference_time` (ISO8601, injected by the agent loop from the alert itself — the
    model never sets it) anchors the window to WHEN THE ALERT FIRED rather than to
    wall-clock now. Those coincide during live triage, but not on a re-triage of a
    historical ticket: the window was previously `now - 24h .. now`, measured against
    each sibling's `created_at` (its TRIAGE time), so replaying an old ticket compared
    it against whatever else happened to be triaged recently — the replay schedule, not
    the security timeline. Alerts that fired AFTER the one under triage then counted as
    "concurrent open alerts" against it. DEMO-107291 (2026-08-04) was escalated on the
    strength of DEMO-107406, which fired ~21h LATER and did not exist when DEMO-107291
    happened; the analyst had already closed 107291 as FP. Beyond the bogus escalation
    that also corrupts the accuracy metric, since the AI gets judged on a verdict it
    could only reach using information a live run could not have had.

    Falls back to `datetime.utcnow()` when no reference is supplied, so live triage
    behaviour is unchanged.
    """
    ref = datetime.utcnow()
    if reference_time:
        try:
            _r = datetime.fromisoformat(str(reference_time).replace("Z", "+00:00"))
            # Compare naive-UTC throughout: ShadowResult.created_at is stored naive.
            ref = _r.replace(tzinfo=None) - (_r.utcoffset() or timedelta(0)) \
                if _r.tzinfo else _r
        except (TypeError, ValueError):
            logger.warning("check_concurrent_alerts: unparseable reference_time %r — "
                           "falling back to now", reference_time)
    cutoff = ref - timedelta(hours=_CONCURRENT_WINDOW_HOURS)
    horizon = ref + timedelta(hours=_CONCURRENT_FORWARD_GRACE_HOURS)
    open_alerts: list[str] = []
    details: list[dict] = []
    try:
        filters = []
        if device_name:
            filters.append({"device_name": device_name.lower()})
        # Device and user are queried SEPARATELY and unioned (OR), so a user-only
        # match on a shared account sweeps in every host running as that account.
        # Correlating on a REAL identity across devices is exactly what this gate is
        # for, so only generic accounts are skipped — not user matching in general.
        if user_name and not _is_generic_account(user_name):
            filters.append({"user_name": user_name.lower()})
        elif user_name:
            logger.info(
                "check_concurrent_alerts: user %r is a generic/shared account — "
                "correlating on device only", user_name,
            )
        if not filters:
            return {"concurrent_count": 0, "open_alerts": [], "open_alert_details": []}

        for filt in filters:
            key, val = list(filt.items())[0]
            q = [
                {key: val},
                ShadowResult.created_at >= cutoff,
                # Upper bound: a sibling that fired after this alert cannot corroborate
                # it. Without this, re-triaging an old ticket saw every later alert.
                ShadowResult.created_at <= horizon,
                In(ShadowResult.ai_triage_class, ["NEEDS_L2", "URGENT", "AUTO_CLOSED_TP"]),
                # Exclude agent-failure shadows (outage/agent_exception): they only
                # *fell back* to NEEDS_L2 without ever being triaged, so they carry no
                # incident signal and must not corroborate concurrency — otherwise one
                # un-triaged ghost drags its same-entity siblings to L2 via the gate.
                ShadowResult.ai_error == None,
                # Exclude siblings a human has TERMINALLY resolved — "open" must mean
                # unresolved, not merely "the AI escalated it" (ai_triage_class is never
                # rewritten on close, so a closed ticket would otherwise linger 24h).
                # Resolved iff L2 closed it (l2_resolved_at) OR L1 closed it directly
                # (l1_resolved_at with NO L2 handoff). A ticket escalated to L2 and still
                # PENDING (l1_handoff_at set, l2_resolved_at None) is genuinely open and
                # MUST keep counting — note the poller sets l1_resolved_at on L1→L2 handoff
                # too, so l1_resolved_at alone is NOT a "closed" signal.
                ShadowResult.l2_resolved_at == None,
                {"$or": [{"l1_handoff_at": {"$ne": None}}, {"l1_resolved_at": None}]},
                # Exclude siblings that THIS GATE escalated and nothing else — otherwise
                # the gate reads its own output back as evidence and the escalations
                # become self-sustaining. Measured on one DBA's SSM sessions: DEMO-108702,
                # 108679, 108667, 108631, 108518 and 108514 were SIX FOR SIX
                # pre_safety_class=AUTO_CLOSED_FP overridden by "Concurrent open alerts",
                # each held open only by the others, with no independent danger signal
                # anywhere in the set. The loop also grows — every new host that DBA
                # touches adds another member, and none of them can ever resolve itself.
                #
                # NARROW ON PURPOSE. Only concurrency-gate escalations are discounted. A
                # sibling the MODEL escalated on its own merits still counts, and so does
                # one held open by any OTHER gate — VT detections, a named EDR threat, the
                # test-device rule, the privesc absence-of-evidence rule. So every genuine
                # signal still propagates exactly as before; what stops propagating is
                # this gate's own verdict being fed back to it.
                {"$or": [
                    {"blocked_by_safety": {"$ne": True}},
                    {"safety_block_reason": {"$not": _CONCURRENCY_BLOCK_RE}},
                ]},
            ]
            if exclude_jira_key:
                # A ticket is not its own concurrent alert (self-count on re-triage).
                q.append({"jira_key": {"$ne": exclude_jira_key}})
            results = await ShadowResult.find(*q).to_list()
            for r in results:
                if r.jira_key not in open_alerts:
                    open_alerts.append(r.jira_key)
                    details.append({
                        "jira_key": r.jira_key,
                        "alert_name": getattr(r, "alert_name", ""),
                        "ai_triage_class": getattr(r, "ai_triage_class", ""),
                        # Needed to tell a DUPLICATE (same alert, same host — one activity
                        # firing repeatedly) from the same alert on a DIFFERENT host, which
                        # is the opposite signal: alert_name alone cannot distinguish them,
                        # and siblings can match on user across hosts.
                        "device_name": getattr(r, "device_name", "") or "",
                        "created_at": r.created_at.isoformat() if getattr(r, "created_at", None) else "",
                        # Handed to L2 and not yet resolved (l2_resolved_at is already
                        # filtered to None above). Not a burst duplicate: a human looked
                        # at the same activity and was not satisfied. See agent_core.loop.
                        # Deliberately NOT l1_awaiting_inputs_at — that is stamped whoever
                        # moved the ticket, and RAPTOR's own user chase moves tickets there,
                        # so bot-chased burst siblings would deadlock each other again.
                        "human_held": bool(getattr(r, "l1_handoff_at", None)),
                    })
    except Exception as exc:
        # Raise, never "0 concurrent": that answer reads as a passed precondition for
        # auto-close (it hid the 7feb2c3 schema bug). Every caller already turns an
        # exception into a failed check — scg wrapper → error → critical-tool gate; loop
        # prefetch → not seeded; uba_guard → others=None.
        logger.error("check_concurrent_alerts failed: %s", exc)
        raise
    return {
        "concurrent_count": len(open_alerts),
        "open_alerts": open_alerts,
        "open_alert_details": details,
    }


# Alert families that ARE a named-malware detection on the host. A device that produced
# one of these recently is not a clean baseline for judging its other alerts.
MALWARE_ALERT_RE = re.compile(
    r"malware was (detected|prevented)|An active .* malware|Netskope -Malware", re.I)
_MALWARE_LOOKBACK_DAYS = 30


# A person's own answer, as a verdict memory records it: the relayed chase reply carries
# the PRIOR BUSINESS JUSTIFICATION prefix (jira_closure_poller._write_verdict_memory), and
# L2 writes "as per (the) confirmation from user". The CASB re-enablement template is not
# one — nobody was asked (DEMO-115919 was cleared on exactly those).
_USER_ANSWER_RE = re.compile(
    r"PRIOR BUSINESS JUSTIFICATION|(?:as per|per|after|on|with|based on) (?:the )?confirmation "
    r"(?:received )?from (?:the )?user|confirmation (?:was )?received from (?:the )?user"
    r"|as (?:per|confirmed by) "
    r"(?:the )?user|user (?:has )?confirmed|\[user —"
    r"|(?:provided|shared|gave|given) (?:a |the |his |her |their )?(?:business )?justification", re.I)


async def dlp_user_justification(user: str) -> dict | None:
    """The person's own earlier answer on a DLP ticket a human closed, or {} if none.

    {"jira_key", "text"}. None when the lookup fails (the caller treats that as none). The
    record must name this person in its own text: verdict memories have been bound to the
    wrong account (DEMO-113085's Investor Grievances answer sits on someone else).
    """
    u = (user or "").strip().lower()
    if not u:
        return {}
    local = u.split("@")[0]
    try:
        rows = await SCGMemory.find(
            {"alert_type": "netskope_dlp", "tier": {"$ne": "archived"},
             "$or": [{"actor": {"$regex": f"^{re.escape(u)}$", "$options": "i"}},
                     {"actors": {"$regex": f"^{re.escape(u)}$", "$options": "i"}}]},
        ).sort("-created_at").limit(30).to_list()
    except Exception as exc:
        logger.warning("dlp_user_justification(%s) failed: %s", u, exc)
        return None
    for m in rows:
        text = f"{m.content or ''} {m.l1_comment or ''} {m.l2_comment or ''} {m.quarantine_reason or ''}"
        low = text.lower()
        # Slack-relayed answers name the email; one typed on the ticket carries the
        # author's display name ("[user — Ira Chopra]").
        if ((local in low or local.replace(".", " ") in low) and _USER_ANSWER_RE.search(text)
                and re.search(r"AUTO_CLOSED_FP|false positive", text, re.I)):
            flat = " ".join(text.split())
            at = _USER_ANSWER_RE.search(flat).start()
            at = max(flat.rfind(". ", 0, at) + 2, flat.rfind("] ", 0, at) + 2, 0)   # sentence start
            return {"jira_key": m.jira_key, "text": flat[at:at + 300]}
    return {}


async def open_urgent_alerts(user_name: str = "", device_name: str = "", reference_time: str = "",
                             exclude_jira_key: str = "", days: int = 14) -> list[dict] | None:
    """URGENT tickets on this user or device from the last `days` that no human has closed.

    An account or host under an open compromise question is not a clean baseline:
    DEMO-117913 auto-closed theo.malik's sign-in spike while DEMO-117523 (wrong
    passwords, then a success from a new IP, URGENT) was still with L2 three days on —
    past the 24h concurrency window. Shared accounts match nothing (every host has root).
    None when the lookup fails; the caller treats that as "cannot rule it out".
    """
    user = (user_name or "").strip().lower()
    host = (device_name or "").strip().lower().split(".")[0]
    who = []
    if user and not _is_generic_account(user):
        who.append({"user_name": {"$regex": f"^{re.escape(user)}$", "$options": "i"}})
    if host:
        who.append({"device_name": {"$regex": f"^{re.escape(host)}(\\.|$)", "$options": "i"}})
    if not who:
        return []
    ref = datetime.utcnow()
    if reference_time:
        try:
            _r = datetime.fromisoformat(str(reference_time).replace("Z", "+00:00"))
            ref = (_r.replace(tzinfo=None) - (_r.utcoffset() or timedelta(0))) if _r.tzinfo else _r
        except (TypeError, ValueError):
            pass
    try:
        q = [{"$or": who}, {"ai_triage_class": "URGENT"},
             {"created_at": {"$gte": ref - timedelta(days=days), "$lte": ref}},
             {"l2_resolved_at": None}, {"l1_resolved_at": None}]
        if exclude_jira_key:
            q.append({"jira_key": {"$ne": exclude_jira_key}})
        rows = await ShadowResult.find(*q).sort("-created_at").limit(5).to_list()
    except Exception as exc:
        logger.warning("open_urgent_alerts(%s, %s) failed: %s", user, host, exc)
        return None
    return [{"jira_key": r.jira_key, "alert_name": r.alert_name,
             "created_at": r.created_at.isoformat() if r.created_at else ""} for r in rows]


async def recent_malware_alerts(device_name: str, reference_time: str = "",
                                exclude_jira_key: str = "",
                                days: int = _MALWARE_LOOKBACK_DAYS) -> list[dict] | None:
    """Named-malware tickets on this device in the `days` before the alert.

    Feeds the gate that refuses an AUTO_CLOSED_FP on a host with recent malware.
    r009mrahaitwd had three Sality detections (a file infector, from a binary on an IT
    file share) and a CustomEnterpriseBlock hit, and RAPTOR still auto-closed two
    PowerShell alerts on it, citing that very history as "confirmed legitimate".

    Matches on the short hostname so FQDN and bare forms meet. Any outcome counts —
    a detection a human closed as authorised is still a detection on the host. Returns
    None when the lookup fails; the caller treats that as "cannot rule it out".
    """
    host = (device_name or "").strip().lower().split(".")[0]
    if not host:
        return []
    ref = datetime.utcnow()
    if reference_time:
        try:
            _r = datetime.fromisoformat(str(reference_time).replace("Z", "+00:00"))
            ref = (_r.replace(tzinfo=None) - (_r.utcoffset() or timedelta(0))) if _r.tzinfo else _r
        except (TypeError, ValueError):
            pass
    try:
        q = [
            {"device_name": {"$regex": f"^{re.escape(host)}(\\.|$)", "$options": "i"}},
            {"alert_name": {"$regex": MALWARE_ALERT_RE.pattern, "$options": "i"}},
            {"created_at": {"$gte": ref - timedelta(days=days), "$lte": ref}},
        ]
        if exclude_jira_key:
            q.append({"jira_key": {"$ne": exclude_jira_key}})
        rows = await ShadowResult.find(*q).sort("-created_at").limit(10).to_list()
    except Exception as exc:
        logger.warning("recent_malware_alerts(%s) failed: %s", host, exc)
        return None
    return [{"jira_key": r.jira_key, "alert_name": r.alert_name,
             "created_at": r.created_at.isoformat() if r.created_at else ""} for r in rows]
