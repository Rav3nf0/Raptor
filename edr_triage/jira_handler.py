"""Jira action handler — post comments, transition tickets, set labels/category.

"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from edr_triage.config import EDRTriageConfig, get_edr_config

logger = logging.getLogger(__name__)


def _wiki_to_adf(wiki: str) -> dict:
    """Convert basic Jira wiki markup to ADF for the REST API v3."""
    import re
    nodes: list[dict] = []
    lines = wiki.split("\n")
    i = 0
    bullet_buf: list[str] = []

    def flush_bullets() -> None:
        if bullet_buf:
            nodes.append({
                "type": "bulletList",
                "content": [
                    {"type": "listItem", "content": [
                        {"type": "paragraph", "content": [{"type": "text", "text": item}]}
                    ]}
                    for item in bullet_buf
                ],
            })
            bullet_buf.clear()

    while i < len(lines):
        line = lines[i]

        if line.strip() == "{noformat}":
            flush_bullets()
            code_lines: list[str] = []
            i += 1
            while i < len(lines) and lines[i].strip() != "{noformat}":
                code_lines.append(lines[i])
                i += 1
            nodes.append({"type": "codeBlock", "attrs": {}, "content": [{"type": "text", "text": "\n".join(code_lines)}]})
            i += 1
            continue

        m = re.match(r"^h(\d)\.\s+(.*)", line)
        if m:
            flush_bullets()
            nodes.append({"type": "heading", "attrs": {"level": int(m.group(1))}, "content": [{"type": "text", "text": m.group(2).strip()}]})
            i += 1
            continue

        if line.startswith("* "):
            bullet_buf.append(line[2:])
            i += 1
            continue

        if line.startswith("# "):
            flush_bullets()
            nodes.append({"type": "orderedList", "content": [
                {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": line[2:]}]}]}
            ]})
            i += 1
            continue

        if not line.strip():
            flush_bullets()
            i += 1
            continue

        # Table rows: header rows start with ||, data rows start with | (but not ||)
        if line.startswith("||") or (line.startswith("|") and not line.startswith("||") and line.endswith("|")):
            flush_bullets()
            table_rows: list[dict] = []
            while i < len(lines):
                row_line = lines[i]
                is_header = row_line.startswith("||")
                is_data = row_line.startswith("|") and not row_line.startswith("||") and row_line.endswith("|")
                if not (is_header or is_data):
                    break
                if is_header:
                    raw_cells = row_line.strip("||").split("||")
                    cell_type = "tableHeader"
                else:
                    raw_cells = row_line.strip("|").split("|")
                    cell_type = "tableCell"
                cells = [
                    {
                        "type": cell_type,
                        "attrs": {},
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": c.strip()}]}],
                    }
                    for c in raw_cells
                ]
                table_rows.append({"type": "tableRow", "content": cells})
                i += 1
            nodes.append({
                "type": "table",
                "attrs": {"isNumberColumnEnabled": False, "layout": "full-width"},
                "content": table_rows,
            })
            continue

        flush_bullets()
        inline: list[dict] = []
        remaining = re.sub(r"\*([^*]+)\*", r"\1", line)
        while remaining:
            link_m = re.search(r"\[([^\|\]]+)\|([^\]]+)\]", remaining)
            if not link_m:
                if remaining:
                    inline.append({"type": "text", "text": remaining})
                break
            before = remaining[:link_m.start()]
            if before:
                inline.append({"type": "text", "text": before})
            inline.append({
                "type": "text",
                "text": link_m.group(1),
                "marks": [{"type": "link", "attrs": {"href": link_m.group(2)}}],
            })
            remaining = remaining[link_m.end():]
        nodes.append({"type": "paragraph", "content": inline or [{"type": "text", "text": ""}]})
        i += 1

    flush_bullets()
    return {"type": "doc", "version": 1, "content": nodes or [{"type": "paragraph", "content": [{"type": "text", "text": "No description"}]}]}


def _build_client(cfg: EDRTriageConfig) -> httpx.AsyncClient:
    from lib.jira_client import build_jira_client
    return build_jira_client(cfg.jira_url, cfg.jira_email, cfg.jira_token, cfg.jira_verify_ssl)


async def add_comment(
    issue_key: str,
    wiki_text: str,
    cfg: Optional[EDRTriageConfig] = None,
    dry_run: bool = False,
) -> bool:
    """Post a wiki-markup comment to a Jira issue, formatted by comment_format.

    Formatting can never cost a comment: if Jira rejects the rich document (HTTP 400 — a
    panel, expand or mark it will not take), the same text is retried without panels,
    expands or colour, and then through the old flat converter.
    """
    if dry_run:
        logger.info("[DRY-RUN] add_comment %s:\n%s", issue_key, wiki_text[:300])
        return True
    cfg = cfg or get_edr_config()
    if not all([cfg.jira_email, cfg.jira_token]):
        return False
    from edr_triage.comment_format import plain_adf, to_adf
    bodies = (("rich", to_adf), ("plain", plain_adf), ("flat", _wiki_to_adf))
    try:
        async with _build_client(cfg) as client:
            for name, build in bodies:
                try:
                    body = build(wiki_text)
                except Exception as exc:
                    logger.error("add_comment(%s): %s formatting failed: %s", issue_key, name, exc)
                    continue
                resp = await client.post(f"/rest/api/3/issue/{issue_key}/comment",
                                         json={"body": body})
                if resp.status_code == 400 and name != "flat":
                    logger.warning("add_comment(%s): Jira rejected the %s body (%s) — retrying "
                                   "simpler", issue_key, name, resp.text[:200])
                    continue
                resp.raise_for_status()
                logger.info("Comment posted to %s", issue_key)
                return True
    except Exception as exc:
        logger.error("add_comment(%s) failed: %s", issue_key, exc)
    return False


async def get_transitions(
    issue_key: str,
    cfg: Optional[EDRTriageConfig] = None,
) -> list[dict]:
    """Return available transitions for a Jira issue."""
    cfg = cfg or get_edr_config()
    try:
        async with _build_client(cfg) as client:
            resp = await client.get(f"/rest/api/3/issue/{issue_key}/transitions")
            resp.raise_for_status()
            return resp.json().get("transitions", [])
    except Exception as exc:
        logger.error("get_transitions(%s) failed: %s", issue_key, exc)
        return []


async def transition_ticket(
    issue_key: str,
    transition_name: str,
    cfg: Optional[EDRTriageConfig] = None,
    dry_run: bool = False,
) -> bool:
    """Transition a Jira issue to the named status.

    Fetches available transitions and matches by name (case-insensitive).
    Returns True on success.
    """
    if dry_run:
        logger.info("[DRY-RUN] transition_ticket %s → %s", issue_key, transition_name)
        return True
    cfg = cfg or get_edr_config()
    transitions = await get_transitions(issue_key, cfg)
    match = next(
        (t for t in transitions if t.get("name", "").lower() == transition_name.lower()),
        None,
    )
    if not match:
        available = [t.get("name") for t in transitions]
        logger.warning(
            "Transition '%s' not found on %s — available: %s",
            transition_name, issue_key, available,
        )
        return False
    try:
        async with _build_client(cfg) as client:
            resp = await client.post(
                f"/rest/api/3/issue/{issue_key}/transitions",
                json={"transition": {"id": match["id"]}},
            )
            resp.raise_for_status()
            logger.info("Transitioned %s → %s", issue_key, transition_name)
            return True
    except Exception as exc:
        logger.error("transition_ticket(%s, %s) failed: %s", issue_key, transition_name, exc)
        return False


async def get_status(
    issue_key: str,
    cfg: Optional[EDRTriageConfig] = None,
) -> str:
    """Return the issue's current status name, or "" if it cannot be read."""
    cfg = cfg or get_edr_config()
    try:
        async with _build_client(cfg) as client:
            resp = await client.get(f"/rest/api/3/issue/{issue_key}", params={"fields": "status"})
            resp.raise_for_status()
            return ((resp.json().get("fields") or {}).get("status") or {}).get("name", "")
    except Exception as exc:
        logger.error("get_status(%s) failed: %s", issue_key, exc)
        return ""


_bot_account_id: Optional[str] = None


async def _self_account_id(cfg: EDRTriageConfig) -> Optional[str]:
    """The bot's own Atlassian accountId, fetched once and cached."""
    global _bot_account_id
    if _bot_account_id:
        return _bot_account_id
    try:
        async with _build_client(cfg) as client:
            resp = await client.get("/rest/api/3/myself")
            resp.raise_for_status()
            _bot_account_id = resp.json().get("accountId")
            return _bot_account_id
    except Exception as exc:
        logger.error("_self_account_id failed: %s", exc)
        return None


async def assign_to_self_if_unassigned(
    issue_key: str,
    cfg: Optional[EDRTriageConfig] = None,
    dry_run: bool = False,
) -> bool:
    """Take ownership of an UNASSIGNED issue. No-op if someone already owns it.

    Required because the `Open -> Assigned` transition carries a workflow validator —
    "Please select the assignee" — that is INVISIBLE to the REST API. `/transitions`
    reports `hasScreen: false` and `fields: []` for it, and `expand=transitions.fields`
    lists no required field, so the 400 can only be discovered by attempting the
    transition. Humans satisfy it the same way: every SIM changelog shows an assignee
    write one or two seconds before the `Open -> Assigned` status change.

    Only when unassigned, deliberately: reassigning a ticket an analyst has already picked
    up would pull it out of their queue, which is a worse outcome than failing to close
    it. Returns True when the issue ends up assigned to somebody (including the case where
    it already was).
    """
    cfg = cfg or get_edr_config()
    if dry_run:
        logger.info("[DRY-RUN] assign_to_self_if_unassigned %s", issue_key)
        return True
    try:
        async with _build_client(cfg) as client:
            resp = await client.get(f"/rest/api/3/issue/{issue_key}",
                                    params={"fields": "assignee"})
            resp.raise_for_status()
            current = (resp.json().get("fields") or {}).get("assignee")
            if current:
                logger.debug("assign_to_self_if_unassigned(%s): already assigned to %s",
                             issue_key, current.get("displayName"))
                return True
            account_id = await _self_account_id(cfg)
            if not account_id:
                return False
            put = await client.put(f"/rest/api/3/issue/{issue_key}/assignee",
                                   json={"accountId": account_id})
            if put.status_code not in (200, 204):
                logger.error("assign_to_self_if_unassigned(%s) HTTP %s: %s",
                             issue_key, put.status_code, put.text[:300])
                return False
            logger.info("Assigned %s to self (required by the Open->Assigned validator)",
                        issue_key)
            return True
    except Exception as exc:
        logger.error("assign_to_self_if_unassigned(%s) failed: %s", issue_key, exc)
        return False


async def owned_by_a_person(issue_key: str, cfg: Optional[EDRTriageConfig] = None) -> Optional[str]:
    """Display name of the PERSON the issue is assigned to; "" when unassigned or assigned to
    RAPTOR itself; None when it cannot be read (callers treat None as "do not act")."""
    cfg = cfg or get_edr_config()
    try:
        async with _build_client(cfg) as client:
            resp = await client.get(f"/rest/api/3/issue/{issue_key}", params={"fields": "assignee"})
            resp.raise_for_status()
            current = (resp.json().get("fields") or {}).get("assignee")
        if not current:
            return ""
        me = await _self_account_id(cfg)
        if me and current.get("accountId") == me:
            return ""
        return current.get("displayName") or current.get("accountId") or "someone"
    except Exception as exc:
        logger.error("owned_by_a_person(%s) failed: %s", issue_key, exc)
        return None


async def assign_issue(
    issue_key: str,
    account_id: str,
    cfg: Optional[EDRTriageConfig] = None,
    dry_run: bool = False,
) -> bool:
    """Assign an issue to a specific accountId, whoever holds it now.

    Deliberately UNCONDITIONAL, unlike `assign_to_self_if_unassigned` above. That one
    refuses to touch an owned ticket because taking it would pull it out of an analyst's
    queue. This one is only ever called as part of a handoff TO a named owner — the
    reassignment is the point, and leaving the previous (L1) assignee on a ticket that
    has just moved to `L2 Analysis required` is what makes routed tickets go unnoticed.
    The previous holder is logged so the handoff is traceable.

    An empty account_id is a no-op returning True: the caller's transition has already
    happened and must not be reported as failed because reassignment was switched off.
    """
    if not (account_id or "").strip():
        return True
    cfg = cfg or get_edr_config()
    if dry_run:
        logger.info("[DRY-RUN] assign_issue %s -> %s", issue_key, account_id)
        return True
    try:
        async with _build_client(cfg) as client:
            prior = ""
            try:
                got = await client.get(f"/rest/api/3/issue/{issue_key}",
                                       params={"fields": "assignee"})
                if got.status_code < 300:
                    cur = (got.json().get("fields") or {}).get("assignee") or {}
                    prior = cur.get("displayName") or ""
            except Exception:
                pass    # provenance only — never block the assignment on it
            put = await client.put(f"/rest/api/3/issue/{issue_key}/assignee",
                                   json={"accountId": account_id})
            if put.status_code not in (200, 204):
                logger.error("assign_issue(%s -> %s) HTTP %s: %s",
                             issue_key, account_id, put.status_code, put.text[:300])
                return False
            logger.info("Assigned %s to %s (was: %s)",
                        issue_key, account_id, prior or "unassigned")
            return True
    except Exception as exc:
        logger.error("assign_issue(%s -> %s) failed: %s", issue_key, account_id, exc)
        return False


async def transition_to_status(
    issue_key: str,
    target_status: str,
    cfg: Optional[EDRTriageConfig] = None,
    dry_run: bool = False,
) -> bool:
    """Move an issue one hop, matching on the TARGET STATUS rather than the name.

    `transition_ticket` matches on the transition's own name, which is unsafe on the SIM
    workflow: the transition literally called "Awaiting More Inputs_1" leads to
    `L2 Analysis required`, and there is no transition called "Resolve" at all even though
    `Resolved` is a valid status. Matching on `to.name` means a rename or a repoint can
    never land the ticket somewhere unintended.
    """
    if dry_run:
        logger.info("[DRY-RUN] transition_to_status %s → %s", issue_key, target_status)
        return True
    cfg = cfg or get_edr_config()
    transitions = await get_transitions(issue_key, cfg)
    match = next(
        (t for t in transitions
         if ((t.get("to") or {}).get("name", "") or "").lower() == target_status.lower()),
        None,
    )
    if not match:
        logger.error(
            "transition_to_status(%s): no transition to %r — offered: %s",
            issue_key, target_status,
            [f"{t.get('name')!r}->{(t.get('to') or {}).get('name')!r}" for t in transitions],
        )
        return False
    try:
        async with _build_client(cfg) as client:
            resp = await client.post(
                f"/rest/api/3/issue/{issue_key}/transitions",
                json={"transition": {"id": match["id"]}},
            )
            if resp.status_code not in (200, 204):
                logger.error("transition_to_status(%s → %s) HTTP %s: %s",
                             issue_key, target_status, resp.status_code, resp.text[:300])
                return False
            logger.info("Transitioned %s → %s (transition %r id=%s)",
                        issue_key, target_status, match.get("name"), match.get("id"))
            return True
    except Exception as exc:
        logger.error("transition_to_status(%s → %s) failed: %s", issue_key, target_status, exc)
        return False


async def walk_to_status(
    issue_key: str,
    route: list[str],
    cfg: Optional[EDRTriageConfig] = None,
    forbidden: tuple[str, ...] = (),
    dry_run: bool = False,
) -> bool:
    """Walk a DECLARED route of statuses, one hop at a time, to reach route[-1].

    The SIM workflow does not let a fresh ticket reach a terminal state in one hop: an
    `Open` incident can only go to `Assigned`, then `Event Analysis`, and only from there
    to `False Positive` (138 of 156 human FP closes took exactly that path). So a
    single `transition_ticket` call can never close anything.

    The route is DECLARED, not discovered. Exploring the graph would mean transitioning
    the ticket to find out where transitions lead, and a wrong guess moves a real
    security ticket. A declared route is auditable, and `forbidden` is checked against
    the WHOLE route before the first hop is taken — which is what keeps an auto-close
    from being walked through `Awaiting more inputs`, the status that fires the Slack
    chase bot at whoever is named in the ticket.

    Hops already behind the ticket are skipped, so this is safe to call on a ticket that
    is partway along. Returns True only if the ticket ends on route[-1].
    """
    if not route:
        return False
    _forbidden = {f.strip().lower() for f in forbidden if f and f.strip()}
    _bad = [h for h in route if h.strip().lower() in _forbidden]
    if _bad:
        logger.error(
            "walk_to_status(%s): refusing route %s — passes through forbidden status(es) %s",
            issue_key, route, _bad,
        )
        return False

    cfg = cfg or get_edr_config()
    target = route[-1]
    current = await get_status(issue_key, cfg)
    if current and current.lower() == target.lower():
        logger.info("walk_to_status(%s): already %s — nothing to do", issue_key, target)
        return True

    # Resume mid-route when the ticket has already advanced past some hops.
    remaining = route
    lowered = [h.lower() for h in route]
    if current and current.lower() in lowered:
        remaining = route[lowered.index(current.lower()) + 1:]

    if dry_run:
        logger.info("[DRY-RUN] walk_to_status %s: %s → %s via %s",
                    issue_key, current or "?", target, remaining)
        return True

    # Precondition, not a courtesy: the `Open -> Assigned` transition rejects an
    # unassigned issue with a 400 the API never advertises. Cheap and idempotent for
    # routes that do not need it, and it leaves the close attributable to the bot in the
    # ticket's own assignee field.
    if not await assign_to_self_if_unassigned(issue_key, cfg):
        logger.error("walk_to_status(%s): could not take ownership — not walking %s",
                     issue_key, route)
        return False

    for hop in remaining:
        if not await transition_to_status(issue_key, hop, cfg):
            logger.error(
                "walk_to_status(%s): stalled at %r on route %s — ticket left in %r, "
                "NOT at %r; no further hops attempted",
                issue_key, hop, route, await get_status(issue_key, cfg), target,
            )
            return False
    return True


async def add_labels(
    issue_key: str,
    labels: list[str],
    cfg: Optional[EDRTriageConfig] = None,
    dry_run: bool = False,
) -> bool:
    """Add labels to a Jira issue (non-destructive — appends, does not replace)."""
    if dry_run:
        logger.info("[DRY-RUN] add_labels %s: %s", issue_key, labels)
        return True
    if not labels:
        return True
    cfg = cfg or get_edr_config()
    try:
        async with _build_client(cfg) as client:
            # Fetch current labels first to avoid overwriting
            get_resp = await client.get(
                f"/rest/api/3/issue/{issue_key}",
                params={"fields": "labels"},
            )
            get_resp.raise_for_status()
            # Jira returns labels as plain strings. This read `lbl["name"]` from the first
            # commit, so on any ticket that ALREADY had a label it raised and the new
            # labels were silently dropped — every re-triage, retry, gate re-triage and
            # give-up note on a labelled ticket (seen on DEMO-115740, 2026-10-05). First
            # triage only ever worked because those tickets start with no labels.
            existing = [lbl if isinstance(lbl, str) else (lbl or {}).get("name", "")
                        for lbl in (get_resp.json().get("fields", {}).get("labels") or [])]
            existing = [lbl for lbl in existing if lbl]
            merged = list(set(existing + labels))
            put_resp = await client.put(
                f"/rest/api/3/issue/{issue_key}",
                json={"fields": {"labels": merged}},
            )
            put_resp.raise_for_status()
            logger.info("Labels set on %s: %s", issue_key, merged)
            return True
    except Exception as exc:
        logger.error("add_labels(%s) failed: %s", issue_key, exc)
        return False


async def set_category(
    issue_key: str,
    category_value: str,
    cfg: Optional[EDRTriageConfig] = None,
    dry_run: bool = False,
) -> bool:
    """Set the Category custom field that fires the Acme Security Bot.

    CORRECTED 2026-09-09: the field is NOT named "category" — that PUT has never once
    succeeded (0 field-change comments from the bot account in 30 days of live traffic).
    There are 9 different fields named "Category" on this Atlassian site; the one SIM
    actually uses is `customfield_10335` (`cfg.category_field_id`), addressed by ID, and
    its options are `Cyble | No Repsonse | Others | Sentinel One | Sumologic` — the typo
    in "No Repsonse" is the option's real spelling (`cfg.category_no_response`) and must
    be reproduced exactly, byte for byte, or the PUT succeeds against a nonexistent
    option value and silently sets nothing.
    """
    if dry_run:
        logger.info("[DRY-RUN] set_category %s: %s", issue_key, category_value)
        return True
    cfg = cfg or get_edr_config()
    field_id = cfg.category_field_id
    try:
        async with _build_client(cfg) as client:
            resp = await client.put(
                f"/rest/api/3/issue/{issue_key}",
                json={"fields": {field_id: {"value": category_value}}},
            )
            if resp.status_code in (200, 204):
                logger.info("Category (%s) set on %s: %s", field_id, issue_key, category_value)
                return True
            logger.error("set_category(%s, %s -> %s) HTTP %s: %s",
                         issue_key, field_id, category_value, resp.status_code, resp.text[:300])
            return False
    except Exception as exc:
        logger.error("set_category(%s, %s) failed: %s", issue_key, category_value, exc)
        return False



async def get_description_adf(
    issue_key: str,
    cfg: Optional[EDRTriageConfig] = None,
) -> Optional[dict]:
    """Fetch the issue's `description` field as its raw ADF document, or None."""
    cfg = cfg or get_edr_config()
    try:
        async with _build_client(cfg) as client:
            resp = await client.get(f"/rest/api/3/issue/{issue_key}",
                                    params={"fields": "description"})
            resp.raise_for_status()
            desc = (resp.json().get("fields") or {}).get("description")
            return desc if isinstance(desc, dict) else None
    except Exception as exc:
        logger.error("get_description_adf(%s) failed: %s", issue_key, exc)
        return None


def _find_involved_users_row(adf: dict) -> Optional[list]:
    """Locate the description's `table` node and return the row (list of 2 cells)
    whose first cell reads "Involved User(s)", or None if there is no such table/row.

    Sentinel/MDE tickets carry the description as ONE `table` node of label/value row
    pairs (Incident description, Severity, IncidentURl, alertLink, Tactics, Alert
    Display Name, Involved Users, DLP Profile). Matching is on the LABEL text via
    `jira_poller._adf_to_text`, not by row position — row order is not a documented
    contract of the source system.
    """
    import re
    from edr_triage.jira_poller import _adf_to_text

    if not isinstance(adf, dict):
        return None
    table = None
    for node in adf.get("content") or []:
        if node.get("type") == "table":
            table = node
            break
    if table is None:
        return None
    label_re = re.compile(r"^\s*involved\s+users?\s*$", re.IGNORECASE)
    for row in table.get("content") or []:
        cells = row.get("content") or []
        # A label-only row is the NORMAL shape on a fresh ticket: the source system
        # emits "Involved Users" with no value cell at all, and the cell only appears
        # once an L1 types an address in (DEMO-115190 vs DEMO-114766). Requiring two cells
        # here made every untouched ticket look row-less, so every live chase aborted.
        if not cells:
            continue
        label = _adf_to_text(cells[0]).strip()
        if label_re.match(label):
            return row
    return None


async def get_involved_users_cell(
    issue_key: str,
    cfg: Optional[EDRTriageConfig] = None,
) -> Optional[str]:
    """Current text of the "Involved Users" value cell.

    Returns None when the description carries no such row at all (a source format
    `set_involved_users` cannot append to safely without guessing table shape) — as
    opposed to "" for a row that exists and is genuinely empty. Callers use this
    DISTINCTION to decide whether a chase can even be attempted, and — separately — to
    refuse to overwrite a cell an L1 or the SOAR already populated deliberately.
    """
    from edr_triage.jira_poller import _adf_to_text

    adf = await get_description_adf(issue_key, cfg)
    row = _find_involved_users_row(adf) if adf else None
    if row is None:
        return None
    cells = row.get("content") or []
    return _adf_to_text(cells[1]).strip() if len(cells) > 1 else ""


async def set_involved_users(
    issue_key: str,
    recipients: list[dict],
    cfg: Optional[EDRTriageConfig] = None,
    dry_run: bool = False,
) -> bool:
    """Write `recipients` (each {"email", "display_name"}) into the description's
    "Involved Users" value cell, as `mailto`-linked text nodes joined by plain ", ".

    Edits ONLY that one cell's `content` and PUTs the WHOLE description back — every
    other row and every other mark in the document must come back byte-identical, since
    an L1 may have hand-formatted the rest of the table. Refuses to run if the cell
    already holds text: use `get_involved_users_cell` first and treat a non-empty result
    as "leave it, something already populated this deliberately" — this function does
    not re-check, so calling it unconditionally would silently clobber that.
    """
    if dry_run:
        who = ", ".join(r.get("email", "") for r in recipients)
        logger.info("[DRY-RUN] set_involved_users %s: %s", issue_key, who)
        return True
    cfg = cfg or get_edr_config()
    adf = await get_description_adf(issue_key, cfg)
    if adf is None:
        logger.error("set_involved_users(%s): could not fetch description", issue_key)
        return False
    row = _find_involved_users_row(adf)
    if row is None:
        logger.error("set_involved_users(%s): no 'Involved Users' row in description — "
                     "refusing to guess a table shape to append one", issue_key)
        return False
    cells = row.get("content") or []
    if len(cells) < 2:
        # Fresh ticket: the row carries only its label. Add the value cell in the same
        # shape an L1's edit produces — the label cell's node type (tableHeader on SIM)
        # holding one paragraph — which is the shape the Security Bot has dispatched on.
        cells.append({"type": cells[0].get("type") or "tableHeader",
                      "content": [{"type": "paragraph", "content": []}]})
        row["content"] = cells

    content = []
    for i, r in enumerate(recipients):
        if i > 0:
            content.append({"type": "text", "text": ", "})
        content.append({
            "type": "text",
            "text": r.get("email", ""),
            "marks": [{"type": "link", "attrs": {"href": f"mailto:{r.get('email', '')}"}}],
        })
    cells[1]["content"] = [{"type": "paragraph", "content": content}]

    try:
        async with _build_client(cfg) as client:
            resp = await client.put(
                f"/rest/api/3/issue/{issue_key}",
                json={"fields": {"description": adf}},
            )
            if resp.status_code not in (200, 204):
                logger.error("set_involved_users(%s) HTTP %s: %s",
                             issue_key, resp.status_code, resp.text[:300])
                return False
            logger.info("Involved Users set on %s: %s",
                        issue_key, ", ".join(r.get("email", "") for r in recipients))
            return True
    except Exception as exc:
        logger.error("set_involved_users(%s) failed: %s", issue_key, exc)
        return False


async def last_status_author(
    issue_key: str,
    to_statuses: tuple[str, ...],
    cfg: Optional[EDRTriageConfig] = None,
) -> Optional[str]:
    """Email of whoever made the MOST RECENT transition into one of `to_statuses`.

    Needed wherever a terminal status must be attributed to a human rather than to
    RAPTOR. Status alone cannot tell them apart — both land on `False Positive` — and
    neither can the assignee, because the bot only takes ownership of UNASSIGNED
    tickets, so an autonomous close often leaves the L1 as assignee.

    Returns None when it cannot be established. Callers must treat None as "not known
    to be human", never as "human".
    """
    cfg = cfg or get_edr_config()
    wanted = {s.strip().lower() for s in to_statuses}
    try:
        async with _build_client(cfg) as client:
            resp = await client.get(f"/rest/api/3/issue/{issue_key}",
                                    params={"fields": "status", "expand": "changelog"})
            resp.raise_for_status()
            hist = (resp.json().get("changelog") or {}).get("histories") or []
    except Exception as exc:
        logger.error("last_status_author(%s) failed: %s", issue_key, exc)
        return None
    last: tuple[str, str] | None = None
    for h in hist:
        for it in h.get("items", []):
            if it.get("field") == "status" and (it.get("toString") or "").strip().lower() in wanted:
                ts = h.get("created", "")
                if last is None or ts > last[0]:
                    last = (ts, ((h.get("author") or {}).get("emailAddress") or "").lower())
    return last[1] if last and last[1] else None
