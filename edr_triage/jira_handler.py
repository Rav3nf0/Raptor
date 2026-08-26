"""Jira action handler — post comments, transition tickets, set labels/category."""
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
    """Post a wiki-markup comment to a Jira issue."""
    if dry_run:
        logger.info("[DRY-RUN] add_comment %s:\n%s", issue_key, wiki_text[:300])
        return True
    cfg = cfg or get_edr_config()
    if not all([cfg.jira_email, cfg.jira_token]):
        return False
    try:
        async with _build_client(cfg) as client:
            resp = await client.post(
                f"/rest/api/3/issue/{issue_key}/comment",
                json={"body": _wiki_to_adf(wiki_text)},
            )
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
            existing = [lbl["name"] for lbl in (get_resp.json().get("fields", {}).get("labels") or [])]
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
    """Set the Category custom field on a Jira issue.

    The field name used by the SIM project is 'category' — adjust the
    customfield_XXXXX ID if your Jira instance uses a numeric field ID.
    """
    if dry_run:
        logger.info("[DRY-RUN] set_category %s: %s", issue_key, category_value)
        return True
    cfg = cfg or get_edr_config()
    try:
        async with _build_client(cfg) as client:
            # First resolve the field ID for 'category' if not hardcoded
            resp = await client.put(
                f"/rest/api/3/issue/{issue_key}",
                json={"fields": {"category": {"value": category_value}}},
            )
            if resp.status_code in (200, 204):
                logger.info("Category set on %s: %s", issue_key, category_value)
                return True
            # Fallback: try as a plain string (some Jira configs use text fields)
            resp2 = await client.put(
                f"/rest/api/3/issue/{issue_key}",
                json={"fields": {"category": category_value}},
            )
            resp2.raise_for_status()
            logger.info("Category set (plain) on %s: %s", issue_key, category_value)
            return True
    except Exception as exc:
        logger.error("set_category(%s, %s) failed: %s", issue_key, category_value, exc)
        return False
