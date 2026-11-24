"""Jira poller — fetch new SIM tickets and filter to MDE-only using three signals."""
from __future__ import annotations

import logging
import re
from typing import Optional

import httpx

from edr_triage.config import EDRTriageConfig, get_edr_config

logger = logging.getLogger(__name__)

# ── Three-signal MDE ticket filter ──────────────────────────────────────────
# Signal 1: alertLink path is /alerts/ (not /incidents/)
_ALERT_LINK_RE = re.compile(r'security\.microsoft\.com/alerts/([^?&"\s\n]+)')
# Signal 2: description contains "Alert Display Name" field (no colon — newline-separated format)
_ALERT_DISPLAY_NAME_RE = re.compile(r'Alert\s+Display\s+Name', re.IGNORECASE)
# Signal 3: alert ID is at least 10 chars — alphanumeric+hyphens (UUID or legacy format)
# Exclude "sn" prefix — those are Sentinel-native alert IDs, not MDE
_MDE_ID_RE = re.compile(r'^(?!sn)[a-zA-Z0-9][a-zA-Z0-9_\-]{9,}$')

# Sentinel identity alert detection — IncidentURl present without an MDE alertLink
_SENTINEL_INCIDENT_URL_RE = re.compile(
    r'IncidentURl\s*[\n:]\s*(\S+Microsoft\.SecurityInsights/Incidents/[^\s]+)',
    re.IGNORECASE,
)

# Field extractors — Sentinel/MDE tickets use newline-separated label/value pairs
# e.g.  "Alert Display Name \nBlock Anydesk \n"
_NEWLINE_FIELD_RE = {
    "alert_name":   re.compile(r'Alert\s+Display\s+Name\s*\n([^\n]+)', re.IGNORECASE),
    "tactics":      re.compile(r'Tactics\s*\n([^\n]+)', re.IGNORECASE),
    "incident_url": re.compile(r'IncidentURl\s*\n(\S+)', re.IGNORECASE),
    "device":       re.compile(r'(?:Computer|Device|Machine)\s*[Nn]ame\s*\n([^\n]+)', re.IGNORECASE),
    "user":         re.compile(r'Involved\s+Users?\s*\n([^\n]+)', re.IGNORECASE),
}

# Known field label words — if a captured value looks like one of these it means
# the field was empty and the regex consumed the next label as the value.
_FIELD_LABEL_RE = re.compile(
    r'^(?:DLP\s+Profile|Alert\s+Display\s+Name|Tactics|IncidentURl|Involved\s+Users?|'
    r'Computer\s+Name|Device\s+Name|Machine\s+Name|Severity|Incident\s+description|alertLink)\s*$',
    re.IGNORECASE,
)
# Colon-separated fallback (older ticket format)
_COLON_FIELD_RE = {
    "alert_name":   re.compile(r'Alert\s+Display\s+Name\s*:\s*(.+)', re.IGNORECASE),
    "tactics":      re.compile(r'Tactics\s*:\s*(.+)', re.IGNORECASE),
    "incident_url": re.compile(r'IncidentURl?\s*:\s*(\S+)', re.IGNORECASE),
    "device":       re.compile(r'(?:Computer|Device|Machine)\s*[Nn]ame\s*:\s*(\S+)', re.IGNORECASE),
    "user":         re.compile(r'Involved\s+Users?\s*:\s*(.+)', re.IGNORECASE),
}


def parse_mde_alert_id(description: str) -> Optional[str]:
    """Return MDE alert ID if all 3 signals match, else None.

    None means the ticket is from Sentinel, Netskope, or another source
    and should be silently skipped (or handled as a Sentinel ticket).
    """
    m = _ALERT_LINK_RE.search(description or "")
    if not m:
        return None
    alert_id = m.group(1).strip()
    if not _ALERT_DISPLAY_NAME_RE.search(description):
        return None
    if not _MDE_ID_RE.match(alert_id):
        return None
    return alert_id


def parse_sentinel_incident_url(description: str) -> Optional[str]:
    """Return the Sentinel incident URL from a Jira description, or None.

    Detects tickets that are Sentinel-sourced identity alerts (no MDE alertLink)
    but contain an IncidentURl pointing to a SecurityInsights Incident.
    """
    m = _SENTINEL_INCIDENT_URL_RE.search(description or "")
    if m:
        return m.group(1).strip()
    # Also try the already-parsed _NEWLINE_FIELD_RE match as a fallback
    m2 = _NEWLINE_FIELD_RE["incident_url"].search(description or "")
    if m2:
        url = m2.group(1).strip()
        if "SecurityInsights/Incidents/" in url:
            return url
    return None


def parse_sentinel_alert_id(description: str) -> Optional[str]:
    """Return the Sentinel-native alert ID from the alertLink, or None.

    Sentinel alerts have an alertLink like security.microsoft.com/alerts/sn<guid>.
    parse_mde_alert_id deliberately EXCLUDES these (sn prefix); this returns exactly
    them — the id needed to look up the alert's OWN entities in the SecurityAlert
    table (SystemAlertId), instead of guessing from the grouped incident.
    """
    m = _ALERT_LINK_RE.search(description or "")
    if not m:
        return None
    aid = m.group(1).strip()
    return aid if aid.lower().startswith("sn") else None


# Upwind CNAPP detection tickets, raised by Upwind's own Jira integration (critical
# detections only). Format verified against DEMO-115057: summary
# "<Severity> Severity Upwind Detection | <title>", label "Upwind", and a description of
# "Label:" / value pairs where the value may sit on the same line or the next one
# depending on how the ADF paragraphs split. The detection id exists ONLY inside the
# console link (sidePanelItemId=uwd-...).
_UPWIND_SUMMARY_RE = re.compile(r'^\s*(?:\w+\s+severity\s+)?upwind\s+detection\s*\|\s*(.*)$',
                                re.IGNORECASE)
_UPWIND_CONSOLE_RE = re.compile(r'https?://console\.upwind\.io/\S+', re.IGNORECASE)
_UPWIND_DETECTION_ID_RE = re.compile(r'\b(uwd-[A-Za-z0-9]+)\b')
_UPWIND_FIELD_RE = {
    "title":          re.compile(r'^\s*Title:[ \t]*\n?[ \t]*(\S.*)$', re.IGNORECASE | re.MULTILINE),
    "detail":         re.compile(r'^\s*Description:[ \t]*\n?[ \t]*(\S.*)$', re.IGNORECASE | re.MULTILINE),
    "severity":       re.compile(r'^\s*Severity:[ \t]*\n?[ \t]*(\S.*)$', re.IGNORECASE | re.MULTILINE),
    "resource_name":  re.compile(r'^\s*Resource\s+name:[ \t]*\n?[ \t]*(\S.*)$', re.IGNORECASE | re.MULTILINE),
    "resource_kind":  re.compile(r'^\s*Resource\s+kind:[ \t]*\n?[ \t]*(\S.*)$', re.IGNORECASE | re.MULTILINE),
    "resource_path":  re.compile(r'^\s*Resource\s+path:[ \t]*\n?[ \t]*(\S.*)$', re.IGNORECASE | re.MULTILINE),
    "cloud_provider": re.compile(r'^\s*Cloud\s+Provider:[ \t]*\n?[ \t]*(\S.*)$', re.IGNORECASE | re.MULTILINE),
    "account_id":     re.compile(r'^\s*Cloud\s+Account\s+ID:[ \t]*\n?[ \t]*(\S.*)$', re.IGNORECASE | re.MULTILINE),
}
# A value that is itself the next label means the field was empty on the ticket.
_UPWIND_LABEL_LINE_RE = re.compile(
    r'^(?:Title|Description|Severity|Link|Resource\s+(?:name|kind|path|details)|'
    r'Cloud\s+Provider|Cloud\s+Account\s+ID|Affected\s+Resource|Detection\s+Details):?\s*$',
    re.IGNORECASE,
)


def is_upwind_ticket(summary: str, labels: list | None, description: str) -> bool:
    if any(str(l).strip().lower() == "upwind" for l in (labels or [])):
        return True
    if _UPWIND_SUMMARY_RE.match(summary or ""):
        return True
    return bool(_UPWIND_CONSOLE_RE.search(description or ""))


def parse_upwind_ticket(summary: str, description: str) -> dict:
    """Extract the Upwind detection fields. Missing fields are omitted, never guessed."""
    text = description or ""
    out: dict = {}
    for field, rx in _UPWIND_FIELD_RE.items():
        m = rx.search(text)
        if m:
            val = m.group(1).strip()
            if val and not _UPWIND_LABEL_LINE_RE.match(val):
                out[field] = val
    link = _UPWIND_CONSOLE_RE.search(text)
    if link:
        out["link"] = link.group(0).rstrip(").,;")
        det = _UPWIND_DETECTION_ID_RE.search(out["link"])
        if det:
            out["detection_id"] = det.group(1)
    if not out.get("title"):
        m = _UPWIND_SUMMARY_RE.match(summary or "")
        if m and m.group(1).strip():
            out["title"] = m.group(1).strip()
    parts = [p.strip() for p in out.get("resource_path", "").split("|")]
    if len(parts) >= 3 and parts[1]:
        out["environment"] = parts[1]
    return out


def build_upwind_ticket(key: str, fields: dict, description: str,
                        existing_comments: str = "") -> Optional[dict]:
    """The pipeline ticket dict for an Upwind detection ticket, or None if it isn't one.

    Shared by the poller, manual run-ticket and dependent re-triage so all three see
    the same ticket. Dedup stays per TICKET (alert_id = jira_key), not per uwd- id:
    claim_alert skips an already-claimed id with no Jira action at all, so keying on the
    detection id would leave a second ticket for the same detection silently untouched.
    """
    summary = fields.get("summary", "") or ""
    if not is_upwind_ticket(summary, fields.get("labels"), description):
        return None
    uw = parse_upwind_ticket(summary, description)
    return {
        "jira_key":     key,
        "alert_id":     key,
        "alert_name":   f"Upwind Detection | {uw.get('title') or summary}",
        "description":  description,
        "created_at":   fields.get("created", ""),
        # Upwind's own rating first: the Jira priority can be edited after creation
        # (DEMO-115057 went Critical -> Medium while Upwind still said CRITICAL), and
        # severity feeds the never-auto-close-CRITICAL gate.
        "severity":     uw.get("severity", "").title()
                        or (fields.get("priority") or {}).get("name", ""),
        "tactics":      "",
        "device_name":  uw.get("resource_name", ""),
        "user_name":    "",
        "is_sentinel":  False,
        "observe_only": False,
        "is_upwind":    True,
        "upwind":       uw,
        "existing_comments": existing_comments,
    }


def parse_description_fields(description: str) -> dict:
    """Extract structured fields from an MDE Jira ticket description.

    Tries newline-separated format first (current MDE auto-sync format),
    then falls back to colon-separated (older tickets).
    """
    result: dict = {}
    text = description or ""
    for field in _NEWLINE_FIELD_RE:
        m = _NEWLINE_FIELD_RE[field].search(text)
        if m:
            val = m.group(1).strip()
            if not _FIELD_LABEL_RE.match(val):
                result[field] = val
        else:
            m2 = _COLON_FIELD_RE[field].search(text)
            if m2:
                result[field] = m2.group(1).strip()
    return result


def _build_client(cfg: EDRTriageConfig) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=cfg.jira_url.rstrip("/"),
        auth=httpx.BasicAuth(cfg.jira_email or "", cfg.jira_token or ""),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=20.0,
        verify=cfg.jira_verify_ssl,
    )


# 10 x 100 tickets per poll; the 6h window normally matches well under one page.
_MAX_POLL_PAGES = 10


async def poll_new_mde_tickets(cfg: Optional[EDRTriageConfig] = None) -> list[dict]:
    """Poll Jira for new SIM tickets and return only MDE alert tickets.

    Each returned dict contains:
        jira_key, alert_id, alert_name, description, created_at, severity, tactics
    """
    cfg = cfg or get_edr_config()

    if not all([cfg.jira_email, cfg.jira_token]):
        logger.warning("Jira credentials not configured — EDR poller skipping")
        return []
    # An empty base_url makes every request raise UnsupportedProtocol, which the
    # except-block below turns into "0 tickets" — indistinguishable from a quiet
    # queue. Fail loudly instead (this silently stopped triage for ~2 days).
    if not cfg.jira_url:
        logger.error("JIRA_URL is not configured — EDR poller cannot reach Jira; "
                     "no tickets will be triaged. Set JIRA_URL.")
        return []

    jql = (
        f'project = "{cfg.jira_project_key}" '
        f'AND status in ("Open", "Assigned", "L2 Analysis Required", "Awaiting more inputs") '
        f'AND created >= -{cfg.jira_lookback_hours}h '
        f'ORDER BY created ASC'
    )

    try:
        async with _build_client(cfg) as client:
            # Page until isLast/no token. One 100-row page, oldest first, meant that any
            # time more than 100 tickets matched (a DLP burst: 70 in one hour on
            # 2026-09-29), the NEWEST tickets fell off the end; if an analyst moved one
            # out of these statuses before the queue drained, RAPTOR never saw it.
            # Hard page cap so a pathological window can't spin forever.
            issues: list[dict] = []
            next_token: str | None = None
            for _ in range(_MAX_POLL_PAGES):
                params = {
                    "jql":        jql,
                    "fields":     "summary,description,created,priority,labels,comment",
                    "maxResults": "100",
                }
                if next_token:
                    params["nextPageToken"] = next_token
                resp = await client.get("/rest/api/3/search/jql", params=params)
                resp.raise_for_status()
                page = resp.json()
                issues.extend(page.get("issues", []))
                next_token = page.get("nextPageToken")
                if page.get("isLast") or not next_token:
                    break
            else:
                logger.warning("Jira poll hit the %d-page cap (%d tickets) — the newest "
                               "tickets in the window were not fetched this cycle",
                               _MAX_POLL_PAGES, len(issues))
    except Exception as exc:
        logger.error("Jira poll failed: %s", exc)
        return []

    from edr_triage.jira_closure_poller import _extract_all_comments

    mde_tickets = []
    for issue in issues:
        key = issue.get("key", "")
        fields = issue.get("fields", {})

        # Extract plain text from the ADF description
        desc_raw = fields.get("description") or {}
        description = _adf_to_text(desc_raw) if isinstance(desc_raw, dict) else str(desc_raw or "")

        # Analyst notes ALREADY on the ticket (a re-swept "Awaiting more inputs" or
        # "L2 Analysis Required" ticket, not a brand-new one) — L1/L2 frequently type
        # out the exact field-level diff by hand (DEMO-108035: Subodh Okafor posted the
        # full policy change — Policy/Result/Change Detected/Current Applications/
        # Current Users — none of which the agent ever saw, because only `description`
        # was ever fetched). Passed through as context; oscar.py decides how to weigh it.
        existing_comments, _, _ = _extract_all_comments(fields, bot_email=cfg.jira_email or "")

        # Opened by /shadow for a Claude-confirmed TP (shadow_hunter/tickets.py): already
        # investigated and already paged, so RAPTOR neither triages nor pages it again.
        if any(str(l).strip().lower() == "deepintel-shadow" for l in (fields.get("labels") or [])):
            logger.debug("[skip] %s — opened by /shadow", key)
            continue

        alert_id = parse_mde_alert_id(description)
        parsed = parse_description_fields(description)

        if not alert_id:
            alert_name = parsed.get("alert_name", fields.get("summary", ""))
            upwind_ticket = build_upwind_ticket(key, fields, description, existing_comments)
            if upwind_ticket:
                logger.info("[upwind] %s → detection=%s resource=%s", key,
                            upwind_ticket["upwind"].get("detection_id", "?"),
                            upwind_ticket["device_name"] or "?")
                mde_tickets.append(upwind_ticket)
                continue
            sentinel_url = parse_sentinel_incident_url(description)
            if sentinel_url:
                logger.info("[sentinel] %s → Sentinel incident alert_name='%s'", key, alert_name)
                mde_tickets.append({
                    "jira_key":     key,
                    "alert_id":     key,
                    "alert_name":   alert_name,
                    "description":  description,
                    "created_at":   fields.get("created", ""),
                    "severity":     (fields.get("priority") or {}).get("name", ""),
                    "tactics":      parsed.get("tactics", ""),
                    "device_name":  parsed.get("device", ""),
                    "user_name":    parsed.get("user", ""),
                    "incident_url": sentinel_url,
                    "sentinel_alert_id": parse_sentinel_alert_id(description) or "",
                    "is_sentinel":  True,
                    "existing_comments": existing_comments,
                })
            else:
                # Non-MDE, non-Sentinel ticket — include for passive observation only
                logger.debug("[observe] %s — non-MDE/Sentinel ticket, queuing for observation", key)
                mde_tickets.append({
                    "jira_key":        key,
                    "alert_id":        key,
                    "alert_name":      alert_name,
                    "description":     description,
                    "created_at":      fields.get("created", ""),
                    "severity":        (fields.get("priority") or {}).get("name", ""),
                    "tactics":         "",
                    "device_name":     "",
                    "user_name":       "",
                    "observe_only":    True,  # pipeline will log + skip, no Jira actions
                    "existing_comments": existing_comments,
                })
            continue

        mde_tickets.append({
            "jira_key":    key,
            "alert_id":    alert_id,
            "alert_name":  parsed.get("alert_name", fields.get("summary", "")),
            "description": description,
            "created_at":  fields.get("created", ""),
            "severity":    (fields.get("priority") or {}).get("name", ""),
            "tactics":     parsed.get("tactics", ""),
            "device_name": parsed.get("device", ""),
            "user_name":   parsed.get("user", ""),
            "incident_url": parsed.get("incident_url", ""),
            "existing_comments": existing_comments,
        })
        logger.info("[match] %s → MDE alert_id=%s", key, alert_id)

    logger.info("Jira poll: %d tickets fetched, %d MDE/Sentinel alerts identified", len(issues), len(mde_tickets))
    return mde_tickets


def adf_to_marked_text(adf: dict) -> str:
    """ADF back to the wiki markup RAPTOR posted: a code run as `x`, a strong run as *x*,
    a paragraph's inline runs joined on one line, a list item indented.

    _adf_to_text drops every mark and puts each inline run on its own line. Since comments
    started arriving as real formatting (mid-October), RAPTOR's own evidence records read
    back as "Device:\\n host" with the command backticks gone, so the PowerShell and Root
    Privesc precedent parsers matched nothing and human FP closes stopped counting
    (DEMO-117178/117953: the same cleared script asked about again and again). Read with
    this, a record parses exactly as it was written, and each command stays one command
    even when it spans lines."""
    if not adf or not isinstance(adf, dict):
        return ""
    t = adf.get("type")
    if t == "text":
        s = adf.get("text", "")
        marks = {m.get("type") for m in (adf.get("marks") or []) if isinstance(m, dict)}
        if "code" in marks:
            s = f"`{s}`"
        if "strong" in marks:
            s = f"*{s}*"
        return s
    if t == "hardBreak":
        return "\n"
    if t in ("mention", "emoji", "inlineCard", "status", "date"):
        a = adf.get("attrs") or {}
        return str(a.get("text") or a.get("shortName") or a.get("url") or "")
    kids = adf.get("content") or []
    if t in ("paragraph", "heading", "codeBlock"):
        return "".join(adf_to_marked_text(k) for k in kids)
    inner = "\n".join(p for p in (adf_to_marked_text(k) for k in kids) if p)
    if t == "listItem":
        return "\n".join("  " + ln for ln in inner.split("\n"))
    return inner


def _adf_to_text(adf: dict) -> str:
    """Recursively extract plain text from an Atlassian Document Format node."""
    if not adf or not isinstance(adf, dict):
        return ""
    if adf.get("type") == "text":
        return adf.get("text", "")
    parts = []
    for child in adf.get("content", []):
        parts.append(_adf_to_text(child))
    return "\n".join(p for p in parts if p)
