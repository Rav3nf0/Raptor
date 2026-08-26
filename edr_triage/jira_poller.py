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
            resp = await client.get(
                "/rest/api/3/search/jql",
                params={
                    "jql":        jql,
                    "fields":     "summary,description,created,priority,labels,comment",
                    "maxResults": "100",
                },
            )
            resp.raise_for_status()
            issues = resp.json().get("issues", [])
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
        # out the exact field-level diff by hand (e.g. the full policy change:
        # Policy/Result/Change Detected/Current Applications/Current Users), none of
        # which the agent ever saw, because only `description` was ever fetched.
        # Passed through as context; oscar.py decides how to weigh it.
        existing_comments, _, _ = _extract_all_comments(fields, bot_email=cfg.jira_email or "")

        alert_id = parse_mde_alert_id(description)
        parsed = parse_description_fields(description)

        if not alert_id:
            alert_name = parsed.get("alert_name", fields.get("summary", ""))
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
