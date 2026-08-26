"""Generic / fallback playbook.

Used for:
  - Unrecognised alert types
  - Root Privesc / suspicious PowerShell (privesc classifier)
  - "No threats found" investigation state (auto-close as FP)
"""
from __future__ import annotations

import re

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult

# AWS CloudTrail / SSM / GuardDuty field parsers — colon-separated in Jira description
_AWS_RE = {
    "device_name":    re.compile(r'Device\s+Name\s*:\s*(.+)', re.IGNORECASE),
    "time_generated": re.compile(r'Time\s+Generated\s*(?:\([^)]*\))?\s*:\s*(.+)', re.IGNORECASE),
    "account_name":   re.compile(r'Account\s+Name\s*:\s*(.+)', re.IGNORECASE),
    "event_name":     re.compile(r'Event\s+Name\s*:\s*(.+)', re.IGNORECASE),
    "instance_id":    re.compile(r'Instance\s+ID\s*:\s*(\S+)', re.IGNORECASE),
    "session_issuer": re.compile(r'Session\s+Issuer\s+User\s+Name\s*:\s*(.+)', re.IGNORECASE),
    "user_arn":       re.compile(r'User\s+Identity\s+ARN\s*:\s*(.+)', re.IGNORECASE),
    "command":        re.compile(r'Initiating\s+Command\s*:\s*(.+)', re.IGNORECASE),
    "source_ip":      re.compile(r'(?:IP\s+[Aa]ddress|Source\s+IP|ipAddressV4)\s*[:\s]*(\d{1,3}(?:\.\d{1,3}){3})', re.IGNORECASE),
    "user_name":      re.compile(r'(?:User\s+Name|userName)\s*:\s*(\S+)', re.IGNORECASE),
    "access_key_id":  re.compile(r'(?:Access\s*Key\s*ID|accessKeyId)\s*:\s*(\S+)', re.IGNORECASE),
    "guardduty_link": re.compile(r'(?:FindingLink|Finding\s+Link)\s*:\s*(https?://\S+)', re.IGNORECASE),
}


_NOISE_CMD_PREFIXES = (
    "/usr/lib/systemd/systemd ",
    "/bin/sh /usr/lib/systemd/system-generators/",
    "/bin/sh /usr/lib/cloud-init/",
    "/bin/sh /etc/update-motd.d/",
    "/usr/lib/systemd/systemd-executor",
    "/usr/sbin/cron",
    "/usr/lib/postfix/sbin/master",
    "/snap/amazon-ssm-agent/",
)

# Max commands to surface (in the Jira comment and the LLM prompt). These alerts
# often carry a host's whole semicolon-joined command history; listing all of it
# buries the privesc-relevant action in routine ops noise and bloats the prompt.
_MAX_CMDS = 12


def _clean_commands(raw: str) -> list[str]:
    """Deduplicate and strip OS/systemd noise from a semicolon-separated command string."""
    seen: set[str] = set()
    result: list[str] = []
    for cmd in raw.split(";"):
        cmd = cmd.strip()
        if not cmd:
            continue
        if any(cmd.startswith(p) for p in _NOISE_CMD_PREFIXES):
            continue
        if cmd in seen:
            continue
        seen.add(cmd)
        result.append(cmd)
    return result


def _arn_session_user(arn: str) -> str:
    """Extract the session principal from an assumed-role ARN.

    arn:aws:sts::123:assumed-role/role-name/user@company.com → user@company.com
    """
    if not arn or "assumed-role/" not in arn:
        return ""
    parts = arn.split("/")
    return parts[-1] if len(parts) >= 3 else ""


def _is_service_account(name: str) -> bool:
    """Heuristic: does this principal look like a non-interactive service/automation account?

    Covers Windows service principals (NT SERVICE\\…, NT AUTHORITY\\…), machine accounts
    (trailing $), well-known SIDs, and common naming (svc-, Exchange AdminApi). Used to
    add benign-automation context to the L1 comment — NOT to auto-close on its own.
    """
    n = (name or "").strip().lower()
    if not n:
        return False
    return (
        n.startswith("nt service\\") or n.startswith("nt authority\\")
        or n.endswith("$") or n.startswith("s-1-5-")
        or "svc-" in n or n.startswith("svc") or "adminapi" in n
        or "msexchange" in n or "healthmailbox" in n
    )


def _additional_hosts_lines(aws: dict) -> list[str]:
    """Render the OTHER hosts of a grouped incident (device / instance / issuer /
    ARN / command) — a grouped root-privesc alert bundles several SSM sessions and
    L1 documents each one; the primary host is rendered inline above this."""
    # isinstance guard: same malformed-row shape already fixed at the source in
    # pipeline.py — guard here too since this reads the RAW additional_hosts rows
    # independently, before that filtering necessarily runs.
    extra = [e for e in ((aws or {}).get("additional_hosts") or []) if isinstance(e, dict)]
    if not extra:
        return []
    lines = ["", f"*Other hosts in this incident ({len(extra)}):*"]
    for h in extra[:_MAX_CMDS]:
        hdr = " · ".join(p for p in (
            h.get("device_name", ""),
            h.get("instance_id", ""),
            (f"issuer {h['session_issuer']}" if h.get("session_issuer") else ""),
        ) if p) or "host"
        lines.append(f"  • {hdr}")
        for c in (h.get("command_lines") or ([h["command"]] if h.get("command") else []))[:3]:
            lines.append(f"      `{c}`")
        if h.get("user_arn"):
            lines.append(f"      ARN: {h['user_arn']}")
    if len(extra) > _MAX_CMDS:
        lines.append(f"  _… {len(extra) - _MAX_CMDS} more hosts_")
    return lines


def _process_check_lines(evidence: dict | None) -> list[str]:
    """Compact Jira-comment rendering of the deterministic service-process check."""
    pc = (evidence or {}).get("process_check")
    if not pc or not pc.get("distinct"):
        return []
    from edr_triage.service_allowlist import summarize_check
    # summarize_check already names the unknowns — keep it to one line (no duplicate).
    return ["", f"*Service-process check:* {summarize_check(pc)}"]


def _parse_aws_fields(description: str) -> dict:
    result = {}
    for key, pat in _AWS_RE.items():
        m = pat.search(description or "")
        if m:
            result[key] = m.group(1).strip()
    return result


_CLOUDTRAIL_ANALYSIS_PROMPT = """\
You are a senior cloud security analyst at a financial services company (ExampleCorp).
Analyse the following AWS CloudTrail / GuardDuty alert and determine whether it represents
a genuine threat or legitimate authorized activity.

Alert context:
- Alert Name: {alert_name}
- Device Name: {device_name}
- Account Name: {account_name}
- Event Name: {event_name}
- Instance ID: {instance_id}
- Session Issuer (IAM Role): {session_issuer}
- User Identity ARN: {user_arn}
- IAM Role / User Name: {user_name}
- Access Key ID: {access_key_id}
- Source IP: {source_ip}
- IP Geolocation: {ip_geo}
- Session MFA: {mfa_status}
- Time Generated (UTC): {time_generated}

Commands executed:
{commands}

Respond ONLY with valid JSON in this exact schema:
{{
  "verdict": "BENIGN" | "SUSPICIOUS" | "NEEDS_REVIEW",
  "reasoning": "<step-by-step explanation of your verdict in 3-4 sentences max>",
  "reasons": ["<concise reason 1>", "<concise reason 2>", ...],
  "recommendation": "<one sentence on what the analyst should do next>"
}}

Guidelines:
- BENIGN: activity is clearly authorized (e.g. DBA running DB maintenance on a test/restore node, read-only config checks, known backup tools like Percona PBM).
- SUSPICIOUS: alert name mentions Kali Linux / penetration testing tool; external residential IP (non-corporate); MFA disabled for the session; commands include network exfiltration, credential dumping, reverse shells, or persistence mechanisms; role does not match the operation.
- NEEDS_REVIEW: ambiguous — production host, unusual role, or commands that could be legitimate but warrant confirmation.
- Be specific in reasons — mention the alert name, source IP, role name, and command patterns by name.
- Keep "reasoning" to 3-4 sentences — explain the key signals that drove your verdict.
- Do not invent information not present in the context.
- PRECEDENT IS NOT A VERDICT: never output BENIGN or recommend auto-closing solely because
  similar alerts were previously False Positive — especially when those priors are on a
  DIFFERENT device/user/role. A prior FP corroborates only when it is the SAME device or user
  AND the current commands/role/IP match; otherwise ignore it and judge this event on its own.
- Do NOT recommend closing "without further investigation" for privilege-escalation / root-session
  alerts. If this event's OWN evidence isn't clearly benign and the only benign signal is prior
  FPs, output NEEDS_REVIEW and request business justification — do not auto-close.
- Only cite a prior decision as FP if the context explicitly says it was closed False Positive;
  do not assume an escalated ("Needs L2") precedent was a False Positive.
"""

_FALLBACK_BENIGN_CMDS = {"pbm", "mongod", "mongo", "systemctl", "docker", "cat ", "vi "}
_FALLBACK_SUSPICIOUS_CMDS = {"curl ", "wget ", " nc ", "bash -i", "/dev/tcp", "/etc/shadow",
                              "authorized_keys", "crontab", "base64 -d", "chmod +x"}


def _rule_based_analyze(aws: dict) -> tuple[str, list[str], str, str]:
    """Simple rule-based fallback used when no local LLM is configured."""
    device     = (aws.get("device_name") or "").lower()
    role       = (aws.get("session_issuer") or aws.get("user_name") or "").lower()
    cmds       = [c.strip().lower() for c in (aws.get("command") or "").split(";") if c.strip()]
    alert_name = (aws.get("alert_name") or "").lower()
    source_ip  = aws.get("source_ip", "")

    reasons = []

    # GuardDuty / Kali Linux detection — immediately SUSPICIOUS
    is_kali    = any(t in alert_name for t in ("kali", "pentest", "pen test", "penetration"))
    mfa_status = (aws.get("mfa_status") or "").upper()
    ip_geo     = aws.get("ip_geo", "")
    if is_kali:
        reasons.append("Alert name indicates Kali Linux / penetration tool activity.")
        if source_ip:
            geo = f" ({ip_geo})" if ip_geo else ""
            reasons.append(f"Activity originated from external IP {source_ip}{geo}.")
        if mfa_status == "DISABLED":
            reasons.append("MFA was disabled for this session.")
        return "SUSPICIOUS", reasons, "Escalate to L2 immediately — Kali Linux tool detected.", ""

    is_test = any(t in device for t in ("test-", "staging", "restore", "dev-", "-dev"))
    is_dba  = any(t in role for t in ("dba", "database", "db-"))
    sus     = [c for c in cmds if any(t in c for t in _FALLBACK_SUSPICIOUS_CMDS)]

    if is_test:
        reasons.append(f"Device '{aws.get('device_name')}' matches test/staging naming.")
    if is_dba:
        reasons.append(f"Session via scoped DBA role '{aws.get('session_issuer') or aws.get('user_name')}'.")
    if sus:
        reasons.append(f"Potentially suspicious commands: {', '.join(sus[:3])}")

    if sus:
        return "SUSPICIOUS", reasons, "Escalate to L2 for immediate review.", ""
    if is_dba:
        return "BENIGN", reasons, "Confirm business justification and close as False Positive if confirmed.", ""
    return "NEEDS_REVIEW", reasons, "Please provide business justification for this activity.", ""


async def _llm_analyze_cloudtrail(aws: dict) -> tuple[str, list[str], str, str]:
    """Analyse a CloudTrail alert using the local LLM (Ollama) only.

    Sensitive EDR data (device names, user ARNs, instance IDs, commands) must
    never leave the company infrastructure — Gemini is explicitly not used here.
    Falls back to rule-based analysis if Ollama is not configured.

    Returns (verdict, reasons, recommendation).
    """
    import json as _json
    import os

    llm_backend = os.getenv("LLM_BACKEND", "ollama").lower()
    llm_url     = os.getenv("LOCAL_LLM_URL", "http://localhost:11434")

    if llm_backend != "ollama" or not llm_url:
        return _rule_based_analyze(aws)

    raw_cmds  = aws.get("command") or ""
    cmds      = _clean_commands(raw_cmds)
    _total    = len(cmds)
    cmds      = cmds[:_MAX_CMDS]
    cmd_block = "\n".join(f"  {c}" for c in cmds) if cmds else "  (none recorded)"
    if _total > _MAX_CMDS:
        cmd_block += f"\n  … {_total - _MAX_CMDS} more routine commands suppressed"

    # Query SCG for prior analyst decisions on this device/user and alert type.
    # This teaches the LLM from accumulated L1 institutional knowledge.
    prior_context = ""
    try:
        from entity_graph.query import get_multi_entity_context, get_playbook_memories
        from edr_triage.classifier import classify as _classify
        alert_type = _classify(aws.get("alert_name", ""))
        entity_ctx = await get_multi_entity_context([
            ("device", aws.get("device_name", "")),
            ("user",   aws.get("user_name", "")),
            ("ip",     aws.get("source_ip", "")),
        ])
        playbook_mems = await get_playbook_memories(alert_type, limit=3)
        parts = []
        if entity_ctx and "No prior context" not in entity_ctx:
            parts.append(f"Entity history:\n{entity_ctx}")
        if playbook_mems:
            lines = [f"  - [{m['tier']}|conf={m['confidence']}] {m['content']}" for m in playbook_mems]
            parts.append("Prior L1 decisions for '{}' alerts:\n{}".format(alert_type, "\n".join(lines)))
        if parts:
            prior_context = "\n\n".join(parts)
    except Exception:
        pass  # never block triage due to SCG unavailability

    prompt = _CLOUDTRAIL_ANALYSIS_PROMPT.format(
        alert_name     = aws.get("alert_name") or "Unknown",
        device_name    = aws.get("device_name") or "Unknown",
        account_name   = aws.get("account_name") or "Unknown",
        event_name     = aws.get("event_name") or "Unknown",
        instance_id    = aws.get("instance_id") or "Unknown",
        session_issuer = aws.get("session_issuer") or "Unknown",
        user_arn       = aws.get("user_arn") or "Unknown",
        user_name      = aws.get("user_name") or "Unknown",
        access_key_id  = aws.get("access_key_id") or "Unknown",
        source_ip      = aws.get("source_ip") or "Unknown",
        ip_geo         = aws.get("ip_geo") or "Unknown",
        mfa_status     = aws.get("mfa_status") or "Unknown",
        time_generated = aws.get("time_generated") or "Unknown",
        commands       = cmd_block,
    )
    if prior_context:
        prompt = (
            "=== PRIOR CONTEXT — reference only, do NOT let this shortcut your investigation ===\n"
            "These are past decisions for this ALERT TYPE, mostly on OTHER devices/users. A prior\n"
            "False Positive on a DIFFERENT device/user/role is a WEAK signal and does NOT make this\n"
            "alert benign on its own. Base your verdict on THIS event's own evidence (session role,\n"
            "commands, source IP, MFA). Treat a prior FP as strong corroboration ONLY when it is the\n"
            "SAME device or user as this alert.\n"
            + prior_context
            + "\n=== END PRIOR CONTEXT ===\n\n"
            + prompt
        )

    model = os.getenv("LOCAL_LLM_MODEL", "deepseek-r1:8b")
    url   = llm_url.rstrip("/") + "/v1/chat/completions"

    import logging as _logging
    _log = _logging.getLogger(__name__)
    _log.info("[LLM] attempting Ollama call: url=%s model=%s alert=%s", url, model, aws.get("alert_name", "?"))

    try:
        import httpx
        async with httpx.AsyncClient(timeout=600.0) as client:
            resp = await client.post(url, json={
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a security analyst. "
                            "Respond only with valid JSON — no explanation, no markdown, no thinking blocks."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
            })
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"].strip()
            # DeepSeek-R1: thinking exposed as separate field; content may still have <think> tags
            if "</think>" in raw:
                raw = raw.split("</think>", 1)[-1].strip()
            import re as _re
            # Strip markdown code fences (```json ... ```)
            raw = _re.sub(r"^```(?:json)?\s*", "", raw, flags=_re.MULTILINE).strip()
            raw = _re.sub(r"```\s*$", "", raw, flags=_re.MULTILINE).strip()
            # Remove trailing commas before } or ] (model sometimes emits invalid JSON)
            raw = _re.sub(r",\s*([}\]])", r"\1", raw)
            # Extract first {...} block — handles prose before/after the JSON object
            m = _re.search(r"\{.*\}", raw, _re.DOTALL)
            if m:
                raw = m.group(0)
            data           = _json.loads(raw)
            verdict        = data.get("verdict", "NEEDS_REVIEW").upper()
            reasoning      = (data.get("reasoning") or "").strip()
            reasons        = data.get("reasons") or []
            recommendation = data.get("recommendation", "")
            if verdict not in ("BENIGN", "SUSPICIOUS", "NEEDS_REVIEW"):
                verdict = "NEEDS_REVIEW"
            _log.info("[LLM] Ollama verdict: %s | alert=%s", verdict, aws.get("alert_name", "?"))
            return verdict, reasons, recommendation, reasoning
    except Exception as exc:
        _log.warning("[LLM] Ollama call FAILED: %s | url=%s — falling back to rule-based", exc, url)
        try:
            _log.debug("[LLM] raw response was: %.500s", raw)
        except Exception:
            pass
        return _rule_based_analyze(aws)


class GenericPlaybook(BasePlaybook):

    def __init__(self, playbook_type: str = "generic") -> None:
        self._type = playbook_type  # "generic" | "privesc" | "no_threat"

    async def run(
        self,
        jira_key: str,
        alert: dict,
        evidence: dict,
        vt: dict,
        timeline: list[dict],
        is_test_device: bool = False,
        sentinel_entities: dict | None = None,
        normalized=None,
    ) -> PlaybookResult:
        from edr_triage.normalized import normalize_alert
        # NB: only the common MDE header fields are normalized here; the AWS/CloudTrail
        # branch below still reads the vendor-specific `aws`/sentinel_entities dicts.
        n = normalized or normalize_alert(alert, evidence, sentinel_entities)
        device     = n.device
        user       = n.user
        alert_name = n.name
        inv_state  = n.investigation_state
        alert_time = n.alert_time
        sev        = n.severity

        file_name = n.file_name
        file_path = n.file_path
        sha256    = n.sha256
        init_proc = n.initiating_process

        # ── Rule-replay evidence (Sentinel scheduled/NRT alert with empty
        #    entities, enriched by re-running the triggering analytics rule) ──
        rr = (sentinel_entities or {}).get("rule_replay") or {}
        if rr and rr.get("fields"):
            rr_device = rr.get("device_name") or device
            rr_user   = rr.get("account_name") or user
            lines = [
                "Hi Team,",
                "",
                f"We have observed a *{alert_name}* alert."
                + (f" (host *{rr_device}*)" if rr_device and rr_device != "Unknown Device" else ""),
                "",
                f"Evidence recovered by re-running the detection rule "
                f"*{rr.get('rule_name') or alert_name}* over the alert window:",
            ]
            if rr_user:               lines.append(f"*User:* {rr_user}")
            if rr.get("operation"):   lines.append(f"*Operation:* {rr['operation']}")
            if rr.get("source_ip"):   lines.append(f"*Source IP:* {rr['source_ip']}")
            if rr.get("command"):     lines.append(f"*Command:* `{rr['command']}`")
            if alert_time:            lines.append(f"*Event time (UTC):* {alert_time}")
            if rr.get("row_count", 0) > 1:
                lines.append(f"_Matched {rr['row_count']} events in the window"
                             + (f"; distinct users: {', '.join(rr['distinct_users'])}_" if rr.get("distinct_users") else "_"))
            # Key row fields (compact).
            _shown = {k: v for k, v in rr["fields"].items()
                      if k not in ("Operation", "EventName", "ActionType")}
            if _shown:
                lines.append("")
                lines.append("*Details:*")
                for k, v in list(_shown.items())[:12]:
                    lines.append(f"  • {k}: {v}")
            # Benign download-source hint (reuse endpoint_process known-good list).
            urls = rr.get("remote_urls") or []
            if urls:
                from edr_triage.playbooks.endpoint_process import _KNOWN_GOOD_DOMAINS, _domain
                good = [u for u in urls if any(_domain(u).endswith(d) for d in _KNOWN_GOOD_DOMAINS)]
                lines += ["", f"*Download source{'s' if len(urls) > 1 else ''}:* " + ", ".join(urls[:5])]
                if len(good) == len(urls):
                    lines.append("↳ All sources on known-good domains — consistent with legitimate tooling.")
            lines += _process_check_lines(evidence)
            lines += [
                "",
                "Recommendation: review the recovered evidence above. Escalating to L2 — "
                "confirm the actor/operation is expected; close as False Positive if it maps "
                "to known service/automation activity.",
                "",
                "[Auto-triaged by RAPTOR]",
            ]
            return PlaybookResult(
                l1_comment="\n".join(lines),
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai", "rule-replay"],
                auto_close=False,
            )

        # ── Sentinel alert-entity binding (Microsoft-Security / MCAS / Office
        #    365 alerts with no compressedRec and no re-runnable KQL rule — the
        #    actor/device come straight from the alert's own entities) ─────────
        sa = (sentinel_entities or {}).get("sentinel_alert") or {}
        if sa and (sa.get("account_name") or sa.get("device_name") or sa.get("command_lines")):
            sa_actor  = sa.get("account_name") or (user if user != "Unknown User" else "")
            sa_device = sa.get("device_name") or (device if device != "Unknown Device" else "")
            sa_cmds   = sa.get("command_lines") or []
            sa_time   = sa.get("event_time") or alert_time
            lines = [
                "Hi Team,",
                "",
                f"We have observed a *{alert_name}* alert.",
                "",
                "Evidence bound from the alert's own Sentinel entities:",
            ]
            if sa_actor:  lines.append(f"*Actor:* {sa_actor}")
            if sa_device: lines.append(f"*Device:* {sa_device}")
            if sa_time:   lines.append(f"*Event time (UTC):* {sa_time}")
            if sa_cmds:
                lines.append(f"*Operation / command{'s' if len(sa_cmds) > 1 else ''}:*")
                for c in sa_cmds[:_MAX_CMDS]:
                    lines.append(f"  `{c}`")
                if len(sa_cmds) > _MAX_CMDS:
                    lines.append(f"  _… {len(sa_cmds) - _MAX_CMDS} more suppressed_")
            if sa_actor and _is_service_account(sa_actor):
                lines += [
                    "",
                    f"↳ Actor `{sa_actor}` looks like a non-interactive service/automation "
                    "account — commonly benign platform automation. Confirm the operation is "
                    "expected before closing.",
                ]
            lines += _process_check_lines(evidence)
            lines += [
                "",
                "Recommendation: escalating to L2 — confirm the actor/operation is expected; "
                "close as False Positive if it maps to known service/automation activity.",
                "",
                "[Auto-triaged by RAPTOR]",
            ]
            return PlaybookResult(
                l1_comment="\n".join(lines),
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai", "sentinel-alert"],
                auto_close=False,
            )

        # ── No threats found → auto-close as FP ───────────────────────────
        if self._type == "no_threat" and not is_test_device:
            l1 = "\n".join([
                f"Hi Team,",
                f"",
                f"We observed *{alert_name}* on host *{device}*.",
                f"",
                f"*User:* {user}",
                f"*Investigation state:* {inv_state}",
                f"*Event time:* {alert_time} UTC",
                f"",
                f"MDE investigation completed with *No threats found* — no malicious activity confirmed.",
                f"",
                f"[Auto-triaged by RAPTOR]",
            ])
            l2 = "\n".join([
                f"MDE investigation for *{alert_name}* completed with *No threats found*.",
                f"No malicious activity confirmed on *{device}*.",
                f"*Marking as False Positive.*",
                f"",
                f"[Auto-triaged by RAPTOR]",
            ])
            return PlaybookResult(
                l1_comment=l1,
                l2_comment=l2,
                triage_class="AUTO_CLOSED_FP",
                action="resolved",
                labels=["edr-triage-ai"],
                auto_close=True,
            )

        # ── AWS CloudTrail / SSM / GuardDuty alert detection ─────────────
        # Prefer Sentinel API data; fall back to parsing _description
        aws = (sentinel_entities or {}).get("cloudtrail") or {}
        if not aws:
            description = alert.get("_description", "")
            aws = _parse_aws_fields(description)
        # Only treat as a genuine AWS/CloudTrail alert when there are real AWS
        # identity/API indicators. Otherwise this is an MDE endpoint alert that
        # merely landed here via generic+incident_url — using the Sentinel parse
        # would report the WRONG host (the incident's first entity) and the wrong
        # command. Fall through to the MDE rendering below instead.
        # A hashed file dropped in a user-home path is an ENDPOINT detection, not a
        # CloudTrail event — even if Sentinel enrichment tacked on an AWS session.
        # Don't let the AWS branch claim it (it would attribute the alert to the
        # unrelated AWS session principal instead of the real endpoint user).
        _fp = (file_path or "").lower()
        _endpoint_file = bool(
            file_name and sha256
            and ("/users/" in _fp or "\\users\\" in _fp or _fp.startswith("c:\\") or "/home/" in _fp)
        )
        _genuine_aws = (not _endpoint_file) and bool(
            ("arn:aws:" in (aws.get("user_arn", "") or "").lower())
            or aws.get("event_name")
            or aws.get("guardduty_link")
            or aws.get("access_key_id")
        )
        if aws and _genuine_aws:
            # Inject alert name so rule-based / LLM analysis has full context
            aws.setdefault("alert_name", alert_name)

            # Sentinel-enriched alert — format with whatever context is available.
            # Prefer the MDE alert's own device over the Sentinel incident's first
            # host (multi-host incidents otherwise report the wrong machine).
            aws_device      = device if (device and device != "Unknown Device") else aws.get("device_name", "")
            aws_user_arn    = aws.get("user_arn", "")
            aws_account     = aws.get("account_name", "")
            aws_issuer      = aws.get("session_issuer", "")
            aws_event       = aws.get("event_name", "")
            aws_instance    = aws.get("instance_id", "")
            aws_command     = aws.get("command", "")
            aws_time        = aws.get("time_generated", alert_time)
            aws_source_ip   = aws.get("source_ip", "")
            aws_ip_geo      = aws.get("ip_geo", "")
            aws_user_name   = aws.get("user_name", "")
            aws_access_key  = aws.get("access_key_id", "")
            aws_mfa_status  = aws.get("mfa_status", "")
            aws_gd_link     = aws.get("guardduty_link", "")

            l1_lines = [
                "Hi Team,",
                "",
                f"We have observed a *{alert_name}* alert. Please find the details below:",
                "",
            ]
            if aws_device and aws_device != "Unknown Device":
                l1_lines.append(f"*Device Name:* {aws_device}")
            if aws_time:
                l1_lines.append(f"*Time Generated (UTC):* {aws_time}")
            if aws_source_ip:
                geo_suffix = f" ({aws_ip_geo})" if aws_ip_geo else ""
                l1_lines.append(f"*Source IP:* {aws_source_ip}{geo_suffix}")
            if aws_account:
                l1_lines.append(f"*Account Name:* {aws_account}")
            if aws_event:
                l1_lines.append(f"*Event Name:* {aws_event}")
            if aws_instance:
                l1_lines.append(f"*Instance ID:* {aws_instance}")
            if aws_issuer:
                l1_lines.append(f"*Session Issuer User Name:* {aws_issuer}")
            if aws_user_name:
                l1_lines.append(f"*IAM Role / User:* {aws_user_name}")
            if aws_user_arn:
                l1_lines.append(f"*User Identity ARN:* {aws_user_arn}")
                session_user = _arn_session_user(aws_user_arn)
                if session_user:
                    l1_lines.append(f"*Session Principal:* {session_user}")
            if aws_access_key:
                l1_lines.append(f"*Access Key ID:* {aws_access_key}")
            if aws_mfa_status:
                l1_lines.append(f"*Session MFA:* {aws_mfa_status}")
            # Command source priority: MDE alert evidence (flagged process) →
            # Sentinel Process-entity commands (also flagged, what L1 cites) →
            # the KQL "Initiating Command" blob (whole-device history, last resort).
            _mde_cmds = (evidence or {}).get("command_lines") or []
            cmds = _mde_cmds or aws.get("command_lines") or _clean_commands(aws_command)
            if cmds:
                total = len(cmds)
                l1_lines.append(f"*Initiating Commands ({total}):*")
                for cmd in cmds[:_MAX_CMDS]:
                    l1_lines.append(f"  `{cmd}`")
                if total > _MAX_CMDS:
                    l1_lines.append(f"  _… {total - _MAX_CMDS} more routine commands suppressed_")
            if aws_gd_link:
                l1_lines.append(f"*GuardDuty Finding:* {aws_gd_link}")
            # Grouped incident: list every other host's session (DEMO-106604 — two
            # SSM StartSessions on two instances were bundled into one alert).
            l1_lines += _additional_hosts_lines(aws)
            verdict, analysis_reasons, recommendation, reasoning = await _llm_analyze_cloudtrail(aws)

            # This CloudTrail path ALWAYS escalates to NEEDS_L2 (return below), so do
            # NOT stamp a single-shot "Verdict: BENIGN" headline — it contradicts the
            # escalation AND the OSCAR agent's copilot verdict (DEMO-107104: this printed
            # "Verdict: BENIGN" while both L1 and the agent escalated to L2). Show the
            # single-shot LLM's findings as CONTEXT only; the disposition is the
            # escalation + business-justification request. The agent's copilot comment
            # (AGENT_PHASE=copilot) is the authoritative AI voice.
            l1_lines += [
                "",
                "----",
                "*AI Analysis (context — this alert is being escalated for L2 review):*",
            ]
            for r in analysis_reasons:
                l1_lines.append(f"* {r}")

            # Never surface a "close as FP" recommendation on a ticket that is going to
            # L2. Keep genuine escalate/review recommendations (SUSPICIOUS / NEEDS_REVIEW);
            # for a benign-leaning single-shot read, request business justification instead.
            if verdict != "BENIGN" and recommendation:
                l1_lines += ["", f"*Recommendation:* {recommendation}"]
            else:
                l1_lines += [
                    "",
                    f"As part of the security review process, we request you to please provide "
                    f"the business justification for the observed *{alert_name}* activity.",
                ]

            if reasoning:
                l1_lines += [
                    "",
                    "*AI Reasoning:*",
                    "{quote}",
                    reasoning,
                    "{quote}",
                ]

            l1_lines += ["", "[Auto-analysed by DeepIntel AI]"]

            return PlaybookResult(
                l1_comment="\n".join(l1_lines),
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai"],
                auto_close=False,
                llm_reasoning=reasoning,
            )

        # ── Privesc / PowerShell → needs L2 with command context ──────────
        l1_lines = [
            f"Hi Team,",
            f"",
            f"We have observed *{alert_name}* on host *{device}*.",
            f"",
            f"*User:* {user}",
        ]
        if file_name:
            l1_lines.append(f"*File:* {file_name} {'at ' + file_path if file_path else ''}")
        if sha256:
            l1_lines.append(f"*Hash:* {sha256}")
        if init_proc:
            l1_lines.append(f"*Initiating process:* {init_proc}")
        # Commands: prefer explicit evidence, then the Sentinel alert's OWN entity commands
        # (surfaced by query_sentinel_alert into sentinel_entities), so the concrete action
        # is stated the way an L1 analyst would — not omitted just because the MDE evidence
        # dict was empty (DEMO-106604 class).
        _cmds = (evidence or {}).get("command_lines") \
            or (sentinel_entities or {}).get("alert_command_lines") or []
        if _cmds:
            l1_lines.append(f"*Command line{'s' if len(_cmds) > 1 else ''} ({len(_cmds)}):*")
            for _c in _cmds[:_MAX_CMDS]:
                l1_lines.append(f"  `{_c}`")
            if len(_cmds) > _MAX_CMDS:
                l1_lines.append(f"  _… {len(_cmds) - _MAX_CMDS} more suppressed_")
        # CloudTrail / SSM specifics (instance, session issuer, ARN, source IP) when the
        # enrichment captured them — the exact fields L1 documents for AWS privesc.
        _ct = (sentinel_entities or {}).get("cloudtrail") or {}
        _acct = _ct.get("account_name") or (evidence or {}).get("account_name") or ""
        if _acct and _acct != user:
            l1_lines.append(f"*Account:* {_acct}")
        if _ct.get("session_issuer"):
            l1_lines.append(f"*Session issuer:* {_ct['session_issuer']}")
        if _ct.get("instance_id"):
            l1_lines.append(f"*Instance ID:* {_ct['instance_id']}")
        if _ct.get("user_arn"):
            l1_lines.append(f"*User ARN:* {_ct['user_arn']}")
        _src_ip = _ct.get("source_ip") or (evidence or {}).get("source_ip") or ""
        if _src_ip:
            l1_lines.append(f"*Source IP:* {_src_ip}")
        l1_lines += _additional_hosts_lines(_ct)
        l1_lines.append(f"*{self._vt_line(vt)}*")
        l1_lines.append(f"*Investigation state:* {inv_state}")
        l1_lines.append(f"*Severity:* {sev}")
        l1_lines.append(f"*Event time:* {alert_time} UTC")
        if is_test_device:
            l1_lines.append(self._test_device_note())
        l1_lines.append(f"")
        l1_lines.append(f"[Auto-triaged by RAPTOR]")

        return PlaybookResult(
            l1_comment="\n".join(l1_lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai"],
            auto_close=False,
        )
