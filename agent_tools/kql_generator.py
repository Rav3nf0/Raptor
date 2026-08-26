"""Gemini-authored hunt tool — generate-and-run with LOCAL entity substitution.

For hunts the deterministic hunt_* builders don't cover, the agent supplies a
PUBLIC `intent` plus structured entity params. Gemini sees ONLY the intent, the
table schema, and placeholder TOKENS (<DEVICE>, <SHA256>, …) — never the real
entity values. It returns a query using those placeholders; we substitute the
real values LOCALLY (safely quoted), lint + column-sanitize, and execute. So:
  * Gemini (not Mistral) authors the KQL, and
  * internal telemetry identifiers never leave the tenant (Gemini is Google's
    external API; the codebase's rule is to never send internal alert data to it).

The agent never handles the KQL string itself (no copy-paste re-hallucination).
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

import httpx

from agent_tools.registry import register

logger = logging.getLogger(__name__)

# Structured param name → placeholder token Gemini may use for that entity's value.
_PLACEHOLDERS = {
    "device": "<DEVICE>", "account": "<ACCOUNT>", "upn": "<UPN>",
    "sha256": "<SHA256>", "ip": "<IP>", "url": "<URL>",
}
# Any <UPPERCASE…> left after substitution = a placeholder we couldn't fill.
_TOKEN_RE = re.compile(r"<[A-Z][A-Z0-9_]*>")
_HEX_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")


def _gemini_url() -> str:
    # Same GEMINI_MODEL source of truth as the auto-fixer in lib/mde_client.py.
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    return f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


async def _gemini_generate(prompt: str) -> tuple[str, str | None]:
    """Call Gemini; return (text, None) or ("", error). Retries on 429/5xx."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return "", "GEMINI_API_KEY not configured"
    # thinkingBudget=0 disables gemini-2.5-flash's default "thinking": those tokens
    # are billed against maxOutputTokens, so with thinking on the model spent ~980 of
    # 1024 on hidden reasoning and TRUNCATED the KQL mid-query (unbalanced parens /
    # trailing pipe → hunt errors → false NEEDS_L2 escalations). Off = clean, complete KQL.
    payload = {"contents": [{"parts": [{"text": prompt}]}],
               "generationConfig": {"temperature": 0.0, "maxOutputTokens": 1024,
                                    "thinkingConfig": {"thinkingBudget": 0}}}
    last = ""
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(f"{_gemini_url()}?key={api_key}", json=payload)
            if resp.status_code == 200:
                text = (resp.json().get("candidates", [{}])[0]
                        .get("content", {}).get("parts", [{}])[0].get("text", "")).strip()
                if text.startswith("```"):
                    text = re.sub(r"^```[a-z]*\n?", "", text).rstrip("`").strip()
                return text, (None if text else "empty response")
            last = f"HTTP {resp.status_code}"
            if resp.status_code not in (429, 500, 502, 503, 504):
                break
        except Exception as exc:
            last = str(exc)[:120]
        if attempt < 2:
            await asyncio.sleep(1.5 * (attempt + 1))
    return "", f"Gemini unavailable ({last})"


def _schema_block(source: str) -> str:
    from lib.mde_client import MDE_TABLE_SCHEMA, SENTINEL_TABLE_SCHEMA
    schema = MDE_TABLE_SCHEMA if source == "mde" else SENTINEL_TABLE_SCHEMA
    return "\n".join(f"- {t}: {', '.join(cols[:16])}" for t, cols in schema.items())


def _kw(intent: str, *words: str) -> bool:
    il = (intent or "").lower()
    return any(w in il for w in words)


def _deterministic_fallback(intent: str, source: str, device: str, account: str,
                            upn: str, sha256: str, ip: str, url: str, window_hours: int):
    """Pick a deterministic hunt_* builder for this intent + entities when Gemini is down.

    Returns (kql, run_kind, label) where run_kind is "mde" | "sentinel", or None if no
    builder fits. Routes by TELEMETRY, not by the caller's `source`: process/execution
    telemetry lives in MDE Device tables (incl. Linux Defender hosts), so an execution
    hunt is sent to mde_process even when the agent asked for source="sentinel" (Sentinel
    has no process-execution table). Builders run locally and quote values safely, so no
    entity ever leaves the tenant on this path.
    """
    from lib import kql_templates as T
    is_net = _kw(intent, "network", "connection", "beacon", "c2", "dns", "traffic", "exfil", "remote ip", "remote url")
    is_logon = _kw(intent, "logon", "login", "sign-in", "signin", "sign in", "authenticat", "credential")
    is_proc = _kw(intent, "process", "execut", "command", "commandline", "command-line", "ran ", "launch", "spawn", "binary", "powershell", "script")
    try:
        # 1) A concrete hash → file events (MDE).
        if sha256:
            return T.mde_file(sha256=sha256, window_hours=window_hours), "mde", "hunt_file(sha256)"
        # 2) A network IOC or an explicitly network-flavoured intent → network events (MDE).
        if ip or url or (is_net and device):
            return (T.mde_network(device=device, remote_ip=ip, remote_url=url, window_hours=window_hours),
                    "mde", "hunt_network")
        # 3) Sign-in / identity intent → SigninLogs by UPN (Sentinel) or MDE logon events.
        if is_logon:
            if upn:
                return T.sentinel_signin(upn=upn, window_hours=window_hours), "sentinel", "hunt_signin(upn)"
            if device or account:
                return T.mde_logons(device=device, account=account, window_hours=window_hours), "mde", "hunt_logons"
        # 4) Process / execution / command-line intent → ALWAYS MDE process events.
        if is_proc and (device or account):
            return T.mde_process(device=device, window_hours=window_hours), "mde", "hunt_process"
        # 5) Bare UPN with no clearer signal → sign-ins.
        if upn:
            return T.sentinel_signin(upn=upn, window_hours=window_hours), "sentinel", "hunt_signin(upn)"
        # 6) A device with no other steer → process events are the most useful default.
        if device:
            return T.mde_process(device=device, window_hours=window_hours), "mde", "hunt_process(device)"
    except ValueError:
        return None
    return None


@register(
    name="hunt_query",
    description=(
        "Gemini-authored hunt for questions the specific hunt_* tools don't cover. "
        "Describe the hunt in `intent` (plain words — do NOT put real device names, users, "
        "hashes, or IPs in the text; pass those as the params below) and choose `source`. "
        "The KQL is generated and RUN for you and returns rows. Prefer a specific hunt_* tool "
        "when one fits; use raw mde_advanced_hunt/sentinel_run_kql only if this reports unavailable."
    ),
    parameters={
        "type": "object",
        "properties": {
            "intent": {"type": "string", "description": "What to hunt for, in plain words. PUBLIC — no real entity values here; use the params below."},
            "source": {"type": "string", "enum": ["mde", "sentinel"], "description": "mde = Device* tables; sentinel = Log Analytics"},
            "device": {"type": "string", "description": "Device hostname to scope to (optional)"},
            "account": {"type": "string", "description": "Account name (optional)"},
            "upn": {"type": "string", "description": "User principal name (optional)"},
            "sha256": {"type": "string", "description": "File hash md5/sha1/sha256 (optional)"},
            "ip": {"type": "string", "description": "IP address (optional)"},
            "url": {"type": "string", "description": "URL/domain (optional)"},
            "window_hours": {"type": "integer", "description": "Lookback hours (default 24, max 168)", "default": 24},
        },
        "required": ["intent", "source"],
    },
)
async def hunt_query(intent: str, source: str, device: str = "", account: str = "", upn: str = "",
                     sha256: str = "", ip: str = "", url: str = "", window_hours: int = 24) -> dict:
    from lib.mde_client import (
        preflight_kql, _sanitize_kql_columns, run_mde_query, run_sentinel_query, get_access_token,
    )
    from lib import kql_templates as T

    source = "sentinel" if str(source).lower().startswith("sent") else "mde"
    if sha256 and not _HEX_HASH_RE.match(sha256.strip()):
        return {"error": f"'{sha256}' is not a valid md5/sha1/sha256 hash", "rows": []}
    provided = {n: v for n, v in (("device", device), ("account", account), ("upn", upn),
                                  ("sha256", sha256), ("ip", ip), ("url", url)) if v}
    avail = {_PLACEHOLDERS[n]: v for n, v in provided.items()}
    ph_list = ", ".join(avail.keys()) or "(none — no entity filters provided)"
    time_field = "Timestamp" if source == "mde" else "TimeGenerated"
    try:
        w = max(1, min(int(window_hours), 168))
    except (TypeError, ValueError):
        w = 24
    engine = ("Microsoft Defender Advanced Hunting (Device* tables)" if source == "mde"
              else "Microsoft Sentinel Log Analytics")

    prompt = (
        f"Write a {engine} KQL query for this hunt:\n\"{intent}\"\n\n"
        f"Available tables (columns):\n{_schema_block(source)}\n\n"
        "Rules:\n"
        "- Return ONLY the KQL, no explanation, no markdown fences\n"
        "- Start with a valid table name (never a comment or backticks)\n"
        f"- Add a time filter: | where {time_field} > ago({w}h)\n"
        "- End with | take 50\n"
        f"- For entity values use ONLY these placeholder tokens, UNQUOTED, exactly as written: {ph_list}\n"
        "  example: | where DeviceName =~ <DEVICE>\n"
        "- Do NOT put any real device name, user, hash, IP, or domain in the query — only the placeholders above\n"
    )
    raw, gerr = await _gemini_generate(prompt)
    if gerr:
        # Gemini is the KQL author for this tool; when it's down (429/5xx exhausted) don't
        # just bounce the agent to hand-written raw KQL — first try a DETERMINISTIC builder
        # from the intent + the entities we already hold. Builders run locally (no LLM), so
        # this removes the Gemini dependency for the common hunts even when the model is out.
        # This is the DEMO-106557 case: an "executions" hunt on a device, Gemini 429 →
        # falls through to mde_process instead of a false-escalating errored hunt.
        fb = _deterministic_fallback(intent, source, device, account, upn, sha256, ip, url, w)
        if fb:
            fb_kql, fb_kind, fb_label = fb
            try:
                if fb_kind == "mde":
                    token = await get_access_token()
                    if token:
                        rows, err = await run_mde_query(fb_kql, token)
                    else:
                        rows, err = None, "MDE token unavailable"
                else:
                    rows, err = await run_sentinel_query(fb_kql)
                if not err and rows is not None:
                    return {"rows": rows, "count": len(rows), "kql": fb_kql,
                            "note": f"Gemini unavailable ({gerr}); ran deterministic builder "
                                    f"{fb_label} instead — result is authoritative, treat as a normal hunt."}
            except Exception as exc:
                logger.warning("hunt_query deterministic fallback failed: %s", exc)
        # No builder fit (or it errored) → let the agent know the raw free-write fallback is legit.
        return {"error": f"hunt_query unavailable: {gerr}. Fall back to raw KQL via "
                         f"mde_advanced_hunt/sentinel_run_kql if you cannot use another hunt_* tool.",
                "rows": []}

    # Substitute placeholders with safely-quoted local values (entities never went to Gemini).
    kql = raw
    for token, val in avail.items():
        kql = kql.replace(token, T._lit(val))
    leftover = _TOKEN_RE.findall(kql)
    if leftover:
        return {"error": f"generated query used unfilled placeholder(s) {sorted(set(leftover))} — "
                         "rephrase the intent or provide those entities as params", "rows": []}

    kql = _sanitize_kql_columns(kql)          # prune any hallucinated columns
    cleaned, pf_err = preflight_kql(kql)       # strip + lint
    if pf_err:
        return {"error": f"{pf_err} (Gemini-generated)", "rows": [], "kql": kql}

    if source == "sentinel":
        rows, err = await run_sentinel_query(cleaned)
    else:
        token = await get_access_token()
        if not token:
            return {"error": "MDE token unavailable", "rows": []}
        rows, err = await run_mde_query(cleaned, token)
    if err:
        return {"error": err, "rows": [], "kql": cleaned}
    return {"rows": rows, "count": len(rows), "kql": cleaned}
