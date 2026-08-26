"""Deterministic hunt tools — the agent supplies STRUCTURED params, the KQL is
built in-code (lib/kql_templates.py). No free-text KQL, so no hallucination
surface for the common hunts. These are the PRIMARY hunt path; mde_advanced_hunt
/ sentinel_run_kql are the free-write fallback for anything not covered here.

Built KQL still runs through run_mde_query / run_sentinel_query, so the existing
lint + auto-fix stay as a backstop.
"""
from __future__ import annotations

import logging
import re

from agent_tools.registry import register
from lib import kql_templates as T

logger = logging.getLogger(__name__)


def _flag_truncation(res: dict) -> dict:
    """Say when a result was CAPPED, so a partial view can't read as a complete one.

    Every row builder ends in `| take 50`. A hunt that matched 1,561 rows and a hunt
    that matched 50 both come back as "50 rows", and the model has no way to tell them
    apart — so it reasons about the sample as though it were the population. DEMO-107545:
    hunt_signin matched 1,561 sign-ins, returned 50, and the agent concluded "the sign-in
    logs for the last 24 hours show only successful sign-ins … the failed sign-ins
    occurred prior to the 24-hour window" and escalated a ticket L1 and L2 both closed
    FP. 608 failures were inside the window; they were simply past the cap.

    Deliberately worded as an INSTRUCTION TO NARROW, not as a warning that the evidence
    is unreliable. "Results incomplete" invites escalating on uncertainty, which is the
    failure this codebase spends most of its gates fighting; a capped hunt is a reason to
    ask a better question, not to hand the ticket to a human.
    """
    if len(res.get("rows") or []) >= T.MAX_ROWS:
        res["truncated"] = True
        res["truncation_note"] = (
            f"Capped at {T.MAX_ROWS} rows (newest first) — MORE matched than are shown, "
            "so this is a sample, not the full picture. Do NOT conclude that something "
            "is absent because it is missing here. To see the rest, narrow the question: "
            "shorten window_hours, or add a filter (process name, account, IP, port). "
            "A capped result is not itself a reason to escalate."
        )
    return res


async def _run_mde(builder, **kw) -> dict:
    from lib.mde_client import run_mde_query, get_access_token
    try:
        kql = builder(**kw)
    except ValueError as exc:
        return {"error": str(exc), "rows": []}
    token = await get_access_token()
    if not token:
        return {"error": "MDE token unavailable", "rows": []}
    rows, err = await run_mde_query(kql, token)
    if err:
        return {"error": err, "rows": [], "kql": kql}
    return _flag_truncation({"rows": rows, "count": len(rows), "kql": kql})


# Tables probed and found empty/non-empty this process. A workspace's table set does
# not change mid-run, so probe each at most once.
_EMPTY_TABLE_CACHE: dict[str, bool] = {}


def _leading_table(kql: str) -> str:
    """First token of a KQL query — the table it reads. "" if not a plain table read."""
    head = (kql or "").strip().splitlines()[0].strip() if (kql or "").strip() else ""
    head = head.split("|", 1)[0].strip()
    return head if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", head or "") else ""


async def _sentinel_table_is_empty(table: str) -> bool:
    """True if `table` holds NO data at all in this workspace (probed over 30d).

    A 0-row hunt against a table that is simply not populated is NOT evidence of
    anything, but it looks identical to a genuine clean result. DEMO-107932: the agent
    hunted SecurityEvent three times (24h, 168h, and a hunt_query), got 0 rows each
    time, and auto-closed FP at 0.95 reasoning "no evidence of local admin group
    changes" — while SecurityEvent is EMPTY workspace-wide (0 rows, 0 distinct
    Computers) and the real evidence sat in MDE DeviceEvents as
    UserAccountAddedToLocalGroup. It even wrote that the device might not be
    forwarding logs, then closed anyway.
    """
    if not table:
        return False
    if table in _EMPTY_TABLE_CACHE:
        return _EMPTY_TABLE_CACHE[table]
    from lib.mde_client import run_sentinel_query
    try:
        rows, err = await run_sentinel_query(f"{table} | where TimeGenerated > ago(30d) | take 1")
        # Only conclude "empty" on a clean run that returned nothing. An error means
        # unknown, and must not be reported as an empty source.
        empty = (err is None) and not rows
    except Exception as exc:
        logger.debug("empty-table probe failed for %s: %s", table, exc)
        empty = False
    _EMPTY_TABLE_CACHE[table] = empty
    return empty


async def _run_sentinel(builder, **kw) -> dict:
    from lib.mde_client import run_sentinel_query
    try:
        kql = builder(**kw)
    except ValueError as exc:
        return {"error": str(exc), "rows": []}
    rows, err = await run_sentinel_query(kql)
    if err:
        return {"error": err, "rows": [], "kql": kql}
    if not rows:
        _tbl = _leading_table(kql)
        if await _sentinel_table_is_empty(_tbl):
            # Surfaced as an ERROR, not a clean 0-row result: the hunt produced no
            # information, so it must read as an evidence GAP (and trip the
            # errored-hunt safety gate) rather than as "nothing happened".
            return {
                # Names BOTH pivots. This used to say only "the data likely lives in
                # MDE (hunt_events / hunt_process)", which is sound for a host-based
                # alert and a dead end for a host-less one: DEMO-108121 is an
                # OfficeActivity alert with no device at all, so MDE has nothing to
                # hunt, and the seven siblings that closed correctly had gone to
                # OfficeActivity instead. The tool has no alert context here (tools are
                # deliberately context-free), so it states the choice rather than
                # guessing — the prompt does the alert-specific routing.
                "error": (f"{_tbl} is EMPTY in this workspace (no rows in 30d) — this hunt "
                          "cannot confirm anything. Not evidence of benign; the data lives "
                          "in a DIFFERENT table. If this alert has a device, try MDE "
                          "(hunt_events / hunt_process). If it has NO device (Office 365, "
                          "identity, cloud), MDE has nothing for it — hunt the source table "
                          "instead (OfficeActivity, SigninLogs, AuditLogs, the *_CL feed) "
                          "via hunt_query."),
                "rows": [], "count": 0, "kql": kql, "source_empty": True,
            }
    return _flag_truncation({"rows": rows, "count": len(rows), "kql": kql})


_WINDOW = {"type": "integer", "description": "Lookback window in hours (default 24, max 168)", "default": 24}


@register(
    name="hunt_process",
    description=(
        "Hunt MDE process executions (DeviceProcessEvents) by device and/or process name, "
        "including the initiating parent process. Preferred over writing KQL by hand for "
        "process correlation / process-tree questions. Provide at least a device or a process_name."
    ),
    parameters={
        "type": "object",
        "properties": {
            "device": {"type": "string", "description": "Device hostname/FQDN"},
            "process_name": {"type": "string", "description": "Process file name, e.g. powershell.exe"},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_process(device: str = "", process_name: str = "", window_hours: int = 24) -> dict:
    return await _run_mde(T.mde_process, device=device, process_name=process_name, window_hours=window_hours)


@register(
    name="hunt_network",
    description=(
        "Hunt MDE network connections (DeviceNetworkEvents) by device, remote IP, or remote URL/domain. "
        "Use for beaconing / C2 / IOC-presence checks. Provide at least one of device / remote_ip / remote_url."
    ),
    parameters={
        "type": "object",
        "properties": {
            "device": {"type": "string", "description": "Device hostname/FQDN"},
            "remote_ip": {"type": "string", "description": "Remote IP address (exact match)"},
            "remote_url": {"type": "string", "description": "Remote URL or domain (substring match)"},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_network(device: str = "", remote_ip: str = "", remote_url: str = "", window_hours: int = 24) -> dict:
    return await _run_mde(T.mde_network, device=device, remote_ip=remote_ip, remote_url=remote_url, window_hours=window_hours)


@register(
    name="hunt_file",
    description=(
        "Hunt MDE file events (DeviceFileEvents) by file hash (md5/sha1/sha256), file name, or device. "
        "Use to check where a hashed/named file was seen. Provide at least one of sha256 / file_name / device."
    ),
    parameters={
        "type": "object",
        "properties": {
            "sha256": {"type": "string", "description": "File hash — md5, sha1, or sha256 (hex)"},
            "file_name": {"type": "string", "description": "File name, e.g. mimikatz.exe"},
            "device": {"type": "string", "description": "Device hostname/FQDN"},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_file(sha256: str = "", file_name: str = "", device: str = "", window_hours: int = 24) -> dict:
    return await _run_mde(T.mde_file, sha256=sha256, file_name=file_name, device=device, window_hours=window_hours)


@register(
    name="hunt_events",
    description=(
        "Hunt MDE DeviceEvents — the catch-all endpoint table the other hunts do NOT cover. "
        "This is where ANTIVIRUS DETECTIONS live (ActionType 'AntivirusDetection'), and also "
        "LOCAL GROUP / ACCOUNT CHANGES ('UserAccountAddedToLocalGroup', "
        "'UserAccountRemovedFromLocalGroup', 'UserAccountCreated', 'UserAccountModified'), "
        "plus ScriptContent, PowerShellCommand, UsbDriveMounted, LDAP/WMI/memory-API activity.\n"
        "For a local-admin / group-membership / account-change alert this is THE table — the "
        "Windows-side equivalents (SecurityEvent 4728/4732 via Sentinel) are a DIFFERENT data "
        "source that may not be populated at all, so an empty Sentinel result says nothing "
        "about whether the change happened.\n"
        "USE THIS whenever an alert is an AV/malware/hacktool detection, and ALWAYS before "
        "concluding a detected file is absent from the endpoint: a file that AV flagged but "
        "that was never EXECUTED has no DeviceProcessEvents row, and if it was downloaded "
        "outside the window it has no DeviceFileEvents row either — so hunt_process and "
        "hunt_file both return 0 rows on a device that is NOT clean. That is especially "
        "common on macOS/Linux. Zero rows here is also not proof of benign.\n"
        "Provide at least one of device / file_name / action_type / sha256. action_type "
        "matches by substring: 'AntivirusDetection' for real detections ('Antivirus' alone "
        "also matches the routine high-volume 'AntivirusReport' heartbeat)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "device": {"type": "string", "description": "Device hostname/FQDN"},
            "file_name": {"type": "string", "description": "File name, e.g. getTGT.py"},
            "action_type": {"type": "string",
                            "description": "ActionType substring, e.g. AntivirusDetection, ScriptContent"},
            "sha256": {"type": "string", "description": "File hash — md5, sha1, or sha256 (hex)"},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_events(device: str = "", file_name: str = "", action_type: str = "",
                      sha256: str = "", window_hours: int = 24) -> dict:
    return await _run_mde(T.mde_events, device=device, file_name=file_name,
                          action_type=action_type, sha256=sha256, window_hours=window_hours)


@register(
    name="hunt_file_burst",
    description=(
        "Detect MASS FILE-WRITE BURSTS on a device — the ransomware/wiper shape. "
        "Aggregates DeviceFileEvents per initiating process and returns files-touched, "
        "duration, files/min and the folder, e.g. "
        "'powershell.exe (4328) — 248 files in 21s (709/min) in C:\\\\Users\\\\admin\\\\Desktop'.\n"
        "USE THIS for ransomware / mass-encryption / wiper / 'suspicious behaviour blocked' "
        "alerts. A timeline or hunt_file CANNOT answer this: a burst is a RATE, and "
        "row-by-row views return individual filenames while the burst is buried among "
        "unrelated events (verified — a real 248-file burst was invisible in a "
        "60-row-per-table timeline).\n"
        "Counts WRITES, not encryption — a backup/build job writing many files looks the "
        "same. Judge by the PROCESS and FOLDER: git in a repo or msiexec installing is "
        "routine; powershell.exe writing hundreds of files into a user's Desktop is not. "
        "Zero rows is NOT proof of benign: OS/AppData/Program-Files paths are excluded as "
        "noise, and a slow or small payload stays under the threshold."
    ),
    parameters={
        "type": "object",
        "properties": {
            "device": {"type": "string", "description": "Device hostname/FQDN (required)"},
            "window_hours": _WINDOW,
            "min_files": {"type": "integer",
                          "description": "Files-touched floor per process (default 50)",
                          "default": 50},
        },
        "required": ["device"],
    },
)
async def hunt_file_burst(device: str = "", window_hours: int = 24,
                          min_files: int = 50) -> dict:
    return await _run_mde(T.mde_file_burst, device=device,
                          window_hours=window_hours, min_files=min_files)


@register(
    name="hunt_script_egress",
    description=(
        "Resolve WHERE a script actually connected — the real hosts behind a "
        "parameterised URL. Returns every network destination the initiating process "
        "reached on this device, summarised by host with call counts and first/last "
        "seen.\n"
        "USE THIS whenever a command line contains a VARIABLE instead of a value — "
        "`Invoke-RestMethod -Uri \"$ApiUrl/api/agent/report\"`, `$Server`, `$Endpoint`, "
        "`$env:…` — and on any 'script was loaded in memory' alert. The captured text is "
        "the script's SHAPE, not its destination: two runs with byte-identical command "
        "lines can post to completely different places, so a command match alone cannot "
        "tell you where the data went. This can.\n"
        "HOW TO JUDGE: destinations that are all internal or a known corporate service "
        "(and match what the script claims to do) corroborate a benign reading and, "
        "together with a matching precedent, support closing. An unexpected external "
        "host, a raw IP with no hostname, or a destination unrelated to the script's "
        "stated purpose is the exfil/C2 shape this alert class exists to catch — "
        "escalate that.\n"
        "Looks back DAYS by default, not hours, and that is deliberate: the alert fires "
        "on the script LOAD and the matching connection often falls outside a tight "
        "window (a 35-minute window around one such alert returned zero rows while the "
        "host's daily runs were plainly visible). Zero rows means no egress was "
        "captured — inconclusive, never proof the script did nothing."
    ),
    parameters={
        "type": "object",
        "properties": {
            "device": {"type": "string", "description": "Device hostname/FQDN (required)"},
            "process_name": {"type": "string",
                             "description": "Initiating process, default 'powershell'",
                             "default": "powershell"},
            "lookback_days": {"type": "integer",
                              "description": "Days to look back (default 7, max 30)",
                              "default": 7},
        },
        "required": ["device"],
    },
)
async def hunt_script_egress(device: str = "", process_name: str = "powershell",
                             lookback_days: int = 7) -> dict:
    res = await _run_mde(T.mde_script_egress, device=device, process_name=process_name,
                         lookback_days=lookback_days)
    if res.get("error"):
        return res
    rows = res.get("rows") or []
    if not rows:
        res["verdict"] = ("No egress captured for this process on this device in the "
                          "window — INCONCLUSIVE. Not evidence the script made no "
                          "connection; widen lookback_days or check the process name.")
        return res
    # Name the destinations plainly. The whole point is to answer "where did it go?" in
    # one line an analyst can act on, rather than leave a row list to be re-read.
    _hosts = [str(r.get("RemoteUrl") or r.get("RemoteIP") or "").strip() for r in rows]
    _hosts = [h for h in _hosts if h]
    res["destinations"] = sorted(set(_hosts))[:15]
    res["verdict"] = (
        f"{len(set(_hosts))} distinct destination(s) reached by {process_name} on "
        f"{device}: {', '.join(sorted(set(_hosts))[:8])}. Judge whether these match what "
        "the script claims to do — an internal/corporate host consistent with its "
        "purpose corroborates benign; an unexpected external host or bare IP does not."
    )
    return res


@register(
    name="hunt_identity_grant",
    description=(
        "Resolve WHO granted a privileged role or group to WHOM, and WHICH roles "
        "(Entra AuditLogs).\n"
        "USE THIS for every privileged-group / privileged-role / 'added to Entra ID "
        "Privileged Groups' / credential-added-to-service-principal alert. Do NOT use "
        "hunt_query: the acting principal is genuinely absent from the alert, and a "
        "free-written AuditLogs query returns rows without the deciding fields — the "
        "role name is NOT in TargetResources.displayName (empty for roles), it is nested "
        "in modifiedProperties under Role.DisplayName. One ticket pulled 50 rows that way "
        "and still concluded 'acting principal, target group name and target user were "
        "missing'.\n"
        "THE ACCOUNT NAMED ON THE ALERT IS USUALLY THE RECIPIENT, NOT THE ACTOR. Do not "
        "read the alert history or risk score of a recipient — or of a grantor — as "
        "evidence about this grant. An administrator who performs grants accumulates "
        "alerts as a matter of course; that is expected, not incriminating.\n"
        "Read the `verdict` on each row. ATTRIBUTION IS NOT AUTHORISATION: naming the "
        "grantor does NOT establish the grant was sanctioned — a compromised admin "
        "account produces exactly this shape. Knowing who acted tells you WHO TO ASK. "
        "For a delegated grant that is REQUEST_JUSTIFICATION addressed to the grantor, "
        "not an auto-close and not an L2 escalation. A SELF-GRANT (actor == recipient) "
        "is the escalation case. Zero rows means the grant is unattributed — "
        "inconclusive, never benign."
    ),
    parameters={
        "type": "object",
        "properties": {
            "actor": {"type": "string",
                      "description": "Substring of the granting UPN, if you have one"},
            "recipient": {"type": "string",
                          "description": "Substring of the UPN that RECEIVED the role — "
                                         "usually the account named on the alert"},
            "alert_time": {"type": "string",
                           "description": "Alert time (ISO 8601). Centres the window."},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_identity_grant(actor: str = "", recipient: str = "", window_hours: int = 24,
                              alert_time: str = "") -> dict:
    _anchor, _note = alert_time, ""
    if alert_time:
        from datetime import datetime, timedelta, timezone
        try:
            _p = datetime.fromisoformat(str(alert_time).strip().replace("Z", "+00:00"))
            if _p.tzinfo is None:
                _p = _p.replace(tzinfo=timezone.utc)
            _age = datetime.now(timezone.utc) - _p
            if _age > timedelta(days=179) or _age < timedelta(days=-1):
                _anchor = ""
                _note = (f" (ignored alert_time={alert_time}: outside AuditLogs retention "
                         "— used a recent window instead)")
        except (TypeError, ValueError):
            _anchor = ""
            _note = f" (ignored unparseable alert_time={alert_time}; used a recent window)"
    res = await _run_sentinel(T.sentinel_identity_grant, actor=actor, recipient=recipient,
                              window_hours=window_hours, anchor_iso=_anchor)
    if res.get("error"):
        return res
    res["anchor_used"] = _anchor or "recent"
    if _note:
        res["note"] = _note.strip()
    # Label in code — the model has twice mis-assigned the actor role on this family by
    # reading raw columns, and the direction of that error (blaming the recipient, or
    # treating a grantor's alert count as suspicion) is the whole failure.
    for r in (res.get("rows") or []):
        _a = (r.get("Actor") or "").strip()
        _app = (r.get("ActorApp") or "").strip()
        _rcp = (r.get("Recipient") or "").strip()
        _roles = ", ".join(r.get("Roles") or []) or "(none captured)"
        if _a and _rcp and _a.lower() == _rcp.lower():
            r["verdict"] = (f"SELF-GRANT — {_a} granted themselves [{_roles}]. Nobody "
                            "independent authorised this. Escalate.")
        elif _a:
            r["verdict"] = (f"DELEGATED — {_a} granted [{_roles}] to {_rcp}. {_a} is the "
                            f"ACTOR; {_rcp} only received it, so do not treat {_rcp}'s "
                            "history as evidence about this grant. This establishes WHO "
                            "acted, NOT that it was authorised — ask the grantor for the "
                            "business justification rather than auto-closing.")
        elif _app:
            r["verdict"] = (f"AUTOMATED — performed by the application '{_app}', not a "
                            f"person, granting [{_roles}] to {_rcp}. There is no human to "
                            "ask; judge by whether this automation is expected.")
        else:
            r["verdict"] = (f"UNATTRIBUTED — no initiating user or app recorded for the "
                            f"grant of [{_roles}] to {_rcp}. Inconclusive, not benign.")
    if not (res.get("rows") or []):
        res["unattributed_note"] = (
            "No matching grant found in AuditLogs. The grant is UNATTRIBUTED — this is "
            "inconclusive and is NOT evidence the change was benign. Widen window_hours "
            "or drop the actor/recipient filter before concluding."
        )
    return res


@register(
    name="hunt_service",
    description=(
        "Identify flagged SERVICE binaries by their AUTHENTICODE SIGNER and fleet "
        "prevalence — who signed each binary, whether that signature is trusted, and how "
        "many devices run it.\n"
        "USE THIS FIRST on 'Rare Process as a Service' and any alert naming unknown "
        "service processes. Do NOT reach for hunt_process there: a service starts at BOOT "
        "and then persists, so it emits no process-launch event inside any triage window "
        "and hunt_process returns 0 rows NO MATTER how many times you retry or how wide "
        "you go — 27 process hunts on one ticket produced nothing while a single call "
        "here resolves every name. That emptiness is a property of how services run, not "
        "evidence about the binary.\n"
        "READ THE `verdict` FIELD ON EACH ROW — it is computed from the certificate "
        "data, so do not re-derive it from the counts. TRUSTED is POSITIVE exculpatory "
        "evidence and is sufficient to close on by itself; UNTRUSTED is the masquerade "
        "tell and should be escalated; NO CERTIFICATE DATA is inconclusive.\n"
        "NoCertRecord counts copies with no row in the certificate table — that is a "
        "TELEMETRY GAP, not an unsigned binary. A trusted vendor binary routinely has a "
        "few (vmcompute.exe in C:\\Windows\\System32 shows 3 of 4). It is NOT a reason to "
        "escalate and NOT 'unsigned hashes'. Only UntrustedHashes means a signature that "
        "failed to chain.\n"
        "Trust the SIGNER over any vendor/CompanyName string you have seen elsewhere: "
        "version-info metadata is attacker-controlled, a signature chain is not.\n"
        "ANY recognized publisher counts. Lenovo, Intel, Dell, HP, NVIDIA, McAfee, "
        "Flexera, eMudhra, Realtek, VMware, Google are trusted publishers exactly as "
        "Microsoft is — the check is whether the signature CHAINS TO A TRUSTED ROOT, "
        "which is what UntrustedHashes==0 already tells you. Do NOT invent a "
        "Microsoft-only rule: on one re-run the model labelled gc_extension_service.exe "
        "(Microsoft, 8/8 trusted), lmgrd.exe (Flexera, 1/1), ReadyForService.exe "
        "(Lenovo, 2/2) and emBridge.exe (eMudhra, 4/4) as 'UNTRUSTED (unsigned or not "
        "Microsoft-signed)' and escalated a ticket L1 and L2 had closed FP. Every one of "
        "those rows said TRUSTED. If the verdict says TRUSTED, it is trusted; report it "
        "as trusted and do not downgrade it on the vendor's name.\n"
        "Names returned under not_found were NOT resolved — that is inconclusive, never "
        "benign; say so rather than clearing them."
    ),
    parameters={
        "type": "object",
        "properties": {
            "names": {"type": "array", "items": {"type": "string"},
                      "description": "The flagged service process names, e.g. "
                                     "['gc_extension_service.exe','ipf_uf.exe']"},
            "lookback_days": {"type": "integer",
                              "description": "Days to look back (default 30, max 30)",
                              "default": 30},
        },
        "required": ["names"],
    },
)
async def hunt_service(names=None, lookback_days: int = 30) -> dict:
    # The model sometimes hands back a comma string instead of an array; accept both
    # rather than failing the one call that can decide this alert family.
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",")]
    _names = [str(n).strip() for n in (names or []) if str(n or "").strip()]
    res = await _run_mde(T.mde_service_identity, names=_names,
                         lookback_days=lookback_days)
    if res.get("error"):
        return res
    # Label each row IN CODE. Handed the raw columns the model did the arithmetic
    # wrong in the direction that costs accuracy: DEMO-107138 called emBridge.exe and
    # mfewc.exe "unsigned and present on only a few devices" and escalated, when they
    # were 4/4 trusted (eMudhra) and 1/1 trusted (McAfee). Same failure hunt_ip_owner
    # had — a list of columns invites a plausible misreading, a stated verdict does not.
    for r in (res.get("rows") or []):
        _t = int(r.get("TrustedHashes") or 0)
        _u = int(r.get("UntrustedHashes") or 0)
        _gap = int(r.get("NoCertRecord") or 0)
        _dev = int(r.get("Devices") or 0)
        if _u:
            r["verdict"] = (f"UNTRUSTED — {_u} of {_t + _u + _gap} copies carry a signature "
                            "that does not chain to a trusted root. Check the path and "
                            "escalate.")
        elif _t:
            _note = (f" ({_gap} further copies have no certificate record — a telemetry "
                     "gap, NOT unsigned; ignore it)" if _gap else "")
            r["verdict"] = (f"TRUSTED — signed by {', '.join(s for s in (r.get('Signers') or []) if s)}"
                            f", on {_dev} devices{_note}. This is positive exculpatory "
                            "evidence: sufficient to close, no further hunting needed.")
        else:
            r["verdict"] = (f"NO CERTIFICATE DATA — seen on {_dev} devices but no copy has a "
                            "certificate record. Inconclusive, not benign and not malicious.")
    # Name every process that did NOT resolve. Without this the model sees a short list
    # of clean rows and reads it as "all clear" — the same absence-of-evidence slip this
    # tool exists to remove, just moved one step later.
    _got = {str(r.get("FileName") or "").lower() for r in (res.get("rows") or [])}
    _missing = [n for n in _names if n.lower() not in _got]
    if _missing:
        res["not_found"] = _missing
        res["not_found_note"] = (
            f"{len(_missing)} of {len(_names)} names did not resolve to any signed binary "
            "in MDE: " + ", ".join(_missing[:10]) + ". This is INCONCLUSIVE for those "
            "names — not evidence they are benign."
        )
    return res


@register(
    name="hunt_ip_owner",
    description=(
        "Resolve WHICH DEVICE HELD AN IP ADDRESS at the time of the alert "
        "(DeviceNetworkInfo — a network-configuration snapshot, not an event table).\n"
        "USE THIS FIRST on any network alert that names a source IP but whose host you "
        "cannot otherwise confirm — beaconing, C2, port sweep, lateral movement. The "
        "hostname printed on such a ticket is frequently NOT the machine that owns the "
        "IP: ten sibling beaconing alerts carrying one source IP each named a different, "
        "wrong device, and none of them was the real owner.\n"
        "Returns one row PER DEVICE seen holding the IP, with a snapshot count. Read the "
        "row count, not just the first row:\n"
        "  exactly 1 device  -> that is the host; hunt THAT device, not the ticket's.\n"
        "  more than 1       -> AMBIGUOUS (RFC-1918 space is reused fleet-wide — "
        "192.168.1.5 belongs to 10 devices even in a 2h window). Do NOT pick one and do "
        "NOT attribute activity to any of them; this is a NEEDS_L2 for manual attribution.\n"
        "  zero rows         -> unresolvable (device offline/not onboarded, or the IP is "
        "NAT/VPN). Inconclusive, never proof of benign.\n"
        "Pass alert_time so the lookup is anchored on the alert instead of now — the "
        "answer changes with DHCP and a wide window is wrong ~1 time in 5."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip": {"type": "string",
                   "description": "The IP address to resolve, e.g. the alert's source IP"},
            "alert_time": {"type": "string",
                           "description": "Alert time (ISO 8601). Anchors the lookup; "
                                          "omit only if genuinely unknown."},
            "window_hours": {"type": "integer",
                             "description": "Hours either side of alert_time (default 1). "
                                            "Widen only if the tight window returns nothing.",
                             "default": 1},
        },
        "required": ["ip"],
    },
)
async def hunt_ip_owner(ip: str = "", alert_time: str = "", window_hours: int = 1) -> dict:
    # DeviceNetworkInfo keeps 30 days. An anchor outside that can only ever return zero
    # rows, and "zero rows" is indistinguishable from a genuinely unresolvable IP — so a
    # bad timestamp silently becomes "unresolvable". The model does supply bad ones:
    # DEMO-107982's re-run passed 2024-07-30 for a 2026 alert. Drop an unusable anchor and
    # fall back to a recent window rather than answering a question about dead time.
    _anchor, _note = alert_time, ""
    if alert_time:
        from datetime import datetime, timedelta, timezone
        try:
            _p = datetime.fromisoformat(str(alert_time).strip().replace("Z", "+00:00"))
            if _p.tzinfo is None:
                _p = _p.replace(tzinfo=timezone.utc)
            _age = datetime.now(timezone.utc) - _p
            if _age > timedelta(days=29) or _age < timedelta(days=-1):
                _anchor = ""
                _note = (f" (ignored alert_time={alert_time}: outside DeviceNetworkInfo's "
                         "30d retention — used a recent window instead, so this answers "
                         "'who holds it now', not 'who held it then')")
        except (TypeError, ValueError):
            _anchor = ""
            _note = f" (ignored unparseable alert_time={alert_time}; used a recent window)"
    res = await _run_mde(T.mde_ip_owner, ip=ip, anchor_iso=_anchor,
                         window_hours=window_hours)
    rows = res.get("rows") or []
    if res.get("error"):
        return res
    res["anchor_used"] = _anchor or "recent"
    # Say what the row count MEANS rather than leaving the model to infer it from a
    # list — the whole failure this tool exists to fix is a single plausible hostname
    # being taken as the answer.
    names = [r.get("DeviceName") for r in rows if r.get("DeviceName")]
    if len(names) == 1:
        res["owner"] = names[0]
        res["ambiguous"] = False
        res["verdict"] = f"{names[0]} held {ip} at that time — hunt THIS device.{_note}"
    elif len(names) > 1:
        res["owner"] = ""
        res["ambiguous"] = True
        res["verdict"] = (f"AMBIGUOUS — {len(names)} devices held {ip} in this window "
                          f"({', '.join(names[:6])}). Do NOT attribute to any of them; "
                          f"escalate for manual host attribution.{_note}")
    else:
        res["owner"] = ""
        res["ambiguous"] = True
        res["verdict"] = (f"No device found holding {ip} in this window — unresolvable "
                          "(offline, not onboarded, or a NAT/VPN address). Inconclusive, "
                          f"NOT evidence of benign.{_note}")
    return res


@register(
    name="hunt_logons",
    description=(
        "Hunt MDE logon events (DeviceLogonEvents) by device and/or account. Use for lateral-movement / "
        "logon-pattern questions. Provide at least a device or an account."
    ),
    parameters={
        "type": "object",
        "properties": {
            "device": {"type": "string", "description": "Device hostname/FQDN"},
            "account": {"type": "string", "description": "Account name"},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_logons(device: str = "", account: str = "", window_hours: int = 24) -> dict:
    return await _run_mde(T.mde_logons, device=device, account=account, window_hours=window_hours)


@register(
    name="hunt_signin",
    description=(
        "Hunt Azure AD sign-ins (Sentinel SigninLogs) for a user principal name (UPN). "
        "Use for identity / sign-in investigations. Requires a upn.\n"
        "Returns TWO things: `outcomes` — every distinct ResultType with its COUNT and "
        "reason, computed over the whole window — and `rows`, the newest individual "
        "sign-ins (capped). On any failure-spike or brute-force alert, READ `outcomes` "
        "FIRST: it is the only part that answers 'how many failed and why', and the rows "
        "are a sample that can miss failures entirely on a busy account. A large count "
        "against a benign ResultType (e.g. 70044, session expired by conditional-access "
        "sign-in-frequency) explains a spike without any threat."
    ),
    parameters={
        "type": "object",
        "properties": {
            "upn": {"type": "string", "description": "User principal name, e.g. user@corp.com"},
            "window_hours": _WINDOW,
        },
        "required": ["upn"],
    },
)
async def hunt_signin(upn: str, window_hours: int = 24) -> dict:
    res = await _run_sentinel(T.sentinel_signin, upn=upn, window_hours=window_hours)
    if res.get("error"):
        return res
    # Counts computed over the FULL window, not over the capped rows — a sign-in-failure
    # alert is a question about volume, and the row sample cannot answer it (DEMO-107545:
    # 50 of 1,561 rows shown, all successes, 608 failures unseen, escalated against an
    # L1+L2 FP). Additive: `rows` keeps its existing shape, so nothing that already reads
    # this tool changes behaviour.
    summary = await _run_sentinel(T.sentinel_signin_summary, upn=upn, window_hours=window_hours)
    if not summary.get("error"):
        res["outcomes"] = summary.get("rows") or []
        _fail = sum(int(r.get("Events") or 0) for r in res["outcomes"]
                    if str(r.get("ResultType") or "0") not in ("0", ""))
        _ok = sum(int(r.get("Events") or 0) for r in res["outcomes"]
                  if str(r.get("ResultType") or "0") in ("0", ""))
        res["outcome_totals"] = {"success": _ok, "failure": _fail}
    return res


@register(
    name="hunt_ca_policy_change",
    description=(
        "Show WHAT CHANGED in an Entra Conditional Access policy (Sentinel AuditLogs), "
        "diffed — which users/groups/roles/apps entered or left each EXCLUSION list, "
        "plus the grant controls and enabled state before and after.\n"
        "USE THIS for every 'Conditional Access …' alert — policy updated, exclusion "
        "changed, policy created/deleted. The audit record stores the entire policy as "
        "JSON in oldValue/newValue, so the change is UNREADABLE without diffing; a "
        "generic AuditLogs query returns the blobs and tells you nothing. Do not use "
        "hunt_signin for this — sign-ins are not policy changes.\n"
        "HOW TO JUDGE: an exclusion added or removed while Grant_Old/Grant_New still "
        "contains 'mfa' and State stays 'enabled' is a scoped change, and a principal "
        "added then removed hours later is a temporary, reverted exclusion — normal "
        "change management. MFA DISAPPEARING from grant controls, the policy flipping "
        "to 'disabled', or a broad group/role being excluded is the weakening this "
        "alert class exists to catch — escalate that.\n"
        "Zero rows means your window or actor filter is wrong, NOT that no change "
        "happened: this table holds ~118M rows over 6 months. Widen the window and "
        "retry before concluding anything.\n"
        "Pass alert_time so the window is centred on the ALERT rather than on now — "
        "without it a ticket picked up a day late hunts the wrong window and comes back "
        "empty, which reads as 'no change found' and manufactures an escalation."
    ),
    parameters={
        "type": "object",
        "properties": {
            "actor": {"type": "string",
                      "description": "Who made the change (substring of the initiating UPN)"},
            "policy": {"type": "string",
                       "description": "Policy display name substring, e.g. 'MFA for All Application'"},
            "alert_time": {"type": "string",
                           "description": "Alert time (ISO 8601). Centres the window; "
                                          "omit only if genuinely unknown."},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_ca_policy_change(actor: str = "", policy: str = "", window_hours: int = 24,
                                alert_time: str = "") -> dict:
    # Same guard as hunt_ip_owner: a bad anchor can only return zero rows, and zero rows
    # here is indistinguishable from "no policy change happened" — so an unusable
    # timestamp silently becomes exculpatory. AuditLogs retains ~180d.
    _anchor, _note = alert_time, ""
    if alert_time:
        from datetime import datetime, timedelta, timezone
        try:
            _p = datetime.fromisoformat(str(alert_time).strip().replace("Z", "+00:00"))
            if _p.tzinfo is None:
                _p = _p.replace(tzinfo=timezone.utc)
            _age = datetime.now(timezone.utc) - _p
            if _age > timedelta(days=179) or _age < timedelta(days=-1):
                _anchor = ""
                _note = (f" (ignored alert_time={alert_time}: outside AuditLogs retention — "
                         "used a recent window instead)")
        except (TypeError, ValueError):
            _anchor = ""
            _note = f" (ignored unparseable alert_time={alert_time}; used a recent window)"
    res = await _run_sentinel(T.sentinel_ca_policy_change, actor=actor, policy=policy,
                              window_hours=window_hours, anchor_iso=_anchor)
    if not res.get("error"):
        res["anchor_used"] = _anchor or "recent"
        if _note:
            res["note"] = _note.strip()
    return res


@register(
    name="hunt_office",
    description=(
        "Hunt Office 365 / Exchange admin operations (Sentinel OfficeActivity) with the "
        "fields that actually DECIDE them: the TARGET object, the PARAMETERS changed, "
        "the RESULT status, and whether the action came from outside.\n"
        "USE THIS for any Office/Exchange/SharePoint/Teams admin alert — 'Rare and "
        "potentially high-risk Office operations', mailbox permission or forwarding "
        "changes, Add-MailboxPermission, Set-Mailbox, New-InboxRule. Those alerts have "
        "NO DEVICE, so MDE holds nothing for them and hunt_process/hunt_events cannot "
        "answer anything; OfficeActivity is where the operation is recorded.\n"
        "Prefer this over hunt_query for this data: a free-written projection tends to "
        "return the operation name and little else, which is not enough to judge — the "
        "target mailbox and the changed parameters are what separate routine Exchange "
        "housekeeping (arbitration/soft-deleted system mailboxes, Identity/Force/"
        "BypassLiveId) from a real change to a person's mailbox (forwarding, delegation, "
        "external access).\n"
        "Read ExternalAccess=false as an internal admin action, and UserType=Admin with "
        "an AppPoolName as a service component rather than a person."
    ),
    parameters={
        "type": "object",
        "properties": {
            "operation": {"type": "string",
                          "description": "Exact operation, e.g. 'Set-Mailbox', "
                                         "'Add-MailboxPermission', 'New-InboxRule'"},
            "user": {"type": "string",
                     "description": "Acting principal (substring of UserId), e.g. the "
                                    "service account or UPN named in the alert"},
            "target": {"type": "string",
                       "description": "Target object substring (OfficeObjectId) — a "
                                      "mailbox name/GUID, if the alert names one"},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_office(operation: str = "", user: str = "", target: str = "",
                      window_hours: int = 24) -> dict:
    return await _run_sentinel(T.sentinel_office_activity, operation=operation, user=user,
                               target=target, window_hours=window_hours)


@register(
    name="hunt_sentinel_event",
    description=(
        "Hunt Windows security events (Sentinel SecurityEvent) by host (Computer) and/or account. "
        "Provide at least a host or an account."
    ),
    parameters={
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Computer/host name"},
            "account": {"type": "string", "description": "Account name (substring match)"},
            "window_hours": _WINDOW,
        },
    },
)
async def hunt_sentinel_event(host: str = "", account: str = "", window_hours: int = 24) -> dict:
    return await _run_sentinel(T.sentinel_security_event, host=host, account=account, window_hours=window_hours)
