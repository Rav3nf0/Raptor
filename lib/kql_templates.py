"""Deterministic, schema-bound KQL builders for the agent's common hunts.

The agent (Mistral) supplies STRUCTURED params; these functions construct valid
KQL in-code — so there is no free-text / hallucination surface for the common
cases (the root-cause fix for the ~51% hunt error rate). MDE Device* tables use
`Timestamp`; Sentinel tables use `TimeGenerated`. Every builder requires at least
one concrete filter (never an unfiltered table scan) and caps rows with `| take N`.

Output is plain KQL; the calling tool runs it through the existing
`run_mde_query` / `run_sentinel_query` (which keep lint + auto-fix as a backstop).
All string params are quoted as KQL literals (`_lit`) so values can't break the
query or inject operators.
"""
from __future__ import annotations

import re

MAX_ROWS = 50
_HEX_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")   # md5(32)/sha1(40)/sha256(64)


def _lit(v: str) -> str:
    """Quote an untrusted string as a KQL double-quoted literal (escape \\ and ")."""
    s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ")
    return f'"{s}"'


def _win(hours) -> int:
    """Clamp a lookback window to a sane 1h..168h (7d) integer."""
    try:
        h = int(hours)
    except (TypeError, ValueError):
        h = 24
    return max(1, min(h, 168))


def _ts(v) -> str:
    """Canonicalise a timestamp for interpolation into a KQL `datetime(...)` literal.

    Anchors are the one parameter here that CANNOT go through `_lit` — `datetime()`
    takes a bare literal, not a quoted string — so the module's "everything is quoted"
    guarantee does not cover them. Parse and re-emit instead: anything that is not a
    real timestamp becomes "", and every caller treats "" as "no anchor" and falls back
    to its relative window. So a malformed or hostile value can only ever cost the
    anchoring, never reach the query.
    """
    from datetime import datetime, timezone
    s = str(v or "").strip().replace("Z", "+00:00")
    if not s:
        return ""
    try:
        p = datetime.fromisoformat(s)
    except (TypeError, ValueError):
        return ""
    if p.tzinfo is None:
        p = p.replace(tzinfo=timezone.utc)
    return p.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build(lines: list[str]) -> str:
    lines.append(f"| take {MAX_ROWS}")
    return "\n".join(lines)


def _window(field: str, window_hours, anchor_iso: str = "") -> tuple[str, str]:
    """The time filter for a hunt, anchored on the alert when an anchor is given.

    `ago(Nh)` means "the N hours before NOW". On a live triage that is the N hours
    before the alert, but on any re-triage or replay it is the wrong range entirely:
    DEMO-107770's re-run asked for AntivirusDetection rows at 24h and got 0, while the
    same hunt at 48h returned the 4 detections it was about. Absent evidence there is
    the worst kind of error, because an empty result reads as "clean".

    Anchored, the window is N hours BEFORE the alert plus N hours AFTER it. The
    before-side is exactly what a live run sees, so anchoring can never shrink the
    evidence a live triage gets; the after-side lets a replay see follow-on activity a
    live run would have caught on its next look. Returns (where-line, anchor), with
    anchor "" when unanchored so the caller can pick its ordering.
    """
    w, anchor = _win(window_hours), _ts(anchor_iso)
    if anchor:
        return (f"| where {field} between (datetime({anchor}) - {w}h .. datetime({anchor}) + {w}h)",
                anchor)
    return f"| where {field} > ago({w}h)", ""


def _order(field: str, anchor: str) -> list[str]:
    """Row order before `| take 50`. Anchored: nearest the alert first, with the signed
    offset kept in the row ("12s before" and "9h after" are different evidence), so the
    cap is spent around the alert instead of on one edge of a 2N-hour span. Unanchored:
    newest first, as before. Without any ORDER the cap returns an ARBITRARY 50."""
    if anchor:
        return [f"| extend SecondsFromAlert = datetime_diff('second', {field}, datetime({anchor}))",
                "| order by abs(SecondsFromAlert) asc"]
    return [f"| order by {field} desc"]


# ── MDE (Advanced Hunting — Device* tables, time field `Timestamp`) ──────────

def mde_process(device: str = "", process_name: str = "", window_hours: int = 24,
                anchor_iso: str = "") -> str:
    """Process executions on a device and/or by process name (incl. the initiating
    parent) — the day-to-day process-correlation / process-tree hunt."""
    if not (device or process_name):
        raise ValueError("hunt_process needs at least a device or a process_name")
    rng, anchor = _window("Timestamp", window_hours, anchor_iso)
    q = ["DeviceProcessEvents", rng]
    if device:
        q.append(f"| where DeviceName =~ {_lit(device)}")
    if process_name:
        q.append(f"| where FileName =~ {_lit(process_name)} or InitiatingProcessFileName =~ {_lit(process_name)}")
    q.append("| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, "
             "InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256")
    q += _order("Timestamp", anchor)
    return _build(q)


def mde_device_timeline(device: str, start_iso: str, end_iso: str, limit: int = 30,
                        per_table: int = 12) -> str:
    """Cross-table device timeline for a bounded window, chronological.

    Replaces `GET /api/machines/{id}/events`, which does not exist in the Defender
    API (404 for every device). Unions the tables that actually carry endpoint
    activity — including DeviceEvents, where AntivirusDetection / ScriptContent land.
    DeviceEvents matters disproportionately on macOS/Linux: on DEMO-107628 the four
    Impacket AV detections existed ONLY there, so any timeline built from the
    process/file tables alone came back empty on a device that was far from clean.

    `datetime(...)` literals rather than ago() so the window can be anchored on the
    ALERT time instead of "now" (a triage running hours later still sees the event).
    """
    if not device:
        raise ValueError("mde_device_timeline needs a device")
    d = _lit(device)
    rng = f'| where Timestamp between (datetime({start_iso}) .. datetime({end_iso}))'
    # Per-table cap, applied INSIDE each branch. Without it one chatty table swamps
    # the result: an unrestricted union on a normal macOS endpoint came back 41/50
    # DeviceProcessEvents (xpcproxy churn), starving every other table. Capping per
    # branch guarantees each evidence source is represented. Newest-first inside the
    # branch, because the events nearest the alert matter most.
    cap = f'| order by Timestamp desc | take {int(per_table)}'
    parts = [
        # DEDICATED detections branch, capped separately so it can never be evicted.
        # A single DeviceEvents branch capped newest-first drops them: ScriptContent
        # churn (~220/window here) is NEWER than the detection, so the 4 real
        # AntivirusDetection rows fell out of the cap and the tool reported none on a
        # device that had four. Detections are rare, so their own branch is cheap.
        f'DeviceEvents {rng} | where DeviceName =~ {d} '
        '| where ActionType contains "AntivirusDetection" '
        f'| order by Timestamp desc | take {int(per_table)} '
        '| project Timestamp, Table="DeviceEvents", ActionType, FileName, FolderPath, '
        'AccountName, ProcessCommandLine=InitiatingProcessCommandLine, SHA256',
        f'DeviceEvents {rng} | where DeviceName =~ {d} '
        '| where ActionType !contains "AntivirusDetection" '
        f'{cap} '
        '| project Timestamp, Table="DeviceEvents", ActionType, FileName, FolderPath, '
        'AccountName, ProcessCommandLine=InitiatingProcessCommandLine, SHA256',
        f'DeviceProcessEvents {rng} | where DeviceName =~ {d} {cap} '
        '| project Timestamp, Table="DeviceProcessEvents", ActionType="ProcessCreated", '
        'FileName, FolderPath, AccountName, ProcessCommandLine, SHA256',
        f'DeviceFileEvents {rng} | where DeviceName =~ {d} {cap} '
        '| project Timestamp, Table="DeviceFileEvents", ActionType, FileName, FolderPath, '
        'AccountName=InitiatingProcessAccountName, '
        'ProcessCommandLine=InitiatingProcessCommandLine, SHA256',
        f'DeviceNetworkEvents {rng} | where DeviceName =~ {d} {cap} '
        '| project Timestamp, Table="DeviceNetworkEvents", ActionType, FileName=RemoteUrl, '
        'FolderPath=tostring(RemoteIP), AccountName=InitiatingProcessAccountName, '
        'ProcessCommandLine=InitiatingProcessCommandLine, SHA256="" ',
        f'DeviceLogonEvents {rng} | where DeviceName =~ {d} {cap} '
        '| project Timestamp, Table="DeviceLogonEvents", ActionType, FileName="", FolderPath="", '
        'AccountName, ProcessCommandLine=InitiatingProcessCommandLine, SHA256="" ',
    ]
    # Rank BEFORE truncating, then restore chronological order. A plain
    # `order by Timestamp asc | take N` keeps the EARLIEST N rows, which on a busy
    # endpoint is startup/CDN noise (xpcproxy, itunes) while the detection that
    # triggered the alert falls outside the cap — verified on DEMO-107628, where the
    # AntivirusDetection rows sat ~1h past the first 50 events. Security-relevant
    # rows are selected first so the cap can never silently drop them.
    # `contains` not `has`: "AntivirusDetection" is a single Kusto token, so
    # `has "Antivirus"` does NOT match it.
    return (
        "union isfuzzy=true\n(" + "),\n(".join(parts) + ")\n"
        # "AntivirusDetection" specifically, NOT `contains "Antivirus"`: the routine
        # "AntivirusReport" heartbeat runs to ~150/device/day and would monopolise the
        # cap it is meant to protect, pushing out the actual detections.
        '| extend _p = case(ActionType contains "AntivirusDetection", 0, '
        'Table == "DeviceLogonEvents", 1, '
        'Table == "DeviceProcessEvents", 2, '
        'Table == "DeviceFileEvents", 3, 4)\n'
        # `order by … | take N`, not `top N by …` — Kusto's `top` accepts only ONE
        # sort expression and 400s ("incomplete fragment") on a second key.
        "| order by _p asc, Timestamp asc\n"
        f"| take {int(limit)}\n"
        "| order by Timestamp asc\n"
        "| project-away _p"
    )


# Directories whose write volume is machine noise, not user data. Removing them is
# what makes a burst query usable at all: fleet-wide over 24h an unfiltered query
# returns 1,273 "bursts" (>=25 files) vs 331 once these are excluded. TRADE-OFF: real
# ransomware does encrypt AppData (browser profiles, mail stores), so these exclusions
# buy signal at the cost of coverage there — the burst tool is a fast-bulk-write
# detector, NOT a general ransomware detector.
_BURST_NOISE_DIRS = (
    "\\\\AppData\\\\", "\\\\Windows\\\\", "\\\\ProgramData\\\\", "\\\\Program Files",
    "/Library/", "/private/var/", "/usr/", "/proc/",
)
# Files-touched floor for one (device, process) pair. Measured on this fleet over 24h:
# >=25 flags a burst on 169 of 707 devices (24% — one alert in four would carry a
# distractor), >=50 flags 17 (2.4%). 50 is where the signal survives and the noise
# mostly doesn't; the residue at 50 is git on build agents and explorer.exe.
_BURST_MIN_FILES = 50


# IP -> device resolution window, in hours EITHER SIDE of the alert. Measured on this
# fleet: over 30 days 18.3% of private IPs map to more than one device (516 of 2,813);
# inside a 2h window that falls to 4.1% (38 of 935). RFC-1918 space is heavily reused —
# 192.168.1.5 belongs to 74 devices over 30d but 10 in a 2h window — so a wide lookup is
# wrong roughly one time in five. Keep it tight; ambiguity is reported, never guessed at.
_IP_OWNER_WINDOW_HOURS = 1


def mde_ip_owner(ip: str, anchor_iso: str = "", window_hours: int = _IP_OWNER_WINDOW_HOURS) -> str:
    """Which device HELD this IP at the time of the alert (DeviceNetworkInfo).

    DeviceNetworkInfo is a STATE table — a periodic snapshot of each device's network
    configuration (~4 rows/device/hour here, 30d retention) — not an event table. Every
    other hunt in this module asks "what happened"; this asks "whose address was that",
    which no event table can answer. Without it a network alert that names only a source
    IP has nothing to bind a host from: DEMO-107982 and nine sibling beaconing alerts each
    carried the same source IP and each named a DIFFERENT, wrong device, none of them the
    machine that actually owned 192.168.75.49 (prdaccord49.corp.example.com, 761 connections to the
    flagged destination).

    Returns one row per device seen holding `ip` in the window, with a count — so the
    CALLER can tell a unique owner from an ambiguous one. Deliberately not `take 1`:
    picking the top row would reintroduce exactly the silent-wrong-host failure this
    exists to fix.
    """
    if not ip or not str(ip).strip():
        raise ValueError("mde_ip_owner needs an ip")
    _ip = _lit(str(ip).strip())
    if anchor_iso:
        # Anchored on the ALERT time, not "now" — a triage (or a replay) running hours
        # later must still see who held the address when the alert fired.
        rng = (f"| where Timestamp between (datetime({anchor_iso}) - {_win(window_hours)}h "
               f".. datetime({anchor_iso}) + {_win(window_hours)}h)")
    else:
        rng = f"| where Timestamp > ago({_win(window_hours)}h)"
    return _build([
        "DeviceNetworkInfo",
        rng,
        f"| where IPAddresses has {_ip}",
        "| summarize snapshots=count(), seen_from=min(Timestamp), seen_to=max(Timestamp) "
        "by DeviceName, DeviceId",
        "| order by snapshots desc",
    ])


def mde_file_burst(device: str = "", window_hours: int = 24,
                   min_files: int = _BURST_MIN_FILES,
                   start_iso: str = "", end_iso: str = "", anchor_iso: str = "") -> str:
    """Mass file-write bursts per (process, PID) on a device — the ransomware shape.

    A timeline CANNOT show this. A burst is a statistical property (how many files,
    how fast, where), and any row-sampling view returns individual filenames instead.
    On DEMO-107770 — a deliberate ransomware simulation — the burst was 262 file events
    inside a 1,077-event window with 110 events NEWER than it, so a newest-first
    timeline sampled right past it: at per_table=12 AND at 60 the burst was invisible,
    while this aggregate returns it as one line:
        powershell.exe (4328) — 248 files, 21s, 709/min, C:\\Users\\admin\\Desktop\\IMP_Data_BKP

    Counts WRITES, not encryption: a backup job writing 300 files and ransomware
    encrypting 300 files are identical here. Treat a hit as "explain this", not as a
    verdict — the deciding evidence is the process, the folder, and whether a ransom
    note or extension change accompanies it.
    """
    if not device:
        raise ValueError("mde_file_burst needs a device")
    if start_iso and end_iso:
        rng = f"| where Timestamp between (datetime({start_iso}) .. datetime({end_iso}))"
    else:
        rng, _ = _window("Timestamp", window_hours, anchor_iso)
    noise =" and ".join(f'FolderPath !contains "{d}"' for d in _BURST_NOISE_DIRS)
    q = [
        "DeviceFileEvents",
        rng,
        f"| where DeviceName =~ {_lit(device)}",
        '| where ActionType in ("FileCreated","FileModified","FileRenamed")',
        f"| where {noise}",
        "| summarize Files=dcount(FileName), Events=count(), FirstSeen=min(Timestamp), "
        "LastSeen=max(Timestamp), Folders=dcount(FolderPath), SampleFolder=any(FolderPath), "
        "SampleFile=any(FileName) by InitiatingProcessFileName, InitiatingProcessId, "
        "InitiatingProcessAccountName",
        "| extend Seconds = datetime_diff('second', LastSeen, FirstSeen)",
        "| extend FilesPerMin = round(Files * 60.0 / iff(Seconds == 0, 1, Seconds), 1)",
        f"| where Files >= {max(1, int(min_files))}",
        "| order by Files desc",
    ]
    return _build(q)


def mde_events(device: str = "", file_name: str = "", action_type: str = "",
               sha256: str = "", window_hours: int = 24, anchor_iso: str = "") -> str:
    """DeviceEvents — the catch-all endpoint table the other builders don't reach.

    This is where AntivirusDetection lands, plus ScriptContent, PowerShellCommand,
    UsbDriveMounted, LDAP/WMI/memory-API activity, etc. It matters most on
    macOS/Linux: a file that AV detected but that was never EXECUTED emits no
    DeviceProcessEvents row and (if it was downloaded outside the window) no
    DeviceFileEvents row either, so process/file hunts return 0 and the endpoint
    looks clean. DEMO-107628: four Impacket detections existed ONLY here while
    hunt_process/hunt_file both came back empty.

    At least one filter is required — DeviceEvents is high-volume (tens of
    thousands of rows/day fleet-wide), so an unfiltered scan is never useful.
    `action_type` matches by substring, so "Antivirus" catches AntivirusDetection
    and AntivirusReport while "AntivirusDetection" narrows to real detections.

    Projects both principal columns (AccountName = the subject the event is ABOUT,
    InitiatingProcessAccountName = who ran it), not just AccountName — DEMO-108975:
    for UserAccountAddedToLocalGroup the acting grantor lives only in
    InitiatingProcessAccountName, and the old projection made a real row look empty.
    """
    if not (device or file_name or action_type or sha256):
        raise ValueError(
            "hunt_events needs at least a device, file_name, action_type or sha256"
        )
    if sha256 and not _HEX_HASH_RE.match(sha256.strip()):
        raise ValueError(f"'{sha256}' is not a valid md5/sha1/sha256 hex hash")
    rng, anchor = _window("Timestamp", window_hours, anchor_iso)
    q = ["DeviceEvents", rng]
    if device:
        q.append(f"| where DeviceName =~ {_lit(device)}")
    if action_type:
        q.append(f"| where ActionType contains {_lit(action_type)}")
    if file_name:
        # FileName or the initiating process — a detection may name either.
        q.append(f"| where FileName =~ {_lit(file_name)} "
                 f"or InitiatingProcessFileName =~ {_lit(file_name)}")
    if sha256:
        h = sha256.strip()
        col = {64: "SHA256", 40: "SHA1", 32: "MD5"}[len(h)]
        q.append(f"| where {col} =~ {_lit(h)}")
    q.append("| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, "
             "AccountName, AccountDomain, AccountSid, InitiatingProcessFileName, "
             "InitiatingProcessCommandLine, InitiatingProcessAccountName, "
             "InitiatingProcessAccountDomain, InitiatingProcessAccountSid")
    q += _order("Timestamp", anchor)
    return _build(q)


def mde_process_details(names: list, window_hours: int = 168) -> str:
    """Resolve a set of flagged process NAMES to their distinct hash + on-disk path
    + file-version vendor (ProcessVersionInfoCompanyName / ProductName), FLEET-WIDE.

    Deliberately NOT device-scoped: a long-running *service* started before the window
    emits no DeviceProcessEvents launch on its own host, so a device-scoped query comes
    back empty (verified — even at 30d). Keying on the already-flagged (rare) FileNames
    across the fleet reliably identifies each binary: a recognized signed vendor seen on
    many devices is strong benign evidence; a blank vendor or a Temp/ProgramData path is
    a masquerade tell. Deduped to one row per (FileName, SHA256, path, vendor)."""
    _names = [n for n in (names or []) if n]
    if not _names:
        raise ValueError("mde_process_details needs at least one process name")
    namelist = ", ".join(_lit(n) for n in _names)
    q = [
        "DeviceProcessEvents",
        f"| where Timestamp > ago({_win(window_hours)}h)",
        f"| where FileName in~ ({namelist})",
        "| summarize Count=count(), Devices=dcount(DeviceName), LastSeen=max(Timestamp) by "
        "FileName, SHA256, FolderPath, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName",
        "| order by FileName asc",
    ]
    return _build(q)


# Admin-only install folders, for KQL's RE2 inside a verbatim @"" string. Same set as
# edr_triage.service_allowlist.STANDARD_LOCATION_RE (kept in step by a test).
#
# windows\cluster\ added 2026-10-26 (DEMO-118550): clussvc.exe is Microsoft's own Failover
# Clustering service binary, and C:\Windows\Cluster\ — not System32 — is its real,
# Windows-Update-managed install location (confirmed: poqexec.exe wrote it there from a
# WinSxS\pending.xml transaction, staged moments earlier by TiWorker.exe under a genuine
# microsoft-windows-failovercluster-clussvc component manifest). Same admin-only tier as
# System32: only SYSTEM/TrustedInstaller creates or writes to it. Absent from this list,
# hunt_service called it "outside the standard install folders" and that framing is what
# both RAPTOR and the prior AI triage read as evidence of a masquerade.
STANDARD_LOCATION_KQL = (r"(?i)^[a-z]:\\(windows\\(system32|syswow64|winsxs|cluster)\\"
                         r"|program files( \(x86\))?\\"
                         r"|programdata\\microsoft\\(windows defender|microsoft defender)\\)")


# Writable-by-users folders inside System32/SysWOW64, excluded from the set above. Same
# list as edr_triage.service_allowlist.WRITABLE_UNDER_WINDOWS_RE (kept in step by a test).
WRITABLE_UNDER_WINDOWS_KQL = (r"(?i)\\windows\\(system32|syswow64)\\(tasks|tasks_migrated|com\\dmp|fxstmp"
                              r"|spool\\(drivers\\color|printers|servers)|microsoft\\crypto\\rsa\\machinekeys)\\")


def mde_service_identity(names: list, lookback_days: int = 30) -> str:
    """Identify flagged SERVICE binaries by AUTHENTICODE SIGNER + fleet prevalence.

    'Rare Process as a Service' is the single biggest live source of wrong escalations,
    and the cause is structural rather than a model mistake: a service starts at boot and
    then persists, so it emits NO DeviceProcessEvents launch inside any triage window.
    Every process hunt therefore comes back empty, and the agent — correctly — refuses to
    read that emptiness as benign. DEMO-107943 ran 27 tool calls and still could not
    commit; DEMO-107772 said it plainly: "returned no results for the past 24 hours and
    7 days. This does not confirm their absence."

    Neither does ServiceInstalled rescue it — that only fires on NEW installs (159,932 in
    30d, none of them these long-running services). The question "is this rare service
    legitimate" is not a question about events at all; it is a question about the BINARY.
    So this asks the binary: who signed it, is that signature trusted, and how much of the
    fleet runs it. Verified against the exact names from those tickets — spoolsv.exe 483
    devices/Microsoft Windows, elevation_service.exe 458/Google LLC+Microsoft,
    gc_extension_service.exe 40/Microsoft, ipf_uf.exe 12/Intel — all signed and trusted.

    Keys on the Authenticode Signer from DeviceFileCertificateInfo, NOT on the
    version-info CompanyName that mde_process_details uses: CompanyName is attacker-
    controlled string metadata (the cowork-svc.exe false-flag case), while a trusted
    signature chain is not forgeable.

    DeviceFileEvents is deliberately NOT unioned in: it surfaces WinSxS / CbsTemp /
    InFlight servicing copies that carry no certificate row, which would make a
    Microsoft-signed OS binary look partly unsigned. Image-load + process-launch cover
    the running service.

    One row per FileName. TrustedHashes < Hashes means some copies are unsigned — the
    masquerade tell — so both counts are returned rather than a single verdict.
    """
    _names = [n for n in (names or []) if n]
    if not _names:
        raise ValueError("mde_service_identity needs at least one process name")
    namelist = ", ".join(_lit(n) for n in _names)
    try:
        _d = int(lookback_days)
    except (TypeError, ValueError):
        _d = 30
    # DeviceFileCertificateInfo / DeviceImageLoadEvents retain 30d; asking for more can
    # only ever return less, and "less" here reads as "unsigned".
    _d = max(1, min(_d, 30))
    return _build([
        f"let names = dynamic([{namelist}]);",
        f"let lookback = {_d}d;",
        # A service started at boot weeks ago has no launch or image-load row of its own
        # inside any lookback, so those two branches alone came back EMPTY for exactly the
        # long-running services this alert flags (DEMO-116509, 2026-10-13: 0 rows for
        # CxAudioSvc.exe while hunt_process found its children). The running binary is
        # still on every event it INITIATES, with its own folder and hash: CxAudioSvc.exe
        # 23 devices, FMService64.exe 18, Goodix 11, FortiClient scheduler.exe 46.
        # Distinct-ed inside each branch so a chatty service cannot flood the union.
        "let seen = union isfuzzy=true",
        " (DeviceImageLoadEvents | where Timestamp > ago(lookback) | where FileName in~ (names)"
        " | distinct FileName, DeviceName, FolderPath, SHA1),",
        " (DeviceProcessEvents   | where Timestamp > ago(lookback) | where FileName in~ (names)"
        " | distinct FileName, DeviceName, FolderPath, SHA1),",
        " (DeviceProcessEvents   | where Timestamp > ago(lookback)"
        " | where InitiatingProcessFileName in~ (names)"
        " | distinct FileName=InitiatingProcessFileName, DeviceName,"
        " FolderPath=InitiatingProcessFolderPath, SHA1=InitiatingProcessSHA1),",
        " (DeviceNetworkEvents   | where Timestamp > ago(lookback)"
        " | where InitiatingProcessFileName in~ (names)"
        " | distinct FileName=InitiatingProcessFileName, DeviceName,"
        " FolderPath=InitiatingProcessFolderPath, SHA1=InitiatingProcessSHA1)",
        # One row per binary whatever case each table logged it in.
        " | extend FileName=tolower(FileName)",
        " | where isnotempty(SHA1);",
        "let certs = DeviceFileCertificateInfo | where Timestamp > ago(lookback)",
        " | summarize Signer=take_any(Signer), Signed=max(toint(IsSigned)),"
        " Trusted=max(toint(IsTrusted)) by SHA1;",
        "let prevalence = seen | summarize Devices=dcount(DeviceName) by FileName;",
        "seen",
        # Odd = this hash ran from outside the admin-only install folders. Counted over
        # EVERY copy (Paths below is only a 3-path sample), so an unsigned impostor of a
        # signed vendor name on one host cannot hide behind the genuine copies elsewhere.
        f"| extend Std = FolderPath matches regex @\"{STANDARD_LOCATION_KQL}\""
        f" and not(FolderPath matches regex @\"{WRITABLE_UNDER_WINDOWS_KQL}\")",
        "| summarize Path=take_any(FolderPath), Odd=max(toint(not(Std))) by FileName, SHA1",
        "| join kind=leftouter certs on SHA1",
        # Three-way, NOT trusted-vs-everything-else. A hash with no row in
        # DeviceFileCertificateInfo is a COVERAGE GAP, not an unsigned binary, and
        # collapsing the two made trusted vendors look partly unsigned: vmcompute.exe
        # (C:\\Windows\\System32, Microsoft Windows) came back 3-of-4 and the agent
        # escalated it as "unsigned hashes … requires L2 review".
        "| summarize Hashes=dcount(SHA1), TrustedHashes=countif(Trusted==1),"
        " UntrustedHashes=countif(Trusted==0), NoCertRecord=countif(isnull(Trusted)),"
        " OddUnverifiedHashes=countif(Odd==1 and isnull(Trusted)),"
        " Signers=make_set(Signer, 6), Paths=make_set(Path, 3) by FileName",
        "| join kind=inner prevalence on FileName",
        "| project FileName, Devices, Hashes, TrustedHashes, UntrustedHashes,"
        " NoCertRecord, OddUnverifiedHashes, Signers, Paths",
        "| order by Devices desc",
    ])


def mde_script_egress(device: str, process_name: str = "powershell",
                      lookback_days: int = 7, anchor_iso: str = "") -> str:
    """WHERE a script actually connected — resolves a parameterised URL to real hosts.

    A 'PowerShell script was loaded in memory' alert captures the script TEXT, and that
    text routinely contains variables rather than values:
        Invoke-RestMethod -Uri "$ApiUrl/api/agent/report" -Headers @{ 'X-API-Key' = $ApiKey }
    Two executions with byte-identical command lines can post to completely different
    places, so matching on the command proves the script's SHAPE, never its destination.
    That is the one hole in closing this family on an exact-command precedent, and it is
    the question an analyst asks first: where did it actually go?

    DeviceNetworkEvents answers it. On e849bqinitwl2 every PowerShell egress in 30 days
    resolved to ironwatch.uat.example.com:443 (plus OCSP certificate checks and internal
    LDAP) — one destination, internal, no divergence.

    Summarised by destination rather than row-by-row, and over DAYS not hours, on
    purpose: the alert fires on the script LOAD, and the matching connection frequently
    falls outside any tight window around it (the 35-minute window around DEMO-107067
    returned zero rows while the daily 03:30 runs were plainly visible). What decides the
    verdict is the SET of destinations this script reaches on this host, not one packet.
    """
    if not device:
        raise ValueError("mde_script_egress needs a device")
    try:
        _d = int(lookback_days)
    except (TypeError, ValueError):
        _d = 7
    _d = max(1, min(_d, 30))
    # Anchored: the N days before the alert plus a day after it, so a replay of an old
    # ticket summarises the script's destinations around THAT load, not this week's.
    anchor = _ts(anchor_iso)
    rng = (f"| where Timestamp between (datetime({anchor}) - {_d}d .. datetime({anchor}) + 1d)"
           if anchor else f"| where Timestamp > ago({_d}d)")
    q = [
        "DeviceNetworkEvents",
        rng,
        f"| where DeviceName startswith {_lit(str(device).split('.')[0])}",
    ]
    if process_name:
        q.append(f"| where InitiatingProcessFileName has {_lit(process_name)}")
    q += [
        "| summarize Calls=count(), First=min(Timestamp), Last=max(Timestamp),"
        " Ports=make_set(RemotePort, 5) by RemoteUrl, RemoteIP",
        "| order by Calls desc",
    ]
    return _build(q)


def mde_network(device: str = "", remote_ip: str = "", remote_url: str = "",
                window_hours: int = 24, anchor_iso: str = "") -> str:
    """Network connections from a device / to an IP / to a URL (domain).

    `anchor_iso` CENTRES the window on the alert instead of ending it at now. On a busy
    host those are different questions: a device-wide sweep with no remote_ip to pivot
    on matches thousands of rows, `| take 50` keeps only the newest, and on a re-triage
    the newest are the connections nearest the RE-RUN. DEMO-108670 is the case — the
    agent asked the right arrival-vector question and got back an hour of traffic that
    postdated the detection entirely.

    Two properties make switching the anchor on safe:
      * `window_hours` stays the TOTAL span in both modes — anchored it is split either
        side of the alert — so an anchor can only ever MOVE the window, never widen it;
      * rows are ordered by PROXIMITY to the anchor rather than newest-first, because
        `| take 50` over a 24h span would otherwise spend the entire cap on one edge.
    SecondsFromAlert is kept in the output: "12s before the detection" and "9h after"
    are different evidence, and nothing else in the row says which one you are reading.
    """
    if not (device or remote_ip or remote_url):
        raise ValueError("hunt_network needs at least a device, remote_ip or remote_url")
    anchor = _ts(anchor_iso)
    if anchor:
        # Half-width in MINUTES, not hours: at window_hours=1 an integer-hour halving
        # floors to 0, and clamping that back up to 1h would make the anchored window
        # 2h — wider than the unanchored one it replaces. Minutes halve exactly at
        # every window size, which is what keeps "never widens" true rather than
        # true-for-the-common-case.
        half_min = max(1, (_win(window_hours) * 60) // 2)
        q = ["DeviceNetworkEvents",
             f"| where Timestamp between (datetime({anchor}) - {half_min}m .. datetime({anchor}) + {half_min}m)"]
    else:
        q = ["DeviceNetworkEvents", f"| where Timestamp > ago({_win(window_hours)}h)"]
    if device:
        q.append(f"| where DeviceName =~ {_lit(device)}")
    if remote_ip:
        q.append(f"| where RemoteIP == {_lit(remote_ip)}")
    if remote_url:
        q.append(f"| where RemoteUrl has {_lit(remote_url)}")
    q.append("| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, "
             "InitiatingProcessFileName, InitiatingProcessCommandLine")
    # Deterministic ordering: _build appends `| take 50`, and without an ORDER that cap
    # returns an ARBITRARY 50 of however many matched.
    if anchor:
        q.append(f"| extend SecondsFromAlert = datetime_diff('second', Timestamp, datetime({anchor}))")
        q.append("| order by abs(SecondsFromAlert) asc")
    else:
        q.append("| order by Timestamp desc")
    return _build(q)


def mde_file(sha256: str = "", file_name: str = "", device: str = "", window_hours: int = 24,
             anchor_iso: str = "") -> str:
    """File events by hash (md5/sha1/sha256) / file name / device."""
    if not (sha256 or file_name or device):
        raise ValueError("hunt_file needs at least a sha256, file_name or device")
    if sha256 and not _HEX_HASH_RE.match(sha256.strip()):
        raise ValueError(f"'{sha256}' is not a valid md5/sha1/sha256 hex hash")
    rng, anchor = _window("Timestamp", window_hours, anchor_iso)
    q = ["DeviceFileEvents", rng]
    if sha256:
        h = sha256.strip()
        col = {64: "SHA256", 40: "SHA1", 32: "MD5"}[len(h)]
        q.append(f"| where {col} =~ {_lit(h)}")
    if file_name:
        q.append(f"| where FileName =~ {_lit(file_name)}")
    if device:
        q.append(f"| where DeviceName =~ {_lit(device)}")
    # Where the file came from decides most "unsigned binary" alerts: DEMO-121950's
    # jit-cli-s3 was downloaded from jit.example.com, a fact the agent never saw.
    # Query strings are cut (S3 presigned links carry a signature).
    q.append("| extend FileOriginUrl = tostring(split(FileOriginUrl, '?')[0]), "
             "FileOriginReferrerUrl = tostring(split(FileOriginReferrerUrl, '?')[0])")
    q.append("| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ActionType, "
             "InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl, "
             "FileOriginReferrerUrl")
    q += _order("Timestamp", anchor)
    return _build(q)


def mde_file_prevalence(sha256: str, days: int = 29, anchor_iso: str = "") -> str:
    """Every device that has held this file in the last `days` (MDE keeps 30), with where
    each copy was downloaded from. One row per device.

    hunt_file is clamped to +-7 days around the alert, which on DEMO-121950 showed the
    internal JIT tool on 1 other Mac instead of 8 and no download source at all.
    """
    h = (sha256 or "").strip()
    if not _HEX_HASH_RE.match(h):
        raise ValueError(f"'{sha256}' is not a valid md5/sha1/sha256 hex hash")
    col = {64: "SHA256", 40: "SHA1", 32: "MD5"}.get(len(h))
    if not col:
        raise ValueError(f"'{sha256}' is not a valid md5/sha1/sha256 hex hash")
    d = max(1, min(int(days or 29), 29))
    anchor = _ts(anchor_iso)
    rng = (f"| where Timestamp between (datetime({anchor}) - {d}d .. datetime({anchor}) + 1h)"
           if anchor else f"| where Timestamp > ago({d}d)")
    return "\n".join([
        "DeviceFileEvents", rng,
        f"| where {col} =~ {_lit(h)}",
        "| extend Origin = tostring(split(FileOriginUrl, '?')[0]), "
        "Referrer = tostring(split(FileOriginReferrerUrl, '?')[0])",
        "| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Events = count(), "
        "Origins = make_set_if(Origin, isnotempty(Origin), 5), "
        "Referrers = make_set_if(Referrer, isnotempty(Referrer), 5), "
        "Names = make_set(FileName, 5), Paths = make_set(FolderPath, 5) by DeviceName",
        "| order by FirstSeen asc",
        f"| take {MAX_ROWS}",
    ])


def mde_logons(device: str = "", account: str = "", window_hours: int = 24,
               anchor_iso: str = "") -> str:
    """Logon events on a device / by an account."""
    if not (device or account):
        raise ValueError("hunt_logons needs at least a device or an account")
    rng, anchor = _window("Timestamp", window_hours, anchor_iso)
    q = ["DeviceLogonEvents", rng]
    if device:
        q.append(f"| where DeviceName =~ {_lit(device)}")
    if account:
        q.append(f"| where AccountName =~ {_lit(account)}")
    q.append("| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, ActionType, "
             "InitiatingProcessFileName")
    q += _order("Timestamp", anchor)
    return _build(q)


# ── Sentinel (Log Analytics — time field `TimeGenerated`) ────────────────────

def sentinel_signin(upn: str = "", window_hours: int = 24, anchor_iso: str = "") -> str:
    """Azure AD interactive sign-ins for a user principal name."""
    if not upn:
        raise ValueError("hunt_signin needs a upn")
    rng, anchor = _window("TimeGenerated", window_hours, anchor_iso)
    return _build([
        "SigninLogs",
        rng,
        f"| where UserPrincipalName =~ {_lit(upn)}",
        "| project TimeGenerated, UserPrincipalName, ResultType, ResultDescription, "
        "IPAddress, AppDisplayName, Location",
        *_order("TimeGenerated", anchor),
    ])


def sentinel_signin_ips(upn: str = "", window_hours: int = 24, anchor_iso: str = "") -> str:
    """Per SOURCE IP for a UPN, over both sign-in tables: volume, failures, successes,
    network (ASN) and country — what an analyst asks first about a failure spike.

    DEMO-116466 (2026-10-10) called 24.239.151.201/.202 "internal (India)" with no lookup.
    They are AS55256, Netskope's egress, which ~400 Acme users sign in through: right
    by luck, and beside the point — a shared egress cannot say WHO signed in. Typed with
    tostring() because the two tables disagree on column types.
    """
    if not upn:
        raise ValueError("sentinel_signin_ips needs a upn")
    rng, _anchor = _window("TimeGenerated", window_hours, anchor_iso)
    branch = (f" | {rng.lstrip('| ')} | where UserPrincipalName =~ {_lit(upn)}"
              " | project IPAddress, ResultType=tostring(ResultType),"
              " ASN=tostring(AutonomousSystemNumber), Country=tostring(Location)")
    return _build([
        "union",
        f" (SigninLogs{branch}),",
        f" (AADNonInteractiveUserSignInLogs{branch})",
        "| summarize Events=count(), Failures=countif(ResultType != \"0\"),"
        " Successes=countif(ResultType == \"0\"), ASN=take_anyif(ASN, isnotempty(ASN)),"
        " Country=take_anyif(Country, isnotempty(Country)) by IPAddress",
        "| order by Events desc",
    ])


def sentinel_signin_summary(upn: str = "", window_hours: int = 24, anchor_iso: str = "") -> str:
    """Sign-in OUTCOMES for a UPN, counted — the shape a failure-spike alert asks about.

    'Privileged Accounts - Sign in Failure Spikes' is a question about counts, and no
    row sample can answer it. DEMO-107545 is the proof: the row hunt returned 50 of 1,561
    matching rows and the agent concluded "the sign-in logs for the last 24 hours show
    only successful sign-ins … the failed sign-ins occurred prior to the 24-hour window",
    then escalated a ticket L1 and L2 both closed FP. The failures were inside the
    window — 608 of them — all ResultType 70044, "session has expired or is invalid due
    to sign-in frequency checks by conditional access", which is the benign explanation
    the analysts closed on.

    Returns one row per (Table, ResultType, ResultDescription) with counts and first/last
    seen, so the failure volume and its REASON are both visible without paging through rows.

    Counts BOTH sign-in tables, as the analytics rule does. DEMO-115064: SigninLogs alone
    showed 25 successes and no failure, the agent read that as "directly contradicts the
    alert" and auto-closed — the spike was not in the table it looked at.
    """
    if not upn:
        raise ValueError("sentinel_signin_summary needs a upn")
    rng, who = _window("TimeGenerated", window_hours, anchor_iso)[0], _lit(upn)
    return _build([
        "union isfuzzy=true",
        f"    (SigninLogs {rng} | where UserPrincipalName =~ {who}"
        " | extend Table = \"interactive\"),",
        f"    (AADNonInteractiveUserSignInLogs {rng}"
        f" | where UserPrincipalName =~ {who} | extend Table = \"non-interactive\")",
        "| extend ResultType = tostring(ResultType)",
        "| summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated),"
        " IPs=dcount(IPAddress), Apps=make_set(AppDisplayName, 5)"
        " by Table, ResultType, ResultDescription",
        "| order by Events desc",
    ])


# Entra result codes that mean "a password was tried and was wrong" (50126: invalid
# username or password) or "wrong so often the account locked" (50053). These are what a
# password spray produces. Deliberately NOT 70044 (Conditional Access sign-in-frequency
# expiry), which is this tenant's dominant BENIGN cause of failure spikes — DEMO-107545 had
# 608 of them — and is not a wrong-password event at all.
SPRAY_FAILURE_CODES = ("50126", "50053")


def sentinel_signin_spray_check(upns: list[str], anchor_iso: str = "",
                                before_hours: int = 24, until_iso: str = "") -> str:
    """For each account: invalid-password failures, and any SUCCESS that came after them.

    The question behind "never auto-close a sign-in failure spike when a success follows
    invalid-password failures". Counting outcomes by type (sentinel_signin_summary) shows
    that a success exists, but not whether it came AFTER the failures — which is the
    difference between a user who logged in and later mistyped, and a spray that got in.
    One row per account: BadPw, FirstBadPw, SuccessAfterBadPw, FirstSuccessAfter and the
    IPs of those later successes.

    Window runs from `before_hours` before the alert to NOW, not to the alert: a spray
    that succeeds shortly after the alert fired is the case that matters most. Accounts
    given without a domain match any UPN beginning `name@`. `until_iso` caps the window
    for replaying a past ticket as it looked at triage time; production leaves it empty.

    Also counts EVERY failure (`Failures`, any non-zero ResultType, 70044 included) across
    BOTH sign-in tables — the analytics rule unions SigninLogs with
    AADNonInteractiveUserSignInLogs (see edr_triage.sentinel_client.query_signin_logs), so
    a spike can live entirely in the non-interactive table. DEMO-115064 auto-closed at 95%
    on "zero failed sign-ins … directly contradicts the alert": the hunt had searched only
    SigninLogs. `Failures == 0` means the failures that fired the alert were not found,
    which is a gap in the evidence, not exculpation. Successes are still counted from the
    INTERACTIVE table only: a background token refresh after a mistyped password is
    routine, and counting it would change what this guard was measured against.
    """
    names = [u.strip() for u in (upns or []) if u and u.strip()]
    if not names:
        raise ValueError("sentinel_signin_spray_check needs at least one account")
    who = " or ".join(
        f"UserPrincipalName =~ {_lit(u)}" if "@" in u
        else f"UserPrincipalName startswith {_lit(u + '@')}"
        for u in names)
    a, u = _ts(anchor_iso), _ts(until_iso)
    end = f"datetime({u})" if u else "now()"
    span = (f"TimeGenerated between (datetime({a}) - {_win(before_hours)}h .. {end})" if a
            else f"TimeGenerated > ago({_win(before_hours) + 24}h)")
    bad = ", ".join(_lit(c) for c in SPRAY_FAILURE_CODES)
    return "\n".join([
        f"let bad = dynamic([{bad}]);",
        "let s = union isfuzzy=true",
        f"    (SigninLogs | where {span} | where {who} | extend Interactive = true),",
        f"    (AADNonInteractiveUserSignInLogs | where {span} | where {who}"
        " | extend Interactive = false)",
        "| extend rt = tostring(ResultType);",
        "s | summarize BadPw = countif(rt in (bad)), FirstBadPw = minif(TimeGenerated, rt in (bad)),",
        "    Failures = countif(rt != \"0\" and rt != \"\"),",
        "    NonInteractiveFailures = countif(rt != \"0\" and rt != \"\" and not(Interactive))",
        "    by UserPrincipalName",
        "| join kind=leftouter (s | where rt == \"0\" and Interactive"
        " | project UserPrincipalName, SuccessAt = TimeGenerated, IPAddress) on UserPrincipalName",
        "| summarize BadPw = take_any(BadPw), FirstBadPw = take_any(FirstBadPw),",
        "    Failures = take_any(Failures), NonInteractiveFailures = take_any(NonInteractiveFailures),",
        "    SuccessAfterBadPw = countif(isnotnull(FirstBadPw) and SuccessAt > FirstBadPw),",
        "    FirstSuccessAfter = minif(SuccessAt, isnotnull(FirstBadPw) and SuccessAt > FirstBadPw),",
        "    SuccessIPs = make_set_if(IPAddress, isnotnull(FirstBadPw) and SuccessAt > FirstBadPw, 10)",
        "    by UserPrincipalName",
        f"| take {MAX_ROWS}",
    ])


def sentinel_ca_policy_change(actor: str = "", policy: str = "", window_hours: int = 24,
                              anchor_iso: str = "") -> str:
    """Entra Conditional Access policy changes, DIFFED — what actually changed.

    The audit record stores the whole policy as JSON in modifiedProperties.oldValue /
    newValue, so "a Conditional Access policy was updated" is unreadable without
    diffing the two blobs. L1 does that by hand, and their comment is far richer than
    anything RAPTOR produced: DEMO-108035's analyst wrote out the policy name, which
    application and which user left the exclusion lists, that MFA and the 9-hour
    sign-in frequency survived — while RAPTOR's own comment on the same ticket said
    only "Conditional Access policy was updated on host Unknown Device".

    Worse, without this the agent hunts and finds nothing, then reasons from the
    nothing: DEMO-108039 concluded "no such update was found in the Azure AD Audit
    Logs … the alert may be a false positive or a misconfiguration", and DEMO-108099
    tried three times (twice via hunt_query, once with raw KQL against AuditLogs) and
    got 0 rows from all three. AuditLogs is not empty — 118M rows, 6 months, 15
    'Update conditional access policy' operations in the last 7 days. The data was
    always there; the queries could not reach the shape.

    Returns the DELTA per policy: which users/groups/roles/apps entered or left each
    exclusion list, plus the grant controls and enabled state before and after. That
    last pair is the safety question — an exclusion added while grantControls still
    reads ["mfa"] and state stays "enabled" is scoped change management; MFA
    disappearing from grantControls, or the policy flipping to "disabled", is the
    thing this alert class exists to catch.
    """
    # Anchored on the ALERT time, not "now". ago(Nh) asks "did this happen in the last N
    # hours of MY run", which is the wrong question on any replay or any triage picked up
    # after a delay: DEMO-108099 hunted at 24h, got 0 rows, and escalated citing "missing
    # evidence about the policy change" — while the same query at 48h returned the 15 rows
    # that decided its sibling DEMO-108036. Zero rows here reads as "no change found", so a
    # window that merely misses the event manufactures an escalation.
    if anchor_iso:
        rng = (f"| where TimeGenerated between (datetime({anchor_iso}) - {_win(window_hours)}h "
               f".. datetime({anchor_iso}) + {_win(window_hours)}h)")
    else:
        rng = f"| where TimeGenerated > ago({_win(window_hours)}h)"
    q = ["AuditLogs", rng,
         '| where OperationName has "conditional access"']
    if actor:
        q.append(f"| where tostring(InitiatedBy.user.userPrincipalName) has {_lit(actor)}")
    q += [
        "| extend Actor = tostring(InitiatedBy.user.userPrincipalName)",
        "| mv-expand tr = TargetResources",
        "| mv-expand mp = tr.modifiedProperties",
        '| where tostring(mp.displayName) == "ConditionalAccessPolicy"',
    ]
    if policy:
        q.append(f"| where tostring(tr.displayName) has {_lit(policy)}")
    q += [
        "| extend O = parse_json(tostring(mp.oldValue)), N = parse_json(tostring(mp.newValue))",
        # set_difference both ways = what entered and what left each exclusion list.
        "| extend UsersExcl_Added    = set_difference(N.conditions.users.excludeUsers, O.conditions.users.excludeUsers),"
        "         UsersExcl_Removed  = set_difference(O.conditions.users.excludeUsers, N.conditions.users.excludeUsers),"
        "         GroupsExcl_Added   = set_difference(N.conditions.users.excludeGroups, O.conditions.users.excludeGroups),"
        "         GroupsExcl_Removed = set_difference(O.conditions.users.excludeGroups, N.conditions.users.excludeGroups),"
        "         RolesExcl_Added    = set_difference(N.conditions.users.excludeRoles, O.conditions.users.excludeRoles),"
        "         AppsExcl_Added     = set_difference(N.conditions.applications.excludeApplications, O.conditions.applications.excludeApplications),"
        "         AppsExcl_Removed   = set_difference(O.conditions.applications.excludeApplications, N.conditions.applications.excludeApplications),"
        "         Grant_Old = tostring(O.grantControls.builtInControls),"
        "         Grant_New = tostring(N.grantControls.builtInControls),"
        "         State_Old = tostring(O.state), State_New = tostring(N.state)",
        "| project TimeGenerated, Actor, Policy=tostring(tr.displayName), Result,"
        " UsersExcl_Added, UsersExcl_Removed, GroupsExcl_Added, GroupsExcl_Removed,"
        " RolesExcl_Added, AppsExcl_Added, AppsExcl_Removed,"
        " Grant_Old, Grant_New, State_Old, State_New",
        "| order by TimeGenerated desc",
    ]
    return _build(q)


def sentinel_identity_grant(actor: str = "", recipient: str = "", window_hours: int = 24,
                            anchor_iso: str = "") -> str:
    """WHO granted a privileged role/group to WHOM, and WHICH roles (Entra AuditLogs).

    'User added to Microsoft Entra ID Privileged Groups' does not name the account that
    performed the addition — only the account that RECEIVED it. On DEMO-106406 that made
    RAPTOR reason about the wrong person twice over: it first bound the recipient as the
    actor, and after the fail-safe it listed the real grantor as a second RECIPIENT,
    stating "the acting principal (who performed the addition) is not named in the alert"
    and then holding that grantor's history against him — "high risk score (47.5) and 50
    prior alerts, indicating a history of suspicious activity" — when he was the admin
    DOING the granting, for whom a high alert count is expected rather than incriminating.

    The agent could already reach this table (hunt_query returned 50 rows) but concluded
    "the critical fields — acting principal, target group name, and target user — were
    missing". They are present, just not where a hand-written query looks: the role name
    is NOT in TargetResources.displayName (empty for roles) but nested in
    modifiedProperties under Role.DisplayName. Hence a template.

    Returns one row per (Actor, Recipient): who initiated, who received, the set of roles
    granted, and the result. Verified on DEMO-106406 — tatum.shah granted
    hayden.roy five admin roles (Groups / User / Helpdesk / Authentication / Intune
    Administrator) in 33 seconds.

    NOTE for the caller: this answers ATTRIBUTION, not AUTHORISATION. Naming the grantor
    does not establish the grant was sanctioned — a compromised admin account produces
    exactly this shape. It tells you WHO to ask, not that the answer is fine.

    At least one of `actor`/`recipient` is required — DEMO-108975: with both empty this
    ran unfiltered over AuditLogs and returned the top tenant-wide grants by volume,
    which the caller then mistook for evidence about an unrelated (non-Entra) alert.
    """
    if not (actor or recipient):
        raise ValueError(
            "hunt_identity_grant needs at least an actor or recipient — an unscoped "
            "query returns unrelated tenant-wide grants, not evidence about this alert"
        )
    if anchor_iso:
        rng = (f"| where TimeGenerated between (datetime({anchor_iso}) - {_win(window_hours)}h "
               f".. datetime({anchor_iso}) + {_win(window_hours)}h)")
    else:
        rng = f"| where TimeGenerated > ago({_win(window_hours)}h)"
    q = [
        "AuditLogs", rng,
        '| where OperationName has_any ("Add member to role", "Add member to group", '
        '"Add eligible member to role")',
        "| extend Actor = tostring(InitiatedBy.user.userPrincipalName),"
        " ActorApp = tostring(InitiatedBy.app.displayName)",
        "| mv-expand tr = TargetResources",
        '| where tostring(tr.type) == "User"',
        "| extend Recipient = tostring(tr.userPrincipalName)",
        "| mv-expand mp = tr.modifiedProperties",
        # Role.DisplayName / Group.DisplayName — tr.displayName is EMPTY for roles, which
        # is exactly why the free-written hunt came back "missing critical fields".
        '| where tostring(mp.displayName) in ("Role.DisplayName", "Group.DisplayName")',
        "| extend Granted = replace_string(tostring(mp.newValue), '\"', '')",
    ]
    if actor:
        q.append(f"| where Actor has {_lit(actor)}")
    if recipient:
        q.append(f"| where Recipient has {_lit(recipient)}")
    q += [
        "| summarize Roles=make_set(Granted, 10), Events=count(),"
        " First=min(TimeGenerated), Last=max(TimeGenerated)"
        " by Actor, ActorApp, Recipient, Result",
        "| order by Events desc",
    ]
    return _build(q)


# Exchange/O365 parameters whose VALUE decides whether a change is dangerous.
OFFICE_KEY_PARAMS = (
    "UnifiedAuditLogIngestionEnabled", "AdminAuditLogEnabled", "AdminAuditLogAgeLimit",
    "AuditDisabled", "AuditEnabled", "AuditBypassEnabled", "AuditLogAgeLimit",
    "ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward",
    "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "DeleteMessage", "MoveToFolder",
    "AutoForwardEnabled", "AccessRights", "GrantSendOnBehalfTo", "Trustee",
    "SoftDeleteMessage", "MarkAsRead",
)


# High-volume read-only operations, left out of an operation-less hunt_office.
OFFICE_READ_NOISE = (
    "MailItemsAccessed", "FileAccessed", "FileAccessedExtended", "FilePreviewed",
    "PageViewed", "PageViewedExtended", "ListViewed", "SearchQueryPerformed",
)


def sentinel_office_activity(operation: str = "", user: str = "", target: str = "",
                             window_hours: int = 24, anchor_iso: str = "") -> str:
    """Office 365 / Exchange admin operations with the fields that DECIDE them.

    'Rare and potentially high-risk Office operations' is a host-less alert, so no MDE
    hunt can touch it — OfficeActivity is where it lives. The agent could already reach
    that table via hunt_query, but the free-written projections came back too thin to
    conclude on: DEMO-108121 pulled 9 Set-Mailbox rows and still emitted
    REQUEST_JUSTIFICATION because they carried "no critical details like the target
    mailbox, specific parameters modified, or the result status". Meanwhile the siblings
    that closed FP had run NO hunt at all and leaned on the actor's history — the family
    was being decided by how little a run looked, not by evidence.

    So this projects exactly what an analyst reads on an Exchange admin operation:
      Target          OfficeObjectId — WHICH mailbox. Verified live: the ones this
                      service account touches are `SPO_Arbitration_…` and
                      `Soft Deleted Objects\\…`, i.e. Exchange SYSTEM mailboxes.
      ChangedParams   the parameter NAMES from the Parameters JSON (Identity, Force,
                      BypassLiveId, Arbitration, …) — what was actually modified.
      ResultStatus    did it succeed.
      ExternalAccess  false = internal admin action, not an external principal.
      UserType        Admin/Regular, and AppPoolName names the calling component.
    """
    rng, anchor = _window("TimeGenerated", window_hours, anchor_iso)
    q = ["OfficeActivity", rng]
    if operation:
        q.append(f"| where Operation =~ {_lit(operation)}")
    else:
        # A person's mailbox logs hundreds of reads a day; unfiltered, they bury the one
        # rare change the alert is about (DEMO-108455: 50 rows of MailItemsAccessed, no
        # New-InboxRule). Reads stay reachable by naming the operation.
        noise = ", ".join(_lit(o) for o in OFFICE_READ_NOISE)
        q.append(f"| where Operation !in~ ({noise})")
    if user:
        q.append(f"| where UserId has {_lit(user)}")
    if target:
        q.append(f"| where OfficeObjectId has {_lit(target)}")
    keyparams = ", ".join(_lit(p) for p in OFFICE_KEY_PARAMS)
    q += [
        # Parameters is a JSON array of {Name, Value}; pull just the names — the values
        # carry GUIDs/PII and would blow the tool-result truncation for no added signal.
        # KQL verbatim string is SINGLE-quoted here on purpose: the pattern itself
        # contains double quotes, and @"…" cannot carry them unescaped.
        """| extend ChangedParams = strcat_array(extract_all(@'"Name":"([^"]+)"', """
        """tostring(Parameters)), ", ")""",
        # ...except the settings that decide whether a change is dangerous, whose VALUE is
        # the whole question: audit on/off, forwarding and redirect targets, permission
        # grants. DEMO-116600 (2026-10-12) called Set-AdminAuditLogConfig routine without
        # being able to see it set AdminAuditLogEnabled=True; =False would be an attacker
        # blinding the tenant, and the names alone look identical.
        f"| extend KeySettings = todynamic(Parameters)",
        f"| mv-apply kp = KeySettings on (where tostring(kp.Name) in~ ({keyparams})"
        " | summarize KeySettings = strcat_array(make_list(strcat(tostring(kp.Name), \"=\","
        " tostring(kp.Value))), \", \"))",
        "| project TimeGenerated, Operation, UserType, UserId, Target=OfficeObjectId, "
        "ResultStatus, ExternalAccess, ClientIP, AppPoolName, ChangedParams, KeySettings",
        *_order("TimeGenerated", anchor),
    ]
    return _build(q)


def sentinel_security_event(host: str = "", account: str = "", window_hours: int = 24,
                            anchor_iso: str = "") -> str:
    """Windows SecurityEvent rows by host (Computer) and/or account."""
    if not (host or account):
        raise ValueError("hunt_sentinel_event needs at least a host or an account")
    rng, anchor = _window("TimeGenerated", window_hours, anchor_iso)
    q = ["SecurityEvent", rng]
    if host:
        q.append(f"| where Computer =~ {_lit(host)}")
    if account:
        q.append(f"| where Account has {_lit(account)}")
    q.append("| project TimeGenerated, Computer, Account, EventID, Activity")
    q += _order("TimeGenerated", anchor)
    return _build(q)
