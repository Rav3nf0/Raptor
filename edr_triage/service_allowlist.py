"""Known-good service-process allowlist + deterministic classifier.

Used for "rare process as a service" / multi-process hunting-query alerts, whose
whole payload is a *list* of service executables across hosts. Classification is
DETERMINISTIC — pure code, no LLM call, no network — so checking 5 or 500
processes costs zero tokens. The playbook/agent are handed a compact summary
(counts + the few unknowns), never the raw list.

The allowlist is deliberately conservative: only vendor-branded service binaries
that are routinely flagged by these hunts. Generic, abusable system binaries
(svchost, powershell, rundll32, wmiprvse, cmd, regsvr32 …) are NEVER allowlisted —
an unknown/generic process is surfaced for review, not cleared.
"""
from __future__ import annotations

import re

# Vendor-branded service executables (lowercase basenames). Extend as the SOC
# confirms more legitimate services — this is the "whitelist" the detection rule's
# own description says to maintain per environment.
_KNOWN_GOOD: set[str] = {
    # Intel
    "igfxcuiservice.exe", "igfxcuiservicen.exe", "intelgraphicssoftware.service.exe",
    "esif_uf.exe", "ipf_uf.exe", "lms.exe", "jhi_service.exe", "ibtsiva.exe",
    # Realtek / audio / Dolby
    "rtkauduservice64.exe", "rtkaudioservice64.exe", "dax3api.exe",
    # Elan / touchpad
    "etdservice.exe", "epdservice.exe",
    # Dell
    "supportassistagent.exe", "dellsupportassistremedationservice.exe",
    "tpmprovisioningservice.exe",
    # HP
    "hpprintscandoctorservice.exe",
    # Lenovo
    "serviceshell.exe", "lenovovantageservice.exe", "tphkload.exe",
    # Microsoft
    "officeclicktorun.exe", "microsoft.management.services.intunewindowsagent.exe",
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
    "mpdefendercoreservice.exe", "onedrive.exe", "vmcompute.exe", "gc_extension_service.exe",
    # McAfee
    "mfewc.exe", "mfemms.exe", "macmnsvc.exe", "masvc.exe", "mcafeewpsservice.exe",
    # Adobe
    "armsvc.exe", "adobeipcbroker.exe",
    # Google
    "googleplaygamesservices.exe", "googleupdate.exe", "googlecrashhandler.exe",
    # Adobe / Dropbox / Brave / Mozilla / VMware / cloud agents
    "adobeupdateservice.exe", "dropboxelevationservice.exe", "braveupdate.exe",
    "maintenanceservice.exe", "vmtoolsd.exe", "amazon-ssm-agent.exe",
    "skylightworkspaceconfigservice.exe",
    # Dell / HP / Intel / Xbox extras
    "dsaupdateservice.exe", "hplaserjetservice.exe", "intel_cst_service_standalone.exe",
    "oneapp.igcc.winservice.exe", "gamingservices.exe", "onedriveupdaterservice.exe",
    # Misc common vendor agents
    "zoom.exe", "elevationservice.exe",
    # Chrome/Edge's real on-disk binary is "elevation_service.exe" (underscore) —
    # kept as a second entry rather than a rename since some installers still ship
    # the no-underscore form.
    "elevation_service.exe", "litssvc.exe",
    # OEM driver services the Rare-Process-as-a-Service escalations kept hitting
    # (quarantine audit 2026-10-12). Each verified in MDE file telemetry: delivered as a
    # Windows Update / DISM driver package under DriverStore\FileRepository on 2-39
    # devices (Intel RST iastorac/iaahcic.inf, Intel SST intcoed.inf, Waves wavesapo
    # .inf, Synaptics synpd.inf).
    "rstmwservice.exe", "intelaudioservice.exe", "wavessyssvc64.exe", "syntpenhservice.exe",
    # No MDE trace, so vetted against vendor documentation instead (5 escalations each):
    # Goodix fingerprint session service, signed Shenzhen Goodix, DriverStore
    # goodixmocusb.inf; Fortemedia APO control service, signed Microsoft Windows Hardware
    # Compatibility Publisher, installed by the Realtek audio driver. CxAudioSvc, HP
    # Touchpoint and ASUS PTP are still unvetted and NOT added.
    "goodixsessionservice.exe", "fmservice64.exe",
    # NOTE: msiexec.exe / spoolsv.exe / sqlservr.exe are intentionally NOT here —
    # legitimate but classic masquerade/abuse targets, so they stay "verify".
}

_EXE_RE = re.compile(r'([^\\/"\']+\.exe)', re.IGNORECASE)

# Where a vendor service legitimately lives: folders only an administrator (or Windows
# itself) can write — System32/SysWOW64/WinSxS (DriverStore included), Windows\Cluster
# (Failover Clustering's own install folder, added 2026-10-26 per DEMO-118550 — see
# lib/kql_templates.STANDARD_LOCATION_KQL for why), Program Files, and Defender's own
# ProgramData\Microsoft platform folders. The list above is matched by NAME, and a name
# is free to forge: msmpeng.exe or fmservice64.exe dropped in C:\Users\Public is exactly
# the masquerade this alert family exists to catch. So a known name only counts as
# known-good from one of these folders, or when the alert gave no path at all. Mirrored
# in lib/kql_templates.STANDARD_LOCATION_RE for the MDE query.
STANDARD_LOCATION_RE = re.compile(
    r"^(?:[a-z]:|\\device\\harddiskvolume\d+)\\"
    r"(?:windows\\(?:system32|syswow64|winsxs|cluster)\\"
    r"|program files(?: \(x86\))?\\"
    r"|programdata\\microsoft\\(?:windows defender|microsoft defender)\\)",
    re.IGNORECASE,
)
# Folders INSIDE System32/SysWOW64 that a standard user can write to (the classic
# AppLocker-bypass set). A file there is not admin-installed, so it does not count.
# Mirrored in lib/kql_templates.WRITABLE_UNDER_WINDOWS_KQL.
WRITABLE_UNDER_WINDOWS_RE = re.compile(
    r"\\windows\\(?:system32|syswow64)\\(?:tasks|tasks_migrated|com\\dmp|fxstmp"
    r"|spool\\(?:drivers\\color|printers|servers)|microsoft\\crypto\\rsa\\machinekeys)\\",
    re.IGNORECASE,
)
_DIR_RE = re.compile(r'((?:[a-z]:|\\device\\harddiskvolume\d+)\\[^"\'<>|]*?)\\?[^\\/"\']+\.exe',
                     re.IGNORECASE)


def process_dir(cmd: str) -> str:
    """The folder of the executable in a command line, lowercased with a trailing
    backslash, or "" when the command line gives no absolute path."""
    s = (cmd or "").strip().strip('"').strip("'")
    if s.startswith("\\??\\"):
        s = s[4:]
    # Anchored: the EXECUTABLE's folder, never a path found later in its arguments
    # (`msmpeng.exe C:\Program Files\x\y.exe` was a bare name, not a Program Files one).
    m = _DIR_RE.match(s)
    if not m:
        return ""
    d = m.group(1).lower()
    return d if d.endswith("\\") else d + "\\"


def is_standard_location(path: str) -> bool:
    """True if `path` (a folder or a full file path) is in an admin-only install location."""
    p = (path or "").strip().strip('"')
    if p.startswith("\\??\\"):
        p = p[4:]
    # Prefix matching means nothing if the path can climb back out of the folder
    # (`C:\Windows\System32\..\..\Users\Public\x.exe`) or hide behind an 8.3 short
    # name. Command lines are attacker-written, so these never vouch.
    if ".." in re.split(r"[\\/]", p) or "~" in p:
        return False
    return bool(STANDARD_LOCATION_RE.match(p)) and not WRITABLE_UNDER_WINDOWS_RE.search(p)


def normalize_process(cmd: str) -> str:
    """Reduce a raw command line to its lowercase executable basename.

    Handles `"C:\\Path\\X.exe" /service`, bare `X.exe`, and quoted forms.
    """
    s = (cmd or "").strip().strip('"').strip("'")
    if not s:
        return ""
    m = _EXE_RE.search(s)
    if m:
        return m.group(1).split("\\")[-1].split("/")[-1].lower()
    return s.split()[0].split("\\")[-1].split("/")[-1].lower()


def is_known_good(name: str) -> bool:
    """True if `name` (a bare filename or a full command line) matches the
    human-vetted vendor allowlist above — independent of any live telemetry.

    Exists so a second, independent consumer (hunt_service's live MDE
    certificate lookup, in agent_core/loop.py's _service_fleet_cleared) can fall
    back to this list when live data has a coverage gap for an otherwise-vetted
    name, without reaching into the private _KNOWN_GOOD set directly.
    """
    return normalize_process(name) in _KNOWN_GOOD


def is_known_good_at(name: str, paths) -> bool:
    """Known name AND at least one path AND every path in a standard install location.

    For the name-only fallbacks, where nothing else vouches for the binary: no path
    evidence is NOT good enough there, unlike classify_processes, which keeps a bare
    name known so it does not flood every alert with "unknown"."""
    ps = [p for p in (paths or []) if p]
    return is_known_good(name) and bool(ps) and all(is_standard_location(p) for p in ps)


def classify_processes(cmds: list[str], unknown_cap: int = 8) -> dict:
    """Deterministically classify a list of service command lines.

    Returns a compact summary — safe to drop straight into an LLM prompt or a
    Jira comment. `unknown` is capped (with `unknown_more`) so an alert with a
    huge result set can't bloat the prompt.
    """
    distinct: list[str] = []
    seen: set[str] = set()
    paths: dict[str, list[str]] = {}
    misplaced: dict[str, str] = {}
    for c in cmds or []:
        p = normalize_process(c)
        if not p:
            continue
        if p not in seen:
            seen.add(p)
            distinct.append(p)
        d = process_dir(c)
        if d:
            if d not in paths.setdefault(p, []) and len(paths[p]) < 3:
                paths[p].append(d)
            # A known name outside an admin-only folder is the masquerade tell: it is
            # not known-good, it is the most suspicious row in the alert.
            if p in _KNOWN_GOOD and not is_standard_location(d) and p not in misplaced:
                misplaced[p] = d

    known = [p for p in distinct if p in _KNOWN_GOOD and p not in misplaced]
    # Misplaced names go FIRST, so the cap can never hide them and the agent hunts them.
    unknown = ([p for p in distinct if p in misplaced]
               + [p for p in distinct if p not in _KNOWN_GOOD])
    return {
        "total_events": len(cmds or []),
        "distinct": len(distinct),
        "known_good": len(known),
        "unknown_count": len(unknown),
        "unknown": unknown[:unknown_cap],
        "unknown_more": max(0, len(unknown) - unknown_cap),
        "all_known_good": not unknown,
        "misplaced": [{"name": n, "path": d} for n, d in misplaced.items()],
        "paths": paths,
    }


def summarize_check(pc: dict) -> str:
    """One-line, token-cheap rendering of a classify_processes() result."""
    if not pc or not pc.get("distinct"):
        return ""
    if pc.get("all_known_good"):
        return (f"{pc['distinct']} distinct service processes across "
                f"{pc['total_events']} events — ALL matched known-good vendor services.")
    unk = ", ".join(pc.get("unknown", []))
    more = f" (+{pc['unknown_more']} more)" if pc.get("unknown_more") else ""
    out = (f"{pc['distinct']} distinct service processes across {pc['total_events']} events — "
           f"{pc['known_good']} known-good; {pc['unknown_count']} UNKNOWN: {unk}{more}.")
    if pc.get("misplaced"):
        out += (" POSSIBLE MASQUERADE — a known vendor name running outside its normal "
                "install folder: " + "; ".join(f"{m['name']} in {m['path']}"
                                               for m in pc["misplaced"][:5]) + ".")
    return out
