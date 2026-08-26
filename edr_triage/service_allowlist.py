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
    # NOTE: msiexec.exe / spoolsv.exe / sqlservr.exe are intentionally NOT here —
    # legitimate but classic masquerade/abuse targets, so they stay "verify".
}

_EXE_RE = re.compile(r'([^\\/"\']+\.exe)', re.IGNORECASE)


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


def classify_processes(cmds: list[str], unknown_cap: int = 8) -> dict:
    """Deterministically classify a list of service command lines.

    Returns a compact summary — safe to drop straight into an LLM prompt or a
    Jira comment. `unknown` is capped (with `unknown_more`) so an alert with a
    huge result set can't bloat the prompt.
    """
    distinct: list[str] = []
    seen: set[str] = set()
    for c in cmds or []:
        p = normalize_process(c)
        if p and p not in seen:
            seen.add(p)
            distinct.append(p)

    known = [p for p in distinct if p in _KNOWN_GOOD]
    unknown = [p for p in distinct if p not in _KNOWN_GOOD]
    return {
        "total_events": len(cmds or []),
        "distinct": len(distinct),
        "known_good": len(known),
        "unknown_count": len(unknown),
        "unknown": unknown[:unknown_cap],
        "unknown_more": max(0, len(unknown) - unknown_cap),
        "all_known_good": not unknown,
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
    return (f"{pc['distinct']} distinct service processes across {pc['total_events']} events — "
            f"{pc['known_good']} known-good; {pc['unknown_count']} UNKNOWN: {unk}{more}.")
