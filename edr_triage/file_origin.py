"""Where did the flagged file come from, and who else has it? (30-day fleet view)

DEMO-121950 (2026-11-12, macOS Gatekeeper bypass, paged): a user ran `xattr -d
com.apple.quarantine jit-cli-s3` and `chmod +x` on our own JIT access tool. The command-line
build is unsigned, so removing the quarantine flag is its install step. RAPTOR escalated at
95%: hunt_file never returned the download URL (jit.example.com), its +-24h window showed the
file on 1 other Mac instead of 8, and nothing told it jit.example.com is ours.

check() returns, for one hash, every device that held it in the last 29 days (MDE keeps 30)
with the URL each copy was downloaded from, and labels URLs from INTERNAL_SOURCES. A download
from an internal source is independent evidence about the FILE (it is our build, not a
lookalike); it says nothing about what the file was then used for. Fails closed: a query
that cannot run is reported as such, never as "no other devices".
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Exact scheme + host + path prefix. Add an entry only for a source Acme controls and
# that publishes only our own builds, never a general file share.
INTERNAL_SOURCES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^https://jit\.example\.com/download/", re.I),
     "Acme JIT access tool download page (jit.example.com)"),
    (re.compile(r"^https://acme-security-appsec-automation\.s3\.ap-south-1\.amazonaws\.com/jit-access/", re.I),
     "AppSec JIT access tool build bucket"),
]

# Alerts where the file's provenance is the question. Kept narrow: every match costs one
# MDE query, and the hunting quota is shared with /shadow.
_APPLIES_RE = re.compile(r"gatekeeper|quarantine (flag|attribute)|unsigned|untrusted (binary|file)",
                         re.I)


def applies(alert_name: str, sha256: str) -> bool:
    return bool(sha256) and bool(_APPLIES_RE.search(alert_name or ""))


def internal_label(url: str) -> str:
    u = (url or "").strip()
    for rx, label in INTERNAL_SOURCES:
        if rx.match(u):
            return label
    return ""


def summarize(rows: list[dict], device: str = "") -> dict:
    """Pure: prevalence rows (one per device) -> the facts the agent is given."""
    dev_l = (device or "").strip().lower()
    devices, origins, alert_dev = [], {}, None
    for r in rows:
        name = str(r.get("DeviceName") or "")
        o = [str(x) for x in (r.get("Origins") or []) if x]
        devices.append(name)
        for u in o:
            origins.setdefault(u, set()).add(name)
        if dev_l and name.lower().split(".")[0] == dev_l.split(".")[0]:
            alert_dev = {"origins": o, "first_seen": str(r.get("FirstSeen") or ""),
                         "paths": [str(p) for p in (r.get("Paths") or [])][:5]}
    labelled = [{"url": u, "devices": len(ds), "internal": internal_label(u)}
                for u, ds in sorted(origins.items(), key=lambda kv: -len(kv[1]))]
    internal = [o for o in labelled if o["internal"]]
    external = [o for o in labelled if not o["internal"]]
    alert_internal = bool(alert_dev and alert_dev["origins"]
                          and all(internal_label(u) for u in alert_dev["origins"]))
    return {"ok": True, "devices": len(devices), "device_names": devices[:15],
            "origins": labelled[:10], "alert_device": alert_dev,
            # The alert's own copy came only from an internal source, and no device anywhere
            # got this hash from anywhere else.
            "internal_origin": alert_internal and not external,
            "internal_label": internal[0]["internal"] if internal else "",
            "external_origins": len(external)}


_cache: dict[str, dict] = {}


async def check(sha256: str, device: str = "", anchor: str = "") -> dict:
    key = f"{(sha256 or '').lower()}|{(device or '').lower()}|{anchor}"
    if key in _cache:
        return _cache[key]
    out = await _check(sha256, device, anchor)
    if len(_cache) > 200:
        _cache.clear()
    _cache[key] = out
    return out


async def _check(sha256: str, device: str, anchor: str) -> dict:
    from lib import kql_templates as T
    try:
        kql = T.mde_file_prevalence(sha256, anchor_iso=anchor)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        from lib.mde_client import get_access_token, run_mde_query
        token = await get_access_token()
        if not token:
            return {"ok": False, "error": "MDE token unavailable"}
        rows, err = await run_mde_query(kql, token)
    except Exception as exc:
        logger.warning("file_origin: query failed: %s", exc)
        return {"ok": False, "error": f"query failed ({str(exc)[:80]})"}
    if err:
        return {"ok": False, "error": f"query failed ({str(err)[:80]})"}
    return summarize(rows or [], device)


def prompt_lines(chk: dict) -> list[str]:
    if not chk:
        return []
    if not chk.get("ok"):
        return [f"\nFile origin (30-day fleet view): COULD NOT BE CHECKED — {chk.get('error')}. "
                "Unknown provenance is not evidence either way."]
    lines = [f"\nFile origin (30-day fleet view, KEY EVIDENCE — already queried, do not "
             f"re-hunt it): this hash was on {chk['devices']} device(s)"
             + (f": {', '.join(chk['device_names'])}" if chk["device_names"] else "") + "."]
    ad = chk.get("alert_device")
    if ad:
        lines.append(f"  This device's copy was downloaded from: "
                     f"{', '.join(ad['origins']) or 'no download URL recorded'}.")
    for o in chk.get("origins") or []:
        tag = f"  <- INTERNAL: {o['internal']}" if o["internal"] else ""
        lines.append(f"  - {o['url']} ({o['devices']} device(s)){tag}")
    if chk.get("internal_origin"):
        lines.append(
            "  How to judge: this device's copy came from an Acme-controlled internal "
            f"source ({chk['internal_label']}) and no device got this hash from anywhere "
            "else. That is independent evidence the file is our own build, not a lookalike. "
            "For a Gatekeeper / quarantine-flag alert, an unsigned internal tool has to have "
            "its quarantine flag removed before macOS will run it, so `xattr -d "
            "com.apple.quarantine <tool>` plus `chmod +x` IS its install step. Judge what "
            "the tool did AFTERWARDS (its command lines and network destinations), not the "
            "removal itself.")
    elif chk.get("external_origins"):
        lines.append("  How to judge: at least one copy came from a source NOT on the internal "
                     "list; provenance does not clear this file.")
    else:
        lines.append("  How to judge: no internal download source is recorded for this "
                     "device's copy; provenance does not clear this file.")
    return lines
