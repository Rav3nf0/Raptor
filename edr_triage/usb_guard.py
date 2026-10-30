"""Files Copied to USB Drives: ASK the copier, never close.

What clears a copy to removable media is the copier's reason for THAT copy (gate G14,
agent_core/loop.py usb_copy_needs_reason) — a drive or user cleared before does not. Over
the 60 days to 2026-10-16, 36 of 43 such tickets went to L2, which closed them on the
copier's or IT's word ("As confirmed by IT team … this activity is legitimate"). So RAPTOR
puts the question to the one reachable person who copied, and the answer — or the silence —
goes to L2, who decides. Nobody to ask (generic account, several users, not on Slack) means
straight to L2 (_L2_DIRECT in pipeline.py).
"""
from __future__ import annotations

ASK_LABEL = "usb-ask"


def applies(alert_name: str) -> bool:
    from agent_core.loop import _is_usb_copy_alert
    return _is_usb_copy_alert(alert_name)


def ask_comment(who: str, reason: str) -> str:
    return ("*RAPTOR is asking the user instead of closing.*\n\n"
            f"Why: {reason}.\n\n"
            "A copy to a USB drive is cleared only by the copier's reason for this copy. RAPTOR "
            f"has asked {who} via the Acme Security Bot; their answer comes back to L2, who "
            "decides.\n\n[Auto-triaged by RAPTOR]")


# ── NO REMOVABLE DRIVE (2026-10-26) ───────────────────────────────────────────────────────
# The Sentinel rule joins file writes to the latest "UsbDriveMounted" event and tests
# `FolderPath startswith DriveLetter`. An internal SATA DVD drive (BusType 11) "mounts" with
# NO drive letter, the empty letter matches every path, and every write to a local D:\ then
# reads as a USB copy. up11nnadaoprwd raised 23 of 50 USB alerts in 60 days this way:
# busywin.exe (Busy accounting) writing its own files to D:\busywin. IT confirmed it
# (BitRaser run, DVD write disabled, nothing copied to USB) — but the drive still mounts
# ~20 times a day, so the alerts keep coming until the rule excludes BusType 11.
#
# G14 (ask the copier) stands aside ONLY when Sentinel shows no removable drive at all: every
# file on the alert was written on the device in the alert window, AND every drive mount on
# that device in the last LOOKBACK_DAYS was internal SATA with no drive letter. One USB/SD
# mount in that period — even days earlier and still plugged in — keeps the ask, because the
# DVD mount would have fired the rule on a real USB write too. Every other gate still runs.
# FAILS CLOSED: any query failure or missing fact means "a removable drive may be involved".

import logging as _logging
import re as _re

_log = _logging.getLogger(__name__)

LOOKBACK_DAYS = 30
INTERNAL_BUS = 11       # STORAGE_BUS_TYPE BusTypeSata — internal DVD/CD and disks
BLOCK_LABELS = ("needs-l2-review", "usb-guard")
_GUID_RE = _re.compile(r"[0-9a-fA-F\-]{20,64}")
_TIME_RE = _re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?")
_HOST_RE = _re.compile(r"[a-z0-9][a-z0-9.\-]{0,253}")


def _kstr(s: str) -> str:
    """KQL verbatim string literal — backslashes in Windows paths stay literal."""
    return '@"' + str(s).replace('"', '""') + '"'


def _load_json(v):
    import json
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v) if v else None
    except Exception:
        return None


async def drive_check(incident_url: str, alert_id: str) -> dict:
    """Was any removable drive involved in this USB alert? Never raises.

    Returns {"internal": True, "device", "paths", "mounts", "reason"} only when it is proven
    that none was; otherwise {"internal": False, "reason": "..."}.
    """
    try:
        return await _drive_check(incident_url, alert_id)
    except Exception as exc:
        _log.warning("usb_guard: drive check failed for %s: %s", alert_id, exc)
        return {"internal": False, "reason": f"drive check failed ({str(exc)[:120]})"}


async def _drive_check(incident_url: str, alert_id: str) -> dict:
    from edr_triage.sentinel_client import _run_la_query, parse_incident_url
    parts = parse_incident_url(incident_url or "")
    if not parts or not alert_id:
        return {"internal": False, "reason": "no Sentinel incident/alert id on the ticket"}
    guid = alert_id[2:] if alert_id.lower().startswith("sn") else alert_id
    if not _GUID_RE.fullmatch(guid):
        return {"internal": False, "reason": "malformed alert id"}
    rows = await _run_la_query(parts, f"""
SecurityAlert
| where VendorOriginalId in ("{guid}", "{alert_id}") or SystemAlertId in ("{guid}", "{alert_id}")
| top 1 by TimeGenerated desc
| project Entities, ExtendedProperties""")
    if not rows:
        return {"internal": False, "reason": "Sentinel alert not found"}
    ents = _load_json(rows[0].get("Entities")) or []
    ext = _load_json(rows[0].get("ExtendedProperties")) or {}
    hosts, paths = [], []
    for e in ents if isinstance(ents, list) else []:
        t = str((e or {}).get("Type") or "").lower()
        if t == "host":
            hn, dom = e.get("HostName") or "", e.get("DnsDomain") or ""
            h = (f"{hn}.{dom}" if hn and dom else hn).lower()
            if h and h not in hosts:
                hosts.append(h)
        elif t == "file":
            d, n = str(e.get("Directory") or ""), str(e.get("Name") or "")
            p = d if n and d.lower().endswith(n.lower()) else (d.rstrip("\\") + "\\" + n if d and n else "")
            if p and p.lower() not in (x.lower() for x in paths):
                paths.append(p)
    start = str(ext.get("Query Start Time UTC") or "").replace(" ", "T")
    end = str(ext.get("Query End Time UTC") or "").replace(" ", "T")
    if len(hosts) != 1 or not _HOST_RE.fullmatch(hosts[0]):
        return {"internal": False, "reason": f"expected one device on the alert, found {len(hosts)}"}
    if not paths:
        return {"internal": False, "reason": "no copied file on the alert"}
    if not (_TIME_RE.fullmatch(start) and _TIME_RE.fullmatch(end)):
        return {"internal": False, "reason": "alert window unreadable"}
    dev = hosts[0]

    # 1. Every file the alert names was really written on this device in the alert window.
    written = await _run_la_query(parts, f"""
DeviceFileEvents
| where TimeGenerated between (datetime({start}) .. datetime({end}))
| where DeviceName =~ {_kstr(dev)} and ActionType == "FileCreated"
| where FolderPath in~ ({", ".join(_kstr(p) for p in paths)})
| distinct FolderPath""")
    found = {str(r.get("FolderPath") or "").lower() for r in written or []}
    missing = [p for p in paths if p.lower() not in found]
    if missing:
        return {"internal": False, "reason": f"no file event read for {missing[0]}"}

    # 2. Every drive mount on this device over the lookback was internal SATA, no letter.
    mounts = await _run_la_query(parts, f"""
DeviceEvents
| where TimeGenerated between ((datetime({end}) - {LOOKBACK_DAYS}d) .. datetime({end}))
| where DeviceName =~ {_kstr(dev)} and ActionType == "UsbDriveMounted"
| extend P = parse_json(AdditionalFields)
| extend Bus = toint(P.BusType), Letter = tostring(P.DriveLetter), Product = tostring(P.ProductName)
| summarize Mounts = count(), Removable = countif(isnull(Bus) or Bus != {INTERNAL_BUS} or isnotempty(Letter)),
            InWindow = countif(TimeGenerated between (datetime({start}) .. datetime({end}))),
            Products = make_set(Product, 5)""")
    m = (mounts or [{}])[0]
    n_all, n_rem, n_win = int(m.get("Mounts") or 0), int(m.get("Removable") or 0), int(m.get("InWindow") or 0)
    if n_all == 0 or n_win == 0:
        return {"internal": False, "reason": "no drive mount found for the alert window"}
    if n_rem:
        return {"internal": False, "reason": (
            f"{n_rem} removable or lettered drive mount(s) on {dev} in the last {LOOKBACK_DAYS} days")}
    products = [p.strip() for p in (_load_json(m.get("Products")) or m.get("Products") or []) if p]
    return {"internal": True, "device": dev, "paths": paths, "mounts": n_all,
            "products": products, "reason": (
                f"no removable drive: all {n_all} drive mounts on {dev} in the last "
                f"{LOOKBACK_DAYS} days were an internal SATA drive with no drive letter "
                f"({', '.join(products) or 'unnamed'}), which makes the rule match any "
                "non-C: write")}


async def enforce_at_close(alert_name: str, labels: list, jira_key: str, check: dict | None,
                           cfg, dry_run: bool = False) -> tuple[bool, str]:
    """Close-gate step: a USB alert closes only when drive_check proved no removable drive.
    Returns (block, reason) and comments either way."""
    if not applies(alert_name):
        return False, ""
    check = check or {}
    from edr_triage.jira_handler import add_comment
    if check.get("internal") is True:
        files = ", ".join(f"`{p}`" for p in (check.get("paths") or [])[:5])
        text = ("*Auto-close permitted: no removable drive was involved.*\n\n"
                f"{check['reason'][0].upper() + check['reason'][1:]}. The files ({files}) "
                "were written to a local disk; the rule matched them only because that "
                "drive mount carries no drive letter.\n\n"
                "Reopen this ticket if a USB or SD drive was in fact used.\n\n"
                "[Auto-triaged by RAPTOR]")
        blocked, why = False, ""
    else:
        for lab in BLOCK_LABELS:
            if lab not in labels:
                labels.append(lab)
        why = check.get("reason") or "removable-drive check did not run"
        text = ("*RAPTOR did not auto-close this ticket.*\n\n"
                f"Reason: {why}.\n\n"
                "A USB-copy alert closes only when Sentinel shows no removable drive on the "
                "device; otherwise the copier's own reason is needed.\n\n"
                "[Auto-triaged by RAPTOR]")
        blocked = True
    try:
        await add_comment(jira_key, text, cfg, dry_run=dry_run)
    except Exception as exc:
        _log.error("usb_guard: comment on %s failed: %s", jira_key, exc)
    return blocked, why
