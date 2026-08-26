"""MDE Alerts REST API client.

Reuses lib/mde_client.get_access_token() for OAuth2 token acquisition.

Endpoints used:
  GET /api/alerts/{alertId}
  GET /api/alerts/{alertId}/evidence
  GET /api/machines/{machineId}/alerts
  GET /api/machines/{machineId}/events  (device timeline)
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

import httpx

logger = logging.getLogger(__name__)

import os as _os
_MDE_API_BASE = "https://api.security.microsoft.com"
_VERIFY_SSL = _os.getenv("MDE_VERIFY_SSL", _os.getenv("CYBLE_VERIFY_SSL", "true")).lower() not in ("false", "0", "no")


def _client(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=_MDE_API_BASE,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=20.0,
        verify=_VERIFY_SSL,
    )


async def fetch_alert(alert_id: str, token: str) -> dict:
    """Fetch a single MDE alert by ID. Returns {} on failure."""
    try:
        async with _client(token) as c:
            resp = await c.get(f"/api/alerts/{alert_id}")
            if resp.status_code == 404:
                logger.warning("MDE alert not found: %s", alert_id)
                return {}
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.error("fetch_alert(%s) failed: %s", alert_id, exc)
        return {}


async def fetch_alert_evidence(alert_id: str, token: str) -> list[dict]:
    """Fetch evidence items for an MDE alert. Returns [] on failure.

    The `/alerts/{id}/evidence` sub-endpoint 404s on this API version — the
    evidence (File + Process entities, incl. processCommandLine) is only
    returned via `$expand=evidence` on the alert itself.
    """
    try:
        async with _client(token) as c:
            resp = await c.get(f"/api/alerts/{alert_id}?$expand=evidence")
            resp.raise_for_status()
            return resp.json().get("evidence", []) or []
    except Exception as exc:
        logger.error("fetch_alert_evidence(%s) failed: %s", alert_id, exc)
        return []


async def fetch_machine_recent_alerts(machine_id: str, token: str, top: int = 10) -> list[dict]:
    """Fetch recent alerts for a machine (used to build attack context).

    Accepts an MDE machine ID or a hostname/FQDN — the API is keyed by machine ID,
    so a hostname is resolved first (else it silently returns no alerts).
    """
    resolved = await resolve_machine_id(machine_id, token)
    if not resolved:
        return []
    try:
        async with _client(token) as c:
            resp = await c.get(f"/api/machines/{resolved}/alerts?$top={top}")
            resp.raise_for_status()
            return resp.json().get("value", [])
    except Exception as exc:
        logger.error("fetch_machine_recent_alerts(%s) failed: %s", resolved, exc)
        return []


_MDE_MACHINE_ID_RE = re.compile(r"^[0-9a-f]{40}$")  # MDE machine IDs are 40-hex-char


async def resolve_machine_id(machine_ref: str, token: str) -> str | None:
    """Resolve a device reference to an MDE machine ID.

    The device timeline/alerts APIs are keyed by the MDE machine ID (a 40-hex-char
    id), NOT the hostname/FQDN. The agent usually only has the hostname, so passing
    it straight through silently returned 0 events. If `machine_ref` already looks
    like a machine ID, return it as-is; otherwise look it up by computerDnsName.
    Returns None if no machine matches.
    """
    if _MDE_MACHINE_ID_RE.match((machine_ref or "").lower()):
        return machine_ref
    host = (machine_ref or "").strip()
    if not host:
        return None
    # MDE matches computerDnsName on the FQDN; also try the short hostname.
    candidates = [host]
    if "." in host:
        candidates.append(host.split(".")[0])
    try:
        async with _client(token) as c:
            for name in candidates:
                resp = await c.get("/api/machines", params={
                    "$filter": f"computerDnsName eq '{name}'", "$top": "1",
                })
                if resp.status_code != 200:
                    continue
                vals = resp.json().get("value", [])
                if vals:
                    return vals[0].get("id")
    except Exception as exc:
        logger.error("resolve_machine_id(%s) failed: %s", machine_ref, exc)
    return None


async def _machine_dns_name(machine_id: str, token: str) -> str:
    """computerDnsName for a machine ID — Advanced Hunting keys on DeviceName."""
    try:
        async with _client(token) as c:
            resp = await c.get(f"/api/machines/{machine_id}")
            if resp.status_code != 200:
                return ""
            return (resp.json() or {}).get("computerDnsName", "") or ""
    except Exception as exc:
        logger.warning("_machine_dns_name(%s) failed: %s", machine_id, exc)
        return ""


async def fetch_machine_timeline(
    machine_id: str,
    token: str,
    lookback_hours: int = 6,
    anchor_iso: str = "",
    window_hours: int = 6,
) -> list[dict]:
    """Fetch device timeline events within a BOUNDED window.

    Returns events in chronological order. Used to:
    - Confirm quarantine sequence for remediated malware
    - Detect file still present on disk for non-quarantined malware
    - Build process chain for reverse shell / lateral movement alerts

    Window: when `anchor_iso` (the alert's event/creation time) is given, the query
    is bounded to [anchor-1h, anchor+window_hours]. Anchoring on the ALERT time — not
    "now" — is what matters: a triage running hours after the alert fired still
    captures the detection events, WITHOUT pulling a full day of unrelated device
    activity (which would be noise, and token cost once it reaches the agent). Falls
    back to the last `lookback_hours` only when no anchor time is available.

    Accepts either an MDE machine ID or a hostname/FQDN. The DEVICE NAME is what the
    query needs (Advanced Hunting keys on DeviceName, not the machine GUID), so a
    machine ID is resolved back to its computerDnsName.

    Backed by Advanced Hunting, NOT `GET /api/machines/{id}/events` — that REST path
    does not exist and returned 404 for every device (verified across Windows, Ubuntu
    and macOS hosts). The old code swallowed that 404 in a bare `except` and returned
    `[]`, so a structurally broken call was indistinguishable from "device is clean":
    the tool reported `count: 0` with no error and the agent read it as an absence of
    malicious activity. On DEMO-107628 that hid a device with 18k+ process events and
    four live AntivirusDetection rows. Errors now RAISE so the caller surfaces them —
    an unavailable timeline must never read as exculpatory evidence.
    """
    resolved = await resolve_machine_id(machine_id, token)
    if not resolved:
        # Signal "device not in MDE" explicitly rather than returning [] silently,
        # which reads like "clean" — this machine may not be Defender-onboarded
        # (e.g. a Sentinel-origin/Linux/cloud host).
        raise ValueError(
            f"machine '{machine_id}' not found in MDE (not Defender-onboarded, or the "
            "identifier is a hostname with no matching device) — no endpoint telemetry available"
        )

    device_name = await _machine_dns_name(resolved, token) or (
        machine_id if not _MDE_MACHINE_ID_RE.match((machine_id or "").lower()) else ""
    )
    if not device_name:
        raise ValueError(
            f"could not resolve a device name for machine '{machine_id}' — cannot query timeline"
        )

    # Bound the window. Anchor on the ALERT time when known (see docstring).
    if anchor_iso:
        try:
            anchor = datetime.fromisoformat(anchor_iso.strip().replace("Z", "+00:00"))
            start = anchor - timedelta(hours=1)
            end = anchor + timedelta(hours=window_hours)
        except Exception:
            start = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
            end = datetime.now(timezone.utc)
    else:
        start = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        end = datetime.now(timezone.utc)

    from lib.kql_templates import mde_device_timeline
    from lib.mde_client import run_mde_query

    kql = mde_device_timeline(device_name, start.isoformat(), end.isoformat())
    rows, err = await run_mde_query(kql, token)
    if err:
        # Do NOT return [] — an errored query is an evidence GAP, not a clean device.
        raise ValueError(f"device timeline query failed for '{device_name}': {err}")
    return rows


def extract_file_evidence(evidence_list: list[dict]) -> dict:
    """Extract the most relevant evidence from an MDE alert's evidence list.

    Returns: file_name, file_path, sha256, initiating_process, and — critically for
    endpoint-process alerts (suspicious curl/wget/etc.) — the actual process
    command line(s) and the account that ran them:
      command_line   : the triggering process command line (best single)
      command_lines  : deduped list of process command lines in the evidence
      account_name   : the account that ran the process
    """
    result = {
        "file_name": "", "file_path": "", "sha256": "", "initiating_process": "",
        "command_line": "", "command_lines": [], "account_name": "",
        # Structured per-process detections (deduped by command line) — lets the
        # playbook render L1-style blocks (command + PID + user + status) instead
        # of a flat command-line firehose.
        "detections": [], "remediation_status": "",
    }

    # File evidence — prefer a File entity with a SHA256, else any fileName.
    for ev in evidence_list:
        if ev.get("entityType") == "File" and ev.get("sha256"):
            result.update(
                file_name=ev.get("fileName", ""),
                file_path=ev.get("filePath", "") or ev.get("directory", ""),
                sha256=ev.get("sha256", ""),
                initiating_process=ev.get("parentProcessName", "") or ev.get("processName", ""),
            )
            break
    else:
        for ev in evidence_list:
            fn = ev.get("fileName") or ev.get("name", "")
            if fn:
                result.update(
                    file_name=fn,
                    file_path=ev.get("filePath", "") or ev.get("directory", ""),
                    sha256=ev.get("sha256", ""),
                    initiating_process=ev.get("parentProcessName", "") or ev.get("processName", ""),
                )
                break

    # Process command lines — the real triggering command (e.g. the curl invocation).
    # Group by command line so repeated PIDs of the same command collapse into one
    # detection block (MDE emits one Process evidence item per PID).
    cmds: list[str] = []
    by_cmd: dict[str, dict] = {}
    # Blocking detection/remediation statuses — Defender stopped the activity.
    _blocked = {"blocked", "prevented", "remediated", "partiallyremediated",
                "successfullyremediated", "quarantined"}
    for ev in evidence_list:
        acct = ev.get("accountName") or ev.get("userAccount") or ""
        if acct and not result["account_name"]:
            dom = ev.get("domainName") or ""
            result["account_name"] = f"{dom}\\{acct}" if dom else acct
        cl = (ev.get("processCommandLine") or ev.get("commandLine") or "").strip()
        if not cl:
            continue
        if cl not in cmds:
            cmds.append(cl)
        det = by_cmd.get(cl)
        if det is None:
            dom = ev.get("domainName") or ""
            ev_acct = ev.get("accountName") or ev.get("userAccount") or ""
            det = {
                "command_line": cl,
                "file_name": ev.get("fileName", ""),
                "process_ids": [],
                "parent": ev.get("parentProcessFileName", "")
                          or ev.get("parentProcessName", ""),
                "account": f"{dom}\\{ev_acct}" if dom and ev_acct else ev_acct,
                "status": ev.get("detectionStatus")
                          or ev.get("remediationStatus", ""),
            }
            by_cmd[cl] = det
        pid = ev.get("processId")
        if pid and pid not in det["process_ids"]:
            det["process_ids"].append(pid)

    result["command_lines"] = cmds[:10]
    result["command_line"] = cmds[0] if cmds else ""
    result["detections"] = list(by_cmd.values())

    # Overall remediation status: blocked if any detection carried a blocking status.
    statuses = [d["status"] for d in by_cmd.values() if d["status"]]
    if any(s.lower().replace(" ", "") in _blocked for s in statuses):
        # Prefer the most specific non-generic label seen.
        result["remediation_status"] = next(
            (s for s in statuses if s.lower().replace(" ", "") in _blocked), statuses[0]
        )

    return result


# Defender detection signature, e.g. "Trojan:VBS/CVE-2025-55182.DE!MTB",
# "Behavior:Win32/…", "HackTool:…". Used to recover the AV verdict from an
# alert's title/description when the structured field is empty.
_DEFENDER_DETECTION_RE = re.compile(
    r'\b((?:Trojan|TrojanDownloader|TrojanSpy|Backdoor|Ransom|Behavior|VirTool|'
    r'HackTool|Exploit|PWS|Worm|Program|Misleading|SoftwareBundler)'
    r'[:/][\w./!@:+-]+)',
)


def extract_alert_classification(alert: dict) -> dict:
    """Pull the Defender/EDR threat classification + disposition from an MDE alert.

    These tell you Defender ALREADY classified/handled the threat (e.g.
    'Trojan:VBS/CVE-2025-55182' / determination=… / status=Resolved) — signal
    that's independent of VirusTotal, which often shows 0 for freshly-seen or
    targeted samples. Falls back to a regex over title/description for the AV
    signature when the structured field is empty.
    """
    out = {
        "threat_name":      alert.get("threatName") or alert.get("threatFamilyName") or "",
        "category":         alert.get("category", "") or "",
        "determination":    alert.get("determination", "") or alert.get("classification", "") or "",
        "detection_source": alert.get("detectionSource", "") or "",
        "alert_status":     alert.get("status", "") or "",
    }
    if not out["threat_name"]:
        blob = " ".join(str(alert.get(k, "")) for k in ("title", "description", "_description"))
        m = _DEFENDER_DETECTION_RE.search(blob)
        if m:
            out["threat_name"] = m.group(1)
    return out


def build_timeline_summary(timeline_events: list[dict], file_name: str, sha256: str) -> str:
    """Build a human-readable timeline summary from device events.

    Filters to events related to the malicious file, returns a compact
    chronological sequence for the L1 comment.
    """
    if not timeline_events:
        return ("No device timeline events retrieved — the device may not be Defender-onboarded "
                "for endpoint telemetry (e.g. a Linux/cloud/UnsupportedOs host); the flagged-process "
                "list above is taken from the alert evidence.")

    fn_lower = file_name.lower() if file_name else ""
    sha_lower = sha256.lower() if sha256 else ""

    relevant = []
    for ev in timeline_events:
        ev_str = str(ev).lower()
        if (fn_lower and fn_lower in ev_str) or (sha_lower and sha_lower in ev_str):
            # Accept BOTH shapes: Advanced Hunting returns PascalCase
            # (Timestamp/ActionType/FileName), the old REST timeline returned
            # camelCase. Reading only camelCase rendered every row as "[] Event: "
            # once the timeline moved to Advanced Hunting.
            ts = (ev.get("Timestamp") or ev.get("eventTime")
                  or ev.get("createdDateTime") or "")[:19].replace("T", " ")
            etype = (ev.get("ActionType") or ev.get("actionType")
                     or ev.get("type") or "Event")
            fname = (
                ev.get("FileName") or ev.get("fileName") or ev.get("processName")
                or ev.get("registryKey", "")
            )
            relevant.append(f"  [{ts}] {etype}: {fname}")

    if not relevant:
        return "No timeline events matched the malicious file."

    lines = [f"Device timeline ({len(relevant)} matching events):"]
    lines.extend(relevant[:15])   # cap at 15 to keep the comment readable
    if len(relevant) > 15:
        lines.append(f"  ... and {len(relevant) - 15} more events")
    return "\n".join(lines)
