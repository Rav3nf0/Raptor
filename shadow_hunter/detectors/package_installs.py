"""Package installs checked against what is known about the package — not "npm ran a shell".

INC-2026-0911-KB began on 2026-08-26 with `npm install self-certificate`, run by the user's
Claude Code agent. OSV had listed the package as malicious since 2026-06-11. The retired
npm_postinstall_scripts detector did flag it — as one of ~112 identical "high" rows a day,
one per install of anything — and nobody reviewed it.

Each explicit install or package run in the window (npm/pnpm/yarn/bun, npx/bunx/dlx, pip/uv/
poetry/pipx/uvx) is judged by:
  * OSV malicious-package advisories (MAL-…) for the version actually installed — pinned, or
    the stable version that was latest at install time. A name-level match alone is not
    enough: cline@2.3.0 was a hijacked release for 8 hours in Feb 2026, and a Sep install of
    cline got 3.x. Known-malicious version: critical.
  * for packages on at most `max_fleet_devices` devices over 30 days, the registry: npm's
    `0.0.1-security` placeholder means the package was pulled as malware (critical); first
    published under 14 days before the install is the profile of a fresh malicious package
    (medium) — OSV lags new malware by hours to days.
Installs by an AI coding agent are marked: the incident's install was one.

Backfill over the 30 days MDE holds (2026-09-30): 15,497 install commands, 409 packages,
known-malicious hits only on up186tdeysecmac2 (a Socket Firewall test with lodahs and
self-certificate[s], 2026-09-28). `npm install` with no names (from package.json) is not
visible: MDE does not show the manifest.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from shadow_hunter.detectors.base import Detector, mask_ids
from shadow_hunter.packages import by_agent, osv_malicious, parse_install, registry_info, version_at

logger = logging.getLogger(__name__)

INSTALL_TOOLS = ("npm", "npx", "pnpm", "yarn", "bun", "bunx", "pip", "pip3", "pipx", "uv", "uvx", "poetry")
INSTALL_VERBS = ("install", "i", "add", "npx", "dlx", "exec", "uvx", "bunx", "isntall")
OWN_SCOPES = ("@acme/", "@acme/")
NEW_PACKAGE_DAYS = 14
REGISTRY_TIMEOUT_S = 8
REGISTRY_CONCURRENCY = 8
REGISTRY_MAX_FAILURES = 3
RUN_BUDGET_S = 300
# A hijacked release of an established package (cline@2.3.0: a stolen npm token, live ~8 h on
# 2026-02-17) is "new" only as a version. On a fleet-rare package, a version published hours
# before the install is the window those releases are caught in, before OSV lists them.
FRESH_VERSION_HOURS = 12
# ...and only for a package that usually releases less than weekly: 72 h on every package gave
# 22 a month of ordinary fast movers (MCP servers, sass, botocore ships almost daily).
SLOW_RELEASE_DAYS = 7


def _usual_release_gap_days(versions: dict[str, str], before: str) -> float | None:
    """Median gap between the last ~10 stable releases before `before`."""
    import re as _re
    ts = sorted(t[:19] for v, t in versions.items() if t and t[:19] < before[:19] and not _re.search(r"[-+]", v))[-11:]
    if len(ts) < 3:
        return None
    gaps = sorted((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 86400
                  for a, b in zip(ts, ts[1:]))
    return gaps[len(gaps) // 2]


def _install_filter(t0: str, t1: str) -> str:
    tools = ", ".join(f'"{t}"' for t in INSTALL_TOOLS)
    verbs = ", ".join(f'"{v}"' for v in INSTALL_VERBS)
    return f"""DeviceProcessEvents
        | where Timestamp between ({t0} .. {t1})
        | where ProcessCommandLine has_any ({tools})
        | where ProcessCommandLine has_any ({verbs})"""


def build_history_kql(end: str = "now()", days: int = 30) -> str:
    return f"""{_install_filter(f"{end} - {days}d", end)}
        | summarize Devices = make_set(DeviceName, 50) by Cmd = substring(ProcessCommandLine, 0, 600)
        | take 50000"""


def build_fleet_counts_kql(names: list[str], end: str = "now()", days: int = 30) -> str:
    """Devices that installed each of `names` over `days`, counted in KQL. Returning the raw
    30-day install history (16k command lines, ~6 MB) instead got the UAT pod OOM-killed
    (256 MiB limit) on 2026-10-01; this returns one small row per name."""
    quoted = ", ".join('"' + n.replace('"', "") + '"' for n in names)
    return f"""let names = dynamic([{quoted}]);
        {_install_filter(f"{end} - {days}d", end)}
        | summarize by DeviceId, Cmd = ProcessCommandLine
        | mv-apply n = names to typeof(string) on (where Cmd has n)
        | summarize Devices = dcount(DeviceId) by n"""


def build_recent_kql(lookback_hours: int = 24, end: str = "now()") -> str:
    return f"""{_install_filter(f"{end} - {lookback_hours}h", end)}
        | summarize Time = min(Timestamp), Parent = take_any(substring(InitiatingProcessCommandLine, 0, 300)),
                    GrandParent = take_any(InitiatingProcessParentFileName)
            by DeviceId, DeviceName, AccountName, Cmd = substring(ProcessCommandLine, 0, 600)
        | take 5000"""


def recent_events(recent: list[dict]) -> list[dict]:
    """Parsed install events from the recent rows (CPU-bound: run it off the event loop)."""
    events = []
    for r in recent:
        for eco, name, pinned in parse_install(r.get("Cmd", "")):
            events.append({"Ecosystem": eco, "Package": name, "Pinned": pinned, "Device": r.get("DeviceName", ""),
                           "DeviceId": r.get("DeviceId", ""), "Account": r.get("AccountName", ""),
                           "Time": str(r.get("Time", "")), "Cmd": r.get("Cmd", "")[:300],
                           "ByAgent": by_agent(r.get("Cmd", ""), r.get("Parent", ""))})
    return events


async def assess(history: list[dict], recent: list[dict], *, osv=osv_malicious, registry=None,
                 max_fleet_devices: int = 2, fleet_counts: dict[str, int] | None = None,
                 events: list[dict] | None = None) -> list[dict]:
    """Rows for to_findings, one per (package, version, device). `osv` and `registry` are
    injectable for tests; registry(eco, name) -> registry_info dict or None. Fleet rarity comes
    from `fleet_counts` (name -> devices, counted in KQL) or, in tests, raw `history` rows."""
    events = events if events is not None else recent_events(recent)
    if fleet_counts is not None:
        for e in events:
            e["FleetDevices"] = max(int(fleet_counts.get(e["Package"], 0)), 1)
    else:
        fleet: dict[tuple, set] = {}
        for h in history:
            for eco, name, _ in parse_install(h.get("Cmd", "")):
                fleet.setdefault((eco, name), set()).update(h.get("Devices") or [])
        for e in events:
            e["FleetDevices"] = len(fleet.get((e["Ecosystem"], e["Package"]), set()) | {e["Device"]})
    # one per device/package/version: an `sfw npm i x` is four processes that all name x
    first: dict[tuple, dict] = {}
    for e in sorted(events, key=lambda e: e["Time"]):
        first.setdefault((e["Device"], e["Ecosystem"], e["Package"], e["Pinned"]), e)
    events = list(first.values())
    if not events:
        return []
    names = sorted({(e["Ecosystem"], e["Package"]) for e in events})
    mal_names = await osv(names)
    if mal_names is None:
        raise RuntimeError("OSV unreachable — package reputation unknown for this run")
    cache: dict[tuple, dict | None] = {}

    async def info(eco, name):
        if (eco, name) not in cache:
            cache[(eco, name)] = await registry(eco, name) if registry else None
        return cache[(eco, name)]

    # registry facts for every package that needs them, fetched concurrently up front
    need = {(e["Ecosystem"], e["Package"]) for e in events
            if (e["Ecosystem"], e["Package"]) in mal_names
            or (e["FleetDevices"] <= max_fleet_devices and not e["Package"].startswith(OWN_SCOPES))}
    await asyncio.gather(*(info(*k) for k in sorted(need)))
    out, versioned = [], []
    for e in events:
        key = (e["Ecosystem"], e["Package"])
        rare = e["FleetDevices"] <= max_fleet_devices and not e["Package"].startswith(OWN_SCOPES)
        if key not in mal_names and not rare:
            continue
        reg = await info(*key)
        taken_down = bool(reg and reg.get("placeholder") and reg.get("placeholder_at")
                          and e["Time"][:19] >= reg["placeholder_at"][:19])
        if taken_down:
            # the registry had already swapped in its security placeholder: the payload was not
            # delivered, but someone tried to install a package pulled as malware
            out.append({**e, "Version": "0.0.1-security", "Reason": "attempted_removed_malware",
                        "MalIds": mal_names.get(key, []), "RemovedAt": reg["placeholder_at"][:19]})
            continue
        version = e["Pinned"] or (version_at(reg["versions"], e["Time"]) if reg and reg.get("versions") else "")
        e.update(Version=version, Created=(reg or {}).get("created", "")[:19])
        if key in mal_names:
            e["MalIds"] = mal_names[key]
            if version:
                versioned.append(e)
            else:
                out.append({**e, "Reason": "malicious_package_version_unknown"})
            continue
        if reg and reg.get("placeholder"):
            out.append({**e, "Reason": "removed_as_malware"})
        elif reg and reg.get("created") and not reg.get("missing"):
            at = datetime.fromisoformat(e["Time"][:19])
            age = at - datetime.fromisoformat(reg["created"][:19])
            published = (reg.get("versions") or {}).get(version, "")
            ver_age = at - datetime.fromisoformat(published[:19]) if published else None
            if timedelta(0) <= age <= timedelta(days=NEW_PACKAGE_DAYS):
                out.append({**e, "Reason": "new_package", "AgeDays": round(age.total_seconds() / 86400, 1)})
            elif ver_age is not None and timedelta(0) <= ver_age <= timedelta(hours=FRESH_VERSION_HOURS):
                gap = _usual_release_gap_days(reg.get("versions") or {}, published)
                if gap is None or gap >= SLOW_RELEASE_DAYS:
                    out.append({**e, "Reason": "fresh_version", "VersionAgeHours": round(ver_age.total_seconds() / 3600, 1),
                                "UsualReleaseGapDays": None if gap is None else round(gap, 1)})
    if versioned:
        hits = await osv([(e["Ecosystem"], e["Package"], e["Version"]) for e in versioned])
        if hits is None:
            raise RuntimeError("OSV unreachable on the versioned lookup")
        for e in versioned:
            ids = hits.get((e["Ecosystem"], e["Package"], e["Version"]))
            if ids:
                out.append({**e, "MalIds": ids, "Reason": "malicious_version"})
            # else: a known-bad package, but not this version (cline 3.x after the 2.3.0 hijack)
    return out


_SEVERITY = {"malicious_version": "critical", "removed_as_malware": "critical", "attempted_removed_malware": "high",
             "malicious_package_version_unknown": "high", "new_package": "medium", "fresh_version": "medium"}
_WHY = {"malicious_version": "OSV lists this version as malicious",
        "removed_as_malware": "the registry replaced it with a security placeholder (pulled as malware)",
        "attempted_removed_malware": "the registry had already pulled it as malware, so the placeholder was installed instead",
        "malicious_package_version_unknown": "OSV lists malicious versions of it; installed version unknown",
        "new_package": "first published {AgeDays} day(s) before this install, on {FleetDevices} device(s) fleet-wide",
        "fresh_version": "this version was published {VersionAgeHours} h before the install (hijacked-release window), "
                         "on {FleetDevices} device(s) fleet-wide"}


class PackageInstallsDetector(Detector):
    name = "package_installs"
    mitre_techniques = ["T1195.002", "T1059.007"]
    severity = "high"
    # every 2 h: each run also scans 30 days of installs for fleet rarity, on the MDE hunting
    # quota RAPTOR shares; an install stays in the 24 h window for 12 runs and is reported once
    cadence_minutes = 120
    query_name = "package_installs"

    def kql(self, lookback_hours: int) -> str:
        return build_recent_kql(lookback_hours=lookback_hours)

    async def fetch(self, defender, lookback_hours: int = 24) -> list[dict]:
        from shadow_hunter.clients import MockDefenderClient
        if isinstance(defender, MockDefenderClient):
            return await defender.hunt(self.query_name)
        import httpx
        from shadow_hunter.config import get_shadow_config
        import time
        t0 = time.monotonic()
        self.run_phases = {}

        def mark(phase):
            self.run_phases[phase] = round(time.monotonic() - t0, 1)
        recent = await defender.hunt(self.query_name, kql=build_recent_kql(lookback_hours=lookback_hours))
        mark("recent")
        if not recent:
            return []
        events = await asyncio.to_thread(recent_events, recent)
        mark("parsed")
        names = sorted({e["Package"] for e in events})
        if not names:
            return []
        counts = await defender.hunt(f"{self.query_name}_fleet", kql=build_fleet_counts_kql(names))
        fleet_counts = {r.get("n", ""): int(r.get("Devices") or 0) for r in counts}
        mark("fleet")
        verify = get_shadow_config().ssl_verify
        self.run_warning = ""
        failures = {"n": 0}
        gate = asyncio.Semaphore(REGISTRY_CONCURRENCY)
        async with httpx.AsyncClient(timeout=REGISTRY_TIMEOUT_S, verify=verify) as client:
            async def reg(eco, name):
                # stop asking once the registry looks unreachable: on UAT a silent egress proxy
                # turned dozens of sequential lookups into a run that never finished
                if failures["n"] >= REGISTRY_MAX_FAILURES:
                    return None
                async with gate:
                    got = await registry_info(client, eco, name)
                if got is None:
                    failures["n"] += 1
                    if failures["n"] == REGISTRY_MAX_FAILURES:
                        self.run_warning = ("package registry unreachable — only OSV-listed malware was checked "
                                            "(no takedown, new-package or fresh-version checks)")
                return got

            async def osv(pkgs):
                got = await osv_malicious(pkgs, verify=verify)
                mark(f"osv_{len(pkgs)}")
                return got
            rows = await asyncio.wait_for(assess([], recent, osv=osv, registry=reg, fleet_counts=fleet_counts,
                                                 events=events), timeout=RUN_BUDGET_S)
            mark("assessed")
            return rows

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            r = mask_ids(dict(r))
            reason = r.get("Reason", "")
            ver = r.get("Version") or "?"
            why = _WHY.get(reason, reason).format(**{"AgeDays": r.get("AgeDays", "?"), "FleetDevices": r.get("FleetDevices", "?"),
                                                     "VersionAgeHours": r.get("VersionAgeHours", "?")})
            out.append({
                "detector": self.name,
                "severity": _SEVERITY.get(reason, "medium"),
                "device_id": r.get("DeviceId") or r.get("Device", ""),
                "device_name": r.get("Device", ""),
                "account_name": r.get("Account", ""),
                "indicator": f"{r.get('Ecosystem')}:{r.get('Package')}@{ver}",
                "summary": (f"{r.get('Ecosystem')} package '{r.get('Package')}@{ver}' installed on '{r.get('Device')}' "
                            f"by {r.get('Account') or '?'}{' via an AI coding agent' if r.get('ByAgent') else ''} — {why}"
                            + (f" ({', '.join(r.get('MalIds') or [])})" if r.get("MalIds") else "")),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
