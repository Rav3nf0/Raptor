"""Incident stories: related findings grouped into one story with a timeline and a report.

Why: the ATLAS intrusion (17-19 Oct 2026) reached /shadow as ~70 separate findings on three
hosts, and 24 more came back as "new" on 19 Oct only because Upwind renamed
'BYOC::byoc-acme-dc::::ffff:10.0.0.76' to 'iatlas-publisher01'. The analyst stitched the
story together by hand. This module does the stitching; the written report is added on
request (a Claude Code pass reads /bundle and posts /report; write_report() is the seam for
an in-app model later). Never Gemini: a story is internal data end to end.

How:
  * Hosts. Every finding's own identifiers (host names via upwind_mirror.host_keys, the
    Upwind asset id, an MDE device id, an IPv4 embedded in a BYOC name) are joined with
    union-find, so one host under several names is one entity. Optionally (Sentinel client
    given) IPs are attached from DeviceNetworkInfo, keeping only IPs with ONE owner in the
    window: private space is reused (lib/kql_templates.mde_ip_owner), so an ambiguous IP is
    left out, never guessed.
  * Edges, each with the reason it was made:
      same_entity       consecutive findings on one host or account within 48 h
      shared_indicator  a rare token (file stem like zzab12cd, file name, domain, public IP,
                        hash, Upwind title) on 2-5 entities within 48 h; tokens on more
                        entities, and a deny-list of everyday ones, never link
      network_touch     host A connected to one of host B's IPs (DeviceNetworkEvents) and
                        B's first finding followed within 60 min
  * A component of linked findings becomes a story when it spans 2+ entities, or holds 3+
    findings on one entity with a seed (a high/critical finding or a 5-in-2h burst).
  * A NEW story also needs a true positive behind it: an analyst's, or the AI's with no
    analyst decision against it. Untriaged groupings wait; an open story keeps growing.
  * Advisory only: never decides, snoozes or allowlists a finding. Closed stories never
    reopen; a new linked finding starts a new story that points back at the closed one.
    Findings an analyst detached never rejoin.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from shadow_hunter.detectors.base import mask_ids

logger = logging.getLogger(__name__)

WINDOW_DAYS = 14
SAME_ENTITY_HOURS = 48
SHARED_TOKEN_HOURS = 48
TOUCH_MINUTES = 60
RARE_MAX_ENTITIES = 5
BURST_COUNT, BURST_HOURS = 5, 2
MAX_CANDIDATES = 5000
MAX_TOUCH_HOSTS, MAX_TOUCH_IPS = 40, 200
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
RUNS_COLL = "story_runs"

# ── redaction ──────────────────────────────────────────────────────────────────

TAIL_MIN_LEN = 12   # below this, the last 4 characters would give away too much of the secret


def _tail(value: str, label: str = "redacted") -> str:
    """'<redacted …oyyp>': the last 4 characters let an analyst tell which credential is meant
    and check it was rotated, without exposing it. Short values (a password like 'Passw0rd!23')
    are hidden whole."""
    return f"<{label} …{value[-4:]}>" if len(value) >= TAIL_MIN_LEN else f"<{label}>"


# Every pattern refuses a value that starts with '<', so redacting twice changes nothing
# (stories are cleaned on the way in and again when served).
_SECRETS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?"),
     lambda m: _tail(m.group(0), "jwt")),
    (re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{8,})"),
     lambda m: m.group(1) + _tail(m.group(2))),
    (re.compile(r"(?i)((?:client_secret|password|passwd|pwd|secret|api[_-]?key|access_token|refresh_token)"
                r"\s*[=:]\s*[\"']?)(?!<)([^\s\"'&,;]{3,})"),
     lambda m: m.group(1) + _tail(m.group(2))),
    (re.compile(r"\b(AKIA|ASIA)([A-Z0-9]{12,})\b"),
     lambda m: m.group(1) + _tail(m.group(2))),
]


def redact_secrets(text: str) -> str:
    for rx, rep in _SECRETS:
        text = rx.sub(rep, text)
    return text


def clean(obj):
    """Secrets out, 12-digit ids masked: everything a story stores or serves goes through this."""
    if isinstance(obj, str):
        return mask_ids(redact_secrets(obj))
    if isinstance(obj, list):
        return [clean(x) for x in obj]
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items()}
    return obj


# ── entity resolution ──────────────────────────────────────────────────────────

_IPV4 = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
_MDE_ID = re.compile(r"^[0-9a-f]{40}$")
_MULTI = re.compile(r"^\d+ devices?$", re.I)


def _host_keys(*names):
    from edr_triage.upwind_mirror import host_keys
    return host_keys(*names)


def _embedded_ip(name: str) -> str:
    """'BYOC::byoc-acme-dc::::ffff:10.0.0.76' -> '10.0.0.76'. Only for names that ARE an
    address (BYOC/INTERNAL_VPC style), never an IP mentioned inside a hostname-like string."""
    n = (name or "").strip()
    if "::ffff:" in n or n.lower().startswith("byoc::") or _IPV4.fullmatch(n):
        m = _IPV4.search(n)
        return m.group(1) if m else ""
    return ""


def _host_names(f) -> list[str]:
    """The host(s) a finding is about. Mass findings ('4 devices') carry their hosts in raw."""
    r = f.raw or {}
    if f.detector == "entity_behavior" and "@" in (f.indicator or ""):
        return [f.indicator.split("@", 1)[0]]
    if f.detector == "person_behavior":
        return [d for d in (r.get("devices") or []) if isinstance(d, str)][:10]
    name = f.device_name or ""
    if _MULTI.match(name) or "," in name:
        devs = r.get("Devices") or r.get("devices") or [x.strip() for x in name.split(",")]
        return [d for d in devs if isinstance(d, str) and d and not _MULTI.match(d)][:10]
    return [name] if name else []


def identifiers(f) -> list[str]:
    """Host identifiers of one finding. All of them name the same host, so they are unioned."""
    out: list[str] = []
    names = _host_names(f)
    single = len(names) == 1
    for n in names:
        ip = _embedded_ip(n)
        if ip:
            out.append(f"ip:{ip}")
        else:
            out += [f"n:{k}" for k in _host_keys(n)]
    if single:
        res = (f.raw or {}).get("resource")
        if not isinstance(res, dict):       # Upwind's resource object; eks_audit stores a Kubernetes resource name
            res = {}
        for aid in (res.get("upwind_asset_id"), res.get("host_id")):
            if aid:
                out.append(f"a:{aid}")
        did = (f.device_id or "").lower()
        if _MDE_ID.match(did):
            out.append(f"d:{did}")
        elif did.startswith(("uwr-", "i-")):
            out.append(f"a:{f.device_id}")
    return list(dict.fromkeys(out))


class _UF:
    def __init__(self):
        self.p: dict = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def resolve_entities(findings: list, extra_aliases: list[tuple[str, str]] = ()) -> tuple[dict, dict]:
    """(finding id -> entity id, entity id -> {names, ips, asset_ids, device_ids}).
    extra_aliases are (identifier, identifier) pairs from outside the findings, e.g. a host
    name and the IP DeviceNetworkInfo says only it held."""
    uf = _UF()
    ids_of: dict[str, list[str]] = {}
    for f in findings:
        try:
            ids = identifiers(f)
        except Exception as exc:   # one malformed finding must not stop every story (19-20 Oct)
            logger.warning("[stories] identifiers of %s (%s) failed: %s", f.id, f.detector, exc)
            ids = []
        ids_of[f.id] = ids
        for a, b in zip(ids, ids[1:]):
            uf.union(a, b)
        for i in ids:
            uf.find(i)
    for a, b in extra_aliases:
        if a in uf.p or b in uf.p:
            uf.union(a, b)
    groups: dict[str, set] = defaultdict(set)
    for i in list(uf.p):
        groups[uf.find(i)].add(i)
    ent_of_root, ents = {}, {}
    for root, members in groups.items():
        names = sorted(m[2:] for m in members if m.startswith("n:"))
        full = [n for n in names if "." in n] or names
        eid = (sorted(full, key=len)[0] if full else sorted(members)[0].split(":", 1)[1])
        ent_of_root[root] = eid
        ents[eid] = {"name": eid, "aliases": names,
                     "ips": sorted(m[3:] for m in members if m.startswith("ip:")),
                     "asset_ids": sorted(m[2:] for m in members if m.startswith("a:")),
                     "device_ids": sorted(m[2:] for m in members if m.startswith("d:"))}
    f2e = {}
    for f in findings:
        ids = ids_of[f.id]
        if ids:
            f2e[f.id] = ent_of_root[uf.find(ids[0])]
        elif f.account_name:
            f2e[f.id] = "acct:" + f.account_name.lower()
            ents.setdefault(f2e[f.id], {"name": f.account_name, "aliases": [], "ips": [], "asset_ids": [], "device_ids": []})
    return f2e, ents


# ── tokens for shared_indicator ────────────────────────────────────────────────

_TOK_RX = [
    ("stem", re.compile(r"\b(zz[0-9a-f]{4,12}|k6[0-9]{4}[0-9a-f]{0,10})\b", re.I)),
    ("file", re.compile(r"\b([\w-]{3,64}\.(?:ashx|aspx|asmx|ps1|psm1|bat|cmd|vbs|hta|jsp|php|sh|dll|exe|scr|py))\b", re.I)),
    ("domain", re.compile(r"\b((?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|app|dev|xyz|top|site|online|ru|cn|pro|cc|info|tk|me|link|club|live))\b", re.I)),
    ("hash", re.compile(r"\b([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)),
]
_DENY = {
    "cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe", "svchost.exe", "explorer.exe", "rundll32.exe",
    "msiexec.exe", "w3wp.exe", "csc.exe", "chrome.exe", "msedge.exe", "python.exe", "pythonw.exe", "node.exe",
    "wscript.exe", "cscript.exe", "regsvr32.exe", "schtasks.exe", "taskhostw.exe", "dllhost.exe", "bash.sh",
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office.net", "live.com", "msn.com",
    "google.com", "googleapis.com", "gstatic.com", "apple.com", "icloud.com", "amazonaws.com", "cloudfront.net",
    "akamaized.net", "github.com", "example.com", "corp.example.com", "goskope.com", "digicert.com", "anthropic.com",
}
_PRIVATE = re.compile(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
# A binary installed by Windows or a vendor (deviceenroller.exe, Intel's igfx*.exe, the Claude
# extension's chrome-native-host.exe) shows up on many hosts for ordinary reasons, so a binary
# name only links hosts when it sits outside these install locations (replay 2026-10-19).
_SYSTEM_PATH = re.compile(r"(\\windows\\(?!temp\\)|system32|syswow64|driverstore|program files|windowsapps|"
                          r"appdata\\local\\packages|appdata\\roaming\\claude|/applications/|/usr/|/opt/homebrew)", re.I)
_BINARY = re.compile(r"\.(exe|dll|sys|scr)$", re.I)
_PATH_START = re.compile(r"[\"'=,;|(]")
# Lineage-shaped findings name processes without their path, so a binary name there can't be
# told apart from an installed one; only their hashes, IPs and domains count.
_NO_FILE_TOKENS = {"entity_behavior", "person_behavior", "fleet_spread"}


def _installed_binary(token: str, blob: str) -> bool:
    """True if any mention of the binary sits in a system/vendor install path. Only the path
    directly in front of the name is judged, not unrelated text before it."""
    for m in re.finditer(re.escape(token), blob, re.I):
        before = blob[max(0, m.start() - 160):m.start()]
        cut = [x.end() for x in _PATH_START.finditer(before)]
        if _SYSTEM_PATH.search(before[cut[-1]:] if cut else before):
            return True
    return False


def tokens(f) -> set[str]:
    """Distinctive strings in a finding. Upwind titles count as tokens too: two hosts raising
    the same rare detection within hours is how publisher02 and iatlas-publisher01 meet."""
    blob = " ".join([f.indicator or "", f.summary or "",
                     json.dumps(f.raw or {}, default=str)[:20000]]).replace("\\\\", "\\")
    out = set()
    for kind, rx in _TOK_RX:
        for m in rx.findall(blob):
            t = m.lower()
            if t in _DENY or (kind == "domain" and any(t.endswith("." + d) for d in _DENY)):
                continue
            if kind == "file" and (f.detector in _NO_FILE_TOKENS or (_BINARY.search(t) and _installed_binary(t, blob))):
                continue
            out.add(f"{kind}:{t}")
    for ip in _IPV4.findall(blob):
        if not _PRIVATE.match(ip) and not ip.startswith(("0.", "255.")):
            out.add(f"ip:{ip}")
    if f.detector == "upwind_threats":
        title = ((f.raw or {}).get("title") or "").strip().lower()
        if title:
            out.add(f"title:{title}")
    return out


# ── time ───────────────────────────────────────────────────────────────────────

def _parse(v) -> datetime | None:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if not v or not isinstance(v, str):
        return None
    try:
        d = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def event_time(f) -> datetime:
    """When it happened, not when /shadow noticed: the timeline must follow the attack."""
    r = f.raw or {}
    for k in ("first_seen", "FirstSeen", "Timestamp", "first_seen_time"):
        d = _parse(r.get(k))
        if d:
            return d
    d = _parse(f.created_at)
    return d or datetime.now(timezone.utc)


# ── edges ──────────────────────────────────────────────────────────────────────

def _edge(a, b, kind, reason):
    return {"a": a, "b": b, "kind": kind, "reason": clean(reason)[:300]}


def same_entity_edges(findings, f2e) -> list[dict]:
    by = defaultdict(list)
    for f in findings:
        if f.id in f2e:
            by[f2e[f.id]].append(f)
    out = []
    for ent, fs in by.items():
        fs.sort(key=event_time)
        for x, y in zip(fs, fs[1:]):
            gap = event_time(y) - event_time(x)
            if gap <= timedelta(hours=SAME_ENTITY_HOURS):
                out.append(_edge(x.id, y.id, "same_entity",
                                 f"both on {ent}, {int(gap.total_seconds() // 60)} min apart"))
    return out


def shared_indicator_edges(findings, f2e, toks: dict) -> list[dict]:
    occ = defaultdict(list)
    for f in findings:
        if f.id in f2e:
            for t in toks.get(f.id, ()):
                occ[t].append(f)
    out = []
    for t, fs in occ.items():
        ents = {f2e[f.id] for f in fs}
        if not 2 <= len(ents) <= RARE_MAX_ENTITIES:
            continue
        fs.sort(key=event_time)
        first_by_ent = {}
        for f in fs:
            first_by_ent.setdefault(f2e[f.id], f)
        anchor = fs[0]
        for ent, f in first_by_ent.items():
            if ent == f2e[anchor.id]:
                continue
            if abs(event_time(f) - event_time(anchor)) <= timedelta(hours=SHARED_TOKEN_HOURS):
                kind, val = t.split(":", 1)
                out.append(_edge(anchor.id, f.id, "shared_indicator",
                                 f"same rare {kind} '{val[:120]}' on {f2e[anchor.id]} and {ent} ({len(ents)} entities in {WINDOW_DAYS}d)"))
    return out


def network_touch_edges(findings, f2e, ents, touches: list[dict]) -> list[dict]:
    """touches: rows {DeviceName, RemoteIP, Times} from DeviceNetworkEvents. An edge when the
    host owning RemoteIP had its first finding 0-60 min after a connection to it."""
    ip_owner = {ip: e for e, d in ents.items() for ip in d.get("ips", [])}
    name_ent = {}
    for e, d in ents.items():
        for n in d.get("aliases", []) + [e]:
            name_ent.setdefault(n.lower(), e)
    first = {}
    for f in sorted(findings, key=event_time):
        if f.id in f2e:
            first.setdefault(f2e[f.id], f)
    by_ent = defaultdict(list)
    for f in findings:
        if f.id in f2e:
            by_ent[f2e[f.id]].append(f)
    out = []
    for row in touches:
        src = name_ent.get(str(row.get("DeviceName", "")).lower()) or name_ent.get(str(row.get("DeviceName", "")).lower().split(".")[0])
        dst = ip_owner.get(str(row.get("RemoteIP", "")).replace("::ffff:", ""))
        if not src or not dst or src == dst or dst not in first:
            continue
        b = first[dst]
        if not by_ent[src]:
            continue
        times = [t for t in (_parse(x) for x in row.get("Times") or []) if t]
        hit = [t for t in times if timedelta(0) <= event_time(b) - t <= timedelta(minutes=TOUCH_MINUTES)]
        if not hit:
            continue
        t = max(hit)
        a = min((f for f in by_ent[src]), key=lambda f: abs(event_time(f) - t))
        out.append(_edge(a.id, b.id, "network_touch",
                         f"{src} connected to {dst} ({row.get('RemoteIP')}) at {t:%Y-%m-%d %H:%M} UTC; "
                         f"{dst}'s first finding came {int((event_time(b) - t).total_seconds() // 60)} min later"))
    return out


# ── Sentinel enrichment (optional, bounded) ────────────────────────────────────

def _kql_names(names) -> str:
    return ", ".join("'" + n.replace("'", "") + "'" for n in names)


async def ip_aliases(client, ents: dict, since: datetime, until: datetime) -> list[tuple[str, str]]:
    """(n:<host>, ip:<addr>) pairs for MDE hosts, keeping IPs only one device held in the window."""
    hosts = sorted({n for d in ents.values() for n in d.get("aliases", []) if "." in n or "-" in n})[:MAX_TOUCH_HOSTS]
    if not hosts:
        return []
    kql = f"""
let t0 = datetime({since:%Y-%m-%dT%H:%M:%SZ}); let t1 = datetime({until:%Y-%m-%dT%H:%M:%SZ});
let mine = DeviceNetworkInfo | where Timestamp between (t0 .. t1)
  | where tolower(DeviceName) in~ ({_kql_names(hosts)}) or tolower(tostring(split(DeviceName, '.')[0])) in~ ({_kql_names(hosts)})
  | mv-expand a = todynamic(IPAddresses) | extend ip = tostring(a.IPAddress)
  | where ip matches regex @'^\\d+\\.\\d+\\.\\d+\\.\\d+$' and ip !startswith '127.' and ip !startswith '169.254.'
  | distinct ip;
DeviceNetworkInfo | where Timestamp between (t0 .. t1)
  | mv-expand a = todynamic(IPAddresses) | extend ip = tostring(a.IPAddress)
  | where ip in (mine)
  | summarize owners = make_set(tolower(DeviceName), 3) by ip
  | where array_length(owners) == 1 | take {MAX_TOUCH_IPS}"""
    rows = await client.query(kql)
    out = []
    for r in rows:
        owners = r.get("owners")
        owners = json.loads(owners) if isinstance(owners, str) else owners or []
        if len(owners) == 1:
            for k in _host_keys(owners[0]):
                out.append((f"n:{k}", f"ip:{r.get('ip')}"))
    return out


async def touches(client, ents: dict, f2e: dict, findings, since: datetime, until: datetime) -> list[dict]:
    src_hosts = sorted({n for e in set(f2e.values()) for n in ents.get(e, {}).get("aliases", []) if "." in n})[:MAX_TOUCH_HOSTS]
    ips = sorted({ip for e in set(f2e.values()) for ip in ents.get(e, {}).get("ips", [])})[:MAX_TOUCH_IPS]
    if not src_hosts or not ips:
        return []
    kql = f"""
DeviceNetworkEvents
| where Timestamp between (datetime({since:%Y-%m-%dT%H:%M:%SZ}) .. datetime({until:%Y-%m-%dT%H:%M:%SZ}))
| where tolower(DeviceName) in~ ({_kql_names(src_hosts)})
| where ActionType in ('ConnectionSuccess', 'ConnectionRequest', 'ConnectionAttempt', 'ConnectionFailed')
| extend rip = replace_string(RemoteIP, '::ffff:', '')
| where rip in ({_kql_names(ips)})
| summarize Times = make_set(bin(Timestamp, 1m), 50) by DeviceName, RemoteIP = rip"""
    rows = await client.query(kql)
    for r in rows:
        if isinstance(r.get("Times"), str):
            r["Times"] = json.loads(r["Times"])
    return rows


# ── components → stories ───────────────────────────────────────────────────────

def components(findings, edges) -> list[list]:
    uf = _UF()
    for f in findings:
        uf.find(f.id)
    for e in edges:
        uf.union(e["a"], e["b"])
    groups = defaultdict(list)
    for f in findings:
        groups[uf.find(f.id)].append(f)
    return list(groups.values())


def _is_seed(f) -> bool:
    return SEV_RANK.get(f.severity, 0) >= SEV_RANK["high"]


def ai_dismissed(f) -> bool:
    """The AI suggested false positive and no human has confirmed it as a threat. Advisory,
    so such a finding still joins a story; it just cannot make one (stories were forming from
    nothing but AI-FP noise: 2 of 8 on UAT, 2026-10-20). The AI never suggests FP on a critical."""
    return getattr(f, "ai_verdict", "") == "false_positive" and getattr(f, "decision", "") != "true_positive"


def human_dismissed(f) -> bool:
    """An analyst dismissed or snoozed it, or a rule allowlisted it: no longer part of a story."""
    return (getattr(f, "decision", "") in ("false_positive", "snooze") or bool(getattr(f, "allowlisted_by_rule", ""))
            or bool(getattr(f, "legacy", False)))


def tp_backed(f) -> bool:
    """A person confirmed it, or the AI suggested true positive and no person has decided."""
    d = getattr(f, "decision", "")
    return d == "true_positive" or (getattr(f, "ai_verdict", "") == "true_positive" and not d)


def qualifies(comp, f2e) -> bool:
    """A story needs real signal: the rules below are judged on the findings the AI did not
    call false positive."""
    comp = [f for f in comp if not ai_dismissed(f)]
    ents = {f2e.get(f.id) for f in comp if f2e.get(f.id)}
    if len(comp) < 2:
        return False
    if len(ents) >= 2:
        return True
    if len(comp) < 3:
        return False
    if any(_is_seed(f) for f in comp):
        return True
    times = sorted(event_time(f) for f in comp)
    return any(times[i + BURST_COUNT - 1] - times[i] <= timedelta(hours=BURST_HOURS)
               for i in range(len(times) - BURST_COUNT + 1))


DET_LABEL = {"encoded_powershell": "encoded PowerShell", "upwind_threats": "Upwind", "rare_persistence": "rare persistence",
             "unusual_remote_logons": "RDP anomaly", "suspicious_parent_child": "parent-child", "exfil_patterns": "exfil",
             "entity_behavior": "behaviour", "person_behavior": "person case", "fleet_spread": "fleet spread",
             "lolbin_abuse": "LOLBin", "defender_exclusions": "Defender exclusion", "package_installs": "package install",
             "edge_attacks": "edge attack", "eks_audit": "EKS audit", "rds_audit": "RDS audit", "ssh_backdoor": "SSH backdoor"}


def describe(comp, f2e, ents) -> dict:
    hosts = sorted({f2e[f.id] for f in comp if f.id in f2e and not f2e[f.id].startswith("acct:")})
    accounts = sorted({f.account_name for f in comp if f.account_name})
    dets = defaultdict(int)
    for f in comp:
        dets[f.detector] += 1
    top = [DET_LABEL.get(d, d) for d, _ in sorted(dets.items(), key=lambda kv: -kv[1])[:3]]
    times = sorted(event_time(f) for f in comp)
    span = times[0].strftime("%d %b") + ("" if times[0].date() == times[-1].date() else "-" + times[-1].strftime("%d %b"))
    who = f"{len(hosts)} hosts" if len(hosts) > 1 else (hosts[0] if hosts else (accounts[0] if accounts else "unknown"))
    timeline = []
    for f in sorted(comp, key=event_time):
        e = f2e.get(f.id, "")
        timeline.append({"ts": event_time(f).isoformat(), "host": e, "ips": ents.get(e, {}).get("ips", []),
                         "event": (((f.raw or {}).get("title") if f.detector == "upwind_threats" else "") or f.summary or f.indicator)[:300],
                         "source": f.detector, "severity": f.severity, "finding_id": f.id})
    sev = max((f.severity for f in comp), key=lambda s: SEV_RANK.get(s, 0))
    return clean({
        "title": f"{who} · {' + '.join(top)} · {span}",
        "severity": sev, "first_seen": times[0], "last_seen": times[-1],
        "entities": {"hosts": [ents[h] for h in hosts if h in ents], "accounts": accounts},
        "timeline": timeline,
    })


# ── build ──────────────────────────────────────────────────────────────────────

async def _candidates(now: datetime) -> list:
    """Open findings, plus confirmed threats: a story is about what happened, and an analyst's
    true positive is part of it. Dismissed, snoozed, allowlisted and legacy findings are out."""
    from shadow_hunter.models import Finding
    since = now - timedelta(days=WINDOW_DAYS)
    return await Finding.find(
        Finding.created_at >= since, Finding.legacy != True, Finding.allowlisted_by_rule == "",  # noqa: E712
        {"$or": [{"reviewed_at": None}, {"decision": "true_positive"}]},
    ).sort("created_at").limit(MAX_CANDIDATES).to_list()


async def build(now: datetime | None = None, client=None) -> dict:
    """Regroup the last WINDOW_DAYS of findings into stories. Idempotent: running it twice
    changes nothing. client: an object with `async query(kql) -> list[dict]` (SentinelLogsClient);
    without it, only the findings' own identifiers and tokens are used."""
    from shadow_hunter.models import AuditLog, Finding, Story
    now = now or datetime.now(timezone.utc)
    pruned, auto_closed = await prune(now)
    stories = {s.id: s for s in await Story.find({"status": {"$in": ["open", "closed"]}}).to_list()}
    detached = {fid for s in stories.values() for fid in s.detached}
    findings = [f for f in await _candidates(now) if f.id not in detached]
    if not findings:
        return {"findings": 0, "stories": 0, "created": 0, "updated": 0, "pruned": pruned, "auto_closed": auto_closed}

    f2e, ents = resolve_entities(findings)
    t0 = min(event_time(f) for f in findings) - timedelta(hours=1)
    t1 = max(event_time(f) for f in findings) + timedelta(hours=1)
    touch_rows, enrich_err = [], ""
    if client is not None:
        try:
            aliases = await ip_aliases(client, ents, t0, t1)
            if aliases:
                f2e, ents = resolve_entities(findings, aliases)
            touch_rows = await touches(client, ents, f2e, findings, t0, t1)
        except Exception as exc:          # enrichment is optional; grouping still runs
            enrich_err = f"{type(exc).__name__}: {str(exc)[:200]}"
            logger.warning("[stories] enrichment skipped: %s", enrich_err)

    toks = {}
    for f in findings:
        try:
            toks[f.id] = tokens(f)
        except Exception as exc:
            logger.warning("[stories] tokens of %s (%s) failed: %s", f.id, f.detector, exc)
            toks[f.id] = set()
    edges = (same_entity_edges(findings, f2e) + shared_indicator_edges(findings, f2e, toks)
             + network_touch_edges(findings, f2e, ents, touch_rows))

    by_id = {f.id: f for f in findings}
    created = updated = 0
    for comp in components(findings, edges):
        if not qualifies(comp, f2e):
            continue
        ids = {f.id for f in comp}
        comp_edges = [e for e in edges if e["a"] in ids and e["b"] in ids]
        open_ids = sorted({f.story_id for f in comp if f.story_id and f.story_id in stories
                           and stories[f.story_id].status == "open"}, key=lambda s: stories[s].created_at)
        closed_ids = sorted({f.story_id for f in comp if f.story_id and f.story_id in stories
                             and stories[f.story_id].status == "closed"})
        if closed_ids:
            # closed stories keep their findings; only the new ones form the continuation
            comp = [f for f in comp if not f.story_id or f.story_id not in closed_ids]
            ids = {f.id for f in comp}
            comp_edges = [e for e in comp_edges if e["a"] in ids and e["b"] in ids]
            if not comp or (not open_ids and not qualifies(comp, f2e)):
                continue
        # A NEW story needs a true positive behind it (a person's, or the AI's undisputed):
        # untriaged groupings were stories nobody needed. An open story still grows as before.
        if not open_ids and not any(tp_backed(f) for f in comp):
            continue
        desc = describe(comp, f2e, ents)
        if open_ids:
            st = stories[open_ids[0]]
            for other in open_ids[1:]:
                o = stories[other]
                o.status, o.merged_into, o.updated_at = "merged", st.id, now
                await o.save()
                await AuditLog(actor="stories", action="story.merged", target_type="story", target_id=o.id,
                               payload={"into": st.id}).insert()
        else:
            st = Story(created_at=now, related=closed_ids)
            created += 1
        before = (sorted(st.finding_ids), st.severity, len(st.edges))
        is_new = st.id not in stories
        keep_sev = (desc["severity"] if is_new or SEV_RANK.get(desc["severity"], 0) >= SEV_RANK.get(st.severity, 0)
                    else st.severity)
        old_edges = {(e["a"], e["b"], e["kind"]): e for e in st.edges}
        for e in comp_edges:
            old_edges.setdefault((e["a"], e["b"], e["kind"]), {**e, "at": now.isoformat()})
        st.finding_ids = sorted(set(st.finding_ids) | ids)
        st.title, st.severity = desc["title"], keep_sev
        st.first_seen, st.last_seen = desc["first_seen"], desc["last_seen"]
        st.entities, st.timeline, st.edges = desc["entities"], desc["timeline"], list(old_edges.values())
        if is_new or before != (sorted(st.finding_ids), st.severity, len(st.edges)):
            st.updated_at = now
            if not is_new:
                updated += 1
        await st.save()
        stories[st.id] = st
        for fid in ids:
            if by_id[fid].story_id != st.id:
                await Finding.find_one(Finding.id == fid).update({"$set": {"story_id": st.id}})
                by_id[fid].story_id = st.id
    return {"findings": len(findings), "entities": len(ents), "edges": len(edges), "touch_rows": len(touch_rows),
            "stories": sum(1 for s in stories.values() if s.status == "open"), "created": created,
            "updated": updated, "pruned": pruned, "auto_closed": auto_closed,
            **({"enrichment_error": enrich_err} if enrich_err else {})}


async def prune(now: datetime) -> tuple[int, int]:
    """Open stories drop findings an analyst dismissed or snoozed since they were grouped
    (kept in `detached`, so they never rejoin), and close when what is left no longer
    qualifies — e.g. every remaining finding is an AI false-positive suggestion. Confirmed
    threats always stay. Returns (findings dropped, stories closed). Audited."""
    from beanie.operators import In
    from shadow_hunter.models import AuditLog, Finding, Story
    dropped = closed = 0
    for st in await Story.find({"status": "open"}).to_list():
        fs = await Finding.find(In(Finding.id, st.finding_ids)).to_list()
        gone = [f.id for f in fs if human_dismissed(f)]
        missing = set(st.finding_ids) - {f.id for f in fs}
        keep = [f for f in fs if f.id not in gone]
        f2e, _ = resolve_entities(keep) if keep else ({}, {})
        if not gone and not missing and qualifies(keep, f2e):
            continue
        if gone or missing:
            st.finding_ids = sorted(f.id for f in keep)
            st.detached = sorted(set(st.detached) | set(gone))
            st.timeline = [t for t in st.timeline if t.get("finding_id") in set(st.finding_ids)]
            st.edges = [e for e in st.edges if e["a"] in set(st.finding_ids) and e["b"] in set(st.finding_ids)]
            dropped += len(gone) + len(missing)
            for fid in gone:
                await Finding.find_one(Finding.id == fid).update({"$set": {"story_id": ""}})
        reason = ""
        if not qualifies(keep, f2e):
            reason = ("every finding was dismissed" if not keep else
                      "the rest are AI false-positive suggestions" if all(ai_dismissed(f) for f in keep) else
                      "what is left no longer links two hosts or forms a burst")
            st.status, st.closed_by, st.closed_at = "closed", "stories:auto", now
            closed += 1
        st.updated_at = now
        await st.save()
        await AuditLog(actor="stories", action="story.auto_closed" if reason else "story.pruned", target_type="story",
                       target_id=st.id, payload={"dropped": gone + sorted(missing), "reason": reason}).insert()
    return dropped, closed


# ── report, bundle, analyst actions ────────────────────────────────────────────

def _trim_raw(raw: dict, limit: int = 2500) -> dict | str:
    s = json.dumps(raw or {}, default=str)
    return raw if len(s) <= limit else s[:limit] + "…"


# The written report follows the ATLAS incident report (v5, 19 Oct 2026): the sections an
# incident lead, the service owners and management read. The writer fills these; the story
# page and the PDF add the IOC table, related alerts, edge/log context, the merged timeline
# and evidence sources from the story itself, so the writer does not retype them.
REPORT_PROMPT_VERSION = "story-report-v1"
REPORT_TEMPLATE = [
    {"heading": "Status and summary",
     "guide": "The answer first: what happened, to which systems and customers, whether it is contained, and the one "
              "thing that is still open. One paragraph, 4-6 sentences, specific numbers and times."},
    {"heading": "What changed since the previous version",
     "guide": "Only when bundle.previous_report exists: new findings, corrections (say what was wrong), new verification. "
              "Bullets, each led by a bold label. Omit the section on a first report."},
    {"heading": "Customer and business impact",
     "guide": "Exposed / attempted / not exposed / scope, each a bold-led bullet. Say what is confirmed from logs and "
              "what is inferred. A table when there are several attempts with different outcomes."},
    {"heading": "Attack path and root cause",
     "guide": "How the attacker got in and moved: the flaw(s), numbered when they combine, with the concrete request, "
              "binary or command. End with the root-cause fix."},
    {"heading": "Credentials, accounts and access",
     "guide": "Which accounts, tokens, keys or secrets were used or exposed, how they were obtained, and what must be "
              "rotated (not just revoked). Never write a secret; refer to it by name or its last 4 characters."},
    {"heading": "Verification",
     "guide": "What was tested or queried to confirm the facts above and whether the hole is still open, with dates. "
              "A small table for test results."},
    {"heading": "Affected systems and scope",
     "guide": "Hosts, services and accounts touched, what each reached, and what was probed but not reached."},
    {"heading": "Containment assessment",
     "guide": "What is in place, its gaps (who it does not stop), and the recommended next containment step."},
    {"heading": "Containment and remediation tracker",
     "guide": "A pipe table: # | Action | Owner | Status (Done / In progress / Not started)."},
    {"heading": "Open questions",
     "guide": "Each a bullet ending with the team that can answer it."},
]
REPORT_GUIDE = (
    "Write for the incident lead, service owners and management. Times in IST (UTC+5:30), written like "
    "'19 Oct 07:16 IST'. Bodies are Markdown: paragraphs, '- ' bullets, '1. ' lists, **bold**, `code` and pipe "
    "tables. Facts only from the bundle and your own read-only investigation; label anything inferred. Never "
    "include secrets (passwords, tokens, keys, connection strings); 12-digit numbers are masked. Do not repeat "
    "the IOC table, the timeline, related alerts or log context: the page and PDF add them from the story. "
    "Leave a section out rather than pad it."
)


def report_prompt(story_id: str, base_url: str = "") -> str:
    """What to paste into Claude Code to get the report written (until an in-app writer exists)."""
    base = (base_url or "").rstrip("/")
    return (
        f"Write the incident report for /shadow story {story_id}. Read {base}/api/shadow/stories/{story_id}/bundle "
        "(session cookie). Think like a security engineer: check the findings, related_alerts and vlogs context, and "
        "investigate further read-only where a claim needs it (VictoriaLogs, MDE/Sentinel hunts; no writes, no "
        "attack traffic). Follow bundle.report_template and bundle.report_guide. Then POST "
        f"{base}/api/shadow/stories/{story_id}/report with {{\"sections\": [{{\"heading\", \"body\"}}...], "
        f"\"by\": \"claude-code-manual\", \"prompt_version\": \"{REPORT_PROMPT_VERSION}\"}}. "
        f"The PDF is {base}/shadow/stories/{story_id}/print."
    )


async def bundle(story_id: str) -> dict | None:
    """Everything a report writer needs, masked: entities with IPs, edges with reasons, the
    timeline, each member finding with its AI suggestion and a trimmed raw, the related Jira
    alerts and VictoriaLogs context, auto IOCs, the previous report and the report template."""
    from beanie.operators import In
    from shadow_hunter.models import Finding, Story
    from shadow_hunter.story_context import iocs, merged_timeline
    st = await Story.get(story_id)
    if not st:
        return None
    fs = await Finding.find(In(Finding.id, st.finding_ids)).to_list()
    ctx = st.context or {}
    return clean({
        "story": {"id": st.id, "title": st.title, "status": st.status, "severity": st.severity,
                  "first_seen": st.first_seen, "last_seen": st.last_seen, "related": st.related},
        "entities": st.entities, "edges": st.edges, "timeline": merged_timeline(st),
        "previous_report": st.report,
        "findings": [{"id": f.id, "detector": f.detector, "severity": f.severity, "device_name": f.device_name,
                      "account_name": f.account_name, "indicator": f.indicator, "summary": f.summary,
                      "event_time": event_time(f), "ai_verdict": f.ai_verdict, "ai_reasoning": f.ai_reasoning,
                      "decision": f.decision, "raw": _trim_raw(f.raw)} for f in sorted(fs, key=event_time)],
        "indicators": st.indicators,
        "related_alerts": ctx.get("alerts", []),
        "infra": ctx.get("infra", {}),
        "vlogs": ctx.get("vlogs", {}),
        "context_fetched_at": ctx.get("fetched_at", ""),
        "iocs": iocs(st, fs),
        "report_template": REPORT_TEMPLATE,
        "report_guide": REPORT_GUIDE,
        "report_prompt_version": REPORT_PROMPT_VERSION,
    })


async def set_report(story_id: str, sections: list[dict], by: str, prompt_version: str = "") -> dict:
    from shadow_hunter.models import AuditLog, Story
    st = await Story.get(story_id)
    if not st:
        raise LookupError("story not found")
    secs = [{"heading": clean(str(s.get("heading", "")))[:200], "body": clean(str(s.get("body", "")))[:20000]}
            for s in (sections or []) if isinstance(s, dict) and (s.get("heading") or s.get("body"))][:30]
    if not secs:
        raise ValueError("report needs at least one section with a heading or body")
    if st.report:
        st.report_history = ([st.report] + st.report_history)[:5]
    st.report = {"sections": secs, "by": clean(by)[:80], "prompt_version": clean(prompt_version)[:80],
                 "at": datetime.now(timezone.utc).isoformat(), "version": int((st.report or {}).get("version", 0)) + 1}
    st.updated_at = datetime.now(timezone.utc)
    st.report_requested_at, st.report_requested_by = None, ""
    await st.save()
    await AuditLog(actor=st.report["by"], action="story.report", target_type="story", target_id=st.id,
                   payload={"version": st.report["version"], "sections": len(secs)}).insert()
    return st.report


REPORT_SYSTEM = (
    "You are a senior incident responder writing the incident report for a security team, its service "
    "owners and management. You reason like a security engineer: every claim traces to evidence in the "
    "bundle, inferred points are labelled as inferred, absence of evidence is not evidence of absence, and "
    "you never call something contained or benign without the evidence that shows it. You cannot run new "
    "queries; where the bundle cannot settle a question, say so and put it under Open questions."
)
BUNDLE_LIMIT = 400_000          # characters of bundle JSON sent to the model (~100k tokens)
_WRITING: set = set()           # background report tasks, held so they are not garbage-collected


def report_writer_enabled() -> bool:
    """In-app reports: Claude only (SHADOW_LLM=claude) and only when SHADOW_STORY_REPORTS is on."""
    from agent_core.backend import shadow_llm
    return shadow_llm() == "claude" and os.getenv("SHADOW_STORY_REPORTS", "0").strip().lower() in ("1", "true", "yes", "on")


def fit_bundle(b: dict, limit: int = BUNDLE_LIMIT) -> str:
    """The bundle as JSON within `limit` characters: raw finding payloads are cut first, then
    log-context rows, then the oldest findings. Says what was cut, so the writer knows."""
    b = json.loads(json.dumps(b, default=str))
    cuts = []
    for raw_cap in (800, 200, 0):
        s = json.dumps(b, default=str)
        if len(s) <= limit:
            break
        for f in b.get("findings", []):
            f["raw"] = (json.dumps(f.get("raw"), default=str)[:raw_cap] + "…") if raw_cap else "(cut)"
        cuts.append(f"finding raw cut to {raw_cap} chars")
    if len(json.dumps(b, default=str)) > limit:
        for src in (b.get("vlogs") or {}).values():
            for res in src.values():
                res["rows"] = (res.get("rows") or [])[:8]
        cuts.append("log-context rows cut to 8 per lookup")
    while len(json.dumps(b, default=str)) > limit and len(b.get("findings", [])) > 20:
        b["findings"] = b["findings"][len(b["findings"]) // 4:]
        cuts.append("oldest findings dropped")
    if cuts:
        b["_cut"] = sorted(set(cuts))
    return json.dumps(b, default=str)[:limit]


def parse_sections(text: str) -> list[dict]:
    """{"sections": [{heading, body}]} out of the model's reply (fenced or bare)."""
    m = re.search(r"\{.*\}", text or "", flags=re.S)
    if not m:
        return []
    try:
        # strict=False: models often put raw line breaks inside the markdown strings
        d = json.loads(m.group(0), strict=False)
    except json.JSONDecodeError:
        return []
    secs = d.get("sections") if isinstance(d, dict) else None
    return [s for s in (secs or []) if isinstance(s, dict) and (s.get("heading") or s.get("body"))]


async def write_report(story_id: str) -> dict | None:
    """In-app report writer: Claude (SHADOW_LLM=claude, SHADOW_STORY_REPORTS=1) with extended
    thinking, from the story bundle alone. Returns the stored report, or None when the writer is
    off. Raises on a failed call or an unusable reply; the caller keeps the story queued for a
    Claude Code pass. Never Gemini."""
    if not report_writer_enabled():
        return None
    from agent_core.backend import get_shadow_backend, shadow_model_id
    b = await bundle(story_id)
    if b is None:
        raise LookupError("story not found")
    template = "\n".join(f"- {t['heading']}: {t['guide']}" for t in REPORT_TEMPLATE)
    prompt = (f"{REPORT_GUIDE}\n\nSections, in this order (omit one that has nothing to say):\n{template}\n\n"
              'Reply with JSON only: {"sections": [{"heading": "...", "body": "markdown"}]}\n\n'
              f"STORY BUNDLE (masked; secrets redacted):\n{fit_bundle(b)}")
    text, _ = await get_shadow_backend(thinking=True).chat(
        [{"role": "system", "content": REPORT_SYSTEM}, {"role": "user", "content": prompt}], [])
    secs = parse_sections(text)
    if not secs:
        raise ValueError(f"no report sections in the model reply ({len(text or '')} chars)")
    return await set_report(story_id, secs, f"ai:{shadow_model_id()}", f"{REPORT_PROMPT_VERSION}-inapp")


async def preview_report(story_id: str, backend, label: str) -> dict:
    """Write a report with any backend WITHOUT storing it on the story (model comparisons).
    Same prompt and bundle as write_report; thinking only if the backend has it."""
    b = await bundle(story_id)
    if b is None:
        raise LookupError("story not found")
    template = "\n".join(f"- {t['heading']}: {t['guide']}" for t in REPORT_TEMPLATE)
    prompt = (f"{REPORT_GUIDE}\n\nSections, in this order (omit one that has nothing to say):\n{template}\n\n"
              'Reply with JSON only: {"sections": [{"heading": "...", "body": "markdown"}]}\n\n'
              f"STORY BUNDLE (masked; secrets redacted):\n{fit_bundle(b)}")
    text, _ = await backend.chat([{"role": "system", "content": REPORT_SYSTEM}, {"role": "user", "content": prompt}], [])
    secs = [{"heading": clean(str(x.get("heading", "")))[:200], "body": clean(str(x.get("body", "")))[:20000]}
            for x in parse_sections(text)]
    out = {"story": story_id, "by": label, "sections": secs, "raw_chars": len(text or ""),
           "at": datetime.now(timezone.utc).isoformat()}
    if not secs:
        out["raw"] = clean((text or "")[:30000])        # unparseable: keep the reply so it can be read
    return out


async def _write_in_background(story_id: str) -> None:
    from shadow_hunter.models import AuditLog
    try:
        rep_ = await write_report(story_id)
        logger.info("[stories] in-app report for %s: v%s", story_id, (rep_ or {}).get("version"))
    except Exception as exc:
        logger.exception("[stories] in-app report for %s failed", story_id)
        await AuditLog(actor="stories", action="story.report_failed", target_type="story", target_id=story_id,
                       payload={"error": f"{type(exc).__name__}: {str(exc)[:300]}"}).insert()


async def request_report(story_id: str, actor: str, base_url: str = "") -> dict:
    """'Get report': the in-app writer when one exists, otherwise the story is marked as
    waiting for a Claude pass (GET /api/shadow/stories?report=requested) and the prompt to
    run it is returned."""
    from shadow_hunter.models import AuditLog, Story
    st = await Story.get(story_id)
    if not st:
        raise LookupError("story not found")
    st.report_requested_at, st.report_requested_by = datetime.now(timezone.utc), clean(actor or "analyst")[:80]
    await st.save()
    writing = report_writer_enabled()
    await AuditLog(actor=st.report_requested_by, action="story.report_requested", target_type="story",
                   target_id=st.id, payload={"in_app": writing}).insert()
    if writing:
        # Opus with thinking takes minutes, longer than an HTTP request should wait. On
        # failure the story stays queued and the prompt below still works.
        task = asyncio.create_task(_write_in_background(st.id))
        _WRITING.add(task)
        task.add_done_callback(_WRITING.discard)
    return {"written": False, "requested": True, "writing": writing, "prompt": report_prompt(st.id, base_url)}


async def add_indicator(story_id: str, value: str, note: str, actor: str) -> dict:
    """An analyst's indicator (e.g. the attacker IP from IIS logs, which no detection carried):
    looked up at the edge and in other logs on the next context refresh. Audited."""
    from shadow_hunter.models import AuditLog, Story
    from shadow_hunter.story_context import MAX_INDICATORS, indicator_kind
    st = await Story.get(story_id)
    if not st:
        raise LookupError("story not found")
    v = (value or "").strip()
    kind = indicator_kind(v)
    if not kind:
        raise ValueError("an indicator is a public IPv4 or a single token (3-100 of letters, digits, . _ @ : / + = -)")
    if any(i.get("value") == v for i in st.indicators):
        return {"ok": True, "indicators": st.indicators, "added": False}
    if len(st.indicators) >= MAX_INDICATORS:
        raise ValueError(f"a story holds at most {MAX_INDICATORS} added indicators")
    st.indicators = st.indicators + [clean({"value": v, "kind": kind, "note": (note or "").strip()[:200],
                                            "by": (actor or "analyst")[:80], "at": datetime.now(timezone.utc).isoformat()})]
    st.context_at = None                     # due for a refresh
    await st.save()
    await AuditLog(actor=actor or "analyst", action="story.indicator_added", target_type="story", target_id=st.id,
                   payload={"value": v, "kind": kind}).insert()
    return {"ok": True, "indicators": st.indicators, "added": True}


async def remove_indicator(story_id: str, value: str, actor: str) -> dict:
    from shadow_hunter.models import AuditLog, Story
    st = await Story.get(story_id)
    if not st:
        raise LookupError("story not found")
    left = [i for i in st.indicators if i.get("value") != (value or "").strip()]
    if len(left) != len(st.indicators):
        st.indicators = left
        await st.save()
        await AuditLog(actor=actor or "analyst", action="story.indicator_removed", target_type="story", target_id=st.id,
                       payload={"value": value}).insert()
    return {"ok": True, "indicators": st.indicators}


async def detach(story_id: str, finding_id: str, actor: str) -> dict:
    from shadow_hunter.models import AuditLog, Finding, Story
    st = await Story.get(story_id)
    if not st or finding_id not in st.finding_ids:
        raise LookupError("finding is not in this story")
    st.finding_ids = [x for x in st.finding_ids if x != finding_id]
    st.detached = sorted(set(st.detached) | {finding_id})
    st.edges = [e for e in st.edges if finding_id not in (e["a"], e["b"])]
    st.timeline = [t for t in st.timeline if t.get("finding_id") != finding_id]
    st.updated_at = datetime.now(timezone.utc)
    await st.save()
    await Finding.find_one(Finding.id == finding_id).update({"$set": {"story_id": ""}})
    await AuditLog(actor=actor, action="story.detach", target_type="story", target_id=st.id,
                   payload={"finding_id": finding_id}).insert()
    return {"ok": True, "findings": len(st.finding_ids)}


async def merge(story_id: str, other_id: str, actor: str) -> dict:
    from beanie.operators import In
    from shadow_hunter.models import AuditLog, Finding, Story
    a, b = await Story.get(story_id), await Story.get(other_id)
    if not a or not b or a.id == b.id:
        raise LookupError("both stories must exist and differ")
    now = datetime.now(timezone.utc)
    a.finding_ids = sorted(set(a.finding_ids) | set(b.finding_ids))
    a.edges += [{"a": a.id, "b": b.id, "kind": "analyst", "reason": f"merged by {actor}", "at": now.isoformat()}] + b.edges
    a.timeline = sorted(a.timeline + b.timeline, key=lambda t: t.get("ts", ""))
    a.severity = max(a.severity, b.severity, key=lambda s: SEV_RANK.get(s, 0))
    a.updated_at = now
    b.status, b.merged_into, b.updated_at = "merged", a.id, now
    await a.save()
    await b.save()
    await Finding.find(In(Finding.id, b.finding_ids)).update({"$set": {"story_id": a.id}})
    await AuditLog(actor=actor, action="story.merge", target_type="story", target_id=a.id, payload={"from": b.id}).insert()
    return {"ok": True, "findings": len(a.finding_ids)}


async def set_status(story_id: str, status: str, actor: str) -> dict:
    from shadow_hunter.models import AuditLog, Story
    if status not in ("open", "closed"):
        raise ValueError("status must be open or closed")
    st = await Story.get(story_id)
    if not st or st.status == "merged":
        raise LookupError("story not found")
    st.status, st.updated_at = status, datetime.now(timezone.utc)
    st.closed_by, st.closed_at = (actor, st.updated_at) if status == "closed" else ("", None)
    await st.save()
    await AuditLog(actor=actor, action=f"story.{status}", target_type="story", target_id=st.id, payload={}).insert()
    return {"ok": True, "status": st.status}


# ── runs ───────────────────────────────────────────────────────────────────────

def _db():
    from shadow_hunter.models import Finding
    return Finding.get_pymongo_collection().database


async def run_logged(client=None) -> dict:
    """build() with its outcome recorded in Mongo (GET /api/shadow/stories/status)."""
    runs = _db()[RUNS_COLL]
    started = datetime.now(timezone.utc)
    rid = started.strftime("%Y-%m-%dT%H:%M:%S")
    await runs.replace_one({"_id": rid}, {"_id": rid, "state": "running", "started": started.isoformat()}, upsert=True)
    try:
        rec = {"state": "done", **await build(client=client)}
    except Exception as exc:
        logger.exception("[stories] build failed")
        rec = {"state": "failed", "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
    rec["finished"] = datetime.now(timezone.utc).isoformat()
    await runs.update_one({"_id": rid}, {"$set": rec})
    return {"run": rid, **rec}


async def status(limit: int = 10) -> dict:
    runs = await _db()[RUNS_COLL].find({}).sort("_id", -1).limit(limit).to_list(limit)
    return {"runs": [{**r, "run": r.pop("_id")} for r in runs]}
