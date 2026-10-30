"""Behaviour-based entity scoring for /shadow — learned profiles, not signature lists.

Each device's process lineages (grandparent > parent > child, version numbers normalised so
python3.13 == python3.12 and Claude Code's `2.1.266` binaries are one name) are profiled
daily. A device is scored on how its behaviour departs from its own history and from the
fleet, combined with the network rarity findings rare_domains already produces:

  novel_risky      lineages this device never ran before, that almost no other device runs,
                   involving an interpreter or a sensitive tool
  rare_persistent  fleet-rare interpreter lineages running from persistence (launchd, cron,
                   services) — whether or not they are new for the device. A persistent
                   implant is NOT novel after its first day; self-novelty alone learns it as
                   normal (INC-2026-0911-KB: the launchd > python3 - lineage already ran on
                   Sep 2), so fleet rarity has to count independently.
  net_high/med     rare_external_domains findings for the device that day

The score multiplies by the number of distinct signal kinds present: one noisy signal
stays low, several different unusual behaviours on one entity rise sharply. Prototype on
the incident day (2026-09-10, 1,132 entities with any signal): macbook-pro-51 ranked #1 at
84, the next entity at 42.

Quota: MDE advanced hunting has a per-tenant CPU quota shared with RAPTOR's own hunts; a
7-day fleet-wide rescan tripped CpuQuotaExceeded. So the builder scans ONE day, once, and
history lives in Mongo: per fleet-rare lineage, the devices that ran it each day; for
common lineages only the fact that they were common.
"""
from __future__ import annotations

import logging
import re
from datetime import date, datetime, timedelta, timezone

logger = logging.getLogger(__name__)

RARE_MAX_DEVICES = 5        # a lineage on more devices than this on a day is "common" that day
NOVEL_MAX_FLEET = 3         # novelty only counts for lineages this rare across the window
RARE_MAX_FLEET = 2          # "fleet-rare" for the persistent signal
HISTORY_DAYS = 7
# One missing day in the window is tolerated: 2026-10-05's build OOM-killed the pod every time,
# and requiring all 7 then refused to score every day until it left the window a week later.
MIN_HISTORY_DAYS = HISTORY_DAYS - 1
TOP_ENTITIES_PER_DAY = 25
NOVELTY_DAMPING = 5.0   # baseline of 5 rare risky lineages/day halves novelty points
MIN_SCORE = 10
BUILD_TIMEOUT_S = 240

# Last result per day, for GET /api/shadow/behavior/status. In Mongo, not process memory:
# the app runs as several replicas, and an in-memory record answered differently depending
# on which replica served the request.
RUNS_COLL = "behavior_runs"

INTERPRETERS = ("python#", "python", "python#.#", "node", "ruby", "perl", "php", "osascript",
                "bash", "sh", "zsh", "dash", "curl", "wget", "powershell", "pwsh", "cmd",
                "wscript", "cscript", "mshta")
SENSITIVE = ("kubectl", "security", "aws", "ssh", "scp", "nc", "ncat", "base#", "openssl",
             "sqlite#", "dscl", "launchctl", "crontab", "certutil", "reg", "schtasks")
DETACHED_PARENTS = ("launchd", "cron", "crond", "systemd", "services", "taskeng")

RARE_COLL = "behavior_lineage_days"
COMMON_COLL = "behavior_common_lineages"
COMMON_DAYS_COLL = "behavior_common_lineage_days"   # per-day devices for common lineages (spread)
# Every ranked device per day, whatever its severity — the ranked view and investigation
# context. Only QUEUE_SEVERITIES also become /shadow findings.
SCORES_COLL = "behavior_scores"
# The top 25 were all written as findings: on 2026-09-28, an ordinary day, that was 14 low and
# 11 medium rows for busy developer Macs, ~175 rows a week that nobody needs to click through.
QUEUE_SEVERITIES = ("high", "medium")
RETENTION_DAYS = 45       # TTL on everything stored here; comfortably past the 7-day window
SPREAD_POINTS = 3
PERSISTENCE_POINTS = 3     # per fleet-rare persistence item created that day, max 2
# RDP by an account new to the target. Not a /shadow row on its own (~5 a day on UAT, mostly
# RMS operators reaching a new desk) — a signal kind, so it adds up with anything else the
# target does. It is also the only view of lateral movement through the jump hosts, whose
# logons the RDP detector's allowlist hides.
ACCESS_POINTS = 2
# A named runtime detection by Upwind's sensor on the same host (process/file/network, MEDIUM
# or above, first seen that day). A second, independent sensor naming the host is strong: a
# signal kind of its own, and more points than one of MDE's weak signals.
UPWIND_POINTS = 4

# A rare binary counts only when it runs from outside the standard install locations. The
# fleet's long tail of legitimate apps (Dictionary, Grammarly, Telegram, Acrobat, Logitech,
# FortiClient) is each on 1-2 devices and starts from launchd — rarity alone made every one
# a "persistent rare binary" (2026-09-28 replay: 3 ordinary laptops scored high). Implants
# sit in user-writable, temp or hidden paths.
STANDARD_BIN_PREFIXES = ("/applications/", "/system/", "/library/", "/usr/bin/", "/usr/sbin/",
                         "/usr/libexec/", "/usr/lib/", "/bin/", "/sbin/", "/opt/homebrew/",
                         "/usr/local/", "/snap/", "c:\\program files", "c:\\windows\\",
                         "c:\\programdata\\microsoft\\")
# A lineage spreading across the fleet matters when its CHILD is a tool an attacker needs —
# not when an ops script rolls `pgrep` out to 70 servers (2026-09-28).
SPREAD_CHILDREN = SENSITIVE + ("curl", "wget", "nc", "ncat", "socat", "osascript", "powershell",
                               "pwsh", "python#", "python#.#", "python", "node", "perl", "ruby")

# Stored command lines are samples for an analyst, and command lines routinely carry secrets.
# Redacted before they are written; 12-digit runs are masked too (Aadhaar-shaped numbers trip
# DLP on anyone who later reads the finding).
_REDACTIONS = [
    # Bearer first: the key=value rule below would otherwise take the word "Bearer" as the
    # value of "Authorization:" and leave the token itself in place.
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), lambda m: "Bearer <redacted>"),
    # A name CONTAINING a secret word (AWS_SECRET_ACCESS_KEY, db_password, X-Api-Key), then
    # = or : or a space, then the value.
    (re.compile(r"(?i)(?P<name>[\w-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key"
                r"|auth(?:orization)?|private[_-]?key|session|cookie)[\w-]*)"
                r"(?P<sep>\s*[=:]\s*|\s+)(?P<val>\"[^\"]*\"|'[^']*'|\S+)"),
     lambda m: m.group("val") if m.group("val") == "<redacted>"
     else f"{m.group('name')}{m.group('sep')}<redacted>"),
    (re.compile(r"(?i)(?P<flag>(?<!\w)--?(?:p|pass(?:word)?|token|secret|key|auth)[= ])(?P<val>\S+)"),
     lambda m: f"{m.group('flag')}<redacted>"),
    (re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@"), lambda m: f"{m.group(1)}<redacted>@"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), lambda m: "<jwt>"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), lambda m: "<aws-key>"),
    # Long key/token-like runs: letters AND digits, no "/" — with "/" in the class it swallowed
    # ordinary long file paths (/System/Library/PrivateFrameworks/... -> /<blob>.<blob>),
    # destroying the evidence and making every such path look non-standard.
    (re.compile(r"(?<![A-Za-z0-9+_-])(?=[A-Za-z0-9+_-]*\d)(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{40,}={0,2}"),
     lambda m: "<blob>"),
    (re.compile(r"\b\d{12}\b"), lambda m: "<12digit>"),
]


def redact_cmd(cmd: str) -> str:
    out = str(cmd or "")
    for rx, repl in _REDACTIONS:
        out = rx.sub(repl, out)
    return out[:300]


def lineage_parts(L: str) -> tuple[str, str, str]:
    parts = (L.split(" > ") + ["", "", ""])[:3]
    return parts[0], parts[1], parts[2]


def lineage_flags(L: str) -> dict:
    """Same classification the builder query applies, derived from the lineage string."""
    p0, p1, p2 = lineage_parts(L)
    return {"interp": p1 in INTERPRETERS or p2 in INTERPRETERS or p1.startswith("python"),
            "sens": p2 in SENSITIVE, "det": p0 in DETACHED_PARENTS}


def nonstandard_path(cmd: str) -> bool:
    """True when the command's executable path is known and sits outside the standard install
    locations. An unknown path (no path in the sample) is NOT treated as non-standard."""
    c = str(cmd or "").strip()
    if c.startswith('"'):
        exe = c[1:].split('"', 1)[0]
    else:
        exe = c.split(" ", 1)[0]
    exe = exe.strip().lower()
    if not exe or ("/" not in exe and "\\" not in exe):
        return False
    # A path mangled by redaction (documents stored before the blob rule was fixed) is
    # unknown, not non-standard.
    if "<blob>" in exe or "<redacted>" in exe:
        return False
    return not exe.startswith(STANDARD_BIN_PREFIXES)


def _expiry(day: date) -> datetime:
    return datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc) + timedelta(days=RETENTION_DAYS)


def _kql_list(items) -> str:
    return ", ".join(f'"{i}"' for i in items)


def _norm(col: str) -> str:
    return f'replace_regex(trim_end(@"\\.exe", tolower({col})), @"[0-9]+", "#")'


def _day_lineages(day: date) -> str:
    return f"""
        let D = datetime({day.isoformat()});
        let interp = dynamic([{_kql_list(INTERPRETERS)}]);
        let sensitive = dynamic([{_kql_list(SENSITIVE)}]);
        let detached = dynamic([{_kql_list(DETACHED_PARENTS)}]);
        let today = DeviceProcessEvents
            | where Timestamp between (D .. D + 1d)
            | extend P0 = {_norm("InitiatingProcessParentFileName")},
                     P1 = {_norm("InitiatingProcessFileName")}, P2 = {_norm("FileName")}
            | extend L = strcat(P0, " > ", P1, " > ", P2);
        let counts = today | summarize DevCount = dcount(DeviceId) by L;"""


def build_rare_kql(day: date) -> str:
    """Per-device rows for lineages seen on <= RARE_MAX_DEVICES devices that day."""
    return _day_lineages(day) + f"""
        today
        | join kind=inner (counts | where DevCount <= {RARE_MAX_DEVICES}) on L
        | extend IsInterp = P1 in (interp) or P2 in (interp) or P1 matches regex @"^python",
                 IsSens = P2 in (sensitive), IsDet = P0 in (detached)
        // Stored command lines are cut to 300 chars (redact_cmd); sending them whole made one busy
        // day's response (19k rows, some 31k-char agent PowerShell wrappers) OOM-kill the 256 MiB
        // pod while it was still being received (2026-10-05, five attempts).
        | summarize n = count(), cmd = take_any(substring(ProcessCommandLine, 0, 600)),
                    IsInterp = max(toint(IsInterp)), IsSens = max(toint(IsSens)),
                    IsDet = max(toint(IsDet)), DevCount = take_any(DevCount)
            by L, DeviceId, DeviceName
        """


def build_common_kql(day: date) -> str:
    """Common lineages for the day, with a device sample — a lineage that is common on its
    FIRST day is spreading (the supply-chain shape fleet rarity alone would hide)."""
    return _day_lineages(day) + f"""
        today
        | summarize DevCount = dcount(DeviceId), Devices = make_set(DeviceName, 25) by L
        | where DevCount > {RARE_MAX_DEVICES}
        """


def rows_to_rare_docs(rows: list[dict], day: date) -> list[dict]:
    """Group per-device rows into one document per (day, lineage)."""
    by_l: dict[str, dict] = {}
    for r in rows:
        L = r.get("L") or ""
        d = by_l.setdefault(L, {"day": day.isoformat(), "L": L, "devices": [],
                                "interp": False, "sens": False, "det": False,
                                "redacted": True, "expires_at": _expiry(day)})
        d["devices"].append({"id": r.get("DeviceId", ""), "name": r.get("DeviceName", ""),
                             "n": int(r.get("n") or 0), "cmd": redact_cmd(r.get("cmd"))})
        d["interp"] |= bool(int(r.get("IsInterp") or 0))
        d["sens"] |= bool(int(r.get("IsSens") or 0))
        d["det"] |= bool(int(r.get("IsDet") or 0))
    return list(by_l.values())


def prior_devices(history_docs: list[dict]) -> dict[str, set[str]]:
    """Lineage -> device ids that ran it, from full history docs (tests; score_day gets the
    same mapping straight from a Mongo aggregation instead of loading the documents)."""
    prior: dict[str, set[str]] = {}
    for h in history_docs:
        prior.setdefault(h["L"], set()).update(dv["id"] for dv in h["devices"])
    return prior


def device_key(name: str, device_id: str = "") -> str:
    """Key for a per-device signal: the name, plus the DeviceId when the source has one."""
    return f"{name}|{device_id}" if device_id and device_id != name else name


def split_device_key(key: str) -> tuple[str, str]:
    name, _, did = key.partition("|")
    return name, did


def score_entities(today_docs: list[dict], prior: dict[str, set[str]], common_in_window: set[str],
                   net_counts: dict[str, dict], novelty_baseline: dict[str, float] | None = None,
                   common_bins: set[str] | None = None,
                   spread: dict[str, list[str]] | None = None,
                   persistence_new: dict[str, list[str]] | None = None,
                   access_new: dict[str, list[str]] | None = None,
                   upwind_new: dict[str, list[str]] | None = None) -> list[dict]:
    """Pure scoring. today_docs: rare-lineage docs for the day being scored.
    prior: lineage -> device ids that ran it in the HISTORY_DAYS before. common_in_window:
    lineages that were common on any day in the window. net_counts: device name ->
    {"high": n, "medium": n} for that day's rare destinations. novelty_baseline: device name
    -> its mean daily count of rare risky lineages over the window (its own normal).
    common_bins: binary names that appear as the child of any common lineage in the window.
    spread: device name -> risky lineages that appeared fleet-wide for the first time today.
    persistence_new: device name -> fleet-rare persistence items it created that day.
    access_new: device name -> RDP logons that day by an account that had never logged on to
    it in the previous 14 days (any source, jump hosts included)."""
    novelty_baseline, common_bins, spread = novelty_baseline or {}, common_bins or set(), spread or {}
    persistence_new, access_new, upwind_new = persistence_new or {}, access_new or {}, upwind_new or {}
    ents: dict[str, dict] = {}

    # Signal maps are keyed by device name, or by device_key(name, id) where the source knows
    # the DeviceId. A factory-default hostname is not unique: on 2026-10-05 six different Macs
    # were all "administrators-macbook-pro", and keyed on the name alone they scored as one
    # device with 128 rare destinations. Such names are split per DeviceId.
    ids_by_name: dict[str, set[str]] = {}
    for doc in today_docs:
        for dv in doc["devices"]:
            if dv.get("id"):
                ids_by_name.setdefault(dv["name"], set()).add(dv["id"])
    # Today's sources only: the baseline also holds ids a reimaged device no longer has.
    for m in (net_counts, spread, persistence_new, access_new, upwind_new):
        for k in m:
            name, did = split_device_key(k)
            if did:
                ids_by_name.setdefault(name, set()).add(did)
    shared = {n for n, ids in ids_by_name.items() if len(ids) > 1}

    def label(name: str, did: str = "") -> str:
        return f"{name}~{did[:6]}" if name in shared and did else name

    def relabel(m: dict) -> dict:
        out: dict = {}
        for k, v in m.items():
            lk = label(*split_device_key(k))
            if lk not in out:
                out[lk] = v
            elif isinstance(v, list):
                out[lk] = list(out[lk]) + list(v)
            elif isinstance(v, dict):
                out[lk] = {x: out[lk].get(x, 0) + v.get(x, 0) for x in set(out[lk]) | set(v)}
            else:
                out[lk] = out[lk] + v
        return out
    net_counts, novelty_baseline, spread = relabel(net_counts), relabel(novelty_baseline), relabel(spread)
    persistence_new, access_new = relabel(persistence_new), relabel(access_new)
    upwind_new = relabel(upwind_new)

    def ent(name: str, did: str = "") -> dict:
        key = label(name, did)
        return ents.setdefault(key, {"device": key, "device_id": did if name in shared else "",
                                     "novel_risky": [], "rare_persistent": [],
                                     "spread": [], "persistence_new": [], "access_new": [], "upwind_new": [],
                                     "net_high": 0, "net_med": 0})

    # Devices running each child binary, across today's rare lineages and their history. A
    # binary almost no device runs counts like an interpreter: an implant written in Go or
    # Rust is not an interpreter, and requiring one left compiled implants half-covered.
    bin_ids: dict[str, set[str]] = {}
    for doc in today_docs:
        child = lineage_parts(doc["L"])[2]
        bin_ids.setdefault(child, set()).update(prior.get(doc["L"], set()))
        bin_ids[child].update(dv["id"] for dv in doc["devices"])

    def rare_binary(L: str, cmd: str) -> bool:
        child = lineage_parts(L)[2]
        return (bool(child) and child not in INTERPRETERS and not child.startswith("python")
                and child not in common_bins and len(bin_ids.get(child, ())) <= RARE_MAX_FLEET
                and nonstandard_path(cmd))

    for doc in today_docs:
        L = doc["L"]
        if L in common_in_window:
            continue
        today_ids = {dv["id"] for dv in doc["devices"]}
        fleet = len(prior.get(L, set()) | today_ids)
        for dv in doc["devices"]:
            rb = rare_binary(L, dv["cmd"])
            sample = {"lineage": L, "cmd": dv["cmd"], "fleet_devices": fleet, "n": dv["n"],
                      "rare_binary": rb}
            novel = dv["id"] not in prior.get(L, set()) and fleet <= NOVEL_MAX_FLEET
            if novel and (doc["interp"] or doc["sens"] or rb):
                ent(dv["name"], dv.get("id", ""))["novel_risky"].append(sample)
            if fleet <= RARE_MAX_FLEET and doc["det"] and (doc["interp"] or rb):
                ent(dv["name"], dv.get("id", ""))["rare_persistent"].append(sample)
    def ent_l(key: str) -> dict:          # a relabelled key: "name" or "name~<id prefix>"
        name, _, short = key.partition("~")
        did = next((i for i in ids_by_name.get(name, ()) if i.startswith(short)), "") if short else ""
        return ent(name, did)
    for name, Ls in spread.items():
        ent_l(name)["spread"] = list(Ls)
    for name, items in persistence_new.items():
        ent_l(name)["persistence_new"] = list(items)
    for name, items in access_new.items():
        ent_l(name)["access_new"] = list(items)
    for name, items in upwind_new.items():
        ent_l(name)["upwind_new"] = list(items)
    for name, c in net_counts.items():
        e = ent_l(name)
        e["net_high"], e["net_med"] = int(c.get("high", 0)), int(c.get("medium", 0))

    out = []
    for e in ents.values():
        nr, rp = len(e["novel_risky"]), len(e["rare_persistent"])
        nm = min(e["net_med"], 5)
        # Novelty is judged against the device's OWN normal: a dev box that runs dozens of
        # rare risky lineages every day (Cursor, Claude Code, kubectl) hitting 10 new ones is
        # routine; a quiet box hitting 10 is not. Persistence and network are not dampened.
        base = float(novelty_baseline.get(e["device"], 0.0))
        novelty_points = min(nr, 10) / (1 + base / NOVELTY_DAMPING)
        e["novelty_baseline"], e["novelty_points"] = round(base, 1), round(novelty_points, 1)
        sp = SPREAD_POINTS if e["spread"] else 0
        pn = PERSISTENCE_POINTS * min(len(e["persistence_new"]), 2)
        pn_own = any(not str(i).endswith(INSTALLER_TAG) for i in e["persistence_new"])
        ac = ACCESS_POINTS * min(len(e["access_new"]), 2)
        uw = UPWIND_POINTS * min(len(e.get("upwind_new") or []), 2)
        stages = sum(1 for v in (novelty_points >= 1, rp, e["net_high"], nm, sp, pn_own, ac, uw) if v)
        # Caps so one chatty process cannot dominate; the multiplier rewards DIFFERENT kinds.
        e["score"] = round((novelty_points + 3 * min(rp, 3) + 4 * min(e["net_high"], 3) + nm + sp + pn + ac + uw)
                           * (1 + stages), 1)
        e["stages"] = stages
        out.append(e)
    out.sort(key=lambda e: -e["score"])
    return out


HIGH_SCORE = 60
HIGH_STAGES_MIN_SCORE = 40


def severity_for(e: dict) -> str:
    # Several DIFFERENT unusual behaviours on one entity is the attack shape — but only when
    # they carry weight. Three barely-there signals (a dampened novelty point, one persistence
    # sample, one medium destination) put three ordinary laptops at "high" on 2026-09-28 with
    # scores of 21-29; the incident scored 60.1 across three strong ones.
    if e["score"] >= HIGH_SCORE or (e["stages"] >= 3 and e["score"] >= HIGH_STAGES_MIN_SCORE):
        return "high"
    if e["score"] >= 25:
        return "medium"
    return "low"


def score_doc(e: dict, day: date, rank: int) -> dict:
    """What is kept about one ranked entity — stored for every rank, and the `raw` of the
    finding when its severity is in QUEUE_SEVERITIES."""
    return {"rank": rank, "score": e["score"], "stages": e["stages"], "severity": severity_for(e),
            "novelty_baseline": e["novelty_baseline"], "novelty_points": e["novelty_points"],
            "novel_risky": e["novel_risky"][:10], "rare_persistent": e["rare_persistent"][:10],
            "spread": e["spread"][:10], "persistence_new": e["persistence_new"][:10],
            "access_new": e.get("access_new", [])[:10],
            "upwind_new": e.get("upwind_new", [])[:10],
            "net_high": e["net_high"], "net_med": e["net_med"], "day": day.isoformat()}


def summarize(e: dict) -> str:
    parts = []
    if e["novel_risky"]:
        parts.append(f"{len(e['novel_risky'])} new fleet-rare risky lineage(s)")
    if e["rare_persistent"]:
        parts.append(f"{len(e['rare_persistent'])} fleet-rare interpreter/binary lineage(s) from persistence")
    if e["net_high"] or e["net_med"]:
        parts.append(f"{e['net_high']} high / {e['net_med']} medium rare destination(s)")
    if e.get("persistence_new"):
        parts.append(f"{len(e['persistence_new'])} fleet-rare persistence item(s) created")
    if e.get("spread"):
        parts.append(f"{len(e['spread'])} risky lineage(s) that appeared fleet-wide for the first time today")
    if e.get("upwind_new"):
        parts.append(f"{len(e['upwind_new'])} new Upwind runtime detection(s)")
    return f"'{e['device']}' behaviour score {e['score']} across {e['stages']} signal kind(s): " + "; ".join(parts)


# ── Mongo + MDE plumbing ─────────────────────────────────────────────────────────────

def _db():
    from shadow_hunter.models import Finding
    return Finding.get_pymongo_collection().database


async def _noop_progress(stage: str, **counts) -> None:
    return None


async def ensure_storage(progress=_noop_progress) -> dict:
    """TTL indexes, plus a one-time pass over documents written before redaction and expiry
    existed: redact their command-line samples and give them an expiry. Idempotent — only
    touches documents not yet marked `redacted`. Re-queries 500 at a time rather than holding
    one cursor open for minutes over the documents it is rewriting."""
    from pymongo import UpdateOne
    db = _db()
    rare, common, cdays = db[RARE_COLL], db[COMMON_COLL], db[COMMON_DAYS_COLL]
    await progress("indexes")
    await rare.create_index([("day", 1), ("L", 1)], unique=True)
    await rare.create_index("L")
    await rare.create_index("redacted")
    await rare.create_index("expires_at", expireAfterSeconds=0)
    await common.create_index("L", unique=True)
    await common.create_index("last_common_at", expireAfterSeconds=RETENTION_DAYS * 86400)
    await cdays.create_index([("day", 1), ("L", 1)], unique=True)
    await cdays.create_index("expires_at", expireAfterSeconds=0)
    scores = db[SCORES_COLL]
    await scores.create_index([("day", 1), ("device", 1)], unique=True)
    await scores.create_index([("day", 1), ("score", -1)])
    await scores.create_index("expires_at", expireAfterSeconds=0)
    migrated = 0
    while True:
        chunk = await rare.find({"redacted": {"$ne": True}}, {"day": 1, "devices": 1}).limit(500).to_list(500)
        if not chunk:
            break
        ops = [UpdateOne({"_id": d["_id"]}, {"$set": {
            "devices": [{**dv, "cmd": redact_cmd(dv.get("cmd"))} for dv in d.get("devices", [])],
            "redacted": True, "expires_at": _expiry(date.fromisoformat(d["day"]))}}) for d in chunk]
        await rare.bulk_write(ops, ordered=False)
        migrated += len(chunk)
        await progress("migrating", migrated=migrated)
    await common.update_many({"last_common_at": {"$exists": False}},
                             [{"$set": {"last_common_at": {"$dateFromString": {"dateString": "$last_common_day"}}}}])
    if migrated:
        logger.info("[behavior] redacted and dated %d pre-existing lineage documents", migrated)
    return {"migrated": migrated}


async def _bulk(coll, ops, progress, stage: str, size: int = 1000, total: int | None = None) -> None:
    """Write ops in chunks. `ops` may be a generator: only one chunk of operations is ever built
    (a full day's list of ReplaceOne objects is tens of MB in a 256 MiB pod)."""
    chunk, done = [], 0
    for op in ops:
        chunk.append(op)
        if len(chunk) >= size:
            await coll.bulk_write(chunk, ordered=False)
            done += len(chunk)
            chunk = []
            await progress(stage, written=done, total=total)
    if chunk:
        await coll.bulk_write(chunk, ordered=False)
        done += len(chunk)
        await progress(stage, written=done, total=total)


async def build_day(day: date, client=None, progress=_noop_progress) -> dict:
    """Profile ONE day into Mongo. Two single-day fleet scans; idempotent per day.

    Each scan is written out and freed before the next starts. Holding the rare rows (19k on a
    busy Monday, with command lines) while the common-lineage scan arrived got the 256 MiB pod
    OOM-killed at "querying_common" every time for 2026-10-05 — three nightly attempts and a
    manual one on 2026-10-08."""
    import gc
    from pymongo import ReplaceOne, UpdateOne
    from shadow_hunter.clients import DefenderClient
    client = client or DefenderClient()
    mig = await ensure_storage(progress)
    db = _db()
    # A full fleet-day scan outlasts the 60s the hourly detectors use.
    await progress("querying_rare")
    rare_rows = await client.hunt("behavior_rare", kql=build_rare_kql(day), timeout=BUILD_TIMEOUT_S)
    n_rare_rows = len(rare_rows)
    docs = rows_to_rare_docs(rare_rows, day)
    del rare_rows
    gc.collect()
    n_rare = len(docs)
    await _bulk(db[RARE_COLL], (ReplaceOne({"day": d["day"], "L": d["L"]}, d, upsert=True) for d in docs),
                progress, "writing_rare", total=n_rare)
    del docs
    gc.collect()

    await progress("querying_common", rare_rows=n_rare_rows)
    common_rows = await client.hunt("behavior_common", kql=build_common_kql(day), timeout=BUILD_TIMEOUT_S)
    if len(common_rows) >= 100_000:
        logger.warning("[behavior] %s: common-lineage result hit the 100k row limit", day)
    n_common = len(common_rows)
    day_at = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
    await _bulk(db[COMMON_COLL], (UpdateOne(
        {"L": r["L"]}, {"$max": {"last_common_day": day.isoformat(), "last_common_at": day_at},
                        "$min": {"first_common_day": day.isoformat()}}, upsert=True) for r in common_rows),
        progress, "writing_common", total=n_common)
    await _bulk(db[COMMON_DAYS_COLL], (ReplaceOne(
        {"day": day.isoformat(), "L": r["L"]},
        {"day": day.isoformat(), "L": r["L"], "devcount": int(r.get("DevCount") or 0),
         "devices": list(r.get("Devices") or [])[:25], "expires_at": _expiry(day)}, upsert=True)
        for r in common_rows), progress, "writing_common_days", total=n_common)
    del common_rows
    gc.collect()
    logger.info("[behavior] built %s: %d rare lineages, %d common", day, n_rare, n_common)
    return {"day": day.isoformat(), "rare_lineages": n_rare, "common_lineages": n_common,
            "migrated": mig["migrated"]}


async def network_counts(day: date, client=None) -> dict[str, dict]:
    """Rare-destination counts per device for THIS day, straight from MDE (one ~5s query).
    Not from stored findings: those are deduplicated forever, so a beacon recurring daily
    counted only on its first day, and a replayed day has no findings at all."""
    from shadow_hunter.clients import DefenderClient
    from shadow_hunter.detectors.rare_domains import RareDomainsDetector, build_kql
    client = client or DefenderClient()
    end = (day + timedelta(days=1)).isoformat()
    rows = await client.hunt("behavior_net", kql=build_kql(end=f"datetime({end})"),
                             timeout=BUILD_TIMEOUT_S)
    net: dict[str, dict] = {}
    from shadow_hunter.detectors.rare_domains import _as_list
    for f in RareDomainsDetector().to_findings(rows):
        # a row is one destination; its DeviceIds and Devices sets are not aligned, so an id is
        # only trusted when one device reached it
        ids = _as_list((f.get("raw") or {}).get("DeviceIds"))
        did = ids[0] if len(ids) == 1 and len(_as_list((f.get("raw") or {}).get("Devices"))) == 1 else ""
        c = net.setdefault(device_key(f["device_name"], did), {"high": 0, "medium": 0})
        if f["severity"] in c:
            c[f["severity"]] += 1
    return net


PACKAGE_MANAGERS = ("dpkg", "rpm", "apt", "apt-get", "yum", "dnf", "zypper", "installer", "msiexec",
                    "package_script_service", "softwareupdated", "unattended-upgr", "snapd", "brew")


def _from_installer(L: str) -> bool:
    gp, parent, _ = lineage_parts(L)
    return any(x in PACKAGE_MANAGERS or x.endswith(".tmp") or x.startswith("setup") for x in (gp, parent))


async def spreading_lineages(day: date, d0: str) -> tuple[dict[str, list[str]], list[dict]]:
    """Risky lineages that were common on their FIRST day and absent from the prior window,
    as (device -> lineages, cases). Fleet rarity hides these by construction: a malicious
    package installed across 20 developer machines is "common" from day one."""
    db = _db()
    firsts = {c["L"] async for c in db[COMMON_COLL].find({"first_common_day": day.isoformat()}, {"L": 1})}
    # a package manager's maintainer scripts and installer runs are rollouts by definition
    # (dpkg > dash > python on 9 servers, a PeaZip installer on 18 devices, 2026-10-01)
    risky = [L for L in firsts if lineage_parts(L)[2] in SPREAD_CHILDREN and not _from_installer(L)]
    if not risky:
        return {}, []
    seen_before = set(await db[RARE_COLL].distinct(
        "L", {"L": {"$in": risky}, "day": {"$gte": d0, "$lt": day.isoformat()}}))
    by_device: dict[str, list[str]] = {}
    cases = []
    async for c in db[COMMON_DAYS_COLL].find({"day": day.isoformat(), "L": {"$in": risky}}):
        if c["L"] in seen_before:
            continue
        cases.append({"L": c["L"], "devcount": c.get("devcount", 0), "devices": c.get("devices", [])})
        for name in c.get("devices", []):
            by_device.setdefault(name, []).append(c["L"])
    return by_device, cases


# Persistence written by a software install. On 2026-09-28 a Logitech Options+ update (its
# updater, and a PKInstallSandbox preinstall script) created two fleet-rare launch agents; with
# the installer's own shells as novelty and its downloads as rare destinations, one ordinary
# install became "three kinds of unusual" and scored high (58.7). The install is already
# visible as novelty, so its persistence still adds points but not a separate signal kind.
# Names alone are not trusted — malware calls itself GoogleUpdater or com.apple.updater — so a
# writer only counts as an installer when every writer runs from an install location; a
# writer in a user-writable path (~/Library, /tmp, AppData) never does. A malicious .pkg still
# runs through the macOS installer framework; its other signals are untouched.
INSTALLER_WRITERS = ("installer", "install", "system_installd", "package_script_service", "installd",
                     "softwareupdated", "msiexec.exe", "trustedinstaller.exe")
INSTALLER_SHELLS = ("bash", "sh", "zsh")
INSTALLER_CMD_MARKERS = ("pkinstallsandbox", "\\package cache\\", "\\windows\\installer\\")
INSTALL_DIRS = ("/applications/", "/library/application support/", "/library/privilegedhelpertools/",
                "/system/", "/usr/sbin/", "/usr/libexec/", "/usr/bin/", "/bin/",
                "c:\\program files\\", "c:\\program files (x86)\\", "c:\\windows\\system32\\",
                "c:\\windows\\syswow64\\", "c:\\windows\\servicing\\")
INSTALLER_TAG = " [installer]"


def installer_written(row: dict) -> bool:
    writers = [str(w).lower() for w in (row.get("Writers") or [])]
    paths = [str(p).lower() for p in (row.get("WriterPaths") or [])]
    cmds = " ".join(str(c).lower() for c in (row.get("WriterCmds") or []))
    if not writers or not paths or not all(p.startswith(INSTALL_DIRS) for p in paths):
        return False
    return all(w in INSTALLER_WRITERS or "updater" in w or w.endswith("update.exe")
               or (w in INSTALLER_SHELLS and any(m in cmds for m in INSTALLER_CMD_MARKERS)) for w in writers)


async def persistence_counts(day: date, client=None) -> dict[str, list[str]]:
    """Fleet-rare persistence created per device on THIS day, from MDE (one ~2s query). Items
    a software install wrote are tagged INSTALLER_TAG: points, but no signal kind of their own."""
    from shadow_hunter.clients import DefenderClient
    from shadow_hunter.detectors.rare_persistence import build_kql
    client = client or DefenderClient()
    end = (day + timedelta(days=1)).isoformat()
    rows = await client.hunt("behavior_persist", kql=build_kql(end=f"datetime({end})"),
                             timeout=BUILD_TIMEOUT_S)
    out: dict[str, list[str]] = {}
    for r in rows:
        item = f"{r.get('Mechanism')}:{r.get('Item')}" + (INSTALLER_TAG if installer_written(r) else "")
        if r.get("Mass"):  # one row for many devices
            for d in r.get("Devices") or []:
                out.setdefault(d, []).append(item)
            continue
        out.setdefault(device_key(r.get("DeviceName", ""), r.get("DeviceId") or ""), []).append(item)
    return out


async def access_counts(day: date, client=None) -> dict[str, list[str]]:
    """RDP logons per target device on THIS day by an account new to it, from MDE (one query)."""
    from shadow_hunter.clients import DefenderClient
    from shadow_hunter.detectors.remote_logons import build_kql
    client = client or DefenderClient()
    end = (day + timedelta(days=1)).isoformat()
    rows = await client.hunt("behavior_access", kql=build_kql(end=f"datetime({end})", new_targets=True),
                             timeout=BUILD_TIMEOUT_S)
    out: dict[str, list[str]] = {}
    for r in rows:
        srcs = ", ".join(s for s in (r.get("SourceIPs") or []) if s) or "unknown"
        out.setdefault(device_key(r.get("DeviceName", ""), r.get("DeviceId") or ""), []).append(
            f"{r.get('AccountName', '?')} from {srcs}")
    return out


async def upwind_counts(day: date, device_names: set[str]) -> dict[str, list[str]]:
    """Upwind runtime detections first seen on THIS day, per MDE device name. Read from the
    Upwind mirror; matched by hostname (an MDE 'x.corp.example.com' meets Upwind's 'x'). Upwind
    resources with no MDE device (Kubernetes workloads, IAM roles) can't join a device score;
    the upwind_threats detector reports those. Any failure scores the day without Upwind."""
    try:
        from edr_triage.upwind_mirror import host_keys, new_runtime_detections
        start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        rows = await new_runtime_detections(start, start + timedelta(days=1), min_severity="MEDIUM")
    except Exception as exc:
        logger.warning("[behavior] Upwind signal skipped for %s: %s", day, exc)
        return {}
    by_key: dict[str, str] = {}
    for n in device_names:
        for k in host_keys(n):
            by_key.setdefault(k, n)
    out: dict[str, list[str]] = {}
    for r in rows:
        if r.get("category") not in ("PROCESS", "FILES", "FILE_EVENTS", "NETWORK"):
            continue
        dev = next((by_key[k] for k in r.get("keys") or [] if k in by_key), None)
        if dev:
            out.setdefault(dev, []).append(f"[{r.get('severity')}] {r.get('title', '')[:120]}")
    return out


async def score_day(day: date, progress=_noop_progress) -> dict:
    """Score one already-built day from Mongo and write the top entities as findings."""
    from shadow_hunter.models import Finding
    db = _db()
    d0 = (day - timedelta(days=HISTORY_DAYS)).isoformat()
    # Without history everything looks novel. Refuse to score until the window is built,
    # rather than filling /shadow with a warm-up burst of false novelty.
    built_days = await db[RARE_COLL].distinct("day", {"day": {"$gte": d0, "$lt": day.isoformat()}})
    if len(built_days) < MIN_HISTORY_DAYS:
        logger.info("[behavior] %s: warming up (%d/%d history days built) — not scoring",
                    day, len(built_days), HISTORY_DAYS)
        return {"day": day.isoformat(), "warming_up": True,
                "history_days_built": len(built_days), "needed": MIN_HISTORY_DAYS}
    await progress("scoring_load")
    today_docs = await db[RARE_COLL].find({"day": day.isoformat()}).to_list(length=None)
    cands = list({d["L"] for d in today_docs})
    # Only lineage -> prior device ids, computed in Mongo. Loading the full 7-day history
    # (~55k docs with command lines) into the app process stalled the first real run for
    # over an hour, and this process also runs RAPTOR's triage.
    prior: dict[str, set[str]] = {}
    async for g in db[RARE_COLL].aggregate([
        {"$match": {"day": {"$gte": d0, "$lt": day.isoformat()}, "L": {"$in": cands}}},
        {"$project": {"_id": 0, "L": 1, "ids": "$devices.id"}},
        {"$unwind": "$ids"},
        {"$group": {"_id": "$L", "ids": {"$addToSet": "$ids"}}},
    ], allowDiskUse=True):
        prior[g["_id"]] = set(g["ids"])
    # Common within the window AND already common by this day — without the second bound a
    # lineage that only became common later would be dropped when replaying an older day.
    common_in_window = {c["L"] async for c in db[COMMON_COLL].find(
        {"L": {"$in": cands}, "last_common_day": {"$gte": d0},
         "first_common_day": {"$lte": day.isoformat()}}, {"L": 1})}
    # Each device's own normal volume of rare risky lineages per day over the window.
    novelty_baseline: dict[str, float] = {}
    async for g in db[RARE_COLL].aggregate([
        {"$match": {"day": {"$gte": d0, "$lt": day.isoformat()},
                    "$or": [{"interp": True}, {"sens": True}]}},
        {"$unwind": "$devices"},
        {"$group": {"_id": {"name": "$devices.name", "id": "$devices.id"}, "n": {"$sum": 1}}},
    ], allowDiskUse=True):
        k = device_key(g["_id"].get("name") or "", g["_id"].get("id") or "")
        novelty_baseline[k] = novelty_baseline.get(k, 0.0) + g["n"] / HISTORY_DAYS
    # Binary names that are the child of any lineage common in the window: a child binary
    # that is common somewhere is not a rare binary, whatever lineage it appears in here.
    common_bins = {lineage_parts(c["L"])[2] async for c in db[COMMON_COLL].find(
        {"last_common_day": {"$gte": d0}, "first_common_day": {"$lte": day.isoformat()}}, {"L": 1})}
    await progress("scoring_spread")
    spread, spread_cases = await spreading_lineages(day, d0)
    await progress("scoring_network")
    net = await network_counts(day)
    await progress("scoring_persistence")
    persist = await persistence_counts(day)
    await progress("scoring_access")
    access = await access_counts(day)
    await progress("scoring_upwind")
    names = {dv["name"] for d in today_docs for dv in d["devices"]}
    for m in (net, persist, access):
        names.update(split_device_key(k)[0] for k in m)
    upwind = await upwind_counts(day, names)
    await progress("scoring_rank")
    ranked = [e for e in score_entities(today_docs, prior, common_in_window, net, novelty_baseline,
                                        common_bins, spread, persist, access, upwind)
              if e["score"] >= MIN_SCORE][:TOP_ENTITIES_PER_DAY]
    written = 0
    docs = [score_doc(e, day, rank) for rank, e in enumerate(ranked, 1)]
    for e, d in zip(ranked, docs):  # at most TOP_ENTITIES_PER_DAY
        await db[SCORES_COLL].update_one(
            {"day": day.isoformat(), "device": e["device"]},
            {"$set": {**d, "device": e["device"], "summary": summarize(e), "expires_at": _expiry(day)}},
            upsert=True)
    # A re-score replaces the day: rows for entities that no longer rank (a fixed rule, or a
    # shared hostname now split per device) must not linger beside the new ones.
    ranked_devices = [e["device"] for e in ranked]
    await db[SCORES_COLL].delete_many({"day": day.isoformat(), "device": {"$nin": ranked_devices}})
    current = {f"{dv}@{day.isoformat()}" for dv in ranked_devices}
    await Finding.get_pymongo_collection().update_many(
        {"detector": "entity_behavior", "indicator": {"$regex": f"@{day.isoformat()}$", "$nin": list(current)},
         "reviewed_at": None, "legacy": {"$ne": True}},
        {"$set": {"legacy": True}})
    for e, d in zip(ranked, docs):
        indicator = f"{e['device']}@{day.isoformat()}"
        raw = {k: v for k, v in d.items() if k != "severity"}
        summary = f"#{d['rank']} " + summarize(e)
        existing = await Finding.find_one(Finding.detector == "entity_behavior", Finding.indicator == indicator,
                                          Finding.legacy != True)  # noqa: E712
        if existing:
            # A re-score (new signal, fixed rule) changes an OPEN case in place — the queue must
            # not keep yesterday's severity. Reviewed cases keep what the analyst saw.
            if existing.reviewed_at is None:
                if d["severity"] in QUEUE_SEVERITIES:
                    existing.severity, existing.summary, existing.raw = d["severity"], summary, raw
                else:
                    existing.legacy = True
                await existing.save()
            continue
        if d["severity"] not in QUEUE_SEVERITIES:
            continue
        await Finding(
            detector="entity_behavior", severity=d["severity"], device_name=e["device"],
            device_id=e.get("device_id", ""),
            indicator=indicator, summary=summary, raw=raw,
        ).insert()
        written += 1
    for case in spread_cases:
        indicator = f"{case['L']}@{day.isoformat()}"
        if await Finding.find_one(Finding.detector == "fleet_spread", Finding.indicator == indicator,
                                 Finding.legacy != True):  # noqa: E712
            continue
        await Finding(
            detector="fleet_spread", severity="medium", device_name=", ".join(case["devices"][:3]),
            indicator=indicator,
            summary=(f"Risky lineage '{case['L']}' appeared on {case['devcount']} devices on its first "
                     f"day, never seen in the prior {HISTORY_DAYS} days — the supply-chain / "
                     f"mass-deployment shape. Confirm it was a sanctioned rollout."),
            raw={**case, "day": day.isoformat()},
        ).insert()
    logger.info("[behavior] scored %s: %d entities written", day, written)
    return {"day": day.isoformat(), "entities_scored": len(ranked), "written": written,
            "by_severity": {s: sum(d["severity"] == s for d in docs) for s in ("high", "medium", "low")},
            "spreading_lineages": len(spread_cases),
            "top": [(e["device"], e["score"]) for e in ranked[:5]]}


async def run_logged(day: date, build: bool, score: bool) -> dict:
    """Build and/or score, recording the outcome (including failures) in Mongo."""
    runs = _db()[RUNS_COLL]
    key = day.isoformat()
    now = lambda: datetime.now(timezone.utc).isoformat()
    prev = await runs.find_one({"_id": key}, {"attempts": 1}) or {}
    await runs.replace_one({"_id": key}, {"_id": key, "state": "running", "started": now(),
                                          "build": build, "score": score,
                                          "attempts": prev.get("attempts", 0) + 1}, upsert=True)
    out: dict = {}

    async def progress(stage: str, **counts) -> None:
        # Where the run is, so a run that stalls or dies shows WHERE (a dead process records
        # nothing else). Best-effort: progress reporting must never fail the run.
        try:
            await runs.update_one({"_id": key}, {"$set": {"stage": stage, "stage_at": now(), **counts}})
        except Exception:
            pass

    try:
        if build:
            out.update(await build_day(day, progress=progress))
        if score:
            out.update(await score_day(day, progress=progress))
        rec = {"state": "done", **out}
    except Exception as exc:
        logger.exception("[behavior] run for %s failed", key)
        rec = {"state": "failed", "error": f"{type(exc).__name__}: {str(exc)[:300]}", **out}
    rec["finished"] = now()
    await runs.update_one({"_id": key}, {"$set": rec})
    return {"day": key, **rec}


STALE_AFTER = timedelta(minutes=30)


def _is_stale(r: dict) -> bool:
    """A 'running' record with no progress for STALE_AFTER means the process died mid-run (a
    crash or restart records nothing), so it must not block a retry forever. Measured from the
    last progress heartbeat, so a long but live run is not mistaken for a dead one."""
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(r.get("stage_at") or r["started"]) > STALE_AFTER
    except (KeyError, TypeError, ValueError):
        return True


async def is_running(day: date) -> bool:
    r = await _db()[RUNS_COLL].find_one({"_id": day.isoformat()})
    return bool(r) and r.get("state") == "running" and not _is_stale(r)


async def status() -> dict:
    db = _db()
    per_day = await db[RARE_COLL].aggregate([
        {"$group": {"_id": "$day", "rare_lineages": {"$sum": 1}}}, {"$sort": {"_id": 1}},
    ]).to_list(length=None)
    runs = await db[RUNS_COLL].find({}).sort("_id", 1).to_list(length=None)
    return {"built_days": {d["_id"]: d["rare_lineages"] for d in per_day},
            "common_lineages": await db[COMMON_COLL].count_documents({}),
            "last_runs": {r.pop("_id"): ({**r, "state": "stale"} if r.get("state") == "running"
                                         and _is_stale(r) else r) for r in runs}}


async def scores(day: str | None = None, limit: int = 100) -> dict:
    """Every ranked device for one scored day (default: the latest), highest first — including
    the low ones that are not /shadow findings."""
    coll = _db()[SCORES_COLL]
    if not day:
        latest = await coll.find({}, {"day": 1}).sort("day", -1).limit(1).to_list(1)
        day = latest[0]["day"] if latest else None
    rows = await coll.find({"day": day}, {"_id": 0, "expires_at": 0}).sort("score", -1).limit(limit).to_list(limit) if day else []
    return {"day": day, "days": sorted(await coll.distinct("day"), reverse=True), "scores": rows}


async def run_daily() -> dict:
    """Build and score yesterday (UTC). Scheduled once a day, off-peak."""
    from shadow_hunter.config import get_shadow_config
    if get_shadow_config().mode != "live":
        return {"skipped": "not live mode"}
    day = datetime.now(timezone.utc).date() - timedelta(days=1)
    return await run_logged(day, build=True, score=True)


MAX_ATTEMPTS = 3
NIGHTLY_DUE = (21, 45)       # UTC: by now the 21:00 run has started, or missed its grace window


def needs_recovery(r: dict | None, *, is_yesterday: bool, now: datetime) -> dict | None:
    """What re-run a day needs, or None. Pods are replaced by the autoscaler and a killed run
    records nothing, so a failed, stalled or never-started night must finish without a human.
    A run that died while scoring kept its built history (build_day is idempotent anyway), so
    it resumes with scoring only."""
    if r is None:
        due = is_yesterday and (now.hour, now.minute) >= NIGHTLY_DUE
        return {"build": True, "score": True} if due else None
    if r.get("attempts", 1) >= MAX_ATTEMPTS:
        return None
    state = r.get("state")
    if state == "failed" or (state == "running" and _is_stale(r)):
        built = str(r.get("stage", "")).startswith("scoring") or not r.get("build", True)
        return {"build": not built, "score": r.get("score", True)}
    return None


async def recovery_plans(now: datetime | None = None) -> list[tuple[date, dict]]:
    """Yesterday's and the day before's runs that failed, stalled or never ran."""
    from shadow_hunter.config import get_shadow_config
    if get_shadow_config().mode != "live":
        return []
    now = now or datetime.now(timezone.utc)
    plans = []
    for back in (1, 2):
        day = now.date() - timedelta(days=back)
        r = await _db()[RUNS_COLL].find_one({"_id": day.isoformat()})
        plan = needs_recovery(r, is_yesterday=back == 1, now=now)
        if plan:
            logger.info("[behavior] recovering %s (%s): %s", day, (r or {}).get("state", "missing"), plan)
            plans.append((day, plan))
    return plans


async def recover_missed() -> list[dict]:
    # Re-read under the lease: another replica may have finished the day meanwhile.
    return [await run_logged(day, **plan) for day, plan in await recovery_plans()]
