"""Person cases: one rolling 14-day story per person across EDR, Netskope, Entra and CloudTrail.

Why: the device behaviour score is keyed by device, so it can't see the cloud and identity
planes, which are keyed by person. INC-2026-0001 was spread across both and over two weeks:
the install and C2 on the laptop on Aug 26 (EDR), the person's AWS session replayed from a
foreign network to list secrets on Sep 7 (CloudTrail). Each was a weak signal in its own tool.

How:
  * Resolve workstations to people nightly, in measured priority order (2026-10-07: 797 of
    1,006 workstations): MDE's logged-on user matched to the Entra name (100% agreement with
    Entra device sign-ins where both answer), then Entra device sign-ins, then Netskope's
    hostname. A shared or unresolved device is left out, never guessed.
  * Per person per day, signals from each plane, all computed in Sentinel (which holds the MDE
    tables too, kept 180 days (Defender itself keeps ~30), so cases replay on the real incident):
      endpoint  fleet-new destinations reached by interpreters (rare_domains' own query), script-
                written persistence (rare_persistence's), and the nightly device behaviour score
      network   Netskope: tunnel / file-drop services, upload volume far above the person's own
                daily maximum, DLP / UBA / malsite alerts; fleet-new destinations count only lightly
                (254 people a day touch at least one — median 1, p99 13)
      identity  Entra: a successful sign-in from a country new for the person, risky sign-ins
      cloud     CloudTrail: the person's session used from a network new to them, sensitive APIs
                they never called before, bursts of access denials, a session key split across
                networks (cloud_session_split's own query)
  * A case is the last 14 days of one person's signals. NOISE RULE: it becomes a finding only
    when at least TWO planes are strong — every single-plane anomaly already has a detector.
    Signals in attack order (endpoint before cloud/identity) raise it.
"""
from __future__ import annotations

import logging
import re
from datetime import date, datetime, timedelta, timezone

logger = logging.getLogger(__name__)

SIGNALS_COLL = "person_signal_days"
CASE_DAYS = 14
RETENTION_DAYS = 45
PLANES = ("endpoint", "network", "identity", "cloud")
SENSITIVE_APIS = ("ListSecrets", "GetSecretValue", "BatchGetSecretValue", "CreateAccessKey", "CreateUser",
                  "CreateLoginProfile", "UpdateLoginProfile", "PutRolePolicy", "PutUserPolicy", "AttachRolePolicy",
                  "AttachUserPolicy", "UpdateAssumeRolePolicy", "PutBucketPolicy", "DeleteTrail", "StopLogging",
                  "PutEventSelectors", "StartSession", "SendCommand", "GetPasswordData", "GetParametersByPath",
                  "AssumeRoleWithWebIdentity", "CreateRole", "DeleteFlowLogs", "DisableKey", "ScheduleKeyDeletion")


def _dt(d: date) -> str:
    return f"datetime({d.isoformat()})"


def _host(n: str) -> str:
    return (n or "").lower().split(".")[0]


# ── Sentinel queries (one per plane per day) ───────────────────────────────────────

def kql_person_map(d1: date) -> str:
    """Workstation hostname -> person, priority mde > entra > netskope, single answers only."""
    return f"""
        let t1 = {_dt(d1)};
        let ws = DeviceInfo | where TimeGenerated between (t1 - 7d .. t1)
            | where DeviceType == "Workstation" or OSPlatform in ("macOS", "Windows10", "Windows11")
            | extend h = tolower(tostring(split(DeviceName, ".")[0])) | distinct h;
        let upnByLocal = SigninLogs | where TimeGenerated between (t1 - 14d .. t1) | where ResultType == "0"
            | extend u = tolower(UserPrincipalName) | extend l = replace_string(tostring(split(u, "@")[0]), ".", "")
            | distinct l, u;
        let byMde = DeviceInfo | where TimeGenerated between (t1 - 7d .. t1) | where isnotempty(LoggedOnUsers)
            | extend h = tolower(tostring(split(DeviceName, ".")[0])) | where h in (ws)
            | mv-expand lu = parse_json(LoggedOnUsers) | extend l = replace_string(tolower(tostring(lu.UserName)), ".", "")
            | where isnotempty(l) and l !in ("administrator", "root", "_mbsetupuser", "admin")
            | join kind=inner upnByLocal on l
            | summarize U = make_set(u, 3) by h | where array_length(U) == 1 | project h, P = tostring(U[0]), Pri = 1;
        let byEntra = SigninLogs | where TimeGenerated between (t1 - 7d .. t1) | where ResultType == "0"
            | extend h = tolower(tostring(split(tostring(DeviceDetail.displayName), ".")[0])) | where h in (ws)
            | summarize U = make_set(tolower(UserPrincipalName), 3) by h | where array_length(U) == 1
            | project h, P = tostring(U[0]), Pri = 2;
        let byNs = Netskope_Events_CL | where TimeGenerated between (t1 - 1d .. t1) | where isnotempty(hostname_s)
            | extend h = tolower(tostring(split(hostname_s, ".")[0])) | where h in (ws)
            | summarize U = make_set(tolower(user_s), 3) by h | where array_length(U) == 1
            | project h, P = tostring(U[0]), Pri = 3;
        union byMde, byEntra, byNs
        | summarize arg_min(Pri, P) by h
        | project Host = h, Person = P, Via = case(Pri == 1, "mde", Pri == 2, "entra", "netskope")
        """


def kql_network(d0: date, d1: date) -> str:
    from shadow_hunter.detectors.exfil_patterns import SERVICE_SUFFIXES
    svc = ", ".join(f'"{s}"' for s in SERVICE_SUFFIXES)
    return f"""
        let t0 = {_dt(d0)}; let t1 = {_dt(d1)};
        let ev = Netskope_Events_CL | where TimeGenerated between (t0 - 6d .. t1) | where isnotempty(user_s)
            | extend u = tolower(user_s),
                     dom = tolower(coalesce(column_ifexists("domain_s", ""), column_ifexists("dsthost_s", ""),
                                            column_ifexists("site_s", ""))),
                     up = todouble(column_ifexists("client_bytes_d", real(0)))
            // registrable name only; a bare IP is not a "domain" (it made 609 people "rare" a day)
            | extend reg = iff(dom matches regex @"^[0-9.:]+$", "", extract(@"([a-z0-9-]+\\.[a-z]{{2,}})$", 1, dom));
        let prior = ev | where TimeGenerated < t0;
        let today = ev | where TimeGenerated >= t0;
        let priorRegs = prior | where isnotempty(reg) | distinct reg;
        let rareNew = today | where isnotempty(reg) and reg !in (priorRegs)
            | summarize Users = dcount(u) by reg | where Users <= 2 | project reg;
        let services = dynamic([{svc}]);
        let priorUp = prior | summarize Daily = sum(up) by u, d = startofday(TimeGenerated)
            | summarize PriorMaxMB = max(Daily) / 1048576.0, PriorDays = count() by u;
        // where the uploads went, for whoever reviews an upload anomaly
        let topUp = today | where up > 0
            | extend app = coalesce(column_ifexists("app_s", ""), reg)
            | summarize B = sum(up) by u, app | order by B desc
            | summarize TopUploads = make_list(strcat(app, " ", tostring(round(B / 1048576.0)), " MB"), 3) by u;
        let alerts = Netskope_Alerts_CL | where TimeGenerated between (t0 .. t1)
            | extend u = tolower(column_ifexists("user_s", "")), k = tolower(column_ifexists("alert_type_s", ""))
            | where k in ("dlp", "uba", "malsite", "malware", "compromisedcredential")
            | summarize Alerts = count(), AlertKinds = make_set(k, 5) by u;
        today
        | summarize RareNew = dcountif(reg, reg in (rareNew)), RareSample = make_set_if(reg, reg in (rareNew), 5),
                    ServiceHits = countif(dom has_any (services)), Services = make_set_if(reg, dom has_any (services), 5),
                    UploadMB = sum(up) / 1048576.0 by u
        | join kind=leftouter priorUp on u
        | join kind=leftouter topUp on u
        | join kind=fullouter alerts on u
        | extend Person = coalesce(u, u1)
        | project Person, RareNew, RareSample, ServiceHits, Services, UploadMB, PriorMaxMB, PriorDays, TopUploads,
                  Alerts, AlertKinds
        | where RareNew > 0 or ServiceHits > 0 or Alerts > 0
               or (UploadMB > 500 and PriorDays >= 3 and UploadMB > 3 * PriorMaxMB)
        """


def kql_identity(d0: date, d1: date) -> str:
    """Entra sign-ins from a country new for the person: successful ones, and attempts where the
    password was accepted and only MFA stopped them (50074/50076/50079/500121 — the attacker has
    the password: INC-2026-0001, 198.51.100.67, 2026-09-10). Risk levels are hidden in this tenant,
    so they are not used. Source IPs are kept for cross-plane matching with CloudTrail."""
    return f"""
        let t0 = {_dt(d0)}; let t1 = {_dt(d1)};
        let mfaStop = dynamic(["50074", "50076", "50079", "500121"]);
        let s = SigninLogs | where TimeGenerated between (t0 - 30d .. t1)
            | extend u = tolower(UserPrincipalName), c = tostring(LocationDetails.countryOrRegion)
            | where isnotempty(c)
            // Netskope's own egress (AS55256) exits through whichever POP is nearest the tunnel, so the
            // "country" is Netskope's, not the person's: 1,504 of 1,605 successful new-country sign-ins
            // over 30 days (2026-10-07), and an AI triage that rightly called such a case FP.
            | where tostring(AutonomousSystemNumber) != "55256";
        let prior = s | where TimeGenerated < t0 and ResultType == "0"
            | summarize PriorCountries = make_set(c, 20), PriorN = count() by u | where PriorN >= 5;
        s | where TimeGenerated >= t0
        | join kind=inner prior on u
        | where not(set_has_element(PriorCountries, c))
        | summarize NewCountryOK = countif(ResultType == "0"), PasswordOkMfaStopped = countif(ResultType in (mfaStop)),
                    NewCountryFailed = countif(ResultType != "0" and ResultType !in (mfaStop)),
                    NewCountries = make_set(c, 5), IPs = make_set(IPAddress, 5),
                    Apps = make_set(AppDisplayName, 3) by u
        | project Person = u, NewCountries, NewCountryOK, PasswordOkMfaStopped, NewCountryFailed, IPs, Apps
        """


def kql_cloud(d0: date, d1: date) -> str:
    from shadow_hunter.detectors.cloud import _human_calls
    apis = ", ".join(f'"{a}"' for a in SENSITIVE_APIS)
    return f"""
        let t0 = {_dt(d0)}; let t1 = {_dt(d1)};
        let calls = {_human_calls("t0", "t1")};
        let hist = {_human_calls("t0 - 14d", "t0")};
        // corporate egress: networks many people use are not "new" for anyone
        let shared = hist | summarize People = dcount(User) by Net | where People > 5 | project Net;
        let personNets = hist | distinct User, Net;
        let newNet = calls | where Net !in (shared) | join kind=leftanti personNets on User, Net
            | summarize NewNetCalls = count(), NewNets = make_set(Net, 4), NewNetIPs = dcount(SourceIpAddress),
                        NewNetSensitive = make_set_if(EventName, EventName in ({apis}), 8),
                        NewNetIPList = make_set(SourceIpAddress, 10),
                        NewNetAgents = make_set(substring(UserAgent, 0, 60), 3) by User;
        let ct = AWSCloudTrail | where TimeGenerated between (t0 - 30d .. t1)
            | where UserIdentityType == "AssumedRole" and UserIdentityArn contains "@"
            | extend User = tostring(split(UserIdentityArn, "/")[-1]);
        let priorApis = ct | where TimeGenerated < t0 and EventName in ({apis}) | distinct User, EventName;
        let firstApis = ct | where TimeGenerated >= t0 and EventName in ({apis})
            | join kind=leftanti priorApis on User, EventName
            | summarize FirstSensitive = make_set(EventName, 10) by User;
        let denied = ct | where ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation",
                                              "AccessDeniedException")
            | summarize N = count() by User, d = startofday(TimeGenerated)
            | summarize Denied = sumif(N, d >= t0), PriorMax = maxif(N, d < t0) by User
            | where Denied >= 20 and Denied > 3 * coalesce(PriorMax, 0);
        newNet
        | join kind=fullouter firstApis on User
        | extend User = coalesce(User, User1)
        | join kind=fullouter denied on User
        | extend User = coalesce(User, User2)
        | extend Person = tolower(User)
        | project Person, NewNetCalls, NewNets, NewNetIPs, NewNetIPList, NewNetSensitive, NewNetAgents, FirstSensitive, Denied
        | where NewNetCalls > 0 or array_length(FirstSensitive) > 0 or Denied > 0
        """


# ── per-day signals ─────────────────────────────────────────────────────────────

def _as_list(v) -> list:
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v.startswith("["):
        import json
        try:
            return json.loads(v)
        except ValueError:
            return []
    return [] if v in (None, "") else [v]


async def endpoint_by_device(d0: date, d1: date, client=None) -> dict[str, dict]:
    """Per workstation host: fleet-new destinations reached by interpreters, and script-written
    persistence — the existing detectors' own queries, run on Sentinel for the day."""
    from shadow_hunter.clients import SentinelLogsClient
    from shadow_hunter.detectors.rare_domains import RareDomainsDetector, build_kql as dom_kql
    from shadow_hunter.detectors.rare_persistence import RarePersistenceDetector, build_kql as per_kql
    client = client or SentinelLogsClient()
    out: dict[str, dict] = {}

    def dev(h: str) -> dict:
        return out.setdefault(_host(h), {"c2_high": [], "rare_dest": [], "persistence": []})
    try:
        rows = await client.query(dom_kql(end=_dt(d1)))
        for f in RareDomainsDetector().to_findings(rows):
            for h in _as_list((f.get("raw") or {}).get("Devices")) or [f["device_name"]]:
                key = "c2_high" if f["severity"] == "high" else "rare_dest"
                if len(dev(h)[key]) < 10:
                    dev(h)[key].append(f["indicator"])
    except Exception as exc:
        logger.warning("[person] endpoint destinations for %s failed: %s", d0, exc)
    try:
        rows = await client.query(per_kql(end=_dt(d1)))
        for f in RarePersistenceDetector().to_findings(rows):
            if f["severity"] == "high" and not (f.get("raw") or {}).get("Mass"):
                if len(dev(f["device_name"])["persistence"]) < 10:
                    dev(f["device_name"])["persistence"].append(str(f["indicator"]).split(":", 1)[-1])
    except Exception as exc:
        logger.warning("[person] endpoint persistence for %s failed: %s", d0, exc)
    return out


# Points per signal, and per plane the level that makes the plane "strong". Tuned on the
# incident (2026-08-26 .. 09-10) and an ordinary fortnight; see docs/sentinel-shadow.md.
W = {
    "c2_high": 6, "rare_dest": 2, "persistence": 4, "device_behavior_high": 8, "device_behavior_medium": 3,
    "net_rare": 0.5, "net_service": 4, "net_upload": 5, "net_alert": 3,
    "id_new_country_ok": 5, "id_password_ok_mfa_stopped": 8, "id_new_country_failed": 1,
    "cloud_new_net": 4, "cloud_new_net_sensitive": 6, "cloud_first_sensitive": 2, "cloud_denied_burst": 3,
    "cloud_session_split": 10,
}
CAPS = {"c2_high": 2, "rare_dest": 3, "persistence": 2, "net_rare": 4, "net_service": 2, "net_alert": 3,
        "id_new_country_failed": 3, "cloud_first_sensitive": 3}
STRONG = 5            # a plane counts toward the 2-plane rule at this many points


def plane_points(sig: dict) -> dict[str, float]:
    """Points per plane for one person-day of signals."""
    def w(name, n=1):
        return W[name] * min(n, CAPS.get(name, n))
    e, n, i, c = (sig.get(p) or {} for p in PLANES)
    pts = {
        "endpoint": (w("c2_high", len(e.get("c2_high", []))) + w("rare_dest", len(e.get("rare_dest", [])))
                     + w("persistence", len(e.get("persistence", [])))
                     + (W["device_behavior_high"] if e.get("behavior") == "high" else
                        W["device_behavior_medium"] if e.get("behavior") == "medium" else 0)),
        "network": (w("net_rare", n.get("rare_new", 0)) + w("net_service", n.get("service_hits", 0))
                    + (W["net_upload"] if n.get("upload_anomaly") else 0) + w("net_alert", n.get("alerts", 0))),
        "identity": ((W["id_new_country_ok"] if i.get("new_country_ok") else 0)
                     + (W["id_password_ok_mfa_stopped"] if i.get("password_ok_mfa_stopped") else 0)
                     + w("id_new_country_failed", i.get("new_country_failed", 0))),
        "cloud": ((W["cloud_new_net"] if c.get("new_net_calls") else 0)
                  + (W["cloud_new_net_sensitive"] if c.get("new_net_sensitive") else 0)
                  + w("cloud_first_sensitive", len(c.get("first_sensitive", [])))
                  + (W["cloud_denied_burst"] if c.get("denied") else 0)
                  + (W["cloud_session_split"] if c.get("session_split") else 0)),
    }
    return {k: round(v, 1) for k, v in pts.items()}


def shared_ips(days: list[dict]) -> list[str]:
    """IPs that appear in more than one plane for the person: one actor across tools."""
    seen: dict[str, set] = {}
    for d in days:
        for plane in ("identity", "cloud"):
            for ip in (d.get(plane) or {}).get("ips", []):
                seen.setdefault(ip, set()).add(plane)
    return sorted(ip for ip, planes in seen.items() if len(planes) > 1)


# Secret / IAM / logging APIs. StartSession and SendCommand are left out: SSM sessions from a home
# network are everyday engineering (2026-09-21..10-06 replay).
CRITICAL_APIS = {"ListSecrets", "GetSecretValue", "BatchGetSecretValue", "CreateAccessKey", "CreateUser",
                 "CreateLoginProfile", "UpdateLoginProfile", "PutRolePolicy", "PutUserPolicy", "AttachRolePolicy",
                 "AttachUserPolicy", "UpdateAssumeRolePolicy", "DeleteTrail", "StopLogging", "PutEventSelectors",
                 "GetPasswordData", "DeleteFlowLogs", "ScheduleKeyDeletion", "DisableKey"}
ROTATION_IPS = 15            # the incident's stolen key came from 27; mobile/VPN churn is single digits


def notable(sig: dict) -> dict[str, list[str]]:
    """Events in one person-day that can anchor a case, by strength. Replays (2026-08-12..09-12 and
    09-21..10-06) showed what is routine and must NOT anchor: access-denial bursts (dozens of
    engineers a week), SSM StartSession from a home network, a new-country sign-in (travel), a
    handful of rotating IPs (mobile/VPN), and device-plus-Netskope traffic (the same browsing seen
    by two sensors). Those are 'weak': they count only next to a device-side notable event."""
    e, n, i, c = (sig.get(p) or {} for p in PLANES)
    strong, weak, dev = [], [], []
    crit = sorted(set(c.get("new_net_sensitive") or []) & CRITICAL_APIS)
    rot = int(c.get("new_net_ips") or 0)
    if len(crit) >= 2 or (crit and rot >= 5):
        strong.append(f"cloud: {', '.join(crit[:4])} from a network new to them ({rot} IPs)")
    elif c.get("new_net_sensitive"):
        weak.append(f"cloud: {', '.join(c['new_net_sensitive'][:3])} from a new network")
    if c.get("session_split"):
        strong.append("cloud: session key used from two networks")
    if c.get("new_net_calls") and rot >= ROTATION_IPS:
        strong.append(f"cloud: new network with {rot} rotating IPs")
    # access-denial bursts: points only (plane_points). As an anchor they made most false cases:
    # engineers hit permission walls daily (a 27,633-denial day was a misconfigured job).
    if i.get("password_ok_mfa_stopped"):
        strong.append(f"identity: correct password from a new country, stopped by MFA ({i['password_ok_mfa_stopped']}x)")
    if i.get("new_country_ok"):
        weak.append(f"identity: signed in from a new country ({', '.join(i.get('new_countries', [])[:3])})")
    if e.get("c2_high"):
        dev.append("endpoint: interpreter from persistence reached a fleet-new host")
    if e.get("persistence"):
        dev.append("endpoint: script-written persistence")
    if e.get("behavior") == "high":
        dev.append("endpoint: device behaviour score high")
    if n.get("service_hits"):
        dev.append("network: tunnel / file-drop service")
    if n.get("upload_anomaly"):
        dev.append(f"network: {n.get('upload_mb')} MB uploaded (own max {n.get('prior_max_mb')} MB)"
                   + (f" to {', '.join(n['top_uploads'])}" if n.get("top_uploads") else ""))
    if set(n.get("alert_kinds") or []) & {"malsite", "malware", "compromisedcredential"}:
        dev.append("network: Netskope malware / malsite / compromised-credential alert")
    return {"strong": strong, "weak": weak, "device": dev}


DEVICE_ACTIVITY_MIN = 10
PAIR_WITHIN_DAYS = 2         # a weak account event pairs only with a device event this close in time


def _near(a: list, b: list, days: int) -> bool:
    from datetime import date as _d
    return any(abs((_d.fromisoformat(x) - _d.fromisoformat(y)).days) <= days for x, _ in a for y, _ in b)     # device-side points in the window that count as activity without a notable event


def score_case(days: list[dict]) -> dict:
    """A person's case from up to CASE_DAYS of daily signal docs (oldest first)."""
    total: dict[str, float] = {p: 0.0 for p in PLANES}
    first_any: dict[str, str] = {}
    acct_events, weak_events, dev_events, timeline = [], [], [], []
    for d in sorted(days, key=lambda x: x["day"]):
        pts = plane_points(d)
        for p, v in pts.items():
            total[p] += v
            if v > 0 and p not in first_any:
                first_any[p] = d["day"]
        nb = notable(d)
        acct_events += [(d["day"], x) for x in nb["strong"]]
        weak_events += [(d["day"], x) for x in nb["weak"]]
        dev_events += [(d["day"], x) for x in nb["device"]]
        if any(pts.values()) or nb["strong"] or nb["weak"] or nb["device"]:
            timeline.append({"day": d["day"], "points": {p: v for p, v in pts.items() if v},
                             "notable": nb["strong"] + nb["weak"] + nb["device"],
                             "detail": {p: d[p] for p in PLANES if d.get(p)}})
    device_pts = min(total["endpoint"], 30) + min(total["network"], 30)
    acct_planes = sorted({x.split(":")[0] for _, x in acct_events})
    links = shared_ips(days)
    anchors = acct_events or (weak_events if dev_events else [])
    # attack order: a device-side notable event before the first account-side anchor
    chain = bool(anchors) and bool(dev_events) and min(dd for dd, _ in dev_events) <= min(dd for dd, _ in anchors)
    score = (sum(min(v, 30) for v in total.values()) + 12 * len(acct_events[:4]) + 4 * len(weak_events[:3])
             + 6 * len(dev_events[:4]))
    score = round(score * (1.5 if chain else 1.0) + (15 if links else 0), 1)
    if acct_events and (dev_events or links or len(acct_planes) >= 2):
        sev = "high"            # stolen-credential use joined to the device, or to itself across tools
    elif acct_events and device_pts >= DEVICE_ACTIVITY_MIN:
        sev = "medium"          # a strong account event, the person's machine active but nothing notable on it
    elif weak_events and dev_events and _near(weak_events, dev_events, days=PAIR_WITHIN_DAYS):
        sev = "medium"          # e.g. malware alert on the laptop and a new-country sign-in within 2 days
    else:
        sev = "none"
    return {"score": score, "severity": sev, "strong_planes": [p for p in PLANES if total[p] >= STRONG],
            "points": total, "chain": chain, "shared_ips": links, "first_seen": first_any,
            "account_events": [f"{d}: {x}" for d, x in acct_events][:10],
            "weak_account_events": [f"{d}: {x}" for d, x in weak_events][:10],
            "device_events": [f"{d}: {x}" for d, x in dev_events][:10],
            "timeline": timeline[-CASE_DAYS:]}


async def daily_signals(day: date, client=None) -> dict[str, dict]:
    """Every plane's signals for one UTC day, keyed by person (lowercased email)."""
    from shadow_hunter.clients import SentinelLogsClient
    from shadow_hunter.detectors.cloud import build_split_kql
    client = client or SentinelLogsClient()
    d1 = day + timedelta(days=1)
    people: dict[str, dict] = {}

    def p(person: str) -> dict:
        return people.setdefault(person.lower(), {"day": day.isoformat(), "person": person.lower(), "devices": []})

    async def q(name, kql):
        try:
            return await client.query(kql)
        except Exception as exc:
            logger.warning("[person] %s for %s failed: %s", name, day, exc)
            return []

    hosts = {r["Host"]: (r["Person"], r["Via"]) for r in await q("person map", kql_person_map(d1))}
    for host, sig in (await endpoint_by_device(day, d1, client)).items():
        if host in hosts and any(sig.values()):
            doc = p(hosts[host][0])
            e = doc.setdefault("endpoint", {"c2_high": [], "rare_dest": [], "persistence": []})
            for k in ("c2_high", "rare_dest", "persistence"):
                e[k] = (e[k] + [f"{host}: {x}" for x in sig[k]])[:10]
            doc["devices"] = sorted(set(doc["devices"]) | {host})
    # the nightly device behaviour score, where it exists for the day (MDE + Upwind signals)
    try:
        from shadow_hunter.behavior import SCORES_COLL, _db
        async for s in _db()[SCORES_COLL].find({"day": day.isoformat(), "severity": {"$in": ["high", "medium"]}},
                                               {"device": 1, "severity": 1, "score": 1}):
            host = _host(str(s["device"]).split("~")[0])
            if host in hosts:
                doc = p(hosts[host][0])
                e = doc.setdefault("endpoint", {"c2_high": [], "rare_dest": [], "persistence": []})
                if s["severity"] == "high" or e.get("behavior") != "high":
                    e["behavior"], e["behavior_score"] = s["severity"], s.get("score")
                doc["devices"] = sorted(set(doc["devices"]) | {host})
    except Exception as exc:
        logger.debug("[person] behaviour scores unavailable for %s: %s", day, exc)

    for r in await q("network", kql_network(day, d1)):
        up = float(r.get("UploadMB") or 0)
        prior = float(r.get("PriorMaxMB") or 0)
        anomaly = up > 500 and int(r.get("PriorDays") or 0) >= 3 and up > 3 * prior
        p(r["Person"])["network"] = {
            "rare_new": int(r.get("RareNew") or 0), "rare_sample": _as_list(r.get("RareSample"))[:5],
            "service_hits": int(r.get("ServiceHits") or 0), "services": _as_list(r.get("Services"))[:5],
            "upload_mb": round(up), "prior_max_mb": round(prior), "upload_anomaly": anomaly,
            "top_uploads": _as_list(r.get("TopUploads"))[:3],
            "alerts": int(r.get("Alerts") or 0), "alert_kinds": _as_list(r.get("AlertKinds"))}
    for r in await q("identity", kql_identity(day, d1)):
        p(r["Person"])["identity"] = {
            "new_countries": _as_list(r.get("NewCountries")), "new_country_ok": int(r.get("NewCountryOK") or 0),
            "password_ok_mfa_stopped": int(r.get("PasswordOkMfaStopped") or 0),
            "new_country_failed": int(r.get("NewCountryFailed") or 0), "ips": _as_list(r.get("IPs")),
            "apps": _as_list(r.get("Apps"))}
    for r in await q("cloud", kql_cloud(day, d1)):
        p(r["Person"])["cloud"] = {
            "new_net_calls": int(r.get("NewNetCalls") or 0), "new_nets": _as_list(r.get("NewNets")),
            "new_net_ips": int(r.get("NewNetIPs") or 0), "ips": _as_list(r.get("NewNetIPList")),
            "new_net_sensitive": _as_list(r.get("NewNetSensitive")), "agents": _as_list(r.get("NewNetAgents")),
            "first_sensitive": _as_list(r.get("FirstSensitive")), "denied": int(r.get("Denied") or 0)}
    for r in await q("session split", build_split_kql(end=_dt(d1))):
        c = p(str(r.get("User") or "")).setdefault("cloud", {})
        c["session_split"] = True
    people.pop("", None)
    return people


def _db():
    from shadow_hunter.models import Finding
    return Finding.get_pymongo_collection().database


async def run_day(day: date, client=None) -> dict:
    """Compute one day's signals, store them, re-score every person with signals in the last
    CASE_DAYS, and write or update their case finding (medium/high only)."""
    from shadow_hunter.detectors.base import mask_ids
    from shadow_hunter.models import Finding
    db = _db()
    coll = db[SIGNALS_COLL]
    signals = await daily_signals(day, client)
    expires = datetime(day.year, day.month, day.day, tzinfo=timezone.utc) + timedelta(days=RETENTION_DAYS)
    for person, doc in signals.items():
        doc = mask_ids(doc)
        doc["expires_at"] = expires
        await coll.replace_one({"_id": f"{day.isoformat()}|{person}"}, {"_id": f"{day.isoformat()}|{person}", **doc},
                               upsert=True)
    start = (day - timedelta(days=CASE_DAYS - 1)).isoformat()
    active = await coll.distinct("person", {"day": {"$gte": start, "$lte": day.isoformat()}})
    out = {"day": day.isoformat(), "people_with_signals": len(signals), "people_in_window": len(active),
           "by_severity": {"high": 0, "medium": 0, "low": 0, "none": 0}, "written": 0, "updated": 0}
    for person in active:
        days = await coll.find({"person": person, "day": {"$gte": start, "$lte": day.isoformat()}},
                               {"_id": 0, "expires_at": 0}).to_list(length=CASE_DAYS)
        case = score_case(days)
        out["by_severity"][case["severity"]] += 1
        if case["severity"] not in ("high", "medium"):
            continue
        case_start = min(t["day"] for t in case["timeline"]) if case["timeline"] else day.isoformat()
        indicator = f"{person}@{case_start}"
        devices = sorted({h for d in days for h in d.get("devices", [])})
        summary = mask_ids(summarize_case(person, case))
        raw = {**case, "person": person, "devices": devices, "as_of": day.isoformat()}
        # One open case per person. The 14-day window slides, so its start date moves; the open
        # (unreviewed) case is the one to grow. Once reviewed, new evidence starts a new case.
        existing = await Finding.find_one(Finding.detector == "person_behavior", Finding.account_name == person,
                                          Finding.reviewed_at == None, Finding.legacy != True)  # noqa: E711,E712
        if existing:
            old_raw = dict(existing.raw or {})
            # an unreviewed case never quietly drops: evidence ageing out of the window is not
            # the threat going away
            rank = {"medium": 1, "high": 2}
            existing.severity = max(existing.severity, case["severity"], key=lambda s: rank.get(s, 0))
            existing.summary = summary
            existing.raw = {**raw, "first_seen_case_start": existing.raw.get("first_seen_case_start", case_start)}
            existing.device_name = ", ".join(devices[:3])
            # re-triage only when the evidence changed, not on every nightly re-score
            evidence = lambda r: (r.get("account_events"), r.get("weak_account_events"), r.get("device_events"))
            if evidence(old_raw) != evidence(raw):
                existing.ai_verdict, existing.ai_at = "", None
            await existing.save()
            out["updated"] += 1
            continue
        raw["first_seen_case_start"] = case_start
        await Finding(detector="person_behavior", severity=case["severity"], device_name=", ".join(devices[:3]),
                      account_name=person, indicator=indicator, summary=summary, raw=raw,
                      mitre_techniques=[]).insert()
        out["written"] += 1
    return out


def summarize_case(person: str, case: dict) -> str:
    acct = case.get("account_events") or case.get("weak_account_events") or []
    bits = [f"'{person}', score {case['score']}: " + (acct[-1].split(": ", 1)[-1] if acct else "account activity")
            + (f" (+{len(acct) - 1} more account events)" if len(acct) > 1 else "")
            + (f"; device: {case['device_events'][-1].split(': ', 1)[-1]}" if case.get("device_events") else
               f"; device activity {case['points']['endpoint'] + case['points']['network']:g} pts")]
    if case["chain"]:
        bits.append("in attack order (device activity before identity/cloud anomalies)")
    if case["shared_ips"]:
        bits.append(f"same IP across sources: {', '.join(case['shared_ips'][:3])}")
    return "; ".join(bits)


RUNS_COLL = "person_runs"


async def run_logged(day: date, client=None) -> dict:
    """run_day with its outcome recorded in Mongo (GET /api/shadow/person/status): pod logs go
    with the pod, and the pods are replaced several times a day."""
    runs = _db()[RUNS_COLL]
    now = lambda: datetime.now(timezone.utc).isoformat()
    await runs.replace_one({"_id": day.isoformat()}, {"_id": day.isoformat(), "state": "running", "started": now()},
                           upsert=True)
    try:
        out = await run_day(day, client)
        rec = {"state": "done", **out}
    except Exception as exc:
        logger.exception("[person] run for %s failed", day)
        rec = {"state": "failed", "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
    rec["finished"] = now()
    await runs.update_one({"_id": day.isoformat()}, {"$set": rec})
    return {"day": day.isoformat(), **rec}


async def status(limit: int = 10) -> dict:
    runs = await _db()[RUNS_COLL].find({}).sort("_id", -1).limit(limit).to_list(limit)
    return {"runs": [{**r, "day": r.pop("_id")} for r in runs]}
