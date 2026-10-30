"""Aurora MySQL audit (RDS) — account changes, unusual destructive statements, guessed passwords.

Reads VictoriaLogs in place: source_type:cloudwatch, log_group /aws/rds/cluster/<name>/audit.
Each line is the Aurora audit CSV `time,server,user,client,connection,query,operation,db,object,
retcode`. The audit policy logs connections and DDL/DCL only — never reads or writes of data.

Three signals, measured over Oct 5-19:
  * Account and privilege changes (CREATE/ALTER/DROP/RENAME USER, GRANT, REVOKE, SET PASSWORD).
    AWS rotating its own rdsadmin@localhost is left out; what remains is ~1 a day, a DBA
    provisioning an account from the admin jump range — worth a look each time, because a new
    database account is how access is kept. GRANT ALL / SUPER / WITH GRANT OPTION is high.
  * DROP DATABASE/SCHEMA always; DROP TABLE / TRUNCATE (non-temporary) only from a cluster+user
    that did not run one in the previous 14 days (16 such pairs exist, all scheduled jobs).
    Keyed on cluster+user, not client: pod IPs rotate.
  * Access denied (1045) for a cluster+user with no failures in the previous 14 days, and high
    when 3+ failures from a client new to failing are followed by a success from it — a guessed
    password. Chronically failing app accounts (cch_user, from rotating pod IPs) stay quiet.

Statements carry passwords (IDENTIFIED BY '...'); they are redacted before anything is stored.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from shadow_hunter.detectors.base import Detector, mask_ids

BASE = 'source_type:cloudwatch log_group:~"^/aws/rds/.*/audit$"'
EXTRACT = '| extract "<ts>,<srv>,<dbuser>,<client>,<conn>,<qid>,<op>," from _msg'
DCL_RE = r"(?i)\b(grant\s|revoke\s|create\s+user\b|alter\s+user\b|drop\s+user\b|rename\s+user\b|set\s+password\b)"
DESTRUCT_RE = r"(?i)\b(drop\s+(database|schema)\b|drop\s+table\b|truncate\s)"
STRONG_GRANT_RE = re.compile(r"(?i)\b(all\s+privileges|super\b|with\s+grant\s+option|grant\s+all\b)")
_SECRET_RE = re.compile(
    r"(?i)(identified\s+(by|with\s+\S+\s+(by|as))\s*)(\\?'[^']*\\?'|\"[^\"]*\"|\S+)|(password\s*(=|\()\s*)(\\?'[^']*\\?'|\"[^\"]*\"|\S+)")
WINDOW_HOURS = 2
BASELINE_DAYS = 14


_SET_PASSWORD_RE = re.compile(r"(?is)^(\s*set\s+password\b[^=]*=).*$")


def redact(sql: str) -> str:
    """Strip passwords from a statement before it is stored or shown. SET PASSWORD loses
    everything after its `=` (the account name can sit between PASSWORD and `=`)."""
    def sub(m):
        return (m.group(1) or m.group(5) or "") + "'***'"
    sql = _SET_PASSWORD_RE.sub(lambda m: m.group(1) + " '***'", sql or "")
    return _SECRET_RE.sub(sub, sql)


def cluster_of(log_group: str) -> str:
    parts = (log_group or "").strip("/").split("/")
    return parts[3] if len(parts) > 3 else (log_group or "?")


def statement(msg: str) -> str:
    """The SQL text out of one audit line (the quoted object field)."""
    m = re.search(r",QUERY,[^,]*,'(.*)',\d+\s*$", msg or "", flags=re.S)
    return (m.group(1) if m else msg or "").replace("\\'", "'")


def q_dcl() -> str:
    from shadow_hunter.clients.victorialogs import literal
    return (f'{BASE} _msg:",QUERY," _msg:~{literal(DCL_RE)} {EXTRACT} '
            '| filter -(dbuser:="rdsadmin" client:="localhost") '
            '| stats by (log_group, dbuser, client) count() n, uniq_values(_msg) limit 5 sample, min(_time) first '
            '| limit 200')


def q_destruct(by_client: bool = True) -> str:
    from shadow_hunter.clients.victorialogs import literal
    by = "(log_group, dbuser, client)" if by_client else "(log_group, dbuser)"
    return (f'{BASE} _msg:",QUERY," _msg:~{literal(DESTRUCT_RE)} -_msg:~"(?i)temporary" {EXTRACT} '
            f'| stats by {by} count() n, uniq_values(_msg) limit 3 sample, min(_time) first | limit 500')


def q_denied(with_success: bool = True) -> str:
    if with_success:
        return (f'{BASE} (_msg:",FAILED_CONNECT," or _msg:",CONNECT,") {EXTRACT} '
                '| stats by (log_group, dbuser, client) count() if (_msg:",FAILED_CONNECT," _msg:",1045") fails, '
                'count() if (op:="CONNECT") ok, min(_time) first | filter fails:>0 | limit 500')
    return (f'{BASE} _msg:",FAILED_CONNECT," _msg:",1045" {EXTRACT} '
            '| stats by (log_group, dbuser, client) count() n | limit 2000')


class RdsAuditDetector(Detector):
    name = "rds_audit"
    mitre_techniques = ["T1136", "T1098", "T1485", "T1110"]
    severity = "medium"
    cadence_minutes = 60
    query_name = "rds_audit"

    def kql(self, lookback_hours: int) -> str:  # not an MDE query; see fetch
        return ""

    async def fetch(self, defender, lookback_hours: int = 24) -> list[dict]:
        from shadow_hunter.clients import MockDefenderClient
        if isinstance(defender, MockDefenderClient):
            return []
        from shadow_hunter.clients.victorialogs import VictoriaLogsClient
        return await self.collect(VictoriaLogsClient(), datetime.now(timezone.utc))

    async def collect(self, c, end: datetime) -> list[dict]:
        """The rows for the WINDOW_HOURS ending at `end` — split out so a replay runs the
        production logic on a past window."""
        from shadow_hunter.clients.victorialogs import as_int, iso
        start = end - timedelta(hours=WINDOW_HOURS)
        base_start = start - timedelta(days=BASELINE_DAYS)
        rows: list[dict] = []
        for r in await c.query(q_dcl(), iso(start), iso(end), 200):
            rows.append({**r, "_kind": "account_change"})
        destruct = await c.query(q_destruct(), iso(start), iso(end), 500)
        if destruct:
            seen = {(r.get("log_group"), r.get("dbuser"))
                    for r in await c.query(q_destruct(by_client=False), iso(base_start), iso(start), 500)}
            for r in destruct:
                drops_db = any(re.search(r"(?i)drop\s+(database|schema)\b", s) for s in _list(r.get("sample")))
                if drops_db or (r.get("log_group"), r.get("dbuser")) not in seen:
                    rows.append({**r, "_kind": "destructive", "_drops_db": drops_db})
        denied = await c.query(q_denied(), iso(start), iso(end), 500)
        if denied:
            hist = await c.query(q_denied(with_success=False), iso(base_start), iso(start), 2000)
            # Keyed on cluster+user: an app account that fails chronically does so from
            # rotating pod IPs (cch_user, every pod a "new client"). The exact client still
            # matters for the high case below — failures then a success from one machine.
            failing_users = {(r.get("log_group"), r.get("dbuser")) for r in hist}
            failing_clients = {(r.get("log_group"), r.get("dbuser"), r.get("client")) for r in hist}
            for r in denied:
                pair = (r.get("log_group"), r.get("dbuser"))
                new_user = pair not in failing_users
                guessed = (as_int(r.get("fails")) >= 3 and as_int(r.get("ok")) > 0
                           and (*pair, r.get("client")) not in failing_clients)
                if new_user or guessed:
                    rows.append({**r, "_kind": "access_denied", "_guessed": guessed})
        return rows

    def to_findings(self, rows: list[dict]) -> list[dict]:
        from shadow_hunter.clients.victorialogs import as_int
        out = []
        for r in rows:
            kind = r.get("_kind")
            cluster, user, client = cluster_of(r.get("log_group", "")), r.get("dbuser") or "?", r.get("client") or "?"
            day = str(r.get("first") or "")[:10]
            stmts = [redact(statement(s))[:300] for s in _list(r.get("sample"))]
            if kind == "account_change":
                strong = any(STRONG_GRANT_RE.search(s) for s in stmts)
                sev = "high" if strong else "medium"
                what = f"{as_int(r.get('n'))} account/privilege change(s) by {user}@{client}"
            elif kind == "destructive":
                sev = "high" if r.get("_drops_db") else "medium"
                what = (f"{as_int(r.get('n'))} destructive statement(s) by {user}@{client}"
                        + ("" if r.get("_drops_db") else f", first for this user on this cluster in {BASELINE_DAYS} days"))
            else:
                fails, ok = as_int(r.get("fails")), as_int(r.get("ok"))
                sev = "high" if r.get("_guessed") else "medium"
                what = (f"{fails} wrong-password login(s) (MySQL 1045) for {user} from {client}, new in {BASELINE_DAYS} days"
                        + (f", then {ok} successful login(s) from the same client" if ok else ""))
            out.append({
                "detector": self.name,
                "severity": sev,
                "device_id": cluster,
                "device_name": cluster,
                "account_name": user,
                "indicator": f"{kind}|{cluster}|{user}|{client}|{day}",
                "summary": mask_ids(f"RDS {cluster}: {what}" + (f" — e.g. {stmts[0]}" if stmts else ""))[:400],
                "raw": {"kind": kind, "cluster": cluster, "db_user": user, "client": client,
                        "statements": stmts, "count": as_int(r.get("n") or r.get("fails")),
                        "successful_logins": as_int(r.get("ok")) if kind == "access_denied" else None,
                        "first": r.get("first"), "source": "victorialogs:rds_audit"},
                "mitre_techniques": {"account_change": ["T1136", "T1098"], "destructive": ["T1485"],
                                     "access_denied": ["T1110"]}.get(kind, []),
            })
        return out


def _list(v) -> list:
    from shadow_hunter.clients.victorialogs import as_list
    return as_list(v)
