"""RDP logons that break the account's own pattern.

The previous version reported every account/device pair with fewer than five RDP logons in
a day — which is almost all of them: ~28 findings a day on UAT (2026-09-30), RMS operators
and admins reaching their usual machines from the usual jump hosts. It also dropped accounts
that Sentinel UEBA had already ranked risky, the opposite of what the ranking is for.

Each account is now compared with its own previous `history_days` of RDP. Of ~90 pairs a day
on UAT, a pair qualifies only when:
  * the source is a public IP (RDP from the internet) — high;
  * the account had no RDP logon at all in the history window — medium; or
  * the target is new for the account AND so is the source — medium (a known admin moving
    somewhere new from somewhere new, the lateral-movement shape).
Replayed on 2026-09-30: 1 new account, 1 new target from a new source, 0 public.
"""
from __future__ import annotations

from shadow_hunter.detectors.base import Detector


def build_kql(lookback_hours: int = 24, history_days: int = 14, end: str = "now()",
              new_targets: bool = False) -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay.
    new_targets=True returns every pair whose target is new for the account, whatever the
    source — the behaviour layer's access signal, not /shadow rows."""
    qualify = "NewTarget" if new_targets else "Public or NewAccount or (NewTarget and NewSource)"
    return f"""
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let rdp = DeviceLogonEvents
            | where Timestamp between ((windowStart - {history_days}d) .. windowEnd)
            | where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"
            | where RemoteIPType != "Loopback"
            | extend Acct = tolower(AccountName), Src = coalesce(RemoteIP, RemoteDeviceName);
        let hist = rdp | where Timestamp < windowStart;
        let acctHist = hist
            | summarize HistTargets = dcount(DeviceId), HistSrcs = make_set_if(Src, isnotempty(Src), 500) by Acct;
        let pairHist = hist | distinct Acct, DeviceId | extend PairSeen = true;
        rdp
        | where Timestamp >= windowStart
        | summarize LogonCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
                    SourceIPs = make_set_if(Src, isnotempty(Src), 5),
                    Public = countif(RemoteIPType == "Public") > 0,
                    AccountName = take_any(AccountName), AccountDomain = take_any(AccountDomain),
                    IsAdmin = max(tostring(IsLocalAdmin))
            by Acct, DeviceId, DeviceName
        | join kind=leftouter acctHist on Acct
        | join kind=leftouter pairHist on Acct, DeviceId
        | extend NewAccount = isnull(HistTargets), NewTarget = isnull(PairSeen),
                 NewSource = array_length(set_difference(SourceIPs, coalesce(HistSrcs, dynamic([])))) > 0
        | where {qualify}
        | project DeviceId, DeviceName, AccountName, AccountDomain, LogonCount, FirstSeen, LastSeen,
                  SourceIPs, IsAdmin, Public, NewAccount, NewTarget, NewSource,
                  HistTargets = coalesce(HistTargets, 0)
        | order by Public desc, NewAccount desc, LastSeen desc
        | take 200
        """


class RemoteLogonsDetector(Detector):
    name = "unusual_remote_logons"
    mitre_techniques = ["T1021.001", "T1078"]
    severity = "medium"
    cadence_minutes = 30
    query_name = "remote_logons"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            source_ips = [s for s in (r.get("SourceIPs") or []) if s]
            first_ip = source_ips[0] if source_ips else ""
            device_name = r.get("DeviceName", "")
            account = r.get("AccountName", "")
            if r.get("Public"):
                why = "from a public IP"
            elif r.get("NewAccount"):
                why = "account has no RDP logon in the previous 14 days"
            elif r.get("NewTarget") and r.get("NewSource"):
                why = (f"new target and new source for this account (it RDPed to "
                       f"{r.get('HistTargets', '?')} other device(s) before)")
            else:
                why = "unusual"  # pre-rework mock rows
            out.append({
                "detector": self.name,
                "severity": "high" if r.get("Public") else self.severity,
                "device_id": r.get("DeviceId") or device_name,
                "device_name": device_name,
                "account_name": account,
                "indicator": f"{account.lower()}@{device_name}",
                "summary": (f"RDP by '{account}' to '{device_name}' from {', '.join(source_ips) or 'unknown'} "
                            f"({r.get('LogonCount', '?')} logon(s)) — {why}"),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
