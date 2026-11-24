"""Getting around the web proxy: a disguised interpreter, an in-house app name in the wrong
place, or a browser forced through a proxy.

e795jwebtechmac, 8-12 Nov 2026: a login item started a copy of Node renamed `acmeprobeta`
(the Acme iOS app's process name, re-signed ad hoc, so its hash is not Node's) running a
local HTTP proxy on 127.0.0.1:8899, and opened the Dia browser with
--proxy-server=http://127.0.0.1:8899. All browsing then left as `acmeprobeta`; WhatsApp,
which Netskope had blocked for the user, worked and Netskope logged none of it. It surfaced
4 days later only because the proxy once touched discord.com (exfil_patterns).

Three shapes, any one is enough, one finding per device:
  disguised_interpreter  a program running from an interpreter's own bin folder (Homebrew
                         node/python/ruby/..., nvm, volta, pyenv, bun, deno, python.org,
                         C:\\Program Files\\nodejs, PythonNN) under a name that is not one of
                         that interpreter's own programs. A hash check misses it: the copy is
                         re-signed.
  inhouse_name           a process named exactly like an in-house app (AcmeProBeta, ...)
                         outside the iOS Simulator / Xcode build folders and not a signed
                         install under /Applications or Program Files.
  forced_proxy           a process started with --proxy-server / --proxy-pac-url (Chromium
                         browsers), except Burp Suite's bundled browser (AppSec testing).

30-day replay to 2026-11-13: 1 device (e795jwebtechmac), nothing else after the Burp and
nested-site-packages exclusions. First live day added one false hit: `git` committing a message
that MENTIONED --proxy-server (target "(Burp") - hence TEXT_CARRIERS and PROXY_TARGET_RE.
"""
from __future__ import annotations

from shadow_hunter.detectors.base import Detector, kql_list

# Interpreter install folders: the program must sit DIRECTLY in that bin folder (a nested
# site-packages helper such as selenium-manager.exe is not a disguised interpreter).
INTERP_DIR_RE = (r"(?i)(/Cellar/(node|node@[0-9]+|python@[0-9.]+|ruby|ruby@[0-9.]+|perl|php|php@[0-9.]+"
                 r"|curl|wget|socat|netcat|nmap|rclone|deno|bun)/[^/]+/bin/[^/]+$"
                 r"|/\.nvm/versions/node/[^/]+/bin/[^/]+$|/\.volta/tools/image/node/[^/]+/bin/[^/]+$"
                 r"|/\.pyenv/versions/[^/]+/bin/[^/]+$|/\.bun/bin/[^/]+$|/\.deno/bin/[^/]+$"
                 r"|/Python\.framework/Versions/[^/]+/bin/[^/]+$"
                 r"|\\Program Files\\nodejs\\[^\\]+$|\\Python3[0-9]+\\[^\\]+$)")
# What legitimately runs from those folders.
INTERP_OWN_RE = (r"(?i)^(node|nodejs|npm|npx|corepack|python[0-9.]*w?|pip[0-9.]*|pydoc[0-9.]*|idle[0-9.]*"
                 r"|2to3[0-9.-]*|python[0-9.]*-config|ruby|gem|irb|erb|bundle|bundler|rake|rdoc|ri"
                 r"|perl[0-9.]*|cpan|php[0-9.]*|php-cgi|phar|curl|curl-config|wget|socat|nc|ncat|nmap"
                 r"|rclone|deno|bun|bunx|uv|uvx)(\.exe|\.cmd)?$")
# In-house app process names a proxy could hide behind (lower case, exact).
INHOUSE_NAMES = ("acmeprobeta", "acmepro", "acme pro", "acme pro beta", "acme")
# Where those names legitimately run.
INHOUSE_OK_RE = r"(?i)(/CoreSimulator/|/DerivedData/)"
PROXY_FLAGS = ("--proxy-server", "--proxy-pac-url")
# Programs that only carry the flag as TEXT (a commit message, a grep, a script being written).
# A real launch from a shell still shows up as the browser's or `open`'s own process event.
TEXT_CARRIERS = ("zsh", "bash", "sh", "dash", "fish", "git", "grep", "rg", "ag", "sed", "awk", "cat", "less",
                 "vim", "nvim", "nano", "code", "cursor", "claude", "python", "python3", "node", "ruby", "perl",
                 "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe", "git.exe", "findstr.exe", "code.exe", "cursor.exe")
# A proxy address: scheme://host[:port] (http, https, socks, a PAC file/data URL) or host:port.
PROXY_TARGET_RE = r"(?i)^((https?|socks[45]?h?|socks|file|data):|[a-z0-9.\-]+:[0-9]{2,5}/?$|\[[0-9a-f:]+\]:[0-9]{2,5}/?$)"


def build_kql(lookback_hours: int = 24, end: str = "now()") -> str:
    """`end` is a KQL datetime expression; now() in production, a fixed datetime for replay."""
    return f"""
        let windowEnd = {end};
        let P = DeviceProcessEvents
            | where Timestamp between ((windowEnd - {lookback_hours}h) .. windowEnd);
        let disguised = P
            | where FolderPath matches regex @'{INTERP_DIR_RE}'
            | where not(FileName matches regex @'{INTERP_OWN_RE}')
            | extend Kind = "disguised_interpreter", Key = tolower(FileName), Target = "";
        let inhouse = P
            | where tolower(FileName) in ({kql_list(INHOUSE_NAMES)})
            | where not(FolderPath matches regex @'{INHOUSE_OK_RE}')
            | where not((FolderPath startswith "/Applications/" or FolderPath has @"\\Program Files")
                        and isnotempty(ProcessVersionInfoCompanyName)
                        and ProcessVersionInfoCompanyName !in ("(ADHOC)", "(APPLE)"))
            | extend Kind = "inhouse_name", Key = tolower(FileName), Target = "";
        let proxied = P
            | where ProcessCommandLine has_any ({kql_list(PROXY_FLAGS)})
            | where not(FileName in~ ({kql_list(TEXT_CARRIERS)}) or FileName matches regex @'(?i)^python[0-9.]+$')
            | where not(FolderPath has "Burp Suite" or InitiatingProcessFolderPath has "Burp Suite")
            | extend Target = extract(@'--proxy-(?:server|pac-url)[= ]["\\x27]?([^\\s"\\x27]+)', 1, ProcessCommandLine)
            | where isnotempty(Target) and Target !~ "direct://" and Target matches regex @'{PROXY_TARGET_RE}'
            | extend Kind = "forced_proxy", Key = tolower(Target);
        union disguised, inhouse, proxied
        | summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Events = count(),
                    Kinds = make_set(Kind, 3), Programs = make_set_if(Key, Kind != "forced_proxy", 5),
                    ProxyTargets = make_set_if(Target, isnotempty(Target), 5),
                    Paths = make_set(FolderPath, 5), Signers = make_set(ProcessVersionInfoCompanyName, 3),
                    Accounts = make_set(AccountName, 3),
                    Parents = make_set(substring(InitiatingProcessCommandLine, 0, 200), 3),
                    CommandLines = make_set(substring(ProcessCommandLine, 0, 300), 5)
            by DeviceId, DeviceName
        | take 100
        """


_KIND_TEXT = {
    "disguised_interpreter": "a program running from an interpreter's install folder under a foreign name",
    "inhouse_name": "a process named like an in-house app outside its normal locations",
    "forced_proxy": "a browser forced through a proxy",
}


class ControlBypassDetector(Detector):
    name = "control_bypass"
    mitre_techniques = ["T1036.003", "T1036.005", "T1090.001", "T1562"]
    severity = "high"
    cadence_minutes = 60
    query_name = "control_bypass"

    def kql(self, lookback_hours: int) -> str:
        return build_kql(lookback_hours=lookback_hours)

    def to_findings(self, rows: list[dict]) -> list[dict]:
        from shadow_hunter.behavior import redact_cmd
        out = []
        for r in rows:
            device = r.get("DeviceName", "")
            kinds = sorted(set(r.get("Kinds") or []))
            programs = [str(p) for p in (r.get("Programs") or []) if p]
            targets = [str(t) for t in (r.get("ProxyTargets") or []) if t]
            accounts = [a for a in (r.get("Accounts") or []) if a]
            cmds = [redact_cmd(str(c))[:160] for c in (r.get("CommandLines") or [])][:3]
            # The proxy target is the stable key across re-runs (the browser is reopened through
            # the same proxy); a disguise alone is keyed by the program name.
            indicator = (f"proxy:{targets[0]}" if targets else f"name:{programs[0] if programs else '?'}")[:120]
            disguised = any(k in kinds for k in ("disguised_interpreter", "inhouse_name"))
            out.append({
                "detector": self.name,
                "severity": "high" if disguised else "medium",
                "device_id": r.get("DeviceId") or device,
                "device_name": device,
                "account_name": accounts[0] if accounts else "",
                "indicator": indicator,
                "summary": (f"'{device}': " + "; ".join(_KIND_TEXT.get(k, k) for k in kinds)
                            + (f" — program {', '.join(programs[:3])}" if programs else "")
                            + (f" — proxy {', '.join(targets[:3])}" if targets else "")
                            + (f"; {cmds[0]}" if cmds else "")),
                "raw": r,
                "mitre_techniques": self.mitre_techniques,
            })
        return out
