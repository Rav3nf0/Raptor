"""control_bypass: disguised interpreters, in-house app names in the wrong place, forced proxies.

Run: .venv/bin/python -m pytest shadow_hunter/control_bypass_test.py -q
"""
from __future__ import annotations

import re

from shadow_hunter.detectors import DETECTORS
from shadow_hunter.detectors.control_bypass import (INHOUSE_OK_RE, INTERP_DIR_RE, INTERP_OWN_RE,
                                                    ControlBypassDetector, build_kql)

DIR, OWN, OK = re.compile(INTERP_DIR_RE), re.compile(INTERP_OWN_RE), re.compile(INHOUSE_OK_RE)

# The real row (e795jwebtechmac, 30-day replay 2026-11-13).
PRANAV = {
    "DeviceId": "d40e", "DeviceName": "e795jwebtechmac",
    "FirstSeen": "2026-11-08T06:37:19Z", "LastSeen": "2026-11-11T08:26:34Z", "Events": 5,
    "Kinds": ["inhouse_name", "forced_proxy", "disguised_interpreter"], "Programs": ["acmeprobeta"],
    "ProxyTargets": ["http://127.0.0.1:8899"], "Accounts": ["jesseweber"],
    "CommandLines": ["/opt/homebrew/Cellar/node/26.8.1/bin/acmeprobeta /Users/jesseweber/_home/proxy/server-toggle/detour-proxy.mjs",
                     "/usr/bin/open -a Dia --args --proxy-server=http://127.0.0.1:8899"],
}


def _disguised(path: str) -> bool:
    return bool(DIR.search(path)) and not OWN.match(path.replace("\\", "/").rsplit("/", 1)[-1])


def test_renamed_node_is_disguised():
    assert _disguised("/opt/homebrew/Cellar/node/26.8.1/bin/acmeprobeta")
    assert _disguised("/Users/x/.nvm/versions/node/v22.1.0/bin/chrome")
    assert _disguised(r"C:\Program Files\nodejs\Teams.exe")


def test_interpreters_own_programs_are_not():
    for p in ("/opt/homebrew/Cellar/node/26.8.1/bin/node", "/opt/homebrew/Cellar/node/26.8.1/bin/npm",
              "/opt/homebrew/Cellar/python@3.12/3.12.7/bin/python3.12", "/Users/x/.pyenv/versions/3.11.9/bin/pip3",
              r"C:\Program Files\nodejs\node.exe", r"C:\Users\a\AppData\Local\Programs\Python\Python314\python.exe"):
        assert not _disguised(p), p


def test_nested_helpers_are_not():
    # 30-day replay: selenium's own helper deep inside site-packages
    assert not _disguised(r"C:\Users\v\AppData\Local\Programs\Python\Python314\Lib\site-packages"
                          r"\selenium\webdriver\common\windows\selenium-manager.exe")
    # /usr/bin stubs share one hash with python3; they are not in an interpreter folder
    assert not _disguised("/usr/bin/git")


def test_inhouse_app_runs_legitimately_only_in_simulator_and_xcode_builds():
    assert OK.search("/Users/a/Library/Developer/CoreSimulator/Devices/X/data/Containers/Bundle/"
                     "Application/Y/AcmeProBeta.app/AcmeProBeta")
    assert OK.search("/Users/a/Library/Developer/Xcode/DerivedData/Acme-abc/Build/Products/AcmeProBeta.app/AcmeProBeta")
    assert not OK.search("/opt/homebrew/Cellar/node/26.8.1/bin/acmeprobeta")


def test_query_shape():
    kql = build_kql()
    assert "union disguised, inhouse, proxied" in kql
    assert '"acmeprobeta"' in kql and "--proxy-server" in kql and "--proxy-pac-url" in kql
    assert 'Burp Suite' in kql and 'Target !~ "direct://"' in kql
    # signed installs of the real app are not flagged; ad hoc copies are
    assert '"(ADHOC)"' in kql
    assert "by DeviceId, DeviceName" in kql            # one row per device


def test_one_high_finding_keyed_on_the_proxy():
    [f] = ControlBypassDetector().to_findings([PRANAV])
    assert f["severity"] == "high" and f["device_name"] == "e795jwebtechmac"
    assert f["indicator"] == "proxy:http://127.0.0.1:8899"
    assert "acmeprobeta" in f["summary"] and "127.0.0.1:8899" in f["summary"]
    assert f["account_name"] == "jesseweber"


def test_a_later_proxy_only_run_has_the_same_key():
    # 11 Nov: only the browser relaunch is inside the window; the hunter dedups on the indicator
    later = {**PRANAV, "Kinds": ["forced_proxy"], "Programs": []}
    [f] = ControlBypassDetector().to_findings([later])
    assert f["indicator"] == "proxy:http://127.0.0.1:8899" and f["severity"] == "medium"


def test_disguise_without_proxy_is_keyed_by_name():
    row = {**PRANAV, "Kinds": ["disguised_interpreter"], "ProxyTargets": []}
    [f] = ControlBypassDetector().to_findings([row])
    assert f["indicator"] == "name:acmeprobeta" and f["severity"] == "high"


def test_registered():
    assert any(d.name == "control_bypass" for d in DETECTORS)


def test_flag_mentioned_in_text_is_not_a_proxy():
    # first live day: `git` committing a message that mentioned the flag -> target "(Burp"
    from shadow_hunter.detectors.control_bypass import PROXY_TARGET_RE, TEXT_CARRIERS
    t = re.compile(PROXY_TARGET_RE)
    assert not t.match("(Burp") and not t.match("--proxy-pac-url") and not t.match("direct")
    for ok in ("http://127.0.0.1:8899", "socks5://localhost:1080", "127.0.0.1:8080", "proxy.corp:3128",
               "[::1]:8899", "file:///Users/x/proxy.pac", "https://pac.example.com/p.pac"):
        assert t.match(ok), ok
    assert {"git", "zsh", "grep", "claude"} <= set(TEXT_CARRIERS)
    kql = build_kql()
    assert "TEXT" not in kql and '"git"' in kql and "Target matches regex" in kql
