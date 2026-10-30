"""package_installs — the parser, and the decisions that separated the real incident package
from false leads in the 30-day backfill (see detectors/package_installs.py).

Run: python -m pytest shadow_hunter/package_installs_test.py -q
"""
from __future__ import annotations

import asyncio

import pytest

from shadow_hunter.detectors import DETECTORS
from shadow_hunter.detectors.package_installs import PackageInstallsDetector, assess
from shadow_hunter.packages import by_agent, parse_install, version_at

CLAUDE_WRAPPED = ("/bin/zsh -c \"source /Users/k/.claude/shell-snapshots/s.sh 2>/dev/null || true && "
                  "eval 'npm i self-certificate' < /dev/null\"")


@pytest.mark.parametrize("cmd,want", [
    ("node /opt/homebrew/bin/npm install self-certificate", [("npm", "self-certificate", "")]),
    ("/usr/bin/env node /opt/homebrew/bin/sfw npm install self-certificates", [("npm", "self-certificates", "")]),
    (CLAUDE_WRAPPED, [("npm", "self-certificate", "")]),
    ('/bin/sh -c "npm install --ignore-scripts types-registry@latest"', [("npm", "types-registry", "")]),
    ('npm i --save-dev --user-agent="t/6" @types/node@18.2.0', [("npm", "@types/node", "18.2.0")]),
    ("yarn add lodash@^4 react", [("npm", "lodash", ""), ("npm", "react", "")]),
    ("npm --prefix ./web install left-pad", [("npm", "left-pad", "")]),
    ("npx -y create-react-app my-app", [("npm", "create-react-app", "")]),
    ("pnpm dlx @scope/tool@1.2.3 --flag", [("npm", "@scope/tool", "1.2.3")]),
    ("python3 -m pip install requests==2.31.0 'urllib3>=2' -r req.txt Flask[async]",
     [("PyPI", "requests", "2.31.0"), ("PyPI", "urllib3", ""), ("PyPI", "flask", "")]),
    ("uv pip install my_pkg", [("PyPI", "my-pkg", "")]),
    ("uv add httpx", [("PyPI", "httpx", "")]),
    ("uvx ruff check .", [("PyPI", "ruff", "")]),
    ("timeout 480 npm ci --silent", []),
    ("npm install", []),
    ("npm run build", []),
    ("pip install -e .", []),
    ("npm i git+https://github.com/x/y.git ./local.tgz", []),
])
def test_parse_install(cmd, want):
    assert parse_install(cmd) == want


def test_agent_installs_are_recognised():
    assert by_agent(CLAUDE_WRAPPED) and not by_agent("zsh -il", "npm i x")


def test_version_at_install_time_is_the_stable_latest_then():
    t = {"1.0.0": "2026-06-11T10:02:57", "1.1.0": "2026-06-26T08:44:42", "2.0.0-beta": "2026-07-01T00:00:00",
         "3.0.0": "2026-09-01T00:00:00"}
    assert version_at(t, "2026-08-26T12:08:05") == "1.1.0"
    assert version_at(t, "2026-06-01T00:00:00") == ""


def test_paused_until_the_pod_has_memory_for_it():
    # re-enable in detectors/__init__.py once UAT pods have >=1 GiB (OOM-killed at 256 MiB)
    assert "package_installs" not in {d.name for d in DETECTORS}


# ── assess() with fake OSV / registry ──────────────────────────────────────────────

REG = {
    ("npm", "self-certificate"): {"versions": {"1.0.0": "2026-06-11T10:02:57", "1.1.0": "2026-06-26T08:44:42"},
                                  "created": "2026-06-11T10:02:57", "placeholder": False, "missing": False},
    ("npm", "cline"): {"versions": {"2.3.0": "2026-02-17T11:26:00", "2.4.0": "2026-02-17T19:23:00",
                                    "3.0.60": "2026-08-26T09:43:00"},
                       "created": "2024-01-01T00:00:00", "placeholder": False, "missing": False},
    ("npm", "self-certificates"): {"versions": {"1.2.9": "2026-08-20T00:00:00", "0.0.1-security": "2026-08-26T18:00:00"},
                                   "created": "2026-08-01T00:00:00", "placeholder": True,
                                   "placeholder_at": "2026-08-26T18:00:00", "missing": False},
    ("npm", "brand-new-lib"): {"versions": {"0.1.0": "2026-09-25T00:00:00"}, "created": "2026-09-25T00:00:00",
                               "placeholder": False, "missing": False},
    ("npm", "old-cli"): {"versions": {"2.2.3": "2026-01-01T00:00:00", "2.3.0": "2026-02-17T11:26:00"},
                         "created": "2024-01-01T00:00:00", "placeholder": False, "missing": False},
    ("npm", "old-lib"): {"versions": {"1.0.0": "2019-01-01T00:00:00"}, "created": "2019-01-01T00:00:00",
                         "placeholder": False, "missing": False},
}
MAL = {("npm", "self-certificate"): ["MAL-2026-5644"], ("npm", "cline"): ["MAL-2026-1380"],
       ("npm", "self-certificates"): ["MAL-2026-14543"]}
MAL_VERSIONS = {("npm", "self-certificate", "1.1.0"), ("npm", "self-certificate", "1.0.0"), ("npm", "cline", "2.3.0")}


async def fake_osv(pkgs):
    out = {}
    for p in pkgs:
        if len(p) == 2 and p in MAL:
            out[p] = MAL[p]
        if len(p) == 3 and p in MAL_VERSIONS:
            out[p] = MAL[p[:2]]
    return out


async def fake_registry(eco, name):
    return REG.get((eco, name))


def _recent(cmd, device="mac-1", time="2026-08-26T12:08:05Z", parent=""):
    return {"DeviceName": device, "DeviceId": f"id-{device}", "AccountName": "user", "Cmd": cmd, "Time": time, "Parent": parent}


def _run(recent, history=()):
    return asyncio.run(assess(list(history), recent, osv=fake_osv, registry=fake_registry))


def test_the_incident_install_is_critical_and_marked_as_agent():
    rows = _run([_recent(CLAUDE_WRAPPED)])
    f = PackageInstallsDetector().to_findings(rows)
    assert len(f) == 1 and f[0]["severity"] == "critical"
    assert f[0]["indicator"] == "npm:self-certificate@1.1.0" and "via an AI coding agent" in f[0]["summary"]


def test_a_package_with_an_old_hijacked_version_is_not_flagged_for_a_clean_version():
    # cline@2.3.0 was malicious for 8 hours in Feb; a September install gets 3.x
    assert _run([_recent("npm install -g cline", time="2026-09-17T13:32:00Z")]) == []
    pinned = _run([_recent("npm install -g cline@2.3.0", time="2026-09-17T13:32:00Z")])
    assert [r["Reason"] for r in pinned] == ["malicious_version"]


def test_install_after_the_registry_takedown_is_an_attempt_not_a_compromise():
    r = _run([_recent("npm install self-certificates", time="2026-09-28T06:56:35Z")])[0]
    assert r["Reason"] == "attempted_removed_malware" and r["Version"] == "0.0.1-security"
    assert PackageInstallsDetector().to_findings([r])[0]["severity"] == "high"


def test_fleet_rare_brand_new_package_is_medium_old_or_common_ones_are_silent():
    rows = _run([_recent("npm i brand-new-lib", time="2026-09-28T00:00:00Z"),
                 _recent("npm i old-lib", time="2026-09-28T00:00:00Z")])
    assert [(r["Package"], r["Reason"]) for r in rows] == [("brand-new-lib", "new_package")]
    common = [{"Cmd": "npm i brand-new-lib", "Devices": ["a", "b", "c"]}]
    assert _run([_recent("npm i brand-new-lib", time="2026-09-28T00:00:00Z")], history=common) == []


def test_one_row_per_device_package_version_however_many_processes_name_it():
    wrap = ["node /opt/homebrew/bin/sfw npm install self-certificate",
            "/usr/bin/env node /opt/homebrew/bin/npm install self-certificate",
            "node /opt/homebrew/bin/npm install self-certificate"]
    assert len(_run([_recent(c) for c in wrap])) == 1


def test_osv_unreachable_is_an_error_not_a_clean_bill():
    async def down(pkgs):
        return None
    with pytest.raises(RuntimeError):
        asyncio.run(assess([], [_recent("npm i anything")], osv=down, registry=fake_registry))


def test_own_scoped_packages_are_not_judged_by_public_registry_age():
    assert _run([_recent("npm i @acme/internal-lib", time="2026-09-28T00:00:00Z")]) == []


def test_a_freshly_published_version_of_an_established_rare_package_is_medium():
    rows = _run([_recent("npm i -g old-cli", time="2026-02-17T15:00:00Z")])
    assert [(r["Reason"], r["Version"]) for r in rows] == [("fresh_version", "2.3.0")]
    f = PackageInstallsDetector().to_findings(rows)[0]
    assert f["severity"] == "medium" and "published 3.6 h before" in f["summary"]
    assert _run([_recent("npm i -g old-cli", time="2026-03-30T00:00:00Z")]) == []     # weeks later: normal
