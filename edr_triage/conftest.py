"""Shared test defaults for edr_triage.

The DLP secret-key close asks whether each file owner has explained such data before
(netskope._secret_key_owners), which reads docs/dlpcontext.txt and the memory store. Tests
written before that check treat every owner as already justified; tests of the check
itself replace this stub (see secret_key_owner_test.py).
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _owners_already_justified(monkeypatch):
    from edr_triage.playbooks import netskope

    async def _all_ok(events):
        return {(e.get("user") or "?").lower(): "on file — test default" for e in events}, []

    monkeypatch.setattr(netskope, "_secret_key_owners", _all_ok)
