"""Fallback playbook — the alert type has no dedicated playbook (yet).

RAPTOR must never silently sit on a ticket: an alert name that matches none of
the specific classifiers (previously `classify()` returning "skip", which made
`_process_ticket` return None with zero Jira action) now lands here instead —
straight to L2 with whatever raw evidence is on the ticket, rather than held
unactioned.

The label this leaves (`no-playbook-fallback`) is deliberately queryable — it
is how the NEXT real playbook gets built. Pull every ticket carrying it, read
what L1 actually wrote in response, and that becomes the field list for a
dedicated playbook. This is exactly how the Netskope DLP playbook was built:
DEMO-110575's L1 comment named every field (Access Method, DLP Rule, DLP Rule
Severity, File Size, ...) that a real playbook then extracted deterministically.
A ticket that keeps landing here with the same alert_name repeatedly is the
signal that it is worth building next.
"""
from __future__ import annotations

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


class FallbackPlaybook(BasePlaybook):

    async def run(
        self,
        jira_key: str,
        alert: dict,
        evidence: dict,
        vt: dict,
        timeline: list[dict],
        is_test_device: bool = False,
        sentinel_entities: dict | None = None,
        normalized=None,
    ) -> PlaybookResult:
        alert_name = (alert or {}).get("alertDisplayName") or "Unknown alert"
        raw_desc = ((alert or {}).get("_description") or "").strip()

        lines = [
            "Hi Team,",
            f'RAPTOR does not yet have a dedicated triage playbook for *"{alert_name}"* — '
            "routing directly to L2 with the raw alert details below rather than holding "
            "it unactioned.",
            "",
        ]
        if raw_desc:
            lines += ["*Raw alert details:*", raw_desc[:3000], ""]
        else:
            lines += ["_No description text was available on this ticket._", ""]
        incident_url = (alert or {}).get("incident_url", "")
        if incident_url:
            lines += [f"*Sentinel Incident:* {incident_url}", ""]
        if is_test_device:
            lines += [self._test_device_note(), ""]
        lines += [
            "Escalating to L2 for manual triage.",
            "",
            "[Auto-triaged by RAPTOR — no dedicated playbook for this alert type]",
        ]
        return PlaybookResult(
            l1_comment="\n".join(lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai", "no-playbook-fallback"],
            auto_close=False,
        )
