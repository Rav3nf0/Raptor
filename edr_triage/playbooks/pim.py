"""Entra ID PIM playbook — "Privileged Role Assigned Outside PIM".

Previously in classifier.py's _SKIP_PATTERNS — never triaged at all. L1 has been
manually reading the raw AuditLogs "Add member to role" record and typing out
UserPrincipalName (recipient), InitiatedBy (grantor), the role name, and the
result (DEMO-92437, DEMO-91197). The single hardest-to-get fact in that record —
WHO granted the role — is exactly what lib.kql_templates.sentinel_identity_grant
already resolves (proven live on DEMO-106406 via the agent loop's
hunt_identity_grant tool); this playbook runs that same query deterministically
instead of asking an L1 to find it by hand. Deterministic, no LLM reasoning,
NEEDS_L2 always — this replaces the retyping, not the judgment call.
"""
from __future__ import annotations

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


class PimPlaybook(BasePlaybook):

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
        from edr_triage.normalized import normalize_alert
        n = normalized or normalize_alert(alert, evidence, sentinel_entities, source="sentinel")
        alert_name   = n.name if n.name != "Alert" else "Privileged Role Assigned Outside PIM"
        incident_url = n.incident_url

        ent = sentinel_entities or {}
        recipient = ent.get("accounts", [""])[0] if ent.get("accounts") else (alert.get("assignedTo") or "")
        grant = ent.get("identity_grant") or {}

        lines = [
            "Hi Team,",
            f'we have observed alert *"{alert_name}"*.',
            "",
        ]
        if recipient:
            lines.append(f"*Recipient (UserPrincipalName):* {recipient}")
        if grant.get("Actor"):
            lines.append(f"*Granted by (InitiatedBy):* {grant['Actor']}")
            if grant.get("ActorApp"):
                lines.append(f"  via app: {grant['ActorApp']}")
        if grant.get("Roles"):
            roles = grant["Roles"] if isinstance(grant["Roles"], list) else [grant["Roles"]]
            lines.append(f"*Role(s) granted:* {', '.join(str(r) for r in roles)}")
        if grant.get("Result"):
            lines.append(f"*Result:* {grant['Result']}")
        if grant.get("Events"):
            when = ""
            if grant.get("First") and grant.get("Last"):
                first = str(grant["First"])[:19].replace("T", " ")
                last = str(grant["Last"])[:19].replace("T", " ")
                when = f" ({first} UTC" + (f" – {last} UTC" if last != first else "") + ")"
            lines.append(f"*Matching events in window:* {grant['Events']}{when}")

        if not grant:
            lines += [
                "",
                "_No matching 'Add member to role/group' AuditLogs record was found for "
                "this recipient in the surrounding 24h window — the grantor could not be "
                "resolved automatically. Check the Sentinel incident's raw AuditLogs entry "
                "directly._",
            ]
        else:
            lines += [
                "",
                "*Note:* attribution is not authorisation — identifying the grantor does "
                "not by itself establish the grant was sanctioned. A grantor with an "
                "unremarkable admin history performing a routine assignment is common; "
                "verify against the recipient's actual role requirements.",
            ]

        if incident_url:
            lines += ["", f"*Sentinel Incident:* {incident_url}"]
        if is_test_device:
            lines += ["", self._test_device_note()]

        lines += [
            "",
            "Escalating to L2 for review.",
            "",
            "[Auto-triaged by RAPTOR]",
        ]

        return PlaybookResult(
            l1_comment="\n".join(lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai", "pim-outside-grant"],
            auto_close=False,
        )
