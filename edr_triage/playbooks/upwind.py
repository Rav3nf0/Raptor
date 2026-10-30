"""Upwind CNAPP detection playbook — tickets raised by Upwind's own Jira integration
(critical runtime detections), e.g. "An AWS host contains a suspicious/malicious file".

The ticket carries the detection title, Upwind's canned description, severity, a console
link and the affected resource — and no evidence (DEMO-115057). The pipeline fetches the
detection from the Upwind API (edr_triage.upwind_client) for the file hashes, paths and
occurrence history; this comment lays those out for L2. Deterministic and always NEEDS_L2:
whether a flagged file is legitimate is L2's call, and the agent's recommendation rides
alongside.
"""
from __future__ import annotations

from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


class UpwindPlaybook(BasePlaybook):

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
        alert = alert or {}
        uw = alert.get("_upwind") or {}
        title = uw.get("title") or alert.get("alertDisplayName") or "Upwind detection"
        resource = uw.get("resource_name") or alert.get("computerDnsName") or ""

        lines = [
            "Hi Team,",
            f'Upwind has raised a *{(uw.get("severity") or alert.get("severity") or "").upper() or "UNRATED"}* '
            f'detection: *"{title}"*' + (f" on `{resource}`." if resource else "."),
            "",
        ]
        if uw.get("detail"):
            lines += [f"_Upwind:_ {uw['detail']}", ""]

        res_lines = []
        for label, key in (("Resource name", "resource_name"), ("Resource kind", "resource_kind"),
                           ("Environment", "environment"), ("Resource path", "resource_path"),
                           ("Cloud provider", "cloud_provider"), ("Cloud account ID", "account_id")):
            if uw.get(key):
                res_lines.append(f"  {label}: {uw[key]}")
        if res_lines:
            lines += ["*Affected resource:*", *res_lines, ""]

        lookup = alert.get("_upwind_detection") or {}
        det = (lookup.get("detection") or {}) if lookup.get("status") == "found" else {}
        dres = det.get("resource") or {}

        det_lines = []
        if uw.get("detection_id"):
            det_lines.append(f"  Detection ID: {uw['detection_id']}")
        if det:
            det_lines.append(f"  Type: {det.get('type', '')} ({det.get('category', '')}), "
                             f"status {det.get('status', '')}")
            det_lines.append(f"  First seen: {det.get('first_seen', '?')}   Last seen: "
                             f"{det.get('last_seen', '?')}   Occurrences: {det.get('occurrence_count', '?')}")
            if dres.get("instance_id"):
                det_lines.append(f"  Instance: {dres['instance_id']} ({dres.get('region', '?')})")
            if det.get("mitre"):
                det_lines.append(f"  MITRE: {', '.join(det['mitre'])}")
        if uw.get("link"):
            det_lines.append(f"  Upwind console: {uw['link']}")
        if det_lines:
            lines += ["*Upwind detection:*", *det_lines, ""]

        files = det.get("files") or []
        if files:
            lines.append(f"*Files flagged ({len(files)}{'+' if det.get('files_truncated') else ''}):*")
            for f in files:
                vt = f.get("vt")
                vt_s = ("" if vt is None else
                        f" — VT {vt.get('detections', 0)}/{vt.get('total', 0)} ({vt.get('verdict')})"
                        if vt.get("total") else " — not on VT (unknown, NOT clean)")
                lines.append(f"  {f.get('name', '')}  {f.get('hash_type', '').upper()} {f.get('hash', '')}{vt_s}")
                for p in f.get("paths") or []:
                    lines.append(f"    {p}")
            lines.append("")
        elif lookup.get("status") in ("error", "not_found"):
            lines += [f"_Upwind API lookup {lookup['status']} — file evidence not retrieved; "
                      "check the detection in the console._", ""]

        # Whether a second sensor can see this host decides what L2 can check without
        # leaving the SOC tooling. machineId is set by the pipeline's MDE name resolve.
        if alert.get("machineId"):
            onboard = alert.get("_mde_onboarding") or "onboarded"
            lines += [f"*MDE coverage:* host resolved in Defender ({onboard}) — its timeline "
                      "and file events can be hunted directly.", ""]
        elif resource:
            lines += ["*MDE coverage:* RAPTOR could not resolve this host in Defender — Upwind "
                      "may be the only sensor with visibility of it.", ""]

        if is_test_device:
            lines += [self._test_device_note(), ""]

        next_steps = (["verify the flagged files above — the hashes, whether they belong to a "
                       "known vendor, and how they got onto the host"] if files else
                      ["open the detection in the Upwind console for the file hash, path and "
                       "the process that wrote or ran it"])
        if alert.get("machineId"):
            next_steps.append("hunt that file/hash on the host in MDE around the detection time")
        next_steps.append("confirm with the resource owner whether the file is expected")
        lines += [
            "Recommendation: " + "; ".join(next_steps) + ".",
            "",
            "Escalating to L2 for review.",
            "",
            "[Auto-triaged by RAPTOR]",
        ]

        return PlaybookResult(
            l1_comment="\n".join(lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai", "upwind-detection"],
            auto_close=False,
        )
