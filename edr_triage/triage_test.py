"""AI triage test suite — runs server-side via POST /api/edr-triage/test."""
from __future__ import annotations

import os
from typing import Any

_SUSPICIOUS = {
    "alert_name":     "Kali Linux user agent detected on EC2 instance",
    "device_name":    "ip-10-212-21-50",
    "account_name":   "prod",
    "event_name":     "ssm:DescribeParameters",
    "instance_id":    "i-04a2ce810d6b72956",
    "session_issuer": "ecs-task-role",
    "user_arn":       "arn:aws:sts::123:assumed-role/ecs-task-role/attacker@gmail.com",
    "user_name":      "attacker@gmail.com",
    "access_key_id":  "ASIAEX1",
    "source_ip":      "49.43.185.99",
    "ip_geo":         "Jodhpur, Rajasthan, IN (Jio ISP)",
    "mfa_status":     "DISABLED",
    "time_generated": "2026-06-30 10:22:00",
    "command":        "ssm:DescribeParameters; ssm:GetParameters",
}
_BENIGN = {
    "alert_name":     "SSM Session Manager activity",
    "device_name":    "db-test-restore-01",
    "account_name":   "nonprod",
    "event_name":     "ssm:StartSession",
    "instance_id":    "i-0abc123456",
    "session_issuer": "dba-role",
    "user_arn":       "arn:aws:sts::123:assumed-role/dba-role/dba@example.com",
    "user_name":      "dba@example.com",
    "access_key_id":  "ASIAEX2",
    "source_ip":      "10.220.9.50",
    "ip_geo":         "Mumbai (Corporate VPN)",
    "mfa_status":     "ENABLED",
    "time_generated": "2026-06-30 09:00:00",
    "command":        "pbm backup start; mongod --version; systemctl status mongod",
}
_NEEDS_REVIEW = {
    "alert_name":     "Unusual API call from EC2 instance",
    "device_name":    "app-prod-api-12",
    "account_name":   "prod",
    "event_name":     "iam:ListRoles",
    "instance_id":    "i-0prod12345",
    "session_issuer": "ec2-instance-role",
    "user_arn":       "arn:aws:sts::123:assumed-role/ec2-instance-role/i-0prod12345",
    "user_name":      "ec2-instance-role",
    "access_key_id":  "ASIAEX3",
    "source_ip":      "10.212.21.100",
    "ip_geo":         "Internal AWS (ap-south-1)",
    "mfa_status":     "NOT_APPLICABLE",
    "time_generated": "2026-06-30 03:15:00",
    "command":        "iam:ListRoles; iam:ListPolicies",
}
_SIM101839_MOCK_CLOUDTRAIL = {
    "alert_name":     "Root Privilege Escalation",
    "device_name":    "ip-10-0-1-50",
    "account_name":   "prod",
    "event_name":     "ssm:StartSession",
    "instance_id":    "i-04a2ce810d6b72956",
    "session_issuer": "SSMServiceRole",
    "user_arn":       "arn:aws:sts::123456789012:assumed-role/SSMServiceRole/ops@example.com",
    "user_name":      "ops@example.com",
    "access_key_id":  "ASIAEXAMPLE01234",
    "source_ip":      "10.220.9.96",
    "ip_geo":         "Mumbai (Corporate VPN)",
    "mfa_status":     "ENABLED",
    "time_generated": "2026-06-30 12:00:00",
    "command":        (
        "sudo su -; whoami; id; "
        "/usr/lib/systemd/systemd --user; "
        "cat /etc/passwd; "
        "ls -la /root; "
        "/snap/amazon-ssm-agent/7983/amazon-ssm-agent"
    ),
}


def _p(passed: bool, name: str, detail: str = "") -> dict:
    return {"name": name, "passed": passed, "detail": detail}


async def run_suite() -> dict:
    checks: list[dict] = []

    # ── 1. Ollama connectivity ────────────────────────────────────────────────
    try:
        import httpx
        url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434")
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(url.rstrip("/") + "/api/tags")
            r.raise_for_status()
            models = [m.get("name") for m in r.json().get("models", [])]
        checks.append(_p(True,  "ollama_reachable",       f"url={url}"))
        checks.append(_p("deepseek-r1:8b" in models, "deepseek_model_loaded", f"models={models}"))
    except Exception as exc:
        checks.append(_p(False, "ollama_reachable", str(exc)))
        checks.append(_p(False, "deepseek_model_loaded",  "skipped — ollama unreachable"))

    # ── 2. LLM verdict accuracy (one call — SUSPICIOUS is the critical path) ──
    # deepseek-r1:8b takes ~8 min per call on CPU; run one representative case
    # to verify the full LLM pipeline (prompt → parse → reasoning) without a
    # 32-minute test run.
    from edr_triage.playbooks.generic import _llm_analyze_cloudtrail
    try:
        verdict, reasons, recommendation, reasoning = await _llm_analyze_cloudtrail(_SUSPICIOUS)
        checks.append(_p(verdict == "SUSPICIOUS", "llm_verdict_suspicious",
                         f"got={verdict} expected=SUSPICIOUS reasons={len(reasons)}"))
        checks.append(_p(bool(reasoning), "llm_verdict_has_reasoning",
                         f"{len(reasoning)} chars" if reasoning else "empty"))
        checks.append(_p(bool(recommendation), "llm_verdict_has_recommendation", recommendation[:80]))
    except Exception as exc:
        checks.append(_p(False, "llm_verdict_suspicious", str(exc)))

    # ── 5. Rule-based fallback ────────────────────────────────────────────────
    from edr_triage.playbooks.generic import _rule_based_analyze
    v, _, _, _ = _rule_based_analyze(_SUSPICIOUS)
    checks.append(_p(v == "SUSPICIOUS", "rule_based_suspicious", f"got={v}"))
    v, _, _, _ = _rule_based_analyze(_BENIGN)
    checks.append(_p(v in ("BENIGN", "NEEDS_REVIEW"), "rule_based_benign_or_review", f"got={v}"))

    # ── 6. Command cleaning ───────────────────────────────────────────────────
    from edr_triage.playbooks.generic import _clean_commands
    raw = (
        "/usr/lib/systemd/systemd --user;"
        "/usr/lib/systemd/systemd --user;"
        "/snap/amazon-ssm-agent/7983/x;"
        "pbm backup start; mongod --version; pbm backup start;"
        "/bin/sh /usr/lib/cloud-init/cloud-init-generator;"
    )
    cleaned = _clean_commands(raw)
    noise_gone = not any(
        any(c.startswith(p) for p in ("/usr/lib/systemd/", "/snap/amazon-ssm-agent/", "/bin/sh /usr/lib/cloud-init/"))
        for c in cleaned
    )
    checks.append(_p(noise_gone, "command_noise_filtered", str(cleaned)))
    checks.append(_p(len(cleaned) == len(set(cleaned)), "command_deduped", f"{len(cleaned)} unique"))
    checks.append(_p({"pbm backup start", "mongod --version"}.issubset(set(cleaned)),
                     "command_real_preserved", str(cleaned)))

    # ── 7. ARN extractor ─────────────────────────────────────────────────────
    from edr_triage.playbooks.generic import _arn_session_user
    for arn, expected in [
        ("arn:aws:sts::123:assumed-role/role/user@example.com", "user@example.com"),
        ("arn:aws:iam::123:user/plainuser",                    ""),
        ("",                                                   ""),
    ]:
        result = _arn_session_user(arn)
        checks.append(_p(result == expected, "arn_extractor",
                         f"arn='{arn[:35]}…' → '{result}' (expected '{expected}')"))

    # ── 8. Classifier ────────────────────────────────────────────────────────
    from edr_triage.classifier import classify
    for name, expected in [
        ("Root Privilege Escalation",              "privesc"),
        ("Block Anydesk",                          "block_tool"),
        ("Netskope DLP Alert",                     "skip"),
        ("Netskope - Failed Login",                "credential_access"),
        ("Ransomware detected",                    "malware"),
        ("Multiple failed sign-in attempts",       "credential_access"),
        ("EC2 instance i-04a2ce810d communicating","skip"),
        ("Unknown random alert type",              "generic"),
    ]:
        result = classify(name)
        checks.append(_p(result == expected, f"classify_{expected}",
                         f"'{name[:40]}' → {result} (expected {expected})"))

    # ── 9. Jira parser ───────────────────────────────────────────────────────
    from edr_triage.jira_poller import parse_mde_alert_id, parse_sentinel_incident_url

    mde_desc = ("alertLink\nhttps://security.microsoft.com/alerts/abc1234567890abcdef?tid=xyz\n"
                "Alert Display Name\nBlock Anydesk\n")
    checks.append(_p(parse_mde_alert_id(mde_desc) == "abc1234567890abcdef",
                     "jira_mde_id_parsed", parse_mde_alert_id(mde_desc)))

    sn_desc = (
        "alertLink\nhttps://security.microsoft.com/alerts/sn1043af19-69a3-4126-b7ca-50fdd94a4bf8?tid=xyz\n"
        "Alert Display Name\nRoot Privilege Escalation\n"
        "IncidentURl\nhttps://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/"
        "subscriptions/00000000/providers/Microsoft.SecurityInsights/Incidents/abc123\n"
    )
    checks.append(_p(parse_mde_alert_id(sn_desc) is None,
                     "jira_sn_alert_rejected_as_mde", str(parse_mde_alert_id(sn_desc))))
    checks.append(_p(bool(parse_sentinel_incident_url(sn_desc)),
                     "jira_sentinel_url_extracted", (parse_sentinel_incident_url(sn_desc) or "")[:60]))

    # ── 10. DEMO-101839 dry-run ────────────────────────────────────────────────
    try:
        verdict, reasons, recommendation, reasoning = await _llm_analyze_cloudtrail(_SIM101839_MOCK_CLOUDTRAIL)
        checks.append(_p(verdict in ("SUSPICIOUS", "NEEDS_REVIEW"),
                         "sim101839_verdict_non_benign",
                         f"verdict={verdict} reasons={len(reasons)}"))
        checks.append(_p(bool(reasoning), "sim101839_reasoning_present",
                         reasoning[:120] if reasoning else "empty"))

        # Build the comment preview
        lines = [f"*AI Analysis — Verdict: {verdict}*"]
        for r in reasons:
            lines.append(f"* {r}")
        if recommendation:
            lines.append(f"*Recommendation:* {recommendation}")
        if reasoning:
            lines += ["", "*AI Reasoning:*", "{quote}", reasoning, "{quote}"]
        lines.append("[Auto-analysed by DeepIntel AI]")
        preview = "\n".join(lines)
        checks.append(_p(True, "sim101839_comment_preview", preview))
    except Exception as exc:
        checks.append(_p(False, "sim101839_dry_run", str(exc)))

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    return {
        "passed": passed,
        "failed": failed,
        "total":  len(checks),
        "checks": checks,
    }
