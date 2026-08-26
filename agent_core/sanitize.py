"""Gemini data sanitizer — strips sensitive infra identifiers before any text reaches an external LLM.

Sensitive fields that must never leave company infrastructure:
  - Device hostnames (incl. FQDN forms, any casing)
  - Usernames / UPNs
  - Internal (RFC1918) IP addresses
  - Internal email addresses (company domains)
  - Windows SIDs, MAC addresses
  - AWS ARNs (arn:aws:...)
  - EC2 instance IDs (i-0abc...)
  - AWS session principals / access key IDs
  - Process command lines from MDE timeline / KQL results

Public IOCs (file hashes, external IPs, external domains) are deliberately NOT
redacted — they are the evidence the external LLM needs to reason about.

Usage:
    s = AlertSanitizer(device_name="LAPTOP-ABC", user_name="john.doe@example.com",
                       extra={"arn:aws:sts::123:assumed-role/admin": "[ARN-1]"})
    clean_text = s.sanitize(raw_text)         # for prompt text
    clean_dict = s.sanitize_obj(raw_dict)     # for tool results (deep)
    real_args  = s.desanitize_obj(agent_args) # before executing a tool call
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any


# Columns from MDE / Sentinel KQL results that must always be stripped.
_STRIP_COLUMNS = frozenset({
    # MDE device fields
    "DeviceName", "ComputerName", "computerDnsName", "deviceDnsName",
    # Identity fields
    "AccountName", "AccountUpn", "userPrincipalName", "aadUserId",
    "InitiatingProcessAccountName", "InitiatingProcessAccountUpn",
    # Command lines — highest sensitivity
    "ProcessCommandLine", "InitiatingProcessCommandLine",
    "CommandLine", "InitiatingProcessParentFileName",
    # AWS
    "userArn", "principalId", "accessKeyId", "sessionIssuerArn",
    "instanceId", "accountId",
})

# Internal email domains to redact. External emails (potential phishing evidence)
# are left intact. Override via SANITIZER_INTERNAL_DOMAINS (comma-separated).
_INTERNAL_DOMAINS = [
    d.strip().lower()
    for d in os.getenv("SANITIZER_INTERNAL_DOMAINS", "example.com,corp.example.com").split(",")
    if d.strip()
]
_INTERNAL_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@(?:" + "|".join(re.escape(d) for d in _INTERNAL_DOMAINS) + r")\b",
    re.IGNORECASE,
) if _INTERNAL_DOMAINS else None

# Regex patterns for values that should be redacted even if not in a known column.
# NOTE: only INTERNAL/infra identifiers — public IOCs (external IPs, hashes,
# external domains) are intentionally preserved as threat evidence.
_SENSITIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"arn:aws:[^\s\"',]+", re.IGNORECASE), "[REDACTED-ARN]"),
    (re.compile(r"\bi-[0-9a-f]{8,17}\b", re.IGNORECASE), "[REDACTED-INSTANCE-ID]"),
    (re.compile(r"\bAKIA[A-Z0-9]{16}\b"), "[REDACTED-ACCESS-KEY]"),
    (re.compile(r"\bASIA[A-Z0-9]{16}\b"), "[REDACTED-ACCESS-KEY]"),
    # RFC1918 private IPv4 ranges — internal infra, not IOCs.
    (re.compile(
        r"\b(?:10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})"
        r"|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})"
        r"|192\.168\.(?:\d{1,3})\.(?:\d{1,3}))\b"
    ), "[REDACTED-INTERNAL-IP]"),
    # Windows security identifiers.
    (re.compile(r"\bS-1-5-(?:\d+-)+\d+\b", re.IGNORECASE), "[REDACTED-SID]"),
    # MAC addresses.
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), "[REDACTED-MAC]"),
]


def _short_token(value: str, prefix: str) -> str:
    """Stable 4-char hex token derived from the value."""
    h = hashlib.sha256(value.lower().encode()).hexdigest()[:4]
    return f"[{prefix}-{h}]"


def _seed_pattern(value: str) -> re.Pattern:
    """Case-insensitive, boundary-aware matcher for a seeded identifier.

    - Not preceded/followed by an identifier char, so we never rewrite a
      substring inside a longer word (e.g. user "sam" won't touch "sample").
    - Optionally consumes a trailing DNS suffix so a bare hostname also
      redacts its FQDN form (LAPTOP-ABC -> LAPTOP-ABC.corp.example.com).
    """
    escaped = re.escape(value)
    return re.compile(
        rf"(?<![\w.@-]){escaped}(?:\.[A-Za-z0-9.-]+)?(?![\w-])",
        re.IGNORECASE,
    )


class AlertSanitizer:
    """Bidirectional sanitizer for a single agent loop run.

    Maintains a stable token ↔ real-value mapping so that:
    - Text going OUT to Gemini has real values replaced with tokens
    - Tool args coming IN from Gemini (containing tokens) are restored before execution
    """

    def __init__(
        self,
        device_name: str = "",
        user_name: str = "",
        extra: dict[str, str] | None = None,
    ) -> None:
        # token → real_value  (for desanitize)
        self._rev: dict[str, str] = {}
        # (compiled case-insensitive pattern, token) for each seeded value
        self._seeded: list[tuple[re.Pattern, str]] = []

        if device_name:
            self._add(device_name, _short_token(device_name, "DEVICE"))
        if user_name:
            self._add(user_name, _short_token(user_name, "USER"))
            # A UPN's local part is often used bare in logs — seed it too.
            if "@" in user_name:
                local = user_name.split("@", 1)[0]
                if len(local) > 2:
                    self._add(local, _short_token(user_name, "USER"))
        for real, token in (extra or {}).items():
            self._add(real, token)

    def _add(self, real: str, token: str) -> None:
        # Guard against catastrophic substring replacement from very short values.
        if not real or len(real.strip()) < 3:
            return
        self._seeded.append((_seed_pattern(real), token))
        # Keep the first (typically fuller, e.g. full UPN) value as the restore
        # target when multiple matched forms share one token.
        self._rev.setdefault(token, real)

    def sanitize(self, text: str) -> str:
        """Replace sensitive values with tokens and apply regex redactions."""
        if not text:
            return text
        # Seeded identifiers first (case-insensitive, boundary + FQDN aware).
        for pattern, token in self._seeded:
            text = pattern.sub(token, text)
        # Then infra regex redactions (ARN, instance-id, keys, internal IP, SID, MAC).
        for pattern, label in _SENSITIVE_PATTERNS:
            text = pattern.sub(label, text)
        # Internal emails last (a seeded local part may already be tokenized).
        if _INTERNAL_EMAIL_RE is not None:
            text = _INTERNAL_EMAIL_RE.sub("[REDACTED-EMAIL]", text)
        return text

    def desanitize(self, text: str) -> str:
        """Replace tokens back to real values (used before executing tool calls)."""
        if not text:
            return text
        for token, real in self._rev.items():
            text = text.replace(token, real)
        return text

    def sanitize_obj(self, obj: Any) -> Any:
        """Deep-sanitize a JSON-serializable object (dict/list/str).

        Additionally strips known sensitive column names from dicts entirely.
        """
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in _STRIP_COLUMNS:
                    out[k] = "[REDACTED]"
                else:
                    out[k] = self.sanitize_obj(v)
            return out
        if isinstance(obj, list):
            return [self.sanitize_obj(item) for item in obj]
        if isinstance(obj, str):
            return self.sanitize(obj)
        return obj

    def desanitize_obj(self, obj: Any) -> Any:
        """Deep-desanitize (restore tokens to real values) in tool call args."""
        if isinstance(obj, dict):
            return {k: self.desanitize_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.desanitize_obj(item) for item in obj]
        if isinstance(obj, str):
            return self.desanitize(obj)
        return obj
