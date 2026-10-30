"""Checks the reasoning SAYS were done, compared with the checks that actually ran.

The 2026-09-30 audit of every autonomous close found no fabricated entity, but the
reasoning routinely reported safety checks that never happened:
  * "No VirusTotal detections, named EDR threats, or concurrent alerts" (DEMO-115177,
    114498, 114122) — no VT or concurrency call on the ticket;
  * "No VT detections, AbuseIPDB scores ≥ 75" (DEMO-113632) — neither was called;
  * "All auto-close safety checks pass: … no tool errors" (DEMO-113798) directly above
    `abuseipdb_lookup_ip → ERROR`.
The verdicts held up; the comment L2 reviews them from did not. This does NOT change a
verdict — the checks it names are not the load-bearing evidence for these families, and
escalating every ticket that repeats the boilerplate would cost real automation for no
safety gain. It makes the comment honest: whatever the reasoning claims without a
matching tool call is listed under it, so a reviewer knows which lines are unverified.

Sentence-level and deliberately narrow: a sentence that says the check was NOT done
("IP reputation checks were not performed") is not a claim that it was.
"""
from __future__ import annotations

import re

# (label, what the reasoning says, tool-name prefixes that back it)
_CHECKS = (
    ("VirusTotal", re.compile(r"\b(virus\s*total|vt)\b", re.I), ("vt_",)),
    ("AbuseIPDB", re.compile(r"\babuse\s*ipdb\b", re.I), ("abuseipdb",)),
    ("concurrent alerts",
     re.compile(r"\bconcurrent (open )?alerts?\b|\bother open alerts?\b", re.I),
     ("scg_check_concurrent_alerts",)),
)
_NO_ERRORS = re.compile(r"\bno (tool |query )?errors?\b", re.I)
_NEGATED = re.compile(
    r"\b(not|never|n't|without|unable|could not|skipped)\b[^.]{0,40}"
    r"\b(perform|check|run|call|quer|conduct|available|look|done|possible)", re.I)
_SENTENCE = re.compile(r"(?<=[.!?;])\s+|\n+")


def _ok(tc) -> bool:
    res = getattr(tc, "result", None) or {}
    return not (isinstance(res, dict) and res.get("error"))


def _backs(tc) -> bool:
    """A call that can back a claim: it succeeded AND returned something to cite.
    A VirusTotal lookup with no record (`no_data`) ran fine but proves nothing."""
    res = getattr(tc, "result", None) or {}
    return _ok(tc) and not (isinstance(res, dict) and res.get("no_data"))


def unverified_claims(reasoning: str, tool_calls: list, evidence: dict | None = None) -> list[str]:
    """Labels of checks the reasoning reports that no successful tool call backs.

    `evidence` covers results the pipeline put in the prompt itself rather than behind a
    tool call — today only VirusTotal on Upwind detection files.
    """
    text = reasoning or ""
    if not text.strip():
        return []
    names = [getattr(tc, "name", "") or "" for tc in tool_calls or []]
    backed = {label for label, _, prefixes in _CHECKS
              if any(n.startswith(prefixes) and _backs(tc)
                     for n, tc in zip(names, tool_calls or []))}
    _uw = ((evidence or {}).get("upwind_detection") or {}).get("detection") or {}
    if any(isinstance(f, dict) and f.get("vt") for f in (_uw.get("files") or [])):
        backed.add("VirusTotal")

    claimed: list[str] = []
    errored = sum(1 for tc in tool_calls or [] if not _ok(tc))
    for sentence in _SENTENCE.split(text):
        if _NEGATED.search(sentence):
            continue
        for label, pattern, _ in _CHECKS:
            if label not in backed and label not in claimed and pattern.search(sentence):
                claimed.append(label)
        if errored and _NO_ERRORS.search(sentence):
            tag = f"no tool errors ({errored} call(s) errored)"
            if tag not in claimed:
                claimed.append(tag)
    return claimed


def render(claims: list[str]) -> list[str]:
    """Jira lines for the comment; empty when every claim is backed."""
    if not claims:
        return []
    return ["", "*⚠ Not verified by any tool call on this ticket:* the reasoning above "
                f"refers to {', '.join(claims)}, but no such check ran successfully. "
                "Treat those statements as unverified."]


# A backticked value that looks like an identifier: has a digit, '/', '.', '@', ':' or
# '\\' in it (user agents, IPs, hosts, files, hashes, codes), 4-120 chars.
_QUOTED = re.compile(r"`([^`\n]{4,120})`")
_IDENTIFIER_SHAPE = re.compile(r"[0-9/.@:\\]")


def ungrounded_values(reasoning: str, tool_calls: list, evidence: dict | None = None,
                      alert: dict | None = None) -> list[str]:
    """Specific values the reasoning quotes that appear in no tool result, the evidence or
    the alert. DEMO-116466's re-run (2026-10-14) cited user agents `python-requests/2.31.0`
    and `PostmanRuntime/7.36.0`; the sign-in hunt returns no user agents at all.

    Results only, never tool ARGUMENTS — those would echo the model's own words back.
    Negated sentences ("no `50126` errors were found") are not claims.
    """
    import json
    text = reasoning if isinstance(reasoning, str) else " ".join(map(str, reasoning or []))
    if not text.strip():
        return []
    ground = " ".join(json.dumps(getattr(tc, "result", None), default=str)
                      for tc in tool_calls or []).lower()
    ground += " " + json.dumps(evidence or {}, default=str).lower()
    ground += " " + json.dumps(alert or {}, default=str).lower()
    ground = ground.replace("\\\\", "\\")          # json-escaped backslashes
    out: list[str] = []
    for sentence in _SENTENCE.split(text):
        if _NEGATED.search(sentence) or re.search(r"\bno\b", sentence, re.I):
            continue
        for q in _QUOTED.findall(sentence):
            v = q.strip()
            if (_IDENTIFIER_SHAPE.search(v) and v.lower() not in ground
                    and v not in out and len(out) < 6):
                out.append(v)
    return out
