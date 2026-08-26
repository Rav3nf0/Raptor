"""Verdict-aware truncation for analyst (L1/L2) comments stored in memory.

Analyst verdicts usually STATE THE CALL ("...hence marking this as a false positive")
at the END of the comment, so a naive ``text[:N]`` can drop the very thing the memory
exists to capture. ``verdict_aware_truncate`` keeps the head (alert + investigation
context) AND guarantees the concluding verdict sentence, inside the char budget.
Deterministic, zero-cost, and never worse than a plain cap (it falls back to one when
no verdict phrase is found).

LATER UPGRADE — LLM summarizer (see ``summarize_comment`` stub below):
For very long comments, an INTERNAL Mistral/Mantle call can replace the head-context
slice with a faithful condensation. It MUST use the internal backend, never Gemini
(comments carry device/user/verdict data), gate above a higher threshold (e.g. >800),
and fall back to ``verdict_aware_truncate`` on any error so memory writing never breaks.
"""
from __future__ import annotations

import re

# Verdict phrases analysts actually use to state the call. Matching any of these in a
# sentence marks it as the "verdict sentence" we must preserve.
_VERDICT_RE = re.compile(
    r'\b(false positive|true positive|marking (?:it|this)|mark(?:ed)? as|'
    r'escalat\w+|closing|benign|malicious|no harm|legitimate|expected|authorized|'
    r'not a threat|confirmed (?:fp|tp|benign|malicious))\b', re.I)

_SENT_SPLIT = re.compile(r'(?<=[.!?])\s+')


def verdict_aware_truncate(text: str, limit: int = 400) -> str:
    """Truncate ``text`` to ``limit`` chars while preserving the verdict sentence.

    - ``len <= limit`` → returned unchanged.
    - No verdict phrase found → plain ``text[:limit] + '…'`` (same as before).
    - Otherwise → head context + ' … ' + the concluding verdict sentence, within budget.
    """
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    sents = _SENT_SPLIT.split(text)
    v_idx = [i for i, s in enumerate(sents) if _VERDICT_RE.search(s)]
    if not v_idx:
        return text[:limit].rstrip() + "…"
    verdict = sents[v_idx[-1]].strip()               # the concluding verdict sentence
    if len(verdict) >= limit:                        # verdict alone already fills the budget
        return verdict[:limit].rstrip() + "…"
    head = text[:limit - len(verdict) - 3].rstrip()  # 3 chars for the ' … ' join
    return f"{head} … {verdict}"


# LATER UPGRADE (not wired in): internal-only faithful summarizer for very long comments.
# When built: call the Mantle/Mistral backend (NEVER Gemini), condense without dropping the
# verdict or its conditions, and fall back to verdict_aware_truncate on any error.
# async def summarize_comment(text: str, limit: int = 400) -> str:
#     if len(text or "") <= 800:
#         return verdict_aware_truncate(text, limit)
#     try:
#         return (await _mantle_condense(text, limit)) or verdict_aware_truncate(text, limit)
#     except Exception:
#         return verdict_aware_truncate(text, limit)
