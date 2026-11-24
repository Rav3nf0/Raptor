"""Per-actor DLP business justifications, read from docs/dlpcontext.txt.

What this is: ~50 justifications L2 collected from users and recorded by hand — "she is
from the Investor Grievances team, the data is NSE/BSE/MCX complaints containing
Aadhaar/PAN", "he does GST reconciliation". They explain WHY a person legitimately holds
the data a DLP rule flagged.

Why it is surfaced per actor rather than as one blob: the whole file already renders on
every DLP ticket as generic "common legitimate patterns" context. That tells an analyst
what the usual reasons are; it does not tell them whether THIS person already gave one.
Naming the actor's own recorded reason is what lets L2 close a ticket without re-asking a
question the org answered months ago.

CONTEXT ONLY, deliberately. It is rendered into the L1 comment for a human to weigh; it
does not feed a verdict and does not close anything. Routing is decided by DLP profile in
netskope.py, unchanged by this. That matters because the justifications vary in strength —
one line attaches "this data was saved as part of business purposes" to sixteen people,
which is far too thin to act on but still worth an analyst seeing.

EXACT EMAIL MATCH ONLY. 17 entries are still keyed by a bare first name ("Dana",
"Robin K") and are deliberately skipped: inferring name -> account is what produced the
wrong-actor attribution this project spent weeks removing, and a justification filed
against the wrong person is worse than none.
"""
from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

_DOC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "docs", "dlpcontext.txt")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# A new record starts where a short key is followed by a dash and the opening of a
# justification. Anchoring on those openers is what separates a genuine new entry from a
# continuation line that merely happens to contain a hyphen (the Anandkumar and Growth &
# Marketing entries both run to several lines).
_ENTRY_RE = re.compile(
    r"^(?P<key>.{1,160}?)\s*-\s*(?P<text>(?:as per|the below|user |this |due to|i work|"
    r"as verified|analysis)\b.*)$",
    re.IGNORECASE,
)

# Jira/Netskope prefixes a deletion hash onto a departed user's address, e.g.
# del_7fa406c46d894ec2a8819afdbbe12b7ashubhangini.gite@example.com. Those never match the
# doc as-is; 7 tickets in a 300-ticket sample carried one.
_DEL_PREFIX_RE = re.compile(r"^del_[0-9a-f]{20,40}", re.IGNORECASE)

# A justification continued onto its own line, opening with a bare dash.
_CONT_START_RE = re.compile(
    r"^-\s*(?P<text>(?:as per|the below|user |this |due to|i work|as verified|analysis)\b.*)$",
    re.IGNORECASE,
)

_CACHE: dict[str, str] | None = None


def _normalise(user: str) -> str:
    u = (user or "").strip().lower()
    return _DEL_PREFIX_RE.sub("", u)


def _parse(text: str) -> dict[str, str]:
    """email -> justification. One record may name several people; each gets the text."""
    out: dict[str, str] = {}
    lines = [l.strip() for l in (text or "").splitlines()]
    key, body = "", []

    def flush():
        if not key:
            return
        just = " ".join(" ".join(body).split())
        if not just:
            return
        for addr in _EMAIL_RE.findall(key):
            out.setdefault(addr.lower(), just)

    i = 0
    while i < len(lines):
        line = lines[i]
        if not line:
            i += 1
            continue

        m = _ENTRY_RE.match(line)
        if m:
            flush()
            key, body = m.group("key"), [m.group("text")]
            i += 1
            continue

        # A key line whose justification starts on the NEXT line, which then opens with
        # a bare dash. This is how the 16-person shared entry is written, and reading it
        # as a continuation of the previous record lost all 16 of them.
        if i + 1 < len(lines) and _EMAIL_RE.search(line):
            nxt = _CONT_START_RE.match(lines[i + 1])
            if nxt:
                flush()
                key, body = line, [nxt.group("text")]
                i += 2
                continue

        if key:
            body.append(line.lstrip("- ").strip())
        i += 1

    flush()
    return out


def _load() -> dict[str, str]:
    global _CACHE
    if _CACHE is None:
        try:
            with open(_DOC, encoding="utf-8") as fh:
                _CACHE = _parse(fh.read())
            logger.info("dlp_context: loaded %d per-actor justifications", len(_CACHE))
        except Exception as exc:
            logger.warning("dlp_context: could not read %s (%s) — per-actor "
                           "justifications unavailable", _DOC, exc)
            _CACHE = {}
    return _CACHE


def justification_for(user: str) -> str:
    """This actor's recorded business justification, or "" if none is on file."""
    u = _normalise(user)
    return _load().get(u, "") if u else ""
