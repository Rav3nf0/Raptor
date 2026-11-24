"""Who may do what: three roles, admin, analyst and viewer.

Every role can view every page (GET/HEAD). Viewers (e.g. leadership) change
nothing except signing themselves out. Any other state-changing request is
ADMIN-ONLY unless it matches ANALYST_ALLOWED below, so a route added later
starts out admin-only until someone decides otherwise.

Analysts do day-to-day triage and investigation. Admins also own whatever changes
how RAPTOR decides or closes (rules, memory, suggestions, planned activity,
allowlists, paging, autonomy settings), bulk or destructive operations, resets,
and batch runs that spend shared quota (MDE hunts, LLM budget).
"""
from __future__ import annotations

import re

ADMIN = "admin"
ANALYST = "analyst"
VIEWER = "viewer"
ROLES = (ADMIN, ANALYST, VIEWER)

_READ_METHODS = {"GET", "HEAD", "OPTIONS"}

# (method, full-path regex). Keep each line's reason; review when adding one.
ANALYST_ALLOWED: list[tuple[str, str]] = [
    ("POST", r"/logout"),
    # Investigation helpers: compute and return, change nothing
    ("POST", r"/correlate"),
    ("POST", r"/policy/evaluate"),
    ("POST", r"/risk/score"),
    ("POST", r"/analyze/threat"),
    # Pulling intel in
    ("POST", r"/ingest/stix"),
    ("POST", r"/ingest/poll/(cyble|otx)"),
    # Brand intel: scan and raise a takedown ticket
    ("POST", r"/brand-intel/run"),
    ("POST", r"/brand-intel/raise-ticket/.+"),
    ("POST", r"/brand-intel/webhook/jira"),
    ("POST", r"/brand-intel/(takedowns/sync|watchlist/sync-takedowns)"),
    # Audit log export (read-only, bulk)
    ("POST", r"/events/export"),
    # RAPTOR: re-triage one ticket, ask for an AI analysis, rescore one ticket
    ("POST", r"/api/edr-triage/run-ticket/[^/]+"),
    ("POST", r"/api/edr-triage/suggestions/analyze"),
    ("POST", r"/api/memory/rescore/[^/]+"),
    # Quarantine review. Promote is recorded under the analyst's name; arming an
    # auto-close with it (auto_fp) is refused in the handler unless admin.
    ("POST", r"/api/memory/quarantine/[^/]+/(flag|promote|dismiss)"),
    # Suggestions: dismissing never arms anything (approve/arm stay admin)
    ("POST", r"/api/edr-triage/suggestions/[^/]+/dismiss"),
    ("POST", r"/api/memory/suggestions/[^/]+/dismiss"),
    # Planned-activity windows, recorded under the analyst's name
    ("POST", r"/api/memory/planned-activity"),
    ("DELETE", r"/api/memory/planned-activity/[^/]+"),
    # Operational: closure-poller sweep, mark an alert type's observations reviewed
    ("POST", r"/api/memory/poll-now"),
    ("POST", r"/api/edr-triage/observations/review"),
    # /shadow: decide findings, run one hunt, work stories and reports
    ("POST", r"/api/shadow/findings/[^/]+/(decision|ai-verdict)"),
    ("POST", r"/api/shadow/hunt/run-one"),
    # An environment-note PROPOSAL never reaches the AI prompt; approving one is admin-only
    ("POST", r"/api/shadow/env-notes/propose"),
    ("POST", r"/api/shadow/stories/[^/]+/(indicators|indicators/remove|report|report/preview"
             r"|report/request|context/refresh|detach|merge|close|reopen)"),
]

_COMPILED = [(m, re.compile(p + r"/?")) for m, p in ANALYST_ALLOWED]


def allowed(role: str, method: str, path: str) -> bool:
    method = method.upper()
    if role == ADMIN or method in _READ_METHODS:
        return role in ROLES
    if role == VIEWER:
        return method == "POST" and path == "/logout"
    if role != ANALYST:
        return False
    return any(m == method and rx.fullmatch(path) for m, rx in _COMPILED)
