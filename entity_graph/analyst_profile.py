"""Per-analyst accuracy tracking — updated by the Jira closure poller.

Scope note: an analyst decision can only be scored where an INDEPENDENT ground
truth exists. In this system that is exclusively an L2 review of an L1-escalated
ticket. Direct L1 closes have no second opinion, so they are deliberately NOT
recorded — recording them would (and previously did) inflate accuracy to ~100%
because there was nothing to disagree with.

The metric captured here is therefore L1 **escalation precision**: of the tickets
an L1 escalated to L2, what fraction did L2 confirm as a true positive (i.e. the
escalation was warranted) vs. closed as a false positive (over-escalation).
"""
from __future__ import annotations

import logging
from datetime import datetime

from entity_graph.models import AnalystProfile

logger = logging.getLogger(__name__)


async def get_or_create_profile(analyst_id: str, display_name: str = "") -> AnalystProfile:
    profile = await AnalystProfile.find_one(AnalystProfile.analyst_id == analyst_id)
    if not profile:
        profile = AnalystProfile(analyst_id=analyst_id, display_name=display_name or analyst_id)
        await profile.insert()
    return profile


async def record_verdict(
    analyst_id: str,
    display_name: str,
    was_correct: bool,
) -> AnalystProfile:
    """Accumulate one ground-truth-scored outcome for an analyst.

    Only call this when an independent ground truth exists (see module docstring).
    The caller decides correctness; this just moves the counters and recomputes the
    trust tier. It never counts an unscoreable close as correct.
    """
    profile = await get_or_create_profile(analyst_id, display_name)
    profile.total_verdicts += 1
    profile.last_active = datetime.utcnow()
    if was_correct:
        profile.correct_verdicts += 1
    profile.update_accuracy()
    await profile.save()
    return profile
