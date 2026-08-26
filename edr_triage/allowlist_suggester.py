"""Actor-allowlist suggestions queue — propose-only.

Mines resolved shadow results for the dominant failure mode behind low AI-vs-human
agreement: OSCAR escalates an alert to NEEDS_L2 while the human repeatedly closes
it as FALSE POSITIVE for the SAME actor (+device, +commands). Each such cluster is
surfaced as an AllowlistSuggestion for an L2 to review.

This is DETERMINISTIC — pure clustering, no LLM call, no network. Suggestions are
NEVER auto-applied: an L2 clicks "Arm" in the AI Memory UI, which writes a golden
auto_fp memory (entity_graph.memory.create_allowlist_memory). Only then does the
pipeline short-circuit start auto-closing that pattern.

Why actor-scoped and not type-wide: the two biggest over-escalation buckets
(root privilege escalation, PowerShell-in-memory) are genuinely risky in general
but benign for specific known-good actors/devices/commands. Pinning the pattern to
the exact principal keeps unknown actors escalating while the vetted ones auto-close.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from entity_graph.models import ShadowResult, AllowlistSuggestion

logger = logging.getLogger(__name__)

# Human verdict that marks an FP closure, and the AI verdict we're trying to fix.
_HUMAN_FP = "AUTO_CLOSED_FP"
_AI_OVERESCALATE = "NEEDS_L2"


def _human_verdict(s: ShadowResult) -> str:
    return (s.l2_triage_class or s.l1_triage_class or "").strip()


def _alert_type(alert_name: str) -> str:
    """The key an armed entry is scoped to — the LEARNING subtype, not the playbook name.

    Must stay identical to what the matcher passes to match_actor_allowlist (pipeline),
    or an armed entry never fires. alert_subtype falls back to classify(), so for every
    pre-existing alert class this returns exactly what it always did.
    """
    try:
        from edr_triage.classifier import alert_subtype
        return alert_subtype(alert_name)
    except Exception:
        return "generic"


def _common_commands(rows: list[ShadowResult]) -> list[str]:
    """Commands to pin on the armed entry — the intersection of normalized
    processes across the cluster. Returns [] (command-agnostic) unless EVERY row
    carries processes and they share a common non-empty set; a single FP closure
    with no captured process means we can't claim the pattern is command-specific.
    """
    proc_sets = [set(r.alert_processes or []) for r in rows]
    if not proc_sets or not all(proc_sets):
        return []
    common = set.intersection(*proc_sets)
    return sorted(common)


async def analyze_fp_clusters(lookback_days: int = 90, min_count: int = 3) -> dict:
    # 90d, not 30d: a genuinely recurring benign pattern can be slower than monthly and
    # was being missed entirely. Measured — Conditional Access for one identity admin has
    # 5 FP closures Apr–Aug, but only 2 fall inside 30 days, so min_count=3 never tripped
    # and the queue stayed empty on the clearest candidate in the data. Widening the
    # window costs nothing in safety: suggestions are propose-only and an L2 still arms.
    """Scan resolved shadow results for repeated same-actor FP closures OSCAR
    over-escalated, and queue AllowlistSuggestion rows for L2 review.

    Returns a summary dict. Writes nothing to the allowlist itself — only pending
    suggestions. Idempotent per (alert_type, actor, device): one open suggestion
    per cluster at a time.
    """
    cutoff = datetime.utcnow() - timedelta(days=lookback_days)
    rows = await ShadowResult.find(
        ShadowResult.verdict_match == False,  # noqa: E712  (Beanie needs ==)
        ShadowResult.created_at >= cutoff,
        ShadowResult.ai_error == None,  # noqa: E711 — skip agent-failure (outage) shadows
    ).to_list()

    # Keep only the fixable over-escalations: human closed FP, AI said NEEDS_L2,
    # and there's an actor to pin the allowlist to.
    clusters: dict[tuple[str, str, str], list[ShadowResult]] = defaultdict(list)
    for s in rows:
        if _human_verdict(s) != _HUMAN_FP:
            continue
        if (s.ai_triage_class or "") != _AI_OVERESCALATE:
            continue
        actor = (s.user_name or "").strip().lower()
        if not actor:
            continue  # no principal → can't arm the actor-allowlist (by design)
        device = (s.device_name or "").strip().lower()
        clusters[(_alert_type(s.alert_name), actor, device)].append(s)

    created, skipped = [], []
    for (alert_type, actor, device), group in clusters.items():
        if len(group) < min_count:
            continue
        cluster_key = f"{alert_type}|{actor}|{device}"

        # Dedupe — one open (pending or already-armed) suggestion per cluster.
        existing = await AllowlistSuggestion.find_one(
            AllowlistSuggestion.cluster_key == cluster_key,
            AllowlistSuggestion.status != "dismissed",
        )
        if existing:
            skipped.append(cluster_key)
            continue

        alert_name = Counter(s.alert_name for s in group).most_common(1)[0][0]
        sugg = AllowlistSuggestion(
            alert_type=alert_type,
            alert_name=alert_name,
            actor=actor,
            device=device,
            commands=_common_commands(group),
            fp_count=len(group),
            evidence_jira_keys=[s.jira_key for s in group][:20],
            cluster_key=cluster_key,
        )
        await sugg.insert()
        created.append({"alert_type": alert_type, "actor": actor,
                        "device": device or "any", "count": len(group)})
        logger.info("[ALLOWLIST-SUGGEST] queued %s — %d FP closures by %s%s",
                    alert_type, len(group), actor, f" on {device}" if device else "")

    return {
        "lookback_days": lookback_days,
        "min_count": min_count,
        "mismatches_scanned": len(rows),
        "suggestions_created": len(created),
        "created": created,
        "skipped_existing": skipped,
    }
