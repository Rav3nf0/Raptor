"""Confidence calibration report — does the model's self-reported confidence mean what
the gates assume it means?

The 0.90 auto-close floor (EDRTriageConfig.autoclose_min_confidence) treats ai_confidence
as "probability this verdict is right". An LLM's self-reported confidence usually is not
that: DEMO-110937 was wrong at 0.95. This measures it against human outcomes, read-only.

Label and row rules — same scored set as /api/memory/shadow-stats, plus two carve-outs,
both REPORTED, never silently dropped:

  * Autonomous closes (autonomous_closed_at set) have no independent human verdict: the
    ticket's final status is the one RAPTOR set, so scoring it would be the model agreeing
    with itself. They are reported separately as closed / reopened, where the reopen is
    the overturn signal (see ShadowResult.autonomous_closed_at).
  * Gate-altered rows (a safety gate changed the verdict, pre_safety_class != final) may
    carry a gate-written confidence — _apply_safety_gates can set max(conf, 0.90), and
    the model's pre-gate confidence is not persisted. The primary table excludes them;
    they are counted and also shown folded in.
"""
from __future__ import annotations

from typing import Iterable

BUCKETS: list[tuple[float, float]] = [
    (0.0, 0.5), (0.5, 0.6), (0.6, 0.7), (0.7, 0.8), (0.8, 0.9), (0.9, 0.95), (0.95, 1.0001),
]
FLOORS = (0.80, 0.85, 0.90, 0.95)
LOW_N = 20


def _label(lo: float, hi: float) -> str:
    return f"{lo:.2f}-{min(hi, 1.0):.2f}"


def _acc(correct: int, n: int):
    return round(correct / n, 3) if n else None


def reliability(rows: list[dict]) -> dict:
    """Bucket rows by ai_confidence and compare stated confidence with actual accuracy.
    `gap` > 0 means over-confident (says more than it achieves)."""
    usable = [r for r in rows if isinstance(r.get("ai_confidence"), (int, float))]
    n = len(usable)
    buckets = []
    ece = 0.0
    for lo, hi in BUCKETS:
        b = [r for r in usable if lo <= r["ai_confidence"] < hi]
        if not b:
            continue
        ok = sum(1 for r in b if r["verdict_match"])
        mean_c = sum(r["ai_confidence"] for r in b) / len(b)
        acc = ok / len(b)
        ece += len(b) / n * abs(mean_c - acc)
        buckets.append({
            "range": _label(lo, hi), "n": len(b), "correct": ok,
            "accuracy": round(acc, 3), "mean_confidence": round(mean_c, 3),
            "gap": round(mean_c - acc, 3), "low_n": len(b) < LOW_N,
        })
    brier = (sum((r["ai_confidence"] - (1.0 if r["verdict_match"] else 0.0)) ** 2 for r in usable) / n
             if n else None)
    return {
        "n": n,
        "accuracy": _acc(sum(1 for r in usable if r["verdict_match"]), n),
        "mean_confidence": round(sum(r["ai_confidence"] for r in usable) / n, 3) if n else None,
        "ece": round(ece, 3) if n else None,
        "brier": round(brier, 3) if brier is not None else None,
        "missing_confidence": len(rows) - n,
        "buckets": buckets,
    }


def _gate_altered(r: dict) -> bool:
    pre = r.get("pre_safety_class") or ""
    return bool(pre) and pre != (r.get("ai_triage_class") or "")


def floor_table(rows: list[dict]) -> list[dict]:
    """For each candidate floor: of the AUTO_CLOSED_FP verdicts at or above it, how many
    did a human agree with? This is the direct read on "is 0.90 a safe place to close"."""
    fp = [r for r in rows if r.get("ai_triage_class") == "AUTO_CLOSED_FP"
          and isinstance(r.get("ai_confidence"), (int, float))]
    out = []
    for t in FLOORS:
        at = [r for r in fp if r["ai_confidence"] >= t]
        ok = sum(1 for r in at if r["verdict_match"])
        out.append({"floor": t, "fp_verdicts": len(at), "human_agreed": ok,
                    "precision": _acc(ok, len(at)), "low_n": len(at) < LOW_N})
    return out


def build_report(rows: Iterable[dict], is_autonomous=lambda name: False, min_family_n: int = 10) -> dict:
    rows = list(rows)
    auto = [r for r in rows if r.get("autonomous_closed_at")]
    human = [r for r in rows if not r.get("autonomous_closed_at")]
    altered = [r for r in human if _gate_altered(r)]
    clean = [r for r in human if not _gate_altered(r)]

    by_verdict = {}
    for cls in sorted({r.get("ai_triage_class") or "?" for r in clean}):
        rel = reliability([r for r in clean if (r.get("ai_triage_class") or "?") == cls])
        by_verdict[cls] = {k: rel[k] for k in ("n", "accuracy", "mean_confidence", "ece")}

    fams: dict[str, list[dict]] = {}
    for r in clean:
        fams.setdefault(r.get("alert_name") or "?", []).append(r)
    by_family = []
    for name, fr in fams.items():
        if len(fr) < min_family_n:
            continue
        rel = reliability(fr)
        by_family.append({
            "alert_name": name, "autonomous": bool(is_autonomous(name)),
            "n": rel["n"], "accuracy": rel["accuracy"],
            "mean_confidence": rel["mean_confidence"], "ece": rel["ece"],
            "gap": (round(rel["mean_confidence"] - rel["accuracy"], 3)
                    if rel["n"] else None),
            "fp_at_0_90": next(f for f in floor_table(fr) if f["floor"] == 0.90),
        })
    by_family.sort(key=lambda f: (-f["autonomous"], -f["n"]))

    reopened = sum(1 for r in auto if r.get("reopened_at"))
    return {
        "basis": ("scored = verdict_match set and ai_error empty (same as shadow-stats). "
                  "Primary table excludes autonomous closes (no independent human label) and "
                  "gate-altered verdicts (confidence may be gate-written); both are counted below."),
        "caveats": [
            "verdict_match credits warranted escalations, so NEEDS_L2 accuracy reads high.",
            "l2_triage_class copies L1 where L1 closed the ticket; one Sentinel incident can "
            "appear as several rows. Labels are noisy, not ground truth.",
            "Autonomous closes are excluded, so for autonomous families the rows above 0.90 "
            "are mostly pre-autonomy history.",
            "Buckets or families with low_n=true (<20 rows) are noise-level; do not act on them.",
            "Prompts, gates and temperature changed over time; compare windows with since_days.",
            "Descriptive only. Do not tune the floor to make this table look better.",
        ],
        "scored": len(rows),
        "primary": reliability(clean),
        "including_gate_altered": {k: v for k, v in reliability(human).items() if k != "buckets"},
        "gate_altered": {"n": len(altered),
                         "accuracy": _acc(sum(1 for r in altered if r["verdict_match"]), len(altered))},
        "autoclose_floor": floor_table(clean),
        "by_verdict": by_verdict,
        "by_family": by_family,
        "autonomous_closes": {
            "n": len(auto), "reopened": reopened,
            "reopen_rate": _acc(reopened, len(auto)),
            "note": "a reopen is disagreement; no reopen is not proof anyone checked",
        },
    }
