"""Side-by-side: the in-app Mistral agent vs Claude's manual verdicts on the same findings.

Question (2026-10-26): is the Bedrock model already in place (Mistral Large 3 on Mantle) good
enough for /shadow suggestions, or is Claude needed? The Claude Code passes left verdicts on
real findings (ai_by=claude-code-manual), and analysts decided some of them. This re-runs the
production agent — same prompt, tools, precedents, rules, temperature 0, step and time caps —
on those findings with the Mistral backend, and stores its answer in `shadow_ai_compare`
WITHOUT touching the finding: Claude's suggestion stays what analysts see.

Selection: findings an analyst decided (ground truth) first, then the ones Claude did not
call FP (where a miss would hurt), then the rest; at most `limit`, paced like the job,
because hunts share the MDE quota with RAPTOR.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

COLL = "shadow_ai_compare"
CLAUDE_BY = "claude-code-manual"
MAX_LIMIT = 60


def _db():
    from shadow_hunter.models import Finding
    return Finding.get_pymongo_collection().database


async def pick(limit: int) -> list[str]:
    """A stratified sample: a third analyst-decided (ground truth), a third Claude TP/unsure
    (where a model miss hurts), a third Claude FP; each spread across detectors round-robin,
    so one big incident (DART: 24 confirmed encoded-PowerShell TPs) cannot fill the run."""
    from shadow_hunter.models import Finding
    rows = await Finding.get_pymongo_collection().find(
        {"ai_by": CLAUDE_BY, "ai_verdict": {"$in": ["true_positive", "false_positive", "unsure"]}},
        {"_id": 1, "decision": 1, "ai_verdict": 1, "severity": 1, "detector": 1, "ai_at": 1}).to_list(length=5000)
    sev = {"critical": 0, "high": 1, "medium": 2}
    rows.sort(key=lambda r: (sev.get(r.get("severity"), 3), str(r.get("ai_at") or "")))
    buckets = [[r for r in rows if r.get("decision") in ("true_positive", "false_positive")],
               [r for r in rows if r.get("decision") not in ("true_positive", "false_positive")
                and r.get("ai_verdict") != "false_positive"],
               [r for r in rows if r.get("decision") not in ("true_positive", "false_positive")
                and r.get("ai_verdict") == "false_positive"]]

    def spread(rs):
        by: dict = {}
        for r in rs:
            by.setdefault(r.get("detector"), []).append(r)
        out, i = [], 0
        while any(i < len(v) for v in by.values()):
            out += [v[i] for v in by.values() if i < len(v)]
            i += 1
        return out
    queues = [spread(b) for b in buckets]
    share = [limit // 3, limit // 3, limit - 2 * (limit // 3)]
    picked = [r for q, n in zip(queues, share) for r in q[:n]]
    rest = [r for q, n in zip(queues, share) for r in q[n:]]
    picked += rest[:limit - len(picked)]                 # a short bucket's room goes to the others
    return [r["_id"] for r in picked]


async def run(run_id: str, limit: int = 40, backend=None, tools=None, execute=None, pace_s: float | None = None,
              engine: str = "mistral", output: str = "short", opus=None) -> dict:
    """Judge up to `limit` Claude-judged findings with the Mistral agent; one row per finding."""
    from agent_core.backend import get_internal_backend
    from shadow_hunter import ai_triage as T
    if tools is None or execute is None:
        import agent_tools.abuseipdb  # noqa: F401  (registers tools)
        import agent_tools.hunt  # noqa: F401
        import agent_tools.upwind  # noqa: F401
        import agent_tools.virustotal  # noqa: F401
        from agent_tools.registry import execute as _execute, get_tools
        tools, execute = get_tools(set(T.SHADOW_TOOLS)), _execute
    backend = backend or get_internal_backend()          # Mistral on Mantle, whatever SHADOW_LLM says
    model = getattr(backend, "model_id", type(backend).__name__)
    if engine == "review":
        model = f"review({output}): {model} gathers, Opus decides"
    coll = _db()[COLL]
    pace = T.PACE_S if pace_s is None else pace_s
    seen = {r["finding_id"] for r in await coll.find({"run": run_id, "finding_id": {"$exists": True}},
                                                     {"finding_id": 1}).to_list(length=MAX_LIMIT + 10)}
    ids = [i for i in await pick(max(1, min(limit, MAX_LIMIT))) if i not in seen]   # resume skips judged ones
    await status(run_id, "running", picked=len(ids) + len(seen), resumed_after=len(seen))
    done = 0
    try:
        for fid in ids:
            try:
                if engine == "review":
                    done += await _one_review(run_id, fid, backend, tools, execute, model, coll, output, opus)
                else:
                    done += await _one(run_id, fid, backend, tools, execute, model, coll)
            except Exception as exc:              # one bad finding must not end the run (2026-10-26: stalled at 6)
                logger.exception("[ai_compare] %s failed", fid)
                await coll.replace_one({"_id": f"{run_id}:{fid}"}, {"run": run_id, "finding_id": fid, "detector": "?",
                                       "severity": "", "summary": "", "human": "", "claude": {"verdict": "", "confidence": None,
                                       "reasoning": ""}, "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                                       "at": datetime.now(timezone.utc)}, upsert=True)
            await status(run_id, "running", judged=len(seen) + done)
            await asyncio.sleep(pace)
    except BaseException as exc:
        await status(run_id, "failed", error=f"{type(exc).__name__}: {str(exc)[:200]}")
        raise
    await status(run_id, "done", judged=len(seen) + done)
    return {"run": run_id, "judged": done, "resumed_after": len(seen)}


async def status(run_id: str, state: str, **kw) -> None:
    await _db()[COLL].update_one({"_id": f"{run_id}:_status"},
                                 {"$set": {"run": run_id, "state": state, "updated": datetime.now(timezone.utc), **kw}},
                                 upsert=True)


async def _one(run_id, fid, backend, tools, execute, model, coll) -> int:
    from agent_core.backend import temperature_override
    from shadow_hunter import ai_triage as T
    from shadow_hunter.models import Finding
    f = await Finding.get(fid)
    if not f:
        return 0
    row = {"run": run_id, "finding_id": f.id, "detector": f.detector, "severity": f.severity,
           "summary": (f.summary or f.indicator or "")[:200], "human": f.decision or "",
           "claude": {"verdict": f.ai_verdict, "confidence": f.ai_confidence, "reasoning": (f.ai_reasoning or "")[:600]},
           "mistral_model": model, "at": datetime.now(timezone.utc)}
    try:
        with temperature_override(0.0):
            v = await asyncio.wait_for(
                T.triage_one(f, backend=backend, tools=tools, execute=execute,
                             precedents=await T.precedents_for(f), rules=await T.rules_for(f.detector)),
                timeout=T.PER_FINDING_TIMEOUT_S)
        row["mistral"] = {"verdict": v["verdict"], "confidence": v["confidence"],
                          "reasoning": (v["reasoning"] or "")[:600], "tool_calls": v["tool_calls"]}
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    await coll.replace_one({"_id": f"{run_id}:{f.id}"}, row, upsert=True)
    return 1


async def _one_review(run_id, fid, backend, tools, execute, model, coll, output, opus) -> int:
    """The grouped-review pipeline on one finding (a group of one), nothing recorded on it.
    Its decision is stored under "mistral" so the summary compares it with Claude the same way."""
    from agent_core.backend import get_shadow_backend
    from shadow_hunter import ai_review as R
    from shadow_hunter.models import Finding
    f = await Finding.get(fid)
    if not f:
        return 0
    row = {"run": run_id, "finding_id": f.id, "detector": f.detector, "severity": f.severity,
           "summary": (f.summary or f.indicator or "")[:200], "human": f.decision or "",
           "claude": {"verdict": f.ai_verdict, "confidence": f.ai_confidence, "reasoning": (f.ai_reasoning or "")[:600]},
           "mistral_model": model, "at": datetime.now(timezone.utc)}
    try:
        gathered = await R.gather([f], backend, tools, execute)
        o = opus or get_shadow_backend(thinking=R.urgent([f]))
        if hasattr(o, "cache_system"):
            o.cache_system = True
        dec = (await R.decide([("g1", [f], gathered)], o, output, execute)).get("g1")
        if not dec:
            raise ValueError("no decision in the reply")
        row["mistral"] = {"verdict": dec["verdict"], "confidence": dec.get("confidence"),
                          "reasoning": str(dec.get("reasoning", ""))[:600],
                          "tool_calls": [c["tool"] for c in gathered["log"]] + dec.get("_checks", []),
                          "checklist": dec.get("checklist"), "gatherer_verdict": (gathered.get("verdict") or {}).get("verdict")}
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    await coll.replace_one({"_id": f"{run_id}:{f.id}"}, row, upsert=True)
    return 1


def summarize(rows: list[dict]) -> dict:
    """Agreement with Claude and with analysts, and the disagreements that matter: Mistral
    calling FP where Claude saw a threat or was unsure (a miss), or an analyst said TP."""
    ok = [r for r in rows if r.get("mistral")]
    pair = lambda r: (r["claude"]["verdict"], r["mistral"]["verdict"])
    matrix: dict = {}
    for r in ok:
        k = f"claude {pair(r)[0]} / mistral {pair(r)[1]}"
        matrix[k] = matrix.get(k, 0) + 1
    agree = sum(1 for r in ok if pair(r)[0] == pair(r)[1])
    human = [r for r in ok if r.get("human") in ("true_positive", "false_positive")]
    risky = [r for r in ok if r["mistral"]["verdict"] == "false_positive"
             and (r["claude"]["verdict"] != "false_positive" or r.get("human") == "true_positive")]
    by_det: dict = {}
    for r in ok:
        d = by_det.setdefault(r["detector"], {"n": 0, "agree": 0})
        d["n"] += 1
        d["agree"] += pair(r)[0] == pair(r)[1]
    return {
        "judged": len(rows), "errors": len(rows) - len(ok),
        "agree_with_claude": agree, "agreement_rate": round(agree / len(ok), 3) if ok else None,
        "matrix": dict(sorted(matrix.items(), key=lambda kv: -kv[1])),
        "human_decided": len(human),
        "claude_matches_human": sum(1 for r in human if r["claude"]["verdict"] == r["human"]),
        "mistral_matches_human": sum(1 for r in human if r["mistral"]["verdict"] == r["human"]),
        "mistral_fp_where_claude_or_human_did_not": len(risky),
        "by_detector": by_det,
        "risky": [{k: r.get(k) for k in ("finding_id", "detector", "severity", "summary", "human", "claude", "mistral")}
                  for r in risky],
    }


async def results(run_id: str) -> dict:
    st = await _db()[COLL].find_one({"_id": f"{run_id}:_status"}) or {}
    st.pop("_id", None)
    rows = await _db()[COLL].find({"run": run_id, "finding_id": {"$exists": True}}).sort("at", 1).to_list(length=MAX_LIMIT + 10)
    for r in rows:
        r.pop("_id", None)
        if isinstance(r.get("at"), datetime):
            r["at"] = r["at"].isoformat()
    if isinstance(st.get("updated"), datetime):
        st["updated"] = st["updated"].isoformat()
    return {"run": run_id, "status": st, **summarize(rows), "rows": rows}


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M") + "-" + uuid.uuid4().hex[:6]
