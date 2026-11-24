"""A labelled record of what RAPTOR was given and what it decided, per ticket.

Why: everything RAPTOR learned was learned on Defender and Sentinel data. The EDR is due
to change (CrowdStrike, ~May 2027), and by then nobody closes tickets by hand, so there
will be no fresh human verdicts to check a reworked RAPTOR against. This corpus is that
check, taken while the verdicts still exist: the ticket, the alert and evidence exactly
as the playbooks and the agent received them, every tool call with its FULL result
(ShadowResult keeps only a summary), RAPTOR's outcome, and later the human's.

A refactor that moves RAPTOR off vendor field names must reproduce these outcomes from
these inputs; a replacement data source is judged against them. It cannot prove a new
vendor's queries return the right rows — only real access can.

Recorded on live runs only: a forced dry re-run reads enrichment that has aged out
(Defender keeps ~30 days) and would overwrite a good record with a thinner one.
Secrets are redacted and 12-digit ids masked before anything is stored. Never raises.

Size: at most `replay_corpus_per_family` records per alert family, but a record a human
called True Positive, sent to L2 or reopened is never dropped, and neither is one still
waiting for its human verdict.
"""
from __future__ import annotations

import json
import logging
import re
import time

logger = logging.getLogger(__name__)

COLLECTION = "edr_replay_corpus"
MAX_BLOB = 60_000          # characters per stored blob (one tool result, the evidence, ...)
MAX_TOOL_CALLS = 80
_LABEL_EVERY_SECONDS = 3600
_last_label = 0.0


def family(alert_name: str) -> str:
    """Reporting family, digits folded: one bucket per kind of alert."""
    from edr_triage.classifier import display_alert_family
    return re.sub(r"\d+", "#", display_alert_family(alert_name)).casefold()


def _blob(obj) -> str:
    """`obj` as redacted JSON text. Over MAX_BLOB it is cut and marked, never silently:
    a replay must be able to tell a short result from a shortened one."""
    from shadow_hunter.stories import clean
    try:
        # Redact the VALUES, then serialise: a secret pattern run over JSON text can eat
        # a closing quote and leave a record that no longer parses.
        s = json.dumps(clean(json.loads(json.dumps(obj, default=str))), ensure_ascii=False)
    except Exception as exc:
        s = json.dumps({"_unserialisable": str(exc)[:200]})
    if len(s) > MAX_BLOB:
        s = json.dumps({"_truncated": True, "chars": len(s), "head": s[:MAX_BLOB]})
    return s


def load(blob: str):
    """The stored object back. A truncated blob comes back as its marker dict."""
    return json.loads(blob) if blob else None


def build(*, jira_key: str, alert_name: str, source: str, playbook: str, ticket: dict,
          alert_data: dict, evidence: dict, sentinel_entities: dict, vt: dict,
          agent_inputs: dict, agent_result, result, action_taken: str) -> dict:
    """The record for one triage. Pure apart from redaction."""
    tool_calls = [{"name": tc.name, "args": _blob(tc.args), "result": _blob(tc.result)}
                  for tc in (getattr(agent_result, "tool_calls", None) or [])[:MAX_TOOL_CALLS]]
    agent = None
    if agent_result is not None:
        agent = {k: getattr(agent_result, k, None) for k in (
            "triage_class", "confidence", "iterations", "error", "pre_safety_class",
            "blocked_by_safety", "safety_block_reason", "safety_gate_kind")}
        agent["reasoning"] = _blob(getattr(agent_result, "reasoning", ""))
    return {
        "jira_key": jira_key, "alert_name": alert_name, "family": family(alert_name),
        "source": source, "playbook": playbook,
        "ticket": _blob(ticket), "alert_data": _blob(alert_data), "evidence": _blob(evidence),
        "sentinel_entities": _blob(sentinel_entities), "vt": _blob(vt),
        "agent_inputs": _blob(agent_inputs or {}),
        "tool_calls": tool_calls, "agent": agent,
        "outcome": {
            "triage_class": getattr(result, "triage_class", ""),
            "action_taken": action_taken,
            "labels": list(getattr(result, "labels", None) or []),
            "l1_comment": _blob(getattr(result, "l1_comment", "")),
            "l2_comment": _blob(getattr(result, "l2_comment", "")),
        },
    }


def _col():
    from lib.mongo import get_col
    col = get_col(COLLECTION)
    col.create_index("jira_key", unique=True)
    col.create_index([("family", 1), ("recorded_at", 1)])
    return col


def record(doc: dict) -> bool:
    """Store (or replace) the ticket's record. Human-verdict fields already on it stay."""
    try:
        _col().update_one({"jira_key": doc["jira_key"]},
                          {"$set": {**doc, "recorded_at": time.time()},
                           "$setOnInsert": {"labelled": False, "keep": False}}, upsert=True)
        return True
    except Exception as exc:
        logger.warning("replay_corpus: record(%s) failed: %s", doc.get("jira_key"), exc)
        return False


def verdict_fields(shadow) -> dict:
    """What a human decided, from the ticket's ShadowResult. `labelled` only once a person
    has given a final answer; `keep` for the records worth more than any cap. Pure."""
    from edr_triage.store import human_outcome
    final = getattr(shadow, "l2_triage_class", None)
    resolved = bool(final and getattr(shadow, "l2_resolved_at", None))
    reopened = bool(getattr(shadow, "reopened_at", None))
    to_l2 = bool(getattr(shadow, "l1_handoff_at", None))
    by_raptor = bool(getattr(shadow, "autonomous_closed_at", None))
    return {
        "human_outcome": human_outcome(shadow),
        "human_class": final or "",
        "handled_by_l2": to_l2,
        "closed_by_raptor": by_raptor,
        # A RAPTOR close nobody reviewed is not a human verdict (store.human_outcome).
        "labelled": reopened or (resolved and not by_raptor) or (resolved and final == "AUTO_CLOSED_TP"),
        "keep": reopened or to_l2 or final in ("AUTO_CLOSED_TP", "URGENT"),
    }


async def label_pending(limit: int = 500) -> int:
    """Copy human verdicts onto records that lack one. Returns how many were updated."""
    try:
        from beanie.operators import In
        from entity_graph.models import ShadowResult
        col = _col()
        keys = [d["jira_key"] for d in col.find({"labelled": {"$ne": True}}, {"jira_key": 1})
                .sort("recorded_at", 1).limit(limit)]
        if not keys:
            return 0
        rows = await ShadowResult.find(In(ShadowResult.jira_key, keys)) \
            .sort(-ShadowResult.created_at).to_list()
        newest: dict = {}
        for r in rows:
            newest.setdefault(r.jira_key, r)
        n = 0
        for key, sr in newest.items():
            f = verdict_fields(sr)
            if f["labelled"] or f["keep"]:
                col.update_one({"jira_key": key}, {"$set": f})
                n += 1
        return n
    except Exception as exc:
        logger.warning("replay_corpus: label_pending failed: %s", exc)
        return 0


def droppable(rows: list[dict], cap: int) -> list[str]:
    """Keys to drop so a family holds at most `cap` records: oldest first, and only
    records with a final human verdict that is not worth keeping. Pure."""
    extra = len(rows) - cap
    if extra <= 0:
        return []
    ok = sorted((r for r in rows if r.get("labelled") and not r.get("keep")),
                key=lambda r: r.get("recorded_at") or 0)
    return [r["jira_key"] for r in ok[:extra]]


def prune(fam: str, cap: int) -> int:
    try:
        col = _col()
        rows = list(col.find({"family": fam},
                             {"jira_key": 1, "labelled": 1, "keep": 1, "recorded_at": 1}))
        drop = droppable(rows, cap)
        if drop:
            col.delete_many({"jira_key": {"$in": drop}})
        return len(drop)
    except Exception as exc:
        logger.warning("replay_corpus: prune(%s) failed: %s", fam, exc)
        return 0


async def capture(cfg, dry_run: bool, **parts) -> None:
    """Called once per triaged ticket, after its outcome is known. Never raises."""
    global _last_label
    try:
        cap = int(getattr(cfg, "replay_corpus_per_family", 0) or 0)
        if cap <= 0 or dry_run:
            return
        doc = build(**parts)
        if not record(doc):
            return
        if time.time() - _last_label > _LABEL_EVERY_SECONDS:
            _last_label = time.time()
            await label_pending()
        prune(doc["family"], cap)
    except Exception as exc:
        logger.warning("replay_corpus: capture(%s) failed: %s", parts.get("jira_key"), exc)


async def report() -> dict:
    """Per family: records held, how many carry a human verdict, and what the verdicts were."""
    from collections import Counter, defaultdict
    await label_pending(limit=2000)
    fams: dict = defaultdict(lambda: {"records": 0, "labelled": 0, "kept": 0, "with_agent": 0,
                                      "human": Counter(), "oldest": None})
    total = 0
    for d in _col().find({}, {"family": 1, "labelled": 1, "keep": 1, "human_class": 1,
                              "handled_by_l2": 1, "agent.triage_class": 1, "recorded_at": 1}):
        f = fams[d.get("family") or "?"]
        total += 1
        f["records"] += 1
        f["labelled"] += bool(d.get("labelled"))
        f["kept"] += bool(d.get("keep"))
        f["with_agent"] += bool((d.get("agent") or {}).get("triage_class"))
        if d.get("labelled"):
            f["human"][("L2: " if d.get("handled_by_l2") else "") + (d.get("human_class") or "reopened")] += 1
        t = d.get("recorded_at")
        f["oldest"] = t if f["oldest"] is None else min(f["oldest"], t or f["oldest"])
    out = [{"family": k, **{**v, "human": dict(v["human"])}} for k, v in fams.items()]
    out.sort(key=lambda r: -r["records"])
    return {"total": total, "labelled": sum(r["labelled"] for r in out),
            "families": len(out), "by_family": out}
