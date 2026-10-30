"""ReAct loop — Think → Act → Observe until final_verdict or max_iterations.

Accepts optional prefetched_context to reuse data already fetched by the
existing pipeline (shadow mode — avoids double API calls).
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from agent_core.backend import LLMBackend, ToolCall
from agent_core.result import AgentResult, ToolCallRecord, normalize_action
from agent_core import oscar as oscar_module
from agent_core import critic as _critic

logger = logging.getLogger(__name__)

# (event, message, details) -> None/awaitable. Optional everywhere it's threaded
# through (run(), _process_ticket(), _run_ticket_bg()) — every existing caller passes
# nothing and gets identical behavior; only the manual run-ticket endpoint's
# stream_progress=true path constructs one.
ProgressCallback = Callable[[str, str, dict], Awaitable[None]]

_MAX_ITER = 10
_FAIL_RETRY_LIMIT = 2
# How many times a verdict that arrives with ZERO investigative tool calls is
# rejected and sent back for investigation before we accept it (and let the
# safety backstop downgrade any auto-close). Keeps empty-entity alerts from
# looping while forcing a real investigation floor in the common case.
_EVIDENCE_GATE_LIMIT = 2
# Same idea, scoped to the multi-host rule: a verdict that skips a named co-host's
# hunt is rejected and re-prompted this many times before the hard gate in
# _apply_safety_gates just escalates it. Gives the model a real chance to close the
# gap on THIS run instead of the ticket needing a whole separate re-triage.
_MULTIHOST_GATE_LIMIT = 2
# A verdict whose text is corrupted (stray foreign-script runs no alert or tool result
# contains — _garbled_reasoning) is discarded and asked for again this many times before
# the garbled_output gate escalates it. The corruption is a decoding fault, not a
# judgement: DEMO-118611 read "kam-margin-calc-eqq-prod", "oakley.das stemming@",
# "madhus لاحق.kv@" and "≥ 00.80" in one response, and went to L2 on that alone.
_GARBLE_RETRY_LIMIT = 1
# Same idea again, for the concurrency check: an auto-close that never called
# scg_check_concurrent_alerts is rejected and re-prompted this many times before
# the hard gate in _apply_safety_gates escalates it.
_CONCURRENCY_GATE_LIMIT = 2
# One chance to verify, or withdraw, checks a close cites but never ran.
_CLAIM_VERIFY_LIMIT = 1
_SOURCE_EMPTY_RETRY_LIMIT = 2
# Measured on this tenant (edr_triage/blank_retriage.py): DeviceEvents/PowerShellCommand
# rows for a "PowerShell script loaded in memory" alert land 26-28 minutes after the
# event. A blank-bound instance of this alert (no device, no command at read time)
# triaged before that window closes cannot possibly have the real row yet — any
# fleet-wide hunt result is necessarily OTHER, unrelated activity. 35 matches
# blank_retriage.MIN_AGE_MINUTES so both paths agree on when evidence is trustworthy.
_BLANK_BOUND_LAG_MINUTES = 35

_FINAL_VERDICT_RE = re.compile(
    r"<final_verdict>\s*(\{.*?})\s*</final_verdict>",
    re.DOTALL | re.IGNORECASE,
)

_TRIAGE_CLASSES = frozenset([
    "AUTO_CLOSED_FP", "AUTO_CLOSED_TP", "NEEDS_L2", "REQUEST_JUSTIFICATION", "URGENT",
])


# Which tool schemas each alert family is SHOWN, baked in so it applies without any
# env config. Derived from measured usage, not guessed: over 174 Netskope DLP runs on
# 2026-09-02 the agent called exactly these five and nothing else. Other families are
# absent from this map and therefore untouched — they were measured using 19 of the 29,
# so there is no safe trim for them yet.
#
# `mde_advanced_hunt` is here despite appearing only ONCE in those 174 runs. Keeping the
# rare one costs ~440 tokens; dropping it risks the run that actually needed it.
_DEFAULT_TOOL_ADVERTISING: dict[str, set[str]] = {
    "netskope_dlp": {
        "scg_get_entity_context",
        "scg_check_concurrent_alerts",
        "sentinel_run_kql",
        "hunt_query",
        "mde_advanced_hunt",
    },
}


def advertised_tools_for(alert_type: str, alert_name: str = "") -> set[str] | None:
    """Which tool schemas to advertise for this alert family, or None for all of them.

    Resolve the family from alert_name FIRST via memory_alert_type, exactly as the
    precedent lookup below does. `alert_type` is the routing/backend key from
    classifier.classify, and it is too COARSE here: classify("Netskope DLP Alerts")
    returns "netskope", which is shared with Netskope malware and UBA — families
    measured using 19 of the 29 tools. Keying the trim on "netskope" would starve them;
    keying it on "netskope_dlp" and passing the coarse value (the first version of this)
    matched nothing at all and silently advertised everything.

    Cost, not capability. The 29 registered schemas serialise to ~7,300 tokens and are
    re-sent on every iteration; measured 2026-09-02, input is 97% of token spend at
    ~12,900 tokens per call against ~430 out. On Netskope DLP — 82% of all traffic — the
    agent called only 5 distinct tools across 174 runs, so 24 schemas were pure waste.
    Trimming DLP to its own five takes a call to ~6,900 tokens (-47%), which is roughly
    $78/month -> $48/month at observed volume.

    Resolution order:
      1. AGENT_TOOL_ALLOWLIST_DISABLED=true  -> advertise everything, for every family
      2. AGENT_TOOL_ALLOWLIST names this family -> use that
      3. _DEFAULT_TOOL_ADVERTISING names it -> use that (the shipped default)
      4. otherwise -> advertise everything

    Both env hooks exist so this can be widened, narrowed or switched off entirely
    without a deploy, matching edr_triage.classifier.is_deterministic_only:

        AGENT_TOOL_ALLOWLIST="netskope_dlp:scg_get_entity_context,sentinel_run_kql"
        AGENT_TOOL_ALLOWLIST="fam_a:t1,t2;fam_b:t3"      # ';' separates families
        AGENT_TOOL_ALLOWLIST_DISABLED=true               # kill switch

    Returning a set only narrows what the model is SHOWN. get_tool_names/execute stay
    unfiltered, so an unadvertised tool still runs if the model names it — usage has a
    long tail and trading a correct verdict for tokens would be a bad deal.
    """
    import os as _os
    if (_os.getenv("AGENT_TOOL_ALLOWLIST_DISABLED", "").lower() == "true"):
        return None
    # Narrow family first, coarse routing key only as a fallback.
    _fam = ""
    if (alert_name or "").strip():
        try:
            from edr_triage.classifier import memory_alert_type as _mem_type
            _fam = _mem_type(alert_name) or ""
        except Exception:
            _fam = ""
        if _fam == "skip":
            _fam = ""
    want = (_fam or alert_type or "").strip().casefold()
    if not want:
        return None

    raw = (_os.getenv("AGENT_TOOL_ALLOWLIST") or "").strip()
    for group in raw.split(";") if raw else []:
        fam, _, names = group.partition(":")
        if fam.strip().casefold() != want:
            continue
        allow = {n.strip() for n in names.split(",") if n.strip()}
        if not allow:
            # "family:" with nothing after it is a config slip, not an instruction to
            # advertise zero tools — that would leave the agent unable to investigate.
            logger.warning("AGENT_TOOL_ALLOWLIST names %r with no tools — advertising "
                           "all tools for it", fam.strip())
            return None
        return allow

    return _DEFAULT_TOOL_ADVERTISING.get(want)
    return None


async def run(
    jira_key: str,
    alert: dict,
    alert_name: str,
    severity: str,
    device_name: str,
    user_name: str,
    sha256: str,
    inv_state: str,
    tactics: list[str],
    incident_url: str,
    is_test_device: bool,
    backend: LLMBackend,
    prefetched_context: Optional[dict] = None,
    max_iter: int = _MAX_ITER,
    alert_type: str = "",
    evidence: Optional[dict] = None,
    source: str = "",
    progress_cb: Optional[ProgressCallback] = None,
) -> AgentResult:
    """Run the ReAct investigation loop. Returns AgentResult.

    `progress_cb`, when given, is awaited with (event, message, details) at each
    iteration boundary and once more with the final verdict — purely for a live
    "watch it work" view (see app/views/edr_triage_views.py's stream_progress path).
    Never awaited when None, so every existing caller is completely unaffected.
    """
    async def _notify(event: str, message: str, details: Optional[dict] = None) -> None:
        if progress_cb:
            try:
                await progress_cb(event, message, details or {})
            except Exception:
                logger.debug("progress_cb failed for %s — ignoring (never fatal to the run)", jira_key)

    await _notify("investigation_started", f"Starting investigation of {alert_name or jira_key}",
                  {"alert_name": alert_name, "severity": severity, "device_name": device_name,
                   "user_name": user_name})

    import agent_tools.virustotal  # noqa: ensure tools are registered
    import agent_tools.abuseipdb   # noqa
    import agent_tools.mde         # noqa
    import agent_tools.sentinel    # noqa
    import agent_tools.hunt        # noqa: deterministic hunt_* builders (primary hunt path)
    import agent_tools.scg         # noqa
    import agent_tools.jira        # noqa
    import agent_tools.kql_generator  # noqa
    import agent_tools.vuln_check  # noqa
    import agent_tools.upwind      # noqa: read-only Upwind mirror (upwind_asset/threats/vulns)
    import agent_tools.vlogs       # noqa: read-only VictoriaLogs edge/EKS/RDS context (hunt_vlogs)
    from agent_tools.registry import execute, get_tools, get_tool_names

    # Sanitizer: active only for GeminiBackend (external LLM).
    # Strips device/user names and infra identifiers before they reach Gemini,
    # then restores tokens before executing tool calls so lookups still work.
    from agent_core.backend import GeminiBackend
    from agent_core.sanitize import AlertSanitizer
    sanitizer = AlertSanitizer(device_name=device_name, user_name=user_name) \
        if isinstance(backend, GeminiBackend) else None

    # Fetch SCG context for entities in this alert
    scg_context = ""
    try:
        from entity_graph.query import get_multi_entity_context
        entities = []
        if device_name:
            entities.append(("device", device_name))
        if user_name:
            entities.append(("user", user_name))
        if sha256:
            entities.append(("hash", sha256))
        # alert_type/device/user describe THIS alert — used only to decide whether a
        # stored business justification still applies to it (see _justification_applies).
        scg_context = await get_multi_entity_context(
            entities, alert_type=alert_type, device_name=device_name, user_name=user_name,
            alert_name=alert_name)
    except Exception as exc:
        logger.warning("SCG context fetch failed: %s", exc)

    # Bounded, curated-only alert-type precedents — surfaces how L1 handled this
    # class of alert before (incl. entity-less memories that entity recall misses).
    try:
        from entity_graph.query import get_playbook_precedents_block
        # Memory bucket, not the routing/backend one: for a family whose memories are
        # filed under a narrower key than its playbook name (currently Netskope DLP —
        # see edr_triage.classifier.memory_alert_type), looking up `alert_type` would
        # miss its own precedents entirely. Falls back to alert_type for every other
        # family, so no existing lookup changes. `alert_type` itself is left alone
        # because it also selects the LLM backend downstream.
        try:
            from edr_triage.classifier import memory_alert_type as _mem_type
            _prec_type = _mem_type(alert_name) or alert_type
        except Exception:
            _prec_type = alert_type
        _prec = await get_playbook_precedents_block(
            _prec_type, exclude_jira=jira_key, limit=3,
            # Lets a precedent that records the SAME command be marked as an exact
            # match rather than a same-type analogy — see the block's own note.
            command_lines=(
                (evidence or {}).get("command_lines")
                # Unattributed invocations recovered when the host could not be bound
                # (60164f6) — this family's commands usually arrive only that way.
                or (evidence or {}).get("candidate_commands")
                or ([(evidence or {}).get("command_line")] if (evidence or {}).get("command_line") else [])
                or []
            ),
        )
        if _prec:
            scg_context = (scg_context + "\n\n" + _prec).strip() if scg_context else _prec
    except Exception as exc:
        logger.warning("Playbook precedent fetch failed: %s", exc)

    # Per-actor justification precedent — only for a multi-actor incident (actor_hosts
    # has >1 entry; empty/absent for a single-actor alert, so this never runs there).
    # Mutates `evidence` in place, before `_ev` copies it below, so both the prompt
    # (built from `_ev`) and the RJ safety gate (which reads `evidence` directly) see
    # the same result without threading a new parameter through either.
    _actor_hosts = (evidence or {}).get("actor_hosts") or []
    if len(_actor_hosts) > 1:
        try:
            from entity_graph.query import get_multi_actor_justification_status
            evidence["actor_justification_hits"] = await get_multi_actor_justification_status(
                _actor_hosts, alert_type)
        except Exception as exc:
            logger.warning("Multi-actor justification lookup failed: %s", exc)

    _scg = sanitizer.sanitize(scg_context) if sanitizer else scg_context
    # Pre-fetched evidence (command lines / file / account) injected up-front so
    # the agent reasons from actual process behavior. Sanitize for the external
    # (Gemini) path; Bedrock stays in-AWS so it gets the raw evidence.
    _ev = dict(evidence or {})
    if sanitizer and _ev:
        _ev = sanitizer.sanitize_obj(_ev)

    # Onboarding truth: a resolved MDE machineId (pipeline resolves it from the
    # hostname for Sentinel-ingested alerts) means the device IS Defender-onboarded,
    # so the prompt can steer MDE process hunts + stop the agent inferring "not onboarded".
    _machine_id = (prefetched_context or {}).get("machine_id", "") or alert.get("machineId", "")

    system_prompt = oscar_module.build_prompt(_scg)
    user_message = oscar_module.format_alert(
        alert=alert,
        jira_key=jira_key,
        alert_name=alert_name,
        severity=severity,
        device_name=sanitizer.sanitize(device_name) if sanitizer else device_name,
        user_name=sanitizer.sanitize(user_name) if sanitizer else user_name,
        sha256=sha256,
        inv_state=inv_state,
        tactics=tactics,
        incident_url=incident_url,
        is_test_device=is_test_device,
        evidence=_ev,
        source=source,
        machine_id=_machine_id,
    )

    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    tools = get_tools(advertised_tools_for(alert_type, alert_name))
    # Deliberately UNfiltered: the allowlist trims what is advertised, never what can
    # run. See get_tools in agent_tools/registry.py.
    valid_names = get_tool_names()
    tool_call_records: list[ToolCallRecord] = []
    # The concurrency check is a PRECONDITION for auto-close, and it is a plain DB query
    # over device/user — no model judgment in it at all. Leaving it to the model to
    # remember was costing correct verdicts outright, because the failure is silent and
    # self-justifying: DEMO-111186 concluded "routine activity" and then escalated on
    # "the scg_check_concurrent_alerts call was not completed before concluding";
    # DEMO-110988 spent all 10 iterations fanning out over ~20 co-hosts and never
    # reached the call; DEMO-111015 concluded FP in 2 calls and noticed the omission
    # only while writing its verdict. None of the three ever called the tool — the
    # claim that it "failed or returned an error" is the model narrating its own gap.
    #
    # The nudge at :338 was meant to recover this, but it hands the model a compliant
    # exit: it says an auto-close without the call "will be rejected and escalated to
    # L2", so answering NEEDS_L2 satisfies the gate without doing the work — and once
    # the verdict is NEEDS_L2 the gate's own AUTO_CLOSED_* condition stops matching, so
    # it never nudges again. Every such run is a guaranteed miss on any ticket a human
    # then closes FP, which is all 57 measured misses.
    #
    # So compute it up front and seed it as a real record, the same way the DLP bind is
    # prefetched rather than asked for. Three things follow: the result is in context
    # from the first turn, _concurrency_check_missing can never fire on a run that had
    # a correlatable entity, and the iteration it used to cost is returned to the
    # investigation. The anti-fabrication property at :1235 is untouched — that gate
    # reads tool ARGS to stop a model CLAIMING a check it never made, and this record
    # is written by code from a real query, not from anything the model said.
    _seeded_concurrency: dict = {}
    if not _concurrency_uncorrelatable(device_name, user_name):
        try:
            from entity_graph.query import check_concurrent_alerts
            _seeded_concurrency = await check_concurrent_alerts(
                device_name=device_name, user_name=user_name,
                exclude_jira_key=jira_key,
                reference_time=_alert_reference_time(alert),
            ) or {}
            # args is a DICT (ToolCallRecord.args: dict) — _fmt_args in result.py calls
            # .items() on it when rendering the investigation record, so a string here
            # takes down the whole agent run with
            # "AttributeError: 'str' object has no attribute 'items'".
            tool_call_records.append(ToolCallRecord(
                name="scg_check_concurrent_alerts",
                args={"device_name": device_name, "user_name": user_name,
                      "prefetched": True},
                result=_seeded_concurrency,
            ))
            logger.info(
                "[AGENT] %s: prefetched concurrency check — %d concurrent open alert(s)",
                jira_key, len(_seeded_concurrency.get("open_alerts") or []),
            )
        except Exception as exc:
            # A failed prefetch must NOT look like a completed check: leave the record
            # out so the existing gate still forces the model to make the call itself.
            _seeded_concurrency = {}
            logger.warning("[AGENT] %s: concurrency prefetch failed (%s) — "
                           "leaving the check to the model", jira_key, exc)

    # Put the answer in front of the model rather than making it ask. Stated as the
    # completed check it is, so the model reasons about the RESULT instead of about
    # whether it still owes a call — the confusion that produced "I cannot confirm the
    # absence of concurrent alerts" on runs that had every fact needed to close.
    if _seeded_concurrency:
        _open = _seeded_concurrency.get("open_alert_details") or []
        if _open:
            _lines = "\n".join(
                f"  - {(o or {}).get('jira_key','?')} · {(o or {}).get('alert_name','?')} "
                f"· AI said {(o or {}).get('ai_triage_class','?')} · {(o or {}).get('created_at','?')}"
                for o in _open[:8]
            )
            _cc = (f"CONCURRENT ALERT CHECK (already performed for you — do NOT call "
                   f"scg_check_concurrent_alerts):\n{len(_open)} other open alert(s) on this "
                   f"device/user within 24h of this alert:\n{_lines}\n"
                   "Judge whether these are the SAME event fanned out, or genuinely "
                   "independent signals. Same-event siblings are not an attack chain.")
        else:
            _cc = ("CONCURRENT ALERT CHECK (already performed for you — do NOT call "
                   "scg_check_concurrent_alerts): NO other open alerts on this device or "
                   "user within 24h. This precondition for auto-close is SATISFIED.")
        # Folded into the EXISTING user turn rather than appended as a second one:
        # messages is [system, user] here, and a second consecutive user message is
        # rejected outright by backends that require alternating roles.
        _cc_txt = sanitizer.sanitize(_cc) if sanitizer else _cc
        messages[-1]["content"] = f"{messages[-1]['content']}\n\n{_cc_txt}"

    # Co-host hunts, run up front for a grouped incident. The multi-host rule needs a hunt
    # per co-host, and left to the model it is skipped by answering NEEDS_L2 with the hunts
    # listed as "next steps" (DEMO-118007: 4 co-hosts, one hunt, 0% confidence) — the
    # nudge only fires on an AUTO_CLOSED_FP, so that exit is never challenged. Same
    # remedy as the concurrency prefetch: code gathers the evidence, the model judges it.
    # Gathering only — every gate still applies to whatever the model concludes.
    _cohost_lines = []
    for _h in _cohost_prefetch_targets(evidence):
        _args = {"device": _h["device"], "process_name": _h["process"], "window_hours": 2,
                 "alert_time": _alert_reference_time(alert)}
        try:
            _r = await execute("hunt_process", _args, prefetched=prefetched_context)
        except Exception as exc:
            _r = {"error": f"co-host prefetch failed: {str(exc)[:120]}"}
        if sanitizer:
            _r = sanitizer.sanitize_obj(_r)
        tool_call_records.append(ToolCallRecord(name="hunt_process", args={**_args, "prefetched": True},
                                                result=_r))
        _cohost_lines.append(
            f"Co-host {_h['device']} (recorded command: {_h['command'][:120]}) — "
            f"hunt_process(process_name='{_h['process']}', ±1h of the alert):\n"
            + json.dumps(_for_model(_r), default=str)[:_TOOL_RESULT_CHARS // 2])
    if _cohost_lines:
        logger.info("[AGENT] %s: prefetched co-host hunts on %d host(s)", jira_key, len(_cohost_lines))
        _ch = ("CO-HOST HUNTS (already run for you, one per co-host, for the command the rule "
               "recorded there). Judge each host on its own result; a host still needs positive "
               "evidence to be cleared, and you may hunt further:\n\n" + "\n\n".join(_cohost_lines))
        messages[-1]["content"] = f"{messages[-1]['content']}\n\n{sanitizer.sanitize(_ch) if sanitizer else _ch}"

    consecutive_no_tool = 0
    evidence_gate_nudges = 0
    multihost_gate_nudges = 0
    garble_retry_nudges = 0
    concurrency_gate_nudges = 0
    claim_verify_nudges = 0
    source_empty_retry_nudges = 0

    from agent_core.backend import GeminiBackend as _GeminiBackend
    from agent_core.backend import BedrockBackend as _BedrockBackend
    from agent_core.backend import MantleBackend as _MantleBackend
    if isinstance(backend, _MantleBackend):
        _backend_name = f"mantle:{backend.model_id}"
    elif isinstance(backend, _BedrockBackend):
        _backend_name = f"bedrock:{backend.model_id}"
    elif isinstance(backend, _GeminiBackend):
        _backend_name = "gemini"
    else:
        _backend_name = "ollama"
    logger.info("[AGENT-LOOP] %s: backend=%s alert_type=%s max_iter=%d", jira_key, _backend_name, alert_type, max_iter)

    _loop_start = time.perf_counter()
    for iteration in range(max_iter):
        _chat_start = time.perf_counter()
        content, tool_calls = await backend.chat(messages, tools)
        _chat_elapsed = time.perf_counter() - _chat_start
        _total_elapsed = time.perf_counter() - _loop_start

        # Strip thinking tokens from context to save window space
        content_clean = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

        _tool_names = [tc.name for tc in tool_calls] if tool_calls else []
        _verdict_preview = content_clean[:120].replace("\n", " ") if content_clean else ""
        logger.info(
            "[AGENT-ITER] %s iter=%d/%d backend=%s chat=%.1fs total=%.1fs tools=%s text=%r",
            jira_key, iteration + 1, max_iter, _backend_name,
            _chat_elapsed, _total_elapsed, _tool_names, _verdict_preview,
        )
        await _notify(
            "iteration",
            (f"Iteration {iteration + 1}/{max_iter}: called {', '.join(_tool_names)}"
             if _tool_names else f"Iteration {iteration + 1}/{max_iter}: reasoning"),
            {"iteration": iteration + 1, "max_iter": max_iter, "tools_called": _tool_names},
        )

        # Check for final verdict — robust balanced-brace extraction handles
        # <final_verdict> tags, bare JSON, fenced code, nested braces, and light
        # repair (trailing commas). Replaces the old non-greedy \{.*?} regex that
        # broke on any nested braces in the verdict JSON.
        verdict_obj = _extract_loose_verdict(content)
        if verdict_obj:
            result = _parse_verdict(verdict_obj, tool_call_records, iteration + 1,
                                    fallback_text=content_clean)
            # Corrupted output: ask for the verdict again, once, before anything else reads
            # it. The garbled reply is NOT kept in the conversation — continuing from it is
            # how the corruption carries forward. The re-ask rides on the last user turn
            # (tool results), so roles still alternate. A second garbled verdict reaches
            # the garbled_output gate in _apply_safety_gates and escalates exactly as before.
            _garble_now = _garbled_reasoning(result.reasoning, tool_call_records, evidence)
            if _garble_now and garble_retry_nudges < _GARBLE_RETRY_LIMIT and messages[-1].get("role") == "user":
                garble_retry_nudges += 1
                logger.warning(
                    "[AGENT-GATE] %s: discarded a corrupted verdict (stray text %r) — asking again "
                    "(retry %d/%d)", jira_key, _garble_now[:20], garble_retry_nudges, _GARBLE_RETRY_LIMIT,
                )
                messages[-1] = {**messages[-1], "content": (
                    f"{messages[-1]['content']}\n\n"
                    "Your previous reply was corrupted (it contained text that appears nowhere in "
                    "the alert or the tool results, and misspelled hostnames and user names) and "
                    "has been discarded. Emit your <final_verdict> again, copying every hostname, "
                    "user name and command exactly as it appears in the alert and tool results.")}
                consecutive_no_tool = 0
                continue
            # Evidence-floor gate: a verdict that arrives with ZERO investigative
            # tool calls is untrustworthy — the model concluded from the alert
            # title/context alone. Reject it (bounded) and force at least one
            # investigation. Calling scg_get_entity_context for the device always
            # returns *something*, so even empty-entity alerts clear the gate after
            # one attempt rather than looping. Auto-closes that still lack evidence
            # are downgraded by _apply_safety_gates below.
            if not tool_call_records and evidence_gate_nudges < _EVIDENCE_GATE_LIMIT:
                evidence_gate_nudges += 1
                logger.info(
                    "[AGENT-GATE] %s: rejected no-evidence verdict %s conf=%.2f "
                    "(nudge %d/%d) — forcing investigation",
                    jira_key, result.triage_class, result.confidence,
                    evidence_gate_nudges, _EVIDENCE_GATE_LIMIT,
                )
                messages.append({"role": "assistant", "content": content_clean})
                messages.append({"role": "user", "content": (
                    "You emitted a verdict without any investigation. You MUST gather "
                    "evidence before concluding: call scg_get_entity_context for the device "
                    "(and the user if present) now, plus vt_lookup_hash if a file hash exists "
                    "or a timeline/hunt query if relevant. Do NOT emit a verdict in your next "
                    "response — investigate first, then re-evaluate. An AUTO-CLOSE with no "
                    "investigation will be rejected and escalated to L2."
                )})
                consecutive_no_tool = 0
                continue
            # Multi-host coverage gate: an AUTO_CLOSED_FP that skips a named co-host's
            # hunt is rejected and re-prompted (bounded), same pattern as the evidence
            # floor above — give the model a real chance to satisfy the MULTI-HOST
            # INCIDENT rule (oscar.py) on THIS run instead of going straight to the hard
            # block in _apply_safety_gates. DEMO-107497: the prompt already says "You MUST
            # investigate EACH co-host" in as many words, and the model still skipped the
            # hunt on the co-host twice in a row — a nudge that names the exact missing
            # host and tool is a much stronger signal than the same instruction sitting
            # in the system prompt from the first message.
            _co_hosts_now = (evidence or {}).get("additional_hosts") or []
            if (result.triage_class == "AUTO_CLOSED_FP" and multihost_gate_nudges < _MULTIHOST_GATE_LIMIT
                    and not _service_fleet_cleared(evidence, tool_call_records)):
                _unassessed_now = _unassessed_co_hosts(_co_hosts_now, tool_call_records)
                if _unassessed_now:
                    multihost_gate_nudges += 1
                    logger.info(
                        "[AGENT-GATE] %s: rejected FP verdict — co-host(s) %s never hunted "
                        "(nudge %d/%d) — forcing investigation",
                        jira_key, _unassessed_now, multihost_gate_nudges, _MULTIHOST_GATE_LIMIT,
                    )
                    messages.append({"role": "assistant", "content": content_clean})
                    messages.append({"role": "user", "content": (
                        f"You concluded AUTO_CLOSED_FP but never ran a hunt on co-host"
                        f"{'s' if len(_unassessed_now) > 1 else ''} {', '.join(_unassessed_now)}. "
                        "Per the MULTI-HOST INCIDENT rule, auto-closing FP requires POSITIVE "
                        f"exculpatory evidence for EVERY host. Call hunt_process (or hunt_logons) "
                        f"on {', '.join(_unassessed_now)} now, then re-evaluate. Do NOT emit a "
                        "verdict in your next response — investigate first. An AUTO_CLOSED_FP "
                        "that still hasn't covered every host will be rejected and escalated to L2."
                    )})
                    consecutive_no_tool = 0
                    continue
            # An auto-close proposed off a hunt that hit a genuinely empty table (not
            # clean — no data at all) and never retried with the tool that actually
            # covers this telemetry. Give the model a real chance to make the right
            # call before the existing errored-hunt gate escalates it regardless.
            if (result.triage_class in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP")
                    and source_empty_retry_nudges < _SOURCE_EMPTY_RETRY_LIMIT
                    and _source_empty_unretried(tool_call_records, device_name)):
                source_empty_retry_nudges += 1
                logger.info(
                    "[AGENT-GATE] %s: rejected %s verdict — hit an empty source table and "
                    "never retried with hunt_process (nudge %d/%d)",
                    jira_key, result.triage_class, source_empty_retry_nudges,
                    _SOURCE_EMPTY_RETRY_LIMIT,
                )
                messages.append({"role": "assistant", "content": content_clean})
                messages.append({"role": "user", "content": (
                    f"You concluded {result.triage_class}, but the hunt that was supposed to "
                    "verify this alert's own activity hit a table with NO data at all — that "
                    "is not evidence of anything, benign or otherwise. This alert has a "
                    f"device ({device_name}); call hunt_process on it now with the alert's "
                    "actual command/process, then re-evaluate. Do NOT emit a verdict in your "
                    f"next response — investigate first. A {result.triage_class} that still "
                    "rests on an empty-table result will be rejected and escalated to L2."
                )})
                consecutive_no_tool = 0
                continue
            # Concurrency check gate: an auto-close that never called
            # scg_check_concurrent_alerts is rejected and re-prompted (bounded), same
            # pattern as the multi-host nudge above. DEMO-107601: a clean, well-reasoned
            # FP case (VT clean, known service account, prior justified occurrences)
            # that simply never made this one call — nudging it to make the call is a
            # real chance to close correctly on THIS run, not a bypass of the gate.
            if (result.triage_class in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP")
                    and (device_name or user_name)
                    and not _concurrency_uncorrelatable(device_name, user_name)
                    and concurrency_gate_nudges < _CONCURRENCY_GATE_LIMIT
                    and _concurrency_check_missing(tool_call_records)):
                concurrency_gate_nudges += 1
                logger.info(
                    "[AGENT-GATE] %s: rejected %s verdict — scg_check_concurrent_alerts "
                    "never called (nudge %d/%d) — forcing investigation",
                    jira_key, result.triage_class, concurrency_gate_nudges, _CONCURRENCY_GATE_LIMIT,
                )
                messages.append({"role": "assistant", "content": content_clean})
                messages.append({"role": "user", "content": (
                    f"You concluded {result.triage_class} but never called "
                    "scg_check_concurrent_alerts. Auto-closing requires ruling out other open "
                    "alerts on the same device/user first. Call scg_check_concurrent_alerts now, "
                    "then re-evaluate. Do NOT emit a verdict in your next response — investigate "
                    f"first. A {result.triage_class} that still hasn't made this call will be "
                    "rejected and escalated to L2."
                )})
                consecutive_no_tool = 0
                continue
            # A close that cites checks it never ran. The 2026-10-14 review found it on 3 of
            # 11 model closes; DEMO-116466 reported "no VirusTotal/AbuseIPDB detections" and
            # an IP's location with neither looked up. claim_check only annotated the comment
            # afterwards. Ask first: run the check, or stop relying on it. Not a block — the
            # model decides again on what it actually has.
            if (result.triage_class in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP")
                    and claim_verify_nudges < _CLAIM_VERIFY_LIMIT):
                from agent_core.claim_check import unverified_claims as _unverified_now
                from agent_core.claim_check import ungrounded_values as _ungrounded_now
                _claims_now = _unverified_now(result.reasoning, tool_call_records, evidence or {})
                _values_now = _ungrounded_now(result.reasoning, tool_call_records,
                                              evidence or {}, alert)
                if _values_now:
                    _claims_now = _claims_now + [
                        "these specific values, which appear in no tool result or alert field: "
                        + ", ".join(f"`{v}`" for v in _values_now)]
                if _claims_now:
                    claim_verify_nudges += 1
                    logger.info("[AGENT-GATE] %s: %s cites unrun checks %s — asking to verify "
                                "or withdraw", jira_key, result.triage_class, _claims_now)
                    messages.append({"role": "assistant", "content": content_clean})
                    messages.append({"role": "user", "content": (
                        f"Your {result.triage_class} reasoning relies on "
                        f"{', '.join(_claims_now)}, but no such check ran successfully on this "
                        "ticket. A security engineer does not state what they have not checked. "
                        "If those checks matter to your decision, run them now. If they do not, "
                        "drop them and decide again from the evidence you actually gathered — "
                        "and do not describe an IP, account or file (its owner, location, "
                        "reputation or purpose) unless a tool result or the alert says so."
                    )})
                    consecutive_no_tool = 0
                    continue
            # Record the MODEL's verdict before any gate/critic downgrade — so we can
            # measure how often the safety layer turns an intended auto-close into an
            # escalation (over-gating visibility).
            result.pre_safety_class = result.triage_class
            result.pre_safety_reasoning = result.reasoning
            _det_fp = bool(((_ev or {}).get("port_sweep_check") or {}).get("known_good"))
            _prior_malware = None
            if result.triage_class == "AUTO_CLOSED_FP" and (device_name or "").strip():
                from entity_graph.query import recent_malware_alerts
                _prior_malware = await recent_malware_alerts(
                    device_name, _alert_reference_time(alert), exclude_jira_key=jira_key)
                # None = the lookup failed; the gate reads that as "cannot rule it out".
                if _prior_malware is None:
                    _prior_malware = [{"error": "malware-history lookup failed"}]
            _open_urgent = None
            if result.triage_class == "AUTO_CLOSED_FP":
                from entity_graph.query import open_urgent_alerts
                _open_urgent = await open_urgent_alerts(
                    user_name, device_name, _alert_reference_time(alert), exclude_jira_key=jira_key)
                if _open_urgent is None:
                    _open_urgent = [{"error": "open-urgent lookup failed"}]
            result = _apply_safety_gates(result, severity, is_test_device, tool_call_records,
                                         deterministic_fp=_det_fp,
                                         prior_malware=_prior_malware,
                                         open_urgent=_open_urgent,
                                         co_hosts=(evidence or {}).get("additional_hosts"),
                                         device_name=device_name, user_name=user_name,
                                         evidence=evidence or {}, alert_name=alert_name,
                                         alert_type=alert_type, alert=alert)
            # Grounding backstop — block an auto-close resting on a fabricated actor/command
            # (DEMO-107147). Runs after the safety gates; only ever downgrades to NEEDS_L2.
            result = _apply_grounding_check(result, evidence or {}, user_name, tool_call_records,
                                            jira_key, alert=alert)
            # LLM grounding critic (opt-in AGENT_GROUNDING_CRITIC_ENABLED) — nuance the
            # deterministic check can't reach, on the INTERNAL backend with RAW facts
            # (never Gemini for alert data). Gated by the deterministic backstop above;
            # only downgrades an auto-close, and only on a CONFIDENT ungrounded finding.
            if result.triage_class in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP") and _critic.grounding_enabled():
                from agent_core.backend import get_internal_backend
                _gd = await _critic.ground_check(
                    result,
                    _build_fact_sheet(evidence or {}, user_name, device_name),
                    _critic._evidence_digest(tool_call_records),
                    get_internal_backend(),
                )
                if _critic.grounding_should_override(_gd):
                    logger.info("[AGENT-GROUNDING] %s: ungrounded (conf=%.2f) → NEEDS_L2: %s",
                                jira_key, _gd.confidence, _gd.reason)
                    result.triage_class = "NEEDS_L2"
                    result.blocked_by_safety = True
                    result.safety_block_reason = (
                        "Grounding critic — verdict rests on unsupported claim(s): "
                        + (", ".join(_gd.unsupported[:3]) if _gd.unsupported else _gd.reason)
                    )
            # Validation debate — rule critic (always) + opt-in LLM critic. Only ever
            # downgrades an auto-close to NEEDS_L2; never relaxes a verdict.
            result = await _apply_validation_critic(
                result, alert_name, severity, backend, sanitizer, jira_key,
            )
            # Annotation only: list the checks the reasoning claims that no tool call
            # backs, so the comment L2 reviews from says which lines are unverified.
            try:
                from agent_core.claim_check import unverified_claims as _unverified
                result.unverified_claims = _unverified(result.reasoning, tool_call_records,
                                                       evidence or {})
                if result.unverified_claims:
                    logger.info("[AGENT-CLAIMS] %s: unverified in reasoning: %s",
                                jira_key, ", ".join(result.unverified_claims))
            except Exception as exc:
                logger.warning("claim check skipped for %s: %s", jira_key, exc)
            logger.info(
                "[AGENT-LOOP] %s: verdict=%s conf=%.2f iterations=%d total=%.1fs",
                jira_key, result.triage_class, result.confidence, iteration + 1,
                time.perf_counter() - _loop_start,
            )
            await _notify("verdict", f"Verdict: {result.triage_class} ({result.confidence:.0%} confidence)",
                          {"triage_class": result.triage_class, "confidence": result.confidence,
                           "iterations": iteration + 1})
            return result

        if not tool_calls:
            consecutive_no_tool += 1
            if consecutive_no_tool >= _FAIL_RETRY_LIMIT:
                logger.warning("%s: no tool calls %d times — defaulting to NEEDS_L2. last_output=%r",
                               jira_key, consecutive_no_tool, content_clean[:300])
                await _notify("verdict", "Verdict: NEEDS_L2 (no recognized verdict emitted)",
                              {"triage_class": "NEEDS_L2", "error": "no_tool_calls"})
                return AgentResult(
                    triage_class="NEEDS_L2",
                    confidence=0.3,
                    reasoning=("Agent did not emit a recognized verdict within retry limit. "
                               f"Last model output: {(content_clean or '(empty)')[:600]}"),
                    tool_calls=tool_call_records,
                    iterations=iteration + 1,
                    error="no_tool_calls",
                )
            # Prompt more explicitly — escalate urgency on second miss
            messages.append({"role": "assistant", "content": content_clean})
            nudge = (
                "You must now emit <final_verdict> immediately. "
                "Do not call any more tools. Output the verdict JSON and nothing else."
                if consecutive_no_tool >= _FAIL_RETRY_LIMIT - 1
                else "Continue investigation. Call the next tool or emit <final_verdict>."
            )
            messages.append({"role": "user", "content": nudge})
            continue
        else:
            consecutive_no_tool = 0

        # Execute tool calls
        tool_results_text = []
        for tc in tool_calls:
            if tc.name not in valid_names:
                tool_result = {"error": f"Unknown tool: {tc.name}"}
            else:
                real_args = sanitizer.desanitize_obj(tc.args) if sanitizer else tc.args
                if tc.name == "scg_check_concurrent_alerts":
                    # Inject the current ticket key so it can't self-count as a
                    # concurrent alert on a re-triage (copy — tc.args is recorded below),
                    # plus when this alert fired, so the 24h window is anchored to the
                    # alert rather than to now. They differ on a re-triage of an old
                    # ticket, where "now" pulls in alerts that postdate it entirely.
                    real_args = {**real_args, "exclude_jira_key": jira_key,
                                 "reference_time": _alert_reference_time(alert)}
                elif tc.name in _ALERT_ANCHORED_HUNTS and not str(real_args.get("alert_time") or "").strip():
                    # Anchor the window on the alert unless the model deliberately chose
                    # its own anchor. Left to the model this is simply forgotten — the
                    # DEMO-108670 re-run called hunt_network with device + window_hours and
                    # nothing else, so it read the 50 connections nearest the RE-RUN; the
                    # DEMO-107770 re-run's hunt_events found 0 of 4 AV detections the same way.
                    real_args = {**real_args, "alert_time": _alert_reference_time(alert)}
                tool_result = await execute(tc.name, real_args, prefetched=prefetched_context)
                if sanitizer:
                    tool_result = sanitizer.sanitize_obj(tool_result)
            tool_call_records.append(ToolCallRecord(name=tc.name, args=tc.args, result=tool_result))
            tool_results_text.append(f"Tool: {tc.name}\nArgs: {json.dumps(tc.args)}\nResult: {json.dumps(_for_model(tool_result), default=str)[:_TOOL_RESULT_CHARS]}")

        messages.append({"role": "assistant", "content": content_clean})
        remaining = max_iter - (iteration + 1)
        tool_results_msg = "Tool results:\n\n" + "\n\n---\n\n".join(tool_results_text)
        if remaining <= 3:
            tool_results_msg += (
                f"\n\n[SYSTEM: {remaining} investigation step(s) remaining. "
                f"You MUST emit <final_verdict> within your next {remaining} response(s). "
                f"If evidence is ambiguous, use NEEDS_L2 with your current confidence rather than continuing to investigate.]"
            )
        messages.append({"role": "user", "content": tool_results_msg})

    # Max iterations reached
    await _notify("verdict", "Verdict: NEEDS_L2 (reached max iterations without a verdict)",
                  {"triage_class": "NEEDS_L2", "error": "max_iterations"})
    return AgentResult(
        triage_class="NEEDS_L2",
        confidence=0.3,
        reasoning=(f"Investigation reached max iterations ({max_iter}) without a verdict. "
                   f"Last model output: {(content_clean or '(empty)')[:600]}"),
        tool_calls=tool_call_records,
        iterations=max_iter,
        error="max_iterations",
    )


# What the model sees of one tool result. Raised from 1500: the summaries a tool adds
# after its rows (hunt_signin's outcomes and per-IP facts) were cut off every time.
_TOOL_RESULT_CHARS = 2500


def _for_model(result):
    """A tool result with its summaries FIRST and the raw `rows` list LAST.

    Results are cut to _TOOL_RESULT_CHARS before the model sees them. Tools build the
    dict rows-first and append their summaries after, so the summary was the part cut:
    DEMO-116466's re-run (2026-10-14) saw 30 raw sign-in rows and never the outcome counts
    or the per-IP facts, then reported "1,786 x 50053 lockouts and 39 x 50126 invalid
    passwords" — neither code appears in that user's sign-ins (50076/50127/70043, all
    policy). Reordering only; nothing is dropped that wasn't dropped before.
    """
    if not isinstance(result, dict):
        return result
    tail = ("rows", "kql")          # raw rows, then the query text (debugging, not evidence)
    return {**{k: v for k, v in result.items() if k not in tail},
            **{k: result[k] for k in tail if k in result}}


def _extract_loose_verdict(text: str) -> dict | None:
    """Find a JSON verdict object with triage_class even without <final_verdict> tags.

    Handles native-tool-use models that emit the verdict JSON as plain text or
    fenced code instead of the R1-style XML wrapper. Scans for the balanced-brace
    object enclosing the first "triage_class" key.
    """
    if not text or "triage_class" not in text:
        return None
    idx = text.find('"triage_class"')
    start = text.rfind("{", 0, idx)
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    obj = _loads_lenient(text[start:i + 1])
                    if isinstance(obj, dict) and obj.get("triage_class"):
                        return obj
                    break
    # Fallback: pull fields by regex even if the JSON is unrepairable (e.g. the
    # model closed the object badly or embedded control chars we couldn't fix).
    return _regex_verdict(text)


def _fix_bad_escapes(s: str) -> str:
    r"""Drop backslashes that JSON does not permit as escapes.

    JSON allows only \" \\ \/ \b \f \n \r \t \uXXXX. Models routinely emit \' when
    quoting an alert name that itself contains single quotes — e.g.
    "Alert \'Ransomware\' behavior was blocked" — which makes json.loads fail with
    'Invalid \escape' and, before this, sent the whole verdict to the regex
    fallback (DEMO-107770). Stripping the stray backslash preserves the text.
    """
    return re.sub(r'\\(?!["\\/bfnrtu])', "", s)


def _loads_lenient(blob: str):
    """json.loads with light repair for common model JSON quirks."""
    b = blob.strip()
    if b.startswith("```"):
        b = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", b).strip()
    _notrail = re.sub(r",\s*([}\]])", r"\1", b)
    candidates = [
        b,
        _notrail,                                          # trailing commas
        _escape_ctrl_in_strings(b),                        # literal newlines/tabs in strings
        _escape_ctrl_in_strings(_notrail),
        _fix_bad_escapes(b),                               # invalid \' style escapes
        _escape_ctrl_in_strings(_fix_bad_escapes(_notrail)),
    ]
    for c in candidates:
        try:
            return json.loads(c)
        except (json.JSONDecodeError, TypeError):
            continue
    return None


def _escape_ctrl_in_strings(s: str) -> str:
    """Escape raw newlines/tabs/CRs that appear INSIDE JSON string literals
    (invalid JSON, but a very common LLM output). Leaves structure untouched."""
    out, in_str, esc = [], False, False
    for ch in s:
        if in_str:
            if esc:
                out.append(ch); esc = False; continue
            if ch == "\\":
                out.append(ch); esc = True; continue
            if ch == '"':
                out.append(ch); in_str = False; continue
            if ch == "\n": out.append("\\n"); continue
            if ch == "\r": out.append("\\r"); continue
            if ch == "\t": out.append("\\t"); continue
            out.append(ch)
        else:
            if ch == '"':
                in_str = True
            out.append(ch)
    return "".join(out)


def _regex_verdict(text: str) -> dict | None:
    """Last-resort verdict extraction by regex when JSON parsing fails.

    `[A-Z_0-9]` — the digit matters: the old `[A-Z_]+` could not match NEEDS_L2,
    the single most common verdict, so this last-resort path silently failed for
    exactly the class it was most often needed for. AUTO_CLOSED_FP/TP and URGENT
    matched fine, which is why it looked like it worked. Consequence: whenever the
    model's JSON was malformed or truncated AND the verdict was NEEDS_L2, the
    fallback returned None, the loop burned its retries and gave up with
    ai_error=no_tool_calls — recorded as an agent FAILURE (excluded from accuracy)
    rather than the escalation the model actually reached (DEMO-107770: the model
    emitted a valid "triage_class": "NEEDS_L2" that was thrown away).
    """
    m = re.search(r'"triage_class"\s*:\s*"([A-Z_0-9]+)"', text)
    if not m or m.group(1) not in _TRIAGE_CLASSES:
        return None
    conf = re.search(r'"confidence"\s*:\s*([0-9]*\.?[0-9]+)', text)
    reason = re.search(r'"reasoning"\s*:\s*"(.*?)"\s*(?:,\s*"[a-z_]+"\s*:|})', text, re.DOTALL)
    if not reason:
        # Truncated mid-string (model hit max_tokens): there is no closing quote, so
        # the pattern above can't terminate. Take everything after the opening quote
        # rather than dropping the analysis entirely — a partial rationale still tells
        # an analyst why the verdict was reached.
        _open = re.search(r'"reasoning"\s*:\s*"(.*)', text, re.DOTALL)
        _txt = _open.group(1) if _open else ""
    else:
        _txt = reason.group(1)
    return {
        "triage_class": m.group(1),
        "confidence": float(conf.group(1)) if conf else 0.5,
        "reasoning": _txt.strip()[:3000],
        "actions": [],
    }


def _strip_verdict_block(text: str) -> str:
    """Remove the <final_verdict> tags / verdict JSON so what's left is the model's
    prose reasoning — used as a fallback when the verdict JSON has no reasoning field."""
    t = re.sub(r"<final_verdict>.*?</final_verdict>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # Drop a bare verdict JSON object if the model emitted it without the tags.
    t = re.sub(r"\{[^{}]*\"triage_class\"[^{}]*\}", "", t, flags=re.DOTALL)
    return t.strip()


# Hunts whose window the loop anchors on the alert time (each takes `alert_time`, and all
# but hunt_network keep it out of the model-visible schema). Without it they search the N
# hours before NOW, which on any re-triage of an older ticket is the wrong range.
_ALERT_ANCHORED_HUNTS = frozenset({
    "hunt_network", "hunt_process", "hunt_file", "hunt_events", "hunt_file_burst",
    "hunt_script_egress", "hunt_logons", "hunt_signin", "hunt_office", "hunt_sentinel_event", "hunt_vlogs",
    "hunt_query",
})


def _alert_reference_time(alert: dict) -> str:
    """When this alert fired, as ISO8601 — the anchor for the concurrent-alert window.

    Same key precedence as edr_triage.normalized. Empty string when the alert carries
    no usable timestamp, which makes check_concurrent_alerts fall back to now (the
    pre-existing behaviour).
    """
    for key in ("alertCreationTime", "firstEventTime", "lastEventTime", "alert_time"):
        val = (alert or {}).get(key)
        if val:
            return str(val)
    return ""


def _too_early_for_blank_bound_evidence(
    alert_name: str, device_name: str, evidence: dict | None, alert: dict | None,
) -> bool:
    """True when this is a blank-bound instance of a known slow-telemetry alert
    family, still inside the measured ingestion-lag window.

    DEMO-109599: triaged 33 seconds after the alert fired, ran a fleet-wide MDE hunt_query
    (no device to scope it to), got 50 rows of activity that had already landed, and
    built a confident AUTO_CLOSED_FP narrative around two of those devices — neither of
    which was the alert's real device. The real row for THIS alert's own event could not
    possibly have existed yet (26-28 min ingestion lag), so nothing in that result set
    could have been it; the model just didn't know that and attributed the alert to
    whatever benign-looking activity was already in the pile.

    This is time-based, not evidence-based, on purpose: no amount of re-prompting within
    the same run fixes a row that doesn't exist yet, so unlike the other gates in this
    module this is a hard override, not a nudge to try again. blank_retriage.py re-checks
    this exact ticket once the window has passed, so the FP conclusion this alert family
    usually reaches is not lost — just deferred until it can be verified for real.

    Scoped narrowly so it cannot touch a working path: only fires when device_name is
    STILL empty (an alert that bound a device immediately, e.g. DEMO-109601/109602, never
    hits this) and only for this specific alert family.
    """
    if (device_name or "").strip():
        return False
    _name = (alert_name or "").lower()
    if "powershell script" not in _name or "memory" not in _name:
        return False
    if (evidence or {}).get("command_lines") or (evidence or {}).get("command_line"):
        return False  # a command line WAS resolved — not the blank shape this guards
    ref = _alert_reference_time(alert or {})
    if not ref:
        return False
    try:
        ref_dt = datetime.fromisoformat(ref.replace("Z", "+00:00"))
        if ref_dt.tzinfo is None:
            ref_dt = ref_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    age_minutes = (datetime.now(timezone.utc) - ref_dt).total_seconds() / 60
    return age_minutes < _BLANK_BOUND_LAG_MINUTES


def _reasoning_text(raw) -> str:
    """Reasoning as plain text, one point per line.

    Models sometimes emit "reasoning" as a JSON array of numbered points, or as a string
    holding a Python/JSON list. str() on either reached Jira as one unreadable line —
    "['1. *Alert Context*: …', '2. …']" (DEMO-117716)."""
    if isinstance(raw, str):
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            import ast
            try:
                parsed = ast.literal_eval(s)
            except (ValueError, SyntaxError):
                try:
                    parsed = json.loads(s)
                except ValueError:
                    parsed = None
            if isinstance(parsed, list):
                raw = parsed
        if isinstance(raw, str):
            return s
    if isinstance(raw, (list, tuple)):
        return "\n".join(t for x in raw if (t := str(x).strip()))
    return str(raw or "").strip()


def _parse_verdict(data: dict, tool_calls: list[ToolCallRecord], iterations: int,
                   fallback_text: str = "") -> AgentResult:
    tc = data.get("triage_class", "NEEDS_L2")
    if tc not in _TRIAGE_CLASSES:
        tc = "NEEDS_L2"

    try:
        confidence = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5

    actions = data.get("actions", []) or []
    if isinstance(actions, str):
        actions = [actions]
    # Models often emit objects here rather than strings; flatten so they never
    # reach the Jira comment (rendered as a raw dict) or the ShadowResult row
    # (typed list[str], and a dict there makes the document unreadable).
    actions = [s for a in actions if (s := normalize_action(a).strip())]

    # Empty-reasoning guard: some models write their analysis as prose and emit a
    # verdict JSON with an empty/absent "reasoning" field. Don't lose the analysis —
    # fall back to the surrounding prose (with the verdict block stripped out).
    reasoning = _reasoning_text(data.get("reasoning", ""))
    if not reasoning and fallback_text:
        reasoning = _strip_verdict_block(fallback_text)[:4000]

    return AgentResult(
        triage_class=tc,
        confidence=confidence,
        reasoning=reasoning,
        recommended_actions=actions,
        tool_calls=tool_calls,
        iterations=iterations,
    )


async def _apply_validation_critic(
    result: AgentResult,
    alert_name: str,
    severity: str,
    backend: LLMBackend,
    sanitizer,
    jira_key: str,
) -> AgentResult:
    """Validation debate over an AUTO-CLOSE verdict. Two layers, both fail-safe and
    one-directional (auto-close → NEEDS_L2 only):

      Layer A — deterministic rule critic (agent_core/verification.py): FP with VT
        detections, TP with no evidence, malicious-process names in the timeline, etc.
      Layer B — opt-in second-LLM critic (AGENT_CRITIC_ENABLED): a bounded call that
        is prompted to refute the verdict; confident dissent forces escalation.

    Non-auto-close verdicts are returned untouched (already headed to a human).
    """
    if result.triage_class not in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP"):
        return result

    # Layer A — rule critic (always on, deterministic, free)
    from agent_core.verification import verify as _verify_rules
    vres = _verify_rules(result)
    if not vres.consistent:
        logger.info("[AGENT-CRITIC-RULE] %s: %s → NEEDS_L2 (%s)",
                    jira_key, result.triage_class, vres.reason)
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_block_reason = f"Rule critic: {vres.reason}"
        return result

    # Layer B — opt-in LLM debate
    from agent_core import critic as _critic
    if not _critic.is_enabled():
        return result
    c = await _critic.critique(result, alert_name, severity, backend, sanitizer)
    result.critic_ran = c.ran
    result.critic_agreed = c.agree if c.ran else None
    result.critic_reason = c.reason
    if _critic.dissent_should_override(c):
        logger.info("[AGENT-CRITIC-LLM] %s: critic dissent (conf=%.2f) → NEEDS_L2: %s",
                    jira_key, c.confidence, c.reason)
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_block_reason = f"Validation critic dissent: {c.reason}"
    return result


# Words that can follow "user" without being a claimed username.
_ACTOR_STOPWORDS = frozenset((
    "account", "identity", "the", "who", "was", "is", "context", "activity",
    "principal", "name", "legitimacy", "and", "or", "with", "from", "session",
    "level", "access", "privileges", "privilege", "role", "not", "has", "had",
    # Verb/gerund forms that follow "user" in ordinary prose ("user switching",
    # "the user switched to", "user running cron"). These are NOT usernames, but the
    # actor regex below happily captured them and blocked a CORRECT auto-close:
    # DEMO-107206's FP was escalated because the reasoning said
    #   "...legitimate privilege escalation (user switching, not root)"
    # and 'switching' was read as a claimed identity absent from the actor fields.
    # That single false escalation then cascaded — it stayed open, so DEMO-107211 /
    # 107218 / 107341 / 107359 each tripped the concurrent-open-alerts gate in turn.
    # NB: listed explicitly rather than stripping every -ed/-ing token, because real
    # usernames do end that way (ahmed, syed, javed, mohammed) and blanket-skipping
    # them would silently disarm this backstop for those people.
    "switching", "switched", "switches", "running", "ran", "runs",
    "executing", "executed", "executes", "attempting", "attempted", "attempts",
    "logging", "logged", "logs", "accessing", "accessed", "accesses",
    "performing", "performed", "performs", "initiating", "initiated", "initiates",
    "escalating", "escalated", "escalates", "using", "used", "uses",
    "invoking", "invoked", "invokes", "elevating", "elevated", "elevates",
    "creating", "created", "creates", "modifying", "modified", "modifies",
    "belonging", "belongs", "appears", "appeared", "seems", "seemed",
    "did", "does", "doing", "being", "been", "having",
))


def _build_fact_sheet(evidence: dict, user_name: str, device_name: str) -> str:
    """Assemble the authoritative alert facts as a clean, labelled block — the ground
    truth the grounding critic fact-checks the verdict against. RAW (internal use only)."""
    ev = evidence or {}
    lines: list[str] = []
    _other_users = [u for u in (ev.get("additional_users") or []) if u]
    if user_name:
        # "the ONLY actor" holds for a single-actor alert (its point is that a name inside
        # an IAM role is not a user — DEMO-107147). It would be false on a grouped
        # multi-user incident, where the co-users listed below are equally real actors.
        lines.append(
            f"Primary user (1 of {len(_other_users) + 1} actors in this incident): {user_name}"
            if _other_users else
            f"Acting user (session principal — the ONLY actor): {user_name}"
        )
    if ev.get("account_name"):
        lines.append(f"Account: {ev['account_name']}")
    if ev.get("session_issuer"):
        lines.append(f"IAM role (a ROLE, NOT a person — never a user): {ev['session_issuer']}")
    if ev.get("user_arn"):
        lines.append(f"Session ARN: {ev['user_arn']}")
    if device_name:
        lines.append(f"Primary host: {device_name}")
    _co = ev.get("additional_hosts") or []
    if _co:
        lines.append("Co-hosts: " + ", ".join(str(h) for h in _co[:20]))
    if _other_users:
        lines.append("Other users in this incident (real actors, same detection): "
                     + ", ".join(str(u) for u in _other_users[:20]))
    _cmds = ev.get("command_lines") or []
    if _cmds:
        lines.append("Commands in THIS alert (the ONLY commands attributable to it):")
        for c in _cmds[:20]:
            lines.append(f"  - {c}")
    if ev.get("file_name"):
        lines.append(f"File: {ev['file_name']}")
    if ev.get("sha256"):
        lines.append(f"SHA256: {ev['sha256']}")
    return "\n".join(lines) or "(no structured facts)"


def _stored_alert_command_gt(jira_key: str) -> str:
    """This ticket's OWN historical record — from BEFORE this run, independent of
    anything the agent just did or said.

    Trusted ONLY when l1_comment_deterministic is True on that record. That flag is
    False exactly when l1_comment is the agent's OWN prior reasoning (autonomous
    phase renders it via agent_result.to_jira_comment — see TriagedAlert's field
    docstring): treating that as ground truth would let the agent validate its
    claim against its own earlier claim, defeating the point of this check. True
    means the field was code-extracted from Sentinel/CloudTrail, no LLM involved —
    the same kind of source live tool results already are.

    DEMO-108679: this run called only entity-context + concurrency tools, no hunt —
    the live re-fetch of Sentinel/CloudTrail data came back with no commands at all
    (the event has aged past the retention this run's enrichment could reach), so
    cmd_gt was empty. But the ticket's OWN record — written the first time it was
    ever triaged, when the data was still fresh — already has the real command
    (`sudo zip -re INT-125399-mysql.zip ...`), and the model correctly recalled it.
    Without this, a TRUE statement gets flagged as fabricated purely because THIS
    run's fresh data-pull came back thinner than the historical one did.
    """
    if not jira_key:
        return ""     # nothing to look up (and no store round-trip to wait on)
    try:
        from edr_triage.store import get_alert_by_jira_key
        doc = get_alert_by_jira_key(jira_key)
        if doc and doc.get("l1_comment_deterministic"):
            return (doc.get("l1_comment") or "").lower()
    except Exception as exc:
        logger.debug("grounding check: stored-alert lookup failed for %s: %s", jira_key, exc)
    return ""


# Tool-result keys that repeat what the MODEL sent rather than what the source returned.
_TOOL_ECHO_KEYS = frozenset({"kql", "query", "error"})

_SLASH_WORDS = re.compile(r"^[a-z][a-z_-]*(?:/[a-z][a-z_-]*)+$")


def _slash_alternatives(cmd: str) -> list[str]:
    """`sudo systemctl restart/status x` -> both commands. Only a bare word/word token is
    expanded (never a path: those start with '/' or contain '.'), and only the first one."""
    toks = cmd.split()
    for i, t in enumerate(toks):
        if _SLASH_WORDS.match(t):
            return [" ".join(toks[:i] + [w] + toks[i + 1:]) for w in t.split("/")]
    return [cmd]


def _apply_grounding_check(result: AgentResult, evidence: dict, user_name: str,
                           tool_calls: list[ToolCallRecord], jira_key: str = "",
                           alert: dict | None = None) -> AgentResult:
    """Deterministic hallucination backstop for AUTO_CLOSE verdicts.

    An auto-close whose reasoning rests on a FABRICATED detail — an actor, command, or
    domain that appears nowhere in the alert fields, any tool result, or this ticket's
    OWN prior (deterministic) record — is unreliable and must not close a ticket.
    Catches the DEMO-107147 failures: the model read 'charlie' out of the IAM role name
    `ssm-session-testing-charlie-role` and invented a `sudo su` command the alert
    never listed, then auto-closed FP at 90%. One-directional: only downgrades an
    auto-close to NEEDS_L2, never relaxes a verdict. `jira_key` is optional and used
    only to look up the ticket's own stored record — omitting it simply narrows
    ground truth back to live evidence + this run's tools, the original behaviour.
    `alert` is optional too, used only by the domain check below for the alert's raw
    description text — omitting it just narrows that one check's ground truth.
    """
    if result.triage_class not in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP"):
        return result
    reasoning = result.reasoning
    if isinstance(reasoning, (list, tuple)):
        reasoning = " ".join(str(x) for x in reasoning)
    reasoning = reasoning or ""
    if not reasoning.strip():
        return result
    ev = evidence or {}

    def _blob(*xs) -> str:
        parts: list[str] = []
        for x in xs:
            if isinstance(x, (list, tuple)):
                parts.extend(str(i) for i in x)
            elif isinstance(x, dict):
                parts.append(" ".join(f"{k} {v}" for k, v in x.items()))
            elif x:
                parts.append(str(x))
        return " ".join(parts).lower()

    tool_blob = _blob(*[f"{tc.name} {tc.args} {tc.result}" for tc in (tool_calls or [])])
    stored_gt = _stored_alert_command_gt(jira_key)   # one lookup, used by both checks
    cmd_gt = (_blob(ev.get("command_lines"), ev.get("initiating_process")) + " " + tool_blob
              + " " + stored_gt)

    # (1) Fabricated ACTOR — narrowly: a name the model read OUT OF THE IAM ROLE string.
    #     That is the failure this guards (DEMO-107147: 'charlie' derived from
    #     `ssm-session-testing-charlie-role`), and the block message says as much.
    #
    #     It used to flag ANY word following "user" that wasn't in the actor fields,
    #     which is ordinary English far more often than it is a fabricated identity —
    #     it blocked correct auto-closes on "…privilege escalation (user switching, not
    #     root)" (DEMO-107206) and "The user discrepancy (`nico.bh…`)" (DEMO-107341),
    #     and each block then cascaded via the concurrent-open-alerts gate. A stopword
    #     list can't fix that; it's whack-a-mole over the whole dictionary.
    #
    #     So require the claimed token to actually occur inside the role/ARN string.
    #     `actor_gt` deliberately excludes the role, so "in the role but not an actor"
    #     is precisely the role-name/actor confusion — and nothing else trips it.
    #     Tradeoff: a fabricated name invented from thin air (not role-derived) is no
    #     longer caught here. That is deliberate — it was costing more correct closes
    #     than it caught fabrications — and the opt-in LLM grounding critic plus the
    #     remaining gates still cover it.
    # Individual identities (not just the joined blob) so a self-correction check
    # below can test "does the model name any of the REAL actors nearby", not just
    # "does one appear somewhere in the whole reasoning".
    actor_list = [str(x).lower() for x in (
        user_name, ev.get("account_name"),
        (ev.get("user_arn") or "").rsplit("/", 1)[-1],   # ARN session principal
        # Co-users on a grouped multi-user incident are real actors from the incident's
        # own Account entities — naming one is grounded, not a fabrication. Widening the
        # actor set can only make this gate fire LESS, never more.
        *(str(u) for u in (ev.get("additional_users") or []) if u),
    ) if x]
    actor_gt = " ".join(actor_list)
    # Tool RESULTS minus the keys that echo the model's own query back: hunt_* returns its
    # KQL as `kql` (and errors often quote it), so a 0-row hunt for `AccountName ==
    # 'charlie'` would otherwise "ground" the very name the model read out of the role.
    def _result_data(r):
        return ({k: v for k, v in r.items() if k not in _TOOL_ECHO_KEYS}
                if isinstance(r, dict) else r)
    actor_evidence = (_blob(ev.get("command_lines"), ev.get("initiating_process"))
                      + " " + _blob(*[f"{_result_data(tc.result)}" for tc in (tool_calls or [])])
                      + " " + stored_gt)
    role_blob = " ".join(str(x).lower() for x in (
        ev.get("session_issuer"), ev.get("user_arn"),
    ) if x)
    # Chars of reasoning scanned AFTER a claimed token for a same-breath correction to
    # a real actor. DEMO-107497: "...executed by the user `charlie` (confirmed as
    # `sage.kapoor@example.com` via the AWS session ARN)" — the model read a name out
    # of the role string, then immediately grounds it in the same sentence. That is the
    # model catching its own slip, not the unreliable-reasoning failure mode this gate
    # exists for, and blocking it costs a correct close for nothing. Short and adjacent
    # on purpose: a coincidental mention of the real actor three paragraphs away (which
    # happens in nearly every reasoning block, since the real actor is usually discussed
    # at length) must not count as a correction.
    _SELF_CORRECT_WINDOW = 220
    for m in re.finditer(r"users?\s+(?:was\s+|is\s+|named\s+)?['\"`]?([A-Za-z0-9._@-]{3,})", reasoning, re.I):
        # Strip a trailing sentence-final period the char class happily captured along
        # with the token (e.g. "...not the user directly. The user ..." -> "directly."):
        # unlike a quote/backtick, '.' is a valid mid-token char (emails, decimals) so it
        # can't be excluded from the class itself, only trimmed off a captured token that
        # turned out to end the sentence instead of continuing it.
        claimed = m.group(1).strip("'\"` ").rstrip(".").lower()
        if claimed in _ACTOR_STOPWORDS or claimed.isdigit():
            continue
        # Not derived from the role string → not the failure mode this gate exists for.
        if not claimed or not role_blob or claimed not in role_blob:
            continue
        if claimed in actor_gt:
            continue
        # Grounded by the alert's own commands or a tool RESULT as a whole word: on these
        # hosts SSM sessions run as the local Linux account `charlie`, and DEMO-112567's own
        # commands were `id charlie` / `id -u charlie`, so "the user charlie" was a fact,
        # not a name read out of the role. Tool ARGUMENTS are excluded (they would echo the
        # model's claim back), and the word boundary keeps `...-charlie-role` from counting.
        if re.search(rf"(?<![a-z0-9._-]){re.escape(claimed)}(?![a-z0-9._-])", actor_evidence):
            continue
        window = reasoning[m.end():m.end() + _SELF_CORRECT_WINDOW].lower()
        if any(a in window for a in actor_list):
            continue  # self-corrected nearby — not the failure mode this gate exists for
        # Same-sentence role/actor CONTRAST. The adjacency window above catches a slip the
        # model corrects in the next breath. It misses the commoner shape, where the slip
        # is in point 1 and the grounding is a later numbered point:
        #   "**AWS Context**: The AWS session ARN confirms that the actor is
        #    `oakley.das@example.com`, not the IAM role (`ssm-session-it-charlie-role`)."
        # Measured across 889 resolved rows this gate fired 4 times. Three carry exactly
        # that sentence and L1 had closed all three FP; the fourth (DEMO-108138) never names
        # the real actor anywhere and still blocks, which is the gate working. Blast radius
        # is therefore those 4 rows and nothing else.
        #
        # Demanding BOTH a real actor AND the full role string in ONE sentence is a
        # stronger test than proximity, not a weaker one: the model has to show it knows
        # the token is a role. Mentioning the actor alone proves nothing — the real actor
        # is discussed at length in nearly every reasoning block, which is exactly why the
        # window above is kept short.
        # `actor_list` carries the ARN's trailing principal, which degrades to the WHOLE
        # role string when the arn has no '/' — and then "sentence contains the role" would
        # satisfy both halves of the test below on its own, grounding nothing. Drop any
        # entry that IS a role/arn string; keep ones merely contained in it, since the real
        # principal is always a substring of its own arn.
        _role_strings = {str(x).lower() for x in (ev.get("session_issuer"),
                                                  ev.get("user_arn")) if x}
        _real_actors = [a for a in actor_list if a and a not in _role_strings]
        _role_words = [t for t in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]{3,}", role_blob)
                       if claimed in t and t != claimed]
        if _role_words and _real_actors and any(
            any(a in _s for a in _real_actors) and any(t in _s for t in _role_words)
            for _s in (x.lower() for x in re.split(r"(?<=[.!?])\s+", reasoning))
        ):
            continue
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_gate_kind = "grounding_actor"
        result.safety_block_reason = (
            f"Auto-close blocked: reasoning asserts user '{claimed}' not in the alert's "
            "actor fields — likely role-name/actor confusion (a name inside the IAM role "
            "is not a user). Cannot trust the FP; escalating."
        )
        return result

    # (2) Fabricated COMMAND — a quoted `sudo …` command absent from the alert commands
    #     and every tool result (privesc alerts are defined by their sudo/su commands, so
    #     a cited sudo command that isn't there is a mis-attribution).
    #     The comparison is whitespace-NORMALISED on BOTH sides. It used to normalise
    #     only the quoted string (`" ".join(q.split())`) while cmd_gt kept whatever
    #     whitespace the evidence carried, so a stored command containing a double space
    #     or a newline failed the substring test against its own normalised form and was
    #     reported as fabricated. Verified 2026-09-04 against this function: identical
    #     command allowed; same command with a doubled space BLOCKED; same command with a
    #     newline BLOCKED. DEMO-108127 was blocked on
    #     `sudo /bin/sh -c "echo BECOME-SUCCESS-..."` — the Ansible become wrapper, which
    #     these alerts carry routinely — and that block then cascaded through the
    #     concurrency gate onto DEMO-108180 and DEMO-108153, so one false block cost three
    #     misses.
    #
    #     No loss of sensitivity: a genuinely fabricated command does not appear in the
    #     evidence under ANY whitespace normalisation. This only stops the same command
    #     failing to match itself.
    cmd_gt_norm = " ".join(cmd_gt.split())
    for q in re.findall(r"`([^`]{2,120})`", reasoning):
        # A capture spanning a NEWLINE is not a command — it is the regex pairing the
        # wrong two backticks. DEMO-108127's reasoning carried 31 backticks (odd), because
        # the model wrote `(`sudo /bin/sh -c "echo BECOME-SUCCESS...")` and never closed
        # the quote before the paren. The regex then paired that opening tick with the one
        # starting the NEXT list item, capturing:
        #     sudo /bin/sh -c "echo BECOME-SUCCESS...") aligns with migration tasks.
        #            - **
        # which begins with "sudo " and is of course absent from the evidence. It blocked
        # a correct FP that both L1 and L2 confirmed, and the block then cascaded through
        # the concurrency gate onto DEMO-108180 and DEMO-108153 — one mis-paired backtick,
        # three misses. A real inline command never contains a newline plus list markup.
        if "\n" in q or "\r" in q:
            continue
        ql = " ".join(q.strip().lower().split())
        # An ABBREVIATED quote cannot be verified by substring match either way — the
        # model is summarising a long command, not fabricating one. Verify the part it
        # actually showed, as a prefix, rather than failing the whole string on the
        # ellipsis it deliberately added. Too short a prefix to be meaningful is skipped
        # rather than blocked: "sudo ..." asserts nothing to check.
        if "..." in ql:
            _prefix = ql.split("...", 1)[0].strip()
            if len(_prefix) < 16 or _prefix in cmd_gt_norm:
                continue
            ql = _prefix
        # A <placeholder> is the same kind of summary ("sudo systemctl restart <service>",
        # DEMO-115149): verify the part shown before it, as for an ellipsis.
        if "<" in ql:
            _prefix = ql.split("<", 1)[0].strip()
            if len(_prefix) < 16 or _prefix in cmd_gt_norm:
                continue
            ql = _prefix
        # "restart/status" is two real commands merged into one quote (DEMO-114452). Accept
        # it only when EVERY expansion is itself in the evidence.
        _alts = _slash_alternatives(ql)
        if len(_alts) > 1 and all(a in cmd_gt_norm for a in _alts):
            continue
        if ql.startswith("sudo ") and ql not in cmd_gt_norm:
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_gate_kind = "grounding_command"
            result.safety_block_reason = (
                f"Auto-close blocked: reasoning cites command `{q.strip()}` not present in the "
                "alert commands or any tool result (fabricated / mis-attributed); escalating."
            )
            return result

    # (3) Fabricated DOMAIN — a domain the model VirusTotal'd that appears nowhere in
    #     real evidence: not bound from GuardDuty/Netskope, not in a command line, not
    #     literally in the alert's own description, and not actually DISCOVERED by any
    #     other tool call (one whose own arguments didn't already name this domain, so
    #     its result isn't just echoing the fabrication back).
    #
    #     DEMO-112580: the GuardDuty EC2-DNS finding hadn't landed from Sentinel yet
    #     (`guardduty_dns` evidence was empty — the deterministic playbook's own comment
    #     said as much: "GuardDuty finding details were not available"), so the model had
    #     no real domain. The alert's own description read "...a remote host that is a
    #     known source of drive-by download attacks" — descriptive category text, not a
    #     hostname — and the model synthesized "drive-by-source-domain.com" out of it,
    #     VirusTotal'd its own invention (trivially clean — it isn't a domain anything
    #     could ever have flagged), and auto-closed FP at 95%. A human later found the
    #     real GuardDuty finding: a Trojan/DriveBySourceTraffic detection for
    #     `h5.acmetop.com` — a domain the model never saw, on a CONFIRMED true positive.
    #
    #     Checked against tool-call ARGUMENTS, not reasoning prose: the fabrication here
    #     is inventing what to investigate, not just what to claim afterward. `domain_gt`
    #     is deliberately broad (the whole evidence dict + alert description) — over-
    #     including ground truth only makes this gate MORE lenient, never a false block.
    domain_gt = _blob(ev, (alert or {}).get("_description", "") if isinstance(alert, dict) else "")
    for tc in (tool_calls or []):
        if tc.name != "vt_lookup_domain":
            continue
        _d = str((tc.args or {}).get("domain", "")).strip().lower()
        if not _d or _d in domain_gt:
            continue
        # A domain some OTHER tool call actually discovered (its own arguments never
        # named this candidate, so its result isn't just the fabrication bouncing back)
        # grounds it too. Excludes every vt_lookup_* call — those only ever echo their
        # own input domain/hash/ip back in the result, never discover one independently.
        _discovered = any(
            _d in _blob(f"{other.result}")
            for other in (tool_calls or [])
            if other is not tc and not other.name.startswith("vt_lookup")
            and _d not in _blob(f"{other.args}")
        )
        if _discovered:
            continue
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_gate_kind = "grounding_domain"
        result.safety_block_reason = (
            f"Auto-close blocked: domain '{_d}' was VirusTotal'd but appears nowhere in "
            "real evidence (not the alert's bound domain, description, command lines, or "
            "a genuine tool discovery) — looks synthesized from descriptive alert text "
            "rather than extracted. Cannot trust the FP; escalating."
        )
        return result

    return result


_COHOST_PREFETCH_MAX = 4


def _cohost_process(cmd: str) -> str:
    """The executable a recorded co-host command runs, for hunt_process: past sudo and its
    flags, basename of the first word. `sudo su` → su, `sudo ./startNgaNotisProd.sh` →
    startNgaNotisProd.sh; a bare `sudo -i` stays sudo."""
    toks = (cmd or "").split()
    while toks and (toks[0] == "sudo" or toks[0].startswith("-")):
        toks = toks[1:]
    return (toks[0].rsplit("/", 1)[-1] if toks else "sudo")[:80]


def _cohost_prefetch_targets(evidence: dict | None) -> list[dict]:
    """[{device, command, process}] for each co-host with a recorded command — none when
    there are more than _COHOST_PREFETCH_MAX (a fleet sweep; the multi-host gate decides)."""
    detail = [d for d in ((evidence or {}).get("additional_hosts_detail") or [])
              if isinstance(d, dict) and d.get("device_name") and d.get("command_lines")]
    if not detail or len(detail) > _COHOST_PREFETCH_MAX:
        return []
    out = []
    for d in detail:
        cmd = str(d["command_lines"][0]).split(", ")[0]
        out.append({"device": d["device_name"], "command": cmd, "process": _cohost_process(cmd)})
    return out


def _unassessed_co_hosts(co_hosts: list | None, tool_calls: list[ToolCallRecord]) -> list[str]:
    """Co-hosts of a grouped incident with no hunt telemetry — SCG "not seen before" /
    no history is NOT exculpatory, a host needs its OWN hunt to be cleared.

    Shared by the pre-verdict nudge in run() (gives the model a real chance to cover
    every host before a verdict is even accepted) and the hard gate below (the
    backstop if it still doesn't) — one definition of "covered" so the two can't drift
    and let a host the nudge considered done still trip the gate, or vice versa.
    """
    if not co_hosts:
        return []
    hunted = " ".join(
        str(tc.args) for tc in tool_calls
        if (tc.name.startswith("hunt_") or tc.name in ("mde_advanced_hunt", "sentinel_run_kql"))
        # A co-host hunt the code ran up front that failed covers nothing — the model's
        # own hunts keep counting exactly as before.
        and not ((tc.args or {}).get("prefetched") and (tc.result or {}).get("error"))
    ).lower()
    return [h for h in co_hosts if h and (str(h).split(".")[0].lower() not in hunted)]



def _dlp_evidence_incomplete(evidence: dict | None) -> str:
    """Reason string when the DLP bind is known not to show the whole incident, else "".

    Two distinct defects, both of which make an auto-close unsafe for the same reason —
    the verdict would rest on evidence we KNOW is partial:

      truncated        the row cap was hit, so events exist that were never fetched.
      bind_strict=False  the analytics rule's own filter returned nothing and the bind
                       fell back to selecting on alert_type_s alone. Those rows are a
                       superset of what the rule fires on, so the bound users are not
                       established to be the alert's subjects.

    DEMO-110841 is why this is a code gate and not a prompt line. The agent was shown 5
    users, none of them the user the alert was raised for, and wrote "**All five users**
    ... false positive" at 0.85 confidence. A model cannot detect that its evidence is
    missing someone; the completeness of the bind is knowable only here.

    One-directional like every other gate: it can escalate an auto-close, never create
    one. Returns "" when there is no DLP evidence, so non-DLP families are untouched.
    """
    _dlp = (evidence or {}).get("netskope_dlp") or {}
    if not _dlp:
        return ""
    if _dlp.get("truncated"):
        # bind_strict is reported here too. Without it the truncation message masked
        # whether the rule-accurate filter had matched at all, which is exactly the
        # question DEMO-110841 needed answered and could not be answered from the row.
        return (f"the DLP bind hit its row cap ({_dlp.get('event_count')} events "
                f"returned, {_dlp.get('events_shown')} shown, "
                f"bind_strict={_dlp.get('bind_strict')}) — events exist that were "
                f"never fetched, so the bound user list may be missing the alert's subject")
    if _dlp.get("bind_strict") is False:
        return ("the DLP bind fell back to selecting on alert_type_s alone because the "
                "analytics rule's own filter matched nothing — the bound rows are a "
                "superset of what this alert fires on, so these users are not "
                "established to be its subjects")
    return ""


_REDUNDANT_HUNT_SOURCES = (
    # (evidence key that must be bound with rows, substrings identifying a hunt that is
    #  re-fetching that SAME source). Both tables are already bound deterministically by
    #  a canned template precisely because hand-written KQL against them keeps failing.
    ("netskope_dlp", ("netskope",)),
    ("guardduty_dns", ("awsguardduty", "guardduty")),
)


def _redundant_bound_source_hunt(tc: ToolCallRecord, evidence: dict | None) -> bool:
    """True when this errored hunt was re-fetching a source ALREADY bound deterministically.

    The errored-hunt gate exists so an auto-close cannot rest on a failed query. But a
    hunt that failed while re-fetching evidence the pipeline had already bound is not an
    evidence gap at all — the verdict rests on the bound rows, not on the failed call.
    Same logic as the `source_empty` and `_self_corrected_tools` carve-outs above: the
    question that call was trying to answer was already answered.

    DEMO-110748, twice in a row: the DLP events were bound and rendered, the model read
    them, correctly concluded scanner-driven -> AUTO_CLOSED_FP at 0.90 (matching L1 and
    L2), then made one redundant Netskope_Alerts_CL hunt that died — first on an unknown
    column, then on unbalanced parentheses — and this gate overrode the right answer
    both times. oscar.py tells the model "do NOT re-query it"; it does anyway, and per
    this codebase's own record a prompt rule the model won't follow is not a control.

    Deliberately narrow: requires BOTH that the evidence key is bound WITH rows AND that
    the failed hunt names that same source. An errored hunt against anything else (a
    device process hunt, a sign-in query) is untouched and still blocks.
    """
    _args = str(getattr(tc, "args", "") or "").lower()
    if not _args:
        return False
    for _key, _needles in _REDUNDANT_HUNT_SOURCES:
        _bound = (evidence or {}).get(_key) or {}
        if not isinstance(_bound, dict):
            continue
        if not (_bound.get("events") or _bound.get("domains")):
            continue                      # nothing actually bound — no substitute evidence
        if any(_n in _args for _n in _needles):
            return True
    return False


def _unaddressed_actors(evidence: dict | None, reasoning: str) -> list[str]:
    """Actors on a multi-actor incident that this verdict never actually addressed.

    Modeled on `_unassessed_co_hosts` above, but for PEOPLE instead of hosts: a
    REQUEST_JUSTIFICATION addressed to one actor settles nothing about a co-actor who
    ran different commands on different hosts (DEMO-109720 — kiran's benign package
    install and morgan's log-tailing/docker-status checks were treated as one
    incident with two incidental extra names, not two people each needing their own
    evidence bar). Empty for a single-actor alert (`actor_hosts` has ≤1 entry there),
    so this can never fire outside a genuinely grouped incident.

    An actor counts as addressed if EITHER a standing justification precedent already
    covers them (`actor_justification_hits`, entity_graph/query.py — advisory context,
    same as every other SCG memory; never auto-close on it alone) OR the model's own
    reasoning names them, meaning it actually evaluated that person rather than
    reasoning about the incident as if only the primary actor existed.
    """
    groups = (evidence or {}).get("actor_hosts") or []
    if len(groups) <= 1:
        return []
    hits = (evidence or {}).get("actor_justification_hits") or {}
    _reasoning_lower = (reasoning or "").lower()
    unaddressed = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        actor = (g.get("actor") or "").strip()
        if not actor:
            continue
        if actor.lower() in hits:
            continue
        if actor.lower() in _reasoning_lower:
            continue
        unaddressed.append(actor)
    return unaddressed


def _service_fleet_cleared(evidence: dict | None, tool_calls: list[ToolCallRecord]) -> bool:
    """True when hunt_service already covers EVERY co-host for a service-process alert.

    oscar.py's prompt (the "EXCEPTION for this alert" block, gated the same way on
    process_check.distinct) tells the model hunt_service's fleet-wide TRUSTED verdict
    IS positive exculpatory evidence for every co-host — its device counts span the
    whole estate, so a per-host hunt_process call would answer a question hunt_service
    already answered. But that carve-out lived ONLY in the prompt; this deterministic
    gate had no matching exception, so it still demanded a per-host hunt and blocked
    the auto-close anyway (DEMO-106242/106568/107943/108101/108252/108605/108761/108863
    — 8 "Rare Process as a Service" misses across weeks, all showing every flagged
    process as TRUSTED in the model's own reasoning, still escalated by this gate).

    Deliberately strict: requires process_check.distinct (the same scope oscar.py's
    prompt uses — never applies to a non-service-process alert) and at least one
    hunt_service call. Reads the raw hash counts directly (TrustedHashes /
    UntrustedHashes), not the human-readable `verdict` string — robust to that
    string's wording changing later.

    Live MDE certificate telemetry has real coverage gaps: NoCertRecord / a name
    hunt_service never resolved at all means MDE never captured a cert row for that
    exact hash this run — inconclusive on live evidence ALONE, not evidence of
    anything. But some exact names in this gap (ipf_uf.exe, mfewc.exe, ...) were
    independently vetted against vendor documentation in the service_allowlist audit
    (14f9de4) — a second, static, human-reviewed source the model can't talk itself
    into. Falling back to that list for a coverage gap closes the SAME hole a
    NoCertRecord row leaves open, evidence-wise.

    This can only ever fill a "no data" gap, never override a bad signal: ANY row
    with UntrustedHashes > 0 (a hash chain that does NOT resolve to a trusted root
    — the actual masquerade tell) fails the whole check immediately, allowlist
    membership or not. A name already on the vetted list showing up with an
    untrusted-signed copy is exactly the scenario this gate exists to catch, not
    waive.
    """
    _pc = (evidence or {}).get("process_check") or {}
    if not _pc.get("distinct"):
        return False
    # A known vendor name running from a user-writable folder is the masquerade this
    # family exists to catch — never cleared by fleet arithmetic, whatever else is true.
    if _pc.get("misplaced"):
        return False
    _svc_calls = [tc for tc in tool_calls if tc.name == "hunt_service" and not tc.result.get("error")]
    if not _svc_calls:
        return False
    _rows = [r for tc in _svc_calls for r in (tc.result.get("rows") or [])]
    if not _rows:
        return False
    if any(int(r.get("UntrustedHashes") or 0) > 0 for r in _rows):
        return False
    # Signed copies on other hosts do not vouch for an unverified copy outside the
    # install folders: that is an impostor of the name, not a telemetry gap. A row from
    # before this column existed cannot show it, so it fails closed.
    if any(r.get("OddUnverifiedHashes") is None or int(r.get("OddUnverifiedHashes") or 0) > 0
           for r in _rows):
        return False
    from edr_triage.service_allowlist import is_known_good_at
    _alert_paths = _pc.get("paths") or {}

    def _vouched(name: str, mde_paths) -> bool:
        # The name-only fallback: the vetted list, and only where every path we have —
        # MDE's and the alert's own — is an admin-only install folder.
        n = (name or "").lower()
        return is_known_good_at(n, list(mde_paths or []) + list(_alert_paths.get(n) or []))
    for r in _rows:
        if int(r.get("TrustedHashes") or 0) <= 0 and not _vouched(r.get("FileName"), r.get("Paths")):
            return False
    for tc in _svc_calls:
        for _missing in (tc.result.get("not_found") or []):
            if not _vouched(_missing, []):
                return False
    return True


# An equivalent check has to be ABOUT alerts, and about OTHER ones. Two conditions
# rather than one phrase, because the wording varies: the real DEMO-108344 call read
# "Check for any open or recen…", which no fixed phrase like "open alerts" matches.
_CONC_SUBJECT_RE = re.compile(r"\balerts?\b|\bincidents?\b", re.I)
_CONC_QUALIFIER_RE = re.compile(
    r"\bconcurrent\b|\bopen\b|\bother\b|\brecent(?:ly)?\b|\bsibling\b|"
    r"\brelated\b|\badditional\b|\bsimultaneous\b",
    re.I,
)


def _concurrency_check_missing(tool_calls: list[ToolCallRecord]) -> bool:
    """True if concurrency was never VERIFIED this run — by any means.

    Shared by the pre-verdict nudge in run() (gives the model a real chance to make
    the call before a verdict is even accepted) and the hard gate below (the
    backstop if it still doesn't) — one definition so the two can't drift.

    Accepts an EQUIVALENT check, not just the one tool name. The gate exists so that
    concurrency is actually established before an auto-close; it is not there to
    enforce a spelling. DEMO-108344 did establish it — "the hunt_query for open or
    recently created alerts on the device dba-operations-0201 or the user … returned
    0 rows. This confirms there are no other open alerts" — reached AUTO_CLOSED_FP over
    8 iterations, and was escalated anyway because the answer arrived via hunt_query.
    Its two siblings in the same DB-migration burst (DEMO-108332, DEMO-108359) show the
    cost is not theoretical: the family diverges on tool choice rather than evidence.

    Deliberately narrow. It requires a hunt-shaped call whose ARGUMENTS ask about other
    alerts — not merely any tool that happened to run, and not a claim in the reasoning
    text. A model that never checked still fails, and a model that only SAYS it checked
    still fails: DEMO-108035 asserted "scg_check_concurrent_alerts confirmed that there
    are no other open alerts" having never called it, and this gate is what caught that
    fabrication. Reading the tool ARGS keeps that property — the model cannot talk its
    way past it, only query its way past it.
    """
    for tc in tool_calls:
        if tc.name == "scg_check_concurrent_alerts":
            return False
        # An equivalent query: a hunt whose own arguments are about other/open alerts.
        if tc.name in ("hunt_query", "sentinel_run_kql", "mde_advanced_hunt"):
            _a = str(tc.args or "")
            if _CONC_SUBJECT_RE.search(_a) and _CONC_QUALIFIER_RE.search(_a):
                if not (tc.result or {}).get("error"):
                    return False
    return True


def _concurrency_uncorrelatable(device_name: str, user_name: str) -> bool:
    """True when a concurrency check CANNOT correlate anything, so requiring it is empty.

    check_concurrent_alerts builds its filters from the device and — only if it is a
    real identity — the user. With no device AND a generic/shared account it builds
    ZERO filters and returns concurrent_count=0 without querying anything. Demanding a
    call that is structurally incapable of finding a sibling doesn't make an auto-close
    safer; it just costs iterations.

    That is not hypothetical. 'Rare and potentially high-risk Office operations' is an
    OfficeActivity alert with no host at all, acting as NT SERVICE\\MSExchangeAdminApi
    NetCore — no device, generic account. The agent auto-closed 7 of them (all matching
    the analyst's FP) and escalated DEMO-108121 having ALREADY concluded FP: "the
    mandatory scg_check_concurrent_alerts call failed to execute successfully … the
    auto-close safety rules cannot be satisfied". 8 iterations, 3 successful tool calls,
    confidence 0.00. The difference between the seven that closed and the one that did
    not was whether the model got a no-op call through before running out of turns —
    nothing about the alert.

    The gate is untouched wherever it can actually correlate: any real device, or any
    non-generic actor, still has to be checked.
    """
    from entity_graph.query import _is_generic_account
    if (device_name or "").strip():
        return False
    return not (user_name or "").strip() or _is_generic_account(user_name)


def _is_hunt_tool(name: str) -> bool:
    """Tools that EXECUTE a telemetry query (so an error is an evidence gap)."""
    return name.startswith("hunt_") or name in (
        "mde_advanced_hunt", "sentinel_run_kql", "mde_get_timeline",
    )


# Playbooks where "we looked and found nothing" is NOT exculpatory. Both are alert
# classes defined by an ACTION (a privilege gained, a credential used) rather than by
# an artefact, so failing to find the action in telemetry is an evidence gap, not a
# clean bill of health. Matches edr_triage.classifier playbook names.
_ABSENCE_SENSITIVE_PLAYBOOKS = frozenset(("privesc", "credential_access"))

# Tool args arrive as a flat string: "device='x', process_name='sudo', window_hours='24'".
# Only these keys name the SUBJECT of a hunt — deliberately excluding device/machine_id,
# so a hostname that happens to contain a subject word cannot make an unrelated
# host-wide sweep look like it asked about the alert.
_SUBJECT_ARG_KEYS = frozenset((
    "process_name", "file_name", "initiating_process", "sha256", "process", "command",
    # hunt_query describes its question in `intent` rather than in structured params, so
    # without this a model that asks the RIGHT question the flexible way gets no credit:
    # DEMO-107268's corroboration was hunt_query intent="Check if the commands 'id charlie'
    # ..." returning 50 rows, while its only structured hunt (process_name='sh') came back
    # empty. Reading intent is safe here in a way that reading REASONING is not — it is
    # the query the model issued, not its argument for a verdict.
    "intent",
))
_ARG_KV_RE = re.compile(r"(\w+)\s*=\s*'([^']*)'")


def _alert_subject_tokens(evidence: dict) -> set[str]:
    """Executable / file names that identify THIS alert's activity.

    Privesc alerts routinely carry no file_name and no initiating_process (DEMO-106604
    has both empty), so the command lines are usually the only source — every word of
    them, not just the first, because `sudo su` must yield BOTH `sudo` and `su` for a
    hunt on either to count as asking about this alert.
    """
    ev = evidence or {}
    toks: set[str] = set()

    def _add(raw) -> None:
        s = str(raw or "").strip().lower().strip("\"'")
        if s:
            toks.add(s.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])

    _add(ev.get("initiating_process"))
    _add(ev.get("file_name"))
    for cmd in (ev.get("command_lines") or []):
        for word in re.split(r"[\s;|&()]+", str(cmd or "").strip().lower()):
            if word and not word.startswith("-"):
                _add(word)
    # 2-char floor, NOT 3. The short names are the load-bearing ones on Linux privesc —
    # `id`, `sh`, `su`, `ps`. A 3-char floor silently dropped them, and DEMO-107740 shows
    # the cost: its corroborating hunt was process_name='id' returning 25 rows, which the
    # gate could not see, so it fired on the empty `sudo` hunt alone and would have
    # escalated a close that both L1 and L2 agreed with. Precision comes from matching
    # only against _SUBJECT_ARG_KEYS values, not from token length.
    # Numerals are dropped: command lines are full of them (`tail -n 100`) and they name
    # no process.
    return {t for t in toks if len(t) >= 2 and not t.isdigit()}


def _hunt_targets_subject(args, subjects: set[str]) -> bool:
    """True when this hunt ASKED ABOUT the alert's own process/file, rather than
    sweeping the host generally. Prefix-tolerant in both directions: recorded args are
    truncated ('check_changetracking_invent...'), so exact equality would silently miss."""
    if not subjects:
        return False
    for key, val in _ARG_KV_RE.findall(str(args or "")):
        if key.lower() not in _SUBJECT_ARG_KEYS:
            continue
        v = val.strip().lower().rstrip(".").rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if len(v) < 2:
            continue
        for t in subjects:
            if v == t or v.startswith(t) or t.startswith(v):
                return True
    return False


def _source_empty_unretried(tool_calls: list[ToolCallRecord], device_name: str) -> bool:
    """True when a hunt hit a genuinely empty Sentinel table (source_empty — the
    table holds no data at all, not "clean") and the agent never tried hunt_process
    afterward, on an alert that HAS a device to hunt.

    The tool's own error text already names the fix — "If this alert has a device,
    try MDE (hunt_events / hunt_process)" — but DEMO-109399 shows that text alone
    isn't reliable: the model read "SecurityEvent is EMPTY... not evidence of
    benign", acknowledged it in its own reasoning, and still reached AUTO_CLOSED_FP
    on a Root Privilege Escalation (`su netra`) that hunt_process could have
    answered directly — then got escalated by the errored-hunt gate anyway, at the
    cost of a miss the right tool call would likely have avoided. A mechanical
    retry, not one more line of prompt text, forces the actual right call before a
    verdict is accepted.

    device_name gates this: a deviceless alert's remedy is hunt_query against the
    real source table (OfficeActivity, SigninLogs, ...), not hunt_process — nudging
    toward a tool that cannot possibly help would just waste a turn.
    """
    if not device_name:
        return False
    if not any((tc.result or {}).get("source_empty") for tc in (tool_calls or [])):
        return False
    return not any(tc.name == "hunt_process" for tc in (tool_calls or []))


def _hunt_rows(result: dict) -> int:
    """Row/event count a hunt returned, across the tools' differing result shapes."""
    if not isinstance(result, dict) or result.get("error"):
        return 0
    n = result.get("count")
    if isinstance(n, int):
        return n
    for key in ("rows", "events"):
        v = result.get(key)
        if isinstance(v, list):
            return len(v)
    return 0


# How many INDEPENDENT hunts must have come back with actual data before a separate
# errored hunt stops blocking an auto-close. 2 = the verdict rests on corroboration
# from more than one successful source, not on the failed one.
_CORROBORATING_HUNTS_REQUIRED = 2


def _ti_flagged_detail(tc: ToolCallRecord) -> str | None:
    """One line describing why this tool call is a zero-tolerance TI hit, or None.

    Covers both reputation sources so a real detection can't slip past the "never
    auto-close on this" gates just because it came from AbuseIPDB instead of
    VirusTotal — the two draw on different report data and either can catch what the
    other misses. vt_lookup_*: `detections > 0` out of `total` engines. AbuseIPDB has
    no engine ratio; `abuse_confidence_score` at or above their own published
    high-confidence threshold (agent_tools.abuseipdb.ABUSE_CONFIDENCE_MALICIOUS_THRESHOLD)
    is the equivalent "zero tolerance" line for that source.
    """
    if tc.name.startswith("vt_lookup") and tc.result.get("detections", 0) > 0:
        return f"VT returned {tc.result['detections']}/{tc.result.get('total', '?')} detections"
    if tc.name == "abuseipdb_lookup_ip":
        from agent_tools.abuseipdb import ABUSE_CONFIDENCE_MALICIOUS_THRESHOLD
        score = tc.result.get("abuse_confidence_score", 0)
        if score >= ABUSE_CONFIDENCE_MALICIOUS_THRESHOLD:
            return (f"AbuseIPDB returned {score}/100 abuse confidence "
                    f"({tc.result.get('total_reports', '?')} reports)")
    return None


def _named_threat_detection(evidence: dict, alert_name: str = "") -> str:
    """The Defender/EDR threat classification on this alert, or "".

    A NAMED detection (`Behavior:Win32/Ransomware!NoteStr.A`, `HackTool:Python/...`,
    `Trojan:...`) is the EDR engine's own positive identification — categorically
    different from a heuristic score. oscar.py already tells the model to weigh it at
    least as heavily as VirusTotal and never to dismiss it on a VT-clean hash, but a
    prompt rule is not enforcement: on DEMO-107770 the model quoted that very rule
    ("The alert is a named Defender detection") and then talked itself past it.
    """
    ev = evidence or {}
    name = str(ev.get("threat_name") or "").strip()
    if name:
        return name
    # Fall back to the alert title for paths that don't populate threat_name
    # (Sentinel/Netskope-origin malware alerts carry it only in the name).
    if re.search(r"ransomware|malware|hacktool|trojan|backdoor|stealer|webshell|"
                 r"exploit|pwdump|impacket|credential dump",
                 alert_name or "", re.I):
        return (alert_name or "").strip()
    if str(ev.get("category") or "").strip().lower() == "malware":
        return f"category={ev.get('category')}"
    return ""


def _grantor_resolved_as(tool_calls: list[ToolCallRecord], user_name: str) -> bool:
    """True when hunt_identity_grant proved `user_name` PERFORMED a privileged grant.

    The identity-grant RJ upgrade exists because the alert names the recipient and the
    grantor is absent, so asking the named user is asking someone who may have done
    nothing. hunt_identity_grant closes that gap — but only for the specific shape where
    the grantor it resolved is the very account on the ticket. Everything else must keep
    the upgrade:
      - no hunt / no rows        -> grantor unknown, nobody verified to ask
      - AUTOMATED (app acted)    -> no human to ask at all
      - SELF-GRANT               -> nobody independent authorised it; that is L2's call
      - DELEGATED by SOMEONE ELSE-> the actor exists but is NOT user_name, so asking
                                    user_name is still asking the wrong person
    Deliberately reads the DELEGATED verdict string this tool writes rather than
    re-deriving actor/recipient here, so the two cannot drift apart.
    """
    _me = (user_name or "").strip().lower()
    if not _me:
        return False
    for tc in (tool_calls or []):
        if getattr(tc, "name", "") != "hunt_identity_grant":
            continue
        res = getattr(tc, "result", None)
        if not isinstance(res, dict):
            continue
        for row in (res.get("rows") or []):
            if not str(row.get("verdict") or "").startswith("DELEGATED"):
                continue
            actor = str(row.get("Actor") or "").strip().lower()
            recipient = str(row.get("Recipient") or "").strip().lower()
            # Must be the ACTOR, not merely present in the row — on DEMO-106406 the same
            # person appears as recipient of a separate automated grant.
            if actor and actor == _me and actor != recipient:
                return True
    return False


def _concurrency_blockers(details: list[dict], this_name: str, this_dev: str) -> list[dict]:
    """The concurrent siblings that still block a close, after discounting duplicates.

    A same-name-same-host sibling is a DUPLICATE (see the concurrency gate in
    _apply_safety_gates) — EXCEPT one a human has handed to L2 and not resolved. The
    carve-out exists for bursts the AI routed against each other; an analyst's escalation
    is a human judgement that this activity is NOT settled. DEMO-113523 closed FP calling
    DEMO-113288 "a duplicate" — 113288 was an L1 escalation ("assumed role, lack of MFA,
    programmatic access") still open with L2. It keeps blocking; when L2 resolves it the
    closure poller re-triggers this ticket via blocked_by_concurrent_keys.
    """
    return [d for d in details
            if d.get("human_held")
            or not ((d.get("alert_name") or "").strip().lower() == this_name
                    and (d.get("device_name") or "").strip().lower() == this_dev)]


def _is_malware_alert(alert_name: str) -> bool:
    """True for an alert that is itself a named-malware detection."""
    from entity_graph.query import MALWARE_ALERT_RE
    return bool(MALWARE_ALERT_RE.search(alert_name or ""))


_NATIONAL_ID_MARKERS = ("national", "aadhar", "aadhaar", "pan ")


def _dlp_has_national_id(evidence: dict | None) -> bool:
    """True when any bound Netskope DLP event is a national-ID (PAN/Aadhaar) finding.
    Same reading as the playbook's _dlp_all_secret_key: the profile and rule names."""
    for e in (((evidence or {}).get("netskope_dlp") or {}).get("events") or []):
        blob = f"{e.get('dlp_profile') or ''} {e.get('dlp_rule') or ''} ".lower()
        if any(m in blob for m in _NATIONAL_ID_MARKERS):
            return True
    return False


_USB_COPY_RE = re.compile(r"files? copied to (?:usb|removable)", re.I)


def _is_usb_copy_alert(alert_name: str) -> bool:
    return bool(_USB_COPY_RE.search(alert_name or ""))


def _office_human_actors(alert_name: str, user_name: str, evidence: dict | None) -> list[str]:
    """The PEOPLE an Office-operations alert names. The rule excludes Exchange's own
    service identities, so every person it lists did one of its rare operations."""
    if "office operations" not in (alert_name or "").lower():
        return []
    from entity_graph.query import _is_generic_account
    seen: list[str] = []
    for u in [user_name, *((evidence or {}).get("additional_users") or [])]:
        u = str(u or "").strip()
        if u and not _is_generic_account(u) and u.lower() not in (s.lower() for s in seen):
            seen.append(u)
    return seen


# Inbox-rule operations a person may run on their own mailbox; anything else a person does
# under this rule (permissions, forwarding via Set-Mailbox, transport rules) goes to a human.
_SELF_RULE_OPS = frozenset(("new-inboxrule", "set-inboxrule", "enable-inboxrule",
                            "updateinboxrules"))
# A rule that sends mail away, destroys it or hides it. MoveToFolder into one of these
# folders, or with MarkAsRead, is how a takeover hides replies from the owner.
_RULE_DANGER_KEYS = ("forwardto", "redirectto", "forwardasattachmentto", "forwardingsmtpaddress",
                     "forwardingaddress", "grantsendonbehalfto", "trustee", "accessrights")
_RULE_TRUE_DANGER = ("deletemessage", "softdeletemessage", "markasread",
                     "delivertomailboxandforward", "autoforwardenabled")
_HIDING_FOLDER = re.compile(r"rss|conversation history|archive|junk|deleted|notes|outbox|"
                            r"sync issues|^[A-Za-z0-9+/=]{20,}$", re.I)
_KEYSETTING = re.compile(r"(\w+)=(.*?)(?=, \w+=|$)")


def _office_rule_risk(person: str, tool_calls: list) -> str:
    """Why `person`'s Office operation is not shown to be harmless, or "" when a hunt_office
    result holds their inbox rule(s) and every one only moves mail into an ordinary folder."""
    local = person.lower().split("@")[0]
    rows = []
    for tc in tool_calls or []:
        if getattr(tc, "name", "") != "hunt_office" or not isinstance(tc.result, dict):
            continue
        rows += [r for r in (tc.result.get("rows") or [])
                 if isinstance(r, dict) and local in str(r.get("UserId", "")).lower()]
    from lib.kql_templates import OFFICE_READ_NOISE
    noise = {o.lower() for o in OFFICE_READ_NOISE}
    rows = [r for r in rows if str(r.get("Operation", "")).lower() not in noise]
    if not rows:
        return "their own operation was never retrieved"
    for r in rows:
        op = str(r.get("Operation", ""))
        if op.lower() not in _SELF_RULE_OPS:
            return f"{op} is not an inbox rule"
        if str(r.get("ExternalAccess", "")).lower() == "true":
            return f"{op} came from outside the tenant"
        for k, v in _KEYSETTING.findall(str(r.get("KeySettings") or "")):
            k, v = k.lower(), v.strip()
            if k in _RULE_DANGER_KEYS and v:
                return f"{op} sets {k}={v[:60]}"
            if k in _RULE_TRUE_DANGER and v.lower() == "true":
                return f"{op} sets {k}=True"
            if k == "movetofolder" and _HIDING_FOLDER.search(v.strip(":\\ ")):
                return f"{op} moves mail to '{v[:40]}'"
    return ""


# Remote-access tools. Acme blocks AnyDesk, TeamViewer, Ammyy and UltraViewer with custom
# MDE indicators (edr_triage/classifier.py _BLOCK_TOOL_PATTERNS); the rest are the same
# class and the usual way a scammer or intruder keeps a hand on a machine. A valid vendor
# signature says who built it, not that it is allowed here. DEMO-117622 closed FP on
# "ultraviewer_service.exe is TRUSTED (signed by DUC FABULOUS CO.)" running as a service.
_REMOTE_ACCESS_RE = re.compile(
    r"\b(?:anydesk|teamviewer|ultraviewer|ammyy|rustdesk|screenconnect|connectwise\s*control|"
    r"splashtop|supremo|aeroadmin|radmin|remoteutilities|rutserv|rfusclient|getscreen|"
    r"dwservice|dwagent|zohoassist|zaservice|meshagent|tightvnc|ultravnc|realvnc|tvnserver|"
    r"winvnc|atera|logmein|gotoassist|parsec|nomachine|remotepc|iperius)", re.I)


def _remote_access_tool(evidence: dict | None, tool_calls: list) -> str:
    """A remote-access tool named by the alert or by data a tool returned, or "". The model's
    own query text (args, the `kql` a hunt echoes) is not read: asking is not finding."""
    parts = [str(evidence or "")]
    for tc in tool_calls or []:
        r = getattr(tc, "result", None)
        parts.append(str({k: v for k, v in r.items() if k != "kql"} if isinstance(r, dict) else r))
    m = _REMOTE_ACCESS_RE.search(" ".join(parts))
    return m.group(0) if m else ""


# Letters of a non-Latin script inside English reasoning. Mistral occasionally degrades
# mid-answer (DEMO-116237: "returned Egyes were clean", "shared/built-in었으며 account").
_FOREIGN_RUN = re.compile(r"[^\W\d_A-Za-zÀ-ɏ]+")


def _garbled_reasoning(reasoning: str, tool_calls: list, evidence: dict | None) -> str:
    """A run of non-Latin letters the alert and tool results never contained, or "".
    Text quoted from real data (a Hindi file name, a Cyrillic domain) is not counted."""
    runs = [r for r in _FOREIGN_RUN.findall(reasoning or "") if len(r) >= 2]
    if not runs:
        return ""
    hay = str(evidence or "") + " ".join(str(getattr(tc, "result", "")) for tc in tool_calls or [])
    for r in runs:
        if r not in hay:
            return r
    return ""


def _apply_safety_gates(result: AgentResult, severity: str, is_test_device: bool, tool_calls: list[ToolCallRecord],
                        deterministic_fp: bool = False, co_hosts: list | None = None,
                        device_name: str = "", user_name: str = "",
                        evidence: dict | None = None, alert_name: str = "",
                        alert_type: str = "", alert: dict | None = None,
                        prior_malware: list | None = None,
                        open_urgent: list | None = None) -> AgentResult:
    """Apply hard safety rules that override the agent's verdict.

    `deterministic_fp` marks a documented, rule-based FP (e.g. a port sweep on a
    SOC-allowlisted known-good port) — the same call the port_sweep playbook makes
    unconditionally. For those the allowlist match IS the exculpatory evidence, so
    the evidence-floor and severity/confidence gates don't apply; the test-device
    gate still does.
    """
    sev = severity.upper()

    # Deterministic upgrade, NEEDS_L2 -> AUTO_CLOSED_FP: oscar.py's prompt already
    # tells the model that hunt_service's fleet-wide TRUSTED verdict on a
    # service-process alert IS positive exculpatory evidence for every co-host, and
    # 194ba64 stopped the multi-host gate from undoing that once the model reaches
    # AUTO_CLOSED_FP. But the model routinely never reaches it in the first place —
    # re-triage of the "Rare Process as a Service" backlog post-194ba64 still showed
    # DEMO-107372/108101/108252/108863/106242 all landing on pre_safety_class ==
    # NEEDS_L2, each reasoning that every flagged process came back trusted, then
    # escalating anyway on host count alone ("100+ co-hosts remain uninvestigated"),
    # the exact thing the prompt tells it not to do. A prompt rule the model won't
    # reliably follow is not a safety property; trust the code-verified evidence
    # instead, but ONLY for this narrow, code-verified shape (_service_fleet_cleared
    # is unchanged, strict, and scoped to process_check alerts) and only absent any
    # independent red flag. Confidence is raised to clear the severity threshold
    # below — the fleet-wide signer clearance IS the evidence, not a hedge — and
    # every downstream gate (test device, evidence floor, concurrency-call-required,
    # CRITICAL, confidence) still runs normally against this upgraded verdict, so a
    # case like DEMO-106568 (hallucinated "zero concurrent alerts" with no matching
    # tool call) still correctly escalates. Doesn't help tickets with a genuinely
    # unresolved binary (DEMO-106078/108976: real "no certificate data" gaps) or a
    # run where hunt_service was never called at all (DEMO-108761) — those need
    # allowlist/data fixes or a clean re-run, not this gate.
    if (result.triage_class == "NEEDS_L2"
            and not result.blocked_by_safety
            and _service_fleet_cleared(evidence, tool_calls)
            and not _named_threat_detection(evidence or {}, alert_name)
            and not any(_ti_flagged_detail(tc) for tc in tool_calls)):
        result.triage_class = "AUTO_CLOSED_FP"
        result.confidence = max(result.confidence, 0.90)

    # National-ID DLP is never a false positive from the model. Policy (2026-09-22) is to
    # ask the file's owner and let L2 decide on the answer, and the playbook already does
    # that — but the agent kept returning AUTO_CLOSED_FP on these, resting on recalled
    # "prior FPs for this user" and an invented "user is HR team" (52 of 160 stuck
    # tickets, quarantine audit 2026-10-12), so the recommendation contradicted the
    # action. Rewritten to REQUEST_JUSTIFICATION BEFORE the RJ block below, so every RJ
    # guard (nobody to ask, CRITICAL, TI flag, ...) still upgrades it to NEEDS_L2.
    # Only ever moves away from a close; the agent never closes DLP (0550bf4), so this
    # changes the recorded recommendation, not any ticket action.
    if result.triage_class == "AUTO_CLOSED_FP" and _dlp_has_national_id(evidence):
        result.triage_class = "REQUEST_JUSTIFICATION"
        result.blocked_by_safety = True
        result.safety_gate_kind = "dlp_national_id"
        result.safety_block_reason = (
            "National-ID DLP finding — policy is to ask the owner and let L2 decide; "
            "the model may not call it a false positive.")

    # A copy to removable media is cleared by the copier's reason for THAT copy. DEMO-116268
    # and DEMO-116658 recommended FP because "the same SanDisk SSD" was in prior FPs and the
    # files were "Acme-related" — company files on a personal drive is the risk, and an
    # earlier answer covers only the earlier copy. v-uma.grover was never asked.
    # One exception, decided by Sentinel and not the model: when no removable drive was
    # involved at all (usb_guard.drive_check — an internal SATA drive's letterless mount made
    # the rule match a local-disk write; DEMO-118633, 23 of 50 USB alerts in 60 days), there
    # is no copy to justify. Every gate below still runs on the FP verdict.
    _usb_internal = ((evidence or {}).get("usb_drive_check") or {}).get("internal") is True
    if (result.triage_class == "AUTO_CLOSED_FP" and _is_usb_copy_alert(alert_name)
            and not _usb_internal):
        from entity_graph.query import _is_generic_account
        result.triage_class = ("NEEDS_L2" if _is_generic_account(user_name)
                               else "REQUEST_JUSTIFICATION")
        result.blocked_by_safety = True
        result.safety_gate_kind = "usb_copy_needs_reason"
        result.safety_block_reason = (
            "Files copied to a USB drive — only the copier's reason for THIS copy clears it; "
            "a drive or user cleared before, or files that look like company work, does not.")

    _rat = _remote_access_tool(evidence, tool_calls) if result.triage_class == "AUTO_CLOSED_FP" else ""
    if _rat:
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_gate_kind = "remote_access_tool"
        result.safety_block_reason = (
            f"Remote-access tool in the evidence ({_rat}) — whether it is allowed on this host "
            "is a policy question for a person; a vendor signature does not answer it.")

    # Office operations naming a PERSON. Every autonomous close of this family had been
    # Exchange's service account changing system mailboxes; the 2 of 80 tickets (90 days)
    # that also named a person were v-drew.calder creating inbox rules (DEMO-113070,
    # DEMO-108455). They were benign ("Move all messages from <colleague> to QA"), but RAPTOR
    # never looked: it judged the service account's Set-Mailbox and called him a
    # "misgrouping", so it would have said the same of a rule forwarding mail outside.
    # The close stands only when every person's own rule was retrieved and only files mail.
    _office_people = _office_human_actors(alert_name, user_name, evidence)
    _office_unsettled = [(p, _office_rule_risk(p, tool_calls)) for p in _office_people]
    _office_unsettled = [(p, why) for p, why in _office_unsettled if why]
    if result.triage_class == "AUTO_CLOSED_FP" and _office_unsettled:
        from entity_graph.query import _is_generic_account
        result.triage_class = ("NEEDS_L2" if _is_generic_account(user_name)
                               or len(_office_people) > 1 else "REQUEST_JUSTIFICATION")
        result.blocked_by_safety = True
        result.safety_gate_kind = "office_person_actor"
        result.safety_block_reason = (
            "Office operation by a person — "
            + "; ".join(f"{p}: {why}" for p, why in _office_unsettled[:5])
            + ". A change to someone's mailbox closes only when it is seen to just file mail.")

    # REQUEST_JUSTIFICATION is a WEAKER call than NEEDS_L2: it routes the ticket into
    # L1's AWAITING MORE INPUTS loop ("ask the principal to explain this") instead of an
    # L2 technical review. That makes it the one verdict a model could use to park a real
    # threat, so it is only permitted where a human explanation could actually settle the
    # question. Any danger signal, or the absence of someone to ask, upgrades it to
    # NEEDS_L2. One-directional in the SAFE direction (RJ → NEEDS_L2, never the reverse):
    # it can only ever add human scrutiny, never remove it, and it cannot touch any
    # existing verdict class — so no currently-working path changes behaviour.
    if result.triage_class == "REQUEST_JUSTIFICATION":
        _rj_block = ""
        if not (user_name or "").strip():
            _rj_block = ("no acting principal identified — there is nobody to ask for a "
                         "business justification")
        # REMOVED 2026-09-02: a branch here upgraded RJ -> NEEDS_L2 whenever every bound
        # DLP event was a CASB API Scan, on the reasoning that a scanner sweep has no
        # actor to ask. The premise held; the DESTINATION was wrong. Measured across 490
        # scored rows, that branch produced 16 misses — every one of them a ticket the
        # human closed AUTO_CLOSED_FP. A scanner finding pre-existing files with no user
        # action is the case that should CLOSE, and this routed it to L2 instead.
        #
        # It also cannot be repaired in place: gates in this function are one-directional
        # and must only ever ADD scrutiny, so no branch here can produce the FP verdict
        # that was actually wanted. Whatever replaces it belongs on the deterministic
        # playbook path (alongside planned-activity and the auto_fp allowlist), not here.
        # Do not reintroduce an RJ -> NEEDS_L2 upgrade for scanner-driven DLP.
        elif (evidence or {}).get("actor_ambiguous"):
            _rj_block = (
                "actor ambiguous — SSM sessions by "
                f"{', '.join((evidence or {}).get('session_principals') or []) or 'several principals'} "
                "overlap the command, and telemetry cannot tell which of them ran it; asking "
                "one of them cannot settle it"
            )
        elif (evidence or {}).get("actor_reachable") is not True:
            # Asking is only possible if the person can receive the question. The Acme
            # Security Bot only speaks Slack, and a third of the directory is not in
            # slack-acme (BPO and most vendor accounts). A justification request that
            # cannot be delivered parks the ticket with nobody asked — DEMO-107682 sat in
            # Awaiting more inputs for a month that way. Fails closed: an absent or failed
            # lookup is treated as unreachable.
            _rj_block = (f"'{user_name}' cannot be asked via Slack "
                         f"({(evidence or {}).get('actor_reach_reason') or 'reachability unknown'})"
                         " — a justification request cannot be delivered")
        elif (oscar_module.is_privilege_grant_alert(alert_name)
              and not _grantor_resolved_as(tool_calls, user_name)):
            # On a role/group GRANT the alert names the RECIPIENT, not the grantor — the
            # acting principal is absent from the alert entirely (DEMO-106406: user_name was
            # the account added, while a different admin performed the grant). Asking the
            # named user to justify is asking the wrong person, and under the Phase-1 user
            # chase it would Slack an employee who did nothing. Until the initiator is
            # resolved from the Entra audit record, this class cannot be a justification
            # request. NOT a claim the activity is malicious — just that RJ is incoherent here.
            #
            # That "until" is now reachable: hunt_identity_grant resolves the initiator from
            # AuditLogs, so _grantor_resolved_as() in the condition above lifts this ONLY
            # when the hunt named a human grantor who IS the user on the ticket — i.e. the
            # person we would ask is provably the person who acted. Every other shape keeps
            # the upgrade: grantor unresolved, performed by an app, a self-grant, or a
            # grantor who is someone other than user_name (asking user_name would still be
            # asking the wrong person). The safety property is unchanged — never chase
            # someone who did nothing.
            _rj_block = (
                f"identity-grant alert — '{user_name}' is the account that RECEIVED the "
                "privilege, not the principal who granted it (the grantor is not in this "
                "alert), so there is no verified actor to ask"
            )
        elif not tool_calls:
            _rj_block = "no investigation performed (zero tool calls)"
        elif is_test_device:
            _rj_block = "known test/red-team device"
        elif sev == "CRITICAL":
            _rj_block = "CRITICAL severity"
        elif _named_threat_detection(evidence or {}, alert_name):
            _rj_block = (f"named EDR threat detection "
                         f"({_named_threat_detection(evidence or {}, alert_name)[:60]}) — "
                         "malware is not resolved by a user explanation")
        elif _unaddressed_actors(evidence, result.reasoning):
            _unaddressed = _unaddressed_actors(evidence, result.reasoning)
            _rj_block = (
                f"multi-actor incident — actor(s) {', '.join(_unaddressed)} have no "
                "justification precedent and are not addressed by this ask; a "
                "justification from one actor cannot cover another's activity"
            )
        else:
            for tc in tool_calls:
                _flag = _ti_flagged_detail(tc)
                if _flag:
                    _rj_block = _flag
                    break
        if _rj_block:
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_block_reason = (
                f"Justification request upgraded to L2: {_rj_block}. "
                + ("L2 must establish the activity another way."
                   if "cannot be asked via Slack" in _rj_block else
                   "This needs technical analysis, not a business justification.")
            )
        return result

    if result.triage_class not in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP"):
        return result

    # Test device — never auto-close (applies even to deterministic FPs)
    if is_test_device:
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_block_reason = "Known test/red-team device — auto-close blocked."
        return result

    # A close whose own explanation is corrupted is not a decision anyone can check.
    _garble = _garbled_reasoning(result.reasoning, tool_calls, evidence)
    if _garble:
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_gate_kind = "garbled_output"
        result.safety_block_reason = (
            f"The model's reasoning is corrupted (stray text '{_garble[:20]}' that appears in "
            "no alert field or tool result) — its verdict cannot be relied on.")
        return result

    # Ambiguous actor — never auto-close. The root command joins to the SSM sessions on
    # the instance by time window only; with more than one principal in that window the
    # evidence cannot say whose command it was (DEMO-112299), so any "benign because this
    # person routinely does this" reasoning rests on a guess.
    if (evidence or {}).get("actor_ambiguous"):
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_block_reason = (
            "Actor ambiguous — SSM sessions by "
            f"{', '.join((evidence or {}).get('session_principals') or []) or 'several principals'} "
            "on this host overlap the command; L2 must establish who ran it.")
        return result

    # Blank-bound slow-telemetry alert, still inside the ingestion-lag window — any
    # fleet-wide hunt result right now is necessarily unrelated activity (see
    # _too_early_for_blank_bound_evidence). Ahead of the deterministic_fp bypass:
    # this alert family has no known-good-allowlist shape, so it never applies here,
    # but the ordering keeps this check unconditional regardless.
    if result.triage_class == "AUTO_CLOSED_FP" and _too_early_for_blank_bound_evidence(
        alert_name, device_name, evidence, alert,
    ):
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_block_reason = (
            "Alert arrived with no bound device or command line, and this alert "
            "family's real telemetry takes 26-28 minutes to land — too early for any "
            "fleet-wide hunt result to be this alert's own activity. Deferred to the "
            "blank-arrival retry once the evidence exists."
        )
        # DEMO-110018: this gate fires precisely when no real evidence for THIS alert
        # can exist yet, so any specific claim in the model's narrative (a device, a
        # script name, a scan result) is by construction not traceable to a tool call
        # — the model wrote a confident FP story anyway, and it rendered ahead of the
        # safety_block_reason above where an analyst skims past it. Don't forward a
        # narrative the gate has just proven can't be grounded; the original is kept
        # in pre_safety_reasoning for debugging.
        logger.warning(
            "[AGENT-GATE] blank-arrival gate discarded ungrounded reasoning for alert "
            "%r: %s", alert_name, (result.pre_safety_reasoning or "")[:500],
        )
        result.reasoning = (
            "No investigation evidence exists yet for this alert — it arrived with no "
            "bound device or command line, so nothing gathered so far can be verified "
            "as this alert's own activity. See the safety-gate note below."
        )
        # The model's suggested actions rest on the same ungrounded narrative (e.g.
        # "close as FP" / "exclude <fabricated script>") and are actively wrong now
        # that the verdict is NEEDS_L2 — drop them rather than carry them forward.
        result.recommended_actions = []
        return result

    # Documented rule-based FP (e.g. known-good port sweep) — trust it like the
    # playbook does, bypassing the evidence-floor + severity/confidence gates.
    if deterministic_fp and result.triage_class == "AUTO_CLOSED_FP":
        return result

    # Evidence floor — never auto-close with zero investigation. A verdict reached
    # purely from the alert title/context (no tool call) has no exculpatory or
    # confirming evidence behind it; escalate. (The loop's evidence gate normally
    # forces investigation first; this is the backstop if it's ever bypassed.)
    if not tool_calls:
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_gate_kind = "evidence_floor"
        result.safety_block_reason = "Auto-close blocked: no investigation performed (zero tool calls) — cannot confirm verdict."
        return result

    # Concurrent-alert check must actually have been CALLED before an auto-close is
    # trusted — the model's own "no concurrent alerts" line in its reasoning is not
    # evidence of anything on its own. DEMO-107497: 7 tool calls, none of them
    # scg_check_concurrent_alerts, yet the reasoning still asserted "No concurrent
    # alerts for the same user/device were identified" — an unverified checklist
    # item, not an actual finding. Model-blind like the multi-host gate: it checks
    # tool-call history, not prose, so it can't be talked past by confident wording.
    # Skipped when there's no device/user to check against — the tool itself is a
    # no-op there (returns concurrent_count=0 immediately for two empty filters), so
    # requiring the call would just be busywork with no safety value. That skip was
    # keyed on `device_name or user_name`, which misses the case that actually bites:
    # a user_name that IS set but is a generic/shared account, which the query drops
    # for correlation exactly as if it were absent. See _concurrency_uncorrelatable.
    if (result.triage_class in ("AUTO_CLOSED_FP", "AUTO_CLOSED_TP")
            and (device_name or user_name)
            and not _concurrency_uncorrelatable(device_name, user_name)):
        if _concurrency_check_missing(tool_calls):
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_gate_kind = "concurrency_check_missing"
            result.safety_block_reason = (
                "Auto-close blocked: scg_check_concurrent_alerts was never called — "
                "concurrency cannot be verified, escalating."
            )
            return result

    # CRITICAL — never auto-close
    if sev == "CRITICAL":
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_block_reason = "CRITICAL severity — never auto-close."
        return result

    # Confidence thresholds
    thresholds = {"HIGH": 0.95, "MEDIUM": 0.80, "LOW": 0.70}
    threshold = thresholds.get(sev, 0.70)
    if result.confidence < threshold:
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_block_reason = f"{sev} severity requires confidence >= {threshold:.0%}, got {result.confidence:.0%}."
        return result

    # A NAMED EDR threat detection is never auto-closed as FP by the model alone.
    # Measured before shipping: of 31 named-threat alerts in the shadow set the agent
    # auto-closed 5 — and 4 of those were wrong, TWO of them confirmed AUTO_CLOSED_TP
    # by L2 (DEMO-107506, DEMO-106071). A 20% hit rate on the single most severe alert
    # class, at 0.95 confidence every time. The recurring failure shape is treating a
    # clean VT hash plus a "blocked/prevented" status as proof of benign, when the
    # binary is a LOLBin (powershell.exe is legitimately signed — the malice is in the
    # SCRIPT) and "blocked" only means this attempt was stopped, not that the activity
    # was authorised. DEMO-107770 was a deliberate ransomware simulation: 248 files
    # written in 21s then a ransom note, auto-closed FP at 0.95.
    # Escalation, not suppression: NEEDS_L2 still lets a human close it FP, and TP
    # verdicts are untouched — only the model unilaterally clearing a named detection
    # is blocked. Cost is bounded (1 of the 5 was a correct FP).
    # An auto-close should not rest on a DLP bind we know is incomplete — but as shipped
    # this gate blocked EVERY DLP auto-close, because truncation turned out to be the
    # normal case, not the exception: the +/-6h window on `alert_type_s =~ "DLP"` holds
    # 200+ rows routinely (measured on DEMO-110841, 110808, 110754 — all three hit the
    # cap). It would have taken DLP from a 76% auto-close rate to ~0.
    #
    # So it is OFF by default until the bind is narrow enough that truncation means
    # something. Raising the row cap is NOT the fix: 200 rows already resolve to only
    # ~14 users, and the alert's actual subject (yash.oberoi@example.com on
    # DEMO-110841) was still absent — so rows are being missed by the WINDOW, not by the
    # count. Prime suspect: this bind filters on TimeGenerated (ingestion time) while
    # the analytics rule carries Netskope's own `timestamp_t`, and Netskope ingestion
    # lag is already a known quantity here (see _BLANK_BOUND_LAG_MINUTES).
    #
    # Kept wired, not deleted: the reason string is logged on every DLP auto-close, so
    # the signal keeps accruing while costing nothing. Flip DLP_INCOMPLETE_BIND_GATE=true
    # to enforce once the bind binds only rows that could have fired the alert.
    if result.triage_class == "AUTO_CLOSED_FP":
        _incomplete = _dlp_evidence_incomplete(evidence)
        if _incomplete:
            if os.getenv("DLP_INCOMPLETE_BIND_GATE", "").lower() == "true":
                result.triage_class = "NEEDS_L2"
                result.blocked_by_safety = True
                result.safety_block_reason = f"Auto-close blocked: {_incomplete}."
                return result
            logger.warning("[AGENT-GATE] DLP auto-close on incomplete evidence "
                           "(gate disabled, observing only): %s", _incomplete)

    if result.triage_class == "AUTO_CLOSED_FP":
        _threat = _named_threat_detection(evidence or {}, alert_name)
        if _threat:
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_block_reason = (
                f"Auto-close blocked: named EDR threat detection ({_threat[:80]}) — "
                "a positive engine identification is not cleared by a clean VT hash or a "
                "'blocked' status; L2 must confirm."
            )
            return result

    # Any real TI detection (VirusTotal OR AbuseIPDB) — never auto-close as FP
    for tc in tool_calls:
        _flag = _ti_flagged_detail(tc)
        if _flag:
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_block_reason = f"{_flag} — zero tolerance, escalating."
            return result

    # A hunt that ERRORED leaves an evidence gap — don't auto-close as FP on it.
    # (A broken/sham KQL returns the same "nothing found" as genuinely-clean
    # telemetry; an errored hunt must not be read as proof of benign.)
    if result.triage_class == "AUTO_CLOSED_FP":
        # Any EXECUTED hunt that errored is an evidence gap → can't confirm benign.
        # Covers the deterministic hunt_* tools and hunt_query (all run a query) plus
        # the raw free-write tools. A pure KQL generator that ran no query would not
        # belong here — but hunt_query executes, so the hunt_ prefix correctly includes it.
        # mde_get_timeline counts as a hunt: it is an evidence source exactly like one,
        # and it could not error before — fetch_machine_timeline swallowed its 404 and
        # returned [], so a broken call reported count:0 with no error and read as
        # "clean". Now that it surfaces failures, the gate has to see them.
        # Hunts that SUCCEEDED and actually returned data. Rows-with-data, not merely
        # "no error": a successful hunt returning 0 rows proves nothing on its own, so
        # it must not count as the corroboration that lets a failed hunt slide.
        _corroborating = [tc for tc in tool_calls
                          if _is_hunt_tool(tc.name) and not tc.result.get("error")
                          and _hunt_rows(tc.result) > 0]
        # SELF-CORRECTED: if the SAME tool went on to return real data elsewhere in the
        # trajectory, an earlier error from it is not an evidence gap — the question that
        # call was trying to answer got answered, just on a later attempt. DEMO-108957:
        # hunt_process(no args) errored twice (a malformed call, not a broken query), then
        # hunt_process(device=..., process_name='tcpdump') came back with 6 rows — the gate
        # still blocked the auto-close because that single corroborating hunt fell short of
        # the unrelated-second-source bar below, penalizing a mistake the model had already
        # fixed. This does NOT forgive a genuinely broken query (DEMO-107802's nonexistent
        # table, DEMO-107932's empty-source case) — those tools never return real data no
        # matter how many times they're called, so they still fall through to the
        # unrelated-corroboration check.
        _self_corrected_tools = {tc.name for tc in _corroborating}
        # REDUNDANT: the failed hunt was re-fetching a source the pipeline had already
        # bound deterministically, so the verdict rests on those bound rows, not on the
        # failed call. See _redundant_bound_source_hunt (DEMO-110748).
        _all_errored = [tc for tc in tool_calls
                        if _is_hunt_tool(tc.name) and tc.result.get("error")
                        and tc.name not in _self_corrected_tools
                        and not _redundant_bound_source_hunt(tc, evidence)]
        # An EMPTY-SOURCE result (`source_empty`) is not a failed query. It is a
        # definitive answer — that table holds no rows at all in this workspace, so the
        # hunt could never have confirmed anything and the agent should go elsewhere,
        # which is exactly what the message tells it to do. Counting it as an evidence
        # gap punishes the agent for PROBING a dead table: DEMO-108064 hunted MDE
        # (hunt_process, 50 rows of `su` telemetry), then probed Sentinel, was told
        # SecurityEvent is empty, and had its AUTO_CLOSED_FP overridden to NEEDS_L2 —
        # against an L1 AND L2 who both closed it FP. The empty-source error was added
        # (DEMO-107932) so an empty table could not be read as "clean"; blocking on it
        # here is the opposite of that intent.
        #
        # Neutral, NOT forgiven: it only stops counting as an error when some other hunt
        # actually returned data. With nothing else returning data the FP would be
        # resting on the empty table itself — the DEMO-107932 shape — and the block stands.
        if _corroborating:
            _errored = [tc for tc in _all_errored if not tc.result.get("source_empty")]
        else:
            _errored = _all_errored
        # SCANNER-DRIVEN DLP: decided by CODE, not by whether a hunt happened to
        # succeed. When every bound DLP event is a CASB API Scan there is no host, no
        # process and no actor action to hunt — the deciding facts (who owns the file,
        # which file, which rule matched) are ALREADY bound by query_netskope_dlp, so an
        # errored auxiliary hunt is not the evidence gap this gate exists to catch.
        #
        # DEMO-110748 twice: model reached AUTO_CLOSED_FP at 0.90, matching L1 AND L2,
        # and was overridden both times by a hunt it never needed — run 1 a redundant
        # Netskope re-query, run 2 an Office 365 hunt against the wrong app entirely
        # (the events are Google Drive) with malformed KQL. Temperature variance means
        # each run invents a DIFFERENT unnecessary hunt, so matching on the hunt itself
        # is whack-a-mole; the family is the stable thing to key on.
        #
        # Deliberately NOT the blanket `deterministic_fp` bypass that port_sweep uses:
        # that returns before the VT-detections, CRITICAL-severity, confidence-threshold
        # and evidence-floor checks too. Those are exactly the checks a DLP alert needs
        # — it is about FILES — so this exempts THIS ONE gate and leaves every other one
        # in force.
        # REMOVED 2026-09-02 with the rest of the scanner-driven DLP logic: this gate used
        # to be exempted when every bound DLP event was a CASB API Scan, on the grounds
        # that a data-at-rest finding has nothing to hunt, so a failed hunt proved nothing.
        # That exemption was the one part of the scanner-driven logic pointing the right
        # way (it let DEMO-110756 close FP, matching the human), so removing it costs
        # accuracy: a DLP auto-close is again blocked when a side hunt errors.
        # Hunts ran and NONE returned data: the close rests on history or names, not on
        # anything seen. DEMO-118344 closed AWS credential abuse with its one hunt at 0 rows,
        # on "598 prior alerts" and role names. The prompt has always said never to close
        # on an empty hunt; this enforces it. Errors are handled just below.
        if (not _corroborating and not _all_errored
                and any(_is_hunt_tool(tc.name) for tc in tool_calls)):
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_gate_kind = "no_hunt_data"
            result.safety_block_reason = (
                "Auto-close blocked: every hunt came back empty, so nothing about this alert "
                "was actually seen — prior alerts and names are not evidence it is benign.")
            return result
        if _errored and len(_corroborating) < _CORROBORATING_HUNTS_REQUIRED:
            tc = _errored[0]
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_gate_kind = "hunt_errored"
            result.safety_block_reason = (
                f"Auto-close blocked: hunt {tc.name} errored "
                f"({str(tc.result.get('error'))[:80]}) — incomplete evidence, cannot confirm benign."
            )
            return result
        if _errored:
            # RELAXATION (deliberate): a failed hunt no longer vetoes an auto-close when
            # >=2 other hunts independently returned data. The gate exists because an
            # errored query yields the same empty result as genuinely-clean telemetry, so
            # the FP must not REST on it — but it could not tell a load-bearing failure
            # from a supplementary one, and blocked either way. DEMO-107802: 14 tool calls,
            # both binaries VT-clean, traceroute tied to the Netskope client, no concurrent
            # alerts, model at 0.90 — escalated because one hand-written Sentinel query hit
            # ASimNetworkSession, a table this workspace does not have. L1 AND L2 both
            # independently closed it FP, so the escalation was pure cost.
            # Accepted risk: an FP whose decisive evidence failed can now pass if two
            # unrelated hunts happened to return rows. Bounded by everything else still
            # applying (VT, evidence floor, concurrency, multi-host, confidence floor),
            # and it is logged so over-permissiveness is measurable rather than silent.
            logger.info(
                "[AGENT-GATE] hunt(s) %s errored but %d corroborating hunts returned data "
                "— allowing %s (relaxed errored-hunt rule)",
                [tc.name for tc in _errored], len(_corroborating), result.triage_class,
            )

    # Grouped multi-host gate — every co-host of a grouped incident needs its OWN
    # positive exculpatory evidence to auto-close FP. If the agent auto-closed FP but
    # never ran a hunt on a co-host, that host is UNASSESSED — SCG "not seen before" /
    # no telemetry is NOT exculpatory. Deterministic backstop for the model ignoring
    # the multi-host prompt rule (DEMO-107147: FP at 90% while its own reasoning admitted
    # "telemetry for the other two hosts was not explicitly checked"). Only fires for a
    # genuine grouped incident (co_hosts present); single-host alerts are unaffected.
    if result.triage_class == "AUTO_CLOSED_FP" and co_hosts and not _service_fleet_cleared(evidence, tool_calls):
        _unassessed = _unassessed_co_hosts(co_hosts, tool_calls)
        if _unassessed:
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_gate_kind = "multi_host_unassessed"
            result.safety_block_reason = (
                "Auto-close blocked: grouped incident co-host(s) with no hunt telemetry ("
                + ", ".join(_unassessed[:5])
                + (f" +{len(_unassessed) - 5} more" if len(_unassessed) > 5 else "")
                + ") — cannot confirm benign for every host, escalating."
            )
            return result

    # Any critical tool call returned an error → cap confidence.
    #
    # A REJECTED ARGUMENT is not degraded evidence. The cap exists because a failed
    # VT lookup or a failed concurrency check means we could not see something we
    # needed — a real gap in what the investigation knows. A tool refusing malformed
    # input is the opposite: nothing was looked up, so nothing is missing, and the
    # model can simply call it correctly. Treating the two the same overturned a
    # correct verdict on DEMO-107068, where the model reached AUTO_CLOSED_FP off an
    # exact-command IronWatch precedent and then called mde_get_alert with a JIRA KEY
    # ('DEMO-107067'); the resulting "not found" capped confidence at 0.60, under the
    # 0.80 medium threshold, and escalated a ticket whose evidence was never in doubt.
    #
    # Tools flag these with invalid_input; everything else — auth failures, timeouts,
    # backend errors, genuine not-founds on a well-formed id — still caps exactly as
    # before. This narrows what counts as a failure, it does not narrow the gate.
    critical_tools = {"vt_lookup_hash", "mde_get_alert", "scg_check_concurrent_alerts"}
    for tc in tool_calls:
        if tc.name in critical_tools and tc.result.get("error") and not tc.result.get("invalid_input"):
            if result.confidence > 0.60:
                result.confidence = 0.60
            if result.confidence < threshold:
                result.triage_class = "NEEDS_L2"
                result.blocked_by_safety = True
                result.safety_block_reason = f"Critical tool {tc.name} returned an error — confidence capped at 0.60."
                return result

    # A host with a named-malware detection in the last 30 days is not a clean baseline,
    # so no other alert on it auto-closes FP. r009mrahaitwd had three Sality detections
    # (a file infector, from a binary on an IT file share) and a CustomEnterpriseBlock
    # hit; RAPTOR still auto-closed two PowerShell alerts there (DEMO-115350, 116363),
    # citing that malware history as "confirmed legitimate" — the opposite of what it
    # means. Measured over Sep 10 - Oct 10: 3 FP verdicts would have gone to L2, all on
    # that one host. `prior_malware` is looked up by the loop: None = not checked (other
    # callers), a row carrying "error" = lookup failed, which blocks (fail closed). A
    # malware alert itself is left to the named-threat gate.
    if (prior_malware and result.triage_class == "AUTO_CLOSED_FP"
            and not _is_malware_alert(alert_name)):
        if any(r.get("error") for r in prior_malware):
            _why = "the device's malware history could not be checked"
        else:
            _why = ("the device had a named-malware detection in the last 30 days ("
                    + ", ".join(f"{r.get('jira_key')} {r.get('alert_name', '')[:50]}"
                                for r in prior_malware[:3]) + ")")
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_gate_kind = "recent_malware_on_host"
        result.safety_block_reason = (
            f"Auto-close blocked: {_why} — an alert on a recently infected host needs a "
            "human, and that history is never evidence the activity is benign.")
        return result

    # An open URGENT ticket on the same person or host (any time in the last 14 days, not
    # yet closed by a human) means that entity is under a compromise question; nothing else
    # about it closes until that is answered. DEMO-117913 closed theo.malik's sign-in
    # spike while DEMO-117523 (URGENT, wrong passwords then a new-IP success) sat with L2.
    if open_urgent and result.triage_class == "AUTO_CLOSED_FP":
        if any(r.get("error") for r in open_urgent):
            _why = "open URGENT tickets for this user/device could not be checked"
        else:
            _why = ("an URGENT ticket on the same user/device is still open ("
                    + ", ".join(f"{r.get('jira_key')} {r.get('alert_name', '')[:50]}"
                                for r in open_urgent[:3]) + ")")
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_gate_kind = "open_urgent_on_entity"
        result.safety_block_reason = (
            f"Auto-close blocked: {_why} — while a possible compromise is being answered, "
            "new alerts on the same account or host go to a human.")
        return result

    # Privilege-escalation / credential-access: an FP may not rest on ABSENCE.
    # OSCAR_SYSTEM has stated this rule since the beginning ("the mere ABSENCE of a
    # signal is NOT sufficient"), but only as prose, and the model ignores it:
    # DEMO-106604 hunted `sudo` on the alerted host, got 0 rows, wrote "Absence of
    # Malicious Activity" and auto-closed a red-team test that L1 AND L2 both
    # confirmed as a TRUE POSITIVE.
    #
    # Deliberately scoped to hunts aimed at THIS alert's own subject, because the
    # obvious formulations are both wrong:
    #   * "some hunt must return rows" — mde_get_timeline returns 30 events on nearly
    #     every host, so DEMO-106604 passes it; and DEMO-108483, where the model was
    #     RIGHT and both analysts agreed, ran no hunt_* at all and would be blocked.
    #     Exactly backwards on both.
    #   * matching phrases in the reasoning — tried for actor claims and it cascaded:
    #     "legitimate privilege escalation (user switching, not root)" read `switching`
    #     as a username, escalated DEMO-107206's correct close, and that one bogus
    #     escalation then tripped the concurrency gate on four more tickets. Gates here
    #     read tool ARGS and RESULTS, never prose.
    # So: only when the agent actually asked about the alert's own process/file AND
    # every such question came back empty. Asking nothing does not trip it — which is
    # what keeps DEMO-108483 (timeline + three analyst-verified memories naming its
    # change ticket) untouched, and is also this gate's known hole.
    if alert_type in _ABSENCE_SENSITIVE_PLAYBOOKS and result.triage_class == "AUTO_CLOSED_FP":
        _subjects = _alert_subject_tokens(evidence or {})
        _scoped = [tc for tc in tool_calls
                   if _is_hunt_tool(tc.name) and _hunt_targets_subject(tc.args, _subjects)]
        if _scoped and all(_hunt_rows(tc.result) == 0 for tc in _scoped):
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            _names = ", ".join(sorted({tc.name for tc in _scoped}))
            result.safety_block_reason = (
                f"Auto-close blocked: every hunt aimed at this alert's own subject "
                f"({_names}) returned 0 rows — a {alert_type} FP cannot rest on absence "
                f"of evidence; positive exculpatory evidence is required."
            )
            return result

    # Concurrent open alerts.
    #
    # A DUPLICATE — the same alert name on the same host — is one activity firing
    # repeatedly, not a second independent signal, and counting it makes the verdict
    # depend on arrival order rather than on evidence. DEMO-108332/108344/108359/108483
    # were four `Root Privilege Escalation` alerts on dba-operations-0201 from one
    # authorised DB migration (change ticket INT-108677, corroborated by three
    # analyst-verified memories). The first three arrived before the burst had
    # accumulated, found nothing open, and auto-closed FP unimpeded. DEMO-108483 arrived
    # last, found its own two siblings open, and was escalated for it — the only one of
    # the four that scored, and it scored as a miss against an L1 AND L2 who both closed
    # it FP. The model had already reached AUTO_CLOSED_FP at 0.95 and even noted the
    # siblings were duplicates of the same benign activity.
    #
    # check_concurrent_alerts has always returned open_alert_details for exactly this —
    # its docstring says the details let a caller "distinguish a true DUPLICATE ... from
    # merely-concurrent distinct alerts (possible attack chain)" — and this gate ignored
    # them and counted rows. Now it reads them.
    #
    # DELIBERATELY NARROW. Only same-name-same-host siblings are discounted; a different
    # alert on the host, or the same alert on another host (lateral movement), still
    # escalates exactly as before. Nothing else is relaxed: VT, named-threat, evidence
    # floor, multi-host, test-device and the privesc absence-of-evidence gate all still
    # apply, and a repeated-attack burst that looks benign has to clear every one of them.
    for tc in tool_calls:
        if tc.name == "scg_check_concurrent_alerts" and tc.result.get("concurrent_count", 0) > 0:
            _details = tc.result.get("open_alert_details") or []
            _this_name = (alert_name or "").strip().lower()
            _this_dev = (device_name or "").strip().lower()
            # Fall back to the old count-only behaviour when details are unavailable
            # (an older shadow, a stubbed result) — never fail open on missing data.
            #
            # `_this_dev` is deliberately NOT required. The device comparison exists to
            # tell a DUPLICATE (same alert, same host) from the same alert on a DIFFERENT
            # host, which is lateral movement — a real signal. A DEVICE-LESS family has no
            # host dimension, so that distinction does not exist, and requiring a device
            # here meant the duplicate carve-out could never run for one: DLP alerts carry
            # no device, so every burst sibling fell through to the count-only path and
            # blocked. DEMO-110772 was blocked by DEMO-110770, and 110748/110758 both by
            # 110746 — every blocker another ticket from the SAME CASB scan burst, so the
            # tickets deadlocked each other while the model had already reached the right
            # FP verdict on all of them.
            #
            # Safe because the correlation is already actor-scoped: check_concurrent_alerts
            # filters on this ticket's user/device, so a sibling in `_details` is by
            # construction the same principal. Same alert_name on the same principal with
            # no host to distinguish them IS a duplicate. The comparison below still works
            # unchanged — for a device-less pair both sides are "" and match — and a
            # sibling with a DIFFERENT alert_name, or a real device where this alert has
            # none, still fails the match and still blocks.
            if _details and _this_name:
                _distinct = _concurrency_blockers(_details, _this_name, _this_dev)
                if not _distinct:
                    logger.info(
                        "[AGENT-GATE] concurrency: all %d open sibling(s) are duplicates of "
                        "'%s' on %s (%s) — not escalating on arrival order",
                        len(_details), alert_name, device_name,
                        ", ".join(d.get("jira_key", "?") for d in _details[:5]),
                    )
                    break
                # Every blocker, not the first three: a held ticket (concurrency_hold.py)
                # waits for ALL of them, and the closure poller re-triggers on each.
                _blocking_keys = [d.get("jira_key", "") for d in _distinct if d.get("jira_key")]
            else:
                _blocking_keys = [k for k in (tc.result.get("open_alerts") or []) if k]
            _keys = ", ".join(_blocking_keys[:3]) or "unknown"
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_block_reason = f"Concurrent open alerts: {_keys}."
            result.blocked_by_concurrent_keys = _blocking_keys
            return result

    return result
