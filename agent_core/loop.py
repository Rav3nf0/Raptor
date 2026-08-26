"""ReAct loop — Think → Act → Observe until final_verdict or max_iterations.

Accepts optional prefetched_context to reuse data already fetched by the
existing pipeline (shadow mode — avoids double API calls).
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Optional

from agent_core.backend import LLMBackend, ToolCall
from agent_core.result import AgentResult, ToolCallRecord, normalize_action
from agent_core import oscar as oscar_module
from agent_core import critic as _critic

logger = logging.getLogger(__name__)

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
# Same idea again, for the concurrency check: an auto-close that never called
# scg_check_concurrent_alerts is rejected and re-prompted this many times before
# the hard gate in _apply_safety_gates escalates it.
_CONCURRENCY_GATE_LIMIT = 2

_FINAL_VERDICT_RE = re.compile(
    r"<final_verdict>\s*(\{.*?})\s*</final_verdict>",
    re.DOTALL | re.IGNORECASE,
)

_TRIAGE_CLASSES = frozenset([
    "AUTO_CLOSED_FP", "AUTO_CLOSED_TP", "NEEDS_L2", "REQUEST_JUSTIFICATION", "URGENT",
])


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
) -> AgentResult:
    """Run the ReAct investigation loop. Returns AgentResult."""
    import agent_tools.virustotal  # noqa: ensure tools are registered
    import agent_tools.mde         # noqa
    import agent_tools.sentinel    # noqa
    import agent_tools.hunt        # noqa: deterministic hunt_* builders (primary hunt path)
    import agent_tools.scg         # noqa
    import agent_tools.jira        # noqa
    import agent_tools.kql_generator  # noqa
    import agent_tools.vuln_check  # noqa
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
            entities, alert_type=alert_type, device_name=device_name, user_name=user_name)
    except Exception as exc:
        logger.warning("SCG context fetch failed: %s", exc)

    # Bounded, curated-only alert-type precedents — surfaces how L1 handled this
    # class of alert before (incl. entity-less memories that entity recall misses).
    try:
        from entity_graph.query import get_playbook_precedents_block
        _prec = await get_playbook_precedents_block(
            alert_type, exclude_jira=jira_key, limit=3,
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

    tools = get_tools()
    valid_names = get_tool_names()
    tool_call_records: list[ToolCallRecord] = []
    consecutive_no_tool = 0
    evidence_gate_nudges = 0
    multihost_gate_nudges = 0
    concurrency_gate_nudges = 0

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

        # Check for final verdict — robust balanced-brace extraction handles
        # <final_verdict> tags, bare JSON, fenced code, nested braces, and light
        # repair (trailing commas). Replaces the old non-greedy \{.*?} regex that
        # broke on any nested braces in the verdict JSON.
        verdict_obj = _extract_loose_verdict(content)
        if verdict_obj:
            result = _parse_verdict(verdict_obj, tool_call_records, iteration + 1,
                                    fallback_text=content_clean)
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
            # Record the MODEL's verdict before any gate/critic downgrade — so we can
            # measure how often the safety layer turns an intended auto-close into an
            # escalation (over-gating visibility).
            result.pre_safety_class = result.triage_class
            _det_fp = bool(((_ev or {}).get("port_sweep_check") or {}).get("known_good"))
            result = _apply_safety_gates(result, severity, is_test_device, tool_call_records,
                                         deterministic_fp=_det_fp,
                                         co_hosts=(evidence or {}).get("additional_hosts"),
                                         device_name=device_name, user_name=user_name,
                                         evidence=evidence or {}, alert_name=alert_name,
                                         alert_type=alert_type)
            # Grounding backstop — block an auto-close resting on a fabricated actor/command
            # (DEMO-107147). Runs after the safety gates; only ever downgrades to NEEDS_L2.
            result = _apply_grounding_check(result, evidence or {}, user_name, tool_call_records, jira_key)
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
            logger.info(
                "[AGENT-LOOP] %s: verdict=%s conf=%.2f iterations=%d total=%.1fs",
                jira_key, result.triage_class, result.confidence, iteration + 1,
                time.perf_counter() - _loop_start,
            )
            return result

        if not tool_calls:
            consecutive_no_tool += 1
            if consecutive_no_tool >= _FAIL_RETRY_LIMIT:
                logger.warning("%s: no tool calls %d times — defaulting to NEEDS_L2. last_output=%r",
                               jira_key, consecutive_no_tool, content_clean[:300])
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
                tool_result = await execute(tc.name, real_args, prefetched=prefetched_context)
                if sanitizer:
                    tool_result = sanitizer.sanitize_obj(tool_result)
            tool_call_records.append(ToolCallRecord(name=tc.name, args=tc.args, result=tool_result))
            tool_results_text.append(f"Tool: {tc.name}\nArgs: {json.dumps(tc.args)}\nResult: {json.dumps(tool_result, default=str)[:1500]}")

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
    return AgentResult(
        triage_class="NEEDS_L2",
        confidence=0.3,
        reasoning=(f"Investigation reached max iterations ({max_iter}) without a verdict. "
                   f"Last model output: {(content_clean or '(empty)')[:600]}"),
        tool_calls=tool_call_records,
        iterations=max_iter,
        error="max_iterations",
    )


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
    reasoning = str(data.get("reasoning", "") or "").strip()
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

    A run can call only entity-context + concurrency tools, no hunt — and the live
    re-fetch of Sentinel/CloudTrail data comes back with no commands at all (the
    event has aged past the retention this run's enrichment could reach), so cmd_gt
    is empty. But the ticket's OWN record — written the first time it was ever
    triaged, when the data was still fresh — already has the real command, and the
    model correctly recalled it. Without this, a TRUE statement gets flagged as
    fabricated purely because THIS run's fresh data-pull came back thinner than the
    historical one did.
    """
    try:
        from edr_triage.store import get_alert_by_jira_key
        doc = get_alert_by_jira_key(jira_key)
        if doc and doc.get("l1_comment_deterministic"):
            return (doc.get("l1_comment") or "").lower()
    except Exception as exc:
        logger.debug("grounding check: stored-alert lookup failed for %s: %s", jira_key, exc)
    return ""


def _apply_grounding_check(result: AgentResult, evidence: dict, user_name: str,
                           tool_calls: list[ToolCallRecord], jira_key: str = "") -> AgentResult:
    """Deterministic hallucination backstop for AUTO_CLOSE verdicts.

    An auto-close whose reasoning rests on a FABRICATED detail — an actor or command
    that appears nowhere in the alert fields, any tool result, or this ticket's OWN
    prior (deterministic) record — is unreliable and must not close a ticket. Catches
    the DEMO-107147 failures: the model read 'charlie' out of the IAM role name
    `ssm-session-testing-charlie-role` and invented a `sudo su` command the alert
    never listed, then auto-closed FP at 90%. One-directional: only downgrades an
    auto-close to NEEDS_L2, never relaxes a verdict. `jira_key` is optional and used
    only to look up the ticket's own stored record — omitting it simply narrows
    ground truth back to live evidence + this run's tools, the original behaviour.
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
    cmd_gt = (_blob(ev.get("command_lines"), ev.get("initiating_process")) + " " + tool_blob
              + " " + _stored_alert_command_gt(jira_key))

    # (1) Fabricated ACTOR — narrowly: a name the model read OUT OF THE IAM ROLE string.
    #     That is the failure this guards (DEMO-107147: 'charlie' derived from
    #     `ssm-session-testing-charlie-role`), and the block message says as much.
    #
    #     It used to flag ANY word following "user" that wasn't in the actor fields,
    #     which is ordinary English far more often than it is a fabricated identity —
    #     it blocked correct auto-closes on "…privilege escalation (user switching, not
    #     root)" (DEMO-107206) and "The user discrepancy (`kushal.gu…`)" (DEMO-107341),
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
    role_blob = " ".join(str(x).lower() for x in (
        ev.get("session_issuer"), ev.get("user_arn"),
    ) if x)
    # Chars of reasoning scanned AFTER a claimed token for a same-breath correction to
    # a real actor. DEMO-107497: "...executed by the user `charlie` (confirmed as
    # `alex.kim@example.com` via the AWS session ARN)" — the model read a name out
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
        window = reasoning[m.end():m.end() + _SELF_CORRECT_WINDOW].lower()
        if any(a in window for a in actor_list):
            continue  # self-corrected nearby — not the failure mode this gate exists for
        result.triage_class = "NEEDS_L2"
        result.blocked_by_safety = True
        result.safety_block_reason = (
            f"Auto-close blocked: reasoning asserts user '{claimed}' not in the alert's "
            "actor fields — likely role-name/actor confusion (a name inside the IAM role "
            "is not a user). Cannot trust the FP; escalating."
        )
        return result

    # (2) Fabricated COMMAND — a quoted `sudo …` command absent from the alert commands
    #     and every tool result (privesc alerts are defined by their sudo/su commands, so
    #     a cited sudo command that isn't there is a mis-attribution).
    for q in re.findall(r"`([^`]{2,120})`", reasoning):
        ql = " ".join(q.strip().lower().split())
        if ql.startswith("sudo ") and ql not in cmd_gt:
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_block_reason = (
                f"Auto-close blocked: reasoning cites command `{q.strip()}` not present in the "
                "alert commands or any tool result (fabricated / mis-attributed); escalating."
            )
            return result

    return result


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
        if tc.name.startswith("hunt_") or tc.name in ("mde_advanced_hunt", "sentinel_run_kql")
    ).lower()
    return [h for h in co_hosts if h and (str(h).split(".")[0].lower() not in hunted)]


def _service_fleet_cleared(evidence: dict | None, tool_calls: list[ToolCallRecord]) -> bool:
    """True when hunt_service already covers EVERY co-host for a service-process alert.

    oscar.py's prompt (the "EXCEPTION for this alert" block, gated the same way on
    process_check.distinct) tells the model hunt_service's fleet-wide TRUSTED verdict
    IS positive exculpatory evidence for every co-host — its device counts span the
    whole estate, so a per-host hunt_process call would answer a question hunt_service
    already answered. But that carve-out lived ONLY in the prompt; this deterministic
    gate had no matching exception, so it still demanded a per-host hunt and blocked
    the auto-close anyway (a run of "Rare Process as a Service" misses across weeks,
    all showing every flagged process as TRUSTED in the model's own reasoning, still
    escalated by this gate).

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
    — a second, static, human-reviewed source the model can't talk itself into.
    Falling back to that list for a coverage gap closes the SAME hole a NoCertRecord
    row leaves open, evidence-wise.

    This can only ever fill a "no data" gap, never override a bad signal: ANY row
    with UntrustedHashes > 0 (a hash chain that does NOT resolve to a trusted root
    — the actual masquerade tell) fails the whole check immediately, allowlist
    membership or not. A name already on the vetted list showing up with an
    untrusted-signed copy is exactly the scenario this gate exists to catch, not
    waive.
    """
    if not ((evidence or {}).get("process_check") or {}).get("distinct"):
        return False
    _svc_calls = [tc for tc in tool_calls if tc.name == "hunt_service" and not tc.result.get("error")]
    if not _svc_calls:
        return False
    _rows = [r for tc in _svc_calls for r in (tc.result.get("rows") or [])]
    if not _rows:
        return False
    if any(int(r.get("UntrustedHashes") or 0) > 0 for r in _rows):
        return False
    from edr_triage.service_allowlist import is_known_good
    for r in _rows:
        if int(r.get("TrustedHashes") or 0) <= 0 and not is_known_good(str(r.get("FileName") or "")):
            return False
    for tc in _svc_calls:
        for _missing in (tc.result.get("not_found") or []):
            if not is_known_good(_missing):
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
    recently created alerts on the device … or the user … returned
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
    # a corroboration was hunt_query intent="Check if the commands 'id charlie' ..."
    # returning 50 rows, while its only structured hunt (process_name='sh') came back
    # empty. Reading intent is safe here in a way that reading REASONING is not — it is
    # the query the model issued, not its argument for a verdict.
    "intent",
))
_ARG_KV_RE = re.compile(r"(\w+)\s*=\s*'([^']*)'")


def _alert_subject_tokens(evidence: dict) -> set[str]:
    """Executable / file names that identify THIS alert's activity.

    Privesc alerts routinely carry no file_name and no initiating_process (both empty),
    so the command lines are usually the only source — every word of them, not just the
    first, because `sudo su` must yield BOTH `sudo` and `su` for a hunt on either to
    count as asking about this alert.
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
    # `id`, `sh`, `su`, `ps`. A 3-char floor silently dropped them, and the cost is real:
    # a corroborating hunt was process_name='id' returning 25 rows, which the gate could
    # not see, so it fired on the empty `sudo` hunt alone and would have escalated a
    # close that both L1 and L2 agreed with. Precision comes from matching only against
    # _SUBJECT_ARG_KEYS values, not from token length.
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


def _apply_safety_gates(result: AgentResult, severity: str, is_test_device: bool, tool_calls: list[ToolCallRecord],
                        deterministic_fp: bool = False, co_hosts: list | None = None,
                        device_name: str = "", user_name: str = "",
                        evidence: dict | None = None, alert_name: str = "",
                        alert_type: str = "") -> AgentResult:
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
    # the multi-host gate no longer undoes that once the model reaches AUTO_CLOSED_FP.
    # But the model routinely never reaches it in the first place — re-triage of the
    # "Rare Process as a Service" backlog still showed tickets landing on
    # pre_safety_class == NEEDS_L2, each reasoning that every flagged process came
    # back trusted, then escalating anyway on host count alone ("100+ co-hosts remain
    # uninvestigated"), the exact thing the prompt tells it not to do. A prompt rule
    # the model won't reliably follow is not a safety property; trust the code-verified
    # evidence instead, but ONLY for this narrow, code-verified shape
    # (_service_fleet_cleared is unchanged, strict, and scoped to process_check alerts)
    # and only absent any independent red flag. Confidence is raised to clear the
    # severity threshold below — the fleet-wide signer clearance IS the evidence, not a
    # hedge — and every downstream gate (test device, evidence floor,
    # concurrency-call-required, CRITICAL, confidence) still runs normally against this
    # upgraded verdict, so a case with a hallucinated "zero concurrent alerts" and no
    # matching tool call still correctly escalates. Doesn't help tickets with a
    # genuinely unresolved binary (real "no certificate data" gaps) or a run where
    # hunt_service was never called at all — those need allowlist/data fixes or a clean
    # re-run, not this gate.
    if (result.triage_class == "NEEDS_L2"
            and not result.blocked_by_safety
            and _service_fleet_cleared(evidence, tool_calls)
            and not _named_threat_detection(evidence or {}, alert_name)
            and not any(tc.name.startswith("vt_lookup") and tc.result.get("detections", 0) > 0
                        for tc in tool_calls)):
        result.triage_class = "AUTO_CLOSED_FP"
        result.confidence = max(result.confidence, 0.90)

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
        else:
            for tc in tool_calls:
                if tc.name.startswith("vt_lookup") and tc.result.get("detections", 0) > 0:
                    _rj_block = (f"VT returned {tc.result['detections']}/"
                                 f"{tc.result.get('total', '?')} detections")
                    break
        if _rj_block:
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_block_reason = (
                f"Justification request upgraded to L2: {_rj_block}. This needs technical "
                "analysis, not a business justification."
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

    # Any VT detections > 0 — never auto-close as FP
    for tc in tool_calls:
        if tc.name.startswith("vt_lookup") and tc.result.get("detections", 0) > 0:
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_block_reason = f"VT returned {tc.result['detections']}/{tc.result.get('total', '?')} detections — zero tolerance, escalating."
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
        # call was trying to answer got answered, just on a later attempt. A hunt_process
        # with no args can error (a malformed call, not a broken query), then
        # hunt_process(device=..., process_name='tcpdump') come back with rows — the gate
        # used to block the auto-close because that single corroborating hunt fell short
        # of the unrelated-second-source bar below, penalizing a mistake the model had
        # already fixed. This does NOT forgive a genuinely broken query (a nonexistent
        # table, an empty-source case) — those tools never return real data no matter how
        # many times they're called, so they still fall through to the
        # unrelated-corroboration check.
        _self_corrected_tools = {tc.name for tc in _corroborating}
        _all_errored = [tc for tc in tool_calls
                        if _is_hunt_tool(tc.name) and tc.result.get("error")
                        and tc.name not in _self_corrected_tools]
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
        if _errored and len(_corroborating) < _CORROBORATING_HUNTS_REQUIRED:
            tc = _errored[0]
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
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

    # Privilege-escalation / credential-access: an FP may not rest on ABSENCE.
    # OSCAR_SYSTEM has stated this rule since the beginning ("the mere ABSENCE of a
    # signal is NOT sufficient"), but only as prose, and the model ignores it: a hunt
    # for `sudo` on the alerted host got 0 rows, the model wrote "Absence of Malicious
    # Activity" and auto-closed a red-team test that L1 AND L2 both confirmed as a TRUE
    # POSITIVE.
    #
    # Deliberately scoped to hunts aimed at THIS alert's own subject, because the
    # obvious formulations are both wrong:
    #   * "some hunt must return rows" — mde_get_timeline returns 30 events on nearly
    #     every host, so the red-team test passes it; and a case where the model was
    #     RIGHT and both analysts agreed ran no hunt_* at all and would be blocked.
    #     Exactly backwards on both.
    #   * matching phrases in the reasoning — tried for actor claims and it cascaded:
    #     "legitimate privilege escalation (user switching, not root)" read `switching`
    #     as a username, escalated a correct close, and that one bogus escalation then
    #     tripped the concurrency gate on four more tickets. Gates here read tool ARGS
    #     and RESULTS, never prose.
    # So: only when the agent actually asked about the alert's own process/file AND
    # every such question came back empty. Asking nothing does not trip it — which is
    # what keeps a timeline-plus-verified-memory close untouched, and is also this
    # gate's known hole.
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
    # depend on arrival order rather than on evidence. Four `Root Privilege Escalation`
    # alerts on one host from a single authorised DB migration (corroborated by three
    # analyst-verified memories): the first three arrived before the burst had
    # accumulated, found nothing open, and auto-closed FP unimpeded. The last arrived,
    # found its own two siblings open, and was escalated for it — the only one of the
    # four that scored, and it scored as a miss against an L1 AND L2 who both closed it
    # FP. The model had already reached AUTO_CLOSED_FP at 0.95 and even noted the
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
            if _details and _this_name and _this_dev:
                _distinct = [d for d in _details
                             if not ((d.get("alert_name") or "").strip().lower() == _this_name
                                     and (d.get("device_name") or "").strip().lower() == _this_dev)]
                if not _distinct:
                    logger.info(
                        "[AGENT-GATE] concurrency: all %d open sibling(s) are duplicates of "
                        "'%s' on %s (%s) — not escalating on arrival order",
                        len(_details), alert_name, device_name,
                        ", ".join(d.get("jira_key", "?") for d in _details[:5]),
                    )
                    break
                _blocking_keys = [d.get("jira_key", "") for d in _distinct[:3] if d.get("jira_key")]
            else:
                _blocking_keys = [k for k in (tc.result.get("open_alerts") or [])[:3] if k]
            _keys = ", ".join(_blocking_keys) or "unknown"
            result.triage_class = "NEEDS_L2"
            result.blocked_by_safety = True
            result.safety_block_reason = f"Concurrent open alerts: {_keys}."
            result.blocked_by_concurrent_keys = _blocking_keys
            return result

    return result
