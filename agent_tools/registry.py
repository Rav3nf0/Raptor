"""Tool registry — maps tool name → async function + JSON schema.

Each tool is registered with:
  - name: unique string identifier
  - description: shown to the LLM in the system prompt
  - parameters: JSON Schema for arguments
  - fn: the async callable

The registry supports prefetched_context to short-circuit API calls when
the existing pipeline has already fetched data (shadow mode).
"""
from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)

# Synonym groups — the LLM often calls a tool with a near-miss param name (host vs
# device, query vs kql, user vs account). A value under any member is remapped to
# whichever member the *target function actually declares*, so the call runs instead
# of dying at fn(**args) with "Invalid arguments".
_SYNONYMS: list[frozenset] = [
    frozenset({"device", "device_name", "devicename", "hostname", "host", "computer", "computer_name"}),
    frozenset({"account", "account_name", "user", "user_name", "username", "upn"}),
    frozenset({"kql", "query", "kql_query"}),
    frozenset({"sha256", "hash", "file_hash", "filehash"}),
    frozenset({"ip", "ip_address", "remote_ip"}),
    frozenset({"url", "domain", "remote_url"}),
]


def _reconcile_args(fn: Callable, name: str, args: dict) -> dict:
    """Make near-miss tool calls succeed instead of TypeError-ing at fn(**args).

    Introspects the function signature and: passes through unchanged if it accepts
    **kwargs; remaps a provided synonym to whichever group member the function
    declares (host->device, query->kql, …); drops unknown kwargs (e.g. a stray
    `description`) — logged — so they can't raise 'Invalid arguments'. Missing REQUIRED
    args are left to surface as a genuine TypeError (that's a real error, not a typo)."""
    if not isinstance(args, dict):
        return args
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return args
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return args  # accepts **kwargs — nothing to reconcile
    accepted = {n for n, p in params.items()
                if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)}
    out = {k: v for k, v in args.items() if k in accepted}
    remapped, dropped = [], []
    for k, v in args.items():
        if k in accepted:
            continue
        target = None
        for grp in _SYNONYMS:
            if k.lower() in grp:
                target = next((c for c in grp if c in accepted and c not in out), None)
                break
        if target:
            out[target] = v
            remapped.append(f"{k}->{target}")
        else:
            dropped.append(k)
    if remapped or dropped:
        logger.info("tool %s: reconciled args (remapped=%s dropped=%s)", name, remapped, dropped)
    return out


@dataclass
class ToolDef:
    name: str
    description: str
    parameters: dict
    fn: Callable[..., Awaitable[Any]]


_REGISTRY: dict[str, ToolDef] = {}


def register(name: str, description: str, parameters: dict):
    """Decorator to register an async function as a tool."""
    def decorator(fn: Callable[..., Awaitable[Any]]):
        _REGISTRY[name] = ToolDef(name=name, description=description, parameters=parameters, fn=fn)
        return fn
    return decorator


def get_tools(only: set[str] | None = None) -> list[dict]:
    """Return tool definitions formatted for LLM system prompt.

    `only` restricts which definitions are ADVERTISED, for token cost. Measured
    2026-09-02: the 29 registered schemas serialise to ~7,300 tokens and are re-sent on
    every iteration of every run — 57% of each request, against ~430 output tokens. On
    Netskope DLP (82% of all traffic) the agent only ever called 5 of the 29, so the
    other 24 were pure cost.

    This does NOT restrict capability: `get_tool_names` and `execute` are deliberately
    left unfiltered, so a model that asks for an unadvertised tool by name still runs it.
    Advertising less makes it unlikely to ask; it cannot make the tool unavailable. That
    matters because usage has a long tail — `mde_advanced_hunt` appeared once in 174 DLP
    runs — and a trim that silently removed a capability would trade cost for a wrong
    verdict.

    Unknown names in `only` are ignored, so a stale env allowlist degrades to "advertise
    what still exists" rather than to an empty tool list.
    """
    return [
        {
            "name": t.name,
            "description": t.description,
            "parameters": t.parameters,
        }
        for t in _REGISTRY.values()
        if only is None or t.name in only
    ]


def get_tool_names() -> set[str]:
    return set(_REGISTRY.keys())


async def execute(name: str, args: dict, prefetched: dict | None = None) -> dict:
    """Execute a tool by name, optionally short-circuiting with prefetched data."""
    tool = _REGISTRY.get(name)
    if not tool:
        return {"error": f"Unknown tool: {name}. Available: {sorted(_REGISTRY.keys())}"}

    # Reconcile near-miss arg names (host->device, query->kql) and drop stray kwargs
    # up-front, so both the prefetch check and the call use canonical, valid args.
    args = _reconcile_args(tool.fn, name, args)

    if prefetched:
        cached = _check_prefetch(name, args, prefetched)
        if cached is not None:
            logger.debug("tool %s: returning prefetched data", name)
            return cached

    try:
        result = await tool.fn(**args)
        return result if isinstance(result, dict) else {"result": result}
    except TypeError as exc:
        return {"error": f"Invalid arguments for {name}: {exc}"}
    except Exception as exc:
        logger.error("tool %s failed: %s", name, exc, exc_info=True)
        return {"error": str(exc)[:300]}


def _check_prefetch(name: str, args: dict, prefetched: dict) -> dict | None:
    """Return cached data if the tool + args match something already fetched."""
    if name == "vt_lookup_hash" and "sha256" in args:
        vt = prefetched.get("vt")
        if vt and prefetched.get("vt_sha256") == args["sha256"]:
            return vt
    if name == "mde_get_alert" and "alert_id" in args:
        alert = prefetched.get("alert_data")
        if alert and prefetched.get("alert_id") == args["alert_id"]:
            return alert
    if name == "mde_get_timeline" and "machine_id" in args:
        timeline = prefetched.get("timeline")
        if timeline is not None and prefetched.get("machine_id") == args["machine_id"]:
            return {"events": timeline}
    return None
