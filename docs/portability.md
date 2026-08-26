# Portability — RAPTOR runs on Sentinel/MDE today, but isn't tied to it

RAPTOR is currently wired to **Microsoft Defender (MDE) + Sentinel + Jira**, but that
coupling is deliberately confined to two thin adapter layers. The triage brain — classifier,
playbooks, agent loop, data-sovereignty sanitizer, and the Security Context Graph — never
sees a vendor API or a query language. This doc explains *why* migration is cheap, *where*
it actually costs, and gives a concrete recipe.

> **In one line:** swapping the **ticketing** source is a small adapter; swapping the
> **hunting/telemetry** source means porting one **query-language layer** (KQL → SPL/ES|QL).
> Everything between those two edges is vendor-agnostic and untouched.

## Why: everything hinges on one normalization interface

Every alert is converted **once**, at intake, into a `NormalizedAlert`
([`edr_triage/normalized.py`](../edr_triage/normalized.py)) — a vendor-neutral shape:
`name, source, severity, tactics, device, user, threat_name, file_name/path,
command_lines, detections, alert_time, description, …`. Its `source` field is literally
typed `"mde" | "sentinel" | future vendors`.

From that point on, **nothing downstream knows or cares where the alert came from**:

```
  vendor intake            PORTABLE CORE (vendor-agnostic)                 vendor exec
 ┌──────────────┐   ┌──────────────────────────────────────────────┐   ┌────────────┐
 │ Jira poller  │──▶│ NormalizedAlert → classifier → playbooks →    │──▶│ hunt/enrich│
 │ + normalize  │   │ agent loop → AlertSanitizer → SCG memory      │   │ (query lang)│
 └──────────────┘   └──────────────────────────────────────────────┘   └────────────┘
    ADAPTER #1                  no vendor coupling here                    ADAPTER #2
```

Concretely, **all 10 playbooks** (`edr_triage/playbooks/*.py`), the classifier, the agent
loop, the sanitizer, and the memory graph operate purely on `NormalizedAlert` fields and
generic strings. Grep confirms it: the query-language (KQL) code lives *only* in the two
edges, never in the playbooks or the memory layer.

## Where vendor coupling actually lives (the only things you touch)

| Adapter | Files | What it does | Migration effort |
|---|---|---|---|
| **#1 Ticketing / alert intake** | `edr_triage/jira_poller.py`, `jira_handler.py`, and the `normalize()` in `edr_triage/normalized.py` | Fetch new alerts; write comments/transitions/labels; map raw alert → `NormalizedAlert` | **Low** — one poller/handler pair + a field mapping. ServiceNow, PagerDuty, or a plain webhook all fit. |
| **#2 Hunting / telemetry** | `lib/mde_client.py`, `lib/kql_templates.py`, `agent_tools/{hunt,mde,sentinel,kql_generator}.py` | Run live hunts and enrichment queries against the SIEM/EDR | **Moderate** — port the query-language layer (KQL → your dialect) and the client that executes it. |

That's the whole coupling surface. The classifier, playbooks, agent reasoning, sanitizer,
and SCG memory are **not** on this list — they don't change.

## Migration recipe

**Swap the ticketing source (e.g. Jira → ServiceNow)** — low effort:
1. Write a poller that returns new alerts and a handler that writes comments/transitions.
2. Populate `NormalizedAlert` from your alert payload.
3. Done — the pipeline, playbooks, agent, and memory are unchanged.

**Swap the SIEM/EDR (e.g. Sentinel/MDE → Splunk or Elastic)** — moderate effort:
1. Implement a telemetry client with the same `hunt(query_name, kql, lookback_hours) -> list[dict]`
   contract that returns rows of dicts (see `lib/mde_client.py`).
2. Port the query layer to your dialect — KQL → **SPL** (Splunk) or **ES|QL/EQL** (Elastic).
   This is the real work, but it's isolated to `lib/kql_templates.py` + the `agent_tools/*`
   hunt tools; nothing downstream is affected.

**Why the hunting swap is easier than it sounds:** RAPTOR's agent *generates* its hunting
queries through the LLM at run time (with `kql_templates` as fallback), rather than relying
only on hardcoded queries. Re-targeting the query language is largely a matter of prompting
the agent for the destination dialect and adapting the fallback templates — not rewriting
every detector by hand.

## Limits

- The **query language** is genuinely coupled work — we don't claim "any SIEM out of the
  box." We claim the coupling is *isolated* to Adapter #2, so it's a bounded port, not a
  rewrite.
- Field semantics differ across vendors (e.g. an EDR's process-tree fields vs. a log-based
  SIEM's). The `NormalizedAlert` mapping is where you reconcile that, once.
- The high-sensitivity routing (on-prem LLM for CloudTrail/privesc/command alerts) is
  independent of the SIEM and carries over unchanged.

The design goal was never "zero-effort SIEM swap" — it was **"vendor coupling confined to
two named files-worth of adapters, so an EDR/SIEM change never ripples into the triage logic,
the data boundary, or the institutional memory."** That is what the normalization interface buys.
