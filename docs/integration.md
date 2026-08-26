# Integration Guide — Adapting RAPTOR to Your Environment

RAPTOR ships wired for a Microsoft Defender + Sentinel + Jira stack, but every
external dependency sits behind a swappable interface. This guide takes you from a clean
clone to a deployment tuned for your own SOC.

> **New here?** Run the credential-free demo first ([`demo/README.md`](../demo/README.md))
> to see the full pipeline against synthetic data before wiring in any real system.

---

## The integration model

RAPTOR has three kinds of extension points. Most teams only touch the first two.

| Layer | How you extend it | Code required? |
|---|---|---|
| **Config** | `.env` values — endpoints, keys, feature flags, model selection | No |
| **Rules** | MongoDB triage-routing rules (via the API) | No |
| **Backends / clients / playbooks** | Implement a small interface, drop the file in | Yes (Python) |

---

## Step 1 — Run in demo mode (no credentials)

Requires **Python 3.11+** and a running **Docker** (for MongoDB).

```bash
python3.11 -m venv .venv && source .venv/bin/activate   # 3.11+ required
pip install -e .
./demo/run_demo.sh            # MongoDB → seed synthetic data → launch on :10004
```

Open `http://localhost:10004` (login `admin` / `demo`). See [`demo/README.md`](../demo/README.md).

- `LLM_BACKEND=rule_based` + `USE_AGENT_LOOP=false` — deterministic playbook, no LLM, no external calls.
- `DEMO_MODE=true` — skips the ticketing/closure pollers so a credential-free run is quiet.

---

## Step 2 — Pick your LLM backend

The LLM sits behind `LLMBackend` in [`agent_core/backend.py`](../agent_core/backend.py). The
agent loop selects its backend with `AGENT_BACKEND`:

| `AGENT_BACKEND` | Class | Data policy | Use when |
|---|---|---|---|
| `ollama` | `OllamaBackend` | On-prem, raw data | Full data sovereignty (regulated environments) |
| `bedrock` | `BedrockBackend` | Stays in your AWS region | You're on AWS and want managed inference |
| `gemini` | Ollama for sensitive alert types, else `GeminiBackend` | **Sanitizer enforced** for Gemini | Non-sensitive classes; public-IOC reasoning |

There is no `rule_based` agent backend — any backend failure or spend-cap trip falls
back to the deterministic playbook (the fail-safe). The legacy generic playbook has its
own `LLM_BACKEND` selector (`ollama` / `gemini` / `rule_based`) used by
[`edr_triage/playbooks/generic.py`](../edr_triage/playbooks/generic.py); for demo/air-gapped
runs set `LLM_BACKEND=rule_based`.

### Bring your own model provider

```python
# agent_core/backend.py
class MyProviderBackend(LLMBackend):
    async def chat(self, messages: list[dict], tools: list[dict]) -> tuple[str, list[ToolCall]]:
        # Call your provider; return (assistant_text, parsed_tool_calls).
        # If your model lacks native tool-calls, emit <tool_call>{...}</tool_call>
        # markers in text — _parse_tool_calls() already handles that.
        ...

    async def health_check(self) -> bool:
        return True
```

> **Sanitizer rule:** the agent loop ([`agent_core/loop.py`](../agent_core/loop.py))
> activates `AlertSanitizer` for `GeminiBackend`. If your new backend sends data to an
> external service, gate it the same way — an `isinstance` check so device names, ARNs,
> and command lines are tokenized before they leave your infrastructure. On-prem /
> in-region backends skip the sanitizer and get raw data.

---

## Step 3 — Connect your ticketing / EDR

Reference stack: MDE (endpoint) + Sentinel (identity/cloud) + Jira (ticketing).

RAPTOR polls Jira for new alert tickets. To use a different ticketing system, the
touchpoints are:

- [`edr_triage/jira_poller.py`](../edr_triage/jira_poller.py) — fetches new tickets
- [`edr_triage/jira_handler.py`](../edr_triage/jira_handler.py) — writes comments, transitions, labels
- [`edr_triage/normalized.py`](../edr_triage/normalized.py) — `NormalizedAlert`, the vendor-agnostic alert view every playbook consumes

Keep the `NormalizedAlert` shape stable and playbooks won't care where the alert came
from. Swap the poller/handler pair for ServiceNow, PagerDuty, or a webhook and the rest
of the pipeline is unchanged.

**Enrichment (optional):** set `MDE_*` for endpoint context and `SENTINEL_*`
(subscription / resource group / workspace) for Log Analytics hunts via
[`lib/mde_client.py`](../lib/mde_client.py). Leave them blank and the agent falls back to
the alert's own fields.

---

## Step 4 — Tune classification (no code)

Alert-name → playbook routing lives in [`edr_triage/classifier.py`](../edr_triage/classifier.py),
but **user-defined rules in MongoDB are checked first**, so you tune routing without
editing code ([`edr_triage/rules.py`](../edr_triage/rules.py)):

```python
from edr_triage.rules import create_rule

create_rule(
    pattern="Acme EDR - Suspicious Binary",
    playbook="malware",          # skip|block_tool|malware|reverse_shell|
                                 # lateral_move|credential_access|privesc|generic|netskope
    match_type="contains",       # or "regex"
    note="Route Acme EDR binary alerts to the malware playbook",
)
```

---

## Step 5 — Add a triage playbook

For bespoke verdict logic, inherit `BasePlaybook`
([`edr_triage/playbooks/base.py`](../edr_triage/playbooks/base.py)) and implement `run()`:

```python
# edr_triage/playbooks/my_playbook.py
from edr_triage.playbooks.base import BasePlaybook, PlaybookResult

class MyPlaybook(BasePlaybook):
    async def run(self, jira_key, alert, evidence, vt, timeline,
                  is_test_device=False, sentinel_entities=None, normalized=None) -> PlaybookResult:
        return PlaybookResult(
            triage_class="NEEDS_L2",     # AUTO_CLOSED_TP|AUTO_CLOSED_FP|NEEDS_L2|URGENT|PENDING
            l1_comment="…",              # wiki markup — this is what gets posted to the ticket
            auto_close=False,
            labels=["my-playbook"],
        )
```

Reuse the shared helpers on `BasePlaybook` (`_vt_line`, `_precedent_section`) for
consistent Jira-comment formatting, then wire the playbook into the classifier (Step 4).

---

## Step 6 — Configure the data boundary

If any alert class is routed to an external LLM, set which identifiers get stripped.
[`AlertSanitizer`](../agent_core/sanitize.py) already redacts ARNs, EC2 IDs, access keys,
RFC1918 IPs, SIDs, and MACs; add your internal email domains and (optionally) your brand
token:

```bash
SANITIZER_INTERNAL_DOMAINS=example.com,corp.example.com
SANITIZER_COMPANY_NAME=acme
```

Device names and user principals are seeded per-run from the alert automatically.

---

## Where things live

| You want to… | Look at |
|---|---|
| Swap the LLM | `agent_core/backend.py` |
| Change alert intake / ticketing | `edr_triage/jira_poller.py`, `jira_handler.py`, `normalized.py` |
| Add MDE/Sentinel enrichment | `lib/mde_client.py`, `agent_tools/` |
| Route alerts to playbooks | `edr_triage/rules.py` (no-code) + `classifier.py` |
| Add verdict logic | `edr_triage/playbooks/` |
| Control the data boundary | `agent_core/sanitize.py` + `SANITIZER_*` |
| Everything configurable | [`env.example`](../env.example) |
