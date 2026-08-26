# RAPTOR Demo — run it locally (no credentials)

Runs the full RAPTOR triage console **offline** against synthetic **Northwind
Securities** data. No Jira, MDE, or LLM credentials are needed and no external
service is contacted.

## Prerequisites

- **Python 3.11+** — check with `python3 --version`. If it's older (e.g. 3.9), use an
  explicit `python3.11`. Installing under < 3.11 fails with
  `Package 'raptor-soc' requires a different Python`.
- **Docker** running (Docker Desktop or equivalent) — the demo starts MongoDB via
  `docker compose`. Alternatively point `MONGODB_URI` at any reachable MongoDB.

## Quick start

```bash
# from the repo root
python3.11 -m venv .venv && source .venv/bin/activate   # use python3.11 explicitly
pip install -e .

./demo/run_demo.sh          # MongoDB up → seed synthetic data → launch on :10004
```

Then open **http://localhost:10004** and log in with **admin / demo**.

`run_demo.sh` is just these steps if you prefer to run them by hand:

```bash
docker compose up -d                       # MongoDB (Docker must be running)
set -a; source demo/demo.env; set +a       # credential-free demo config
python demo/seed_demo.py                    # synthetic data
uvicorn app.main:app --port 10004
```

## What you'll see

- **RAPTOR queue** (`/edr-triage`) — synthetic alerts with AI verdicts
  (AUTO_CLOSED_FP/TP, NEEDS_L2, URGENT), confidence, and the per-alert agent
  investigation trail. Click any alert to open the detail drawer, then scroll to the
  **"Posted to Jira"** panel — the exact comment, transition, and labels RAPTOR would
  write to the ticket (dry-run: shown, not sent).
- **AI Memory / SCG** (`/memory/quarantine`) — the tiered institutional memory
  (quarantine → curated → golden), the analyst leaderboard, and the AI-vs-human
  accuracy + drift widgets. The **Quarantine Queue** tab shows the AI↔analyst
  disagreements (click one for the "RAPTOR proposed ↔ L1/L2 decided" panel), and
  **Planned Activity** shows the declared maintenance windows.
- **Context Graph** — an interactive node-link map of the entities RAPTOR tracks
  (devices/users), the alerts linking them (colored by verdict), and the memories
  it learned. Hover a node to trace its links, click for details. It's a tab on the
  AI-Memory page and also a full-screen page at **`/memory/graph`** (there's an
  *Open full screen* button on the tab). Dashed rings mark AI↔analyst disagreements.

## Drive a live triage

Everything above is seeded. To watch one alert triaged end-to-end on synthetic data
(deterministic playbook, no LLM), click **"Run synthetic alert"** in the RAPTOR UI —
or call the endpoint (`POST /api/edr-triage/run-synthetic`) with your session cookie.

## See the *real* mechanisms (for a live demo / recording)

The default demo (`rule_based`, seeded) shows the UI and data flow. To demonstrate the
two novel mechanisms *actually working* — with no company data — use these:

**1. The data-sovereignty boundary — no LLM, no key, fully real:**

```bash
python demo/show_boundary.py
```

Runs the shipped `AlertSanitizer` on a realistic alert and prints the round trip: raw
alert → what crosses to the cloud LLM (identifiers tokenized, public IOCs preserved) →
the LLM's tool call (tokens only) → the restored real values used on-prem. It asserts
zero leakage and exits non-zero if anything leaks — so it's a live demo *and* a test.
This is the cleanest way to show the headline novelty; it needs nothing but Python.

**2. The agent loop with a real model — free and local (Ollama):**

```bash
# install Ollama (ollama.com), then:
ollama pull deepseek-r1:8b
AGENT_BACKEND=ollama USE_AGENT_LOOP=true DEMO_MODE=true \
DEEPINTEL_PASSWORD=demo MONGODB_URI=mongodb://localhost:27017 \
uvicorn app.main:app --port 10004
```

Now "Run synthetic alert" drives the **real ReAct agent** (think → tool calls → verdict)
against a real on-prem model — offline, no cost, no credentials.

**3. The sanitizer firing inside the live app** happens only for the *external* backend
(on-prem/Ollama is trusted with raw data by design). To show it in-app, set
`AGENT_BACKEND=gemini` with a `GEMINI_API_KEY` — the sanitizer tokenizes before every
Gemini call. For a credential-free proof, prefer `show_boundary.py` above.

> **Recording tip:** record *this open-source repo* (with Ollama for real reasoning +
> `show_boundary.py` for the boundary), not a hosted internal tool — so what you demo is
> exactly what attendees can clone, with zero company data on screen.

## Tests and reviewer-proofing

All credential-free and runnable from a clean clone:

```bash
python tests/test_boundary.py     # zero-leakage + round-trip test (also runs under pytest)
python demo/attack_boundary.py    # adversarial finding: crafts identifiers past the sanitizer
python demo/accuracy_chart.py     # regenerates docs/accuracy-over-time.svg from the shadow record
```

`test_boundary.py` proves the defended cases; `attack_boundary.py` demonstrates the
documented gaps (see [../docs/attacking-the-boundary.md](../docs/attacking-the-boundary.md)).

## Reset the data

```bash
python demo/seed_demo.py      # idempotent — clears and re-seeds the demo collections
```

## Notes

- `DEMO_MODE=true` skips the ticketing/closure pollers (they'd only log connection
  noise without credentials).
- `LLM_BACKEND=rule_based` + `USE_AGENT_LOOP=false` keep triage fully deterministic and
  offline. To try a real model, see the [Integration Guide](../docs/integration.md) and
  set `AGENT_BACKEND` / `LLM_BACKEND` with the matching credentials.
- Stop everything with `docker compose down` (add `-v` to also drop the MongoDB volume).
