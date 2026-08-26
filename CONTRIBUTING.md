# Contributing to RAPTOR

Thanks for your interest. RAPTOR is built around a few small, stable interfaces, so most
useful additions don't require touching the core pipeline.

## Ways to contribute

- **Playbooks** — verdict logic for an alert type. One class with a `run()` in
  `edr_triage/playbooks/`; see `generic.py` for the shape.
- **Routing rules** — send alerts to a playbook without code, via `edr_triage/rules.py`
  (matched before the classifier).
- **LLM backends** — implement `chat()` and `health_check()` in `agent_core/backend.py`. If
  the backend is external, the sanitizer must be enforced.
- **Ticketing / SIEM adapters** — anything that produces a `NormalizedAlert` at intake or
  runs a hunt query for enrichment. Everything between those two edges is vendor-agnostic;
  see [docs/portability.md](docs/portability.md).
- **Boundary hardening** — [docs/attacking-the-boundary.md](docs/attacking-the-boundary.md)
  lists scoped items: internal IPv6, per-run token salt, entropy/allowlist checks on
  preserved IOCs, command-line scanning.
- **Graph scoping** — the ego-graph, time-window, and top-N filters described in
  [docs/scaling-the-graph.md](docs/scaling-the-graph.md).
- **Docs and demo** — corrections, clearer examples, more synthetic scenarios.

## Development

Requires Python 3.11+ and Docker.

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e .
./demo/run_demo.sh          # MongoDB up, seed synthetic data, serve on :10004
```

Before opening a PR, check that:

- `python demo/show_boundary.py` passes (asserts zero leakage).
- `./demo/run_demo.sh` comes up and the console loads with the seeded data.
- `python -m py_compile` (or your linter) is clean on the files you changed.

## Data hygiene

This repo is extracted from a private one, so keeping it clean matters:

- No real hostnames, usernames, emails, ticket IDs, IPs, or company names anywhere — code,
  comments, tests, fixtures, or screenshots. Use the synthetic *Northwind Securities* set
  (`WKSTN-####`, `alice.chen@example.com`, `DEMO-####`).
- No credentials or API keys, ever. `.env` is gitignored; the demo runs on `demo/demo.env`
  with every external secret blank.
- New fixtures should be synthetic from the start.

## Pull requests

- Fork, create a topic branch, open a PR against `main`.
- Keep PRs focused; say what changed and why.
- Apache-2.0, no CLA — opening a PR is your agreement to license the contribution under
  Apache-2.0.

## Reporting a boundary bypass

The sanitizer has a documented threat model in
[docs/attacking-the-boundary.md](docs/attacking-the-boundary.md). If you find a bypass, open
an issue with the attack class and a minimal repro. No bounty, but credit is given.
