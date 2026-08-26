# RAPTOR — Black Hat Arsenal

**An open-source agentic SOC triage engine that runs cloud LLMs on regulated data without
leaking it, and learns from analyst decisions through a decaying, tiered memory graph.**

## Abstract

RAPTOR is an open-source, self-hosted autonomous L1 SOC analyst. It polls a ticketing/EDR
stack, classifies each alert, investigates it with a ReAct agent loop over real tools
(Defender/Sentinel KQL, VirusTotal, Jira), and posts a verdict.

Its defining feature is a bidirectional entity sanitizer: device names, user principals, AWS
ARNs, internal IPs, and command lines are tokenized before any external-LLM call and restored
before tool execution, so the model reasons over tokens while live queries run on real values.
Public IOCs — hashes and external domains — are preserved as evidence. A second contribution,
the Security Context Graph, is a tiered memory (`quarantine → curated → golden`) that promotes
what the AI and analyst agree on, quarantines disagreements, and decays stale patterns.

RAPTOR was extracted from a platform running in a financial-services SOC and is, to our
knowledge, the first open-source agentic SOC triage engine with an enforced application-layer
data-sovereignty boundary. Clone it and run the full pipeline on bundled synthetic data with
zero credentials.

## Problem statement

AI-assisted SOC triage is arriving fast, but in regulated sectors (finance, healthcare,
government) it stalls on two problems.

**Data residency.** Sending alert data — device names, user principals, cloud ARNs, internal
IPs, command lines — to a cloud LLM breaks data-sovereignty and privacy requirements. The
usual answers are all-or-nothing: self-host a weaker model and forfeit state-of-the-art
capability, or trust contractual no-retention promises. Neither is an *enforced technical
control* at the point where data would leave.

**Trust over time.** An AI SOC that learns from analyst feedback also learns the wrong lessons
if left unchecked: a one-off exception hardens into a standing rule, and a stale pattern keeps
auto-closing alerts that now matter. How the system avoids learning garbage — and how it earns
the right to act — has no good open-source answer today.

RAPTOR answers both with enforced controls rather than promises, and ships them open source.

## Solution overview

RAPTOR sits between your ticketing/EDR stack and an LLM and runs each alert through a fixed
pipeline:

1. **Intake & normalize.** A poller converts each alert (Jira + MDE/Sentinel today) into a
   vendor-neutral `NormalizedAlert`; everything downstream is source-agnostic.
2. **Classify & route.** No-code rules and a classifier pick the playbook (malware, privesc,
   credential-access, lateral-move, …) and subtype.
3. **Investigate.** A ReAct loop (think → act → observe) runs real tools — KQL hunts,
   VirusTotal, precedent recall, Jira — behind deterministic safety gates that can only escalate.
4. **Cross the boundary.** The sanitizer tokenizes device/user/ARN/IP/SID/command-line values
   before any external-LLM call and restores them before a tool runs; high-sensitivity classes
   skip the cloud entirely and use an on-prem model on raw data.
5. **Verdict & act.** The agent returns a verdict with confidence and MITRE mapping and, per
   rollout phase, comments on, transitions, or auto-closes the ticket.
6. **Learn.** On close, the human outcome is scored against the verdict and written to the
   Security Context Graph (promote, quarantine, or decay), which feeds back into step 3.

Autonomy is earned per alert class: RAPTOR runs in **shadow** (records only), then **copilot**
(advisory comments), then **autonomous** (acts) — and a class is promoted only once its measured
accuracy against analysts clears a threshold.

**Stack:** Python 3.11, FastAPI, MongoDB. Pluggable LLM backends (Ollama, Bedrock, Gemini —
sanitizer enforced for external ones). Apache-2.0. Runs offline on synthetic data.

## Why Black Hat Arsenal should accept this

The payoff is concrete, measurable on the bundled data, and the kind an attendee can act on.

- **It removes the largest, dullest part of SOC work.** RAPTOR auto-resolves the clear-cut
  alerts and escalates only what needs a person. On the bundled demo that is 6 of 12 alerts
  (50%) auto-closed at high confidence, with the evidence attached. In a real queue, where
  benign alerts dominate, that is the difference between an analyst reading every alert and
  reading only the ones that matter.
- **It unlocks frontier LLMs on data that legally cannot leave.** A finance, health, or
  government SOC cannot send device names, users, ARNs, or command lines to a cloud model; the
  compliance answer is "no." The tokenization boundary turns that into "yes, with an enforced
  control you can show an auditor." Without it these teams are stuck on weaker self-hosted
  models; with it they get state-of-the-art reasoning on real alerts.
- **Each verdict is faster and cheaper than a human pass.** An alert gets an evidence-backed
  verdict (hash reputation, live hunts, precedent, MITRE) the moment it lands, for cents of
  model spend, instead of waiting hours in a queue. Once a pattern is settled it becomes golden
  memory and future matches close with no LLM call at all.
- **The value compounds instead of plateauing.** Accuracy rises as the memory learns from
  analyst closures (about 83% AI-vs-analyst agreement on the demo record, and the metric is
  kept honest), and RAPTOR earns write access one alert class at a time only after it has proven
  itself. Automation and trust grow together rather than on a leap of faith.
- **Take-home for the room.** It clones and runs offline with zero credentials, ships a runnable
  exploit of its own boundary, and the sanitizer is a standalone primitive you can drop into any
  regulated LLM pipeline.
