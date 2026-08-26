# Attacking the Boundary — a threat model of the sanitizer

The data-sovereignty boundary ([`agent_core/sanitize.py`](../agent_core/sanitize.py)) is
RAPTOR's core claim, so it ships with a threat model rather than assurances. This document
states **what the boundary defends, what it does not, how it can be attacked, and what
would harden it** — each item maps to the shipped implementation.

> **In one line:** the sanitizer is a strong *default-deny-by-token* filter
> for the identifiers it knows about, and **defense-in-depth**, not a cryptographic
> guarantee. Deploy it *with* an egress DLP control and provider data-handling terms — not
> instead of them.

**Runnable repro:** [`demo/attack_boundary.py`](../demo/attack_boundary.py) demonstrates
classes A and B below — it crafts a second internal host, a second user, an internal IPv6,
and a base64-encoded device name past the sanitizer and prints exactly what leaks, with the
mitigation for each. The defended cases are covered by [`tests/test_boundary.py`](../tests/test_boundary.py).

## What it defends (design intent)

Before any text reaches an external LLM, the sanitizer:

- **Tokenizes seeded identifiers** — the alert's device and user (plus the bare UPN local
  part and the FQDN form) become stable `[DEVICE-xxxx]` / `[USER-xxxx]` tokens.
- **Redacts by regex** — AWS ARNs, EC2 instance IDs, `AKIA`/`ASIA` access keys, RFC1918
  IPv4 ranges, Windows SIDs, MAC addresses.
- **Strips known columns** — `DeviceName`, `AccountName`, `ProcessCommandLine`, etc. are
  removed wholesale from structured KQL/MDE result dicts (`sanitize_obj`).
- **Redacts internal emails** — addresses at configured company domains.
- **Preserves public IOCs** — external IPs, domains, and file hashes pass through
  unchanged; they are the evidence the model needs.
- **Restores tokens before tool execution** — so lookups run on real values on-prem.

## What it does NOT defend (be explicit)

- It is **not** anti-prompt-injection. It controls *identifier egress*, not model behavior.
- It is **not** a guarantee that *no* sensitive string ever leaves — it hides what it is
  *told about* (seeds) or what *matches a pattern*. Unenumerated sensitive data can pass.
- It does **not** protect the *public-IOC channel* — anything shaped like an external
  domain/IP/hash is deliberately let through.

---

## Attack classes

### A. Coverage gaps — unenumerated sensitive entities *(highest real risk)*

The sanitizer seeds only the alert's **primary** device and user. Any *other* sensitive
identifier in free text leaks unless a regex/column catches it:

- A **lateral-movement target host** named in a command line (not the alert's own device).
- A **jump host / server name** that is an internal hostname but not RFC1918 and not seeded.
- A **second user / analyst name** quoted in evidence or a prior comment.
- **Cloud resource names** with no ARN form — S3 bucket names, RDS/Redshift identifiers,
  GCP project IDs, Azure resource names.

**Status:** partial gap. Mitigation below (seed *all* extracted entities, not just two).

### B. Format-evasion of the regexes

The redaction regexes match specific shapes; near-misses survive:

- **Internal IPv6** — only RFC1918 **IPv4** is matched. Unique-local (`fd00::/8`) and
  link-local (`fe80::`) IPv6 addresses pass through. **Gap.**
- **Non-canonical IPv4** — zero-padded (`010.000.004.017`) or integer-form addresses.
- **Encoded identifiers inside command lines** — `sanitize()` on prompt *text* applies the
  regexes but does **not** strip the command line wholesale (only the `ProcessCommandLine`
  *column* is stripped, and only in `sanitize_obj`). A device name or secret embedded in a
  base64/hex blob (e.g. an encoded PowerShell arg) is not decoded, so it survives. **Gap.**

### C. Token determinism → cross-request correlation

`_short_token` = `sha256(value.lower())[:4]`. This is **deterministic across runs**: the
same host is always `[DEVICE-5b24]`. A curious or compromised external provider can
therefore **correlate one host's activity across many requests over time**, and with
enough surrounding context potentially re-identify it — even though the plaintext name
never left. The 4-hex space (65k) also allows rare **token collisions**, where two entities
share a token and `desanitize` restores the *first-seen* value — a correctness/safety bug
(a tool could run against the wrong host). **Gap (privacy) + low-probability correctness.**

### D. Reverse-channel via the desanitizer

`desanitize` is a literal token→value replacement on model-supplied tool args. Combined
with **prompt injection** in attacker-influenced alert text, a model can be steered to
emit a tool call that, after restoration, acts on a real (seeded) host. Blast radius is
bounded to seeded entities, but the boundary itself provides **no** defense here — tool
authorization must. RAPTOR's deterministic safety gates address part of this; the
sanitizer does not.

### E. Exfiltration through the public-IOC channel

External domains/IPs/hashes are intentionally preserved. Attacker-influenced content can
smuggle data out **encoded as a domain-shaped string** — e.g. `<base64-of-secret>.evil.tld`
appears in the alert, is treated as a "public IOC," and is forwarded verbatim. **Gap** —
inherent to preserving IOCs; needs an entropy/allowlist check.

### F. Short-value guard bypass

Values shorter than 3 characters are never seeded (a guard against catastrophic substring
replacement). A 2-character hostname or username is therefore never tokenized. Niche, but
real for short internal naming schemes.

---

## What holds well

- The alert's **primary device and user** — including FQDN and bare-local-part forms,
  case-insensitively, with word-boundary safety — are reliably tokenized.
- **Standard AWS ARNs, instance IDs, access keys, RFC1918 IPv4, SIDs, MACs, internal
  emails** — solid coverage for the overwhelmingly common cases.
- **Structured KQL/MDE results** — sensitive columns are dropped wholesale.
- **Round-trip integrity** for seeded values is exact (verified by `demo/show_boundary.py`,
  which asserts zero leakage of the enumerated sensitive set and IOC preservation).

---

## Hardening roadmap

Ordered by leverage. These are the fixes an adversarial review should drive:

1. **Seed every extracted entity, not just two.** Feed the alert's full entity set
   (`entity_graph` extractor output — every device/user/host it finds) into the sanitizer
   so class **A** shrinks dramatically.
2. **Per-run salt on tokens.** `sha256(salt + value)` with a per-run salt kills cross-request
   correlation (class **C**) while keeping within-run stability.
3. **Scan command-line *text*, not just the column.** Apply seed/regex redaction to
   free-text command lines and, where feasible, decode common encodings before scanning
   (class **B**).
4. **Add internal IPv6** (`fd00::/8`, `fe80::/10`) and non-canonical IPv4 handling (class **B**).
5. **Entropy / allowlist check on preserved IOCs** — flag high-entropy or over-long
   subdomains that may be data-encoded-as-domain (class **E**).
6. **Keep tool authorization separate** — the boundary is not an injection defense; pair it
   with RAPTOR's safety gates and least-privilege tool scopes (class **D**).

## Deployment guidance

Treat the boundary as one layer:

- **Net egress:** run RAPTOR's external-LLM calls through an egress proxy / DLP filter as a
  second net — the sanitizer is application-layer and can miss class-A/B data.
- **Contractual:** external providers should still carry no-retention / no-train terms.
- **Prefer on-prem for the highest-sensitivity alert classes** — RAPTOR already routes
  CloudTrail/privesc/command alerts to an on-prem backend where the sanitizer is not even
  needed, and only anonymized/public-IOC classes to the external path.

The claim RAPTOR makes is not "nothing sensitive can ever leak." It is: *for the
enumerated identifier classes, sensitive values are replaced with tokens before egress and
restored before execution, verifiably and by default* — and this document lays out where
that holds and where it doesn't.
