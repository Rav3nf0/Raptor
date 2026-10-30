"""Netskope web-proxy playbook — "Failed Login" / blocked web-access events.

These are Netskope web-filtering / policy events (e.g. a blocked category or app
like Social Media / Facebook), NOT Azure AD credential attacks. They were
previously misrouted to the Entra credential_access playbook, which printed the
wrong "incorrect password / account locked" narrative and dropped the
Netskope-specific evidence (hostname, source IP, app, URL, user agent, category).
"""
from __future__ import annotations

import re

from edr_triage.config import get_edr_config
from edr_triage.playbooks.base import BasePlaybook, PlaybookResult


# Known Netskope field labels — used to bound a captured value so a flattened
# single-line description ("User: x Category: y Hostname: z …") doesn't let one
# field greedily swallow the rest.
_NS_LABELS = (
    r"User\s+Agent|Source\s+IP|Involved\s+Users?|Users?|Category|"
    r"Hostname|App|Url|URL|Page|DLP\s+Profile"
)


def _field(text: str, label_pattern: str) -> str:
    """Pull a single labelled field (e.g. 'Hostname: X') from alert text.

    Stops the value at the next known label or a 2+ space separator so multi-field
    lines parse cleanly.
    """
    if not text:
        return ""
    m = re.search(label_pattern + r"\s*:\s*(.+)", text, re.IGNORECASE)
    if not m:
        return ""
    val = m.group(1).splitlines()[0]
    val = re.split(r"\s{2,}", val)[0]                                  # real desc uses 2+ space separators
    val = re.split(rf"\s+(?:{_NS_LABELS})\s*:", val, flags=re.IGNORECASE)[0]  # or stop at next known label
    return val.strip()[:200]


# Profile-based DLP routing, per the standing rule set 2026-09-22:
#   DLP-Secret-key  -> false positive
#   national IDs    -> raise to L2
#
# Composition is the load-bearing part. A DLP ticket is a BUNDLE, not one finding —
# the Sentinel rule aggregates with SingleAlert, so one alert routinely carries many
# events across several users and profiles (DEMO-111418 carried 15 events mixing both
# profiles). So this auto-closes ONLY when EVERY event is a secret-key finding: one
# national-ID event anywhere in the bundle escalates the whole ticket, because closing
# it would close that finding too.
#
# Anything unrecognised also escalates. A new or renamed profile must not inherit the
# false-positive verdict by default.
def _dlp_all_secret_key(events: list[dict]) -> bool:
    """True when every bound event is a secrets/password finding and none is a national-ID one."""
    import os
    if os.getenv("DLP_SECRET_KEY_AUTOCLOSE_DISABLED", "").lower() == "true":
        return False
    if not events:
        return False
    for e in events:
        blob = f"{e.get('dlp_profile') or ''} {e.get('dlp_rule') or ''}".strip().lower()
        if not blob:
            return False                      # unclassifiable event — do not auto-close
        if "national" in blob or "aadhar" in blob or "aadhaar" in blob or "pan " in blob:
            return False                      # a national-ID finding is in this bundle
        if not ("secret" in blob or "password" in blob):
            return False                      # some other profile — escalate, do not assume
    return True


# Netskope's names for the company tenants a CASB API scan reads. Only a file at rest in one
# of these closes on the secret-key rule; any other app name (or none) fails closed.
_AT_REST_COMPANY_APPS = frozenset({
    "google drive", "google gmail",
    "microsoft office 365 onedrive for business", "microsoft office 365 outlook.com",
})


async def _secret_key_owners(events: list[dict]) -> tuple[dict[str, str], list[str]]:
    """({user: where their justification is}, [users with none]). A justification is an
    entry in docs/dlpcontext.txt or a DLP ticket a human closed on the person's own answer;
    a failed lookup counts as none, so the user is asked rather than closed on."""
    from edr_triage.dlp_context import justification_for
    from entity_graph.query import dlp_user_justification
    ok, missing = {}, []
    for u in dict.fromkeys((e.get("user") or "").strip().lower() for e in events):
        if not u:
            missing.append("an unnamed user")
            continue
        j = justification_for(u)
        if j:
            ok[u] = f"on file — {j[:200]}"
            continue
        rec = await dlp_user_justification(u)
        if rec:
            ok[u] = f"{rec['jira_key']} — {rec['text'][:200]}"
        else:
            missing.append(u)
    return ok, missing


class NetskopePlaybook(BasePlaybook):

    async def run(
        self,
        jira_key: str,
        alert: dict,
        evidence: dict,
        vt: dict,
        timeline: list[dict],
        is_test_device: bool = False,
        sentinel_entities: dict | None = None,
        normalized=None,
    ) -> PlaybookResult:
        from edr_triage.normalized import normalize_alert
        n = normalized or normalize_alert(alert, evidence, sentinel_entities, source="sentinel")
        alert_name   = n.name if n.name != "Alert" else "Netskope - Failed Login"
        incident_url = n.incident_url
        desc         = n.description

        ent = sentinel_entities or {}

        # ── Netskope DLP branch ────────────────────────────────────────────
        # Detail bound from Netskope_Alerts_CL by the pipeline. Deterministic —
        # no LLM reasoning here on purpose: this replaces the MECHANICAL half of
        # what L1 currently retypes by hand from the Sentinel incident every time
        # (user, access method, activity, DLP profile/rule/severity, file size,
        # timestamp — see DEMO-110575). Verdict is always NEEDS_L2: a DLP hit needs
        # a human to confirm what the data actually is and whether the business
        # reason holds, the same as every prior DLP ticket in this project's history.
        dlp = ent.get("netskope_dlp") or {}
        if dlp and dlp.get("events"):
            events = dlp["events"]
            multi = len(events) > 1
            lines = [
                "Hi Team,",
                f"we have received a *Netskope DLP alert*"
                + (f" with *{len(events)} flagged events*." if multi else "."),
                "",
            ]
            for i, e in enumerate(events, 1):
                prefix = f"*Event {i}:*" if multi else "*Details:*"
                lines.append(prefix)
                if e.get("user"):
                    lines.append(f"  *User:* {e['user']}")
                if e.get("access_method"):
                    lines.append(f"  *Access Method:* {e['access_method']}")
                if e.get("activity"):
                    lines.append(f"  *Activity:* {e['activity']}")
                if e.get("app"):
                    lines.append(f"  *Application:* {e['app']}")
                if e.get("dlp_profile"):
                    lines.append(f"  *DLP Profile:* {e['dlp_profile']}")
                if e.get("dlp_rule"):
                    lines.append(f"  *DLP Rule:* {e['dlp_rule']}")
                if e.get("dlp_rule_severity"):
                    lines.append(f"  *DLP Rule Severity:* {e['dlp_rule_severity']}")
                if e.get("dlp_incident_id"):
                    lines.append(f"  *DLP Incident ID:* {e['dlp_incident_id']}")
                # `dlp_file` FIRST: it is the key _normalize_dlp_row actually emits, and
                # alert-bound rows (the primary path — 94% of DLP tickets) all come
                # through that normaliser. Reading only object_name/file_name/file_path
                # meant this line silently never rendered, so no DLP ticket has ever
                # named its file. Measured 2026-09-02 across 360 DLP tickets: the
                # ~147 `DLP-Secret-key` findings say "a 2,820,676-byte Google Drive file
                # contains a password" and nothing more — 18 of them share that exact
                # byte size, i.e. one file re-scanned, invisibly. Humans closed 28 of
                # them FP without being able to see which file they were judging, and a
                # credential cannot be rotated if the ticket does not locate it.
                #
                # The later keys are kept for window-sweep rows, which arrive already
                # aliased and bypass the normaliser.
                _obj = (e.get("dlp_file") or e.get("object_name")
                        or e.get("file_name") or e.get("file_path"))
                if _obj:
                    lines.append(f"  *File/Object:* {str(_obj)[:200]}")
                if e.get("file_size"):
                    try:
                        lines.append(f"  *File Size:* {int(float(e['file_size'])):,} bytes")
                    except (TypeError, ValueError):
                        lines.append(f"  *File Size:* {e['file_size']}")
                # Same key mismatch: the normaliser emits `site` (from site/page_site/
                # page), never `page`, so this line was dead on alert-bound rows too.
                # The URL first: it names the destination (DEMO-117744's was the security
                # team's own SAST bucket, acme-security-sast-sca-files), where the site is
                # only "Amazon S3" — which left both RAPTOR and the L1 guessing.
                _site = str(e.get("page") or e.get("site") or "")
                _url = str(e.get("url") or "")
                if _url:
                    lines.append(f"  *URL/Page:* {_url[:200]}"
                                 + (f" ({_site})" if _site and _site.lower() not in _url.lower() else ""))
                elif _site:
                    lines.append(f"  *URL/Page:* {_site[:200]}")
                if e.get("hostname") or e.get("device"):
                    lines.append(f"  *Device:* {e.get('hostname') or e.get('device')}")
                if e.get("src_ip") or e.get("user_ip"):
                    lines.append(f"  *Source IP:* {e.get('src_ip') or e.get('user_ip')}")
                if e.get("TimeGenerated"):
                    lines.append(f"  *Timestamp (UTC):* {str(e['TimeGenerated'])[:19].replace('T', ' ')}")
                lines.append("")
            _complete = dlp.get("event_count", len(events)) == len(events)
            if dlp.get("bind_grouped"):
                lines += [
                    f"_Sentinel grouped this alert: one run of the DLP rule returned "
                    f"{dlp.get('event_count', len(events))} results from "
                    f"{len(dlp.get('users') or [])} user(s), more than the 150 it alerts on "
                    "one by one, so all of them sit in this one alert."
                    + ("" if _complete else f" The first {len(events)} are shown; open the "
                       "Sentinel incident for the rest.") + "_",
                    "",
                ]
            if dlp.get("ambiguous"):
                lines += [
                    f"⚠ Multiple users had DLP hits in this window ({', '.join(dlp.get('users', []))}) "
                    "— verify this is the right user for this specific ticket.",
                    "",
                ]

            # This actor's OWN recorded justification, when L2 has one on file. The
            # generic pattern block below tells an analyst what the usual reasons are;
            # this tells them whether THIS person already gave one — which is the
            # difference between closing a ticket and re-asking a question the org
            # answered months ago. Covers 58% of DLP tickets (38 of 92 recent actors),
            # because the documented people are the recurring high-volume ones.
            #
            # CONTEXT ONLY and deliberately not a verdict input: routing is decided by
            # DLP profile above, and these vary in strength — one entry attaches "saved
            # as part of business purposes" to sixteen people.
            try:
                from edr_triage.dlp_context import justification_for
                _seen, _known = set(), []
                for _e in events:
                    _u = (_e.get("user") or "").strip()
                    if not _u or _u.lower() in _seen:
                        continue
                    _seen.add(_u.lower())
                    _j = justification_for(_u)
                    if _j:
                        _known.append(f"  • *{_u}*: {_j[:400]}")
                if _known:
                    lines += [
                        "*Business justification already on file for this actor "
                        "(context only — confirm it still covers THIS data):*",
                        *_known,
                        "",
                    ]
            except Exception:
                pass

            # General DLP FP-pattern context, imported from historical L2 resolutions —
            # context only, per SCGMemory's own rule: never a substitute for confirming
            # THIS user's actual data/reason. See entity_graph/query.py::get_playbook_memories.
            try:
                from entity_graph.query import get_playbook_memories
                _precedents = await get_playbook_memories("netskope_dlp", limit=1)
                if _precedents and _precedents[0].get("content"):
                    lines += [
                        "*Common legitimate DLP-trigger patterns at Acme (context only — "
                        "still confirm the specific user's data/reason for THIS alert):*",
                        _precedents[0]["content"],
                        "",
                    ]
            except Exception:
                pass

            if incident_url:
                lines += [f"*Sentinel Incident:* {incident_url}", ""]
            if is_test_device:
                lines += [self._test_device_note(), ""]
            # Judged on every bound event, never on the shown subset: a grouped alert can
            # carry hundreds, and one national-ID finding among the unshown ones must not be
            # closed with the rest.
            _all_secret = _complete and _dlp_all_secret_key(events)
            _secret_only = _all_secret
            # A secret-key file AT REST in a company tenant closes whatever the owner's
            # history (user's call, 2026-10-26, on 60 days of evidence): 1,152 of 1,152
            # human decisions on these were closes, none a true positive, and the owner was
            # never really asked. The only secret-key TP in that window was an UPLOAD to an
            # AI tool (DEMO-111848), so anything uploaded, posted or held in another app —
            # AI tools, Slack, S3, partner/regulator sites, no app — keeps the owner rule
            # below and is never closed on this path. An earlier answer on file is cited.
            _at_rest_company = bool(events) and all(
                (e.get("activity") or "").strip().lower() == "casb api scan"
                and (e.get("app") or "").strip().lower() in _AT_REST_COMPANY_APPS
                for e in events)
            _why_ok, _unasked = {}, []
            if _all_secret:
                _why_ok, _unasked = await _secret_key_owners(events)
            if _all_secret and _at_rest_company:
                lines += [
                    "Every flagged event here is a *DLP-Secret-key* finding (secrets/"
                    "password pattern) in a file at rest in a company "
                    + ", ".join(sorted({(e.get("app") or "").strip() for e in events}))
                    + " account, found by a CASB API scan — no upload, post or share. These "
                    "are closed as false positive by standing rule. No national-ID data is "
                    "involved in this ticket.",
                    "",
                ]
                if _why_ok:
                    lines += ["*Why this person holds it (their own earlier answer):*",
                              *[f"  • *{u}*: {w}" for u, w in _why_ok.items()], ""]
                if _unasked:
                    lines += ["No earlier answer on file for " + ", ".join(_unasked) + ".", ""]
                lines += ["Closing as a false positive.", "", "[Auto-triaged by RAPTOR]"]
                return PlaybookResult(
                    l1_comment="\n".join(lines),
                    triage_class="AUTO_CLOSED_FP",
                    action="resolved",
                    labels=["edr-triage-ai", "netskope-dlp", "dlp-secret-key"]
                           + (["multi-event"] if multi else []),
                    auto_close=True,
                )
            # Anything else secret-key (an upload, a post, another app): recommend only, and
            # only for people who have already explained such data. L2, on the 2026-10-14
            # review: kai.verma (DEMO-116210) and ira.chopra (DEMO-115919) were new and should
            # have been asked; rhys.kohli and pia.gandhi (DEMO-116205/116214) had
            # given reasons, which the recommendation should cite.
            if _all_secret and _unasked:
                lines += [
                    "Every flagged event is a *DLP-Secret-key* finding, but "
                    + ", ".join(_unasked) + (" has" if len(_unasked) == 1 else " have")
                    + " never explained data like this, so the standing false-positive "
                    "rule does not cover them yet.",
                    "",
                ]
                _all_secret = False
            if _all_secret:
                lines += [
                    "Every flagged event here is a *DLP-Secret-key* finding (secrets/"
                    "password pattern). No national-ID data is involved in this ticket.",
                    "",
                    "*Why this person holds it (their own earlier answer):*",
                    *[f"  • *{u}*: {w}" for u, w in _why_ok.items()],
                    "",
                    "Recommend closing as a false positive. Not closed automatically: the "
                    "file was uploaded, posted or shared, or is not in a company Drive, "
                    "Gmail, OneDrive or Outlook account.",
                    "",
                    "[Auto-triaged by RAPTOR]",
                ]
                return PlaybookResult(
                    l1_comment="\n".join(lines),
                    triage_class="AUTO_CLOSED_FP",
                    action="labels_only",
                    labels=["edr-triage-ai", "netskope-dlp", "dlp-secret-key"]
                           + (["multi-event"] if multi else []),
                    auto_close=False,
                )

            lines += [
                "Recommendation: confirm with the user what the flagged data is and why it "
                "was saved/shared, and whether it has since been removed if inappropriate.",
                "",
            ]
            # ── Ask the user (2026-10-06) ──
            # What humans do with a national-ID / other non-secret DLP finding is ASK the
            # person: 172 of the 453 decided ones in the 30 days to 2026-10-05 were parked in
            # Awaiting more inputs while an L1 asked by hand, and L2 closed most of the rest
            # "as per the confirmation from user". So RAPTOR asks through the Acme Security
            # Bot and the answer goes to L2 (chase_reply_poller) — RAPTOR never closes on it.
            # Only an alert-bound subject is ever asked (a window sweep names candidates,
            # not the actor), only within EDR_USER_CHASE_MAX_USERS, never on a test device,
            # and only people the bot can reach (85% of these tickets).
            _recips, _unreach = [], []
            _users = [u for u in (dlp.get("users") or []) if u]
            _max_users = get_edr_config().user_chase_max_users
            # Secret-key-only bundles whose owner never explained such data: asking is OFF
            # until RAPTOR matures (user's call, 2026-10-23) — left for an analyst, unmessaged.
            _no_secret_ask = _secret_only and not get_edr_config().dlp_secret_key_ask
            if _no_secret_ask:
                lines.append("*Not asking the owner via Slack:* asking about DLP-Secret-key "
                             "findings is switched off for now (EDR_DLP_SECRET_KEY_ASK).")
            if (dlp.get("bind_source") == "alert" and not is_test_device and not _no_secret_ask
                    and 0 < len(_users) <= _max_users):
                from edr_triage.identity import eligible_recipients
                _recips, _unreach = await eligible_recipients(_users)
                if _unreach:
                    lines.append("*Cannot be asked via Slack — L2 must establish these:* "
                                 + "; ".join(_unreach))
            if _recips:
                who = ", ".join(f"{r['display_name']} ({r['email']})" for r in _recips)
                lines += [f"*RAPTOR will ask {who} to explain this via the Acme Security "
                          "Bot; the answer goes to L2, who decides.*", "",
                          "[Auto-triaged by RAPTOR]"]
                return PlaybookResult(
                    l1_comment="\n".join(lines),
                    triage_class="NEEDS_L2",
                    action="user_confirmation",
                    labels=["edr-triage-ai", "netskope-dlp", "user-chase-pending"]
                           + (["chase-partial"] if _unreach else [])
                           + (["multi-event"] if multi else []),
                    auto_close=False,
                    chase_recipients=_recips,
                    chase_reason="Netskope DLP finding — the user is asked what the data is "
                                 "and why it was saved or shared (deterministic rule)",
                )
            lines += ["Escalating to L2 for review.", "", "[Auto-triaged by RAPTOR]"]
            # Nobody RAPTOR can ask: an L1 would only move it to L2 by hand (7 of the 30
            # unreachable-owner tickets 2026-10-07..09 sat in L2, the rest waited for that).
            # The move itself is the pipeline's, gated like every state change.
            _to_l2 = bool(_unreach) and get_edr_config().dlp_unreachable_to_l2
            return PlaybookResult(
                l1_comment="\n".join(lines),
                triage_class="NEEDS_L2",
                action="route_to_l2" if _to_l2 else "labels_only",
                labels=["needs-l2-review", "edr-triage-ai", "netskope-dlp"]
                       + (["multi-event"] if multi else []),
                auto_close=False,
            )

        # A DLP ticket whose events could not be read: the alert's row was not in Log
        # Analytics yet, or its grouped query no longer reproduces the alert. Say so,
        # rather than fall through to the web-access template below, which would call it
        # a blocked web request. No user is named, so nobody is asked; a person must open
        # the Sentinel incident.
        if "dlp" in (alert_name or "").lower():
            lines = [
                "Hi Team,",
                "we have received a *Netskope DLP alert*, but RAPTOR could not read its "
                "events: the alert's own rows were not available from Sentinel when it "
                "looked. No user, file or DLP rule is established, so nobody was asked and "
                "nothing was closed.",
                "",
            ]
            if incident_url:
                lines += [f"*Sentinel Incident:* {incident_url}", ""]
            if is_test_device:
                lines += [self._test_device_note(), ""]
            lines += ["Open the Sentinel incident to see the flagged events. Escalating to L2 "
                      "for review.", "", "[Auto-triaged by RAPTOR]"]
            return PlaybookResult(
                l1_comment="\n".join(lines),
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai", "netskope-dlp", "dlp-unbound"],
                auto_close=False,
            )

        # ── Netskope cloud-malware branch ─────────────────────────────────
        # Detail bound from Netskope_Alerts_CL by the pipeline (DEMO-104584).
        nm = ent.get("netskope_malware") or {}
        if nm and nm.get("malware_name"):
            action  = (nm.get("action") or "").strip()
            blocked = any(t in action.lower() for t in ("block", "prevent", "quarantin"))
            sev     = (nm.get("severity") or "").strip() or "unknown"
            lines = [
                "Hi Team,",
                f"we have received a *Netskope malware alert* — *{nm.get('malware_name')}* "
                f"({nm.get('malware_type') or 'malware'}, severity {sev}).",
                "",
            ]
            if nm.get("user"):
                lines.append(f"*User:* {nm['user']}" + (f" ({nm['user_ip']})" if nm.get("user_ip") else ""))
            if nm.get("hostname") or nm.get("device"):
                lines.append(f"*Device:* {nm.get('hostname') or nm.get('device')}"
                             + (f" — {nm['os']}" if nm.get("os") else ""))
            if nm.get("activity"):
                lines.append(f"*Activity:* {nm['activity']}" + (f" via {nm['browser']}" if nm.get("browser") else ""))
            if nm.get("app"):
                lines.append(f"*Application:* {nm['app']}")
            if nm.get("page"):
                lines.append(f"*Page/URL:* {nm['page']}")
            if nm.get("src_ip") or nm.get("dst_ip"):
                loc = f" ({nm['src_location']}, {nm['src_country']})" if nm.get("src_location") else ""
                dst = f"  →  *Dest IP:* {nm['dst_ip']}" if nm.get("dst_ip") else ""
                lines.append(f"*Source IP:* {nm.get('src_ip', '?')}{loc}{dst}")
            if nm.get("policy"):
                lines.append(f"*Policy:* {nm['policy']}")
            if nm.get("detection_engine"):
                lines.append(f"*Detection engine:* {nm['detection_engine']}")
            if nm.get("scanner_result"):
                lines.append(f"*Scanner result:* {nm['scanner_result']}")
            if action:
                flag = "  ✓ blocked/prevented" if blocked else "  ⚠ detection only — NOT confirmed blocked"
                lines.append(f"*Netskope action:* {action}{flag}")
            if nm.get("sha256"):
                lines.append(f"*SHA256:* {nm['sha256']}")
            if nm.get("ambiguous"):
                others = ", ".join([nm.get("user", "")] + (nm.get("other_users") or []))
                lines += ["", f"⚠ Multiple users had malware detections in this window ({others}) — verify this is the right user."]
            lines += [
                "",
                ("Recommendation: Netskope reports this as *blocked/prevented* — confirm remediation and "
                 "that the user did not retrieve the file; likely a false positive if prevention held. Escalating to L2."
                 if blocked else
                 "Recommendation: Netskope *detected* this malicious file but the action does not confirm a block — "
                 "verify whether the download was blocked or the file reached the endpoint (check MDE on the host) and "
                 "validate the SHA256. Escalating to L2."),
                "",
                "[Auto-triaged by RAPTOR]",
            ]
            return PlaybookResult(
                l1_comment="\n".join(lines),
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai", "netskope-malware"],
                auto_close=False,
            )

        # ── Netskope UBA branch (Bulk Upload / Bulk Download) ─────────────
        # Detail bound from Netskope_Alerts_CL by the pipeline (DEMO-107416). The rule
        # aggregates SingleAlert, so one alert covers every matched row — report EVERY
        # user, each with their own host/app/file detail. Reporting only the first
        # account entity is how DEMO-107416 named taylor.singh while L1 investigated
        # toby.vohra, leaving the other user's uploads unexamined on a closed ticket.
        # Netskope failed-login groups. The alert is an AGGREGATE — the rule fires on
        # >2 failures for one (user, app, device, source IP) combination — so the L1
        # comment has to carry the COUNT and the group shape, which is the only thing
        # separating a stale cached credential from credential stuffing. Before this the
        # comment carried Entra sign-in data only: the wrong identity plane entirely.
        fl = ent.get("netskope_failed_login") or {}
        if fl and fl.get("groups"):
            _g = fl["groups"]
            _users = fl.get("users") or []
            _ips = sorted({str(x.get("src_ip")) for x in _g if x.get("src_ip")})
            _apps = sorted({str(x.get("app")) for x in _g if x.get("app")})
            lines = [
                "Hi Team,",
                f"we have received a *Netskope failed-login* alert — "
                f"*{fl.get('total_failures', 0)} failed logins* across "
                f"*{fl.get('group_count', 0)} group(s)*, worst single group "
                f"{fl.get('max_failures', 0)}.",
                "",
                f"*Users:* {', '.join(_users) or 'not resolved'}",
                f"*Apps:* {', '.join(_apps) or 'not resolved'}",
                f"*Source IPs:* {', '.join(_ips) or 'not resolved'}",
                "",
                "*Failure groups:*",
            ]
            for e in _g[:10]:
                lines.append(
                    f"  *{e.get('user') or e.get('from_user') or 'unknown user'}* — "
                    f"{e.get('failure_count')} failures")
                for label, key in (("App", "app"), ("Device", "device_classification"),
                                   ("Hostname", "hostname"), ("OS", "os"),
                                   ("Browser", "browser"), ("Source IP", "src_ip"),
                                   ("Action", "action"), ("Policy", "policy"),
                                   ("Cloud Confidence", "ccl"), ("Site", "page_site")):
                    if e.get(key):
                        lines.append(f"    *{label}:* {e[key]}")
                lines.append("")
            if fl.get("truncated"):
                lines.append("_More failure groups exist than were fetched._")
            # Breadth is what an L2 needs called out, because it is the difference
            # between one person's stale password and a spray across accounts.
            if len(_users) > 1 and len(_ips) == 1:
                lines.append(f"*Note:* {len(_users)} distinct users failing from a single "
                             f"source IP ({_ips[0]}) — check for credential stuffing.")
            elif len(_ips) > 1 and len(_users) == 1:
                lines.append(f"*Note:* one user failing from {len(_ips)} distinct source "
                             f"IPs — check for impossible travel / shared credentials.")
            return PlaybookResult(
                triage_class="NEEDS_L2",
                action="event_analysis",
                auto_close=False,
                l1_comment="\n".join(lines),
            )

        uba = ent.get("netskope_uba") or {}
        if uba and uba.get("by_user"):
            kind      = uba.get("kind", "Upload")
            by_user   = uba["by_user"]
            uba_users = uba.get("users") or list(by_user)
            multi     = len(uba_users) > 1
            lines = [
                "Hi Team,",
                f"we have received a *Netskope bulk-{kind.lower()} anomaly* alert"
                + (f" spanning *{len(uba_users)} users* ({uba.get('event_count', 0)} events)."
                   if multi else f" ({uba.get('event_count', 0)} events)."),
                "",
                f"Netskope's UBA engine flagged an abnormal volume of file {kind.lower()}s. "
                "Each user below is a SEPARATE instance in this one alert and needs its own "
                "business justification — clearing one does not clear the others.",
                "",
            ]
            for u in uba_users:
                b = by_user.get(u) or {}
                lines.append(f"*User:* {u}  —  {b.get('events', 0)} {kind.lower()}(s)")
                if b.get("hosts"):
                    lines.append(f"  *Host:* {', '.join(b['hosts'][:4])}"
                                 + (f" ({b['device']})" if b.get("device") else "")
                                 + (f" — {b['os']}" if b.get("os") else ""))
                if b.get("apps"):
                    lines.append(f"  *App:* {', '.join(b['apps'][:4])}"
                                 + (f"  (CCL {b['ccl']})" if b.get("ccl") else ""))
                # Company or personal account of that app. L2 needs it to judge the
                # activity, and uba_learner reads it back from this line — an approved
                # pattern is only ever learned for an account that was actually shown.
                _inst = [x for x in (b.get("instances") or []) if x] or ["(not recorded)"]
                lines.append(f"  *Account:* {', '.join(_inst[:4])}"
                             + (f" (+{len(_inst) - 4} more)" if len(_inst) > 4 else ""))
                if b.get("pages"):
                    lines.append(f"  *Page:* {', '.join(b['pages'][:3])}")
                if b.get("file_types"):
                    lines.append(f"  *File type:* {', '.join(b['file_types'][:5])}")
                if b.get("total_bytes"):
                    lines.append(f"  *Total size:* {b['total_bytes']:,} bytes")
                if b.get("src_ips"):
                    lines.append(f"  *Source IP:* {', '.join(b['src_ips'][:4])}")
                if b.get("device_classification"):
                    lines.append(f"  *Device classification:* {b['device_classification']}")
                if b.get("useragent"):
                    lines.append(f"  *User agent:* {b['useragent'][:160]}")
                _fs, _ls = b.get("first_seen", ""), b.get("last_seen", "")
                if _fs:
                    lines.append(f"  *Time:* {_fs} UTC" + (f" → {_ls} UTC" if _ls and _ls != _fs else ""))
                lines.append("")
            if uba.get("subject_unverified"):
                # The humans reading this must not take the user list as fact. Without
                # this line the sweep's bystanders are presented exactly like the real
                # subject — which is how DEMO-109433 put eight uninvolved employees into
                # a security ticket's permanent record.
                lines += [
                    f"_*Subject unverified:* these {len(uba_users)} user(s) come from a "
                    "TIME-WINDOW sweep, not from the alert's own matched rows, so some "
                    "may be unrelated activity that merely overlapped the window. "
                    "Confirm the actual subject against the alert before acting._",
                    "",
                ]
            if incident_url:
                lines += [f"*Sentinel Incident:* {incident_url}", ""]
            if is_test_device:
                lines += [self._test_device_note(), ""]
            lines += [
                "As part of the security review process, we request the business justification "
                f"for the observed {kind.lower()} activity"
                + (" from EACH user listed above." if multi else "."),
                "",
                "Escalating to L2 for review.",
                "",
                "[Auto-triaged by RAPTOR]",
            ]
            # ── Deterministic user chase (Phase 1) — Bulk DOWNLOAD, single user only ──
            # EVERY named user on a Bulk Upload or Bulk Download ticket is asked to
            # explain the activity (decided 2026-09-30). This is the workflow, not an
            # optimisation: L1 today closes most of these on "approved apps such as Slack,
            # S3, Cursor", which cannot tell a company workspace from a personal one — and
            # a bulk UPLOAD to a personal instance of an approved app is exactly what
            # exfiltration looks like. So: ask the people, let L2 approve any close
            # (chase_reply_poller routes every answered chase to L2), and only later let
            # L2-approved patterns close on their own (uba_learner).
            #
            # Deterministic, not a model verdict: the model must never be able to reach
            # a Slack DM (see REQUEST_JUSTIFICATION's action="labels_only" contract) —
            # this branch runs whether or not the agent even executes.
            #
            # All users, bounded by EDR_USER_CHASE_MAX_USERS. The multi-address cell was
            # verified against 120 days of bot history: 6 of 7 multi-address cells got a
            # dispatch per address, including both comma-separated ones — the format
            # set_involved_users writes. The one partial case used bare newlines, which
            # this code never produces.
            #
            # Users the bot cannot reach (not in slack-acme, not resolvable) are NOT
            # silently dropped: the reachable ones are chased and the rest are named for
            # L2, who must establish their part before any close (label chase-partial).
            # Amazon S3: the "account" Netskope records is an AWS account id nobody here can
            # prove is Acme's, so an S3 transfer is justified every time and never becomes
            # a standing approval (uba_guard, uba_learner). Said up front so L2 does not
            # close it on "S3 is an approved app", which is how L1 closed 44 of them.
            # The notes below (S3, who cannot be asked, why no chase, who will be asked)
            # go ABOVE the footer: the pipeline inserts its "Previous occurrences" block
            # just before the footer, so a note appended after it ended up stranded below
            # both (DEMO-115194).
            _footer = lines.pop() if lines and lines[-1] == "[Auto-triaged by RAPTOR]" else ""
            from edr_triage.uba_guard import always_justify
            _s3 = always_justify(sorted({a for b in by_user.values() for a in (b.get("apps") or [])}))
            _s3_labels = ["s3-always-justify"] if _s3 else []
            if _s3:
                lines.append("*Amazon S3 — justification required every time:* Netskope cannot "
                             "show whose AWS account a bucket belongs to, so RAPTOR never "
                             "learns or auto-closes S3 activity. L2: confirm the bucket and "
                             "account are Acme's before closing — \"S3 is an approved app\" "
                             "is not enough.")
            _chase_recipients: list = []
            _chase_reason = ""
            _unreachable: list = []
            _max_users = get_edr_config().user_chase_max_users
            # An unverified subject must never be chased. A window-swept bind returns a
            # CANDIDATE set, not the alert's actual actor: on DEMO-109433 the sweep's
            # 10-minute window turned a one-user alert into nine users. DMing somebody
            # because they happened to download a file in the same ten minutes as the
            # real subject is precisely the harm the reachability gate exists to avoid,
            # one step earlier in the chain.
            _bound_to_alert = (uba.get("bind_source") == "alert")
            if _bound_to_alert and 0 < len(uba_users) <= _max_users:
                from edr_triage.identity import eligible_recipients
                _elig, _unreachable = await eligible_recipients(uba_users)
                if _elig:
                    _chase_recipients = _elig
                    _chase_reason = (
                        f"Netskope bulk-{kind.lower()} anomaly — business justification "
                        "requested from every reachable named user (deterministic rule)"
                    )
                if _unreachable:
                    lines.append("*Cannot be asked via Slack — L2 must establish these:* "
                                 + "; ".join(_unreachable))
            elif not _bound_to_alert and uba_users:
                lines.append("*No user chase:* the users above come from a time-window sweep, "
                             "not the alert itself, so they are candidates rather than the "
                             "actual subject.")
            elif len(uba_users) > _max_users:
                lines.append(f"*No user chase:* {len(uba_users)} users exceeds the "
                             f"{_max_users}-user limit for one ticket.")

            if _chase_recipients:
                who = ", ".join(f"{r['display_name']} ({r['email']})" for r in _chase_recipients)
                lines.append(
                    f"*RAPTOR will request business justification from {who} "
                    f"via the Acme Security Bot.*"
                )
                if _footer:
                    lines += ["", _footer]
                return PlaybookResult(
                    l1_comment="\n".join(lines),
                    triage_class="NEEDS_L2",
                    action="user_confirmation",
                    labels=["edr-triage-ai", "netskope-uba", "user-chase-pending"]
                           + (["chase-partial"] if _unreachable else []) + _s3_labels,
                    auto_close=False,
                    chase_recipients=_chase_recipients,
                    chase_reason=_chase_reason,
                )

            if _footer:
                lines += ["", _footer]
            return PlaybookResult(
                l1_comment="\n".join(lines),
                triage_class="NEEDS_L2",
                action="labels_only",
                labels=["needs-l2-review", "edr-triage-ai", "netskope-uba"]
                       + (["multi-user"] if multi else []) + _s3_labels,
                auto_close=False,
            )

        # Sentinel enrichment first, then fall back to parsing the alert description.
        accounts   = ent.get("accounts", []) or ([_field(desc, r"(?:Involved )?Users?")] if _field(desc, r"(?:Involved )?Users?") else [])
        category   = _field(desc, r"Category")
        app        = ent.get("app_display_name", "") or _field(desc, r"App")
        url        = (ent.get("urls") or [""])[0] or _field(desc, r"Url")
        hostname   = (ent.get("hosts") or [""])[0] or _field(desc, r"Hostname")
        source_ip  = (ent.get("ips") or [""])[0] or _field(desc, r"Source\s+IP")
        user_agent = ent.get("browser", "") or _field(desc, r"User\s+Agent")
        start_time = ent.get("start_time", "")
        end_time   = ent.get("end_time", "")

        accounts = [a for a in accounts if a]
        multi_user = len(accounts) > 1

        lines = [
            "Hi team,",
            f'we have received a Netskope web-access alert *"{alert_name}"*'
            + (f" involving *{len(accounts)} users*." if multi_user else "."),
            "",
            "Netskope blocked/failed this web request under its web-filtering policy. "
            "This is a *web-proxy policy event* (e.g. a blocked category or application), "
            "not an Azure AD credential/password attack.",
            "",
        ]

        if accounts:
            lines.append(f"*Affected Users ({len(accounts)}):*")
            for a in accounts:
                lines.append(f"  - {a}")
        if category:
            lines.append(f"*Category:* {category}")
        if app:
            lines.append(f"*App:* {app}")
        if url:
            lines.append(f"*URL:* {url}")
        if hostname:
            lines.append(f"*Hostname:* {hostname}")
        if source_ip:
            lines.append(f"*Source IP:* {source_ip}")
        if user_agent:
            lines.append(f"*User Agent:* {user_agent}")
        if start_time:
            lines.append(f"*StartTime:* {start_time}")
        if end_time:
            lines.append(f"*EndTime:* {end_time}")
        if incident_url:
            lines += ["", f"*Sentinel Incident:* {incident_url}"]

        if not any([category, app, url, hostname, source_ip, user_agent]):
            lines += [
                "",
                "_Note: Netskope event details (hostname, source IP, app, URL, user agent) "
                "were not available from the Sentinel API — open the Sentinel incident for the "
                "per-user web-access records._",
            ]

        if is_test_device:
            lines += ["", self._test_device_note()]

        lines += [
            "",
            "Recommendation: confirm whether this web access is expected for the user's role. "
            "If unexpected or policy-relevant, investigate for data exfiltration / misuse; "
            "otherwise this is likely a benign web-filtering block.",
            "",
            "Escalating to L2 for review.",
            "",
            "[Auto-triaged by RAPTOR]",
        ]

        return PlaybookResult(
            l1_comment="\n".join(lines),
            triage_class="NEEDS_L2",
            action="labels_only",
            labels=["needs-l2-review", "edr-triage-ai", "netskope-web"],
            auto_close=False,
        )
