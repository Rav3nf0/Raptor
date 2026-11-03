"""The incident story page and its report (PDF) — server-rendered HTML for /shadow stories.

  render_story_page    /shadow/stories/{id}: one page with everything about the incident —
                       the written report's summary, a merged timeline (findings, Jira alerts,
                       edge requests, other logs), systems, every alert and detection, the
                       VictoriaLogs context, indicators and why the findings were grouped.
  render_story_report  /shadow/stories/{id}/print: the written report in the layout of the
                       ATLAS v5 report, followed by sections built from the story itself;
                       light, A4, the browser's Save as PDF makes the file.

Everything shown passes through stories.clean() and is HTML-escaped; report bodies are a
small Markdown subset rendered after escaping (no raw HTML, http(s) links only).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from html import escape

IST = timezone(timedelta(hours=5, minutes=30))
JIRA_BROWSE = "https://jira.example.com/browse/"
KIND_LABEL = {"finding": "Detection", "alert": "Jira alert", "edge": "Edge", "logs": "Logs"}


def e(v) -> str:
    return escape("" if v is None else str(v))


def ist(ts, with_date: bool = True) -> str:
    """'19 Oct 07:16' in IST from an ISO string or datetime ('' when unparseable)."""
    from shadow_hunter.stories import _parse
    d = _parse(ts)
    if not d:
        return ""
    d = d.astimezone(IST)
    return d.strftime("%d %b %H:%M") if with_date else d.strftime("%H:%M")


def _day(ts) -> str:
    from shadow_hunter.stories import _parse
    d = _parse(ts)
    return d.astimezone(IST).strftime("%a %d %b %Y") if d else ""


# ── Markdown subset ────────────────────────────────────────────────────────────

_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^\s)]+)\)")
_SEP = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
_UL = re.compile(r"^\s*[-*]\s+(.*)$")
_OL = re.compile(r"^\s*\d+[.)]\s+(.*)$")
_H = re.compile(r"^(#{1,4})\s+(.*)$")


def inline(text: str) -> str:
    s = escape(text)
    codes: list[str] = []

    def keep(m):
        codes.append(f"<code>{m.group(1)}</code>")
        return f"\x00{len(codes) - 1}\x00"
    s = _CODE.sub(keep, s)
    s = _BOLD.sub(r"<b>\1</b>", s)
    s = _LINK.sub(lambda m: f'<a href="{m.group(2)}" target="_blank" rel="noopener">{m.group(1)}</a>', s)
    return re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], s)


def _cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def md(text: str) -> str:
    """Paragraphs, #-headings (shown as h3/h4), '- ' and '1. ' lists, pipe tables, **bold**,
    `code`, [links](https://...). Input is escaped first; nothing else is interpreted."""
    lines = (text or "").replace("\r\n", "\n").split("\n")
    out: list[str] = []
    para: list[str] = []
    lst: tuple[str, list[str]] | None = None

    def flush():
        nonlocal para, lst
        if para:
            out.append("<p>" + "<br>".join(inline(p) for p in para) + "</p>")
            para = []
        if lst:
            tag, items = lst
            out.append(f"<{tag}>" + "".join(f"<li>{inline(i)}</li>" for i in items) + f"</{tag}>")
            lst = None

    i = 0
    while i < len(lines):
        ln = lines[i]
        if not ln.strip():
            flush()
        elif "|" in ln and i + 1 < len(lines) and _SEP.match(lines[i + 1]):
            flush()
            head = _cells(ln)
            rows = []
            i += 2
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                rows.append(_cells(lines[i]))
                i += 1
            out.append('<div class="tw"><table><thead><tr>' + "".join(f"<th>{inline(h)}</th>" for h in head)
                       + "</tr></thead><tbody>"
                       + "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in rows)
                       + "</tbody></table></div>")
            continue
        elif _H.match(ln):
            flush()
            m = _H.match(ln)
            lvl = "h3" if len(m.group(1)) <= 2 else "h4"
            out.append(f"<{lvl}>{inline(m.group(2))}</{lvl}>")
        elif _UL.match(ln) or _OL.match(ln):
            tag = "ul" if _UL.match(ln) else "ol"
            item = (_UL.match(ln) or _OL.match(ln)).group(1)
            if para:
                out.append("<p>" + "<br>".join(inline(p) for p in para) + "</p>")
                para = []
            if lst and lst[0] != tag and not ln.startswith((" ", "\t")):
                flush()
            if lst:
                lst[1].append(item)
            else:
                lst = (tag, [item])
        elif lst and ln.startswith((" ", "\t")):
            lst[1][-1] += " " + ln.strip()
        else:
            if lst:
                flush()
            para.append(ln.strip())
        i += 1
    flush()
    return "".join(out)


# ── shared pieces ──────────────────────────────────────────────────────────────

def _jira(key: str) -> str:
    k = e(key)
    return f'<a href="{JIRA_BROWSE}{k}" target="_blank" rel="noopener">{k}</a>' if key else "—"


def _alerts_table(alerts: list[dict]) -> str:
    if not alerts:
        return '<p class="muted">No RAPTOR / Jira alerts on these hosts or accounts in the story window (±48 h).</p>'
    rows = "".join(
        f"<tr><td class='mono'>{_jira(a.get('jira_key', ''))}</td><td class='mono'>{e(ist(a.get('created_at')))}</td>"
        f"<td>{e(a.get('alert_name'))}</td><td>{e(a.get('device_name') or '—')}</td><td>{e(a.get('user_name') or '—')}</td>"
        f"<td>{e(a.get('ai_triage_class') or '—')}</td>"
        f"<td>{e(' / '.join(x for x in (a.get('l1_triage_class'), a.get('l2_triage_class')) if x) or '—')}</td>"
        f"<td class='muted'>{e(a.get('matched_on'))}</td></tr>" for a in alerts)
    return ('<div class="tw"><table><thead><tr><th>Ticket</th><th>Created (IST)</th><th>Alert</th><th>Host</th><th>User</th>'
            '<th>RAPTOR</th><th>L1 / L2</th><th>Matched on</th></tr></thead><tbody>' + rows + "</tbody></table></div>")


def _vl_meta(res: dict) -> str:
    bits = [f"{ist(res.get('window', ['', ''])[0])} → {ist(res.get('window', ['', ''])[1])} IST",
            f"chunks {res.get('chunks', '')}"]
    if res.get("note"):
        bits.append(res["note"])
    err = "".join(f"<div class='err'>{e(x)}</div>" for x in res.get("errors", []))
    return f"<div class='muted small'>{e(' · '.join(bits))}</div>{err}"


def _vlogs_html(vl: dict) -> str:
    from shadow_hunter.clients.victorialogs import as_int, as_list
    parts = []
    for ip, res in (vl.get("edge") or {}).items():
        rows = res.get("rows") or []
        body = ("".join(
            f"<tr><td>{e(r.get('ClientRequestHost'))}</td><td>{e(r.get('ClientRequestMethod'))}</td>"
            f"<td class='num'>{e(r.get('EdgeResponseStatus'))} / {e(r.get('OriginResponseStatus'))}</td>"
            f"<td class='num'>{as_int(r.get('n')):,}</td><td class='num'>{as_int(r.get('attack_paths')):,}</td>"
            f"<td class='mono small'>{e(', '.join(str(p) for p in as_list(r.get('sample_paths'))[:3]))}</td>"
            f"<td class='mono'>{e(ist(r.get('first')))} → {e(ist(r.get('last')))}</td></tr>" for r in rows[:25])
            or "<tr><td colspan=7 class='muted'>No requests at the edge in this window.</td></tr>")
        from shadow_hunter.story_context import SKIP_TERMS
        shared = (" <span class='muted small'>(shared corporate NAT: counts include all staff traffic)</span>"
                  if ip in SKIP_TERMS else "")
        parts.append(f"<h3>Edge (Cloudflare) · <span class='mono'>{e(ip)}</span>{shared}</h3>{_vl_meta(res)}"
                     "<div class='tw'><table><thead><tr><th>Host</th><th>Method</th><th>Edge / origin</th><th>Requests</th>"
                     f"<th>Attack-shaped</th><th>Sample paths</th><th>First → last (IST)</th></tr></thead><tbody>{body}</tbody></table></div>")
    for user, res in (vl.get("eks") or {}).items():
        rows = res.get("rows") or []
        body = ("".join(
            f"<tr><td>{e(r.get('verb'))}</td><td>{e(r.get('objectRef.resource'))}"
            f"{('/' + e(r.get('objectRef.subresource'))) if r.get('objectRef.subresource') else ''}</td>"
            f"<td class='num'>{e(r.get('responseStatus.code'))}</td><td class='num'>{as_int(r.get('n')):,}</td>"
            f"<td>{e(', '.join(str(x) for x in as_list(r.get('namespaces'))[:3]))}</td>"
            f"<td class='mono'>{e(ist(r.get('first')))} → {e(ist(r.get('last')))}</td></tr>" for r in rows[:25])
            or "<tr><td colspan=6 class='muted'>No EKS API activity in this window.</td></tr>")
        parts.append(f"<h3>EKS prod API · {e(user)}</h3>{_vl_meta(res)}"
                     "<div class='tw'><table><thead><tr><th>Verb</th><th>Resource</th><th>HTTP</th><th>Count</th>"
                     f"<th>Namespaces</th><th>First → last (IST)</th></tr></thead><tbody>{body}</tbody></table></div>")
    for ip, res in (vl.get("rds") or {}).items():
        rows = res.get("rows") or []
        body = ("".join(
            f"<tr><td>{e(r.get('log_group'))}</td><td>{e(r.get('dbuser'))}</td><td>{e(r.get('op'))}</td>"
            f"<td class='num'>{as_int(r.get('n')):,}</td><td class='mono small'>{e('; '.join(as_list(r.get('sample'))[:2]))}</td>"
            f"<td class='mono'>{e(ist(r.get('first')))} → {e(ist(r.get('last')))}</td></tr>" for r in rows[:25])
            or "<tr><td colspan=6 class='muted'>No database connections or statements from this host.</td></tr>")
        parts.append(f"<h3>Aurora audit (RDS) · client <span class='mono'>{e(ip)}</span></h3>{_vl_meta(res)}"
                     "<div class='tw'><table><thead><tr><th>Cluster log</th><th>DB user</th><th>Operation</th><th>Count</th>"
                     f"<th>Sample</th><th>First → last (IST)</th></tr></thead><tbody>{body}</tbody></table></div>")
    for term, res in (vl.get("mentions") or {}).items():
        rows = res.get("rows") or []
        body = ("".join(
            f"<tr><td>{e(r.get('source_type'))}</td><td>{e(r.get('kubernetes.namespace_name') or r.get('log_group') or '—')}</td>"
            f"<td class='num'>{as_int(r.get('n')):,}</td>"
            f"<td class='mono'>{e(ist(r.get('first')))} → {e(ist(r.get('last')))}</td></tr>" for r in rows[:20])
            or "<tr><td colspan=4 class='muted'>Not found in other logs in this window.</td></tr>")
        parts.append(f"<h3>Other logs mentioning <span class='mono'>{e(term)}</span></h3>{_vl_meta(res)}"
                     "<div class='tw'><table><thead><tr><th>Source</th><th>Namespace / log group</th><th>Lines</th>"
                     f"<th>First → last (IST)</th></tr></thead><tbody>{body}</tbody></table></div>")
    return "".join(parts)


def _iocs_table(rows: list[dict]) -> str:
    if not rows:
        return '<p class="muted">—</p>'
    return ('<div class="tw"><table><thead><tr><th>Indicator</th><th>Type</th><th>Note</th></tr></thead><tbody>'
            + "".join(f"<tr><td class='mono'>{e(r['value'])}</td><td>{e(r['type'])}</td><td>{e(r.get('note', ''))}</td></tr>"
                      for r in rows) + "</tbody></table></div>")


def _edges_list(edges: list[dict]) -> str:
    return "<ul>" + ("".join(f"<li><b>{e(x.get('kind'))}</b>: {e(x.get('reason'))}</li>" for x in edges[:80])
                     or "<li>—</li>") + "</ul>"


def _sources(st, ctx: dict) -> str:
    from shadow_hunter.stories import DET_LABEL
    dets = sorted({t.get("source", "") for t in st.timeline or [] if t.get("source")})
    vl = ctx.get("vlogs") or {}
    items = [f"<b>/shadow detections:</b> {e(', '.join(DET_LABEL.get(d, d) for d in dets) or '—')}",
             f"<b>RAPTOR / Jira alerts:</b> {len(ctx.get('alerts', []))} on the story's hosts and accounts (±48 h)"]
    if vl:
        items.append("<b>VictoriaLogs:</b> "
                     + e(", ".join(f"{k} {len(v)}" for k, v in vl.items() if v) or "queried, nothing found")
                     + (f" (snapshot {e(ist(ctx.get('fetched_at')))} IST)" if ctx.get("fetched_at") else ""))
    else:
        items.append("<b>VictoriaLogs:</b> not fetched yet")
    items.append("<b>Handling:</b> secrets are redacted (long ones keep their last 4 characters) and 12-digit IDs are masked.")
    return "<ul>" + "".join(f"<li>{x}</li>" for x in items) + "</ul>"


# ── the story page ─────────────────────────────────────────────────────────────

_DARK = """
  :root { --ink:#081113; --panel:#0D191C; --panel-2:#112226; --panel-3:#172D32; --rule:#1D3439; --rule-soft:#14262A;
          --fg:#D3E2E0; --fg-bright:#EEF7F5; --fg-dim:#86A19E; --fg-faint:#52706C; --accent:#45D3C2; --accent-deep:#1C6F66;
          --crit:#FF5A5F; --high:#FF8B3D; --med:#E9C54A; --low:#6AA6C8; --ok:#5BC98A;
          --sans:"IBM Plex Sans",-apple-system,"Segoe UI",system-ui,sans-serif; --mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace; }
  * { box-sizing:border-box; } html,body { margin:0; }
  body { background:var(--ink); color:var(--fg); font:15px/1.6 var(--sans); -webkit-font-smoothing:antialiased; }
  a { color:var(--accent); } .mono,code { font-family:var(--mono); font-size:.92em; } .num { font-family:var(--mono); font-variant-numeric:tabular-nums; }
  code { background:var(--panel-3); padding:1px 5px; border-radius:4px; color:var(--fg-bright); }
  .top { position:sticky; top:0; z-index:5; background:rgba(8,17,19,.88); backdrop-filter:blur(10px); border-bottom:1px solid var(--rule-soft); }
  .top .in { max-width:1080px; margin:0 auto; padding:0 16px; height:54px; display:flex; align-items:center; gap:14px; }
  .top a.back { color:var(--fg-dim); text-decoration:none; font-size:13px; } .top .sp { flex:1; }
  .btn { border:1px solid var(--rule); background:var(--panel-2); color:var(--fg); padding:6px 12px; border-radius:8px; font:500 13px var(--sans); cursor:pointer; text-decoration:none; white-space:nowrap; }
  .btn:hover { border-color:var(--accent-deep); color:var(--fg-bright); } .btn.primary { background:var(--accent); border-color:var(--accent); color:#042421; font-weight:600; }
  main { max-width:1080px; margin:0 auto; padding:28px 16px 80px; }
  .kicker { font:500 12px var(--mono); letter-spacing:.12em; text-transform:uppercase; color:var(--fg-faint); }
  h1 { font-size:28px; line-height:1.25; color:var(--fg-bright); margin:8px 0 10px; }
  h2 { font-size:19px; color:var(--fg-bright); margin:40px 0 12px; padding-top:18px; border-top:1px solid var(--rule-soft); }
  h3 { font-size:15px; color:var(--fg-bright); margin:22px 0 6px; } h4 { font-size:14px; margin:16px 0 4px; }
  .muted { color:var(--fg-dim); } .small { font-size:12px; } .err { color:var(--high); font-size:12px; }
  .sev { display:inline-block; font:600 11px var(--mono); text-transform:uppercase; letter-spacing:.08em; padding:2px 8px; border-radius:999px; border:1px solid; }
  .s-critical { color:var(--crit); } .s-high { color:var(--high); } .s-medium { color:var(--med); } .s-low { color:var(--low); }
  .glance { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:1px; background:var(--rule-soft);
            border:1px solid var(--rule-soft); border-radius:12px; overflow:hidden; margin:20px 0 6px; }
  .glance div { background:var(--panel); padding:12px 14px; } .glance label { display:block; font-size:11px; letter-spacing:.08em; text-transform:uppercase; color:var(--fg-faint); }
  .glance b { font:600 22px var(--mono); color:var(--fg-bright); }
  .lead { font-size:16px; background:var(--panel); border:1px solid var(--rule-soft); border-left:3px solid var(--accent); border-radius:10px; padding:14px 18px; margin:22px 0; }
  .lead p { margin:0 0 8px; } .lead p:last-child { margin:0; }
  .actions { display:flex; flex-wrap:wrap; gap:8px; margin:14px 0 0; }
  .tw { overflow-x:auto; margin:8px 0; border:1px solid var(--rule-soft); border-radius:10px; }
  table { width:100%; border-collapse:collapse; font-size:13px; } th,td { padding:7px 10px; text-align:left; vertical-align:top; border-bottom:1px solid var(--rule-soft); }
  th { background:var(--panel-2); color:var(--fg-dim); font-weight:500; font-size:12px; white-space:nowrap; } tr:last-child td { border-bottom:0; }
  .day { font:600 12px var(--mono); color:var(--fg-faint); letter-spacing:.06em; text-transform:uppercase; margin:20px 0 6px; }
  .tl { list-style:none; margin:0; padding:0 0 0 18px; border-left:2px solid var(--rule); }
  .tl li { position:relative; padding:6px 0 10px 10px; } .tl li::before { content:""; position:absolute; left:-25px; top:13px; width:10px; height:10px; border-radius:50%; background:var(--fg-faint); border:2px solid var(--ink); }
  .tl li.k-alert::before { background:var(--high); } .tl li.k-edge::before { background:var(--low); } .tl li.k-logs::before { background:var(--med); } .tl li.k-finding::before { background:var(--accent); }
  .tl .t { font:500 12px var(--mono); color:var(--fg-dim); margin-right:8px; } .tag { font:500 11px var(--mono); color:var(--fg-dim); border:1px solid var(--rule); border-radius:5px; padding:0 6px; margin-right:6px; }
  .tl .ev { color:var(--fg); } .tl .who { color:var(--fg-faint); font-size:12px; }
  details summary { cursor:pointer; color:var(--fg-dim); } .report-sec { margin-top:6px; }
  .addind { display:flex; flex-wrap:wrap; gap:8px; margin:8px 0 10px; }
  .addind input { background:var(--panel); color:var(--fg); border:1px solid var(--rule); border-radius:8px; padding:6px 10px; font:13px var(--sans); min-width:0; flex:1 1 180px; }
  .chipx { display:inline-flex; gap:6px; align-items:center; border:1px solid var(--accent-deep); border-radius:999px; padding:2px 4px 2px 10px; margin:0 6px 6px 0; font:12px var(--mono); }
  .chipx button { background:none; border:0; color:var(--fg-dim); cursor:pointer; font-size:14px; }
  .toast { position:fixed; bottom:18px; left:50%; transform:translateX(-50%); background:var(--panel-3); border:1px solid var(--rule); padding:10px 16px; border-radius:10px; display:none; max-width:92vw; }
  textarea.prompt { width:100%; min-height:150px; background:var(--panel); color:var(--fg); border:1px solid var(--rule); border-radius:8px; font:12px/1.5 var(--mono); padding:10px; }
  @media (max-width:640px) { h1 { font-size:22px; } main { padding-top:18px; } }
"""


def render_story_page(st, findings: list) -> str:
    from shadow_hunter.stories import DET_LABEL, clean
    from shadow_hunter.story_context import iocs, merged_timeline
    ctx = clean(st.context or {})
    rep = clean(st.report or {})
    ent = clean(st.entities or {})
    alerts = ctx.get("alerts", [])
    tl = clean(merged_timeline(st))
    sid = e(st.id)

    lead = ""
    secs = rep.get("sections") or []
    if secs:
        lead = (f"<div class='lead'>{md(secs[0].get('body', ''))}<div class='muted small'>From report v{e(rep.get('version'))} "
                f"by {e(rep.get('by'))}, {e(ist(rep.get('at')))} IST</div></div>")
    else:
        lead = ("<div class='lead muted'>No written report yet. <b>Get report</b> below queues it for a Claude pass, which reads "
                "everything on this page and writes it in the incident-report format.</div>")
    req = ""
    if st.report_requested_at:
        req = (f"<span class='muted small'>Report requested {e(ist(st.report_requested_at))} IST by "
               f"{e(st.report_requested_by)}; waiting for the Claude pass.</span>")

    days, cur = [], None
    for t in tl:
        d = _day(t["ts"])
        if d != cur:
            if cur is not None:
                days.append("</ul>")
            days.append(f"<div class='day'>{e(d)}</div><ul class='tl'>")
            cur = d
        who = e(t.get("host", ""))
        ref = (f" · {_jira(t['ref'])}" if t["kind"] == "alert" else "")
        src = "" if t["kind"] == "alert" or t.get("source") == "logs" else DET_LABEL.get(t.get("source", ""), t.get("source", ""))
        days.append(f"<li class='k-{e(t['kind'])}'><span class='t'>{e(ist(t['ts'], False))}</span>"
                    f"<span class='tag'>{e(KIND_LABEL.get(t['kind'], t['kind']))}{(' · ' + e(src)) if src else ''}</span>"
                    + (f"<span class='sev s-{e(t['severity'])}'>{e(t['severity'])}</span> " if t.get("severity") else "")
                    + f"<span class='ev'>{e(t.get('event', ''))}</span>{ref}<div class='who'>{who}</div></li>")
    if cur is not None:
        days.append("</ul>")

    hosts = "".join(f"<tr><td class='mono'>{e(h.get('name'))}</td><td class='mono'>{e(', '.join(h.get('ips', [])) or '—')}</td>"
                    f"<td>{e(', '.join(a for a in h.get('aliases', []) if a != h.get('name')) or '—')}</td></tr>"
                    for h in ent.get("hosts", []))
    accts = ", ".join(e(a) for a in ent.get("accounts", [])) or "—"
    fs = sorted(findings, key=lambda f: str((f.raw or {}).get("FirstSeen") or (f.raw or {}).get("first_seen") or f.created_at))
    frows = "".join(
        f"<tr><td><span class='sev s-{e(f.severity)}'>{e(f.severity)}</span></td><td>{e(DET_LABEL.get(f.detector, f.detector))}</td>"
        f"<td class='mono'>{e(f.device_name or '—')}</td><td>{e(clean(f.summary or f.indicator or '')[:300])}</td>"
        f"<td>{e(f.decision or ('AI: ' + f.ai_verdict if getattr(f, 'ai_verdict', '') else 'open'))}</td>"
        f"<td><a href='/shadow?finding={e(f.id)}'>open</a></td></tr>" for f in fs)
    vl = ctx.get("vlogs") or {}
    vl_html = _vlogs_html(vl) if vl else "<p class='muted'>Not fetched yet. It refreshes every 30 minutes, or use <b>Refresh context</b>.</p>"
    n_ips = len({ip for h in ent.get("hosts", []) for ip in h.get("ips", [])})
    report_body = "".join(f"<h3>{e(s.get('heading'))}</h3><div class='report-sec'>{md(s.get('body', ''))}</div>" for s in secs)

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident story</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_DARK}</style></head><body>
<div class="top"><div class="in"><a class="back" href="/shadow?view=stories">← Stories</a><span class="sp"></span>
<a class="btn" href="/shadow/stories/{sid}/print" target="_blank" rel="noopener">Report PDF</a></div></div>
<main>
<div class="kicker">Incident story · {e(st.status)}</div>
<h1>{e(clean(st.title))}</h1>
<div><span class="sev s-{e(st.severity)}">{e(st.severity)}</span>
<span class="muted"> {e(ist(st.first_seen))} → {e(ist(st.last_seen))} IST · updated {e(ist(st.updated_at))} IST</span></div>
<div class="glance">
<div><label>Detections</label><b>{len(st.finding_ids)}</b></div>
<div><label>Jira alerts</label><b>{len(alerts)}</b></div>
<div><label>Hosts</label><b>{len(ent.get('hosts', []))}</b></div>
<div><label>Accounts</label><b>{len(ent.get('accounts', []))}</b></div>
<div><label>Host IPs</label><b>{n_ips}</b></div>
<div><label>Timeline events</label><b>{len(tl)}</b></div>
</div>
{lead}
<div class="actions">
<button class="btn primary" data-act="report">Get report</button>
<a class="btn" href="/shadow/stories/{sid}/print" target="_blank" rel="noopener">Report PDF</a>
<button class="btn" data-act="context">Refresh context</button>
{('<button class="btn" data-act="close">Close story</button>' if st.status == 'open' else '<button class="btn" data-act="reopen">Reopen</button>' if st.status == 'closed' else '')}
{req}
</div>
<div id="prompt-box" hidden><p class="muted small">The in-app report writer is off (SHADOW_LLM=claude and SHADOW_STORY_REPORTS=1 turn it on). The story is queued; paste this into Claude Code to write it now:</p><textarea class="prompt" id="prompt" readonly></textarea></div>

<h2>What happened</h2>
<p class="muted small">Detections, Jira alerts, first and last edge requests, and first appearances in other logs, in IST.</p>
{''.join(days) or '<p class="muted">—</p>'}

<h2>Systems and accounts</h2>
<div class="tw"><table><thead><tr><th>Host</th><th>IP addresses</th><th>Other names</th></tr></thead><tbody>{hosts or '<tr><td colspan=3>—</td></tr>'}</tbody></table></div>
<p><b>Accounts:</b> {accts}</p>

<h2>Detections in /shadow ({len(fs)})</h2>
<div class="tw"><table><thead><tr><th>Severity</th><th>Detector</th><th>Host</th><th>What</th><th>Decision</th><th></th></tr></thead><tbody>{frows or '<tr><td colspan=6>—</td></tr>'}</tbody></table></div>

<h2>RAPTOR / Jira alerts ({len(alerts)})</h2>
{_alerts_table(alerts)}
{('<p class="err">' + e(ctx['alerts_error']) + '</p>') if ctx.get('alerts_error') else ''}

<h2>Edge, Kubernetes, database and other logs</h2>
<p class="muted small">From VictoriaLogs, snapshotted onto the story so it outlives log retention{(' · snapshot ' + e(ist(ctx.get('fetched_at'))) + ' IST') if ctx.get('fetched_at') else ''}.</p>
{vl_html}

<h2>Indicators</h2>
<p class="muted small">Add what the detections do not carry (an attacker IP from web-server logs, a file stem). The edge
and other logs are searched for it on the next refresh, which starts right away.</p>
<form class="addind" id="add-ind"><input name="value" placeholder="198.51.100.23 or zzab12cd" required maxlength="100">
<input name="note" placeholder="where it came from (optional)" maxlength="200"><button class="btn" type="submit">Add indicator</button></form>
{_added(st)}
{_iocs_table(clean(iocs(st, findings)))}

<h2>Written report</h2>
{report_body or '<p class="muted">None yet.</p>'}

<h2>Why these are grouped</h2>
<details><summary>{len(st.edges or [])} links between findings</summary>{_edges_list(clean(st.edges or []))}</details>
<p class="muted small">A story only groups and adds context. Confirm or dismiss each detection in the queue.</p>
</main>
<div class="toast" id="toast"></div>
<script>
(function () {{
  var id = {_js(st.id)};
  function toast(m) {{ var t = document.getElementById('toast'); t.textContent = m; t.style.display = 'block'; setTimeout(function () {{ t.style.display = 'none'; }}, 4000); }}
  function post(url, body) {{
    return fetch(url, {{ method: 'POST', credentials: 'same-origin', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify(body || {{}}) }})
      .then(function (r) {{ if (!r.ok) throw new Error(r.status); return r.json(); }});
  }}
  var base0 = '/api/shadow/stories/' + encodeURIComponent(id);
  document.getElementById('add-ind').addEventListener('submit', function (ev) {{
    ev.preventDefault();
    var f = ev.target;
    post(base0 + '/indicators', {{ value: f.value.value, note: f.note.value, actor: 'analyst' }})
      .then(function () {{ return post(base0 + '/context/refresh'); }})
      .then(function () {{ toast('Added — looking it up now; reload in a few minutes'); setTimeout(function () {{ location.reload(); }}, 1500); }})
      .catch(function () {{ toast('Not added: use a public IPv4 or a single token'); }});
  }});
  document.addEventListener('click', function (ev) {{
    var r = ev.target.closest('[data-rm]'); if (!r) return;
    if (!confirm('Remove ' + r.getAttribute('data-rm') + ' from this story?')) return;
    post(base0 + '/indicators/remove', {{ value: r.getAttribute('data-rm'), actor: 'analyst' }}).then(function () {{ location.reload(); }});
  }});
  document.querySelector('.actions').addEventListener('click', function (ev) {{
    var b = ev.target.closest('[data-act]'); if (!b) return;
    var a = b.getAttribute('data-act'), base = '/api/shadow/stories/' + encodeURIComponent(id);
    b.disabled = true;
    var p = a === 'report' ? post(base + '/report/request', {{ actor: 'analyst' }}).then(function (d) {{
              if (d.written) {{ location.reload(); return; }}
              if (d.writing) {{ toast('Claude is writing the report — reload in 2-4 minutes'); return; }}
              document.getElementById('prompt').value = d.prompt || ''; document.getElementById('prompt-box').hidden = false;
              toast('Report requested — queued for the Claude pass'); }})
          : a === 'context' ? post(base + '/context/refresh').then(function () {{ toast('Refreshing context — reload in a few minutes'); }})
          : post(base + '/' + a, {{ actor: 'analyst' }}).then(function () {{ location.reload(); }});
    p.catch(function () {{ toast('That did not work — check the session and try again'); }}).then(function () {{ b.disabled = false; }});
  }});
}})();
</script>
</body></html>"""


def _added(st) -> str:
    from shadow_hunter.stories import clean
    items = clean(st.indicators or [])
    if not items:
        return ""
    return "<div>" + "".join(f"<span class='chipx' title='{e(i.get('note', ''))}'>{e(i['value'])}"
                             f"<button type='button' data-rm='{e(i['value'])}' aria-label='Remove'>×</button></span>"
                             for i in items) + "</div>"


def _js(v: str) -> str:
    import json
    return json.dumps(str(v)).replace("<", "\\u003c")


# ── the report (print / PDF) ───────────────────────────────────────────────────

_LIGHT = """
  :root { --ink:#1b1f24; --muted:#57606a; --line:#d0d7de; --head:#f3f4f6; --accent:#0f766e; }
  body { font:13px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif; color:var(--ink); background:#fff; max-width:900px; margin:24px auto; padding:0 16px; }
  h1 { font-size:24px; margin:0 0 6px; line-height:1.25; } h2 { font-size:17px; margin:26px 0 8px; } h3 { font-size:14px; margin:16px 0 6px; } h4 { font-size:13px; margin:12px 0 4px; }
  .muted { color:var(--muted); } .small { font-size:11px; } .err { color:#b42318; font-size:11px; }
  .mono,code { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11.5px; } code { background:#f3f4f6; padding:0 4px; border-radius:3px; }
  .tw { overflow-x:auto; } table { width:100%; border-collapse:collapse; margin:6px 0 8px; }
  th,td { border:1px solid var(--line); padding:4px 6px; text-align:left; vertical-align:top; font-size:11.5px; } th { background:var(--head); }
  ul,ol { padding-left:20px; } li { margin:3px 0; } p { margin:6px 0; } a { color:var(--accent); }
  .byline { color:var(--muted); margin-bottom:14px; } .sev { text-transform:uppercase; font-weight:600; font-size:11px; }
  .bar { display:flex; gap:8px; margin:10px 0 18px; } .bar button,.bar a { font:inherit; padding:4px 10px; }
  .appx { border-top:2px solid var(--line); margin-top:28px; } .notice { border:1px solid var(--line); background:#fffbea; padding:8px 12px; border-radius:6px; }
  .conf { font-size:10.5px; color:var(--muted); border-top:1px solid var(--line); margin-top:28px; padding-top:6px; }
  @media print { .bar { display:none; } body { margin:0; max-width:none; } @page { size:A4; margin:14mm; } h2 { break-after:avoid; } tr { break-inside:avoid; } }
"""


def render_story_report(st, findings: list) -> str:
    from shadow_hunter.stories import clean
    from shadow_hunter.story_context import iocs, merged_timeline
    ctx = clean(st.context or {})
    rep = clean(st.report or {})
    secs = rep.get("sections") or []
    title = clean(st.title)
    version = rep.get("version")
    body = "".join(f"<h2>{e(s.get('heading'))}</h2>{md(s.get('body', ''))}" for s in secs)
    if not body:
        body = ("<p class='notice'>No written report yet. Use <b>Get report</b> on the story page; a Claude pass writes "
                "the summary, impact, attack path, verification, containment and open questions. The sections below "
                "come from the story itself.</p>")
    tl = clean(merged_timeline(st))
    tl_rows = "".join(f"<tr><td class='mono'>{e(ist(t['ts']))}</td><td>{e(KIND_LABEL.get(t['kind'], t['kind']))}</td>"
                      f"<td>{e(t.get('host', ''))}</td><td>{e(t.get('event', ''))}</td></tr>" for t in tl)
    vl = ctx.get("vlogs") or {}
    byline = " · ".join(x for x in [
        datetime.now(IST).strftime("%d %b %Y"),
        f"report v{version} by {rep.get('by')}" if secs else "no written report yet",
        f"severity <span class='sev'>{e(st.severity)}</span>",
        f"{e(ist(st.first_seen))} → {e(ist(st.last_seen))} IST",
        (f"supersedes v{version - 1}" if isinstance(version, int) and version > 1 else ""),
    ] if x)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident report</title><style>{_LIGHT}</style></head><body>
<div class="bar"><button onclick="window.print()">Save as PDF</button><a href="/shadow/stories/{e(st.id)}">Back to the story</a></div>
<h1>{e(title)} — Incident Report{(' v' + e(version)) if version else ''}</h1>
<div class="byline">{byline}</div>
{body}
<div class="appx">
<h2>Indicators of compromise</h2>
{_iocs_table(clean(iocs(st, findings)))}
<h2>Related RAPTOR / Jira alerts</h2>
{_alerts_table(ctx.get('alerts', []))}
<h2>Edge, Kubernetes, database and other logs</h2>
{_vlogs_html(vl) if vl else "<p class='muted'>Not fetched yet.</p>"}
<h2>Timeline (IST)</h2>
<div class="tw"><table><thead><tr><th>Time</th><th>Kind</th><th>Where</th><th>Event</th></tr></thead><tbody>{tl_rows or '<tr><td colspan=4>—</td></tr>'}</tbody></table></div>
<h2>Evidence sources and handling</h2>
{_sources(st, ctx)}
<h2>Why these findings are grouped</h2>
{_edges_list(clean(st.edges or []))}
</div>
<div class="conf">CONFIDENTIAL · security incident story {e(st.id)} · secrets and 12-digit IDs are redacted</div>
</body></html>"""
