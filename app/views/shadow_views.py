"""SentinelShadow — triage page and JSON API endpoints.

Routes:
    GET  /shadow                        — triage page (queue, detector lanes, detail drawer)
    GET  /api/shadow/stats              — summary KPIs
    GET  /api/shadow/findings           — paginated list with filters
    GET  /api/shadow/findings/{id}      — single finding
    POST /api/shadow/findings/{id}/decision — record TP / FP / snooze
    GET  /api/shadow/allowlist          — all YAML rules as JSON
    POST /api/shadow/hunt/run           — trigger all detectors immediately
    GET  /api/shadow/process-tree/{id}  — synthetic 3-level process tree
    GET  /api/shadow/stories            — incident stories (related findings grouped)
    GET  /shadow/stories/{id}           — the story page: everything about one incident
    GET  /shadow/stories/{id}/print     — the incident report, v5 layout (save as PDF)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(tags=["shadow"])

# Single in-memory Sentinel mock so incidents persist across calls in this process
_sentinel = None


def _get_sentinel():
    global _sentinel
    if _sentinel is None:
        from shadow_hunter.clients import MockSentinelClient
        _sentinel = MockSentinelClient()
    return _sentinel


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------

@router.get("/shadow", response_class=HTMLResponse, include_in_schema=False)
async def shadow_page():
    return HTMLResponse(_render_page())


def _render_page() -> str:
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shadow — Threat Hunting</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --ink: #081113;
    --panel: #0D191C;
    --panel-2: #112226;
    --panel-3: #172D32;
    --rule: #1D3439;
    --rule-soft: #14262A;
    --fg: #D3E2E0;
    --fg-bright: #EEF7F5;
    --fg-dim: #86A19E;
    --fg-faint: #52706C;
    --accent: #45D3C2;
    --accent-deep: #1C6F66;
    --accent-glow: rgba(69, 211, 194, 0.10);
    --crit: #FF5A5F;
    --high: #FF8B3D;
    --med: #E9C54A;
    --low: #6AA6C8;
    --ok: #5BC98A;
    --sans: "IBM Plex Sans", -apple-system, "Segoe UI", system-ui, sans-serif;
    --mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body {
    background: var(--ink);
    background-image: radial-gradient(1200px 500px at 85% -120px, rgba(69, 211, 194, 0.07), transparent 70%);
    background-repeat: no-repeat;
    color: var(--fg); font: 14px/1.5 var(--sans); min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }
  a { color: inherit; }
  button { font: inherit; cursor: pointer; }
  .mono { font-family: var(--mono); }
  .num { font-family: var(--mono); font-variant-numeric: tabular-nums; }
  .wrap { max-width: 1240px; margin: 0 auto; padding: 0 20px; }

  /* top bar */
  .top { position: sticky; top: 0; z-index: 20; backdrop-filter: blur(10px);
         background: rgba(8, 17, 19, 0.82); border-bottom: 1px solid var(--rule-soft); }
  .top .wrap { display: flex; align-items: center; gap: 18px; height: 60px; }
  .back { font-size: 12px; color: var(--fg-faint); text-decoration: none; }
  .back:hover { color: var(--fg-dim); }
  .mark { display: flex; align-items: baseline; gap: 12px; }
  .mark b { font-family: var(--mono); font-weight: 600; font-size: 17px; letter-spacing: 0.32em;
            color: var(--fg-bright); text-transform: uppercase; }
  .mark { align-items: center; }
  .mark em { width: 9px; height: 9px; border-radius: 50%; background: var(--accent); align-self: center;
             box-shadow: 0 0 0 4px var(--accent-glow), 0 0 14px rgba(69, 211, 194, 0.55); }
  .mark span { font-size: 12px; color: var(--fg-faint); }
  .top .spacer { flex: 1; }
  .hunt-status { font-size: 12px; color: var(--fg-dim); }
  .btn { border: 1px solid var(--rule); background: var(--panel-2); color: var(--fg);
         padding: 7px 14px; border-radius: 8px; font-size: 13px; font-weight: 500; transition: .15s; }
  .btn:hover { border-color: var(--accent-deep); color: var(--fg-bright); }
  .btn.primary { background: var(--accent); border-color: var(--accent); color: #042421; font-weight: 600; }
  .btn.primary:hover { filter: brightness(1.08); color: #042421; }
  .btn:disabled { opacity: .5; cursor: default; }

  /* overview */
  .overview { display: grid; grid-template-columns: 1.4fr repeat(4, 1fr); gap: 1px; margin: 26px 0 22px;
              background: var(--rule-soft); border: 1px solid var(--rule-soft); border-radius: 14px; overflow: hidden; }
  .stat { background: var(--panel); padding: 16px 18px; }
  .stat label { display: block; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-faint); }
  .stat .v { font: 600 26px/1.2 var(--mono); color: var(--fg-bright); margin-top: 6px; }
  .stat .sub { font-size: 12px; color: var(--fg-dim); margin-top: 2px; }
  .stat.lead { background: linear-gradient(135deg, var(--panel-2), var(--panel)); }
  .stat.lead .v { font-size: 38px; color: var(--accent); }
  .sevmix { display: flex; height: 6px; border-radius: 3px; overflow: hidden; margin-top: 10px; background: var(--panel-3); }
  .sevmix span { display: block; height: 100%; }

  /* detector lanes */
  .lanes { display: flex; gap: 8px; overflow-x: auto; padding-bottom: 4px; margin-bottom: 14px; scrollbar-width: thin; }
  .lane { flex: 0 0 auto; display: flex; align-items: center; gap: 10px; border: 1px solid var(--rule);
          background: var(--panel); color: var(--fg-dim); padding: 8px 12px; border-radius: 10px;
          font-size: 13px; transition: .15s; }
  .lane:hover { color: var(--fg); border-color: var(--fg-faint); }
  .lane .n { font-family: var(--mono); font-size: 12px; color: var(--fg-faint); }
  .lane.zero { opacity: .55; }
  .lane.on { border-color: var(--accent); color: var(--fg-bright); background: var(--accent-glow); }
  .lane.on .n { color: var(--accent); }
  .lane.bad { border-color: rgba(255, 90, 95, .55); opacity: 1; }
  .lane.warned { border-color: rgba(233, 197, 74, .55); opacity: 1; }
  .lane.warned .warn { background: var(--med); }
  .lane .warn { font-style: normal; font: 700 11px/16px var(--mono); width: 16px; height: 16px; border-radius: 50%;
                background: var(--crit); color: #1a0506; text-align: center; }

  /* toolbar */
  .toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 12px; }
  .seg { display: inline-flex; border: 1px solid var(--rule); border-radius: 9px; overflow: hidden; background: var(--panel); }
  .seg button { border: 0; background: transparent; color: var(--fg-dim); padding: 6px 12px; font-size: 12.5px; }
  .seg button + button { border-left: 1px solid var(--rule); }
  .seg button:hover { color: var(--fg); }
  .seg button.on { background: var(--panel-3); color: var(--fg-bright); }
  .switch { display: inline-flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--fg-dim); cursor: pointer; user-select: none; }
  .switch input { accent-color: var(--accent); }
  .toolbar .hint { margin-left: auto; font-size: 12px; color: var(--fg-faint); }
  kbd { font-family: var(--mono); font-size: 11px; border: 1px solid var(--rule); border-bottom-width: 2px;
        border-radius: 4px; padding: 0 5px; color: var(--fg-dim); background: var(--panel); }

  /* queue */
  .queue { list-style: none; margin: 0; padding: 0; border: 1px solid var(--rule-soft); border-radius: 14px;
           overflow: hidden; background: var(--panel); }
  .row { display: grid; grid-template-columns: 4px 1fr auto; gap: 0 16px; align-items: center;
         padding: 13px 18px 13px 0; border-bottom: 1px solid var(--rule-soft); cursor: pointer; transition: background .12s; }
  .row:last-child { border-bottom: 0; }
  .row:hover { background: var(--panel-2); }
  .row.sel { background: var(--panel-2); box-shadow: inset 0 0 0 1px var(--accent-deep); }
  .row .bar { align-self: stretch; border-radius: 0 3px 3px 0; }
  .row-main { min-width: 0; }
  .row-title { color: var(--fg-bright); font-size: 13.5px; display: -webkit-box; -webkit-line-clamp: 2;
               -webkit-box-orient: vertical; overflow: hidden; }
  .row-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 14px; margin-top: 5px; font-size: 12px; color: var(--fg-dim); }
  .row-meta .det { color: var(--accent); }
  .row-meta .dev { font-family: var(--mono); font-size: 11.5px; color: var(--fg); }
  .row-meta time { color: var(--fg-faint); }
  .pill { display: inline-block; font-size: 11px; padding: 1px 8px; border-radius: 999px;
          border: 1px solid var(--rule); color: var(--fg-dim); background: var(--panel-2); }
  .pill.mitre { font-family: var(--mono); font-size: 10.5px; }
  .row-side { display: flex; align-items: center; justify-content: flex-end; gap: 10px; }
  .sev { font: 600 10.5px/1 var(--mono); letter-spacing: .08em; text-transform: uppercase; padding: 5px 8px;
         border-radius: 6px; border: 1px solid currentColor; white-space: nowrap; }
  .score { font: 600 15px/1 var(--mono); color: var(--fg-bright); min-width: 38px; text-align: right; }
  .acts { display: flex; gap: 4px; opacity: 0; transition: opacity .12s; }
  .row:hover .acts, .row.sel .acts { opacity: 1; }
  .act { border: 1px solid var(--rule); background: var(--panel-3); color: var(--fg-dim); border-radius: 6px;
         font-size: 11.5px; padding: 3px 8px; }
  .act:hover { color: var(--fg-bright); }
  .act.tp:hover { border-color: var(--crit); color: var(--crit); }
  .act.fp:hover { border-color: var(--ok); color: var(--ok); }
  .decision { font-size: 11.5px; padding: 3px 9px; border-radius: 6px; background: var(--panel-3); color: var(--fg-dim); }
  .decision.true_positive { color: var(--crit); }
  .decision.false_positive { color: var(--ok); }
  .ai { font: 600 10.5px/1 var(--mono); padding: 3px 7px; border-radius: 6px; border: 1px dashed currentColor; white-space: nowrap; }
  .ai.true_positive { color: var(--crit); } .ai.false_positive { color: var(--ok); } .ai.unsure { color: var(--med); }
  .aibox .attn { color: var(--med); }
  .aibox { border: 1px dashed var(--rule); border-radius: 10px; padding: 12px 14px; margin-bottom: 22px; background: var(--panel-2); }
  .aibox .hd { display: flex; align-items: center; gap: 10px; font-size: 12.5px; color: var(--fg-dim); }
  .aibox .hd b { font-weight: 600; }
  .aibox p { margin: 8px 0 0; font-size: 13px; color: var(--fg); line-height: 1.5; }
  .aibox ul { margin: 8px 0 0; padding-left: 18px; font-size: 12px; color: var(--fg-dim); }
  .aibox small { display: block; margin-top: 8px; color: var(--fg-faint); font-size: 11px; }
  .s-critical { color: var(--crit); } .bg-critical { background: var(--crit); }
  .s-high { color: var(--high); } .bg-high { background: var(--high); }
  .s-medium { color: var(--med); } .bg-medium { background: var(--med); }
  .s-low { color: var(--low); } .bg-low { background: var(--low); }
  .empty { padding: 56px 20px; text-align: center; color: var(--fg-dim); }
  .empty b { display: block; font-size: 16px; color: var(--fg-bright); margin-bottom: 4px; font-weight: 600; }
  .skel { height: 58px; border-bottom: 1px solid var(--rule-soft);
          background: linear-gradient(90deg, var(--panel) 0%, var(--panel-2) 50%, var(--panel) 100%);
          background-size: 200% 100%; animation: sh 1.4s infinite; }
  @keyframes sh { to { background-position: -200% 0; } }
  .pager { display: flex; align-items: center; justify-content: space-between; margin: 12px 2px 0;
           font-size: 12px; color: var(--fg-faint); }
  .pager div { display: flex; gap: 6px; }

  /* allowlist */
  .allow { margin: 34px 0 60px; border: 1px solid var(--rule-soft); border-radius: 14px; background: var(--panel); }
  .allow summary { list-style: none; cursor: pointer; padding: 14px 18px; display: flex; align-items: center; gap: 10px;
                   font-weight: 500; color: var(--fg); }
  .allow summary::-webkit-details-marker { display: none; }
  .allow summary::before { content: "›"; color: var(--fg-faint); font-size: 18px; line-height: 1; transition: transform .15s; }
  .allow[open] summary::before { transform: rotate(90deg); }
  .allow summary span { color: var(--fg-faint); font-size: 12.5px; font-weight: 400; }
  .rules { border-top: 1px solid var(--rule-soft); }
  .rule { display: grid; grid-template-columns: minmax(160px, 1fr) 150px minmax(200px, 1.4fr) minmax(180px, 1.4fr);
          gap: 14px; padding: 11px 18px; border-bottom: 1px solid var(--rule-soft); font-size: 12.5px; }
  .rule:last-child { border-bottom: 0; }
  .rule .nm { font-family: var(--mono); color: var(--fg-bright); font-size: 12px; word-break: break-all; }
  .rule .mt { font-family: var(--mono); color: var(--fg-dim); font-size: 11.5px; word-break: break-all; }
  .rule .why { color: var(--fg-dim); }
  .rule .why small { display: block; color: var(--fg-faint); }
  .rule .src { display: flex; align-items: center; gap: 10px; margin-top: 5px; font-family: var(--sans); }
  .more { padding: 10px 18px; }

  /* drawer */
  .scrim { position: fixed; inset: 0; background: rgba(2, 8, 9, 0.55); opacity: 0; pointer-events: none; transition: .2s; z-index: 30; }
  .scrim.open { opacity: 1; pointer-events: auto; }
  .drawer { position: fixed; top: 0; right: 0; bottom: 0; width: min(640px, 100vw); background: var(--panel);
            border-left: 1px solid var(--rule); transform: translateX(100%); transition: transform .22s ease; z-index: 31;
            display: flex; flex-direction: column; }
  .drawer.open { transform: none; }
  .d-head { display: flex; align-items: center; gap: 10px; padding: 16px 22px; border-bottom: 1px solid var(--rule-soft); }
  .d-head .det { color: var(--accent); font-size: 13px; }
  .d-head .x { margin-left: auto; border: 0; background: transparent; color: var(--fg-faint); font-size: 22px; line-height: 1; }
  .d-head .x:hover { color: var(--fg-bright); }
  .d-body { overflow-y: auto; padding: 20px 22px 28px; flex: 1; }
  .d-title { font-size: 16px; font-weight: 500; color: var(--fg-bright); line-height: 1.45; margin: 0 0 18px; }
  .facts { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--rule-soft);
           border: 1px solid var(--rule-soft); border-radius: 10px; overflow: hidden; margin-bottom: 22px; }
  .fact { background: var(--panel-2); padding: 10px 12px; min-width: 0; }
  .fact label, .sect > label { display: block; font-size: 10.5px; letter-spacing: .08em; text-transform: uppercase; color: var(--fg-faint); }
  .fact div { margin-top: 3px; font-size: 13px; color: var(--fg); overflow-wrap: anywhere; }
  .fact.wide { grid-column: 1 / -1; }
  .sect { margin-bottom: 22px; }
  .sect > label { margin-bottom: 8px; }
  .ev { border: 1px solid var(--rule-soft); border-radius: 10px; overflow: hidden; }
  .ev-row { display: grid; grid-template-columns: 150px 1fr; gap: 12px; padding: 8px 12px; border-bottom: 1px solid var(--rule-soft); font-size: 12.5px; }
  .ev-row:last-child { border-bottom: 0; }
  .ev-row .k { color: var(--fg-faint); font-family: var(--mono); font-size: 11.5px; overflow-wrap: anywhere; }
  .ev-row .v { color: var(--fg); font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; white-space: pre-wrap; }
  .lin { border: 1px solid var(--rule-soft); border-radius: 10px; margin-bottom: 8px; padding: 9px 12px; background: var(--panel-2); }
  .lin .l { font-family: var(--mono); font-size: 12px; color: var(--fg-bright); }
  .lin .c { font-family: var(--mono); font-size: 11.5px; color: var(--fg-dim); margin-top: 4px; overflow-wrap: anywhere; }
  .lin .tags { margin-top: 6px; display: flex; gap: 6px; flex-wrap: wrap; }
  .gauge { position: relative; height: 10px; border-radius: 5px; background: var(--panel-3); overflow: visible; margin: 10px 0 6px; }
  .gauge .fill { height: 100%; border-radius: 5px; }
  .gauge .th { position: absolute; top: -5px; bottom: -5px; width: 2px; background: var(--fg-dim); }
  .gauge-legend { display: flex; justify-content: space-between; font-size: 11.5px; color: var(--fg-faint); }
  .sig { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-top: 14px; }
  .sig div { border: 1px solid var(--rule-soft); border-radius: 10px; padding: 9px 10px; background: var(--panel-2); }
  .sig b { display: block; font: 600 18px/1.2 var(--mono); color: var(--fg-bright); }
  .sig span { font-size: 11px; color: var(--fg-faint); }
  .sig .hot b { color: var(--high); }
  pre.raw { margin: 0; padding: 12px; border-radius: 10px; background: #061012; border: 1px solid var(--rule-soft);
            color: var(--fg-dim); font: 11.5px/1.5 var(--mono); max-height: 320px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
  .linkish { border: 0; background: transparent; color: var(--accent); font-size: 12px; padding: 0; }
  .d-foot { border-top: 1px solid var(--rule-soft); padding: 14px 22px; background: var(--panel-2); }
  .d-foot .btns { display: flex; gap: 8px; flex-wrap: wrap; }
  .d-foot .btn.tp { border-color: rgba(255, 90, 95, .45); color: #FFB3B5; }
  .d-foot .btn.tp:hover { background: rgba(255, 90, 95, .12); }
  .d-foot .btn.fp { border-color: rgba(91, 201, 138, .45); color: #A8E8C3; }
  .d-foot .btn.fp:hover { background: rgba(91, 201, 138, .10); }
  .d-foot p { margin: 9px 0 0; font-size: 11.5px; color: var(--fg-faint); }

  /* stories */
  .viewseg { margin-right: 12px; }
  .viewseg .n { font: 600 11px/1 var(--mono); margin-left: 4px; color: var(--fg-faint); }
  .story-chip { border: 1px solid var(--accent-deep); color: var(--accent); background: transparent; border-radius: 999px;
                font-size: 11px; padding: 1px 8px; cursor: pointer; }
  .story-chip:hover { background: var(--panel-3); }
  .hostchip { font-family: var(--mono); font-size: 11px; }
  .rep { border: 1px solid var(--rule-soft); border-radius: 10px; padding: 12px 14px; margin-bottom: 22px; background: var(--panel-2); }
  .rep h4 { margin: 10px 0 4px; font-size: 13px; color: var(--fg-bright); }
  .rep h4:first-child { margin-top: 0; }
  .rep p { margin: 0 0 6px; font-size: 13px; line-height: 1.5; white-space: pre-wrap; }
  .rep small { color: var(--fg-faint); font-size: 11px; }
  .edge { font-size: 12px; color: var(--fg-dim); padding: 6px 0; border-bottom: 1px solid var(--rule-soft); }
  .edge:last-child { border-bottom: 0; }
  .edge b { color: var(--accent); font-weight: 500; font-family: var(--mono); font-size: 11px; }
  .mem { display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: center; padding: 7px 0; border-bottom: 1px solid var(--rule-soft); font-size: 12.5px; }
  .mem:last-child { border-bottom: 0; }

  .toast { position: fixed; left: 50%; bottom: 24px; transform: translate(-50%, 20px); opacity: 0; transition: .2s;
           background: var(--panel-3); border: 1px solid var(--rule); color: var(--fg-bright); padding: 10px 16px;
           border-radius: 10px; font-size: 13px; z-index: 40; pointer-events: none; max-width: calc(100vw - 32px); }
  .toast.show { opacity: 1; transform: translate(-50%, 0); }

  @media (max-width: 900px) {
    .overview { grid-template-columns: 1fr 1fr; }
    .stat.lead { grid-column: 1 / -1; }
    .rule { grid-template-columns: 1fr; gap: 4px; }
    .toolbar .hint { display: none; }
  }
  @media (max-width: 600px) {
    .wrap { padding: 0 16px; }
    .mark span, .hunt-status { display: none; }
    .row { grid-template-columns: 4px 1fr; }
    .row-side { grid-column: 2; margin-top: 8px; justify-content: flex-start; }
    .row-side .acts { order: 3; }
    .acts { opacity: 1; }
    .facts { grid-template-columns: 1fr; }
    .ev-row { grid-template-columns: 1fr; gap: 2px; }
    .sig { grid-template-columns: 1fr 1fr; }
  }
</style>
</head>
<body>

<header class="top">
  <div class="wrap">
    <a class="back" href="/dashboard">&larr; DeepIntel</a>
    <div class="mark"><em></em><b>Shadow</b><span>Behaviour-based hunting &middot; Defender telemetry</span></div>
    <div class="spacer"></div>
    <div class="seg viewseg" id="seg-view" role="group" aria-label="View">
      <button type="button" data-v="queue" class="on">Queue</button>
      <button type="button" data-v="stories" title="Related findings grouped into incident stories">Stories<span class="n" id="story-n"></span></button>
    </div>
    <span class="hunt-status" id="hunt-status"></span>
    <button class="btn primary" id="hunt-btn" type="button">Run hunt</button>
  </div>
</header>

<main class="wrap">
  <section class="overview" id="overview">
    <div class="stat lead">
      <label>Needs review</label>
      <div class="v num" id="k-open">&mdash;</div>
      <div class="sevmix" id="k-mix"></div>
      <div class="sub" id="k-mix-text">&nbsp;</div>
    </div>
    <div class="stat"><label>Confirmed threats</label><div class="v num" id="k-tp">&mdash;</div><div class="sub">true positives</div></div>
    <div class="stat"><label>Dismissed</label><div class="v num" id="k-fp">&mdash;</div><div class="sub">false positives</div></div>
    <div class="stat"><label>Allowlisted</label><div class="v num" id="k-al">&mdash;</div><div class="sub">hidden by a rule</div></div>
    <div class="stat"><label>Retired</label><div class="v num" id="k-legacy">&mdash;</div><div class="sub">pre-revamp backlog</div></div>
  </section>

  <nav class="lanes" id="lanes" aria-label="Detectors"></nav>

  <div class="toolbar">
    <div class="seg" id="seg-sev" role="group" aria-label="Severity">
      <button type="button" data-v="" class="on">All</button>
      <button type="button" data-v="critical">Critical</button>
      <button type="button" data-v="high">High</button>
      <button type="button" data-v="medium">Medium</button>
      <button type="button" data-v="low">Low</button>
    </div>
    <div class="seg" id="seg-rev" role="group" aria-label="Status">
      <button type="button" data-v="false" class="on">Needs review</button>
      <button type="button" data-v="true">Reviewed</button>
      <button type="button" data-v="all">All</button>
    </div>
    <div class="seg" id="seg-sort" role="group" aria-label="Sort">
      <button type="button" data-v="priority" class="on">Priority</button>
      <button type="button" data-v="recent">Newest</button>
    </div>
    <div class="seg" id="seg-ai" role="group" aria-label="AI suggestion">
      <button type="button" data-v="" class="on">Any</button>
      <button type="button" data-v="fp" title="AI suggests false positive, nothing to follow up">AI: FP</button>
      <button type="button" data-v="attention" title="AI found it benign but flagged something to act on (policy, exposure)">AI: attention</button>
      <button type="button" data-v="tp" title="AI suggests true positive">AI: TP</button>
      <button type="button" data-v="unsure">AI: unsure</button>
      <button type="button" data-v="none" title="No AI suggestion yet">No AI</button>
    </div>
    <label class="switch"><input type="checkbox" id="show-al"> Show allowlisted</label>
    <span class="hint"><kbd>j</kbd> <kbd>k</kbd> move &middot; <kbd>&crarr;</kbd> open &middot; <kbd>esc</kbd> close</span>
  </div>

  <ul class="queue" id="queue"></ul>
  <div class="pager">
    <span id="page-info"></span>
    <div>
      <button class="btn" id="prev" type="button">Previous</button>
      <button class="btn" id="next" type="button">Next</button>
    </div>
  </div>

  <details class="allow" id="allow">
    <summary>Allowlist rules <span id="al-count"></span></summary>
    <div class="rules" id="rules"></div>
    <div class="more"><button class="btn" id="al-more" type="button" hidden>Load more</button></div>
  </details>

  <section id="stories" hidden>
    <div class="toolbar">
      <div class="seg" id="seg-story" role="group" aria-label="Story status">
        <button type="button" data-v="open" class="on">Open</button>
        <button type="button" data-v="closed">Closed</button>
        <button type="button" data-v="all">All</button>
      </div>
      <button class="btn" id="story-run" type="button" title="Regroup findings into stories now">Rebuild stories</button>
      <span class="hint">Grouping is advisory: it never confirms, dismisses or snoozes a finding</span>
    </div>
    <ul class="queue" id="story-list"></ul>
  </section>
</main>

<div class="scrim" id="scrim"></div>
<aside class="drawer" id="drawer" aria-hidden="true">
  <div class="d-head" id="d-head"></div>
  <div class="d-body" id="d-body"></div>
  <div class="d-foot" id="d-foot"></div>
</aside>
<div class="toast" id="toast"></div>

<script>
var DET = {
  entity_behavior:         ['Behaviour', 'Devices whose activity broke both their own normal and the fleet\u2019s'],
  rare_persistence:        ['Rare persistence', 'Startup items, launchd, cron and scheduled tasks almost no other device has'],
  exfil_patterns:          ['Exfil & tunnels', 'Non-browser processes reaching file-drop, paste, webhook or tunnel services'],
  rare_external_domains:   ['Rare destinations', 'Fleet-new destinations reached by an interpreter or rare binary'],
  encoded_powershell:      ['Encoded PowerShell', 'Decoded PowerShell content new to the fleet'],
  suspicious_parent_child: ['Parent \u2192 child', 'Office, mail or browser starting a shell or LOLBin with a new command'],
  lolbin_abuse:            ['LOLBins', 'Signed Windows binaries used for their known abuse techniques'],
  unusual_remote_logons:   ['RDP anomalies', 'RDP that breaks the account\u2019s own 14-day pattern'],
  defender_exclusions:     ['Defender exclusions', 'Exclusions added by a script host rather than central management'],
  package_installs:        ['Package installs', 'npm/PyPI installs of known-malicious, pulled or brand-new packages'],
  cloud_session_split:     ['Cloud session split', 'One AWS session credential used from a new network, a second OS or a rotating proxy'],
  edr_silent_active:       ['EDR silent', 'Devices the EDR has not heard from while they are signing in or calling AWS'],
  person_behavior:         ['Person cases', 'One person across EDR, Netskope, Entra and CloudTrail: two or more independent sources in 14 days'],
  upwind_threats:          ['Upwind', 'New Upwind CNAPP detections on cloud workloads, Kubernetes, IAM and Upwind-covered hosts'],
  edge_attacks:            ['Edge attacks', 'Attack-shaped requests at the Cloudflare edge that our origin answered 2xx (VictoriaLogs)'],
  eks_audit:               ['EKS prod', 'Human hands on the prod cluster (pod shells, secret reads, RBAC, tokens) and anonymous access (VictoriaLogs)'],
  rds_audit:               ['RDS audit', 'Database account changes, first-time destructive statements and guessed passwords on prod Aurora (VictoriaLogs)']
};
var ORDER = Object.keys(DET);
var SEVS = ['critical', 'high', 'medium', 'low'];
var S = { det: '', sev: '', rev: 'false', sort: 'priority', ai: '', al: false, page: 0, limit: 40, total: 0, rows: [], sel: -1, open: null,
          alOffset: 0, alTotal: 0, view: 'queue', storyStatus: 'open', stories: [], openStory: null };

function $(id) { return document.getElementById(id); }
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function label(d) { return (DET[d] || [d])[0]; }
function parseTs(iso) {
  if (!iso) return null;
  return new Date(/[zZ]$|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + 'Z');
}
function ago(iso) {
  var d = parseTs(iso); if (!d) return '';
  var m = (Date.now() - d.getTime()) / 60000;
  if (m < 1) return 'just now';
  if (m < 60) return Math.round(m) + 'm ago';
  if (m < 1440) return Math.round(m / 60) + 'h ago';
  if (m < 10080) return Math.round(m / 1440) + 'd ago';
  return d.toISOString().slice(0, 10);
}
function ist(iso) {
  var d = parseTs(iso); if (!d) return '';
  return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'short' }) + ' IST';
}
function toast(msg) {
  var t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toast._t); toast._t = setTimeout(function () { t.classList.remove('show'); }, 4200);
}
function getJSON(url, opts) {
  return fetch(url, opts).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); });
}

/* ---------- overview + lanes ---------- */
var HEALTH = {};
function loadHealth() {
  getJSON('/api/shadow/detectors/status').then(function (d) {
    HEALTH = {};
    (d.detectors || []).forEach(function (r) { HEALTH[r.detector] = r; });
    if (S.lastBy) renderLanes(S.lastBy);
  }).catch(function () {});
}
function loadStats() {
  getJSON('/api/shadow/stats').then(function (d) {
    $('k-open').textContent = d.unreviewed || 0;
    $('k-tp').textContent = d.true_positives || 0;
    $('k-fp').textContent = d.false_positives || 0;
    $('k-al').textContent = d.allowlisted || 0;
    $('k-legacy').textContent = (d.legacy || 0).toLocaleString('en-IN');
    var bs = d.by_severity || {}, tot = 0;
    SEVS.forEach(function (s) { tot += bs[s] || 0; });
    $('k-mix').innerHTML = tot ? SEVS.map(function (s) {
      return bs[s] ? '<span class="bg-' + s + '" style="width:' + (100 * bs[s] / tot) + '%"></span>' : '';
    }).join('') : '';
    $('k-mix-text').textContent = tot ? SEVS.filter(function (s) { return bs[s]; })
      .map(function (s) { return bs[s] + ' ' + s; }).join(' \u00b7 ') : 'Queue clear';
    renderLanes(d.by_detector || {});
  }).catch(function () {});
}
function renderLanes(by) {
  S.lastBy = by;
  var keys = ORDER.concat(Object.keys(by).filter(function (k) { return ORDER.indexOf(k) < 0; }));
  var all = 0; Object.keys(by).forEach(function (k) { all += by[k]; });
  var html = '<button type="button" class="lane' + (S.det === '' ? ' on' : '') + '" data-det="">All detectors <span class="n">' + all + '</span></button>';
  html += keys.map(function (k) {
    var n = by[k] || 0, h = HEALTH[k], bad = h && h.ok === false, warn = h && !bad && h.warning;
    var tip = (DET[k] || ['', ''])[1] + (h && h.last_run ? '\nLast run ' + ago(h.last_run) +
      (bad ? ' FAILED: ' + h.error : warn ? ' with a warning: ' + h.warning : ' ok') : '');
    return '<button type="button" class="lane' + (S.det === k ? ' on' : '') + (n ? '' : ' zero') + (bad ? ' bad' : warn ? ' warned' : '') +
      '" data-det="' + esc(k) + '" title="' + esc(tip) + '">' + (bad || warn ? '<i class="warn">!</i>' : '') + esc(label(k)) +
      ' <span class="n">' + n + '</span></button>';
  }).join('');
  $('lanes').innerHTML = html;
}
$('lanes').addEventListener('click', function (e) {
  var b = e.target.closest('.lane'); if (!b) return;
  S.det = b.getAttribute('data-det'); S.page = 0;
  Array.prototype.forEach.call(document.querySelectorAll('.lane'), function (x) { x.classList.toggle('on', x === b); });
  loadFindings();
});

/* ---------- queue ---------- */
function behaviourPills(r) {
  var p = [];
  var nov = (r.novel_risky || []).length, per = (r.rare_persistent || []).length, spr = (r.spread || []).length;
  if (nov) p.push(nov + ' novel lineage' + (nov > 1 ? 's' : ''));
  if (per) p.push(per + ' from persistence');
  if (r.net_high) p.push(r.net_high + ' high-risk destination' + (r.net_high > 1 ? 's' : ''));
  if ((r.persistence_new || []).length) p.push((r.persistence_new || []).length + ' new persistence');
  if ((r.access_new || []).length) p.push('new RDP access');
  if ((r.upwind_new || []).length) p.push((r.upwind_new || []).length + ' Upwind detection' + ((r.upwind_new || []).length > 1 ? 's' : ''));
  if (r.net_med) p.push(r.net_med + ' rare destination' + (r.net_med > 1 ? 's' : ''));
  if (spr) p.push('spreading');
  return p.map(function (x) { return '<span class="pill">' + esc(x) + '</span>'; }).join('');
}
var AI_LABEL = { true_positive: 'TP', false_positive: 'FP', unsure: 'unsure' };
function aiChip(f) {
  if (!f.ai_verdict) return '';
  var c = f.ai_confidence != null ? ' ' + Math.round(f.ai_confidence * 100) + '%' : '';
  return '<span class="ai ' + esc(f.ai_verdict) + '" title="AI suggestion (' + esc(f.ai_by) + '); not a decision">AI ' +
    esc(AI_LABEL[f.ai_verdict] || f.ai_verdict) + esc(c) + (f.ai_attention ? ' \u2691' : '') + '</span>';
}
function aiBlock(f) {
  if (!f.ai_verdict) return '';
  var name = { true_positive: 'true positive', false_positive: 'false positive', unsure: 'unsure' }[f.ai_verdict] || f.ai_verdict;
  var agreed = f.ai_agreed === true ? ' · the analyst agreed' : f.ai_agreed === false ? ' · the analyst disagreed' : '';
  return '<div class="aibox"><div class="hd">' + aiChip(f) + '<span>AI suggests <b>' + esc(name) + '</b>' + esc(agreed) + '</span></div>' +
    (f.ai_attention ? '<p class="attn"><b>\u2691 Needs attention:</b> ' + esc(f.ai_attention) + '</p>' : '') +
    (f.ai_reasoning ? '<p>' + esc(f.ai_reasoning) + '</p>' : '') +
    ((f.ai_evidence || []).length ? '<ul>' + f.ai_evidence.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>' : '') +
    '<small>' + esc(f.ai_by) + ' · ' + esc(ago(f.ai_at)) + ' · a suggestion only: nothing is dismissed or confirmed until an analyst decides</small></div>';
}
function rowHTML(f, i) {
  var r = f.raw || {}, beh = f.detector === 'entity_behavior';
  var title = beh ? (f.device_name + ' \u2014 behaviour on ' + (r.day || '') + ', rank #' + (r.rank || '?')) : f.summary;
  var meta = '<span class="det">' + esc(label(f.detector)) + '</span>' +
    (f.device_name && !beh ? '<span class="dev">' + esc(f.device_name) + '</span>' : '') +
    (f.account_name ? '<span>' + esc(f.account_name) + '</span>' : '') +
    (beh ? behaviourPills(r) : (f.mitre_techniques || []).slice(0, 2).map(function (t) { return '<span class="pill mitre">' + esc(t) + '</span>'; }).join('')) +
    (f.allowlisted_by_rule ? '<span class="pill">allowlisted</span>' : '') +
    (f.story_id ? '<button type="button" class="story-chip" data-story="' + esc(f.story_id) + '" title="Part of an incident story">story</button>' : '') +
    aiChip(f) +
    '<time title="' + esc(ist(f.created_at)) + '">' + esc(ago(f.created_at)) + '</time>';
  var side = (f.decision ? '<span class="decision ' + esc(f.decision) + '">' + esc(f.decision.replace('_', ' ')) + '</span>' :
      '<span class="acts">' +
        '<button type="button" class="act tp" data-act="true_positive" title="Confirm threat (true positive)">Confirm</button>' +
        '<button type="button" class="act fp" data-act="false_positive" title="Dismiss as false positive \u2014 also adds an allowlist rule built from this finding">Dismiss</button>' +
        '<button type="button" class="act" data-act="snooze" title="Snooze">Snooze</button>' +
      '</span>') +
    (beh && r.score != null ? '<span class="score" title="behaviour score">' + esc(r.score) + '</span>' : '') +
    '<span class="sev s-' + esc(f.severity) + '">' + esc(f.severity) + '</span>';
  return '<li class="row' + (i === S.sel ? ' sel' : '') + '" data-i="' + i + '">' +
    '<span class="bar bg-' + esc(f.severity) + '"></span>' +
    '<div class="row-main"><div class="row-title">' + esc(title) + '</div><div class="row-meta">' + meta + '</div></div>' +
    '<div class="row-side">' + side + '</div></li>';
}
function renderQueue() {
  var q = $('queue');
  if (!S.rows.length) {
    var filtered = S.det || S.sev || S.ai || S.rev !== 'false';
    q.innerHTML = '<li class="empty"><b>' + (filtered ? 'Nothing matches these filters' : 'Queue clear') + '</b>' +
      (filtered ? 'Try another detector or severity.' : 'Nothing needs review right now.') + '</li>';
  } else {
    q.innerHTML = S.rows.map(rowHTML).join('');
  }
  var a = S.total ? S.page * S.limit + 1 : 0, b = Math.min((S.page + 1) * S.limit, S.total);
  $('page-info').textContent = S.total ? a + '\u2013' + b + ' of ' + S.total : '';
  $('prev').disabled = S.page === 0;
  $('next').disabled = (S.page + 1) * S.limit >= S.total;
}
function loadFindings() {
  var p = new URLSearchParams({ limit: S.limit, offset: S.page * S.limit, reviewed: S.rev, sort: S.sort });
  if (S.sev) p.set('severity', S.sev);
  if (S.det) p.set('detector', S.det);
  if (S.ai) p.set('ai', S.ai);
  p.set('hide_allowlisted', (S.rev === 'true' || S.al) ? 'false' : 'true');
  $('queue').innerHTML = '<li class="skel"></li><li class="skel"></li><li class="skel"></li>';
  getJSON('/api/shadow/findings?' + p).then(function (d) {
    S.rows = d.findings || []; S.total = d.total || 0; S.sel = -1;
    renderQueue();
  }).catch(function () {
    $('queue').innerHTML = '<li class="empty"><b>Could not load findings</b>Check the session and reload.</li>';
  });
}
$('queue').addEventListener('click', function (e) {
  var li = e.target.closest('.row'); if (!li) return;
  var i = +li.getAttribute('data-i'), act = e.target.closest('[data-act]'), sc = e.target.closest('[data-story]');
  if (sc) { e.stopPropagation(); openStory(sc.getAttribute('data-story')); return; }
  if (act) { e.stopPropagation(); decide(S.rows[i], act.getAttribute('data-act')); return; }
  select(i); openDrawer(S.rows[i]);
});
function wireSeg(id, key) {
  $(id).addEventListener('click', function (e) {
    var b = e.target.closest('button'); if (!b) return;
    S[key] = b.getAttribute('data-v'); S.page = 0;
    Array.prototype.forEach.call(this.children, function (x) { x.classList.toggle('on', x === b); });
    loadFindings();
  });
}
wireSeg('seg-sev', 'sev'); wireSeg('seg-rev', 'rev'); wireSeg('seg-sort', 'sort'); wireSeg('seg-ai', 'ai');
$('show-al').addEventListener('change', function () { S.al = this.checked; S.page = 0; loadFindings(); });
$('prev').addEventListener('click', function () { S.page = Math.max(0, S.page - 1); loadFindings(); });
$('next').addEventListener('click', function () { S.page += 1; loadFindings(); });

function select(i) {
  S.sel = i;
  Array.prototype.forEach.call(document.querySelectorAll('.row'), function (li) {
    var on = +li.getAttribute('data-i') === i; li.classList.toggle('sel', on);
    if (on) li.scrollIntoView({ block: 'nearest' });
  });
}

/* ---------- drawer ---------- */
function fact(k, v, wide) {
  return v ? '<div class="fact' + (wide ? ' wide' : '') + '"><label>' + esc(k) + '</label><div>' + v + '</div></div>' : '';
}
function lineageList(items, withMeta) {
  return items.slice(0, 10).map(function (x) {
    var tags = [];
    if (withMeta && x.fleet_devices != null) tags.push('on ' + x.fleet_devices + ' device(s) fleet-wide');
    if (withMeta && x.n) tags.push(x.n + ' run(s)');
    if (x.rare_binary) tags.push('rare binary');
    return '<div class="lin"><div class="l">' + esc(x.lineage || x) + '</div>' +
      (x.cmd ? '<div class="c">' + esc(x.cmd) + '</div>' : '') +
      (tags.length ? '<div class="tags">' + tags.map(function (t) { return '<span class="pill">' + esc(t) + '</span>'; }).join('') + '</div>' : '') +
      '</div>';
  }).join('') + (items.length > 10 ? '<div class="pill">+' + (items.length - 10) + ' more</div>' : '');
}
function behaviourBlock(r) {
  var score = +r.score || 0, max = 90, th = 60;
  var sevc = score >= th ? 'var(--high)' : score >= 30 ? 'var(--med)' : 'var(--low)';
  var h = '<div class="sect"><label>Behaviour score</label>' +
    '<div class="gauge"><div class="fill" style="width:' + Math.min(100, 100 * score / max) + '%;background:' + sevc + '"></div>' +
    '<div class="th" style="left:' + (100 * th / max) + '%" title="high threshold"></div></div>' +
    '<div class="gauge-legend"><span>' + esc(score) + ' \u00b7 ' + esc(r.stages || 0) + ' signal kind(s)</span><span>high at 60, or 3 kinds at 40</span></div>' +
    '<div class="sig">' +
      '<div' + ((r.novel_risky || []).length ? ' class="hot"' : '') + '><b>' + (r.novel_risky || []).length + '</b><span>novel lineages</span></div>' +
      '<div' + ((r.rare_persistent || []).length ? ' class="hot"' : '') + '><b>' + (r.rare_persistent || []).length + '</b><span>from persistence</span></div>' +
      '<div' + (r.net_high ? ' class="hot"' : '') + '><b>' + (r.net_high || 0) + ' / ' + (r.net_med || 0) + '</b><span>high / rare destinations</span></div>' +
      '<div' + ((r.spread || []).length ? ' class="hot"' : '') + '><b>' + (r.spread || []).length + '</b><span>spreading</span></div>' +
      '<div' + ((r.persistence_new || []).length ? ' class="hot"' : '') + '><b>' + (r.persistence_new || []).length + '</b><span>new persistence</span></div>' +
      '<div' + ((r.access_new || []).length ? ' class="hot"' : '') + '><b>' + (r.access_new || []).length + '</b><span>new RDP access</span></div>' +
      '<div' + ((r.upwind_new || []).length ? ' class="hot"' : '') + '><b>' + (r.upwind_new || []).length + '</b><span>new Upwind detections</span></div>' +
    '</div></div>';
  if ((r.rare_persistent || []).length) h += '<div class="sect"><label>Running from persistence, rare in the fleet</label>' + lineageList(r.rare_persistent, true) + '</div>';
  if ((r.novel_risky || []).length) h += '<div class="sect"><label>Novel risky lineages</label>' + lineageList(r.novel_risky, false) + '</div>';
  if ((r.spread || []).length) h += '<div class="sect"><label>Spreading across the fleet</label>' + lineageList(r.spread, false) + '</div>';
  if ((r.persistence_new || []).length) h += '<div class="sect"><label>Persistence created, rare in the fleet</label>' +
    lineageList(r.persistence_new.map(function (x) { var inst = / \[installer\]$/.test(x);
      return { lineage: x.replace(/ \[installer\]$/, ''), cmd: inst ? 'written by a software installer \u2014 counted, but not as its own signal' : '' }; }), false) + '</div>';
  if ((r.access_new || []).length) h += '<div class="sect"><label>RDP by accounts new to this device</label>' +
    lineageList(r.access_new, false) + '</div>';
  if ((r.upwind_new || []).length) h += '<div class="sect"><label>New Upwind detections on this host</label>' +
    lineageList(r.upwind_new, false) + '</div>';
  if (r.novelty_baseline != null) h += '<div class="sect"><label>Device baseline</label><div class="ev">' +
    '<div class="ev-row"><div class="k">novelty points</div><div class="v">' + esc(r.novelty_points) + '</div></div>' +
    '<div class="ev-row"><div class="k">own daily baseline</div><div class="v">' + esc(r.novelty_baseline) + ' novel lineages/day</div></div></div></div>';
  return h;
}
function personBlock(r) {
  var PL = { endpoint: 'Endpoint', network: 'Netskope', identity: 'Entra', cloud: 'CloudTrail' };
  var h = '<div class="sect"><label>Case across sources</label><div class="ev">' +
    '<div class="ev-row"><div class="k">score</div><div class="v">' + esc(r.score) + ' (' + esc((r.strong_planes || []).map(function (p) { return PL[p] || p; }).join(' + ')) + ')</div></div>' +
    '<div class="ev-row"><div class="k">attack order</div><div class="v">' + (r.chain ? 'yes: device activity came before the identity/cloud anomalies' : 'no') + '</div></div>' +
    ((r.shared_ips || []).length ? '<div class="ev-row"><div class="k">same IP in 2+ sources</div><div class="v">' + esc(r.shared_ips.join(', ')) + '</div></div>' : '') +
    '<div class="ev-row"><div class="k">devices</div><div class="v">' + esc((r.devices || []).join(', ') || '-') + '</div></div></div></div>';
  h += '<div class="sect"><label>Timeline</label>' + (r.timeline || []).slice().reverse().map(function (t) {
    var pts = Object.keys(t.points || {}).map(function (p) { return (PL[p] || p) + ' ' + t.points[p]; }).join(' \u00b7 ');
    var det = Object.keys(t.detail || {}).map(function (p) {
      var d = t.detail[p], bits = [];
      Object.keys(d).forEach(function (k) {
        var v = d[k]; if (v === 0 || v === false || v == null || (Array.isArray(v) && !v.length) || v === '') return;
        bits.push(k.replace(/_/g, ' ') + ': ' + (Array.isArray(v) ? v.slice(0, 4).join(', ') : v));
      });
      return '<div class="c"><b>' + esc(PL[p] || p) + '</b> ' + esc(bits.join(' \u00b7 ')) + '</div>';
    }).join('');
    return '<div class="lin"><div class="l">' + esc(t.day) + ' \u2014 ' + esc(pts) + '</div>' + det + '</div>';
  }).join('') + '</div>';
  return h;
}
function evidenceBlock(r) {
  var skip = { DeviceId: 1, DeviceName: 1, Shape: 1 };
  var rows = Object.keys(r).filter(function (k) { return !skip[k] && r[k] !== '' && r[k] != null; }).map(function (k) {
    var v = r[k];
    if (Array.isArray(v)) v = v.map(function (x) { return typeof x === 'object' ? JSON.stringify(x) : x; }).join('\n');
    else if (typeof v === 'object') v = JSON.stringify(v);
    else if (typeof v === 'boolean') v = v ? 'yes' : 'no';
    return '<div class="ev-row"><div class="k">' + esc(k) + '</div><div class="v">' + esc(String(v).slice(0, 1200)) + '</div></div>';
  });
  return rows.length ? '<div class="sect"><label>Evidence</label><div class="ev">' + rows.join('') + '</div></div>' : '';
}
function openDrawer(f) {
  S.open = f;
  var r = f.raw || {}, beh = f.detector === 'entity_behavior';
  $('d-head').innerHTML = '<span class="sev s-' + esc(f.severity) + '">' + esc(f.severity) + '</span>' +
    '<span class="det" title="' + esc((DET[f.detector] || ['', ''])[1]) + '">' + esc(label(f.detector)) + '</span>' +
    '<button class="x" type="button" aria-label="Close" id="d-close">&times;</button>';
  var body = '<p class="d-title">' + esc(f.summary) + '</p><div class="facts">' +
    fact('Device', esc(f.device_name)) +
    fact('Account', esc(f.account_name)) +
    fact('Found', esc(ist(f.created_at)) + ' <span style="color:var(--fg-faint)">(' + esc(ago(f.created_at)) + ')</span>') +
    fact('MITRE ATT&CK', (f.mitre_techniques || []).map(function (t) { return '<span class="pill mitre">' + esc(t) + '</span>'; }).join(' ')) +
    fact('Indicator', '<span class="mono" style="font-size:12px">' + esc(f.indicator) + '</span>', true) +
    (f.allowlisted_by_rule ? fact('Allowlisted by', '<span class="mono">' + esc(f.allowlisted_by_rule) + '</span>', true) : '') +
    '</div>';
  body += aiBlock(f);
  body += beh ? behaviourBlock(r) : f.detector === 'person_behavior' ? personBlock(r) : evidenceBlock(r);
  body += '<div class="sect"><label>Raw <button class="linkish" type="button" id="raw-t">show</button></label>' +
    '<pre class="raw" id="raw" hidden>' + esc(JSON.stringify(r, null, 2)) + '</pre></div>';
  $('d-body').innerHTML = body; $('d-body').scrollTop = 0;
  if (f.decision) {
    $('d-foot').innerHTML = '<span class="decision ' + esc(f.decision) + '">' + esc(f.decision.replace('_', ' ')) + '</span>' +
      (f.reviewed_by ? ' <span style="font-size:12px;color:var(--fg-faint)">by ' + esc(f.reviewed_by) + ' \u00b7 ' + esc(ago(f.reviewed_at)) + '</span>' : '') +
      (f.note ? '<p>' + esc(f.note) + '</p>' : '');
  } else {
    var acc = f.ai_verdict === 'true_positive' || f.ai_verdict === 'false_positive';
    $('d-foot').innerHTML = '<div class="btns">' +
      (acc ? '<button class="btn ' + (f.ai_verdict === 'true_positive' ? 'tp' : 'fp') + '" type="button" data-act="' + esc(f.ai_verdict) +
        '" data-ai="1" title="Records the same decision as the button it matches">Accept AI: ' +
        (f.ai_verdict === 'true_positive' ? 'confirm' : 'dismiss') + '</button>' : '') +
      '<button class="btn tp" type="button" data-act="true_positive">Confirm threat</button>' +
      '<button class="btn fp" type="button" data-act="false_positive">Dismiss &amp; allowlist</button>' +
      '<button class="btn" type="button" data-act="snooze">Snooze</button></div>' +
      '<p>Dismiss adds an allowlist rule built from this finding and hides the open findings it matches; it can be removed under Allowlist rules. Snooze only records the review.</p>';
  }
  $('d-close').onclick = closeDrawer;
  $('raw-t').onclick = function () { var p = $('raw'); p.hidden = !p.hidden; this.textContent = p.hidden ? 'show' : 'hide'; };
  $('drawer').classList.add('open'); $('drawer').setAttribute('aria-hidden', 'false'); $('scrim').classList.add('open');
}
function closeDrawer() {
  S.open = null;
  $('drawer').classList.remove('open'); $('drawer').setAttribute('aria-hidden', 'true'); $('scrim').classList.remove('open');
}
$('scrim').addEventListener('click', closeDrawer);
$('d-foot').addEventListener('click', function (e) {
  var b = e.target.closest('[data-act]');
  if (b && S.open) decide(S.open, b.getAttribute('data-act'), b.hasAttribute('data-ai') ? 'accepted AI suggestion: ' + (S.open.ai_reasoning || '').slice(0, 400) : '');
});

/* ---------- decisions ---------- */
function decide(f, decision, note) {
  getJSON('/api/shadow/findings/' + f.id + '/decision', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision: decision, reviewer: 'analyst@example.com', note: note || '' })
  }).then(function (d) {
    if (!d.ok) throw new Error('rejected');
    closeDrawer();
    var msg = decision === 'true_positive' ? 'Confirmed as a threat' : decision === 'false_positive' ? 'Dismissed' : 'Snoozed';
    if (d.allowlist_rule) msg += ' \u00b7 allowlist rule ' + d.allowlist_rule + ' added' +
      (d.also_hidden ? ', ' + d.also_hidden + ' more open finding(s) hidden' : '');
    else if (decision === 'false_positive') msg += ' \u00b7 no safe allowlist rule, review recorded only';
    if (d.sentinel_incident_id) msg += ' \u00b7 incident ' + d.sentinel_incident_id;
    toast(msg);
    loadFindings(); loadStats();
    if ($('allow').open) { S.alOffset = 0; $('rules').innerHTML = ''; loadRules(); }
  }).catch(function () { toast('Could not record the decision'); });
}

/* ---------- hunt ---------- */
$('hunt-btn').addEventListener('click', function () {
  var btn = this; btn.disabled = true; $('hunt-status').textContent = 'Hunting\u2026';
  getJSON('/api/shadow/hunt/run', { method: 'POST' }).then(function (d) {
    $('hunt-status').textContent = d.inserted + ' new \u00b7 ' + d.skipped_existing + ' already known';
    loadFindings(); loadStats();
  }).catch(function () {
    $('hunt-status').textContent = 'Hunt still running or failed \u2014 refresh in a minute';
  }).then(function () { btn.disabled = false; setTimeout(function () { $('hunt-status').textContent = ''; }, 12000); });
});

/* ---------- allowlist ---------- */
function loadRules() {
  getJSON('/api/shadow/allowlist?limit=25&offset=' + S.alOffset).then(function (d) {
    S.alTotal = d.total || 0;
    $('al-count').textContent = S.alTotal + ' rule' + (S.alTotal === 1 ? '' : 's');
    $('rules').insertAdjacentHTML('beforeend', (d.rules || []).map(function (r) {
      return '<div class="rule"><div class="nm">' + esc(r.name) +
          '<div class="src"><span class="pill">' + (r.source === 'ui' ? 'added in UI' : 'rules.yaml') + '</span>' +
          (r.source === 'ui' ? '<button type="button" class="linkish" data-del="' + esc(r.name) + '">Remove</button>' : '') + '</div></div>' +
        '<div class="why">' + esc(r.detector ? label(r.detector) : 'all detectors') + '</div>' +
        '<div class="mt">' + esc(JSON.stringify(r.match)) + '</div>' +
        '<div class="why">' + esc(r.reason) + (r.owner ? '<small>' + esc(r.owner) + (r.created_at ? ' \u00b7 ' + esc(ago(r.created_at)) : '') + '</small>' : '') + '</div></div>';
    }).join(''));
    S.alOffset += (d.rules || []).length;
    $('al-more').hidden = S.alOffset >= S.alTotal;
  }).catch(function () {});
}
$('allow').addEventListener('toggle', function () { if (this.open && !S.alOffset) loadRules(); });
$('al-more').addEventListener('click', loadRules);
$('rules').addEventListener('click', function (e) {
  var b = e.target.closest('[data-del]'); if (!b) return;
  var name = b.getAttribute('data-del');
  if (!confirm('Remove allowlist rule ' + name + '? The open findings it hid return to the queue.')) return;
  getJSON('/api/shadow/allowlist/' + encodeURIComponent(name), { method: 'DELETE' }).then(function (d) {
    toast('Rule removed' + (d.restored ? ' \u00b7 ' + d.restored + ' finding(s) back in the queue' : ''));
    S.alOffset = 0; $('rules').innerHTML = ''; loadRules(); loadFindings(); loadStats();
  }).catch(function () { toast('Could not remove the rule'); });
});
getJSON('/api/shadow/allowlist?limit=1').then(function (d) {
  $('al-count').textContent = (d.total || 0) + ' rule' + (d.total === 1 ? '' : 's');
}).catch(function () {});

/* ---------- stories ---------- */
function setView(v) {
  S.view = v;
  ['overview', 'lanes', 'queue', 'allow'].forEach(function (id) { $(id).hidden = v !== 'queue'; });
  document.querySelector('main > .toolbar').hidden = v !== 'queue';
  document.querySelector('.pager').hidden = v !== 'queue';
  $('stories').hidden = v !== 'stories';
  if (v === 'stories') loadStories();
}
$('seg-view').addEventListener('click', function (e) {
  var b = e.target.closest('button'); if (!b) return;
  Array.prototype.forEach.call(this.children, function (x) { x.classList.toggle('on', x === b); });
  setView(b.getAttribute('data-v'));
});
$('seg-story').addEventListener('click', function (e) {
  var b = e.target.closest('button'); if (!b) return;
  S.storyStatus = b.getAttribute('data-v');
  Array.prototype.forEach.call(this.children, function (x) { x.classList.toggle('on', x === b); });
  loadStories();
});
function hostChips(hosts) {
  return (hosts || []).slice(0, 4).map(function (h) {
    return '<span class="pill hostchip">' + esc(h.name) + ((h.ips || []).length ? ' \u00b7 ' + esc(h.ips[0]) : '') + '</span>';
  }).join('') + ((hosts || []).length > 4 ? '<span class="pill">+' + (hosts.length - 4) + '</span>' : '');
}
function storyRow(st, i) {
  var span = (st.first_seen || '').slice(0, 16).replace('T', ' ') + ' \u2192 ' + (st.last_seen || '').slice(0, 16).replace('T', ' ') + ' UTC';
  return '<li class="row" data-s="' + i + '"><span class="bar bg-' + esc(st.severity) + '"></span>' +
    '<div class="row-main"><div class="row-title">' + esc(st.title) + '</div><div class="row-meta">' +
      hostChips(st.hosts) + '<span>' + st.findings + ' finding' + (st.findings === 1 ? '' : 's') + '</span>' +
      (st.alerts ? '<span>' + st.alerts + ' Jira alert' + (st.alerts === 1 ? '' : 's') + '</span>' : '') +
      '<span class="pill">' + (st.report_version ? 'report v' + st.report_version : st.report_requested_at ? 'report requested' : 'no report') + '</span>' +
      (st.status !== 'open' ? '<span class="pill">' + esc(st.status) + '</span>' : '') +
      '<time title="' + esc(span) + '">' + esc(ago(st.updated_at)) + '</time></div></div>' +
    '<div class="row-side"><span class="sev s-' + esc(st.severity) + '">' + esc(st.severity) + '</span></div></li>';
}
function loadStories() {
  $('story-list').innerHTML = '<li class="skel"></li><li class="skel"></li>';
  getJSON('/api/shadow/stories?status=' + S.storyStatus + '&limit=100').then(function (d) {
    S.stories = d.stories || [];
    if (S.storyStatus === 'open') $('story-n').textContent = d.total ? String(d.total) : '';
    $('story-list').innerHTML = S.stories.length ? S.stories.map(storyRow).join('') :
      '<li class="empty"><b>No ' + (S.storyStatus === 'all' ? '' : S.storyStatus + ' ') + 'stories</b>Related findings are grouped here every 30 minutes.</li>';
  }).catch(function () { $('story-list').innerHTML = '<li class="empty"><b>Could not load stories</b>Check the session and reload.</li>'; });
}
$('story-list').addEventListener('click', function (e) {
  var li = e.target.closest('[data-s]'); if (!li) return;
  location.href = '/shadow/stories/' + encodeURIComponent(S.stories[+li.getAttribute('data-s')].id);
});
$('story-run').addEventListener('click', function () {
  var b = this; b.disabled = true;
  getJSON('/api/shadow/stories/run', { method: 'POST' }).then(function (d) {
    toast(d.started ? 'Rebuilding stories \u2014 refresh in a minute' : 'A build is already running');
  }).catch(function () { toast('Could not start the build'); }).then(function () { setTimeout(function () { b.disabled = false; loadStories(); }, 20000); });
});
function openStory(id) {
  getJSON('/api/shadow/stories/' + encodeURIComponent(id)).then(function (st) {
    S.open = null; S.openStory = st;
    $('d-head').innerHTML = '<span class="sev s-' + esc(st.severity) + '">' + esc(st.severity) + '</span><span class="det">Incident story</span>' +
      '<button class="x" type="button" aria-label="Close" id="d-close">&times;</button>';
    var hosts = (st.entities && st.entities.hosts) || [];
    var body = '<p class="d-title">' + esc(st.title) + '</p><div class="facts">' +
      fact('Status', esc(st.status) + (st.closed_by ? ' by ' + esc(st.closed_by) : '')) +
      fact('Findings', String(st.finding_ids.length)) +
      fact('First seen', esc(ist(st.first_seen))) + fact('Last seen', esc(ist(st.last_seen))) +
      ((st.related || []).length ? fact('Continues', (st.related || []).map(function (r) { return '<button class="linkish" data-open-story="' + esc(r) + '">earlier story</button>'; }).join(' '), true) : '') +
      '</div>';
    body += '<div class="sect"><label>Systems</label><div class="ev">' + (hosts.length ? hosts.map(function (h) {
      var other = (h.aliases || []).filter(function (a) { return a !== h.name; });
      return '<div class="ev-row"><div class="k">' + esc(h.name) + '</div><div class="v">' + esc((h.ips || []).join(', ') || 'no IP resolved') +
        (other.length ? '\nalso seen as ' + esc(other.join(', ')) : '') + '</div></div>';
    }).join('') : '<div class="ev-row"><div class="k">\u2014</div><div class="v">accounts: ' + esc((st.entities.accounts || []).join(', ')) + '</div></div>') + '</div></div>';
    var rep = st.report || {};
    body += '<div class="sect"><label>Report</label><div class="rep">' + ((rep.sections || []).length ? rep.sections.map(function (x) {
      return '<h4>' + esc(x.heading) + '</h4><p>' + esc(x.body) + '</p>';
    }).join('') + '<small>v' + esc(rep.version) + ' \u00b7 ' + esc(rep.by) + ' \u00b7 ' + esc(ago(rep.at)) + '</small>' :
      '<p>No written report yet. Ask for a Claude pass on this story; it reads the evidence bundle and posts the report here.</p>') + '</div></div>';
    body += '<div class="sect"><label>Timeline (UTC)</label>' + (st.timeline || []).map(function (t) {
      return '<div class="lin"><div class="l">' + esc((t.ts || '').slice(0, 19).replace('T', ' ')) + ' \u00b7 ' + esc(t.host) +
        ((t.ips || []).length ? ' (' + esc(t.ips.join(', ')) + ')' : '') + '</div><div class="c">' + esc(label(t.source)) + ' \u00b7 ' + esc(t.severity) + ' \u2014 ' + esc(t.event) + '</div></div>';
    }).join('') + '</div>';
    body += '<div class="sect"><label>Why these are grouped</label><div class="ev" style="padding:4px 12px">' + (st.edges || []).slice(0, 80).map(function (x) {
      return '<div class="edge"><b>' + esc(x.kind.replace('_', ' ')) + '</b> ' + esc(x.reason) + '</div>';
    }).join('') + '</div></div>';
    body += '<div class="sect"><label>Findings</label><div class="ev" style="padding:4px 12px">' + (st.members || []).map(function (f) {
      return '<div class="mem"><div><span class="sev s-' + esc(f.severity) + '">' + esc(f.severity) + '</span> ' + esc(label(f.detector)) +
        ' \u00b7 <span class="mono">' + esc(f.device_name) + '</span><br><span style="color:var(--fg-dim)">' + esc((f.summary || '').slice(0, 160)) + '</span></div>' +
        (st.status === 'open' ? '<button class="act" type="button" data-detach="' + esc(f.id) + '" title="Remove from this story; it never rejoins">Detach</button>' : '') + '</div>';
    }).join('') + '</div></div>';
    $('d-body').innerHTML = body; $('d-body').scrollTop = 0;
    $('d-foot').innerHTML = '<div class="btns"><a class="btn primary" href="/shadow/stories/' + encodeURIComponent(st.id) + '">Open story page</a>' +
      '<a class="btn" href="/shadow/stories/' + encodeURIComponent(st.id) + '/print" target="_blank" rel="noopener">Report PDF</a>' +
      (st.status === 'open' ? '<button class="btn" type="button" data-story-act="close">Close story</button>' :
       st.status === 'closed' ? '<button class="btn" type="button" data-story-act="reopen">Reopen</button>' : '') +
      '</div><p>A story only groups findings. Confirm or dismiss each finding in the queue.</p>';
    $('d-close').onclick = closeDrawer;
    $('drawer').classList.add('open'); $('drawer').setAttribute('aria-hidden', 'false'); $('scrim').classList.add('open');
  }).catch(function () { toast('Could not load the story'); });
}
function storyAction(action, extra) {
  var st = S.openStory; if (!st) return;
  getJSON('/api/shadow/stories/' + encodeURIComponent(st.id) + '/' + action, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(Object.assign({ actor: 'analyst@example.com' }, extra || {}))
  }).then(function () {
    toast(action === 'detach' ? 'Finding removed from the story' : action === 'close' ? 'Story closed' : 'Story reopened');
    if (action === 'detach') openStory(st.id); else closeDrawer();
    if (S.view === 'stories') loadStories(); else loadFindings();
  }).catch(function () { toast('Could not update the story'); });
}
$('d-body').addEventListener('click', function (e) {
  var d = e.target.closest('[data-detach]');
  if (d) { if (confirm('Remove this finding from the story? It will not be grouped into it again.')) storyAction('detach', { finding_id: d.getAttribute('data-detach') }); return; }
  var o = e.target.closest('[data-open-story]');
  if (o) openStory(o.getAttribute('data-open-story'));
});
$('d-foot').addEventListener('click', function (e) {
  var b = e.target.closest('[data-story-act]');
  if (b) storyAction(b.getAttribute('data-story-act'));
});
getJSON('/api/shadow/stories?status=open&limit=1').then(function (d) { $('story-n').textContent = d.total ? String(d.total) : ''; }).catch(function () {});

/* ---------- keyboard ---------- */
document.addEventListener('keydown', function (e) {
  if (e.target.closest && e.target.closest('input, select, textarea')) return;
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === 'Escape') { closeDrawer(); return; }
  if (S.view !== 'queue' || !S.rows.length) return;
  if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); select(Math.min(S.rows.length - 1, S.sel + 1)); if (S.open) openDrawer(S.rows[S.sel]); }
  else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); select(Math.max(0, S.sel - 1)); if (S.open) openDrawer(S.rows[S.sel]); }
  else if ((e.key === 'Enter' || e.key === 'o') && S.sel >= 0) { e.preventDefault(); openDrawer(S.rows[S.sel]); }
});

loadStats();
loadHealth();
loadFindings();
(function () {  // deep links from the story page: ?view=stories, ?finding=<id>
  var q = new URLSearchParams(location.search);
  if (q.get('view') === 'stories') { var sb = $('seg-view').querySelector('[data-v="stories"]'); if (sb) sb.click(); }
  if (q.get('finding')) getJSON('/api/shadow/findings/' + encodeURIComponent(q.get('finding'))).then(openDrawer)
    .catch(function () { toast('Could not open that finding'); });
})();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

class DecisionIn(BaseModel):
    decision: str       # true_positive | false_positive | snooze
    reviewer: str = "analyst"
    note: str = ""


@router.get("/api/shadow/stats")
async def shadow_stats():
    from shadow_hunter.models import Finding
    live = Finding.legacy != True  # noqa: E712 — matches rows without the field too
    total       = await Finding.find(live).count()
    unreviewed  = await Finding.find(live, Finding.reviewed_at == None, Finding.allowlisted_by_rule == "").count()  # noqa: E711
    allowlisted = await Finding.find(live, Finding.allowlisted_by_rule != "").count()
    reviewed    = await Finding.find(Finding.reviewed_at != None).count()  # noqa: E711
    tp_count    = await Finding.find(Finding.decision == "true_positive").count()
    fp_count    = await Finding.find(Finding.decision == "false_positive").count()
    legacy      = await Finding.find(Finding.legacy == True).count()  # noqa: E712

    pipeline = [
        {"$match": {"reviewed_at": None, "allowlisted_by_rule": "", "legacy": {"$ne": True}}},
        {"$group": {"_id": "$detector", "count": {"$sum": 1}}},
    ]
    coll = Finding.get_pymongo_collection()
    by_detector_raw = await coll.aggregate(pipeline).to_list(length=None)
    by_detector = {r["_id"]: r["count"] for r in by_detector_raw if r["_id"]}
    pipeline[1] = {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    by_severity = {r["_id"]: r["count"] for r in await coll.aggregate(pipeline).to_list(length=None) if r["_id"]}

    return {
        "total": total,
        "unreviewed": unreviewed,
        "reviewed": reviewed,
        "allowlisted": allowlisted,
        "true_positives": tp_count,
        "false_positives": fp_count,
        "legacy": legacy,
        "by_detector": by_detector,
        "by_severity": by_severity,
    }


@router.get("/api/shadow/findings")
async def shadow_list_findings(
    severity: Optional[str] = None,
    detector: Optional[str] = None,
    hide_allowlisted: bool = True,
    reviewed: str = "false",  # "false" | "true" | "all"
    include_legacy: bool = False,
    limit: int = 50,
    offset: int = 0,
    sort: str = "recent",  # "recent" | "priority" (severity, then behaviour score, then recency)
    ai: Optional[str] = None,  # "fp" | "attention" | "tp" | "unsure" | "none" (no suggestion yet)
    story: Optional[str] = None,  # findings grouped into this incident story
):
    from beanie.operators import In, NotIn
    from shadow_hunter.models import Finding
    conditions = []
    if ai == "attention":
        # FP or not, the AI flagged something to act on; never part of ai=fp
        conditions.append(NotIn(Finding.ai_attention, ["", None]))
    elif ai:
        want = {"fp": "false_positive", "tp": "true_positive", "unsure": "unsure", "none": ""}.get(ai)
        if want is None:
            raise HTTPException(400, "ai must be fp, tp, unsure or none")
        # older rows have no ai_verdict field at all; $in with null matches them
        conditions.append(In(Finding.ai_verdict, ["", None]) if not want else Finding.ai_verdict == want)
        if ai == "fp":
            conditions.append(In(Finding.ai_attention, ["", None]))
    if story:
        conditions.append(Finding.story_id == story)
    if not include_legacy:
        conditions.append(Finding.legacy != True)  # noqa: E712
    if severity:
        conditions.append(Finding.severity == severity)
    if detector:
        conditions.append(Finding.detector == detector)
    if hide_allowlisted:
        conditions.append(Finding.allowlisted_by_rule == "")
    if reviewed == "false":
        conditions.append(Finding.reviewed_at == None)  # noqa: E711
    elif reviewed == "true":
        conditions.append(Finding.reviewed_at != None)  # noqa: E711
    # "all" → no filter on reviewed_at

    total = await Finding.find(*conditions).count()
    if sort != "priority":
        findings = await Finding.find(*conditions).sort("-created_at").skip(offset).limit(limit).to_list()
        return {"findings": [_serialize(f) for f in findings], "total": total}
    # Newest-first buried the one high behaviour case on the incident day under 40 lower
    # findings. Severity is a string, so rank it in the pipeline; page by id, then load.
    rank = {"$switch": {"branches": [{"case": {"$eq": ["$severity", s]}, "then": i}
                                     for i, s in enumerate(_SEVERITY_ORDER)], "default": len(_SEVERITY_ORDER)}}
    pipeline = [{"$match": Finding.find(*conditions).get_filter_query()},
                {"$addFields": {"_rank": rank}},
                {"$sort": {"_rank": 1, "raw.score": -1, "created_at": -1}},
                {"$skip": offset}, {"$limit": limit}, {"$project": {"_id": 1}}]
    ids = [d["_id"] for d in await Finding.get_pymongo_collection().aggregate(pipeline).to_list(length=None)]
    by_id = {f.id: f for f in await Finding.find(In(Finding.id, ids)).to_list()}
    return {"findings": [_serialize(by_id[i]) for i in ids if i in by_id], "total": total}


_SEVERITY_ORDER = ("critical", "high", "medium", "low")


@router.get("/api/shadow/findings/{finding_id}")
async def shadow_get_finding(finding_id: str):
    from shadow_hunter.models import Finding
    f = await Finding.get(finding_id)
    if not f:
        raise HTTPException(404, "not found")
    return _serialize(f)


@router.post("/api/shadow/findings/{finding_id}/decision")
async def shadow_decide(finding_id: str, body: DecisionIn):
    from shadow_hunter.models import AuditLog, Finding
    from shadow_hunter.allowlist import AllowlistEngine

    f = await Finding.get(finding_id)
    if not f:
        raise HTTPException(404, "not found")
    if body.decision not in {"true_positive", "false_positive", "snooze"}:
        raise HTTPException(400, "invalid decision — must be true_positive, false_positive or snooze")

    sentinel_id = ""
    allowlist_rule_name = ""
    also_hidden = 0

    if body.decision == "true_positive":
        sentinel_id = await _get_sentinel().create_incident_from_finding(_serialize(f))

    elif body.decision == "false_positive":
        rule = AllowlistEngine.rule_from_finding(_serialize(f), body.reviewer, body.note)
        try:
            added = await AllowlistEngine.add_rule(rule)
            if added:
                allowlist_rule_name = added.name
                also_hidden = await AllowlistEngine.apply_to_open(added, exclude_id=f.id)
            else:
                logger.warning("No safe allowlist rule derivable from finding %s — review recorded only", finding_id)
        except Exception:
            logger.exception("Failed to store allowlist rule for finding %s", finding_id)

    from shadow_hunter.ai_triage import agreement
    f.decision = body.decision
    f.reviewed_by = body.reviewer
    f.reviewed_at = datetime.now(timezone.utc)
    f.sentinel_incident_id = sentinel_id
    f.note = body.note
    f.ai_agreed = agreement(f.ai_verdict, body.decision)
    await f.save()

    await AuditLog(
        actor=body.reviewer,
        action=f"decision.{body.decision}",
        target_type="finding",
        target_id=finding_id,
        payload={
            "sentinel_incident_id": sentinel_id,
            "allowlist_rule": allowlist_rule_name,
            "also_hidden": also_hidden,
            "note": body.note,
        },
    ).insert()

    return {"ok": True, "sentinel_incident_id": sentinel_id, "allowlist_rule": allowlist_rule_name,
            "also_hidden": also_hidden}


class AIVerdictIn(BaseModel):
    verdict: str        # true_positive | false_positive | unsure
    confidence: Optional[float] = None
    reasoning: str = ""
    evidence: list[str] = []
    by: str = "claude-code-manual"
    prompt_version: str = ""
    attention: str = ""  # non-empty: benign but needs follow-up; kept out of ai=fp


@router.post("/api/shadow/findings/{finding_id}/ai-verdict")
async def shadow_ai_verdict(finding_id: str, body: AIVerdictIn):
    """Record an AI suggestion. No side effects: the finding stays in the queue, nothing is
    allowlisted or escalated. An analyst accepting it goes through /decision as usual."""
    from shadow_hunter.ai_triage import record_verdict
    from shadow_hunter.models import Finding
    f = await Finding.get(finding_id)
    if not f:
        raise HTTPException(404, "not found")
    try:
        await record_verdict(f, body.verdict, body.confidence, body.reasoning, body.evidence, body.by,
                             body.prompt_version, body.attention)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return _serialize(f)


@router.post("/api/shadow/ai/run")
async def shadow_ai_run(limit: int = 3):
    """Suggest verdicts for up to `limit` open findings now, in the background (same caps as the
    scheduled job; works whether or not SHADOW_AI_TRIAGE is set, for trying it out)."""
    from shadow_hunter import ai_triage
    from shadow_hunter.scheduler import acquire_lease, release_lease

    async def go():
        if not await acquire_lease("ai_triage", 25 * 60):
            logger.info("[ai_triage] another run holds the lease")
            return
        try:
            logger.info("[ai_triage] manual run: %s", await ai_triage.run_batch(limit=max(1, min(limit, 10))))
        except Exception:
            logger.exception("[ai_triage] manual run failed")
        finally:
            await release_lease("ai_triage")
    import asyncio
    task = asyncio.create_task(go())
    _RUN_ONE_TASKS.add(task)  # hold a reference so the task is not GC'd mid-run
    task.add_done_callback(_RUN_ONE_TASKS.discard)
    return {"started": True, "limit": limit}


@router.post("/api/shadow/ai/compare")
async def shadow_ai_compare_start(limit: int = 40, resume: str = "", engine: str = "mistral", output: str = "short"):
    """Re-judge up to `limit` findings Claude already judged with the in-app Mistral agent, in
    the background, without changing them; read the outcome at GET /api/shadow/ai/compare/{run}.
    resume=<run id> continues that run, skipping the findings it already judged.
    engine=review runs the grouped-review pipeline instead (Mistral gathers, Opus decides;
    needs SHADOW_LLM=claude), output=short|full its reply length."""
    import asyncio
    import re as _re
    from shadow_hunter import ai_compare
    from shadow_hunter.scheduler import acquire_lease, release_lease
    if resume and not _re.fullmatch(r"[0-9T]{13}-[0-9a-f]{6}", resume):
        raise HTTPException(400, "resume must be a run id")
    run_id = resume or ai_compare.new_run_id()

    async def go():
        if not await acquire_lease("ai_compare", 60 * 60):
            await ai_compare.status(run_id, "not started", error="another comparison holds the lease")
            return
        try:
            logger.info("[ai_compare] %s", await ai_compare.run(
                run_id, limit=limit, engine="review" if engine == "review" else "mistral",
                output="full" if output == "full" else "short"))
        except Exception:
            logger.exception("[ai_compare] run %s failed", run_id)
        finally:
            await release_lease("ai_compare")
    task = asyncio.create_task(go())
    _RUN_ONE_TASKS.add(task)  # hold a reference so the task is not GC'd mid-run
    task.add_done_callback(_RUN_ONE_TASKS.discard)
    return {"started": True, "run": run_id, "poll": f"/api/shadow/ai/compare/{run_id}"}


@router.post("/api/shadow/stories/{story_id}/report/preview")
async def shadow_story_report_preview(story_id: str):
    """Write this story's report with the in-app Mistral backend, in the background, stored in
    shadow_ai_compare (never on the story). Read it at GET .../report/preview."""
    import asyncio
    from agent_core.backend import get_internal_backend
    from shadow_hunter import ai_compare, stories

    async def go():
        coll = ai_compare._db()[ai_compare.COLL]
        b = get_internal_backend()
        b.max_tokens = 8192
        try:
            out = await stories.preview_report(story_id, b, "ai:" + getattr(b, "model_id", "mistral"))
        except Exception as exc:
            out = {"story": story_id, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
        await coll.replace_one({"_id": f"story-preview:{story_id}"}, out, upsert=True)
    task = asyncio.create_task(go())
    _RUN_ONE_TASKS.add(task)
    task.add_done_callback(_RUN_ONE_TASKS.discard)
    return {"started": True}


@router.get("/api/shadow/stories/{story_id}/report/preview")
async def shadow_story_report_preview_get(story_id: str):
    from shadow_hunter import ai_compare
    d = await ai_compare._db()[ai_compare.COLL].find_one({"_id": f"story-preview:{story_id}"})
    if not d:
        raise HTTPException(404, "no preview yet")
    d.pop("_id", None)
    return d


@router.get("/api/shadow/ai/compare/{run_id}")
async def shadow_ai_compare_results(run_id: str):
    from shadow_hunter import ai_compare
    return await ai_compare.results(run_id)


@router.post("/api/shadow/person/run")
async def shadow_person_run(day: str):
    """Build person cases for one UTC day (YYYY-MM-DD) in the background. Days must be run in
    order for a case to see its earlier days."""
    import asyncio
    from datetime import date as _date
    from shadow_hunter.person import run_logged

    async def go():
        try:
            logger.info("[person] manual run %s: %s", day, await run_logged(_date.fromisoformat(day)))
        except Exception:
            logger.exception("[person] manual run %s failed", day)
    task = asyncio.create_task(go())
    _RUN_ONE_TASKS.add(task)
    task.add_done_callback(_RUN_ONE_TASKS.discard)
    return {"started": True, "day": day}


@router.get("/api/shadow/person/status")
async def shadow_person_status():
    """The last person-case runs: state, timings, cases written/updated, or the error."""
    from shadow_hunter.person import status
    return await status()


class StoryReportIn(BaseModel):
    sections: list[dict]            # [{heading, body}]
    by: str = "claude-code-manual"
    prompt_version: str = ""


class StoryActionIn(BaseModel):
    actor: str = "analyst@example.com"
    finding_id: str = ""
    other_id: str = ""


@router.get("/api/shadow/stories")
async def shadow_list_stories(status: str = "open", limit: int = 50, offset: int = 0, report: str = ""):
    """Incident stories, most recently changed first. status: open | closed | merged | all.
    report=requested: only stories waiting for a written report (the Claude pass's queue)."""
    from shadow_hunter.models import Story
    q = {} if status == "all" else {"status": status}
    if report == "requested":
        q["report_requested_at"] = {"$ne": None}
    total = await Story.find(q).count()
    rows = await Story.find(q).sort("-updated_at").skip(offset).limit(min(limit, 200)).to_list()
    return {"stories": [_serialize_story(s) for s in rows], "total": total}


@router.get("/api/shadow/stories/status")
async def shadow_stories_status():
    """The last story builds: state, timings, stories created/updated, or the error."""
    from shadow_hunter.stories import status
    return await status()


@router.post("/api/shadow/stories/run")
async def shadow_stories_run(enrich: bool = True):
    """Regroup findings into stories now, in the background, under the scheduled job's lease."""
    import asyncio
    from shadow_hunter.scheduler import acquire_lease, release_lease
    from shadow_hunter.stories import run_logged
    if not await acquire_lease("story_build", 25 * 60):
        return {"started": False, "reason": "a build is already running"}

    async def go():
        try:
            client = None
            if enrich:
                from shadow_hunter.clients.sentinel_logs import SentinelLogsClient
                client = SentinelLogsClient()
            logger.info("[stories] manual run: %s", await run_logged(client=client))
        except Exception:
            logger.exception("[stories] manual run failed")
        finally:
            await release_lease("story_build")
    task = asyncio.create_task(go())
    _RUN_ONE_TASKS.add(task)
    task.add_done_callback(_RUN_ONE_TASKS.discard)
    return {"started": True, "poll": "/api/shadow/stories/status"}


@router.get("/api/shadow/stories/{story_id}")
async def shadow_get_story(story_id: str):
    from beanie.operators import In
    from shadow_hunter.models import Finding, Story
    st = await Story.get(story_id)
    if not st:
        raise HTTPException(404, "not found")
    fs = await Finding.find(In(Finding.id, st.finding_ids)).to_list()
    return {**_serialize_story(st, full=True), "members": [_serialize(f) for f in fs]}


@router.get("/api/shadow/stories/{story_id}/bundle")
async def shadow_story_bundle(story_id: str):
    """Masked evidence bundle for writing the report (a Claude Code pass reads this)."""
    from shadow_hunter.stories import bundle
    b = await bundle(story_id)
    if b is None:
        raise HTTPException(404, "not found")
    return b


@router.post("/api/shadow/stories/{story_id}/report")
async def shadow_story_report(story_id: str, body: StoryReportIn):
    """Store a written report on a story. Secrets and 12-digit ids are redacted on the way in;
    the previous five versions are kept."""
    from shadow_hunter.stories import set_report
    try:
        return await set_report(story_id, body.sections, body.by, body.prompt_version)
    except LookupError:
        raise HTTPException(404, "not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


class ReportRequestIn(BaseModel):
    actor: str = "analyst"


@router.post("/api/shadow/stories/{story_id}/report/request")
async def shadow_story_report_request(story_id: str, body: ReportRequestIn, request: Request):
    """'Get report': written in-app when a writer is enabled, otherwise queued for a Claude pass
    and the prompt to run it is returned."""
    from shadow_hunter.stories import request_report
    try:
        return await request_report(story_id, body.actor, str(request.base_url))
    except LookupError:
        raise HTTPException(404, "not found")


class IndicatorIn(BaseModel):
    value: str
    note: str = ""
    actor: str = "analyst"


@router.post("/api/shadow/stories/{story_id}/indicators")
async def shadow_story_add_indicator(story_id: str, body: IndicatorIn):
    """Add an indicator (a public IP or one token) the story's findings do not carry; the
    context refresh looks it up at the edge and in other logs."""
    from shadow_hunter.stories import add_indicator
    try:
        return await add_indicator(story_id, body.value, body.note, body.actor)
    except LookupError:
        raise HTTPException(404, "not found")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post("/api/shadow/stories/{story_id}/indicators/remove")
async def shadow_story_remove_indicator(story_id: str, body: IndicatorIn):
    from shadow_hunter.stories import remove_indicator
    try:
        return await remove_indicator(story_id, body.value, body.actor)
    except LookupError:
        raise HTTPException(404, "not found")


@router.post("/api/shadow/stories/{story_id}/context/refresh")
async def shadow_story_context_refresh(story_id: str, vlogs: bool = True):
    """Re-fetch the story's related Jira alerts and VictoriaLogs context now, in the background
    (a few minutes for a large story). The scheduled refresh runs every 30 minutes."""
    import asyncio
    from shadow_hunter.models import Story
    from shadow_hunter.story_context import refresh
    if not await Story.get(story_id):
        raise HTTPException(404, "not found")

    async def go():
        try:
            logger.info("[story_context] manual refresh: %s", await refresh(story_id, vlogs=vlogs))
        except Exception:
            logger.exception("[story_context] manual refresh of %s failed", story_id)
    task = asyncio.create_task(go())
    _RUN_ONE_TASKS.add(task)  # hold a reference so the task is not GC'd mid-run
    task.add_done_callback(_RUN_ONE_TASKS.discard)
    return {"started": True}


@router.post("/api/shadow/stories/{story_id}/{action}")
async def shadow_story_action(story_id: str, action: str, body: StoryActionIn):
    """detach (finding_id) | merge (other_id) | close | reopen. Never touches a finding's decision."""
    from shadow_hunter import stories
    try:
        if action == "detach":
            return await stories.detach(story_id, body.finding_id, body.actor)
        if action == "merge":
            return await stories.merge(story_id, body.other_id, body.actor)
        if action in ("close", "reopen"):
            return await stories.set_status(story_id, "closed" if action == "close" else "open", body.actor)
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    raise HTTPException(400, "action must be detach, merge, close or reopen")


async def _story_and_findings(story_id: str):
    from beanie.operators import In
    from shadow_hunter.models import Finding, Story
    st = await Story.get(story_id)
    if not st:
        raise HTTPException(404, "not found")
    return st, await Finding.find(In(Finding.id, st.finding_ids)).to_list()


@router.get("/shadow/stories/{story_id}", response_class=HTMLResponse, include_in_schema=False)
async def shadow_story_page(story_id: str):
    """One page with everything about the incident (app/views/story_page.py)."""
    from app.views.story_page import render_story_page
    return HTMLResponse(render_story_page(*await _story_and_findings(story_id)))


@router.get("/shadow/stories/{story_id}/print", response_class=HTMLResponse, include_in_schema=False)
async def shadow_story_print(story_id: str):
    """The incident report in the v5 layout; the browser's Save as PDF makes the file."""
    from app.views.story_page import render_story_report
    return HTMLResponse(render_story_report(*await _story_and_findings(story_id)))


@router.get("/api/shadow/upwind/status")
async def shadow_upwind_status():
    """What the Upwind mirror holds and its last syncs (edr_triage/upwind_mirror.py)."""
    from edr_triage.upwind_mirror import status
    return await status()


@router.post("/api/shadow/upwind/sync")
async def shadow_upwind_sync(full: bool = False):
    """Refresh the Upwind mirror now, in the background, under the same lease as the
    scheduled sync (so it never overlaps one). Poll /api/shadow/upwind/status."""
    import asyncio
    from shadow_hunter.scheduler import _upwind_sync_job
    task = asyncio.create_task(_upwind_sync_job(full, force=True))
    _RUN_ONE_TASKS.add(task)  # hold a reference so the task is not GC'd mid-run
    task.add_done_callback(_RUN_ONE_TASKS.discard)
    return {"started": True, "full": full, "poll": "/api/shadow/upwind/status"}


@router.post("/api/shadow/ai/reset")
async def shadow_ai_reset(ids: str, reason: str = ""):
    """Clear the AI suggestion on the given findings (comma-separated ids) so the agent judges
    them again — e.g. after a prompt or rule fix. Reviewed findings and human decisions are not
    touched. Audited."""
    from shadow_hunter.models import AuditLog, Finding
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    if not id_list:
        raise HTTPException(400, "ids required")
    res = await Finding.get_pymongo_collection().update_many(
        {"_id": {"$in": id_list}, "reviewed_at": None},
        {"$set": {"ai_verdict": "", "ai_confidence": None, "ai_reasoning": "", "ai_evidence": [], "ai_by": "",
                  "ai_at": None, "ai_error": "", "ai_attempts": 0, "ai_attention": ""}})
    await AuditLog(actor="admin", action="ai_verdict.reset", target_type="finding", target_id=",".join(id_list)[:500],
                   payload={"reset": res.modified_count, "reason": reason}).insert()
    return {"ok": True, "reset": res.modified_count}


_LLM_HINTS = [
    ("on-demand throughput", "Use an inference-profile id (apac.anthropic.… or global.anthropic.…), not the bare model id."),
    ("model identifier is invalid", "SHADOW_CLAUDE_MODEL is not a model or inference-profile id this region knows; list them with "
                                    "`aws bedrock list-inference-profiles --region ap-south-1`."),
    ("use case", "Submit Anthropic's one-time use-case form in the Bedrock console (Model access), then retry."),
    ("don't have access to the model", "Enable the model under Bedrock → Model access in this account."),
    ("not authorized", "The pod role needs bedrock:InvokeModel on the inference profile ARN AND on the foundation-model ARNs "
                       "in every region the profile routes to."),
    ("accessdenied", "The pod role needs bedrock:InvokeModel on the inference profile ARN AND on the foundation-model ARNs "
                     "in every region the profile routes to (or model access is not granted)."),
    ("budget exceeded", "The shadow budget (SHADOW_CLAUDE_MONTHLY_BUDGET_USD) is used up for this month."),
    ("is not set", "Set SHADOW_CLAUDE_MODEL."),
    ("anthropic package", "The Mantle transport needs the `anthropic` package in the image; or use SHADOW_CLAUDE_TRANSPORT=runtime."),
]


@router.get("/api/shadow/llm-check")
async def shadow_llm_check():
    """Diagnostic: can /shadow reach its model? Sends one tiny prompt through get_shadow_backend()
    and reports the model, transport, the shadow budget, and a hint when the call fails."""
    import os
    from agent_core import budget
    from agent_core.backend import get_shadow_backend, shadow_llm, shadow_model_id
    out: dict = {"llm": shadow_llm(), "model": shadow_model_id(), "region": os.getenv("AWS_REGION", "ap-south-1"),
                 "transport": os.getenv("SHADOW_CLAUDE_TRANSPORT", "runtime") if shadow_llm() == "claude" else "internal",
                 "ai_triage_on": os.getenv("SHADOW_AI_TRIAGE", "0").lower() in ("1", "true", "yes", "on"),
                 "story_reports_on": os.getenv("SHADOW_STORY_REPORTS", "0").lower() in ("1", "true", "yes", "on"),
                 "ok": False}
    try:
        import asyncio
        out["budget"] = await asyncio.to_thread(budget.summary, "shadow" if shadow_llm() == "claude" else "agent")
    except Exception as exc:
        out["budget_error"] = str(exc)[:200]
    try:
        b = get_shadow_backend()
        out["backend"] = type(b).__name__
        text, _ = await b.chat([{"role": "user", "content": "Reply with the single word: OK"}], [])
        out["ok"], out["reply"] = True, (text or "").strip()[:80]
    except Exception as exc:
        msg = str(exc)
        out["error"] = msg[:600]
        low = msg.lower()
        out["hint"] = next((h for k, h in _LLM_HINTS if k in low), "")
    logger.info("SHADOW-LLM-CHECK %s", {k: v for k, v in out.items() if k != "budget"})
    return out


@router.get("/api/shadow/ai/stats")
async def shadow_ai_stats():
    from shadow_hunter.ai_triage import stats
    from shadow_hunter.models import Finding
    return await stats(Finding.get_pymongo_collection())


@router.get("/api/shadow/allowlist")
async def shadow_allowlist(limit: int = 25, offset: int = 0):
    from shadow_hunter.config import get_shadow_config
    from shadow_hunter.allowlist import AllowlistEngine
    engine = await AllowlistEngine.load_all(get_shadow_config().allowlist_path)
    all_rules = [
        {
            "name": r.name,
            "detector": r.detector,
            "match": r.match,
            "reason": r.reason,
            "owner": r.owner,
            "source": r.source,
            "created_at": r.created_at,
        }
        for r in engine.rules
    ]
    total = len(all_rules)
    page_rules = all_rules[offset: offset + limit]
    return {"rules": page_rules, "total": total, "offset": offset, "limit": limit}


@router.delete("/api/shadow/allowlist/{name}")
async def shadow_delete_allowlist_rule(name: str):
    """Delete a rule added from the UI; the unreviewed findings it hid return to the queue.
    rules.yaml rules change through the repo, not here."""
    from shadow_hunter.allowlist import AllowlistEngine
    from shadow_hunter.models import AuditLog
    out = await AllowlistEngine.delete_rule(name)
    if not out["deleted"]:
        raise HTTPException(404, "no UI rule with that name (repo rules live in rules.yaml)")
    await AuditLog(actor="analyst", action="allowlist.delete", target_type="allowlist_rule",
                   target_id=name, payload=out).insert()
    return {"ok": True, **out}


@router.post("/api/shadow/hunt/run")
async def shadow_run_hunt():
    from shadow_hunter.hunter import run_all
    result = await run_all()
    return result


@router.delete("/api/shadow/findings")
async def shadow_clear_findings():
    """Fresh-restart the threat hunting shadow — deletes every Finding.

    Audit log and allowlist rules are untouched; only shadow_findings is wiped.
    """
    from shadow_hunter.models import Finding
    result = await Finding.delete_all()
    return {"ok": True, "deleted": result.deleted_count if result else 0}


_BEHAVIOR_TASKS: set = set()


@router.post("/api/shadow/behavior/run")
async def shadow_behavior_run(day: str, build: bool = True, score: bool = True):
    """Start a build (one fleet-day MDE scan) and/or score of one UTC day, YYYY-MM-DD, in the
    background and return at once — a fleet-day scan outlasts the ~50s ingress timeout.
    Poll GET /api/shadow/behavior/status. To seed history, build the previous HISTORY_DAYS
    days with score=false, one at a time, oldest first, a few minutes apart (the MDE hunting
    quota is shared with RAPTOR). Scoring refuses (warming_up) until that history exists."""
    import asyncio
    from datetime import date as _date
    from shadow_hunter import behavior
    d = _date.fromisoformat(day)
    if await behavior.is_running(d):
        return {"started": False, "reason": f"{day} is already running"}
    task = asyncio.create_task(behavior.run_logged(d, build, score))
    _BEHAVIOR_TASKS.add(task)  # hold a reference so the task is not GC'd mid-run
    task.add_done_callback(_BEHAVIOR_TASKS.discard)
    return {"started": True, "day": day, "build": build, "score": score,
            "poll": "/api/shadow/behavior/status"}


@router.get("/api/shadow/behavior/scores")
async def shadow_behavior_scores(day: Optional[str] = None, limit: int = 100):
    """Every ranked device for a scored day (default latest), low scores included."""
    from shadow_hunter import behavior
    return await behavior.scores(day, min(limit, 500))


@router.get("/api/shadow/detectors/status")
async def shadow_detector_status():
    """Last run of each detector: ok or the error, rows, when it last succeeded. A detector
    whose source is unreachable finds nothing — this is what tells that apart from quiet."""
    from shadow_hunter.detectors import DETECTORS
    from shadow_hunter.hunter import RUNS_COLL
    from shadow_hunter.models import Finding
    runs = {r["detector"]: r for r in await Finding.get_pymongo_collection().database[RUNS_COLL]
            .find({}, {"_id": 0}).to_list(length=None)}
    return {"detectors": [{"detector": d.name, "cadence_minutes": d.cadence_minutes,
                           **runs.get(d.name, {"last_run": None, "ok": None})} for d in DETECTORS]}


_RUN_ONE_TASKS: set = set()


@router.post("/api/shadow/hunt/run-one")
async def shadow_run_one(detector: str, force: bool = False):
    """Run one detector now, in the background, through its usual lease. force=true clears a
    lease left behind by a run that died with its pod (it would otherwise block the detector
    until it expires). Poll GET /api/shadow/detectors/status."""
    import asyncio
    from shadow_hunter.detectors import DETECTORS
    from shadow_hunter.models import Finding
    from shadow_hunter.scheduler import LOCK_COLL, _job
    det = next((d for d in DETECTORS if d.name == detector), None)
    if not det:
        raise HTTPException(404, f"no detector {detector}")
    locks = Finding.get_pymongo_collection().database[LOCK_COLL]
    lease = await locks.find_one({"_id": f"detector:{detector}"}, {"_id": 0})
    if force:
        await locks.delete_one({"_id": f"detector:{detector}"})
    task = asyncio.create_task(_job(det))
    _RUN_ONE_TASKS.add(task)
    task.add_done_callback(_RUN_ONE_TASKS.discard)
    return {"started": True, "detector": detector, "previous_lease": lease, "lease_cleared": force,
            "poll": "/api/shadow/detectors/status"}


@router.get("/api/shadow/admin/egress-check")
async def shadow_egress_check():
    """Can this pod reach what the detectors call? One small request each, 8 s cap."""
    import time
    import httpx
    from shadow_hunter.config import get_shadow_config
    targets = {"osv": ("POST", "https://api.osv.dev/v1/querybatch",
                       {"queries": [{"package": {"ecosystem": "npm", "name": "lodahs"}}]}),
               "npm": ("GET", "https://registry.npmjs.org/lodahs", None),
               "pypi": ("GET", "https://pypi.org/pypi/requests/json", None)}
    out = {}
    async with httpx.AsyncClient(timeout=8, verify=get_shadow_config().ssl_verify) as client:
        for name, (method, url, body) in targets.items():
            t = time.monotonic()
            try:
                r = await client.request(method, url, json=body)
                out[name] = {"status": r.status_code, "ms": round((time.monotonic() - t) * 1000),
                             "looks_like": "json" if r.headers.get("content-type", "").startswith("application/json")
                             else r.headers.get("content-type", "")[:40]}
            except Exception as exc:
                out[name] = {"error": f"{type(exc).__name__}: {str(exc)[:160]}", "ms": round((time.monotonic() - t) * 1000)}
    return out


@router.get("/api/shadow/behavior/status")
async def shadow_behavior_status():
    from shadow_hunter import behavior
    return await behavior.status()


@router.post("/api/shadow/admin/mark-legacy")
async def shadow_mark_legacy(before: Optional[str] = None, detector: Optional[str] = None,
                             severity: Optional[str] = None, ids: Optional[str] = None,
                             reason: str = ""):
    """Retire the pre-revamp backlog without deleting it: every UNREVIEWED finding created
    before `before` (ISO datetime, default now) is marked legacy — hidden from the queue and
    the stats, excluded from dedup, kept for replay. Reviewed findings are left alone.
    Idempotent: re-running only touches rows not already marked. `detector` limits it to one
    detector (e.g. retiring entity_behavior cases written by an older scoring version), and
    `severity` to one severity (e.g. the low behaviour cases the queue no longer takes), and
    `ids` (comma-separated finding ids) to exactly those findings — noise a detector fix has
    since removed. Every call is audited."""
    from shadow_hunter.models import AuditLog, Finding
    cutoff = datetime.fromisoformat(before.replace("Z", "+00:00")) if before else datetime.now(timezone.utc)
    query = {"reviewed_at": None, "legacy": {"$ne": True}, "created_at": {"$lt": cutoff}}
    if detector:
        query["detector"] = detector
    if severity:
        query["severity"] = severity
    id_list = [i.strip() for i in (ids or "").split(",") if i.strip()]
    if id_list:
        query["_id"] = {"$in": id_list}
        if not before:
            query.pop("created_at")          # explicit ids need no time bound
    result = await Finding.get_pymongo_collection().update_many(query, {"$set": {"legacy": True}})
    logger.info("[shadow] marked %d findings legacy (before %s)", result.modified_count, cutoff.isoformat())
    await AuditLog(actor="admin", action="mark_legacy", target_type="finding", target_id=",".join(id_list)[:500],
                   payload={"marked": result.modified_count, "before": cutoff.isoformat(), "detector": detector,
                            "severity": severity, "reason": reason}).insert()
    return {"ok": True, "marked_legacy": result.modified_count, "before": cutoff.isoformat(),
            "detector": detector, "severity": severity}


@router.get("/api/shadow/process-tree/{finding_id}")
async def shadow_process_tree(finding_id: str):
    from shadow_hunter.models import Finding
    f = await Finding.get(finding_id)
    if not f:
        raise HTTPException(404, "not found")

    raw = f.raw or {}
    procs = raw.get("InitiatingProcesses") or []
    if isinstance(procs, str):
        procs = [procs]

    initiating = procs[0] if procs else "explorer.exe"
    child = (
        raw.get("FileName")
        or (raw.get("ProcessCommandLine", "").split()[0] if raw.get("ProcessCommandLine") else None)
        or (f.indicator.split("→")[-1] if "→" in f.indicator else "unknown.exe")
    )

    tree = {
        "pid": 4,
        "name": "System",
        "cmdline": "",
        "children": [{
            "pid": 812,
            "name": "svchost.exe",
            "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
            "children": [{
                "pid": 2240,
                "name": initiating,
                "cmdline": initiating,
                "children": [{
                    "pid": 6144,
                    "name": child,
                    "cmdline": (
                        raw.get("ProcessCommandLine")
                        or (raw.get("SampleCommandLines", [""])[0]
                            if isinstance(raw.get("SampleCommandLines"), list) else child)
                    ),
                    "highlight": True,
                    "children": [],
                }],
            }],
        }],
    }
    return {"finding_id": finding_id, "device": f.device_name, "tree": tree}


# ---------------------------------------------------------------------------
# Serializer
# ---------------------------------------------------------------------------

def _serialize(f) -> dict:
    return {
        "id": f.id,
        "detector": f.detector,
        "severity": f.severity,
        "device_id": f.device_id,
        "device_name": f.device_name,
        "account_name": f.account_name,
        "indicator": f.indicator,
        "summary": f.summary,
        "raw": f.raw,
        "mitre_techniques": f.mitre_techniques,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "reviewed_at": f.reviewed_at.isoformat() if f.reviewed_at else None,
        "reviewed_by": f.reviewed_by,
        "decision": f.decision,
        "note": f.note,
        "sentinel_incident_id": f.sentinel_incident_id,
        "allowlisted_by_rule": f.allowlisted_by_rule,
        "ai_verdict": f.ai_verdict,
        "ai_confidence": f.ai_confidence,
        "ai_reasoning": f.ai_reasoning,
        "ai_evidence": f.ai_evidence,
        "ai_by": f.ai_by,
        "ai_at": f.ai_at.isoformat() if f.ai_at else None,
        "ai_error": f.ai_error,
        "ai_agreed": f.ai_agreed,
        "ai_attention": f.ai_attention,
        "story_id": getattr(f, "story_id", "") or "",
    }


def _serialize_story(st, full: bool = False) -> dict:
    out = {
        "id": st.id, "title": st.title, "status": st.status, "severity": st.severity,
        "first_seen": st.first_seen.isoformat() if st.first_seen else None,
        "last_seen": st.last_seen.isoformat() if st.last_seen else None,
        "created_at": st.created_at.isoformat() if st.created_at else None,
        "updated_at": st.updated_at.isoformat() if st.updated_at else None,
        "hosts": [{"name": h.get("name"), "ips": h.get("ips", [])} for h in (st.entities or {}).get("hosts", [])],
        "accounts": (st.entities or {}).get("accounts", []),
        "findings": len(st.finding_ids),
        "report_version": (st.report or {}).get("version", 0),
        "report_requested_at": st.report_requested_at.isoformat() if st.report_requested_at else None,
        "context_at": st.context_at.isoformat() if st.context_at else None,
        "alerts": len((st.context or {}).get("alerts", [])),
        "related": st.related, "merged_into": st.merged_into,
    }
    if full:
        out.update({"entities": st.entities, "edges": st.edges, "timeline": st.timeline, "report": st.report,
                    "finding_ids": st.finding_ids, "detached": st.detached, "closed_by": st.closed_by})
    return out

