#!/usr/bin/env python3
"""Generate the AI-vs-analyst accuracy-over-time chart from the shadow record.

Reads scored ShadowResults from MongoDB (verdict_match set), orders them by close time,
and plots cumulative accuracy as verdicts accrue — the "does it actually get it right, and
does that hold as memory grows" slide. Writes a self-contained SVG (no plotting libraries).

    python demo/accuracy_chart.py            # -> docs/accuracy-over-time.svg

Uses MONGODB_URI / MONGODB_DB (defaults: localhost / deepintel).
"""
from __future__ import annotations

import os
from pymongo import MongoClient

URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB = os.getenv("MONGODB_DB", "deepintel")
OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "accuracy-over-time.svg")


def _series():
    db = MongoClient(URI, serverSelectionTimeoutMS=4000)[DB]
    rows = list(db["eg_shadow_results"].find(
        {"verdict_match": {"$in": [True, False]}},
        {"verdict_match": 1, "created_at": 1},
    ))
    rows.sort(key=lambda r: r.get("created_at") or 0)
    pts, hits = [], 0
    for i, r in enumerate(rows, 1):
        hits += 1 if r.get("verdict_match") else 0
        pts.append((i, round(100 * hits / i, 1)))
    return pts


def _svg(pts) -> str:
    W, H = 760, 380
    ml, mr, mt, mb = 56, 24, 46, 52
    pw, ph = W - ml - mr, H - mt - mb
    n = len(pts)
    def X(i): return ml + (pw * (i - 1) / max(n - 1, 1))
    def Y(a): return mt + ph * (1 - a / 100.0)

    grid = "".join(
        f'<line x1="{ml}" y1="{Y(v):.1f}" x2="{ml+pw}" y2="{Y(v):.1f}" stroke="#1c232e" stroke-width="1"/>'
        f'<text x="{ml-10}" y="{Y(v)+4:.1f}" text-anchor="end" fill="#59616e" font-size="11" font-family="ui-monospace,Menlo,monospace">{v}%</text>'
        for v in range(0, 101, 20)
    )
    line = "M" + " L".join(f"{X(i):.1f} {Y(a):.1f}" for i, a in pts)
    area = f"M{ml} {mt+ph} L" + " L".join(f"{X(i):.1f} {Y(a):.1f}" for i, a in pts) + f" L{ml+pw} {mt+ph} Z"
    dots = "".join(
        f'<circle cx="{X(i):.1f}" cy="{Y(a):.1f}" r="3.2" fill="#9E86F0" stroke="#0c1116" stroke-width="1.5"/>'
        for i, a in pts
    )
    final = pts[-1][1] if pts else 0
    last_x, last_y = X(n), Y(final)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="Segoe UI, Helvetica, Arial, sans-serif">
  <defs><linearGradient id="a" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#9E86F0" stop-opacity="0.28"/><stop offset="1" stop-color="#9E86F0" stop-opacity="0"/></linearGradient></defs>
  <rect width="{W}" height="{H}" rx="12" fill="#0c1116"/>
  <text x="{ml}" y="26" fill="#e6edf3" font-size="14" font-weight="700">AI vs. analyst agreement, cumulative</text>
  <text x="{ml}" y="42" fill="#59616e" font-size="11">accuracy over the closed-ticket record ({n} scored verdicts)</text>
  {grid}
  <path d="{area}" fill="url(#a)"/>
  <path d="{line}" fill="none" stroke="#9E86F0" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>
  {dots}
  <circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="5" fill="#46B87A" stroke="#0c1116" stroke-width="2"/>
  <text x="{last_x-8:.1f}" y="{last_y-12:.1f}" text-anchor="end" fill="#46B87A" font-size="13" font-weight="700">{final}%</text>
  <text x="{ml}" y="{H-18}" fill="#59616e" font-size="11" font-family="ui-monospace,Menlo,monospace">oldest closure</text>
  <text x="{ml+pw}" y="{H-18}" text-anchor="end" fill="#59616e" font-size="11" font-family="ui-monospace,Menlo,monospace">most recent →</text>
</svg>
'''


def main():
    pts = _series()
    if not pts:
        print("No scored ShadowResults found — seed the demo first (python demo/seed_demo.py).")
        return
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(_svg(pts))
    print(f"Wrote {os.path.normpath(OUT)} — {len(pts)} scored verdicts, final {pts[-1][1]}% cumulative accuracy.")


if __name__ == "__main__":
    main()
