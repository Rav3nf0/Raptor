"""The RAPTOR left rail (pages + Settings + Sign out) for pages with their own design.

Self-contained: fixed to the left edge, own class names and colours, so it can be
dropped into /dashboard and /shadow without touching their styles. `with_rail()`
inserts it right after <body ...> and shifts the body right (margin, so the
page keeps its own padding) so nothing sits under it.
"""
from __future__ import annotations

import re

_W = 66  # same width as the RAPTOR rail

_ICON = {
    "triage": '<path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"/>',
    "memory": '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
    "dashboard": '<path d="M3 12l9-9 9 9M5 10v10h14V10"/>',
    "shadow": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1" fill="currentColor"/>',
    "settings": '<path d="M12 15a3 3 0 100-6 3 3 0 000 6z"/><path d="M19 12a7 7 0 00-.1-1l2-1.6-2-3.4-2.4 1a7 7 0 00-1.7-1L14.5 2h-5l-.3 2.9a7 7 0 00-1.7 1l-2.4-1-2 3.4L3.1 11a7 7 0 000 2l-2 1.6 2 3.4 2.4-1a7 7 0 001.7 1L9.5 22h5l.3-2.9a7 7 0 001.7-1l2.4 1 2-3.4-2-1.6a7 7 0 00.1-1z"/>',
    "signout": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
}
_PAGES = [("triage", "/edr-triage", "Triage Console"), ("memory", "/memory/quarantine", "AI Memory"),
          ("dashboard", "/dashboard", "Dashboard"), ("shadow", "/shadow", "Threat Hunting")]

# Colours per theme: purple matches RAPTOR, cyan matches /shadow.
_THEMES = {
    "purple": dict(bg1="#0C1116", bg2="#090C10", line="#252B36", s1="#12151B", s2="#181C24", s3="#1E2430",
                   faint="#59616E", dim="#8E96A4", text="#DDE1E8",
                   accent="#9E86F0", deep="#5B3FB0", glow="rgba(158,134,240,0.12)"),
    "cyan": dict(bg1="#0B1517", bg2="#081113", line="#1D3439", s1="#0D191C", s2="#112226", s3="#172D32",
                 faint="#52706C", dim="#86A19E", text="#D3E2E0",
                 accent="#45D3C2", deep="#1C6F66", glow="rgba(69,211,194,0.10)"),
}

_CSS = f"""<style>
  .di-rail {{ position: fixed; top: 0; left: 0; bottom: 0; width: {_W}px; z-index: 25;
    display: flex; flex-direction: column; align-items: center; gap: 6px; padding: 16px 0;
    background: linear-gradient(180deg, var(--di-bg1), var(--di-bg2)); border-right: 1px solid var(--di-line);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, system-ui, sans-serif; box-sizing: border-box; }}
  .di-rail .di-glyph {{ width: 38px; height: 38px; border-radius: 11px; display: grid; place-items: center; margin-bottom: 14px;
    background: linear-gradient(160deg, var(--di-s3), var(--di-s1)); border: 1px solid var(--di-line); color: var(--di-accent); }}
  .di-rail .di-glyph svg {{ width: 20px; height: 20px; }}
  .di-rail .di-btn {{ width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; color: var(--di-faint);
    position: relative; transition: .16s; border: 1px solid transparent; background: transparent; padding: 0; margin: 0;
    cursor: pointer; text-decoration: none; -webkit-appearance: none; appearance: none; }}
  .di-rail .di-btn svg {{ width: 19px; height: 19px; }}
  .di-rail .di-btn:hover {{ color: var(--di-dim); background: var(--di-s2); }}
  .di-rail .di-btn.on {{ color: var(--di-accent); background: var(--di-glow); border-color: var(--di-deep); }}
  .di-rail .di-spacer {{ flex: 1; }}
  .di-rail form {{ margin: 0; }}
  .di-rail .di-tip {{ position: absolute; left: 52px; white-space: nowrap; background: var(--di-s3); border: 1px solid var(--di-line);
    color: var(--di-text); font-size: 12px; line-height: 1.2; padding: 5px 9px; border-radius: 8px; opacity: 0; pointer-events: none;
    transform: translateX(-4px); transition: .14s; }}
  .di-rail .di-btn:hover .di-tip {{ opacity: 1; transform: translateX(0); }}
  body.di-has-rail {{ margin-left: {_W}px !important; }}
</style>"""


def _svg(name: str) -> str:
    return ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" '
            f'stroke-linecap="round" stroke-linejoin="round">{_ICON[name]}</svg>')


def _theme_vars(theme: str) -> str:
    t = _THEMES.get(theme, _THEMES["purple"])
    return "".join(f"--di-{k}:{v};" for k, v in t.items())


def rail_html(active: str = "", theme: str = "purple") -> str:
    links = "".join(
        f'<a class="di-btn{" on" if key == active else ""}" href="{href}">{_svg(key)}<span class="di-tip">{tip}</span></a>'
        for key, href, tip in _PAGES)
    return (
        _CSS
        + f'<aside class="di-rail" aria-label="Navigation" style="{_theme_vars(theme)}">'
        + '<div class="di-glyph"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" '
          'stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 L20 7 L17 14 C15.5 18 12 22 12 22 '
          'C12 22 8.5 18 7 14 L4 7 Z"/><path d="M12 8 L12 15 M9 11 L12 8 L15 11"/></svg></div>'
        + links
        + '<div class="di-spacer"></div>'
        + f'<a class="di-btn{" on" if active == "settings" else ""}" href="/settings">{_svg("settings")}<span class="di-tip">Settings</span></a>'
        + f'<form method="POST" action="/logout"><button class="di-btn" type="submit">{_svg("signout")}'
          '<span class="di-tip">Sign out</span></button></form>'
        + '</aside>'
    )


_BODY = re.compile(r"<body\b([^>]*)>", re.IGNORECASE)


def with_rail(page: str, active: str = "", theme: str = "purple") -> str:
    """Insert the rail after <body> and tag the body so it is padded clear of it."""
    m = _BODY.search(page)
    if not m:
        return page
    attrs = m.group(1)
    cls = re.search(r'class="([^"]*)"', attrs)
    if cls:
        attrs = attrs[:cls.start()] + f'class="{cls.group(1)} di-has-rail"' + attrs[cls.end():]
    else:
        attrs += ' class="di-has-rail"'
    return page[:m.start()] + f"<body{attrs}>" + rail_html(active, theme) + page[m.end():]
