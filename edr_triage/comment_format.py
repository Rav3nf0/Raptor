"""RAPTOR's Jira comments as structured ADF — formatted the way L1 writes them.

The shared brand_intel converter turned every line into a bare paragraph and DROPPED bold
(`*x*` -> `x`), so a RAPTOR comment rendered as ~25 flat lines (DEMO-116330) next to L1
comments built from bold-keyed bullet lists. This renders the same text, unchanged, as:

  * "Key: value" runs (indented, or 3+ in a row)   -> bullet list, key in bold
  * `* ` / `- ` / `• ` and `# ` / `1. ` lines       -> bullet / numbered lists (one nesting level)
  * `*Label: sentence…*` (the model's habit)        -> bold label, plain sentence
  * `**x**` `*x*` `_x_` `` `x` `` {color:#hex}x{color} [text|url]
  * e-mail addresses -> mailto links; DEMO-123 -> ticket links; long URLs -> short link text
  * a recognised headline (what RAPTOR did)         -> coloured panel
  * bulky sections (tool calls, previous occurrences, DLP pattern notes) -> collapsed expand
  * {noformat}, ||tables||, h3. headings, {panel:type}…{panel}, {expand:Title}…{expand},
    {quote}…{quote} (one line or a block)

`to_adf` never raises for ordinary text; `plain_adf` is the conservative fallback the caller
retries with if Jira rejects a node (panel/expand) — so formatting can never cost a comment.
"""
from __future__ import annotations

import re

JIRA_BROWSE = "https://jira.example.com/browse/"

# ── headline → panel colour ───────────────────────────────────────────────────
_HEADLINES = [
    (re.compile(r"^\W*\[RAPTOR chase-reply\].*\bNOT them\b", re.I), "error"),
    (re.compile(r"^\W*\[RAPTOR chase-reply\]", re.I), "info"),
    (re.compile(r"^\W*RAPTOR (closed|marked)\b", re.I), "success"),
    (re.compile(r"^\W*\[AUTO-FP\]", re.I), "success"),
    (re.compile(r"^\W*RAPTOR recommends: False Positive", re.I), "success"),
    (re.compile(r"^\W*RAPTOR moved this ticket", re.I), "info"),
    (re.compile(r"^\W*RAPTOR will ask|^\W*RAPTOR asked", re.I), "info"),
    (re.compile(r"^\W*\[NEEDS L2\]|^\W*RAPTOR recommends: review", re.I), "warning"),
    (re.compile(r"^\W*RAPTOR\b.*\b(aborted|could not|failed)\b", re.I), "error"),
    (re.compile(r"^\W*\[(!!! )?URGENT\]", re.I), "error"),
    (re.compile(r"^\W*RAPTOR Copilot|^\W*Second opinion only|^\W*RAPTOR:", re.I), "note"),
]

# Sections a reader rarely needs open: collapsed under their own header line.
_COLLAPSE = re.compile(r"^(Evidence gathered\b|Previous occurrences\b|Common legitimate DLP-trigger"
                       r"|RAPTOR evidence record\b)", re.I)
# "Key:" labels that introduce prose, never a key/value list item.
_PROSE_KEYS = {"recommendation", "note", "why", "ticket state", "safety gate triggered",
               "reasoning", "reason", "conclusion"}

_KV = re.compile(r"^(\s*)\*?([A-Za-z][\w /()\-.&']{0,38}?):\*?[ \t]+(\S.*)$")
_LIST = re.compile(r"^(\s*)([*•\-]|#|\d{1,2}[.)])\s+(.*)$")
_HEADER = re.compile(r"^\s*([A-Z][^:]{1,70}):\s*$")
_CODE_ONLY = re.compile(r"^\s+(`[^`]+`)\s*$")
# Where a new section starts: every generator opens one with a bold label, "*Label:*".
_SECTION = re.compile(r"^\*[^*\n]{2,90}:\*")
_FOOTER = re.compile(r"^\[[^\]]*(RAPTOR|DeepIntel)[^\]]*\]$")

_INLINE = re.compile(
    r"(?P<color>\{color:(?P<hex>#[0-9a-fA-F]{6})\}(?P<ctext>.+?)\{color\})"
    r"|(?P<link>\[(?P<ltext>[^\]|]+)\|(?P<lurl>[^\]\s]+)\])"
    r"|(?P<code>`(?P<ctxt>[^`\n]+)`)"
    r"|(?P<b2>\*\*(?P<b2t>[^*\n]+?)\*\*)"
    r"|(?P<b1>(?<![\w*])\*(?P<b1t>[^*\s](?:[^*\n]*?[^*\s])?)\*(?![\w*]))"
    r"|(?P<em>(?<![\w])_(?P<emt>[^_\n]+?)_(?![\w]))"
    r"|(?P<url>https?://[^\s<>\]\)\"']+)"
    r"|(?P<mail>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"
    r"|(?P<sim>\bSIM-\d+\b)"
)


def _t(text: str, marks: list | None = None) -> dict:
    n = {"type": "text", "text": text}
    if marks:
        seen, uniq = set(), []
        for m in marks:                 # Jira rejects a mark repeated on one node
            if m["type"] not in seen:
                seen.add(m["type"])
                uniq.append(m)
        n["marks"] = uniq
    return n


def _url_label(url: str) -> str:
    if "portal.azure.com" in url and "/Incidents/" in url:
        return "Sentinel incident"
    if "security.microsoft.com" in url:
        return "Defender portal"
    m = re.search(r"console\.aws\.amazon\.com/guardduty/.*[?&#]fId=([0-9a-f]+)", url, re.I)
    if m:
        return f"GuardDuty finding {m.group(1)}"
    if len(url) <= 70:
        return url
    host = re.sub(r"^https?://", "", url).split("/")[0]
    return f"{host} link"


def inline(text: str, base: list | None = None) -> list[dict]:
    """Inline marks for one line of text. `base` marks apply to every node."""
    base = list(base or [])
    out: list[dict] = []
    pos = 0
    for m in _INLINE.finditer(text or ""):
        if m.start() > pos:
            out.append(_t(text[pos:m.start()], base))
        g = m.lastgroup
        if g == "color":
            out += inline(m.group("ctext"), base + [{"type": "textColor",
                                                      "attrs": {"color": m.group("hex").lower()}}])
        elif g == "link":
            out.append(_t(m.group("ltext"), base + [{"type": "link", "attrs": {"href": m.group("lurl")}}]))
        elif g == "code":
            out.append(_t(m.group("ctxt"), [{"type": "code"}]))   # code takes no other marks
        elif g == "b2":
            out += inline(m.group("b2t"), base + [{"type": "strong"}])
        elif g == "b1":
            inner = m.group("b1t")
            # The model bolds whole sentences: `*Alert Context: This is …*`. Bold the label only.
            lab = re.match(r"^([^:]{2,40}):\s+(.{20,})$", inner, re.S)
            if lab:
                out.append(_t(lab.group(1) + ":", base + [{"type": "strong"}]))
                out += inline(" " + lab.group(2), base)
            else:
                out += inline(inner, base + [{"type": "strong"}])
        elif g == "em":
            out += inline(m.group("emt"), base + [{"type": "em"}])
        elif g == "url":
            url = m.group("url").rstrip(".,;:")
            tail = m.group("url")[len(url):]
            out.append(_t(_url_label(url), base + [{"type": "link", "attrs": {"href": url}}]))
            if tail:
                out.append(_t(tail, base))
        elif g == "mail":
            addr = m.group("mail")
            out.append(_t(addr, base + [{"type": "link", "attrs": {"href": f"mailto:{addr}"}}]))
        elif g == "sim":
            key = m.group("sim")
            out.append(_t(key, base + [{"type": "link", "attrs": {"href": JIRA_BROWSE + key}}]))
        pos = m.end()
    if pos < len(text or ""):
        out.append(_t(text[pos:], base))
    return [n for n in out if n.get("text")]


def _para(text: str, base: list | None = None) -> dict:
    return {"type": "paragraph", "content": inline(text, base) or [_t(" ")]}


def _kv_para(key: str, value: str) -> dict:
    return {"type": "paragraph", "content": [_t(key.strip() + ":", [{"type": "strong"}]), _t(" ")]
            + inline(value)}


def _is_kv(line: str) -> bool:
    m = _KV.match(line)
    return bool(m) and m.group(2).strip().lower() not in _PROSE_KEYS and "://" not in m.group(2)


def _panel_type(line: str) -> str | None:
    for rx, kind in _HEADLINES:
        if rx.search(line):
            return kind
    return None


def _lists(items: list[tuple[int, str, str]]) -> list[dict]:
    """[(indent, marker, text)] -> list nodes, one nesting level under a deeper indent."""
    blocks: list[dict] = []
    top_indent = items[0][0]
    for indent, marker, text in items:
        kind = "orderedList" if (marker == "#" or marker[0].isdigit()) else "bulletList"
        if marker[0].isdigit():
            indent = top_indent      # the model indents "2." "3." at random; numbers are one list
        # "# - sub point": the model nests a dash item inside a numbered list
        sub = re.match(r"^[-•]\s+(.*)$", text) if kind == "orderedList" else None
        if sub and blocks and blocks[-1]["type"] == "orderedList":
            indent, kind, text = top_indent + 2, "bulletList", sub.group(1)
        li = {"type": "listItem", "content": [_kv_para(*_KV.match(text).groups()[1:])
                                               if _is_kv(text) and len(text) < 160 else _para(text)]}
        if indent > top_indent + 1 and blocks and blocks[-1]["content"]:
            parent = blocks[-1]["content"][-1]
            if len(parent["content"]) > 1 and parent["content"][-1]["type"] == kind:
                parent["content"][-1]["content"].append(li)
            else:
                parent["content"].append({"type": kind, "content": [li]})
            continue
        if blocks and blocks[-1]["type"] == kind:
            blocks[-1]["content"].append(li)
        else:
            blocks.append({"type": kind, "content": [li]})
    return blocks


def _blocks(lines: list[str], nested: bool = False) -> list[dict]:
    nodes: list[dict] = []
    i = 0
    first_text = not nested
    while i < len(lines):
        line = lines[i].rstrip()
        s = line.strip()
        if not s:
            i += 1
            continue
        if s == "{noformat}":
            j = i + 1
            while j < len(lines) and lines[j].strip() != "{noformat}":
                j += 1
            nodes.append({"type": "codeBlock", "attrs": {},
                          "content": [_t("\n".join(lines[i + 1:j]) or " ")]})
            i = j + 1
            continue
        pm = re.match(r"^\{(panel|expand)(?::([^}]*))?\}$", s)
        if pm:
            tag, arg = pm.group(1), (pm.group(2) or "").strip()
            j = i + 1
            while j < len(lines) and lines[j].strip() != "{" + tag + "}":
                j += 1
            # nested=True: no auto-collapsed section inside an explicit one — Jira rejects an
            # expand inside an expand, and the comment would fall back to plain text.
            inner = _blocks(lines[i + 1:j], nested=True) or [_para(" ")]
            if tag == "panel":
                kind = arg.replace("type=", "") or "info"
                nodes.append({"type": "panel", "attrs": {"panelType": kind},
                              "content": [n for n in inner if n["type"] in
                                          ("paragraph", "bulletList", "orderedList", "heading")]})
            else:
                nodes.append({"type": "expand", "attrs": {"title": arg or "Details"}, "content": inner})
            i = j + 1
            first_text = False
            continue
        qm = re.fullmatch(r"\{quote\}(.*?)\{quote\}", s)
        if qm or s == "{quote}":
            if qm:
                inner, i = [qm.group(1)], i + 1
            else:
                j = i + 1
                while j < len(lines) and lines[j].strip() != "{quote}":
                    j += 1
                inner, i = lines[i + 1:j], j + 1
            body = [n for n in _blocks(inner, nested=True)
                    if n["type"] in ("paragraph", "bulletList", "orderedList")]
            nodes.append({"type": "blockquote", "content": body or [_para(" ")]})
            first_text = False
            continue
        hm = re.match(r"^h([1-6])\.\s+(.*)$", s)
        if hm:
            nodes.append({"type": "heading", "attrs": {"level": int(hm.group(1))},
                          "content": inline(hm.group(2))})
            i += 1
            continue
        if s.startswith("|") and s.endswith("|"):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|") and lines[i].strip().endswith("|"):
                r = lines[i].strip()
                hdr = r.startswith("||")
                cells = (r.strip("|").split("||") if hdr else r.strip("|").split("|"))
                rows.append({"type": "tableRow", "content": [
                    {"type": "tableHeader" if hdr else "tableCell", "attrs": {},
                     "content": [_para(c.strip())]} for c in cells]})
                i += 1
            nodes.append({"type": "table", "attrs": {"isNumberColumnEnabled": False,
                                                     "layout": "default"}, "content": rows})
            continue
        if first_text:
            first_text = False
            kind = _panel_type(s)
            if kind:
                nodes.append({"type": "panel", "attrs": {"panelType": kind},
                              "content": [_para(s, [{"type": "strong"}])]})
                i += 1
                continue
        # a bulky section: header line + its body (to the next blank line / header) collapsed
        if not nested and _COLLAPSE.match(s.strip("*")):
            # ...to the next section label or the closing tag; across a blank line only while
            # the body carries on as a list or indented block (it may hold blank lines)
            j, after_blank = i + 1, False
            while j < len(lines):
                raw = lines[j].rstrip()
                nxt = raw.strip()
                if _SECTION.match(nxt) or _FOOTER.match(nxt):
                    break
                if not nxt:
                    after_blank = True
                elif after_blank and not (_LIST.match(raw) or raw.startswith(" ")):
                    break
                else:
                    after_blank = False
                j += 1
            body = _blocks(lines[i + 1:j], nested=True)
            title = s.strip("*").rstrip(":").strip()
            if len(title) > 90:
                # never cut words off: a long header is kept whole inside, under a short title
                short = re.split(r"\s[(—,]", title, 1)[0].strip()
                body = [_para(s.strip("*"))] + body
                title = short if 10 <= len(short) <= 90 else title[:87].rstrip() + "…"
            nodes.append({"type": "expand", "attrs": {"title": title},
                          "content": body or [_para(" ")]})
            i = j
            continue
        # lists, key/value runs and bare indented code lines, gathered together
        run: list[tuple[int, str, str]] = []
        j = i
        while j < len(lines) and lines[j].strip():
            ln = lines[j].rstrip()
            lm, cm = _LIST.match(ln), _CODE_ONLY.match(ln)
            if lm:          # "*bold*" never matches: a list marker needs a space after it
                run.append((len(lm.group(1)), lm.group(2), lm.group(3)))
            elif cm:
                run.append((len(ln) - len(ln.lstrip()), "•", cm.group(1)))
            elif _is_kv(ln) and (ln.startswith("  ") or run or _kv_run_len(lines, j) >= 3):
                run.append((len(ln) - len(ln.lstrip()), "•", ln.strip()))
            else:
                break
            j += 1
        if run:
            nodes += _lists(run)
            i = j
            continue
        if _HEADER.match(line) and len(s) <= 72:
            nodes.append(_para(s.strip("*"), [{"type": "strong"}]))
            i += 1
            continue
        km = _KV.match(line)
        if km and km.group(2).strip().lower() in _PROSE_KEYS:
            nodes.append(_kv_para(km.group(2), km.group(3)))
        else:
            nodes.append(_para(s))
        i += 1
    return nodes


def _kv_run_len(lines: list[str], j: int) -> int:
    n = 0
    while j + n < len(lines) and lines[j + n].strip() and _is_kv(lines[j + n].rstrip()):
        n += 1
    return n


def _footer(nodes: list[dict]) -> list[dict]:
    """The trailing "[Auto-triaged by RAPTOR]" tag, quiet: small grey italics."""
    if nodes and nodes[-1]["type"] == "paragraph":
        txt = "".join(n.get("text", "") for n in nodes[-1]["content"])
        if re.fullmatch(r"\s*\[[^\]]*(RAPTOR|DeepIntel)[^\]]*\]\s*", txt):
            nodes[-1] = {"type": "paragraph", "content": [_t(txt.strip(), [
                {"type": "em"}, {"type": "textColor", "attrs": {"color": "#6b778c"}}])]}
    return nodes


def to_adf(text: str) -> dict:
    lines = (text or "").replace("\r\n", "\n").split("\n")
    nodes = _footer(_blocks(lines))
    return {"type": "doc", "version": 1, "content": nodes or [_para(" ")]}


def plain_adf(text: str) -> dict:
    """No panels, expands or colour — the fallback if Jira rejects a richer node."""
    def strip(nodes: list[dict]) -> list[dict]:
        out = []
        for n in nodes:
            if n["type"] in ("panel", "expand"):
                if n["type"] == "expand":
                    out.append(_para(n["attrs"]["title"], [{"type": "strong"}]))
                out += strip(n["content"])
                continue
            if "content" in n and isinstance(n["content"], list):
                n = {**n, "content": strip(n["content"])}
            if n.get("marks"):
                n = {**n, "marks": [m for m in n["marks"] if m["type"] != "textColor"]}
            out.append(n)
        return out
    doc = to_adf(text)
    return {**doc, "content": strip(doc["content"])}
