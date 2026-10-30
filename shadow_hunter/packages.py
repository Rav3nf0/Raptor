"""Package names out of install command lines, and their reputation from OSV.dev.

INC-2026-0911-KB started with `npm install self-certificate`, run on 2026-08-26 by the user's
Claude Code agent. OSV had listed that package as malicious (MAL-2026-5644, from Amazon
Inspector's feed via OpenSSF malicious-packages) since 2026-06-11. The old detector keyed on
"npm spawned a shell", which is every install; the package name was the signal.

Only explicit installs are visible here: `npm install` / `npm ci` with no names installs from
package.json, whose contents MDE does not show.
"""
from __future__ import annotations

import logging
import re
import shlex

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_MAX = 1000

_NPM_TOOLS = {"npm", "pnpm", "yarn", "bun"}
_NPM_VERBS = {"install", "i", "add", "isntall", "in"}
_NPX_TOOLS = {"npx", "bunx"}                       # run a package straight from the registry
_PY_TOOLS = {"pip", "pip3", "pipx"}
_PY_VERBS = {"install"}
# Flags that take a separate value; the value is not a package name.
_VALUE_FLAGS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
                "--extra-index-url", "--prefix", "--target", "-t", "--registry", "--cache", "--tag",
                "--user-agent", "-p", "--package", "--python", "--root", "--src", "--workspace", "-w",
                "--filter", "--dir", "-C", "--cwd", "--userconfig"}
_NPM_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.I)
_PY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_EXACT = re.compile(r"^\d+\.\d+\.\d+([-+][\w.-]+)?$")    # a pinned version, not a range or tag
AGENT_MARKERS = (".claude/shell-snapshots", "claude --", "/claude ", "cursor", "codex", "windsurf", "aider",
                 "copilot", "gemini")


_OPERATORS = {"&&", "||", ";", "|", "&", ";;"}


def _commands(cmd: str) -> list[list[str]]:
    """Split a shell line into simple commands on && || ; | &, respecting quotes."""
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|")
    lex.whitespace_split = True
    try:
        toks = list(lex)
    except ValueError:            # unbalanced quotes in a truncated command line
        toks = cmd.split()
    out, cur = [], []
    for t in toks:
        if t in _OPERATORS:
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    return out


def _base(tok: str) -> str:
    b = tok.rsplit("/", 1)[-1].lower()
    return b[:-4] if b.endswith(".exe") or b.endswith(".cmd") else b


def _npm_name(tok: str) -> tuple[str, str] | None:
    if tok.startswith(("-", ".", "/", "~", "file:", "git+", "git:", "github:", "http://", "https://", "link:", "workspace:")) \
            or tok.endswith(".tgz"):
        return None
    if tok.startswith("@"):
        scope, _, rest = tok.partition("/")
        name, _, ver = rest.partition("@") if rest else ("", "", "")
        name = scope + "/" + name if name else None
    else:
        name, _, ver = tok.partition("@")
    if not name or not _NPM_NAME.match(name):
        return None
    return name.lower(), ver if _EXACT.match(ver or "") else ""


def _py_name(tok: str) -> tuple[str, str] | None:
    if tok.startswith(("-", ".", "/", "~", "git+", "http://", "https://")) or tok.endswith((".whl", ".tar.gz", ".zip", ".txt")):
        return None
    name = re.split(r"[\[<>=!~;@ ]", tok, 1)[0]
    if not name or not _PY_NAME.match(name):
        return None
    pin = re.search(r"==\s*([0-9][\w.+-]*)$", tok)
    return name.lower().replace("_", "-"), pin.group(1) if pin else ""


def parse_install(cmd: str) -> list[tuple[str, str, str]]:
    """[(ecosystem, name, pinned_version or "")] explicitly installed or executed by one
    command line. Handles
    wrappers (sfw, sudo, env, timeout, python -m pip, uv pip/add, poetry add) and several
    commands chained with && / ; / |."""
    out: list[tuple[str, str, str]] = []
    for toks in _commands(cmd or ""):
        i = 0
        # peel wrappers: sfw npm i x / sudo -H pip install y / env A=1 npm i z / timeout 480 npm ci
        while i < len(toks) and (_base(toks[i]) in {"sudo", "env", "sfw", "time", "nohup", "node", "command", "exec", "timeout"}
                                 or "=" in toks[i] or (toks[i].startswith("-") and i and _base(toks[i - 1]) == "sudo")
                                 or (i and _base(toks[i - 1]) == "timeout" and toks[i].isdigit())):
            i += 1
        if i >= len(toks):
            continue
        tool = _base(toks[i]); rest = toks[i + 1:]
        # sh -c "npm i x", and Claude Code's zsh -c "source … && eval 'npm i x'"
        if tool in {"sh", "bash", "zsh", "dash"} and "-c" in rest[:3]:
            k = rest.index("-c")
            if k + 1 < len(rest):
                out += [p for p in parse_install(rest[k + 1]) if p not in out]
            continue
        if tool == "eval" and rest:
            out += [p for p in parse_install(" ".join(rest)) if p not in out]
            continue
        eco, verbs, namer = None, set(), None
        if tool.startswith("python") and rest[:2] == ["-m", "pip"]:
            tool, rest = "pip", rest[2:]
        if tool == "uv" and rest[:1] == ["pip"]:
            tool, rest = "pip", rest[1:]
        if tool in _NPM_TOOLS:
            if rest[:1] in (["exec"], ["dlx"], ["x"]):
                eco, namer, rest, verbs = "npm", _npm_name, rest[1:], None
            else:
                eco, verbs, namer = "npm", _NPM_VERBS, _npm_name
        elif tool in _NPX_TOOLS:
            eco, namer, verbs = "npm", _npm_name, None
        elif tool in _PY_TOOLS:
            eco, verbs, namer = "PyPI", _PY_VERBS, _py_name
        elif tool in ("uv", "poetry"):
            eco, verbs, namer = "PyPI", {"add"}, _py_name
        elif tool == "uvx":
            eco, namer, verbs = "PyPI", _py_name, None
        if not eco:
            continue
        if verbs is not None:
            # the verb may follow global flags: npm --prefix x install foo
            j = 0
            while j < len(rest) and rest[j].startswith("-"):
                j += 2 if rest[j] in _VALUE_FLAGS else 1
            if j >= len(rest) or rest[j].lower() not in verbs:
                continue
            args = rest[j + 1:]
        else:
            args = rest
        skip = False
        for n, tok in enumerate(args):
            if skip:
                skip = False
                continue
            if tok in _VALUE_FLAGS:
                skip = True
                continue
            if "=" in tok and tok.startswith("-"):
                continue
            got = namer(tok)
            if got:
                out.append((eco, got[0], got[1]))
                if verbs is None:      # npx/uvx/dlx run ONE package; the rest are its arguments
                    break
    return list(dict.fromkeys(out))


def by_agent(*cmdlines: str) -> bool:
    blob = " ".join(c or "" for c in cmdlines).lower()
    return any(m in blob for m in AGENT_MARKERS)


def _vkey(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v)[:4])


def version_at(versions: dict[str, str], at_iso: str) -> str:
    """The stable version a no-version install got at `at_iso`: the highest non-prerelease
    published by then. (npm's `latest` tag history is not public; this matches it in practice.)"""
    ok = [v for v, t in versions.items() if t and t[:19] <= at_iso[:19] and not re.search(r"[-+]", v)]
    return max(ok, key=_vkey) if ok else ""


async def registry_info(client, eco: str, name: str) -> dict | None:
    """{"versions": {version: published_iso}, "created": iso, "placeholder": bool} from the
    npm registry or PyPI; {"missing": True} when the package is gone; None when unreachable.
    npm replaces removed malware with a `0.0.1-security` "security holding package"."""
    from urllib.parse import quote
    url = (f"https://registry.npmjs.org/{quote(name, safe='@')}" if eco == "npm"
           else f"https://pypi.org/pypi/{quote(name)}/json")
    try:
        resp = await client.get(url)
    except Exception:
        return None
    if resp.status_code == 404:
        return {"missing": True, "versions": {}, "created": "", "placeholder": False}
    if resp.status_code >= 400:
        return None
    d = resp.json()
    if eco == "npm":
        t = {k: v for k, v in (d.get("time") or {}).items() if k not in ("created", "modified")}
        latest = (d.get("dist-tags") or {}).get("latest", "")
        placeholder = latest.endswith("-security") or "security holding package" in (d.get("description") or "")
        # `time` keeps versions npm has since unpublished; after the takedown an install got the
        # placeholder, before it the version that was latest then
        return {"versions": t, "created": (d.get("time") or {}).get("created", ""), "missing": False,
                "placeholder": placeholder, "placeholder_at": t.get(latest, "") if placeholder else ""}
    rel = {v: min((f.get("upload_time_iso_8601") or f.get("upload_time") or "") for f in files) if files else ""
           for v, files in (d.get("releases") or {}).items()}
    return {"versions": rel, "created": min((t for t in rel.values() if t), default=""), "missing": False,
            "placeholder": False}


async def osv_malicious(packages: list[tuple], timeout: float = 20.0, verify=True) -> dict | None:
    """{package: [MAL-… ids]} for (ecosystem, name) or (ecosystem, name, version) tuples OSV
    lists as malicious code — for a version, only advisories affecting that version. One
    batched call per 1000. None when OSV cannot be reached — never read that as "clean"."""
    import httpx
    pkgs = list(dict.fromkeys(packages))
    found: dict[tuple, list[str]] = {}
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
            for k in range(0, len(pkgs), OSV_BATCH_MAX):
                chunk = pkgs[k:k + OSV_BATCH_MAX]
                queries = []
                for p in chunk:
                    q = {"package": {"ecosystem": p[0], "name": p[1]}}
                    if len(p) > 2 and p[2]:
                        q["version"] = p[2]
                    queries.append(q)
                resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
                resp.raise_for_status()
                for pkg, res in zip(chunk, resp.json().get("results", [])):
                    mal = [v["id"] for v in (res.get("vulns") or []) if str(v.get("id", "")).startswith("MAL-")]
                    if mal:
                        found[pkg] = mal
    except Exception as exc:  # network/egress/HTTP
        logger.warning("[packages] OSV lookup failed: %s", exc)
        return None
    return found
