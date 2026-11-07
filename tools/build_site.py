#!/usr/bin/env python3
"""Builds the Lantern SDK's website into <out-dir> (site/README.md).

    python3 tools/build_site.py <out-dir>

One page, in the fifteen languages of Boréale's sites (English at the root,
each other language in its folder): what the libraries do, how they compare,
the same call in every language and the examples CI runs, all read from
sdk.json (tools/site_data.py), so the page says what the repository says.
site/template.html is the page around site/home.html; each {{key}} is the
key's text in the language's catalog, site/i18n/<language>.json. What
Boréale's sites share (the languages, the header's two menus, the links out
and their UTM tags, the audience, the fonts and marks) is boreale-site's, the
submodule library/boreale-site. Served at https://sdk.lantern.boreale.dev/
(SITE_URL for another address). Python's standard library only.
"""
import html
import json
import os
import re
import shutil
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "library" / "boreale-site"))
import boreale_site as boreale  # noqa: E402  (library/boreale-site)
from boreale_site import CODES, LANGUAGES, OG_LOCALES, fill, folder  # noqa: E402

SITE = ROOT / "site"
REPO = "https://github.com/JigSawFr/lantern-sdk"
LANTERN_URL = "https://lantern.boreale.dev/"
BRIDGE_URL = "https://bridge.lantern.boreale.dev/"
# This site in boreale-site's sites.json: its address, its utm_source, its place in the menu.
SDK = boreale.Site("sdk", os.environ.get("SITE_URL"))
SITE_URL = SDK.url
ENGLISH = CODES[0]
SPEC = ROOT / "spec" / "SPEC.md"
# The conformance levels (SPEC.md § 17), as the protocol's site names them.
LEVELS = [("core", "Core"), ("titles", "+titles"), ("homebrew", "+homebrew"), ("saves", "+saves"),
          ("cheats", "+cheats"), ("requests", "+requests"), ("admin", "+admin"), ("events", "+events"),
          ("peers", "+peers"), ("sync", "+sync"), ("encrypted_saves", "+encrypted_saves"), ("deltas", "+deltas"),
          ("static", "Static")]


def spec_sections() -> dict:
    """The specification's numbered sections and their anchors, from its submodule (spec/SPEC.md): what the calls'
    "§ 4.2" link to on the protocol's site. Empty, so that the numbers stay unlinked, without the submodule."""
    try:
        lines = SPEC.read_text(encoding="utf-8").split("\n")
    except OSError:
        return {}
    out = {}
    for line in lines:
        if m := re.match(r"#{2,3} ((\d+(?:\.\d+)?)\.? .*?|Annexe? ([A-Z]) .*?|([A-Z]\.\d+) .*?)(?: \{#([a-z0-9-]+)\})?$", line):
            shown = m.group(1)
            number = m.group(2) or m.group(3) or m.group(4)
            slug = re.sub(r"[^\w\- ]", "", re.sub(r"<[^>]+>", "", re.sub(r"[`*]", "", shown)).lower()).replace(" ", "-")
            out[number] = m.group(5) or slug
    return out


# ---- The SDK's page: sdk.json, what lantern-sdk says about itself (its tools/site_data.py), read at each build.

SDK_REPO = REPO
SDK_SCHEMA = 1
SDK_CALLS = ("handshake", "apps", "missing", "download", "pair", "await_pairing", "upload_save", "events", "serve",
             "static_write", "static_read")
SDK_LANGS = ("cpp", "c", "python", "typescript", "go", "rust")
SDK_NAMES = {"cpp": "C++", "c": "C", "python": "Python", "typescript": "TypeScript", "go": "Go", "rust": "Rust"}


def sdk_data() -> dict | None:
    """sdk.json, which this repository's tools/site_data.py writes, read at each build; None when it is not there or
    states a newer `schema`, and the page then says its data is not there (the rule of versioned formats)."""
    try:
        data = json.loads((ROOT / "sdk.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("schema"), int) or data["schema"] > SDK_SCHEMA:
        return None
    return data


def sdk_values(catalog: dict, root: str, sections: dict) -> dict:
    """The SDK page's blocks, from sdk.json; empty ones and a note when the data is not there."""
    data = sdk_data()
    keys = ("sdk_head", "sdk_cards", "sdk_parity", "sdk_levels", "sdk_calls", "sdk_examples", "sdk_versions", "sdk_use", "sdk_origin")
    trust = sdk_trust(catalog, root)
    nav = sdk_nav(catalog)
    if data is None:
        return {**{k: "" for k in keys}, "sdk_legend": sdk_legend(catalog), "sdk_trust": trust, "sdk_nav": nav,
                "sdk_nodata": f'<p class="note">{catalog["sdk_nodata"]}</p>'}
    return {"sdk_nodata": "", "sdk_legend": sdk_legend(catalog), "sdk_trust": trust, "sdk_nav": nav, "sdk_head": sdk_head(catalog, data), "sdk_use": sdk_use(catalog, data), "sdk_origin": sdk_origin(catalog),
            "sdk_cards": sdk_cards(catalog, data),
            "sdk_parity": sdk_parity(catalog, data), "sdk_levels": sdk_levels(catalog, data, root),
            "sdk_calls": sdk_calls(catalog, data, root, sections), "sdk_examples": sdk_examples(catalog, data),
            "sdk_versions": sdk_versions(catalog, data)}


def sdk_legend(catalog: dict) -> str:
    return catalog["sdk_legend"].replace("◐", HALF)


SDK_SECTIONS = ("pick", "parity", "calls", "examples", "try", "trust", "versions")


def sdk_nav(catalog: dict) -> str:
    links = "".join(f'<li><a href="#{k}">{catalog["sdk_nav_" + k]}</a></li>' for k in SDK_SECTIONS)
    return f'<nav class="subnav" aria-label="{html.escape(catalog["sdk_nav_aria"], quote=True)}"><ul>{links}</ul></nav>'


def sdk_trust(catalog: dict, root: str) -> str:
    tiles = (("suite", f'{LANTERN_URL}conformance/'), ("hostile", None), ("vectors", None), ("release", None))
    out = []
    for key, link in tiles:
        text = catalog["sdk_trust_" + key + ("_x" if key == "release" else "")]
        title = catalog["sdk_trust_" + key + "_t"]
        head = f'<a href="{html.escape(link, quote=True)}">{title}</a>' if link else title
        out.append(f'<li class="card"><h3>{head}</h3><p>{text}</p></li>')
    return '<ul class="cards cards-small trust">' + "".join(out) + "</ul>"


def sdk_head(catalog: dict, data: dict) -> str:
    sdk = data.get("sdk", {})
    release = sdk.get("release")
    state = catalog["sdk_released"].replace("{v}", str(release)) if release else catalog["sdk_unreleased"]
    chips = [("sdk_k_version", sdk.get("version", "")), ("sdk_k_draft", sdk.get("spec_draft", "")),
             ("sdk_k_capi", sdk.get("c_api_version", ""))]
    items = "".join(f'<li>{catalog[k]} <strong>{html.escape(str(v))}</strong></li>' for k, v in chips if v != "")
    return (f'<ul class="chips">{items}</ul>\n    <p class="note">{state} '
            f'<a href="{html.escape(sdk.get("releases", SDK_REPO), quote=True)}">{catalog["sdk_releases"]}</a> · '
            f'<a href="{SDK_REPO}">GitHub</a></p>')


#: Who each library is for: (the text's key, the language), the reader's own situation first.
SDK_USES = (("console", "cpp"), ("mobile", "c"), ("python", "python"), ("web", "typescript"))


def sdk_use(catalog: dict, data: dict) -> str:
    """"Which one is for me": a line a situation, leading to the card of the language; and the picker that, with
    script, sets the language the page follows (the buttons are hidden until sdk.js shows them)."""
    ids = {lang.get("id") for lang in data.get("languages", [])}
    items = "".join(f'<li>{catalog["sdk_use_" + key]} <a href="#sdk-{lang}">{SDK_NAMES[lang]}</a></li>'
                    for key, lang in SDK_USES if lang in ids)
    buttons = "".join(f'<button type="button" data-pick="{lang}" aria-pressed="false">{SDK_NAMES[lang]}</button>'
                      for lang in SDK_LANGS if lang in ids)
    label = html.escape(catalog["sdk_i_code"], quote=True)
    return (f'<h3 class="which">{catalog["sdk_use_title"]}</h3>\n    <ul class="uses">{items}</ul>\n'
            f'    <div class="picker" hidden role="group" aria-label="{label}"><span>{catalog["sdk_i_code"]}</span>{buttons}</div>')


def sdk_origin(catalog: dict) -> str:
    """Nothing to say: the page is built from the repository it describes."""
    return ""


def sdk_counts(data: dict, lang: str) -> tuple[int, int, int] | None:
    families = data.get("families", [])
    if not any(lang in row.get("support", {}) for row in families):
        return None
    got = [sum(1 for row in families if row.get("support", {}).get(lang, {}).get(side) == "yes") for side in ("client", "server")]
    return got[0], got[1], len(families)


def sdk_cards(catalog: dict, data: dict) -> str:
    cards = []
    for lang in data.get("languages", []):
        name = html.escape(str(lang.get("name", "")))
        status = lang.get("status", "")
        facts = [("sdk_k_requires", lang.get("requires")), ("sdk_k_package", lang.get("package")),
                 ("sdk_k_adapters", ", ".join(lang.get("adapters", [])))]
        rows = "".join(f"<div><dt>{catalog[k]}</dt><dd>{html.escape(str(v))}</dd></div>" for k, v in facts if v)
        rows = rows.replace(f"<dd>{html.escape(str(lang.get('package') or ''))}</dd>", f"<dd><code>{html.escape(str(lang.get('package') or '')).replace('/', '/<wbr>')}</code></dd>") if lang.get("package") else rows
        install = lang.get("install")
        code = (f'<pre tabindex="0"><code>{html.escape(install)}</code></pre>' if install and (data.get("sdk") or {}).get("release") else "")
        readme = lang.get("readme")
        link = (f'<p class="more"><a href="{SDK_REPO}/blob/main/{html.escape(readme, quote=True)}">{catalog["sdk_readme"]}</a></p>'
                if readme else "")
        counts = sdk_counts(data, str(lang.get("id", "")))
        parity = (f'<p class="parity"><span>{catalog["sdk_client"]} <strong>{counts[0]}/{counts[2]}</strong></span> '
                  f'<span>{catalog["sdk_server"]} <strong>{counts[1]}/{counts[2]}</strong></span></p>' if counts else "")
        state = catalog["sdk_status_" + status] if "sdk_status_" + status in catalog else ""
        cards.append(f'<li class="card{" linked" if readme else ""}" id="sdk-{html.escape(str(lang.get("id", "")), quote=True)}" data-lang="{html.escape(str(lang.get("id", "")), quote=True)}"><h3>{name}</h3><p class="kind"><span class="pill pill-{html.escape(str(status), quote=True)}">{state}</span>'
                     f' {catalog["sdk_role_" + lang.get("role", "both")]}</p>{parity}<dl class="facts">{rows}</dl>{code}{link}</li>')
    return '<ul class="cards cards-small">' + "".join(cards) + "</ul>"


HALF = '<span class="half" aria-hidden="true"></span>'  # "part of it": drawn, a glyph of that shape is missing from most fonts
MARKS = {"yes": ("✓", "sdk_yes"), "partial": (HALF, "sdk_partial"), "no": ("–", "sdk_no")}


def sdk_cell(catalog: dict, kind: str) -> str:
    mark, key = MARKS.get(kind, ("–", "sdk_no"))
    shown = mark if mark == HALF else f'<span aria-hidden="true">{mark}</span>'
    return f'{shown}<span class="sr">{catalog[key]}</span>'


def sdk_parity_list(catalog: dict, data: dict, langs: list) -> str:
    """The parity by language, for a narrow screen where the table of twelve columns does not fit: a fold a language,
    its summary says how far it goes, its rows are the families."""
    families = data.get("families", [])
    out = []
    for lang in langs:
        got = sdk_counts(data, lang)
        if got is None:
            continue
        rows = "".join(
            f'<tr><th scope="row"><code>{html.escape(str(row.get("family", "")))}</code></th>'
            + "".join(f'<td class="{"reached" if row.get("support", {}).get(lang, {}).get(side) == "yes" else "none"}">'
                      f'{sdk_cell(catalog, row.get("support", {}).get(lang, {}).get(side, "no"))}</td>' for side in ("client", "server"))
            + "</tr>" for row in families)
        out.append(f'<details data-lang="{lang}"><summary><span>{SDK_NAMES[lang]}</span> <small>{catalog["sdk_client"]} {got[0]}/{got[2]} · '
                   f'{catalog["sdk_server"]} {got[1]}/{got[2]}</small></summary><table><caption class="sr">{SDK_NAMES[lang]}</caption>'
                   f'<thead><tr><th scope="col">{catalog["sdk_family"]}</th><th scope="col">{catalog["sdk_client"]}</th>'
                   f'<th scope="col">{catalog["sdk_server"]}</th></tr></thead><tbody>{rows}</tbody></table></details>')
    return f'<div class="parity-list">{"".join(out)}</div>'


def sdk_parity(catalog: dict, data: dict) -> str:
    langs = [lang for lang in SDK_LANGS if any(lang in row.get("support", {}) for row in data.get("families", []))]
    heads = "".join(f'<th scope="col" colspan="2" data-lang="{lang}">{SDK_NAMES[lang]}</th>' for lang in langs)
    sub = "".join(f'<th scope="col" data-lang="{lang}">{catalog["sdk_client"]}</th><th scope="col" data-lang="{lang}">{catalog["sdk_server"]}</th>' for lang in langs)
    rows = []
    for row in data.get("families", []):
        cells = ""
        for lang in langs:
            cell = row.get("support", {}).get(lang, {})
            cells += (f'<td data-lang="{lang}" class="{"reached" if cell.get("client") == "yes" else "none"}">{sdk_cell(catalog, cell.get("client", "no"))}</td>'
                      f'<td data-lang="{lang}" class="{"reached" if cell.get("server") == "yes" else "none"}">{sdk_cell(catalog, cell.get("server", "no"))}</td>')
        rows.append(f'<tr><th scope="row"><code>{html.escape(str(row.get("family", "")))}</code></th>{cells}</tr>')
    families = data.get("families", [])
    total = ""
    for lang in langs:
        for side in ("client", "server"):
            got = sum(1 for row in families if row.get("support", {}).get(lang, {}).get(side) == "yes")
            total += f'<td data-lang="{lang}" class="sum {"reached" if got == len(families) else "none" if got == 0 else "some"}">{got}/{len(families)}</td>'
    return (f'<div class="table matrix" tabindex="0" role="region" aria-label="{html.escape(catalog["sdk_parity_title"], quote=True)}"><table><caption class="sr">{html.escape(catalog["sdk_parity_title"])}</caption>'
            f'<thead><tr><th scope="col" rowspan="2">{catalog["sdk_family"]}</th>{heads}</tr><tr>{sub}</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody><tfoot><tr><th scope="row">{catalog["sdk_total"]}</th>{total}</tr></tfoot></table></div>'
            + sdk_parity_list(catalog, data, langs))


def sdk_levels(catalog: dict, data: dict, root: str) -> str:
    """The levels each checked server reaches in CI (the string is "Lantern Core +titles …"), a chip a level, each
    leading to its badge's page; /badge/ has the badges themselves, which are too heavy to repeat here."""
    known = dict(LEVELS)
    rows = []
    for lang, level in (data.get("levels") or {}).items():
        reached = [("core" if token == "Core" else token.lstrip("+")) for token in str(level).replace("Lantern ", "", 1).split()]
        chips = "".join(f'<li><a href="{LANTERN_URL}badge/">{html.escape(known[k])}</a></li>' for k in reached if k in known)
        rows.append(f'<li><strong>{SDK_NAMES.get(lang, html.escape(lang))}</strong><ul class="chips">{chips}</ul></li>')
    return f'<ul class="plain levels">{"".join(rows)}</ul>' if rows else ""


def sdk_calls(catalog: dict, data: dict, root: str, sections: dict) -> str:
    calls = {c.get("id"): c for c in data.get("calls", [])}
    langs = [lang for lang in SDK_LANGS if any(lang in c.get("calls", {}) for c in calls.values())]
    heads = "".join(f'<th scope="col" data-lang="{lang}">{SDK_NAMES[lang]}</th>' for lang in langs)
    rows = []
    for gesture in SDK_CALLS:
        call = calls.get(gesture)
        if call is None:
            continue
        cells = "".join(
            (f'<td data-lang="{lang}"><a href="{SDK_REPO}/blob/main/{html.escape(call["where"][lang], quote=True)}"><code>{html.escape(call["calls"][lang])}</code></a></td>'
             if call["calls"].get(lang) and lang in call.get("where", {}) else f'<td data-lang="{lang}" class="none"><span aria-hidden="true">–</span>'
             f'<span class="sr">{catalog["sdk_no"]}</span></td>') for lang in langs)
        spec = str(call.get("spec", ""))
        anchor = sections.get(spec)
        mark = f'§&nbsp;{html.escape(spec)}'
        link = f'<a href="{LANTERN_URL}spec/#{anchor}">{mark}</a>' if anchor else mark
        rows.append(f'<tr><th scope="row">{catalog["sdk_g_" + gesture]} {link}</th>{cells}</tr>')
    later = [SDK_NAMES[lang["id"]] for lang in data.get("languages", []) if lang.get("id") in SDK_NAMES and lang["id"] not in langs]
    note = f'<p class="note">{catalog["sdk_calls_later"].replace("{langs}", ", ".join(later))}</p>' if later else ""
    return (f'<div class="table calls" tabindex="0" role="region" aria-label="{html.escape(catalog["sdk_calls_title"], quote=True)}"><table><caption class="sr">{html.escape(catalog["sdk_calls_title"])}</caption>'
            f'<thead><tr><th scope="col">{catalog["sdk_gesture"]}</th>{heads}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>{note}')


#: The examples are gathered by the task they do, from their file names: (task, the start of the name), then the
#: variant a name carries after it, shown beside the language ("Python (Flask)").
SDK_TASKS = (("read", ("read",)), ("pair", ("pair",)), ("serve", ("serve", "demo")), ("static", ("static",)))
SDK_VARIANTS = {"flask": "Flask", "fastapi": "FastAPI", "node": "node:http", "server": "server core"}


def sdk_task(path: str) -> tuple[str | None, str | None]:
    stem = re.split(r"[-_]", Path(path).stem, maxsplit=1)
    for task, starts in SDK_TASKS:
        if stem[0] in starts:
            return task, (stem[1] if len(stem) > 1 else None)
    return None, None


#: The keywords each language's examples are coloured with; the rest of a line is left as it is.
SDK_KEYWORDS = {
    "cpp": "auto bool break case catch class const constexpr continue co_await co_return else enum explicit false for if inline namespace new noexcept nullptr operator private public return static struct switch template this throw true try typename using virtual void while int char unsigned",
    "c": "break case char const continue else enum extern false for if int return sizeof static struct switch true typedef union unsigned void while",
    "python": "and as assert async await class def elif else except False finally for from if import in is lambda None not or pass raise return True try while with yield",
    "typescript": "as async await break case catch class const continue default else export extends false finally for from function if import in instanceof interface let new null of return static switch this throw true try type typeof undefined var void while",
    "go": "break case chan const continue default defer else false for func go if import interface map nil package range return select struct switch true type var",
    "rust": "as async await break const continue crate else enum false fn for if impl in let loop match mod move mut pub ref return self Self static struct trait true type unsafe use where while",
}
_DQ = r'"(?:\\.|[^"\\\n])*"'
_SQ = r"'(?:\\.|[^'\\\n])*'"
_CHAR = r"'(?:\\.|[^'\\\n])'"
_TICK = r"`[^`]*`"
_TRIPLE = r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\''
#: Per language: how a line comment starts and what a string looks like.
SDK_SYNTAX = {
    "cpp": (r"//[^\n]*", f"{_DQ}|{_CHAR}"), "c": (r"//[^\n]*", f"{_DQ}|{_CHAR}"),
    "python": (r"#[^\n]*", f"{_TRIPLE}|{_DQ}|{_SQ}"), "typescript": (r"//[^\n]*", f"{_DQ}|{_SQ}|{_TICK}"),
    "go": (r"//[^\n]*", f"{_DQ}|{_TICK}|{_CHAR}"), "rust": (r"//[^\n]*", _DQ),
}


def sdk_highlight(source: str, lang: str) -> str:
    """The source of an example, escaped and with spans for its comments, strings, numbers and keywords: a small
    tokenizer, not a parser (a miss only leaves a word uncoloured). Classes only, so the CSP stays as it is."""
    comment, strings = SDK_SYNTAX.get(lang, (r"//[^\n]*", _DQ))
    words = set(SDK_KEYWORDS.get(lang, "").split())
    pattern = re.compile(rf"(?P<c>{comment}|/\*[\s\S]*?\*/)|(?P<s>{strings})|(?P<n>\b\d[\w.]*)|(?P<k>\b[A-Za-z_]\w*\b)")
    out, last = [], 0
    for m in pattern.finditer(source):
        out.append(html.escape(source[last:m.start()]))
        kind, text = m.lastgroup, m.group()
        if kind == "k" and text not in words:
            out.append(html.escape(text))
        else:
            out.append(f'<span class="tk-{kind}">{html.escape(text)}</span>')
        last = m.end()
    out.append(html.escape(source[last:]))
    return "".join(out)


SDK_FOLD = 30  # lines above which an example is shown cut, with "show all"


def sdk_code(catalog: dict, ident: str, lang: str, source: str) -> str:
    """An example's source, coloured; a long one is cut with a toggle (a checkbox, so that it works without script)."""
    pre = f'<pre tabindex="0"><code class="language-{html.escape(lang, quote=True)}">{sdk_highlight(source, lang)}</code></pre>'
    lines = source.count("\n") + 1
    if lines <= SDK_FOLD:
        return pre
    more = catalog["sdk_show_all"].replace("{n}", str(lines))
    return (f'<div class="fold"><input type="checkbox" id="{ident}-fold" class="fold-toggle">'
            f'<div class="fold-body">{pre}</div>'
            f'<label for="{ident}-fold"><span class="fold-more">{more}</span><span class="fold-less">{catalog["sdk_show_less"]}</span></label></div>')


def sdk_examples(catalog: dict, data: dict) -> str:
    """One block per task, the examples of the languages as tabs: radio buttons and CSS, so that they work without
    script (the first tab shows; with the styles off, every one is listed)."""
    by_task: dict = {}
    for example in data.get("examples", []):
        task, variant = sdk_task(str(example.get("path", "")))
        if task:
            by_task.setdefault(task, []).append((example, variant))
    out = []
    for task, _ in SDK_TASKS:
        group = sorted(by_task.get(task, []), key=lambda e: (SDK_LANGS.index(e[0].get("language")) if e[0].get("language") in SDK_LANGS else 99,
                                                              str(e[0].get("path"))))
        if not group:
            continue
        inputs, panels = "", ""
        for n, (example, variant) in enumerate(group):
            lang = str(example.get("language"))
            label = SDK_NAMES.get(lang, lang) + (f" ({SDK_VARIANTS[variant]})" if variant in SDK_VARIANTS else "")
            ident = f"ex-{task}-{n}"
            path = html.escape(str(example.get("path", "")), quote=True)
            title = re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(str(example.get("title", ""))))
            inputs += (f'<input type="radio" name="ex-{task}" id="{ident}" data-lang="{html.escape(lang, quote=True)}"{" checked" if n == 0 else ""}>'
                       f'<label for="{ident}">{html.escape(label)}</label>')
            panels += (f'<div class="panel"><p class="note">{title} · <a href="{SDK_REPO}/blob/main/{path}">{path}</a></p>'
                       f'{sdk_code(catalog, ident, lang, str(example.get("source", "")))}</div>')
        out.append(f'<h3 id="ex-{task}-title">{catalog["sdk_task_" + task]}</h3><div class="tabs" role="radiogroup" aria-labelledby="ex-{task}-title">{inputs}<div class="panels">{panels}</div></div>')
    return "\n".join(out)


def sdk_versions(catalog: dict, data: dict) -> str:
    """The version of the SDK, the draft it follows and the C API it exposes, a row a release (the one in the
    source until there is a release: sdk.json has no list of past ones yet)."""
    sdk = data.get("sdk", {})
    capi = f'{sdk.get("c_api_version")} (ABI {sdk.get("c_abi_version")})' if sdk.get("c_api_version") else ""
    head = "".join(f'<th scope="col">{catalog[k]}</th>' for k in ("sdk_k_version", "sdk_k_draft", "sdk_k_capi", "sdk_k_release"))
    row = "".join(f"<td>{html.escape(str(v))}</td>" for v in (sdk.get("version", ""), sdk.get("spec_draft", ""), capi,
                                                              sdk.get("release") or catalog["sdk_none_yet"]))
    return (f'<div class="table versions" tabindex="0" role="region" aria-label="{html.escape(catalog["sdk_versions_title"], quote=True)}">'
            f'<table><caption class="sr">{html.escape(catalog["sdk_versions_title"])}</caption><thead><tr>{head}</tr></thead><tbody><tr>{row}</tr></tbody></table></div>')


#: The hero's excerpt of the "read a library" example, per language: where it starts and where it ends in the file.
#: The lines are the example's own (CI runs it), so the hero cannot drift from it; a file that no longer has these
#: markers stops the build.
HERO_CUT = {
    "python": (r"^\s*with lantern\.LanternClient", r"bytes\)\"\)$"),
    "typescript": (r"^const client = new NodeLanternClient", r"^}$"),
}


def sdk_hero_excerpt(source: str, lang: str) -> str:
    start, end = (re.compile(pattern) for pattern in HERO_CUT[lang])
    lines = source.splitlines()
    first = next((i for i, line in enumerate(lines) if start.search(line)), None)
    last = next((i for i in range(first or 0, len(lines)) if end.search(lines[i])), None) if first is not None else None
    if first is None or last is None:
        raise SystemExit(f"build_site: the hero's excerpt of the {lang} example is gone; update HERO_CUT")
    return textwrap.dedent("\n".join(lines[first:last + 1]))


def sdk_hero_code(catalog: dict, data: dict | None) -> str:
    """The first calls of reading a library, in two languages as tabs (the language the page follows)."""
    if not data:
        return ""
    wanted = {e["language"]: e for e in data.get("examples", []) if e.get("id") == "read-library" and e.get("language") in HERO_CUT}
    if not wanted:
        return ""
    inputs, panels = "", ""
    for n, lang in enumerate(lang for lang in SDK_LANGS if lang in wanted):
        example = wanted[lang]
        ident = f"hero-{lang}"
        path = html.escape(str(example.get("path", "")), quote=True)
        inputs += (f'<input type="radio" name="hero-code" id="{ident}" data-lang="{lang}"{" checked" if n == 0 else ""}>'
                   f'<label for="{ident}">{SDK_NAMES[lang]}</label>')
        panels += (f'<div class="panel"><pre tabindex="0"><code class="language-{lang}">'
                   f'{sdk_highlight(sdk_hero_excerpt(str(example.get("source", "")), lang), lang)}</code></pre>'
                   f'<p class="note"><a href="{SDK_REPO}/blob/main/{path}">{path}</a></p></div>')
    return f'<div class="hero-code"><div class="tabs">{inputs}<div class="panels">{panels}</div></div></div>'


# ---- The page.

def page_header(language: str, catalog: dict, root: str) -> str:
    return SDK.header(language, catalog, root, "", links=[
        ("nav_spec", f"{LANTERN_URL}spec/"), ("footer_conformance", f"{LANTERN_URL}conformance/"),
        ("nav_bridge", BRIDGE_URL),
    ], cta=("sdk_cta_link", REPO), label=catalog["nav_label"], latest=VERSIONS)


def page_footer(language: str, catalog: dict, root: str) -> str:
    return SDK.footer(language, catalog, root, columns=[
        (catalog["nav_project"], [(catalog["nav_spec"], f"{LANTERN_URL}spec/"), (catalog["footer_conformance"], f"{LANTERN_URL}conformance/"),
                                  (catalog["nav_bridge"], BRIDGE_URL)]),
        (catalog["footer_label"], [("GitHub", REPO), (catalog["footer_issues"], f"{REPO}/issues")]),
    ], fine=catalog["footer_trademarks"])


def page_html(template: str, language: str, catalog: dict, sections: dict, lost: bool = False) -> str:
    root = "../" * (0 if language == ENGLISH else 1)
    if lost:
        root = boreale.urlparse(SITE_URL).path if hasattr(boreale, "urlparse") else "/"  # 404.html is served at any depth
    values = dict(catalog)
    values.update({
        "lang": boreale.html_lang(language), "root": root, "home": folder(language), "site": SITE_URL, "page": "sdk",
        "url": SITE_URL + folder(language), "title": catalog["title_sdk"],
        "description": html.escape(catalog["description_sdk"], quote=True), "og_locale": OG_LOCALES[language], "social": f"social/{language}.jpg",
        "first_visit": "", "indexing": SDK.indexing(language, ""),
        "skip": SDK.skip(catalog), "sky": SDK.sky(home=False), "header": page_header(language, catalog, root),
        "crumbs": "", "main_class": ' class="wrap"', "footer": page_footer(language, catalog, root),
        "audience": SDK.audience(root), "repo": REPO, "lantern": LANTERN_URL,
        "hero": (f'<div class="wrap hero small hero-sdk">\n    <div class="hero-text"><span class="eyebrow">{catalog["sdk_eyebrow"]}</span>\n'
                 f'    <h1>{catalog["sdk_title"]}</h1>\n    <p class="lede">{catalog["sdk_lede"]}</p></div>\n'
                 f'    {sdk_hero_code(catalog, sdk_data())}\n  </div>'),
        "scripts": (f'<script src="{root}assets/code.js" defer data-copy="{html.escape(catalog["ui_copy"], quote=True)}" '
                    f'data-copied="{html.escape(catalog["ui_copied"], quote=True)}" '
                    f'data-failed="{html.escape(catalog["ui_copy_failed"], quote=True)}"></script>\n'
                    f'<script src="{root}assets/sdk.js" defer></script>\n'
                    f'<script src="{root}assets/playground.js" defer></script>'),
    })
    values["structured"] = structured_data(language, catalog)
    if lost:
        # The root's 404.html (the English one) sends a visitor reading another language to that language's 404.html
        # (boreale-site's lang.js); the site's path tells it where.
        values.update({
            "title": catalog["lost_page_title"], "description": html.escape(catalog["lost_text"], quote=True),
            "indexing": SDK.indexing(language, "", True), "structured": "", "hero": "", "scripts": "",
            "lost": f' data-lost="{root}"' if language == ENGLISH else "",
        })
        body = (SITE / "lost.html").read_text(encoding="utf-8")
    else:
        values["lost"] = ""
        values.update(sdk_values(catalog, root, sections))
        body = (SITE / "home.html").read_text(encoding="utf-8")
    values["body"] = fill(body, values)
    return SDK.links_out(fill(template, values))


def structured_data(language: str, catalog: dict) -> str:
    """What the page is, for search engines: schema.org's SoftwareSourceCode, in the page's language. A data block,
    which the Content-Security-Policy leaves alone."""
    data = {
        "@context": "https://schema.org", "@type": "SoftwareSourceCode", "name": "Lantern SDK",
        "description": catalog["description_sdk"], "url": SITE_URL + folder(language), "codeRepository": REPO,
        "programmingLanguage": [SDK_NAMES[lang] for lang in SDK_LANGS], "license": "https://spdx.org/licenses/MIT.html",
        "inLanguage": boreale.html_lang(language), "isPartOf": {"@type": "SoftwareSourceCode", "name": "Lantern", "url": LANTERN_URL},
    }
    return '<script type="application/ld+json">' + json.dumps(data, ensure_ascii=False).replace("<", "\\u003c") + "</script>"


def main() -> None:
    global VERSIONS
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = Path(sys.argv[1])
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    shutil.copytree(SITE / "assets", out / "assets")
    boreale.copy_assets(out)
    catalogs = boreale.catalogs(SITE / "i18n")
    template = (SITE / "template.html").read_text(encoding="utf-8")
    VERSIONS = boreale.latest_versions()
    sections = spec_sections()
    urls = []
    for language, _, _, _ in LANGUAGES:
        target = out / folder(language) / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(page_html(template, language, catalogs[language], sections), encoding="utf-8")
        (target.parent / "404.html").write_text(page_html(template, language, catalogs[language], sections, lost=True), encoding="utf-8")
        urls.append(SITE_URL + folder(language))
    (out / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "".join(f"  <url><loc>{html.escape(u)}</loc></url>\n" for u in urls) + "</urlset>\n", encoding="utf-8")
    (out / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}sitemap.xml\n", encoding="utf-8")
    host = boreale.urlparse(SITE_URL).hostname if hasattr(boreale, "urlparse") else SITE_URL.split("/")[2]
    if host and not host.endswith("github.io"):
        (out / "CNAME").write_text(host + "\n", encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    print(f"build_site: {len(urls)} pages in {out}")


VERSIONS: dict = {}

if __name__ == "__main__":
    main()
