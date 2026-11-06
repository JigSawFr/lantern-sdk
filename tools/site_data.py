#!/usr/bin/env python3
"""Writes and checks sdk.json: what the SDK says about itself, for lantern.boreale.dev's SDK page.

    python3 tools/site_data.py            # prints the document
    python3 tools/site_data.py --write    # writes sdk.json at the root
    python3 tools/site_data.py --check    # fails unless sdk.json is what the sources say

The file is a format read by another program (the site's build), so it carries `schema` (1) as every such format
does: a field added keeps it, a field that changes meaning raises it, and a reader skips what it does not know.

    schema     1
    sdk        version, spec_draft, c_api_version, c_abi_version, release (null until a release is published),
               repository, releases (the page of releases)
    languages  [id, name, folder (null: planned), status (complete | building | planned), role (client | both),
               package, install (null before the first release), requires, adapters, readme, doc_languages?]
    families   [family, support: {language: {client, server}}]  (yes | partial | no, from the README's table)
    levels     {language: "Lantern Core +titles …"} the levels the language's server reaches in CI
    calls      [id, spec, calls: {language: name | null}, where: {language: file}]  (tools/sdk-calls.json)
    examples   [id, language, path, title, source]  (the files of each language's examples/ folder)

Everything is read from the sources (versions, the README's table, the files of examples/, the calls' names),
so it cannot drift; what is said by hand (a language's role, its install line) is in LANGUAGES below.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "sdk.json"
SCHEMA = 1
REPOSITORY = "https://github.com/JigSawFr/lantern-sdk"

#: What cannot be read from the sources: how each language is used. `install` is for after the first release.
LANGUAGES: list[dict[str, Any]] = [
    {
        "id": "cpp", "name": "C++23", "folder": "cpp", "status": "complete", "role": "both",
        "package": "lantern", "install": None, "adapters": ["libcurl", "mbedTLS", "POSIX sockets"],
    },
    {
        "id": "c", "name": "C", "folder": "c", "status": "complete", "role": "client",
        "package": "lantern (C ABI)", "install": None, "adapters": ["Swift", "Kotlin (JNI)"],
    },
    {
        "id": "python", "name": "Python", "folder": "python", "status": "complete", "role": "both",
        "package": "lantern-protocol", "install": "pip install lantern-protocol", "adapters": ["Flask", "FastAPI", "httpx"],
    },
    {
        "id": "typescript", "name": "TypeScript", "folder": "typescript", "status": "complete", "role": "both",
        "package": "lantern-protocol", "install": "npm install lantern-protocol", "adapters": ["node:http", "Hono (web Requests)"],
    },
    {
        "id": "go", "name": "Go", "folder": "go", "status": "building", "role": "both",
        "package": "github.com/JigSawFr/lantern-sdk/go", "install": "go get github.com/JigSawFr/lantern-sdk/go",
        "adapters": ["net/http"],
    },
    {
        "id": "rust", "name": "Rust", "folder": "rust", "status": "building", "role": "both",
        "package": "lantern-protocol", "install": None, "adapters": [],
    },
]
#: Where each language's calls are looked for.
SOURCES = {"cpp": "cpp/include", "c": "c/include", "python": "python/src", "typescript": "typescript/src"}
SUFFIXES = {"cpp": {".hpp"}, "c": {".h"}, "python": {".py"}, "typescript": {".ts"}}
EXAMPLES = {"cpp": ("cpp/examples", {".cpp"}), "c": ("c/examples", {".c"}), "python": ("python/examples", {".py"}),
            "typescript": ("typescript/examples", {".ts"})}
LEVEL_FILES = {
    "python": ("python/tests/test_conformance.py", r'^LEVELS = "(.*)"$'),
    "typescript": ("typescript/test/integration/conformance.test.ts", r'^const LEVELS =\s*"(.*)";$'),
}
SUPPORT = {"✓": "yes", "◐": "partial", "–": "no"}
COLUMN_ID = {"C++": "cpp", "C": "c", "Python": "python", "TypeScript": "typescript", "Go": "go", "Rust": "rust"}


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def one(pattern: str, path: str) -> str:
    found = re.search(pattern, text(path), re.M)
    if found is None:
        sys.exit(f"site_data.py: {path}: no match for {pattern}")
    return found.group(1)


def sdk() -> dict[str, Any]:
    return {
        "version": one(r'^__version__ = "([^"]+)"', "python/src/lantern/_version.py"),
        "spec_draft": one(r'^SPEC_DRAFT = "([^"]+)"', "python/src/lantern/_version.py"),
        "c_api_version": int(one(r"^#define LANTERN_C_API_VERSION (\d+)", "c/include/lantern/lantern.h")),
        "c_abi_version": int(one(r"^#define LANTERN_C_ABI_VERSION (\d+)", "c/include/lantern/lantern.h")),
        "release": None,
        "repository": REPOSITORY,
        "releases": f"{REPOSITORY}/releases",
    }


def requires() -> dict[str, str]:
    pyproject = tomllib.loads(text("python/pyproject.toml"))
    node = json.loads(text("typescript/package.json"))["engines"]["node"]
    return {
        "cpp": "C++23 (CMake 3.28)",
        "c": "C11, over the C++ library",
        "python": f"Python {pyproject['project']['requires-python'].removeprefix('>=')}+",
        "typescript": f"Node {node.removeprefix('>=')}+ or a browser",
        "go": f"Go {one(r'^go (\S+)$', 'go/go.mod')}+",
        "rust": f"Rust {one(r'^rust-version = "(.*)"', 'rust/Cargo.toml')}+",
    }


def languages() -> list[dict[str, Any]]:
    needs = requires()
    out = []
    for entry in LANGUAGES:
        folder = entry["folder"]
        out.append({**entry, "requires": needs[entry["id"]], "readme": f"{folder}/README.md" if folder else None})
    return out


def families() -> list[dict[str, Any]]:
    found = re.search(r"<!-- families:start -->(.*?)<!-- families:end -->", text("README.md"), re.S)
    if found is None:
        sys.exit("site_data.py: README.md has no table of families")
    rows = [line for line in found.group(1).splitlines() if line.startswith("|")]
    header = [c.strip() for c in rows[0].strip("|").split("|")][1:]
    out = []
    for row in rows[2:]:
        cells = [c.strip() for c in row.strip("|").split("|")]
        support = {}
        for column, cell in zip(header, cells[1:], strict=True):
            client, server = (SUPPORT[part.strip()] for part in cell.split("/"))
            support[COLUMN_ID[column]] = {"client": client, "server": server}
        out.append({"family": cells[0].strip("`"), "support": support})
    return out


def levels() -> dict[str, str]:
    return {lang: one(pattern, path) for lang, (path, pattern) in LEVEL_FILES.items()}


def calls() -> list[dict[str, Any]]:
    gestures = json.loads(text("tools/sdk-calls.json"))["gestures"]
    sources = {
        lang: [p for p in sorted((ROOT / folder).rglob("*")) if p.suffix in SUFFIXES[lang]]
        for lang, folder in SOURCES.items()
    }
    out = []
    for gesture in gestures:
        where: dict[str, str] = {}
        for lang, name in gesture["calls"].items():
            if name is None:
                continue
            word = re.compile(rf"\b{re.escape(name)}\b")
            hits = [p for p in sources[lang] if word.search(p.read_text(encoding="utf-8"))]
            if not hits:
                sys.exit(f"site_data.py: {gesture['id']}: {lang} has no `{name}` in {SOURCES[lang]}")
            where[lang] = hits[0].relative_to(ROOT).as_posix()
        out.append({"id": gesture["id"], "spec": gesture["spec"], "calls": gesture["calls"], "where": where})
    return out


def title_of(source: str) -> str:
    """The first sentence of a file's leading comment or docstring."""
    lines = []
    for line in source.lstrip().splitlines():
        bare = re.sub(r"^\s*(?:/\*\*?|\*/|\*|//|\"\"\"|#)", "", line).strip().strip('"')
        if not bare:
            if lines:
                break
            continue
        lines.append(bare)
    joined = " ".join(lines)
    return re.split(r"(?<=[a-z)`])\.(?:\s|$)", joined, maxsplit=1)[0].strip().rstrip(".:")


def examples() -> list[dict[str, Any]]:
    out = []
    for lang, (folder, suffixes) in EXAMPLES.items():
        for path in sorted((ROOT / folder).iterdir()):
            if path.suffix in suffixes and not path.name.startswith(("_", "CMake")):
                source = path.read_text(encoding="utf-8")
                out.append({
                    "id": path.stem.replace("_", "-"), "language": lang,
                    "path": path.relative_to(ROOT).as_posix(), "title": title_of(source), "source": source,
                })
    return out


def document() -> dict[str, Any]:
    return {
        "schema": SCHEMA, "sdk": sdk(), "languages": languages(), "families": families(),
        "levels": levels(), "calls": calls(), "examples": examples(),
    }


def render() -> str:
    return json.dumps(document(), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write", action="store_true", help="write sdk.json")
    parser.add_argument("--check", action="store_true", help="fail unless sdk.json is what the sources say")
    args = parser.parse_args(argv)
    now = render()
    if args.write:
        OUT.write_text(now, encoding="utf-8")
        print(f"wrote {OUT.relative_to(ROOT)}")
    elif args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != now:
            print("::error file=sdk.json::sdk.json is not what the sources say: python3 tools/site_data.py --write", file=sys.stderr)
            return 1
        print("sdk.json is up to date")
    else:
        sys.stdout.write(now)
    return 0


if __name__ == "__main__":
    sys.exit(main())
