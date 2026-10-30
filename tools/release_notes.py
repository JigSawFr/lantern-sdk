#!/usr/bin/env python3
"""A release's notes, one section per language (RELEASING.md).

    python3 tools/release_notes.py 0.5.0 [--sums dist/SHA256SUMS] > notes.md

release-please writes one CHANGELOG.md for the SDK, its entries sorted by
type; the release page sorts them again by language, from each entry's
Conventional Commits scope (`feat(cpp): …` under C++). Above them: a
summary written by hand when there is one (.github/release-notes/X.Y.Z.md),
what each language's package is and which draft of the specification it
follows (read from the libraries themselves), how to fetch the C++ library
with CMake, and how to verify the files.

Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/JigSawFr/lantern-sdk"

# Scope -> language; any other scope (sdk, spec, repo, release…) is everyone's
LANGUAGES = {"cpp": "C++", "c": "C", "python": "Python", "typescript": "TypeScript"}
ORDER = ["C++", "C", "Python", "TypeScript", "Every language"]


def draft(path: str, pattern: str) -> str:
    file = ROOT / path
    match = re.search(pattern, file.read_text(encoding="utf-8")) if file.exists() else None
    return match.group(1) if match else "?"


def drafts() -> dict[str, str]:
    """The specification's draft each language follows, as it states it."""
    return {
        "C++": draft("cpp/include/lantern/lantern.hpp", r'spec_draft = "([^"]+)"'),
        "C": draft("c/include/lantern/lantern.h", r'#define LANTERN_SPEC_DRAFT "([^"]+)"'),
        "Python": draft("python/src/lantern/_version.py", r'SPEC_DRAFT = "([^"]+)"'),
        "TypeScript": draft("typescript/README.md", r"\*\*draft (\d+\.\d+)\*\*"),
    }


def changelog(version: str) -> list[tuple[str, str, str]]:
    """(language, section, entry) for each entry of CHANGELOG.md's section for this version."""
    path = ROOT / "CHANGELOG.md"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    start = re.search(rf"^## \[?{re.escape(version)}\]?.*$", text, flags=re.M)
    if not start:
        return []
    following = re.search(r"^## ", text[start.end() :], flags=re.M)
    body = text[start.end() : start.end() + following.start()] if following else text[start.end() :]
    entries = []
    section = "Changes"
    for line in body.splitlines():
        heading = re.match(r"^### (.+)$", line)
        if heading:
            section = heading.group(1).strip()
            continue
        item = re.match(r"^\* (?:\*\*([\w.-]+):\*\* )?(.+)$", line)
        if item:
            scope, entry = item.group(1), item.group(2)
            entries.append((LANGUAGES.get(scope or "", "Every language"), section, entry))
    return entries


def sums(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        out[name.lstrip("*")] = digest
    return out


def notes(version: str, sums_path: Path | None) -> str:
    tag = f"v{version}"
    download = f"{REPO}/releases/download/{tag}"
    draft_of = drafts()
    hashes = sums(sums_path)
    out: list[str] = []
    summary = ROOT / ".github" / "release-notes" / f"{version}.md"
    if summary.exists():
        out += [summary.read_text(encoding="utf-8").strip(), ""]
    out += [
        f"One version for the whole SDK, {version}, in every language. Each library follows a draft of "
        "[the Lantern specification](https://github.com/JigSawFr/lantern):",
        "",
        "| Language | Package | Specification | Get it |",
        "|---|---|---|---|",
        f"| C++ | CMake package `Lantern` (`Lantern::lantern`) | draft {draft_of['C++']} | "
        f"[`lantern-cpp-{version}-linux-x86_64.tar.gz`]({download}/lantern-cpp-{version}-linux-x86_64.tar.gz), "
        "or the source with CMake (below) |",
        f"| C | CMake package `LanternC` (`Lantern::c`, `liblantern_c.so.1`) | draft {draft_of['C']} | "
        f"[`lantern-c-{version}-linux-x86_64.tar.gz`]({download}/lantern-c-{version}-linux-x86_64.tar.gz), "
        "or the source |",
        f"| Python | [`lantern-protocol`](https://pypi.org/project/lantern-protocol/{version}/) | "
        f"draft {draft_of['Python']} | `pip install lantern-protocol=={version}` |",
        f"| TypeScript | [`lantern-protocol`](https://www.npmjs.com/package/lantern-protocol/v/{version}) | "
        f"draft {draft_of['TypeScript']} | `npm install lantern-protocol@{version}` |",
        "",
    ]
    entries = changelog(version)
    for language in ORDER:
        mine = [(section, entry) for lang, section, entry in entries if lang == language]
        if not mine:
            continue
        out += [f"## {language}", ""]
        for section in dict.fromkeys(section for section, _ in mine):
            out += [f"### {section}", ""]
            out += [f"* {entry}" for s, entry in mine if s == section]
            out.append("")
    if not entries:
        out += [f"The changes: [CHANGELOG.md]({REPO}/blob/{tag}/CHANGELOG.md).", ""]
    source = f"lantern-sdk-{version}.tar.gz"
    url_hash = f"\n    URL_HASH SHA256={hashes[source]}" if source in hashes else ""
    out += [
        "## The C++ library from CMake",
        "",
        "```cmake",
        "include(FetchContent)",
        "FetchContent_Declare(lantern",
        f"    URL {download}/{source}{url_hash}",
        "    SOURCE_SUBDIR cpp)",
        "FetchContent_MakeAvailable(lantern)",
        "target_link_libraries(my_app PRIVATE Lantern::lantern)",
        "```",
        "",
        "`SOURCE_SUBDIR c` and `Lantern::c` (or `Lantern::c_static`) give the C API the same way.",
        "",
        "## Verifying",
        "",
        "Every file here was built by this repository's release workflow, from the tag's commit, and is "
        "attested (SLSA build provenance, signed with Sigstore); each package also has its SBOM "
        "(CycloneDX), attested with it. `SHA256SUMS` lists every file.",
        "",
        "```sh",
        f"gh release download {tag} -R JigSawFr/lantern-sdk",
        "sha256sum -c SHA256SUMS",
        f"gh attestation verify lantern-sdk-{version}.tar.gz -R JigSawFr/lantern-sdk",
        f"gh attestation verify lantern-cpp-{version}-linux-x86_64.tar.gz -R JigSawFr/lantern-sdk \\",
        "    --predicate-type https://cyclonedx.org/bom",
        "```",
        "",
        "PyPI keeps the Python package's own attestations (PEP 740), npm the TypeScript package's provenance "
        f"(`npm audit signatures`). The Python package, the npm tarball and the source archive can be rebuilt "
        f"byte for byte: `tools/reproduce.sh release {tag}`. "
        f"[SECURITY.md]({REPO}/blob/{tag}/SECURITY.md#verifying-a-release) says more.",
    ]
    return "\n".join(out).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("version", help="X.Y.Z, without the v")
    parser.add_argument("--sums", type=Path, help="the release's SHA256SUMS, for the CMake snippet's hash")
    args = parser.parse_args(argv)
    sys.stdout.write(notes(args.version, args.sums))
    return 0


if __name__ == "__main__":
    sys.exit(main())
