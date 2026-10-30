#!/usr/bin/env python3
"""The SDK's one version, as every language states it (RELEASING.md).

release-please writes the version into the files release-please-config.json
lists as extra-files (a marker x-release-please-version on the line, or a
block between x-release-please-start-version and x-release-please-end; a JSON
path for package.json). The release pull request's sync step then brings the
files derived from them along (typescript/package-lock.json, c/abi/lantern.abi).
This script reads them all back:

    python3 tools/release_versions.py              # the table; fails if a file states none
    python3 tools/release_versions.py --expect 0.5.0   # and fails unless each says 0.5.0
    python3 tools/release_versions.py --manifest   # the last release's version

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "release-please-config.json"
MANIFEST = ROOT / ".release-please-manifest.json"
SEMVER = re.compile(r"\b\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[-\w.]+)?\b")

# Files release-please does not write, made from those it does by the release
# pull request's sync step: (path, how to read the version)
DERIVED = [
    ("typescript/package-lock.json", "json:$.version"),
    ("typescript/package-lock.json", 'json:$.packages[""].version'),
    ("c/abi/lantern.abi", r're:^define LANTERN_VERSION_STRING: "([^"]+)"$'),
]


def json_path(document: object, path: str) -> object:
    """The value at a simple JSON path: $.a.b or $.a["b"]."""
    value = document
    for key in re.findall(r'\.([A-Za-z_][\w-]*)|\["([^"]*)"\]', path.removeprefix("$")):
        name = key[0] or key[1]
        if not isinstance(value, dict) or name not in value:
            return None
        value = value[name]
    return value


def generic(text: str) -> list[str]:
    """The versions release-please's generic updater would rewrite."""
    found: list[str] = []
    in_block = False
    for line in text.splitlines():
        if "x-release-please-start-version" in line:
            in_block = True
            continue
        if "x-release-please-end" in line:
            in_block = False
            continue
        if in_block or "x-release-please-version" in line:
            found.extend(m.group(0) for m in SEMVER.finditer(line))
    return found


def read(path: str, how: str) -> list[str]:
    file = ROOT / path
    if not file.exists():
        return []
    text = file.read_text(encoding="utf-8")
    if how == "generic":
        return generic(text)
    if how.startswith("json:"):
        value = json_path(json.loads(text), how.removeprefix("json:"))
        return [value] if isinstance(value, str) else []
    if how.startswith("re:"):
        return re.findall(how.removeprefix("re:"), text, flags=re.M)
    raise SystemExit(f"release_versions.py: unknown way of reading {path}: {how}")


def locations() -> list[tuple[str, str]]:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    out = []
    for listed in config["packages"]["."].get("extra-files", []):
        entry = {"type": "generic", "path": listed} if isinstance(listed, str) else listed
        how = "generic" if entry["type"] == "generic" else f"json:{entry['jsonpath']}"
        if entry["type"] not in ("generic", "json"):
            raise SystemExit(f"release_versions.py: an extra-file of type {entry['type']} is not read here")
        out.append((entry["path"], how))
    return out + DERIVED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--expect", metavar="VERSION", help="fail unless every file states this version")
    parser.add_argument("--manifest", action="store_true", help="print the manifest's version and stop")
    args = parser.parse_args(argv)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))["."]
    if args.manifest:
        print(manifest)
        return 0
    status = 0
    seen: set[str] = set()
    print(f"{'file':<40} version")
    for path, how in locations():
        versions = read(path, how)
        shown = ", ".join(versions) if versions else "(none)"
        print(f"{path:<40} {shown}")
        seen.update(versions)
        if not versions:
            print(f"::error file={path}::release_versions.py: no version found ({how})", file=sys.stderr)
            status = 1
        elif args.expect and any(v != args.expect for v in versions):
            print(f"::error file={path}::release_versions.py: {shown}, not {args.expect}", file=sys.stderr)
            status = 1
    print(f"{'.release-please-manifest.json':<40} {manifest} (the last release)")
    if not args.expect and len(seen) > 1:
        # Between releases the languages may disagree (one moved to a new
        # draft before the others); release-please's pull request makes
        # them one, and the release checks it with --expect.
        print(
            f"::warning::release_versions.py: the files state {', '.join(sorted(seen))}; the release pull "
            "request makes them one",
            file=sys.stderr,
        )
    return status


if __name__ == "__main__":
    sys.exit(main())
