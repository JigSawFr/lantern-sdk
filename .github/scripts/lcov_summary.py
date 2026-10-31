#!/usr/bin/env python3
"""A coverage report in LCOV's format, as a Markdown table for a job's summary.

    lcov_summary.py <title> <file.lcov> [--strip <prefix>] >> "$GITHUB_STEP_SUMMARY"

One row per source file (lines, functions and branches covered, in per cent),
the least covered first, then the total. cpp.yml's coverage job writes it with
llvm-cov export --format=lcov.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Counts:
    lines: int = 0
    lines_hit: int = 0
    functions: int = 0
    functions_hit: int = 0
    branches: int = 0
    branches_hit: int = 0

    def add(self, other: Counts) -> None:
        self.lines += other.lines
        self.lines_hit += other.lines_hit
        self.functions += other.functions
        self.functions_hit += other.functions_hit
        self.branches += other.branches
        self.branches_hit += other.branches_hit


def percent(hit: int, total: int) -> str:
    return f"{100 * hit / total:.1f} %" if total else "–"


def read(path: Path, strip: str) -> dict[str, Counts]:
    files: dict[str, Counts] = {}
    name = ""
    counts = Counts()
    keys = {"LF": "lines", "LH": "lines_hit", "FNF": "functions", "FNH": "functions_hit", "BRF": "branches", "BRH": "branches_hit"}
    for raw in path.read_text(encoding="utf-8").splitlines():
        key, _, value = raw.partition(":")
        if key == "SF":
            name = value.removeprefix(strip)
            counts = files.setdefault(name, Counts())
        elif key in keys:
            setattr(counts, keys[key], getattr(counts, keys[key]) + int(value))
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("title")
    parser.add_argument("lcov", type=Path)
    parser.add_argument("--strip", default="", help="a prefix to remove from the file names")
    args = parser.parse_args()

    files = read(args.lcov, args.strip)
    total = Counts()
    for counts in files.values():
        total.add(counts)

    out = sys.stdout
    out.write(f"### {args.title}\n\n")
    out.write(f"**{percent(total.lines_hit, total.lines)}** of {total.lines} lines, ")
    out.write(f"{percent(total.functions_hit, total.functions)} of the functions, ")
    out.write(f"{percent(total.branches_hit, total.branches)} of the branches, in {len(files)} files.\n\n")
    out.write("<details><summary>Per file, the least covered first</summary>\n\n")
    out.write("| File | Lines | Functions | Branches |\n|---|--:|--:|--:|\n")
    for name, c in sorted(files.items(), key=lambda item: (item[1].lines_hit / (item[1].lines or 1), item[0])):
        out.write(
            f"| `{name}` | {percent(c.lines_hit, c.lines)} | {percent(c.functions_hit, c.functions)} "
            f"| {percent(c.branches_hit, c.branches)} |\n"
        )
    out.write("\n</details>\n\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
