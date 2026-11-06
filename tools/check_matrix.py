#!/usr/bin/env python3
"""Checks the table of families by language in README.md.

The table says, for every family of the specification (SPEC.md § 4.2) and
every library, whether it reads the family as a client and whether it serves
it ("client / server": ✓ yes, – no, ◐ part of it). What can be shown is:

- the rows are the families of the Python library's vocabulary, in its order,
  and those of the TypeScript library's, the same;
- a server toolkit that is checked (Python's, TypeScript's) shows ✓ for exactly
  the families its demo offers a caller who holds every scope;
- no other server claims ✓: it would have no conformance run to show it.

  tools/check_matrix.py        (from the repository's root; needs uv and node)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
#: The columns of the table, in order, and which of them are servers that are checked.
LIBRARIES = ("C++", "C", "Python", "TypeScript", "Rust")
CHECKED = ("Python", "TypeScript")
CELL = re.compile(r"^(✓|–) / (✓|–|◐)$")


def run(command: list[str], folder: str) -> dict[str, list[str]]:
    done = subprocess.run(command, cwd=ROOT / folder, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        sys.exit(f"{' '.join(command)} (in {folder}) failed:\n{done.stderr}")
    return json.loads(done.stdout.strip().splitlines()[-1])


def table() -> list[tuple[str, dict[str, str]]]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    found = re.search(r"<!-- families:start -->(.*?)<!-- families:end -->", text, re.S)
    if found is None:
        sys.exit("README.md has no table between <!-- families:start --> and <!-- families:end -->")
    rows = [line for line in found.group(1).splitlines() if line.startswith("|")]
    header = [c.strip() for c in rows[0].strip("|").split("|")]
    if header != ["Family", *LIBRARIES]:
        sys.exit(f"the table's columns are {header}, not {['Family', *LIBRARIES]}")
    out = []
    for row in rows[2:]:
        cells = [c.strip() for c in row.strip("|").split("|")]
        if len(cells) != len(header):
            sys.exit(f"a row with {len(cells)} cells: {row}")
        for library, cell in zip(LIBRARIES, cells[1:], strict=True):
            if CELL.match(cell) is None:
                sys.exit(f"{cells[0]} / {library}: '{cell}' is not '✓ / ✓', '– / –'… (client / server)")
        out.append((cells[0].strip("`"), dict(zip(LIBRARIES, cells[1:], strict=True))))
    return out


def main() -> None:
    python = run(["uv", "run", "python", "tools/families.py"], "python")
    typescript = run(["node", "tools/families.ts"], "typescript")
    problems: list[str] = []
    if python["families"] != typescript["families"]:
        problems.append(f"Python's families {python['families']} are not TypeScript's {typescript['families']}")
    rows = table()
    if [name for name, _ in rows] != python["families"]:
        problems.append(f"the table's rows {[n for n, _ in rows]} are not the families {python['families']}")
    served = {"Python": set(python["server"]), "TypeScript": set(typescript["server"])}
    for name, cells in rows:
        for library, cell in cells.items():
            server = cell.split(" / ")[1]
            if library in CHECKED:
                if (server == "✓") != (name in served[library]):
                    problems.append(f"{name} / {library}: the table says '{server}', the demo server {'offers' if name in served[library] else 'does not offer'} it")
            elif server == "✓":
                problems.append(f"{name} / {library}: a server marked ✓ needs a conformance run in CI, and this check knows none for it")
    if problems:
        sys.exit("README.md's table of families:\n  " + "\n  ".join(problems))
    print(f"the table of {len(rows)} families agrees with the Python and TypeScript servers")


if __name__ == "__main__":
    main()
