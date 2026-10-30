#!/usr/bin/env python3
"""The C API's ABI as text, kept in c/abi/lantern.abi, so that every change
to it shows in a diff and the ABI policy (c/README.md) is checked:

    python3 c/tools/abi_dump.py              # prints the dump
    python3 c/tools/abi_dump.py --update     # writes c/abi/lantern.abi
    python3 c/tools/abi_dump.py --check [--library liblantern_c.so]

The dump lists, from c/include/lantern/*.h: the macros, every enum constant
and its value, every typedef, every struct with its members in order, and
every exported function's prototype, one per line, sorted.

--check compares the headers with the dump kept, and fails on any
difference, saying which kind it is:
- a removal or a change (a function's prototype, a constant's value, a
  struct's members other than appended ones, a struct without struct_size
  that grew) breaks the ABI: LANTERN_C_ABI_VERSION must go up with it;
- an addition (a function, a constant, members appended to a struct that
  begins with struct_size) needs LANTERN_C_API_VERSION one higher.
In both cases the dump is then written again (--update) and committed with
the change. With --library, the shared library's exported symbols (nm) must
be exactly the functions of the dump.

Standard library only; nm (binutils or LLVM) for --library.
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
C = HERE.parent
HEADERS = [C / "include" / "lantern" / "lantern.h", C / "include" / "lantern" / "lantern_documents.h"]
DUMP = C / "abi" / "lantern.abi"


def strip(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def squash(text):
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s*([(),;*\[\]])\s*", r"\1", text)
    return text.replace(",", ", ")


def entries(headers):
    """{key: value}: key is "kind name"."""
    out = {}
    for path in headers:
        raw = path.read_text(encoding="utf-8")
        for name, value in re.findall(r"^#define (LANTERN_[A-Z0-9_]+) (\S.*)$", raw, flags=re.M):
            if name in ("LANTERN_API", "LANTERN_INIT") or name.endswith("_H"):
                continue
            out[f"define {name}"] = value.strip()
        text = strip(raw)
        # The export macro's own definitions are not part of the ABI
        text = re.sub(r"^#.*$", " ", text, flags=re.M)
        for body in re.findall(r"\benum\s*\{(.*?)\}\s*;", text, flags=re.S):
            for name, value in re.findall(r"(LANTERN_[A-Z0-9_]+)\s*=\s*(-?\d+)", body):
                out[f"constant {name}"] = value
        for body, name in re.findall(r"typedef\s+struct\s+\w+\s*\{(.*?)\}\s*(\w+)\s*;", text, flags=re.S):
            members = [squash(m) for m in body.split(";") if m.strip()]
            out[f"struct {name}"] = "; ".join(members)
        for name in re.findall(r"typedef\s+struct\s+(\w+)\s+\1\s*;", text):
            out.setdefault(f"opaque {name}", "")
        for base, name in re.findall(r"typedef\s+(int32_t|uint32_t|int64_t)\s+(\w+)\s*;", text):
            out[f"typedef {name}"] = base
        for declaration in re.findall(r"typedef\s+[^;{]*\(\s*\*\s*\w+\s*\)\s*\([^;]*\)\s*;", text, flags=re.S):
            name = re.search(r"\(\s*\*\s*(\w+)\s*\)", declaration).group(1)
            out[f"callback {name}"] = squash(declaration)
        for declaration in re.findall(r"LANTERN_API\s+([^;]*?\))\s*;", text, flags=re.S):
            name = re.search(r"(lantern_\w+)\s*\(", declaration).group(1)
            out[f"function {name}"] = squash(declaration)
    return out


def render(found):
    lines = ["# The C API's ABI, from c/include/lantern (python3 c/tools/abi_dump.py --update).",
             "# Kept so that each change shows; c/README.md says what may change."]
    for key in sorted(found):
        value = found[key]
        lines.append(f"{key}: {value}" if value else key)
    return "\n".join(lines) + "\n"


def parse(text):
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(": ")
        out[key] = value
    return out


def compare(kept, found):
    """(breaking, additions) between the dump kept and the headers."""
    breaking, additions = [], []
    for key, value in kept.items():
        if key.startswith("define LANTERN_C_") or key.startswith("define LANTERN_VERSION") or key.startswith(
                "define LANTERN_SPEC"):
            continue
        if key not in found:
            breaking.append(f"removed: {key}")
        elif found[key] != value:
            if key.startswith("struct "):
                old, new = value.split("; "), found[key].split("; ")
                if old[0] == "size_t struct_size" and new[:len(old)] == old:
                    additions.append(f"appended to {key}: {'; '.join(new[len(old):])}")
                    continue
            breaking.append(f"changed: {key}: {value} -> {found[key]}")
    for key in found:
        if key not in kept:
            additions.append(f"added: {key}")
    return breaking, additions


def exported(library):
    nm = shutil.which("nm") or shutil.which("llvm-nm")
    if nm is None:
        raise SystemExit("abi_dump.py: no nm to read the library's symbols")
    args = [nm, "-g", "-U", library] if sys.platform == "darwin" else [nm, "-D", "--defined-only", library]
    listed = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    names = set()
    for line in listed.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "t", "W"):
            names.add(parts[2].lstrip("_") if sys.platform == "darwin" else parts[2].split("@")[0])
    return names


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--update", action="store_true", help="write c/abi/lantern.abi")
    p.add_argument("--check", action="store_true", help="fail when the headers differ from the dump kept")
    p.add_argument("--library", help="the shared library, whose exports must be the dump's functions")
    args = p.parse_args(argv)
    found = entries(HEADERS)
    text = render(found)
    if args.update:
        DUMP.parent.mkdir(parents=True, exist_ok=True)
        DUMP.write_text(text, encoding="utf-8")
        print(f"wrote {DUMP.relative_to(C.parent)}: {sum(k.startswith('function ') for k in found)} functions")
        return 0
    if not args.check:
        sys.stdout.write(text)
        return 0
    status = 0
    kept_text = DUMP.read_text(encoding="utf-8") if DUMP.exists() else ""
    if kept_text != text:
        kept = parse(kept_text)
        breaking, additions = compare(kept, found)
        api = (kept.get("define LANTERN_C_API_VERSION"), found.get("define LANTERN_C_API_VERSION"))
        abi = (kept.get("define LANTERN_C_ABI_VERSION"), found.get("define LANTERN_C_ABI_VERSION"))
        for line in breaking:
            print(f"ABI break: {line}", file=sys.stderr)
        for line in additions:
            print(f"ABI addition: {line}", file=sys.stderr)
        if breaking and abi[0] == abi[1]:
            print("abi_dump.py: the ABI breaks and LANTERN_C_ABI_VERSION did not go up (c/README.md)", file=sys.stderr)
        if additions and api[0] == api[1]:
            print("abi_dump.py: the API grew and LANTERN_C_API_VERSION did not go up", file=sys.stderr)
        print("abi_dump.py: c/abi/lantern.abi is not the headers': run python3 c/tools/abi_dump.py --update "
              "and commit it with the change", file=sys.stderr)
        status = 1
    else:
        print(f"ABI: as kept ({sum(k.startswith('function ') for k in found)} functions)")
    if args.library:
        functions = {key.split(" ", 1)[1] for key in found if key.startswith("function ")}
        names = exported(args.library)
        extra = sorted(names - functions)
        missing = sorted(functions - names)
        for name in extra[:20]:
            print(f"exported but not declared: {name}", file=sys.stderr)
        for name in missing[:20]:
            print(f"declared but not exported: {name}", file=sys.stderr)
        if extra or missing:
            status = 1
        else:
            print(f"exports: {len(names)} symbols, exactly the declared functions")
    return status


if __name__ == "__main__":
    sys.exit(main())
