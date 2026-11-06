#!/usr/bin/env python3
"""Runs the specification's conformance suite against the C++ demo server.

    python3 run_conformance.py --demo lantern_demo_server --suite spec/conformance/run.py [--origin ORIGIN]

It starts the demo (examples/demo_server.cpp, on a free loopback port, which
the demo prints as its URL), runs `run.py URL --origin ORIGIN` against it as
an anonymous client, and stops the demo. It fails when the suite reports a
failed check, or when Lantern Core is not among the levels it reaches. Checks
that need a token are skipped by the suite, as for any anonymous run; warnings
(plain HTTP on loopback, JSON that is not compressed) are allowed. Standard
library only; the suite's schema checks need jsonschema and referencing
(spec/tools/requirements.txt), and are left out without them.
"""
import argparse
import importlib.util
import re
import subprocess
import sys

ORIGIN = "https://app.example.org"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--demo", required=True, help="the demo server's executable")
    parser.add_argument("--suite", required=True, help="spec/conformance/run.py")
    parser.add_argument("--origin", default=ORIGIN, help="the origin the demo allows (CORS)")
    args = parser.parse_args()

    demo = subprocess.Popen([args.demo, "0"], stdout=subprocess.PIPE, text=True)
    try:
        url = demo.stdout.readline().strip()
        if not url.startswith("http://127.0.0.1:"):
            print(f"the demo server did not say where it listens: {url!r}", file=sys.stderr)
            return 1
        command = [sys.executable, args.suite, url, "--origin", args.origin]
        if any(importlib.util.find_spec(m) is None for m in ("jsonschema", "referencing")):
            command.append("--no-schemas")
        run = subprocess.run(command, capture_output=True, text=True, check=False)
    finally:
        demo.terminate()
        demo.wait(timeout=10)
    print(run.stdout)
    print(run.stderr, file=sys.stderr)
    summary = re.search(r"(\d+) passed, (\d+) failed, (\d+) warning\(s\), (\d+) skipped", run.stdout)
    levels = re.search(r"Levels reached[^\n]*:\s*([^\n]*)", run.stdout)
    if summary is None or levels is None:
        print("the suite's report could not be read", file=sys.stderr)
        return 1
    failed = int(summary.group(2))
    if failed or "Lantern Core" not in levels.group(1):
        print(f"{failed} check(s) failed; levels reached: {levels.group(1)}", file=sys.stderr)
        return 1
    print(f"conformance: {summary.group(0)}; levels reached: {levels.group(1)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
