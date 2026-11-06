#!/usr/bin/env python3
"""Runs the specification's conformance suite against the C++ demo server.

    python3 run_conformance.py --demo lantern_demo_server --suite spec/conformance/run.py [--origin ORIGIN]

The suite runs three times, each against a demo server of its own (the
pairing and invitation checks leave their address rate limited for a while):

- anonymously, against the public demo;
- with the demo console's token and its device key (--token, --key), against
  the public demo: the signed requests, the scopes, the pairing flow;
- with the same token against the private demo (`--private`), which asks for
  a token on the library.

Each run starts the demo (examples/demo_server.cpp, on a free loopback port,
which the demo prints as its URL), runs `run.py URL --origin ORIGIN`, and stops
the demo. It fails when a check fails, when a check of the families the demo
serves (the library with its titles, changes and sections, pairing, signatures) is
not a pass, when an unexpected
warning is raised, or, with the token, when Lantern Core and +titles are not among the
levels reached (without one the suite cannot check signed requests, and says
so).
Warnings allowed: plain HTTP on loopback, JSON that is not compressed. Standard
library only; the suite's schema checks need jsonschema and referencing
(spec/tools/requirements.txt), and are left out without them.
"""
import argparse
import base64
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
import tempfile

ORIGIN = "https://app.example.org"
# The demo console's token and the phrase its device key is made from: the
# same as examples/demo_accounts.hpp, for the demo only.
TOKEN = "et_demo-0123456789abcdef0123456789abcdef"
KEY_PHRASE = "Mira's fictional console key"

# The checks that must pass, not be skipped, by what the demo serves.
LIBRARY = [
    "handshake.well-known", "handshake.v1", "handshake.anonymous", "handshake.platforms",
    "auth.unknown-token", "auth.unknown-handshake", "auth.basic-refused",
    "apps.first-page", "apps.pages.name", "apps.pages.added", "apps.pages.release", "apps.sha256",
    "apps.platforms", "apps.page-size", "apps.bad-cursor", "apps.filters", "apps.etag",
    "platforms.filter", "platforms.query", "platforms.unknown", "platforms.bad-name", "platforms.vary",
    "missing.no-platform", "missing.installed", "missing.up-to-date", "missing.base", "missing.malformed",
    "files.whole", "files.ranges", "files.unsatisfiable", "files.unknown",
    "schema.refused.library", "errors.unknown-route", "errors.problem", "errors.never-200",
    "errors.www-authenticate", "auth.no-basic", "documents.schema", "documents.type", "documents.limits",
    "documents.date", "language.problem", "features.library",
    "cors.preflight", "cors.max-age", "cors.responses", "cors.other-origin", "cors.credentials",
]
# The families the library offers beside the apps: changes (§ 6.4), sections (§ 6.5; the suite only
# probes the route, as `features.sections`) and titles (§ 7), images and title changes included.
CATALOG = [
    "features.changes", "features.sections", "features.titles", "changes.token", "changes.bad-token",
    "titles.known", "titles.unknown", "titles.bulk", "titles.bulk-limit", "titles.images", "titles.changes",
    "titles.bad-token",
]
# Pairing (§ 5.2, § 5.4) is offered to every caller, anonymous included.
PAIRING = [
    "handshake.auth", "pairing.offered", "pairing.code", "pairing.verify-complete", "pairing.waiting",
    "pairing.slow-down", "pairing.unknown", "pairing.key", "pairing.after-slow-down",
    "invitations.rate-limit", "pairing.rate-limit", "schema.refused.pairing", "features.pairing",
    "admin.refused", "features.admin",
]
# With the console's token, bound to its key.
WITH_TOKEN = [
    "handshake.account", "features.anonymous", "caching.private", "auth.tokens",
    "signatures.unsigned", "signatures.invalid", "signatures.stale", "signatures.replayed",
    "signatures.digest", "signatures.accept-signature",
]
# What only a private server shows.
PRIVATE = ["auth.missing"]
# Plain HTTP on loopback, and JSON that the server does not compress (§ 2.1).
WARNINGS = ["transport.https", "compression.json"]

RUNS = [
    ("anonymous", False, False, LIBRARY + CATALOG + PAIRING),
    ("token", False, True, LIBRARY + CATALOG + PAIRING + WITH_TOKEN),
    ("private, with a token", True, True, LIBRARY + CATALOG + PAIRING + WITH_TOKEN + PRIVATE),
]


def run_once(args, key_file, name, private, token, required):
    demo = subprocess.Popen([args.demo, "0"] + (["--private"] if private else []), stdout=subprocess.PIPE, text=True)
    try:
        url = demo.stdout.readline().strip()
        if not url.startswith("http://127.0.0.1:"):
            print(f"the demo server did not say where it listens: {url!r}", file=sys.stderr)
            return False
        command = [sys.executable, args.suite, url, "--origin", args.origin]
        if token:
            command += ["--token", TOKEN, "--key", key_file]
        if any(importlib.util.find_spec(m) is None for m in ("jsonschema", "referencing")):
            command.append("--no-schemas")
        run = subprocess.run(command, capture_output=True, text=True, check=False)
    finally:
        demo.terminate()
        demo.wait(timeout=10)
    print(f"== {name}")
    print(run.stdout)
    print(run.stderr, file=sys.stderr)
    summary = re.search(r"(\d+) passed, (\d+) failed, (\d+) warning\(s\), (\d+) skipped", run.stdout)
    levels = re.search(r"Levels reached[^\n]*:\s*([^\n]*)", run.stdout)
    if summary is None or levels is None:
        print(f"{name}: the suite's report could not be read", file=sys.stderr)
        return False
    status = {m.group(2): m.group(1) for m in re.finditer(r"^(PASS|FAIL|WARN|SKIP)\s+§ \S+\s+(\S+)", run.stdout, re.M)}
    problems = []
    if int(summary.group(2)):
        problems.append(f"{summary.group(2)} check(s) failed")
    # Anonymously, the checks of signed requests are left out (a server that signs needs a token for them)
    if token and not all(level in levels.group(1) for level in ("Lantern Core", "+titles")):
        problems.append(f"levels reached: {levels.group(1)}")
    problems += [f"{check}: {status.get(check, 'absent')}, expected PASS" for check in required
                 if status.get(check) != "PASS"]
    problems += [f"{check}: an unexpected warning" for check, s in status.items()
                 if s == "WARN" and check not in WARNINGS]
    for problem in problems:
        print(f"{name}: {problem}", file=sys.stderr)
    if not problems:
        print(f"conformance ({name}): {summary.group(0)}; levels reached: {levels.group(1)}")
    return not problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--demo", required=True, help="the demo server's executable")
    parser.add_argument("--suite", required=True, help="spec/conformance/run.py")
    parser.add_argument("--origin", default=ORIGIN, help="the origin the demo allows (CORS)")
    args = parser.parse_args()

    # The suite reads the device key from a file: its 32-byte seed, in base64
    seed = base64.b64encode(hashlib.sha256(KEY_PHRASE.encode()).digest()).decode()
    with tempfile.TemporaryDirectory() as folder:
        key_file = os.path.join(folder, "demo.key")
        with open(key_file, "w", encoding="ascii") as handle:
            handle.write(seed)
        ok = True
        for name, private, token, required in RUNS:
            ok = run_once(args, key_file, name, private, token, required) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
