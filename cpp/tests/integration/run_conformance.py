#!/usr/bin/env python3
"""Runs the specification's conformance suite against the C++ demo server.

    python3 run_conformance.py --demo lantern_demo_server --suite spec/conformance/run.py [--origin ORIGIN]

The suite runs four times, each against a demo server of its own (the
pairing and invitation checks leave their address rate limited for a while):

- anonymously, against the public demo;
- with the demo console's token and its device key (--token, --key), against
  the public demo: the signed requests, the scopes, the pairing flow, the
  requests, and the administration API (--admin-writes: the suite makes an
  account of its own and deletes it);
- with the same token against the private demo (`--private`), which asks for
  a token on the library;
- with the same token against a demo that keeps no encrypted backup
  (`--no-encrypted-saves`), which must refuse one (L-9.4-5).

Each run starts the demo (examples/demo_server.cpp, on a free loopback port,
which the demo prints as its URL), runs `run.py URL --origin ORIGIN`, and stops
the demo. It fails when a check fails, when a check of the families the demo
serves (the library with its titles, changes and sections, homebrew, cheats, saves with the encrypted ones,
requests, administration with its invitations and rating caps, events with their long poll, grants for peers,
sync, pairing, signatures) is not a pass, when an unexpected
warning is raised, or, with the token, when Lantern Core, +titles, +homebrew, +saves, +cheats, +requests, +admin,
+events, +peers and +sync are not among the levels reached (without one the suite cannot check signed requests, nor
the saves, which need the scope `saves`, and says so).
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
# Homebrew (§ 8, read with the scope library) and cheat sets (§ 10, whose scope everyone holds on a
# public server).
HOMEBREW = [
    "features.homebrew", "homebrew.pages", "homebrew.entries", "homebrew.manifests", "homebrew.kinds",
    "homebrew.filters", "homebrew.requires", "homebrew.ports", "homebrew.packages", "homebrew.signatures",
    "homebrew.updates", "homebrew.updates-platform", "homebrew.unknown", "schema.refused.homebrew",
]
CHEATS = ["features.cheats", "cheats.sets", "cheats.text", "cheats.unknown"]
# Save backups (§ 9), for a token with the scope saves: the listing, the resumable upload, one request, the
# archive back, deletion; the encrypted ones (§ 9.4) are kept as sent.
SAVES = [
    "features.saves", "saves.limits", "saves.list", "saves.no-platform", "saves.upload", "saves.read",
    "saves.upload-digest", "saves.upload-too-large", "saves.single", "saves.cleanup", "schema.refused.saves",
]
ENCRYPTED_SAVES = ["e2e.upload"]
# Requests for games (§ 11), for a token with the scope requests.
REQUESTS = ["features.requests", "requests.list", "requests.create", "requests.delete"]
# The administration API (§ 5.5-5.7), for a token with the scope admin: accounts (the suite makes one of its own
# and deletes it: --admin-writes), pairings approved with a rating cap that hides what is above it, refused, devices
# revoked, an invitation redeemed, the requests of every account decided.
ADMIN = [
    "admin.users", "admin.users-write", "admin.pairings", "admin.rating-cap", "admin.refuse", "admin.devices",
    "admin.invitations", "admin.requests", "admin.users-delete",
]
# Events (§ 18), for a token with the scope requests (it makes events of its own): the stream, resuming with
# Last-Event-ID, a bad id, the heartbeat, the streams a token may hold, a revoked device's stream ended, and
# the long poll of changes (§ 18.3).
EVENTS = [
    "features.events", "events.stream", "events.resume", "events.bad-token", "events.heartbeat", "events.limit",
    "events.revoked", "events.long-poll",
]
# Grants for peers (§ 19.3), read with the scope library: the grant key in the handshake, grants that verify.
# The peer (§ 19.4) is a console's program, not a server's: its checks need --peer and are left out.
PEERS = ["features.peers", "peers.handshake", "peers.grant", "values.hex-case"]
# Sync (§ 20), for a token with the scopes sync.read and sync.write: the overview with the device's id, items
# merged by the rule, a date far ahead, If-Match, another generation, another device's item, malformed items.
SYNC = [
    "features.sync", "sync.overview", "sync.write", "sync.future", "sync.if-match", "sync.generation",
    "sync.installed", "sync.malformed",
]
# Differential updates (§ 22), read with the scope library: the demo's two updates of one game are large enough
# for a chunk index, so the indexes, their route and a newer version put together from an older one are checked.
DELTAS = ["features.deltas", "deltas.index", "deltas.cut", "deltas.route", "deltas.update", "cache.immutable"]
# Pairing (§ 5.2, § 5.4) is offered to every caller, anonymous included.
PAIRING = [
    "handshake.auth", "pairing.offered", "pairing.code", "pairing.verify-complete", "pairing.waiting",
    "pairing.slow-down", "pairing.unknown", "pairing.key", "pairing.after-slow-down",
    "invitations.rate-limit", "pairing.rate-limit", "schema.refused.pairing", "features.pairing",
    "admin.refused", "features.admin",
]
# With the console's token, bound to its key: it holds cheats.write, so a set is written, replaced and
# deleted; anonymously, writing is refused.
WITH_TOKEN = [
    "cheats.write-cycle",
    "handshake.account", "features.anonymous", "caching.private", "auth.tokens",
    "signatures.unsigned", "signatures.invalid", "signatures.stale", "signatures.replayed",
    "signatures.digest", "signatures.accept-signature",
]
# What only a private server shows.
PRIVATE = ["auth.missing"]
# A server that keeps no encrypted backup refuses one.
NO_ENCRYPTED = ["e2e.not-offered"]
# Anonymous callers: writing a cheat set is refused
ANONYMOUS = ["cheats.write"]
# Plain HTTP on loopback, and JSON that the server does not compress (§ 2.1).
WARNINGS = ["transport.https", "compression.json"]

BASE = LIBRARY + CATALOG + HOMEBREW + CHEATS + DELTAS + PAIRING
CORE_LEVELS = ("Lantern Core", "+titles", "+homebrew", "+saves", "+cheats", "+requests", "+admin", "+events",
               "+peers", "+sync", "+deltas")

# (name, the demo's flags, whether it has a token, the levels it must reach, the checks that must pass)
RUNS = [
    ("anonymous", [], False, (), BASE + ANONYMOUS),
    ("token", [], True, CORE_LEVELS + ("+encrypted_saves",),
     BASE + WITH_TOKEN + SAVES + ENCRYPTED_SAVES + REQUESTS + ADMIN + EVENTS + PEERS + SYNC),
    ("private, with a token", ["--private"], True, CORE_LEVELS + ("+encrypted_saves",),
     BASE + WITH_TOKEN + SAVES + ENCRYPTED_SAVES + REQUESTS + ADMIN + EVENTS + PEERS + SYNC + PRIVATE),
    ("without encrypted saves", ["--no-encrypted-saves"], True, CORE_LEVELS,
     BASE + WITH_TOKEN + SAVES + NO_ENCRYPTED + REQUESTS + ADMIN + EVENTS + PEERS + SYNC),
]


def run_once(args, key_file, name, flags, token, levels_needed, required):
    demo = subprocess.Popen([args.demo, "0"] + flags, stdout=subprocess.PIPE, text=True)
    try:
        url = demo.stdout.readline().strip()
        if not url.startswith("http://127.0.0.1:"):
            print(f"the demo server did not say where it listens: {url!r}", file=sys.stderr)
            return False
        command = [sys.executable, args.suite, url, "--origin", args.origin]
        if token:
            command += ["--token", TOKEN, "--key", key_file, "--admin-writes"]
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
    if not all(level in levels.group(1) for level in levels_needed):
        problems.append(f"levels reached: {levels.group(1)}")
    if token and "+encrypted_saves" not in levels_needed and "+encrypted_saves" in levels.group(1):
        problems.append(f"levels reached: {levels.group(1)}, but this server keeps no encrypted backup")
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
        for name, flags, token, levels_needed, required in RUNS:
            ok = run_once(args, key_file, name, flags, token, levels_needed, required) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
