"""The specification's conformance suite (spec/conformance/run.py) against
the demo server built from the toolkit (tests/demo.py), served by Flask and
by FastAPI, anonymously and with a token. Families the toolkit does not
offer (sections, saves, requests) are declared 0: the suite checks that
their routes are refused, and skips the rest of them. The demo pairs
devices, checks signed requests, answers the administration API (an account
of the suite's own made, then deleted: --admin-writes), streams events,
gives grants and keeps sync data; a peer of the toolkit (lantern.peer)
serves its files, and both answer LAN discovery: with its token, bound to
its key, it reaches the levels LEVELS says. Last, the static library the
generator writes (lantern.static) passes --static."""

from __future__ import annotations

import importlib.util
import io
import re
import socket
import threading
from pathlib import Path
from types import ModuleType

import pytest

from conftest import SPEC
from demo import DEMO_KEY, DEMO_TOKEN, GRANT_SEED, UID, build_library, demo_accounts, make_lantern, serve
from lantern import ed25519, static
from lantern.peer import Peer
from lantern.server.discovery import DiscoveryResponder
from lantern.server.files import FileRef
from lantern.server.http import content_coding

pytestmark = pytest.mark.conformance

# The read-side checks of the families the toolkit offers: each must pass, not be skipped.
REQUIRED = [
    "handshake.well-known",
    "handshake.v1",
    "handshake.anonymous",
    "handshake.platforms",
    "auth.unknown-token",
    "auth.unknown-handshake",
    "auth.basic-refused",
    "apps.first-page",
    "apps.pages.name",
    "apps.pages.added",
    "apps.pages.release",
    "apps.sha256",
    "apps.platforms",
    "apps.page-size",
    "apps.bad-cursor",
    "apps.filters",
    "apps.etag",
    "platforms.filter",
    "platforms.query",
    "platforms.unknown",
    "platforms.bad-name",
    "platforms.vary",
    "missing.no-platform",
    "missing.installed",
    "missing.up-to-date",
    "missing.base",
    "missing.malformed",
    "files.whole",
    "files.ranges",
    "files.unsatisfiable",
    "files.unknown",
    "changes.token",
    "changes.bad-token",
    "titles.known",
    "titles.unknown",
    "titles.bulk",
    "titles.bulk-limit",
    "titles.changes",
    "titles.bad-token",
    "homebrew.pages",
    "homebrew.entries",
    "homebrew.manifests",
    "homebrew.kinds",
    "homebrew.filters",
    "homebrew.requires",
    "homebrew.ports",
    "homebrew.packages",
    "homebrew.signatures",
    "homebrew.updates",
    "homebrew.updates-platform",
    "homebrew.unknown",
    "cheats.sets",
    "cheats.text",
    "cheats.unknown",
    "cheats.write",
    "schema.refused.library",
    "schema.refused.homebrew",
    "errors.unknown-route",
    "errors.problem",
    "errors.never-200",
    "errors.www-authenticate",
    "auth.no-basic",
    "documents.schema",
    "documents.type",
    "documents.limits",
    *[
        f"features.{f}"
        for f in ("library", "titles", "changes", "sections", "homebrew", "saves", "cheats", "requests", "pairing")
    ],
]
# Pairing, offered to every caller.
REQUIRED += [
    "handshake.auth",
    "pairing.offered",
    "pairing.code",
    "pairing.verify-complete",
    "pairing.waiting",
    "pairing.slow-down",
    "pairing.unknown",
    "pairing.key",
    "admin.refused",
    "language.problem",
    "compression.files",
    "documents.date",
    "features.admin",
]
# With the demo's token, bound to its key, and every scope the demo serves.
WITH_TOKEN = [
    "handshake.account",
    "features.anonymous",
    "caching.private",
    "signatures.unsigned",
    "signatures.invalid",
    "signatures.stale",
    "signatures.replayed",
    "signatures.digest",
    "signatures.accept-signature",
    "admin.users",
    "admin.pairings",
    "admin.rating-cap",
    "admin.refuse",
    "admin.devices",
    "admin.invitations",
    "admin.users-write",
    "admin.users-delete",
    "compression.etag",
    # Draft 0.5.
    "features.events",
    "features.peers",
    "features.sync",
    "events.stream",
    "events.resume",
    "events.bad-token",
    "events.long-poll",
    "events.heartbeat",
    "events.limit",
    "events.revoked",
    "peers.handshake",
    "peers.grant",
    "peers.mirrors",
    "peer.refused",
    "peer.serves",
    "peer.discovery",
    "peer.rate",
    "sync.overview",
    "sync.write",
    "sync.future",
    "sync.if-match",
    "sync.generation",
    "sync.installed",
    "sync.malformed",
    "sync.limits",
    "discovery.reply",
    "invitations.rate-limit",
    "pairing.rate-limit",
]
#: The levels the demo reaches with its token (SPEC.md § 17).
LEVELS = "Lantern Core +titles +homebrew +cheats +admin +events +peers +sync"


def suite() -> ModuleType:
    jsonschema = pytest.importorskip("jsonschema")
    assert jsonschema
    spec = importlib.util.spec_from_file_location("lantern_conformance", SPEC / "conformance" / "run.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def free_udp() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def demo_peer(lib: object) -> Peer:
    """A peer of the toolkit that holds every app and homebrew package of the demo's library."""
    files: dict[str, FileRef] = {}
    for a in lib.apps():  # type: ignore[attr-defined]
        files[a.sha256] = lib.file(a.file.rsplit("/", 1)[1])  # type: ignore[attr-defined]
    for e in lib.homebrew(()):  # type: ignore[attr-defined]
        for p in [e.package, *(e.packages or [])]:
            files[p.sha256] = lib.file(p.file.rsplit("/", 1)[1])  # type: ignore[attr-defined]
    return Peer(("127.0.0.1", 0), files, {UID: ed25519.public_key(GRANT_SEED)}, name="Noor's console")


@pytest.mark.parametrize("framework", ["flask", "fastapi"])
@pytest.mark.parametrize("token", [False, True], ids=["anonymous", "token"])
def test_the_suite_passes(framework: str, token: bool, tmp_path: Path) -> None:
    pytest.importorskip(framework)
    if framework == "fastapi":
        pytest.importorskip("uvicorn")
    run = suite()
    out = io.StringIO()
    key = tmp_path / "demo.key"
    key.write_text(DEMO_KEY.seed_b64(), encoding="ascii")
    lib = build_library()
    app = make_lantern(lib, accounts=demo_accounts())
    peer = demo_peer(lib)
    threading.Thread(target=peer.serve_forever, daemon=True).start()
    peer_port = free_udp()
    peer_sock = peer.discovery(peer_port, "127.0.0.1")
    try:
        with serve(framework, app) as url:
            server_port = free_udp()
            responder = DiscoveryResponder(
                app, int(url.rstrip("/").rsplit(":", 1)[1]), port=server_port, host="127.0.0.1"
            ).start()
            args = [url, "--discover", "127.0.0.1", "--discover-port", str(server_port)]
            if token:
                args += [
                    "--token",
                    DEMO_TOKEN,
                    "--key",
                    str(key),
                    "--admin-writes",
                    "--peer",
                    f"http://127.0.0.1:{peer.port}/lantern",
                    "--peer-discover-port",
                    str(peer_port),
                ]
            try:
                code = run.main(args, out=out)
            finally:
                responder.stop()
    finally:
        peer_sock.close()
        peer.shutdown()
        peer.server_close()
    report = out.getvalue()
    status = {m.group(2): m.group(1) for m in re.finditer(r"^(PASS|FAIL|WARN|SKIP)\s+§ \S+\s+(\S+)", report, re.M)}
    failed = [line for line in report.splitlines() if line.startswith("FAIL")]
    assert code == 0 and not failed, report
    for check in REQUIRED + (WITH_TOKEN if token else []):
        assert status.get(check) == "PASS", f"{check}: {status.get(check)}\n{report}"
    warnings = [cid for cid, s in status.items() if s == "WARN"]
    # Plain HTTP on loopback; and gzip without zstd, before Python 3.14 (the standard library has no zstd or br).
    expected = ["transport.https"] + ([] if zstd_available() else ["compression.json"])
    assert warnings == expected, report
    if token:
        assert f"Levels reached (SPEC.md § 17, draft 0.5): {LEVELS}" in report, report


def test_the_generators_static_library(tmp_path: Path) -> None:
    """The generator's output (lantern.static) through the suite's --static (SPEC.md § 21)."""
    run = suite()
    out = io.StringIO()
    static.export(build_library(), tmp_path / "library", uid=UID, name="Demo shelf", page_size=2)
    code = run.main(["--static", str(tmp_path / "library")], out=out)
    report = out.getvalue()
    assert code == 0 and "FAIL" not in report, report
    for check in (
        "handshake",
        "pages.apps",
        "pages.titles",
        "pages.homebrew",
        "titles",
        "homebrew",
        "cheats",
        "paths",
        "files",
    ):
        assert re.search(rf"^PASS\s+§ \S+\s+static\.{re.escape(check)}\s", report, re.M), f"{check}\n{report}"
    assert "Levels reached (SPEC.md § 17, draft 0.5): Lantern Static" in report


def zstd_available() -> bool:
    return content_coding("zstd") == "zstd"
