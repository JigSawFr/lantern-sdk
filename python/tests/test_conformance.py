"""The specification's conformance suite (spec/conformance/run.py) against
the demo server built from the toolkit (tests/demo.py), served by Flask and
by FastAPI, anonymously and with a token. The demo offers every family of
the draft 0.11: it curates sections, pairs devices, checks signed requests,
takes cheat sets written, keeps save backups (encrypted ones among them)
and requests, cuts two versions of an update into chunks (§ 22), allows one page's origin (§ 2.5),
answers the administration API (an account of the suite's
own made, then deleted: --admin-writes), streams events, gives grants and
keeps sync data; a peer of the toolkit (lantern.peer) serves its files, and
both answer LAN discovery: with its token, bound to its key, it reaches
every level LEVELS says. A demo that keeps no encrypted backup refuses one
(§ 9.4). Last, the static library the generator writes (lantern.static)
passes --static."""

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
from demo import DEMO_KEY, DEMO_ORIGIN, DEMO_TOKEN, GRANT_SEED, UID, build_library, demo_accounts, make_lantern, serve
from lantern import ed25519, static
from lantern.peer import Peer
from lantern.server.discovery import DiscoveryResponder
from lantern.server.files import FileRef
from lantern.server.http import content_coding
from lantern.spki import spki_sha256

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
# Without a token: writing a cheat set is refused.
ANONYMOUS = ["cheats.write"]
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
    # Draft 0.7: no `web`, browsers, a pairing's poll after a slow_down, and differential updates.
    "platforms.web",
    "cors.preflight",
    "cors.max-age",
    "cors.responses",
    "cors.other-origin",
    "cors.credentials",
    "pairing.after-slow-down",
    "features.deltas",
    "deltas.index",
    "deltas.cut",
    "deltas.route",
    "deltas.update",
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
    "cheats.write-cycle",
    "requests.list",
    "requests.create",
    "requests.delete",
    "saves.limits",
    "saves.list",
    "saves.no-platform",
    "saves.upload",
    "saves.read",
    "saves.upload-digest",
    "saves.upload-too-large",
    "saves.single",
    "saves.cleanup",
    "e2e.upload",
    "schema.refused.saves",
    "schema.refused.requests",
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
#: The levels the demo reaches with its token (SPEC.md § 17): every one of the draft 0.11.
LEVELS = "Lantern Core +titles +homebrew +saves +cheats +requests +admin +events +peers +sync +encrypted_saves +deltas"


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
    lib = build_library(delta=True)
    app = make_lantern(lib, accounts=demo_accounts(), cors_origins=[DEMO_ORIGIN])
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
            args = [url, "--discover", "127.0.0.1", "--discover-port", str(server_port), "--origin", DEMO_ORIGIN]
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
    for check in REQUIRED + (WITH_TOKEN if token else ANONYMOUS):
        assert status.get(check) == "PASS", f"{check}: {status.get(check)}\n{report}"
    warnings = [cid for cid, s in status.items() if s == "WARN"]
    # Plain HTTP on loopback; and gzip without zstd, before Python 3.14 (the standard library has no zstd or br).
    expected = ["transport.https"] + ([] if zstd_available() else ["compression.json"])
    assert warnings == expected, report
    if token:
        assert f"Levels reached (SPEC.md § 17, draft 0.11): {LEVELS}" in report, report


def test_the_generators_static_library(tmp_path: Path) -> None:
    """The generator's output (lantern.static) through the suite's --static (SPEC.md § 21)."""
    run = suite()
    out = io.StringIO()
    static.export(build_library(delta=True), tmp_path / "library", uid=UID, name="Demo shelf", page_size=2)
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
        "chunks",
    ):
        assert re.search(rf"^PASS\s+§ \S+\s+static\.{re.escape(check)}\s", report, re.M), f"{check}\n{report}"
    assert "Levels reached (SPEC.md § 17, draft 0.11): Lantern Static" in report


def zstd_available() -> bool:
    return content_coding("zstd") == "zstd"


def test_a_server_without_encrypted_saves(tmp_path: Path) -> None:
    """A demo that keeps save backups but no encrypted one: it refuses one with 400 (SPEC.md § 9.4,
    L-9.4-5), and reaches +saves without +encrypted_saves."""
    pytest.importorskip("flask")
    run = suite()
    out = io.StringIO()
    key = tmp_path / "demo.key"
    key.write_text(DEMO_KEY.seed_b64(), encoding="ascii")
    with serve("flask", make_lantern(accounts=demo_accounts(), encrypted_saves=False)) as url:
        server_port = free_udp()
        responder = DiscoveryResponder(
            make_lantern(), int(url.rstrip("/").rsplit(":", 1)[1]), port=server_port, host="127.0.0.1"
        ).start()
        try:
            code = run.main(
                [
                    url,
                    "--token",
                    DEMO_TOKEN,
                    "--key",
                    str(key),
                    "--discover",
                    "127.0.0.1",
                    "--discover-port",
                    str(server_port),
                ],
                out=out,
            )
        finally:
            responder.stop()
    report = out.getvalue()
    assert code == 0 and "\nFAIL" not in report, report
    assert re.search(r"^PASS\s+§ 9\.4\s+e2e\.not-offered\s", report, re.M), report
    levels = next(line for line in report.splitlines() if line.startswith("Levels reached"))
    assert "+saves" in levels and "+encrypted_saves" not in levels, levels


def self_signed(folder: Path) -> tuple[Path, Path]:
    """A certificate for 127.0.0.1 and its key (PEM), made for one run."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = folder / "cert.pem", folder / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_file, key_file


# The suite's TLS-floor check offers TLS 1.0 and 1.1 on purpose, to see them refused; Python 3.15 warns of it.
@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1:DeprecationWarning")
@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1_1:DeprecationWarning")
@pytest.mark.parametrize("framework", ["flask", "fastapi"])
def test_the_suite_over_https(framework: str, tmp_path: Path) -> None:
    """The suite over TLS, trusting the demo's certificate: § 2's transport checks have something to check."""
    pytest.importorskip(framework)
    if framework == "fastapi":
        pytest.importorskip("uvicorn")
    run = suite()
    out = io.StringIO()
    cert, key = self_signed(tmp_path)
    # The approval page shows the short fingerprint of the key the server's certificate carries (§ 5.3)
    app = make_lantern(accounts=demo_accounts(), spki=spki_sha256(cert.read_text(encoding="ascii")))
    with serve(framework, app, tls=(cert, key)) as url:
        assert url.startswith("https://")
        code = run.main([url, "--cafile", str(cert)], out=out)
    report = out.getvalue()
    status = {m.group(2): m.group(1) for m in re.finditer(r"^(PASS|FAIL|WARN|SKIP)\s+§ \S+\s+(\S+)", report, re.M)}
    failed = [line for line in report.splitlines() if line.startswith("FAIL")]
    assert code == 0 and not failed, report
    for check in ("transport.https", "transport.hsts"):
        assert status.get(check) == "PASS", f"{check}: {status.get(check)}\n{report}"
    # TLS 1.1 and older refused: uvicorn drops the connection without an alert, which the suite
    # cannot tell from its own limits (a skip, not a failure)
    assert status.get("transport.tls") in ("PASS", "SKIP"), report
