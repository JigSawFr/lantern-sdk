#!/usr/bin/env python3
"""A deliberately malicious Lantern server, for testing clients: each
scenario breaks one rule a client relies on, and says what a client must do
about it. Any client library of this repository runs against it in CI (the
Python one in tests/test_hostile.py; the C++ one later, through the command
line below).

    python3 tools/hostile_server.py --list                  # the scenarios, as JSON
    python3 tools/hostile_server.py bad-digest --port 8099  # serve one
    python3 tools/hostile_server.py spki-wrong --tls        # one that needs TLS

Serving, it prints one JSON line, then serves until it is stopped:

    {"scenario": "bad-digest", "url": "http://127.0.0.1:8099/", "token": "et_…",
     "pin": null, "expect": "…", "app": {…}}

`token` is the token a client sends (the server takes any); `pin` is the
fingerprint (SHA-256 of the SPKI, hex) a client must pin for a TLS scenario,
which the server then breaks; `app`, `entry` and `code` are the documents a
client acts on. Every request the server read is logged on standard error
as one JSON line ({"method", "path", "authorization"}), so that a harness
can check what a client sent, and to which key.

It listens on loopback only. The TLS scenarios make two self-signed
certificates with the `cryptography` package (the library's `crypto` extra).
It needs the library itself (src/, or installed) for its digests and
fingerprints. Everything it serves is fictional.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import socket
import ssl
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lantern.homebrew import manifest_sha256
from lantern.models import ManifestEntry
from lantern.spki import spki_sha256

UID = "7e0d1c2b-3a4f-4b5c-8d6e-0f1a2b3c4d5e"
TOKEN = "et_hostile-0123456789abcdef0123456789ab"
BASE = "/api/lantern"
FILE = bytes((i * 7 + 3) % 251 for i in range(4096))
FILE_SHA256 = hashlib.sha256(FILE).hexdigest()
JSON_LIMIT = 32 << 20  # SPEC.md § 13
#: The eight encodings of the points of small order (SPEC.md § 8.4).
SMALL_ORDER = "0100000000000000000000000000000000000000000000000000000000000000"


@dataclass(frozen=True)
class Scenario:
    name: str
    what: str
    expect: str
    tls: bool = False


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in [
        Scenario(
            "spki-wrong",
            "TLS with a key other than the one the client pinned (`pin`).",
            "Refuse the connection before sending the request (PinMismatch): the server logs no request.",
            tls=True,
        ),
        Scenario(
            "key-changed",
            "TLS with the key `pin` for the first connection, then another key (a server whose key changed).",
            "The first request goes; the next ones are refused before they are sent (PinMismatch).",
            tls=True,
        ),
        Scenario(
            "manifest-dotdot",
            "A homebrew entry whose manifest climbs out of its folder with `..`.",
            "Refuse to install it (the install plan is refused).",
        ),
        Scenario(
            "manifest-relative",
            "A homebrew entry whose manifest has a path that is not absolute, and a drive letter.",
            "Refuse to install it.",
        ),
        Scenario(
            "manifest-outside",
            "A homebrew entry whose manifest writes outside every root of the platform's profile.",
            "Refuse to install it.",
        ),
        Scenario(
            "newer-schema",
            "Every document has schema 2.",
            "Treat each as absent (NewerSchema), never as an error of the server, and write nothing back.",
        ),
        Scenario(
            "oversized-document",
            "A page of apps of 33 MiB.",
            "Stop reading at 32 MiB and refuse it (DocumentError).",
        ),
        Scenario("deep-document", "A page nested 40 deep.", "Refuse it (DocumentError)."),
        Scenario(
            "long-string",
            "An app whose name is 600 bytes (512 at most).",
            "Refuse it (DocumentError).",
        ),
        Scenario("page-too-long", "A page of 1001 apps (1000 at most).", "Refuse it (DocumentError)."),
        Scenario(
            "manifest-too-long",
            "A homebrew entry whose manifest has 4097 files (4096 at most).",
            "Refuse it (DocumentError).",
        ),
        Scenario(
            "bad-digest",
            "A file whose Repr-Digest is not the document's sha256.",
            "Refuse the download (IntegrityError); keep nothing of it.",
        ),
        Scenario(
            "wrong-bytes",
            "A file whose bytes are not the document's sha256, though its headers are right.",
            "Refuse the download once read (IntegrityError); keep nothing of it.",
        ),
        Scenario(
            "truncated",
            "A file cut halfway, its Content-Length the whole size.",
            "Fail the download (TransportError) and install nothing; resume it with a Range.",
        ),
        Scenario(
            "wrong-content-range",
            "A resumed download answered 206 with a Content-Range that is not the one asked for.",
            "Refuse it (UnexpectedResponse); keep nothing of it.",
        ),
        Scenario(
            "extra-bytes",
            "A file with more bytes than its size.",
            "Refuse it as they arrive (IntegrityError).",
        ),
        Scenario(
            "small-order-key",
            "A homebrew entry signed by a key of small order, S = 0: a forgery the bare equation accepts.",
            "Refuse the signature (it does not verify), whatever the message.",
        ),
        Scenario(
            "expired-challenge",
            "Every signed request is refused 401 signature_expired, with a Date ten years off.",
            "Sign again once with the server's Date, then give up (SignatureExpired): two requests, no loop.",
        ),
        Scenario(
            "replayed-challenge",
            "Every signed request is refused 401 signature_replayed.",
            "Sign again once with a new nonce, then give up (SignatureReplayed): two requests, no loop.",
        ),
        Scenario(
            "pairing-elsewhere",
            "A pairing code whose poll address and verify_complete are on another origin.",
            "Refuse the code (DocumentError): show nothing, poll nothing.",
        ),
        Scenario(
            "redirect",
            "Every route answers 302 to another host.",
            "Never follow it (UnexpectedResponse), and send the token nowhere else.",
        ),
    ]
}


def make_certificate(name: str = "Hostile shelf") -> tuple[str, str]:
    """A self-signed certificate for 127.0.0.1 and localhost, and its key (PEM): needs `cryptography`."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return cert_pem, key_pem


def spki_of(cert_pem: str) -> str:
    """The fingerprint of a certificate's key (SPEC.md § 5.3), with the library's own reader."""
    return spki_sha256(cert_pem)


def server_context(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as folder:
        cert, key = Path(folder) / "cert.pem", Path(folder) / "key.pem"
        cert.write_text(cert_pem, encoding="ascii")
        key.write_text(key_pem, encoding="ascii")
        context.load_cert_chain(cert, key)
    return context


def hello(schema: int = 1) -> dict[str, Any]:
    return {
        "schema": schema,
        "uid": UID,
        "name": "Hostile shelf",
        "base": BASE,
        "versions": [1],
        "platforms": ["switch"],
        "account": {"state": "active", "scopes": ["library"], "bound": True},
        "features": {"library": 1, "homebrew": 1, "pairing": 1, "signatures": 1},
        "auth": {"bearer_only": True, "skew": 300},
        "limits": {"page_size": 1000},
    }


def app(name: str = "Frostline Tales", **changes: Any) -> dict[str, Any]:
    doc = {
        "id": "a_frost",
        "platform": "switch",
        "title_id": "0100ABCD00010000",
        "app_id": "0100ABCD00010000",
        "type": "base",
        "version_code": 0,
        "name": name,
        "size": len(FILE),
        "format": "nsp",
        "sha256": FILE_SHA256,
        "file": f"{BASE}/v1/files/f_frost",
    }
    doc.update(changes)
    return doc


def manifest_entry(path: str, data: bytes = b"lamp") -> dict[str, Any]:
    return {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def manifest_digest(manifest: list[dict[str, Any]]) -> str:
    return manifest_sha256([ManifestEntry.from_json(m) for m in manifest])


def entry(manifest: list[dict[str, Any]], signature: dict[str, str] | None = None) -> dict[str, Any]:
    package: dict[str, Any] = {
        "file": f"{BASE}/v1/files/f_lamp",
        "format": "zip",
        "size": len(FILE),
        "sha256": FILE_SHA256,
        "manifest": manifest,
        "manifest_sha256": manifest_digest(manifest),
    }
    doc: dict[str, Any] = {
        "schema": 1,
        "id": "org.example.paperlamp",
        "platform": "switch",
        "kind": "app",
        "name": "Paper Lamp",
        "author": "Ines",
        "version": "0.9.2",
        "build": 902,
        "package": package,
    }
    if signature is not None:
        doc["signature"] = signature
    return doc


def hostile_entry(scenario: str) -> dict[str, Any]:
    if scenario == "manifest-dotdot":
        return entry([manifest_entry("/switch/org.example.paperlamp/../../atmosphere/contents/x/exefs.nsp")])
    if scenario == "manifest-relative":
        return entry([manifest_entry("switch/paperlamp.nro"), manifest_entry("/C:\\paperlamp.nro")])
    if scenario == "manifest-outside":
        return entry([manifest_entry("/bootloader/hekate_ipl.ini")])
    if scenario == "manifest-too-long":
        return entry([manifest_entry(f"/switch/org.example.paperlamp/f{i}.bin") for i in range(4097)])
    if scenario == "small-order-key":
        forged = base64.b64encode(bytes.fromhex(SMALL_ORDER) + bytes(32)).decode()
        key = base64.b64encode(bytes.fromhex(SMALL_ORDER)).decode()
        return entry(
            [manifest_entry("/switch/org.example.paperlamp/paperlamp.nro")],
            {"alg": "ed25519", "public_key": key, "value": forged},
        )
    return entry([manifest_entry("/switch/org.example.paperlamp/paperlamp.nro")])


def nested(depth: int) -> Any:
    out: Any = "frost"
    for _ in range(depth):
        out = [out]
    return out


class Handler(BaseHTTPRequestHandler):
    server: HostileHTTPServer
    protocol_version = "HTTP/1.1"

    date: str | None = None  # a Date of the scenario's, in place of the clock's

    def log_message(self, fmt: str, *args: Any) -> None:
        return None

    def date_time_string(self, timestamp: float | None = None) -> str:
        return self.date or super().date_time_string(timestamp)

    def do_GET(self) -> None:
        self.answer()

    def do_HEAD(self) -> None:
        self.answer()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, 1 << 20))
        self.answer()

    def send(self, status: int, body: bytes, ctype: str = "application/json", **headers: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", headers.pop("length", str(len(body))))
        for k, v in headers.items():
            self.send_header(k.replace("_", "-"), v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def doc(self, doc: Any, status: int = 200) -> None:
        self.send(status, json.dumps(doc).encode())

    def problem(self, status: int, code: str, **headers: str) -> None:
        doc = {"schema": 1, "type": "about:blank", "title": code, "status": status, "code": code}
        self.send(status, json.dumps(doc).encode(), "application/problem+json", **headers)

    def answer(self) -> None:
        self.server.log(self)
        scenario, path = self.server.scenario, self.path.split("?")[0]
        schema = 2 if scenario == "newer-schema" else 1
        if scenario == "redirect":
            self.send(302, b"", Location="http://192.0.2.10/api/lantern/v1/apps")
            return
        if scenario in ("expired-challenge", "replayed-challenge") and self.headers.get("Signature"):
            code = "signature_expired" if scenario == "expired-challenge" else "signature_replayed"
            headers = {
                "WWW-Authenticate": 'Bearer realm="lantern", error="invalid_token"',
                "Accept-Signature": 'lantern=("@method" "@target-uri" "authorization");alg="ed25519"',
            }
            if code == "signature_expired":
                self.date = format_datetime(datetime.now(UTC) + timedelta(days=3650), usegmt=True)
            self.problem(401, code, **headers)
            return
        if path in ("/.well-known/lantern", f"{BASE}/v1", f"{BASE}/v1/"):
            self.doc(hello(schema))
        elif path == f"{BASE}/v1/apps":
            self.apps(schema)
        elif path == f"{BASE}/v1/homebrew/org.example.paperlamp":
            self.doc({**hostile_entry(scenario), "schema": schema})
        elif path in (f"{BASE}/v1/files/f_frost", f"{BASE}/v1/files/f_lamp"):
            self.file()
        elif path == f"{BASE}/v1/pairing" and self.command == "POST":
            elsewhere = "https://192.0.2.10" if scenario == "pairing-elsewhere" else ""
            host = f"http://{self.headers.get('Host') or '127.0.0.1'}"
            self.doc(
                {
                    "schema": schema,
                    "code": "KQ4M-7TXD",
                    "verify": f"{host}/pair",
                    "verify_complete": f"{elsewhere or host}/pair?code=KQ4M-7TXD",
                    "poll": f"{elsewhere}{BASE}/v1/pairing/p_hostile",
                    "interval": 1,
                    "expires": 600,
                }
            )
        else:
            self.problem(404, "not_found")

    def apps(self, schema: int) -> None:
        scenario = self.server.scenario
        if scenario == "oversized-document":
            padding = (JSON_LIMIT + (1 << 20)) // 1024
            note = "x" * 1000
            items = [app(f"Frostline Tales {i}", x_hostile=note) for i in range(padding)]
            body = json.dumps({"schema": 1, "items": items, "total": len(items), "next": None}).encode()
            self.send(200, body)
            return
        items = [app()]
        if scenario == "long-string":
            items = [app("Frostline " * 60)]
        elif scenario == "page-too-long":
            items = [app(f"Frostline Tales {i}", id=f"a_{i}") for i in range(1001)]
        doc: dict[str, Any] = {"schema": schema, "items": items, "total": len(items), "next": None}
        if scenario == "deep-document":
            doc["x-hostile"] = nested(40)
        self.doc(doc)

    def file(self) -> None:
        scenario = self.server.scenario
        digest = "sha-256=:" + base64.b64encode(hashlib.sha256(FILE).digest()).decode() + ":"
        data = FILE
        if scenario == "bad-digest":
            digest = "sha-256=:" + base64.b64encode(hashlib.sha256(b"another file").digest()).decode() + ":"
        elif scenario == "wrong-bytes":
            data = bytes(len(FILE))
        elif scenario == "extra-bytes":
            data = FILE + b"and more"
        start = 0
        wanted = self.headers.get("Range")
        if wanted and wanted.startswith("bytes=") and wanted.endswith("-"):
            start = int(wanted[6:-1] or 0)
        if start:
            shown = start + 1 if scenario == "wrong-content-range" else start
            self.send(
                206,
                data[start:],
                "application/octet-stream",
                Content_Range=f"bytes {shown}-{len(FILE) - 1}/{len(FILE)}",
                Repr_Digest=digest,
            )
            return
        if scenario == "truncated":
            self.send(
                200, data[: len(data) // 2], "application/octet-stream", length=str(len(data)), Repr_Digest=digest
            )
            self.close_connection = True
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)  # a FIN after the half: the client reads it, then the end
            return
        self.send(200, data, "application/octet-stream", Repr_Digest=digest)


class HostileHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, scenario: str, port: int, contexts: list[ssl.SSLContext], rotate_after: int) -> None:
        super().__init__(("127.0.0.1", port), Handler)
        self.scenario, self.contexts, self.rotate_after = scenario, contexts, rotate_after
        self.connections = 0
        self.requests: list[dict[str, Any]] = []
        self.on_request: Callable[[dict[str, Any]], None] | None = None
        self._lock = threading.Lock()

    def get_request(self) -> tuple[socket.socket, Any]:
        sock, address = self.socket.accept()
        if not self.contexts:
            return sock, address
        with self._lock:
            index = 0 if self.connections < self.rotate_after else min(1, len(self.contexts) - 1)
            self.connections += 1
        return self.contexts[index].wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address

    def log(self, handler: Handler) -> None:
        entry = {"method": handler.command, "path": handler.path, "authorization": handler.headers.get("Authorization")}
        with self._lock:
            self.requests.append(entry)
        if self.on_request is not None:
            self.on_request(entry)

    def handle_error(self, request: Any, client_address: Any) -> None:
        return None  # a client that hangs up on a key it refuses is the point


class HostileServer:
    """A scenario served on loopback, in a thread.

        with HostileServer("bad-digest") as server:
            client = LanternClient(server.url, token=server.token)
            ...
            assert server.requests  # what the client sent

    A TLS scenario (`tls=True`, or one that needs it) makes two certificates:
    `pin` is the first one's key, which the client pins; spki-wrong serves
    the second from the start, key-changed after `rotate_after` connections."""

    def __init__(self, scenario: str, *, port: int = 0, tls: bool | None = None, rotate_after: int = 1) -> None:
        if scenario not in SCENARIOS:
            raise ValueError(f"no scenario {scenario!r}: one of {', '.join(SCENARIOS)}")
        self.scenario = SCENARIOS[scenario]
        use_tls = self.scenario.tls if tls is None else tls
        contexts: list[ssl.SSLContext] = []
        self.pin: str | None = None
        if use_tls:
            first, second = make_certificate("Hostile shelf"), make_certificate("Hostile shelf")
            self.pin = spki_of(first[0])
            self.other_pin = spki_of(second[0])
            contexts = [server_context(*first), server_context(*second)]
            if scenario == "spki-wrong":
                contexts = [contexts[1]]
        after = rotate_after if scenario == "key-changed" else 1 << 62
        self.server = HostileHTTPServer(scenario, port, contexts, after)
        scheme = "https" if use_tls else "http"
        self.url = f"{scheme}://127.0.0.1:{self.server.server_address[1]}/"
        self.token = TOKEN
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def requests(self) -> list[dict[str, Any]]:
        return list(self.server.requests)

    def __enter__(self) -> HostileServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def describe(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario.name,
            "url": self.url,
            "token": self.token,
            "pin": self.pin,
            "expect": self.scenario.expect,
            "app": app(),
            "entry": "org.example.paperlamp",
            "code": "KQ4M-7TXD",
        }


def scenarios() -> Iterator[dict[str, Any]]:
    for s in SCENARIOS.values():
        yield {"name": s.name, "what": s.what, "expect": s.expect, "tls": s.tls}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("scenario", nargs="?", help="the scenario to serve")
    parser.add_argument("--list", action="store_true", help="list the scenarios, as JSON, and exit")
    parser.add_argument("--port", type=int, default=0, help="TCP port on 127.0.0.1 (0: any)")
    parser.add_argument("--tls", action="store_true", help="serve over TLS (the TLS scenarios always do)")
    parser.add_argument("--rotate-after", type=int, default=1, help="key-changed: connections before the new key")
    args = parser.parse_args(argv)
    if args.list:
        print(json.dumps(list(scenarios()), indent=1))
        return 0
    if not args.scenario:
        parser.error("name a scenario, or --list")
    with HostileServer(
        args.scenario, port=args.port, tls=True if args.tls else None, rotate_after=args.rotate_after
    ) as server:
        server.server.on_request = lambda e: print(json.dumps(e), file=sys.stderr, flush=True)
        print(json.dumps(server.describe()), flush=True)
        with contextlib.suppress(KeyboardInterrupt):
            server.thread.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
