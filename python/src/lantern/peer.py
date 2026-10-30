"""A minimal peer (SPEC.md § 19.4): a paired console's sharing, the files it
holds served to the other devices of its network, by their SHA-256, to the
holders of a grant of its server.

    python -m lantern.peer --folder DIR --server https://shelf.example.org/ \\
        [--token T --key-file FILE] [--pin SPKI] [--host 192.168.1.20] [--port 47116] \\
        [--slots 2] [--name NAME] [--discovery] [--dns-sd] [--tls-cert C --tls-key K]

It reads its server's handshake (the server's uid, and `peers.key`, the key
its grants verify by) and its listings of apps and homebrew, as the client
it is, with its token and device key when the server is private. Of the
files of DIR it serves only those whose size and SHA-256 are an app's or a
homebrew package's of that server (L-19.4-2): never a save, a key or
anything named by a path. It answers:

    GET <base>/v1/blobs/sha256/<hex>     Lantern-Grant: <grant>

as a file (§ 6.6: ranges, a strong ETag, Repr-Digest), and HEAD alike; 403
without a grant that verifies by the key of a server it paired with, for
that very file, not expired by its clock (L-19.4-1); 404 for a file it does
not hold; 429 beyond `slots` downloads at once or a few requests a second
from one address (L-19.4-4); problems as § 12 says, without
WWW-Authenticate (L-19.4-5). It answers its own networks only (L-19.4-3):
loopback and § 19.2's private ones. With --discovery it answers the
discovery datagram that asks for peers (§ 19.5); with --dns-sd it
advertises `_lantern-peer._tcp` (the `dnssd` extra).

Plain HTTP only on a loopback or private address (§ 19.4); give
--tls-cert and --tls-key elsewhere. It is off unless its user turns it on:
an app starts a Peer when its user asks (Annex B.11), and stops it.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import re
import socket
import ssl
import sys
import threading
import uuid
from collections.abc import Callable, Generator, Iterable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from lantern._base import SCHEMA, JSONValue
from lantern.digest import sha256_file
from lantern.discovery import PEER_SERVICE, PORT
from lantern.grants import grant_key, is_private, read_grant
from lantern.http import Headers
from lantern.limits import DATAGRAM, NAME, clip
from lantern.server.files import FileRef, file_response
from lantern.server.http import ProblemError, ServerRequest, ServerResponse, problem_response
from lantern.server.pairing import Limiter

BASE = "/lantern"
PEER_PORT = 47116
SLOTS = 2
#: Requests per address, per second (SPEC.md § 19.4: a few).
RATE = (10, 1.0)
_PATH = re.compile(r"/v1/blobs/sha256/([0-9a-f]{64})")


class _Handler(BaseHTTPRequestHandler):
    server: Peer
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "LanternPythonPeer/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        if not self.server.quiet:
            super().log_message(fmt, *args)

    def do_GET(self) -> None:
        self._serve()

    def do_HEAD(self) -> None:
        self._serve()

    def _request(self) -> ServerRequest:
        return ServerRequest(
            self.command,
            self.path.split("?", 1)[0],
            {},
            Headers(list(self.headers.items())),
            target=self.path,
            remote=self.client_address[0],
            scheme="https" if self.server.tls else "http",
        )

    def _send(self, response: ServerResponse) -> None:
        self.send_response(response.status)
        for k, v in response.headers.items():
            self.send_header(k, v)
        self.end_headers()
        body = response.iter_body()
        try:
            if self.command != "HEAD":
                for chunk in body:
                    self.wfile.write(chunk)
        except OSError:
            self.close_connection = True
        finally:
            body.close()  # the download's slot is free again

    def _serve(self) -> None:
        request = self._request()
        try:
            self._send(self.server.answer(request))
        except ProblemError as e:
            response = problem_response(request, e)
            response.headers.pop("Vary", None)
            self._send(response)


class Peer(ThreadingHTTPServer):
    """A peer on `address`: the `files` it holds and checked ({sha256: FileRef}), and the grant keys of the
    servers it paired with (`keys`, {uid: 32 bytes}). `serve_forever()` in a thread; `shutdown()` stops it
    (the user turned sharing off)."""

    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        files: Mapping[str, FileRef],
        keys: Mapping[str, bytes],
        *,
        slots: int = SLOTS,
        name: str = "Lantern peer",
        base: str = BASE,
        tls: ssl.SSLContext | None = None,
        uid: str | None = None,
        quiet: bool = True,
        rate: tuple[int, float] = RATE,
    ) -> None:
        host = address[0]
        if tls is None and host not in ("0.0.0.0", "::") and not is_private(host):  # noqa: S104 - its networks
            raise ValueError("plain HTTP only on a loopback or private address: give a TLS context")
        if not 1 <= slots <= 8:
            raise ValueError("slots is 1 to 8 (SPEC.md § 19.5)")
        if ":" in host:
            self.address_family = socket.AF_INET6
        super().__init__(address, _Handler)
        if tls is not None:
            self.socket = tls.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)
        self.files, self.keys = dict(files), dict(keys)
        self.slots, self.name, self.base, self.tls = slots, name, base.rstrip("/"), tls is not None
        self.uid, self.quiet = uid or str(uuid.uuid4()), quiet
        self.limiter = Limiter(*rate)
        self.active = 0
        self._lock = threading.Lock()
        #: Downloads served whole, to show the user (Annex B.11).
        self.served = 0

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def answer(self, request: ServerRequest) -> ServerResponse:
        """The answer to a request; ProblemError for a refusal."""
        if not is_private(request.remote):
            raise ProblemError(403, "forbidden", "A peer answers its own networks only.")
        wait = self.limiter.hit(request.remote)
        if wait:
            raise ProblemError(
                429, "slow_down", "Too many requests from this address.", headers={"Retry-After": str(math.ceil(wait))}
            )
        if request.method not in ("GET", "HEAD"):
            raise ProblemError(405, "bad_request", "A peer serves GET and HEAD.", headers={"Allow": "GET, HEAD"})
        m = _PATH.fullmatch(request.path[len(self.base) :]) if request.path.startswith(self.base + "/") else None
        if m is None:
            raise ProblemError(404, "not_found", "A peer serves <base>/v1/blobs/sha256/<hex> alone.")
        sha = m.group(1)
        found = read_grant(request.header("Lantern-Grant") or "", self.keys)
        if found is None or found.sha256 != sha:
            raise ProblemError(
                403,
                "forbidden",
                "A grant of a server this peer paired with, for this file, not expired (SPEC.md § 19.4).",
            )
        held = self.files.get(sha)
        if held is None or held.size != found.size:
            raise ProblemError(404, "not_found", "This peer does not hold that file.")
        if not self._take():
            raise ProblemError(
                429, "slow_down", f"{self.slots} downloads at once at most.", headers={"Retry-After": "5"}
            )
        try:
            response = file_response(request, held)
        except BaseException:
            self._release()
            raise
        response.headers["Cache-Control"] = "no-store"
        response.headers.pop("Vary", None)
        if request.method == "HEAD":
            self._release()
            return response
        if response.status == 200:
            self.served += 1
        return _Releasing(response, self._release)

    def _take(self) -> bool:
        with self._lock:
            if self.active >= self.slots:
                return False
            self.active += 1
            return True

    def _release(self) -> None:
        with self._lock:
            self.active = max(0, self.active - 1)

    def reply(self, data: bytes, address: str, limiter: Limiter) -> bytes | None:
        """The reply to a discovery datagram (SPEC.md § 19.5): only to one that asks for peers, from this
        device's networks; None otherwise."""
        if len(data) > DATAGRAM or not is_private(address):
            return None
        try:
            doc: JSONValue = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return None
        if not isinstance(doc, dict) or doc.get("lantern") != "discover" or doc.get("peers") is not True:
            return None
        schema = doc.get("schema")
        if not isinstance(schema, int) or isinstance(schema, bool) or schema != SCHEMA or limiter.hit(address):
            return None
        reply = {
            "schema": SCHEMA,
            "lantern": "peer",
            "uid": self.uid,
            "name": clip(self.name, NAME),
            "port": self.port,
            "base": self.base,
            "tls": self.tls,
            "slots": self.slots,
            "servers": sorted(self.keys)[:16],
        }
        raw = json.dumps(reply, ensure_ascii=False, separators=(",", ":")).encode()
        return raw if len(raw) <= DATAGRAM else None

    def discovery(self, port: int = PORT, host: str = "") -> socket.socket:
        """Answers, on UDP `port`, the discovery datagrams that ask for peers; the socket, to close."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((host, port))
        limiter = Limiter(5, 1.0)

        def loop() -> None:
            while True:
                try:
                    data, source = sock.recvfrom(DATAGRAM + 1)
                except OSError:
                    return
                if not data:
                    return
                out = self.reply(data, source[0], limiter)
                if out is not None:
                    with contextlib.suppress(OSError):
                        sock.sendto(out, source)

        threading.Thread(target=loop, daemon=True).start()
        return sock

    def advertise_dnssd(self, address: str, *, interfaces: Any = None) -> Any:
        """Advertises the peer with DNS-SD as `_lantern-peer._tcp` (SPEC.md § 19.5), with the TXT keys
        servers, path, v and tls; the zeroconf.Zeroconf to close(). The `dnssd` extra."""
        try:
            from zeroconf import InterfaceChoice, ServiceInfo, Zeroconf
        except ImportError as e:  # pragma: no cover - the extra is missing
            raise ImportError("DNS-SD needs the dnssd extra: pip install 'lantern-protocol[dnssd]'") from e
        label = "".join(c if c.isalnum() or c in " -" else "-" for c in self.name)[:63].strip() or "Lantern peer"
        info = ServiceInfo(
            PEER_SERVICE,
            f"{label}.{PEER_SERVICE}",
            addresses=[socket.inet_aton(address)],
            port=self.port,
            properties={
                "servers": ",".join(sorted(self.keys)),
                "path": self.base,
                "v": "1",
                "tls": "1" if self.tls else "0",
            },
        )
        zc = Zeroconf(interfaces=interfaces if interfaces is not None else InterfaceChoice.All)
        zc.register_service(info)
        return zc


class _Releasing(ServerResponse):
    """A response whose download slot is freed once it was sent."""

    def __init__(self, response: ServerResponse, release: Callable[[], None]) -> None:
        super().__init__(response.status, response.headers, response.body)
        self._release = release

    def iter_body(self) -> Generator[bytes]:
        try:
            yield from super().iter_body()
        finally:
            self._release()


def held_files(folder: str | Path, wanted: Iterable[tuple[str, int]]) -> dict[str, FileRef]:
    """{sha256: FileRef} of the files of `folder` whose (sha256, size) is among `wanted`: those the peer checked
    against its server's documents, and alone serves. Hidden files and folders are left out."""
    root = Path(folder)
    sizes = {size for _, size in wanted}
    want = set(wanted)
    out: dict[str, FileRef] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(p.startswith(".") for p in path.relative_to(root).parts):
            continue
        size = path.stat().st_size
        if size not in sizes:
            continue
        sha = sha256_file(path).hexdigest()
        if (sha, size) in want:
            out[sha] = FileRef(str(path), size, sha)
    return out


def server_files(client: Any) -> tuple[str, bytes, set[tuple[str, int]]]:
    """(uid, grant key, {(sha256, size)} of every app and homebrew package) of a server, read with a
    LanternClient: what a peer may serve of it."""
    hello = client.handshake()
    key = grant_key(hello.peers.key) if hello.peers is not None else None
    if key is None:
        raise SystemExit("peer: the server gives no peers.key: it offers no grants (SPEC.md § 19.3)")
    wanted: set[tuple[str, int]] = set()
    if client.offers("library"):
        wanted |= {(a.sha256, a.size) for a in client.iter_apps(page_size=500)}
    if client.offers("homebrew"):
        for e in client.iter_homebrew(page_size=500):
            wanted |= {(p.sha256, p.size) for p in [e.package, *(e.packages or [])]}
    return hello.uid, key, wanted


def main(argv: list[str] | None = None) -> int:
    from lantern.client import LanternClient
    from lantern.signatures import DeviceKey

    p = argparse.ArgumentParser(prog="python -m lantern.peer", description="A Lantern peer (SPEC.md § 19.4).")
    p.add_argument("--folder", required=True, help="the files this console holds")
    p.add_argument("--server", required=True, help="its server, e.g. https://shelf.example.org/")
    p.add_argument("--token", help="the device's token, when the server is private")
    p.add_argument("--key-file", help="the file of the device's key (its 32-byte seed, base64)")
    p.add_argument("--pin", help="the SHA-256 of the server's key, pinned at pairing (SPEC.md § 5.3)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=PEER_PORT)
    p.add_argument("--slots", type=int, default=SLOTS, help="downloads at once, 1 to 8")
    p.add_argument("--name", default=(socket.gethostname()[:64] or "Lantern peer"))
    p.add_argument("--tls-cert")
    p.add_argument("--tls-key")
    p.add_argument("--discovery", action="store_true", help="answer discovery datagrams that ask for peers")
    p.add_argument("--discovery-port", type=int, default=PORT)
    p.add_argument("--dns-sd", action="store_true", help="advertise _lantern-peer._tcp (the dnssd extra)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    if not 1 <= args.slots <= 8:
        p.error("--slots is 1 to 8")
    key = DeviceKey.from_b64(Path(args.key_file).read_text(encoding="ascii").strip()) if args.key_file else None
    with LanternClient(args.server, user_agent="LanternPythonPeer/1.0", token=args.token, key=key, pin=args.pin) as c:
        uid, grant, wanted = server_files(c)
    files = held_files(args.folder, wanted)
    tls = None
    if args.tls_cert:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.tls_cert, args.tls_key)
    try:
        peer = Peer(
            (args.host, args.port), files, {uid: grant}, slots=args.slots, name=args.name, tls=tls, quiet=args.quiet
        )
    except ValueError as e:
        p.error(str(e))
    if args.discovery:
        peer.discovery(args.discovery_port)
    zc = peer.advertise_dnssd(args.host) if args.dns_sd else None
    print(
        f"peer: {len(files)} file(s) of {uid} shared, on {'https' if tls else 'http'}://{args.host}:{peer.port}"
        f"{peer.base}/v1/blobs/sha256/",
        file=sys.stderr,
        flush=True,
    )
    try:
        peer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if zc is not None:
            zc.close()
        peer.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
