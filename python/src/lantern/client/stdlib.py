"""A transport of the standard library alone (http.client and ssl)."""

from __future__ import annotations

import http.client
import ssl
from collections.abc import Iterator
from urllib.parse import urlsplit

from lantern.client.tls import check_pin, peer_spki, unverified_context
from lantern.client.transport import CHUNK, Request, Response
from lantern.errors import TransportError
from lantern.http import Headers


class StdlibTransport:
    """One connection per request, over http.client.

    HTTPS certificates are checked against the system's CA store, or `cafile`
    (PEM), or `context` when given. For a LAN server with a self-signed
    certificate (SPEC.md § 5.3), `verify=False` checks no CA: the client then
    reads the key's fingerprint and the user compares it at pairing; `pin`
    (the key's SHA-256, hex) is the key pinned once paired, and implies
    `verify=False`. With a pin, the key is checked once the TLS handshake is
    done, before a byte of the request is sent: another key raises
    PinMismatch. Each response carries the fingerprint of its connection's
    key (`spki`), and `seen` keeps the last one."""

    def __init__(
        self,
        *,
        cafile: str | None = None,
        context: ssl.SSLContext | None = None,
        verify: bool = True,
        pin: str | None = None,
    ) -> None:
        self.verify = verify and pin is None
        self.pin = pin
        self._context = context or ssl.create_default_context(cafile=cafile)
        self._unverified = unverified_context()
        self.seen: str | None = None

    @property
    def context(self) -> ssl.SSLContext:
        return self._context if self.verify and self.pin is None else self._unverified

    def send(self, request: Request, *, timeout: float) -> Response:
        parts = urlsplit(request.url)
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname or "", parts.port, timeout=timeout, context=self.context)
        else:
            conn = http.client.HTTPConnection(parts.hostname or "", parts.port, timeout=timeout)
        headers = dict(request.headers.items())
        if request.body is not None:
            headers["Content-Length"] = str(len(request.body))
        spki = None
        try:
            if parts.scheme == "https":
                conn.connect()
                assert isinstance(conn.sock, ssl.SSLSocket)
                spki = self.seen = peer_spki(conn.sock)
                check_pin(spki, self.pin, f"{parts.hostname}:{parts.port or 443}")
            conn.request(request.method, target, body=request.body, headers=headers)
            answer = conn.getresponse()
        except TransportError:
            conn.close()
            raise
        except (OSError, http.client.HTTPException) as e:
            conn.close()
            raise TransportError(f"{request.method} {request.url}: {e}") from e

        length = answer.getheader("Content-Length")
        expected = int(length) if length is not None and length.strip().isdigit() else None

        def chunks() -> Iterator[bytes]:
            got = 0
            try:
                while chunk := answer.read(CHUNK):
                    got += len(chunk)
                    yield chunk
            except (OSError, http.client.HTTPException) as e:
                raise TransportError(f"{request.method} {request.url}: {e}") from e
            if expected is not None and got < expected and request.method != "HEAD" and answer.status != 304:
                raise TransportError(f"{request.method} {request.url}: cut after {got} of {expected} bytes")

        response = Response(answer.status, Headers(answer.getheaders()), chunks(), conn.close)
        response.spki = spki
        return response

    def close(self) -> None:
        return None
