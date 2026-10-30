"""A transport of the standard library alone (http.client and ssl)."""

from __future__ import annotations

import http.client
import ssl
from collections.abc import Iterator
from urllib.parse import urlsplit

from lantern.client.transport import CHUNK, Request, Response
from lantern.errors import TransportError
from lantern.http import Headers


class StdlibTransport:
    """One connection per request, over http.client. HTTPS certificates are
    checked against the system's CA store, or `cafile` (PEM) when given, or
    `context` when given."""

    def __init__(self, *, cafile: str | None = None, context: ssl.SSLContext | None = None) -> None:
        self.context = context or ssl.create_default_context(cafile=cafile)

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
        try:
            conn.request(request.method, target, body=request.body, headers=headers)
            answer = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            conn.close()
            raise TransportError(f"{request.method} {request.url}: {e}") from e

        def chunks() -> Iterator[bytes]:
            try:
                while chunk := answer.read(CHUNK):
                    yield chunk
            except (OSError, http.client.HTTPException) as e:
                raise TransportError(f"{request.method} {request.url}: {e}") from e

        return Response(answer.status, Headers(answer.getheaders()), chunks(), conn.close)

    def close(self) -> None:
        return None
