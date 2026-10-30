"""The client's request pipeline and its transports.

A request goes through three steps before it leaves:

1. the client builds it (method, URL, the headers SPEC.md § 2 asks for);
2. its credentials are applied (today a bearer token, `BearerToken`), and
   then its signer, when one is set (`RequestSigner`, for the request
   signatures of a later draft), both only for the server's own origin:
   never for another host a document points at (SPEC.md § 2, § 7.1);
3. a transport sends it: `StdlibTransport` (the standard library, no
   dependency) or `HttpxTransport` and `AsyncHttpxTransport` (the `httpx`
   extra). Any object with the same `send` will do.

A transport never follows a redirect: the client treats one as an answer
the protocol does not allow.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from typing import Protocol

from lantern._base import DocumentError
from lantern.http import Headers, origin

CHUNK = 1 << 16


@dataclass
class Request:
    """A request about to be sent: an absolute URL, its headers and body."""

    method: str
    url: str
    headers: Headers = field(default_factory=Headers)
    body: bytes | None = None


class Credentials(Protocol):
    """What proves who the client is, applied to each request to the server's origin."""

    def apply(self, request: Request) -> None: ...


class RequestSigner(Protocol):
    """Signs a request to the server's origin, after its credentials: the
    place for the HTTP message signatures (RFC 9421) of a later draft. It may
    add headers (Signature, Signature-Input, Content-Digest) and must not
    change the method, URL or body."""

    def sign(self, request: Request) -> None: ...


class BearerToken:
    """`Authorization: Bearer <token>` (SPEC.md § 5.1)."""

    def __init__(self, token: str) -> None:
        if not token or any(c.isspace() for c in token):
            raise ValueError("a token is a non-empty string without spaces")
        self._token = token

    def apply(self, request: Request) -> None:
        request.headers["Authorization"] = f"Bearer {self._token}"

    def __repr__(self) -> str:
        return "BearerToken(…)"


@dataclass
class Pipeline:
    """Credentials, then signer, for the requests to `server_origin` only."""

    server_origin: tuple[str, str, int]
    credentials: Credentials | None = None
    signer: RequestSigner | None = None

    def prepare(self, request: Request) -> Request:
        if origin(request.url) == self.server_origin:
            if self.credentials is not None:
                self.credentials.apply(request)
            if self.signer is not None:
                self.signer.sign(request)
        else:
            request.headers.pop("Authorization", None)
        return request


class Response:
    """A response whose body is read as it arrives. Close it, or use it as a context manager."""

    def __init__(
        self, status: int, headers: Headers, chunks: Iterator[bytes], close: Callable[[], None] = lambda: None
    ) -> None:
        self.status, self.headers = status, headers
        self._chunks, self._close = chunks, close
        #: The fingerprint (SHA-256 of the SPKI, hex) of the key of the TLS connection, when the transport knows it.
        self.spki: str | None = None

    def iter_bytes(self) -> Iterator[bytes]:
        yield from self._chunks

    def read(self, limit: int) -> bytes:
        """The whole body, at most `limit` bytes: DocumentError beyond."""
        out = bytearray()
        for chunk in self._chunks:
            out += chunk
            if len(out) > limit:
                raise DocumentError(f"a body above {limit} bytes")
        return bytes(out)

    def close(self) -> None:
        self._close()

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AsyncResponse:
    """A response of an async transport, its body read as it arrives."""

    def __init__(
        self, status: int, headers: Headers, chunks: AsyncIterator[bytes], close: Callable[[], object] | None = None
    ) -> None:
        self.status, self.headers = status, headers
        self._chunks, self._close = chunks, close
        self.spki: str | None = None

    async def iter_bytes(self) -> AsyncIterator[bytes]:
        async for chunk in self._chunks:
            yield chunk

    async def read(self, limit: int) -> bytes:
        out = bytearray()
        async for chunk in self._chunks:
            out += chunk
            if len(out) > limit:
                raise DocumentError(f"a body above {limit} bytes")
        return bytes(out)

    async def close(self) -> None:
        if self._close is not None:
            result = self._close()
            if hasattr(result, "__await__"):
                await result

    async def __aenter__(self) -> AsyncResponse:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


class Transport(Protocol):
    """Sends a request and gives its response, its body not read yet. Raises
    lantern.TransportError when the connection fails."""

    def send(self, request: Request, *, timeout: float) -> Response: ...

    def close(self) -> None: ...


class AsyncTransport(Protocol):
    async def send(self, request: Request, *, timeout: float) -> AsyncResponse: ...

    async def close(self) -> None: ...
