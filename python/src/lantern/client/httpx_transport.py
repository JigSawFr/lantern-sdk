"""Transports over httpx (the `httpx` extra), sync and async.

For a LAN server's self-signed certificate (SPEC.md § 5.3): `verify=False`
checks no CA (before pairing, to read the key's fingerprint), and `pin` (the
key's SHA-256, hex) is the key pinned once paired. httpx sends a request as
soon as its connection is up, so a pin is checked before: the server's
certificate is read on a connection of its own, its key compared with the
pin, and the requests then go over a client that trusts that certificate
alone. A certificate renewed over the same key is read again; another key
raises PinMismatch, and nothing is sent.
"""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterator, Iterator
from typing import Any
from urllib.parse import urlsplit

import httpx

from lantern.client.tls import check_pin, fetch_certificate, peer_spki, pinned_context
from lantern.client.transport import CHUNK, AsyncResponse, Request, Response
from lantern.errors import TransportError
from lantern.http import Headers
from lantern.spki import spki_sha256


def _request(client: httpx.Client | httpx.AsyncClient, request: Request, timeout: float) -> httpx.Request:
    return client.build_request(
        request.method, request.url, headers=list(request.headers.items()), content=request.body, timeout=timeout
    )


def _spki(answer: httpx.Response) -> str | None:
    stream: Any = answer.extensions.get("network_stream")
    ssl_object = stream.get_extra_info("ssl_object") if stream is not None else None
    return peer_spki(ssl_object) if isinstance(ssl_object, ssl.SSLObject | ssl.SSLSocket) else None


class _Pinned:
    """The certificate a pin was checked on, per origin, and the context that trusts it."""

    def __init__(self) -> None:
        self.contexts: dict[tuple[str, int, str], ssl.SSLContext] = {}

    def context(self, url: str, pin: str, timeout: float, *, again: bool = False) -> ssl.SSLContext:
        parts = urlsplit(url)
        host, port = parts.hostname or "", parts.port or 443
        key = (host, port, pin.lower())
        if again or key not in self.contexts:
            der = fetch_certificate(host, port, timeout)
            check_pin(spki_sha256(der), pin, f"{host}:{port}")
            self.contexts[key] = pinned_context(der)
        return self.contexts[key]


class HttpxTransport:
    """Over an httpx.Client: the one given (its own settings kept, but redirects
    are never followed), or one of its own, closed with the transport."""

    def __init__(
        self, client: httpx.Client | None = None, *, verify: str | bool = True, pin: str | None = None
    ) -> None:
        if client is not None and pin is not None:
            raise ValueError("a pin needs the transport's own clients: give no client")
        self._own = client is None
        self.verify = verify is not False and pin is None
        self.pin = pin
        self.client = client or httpx.Client(verify=verify if pin is None else False)
        self._pinned = _Pinned()
        self._clients: dict[int, httpx.Client] = {}

    def _client(self, request: Request, timeout: float, again: bool = False) -> httpx.Client:
        if self.pin is None or urlsplit(request.url).scheme != "https":
            return self.client
        context = self._pinned.context(request.url, self.pin, timeout, again=again)
        if id(context) not in self._clients:
            self._clients[id(context)] = httpx.Client(verify=context)
        return self._clients[id(context)]

    def send(self, request: Request, *, timeout: float) -> Response:
        client = self._client(request, timeout)
        try:
            try:
                answer = client.send(_request(client, request, timeout), stream=True, follow_redirects=False)
            except httpx.ConnectError:
                if client is self.client:
                    raise
                client = self._client(request, timeout, again=True)  # renewed over the same key?
                answer = client.send(_request(client, request, timeout), stream=True, follow_redirects=False)
        except httpx.HTTPError as e:
            raise TransportError(f"{request.method} {request.url}: {e}") from e

        def chunks() -> Iterator[bytes]:
            try:
                yield from answer.iter_bytes(CHUNK)
            except httpx.HTTPError as e:
                raise TransportError(f"{request.method} {request.url}: {e}") from e

        response = Response(answer.status_code, Headers(answer.headers.multi_items()), chunks(), answer.close)
        response.spki = _spki(answer)
        return response

    def close(self) -> None:
        for c in self._clients.values():
            c.close()
        if self._own:
            self.client.close()


class AsyncHttpxTransport:
    """Over an httpx.AsyncClient, as HttpxTransport."""

    def __init__(
        self, client: httpx.AsyncClient | None = None, *, verify: str | bool = True, pin: str | None = None
    ) -> None:
        if client is not None and pin is not None:
            raise ValueError("a pin needs the transport's own clients: give no client")
        self._own = client is None
        self.verify = verify is not False and pin is None
        self.pin = pin
        self.client = client or httpx.AsyncClient(verify=verify if pin is None else False)
        self._pinned = _Pinned()
        self._clients: dict[int, httpx.AsyncClient] = {}

    def _client(self, request: Request, timeout: float, again: bool = False) -> httpx.AsyncClient:
        if self.pin is None or urlsplit(request.url).scheme != "https":
            return self.client
        context = self._pinned.context(request.url, self.pin, timeout, again=again)
        if id(context) not in self._clients:
            self._clients[id(context)] = httpx.AsyncClient(verify=context)
        return self._clients[id(context)]

    async def send(self, request: Request, *, timeout: float) -> AsyncResponse:
        client = self._client(request, timeout)
        try:
            try:
                answer = await client.send(_request(client, request, timeout), stream=True, follow_redirects=False)
            except httpx.ConnectError:
                if client is self.client:
                    raise
                client = self._client(request, timeout, again=True)
                answer = await client.send(_request(client, request, timeout), stream=True, follow_redirects=False)
        except httpx.HTTPError as e:
            raise TransportError(f"{request.method} {request.url}: {e}") from e

        async def chunks() -> AsyncIterator[bytes]:
            try:
                async for chunk in answer.aiter_bytes(CHUNK):
                    yield chunk
            except httpx.HTTPError as e:
                raise TransportError(f"{request.method} {request.url}: {e}") from e

        response = AsyncResponse(answer.status_code, Headers(answer.headers.multi_items()), chunks(), answer.aclose)
        response.spki = _spki(answer)
        return response

    async def close(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        if self._own:
            await self.client.aclose()
