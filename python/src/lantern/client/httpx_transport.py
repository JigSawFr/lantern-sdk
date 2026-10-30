"""Transports over httpx (the `httpx` extra), sync and async."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx

from lantern.client.transport import CHUNK, AsyncResponse, Request, Response
from lantern.errors import TransportError
from lantern.http import Headers


def _request(client: httpx.Client | httpx.AsyncClient, request: Request, timeout: float) -> httpx.Request:
    return client.build_request(
        request.method, request.url, headers=list(request.headers.items()), content=request.body, timeout=timeout
    )


class HttpxTransport:
    """Over an httpx.Client: the one given (its own settings kept, but redirects
    are never followed), or one of its own, closed with the transport."""

    def __init__(self, client: httpx.Client | None = None, *, verify: str | bool = True) -> None:
        self._own = client is None
        self.client = client or httpx.Client(verify=verify)

    def send(self, request: Request, *, timeout: float) -> Response:
        try:
            answer = self.client.send(_request(self.client, request, timeout), stream=True, follow_redirects=False)
        except httpx.HTTPError as e:
            raise TransportError(f"{request.method} {request.url}: {e}") from e

        def chunks() -> Iterator[bytes]:
            try:
                yield from answer.iter_bytes(CHUNK)
            except httpx.HTTPError as e:
                raise TransportError(f"{request.method} {request.url}: {e}") from e

        return Response(answer.status_code, Headers(answer.headers.multi_items()), chunks(), answer.close)

    def close(self) -> None:
        if self._own:
            self.client.close()


class AsyncHttpxTransport:
    """Over an httpx.AsyncClient, as HttpxTransport."""

    def __init__(self, client: httpx.AsyncClient | None = None, *, verify: str | bool = True) -> None:
        self._own = client is None
        self.client = client or httpx.AsyncClient(verify=verify)

    async def send(self, request: Request, *, timeout: float) -> AsyncResponse:
        try:
            answer = await self.client.send(
                _request(self.client, request, timeout), stream=True, follow_redirects=False
            )
        except httpx.HTTPError as e:
            raise TransportError(f"{request.method} {request.url}: {e}") from e

        async def chunks() -> AsyncIterator[bytes]:
            try:
                async for chunk in answer.aiter_bytes(CHUNK):
                    yield chunk
            except httpx.HTTPError as e:
                raise TransportError(f"{request.method} {request.url}: {e}") from e

        return AsyncResponse(answer.status_code, Headers(answer.headers.multi_items()), chunks(), answer.aclose)

    async def close(self) -> None:
        if self._own:
            await self.client.aclose()
