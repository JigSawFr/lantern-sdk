"""A transport that answers from a function, for the client's unit tests."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

from lantern.client.transport import AsyncResponse, Request, Response
from lantern.http import Headers

Answer = tuple[int, dict[str, str], bytes]
UID = "6f1c2a8e-2b1d-4c3e-9f00-112233445566"


def doc(status: int = 200, body: Any = None, **headers: str) -> Answer:
    raw = json.dumps(body).encode()
    ctype = "application/json" if status < 400 else "application/problem+json"
    return status, {"Content-Type": ctype, **headers}, raw


def hello(**changes: Any) -> dict[str, Any]:
    out = {
        "schema": 1,
        "uid": UID,
        "name": "Test shelf",
        "base": "/api/lantern",
        "versions": [1],
        "platforms": ["switch"],
        "account": {"state": "anonymous", "scopes": ["library"]},
        "features": {"library": 1, "titles": 1, "homebrew": 2, "cheats": 0},
    }
    out.update(changes)
    return out


class FakeTransport:
    def __init__(self, answer: Callable[[Request], Answer], chunk: int = 7) -> None:
        self.answer, self.chunk = answer, chunk
        self.requests: list[Request] = []
        self.closed = False

    def _chunks(self, body: bytes) -> Iterator[bytes]:
        for i in range(0, len(body), self.chunk):
            yield body[i : i + self.chunk]

    def send(self, request: Request, *, timeout: float) -> Response:
        self.requests.append(request)
        status, headers, body = self.answer(request)
        return Response(status, Headers(headers), self._chunks(body))

    def close(self) -> None:
        self.closed = True


class AsyncFakeTransport(FakeTransport):
    async def send(self, request: Request, *, timeout: float) -> AsyncResponse:  # type: ignore[override]
        self.requests.append(request)
        status, headers, body = self.answer(request)

        async def chunks() -> AsyncIterator[bytes]:
            for c in self._chunks(body):
                yield c

        return AsyncResponse(status, Headers(headers), chunks())

    async def close(self) -> None:  # type: ignore[override]
        self.closed = True
