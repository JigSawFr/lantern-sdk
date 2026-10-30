"""Event streams (SPEC.md § 18.1), as a client keeps one open: connected,
read event by event, resumed with `Last-Event-ID` after a cut, for the sync
and the async client.

    for event in client.events():                  # blocks; ends only on close() or an error
        if event.event == "request":
            notify(event.data)

A stream connects again by itself when the connection drops, when it stays
silent twice `limits.heartbeat`, or after `shutdown`: it waits the server's
`retry` at least (L-18.1-9), doubled while connecting fails (Annex B.2), and
resumes after the last id it read. A server that no longer knows that id
(410) raises Gone: the app reads again what it shows, and iterates again,
which connects without an id. Too many streams (429) waits Retry-After.
Every other refusal raises its error. An event of a type this library does
not know, or of a newer schema, is skipped (L-18.1-5); a line or an event
beyond § 13's bounds raises DocumentError and closes the stream.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import deque
from collections.abc import AsyncIterator, Callable, Iterator
from typing import TYPE_CHECKING, Any

from lantern._base import LanternError
from lantern.client.core import ERROR_BODY, retry_signature
from lantern.client.transport import AsyncResponse, Request, Response
from lantern.errors import Gone, ProblemError, SlowDown, TransportError, UnexpectedResponse
from lantern.events import DEFAULT_RETRY, Backoff, ServerEvent, SSEParser, read_event, read_timeout
from lantern.http import media_type

if TYPE_CHECKING:
    from lantern.client.aio import AsyncLanternClient
    from lantern.client.sync import LanternClient

EVENT_STREAM = "text/event-stream"


def _waits_on(error: ProblemError) -> bool:
    """Whether a refusal to open a stream is waited out rather than raised: 429, and a server's failure."""
    return isinstance(error, SlowDown) or error.status >= 500


class _State:
    """What a stream keeps across its connections."""

    def __init__(self, since: str | None) -> None:
        self.last_id = since
        self.retry = DEFAULT_RETRY
        self.backoff = Backoff()
        self.pending: deque[ServerEvent] = deque()
        self.parser = SSEParser()
        self.wait = 0.0  # before the next connection
        self.closed = False
        #: A bound the stream broke (§ 13), raised once the events before it were given.
        self.error: LanternError | None = None

    def take(self, chunk: bytes) -> bool:
        """Reads a chunk: the events it completes are pending; whether the stream asked to be left (shutdown)."""
        leave = False
        for raw in self.parser.feed(chunk):
            if self.parser.retry is not None:
                self.retry = self.parser.retry
            self.last_id = self.parser.last_id or self.last_id
            event = read_event(raw)
            if event is None:
                continue
            if event.event == "ready":
                self.backoff.reset()
            if event.event == "shutdown":
                after = event.data.get("retry")
                seconds = after if isinstance(after, int) and not isinstance(after, bool) and after > 0 else 0
                self.wait = max(self.retry / 1000.0, float(seconds))
                leave = True
            self.pending.append(event)
        if self.parser.retry is not None:
            self.retry = self.parser.retry
        self.error = self.parser.error
        return leave

    def dropped(self) -> None:
        """The connection ended: wait before the next, the server's retry at least, more while it fails."""
        self.parser = SSEParser()
        self.wait = max(self.wait, self.backoff.next(self.retry))

    def refused(self, error: ProblemError) -> None:
        if isinstance(error, Gone):
            self.last_id = None  # the next connection starts from now (SPEC.md § 18.1)
        self.wait = max(self.backoff.next(self.retry), float(error.retry_after or 0))


def _check_open(status: int, content_type: str | None) -> None:
    if status == 200 and media_type(content_type) != EVENT_STREAM:
        raise UnexpectedResponse(f"events: Content-Type {content_type!r}, not {EVENT_STREAM}", status)


class EventStream(Iterator[ServerEvent]):
    """The events of a server, as LanternClient.events() opens them. `last_id` is where it would resume
    from; close() ends it, from another thread too."""

    def __init__(
        self,
        client: LanternClient,
        since: str | None = None,
        *,
        platform: str | None = None,
        reconnect: bool = True,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client, self.platform, self.reconnect, self.sleep = client, platform, reconnect, sleep
        self._state = _State(since)
        self._response: Response | None = None
        self._chunks: Iterator[bytes] | None = None

    @property
    def last_id(self) -> str | None:
        return self._state.last_id

    @property
    def retry(self) -> int:
        """The milliseconds the server asks a client to wait before it connects again."""
        return self._state.retry

    def __iter__(self) -> EventStream:
        return self

    def __next__(self) -> ServerEvent:
        state = self._state
        while True:
            if state.pending:
                return state.pending.popleft()
            if state.error is not None:
                error, state.error = state.error, None
                self.close()
                raise error
            if state.closed:
                raise StopIteration
            if self._chunks is None:
                if state.wait > 0:
                    self.sleep(state.wait)
                    state.wait = 0.0
                if state.closed:
                    raise StopIteration
                self._connect()
                continue
            try:
                chunk = next(self._chunks)
            except StopIteration:
                chunk = None
            except TransportError:
                if state.closed:
                    raise StopIteration from None
                self._drop()
                if not self.reconnect:
                    raise
                continue
            if chunk is None:
                self._drop()
                if not self.reconnect:
                    state.closed = True
                continue
            try:
                leave = state.take(chunk)
            except LanternError:
                self.close()
                raise
            if leave:
                self._drop()

    def _connect(self) -> None:
        client, state = self.client, self._state
        if client.core.base is None:
            client.handshake()
        hello = client.core.hello
        timeout = read_timeout(hello.limits.heartbeat if hello is not None and hello.limits is not None else None)
        for attempt in range(2):
            request: Request = client.core.events_request(state.last_id, self.platform)
            try:
                response = client.transport.send(request, timeout=timeout)
            except TransportError:
                state.dropped()
                if not self.reconnect:
                    raise
                return
            if response.status == 200:
                try:
                    _check_open(response.status, response.headers.get("Content-Type"))
                except LanternError:
                    response.close()
                    raise
                client.core.note("events", response.headers)
                self._response, self._chunks = response, response.iter_bytes()
                return
            body = _read_error(response)
            response.close()
            error = client.core.error("events", response.status, response.headers, body)
            if isinstance(error, ProblemError) and retry_signature(client.core, error, request, attempt):
                continue
            if isinstance(error, ProblemError) and self.reconnect and _waits_on(error):
                state.refused(error)
                return
            if isinstance(error, Gone):
                state.refused(error)
            raise error

    def _drop(self) -> None:
        if self._response is not None:
            with contextlib.suppress(Exception):
                self._response.close()
        self._response, self._chunks = None, None
        if not self._state.closed:
            self._state.dropped()

    def close(self) -> None:
        """Ends the stream: iterating stops."""
        self._state.closed = True
        if self._response is not None:
            with contextlib.suppress(Exception):
                self._response.close()


class AsyncEventStream(AsyncIterator[ServerEvent]):
    """The events of a server, as AsyncLanternClient.events() opens them."""

    def __init__(
        self,
        client: AsyncLanternClient,
        since: str | None = None,
        *,
        platform: str | None = None,
        reconnect: bool = True,
        sleep: Callable[[float], Any] = asyncio.sleep,
    ) -> None:
        self.client, self.platform, self.reconnect, self.sleep = client, platform, reconnect, sleep
        self._state = _State(since)
        self._response: AsyncResponse | None = None
        self._chunks: AsyncIterator[bytes] | None = None

    @property
    def last_id(self) -> str | None:
        return self._state.last_id

    @property
    def retry(self) -> int:
        return self._state.retry

    def __aiter__(self) -> AsyncEventStream:
        return self

    async def __anext__(self) -> ServerEvent:
        state = self._state
        while True:
            if state.pending:
                return state.pending.popleft()
            if state.error is not None:
                error, state.error = state.error, None
                await self.aclose()
                raise error
            if state.closed:
                raise StopAsyncIteration
            if self._chunks is None:
                if state.wait > 0:
                    await self.sleep(state.wait)
                    state.wait = 0.0
                if state.closed:
                    raise StopAsyncIteration
                await self._connect()
                continue
            try:
                chunk: bytes | None = await self._chunks.__anext__()
            except StopAsyncIteration:
                chunk = None
            except TransportError:
                if state.closed:
                    raise StopAsyncIteration from None
                await self._drop()
                if not self.reconnect:
                    raise
                continue
            if chunk is None:
                await self._drop()
                if not self.reconnect:
                    state.closed = True
                continue
            try:
                leave = state.take(chunk)
            except LanternError:
                await self.aclose()
                raise
            if leave:
                await self._drop()

    async def _connect(self) -> None:
        client, state = self.client, self._state
        if client.core.base is None:
            await client.handshake()
        hello = client.core.hello
        timeout = read_timeout(hello.limits.heartbeat if hello is not None and hello.limits is not None else None)
        for attempt in range(2):
            request = client.core.events_request(state.last_id, self.platform)
            try:
                response = await client.transport.send(request, timeout=timeout)
            except TransportError:
                state.dropped()
                if not self.reconnect:
                    raise
                return
            if response.status == 200:
                try:
                    _check_open(response.status, response.headers.get("Content-Type"))
                except LanternError:
                    await response.close()
                    raise
                client.core.note("events", response.headers)
                self._response, self._chunks = response, response.iter_bytes()
                return
            try:
                body = await response.read(ERROR_BODY)
            except LanternError:
                body = b""
            await response.close()
            error = client.core.error("events", response.status, response.headers, body)
            if isinstance(error, ProblemError) and retry_signature(client.core, error, request, attempt):
                continue
            if isinstance(error, ProblemError) and self.reconnect and _waits_on(error):
                state.refused(error)
                return
            if isinstance(error, Gone):
                state.refused(error)
            raise error

    async def _drop(self) -> None:
        if self._response is not None:
            with contextlib.suppress(Exception):
                await self._response.close()
        self._response, self._chunks = None, None
        if not self._state.closed:
            self._state.dropped()

    async def aclose(self) -> None:
        """Ends the stream: iterating stops."""
        self._state.closed = True
        if self._response is not None:
            with contextlib.suppress(Exception):
                await self._response.close()


def _read_error(response: Response) -> bytes:
    try:
        return response.read(ERROR_BODY)
    except LanternError:
        return b""


__all__ = ["AsyncEventStream", "EventStream"]
