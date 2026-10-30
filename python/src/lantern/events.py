"""Events (SPEC.md § 18): what a server pushes as it happens, read from its
Server-Sent Events stream or from a long poll, without I/O here.

`SSEParser` reads a stream's bytes as they arrive (the WHATWG HTML
standard's rules: lines ending in CR, LF or CRLF, the fields `id`, `event`,
`data` and `retry`, comments), within bounds: a line, and an event's data,
of a few KiB at most (§ 13: an event's `data` is 4 KiB at most), so that a
server cannot make a client hold more. `read_event()` then applies the rules
of § 18.1: `data` is one JSON document with its `schema`; an event a reader
does not know, or of a newer schema, is skipped (L-18.1-5).

    parser = SSEParser()
    for raw in parser.feed(chunk):
        event = read_event(raw)
        if event is not None:
            ...

The client's streams (LanternClient.events(), AsyncLanternClient.events())
resume with `Last-Event-ID`, wait the server's `retry` before connecting
again and back off while connecting fails (L-18.1-9, Annex B.2), and connect
again after twice `limits.heartbeat` of silence.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from lantern._base import SCHEMA, DocumentError, JSONObject
from lantern.limits import load_json

#: The events of this version (SPEC.md § 18.2); a later one may add others, which a reader skips.
KNOWN_EVENTS = ("ready", "library", "request", "pairing", "save", "sync", "shutdown")
#: An event's `data` (SPEC.md § 13), and a line of the stream, in bytes.
DATA_LIMIT = 4096
LINE_LIMIT = DATA_LIMIT + 64
#: The wait before connecting again when the server gave no `retry`, in milliseconds.
DEFAULT_RETRY = 5000
#: The longest wait between two attempts to connect (Annex B.2).
BACKOFF_LIMIT = 300.0


@dataclass(frozen=True)
class RawEvent:
    """An event as the stream gave it: its type (`message` when none), its data's text, and the last event
    id the stream set (None when it set none)."""

    event: str
    data: str
    id: str | None


@dataclass(frozen=True)
class ServerEvent:
    """An event of SPEC.md § 18.2: `event` (`library`, `request`…), its `data` document, and its `id`, a
    token of /v1/changes to resume from."""

    id: str | None
    event: str
    data: JSONObject


class SSEParser:
    """A Server-Sent Events stream, read as its bytes arrive. `retry` is the last reconnection time the
    stream gave (ms), `last_id` its last event id; `seen` counts the lines read (comments, heartbeats and
    blank lines included), so that a reader knows the stream is alive."""

    def __init__(self, *, line_limit: int = LINE_LIMIT, data_limit: int = DATA_LIMIT) -> None:
        self.line_limit, self.data_limit = line_limit, data_limit
        self.retry: int | None = None
        self.last_id: str | None = None
        self.seen = 0
        #: The bound a line broke, once it did: the stream is then refused.
        self.error: DocumentError | None = None
        self._buffer = bytearray()
        self._cr = False
        self._first = True
        self._event = ""
        self._data: list[str] = []
        self._size = 0

    def feed(self, chunk: bytes) -> list[RawEvent]:
        """The events `chunk` completes; DocumentError beyond the bounds, or for a line that is not UTF-8. The
        events completed before such a line are given first: the error is then raised by the next call, and
        kept in `error`."""
        if self.error is not None:
            raise self.error
        out: list[RawEvent] = []
        try:
            for byte in chunk:
                if self._cr:
                    self._cr = False
                    if byte == 0x0A:  # CRLF: the CR ended the line already
                        continue
                if byte in (0x0A, 0x0D):
                    self._cr = byte == 0x0D
                    event = self._line(bytes(self._buffer))
                    self._buffer.clear()
                    if event is not None:
                        out.append(event)
                    continue
                self._buffer.append(byte)
                if len(self._buffer) > self.line_limit:
                    raise DocumentError(f"a line of the event stream above {self.line_limit} bytes", "events")
        except DocumentError as e:
            self.error = e
            self._buffer.clear()
            if not out:
                raise
        return out

    def _line(self, raw: bytes) -> RawEvent | None:
        self.seen += 1
        if self._first:
            self._first = False
            raw = raw.removeprefix(b"\xef\xbb\xbf")
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise DocumentError("a line of the event stream that is not UTF-8", "events") from None
        if line == "":
            return self._dispatch()
        if line.startswith(":"):
            return None
        name, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if name == "event":
            self._event = value
        elif name == "data":
            self._size += len(value.encode()) + 1
            if self._size > self.data_limit + 1:
                raise DocumentError(f"an event's data above {self.data_limit} bytes", "events")
            self._data.append(value)
        elif name == "id" and "\0" not in value:
            self.last_id = value or None
        elif name == "retry" and value.isdigit() and value.isascii():
            self.retry = int(value)
        return None

    def _dispatch(self) -> RawEvent | None:
        data, event = self._data, self._event or "message"
        self._data, self._event, self._size = [], "", 0
        if not data:
            return None
        return RawEvent(event, "\n".join(data), self.last_id)


def read_event(raw: RawEvent) -> ServerEvent | None:
    """An event of SPEC.md § 18 from what the stream gave, or None when a reader skips it: a type it does not
    know, data that is not a JSON document with an integer `schema`, or of a newer schema (L-18.1-5)."""
    if raw.event not in KNOWN_EVENTS:
        return None
    return event_of(raw.id, raw.event, raw.data.encode())


def event_of(event_id: str | None, event: str, data: bytes | JSONObject) -> ServerEvent | None:
    """An event read from its parts (a stream's, or a long poll's item); None when a reader skips it."""
    if event not in KNOWN_EVENTS:
        return None
    if isinstance(data, bytes):
        try:
            doc = load_json(data, limit=DATA_LIMIT, where=f"event {event}")
        except DocumentError:
            return None
    else:
        doc = data
    schema = doc.get("schema") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or not isinstance(schema, int) or isinstance(schema, bool) or schema < 1:
        return None
    if schema > SCHEMA:
        return None
    return ServerEvent(event_id, event, doc)


class Backoff:
    """The waits between attempts to connect (SPEC.md § 18.1, Annex B.2): the server's `retry` at least,
    doubled while connecting fails, up to five minutes, with some jitter; back to `retry` once a stream
    began."""

    def __init__(self, limit: float = BACKOFF_LIMIT) -> None:
        self.limit = limit
        self.failures = 0

    def next(self, retry_ms: int) -> float:
        base = max(retry_ms / 1000.0, 0.0)
        wait: float = min(self.limit, max(base, base * float(2 ** min(self.failures, 16))))
        self.failures += 1
        if self.failures > 1:
            wait = min(self.limit, wait * (1 + random.random() / 4))  # noqa: S311 - jitter, not a secret
        return max(wait, base)

    def reset(self) -> None:
        self.failures = 0


def read_timeout(heartbeat: int | None) -> float:
    """How long a stream may stay silent before the client connects again: twice `limits.heartbeat` (60 s
    when the handshake gives none), and a few seconds more for the network."""
    return 2.0 * (heartbeat or 60) + 5.0


__all__ = [
    "DATA_LIMIT",
    "DEFAULT_RETRY",
    "KNOWN_EVENTS",
    "LINE_LIMIT",
    "Backoff",
    "RawEvent",
    "SSEParser",
    "ServerEvent",
    "event_of",
    "read_event",
    "read_timeout",
]
