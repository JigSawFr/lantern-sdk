"""Events on the client's side (SPEC.md § 18): the Server-Sent Events parser
and its bounds, the rules a reader keeps, and the stream's reconnections
(retry, Last-Event-ID, 410, 429, shutdown), over a transport that answers
from a function."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

import lantern
from fakes import AsyncFakeTransport, FakeTransport, doc, hello
from lantern.client import AsyncLanternClient, LanternClient
from lantern.client.transport import Request
from lantern.events import Backoff, RawEvent, SSEParser, event_of, read_event, read_timeout

AGENT = "LanternEventsTest/1.0"


def parse(data: bytes, **options: Any) -> tuple[list[RawEvent], SSEParser]:
    p = SSEParser(**options)
    out: list[RawEvent] = []
    for i in range(0, len(data), 3):  # as a network would cut it
        out += p.feed(data[i : i + 3])
    return out, p


def test_the_parser_reads_the_whatwg_form() -> None:
    raw = (
        b"\xef\xbb\xbfretry: 5000\r\n\r\n"
        b'id: s_1\nevent: ready\ndata: {"schema":1}\n\n'
        b": heartbeat\n\n"
        b'id: s_2\revent: request\rdata:{"schema":1,\r'
        b'data: "id":"r_7"}\r\r'
        b"data: no event type\n\n"
        b"id\nevent: sync\ndata: {}\n\n"
    )
    events, p = parse(raw)
    assert p.retry == 5000
    assert [(e.event, e.id) for e in events] == [
        ("ready", "s_1"),
        ("request", "s_2"),
        ("message", "s_2"),
        ("sync", None),
    ]
    assert events[1].data == '{"schema":1,\n"id":"r_7"}'
    assert p.seen > 8  # comments and blank lines count as signs of life


def test_ids_with_nul_and_retry_not_digits_are_ignored() -> None:
    events, p = parse(b"retry: soon\nid: a\x00b\nid: s_9\ndata: x\n\n")
    assert p.retry is None and events[0].id == "s_9"


def test_the_bounds() -> None:
    with pytest.raises(lantern.DocumentError, match="line"):
        SSEParser(line_limit=100).feed(b"data: " + b"x" * 200)
    with pytest.raises(lantern.DocumentError, match="data"):
        parse(b"data: " + b"x" * 3000 + b"\ndata: " + b"x" * 3000 + b"\n\n")
    with pytest.raises(lantern.DocumentError, match="UTF-8"):
        SSEParser().feed(b"data: \xff\n")
    parse(b"data: " + b"x" * 4096 + b"\n\n")  # 4 KiB: the bound itself


def test_what_a_reader_skips() -> None:
    assert read_event(RawEvent("ready", '{"schema":1}', "s_1")) is not None
    assert read_event(RawEvent("x-unknown", '{"schema":1}', "s_1")) is None  # L-18.1-5
    assert read_event(RawEvent("request", '{"schema":2,"id":"r"}', "s_1")) is None  # newer
    assert read_event(RawEvent("request", "not json", "s_1")) is None
    assert read_event(RawEvent("request", '{"id":"r"}', "s_1")) is None  # no schema
    assert event_of("s_1", "sync", {"schema": 1, "collection": "wishes", "rev": 3, "x-later": True}) is not None


def test_backoff_and_timeout() -> None:
    b = Backoff(limit=60)
    waits = [b.next(5000) for _ in range(8)]
    assert waits[0] == 5.0 and all(w >= 5.0 for w in waits) and max(waits) <= 60
    assert waits[3] > waits[1]
    b.reset()
    assert b.next(5000) == 5.0
    assert read_timeout(15) == 35.0 and read_timeout(None) == 125.0


def sse(*events: tuple[str, str, dict[str, Any]], retry: int = 2000) -> bytes:
    out = f"retry: {retry}\n\n".encode()
    for eid, kind, data in events:
        out += f"id: {eid}\nevent: {kind}\ndata: {json.dumps(data)}\n\n".encode()
    return out


class Server:
    """Answers the handshake, then each connection to /v1/events from a list."""

    def __init__(self, streams: list[tuple[int, dict[str, str], bytes]]) -> None:
        self.streams = streams
        self.opened: list[Request] = []

    def __call__(self, r: Request) -> tuple[int, dict[str, str], bytes]:
        if r.url.endswith("/.well-known/lantern"):
            return doc(200, hello(limits={"page_size": 100, "heartbeat": 5, "event_streams": 2, "wait": 60}))
        assert "/v1/events" in r.url
        self.opened.append(r)
        if not self.streams:
            return 503, {"Content-Type": "application/problem+json", "Retry-After": "1"}, b"{}"
        return self.streams.pop(0)


STREAM = {"Content-Type": "text/event-stream"}


def test_a_stream_resumes_with_last_event_id() -> None:
    server = Server(
        [
            (
                200,
                STREAM,
                sse(("s_1", "ready", {"schema": 1}), ("s_2", "request", {"schema": 1, "id": "r_1", "status": "done"})),
            ),
            (
                200,
                STREAM,
                sse(
                    ("s_2", "ready", {"schema": 1}),
                    ("s_3", "x-later", {"schema": 1}),
                    ("s_4", "sync", {"schema": 1, "collection": "wishes", "rev": 2}),
                ),
            ),
        ]
    )
    waits: list[float] = []
    with LanternClient(
        "https://shelf.example.org", user_agent=AGENT, token="et_t", transport=FakeTransport(server)
    ) as c:
        stream = c.events(sleep=waits.append)
        got = [next(stream) for _ in range(4)]
        stream.close()
    assert [(e.event, e.id) for e in got] == [("ready", "s_1"), ("request", "s_2"), ("ready", "s_2"), ("sync", "s_4")]
    assert "Last-Event-ID" not in server.opened[0].headers
    assert server.opened[1].headers["Last-Event-ID"] == "s_2"  # resumed after the last one read
    assert server.opened[0].headers["Accept"] == "text/event-stream"
    assert server.opened[0].headers["Authorization"] == "Bearer et_t"
    assert waits == [2.0]  # the server's retry, at least (L-18.1-9)
    assert stream.last_id == "s_4" and stream.retry == 2000


def test_gone_slow_down_and_shutdown() -> None:
    problem = {"Content-Type": "application/problem+json"}
    server = Server(
        [
            (429, {**problem, "Retry-After": "7"}, json.dumps({"status": 429, "code": "slow_down"}).encode()),
            (200, STREAM, sse(("s_5", "ready", {"schema": 1}), ("s_6", "shutdown", {"schema": 1, "retry": 30}))),
            (410, problem, json.dumps({"status": 410, "code": "gone"}).encode()),
            (200, STREAM, sse(("s_9", "ready", {"schema": 1}))),
        ]
    )
    waits: list[float] = []
    with LanternClient("https://shelf.example.org", user_agent=AGENT, transport=FakeTransport(server)) as c:
        stream = c.events("s_4", sleep=waits.append)
        assert next(stream).event == "ready"
        assert next(stream).event == "shutdown"
        with pytest.raises(lantern.Gone):
            next(stream)
        assert stream.last_id is None  # the next connection starts from now (§ 18.1)
        assert next(stream).id == "s_9"
        stream.close()
    assert waits[0] >= 7.0  # Retry-After
    assert waits[1] >= 30.0  # shutdown's retry
    assert [r.headers.get("Last-Event-ID") for r in server.opened] == ["s_4", "s_4", "s_6", None]


def test_refusals_are_raised_and_a_stream_without_reconnect_ends() -> None:
    forbidden = (403, {"Content-Type": "application/problem+json"}, b'{"status":403,"code":"forbidden"}')
    with (
        LanternClient("https://shelf.example.org", user_agent=AGENT, transport=FakeTransport(Server([forbidden]))) as c,
        pytest.raises(lantern.Forbidden),
    ):
        next(c.events())
    once = Server([(200, STREAM, sse(("s_1", "ready", {"schema": 1})))])
    with LanternClient("https://shelf.example.org", user_agent=AGENT, transport=FakeTransport(once)) as c:
        assert [e.event for e in c.events(reconnect=False)] == ["ready"]
    json_answer = Server([(200, {"Content-Type": "application/json"}, b"{}")])
    with (
        LanternClient("https://shelf.example.org", user_agent=AGENT, transport=FakeTransport(json_answer)) as c,
        pytest.raises(lantern.UnexpectedResponse),
    ):
        next(c.events())


def test_an_oversized_event_closes_the_stream() -> None:
    big = b"retry: 1000\n\nid: s_1\nevent: library\ndata: " + b"x" * 9000 + b"\n\n"
    with LanternClient(
        "https://shelf.example.org", user_agent=AGENT, transport=FakeTransport(Server([(200, STREAM, big)]), chunk=512)
    ) as c:
        stream = c.events()
        with pytest.raises(lantern.DocumentError):
            next(stream)
        with pytest.raises(StopIteration):
            next(stream)


def test_the_async_stream() -> None:
    server = Server(
        [
            (200, STREAM, sse(("s_1", "ready", {"schema": 1}))),
            (
                200,
                STREAM,
                sse(("s_1", "ready", {"schema": 1}), ("s_2", "save", {"schema": 1, "title_id": "0100ABCD00010000"})),
            ),
        ]
    )
    waits: list[float] = []

    async def nap(seconds: float) -> None:
        waits.append(seconds)

    async def run() -> list[str]:
        async with AsyncLanternClient(
            "https://shelf.example.org", user_agent=AGENT, transport=AsyncFakeTransport(server)
        ) as c:
            stream = c.events(sleep=nap)
            out = [(await stream.__anext__()).event for _ in range(3)]
            await stream.aclose()
            with pytest.raises(StopAsyncIteration):
                await stream.__anext__()
            return out

    assert asyncio.run(run()) == ["ready", "ready", "save"]
    assert server.opened[1].headers["Last-Event-ID"] == "s_1" and waits == [2.0]


def test_a_long_poll() -> None:
    seen: list[str] = []

    def answer(r: Request) -> tuple[int, dict[str, str], bytes]:
        if r.url.endswith("/.well-known/lantern"):
            return doc(200, hello(limits={"page_size": 100, "heartbeat": 5, "event_streams": 2, "wait": 60}))
        seen.append(r.url)
        events = [
            {"id": "s_2", "event": "request", "data": {"schema": 1, "id": "r_1", "status": "done"}},
            {"id": "s_3", "event": "x-later", "data": {"schema": 1}},
            {"id": "s_4", "event": "pairing", "data": {"schema": 2}},
        ]
        return doc(200, {"schema": 1, "added": [], "removed": [], "since": "s_4", "events": events})

    with LanternClient("https://shelf.example.org", user_agent=AGENT, transport=FakeTransport(answer)) as c:
        found, since = c.poll_events("s_1", wait=600)
    assert [e.id for e in found] == ["s_2"] and since == "s_4"
    assert "wait=60" in seen[0] and "since=s_1" in seen[0]  # lowered to limits.wait (§ 18.3)
    with pytest.raises(ValueError, match="wait"):
        LanternClient("https://shelf.example.org", transport=FakeTransport(answer)).wait_changes("s_1", -1)


def test_the_events_before_a_bound_broken_come_first() -> None:
    p = SSEParser()
    good = b'id: s_1\nevent: ready\ndata: {"schema":1}\n\n'
    out = p.feed(good + b"data: " + b"x" * 5000)
    assert [e.event for e in out] == ["ready"] and p.error is not None
    with pytest.raises(lantern.DocumentError):
        p.feed(b"\n\n")
