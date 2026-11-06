"""Differential updates by the client (SPEC.md § 22.3), against the demo server built from the toolkit, served by
Flask and by FastAPI over HTTP: the chunk index, a newer version put together from an older one, ranges from the
server and from a mirror, and every way it falls back to the whole file (L-22.3-4): a bad index, a wrong chunk, a
short range, a source that sends more than it was asked. Then an upload resumed in the server's chunks (§ 9.3)."""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import itertools
import re
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

import lantern
from demo import DEMO_KEY, DEMO_TOKEN, build_library, delta_pair, demo_accounts, make_lantern, serve
from fakes import AsyncFakeTransport, FakeTransport
from lantern import chunks
from lantern._generated.models import App, Mirror
from lantern.client import AsyncLanternClient, LanternClient
from lantern.client.stdlib import StdlibTransport
from lantern.client.transport import AsyncResponse, Request, Response
from lantern.http import Headers
from lantern.server import LanternApp, SaveLimits
from test_client_writes import TITLE, archive

pytestmark = pytest.mark.conformance

OLD, NEW = delta_pair()
Tamper = Callable[[Request, int, Headers, Iterator[bytes]], tuple[int, Headers, Iterator[bytes]]]


def ranged(answer: Request, data: bytes) -> tuple[int, dict[str, str], bytes]:
    """A file server's answer to a request, ranges honoured."""
    m = re.fullmatch(r"bytes=(\d+)-(\d+)", answer.headers.get("Range") or "")
    if not m:
        return 200, {"Content-Type": "application/octet-stream", "Content-Length": str(len(data))}, data
    a, b = int(m.group(1)), min(int(m.group(2)), len(data) - 1)
    return (
        206,
        {"Content-Range": f"bytes {a}-{b}/{len(data)}", "Content-Type": "application/octet-stream"},
        data[a : b + 1],
    )


class Spy:
    """The standard transport, watched: what it was asked, what came back, and a tamper hook on an answer."""

    def __init__(self, tamper: Tamper | None = None) -> None:
        self.inner = StdlibTransport()
        self.tamper = tamper
        self.log: list[tuple[str, str, str | None, int]] = []
        self.pulled = 0

    def send(self, request: Request, *, timeout: float) -> Response:
        r = self.inner.send(request, timeout=timeout)
        status, headers, chunks_ = r.status, r.headers, r.iter_bytes()
        if self.tamper is not None:
            status, headers, chunks_ = self.tamper(request, status, headers, chunks_)
        self.log.append((request.method, urlsplit(request.url).path, request.headers.get("Range"), status))

        def counted() -> Iterator[bytes]:
            for piece in chunks_:
                self.pulled += len(piece)
                yield piece

        return Response(status, headers, counted(), r.close)

    def close(self) -> None:
        self.inner.close()

    @property
    def ranges(self) -> list[str]:
        return [r for m, p, r, s in self.log if m == "GET" and "/files/" in p and r is not None]

    @property
    def whole(self) -> list[str]:
        return [p for m, p, r, s in self.log if m == "GET" and "/files/" in p and r is None]


@pytest.fixture(params=["flask", "fastapi"])
def demo(request: pytest.FixtureRequest) -> Iterator[tuple[str, LanternApp]]:
    pytest.importorskip(request.param)
    if request.param == "fastapi":
        pytest.importorskip("uvicorn")
    app = make_lantern(build_library(delta=True), accounts=demo_accounts())
    with serve(request.param, app) as url:
        yield url, app


def client(url: str, spy: Spy | None = None, **options: Any) -> LanternClient:
    return LanternClient(
        url, user_agent="DeltaTest/1.0", platform="switch", token=DEMO_TOKEN, key=DEMO_KEY, transport=spy, **options
    )


def versions(c: LanternClient) -> tuple[App, App]:
    found = {a.sha256: a for a in c.iter_apps() if a.chunks is not None}
    return found[hashlib.sha256(OLD).hexdigest()], found[hashlib.sha256(NEW).hexdigest()]


def test_the_index_by_its_file_or_by_its_sha256(demo: tuple[str, LanternApp]) -> None:
    url, _ = demo
    with client(url) as c:
        _, new = versions(c)
        index = c.chunk_index(new)
        assert index.sha256 == new.sha256 and index.size == new.size and sum(n for n, _ in index.chunks) == new.size
        assert c.chunk_index_of(new.sha256, new.size) == index
        with pytest.raises(lantern.NotFound):
            c.chunk_index_of("0" * 64, 10)
        with pytest.raises(ValueError, match="SHA-256"):
            c.chunk_index_of("ABC", 10)
        # An index of another file is refused (L-22.3-1).
        with pytest.raises(chunks.UnusableIndex, match="another file"):
            c.chunk_index_of(new.sha256, new.size + 1)
        small = next(a for a in c.iter_apps() if a.chunks is None)
        with pytest.raises(chunks.UnusableIndex, match="no chunk index"):
            c.chunk_index(small)


def test_a_newer_version_is_put_together_from_the_older_one(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    """[L-22.3-2] [L-22.3-3] The ranges the seed lacks, from the server, each chunk then the whole file checked."""
    url, _ = demo
    spy = Spy()
    progress: list[int] = []
    with client(url, spy) as c:
        _, new = versions(c)
        dest = tmp_path / "update.nsz"
        out = c.download_delta(new, dest, seeds=[OLD], progress=lambda done, total: progress.append(done))
        assert out == dest and dest.read_bytes() == NEW and not dest.with_name("update.nsz.part").exists()
        report = c.last_delta
        assert report is not None and report.used and report.reason is None
        assert report.ranges == len(spy.ranges) >= 1 and spy.whole == []
        assert (
            report.read + report.reused == new.size and report.read < new.size * 0.6
        )  # the chunks the changes touch, not the file
        assert spy.pulled < new.size * 0.7  # the index and two ranges, not the file
        assert progress[-1] == new.size and progress == sorted(progress)


def test_a_seed_may_be_a_file_or_several(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    seed = tmp_path / "older.nsz"
    seed.write_bytes(OLD)
    with client(url) as c:
        _, new = versions(c)
        assert c.download_delta(new, tmp_path / "a", seeds=[seed]).read_bytes() == NEW
        assert c.last_delta is not None and c.last_delta.used
        both = c.download_delta(new, tmp_path / "b", seeds=[b"unrelated bytes", str(seed)])
        assert both.read_bytes() == NEW and c.last_delta.used


@pytest.mark.parametrize("what", ["no seed", "no index", "nothing shared"])
def test_the_whole_file_when_there_is_nothing_to_gain(demo: tuple[str, LanternApp], tmp_path: Path, what: str) -> None:
    """[L-22.3-4] No seed, no index or no chunk in common: the file is read whole, as without the family."""
    url, _ = demo
    spy = Spy()
    with client(url, spy) as c:
        _, new = versions(c)
        if what == "no index":
            plain = dataclasses.replace(new, chunks=None)
            assert c.download_delta(plain, tmp_path / "f", seeds=[OLD]).read_bytes() == NEW
        elif what == "no seed":
            assert c.download_delta(new, tmp_path / "f", seeds=[]).read_bytes() == NEW
        else:
            assert c.download_delta(new, tmp_path / "f", seeds=[b"x" * 5000]).read_bytes() == NEW
        assert c.last_delta is not None and not c.last_delta.used and c.last_delta.reason
        assert spy.ranges == [] and len(spy.whole) == 1


# Hostile sources.


def flip(
    request: Request, status: int, headers: Headers, body: Iterator[bytes]
) -> tuple[int, Headers, Iterator[bytes]]:
    """A range whose bytes are not the chunks' (one byte flipped in the middle)."""
    if status != 206:
        return status, headers, body
    data = bytearray(b"".join(body))
    data[len(data) // 2] ^= 1
    return status, headers, iter([bytes(data)])


def short(
    request: Request, status: int, headers: Headers, body: Iterator[bytes]
) -> tuple[int, Headers, Iterator[bytes]]:
    if status != 206:
        return status, headers, body
    return status, headers, iter([b"".join(body)[:-1]])


def long(
    request: Request, status: int, headers: Headers, body: Iterator[bytes]
) -> tuple[int, Headers, Iterator[bytes]]:
    if status != 206:
        return status, headers, body
    return status, headers, iter([b"".join(body) + b"\0" * 10])


def ignores_range(
    request: Request, status: int, headers: Headers, body: Iterator[bytes]
) -> tuple[int, Headers, Iterator[bytes]]:
    """A server that answers a range with the whole file, 200."""
    if status != 206 or "/files/" not in request.url:
        return status, headers, body
    return 200, Headers({"Content-Type": "application/octet-stream"}), iter([NEW])


def wrong_range(
    request: Request, status: int, headers: Headers, body: Iterator[bytes]
) -> tuple[int, Headers, Iterator[bytes]]:
    if status != 206:
        return status, headers, body
    out = Headers(dict(headers.items()))
    out["Content-Range"] = f"bytes 0-9/{len(NEW)}"
    return status, out, iter([b"".join(body)])


def bad_digest(
    request: Request, status: int, headers: Headers, body: Iterator[bytes]
) -> tuple[int, Headers, Iterator[bytes]]:
    if status != 206:
        return status, headers, body
    out = Headers(dict(headers.items()))
    out["Repr-Digest"] = "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
    return status, out, body


def other_index(
    request: Request, status: int, headers: Headers, body: Iterator[bytes]
) -> tuple[int, Headers, Iterator[bytes]]:
    """An index served other than the bytes whose size and SHA-256 the document gives."""
    if "/chunks/" not in request.url:
        return status, headers, body
    return status, headers, iter([b"".join(body).replace(b'"schema":1', b'"schema":2')])


def not_found(
    request: Request, status: int, headers: Headers, body: Iterator[bytes]
) -> tuple[int, Headers, Iterator[bytes]]:
    if status != 206:
        return status, headers, body
    return 404, Headers({"Content-Type": "application/problem+json"}), iter([b"{}"])


@pytest.mark.parametrize(
    ("tamper", "why"),
    [
        (flip, "SHA-256"),
        (short, "bytes"),
        (long, "more than"),
        (ignores_range, "status 200"),
        (wrong_range, "Content-Range"),
        (bad_digest, "Repr-Digest"),
        (other_index, "UnusableIndex"),
        (not_found, ""),
    ],
    ids=lambda x: getattr(x, "__name__", x),
)
def test_a_source_that_lies_costs_the_whole_file_not_a_wrong_one(
    demo: tuple[str, LanternApp], tmp_path: Path, tamper: Tamper, why: str
) -> None:
    """[L-22.3-2] [L-22.3-3] [L-22.3-4] Nothing wrong is kept, nothing past the file's size is written, and the
    file is read whole instead, which is right."""
    url, _ = demo
    spy = Spy(tamper)
    with client(url) as c:
        _, new = versions(c)
    with client(url, spy) as c:
        dest = tmp_path / "update.nsz"
        out = c.download_delta(new, dest, seeds=[OLD])
        assert out.read_bytes() == NEW  # the whole file, checked, when the ranges were refused
        assert not dest.with_name("update.nsz.part").exists()
        assert c.last_delta is not None and not c.last_delta.used
        assert why in (c.last_delta.reason or "")
        assert len(spy.whole) == 1 or tamper is other_index


def test_a_server_that_ignores_ranges_is_not_read_to_the_end(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    """[L-22.3-3] A 200 for a range is dropped at once: the file is not pulled to find out."""
    url, _ = demo

    def ignore(
        request: Request, status: int, headers: Headers, body: Iterator[bytes]
    ) -> tuple[int, Headers, Iterator[bytes]]:
        if status != 206:
            return status, headers, body
        return (
            200,
            Headers({"Content-Type": "application/octet-stream"}),
            iter([NEW[i : i + 4096] for i in range(0, len(NEW), 4096)]),
        )

    spy = Spy(ignore)
    with client(url, spy) as c:
        _, new = versions(c)
        c.download_delta(new, tmp_path / "f", seeds=[OLD])
    assert spy.pulled < 3 * len(NEW)  # the answers to the ranges were not read (the generator is not drained)


def test_a_seed_that_changed_since_it_was_cut_is_not_used(tmp_path: Path) -> None:
    from lantern.client.delta import Assembly

    seed = tmp_path / "older.nsz"
    seed.write_bytes(OLD)
    old = next(a for a in build_library(delta=True).apps() if a.sha256 == hashlib.sha256(OLD).hexdigest())
    new = next(a for a in build_library(delta=True).apps() if a.sha256 == hashlib.sha256(NEW).hexdigest())
    index = chunks.read_index(chunks.build_index(NEW)[1], sha256=new.sha256, size=new.size)
    assembly = Assembly(new, index, [seed])
    piece = next(p for p in assembly.pieces if p.source is not None)
    assert piece.source is not None
    changed = bytearray(OLD)
    changed[piece.source[1] + 5] ^= 1
    seed.write_bytes(bytes(changed))
    with pytest.raises(chunks.Refused, match="seed"):
        assembly.seed(piece)
    assert old.sha256 != new.sha256


def test_a_seed_that_is_gone_is_the_whole_file(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    with client(url) as c:
        _, new = versions(c)
        out = c.download_delta(new, tmp_path / "f", seeds=[tmp_path / "missing.nsz"])
        assert out.read_bytes() == NEW and c.last_delta is not None and not c.last_delta.used


# A mirror's ranges (SPEC.md § 19).


def with_mirror(app: App) -> App:
    return dataclasses.replace(app, mirrors=[Mirror(url="https://mirror.example.org/glass-orchard.nsz")])


def test_the_ranges_come_from_a_mirror_first(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    """[L-19.1-2] No token, signature or cookie goes to a mirror; the server is not asked for a range."""
    url, _ = demo
    spy = Spy()
    mirror = FakeTransport(lambda r: ranged(r, NEW), chunk=4096)
    with client(url, spy, mirror_transport=mirror) as c:
        _, new = versions(c)
        out = c.download_delta(with_mirror(new), tmp_path / "f", seeds=[OLD])
        assert out.read_bytes() == NEW and c.last_delta is not None and c.last_delta.used
        assert spy.ranges == [] and len(mirror.requests) == c.last_delta.ranges >= 1
        for r in mirror.requests:
            assert r.headers.get("Authorization") is None and r.headers.get("Signature") is None
            assert r.url == "https://mirror.example.org/glass-orchard.nsz" and r.headers["Range"].startswith("bytes=")
            assert r.headers.get("Accept-Encoding") == "identity"


def test_a_mirror_that_fails_leaves_the_range_to_the_server(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    spy = Spy()
    wrong = bytearray(NEW)
    for i in range(0, len(wrong), 97):
        wrong[i] ^= 0xFF  # bytes that are no chunk of the file
    mirror = FakeTransport(lambda r: ranged(r, bytes(wrong)), chunk=4096)
    with client(url, spy, mirror_transport=mirror) as c:
        _, new = versions(c)
        out = c.download_delta(with_mirror(new), tmp_path / "f", seeds=[OLD])
        assert out.read_bytes() == NEW and c.last_delta is not None and c.last_delta.used
        assert mirror.requests and spy.ranges  # the mirror was tried, the server then gave the range
        assert spy.whole == []


def test_a_mirror_that_is_down_is_skipped(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    url, _ = demo
    mirror = FakeTransport(lambda r: (503, {"Content-Type": "application/problem+json"}, b'{"schema":1}'))
    with client(url, mirror_transport=mirror) as c:
        _, new = versions(c)
        assert c.download_delta(with_mirror(new), tmp_path / "f", seeds=[OLD]).read_bytes() == NEW
        assert c.last_delta is not None and c.last_delta.used


# The asynchronous client does the same.


class AsyncSpy:
    def __init__(self, tamper: Tamper | None = None) -> None:
        from lantern.client.httpx_transport import AsyncHttpxTransport

        self.inner = AsyncHttpxTransport()
        self.tamper = tamper
        self.log: list[tuple[str, str, str | None, int]] = []

    async def send(self, request: Request, *, timeout: float) -> AsyncResponse:
        r = await self.inner.send(request, timeout=timeout)
        self.log.append((request.method, urlsplit(request.url).path, request.headers.get("Range"), r.status))
        if self.tamper is None or r.status != 206:
            return r
        body = [piece async for piece in r.iter_bytes()]
        status, headers, pieces = self.tamper(request, r.status, r.headers, iter(body))

        async def again() -> AsyncIterator[bytes]:
            for piece in pieces:
                yield piece

        return AsyncResponse(status, headers, again(), r.close)

    async def close(self) -> None:
        await self.inner.close()


def aclient(url: str, transport: Any = None, **options: Any) -> AsyncLanternClient:
    return AsyncLanternClient(
        url,
        user_agent="DeltaTest/1.0",
        platform="switch",
        token=DEMO_TOKEN,
        key=DEMO_KEY,
        transport=transport,
        **options,
    )


def test_async_a_newer_version_from_the_older_one(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    pytest.importorskip("httpx")

    async def run() -> None:
        url, _ = demo
        spy = AsyncSpy()
        async with aclient(url, spy) as c:
            found = {a.sha256: a async for a in c.iter_apps() if a.chunks is not None}
            new = found[hashlib.sha256(NEW).hexdigest()]
            index = await c.chunk_index(new)
            assert await c.chunk_index_of(new.sha256, new.size) == index
            seed = tmp_path / "older.nsz"
            seed.write_bytes(OLD)
            progress: list[int] = []
            for seeds in ([OLD], [seed]):
                out = await c.download_delta(
                    new, tmp_path / "update.nsz", seeds=seeds, progress=lambda d, t: progress.append(d)
                )
                assert out.read_bytes() == NEW and c.last_delta is not None and c.last_delta.used
                assert c.last_delta.read < new.size * 0.6 and c.last_delta.reused > new.size * 0.4
            assert progress[-1] == new.size
            assert not [1 for m, p, r, s in spy.log if "/files/" in p and r is None]

    asyncio.run(run())


@pytest.mark.parametrize("tamper", [flip, short, long, wrong_range, not_found], ids=lambda t: t.__name__)
def test_async_a_source_that_lies_costs_the_whole_file(
    demo: tuple[str, LanternApp], tmp_path: Path, tamper: Tamper
) -> None:
    pytest.importorskip("httpx")

    async def run() -> None:
        url, _ = demo
        spy = AsyncSpy(tamper)
        async with aclient(url, spy) as c:
            found = {a.sha256: a async for a in c.iter_apps() if a.chunks is not None}
            new = found[hashlib.sha256(NEW).hexdigest()]
            out = await c.download_delta(new, tmp_path / "update.nsz", seeds=[OLD])
            assert out.read_bytes() == NEW and not (tmp_path / "update.nsz.part").exists()
            assert c.last_delta is not None and not c.last_delta.used and c.last_delta.reason
            assert len([1 for m, p, r, s in spy.log if "/files/" in p and r is None]) == 1

    asyncio.run(run())


def test_async_ranges_from_a_mirror_and_no_gain(demo: tuple[str, LanternApp], tmp_path: Path) -> None:
    pytest.importorskip("httpx")

    async def run() -> None:
        url, _ = demo
        mirror = AsyncFakeTransport(lambda r: ranged(r, NEW), chunk=4096)
        async with aclient(url, mirror_transport=mirror) as c:
            found = {a.sha256: a async for a in c.iter_apps() if a.chunks is not None}
            new = found[hashlib.sha256(NEW).hexdigest()]
            out = await c.download_delta(with_mirror(new), tmp_path / "f", seeds=[OLD])
            assert out.read_bytes() == NEW and c.last_delta is not None and c.last_delta.used
            assert len(mirror.requests) == c.last_delta.ranges >= 1
            assert all(r.headers.get("Authorization") is None for r in mirror.requests)
            none = await c.download_delta(new, tmp_path / "g", seeds=[])
            assert none.read_bytes() == NEW and c.last_delta is not None and c.last_delta.reason == "no seed"

    asyncio.run(run())


# An upload resumed in the server's chunks (SPEC.md § 9.3).


class Cut(Exception):
    """A connection lost half-way."""


def cut(done: int, total: int) -> None:
    raise Cut


@pytest.mark.parametrize("framework", ["flask", "fastapi"])
def test_a_resumed_upload_goes_on_in_the_servers_chunks(framework: str, tmp_path: Path) -> None:
    """[L-9.3-3] The client that kept only the upload's address asks HEAD for the chunk size: a server whose chunks
    are of 100,000 bytes would answer 413 to the default megabyte."""
    pytest.importorskip(framework)
    if framework == "fastapi":
        pytest.importorskip("uvicorn")
    app = make_lantern(build_library(), accounts=demo_accounts(), save_limits=SaveLimits(chunk=100_000))
    big = tmp_path / "big.zip"
    big.write_bytes(archive(450_000))
    with (
        serve(framework, app) as url,
        LanternClient(url, user_agent="DeltaTest/1.0", platform="switch", token=DEMO_TOKEN, key=DEMO_KEY) as c,
    ):
        with pytest.raises(Cut):
            c.upload_save(TITLE, big, kind="account", progress=cut)
        assert c.last_upload is not None
        state = c.upload_state(c.last_upload)
        assert (state.offset, state.length, state.chunk_size) == (100_000, big.stat().st_size, 100_000)
        assert c.upload_offset(c.last_upload) == (100_000, big.stat().st_size)
        sent: list[int] = []
        done = c.upload_save(TITLE, big, resume=c.last_upload, progress=lambda d, t: sent.append(d))
        assert done.sha256 == hashlib.sha256(big.read_bytes()).hexdigest()
        assert sent[0] == 200_000 and all(b - a <= 100_000 for a, b in itertools.pairwise(sent))


def test_async_a_resumed_upload(tmp_path: Path) -> None:
    pytest.importorskip("httpx")

    async def run() -> None:
        app = make_lantern(build_library(), accounts=demo_accounts(), save_limits=SaveLimits(chunk=100_000))
        big = tmp_path / "big.zip"
        big.write_bytes(archive(450_000))
        with serve("flask", app) as url:
            async with aclient(url) as c:
                with pytest.raises(Cut):
                    await c.upload_save(TITLE, big, kind="account", progress=cut)
                assert c.last_upload is not None
                state = await c.upload_state(c.last_upload)
                assert state.chunk_size == 100_000 and state.offset == 100_000
                done = await c.upload_save(TITLE, big, resume=c.last_upload)
                assert done.sha256 == hashlib.sha256(big.read_bytes()).hexdigest()

    asyncio.run(run())


def test_a_server_that_does_not_say_its_chunk_size_is_resumed_in_a_megabyte() -> None:
    """HEAD without Lantern-Chunk-Size (a server of draft 0.6): the 1 MiB the client used until now."""
    from lantern.client.core import RESUME_CHUNK, ClientCore

    core = ClientCore("https://shelf.example.org/", base="/api/lantern")
    call = core.upload_state("https://shelf.example.org/api/lantern/v1/uploads/u_1")
    assert call.empty is not None
    state = call.empty(204, Headers({"Upload-Offset": "10", "Upload-Length": "20"}))
    assert tuple(state) == (10, 20, None) and RESUME_CHUNK == 1 << 20
    with_size = call.empty(204, Headers({"Upload-Offset": "0", "Lantern-Chunk-Size": "65536"}))
    assert with_size.chunk_size == 65536 and with_size.length is None
    for bad in ("0", "-5", "many"):
        assert call.empty(204, Headers({"Upload-Offset": "0", "Lantern-Chunk-Size": bad})).chunk_size is None
