"""Compressed responses (SPEC.md § 2.1): what the client asks for and how it reads what comes back."""

from __future__ import annotations

import asyncio
import gzip
from collections.abc import AsyncIterator, Iterator

import pytest

from lantern._base import DocumentError
from lantern.client import coding
from lantern.client.transport import AsyncResponse, Response
from lantern.http import Headers

DOCUMENT = b'{"schema":1,"items":[' + b",".join(b'{"id":"%d"}' % i for i in range(2000)) + b"]}"


def split(data: bytes, size: int) -> Iterator[bytes]:
    for i in range(0, len(data), size):
        yield data[i : i + size]


def read(headers: dict[str, str], chunks: Iterator[bytes], limit: int = 1 << 20) -> bytes:
    return Response(200, Headers(headers), chunks).read(limit)


def test_the_client_asks_for_what_it_reads() -> None:
    asked = [c.strip() for c in coding.accepted().split(",")]
    assert "gzip" in asked
    assert set(asked) <= {"gzip", "zstd"}


def test_a_gzip_body_is_read_as_the_document() -> None:
    body = gzip.compress(DOCUMENT)
    assert len(body) < len(DOCUMENT)
    assert read({"Content-Encoding": "gzip"}, split(body, 7)) == DOCUMENT
    assert read({"Content-Encoding": "GZIP"}, iter([body])) == DOCUMENT


def test_the_headers_describe_the_document_once_decoded() -> None:
    headers = Headers({"Content-Encoding": "gzip", "Content-Length": "12", "Content-Type": "application/json"})
    response = Response(200, headers, iter([gzip.compress(b"{}")]))
    assert "Content-Encoding" not in response.headers and "Content-Length" not in response.headers
    assert response.headers["Content-Type"] == "application/json"
    assert response.read(10) == b"{}"


def test_a_body_without_coding_is_as_it_is() -> None:
    assert read({}, iter([DOCUMENT])) == DOCUMENT
    assert read({"Content-Encoding": "identity"}, iter([DOCUMENT])) == DOCUMENT


def test_members_one_after_the_other_make_one_document() -> None:
    body = gzip.compress(DOCUMENT[:100]) + gzip.compress(DOCUMENT[100:])
    assert read({"Content-Encoding": "gzip"}, split(body, 50)) == DOCUMENT


def test_a_body_that_expands_without_end_stops_at_the_limit() -> None:
    bomb = gzip.compress(bytes(200 * 1024 * 1024), compresslevel=9)
    assert len(bomb) < 300 * 1024
    with pytest.raises(DocumentError, match="a body above"):
        read({"Content-Encoding": "gzip"}, split(bomb, 4096), limit=1 << 20)


@pytest.mark.parametrize(
    "body",
    [gzip.compress(DOCUMENT)[:-9], b"not gzip at all", gzip.compress(DOCUMENT) + b"junk"],
    ids=["cut", "not gzip", "trailing junk"],
)
def test_a_gzip_body_that_is_not_one_is_refused(body: bytes) -> None:
    with pytest.raises(DocumentError, match="gzip"):
        read({"Content-Encoding": "gzip"}, split(body, 11))


@pytest.mark.parametrize("name", ["br", "deflate", "gzip, br", "gzip, gzip"])
def test_a_coding_that_was_not_asked_for_is_refused(name: str) -> None:
    with pytest.raises(DocumentError):
        Response(200, Headers({"Content-Encoding": name}), iter([b"{}"]))


@pytest.mark.skipif(coding._zstd is None, reason="zstd is Python 3.14's")
def test_a_zstd_body_is_read_as_the_document() -> None:
    zstd = coding._zstd
    assert zstd is not None
    body = zstd.compress(DOCUMENT)
    assert read({"Content-Encoding": "zstd"}, split(body, 13)) == DOCUMENT
    with pytest.raises(DocumentError, match="a body above"):
        read({"Content-Encoding": "zstd"}, split(zstd.compress(bytes(100 * 1024 * 1024)), 4096), limit=1 << 20)
    with pytest.raises(DocumentError, match="zstd"):
        read({"Content-Encoding": "zstd"}, split(body[:-5], 13))


def test_an_async_body_is_read_the_same_way() -> None:
    async def chunks(data: bytes) -> AsyncIterator[bytes]:
        for piece in split(data, 9):
            yield piece

    async def run() -> None:
        body = gzip.compress(DOCUMENT)
        response = AsyncResponse(200, Headers({"Content-Encoding": "gzip"}), chunks(body))
        assert await response.read(1 << 20) == DOCUMENT
        bomb = gzip.compress(bytes(100 * 1024 * 1024), compresslevel=9)
        response = AsyncResponse(200, Headers({"Content-Encoding": "gzip"}), chunks(bomb))
        with pytest.raises(DocumentError, match="a body above"):
            await response.read(1 << 20)
        response = AsyncResponse(200, Headers({"Content-Encoding": "gzip"}), chunks(body[:-9]))
        with pytest.raises(DocumentError, match="gzip"):
            await response.read(1 << 20)

    asyncio.run(run())
