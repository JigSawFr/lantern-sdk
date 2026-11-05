"""Content codings of a response (SPEC.md § 2.1): gzip, and zstd where this Python has it.

A client MAY ask for a compressed JSON document; the limits of § 13 then apply
to the document once decompressed, so a body is inflated a piece at a time and
the reader stops at its limit: a small body that expands without end costs the
reader no more than a plain one of the limit's size.
"""

from __future__ import annotations

import zlib
from collections.abc import AsyncIterator, Iterator
from typing import Any, Protocol

from lantern._base import DocumentError

#: What one step of a decoder gives at most, whatever the body inflates to.
PIECE = 1 << 16

try:  # Python 3.14
    from compression import zstd as _zstd  # type: ignore[import-not-found, unused-ignore]
except ImportError:  # pragma: no cover - the other Pythons
    _zstd = None


def accepted() -> str:
    """The Accept-Encoding of a request for a JSON document."""
    return "zstd, gzip" if _zstd is not None else "gzip"


class _Decoder(Protocol):
    def feed(self, data: bytes) -> Iterator[bytes]: ...

    def finish(self) -> None: ...


class _Gzip:
    """gzip (RFC 1952): members one after the other, as the format allows."""

    def __init__(self) -> None:
        self._z = zlib.decompressobj(wbits=31)
        self._open = False

    def feed(self, data: bytes) -> Iterator[bytes]:
        while data:
            self._open = True
            try:
                out = self._z.decompress(data, PIECE)
                while out:
                    yield out
                    out = self._z.decompress(self._z.unconsumed_tail, PIECE) if self._z.unconsumed_tail else b""
            except zlib.error as e:
                raise DocumentError(f"a gzip body that does not decode: {e}") from e
            if self._z.eof:
                data = self._z.unused_data
                self._z = zlib.decompressobj(wbits=31)
                self._open = False
            else:
                data = b""

    def finish(self) -> None:
        if self._open:
            raise DocumentError("a gzip body that ends early")


class _Zstd:
    """zstd (RFC 8878), frames one after the other."""

    def __init__(self) -> None:
        assert _zstd is not None
        self._d: Any = _zstd.ZstdDecompressor()
        self._open = False

    def feed(self, data: bytes) -> Iterator[bytes]:
        assert _zstd is not None
        while data:
            self._open = True
            try:
                out = self._d.decompress(data, PIECE)
                while out:
                    yield out
                    out = b"" if self._d.eof or self._d.needs_input else self._d.decompress(b"", PIECE)
            except _zstd.ZstdError as e:
                raise DocumentError(f"a zstd body that does not decode: {e}") from e
            if self._d.eof:
                data = self._d.unused_data
                self._d = _zstd.ZstdDecompressor()
                self._open = False
            else:
                data = b""

    def finish(self) -> None:
        if self._open:
            raise DocumentError("a zstd body that ends early")


def decoder(coding: str | None) -> _Decoder | None:
    """The decoder of a Content-Encoding: None for a body as it is, DocumentError for a coding not asked for."""
    names = [c.strip().lower() for c in (coding or "").split(",") if c.strip()]
    names = [c for c in names if c != "identity"]
    if not names:
        return None
    if len(names) > 1:
        raise DocumentError(f"a body in more than one coding: {coding}")
    if names[0] in ("gzip", "x-gzip"):
        return _Gzip()
    if names[0] == "zstd" and _zstd is not None:
        return _Zstd()
    raise DocumentError(f"a body in a coding that was not asked for: {names[0]}")


def decode(chunks: Iterator[bytes], how: _Decoder) -> Iterator[bytes]:
    for chunk in chunks:
        yield from how.feed(chunk)
    how.finish()


async def adecode(chunks: AsyncIterator[bytes], how: _Decoder) -> AsyncIterator[bytes]:
    async for chunk in chunks:
        for piece in how.feed(chunk):
            yield piece
    how.finish()
