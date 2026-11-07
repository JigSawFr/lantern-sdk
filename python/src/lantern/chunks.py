"""Differential updates (SPEC.md § 22, feature `deltas`): a newer version of a
file put together from the bytes of an older one, and only the rest downloaded.

    raw = client.fetch(app.chunks.url, sha256=app.chunks.sha256, size=app.chunks.size)
    index = chunks.read_index(raw, sha256=app.sha256, size=app.size, ref=app.chunks)   # L-22.3-1
    data = chunks.assemble(index, [older_bytes], read_range, app.sha256, app.size)    # L-22.3-2, -3, -4

The pieces, all standard library and no I/O of their own but a seed file's:

- cut() and cut_file(): lantern-cdc-1, the chunker of § 22.2 (a gear table
  from SHA-256; a chunk ends where the top bits of the rolling hash are
  clear), `size_for()` the chunker's size a server picks for a file;
- build_index() and ref(): a file's chunk index, in canonical JSON (§ 2.3),
  and the `chunks` of its app or package (§ 22.1), what a server writes;
  index_file(), a file on disk's SHA-256 and index from a single read;
- read_index(): what a client checks of an index before it uses it (§ 22.3,
  L-22.3-1), refused as UnusableIndex, after which it reads the whole file;
- plan(), ranges_of() and Pieces: what comes from a seed and what is read as
  a range of the file; Collector, the chunks of a range checked as its
  bytes arrive (L-22.3-2, L-22.3-3); assemble(), the whole in memory.

Test vectors: vectors/chunks.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from lantern._base import JSONObject, JSONValue, LanternError
from lantern._generated.models import ChunksRef
from lantern.canonical import canonical
from lantern.errors import IntegrityError

#: The chunker of § 22.2.
ALG = "lantern-cdc-1"
#: A chunker's size: a power of two from 64 KiB to 4 MiB.
SIZES: tuple[int, ...] = tuple(1 << b for b in range(16, 23))
#: Chunks in an index, and an index's bytes (SPEC.md § 13).
CHUNKS_LIMIT = 100_000
INDEX_LIMIT = 8 << 20
#: The gear table (§ 22.2): the first 8 bytes of SHA-256(`lantern-cdc-1` || the byte), big-endian.
GEAR: tuple[int, ...] = tuple(
    int.from_bytes(hashlib.sha256(ALG.encode() + bytes([i])).digest()[:8], "big") for i in range(256)
)
_MASK64 = (1 << 64) - 1
_HEX = re.compile(r"^[0-9a-f]{64}$")

#: What a seed is: bytes the client holds, or the path of a file.
Seed = bytes | bytearray | memoryview | str | os.PathLike[str]


class UnusableIndex(LanternError):
    """A chunk index a client cannot use (SPEC.md § 22.3): it reads the whole file instead."""


class Refused(IntegrityError):
    """A chunk, a range or a file put together that does not match what its index says (L-22.3-2): the whole file
    is read instead (L-22.3-4)."""


def bounds(size: int) -> tuple[int, int, int]:
    """(min, max, mask) of lantern-cdc-1 for a chunker of `size` (SPEC.md § 22.2)."""
    if size not in SIZES:
        raise ValueError(f"a chunker's size is a power of two from 65536 to 4194304, not {size}")
    bits = size.bit_length() - 1
    return size >> 2, size << 2, ((1 << bits) - 1) << (64 - bits)


def _end(view: memoryview, low: int, high: int, mask: int) -> int:
    """The length of the first chunk of `view`, which holds `high` bytes at most of a chunk's start: all of them
    when `low` or fewer, else up to the first byte (from the `low`-th on) after which the hash AND `mask` is 0."""
    n = len(view)
    if n <= low:
        return n
    end = min(n, high)
    gear, h, i = GEAR, 0, low
    for byte in view[low:end]:
        h = ((h << 1) + gear[byte]) & _MASK64
        i += 1
        if not h & mask:
            return i
    return end


def cut(data: bytes | bytearray | memoryview, size: int) -> list[tuple[int, int]]:
    """lantern-cdc-1 (SPEC.md § 22.2): the (offset, length) of each chunk of `data`, for a chunker of `size`. A
    chunk ends at the end of the data, or after the first byte from its `min`-th on whose gear hash has its
    top bits clear, or at its `max`-th."""
    low, high, mask = bounds(size)
    view = memoryview(data)
    out: list[tuple[int, int]] = []
    start, n = 0, len(view)
    while start < n:
        length = _end(view[start : start + high], low, high, mask)
        out.append((start, length))
        start += length
    return out


def cut_file(path: str | os.PathLike[str], size: int) -> Iterator[tuple[int, int, str]]:
    """(offset, length, sha256) of each chunk of the file at `path`, read a chunk at a time (16 MiB at most in
    memory), for a chunker of `size`."""
    low, high, mask = bounds(size)
    with Path(path).open("rb") as f:
        start = 0
        while True:
            f.seek(start)
            buf = f.read(high)
            if not buf:
                return
            view = memoryview(buf)
            length = _end(view, low, high, mask)
            yield start, length, hashlib.sha256(view[:length]).hexdigest()
            start += length


def size_for(length: int) -> int | None:
    """The chunker's size a server may choose for a file of `length` bytes: the smallest from 64 KiB whose chunks
    stay about 16,384 and, whatever the bytes, within the limit of 100,000; None for a file too large for any."""
    for size in SIZES:
        if length // ((size >> 2) + 1) + 1 <= CHUNKS_LIMIT and length <= size * 16384:
            return size
    last = SIZES[-1]
    return last if length // ((last >> 2) + 1) + 1 <= CHUNKS_LIMIT else None


def build_index(data: bytes | bytearray | memoryview, size: int | None = None) -> tuple[JSONObject, bytes]:
    """(the document, its canonical bytes) of the chunk index of a file (SPEC.md § 22.1). `size`: the chunker's,
    by default size_for()'s; ValueError for a file too large for any."""
    chunker = size or size_for(len(data))
    if chunker is None:
        raise ValueError("a file too large for a chunk index")
    view = memoryview(data)
    chunks: list[JSONValue] = [[n, hashlib.sha256(view[o : o + n]).hexdigest()] for o, n in cut(view, chunker)]
    doc: JSONObject = {
        "schema": 1,
        "sha256": hashlib.sha256(view).hexdigest(),
        "size": len(view),
        "chunker": {"alg": ALG, "size": chunker},
        "chunks": chunks,
    }
    return doc, canonical(doc)


class FileDigest(NamedTuple):
    """What index_file() learns of a file in one read: its SHA-256 and size, and, unless the file is too large
    for any chunker, its chunk index (the document and its canonical bytes)."""

    sha256: str
    size: int
    index: tuple[JSONObject, bytes] | None


def index_file(
    path: str | os.PathLike[str],
    size: int | None = None,
    *,
    progress: Callable[[int], None] | None = None,
    chunk_index: bool = True,
) -> FileDigest:
    """The SHA-256 of the file at `path` and its chunk index (SPEC.md § 22.1), from one read of it: what a server
    needs before it lists a file, whatever its size, without reading a file of many gigabytes twice. Memory holds
    16 MiB at most. `size`: the chunker's, by default size_for()'s; `progress`: called with the bytes read so far;
    `chunk_index=False`: only the SHA-256 (FileDigest.index is None). The file is not to change meanwhile."""
    length = Path(path).stat().st_size
    chunker = (size or size_for(length)) if chunk_index else None
    whole = hashlib.sha256()
    chunks: list[JSONValue] = []
    done = 0
    with Path(path).open("rb") as f:
        if chunker is None:
            while block := f.read(1 << 20):
                whole.update(block)
                done += len(block)
                if progress:
                    progress(done)
            return FileDigest(whole.hexdigest(), done, None)
        low, high, mask = bounds(chunker)
        buf = bytearray()
        eof = False
        while True:
            while len(buf) < high and not eof:
                block = f.read(max(high - len(buf), 1 << 20))
                if block:
                    buf += block
                else:
                    eof = True
            if not buf:
                break
            with memoryview(buf) as view:
                n = _end(view[:high], low, high, mask)
                piece = bytes(view[:n])
            del buf[:n]
            whole.update(piece)
            chunks.append([n, hashlib.sha256(piece).hexdigest()])
            done += n
            if progress:
                progress(done)
    doc: JSONObject = {
        "schema": 1,
        "sha256": whole.hexdigest(),
        "size": done,
        "chunker": {"alg": ALG, "size": chunker},
        "chunks": chunks,
    }
    return FileDigest(whole.hexdigest(), done, (doc, canonical(doc)))


def ref(url: str, raw: bytes) -> JSONObject:
    """An app's or a package's `chunks` (SPEC.md § 22.1): where its index is, and the index's size and SHA-256."""
    return {"url": url, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


@dataclass(frozen=True, slots=True)
class Index:
    """A chunk index a client may use: the file it describes, its chunker's `size`, and each chunk as (length,
    sha256), in the file's order."""

    sha256: str
    size: int
    chunker_size: int
    chunks: tuple[tuple[int, str], ...]


def read_index(raw: bytes, *, sha256: str, size: int, ref: ChunksRef | None = None) -> Index:
    """The index a client may use for the file of `sha256` and `size`, from the bytes `raw` read at the `chunks.url`
    of its app or package (SPEC.md § 22.3, L-22.3-1). `ref` is that `chunks`
    (lantern.models.ChunksRef): the bytes' size and SHA-256 must be its. Raises UnusableIndex unless the
    document is of schema 1 (a later one is absent, § 3.2), names that file, a chunker this library knows, and
    chunks of 1 byte to the chunker's max, in lower-case hex, 100,000 at most, whose sizes add up to the file's."""
    if ref is not None:
        if len(raw) != ref.size:
            raise UnusableIndex(f"{len(raw)} bytes, not the {ref.size} the document gives")
        if hashlib.sha256(raw).hexdigest() != ref.sha256:
            raise UnusableIndex("its SHA-256 is not the one the document gives")
    if len(raw) > INDEX_LIMIT:
        raise UnusableIndex(f"above {INDEX_LIMIT} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise UnusableIndex("not JSON") from None
    if not isinstance(doc, dict) or type(doc.get("schema")) is not int:
        raise UnusableIndex("not a document")
    if doc["schema"] != 1:
        raise UnusableIndex(f"schema {doc['schema']}, which this library does not read")
    chunker = doc.get("chunker")
    if not (
        isinstance(chunker, dict)
        and chunker.get("alg") == ALG
        and type(chunker.get("size")) is int
        and chunker["size"] in SIZES
    ):
        raise UnusableIndex("a chunker this library does not know")
    if doc.get("sha256") != sha256 or type(doc.get("size")) is not int or doc["size"] != size:
        raise UnusableIndex("the index of another file")
    chunks = doc.get("chunks")
    high = bounds(chunker["size"])[1]
    if not isinstance(chunks, list) or len(chunks) > CHUNKS_LIMIT:
        raise UnusableIndex(f"chunks: a list of {CHUNKS_LIMIT} at most")
    total = 0
    out: list[tuple[int, str]] = []
    for c in chunks:
        if not (
            isinstance(c, list)
            and len(c) == 2
            and type(c[0]) is int
            and 1 <= c[0] <= high
            and isinstance(c[1], str)
            and _HEX.match(c[1])
        ):
            raise UnusableIndex(f"a chunk of another form: {str(c)[:80]}")
        total += c[0]
        out.append((c[0], c[1]))
    if total != size:
        raise UnusableIndex(f"its chunks add up to {total} bytes, not the file's {size}")
    return Index(sha256, size, chunker["size"], tuple(out))


def seed_chunks(seed: Seed, size: int) -> dict[str, tuple[int, int]]:
    """{sha256: (offset, length)} of the chunks of `seed`, cut by the chunker of the index it reads (SPEC.md
    § 22.3); the first of the chunks that are the same bytes."""
    out: dict[str, tuple[int, int]] = {}
    if isinstance(seed, bytes | bytearray | memoryview):
        view = memoryview(seed)
        for o, n in cut(view, size):
            out.setdefault(hashlib.sha256(view[o : o + n]).hexdigest(), (o, n))
    else:
        for o, n, digest in cut_file(seed, size):
            out.setdefault(digest, (o, n))
    return out


def read_seed(seed: Seed, offset: int, length: int) -> bytes:
    """`length` bytes of `seed` from `offset`."""
    if isinstance(seed, bytes | bytearray | memoryview):
        return bytes(memoryview(seed)[offset : offset + length])
    with Path(seed).open("rb") as f:
        f.seek(offset)
        return f.read(length)


class Piece(NamedTuple):
    """A chunk of the file put together: where it goes, its size and SHA-256, and `source`, (n, offset) for the
    n-th seed's bytes at that offset, or None when it is read from the file's source."""

    offset: int
    length: int
    sha256: str
    source: tuple[int, int] | None


def plan(index: Index, seeds: Sequence[Seed]) -> list[Piece]:
    """What a client takes from where (SPEC.md § 22.3): a Piece for each chunk of the index, from the first seed
    that holds a chunk of the same size and SHA-256, else to read."""
    found = [seed_chunks(s, index.chunker_size) for s in seeds]
    out: list[Piece] = []
    offset = 0
    for length, digest in index.chunks:
        source = next(((n, f[digest][0]) for n, f in enumerate(found) if digest in f and f[digest][1] == length), None)
        out.append(Piece(offset, length, digest, source))
        offset += length
    return out


def ranges_of(pieces: Sequence[Piece], gap: int = 0) -> list[tuple[int, int]]:
    """The ranges to ask for, (start, end) inclusive, of the pieces to read, joined when at most `gap` bytes apart
    (a piece in between, which a seed holds, is then read too)."""
    out: list[tuple[int, int]] = []
    for p in pieces:
        if p.source is not None:
            continue
        if out and p.offset - out[-1][1] - 1 <= gap:
            out[-1] = (out[-1][0], p.offset + p.length - 1)
        else:
            out.append((p.offset, p.offset + p.length - 1))
    return out


def segments(pieces: Sequence[Piece], gap: int = 0) -> list[tuple[bool, list[Piece]]]:
    """The pieces in order, grouped: (True, the pieces one range holds) or (False, pieces from seeds), for the
    ranges ranges_of() gives with `gap`."""
    spans = ranges_of(pieces, gap)
    out: list[tuple[bool, list[Piece]]] = []
    at = 0
    for p in pieces:
        while at < len(spans) and spans[at][1] < p.offset:
            at += 1
        read = at < len(spans) and spans[at][0] <= p.offset and p.offset + p.length - 1 <= spans[at][1]
        if out and out[-1][0] == read and (not read or out[-1][1][-1].offset + out[-1][1][-1].length == p.offset):
            out[-1][1].append(p)
        else:
            out.append((read, [p]))
    return out


class Collector:
    """The chunks of one range, checked as its bytes arrive (SPEC.md § 22.3): feed() takes what a source sent
    and gives the chunks it completed, each checked by its SHA-256 (L-22.3-2); a source that sends more than the
    range (L-22.3-3), or bytes that are not the chunk, raises Refused. finish() raises Refused unless every
    chunk came."""

    def __init__(self, pieces: Sequence[Piece]) -> None:
        self.pieces = list(pieces)
        self.at = 0
        self.buffer = bytearray()
        self.expected = sum(p.length for p in self.pieces)
        self.received = 0

    def feed(self, data: bytes) -> list[tuple[Piece, bytes]]:
        self.received += len(data)
        if self.received > self.expected:
            raise Refused(f"a source sent more than the {self.expected} bytes asked for")
        self.buffer += data
        out: list[tuple[Piece, bytes]] = []
        while self.at < len(self.pieces) and len(self.buffer) >= self.pieces[self.at].length:
            piece = self.pieces[self.at]
            body = bytes(self.buffer[: piece.length])
            del self.buffer[: piece.length]
            if hashlib.sha256(body).hexdigest() != piece.sha256:
                raise Refused(f"the chunk at {piece.offset} does not match its SHA-256")
            self.at += 1
            out.append((piece, body))
        return out

    def finish(self) -> None:
        if self.at != len(self.pieces):
            raise Refused(f"the range gave {self.received} of the {self.expected} bytes asked for")


def assemble(
    index: Index,
    seeds: Sequence[Seed],
    read_range: Callable[[int, int], bytes],
    sha256: str,
    size: int,
    *,
    gap: int = 0,
) -> bytes:
    """The file an index describes (SPEC.md § 22.3), in memory: each chunk from a seed or from
    `read_range(start, end)` (the file's bytes from start to end, inclusive), checked by its SHA-256 as it comes,
    then the whole file by `sha256` and `size`, before anything of it is used. Raises Refused when a range, a
    chunk or the file does not match, after which a client reads the whole file (L-22.3-4)."""
    out = bytearray()
    for read, group in segments(plan(index, seeds), gap):
        if read:
            start, end = group[0].offset, group[-1].offset + group[-1].length - 1
            data = read_range(start, end)
            if len(data) != end - start + 1:
                raise Refused(f"the range {start}-{end} gave {len(data)} bytes")
            collector = Collector(group)
            for _, body in collector.feed(data):
                out += body
            collector.finish()
        else:
            for p in group:
                assert p.source is not None
                body = read_seed(seeds[p.source[0]], p.source[1], p.length)
                if hashlib.sha256(body).hexdigest() != p.sha256:
                    raise Refused(f"the seed's chunk for {p.offset} does not match its SHA-256")
                out += body
        if len(out) > size:
            raise Refused("more bytes than the file's size")
    if len(out) != size or hashlib.sha256(out).hexdigest() != sha256:
        raise Refused("the file put together does not match its sha256: read it whole")
    return bytes(out)


__all__ = [
    "ALG",
    "CHUNKS_LIMIT",
    "GEAR",
    "INDEX_LIMIT",
    "SIZES",
    "Collector",
    "Index",
    "Piece",
    "Refused",
    "Seed",
    "UnusableIndex",
    "assemble",
    "bounds",
    "build_index",
    "cut",
    "cut_file",
    "plan",
    "ranges_of",
    "read_index",
    "read_seed",
    "ref",
    "seed_chunks",
    "segments",
    "size_for",
]
