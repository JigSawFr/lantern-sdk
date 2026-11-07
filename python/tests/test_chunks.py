"""Differential updates, the library's pieces (SPEC.md § 22): the chunker, indexes and what a client checks of
one, the plan and the assembly, with the hostile cases: a bad index, a wrong chunk, a short range, a source that
sends more than it was asked."""

from __future__ import annotations

import hashlib
import itertools
import json
import random
from collections.abc import Callable
from pathlib import Path

import pytest

from lantern import chunks
from lantern._generated.models import ChunksRef
from lantern.canonical import canonical

SIZE = 65536


def bytes_of(seed: int, size: int) -> bytes:
    return random.Random(seed).randbytes(size)


OLD = bytes_of(1, 700_000)
NEW = OLD[:200_000] + bytes_of(2, 3_000) + OLD[200_000:500_000] + bytes_of(3, 1_000) + OLD[501_000:]


def index_of(data: bytes, size: int = SIZE) -> tuple[chunks.Index, bytes, ChunksRef]:
    _, raw = chunks.build_index(data, size)
    ref = ChunksRef.from_json(chunks.ref("v1/chunks/sha256/x.json", raw))
    return chunks.read_index(raw, sha256=hashlib.sha256(data).hexdigest(), size=len(data), ref=ref), raw, ref


def test_cuts_stay_within_the_bounds_and_add_up() -> None:
    cuts = chunks.cut(NEW, SIZE)
    low, high, _ = chunks.bounds(SIZE)
    assert sum(n for _, n in cuts) == len(NEW) and next(o for o, _ in cuts) == 0
    assert all(low <= n <= high for _, n in cuts[:-1]) and 1 <= cuts[-1][1] <= high
    assert all(a + n == b for (a, n), (b, _) in itertools.pairwise(cuts))


def test_a_change_moves_only_the_chunks_near_it() -> None:
    """[L-22.1-1] Chunks end where they ended once past a change: most are shared by the two versions."""
    old = bytes_of(4, 3_000_000)
    new = old[:1_000_000] + bytes_of(5, 3_000) + old[1_000_000:2_000_000] + bytes_of(6, 1_000) + old[2_001_000:]
    before = {c[1] for c in json.loads(chunks.build_index(old, SIZE)[1])["chunks"]}
    after = [c[1] for c in json.loads(chunks.build_index(new, SIZE)[1])["chunks"]]
    assert len(before) > 20
    assert sum(1 for h in after if h in before) >= len(after) - 8


def test_a_chunker_of_another_size_cuts_other_chunks() -> None:
    assert chunks.cut(NEW, SIZE) != chunks.cut(NEW, 4 * SIZE)


def test_the_bytes_cut_are_not_copied() -> None:
    """A view cuts as bytes do (the loop works on memoryview slices)."""
    assert chunks.cut(memoryview(NEW), SIZE) == chunks.cut(NEW, SIZE)
    assert chunks.cut(bytearray(NEW), SIZE) == chunks.cut(NEW, SIZE)


def test_an_empty_file_has_no_chunk() -> None:
    assert chunks.cut(b"", SIZE) == []
    index, raw, _ = index_of(b"")
    assert index.chunks == () and index.size == 0
    assert chunks.assemble(index, [], lambda a, b: b"", hashlib.sha256(b"").hexdigest(), 0) == b""
    assert raw == canonical(json.loads(raw))


def test_a_file_too_large_for_any_chunker_has_no_index(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chunks, "size_for", lambda length: None)
    with pytest.raises(ValueError, match="too large"):
        chunks.build_index(b"abc")


def test_a_file_on_disk_is_cut_a_chunk_at_a_time(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_bytes(NEW)
    assert [(o, n) for o, n, _ in chunks.cut_file(path, SIZE)] == chunks.cut(NEW, SIZE)
    assert dict(chunks.seed_chunks(path, SIZE)) == dict(chunks.seed_chunks(NEW, SIZE))


# What a client checks of an index (L-22.3-1).


def tweak(raw: bytes, **changes: object) -> bytes:
    doc = json.loads(raw)
    doc.update(changes)
    return canonical(doc)


def read(raw: bytes, data: bytes = NEW, ref: ChunksRef | None = None) -> chunks.Index:
    return chunks.read_index(raw, sha256=hashlib.sha256(data).hexdigest(), size=len(data), ref=ref)


def test_the_index_a_server_writes_is_read() -> None:
    index, raw, ref = index_of(NEW)
    assert index == read(raw, ref=ref)
    assert sum(n for n, _ in index.chunks) == len(NEW)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda r: r + b" ", id="bytes of another size than the document gives"),
        pytest.param(lambda r: r[:-1] + b" ", id="bytes of another SHA-256"),
    ],
)
def test_bytes_that_are_not_the_documents(mutate: object) -> None:
    _, raw, ref = index_of(NEW)
    with pytest.raises(chunks.UnusableIndex):
        read(mutate(raw), ref=ref)  # type: ignore[operator]


def test_more_than_the_limit_of_bytes() -> None:
    with pytest.raises(chunks.UnusableIndex, match="above"):
        read(b" " * (chunks.INDEX_LIMIT + 1))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff\xfe",
        b"[1]",
        b"null",
        b'{"schema": "1"}',
        b'{"schema": true}',
        pytest.param(b"[" * 100_000, id="deep-nesting"),
    ],
)
def test_not_a_document(raw: bytes) -> None:
    with pytest.raises(chunks.UnusableIndex):
        read(raw)


def test_a_later_schema_is_absent() -> None:
    _, raw, _ = index_of(NEW)
    with pytest.raises(chunks.UnusableIndex, match="schema 2"):
        read(tweak(raw, schema=2))


@pytest.mark.parametrize(
    "chunker",
    [
        {"alg": "x-other-cdc", "size": SIZE},
        {"alg": chunks.ALG, "size": 65535},
        {"alg": chunks.ALG, "size": 8388608},
        {"alg": chunks.ALG, "size": "65536"},
        {"alg": chunks.ALG},
        "lantern-cdc-1",
        None,
    ],
)
def test_a_chunker_this_library_does_not_know(chunker: object) -> None:
    _, raw, _ = index_of(NEW)
    with pytest.raises(chunks.UnusableIndex, match="chunker"):
        read(tweak(raw, chunker=chunker))


def test_a_chunker_size_written_as_a_float() -> None:
    _, raw, _ = index_of(NEW)
    assert b'"size":65536}' in raw
    with pytest.raises(chunks.UnusableIndex, match="chunker"):
        read(raw.replace(b'"size":65536}', b'"size":65536.0}', 1))


def test_the_index_of_another_file() -> None:
    _, raw, _ = index_of(NEW)
    with pytest.raises(chunks.UnusableIndex, match="another file"):
        read(tweak(raw, sha256="0" * 64))
    with pytest.raises(chunks.UnusableIndex, match="another file"):
        read(tweak(raw, size=len(NEW) + 1))
    with pytest.raises(chunks.UnusableIndex, match="another file"):
        read(raw, data=OLD)


@pytest.mark.parametrize(
    "chunk",
    [
        [0, "a" * 64],
        [-5, "a" * 64],
        [262145, "a" * 64],
        [10, "A" * 64],
        [10, "a" * 63],
        [10, 5],
        ["10", "a" * 64],
        [10.5, "a" * 64],
        [True, "a" * 64],
        [10],
        [10, "a" * 64, 1],
        {"size": 10},
        None,
    ],
)
def test_a_chunk_of_another_form(chunk: object) -> None:
    _, raw, _ = index_of(NEW)
    doc = json.loads(raw)
    doc["chunks"] = [chunk, *doc["chunks"][1:]]
    with pytest.raises(chunks.UnusableIndex, match="chunk"):
        read(canonical(doc))


def test_chunks_that_do_not_add_up_to_the_file() -> None:
    _, raw, _ = index_of(NEW)
    doc = json.loads(raw)
    with pytest.raises(chunks.UnusableIndex, match="add up"):
        read(canonical({**doc, "chunks": doc["chunks"][:-1]}))
    with pytest.raises(chunks.UnusableIndex, match="add up"):
        read(canonical({**doc, "chunks": doc["chunks"] * 2}))


def test_more_than_100000_chunks() -> None:
    _, raw, _ = index_of(NEW)
    doc = json.loads(raw)
    sha = hashlib.sha256(bytes(100_001)).hexdigest()
    with pytest.raises(chunks.UnusableIndex, match="100000"):
        read(
            canonical({**doc, "chunks": [[1, "a" * 64]] * 100_001, "size": 100_001, "sha256": sha}),
            data=bytes(100_001),
        )


# The plan.


def test_the_plan_takes_from_the_seed_what_it_holds() -> None:
    index, _, _ = index_of(NEW)
    plan = chunks.plan(index, [OLD])
    assert sum(p.length for p in plan) == len(NEW)
    shared = [p for p in plan if p.source is not None]
    assert shared and len(shared) < len(plan)
    for p in shared:
        assert p.source is not None
        assert OLD[p.source[1] : p.source[1] + p.length] == NEW[p.offset : p.offset + p.length]
    # The first seed that holds a chunk gives it.
    again = chunks.plan(index, [b"unrelated", OLD, OLD])
    assert all(p.source is None or p.source[0] == 1 for p in again)


def test_a_chunk_of_the_seed_of_another_size_is_not_taken() -> None:
    """A chunk found by its SHA-256 alone but of another length (in the seed, cut otherwise) is read."""
    index, _, _ = index_of(b"x" * 100)
    assert chunks.plan(index, [b"x" * 100])[0].source is not None
    assert chunks.plan(index, [b"x" * 99])[0].source is None


def test_ranges_join_neighbours() -> None:
    index, _, _ = index_of(NEW)
    plan = chunks.plan(index, [OLD])
    tight = chunks.ranges_of(plan)
    wide = chunks.ranges_of(plan, gap=1 << 20)
    assert len(wide) == 1 and len(tight) > 1
    assert wide[0] == (plan[0].offset if plan[0].source is None else tight[0][0], tight[-1][1])
    for (_, a), (b, _) in itertools.pairwise(tight):
        assert b - a - 1 > 0  # apart: a seed's chunk lies between
    # The groups follow the ranges: each range's pieces together, the others from the seeds.
    groups = chunks.segments(plan, 0)
    spans = [(g[0].offset, g[-1].offset + g[-1].length - 1) for read_, g in groups if read_]
    assert spans == tight
    assert [p for _, g in groups for p in g] == plan


# The assembly, and its hostile cases (L-22.3-2, L-22.3-3, L-22.3-4).


def assemble(
    index: chunks.Index, read_range: Callable[[int, int], bytes], seeds: list[chunks.Seed] | None = None
) -> bytes:
    return chunks.assemble(
        index, [OLD] if seeds is None else seeds, read_range, hashlib.sha256(NEW).hexdigest(), len(NEW)
    )


def honest(start: int, end: int) -> bytes:
    return NEW[start : end + 1]


def test_a_file_put_together() -> None:
    index, _, _ = index_of(NEW)
    asked: list[tuple[int, int]] = []

    def read_range(start: int, end: int) -> bytes:
        asked.append((start, end))
        return honest(start, end)

    assert assemble(index, read_range) == NEW
    assert 0 < sum(e - s + 1 for s, e in asked) < len(NEW) // 2  # most of the file came from the seed


def test_a_chunk_that_is_not_the_one_the_index_names_is_refused() -> None:
    """[L-22.3-2] One flipped byte in a range."""
    index, _, _ = index_of(NEW)

    def flipped(start: int, end: int) -> bytes:
        data = bytearray(honest(start, end))
        data[len(data) // 2] ^= 1
        return bytes(data)

    with pytest.raises(chunks.Refused, match="SHA-256"):
        assemble(index, flipped)


def test_a_short_range_is_refused() -> None:
    index, _, _ = index_of(NEW)
    with pytest.raises(chunks.Refused, match="gave"):
        assemble(index, lambda s, e: honest(s, e)[:-1])


def test_a_long_range_is_refused() -> None:
    """[L-22.3-3] A source that sends more than the range asked for."""
    index, _, _ = index_of(NEW)
    with pytest.raises(chunks.Refused, match="gave"):
        assemble(index, lambda s, e: honest(s, e) + b"x")


def test_a_file_that_is_not_the_documents_is_refused() -> None:
    """The chunks all match, the file does not: its document says another SHA-256."""
    index, _, _ = index_of(NEW)
    with pytest.raises(chunks.Refused, match="does not match its sha256"):
        chunks.assemble(index, [OLD], honest, "0" * 64, len(NEW))


def test_the_collector_checks_each_chunk_as_it_comes() -> None:
    index, _, _ = index_of(NEW)
    plan = chunks.plan(index, [])
    group = plan[:3]
    total = sum(p.length for p in group)
    data = NEW[:total]
    collector = chunks.Collector(group)
    got = []
    for i in range(0, total, 5000):
        got += collector.feed(data[i : i + 5000])
    collector.finish()
    assert [p for p, _ in got] == group and b"".join(b for _, b in got) == data
    # More than asked.
    with pytest.raises(chunks.Refused, match="more than"):
        chunks.Collector(group).feed(data + b"x")
    # Less than asked.
    short = chunks.Collector(group)
    short.feed(data[:-1])
    with pytest.raises(chunks.Refused, match="of the"):
        short.finish()
    # Another chunk.
    with pytest.raises(chunks.Refused, match="SHA-256"):
        chunks.Collector(group).feed(b"\0" * total)


def test_a_seed_may_be_a_path(tmp_path: Path) -> None:
    index, _, _ = index_of(NEW)
    path = tmp_path / "old"
    path.write_bytes(OLD)
    assert assemble(index, honest, [path]) == NEW
    assert assemble(index, honest, [str(path)]) == NEW


def test_no_seed_reads_every_range() -> None:
    index, _, _ = index_of(NEW)
    asked: list[tuple[int, int]] = []

    def read_range(start: int, end: int) -> bytes:
        asked.append((start, end))
        return honest(start, end)

    assert assemble(index, read_range, []) == NEW
    assert asked == [(0, len(NEW) - 1)]


def test_a_file_is_hashed_and_indexed_in_one_read(tmp_path: Path) -> None:
    """The same index as build_index() gives, and the SHA-256 of the file, from a file read once."""
    for data in (b"", b"a", NEW, OLD, bytes(range(256)) * 4096):
        path = tmp_path / "f"
        path.write_bytes(data)
        seen: list[int] = []
        found = chunks.index_file(path, SIZE, progress=seen.append)
        assert found.sha256 == hashlib.sha256(data).hexdigest() and found.size == len(data)
        assert found.cdc == chunks.build_index(data, SIZE)
        assert seen == sorted(seen) and (seen[-1] if seen else 0) == len(data)


def test_a_file_can_be_hashed_without_an_index(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_bytes(NEW)
    assert chunks.index_file(path, chunk_index=False) == (hashlib.sha256(NEW).hexdigest(), len(NEW), None)


def test_a_file_too_large_for_any_chunker_is_still_hashed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "f"
    path.write_bytes(NEW)
    monkeypatch.setattr(chunks, "size_for", lambda length: None)
    assert chunks.index_file(path) == (hashlib.sha256(NEW).hexdigest(), len(NEW), None)
