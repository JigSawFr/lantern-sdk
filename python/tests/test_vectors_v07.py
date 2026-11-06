"""The specification's test vectors of draft 0.7 (spec/vectors), byte for
byte: canonical JSON (§ 2.3) and chunks (§ 22). The static layout's chunk
route is in test_vectors_v05.py with the others, and sync's merge rule, with
the numbers of §.2.3, there too."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import SPEC
from lantern import canonical as canon
from lantern import chunks
from lantern._generated.models import ChunksRef


def vectors(name: str) -> Any:
    return json.loads((SPEC / "vectors" / f"{name}.json").read_text(encoding="utf-8"))


CANONICAL = vectors("canonical-json")
CHUNKS = vectors("chunks")


# Canonical JSON (SPEC.md § 2.3, RFC 8785).


@pytest.mark.parametrize("case", CANONICAL["cases"], ids=lambda c: c["name"])
def test_canonical_json(case: dict[str, Any]) -> None:
    """§ 2.3: members by UTF-16 code units, numbers as ECMAScript writes them, only what JSON must escape."""
    value = json.loads(case["json"])  # 1.0 stays a float: Python's reader keeps it a number of its own
    raw = canon.canonical(value)
    assert raw.decode("utf-8") == case["canonical"]
    assert hashlib.sha256(raw).hexdigest() == case["sha256"]


def test_numbers() -> None:
    for text, want in (
        ("1.0", "1"),
        ("-0.0", "0"),
        ("0.5", "0.5"),
        ("1e21", "1e+21"),
        ("1e20", "100000000000000000000"),
        ("1e-7", "1e-7"),
        ("0.000001", "0.000001"),
        ("5e-324", "5e-324"),
        ("1.7976931348623157e308", "1.7976931348623157e+308"),
        ("123456789012345680000", "123456789012345680000"),
        ("9007199254740993", "9007199254740992"),  # past 2^53: a double's nearest
    ):
        assert canon.number(json.loads(text)) == want, text


def test_numbers_i_json_refuses() -> None:
    for bad in (float("nan"), float("inf"), float("-inf"), 10**400):
        with pytest.raises(ValueError, match=r"JSON|double"):
            canon.number(bad)
    with pytest.raises(TypeError):
        canon.number(True)


def test_deep_nesting_does_not_recurse() -> None:
    """A value nested 100,000 deep is written without a stack overflow (no recursion)."""
    value: Any = []
    for _ in range(100_000):
        value = [value]
    assert canon.canonical(value) == b"[" * 100_001 + b"]" * 100_001


def test_not_json() -> None:
    with pytest.raises(TypeError):
        canon.canonical({"a": object()})  # type: ignore[dict-item]


# Chunks (SPEC.md § 22).


def stream(seed: str, size: int) -> bytes:
    """The bytes of a vector's file: SHA-256(seed || i, 8 bytes big-endian) for i = 0, 1, ..., cut to `size`."""
    out = bytearray()
    i = 0
    while len(out) < size:
        out += hashlib.sha256(seed.encode() + i.to_bytes(8, "big")).digest()
        i += 1
    return bytes(out[:size])


BASE = stream("lantern-cdc-1 vector", 1_000_000)
EDITED = BASE[:300_000] + stream("an insertion", 777) + BASE[300_000:700_000] + BASE[710_000:]


def file_of(case: dict[str, Any]) -> bytes:
    spec = case["file"]
    if "zeros" in spec:
        return bytes(spec["zeros"])
    if "edit" in spec:
        return EDITED
    return stream(spec["seed"], spec["size"]) if spec["seed"] else b""


def test_the_gear_table() -> None:
    g = CHUNKS["gear"]
    assert [f"{x:016x}" for x in chunks.GEAR[:4]] == g["first"]
    assert f"{chunks.GEAR[255]:016x}" == g["last"]
    assert hashlib.sha256(b"".join(x.to_bytes(8, "big") for x in chunks.GEAR)).hexdigest() == g["sha256"]


@pytest.mark.parametrize("case", CHUNKS["cases"], ids=lambda c: c["name"])
def test_files_are_cut_and_indexed(case: dict[str, Any], tmp_path: Path) -> None:
    """[L-22.1-1] The same cuts, chunks and index bytes: a file has the same index wherever it is cut."""
    data = file_of(case)
    assert hashlib.sha256(data).hexdigest() == case["file_sha256"] and len(data) == case["file_size"]
    size = case["chunker"]["size"]
    cuts = chunks.cut(data, size)
    assert [o for o, _ in cuts] == case["cuts"]
    assert [[n, hashlib.sha256(data[o : o + n]).hexdigest()] for o, n in cuts] == case["chunks"]
    doc, raw = chunks.build_index(data, size)
    assert raw.decode() == case["index"] and len(raw) == case["index_size"]
    assert hashlib.sha256(raw).hexdigest() == case["index_sha256"]
    assert doc["chunks"] == case["chunks"]
    # A file on disk is cut by the same rule, a chunk at a time.
    path = tmp_path / "file"
    path.write_bytes(data)
    assert [(o, n, h) for o, n, h in chunks.cut_file(path, size)] == [
        (o, n, c[1]) for (o, n), c in zip(cuts, case["chunks"], strict=True)
    ]
    # The index it wrote is one a client reads back.
    ref = ChunksRef.from_json(chunks.ref("v1/chunks/sha256/x.json", raw))
    index = chunks.read_index(raw, sha256=case["file_sha256"], size=case["file_size"], ref=ref)
    assert [list(c) for c in index.chunks] == case["chunks"] and index.chunker_size == size


def test_the_chunker_size_a_server_chooses() -> None:
    assert chunks.size_for(0) == chunks.size_for(1) == 65536
    assert chunks.size_for(65536 * 16384) == 65536
    assert chunks.size_for(65536 * 16384 + 1) == 131072
    # Too large for any chunker: 100,000 chunks of at least 1 MiB + 1 is the most.
    assert chunks.size_for(1 << 50) is None
    for length in (1, 1000, 1 << 20, 100 << 20, 10 << 30, 60 << 30):
        size = chunks.size_for(length)
        assert size is not None
        assert length // ((size >> 2) + 1) + 1 <= chunks.CHUNKS_LIMIT  # whatever the bytes, within the limit


def test_a_bounds_size_is_one_of_the_chunkers() -> None:
    assert chunks.bounds(65536) == (16384, 262144, 0xFFFF << 48)
    for bad in (0, 65535, 32768, 8388608):
        with pytest.raises(ValueError, match="power of two"):
            chunks.bounds(bad)


def test_a_newer_version_from_an_older_one() -> None:
    """[L-22.3-2] The chunks found in the older bytes, the ranges of the newer file to read, and the file put
    together, checked chunk by chunk and whole."""
    update = CHUNKS["update"]
    case = CHUNKS["cases"][4]
    _, raw = chunks.build_index(EDITED, case["chunker"]["size"])
    assert hashlib.sha256(raw).hexdigest() == update["index_sha256"]
    index = chunks.read_index(raw, sha256=case["file_sha256"], size=case["file_size"])
    plan = chunks.plan(index, [BASE])
    assert [
        {
            "offset": p.offset,
            "size": p.length,
            "sha256": p.sha256,
            "from": f"seed at {p.source[1]}" if p.source else "read",
        }
        for p in plan
    ] == update["plan"]
    ranges = chunks.ranges_of(plan)
    assert [f"bytes={a}-{b}" for a, b in ranges] == update["ranges"]
    assert sum(p.length for p in plan if p.source is None) == update["read"]
    asked: list[tuple[int, int]] = []

    def read_range(start: int, end: int) -> bytes:
        asked.append((start, end))
        return EDITED[start : end + 1]

    assert chunks.assemble(index, [BASE], read_range, case["file_sha256"], case["file_size"]) == EDITED
    assert asked == ranges


@pytest.mark.parametrize("case", CHUNKS["refused"], ids=lambda c: c["name"])
def test_indexes_a_client_refuses(case: dict[str, Any]) -> None:
    """[L-22.3-1] An index that fails a check is unusable: the file is read whole."""
    assert case["usable"] is False
    with pytest.raises(chunks.UnusableIndex):
        chunks.read_index(
            case["index"].encode(),
            sha256=case["file_sha256"],
            size=case["file_size"],
            ref=ChunksRef.from_json(case["chunks"]),
        )
