"""lantern.server.file_index: hashes kept under their validators, a queue in order, a sample verified."""

from __future__ import annotations

import hashlib
import os
import random
import sqlite3
import sys
from pathlib import Path

import pytest

from lantern.server.file_index import (
    NAMED,
    Entry,
    IndexSchemaError,
    SqliteIndex,
    hash_pending,
    scan,
    sha256_file,
    verify_sample,
)


def write(path: Path, data: bytes, mtime: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if mtime is not None:
        os.utime(path, ns=(mtime, mtime))
    return path


def test_scan_lists_regular_files_in_order(tmp_path: Path) -> None:
    write(tmp_path / "b.nsp", b"bb")
    write(tmp_path / "sub" / "a.nsp", b"a")
    write(tmp_path / "skip.txt", b"x")
    entries = list(scan(tmp_path, lambda p: None if p.endswith(".txt") else (1 if "sub" in p else 0)))
    assert [(e.path, e.size, e.priority) for e in entries] == [("b.nsp", 2, 0), ("sub/a.nsp", 1, 1)]


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links")
def test_scan_does_not_follow_links(tmp_path: Path) -> None:
    outside = tmp_path / "out"
    write(outside / "secret.nsp", b"s")
    root = tmp_path / "root"
    write(root / "a.nsp", b"a")
    (root / "link.nsp").symlink_to(outside / "secret.nsp")
    (root / "dir").symlink_to(outside, target_is_directory=True)
    assert [e.path for e in scan(root)] == ["a.nsp"]


def test_sync_adds_changes_and_removes() -> None:
    with SqliteIndex(":memory:") as index:
        assert index.sync("s", [Entry("a", 1, 10), Entry("b", 2, 10)]).added == 2
        [first] = index.pending(1)
        index.set_hash(first, "h")
        result = index.sync("s", [Entry("a", 1, 10), Entry("b", 3, 11), Entry("c", 1, 1)])
        assert (result.added, result.changed, result.removed) == (1, 1, 0)
        result = index.sync("s", [Entry("c", 1, 1)])
        assert result.removed == 2 and [r.path for r in index.rows()] == ["c"]


def test_a_sync_names_the_files_it_found() -> None:
    with SqliteIndex(":memory:") as index:
        index.sync("s", [Entry("a", 1, 10), Entry("b", 2, 10)])
        result = index.sync("s", [Entry("a", 1, 11), Entry("c", 1, 1)])
        assert (result.added_paths, result.changed_paths, result.removed_paths) == (("c",), ("a",), ("b",))
        many = index.sync("t", [Entry(f"f{n}", 1, 1) for n in range(40)])
        assert many.added == 40 and len(many.added_paths) == NAMED


def test_the_queue_is_priority_then_smallest() -> None:
    with SqliteIndex(":memory:") as index:
        index.sync(
            "s", [Entry("dlc", 1, 1, 2), Entry("big-base", 9, 1, 0), Entry("small-base", 2, 1, 0), Entry("up", 5, 1, 1)]
        )
        assert [r.path for r in index.pending()] == ["small-base", "big-base", "up", "dlc"]
        assert [r.path for r in index.pending(2)] == ["small-base", "big-base"]
        assert index.pending(10, ["other"]) == []


def test_a_hash_is_recorded_only_under_its_validators() -> None:
    with SqliteIndex(":memory:") as index:
        index.sync("s", [Entry("a", 1, 10)])
        [row] = index.pending()
        index.sync("s", [Entry("a", 1, 11)])  # changed meanwhile
        assert index.set_hash(row, "h") is False
        assert index.hashed() == [] and index.counts() == {"hashed": 0, "pending": 1}


def test_hashing_in_place(tmp_path: Path) -> None:
    root = tmp_path / "games"
    write(root / "a.nsp", b"alpha")
    write(root / "b.nsp", b"beta")
    done: list[tuple[str, str]] = []
    with SqliteIndex(tmp_path / "idx" / "files.db") as index:
        index.sync("s", scan(root))
        assert index.pending_bytes() == 9
        assert hash_pending(index, {"s": root}, on_hashed=lambda s, p: done.append((s, p))) == 2
        assert {r.path: r.sha256 for r in index.hashed("s")} == {
            "a.nsp": hashlib.sha256(b"alpha").hexdigest(),
            "b.nsp": hashlib.sha256(b"beta").hexdigest(),
        }
        assert sorted(done) == [("s", "a.nsp"), ("s", "b.nsp")]
        assert index.counts_by_source() == {"s": {"hashed": 2, "pending": 0}}
        assert hash_pending(index, {"s": root}) == 0


def test_a_file_changed_after_the_scan_is_left_pending(tmp_path: Path) -> None:
    file = write(tmp_path / "a.nsp", b"alpha", 1_000_000_000)
    with SqliteIndex(":memory:") as index:
        index.sync("s", scan(tmp_path))
        write(file, b"alphabet", 2_000_000_000)
        assert hash_pending(index, {"s": tmp_path}) == 0 and index.counts()["pending"] == 1
        index.sync("s", scan(tmp_path))
        assert hash_pending(index, {"s": tmp_path}) == 1


def test_a_missing_file_is_left_pending(tmp_path: Path) -> None:
    with SqliteIndex(":memory:") as index:
        index.sync("s", [Entry("gone.nsp", 1, 1)])
        assert hash_pending(index, {"s": tmp_path}) == 0


def test_hashing_can_be_stopped(tmp_path: Path) -> None:
    write(tmp_path / "a", b"1")
    write(tmp_path / "b", b"2")
    with SqliteIndex(":memory:") as index:
        index.sync("s", scan(tmp_path))
        calls = iter([False, True])
        assert hash_pending(index, {"s": tmp_path}, should_stop=lambda: next(calls)) == 1


def test_a_sample_finds_a_file_changed_under_the_same_validators(tmp_path: Path) -> None:
    file = write(tmp_path / "a.nsp", b"alpha", 1_000_000_000)
    write(tmp_path / "b.nsp", b"beta", 1_000_000_000)
    with SqliteIndex(":memory:") as index:
        index.sync("s", scan(tmp_path))
        hash_pending(index, {"s": tmp_path})
        assert verify_sample(index, {"s": tmp_path}, 5, rng=random.Random(1)) == []
        write(file, b"ALPHA", 1_000_000_000)  # same size, same time
        assert verify_sample(index, {"s": tmp_path}, 5, rng=random.Random(1)) == [("s", "a.nsp")]
        assert [r.path for r in index.pending()] == ["a.nsp"]
        assert hash_pending(index, {"s": tmp_path}) == 1
        assert sha256_file(file) == next(r.sha256 for r in index.hashed() if r.path == "a.nsp")


def test_rehash_all_or_one_source() -> None:
    with SqliteIndex(":memory:") as index:
        index.sync("s", [Entry("a", 1, 1)])
        index.sync("t", [Entry("b", 1, 1)])
        for row in index.pending():
            index.set_hash(row, "h")
        assert index.rehash("s") == 1 and index.counts() == {"hashed": 1, "pending": 1}
        assert index.rehash() == 1


def test_it_survives_a_restart_and_refuses_a_newer_schema(tmp_path: Path) -> None:
    path = tmp_path / "files.db"
    with SqliteIndex(path) as index:
        index.sync("s", [Entry("a", 1, 1)])
    with SqliteIndex(path) as again:
        assert [r.path for r in again.rows()] == ["a"]
    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA user_version = 99")
        db.commit()
        with pytest.raises(IndexSchemaError):
            SqliteIndex(path)
    finally:
        db.close()
