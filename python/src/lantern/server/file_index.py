"""An index of the files a server serves in place, with their SHA-256 (SPEC.md § 6.1, `sha256` of an app).

A library that serves the files of a disk must know each file's SHA-256 before it can list it, and reading a
whole volume to find out takes hours: the hash is computed once, in the background, and kept with the validators
it was computed under (the size and the modification time); a file whose validators change is hashed again, and a
hash is recorded only if they are still those when the read ends. A file is not listed until it is hashed.

    store = SqliteIndex("/config/lantern-files.db")          # or your own IndexStore (a database table)
    store.sync("games", scan(Path("/games"), priority=package_priority))
    hash_pending(store, {"games": Path("/games")})            # in a worker, until it returns 0
    for row in store.hashed("games"): ...                      # what can be listed

`IndexStore` is what the functions here need; `SqliteIndex` is one, in a SQLite file. A server that already has a
table of files implements the protocol on it.
"""

from __future__ import annotations

import hashlib
import os
import random
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from lantern.server._sqlite import SqliteFile, StoreSchemaError

__all__ = [
    "SCHEMA",
    "Entry",
    "IndexSchemaError",
    "IndexStore",
    "Row",
    "SqliteIndex",
    "SyncResult",
    "hash_pending",
    "scan",
    "sha256_file",
    "verify_sample",
]

#: The schema of `SqliteIndex` (SQLite's `user_version`).
SCHEMA = 1

IndexSchemaError = StoreSchemaError

_READ = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Entry:
    """A file seen on disk: its path inside the source and its validators. `priority` orders the queue: the lowest
    first (a base game, then its updates, then its DLC, for example)."""

    path: str
    size: int
    mtime_ns: int
    priority: int = 0


@dataclass(frozen=True, slots=True)
class Row:
    source: str
    path: str
    size: int
    mtime_ns: int
    sha256: str | None


@dataclass(frozen=True, slots=True)
class SyncResult:
    added: int
    changed: int
    removed: int


class IndexStore(Protocol):
    """Where the hashes are kept. Every method may be called from several threads."""

    def sync(self, source: str, entries: Iterable[Entry]) -> SyncResult:
        """Makes the source's rows match what is on disk: a new file is pending, a file whose size or time changed
        loses its hash and is pending again, a file that is gone disappears."""
        ...

    def pending(self, limit: int = 100, sources: Collection[str] | None = None) -> list[Row]:
        """Files to hash: the lowest priority number first, then the smallest; of `sources` when given."""
        ...

    def set_hash(self, row: Row, sha256: str) -> bool:
        """Records a hash only if the validators are still those of `row`; whether it was."""
        ...

    def hashed(self, source: str | None = None) -> list[Row]:
        """The files that can be listed: those with a hash."""
        ...

    def rows(self, source: str | None = None) -> list[Row]:
        """Every file known, hashed or waiting."""
        ...

    def counts(self) -> dict[str, int]:
        """{"hashed": n, "pending": n}."""
        ...

    def pending_bytes(self) -> int:
        """The size of the files still to hash."""
        ...

    def rehash_files(self, files: Collection[tuple[str, str]]) -> int:
        """Forgets the hash of these (source, path) and queues them before everything else; how many."""
        ...


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(_READ):
            digest.update(chunk)
    return digest.hexdigest()


def scan(root: str | os.PathLike[str], priority: Callable[[str], int | None] | None = None) -> Iterator[Entry]:
    """The regular files under `root`, with paths relative and written with `/`. Symbolic links are not followed:
    a link could point out of the volume. `priority` gives a file its queue priority from its relative path, or
    None to leave the file out (a file nothing would list is not worth hashing)."""
    base = Path(root)
    for directory, subdirectories, names in os.walk(base, followlinks=False):
        subdirectories[:] = sorted(d for d in subdirectories if not (Path(directory) / d).is_symlink())
        for name in sorted(names):
            file = Path(directory) / name
            if file.is_symlink():
                continue
            relative = file.relative_to(base).as_posix()
            rank = 0 if priority is None else priority(relative)
            if rank is None:
                continue
            try:
                info = file.stat()
            except OSError:
                continue
            yield Entry(relative, info.st_size, info.st_mtime_ns, rank)


def hash_pending(
    store: IndexStore,
    roots: Mapping[str, Path],
    *,
    limit: int = 100,
    on_hashed: Callable[[str, str], object] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> int:
    """Hashes up to `limit` pending files, read in place under `roots` (by source); how many were recorded.

    A file that changed or vanished while it was read stays pending, or is removed by the next `sync`: the hash
    is kept only if the validators still match. `should_stop` is asked between files, to end early."""
    done = 0
    for row in store.pending(limit, tuple(roots)):
        if should_stop is not None and should_stop():
            break
        file = roots[row.source] / row.path
        try:
            before = file.stat()
            if (before.st_size, before.st_mtime_ns) != (row.size, row.mtime_ns):
                continue
            digest = sha256_file(file)
            after = file.stat()
        except OSError:
            continue
        if (after.st_size, after.st_mtime_ns) != (row.size, row.mtime_ns):
            continue
        if store.set_hash(row, digest):
            done += 1
            if on_hashed is not None:
                on_hashed(row.source, row.path)
    return done


def verify_sample(
    store: IndexStore, roots: Mapping[str, Path], count: int = 5, *, rng: random.Random | None = None
) -> list[tuple[str, str]]:
    """Reads again `count` files at random among the hashed ones and checks their hash: a file whose content
    changed under the same size and time (a restored backup, a tool that keeps them) is queued to be hashed
    again, and returned as (source, path). A cheap guard, not a full scan."""
    rows = [r for r in store.hashed() if r.source in roots]
    chosen = (rng or random).sample(rows, min(count, len(rows)))
    bad = []
    for row in chosen:
        try:
            same = sha256_file(roots[row.source] / row.path) == row.sha256
        except OSError:
            continue  # gone: the next sync removes it
        if not same:
            bad.append((row.source, row.path))
    if bad:
        store.rehash_files(bad)
    return bad


_TABLES = """
CREATE TABLE files (
    source TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source, path)
);
CREATE INDEX files_pending ON files (priority, size) WHERE sha256 IS NULL
"""

_ROW = "source, path, size, mtime_ns, sha256"


class SqliteIndex:
    """`IndexStore` in a SQLite file; safe from several threads of one process."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        name = os.fspath(path)
        if name != ":memory:":
            Path(name).parent.mkdir(parents=True, exist_ok=True)
        self._file = SqliteFile(path, what="file index", schema=SCHEMA, tables=_TABLES, sentinel="files")

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> SqliteIndex:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def sync(self, source: str, entries: Iterable[Entry]) -> SyncResult:
        seen = {entry.path: entry for entry in entries}
        added = changed = 0
        with self._file.transaction() as db:
            known = {
                path: (size, mtime)
                for path, size, mtime in db.execute(
                    "SELECT path, size, mtime_ns FROM files WHERE source = ?", (source,)
                )
            }
            for path, entry in seen.items():
                if path not in known:
                    db.execute(
                        "INSERT INTO files (source, path, size, mtime_ns, priority) VALUES (?, ?, ?, ?, ?)",
                        (source, path, entry.size, entry.mtime_ns, entry.priority),
                    )
                    added += 1
                elif known[path] != (entry.size, entry.mtime_ns):
                    db.execute(
                        "UPDATE files SET size = ?, mtime_ns = ?, sha256 = NULL, priority = ? "
                        "WHERE source = ? AND path = ?",
                        (entry.size, entry.mtime_ns, entry.priority, source, path),
                    )
                    changed += 1
            gone = [(source, path) for path in known if path not in seen]
            db.executemany("DELETE FROM files WHERE source = ? AND path = ?", gone)
        return SyncResult(added=added, changed=changed, removed=len(gone))

    def pending(self, limit: int = 100, sources: Collection[str] | None = None) -> list[Row]:
        query = f"SELECT {_ROW} FROM files WHERE sha256 IS NULL"  # noqa: S608
        args: tuple[str | int, ...] = ()
        if sources is not None:
            query += " AND source IN (" + ",".join("?" * len(sources)) + ")"  # marks only, never a value
            args = tuple(sources)
        with self._file.lock:
            rows = self._file.db.execute(query + " ORDER BY priority, size, source, path LIMIT ?", (*args, limit))
            return [Row(*r) for r in rows.fetchall()]

    def set_hash(self, row: Row, sha256: str) -> bool:
        with self._file.transaction() as db:
            cursor = db.execute(
                "UPDATE files SET sha256 = ? WHERE source = ? AND path = ? AND size = ? AND mtime_ns = ?",
                (sha256, row.source, row.path, row.size, row.mtime_ns),
            )
            return cursor.rowcount == 1

    def _listing(self, where: str, source: str | None) -> list[Row]:
        query = f"SELECT {_ROW} FROM files {where}"  # noqa: S608
        args: tuple[str, ...] = ()
        if source is not None:
            query += (" AND" if where else " WHERE") + " source = ?"
            args = (source,)
        with self._file.lock:
            return [Row(*r) for r in self._file.db.execute(query + " ORDER BY source, path", args)]

    def hashed(self, source: str | None = None) -> list[Row]:
        return self._listing("WHERE sha256 IS NOT NULL", source)

    def rows(self, source: str | None = None) -> list[Row]:
        return self._listing("", source)

    def counts(self) -> dict[str, int]:
        with self._file.lock:
            done, todo = self._file.db.execute("SELECT COUNT(sha256), COUNT(*) - COUNT(sha256) FROM files").fetchone()
        return {"hashed": int(done), "pending": int(todo)}

    def counts_by_source(self) -> dict[str, dict[str, int]]:
        with self._file.lock:
            rows = self._file.db.execute(
                "SELECT source, COUNT(sha256), COUNT(*) - COUNT(sha256) FROM files GROUP BY source ORDER BY source"
            ).fetchall()
        return {source: {"hashed": int(done), "pending": int(todo)} for source, done, todo in rows}

    def pending_bytes(self) -> int:
        with self._file.lock:
            (total,) = self._file.db.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE sha256 IS NULL").fetchone()
        return int(total)

    def rehash_files(self, files: Collection[tuple[str, str]]) -> int:
        done = 0
        with self._file.transaction() as db:
            for source, path in files:
                done += db.execute(
                    "UPDATE files SET sha256 = NULL, priority = -1 WHERE source = ? AND path = ?", (source, path)
                ).rowcount
        return done

    def rehash(self, source: str | None = None) -> int:
        """Forgets the hashes of a source (or of all), so they are computed again; how many."""
        query = "UPDATE files SET sha256 = NULL WHERE sha256 IS NOT NULL"
        args: tuple[str, ...] = ()
        if source is not None:
            query += " AND source = ?"
            args = (source,)
        with self._file.transaction() as db:
            return db.execute(query, args).rowcount
