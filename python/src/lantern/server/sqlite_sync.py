"""Sync data kept in a SQLite file (SPEC.md § 20): what `MemorySync` is, surviving a restart.

The same rules as `MemorySync`: items merged one by one by § 20.4's rule, a revision per collection, deletions
kept `retention` (30 days at least, § 20.5), and a `generation` that changes only when the data is erased.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from lantern import sync as syncing
from lantern.server._sqlite import SqliteFile, StoreSchemaError
from lantern.server.http import ProblemError, bad_request
from lantern.server.sync import ITEMS, new_generation

__all__ = ["SCHEMA", "SqliteSync", "SyncSchemaError"]

#: The schema this version writes (SQLite's `user_version`).
SCHEMA = 1

SyncSchemaError = StoreSchemaError

_TABLES = """
CREATE TABLE accounts (user TEXT PRIMARY KEY, generation TEXT NOT NULL);
CREATE TABLE collections (
    user TEXT NOT NULL,
    name TEXT NOT NULL,
    rev INTEGER NOT NULL,
    floor INTEGER NOT NULL,
    PRIMARY KEY (user, name)
);
CREATE TABLE items (
    user TEXT NOT NULL,
    collection TEXT NOT NULL,
    key TEXT NOT NULL,
    updated TEXT NOT NULL,
    value TEXT,
    deleted INTEGER NOT NULL,
    rev INTEGER NOT NULL,
    kept TEXT NOT NULL,
    PRIMARY KEY (user, collection, key)
)
"""

_ITEM = "key, updated, value, deleted, rev, kept"


def _item(row: tuple[object, ...]) -> syncing.Item:
    value = row[2]
    return syncing.Item(
        str(row[0]), str(row[1]), json.loads(value) if isinstance(value, str) else None, bool(row[3]), int(str(row[4]))
    )


class SqliteSync:
    """The same sync data as `MemorySync`, in a SQLite file; safe from several threads of one process."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        limit: int = ITEMS,
        *,
        retention: timedelta = timedelta(days=syncing.TOMBSTONE_DAYS),
    ) -> None:
        if not 1 <= limit <= syncing.ITEMS_LIMIT:
            raise ValueError("limits.sync_items is 1 to 100,000 (SPEC.md § 13)")
        self.limit, self.retention = limit, retention
        self._file = SqliteFile(path, what="sync", schema=SCHEMA, tables=_TABLES, sentinel="accounts")

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> SqliteSync:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @staticmethod
    def _generation(db: sqlite3.Connection, user: str) -> str:
        row = db.execute("SELECT generation FROM accounts WHERE user = ?", (user,)).fetchone()
        if row is not None:
            return str(row[0])
        generation = new_generation()
        db.execute("INSERT INTO accounts VALUES (?, ?)", (user, generation))
        return generation

    def _collection(self, db: sqlite3.Connection, user: str, name: str) -> tuple[int, int]:
        """(rev, floor) of the collection, the deletions past their retention dropped first."""
        db.execute("INSERT OR IGNORE INTO collections VALUES (?, ?, 0, 0)", (user, name))
        cutoff = (datetime.now(UTC) - self.retention).isoformat()
        gone = db.execute(
            "SELECT MAX(rev) FROM items WHERE user = ? AND collection = ? AND deleted = 1 AND kept < ?",
            (user, name, cutoff),
        ).fetchone()[0]
        if gone is not None:
            db.execute(
                "DELETE FROM items WHERE user = ? AND collection = ? AND deleted = 1 AND kept < ?",
                (user, name, cutoff),
            )
            db.execute("UPDATE collections SET floor = MAX(floor, ?) WHERE user = ? AND name = ?", (gone, user, name))
        rev, floor = db.execute(
            "SELECT rev, floor FROM collections WHERE user = ? AND name = ?", (user, name)
        ).fetchone()
        return int(rev), int(floor)

    def overview(self, user: str) -> tuple[str, dict[str, tuple[int, int]]]:
        with self._file.transaction() as db:
            out = {}
            for name in syncing.COLLECTIONS:
                rev, _ = self._collection(db, user, name)
                live = db.execute(
                    "SELECT COUNT(*) FROM items WHERE user = ? AND collection = ? AND deleted = 0", (user, name)
                ).fetchone()[0]
                out[name] = (rev, int(live))
            return self._generation(db, user), out

    def read(self, user: str, collection: str, since: int | None) -> tuple[str, int, list[syncing.Item]]:
        with self._file.transaction() as db:
            generation = self._generation(db, user)
            rev, floor = self._collection(db, user, collection)
            base = f"SELECT {_ITEM} FROM items WHERE user = ? AND collection = ?"  # noqa: S608
            if since is None:
                rows = db.execute(base + " AND deleted = 0 ORDER BY rowid", (user, collection)).fetchall()
            else:
                if since > rev:
                    raise bad_request("This revision was never given: read the collection whole.")
                if since < floor:
                    raise ProblemError(410, "gone", "Its deletions are gone: read the collection whole.")
                rows = db.execute(base + " AND rev > ? ORDER BY rowid", (user, collection, since)).fetchall()
            return generation, rev, [_item(r) for r in rows]

    def merge(
        self,
        user: str,
        collection: str,
        generation: str,
        items: Sequence[syncing.Item],
        *,
        if_match: str | None,
        now: datetime,
        skew: int,
    ) -> tuple[str, int, list[syncing.Item]]:
        with self._file.transaction() as db:
            have_generation = self._generation(db, user)
            rev, _ = self._collection(db, user, collection)
            if generation != have_generation:
                raise ProblemError(
                    409, "conflict", "This sync data was deleted since: ask the user again (SPEC.md § 20.3)."
                )
            if if_match is not None and if_match.strip() != f'"{have_generation}-{rev}"':
                raise ProblemError(
                    412,
                    "precondition_failed",
                    "The collection changed since it was read: read it again.",
                    title="Precondition failed",
                )
            count = int(
                db.execute(
                    "SELECT COUNT(*) FROM items WHERE user = ? AND collection = ?", (user, collection)
                ).fetchone()[0]
            )
            known = {
                str(r[0])
                for r in db.execute("SELECT key FROM items WHERE user = ? AND collection = ?", (user, collection))
            }
            if count + sum(1 for i in items if i.key not in known) > self.limit:
                raise ProblemError(413, "too_large", f"A collection holds {self.limit} items at most here.")
            out = []
            for sent in items:
                row = db.execute(
                    f"SELECT {_ITEM} FROM items WHERE user = ? AND collection = ? AND key = ?",  # noqa: S608
                    (user, collection, sent.key),
                ).fetchone()
                kept, replaced = syncing.merge(_item(row) if row else None, sent, now=now, skew=skew)
                if replaced:
                    rev += 1
                    kept = syncing.Item(kept.key, kept.updated, kept.value, kept.deleted, rev)
                    db.execute(
                        "INSERT INTO items (user, collection, key, updated, value, deleted, rev, kept) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user, collection, key) DO UPDATE SET "
                        "updated = excluded.updated, value = excluded.value, deleted = excluded.deleted, "
                        "rev = excluded.rev, kept = excluded.kept",
                        (
                            user,
                            collection,
                            kept.key,
                            kept.updated,
                            None if kept.value is None else json.dumps(kept.value),
                            int(kept.deleted),
                            rev,
                            now.astimezone(UTC).isoformat(),
                        ),
                    )
                out.append(kept)
            db.execute("UPDATE collections SET rev = ? WHERE user = ? AND name = ?", (rev, user, collection))
            return have_generation, rev, out

    def erase(self, user: str, collection: str | None = None) -> str:
        with self._file.transaction() as db:
            self._generation(db, user)
            if collection is None:
                db.execute("DELETE FROM items WHERE user = ?", (user,))
                db.execute("DELETE FROM collections WHERE user = ?", (user,))
            else:
                db.execute("DELETE FROM items WHERE user = ? AND collection = ?", (user, collection))
                db.execute("DELETE FROM collections WHERE user = ? AND name = ?", (user, collection))
            generation = new_generation()
            db.execute("UPDATE accounts SET generation = ? WHERE user = ?", (generation, user))
            return generation

    def forget(self, user: str) -> None:
        with self._file.transaction() as db:
            for table in ("items", "collections", "accounts"):
                db.execute(f"DELETE FROM {table} WHERE user = ?", (user,))  # noqa: S608
