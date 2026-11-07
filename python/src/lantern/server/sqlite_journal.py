"""A change journal kept in a SQLite file (SPEC.md § 6.4, § 7.3): what `MemoryJournal` is, surviving a restart.

A library that is a database of its own records each change here and answers `/v1/changes` from `since`: the
positions keep growing across restarts, and the `epoch` stays the same for the life of the file, so a client's
`since` token stays good. Only the last `keep` changes are kept; `floor` is the position below which they are gone.
"""

from __future__ import annotations

import os
import secrets

from lantern.server._sqlite import SqliteFile, StoreSchemaError

__all__ = ["SCHEMA", "JournalSchemaError", "SqliteJournal"]

#: The schema this version writes (SQLite's `user_version`).
SCHEMA = 1

JournalSchemaError = StoreSchemaError

_TABLES = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE events (
    position INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    platform TEXT NOT NULL
)
"""


class SqliteJournal:
    """The same journal as `MemoryJournal` (`epoch`, `seq`, `floor`, `record`, `since`), in a SQLite file."""

    def __init__(self, path: str | os.PathLike[str], keep: int = 10000) -> None:
        if keep < 1:
            raise ValueError("keep is 1 or more")
        self.keep = keep
        self._file = SqliteFile(path, what="journal", schema=SCHEMA, tables=_TABLES, sentinel="meta")
        with self._file.transaction() as db:
            db.execute("INSERT OR IGNORE INTO meta VALUES ('epoch', ?)", (secrets.token_hex(4),))
            db.execute("INSERT OR IGNORE INTO meta VALUES ('seq', '0')")
            db.execute("INSERT OR IGNORE INTO meta VALUES ('floor', '0')")
            self.epoch = str(db.execute("SELECT value FROM meta WHERE key = 'epoch'").fetchone()[0])

    def _meta(self, key: str) -> int:
        with self._file.lock:
            return int(self._file.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()[0])

    @property
    def seq(self) -> int:
        """The position of the last change."""
        return self._meta("seq")

    @property
    def floor(self) -> int:
        """The position below which the changes are gone."""
        return self._meta("floor")

    def record(self, kind: str, key: str, platform: str) -> None:
        with self._file.transaction() as db:
            seq = int(db.execute("SELECT value FROM meta WHERE key = 'seq'").fetchone()[0]) + 1
            db.execute("INSERT INTO events VALUES (?, ?, ?, ?)", (seq, kind, key, platform))
            db.execute("UPDATE meta SET value = ? WHERE key = 'seq'", (str(seq),))
            if seq > self.keep:
                cut = seq - self.keep
                db.execute("DELETE FROM events WHERE position <= ?", (cut,))
                db.execute("UPDATE meta SET value = ? WHERE key = 'floor'", (str(cut),))

    def since(self, after: int, kinds: tuple[str, ...], platform: str | None) -> list[tuple[str, str]]:
        marks = ",".join("?" * len(kinds))
        sql = f"SELECT kind, key FROM events WHERE position > ? AND kind IN ({marks})"  # noqa: S608
        args: list[object] = [after, *kinds]
        if platform is not None:
            sql += " AND platform = ?"
            args.append(platform)
        with self._file.lock:
            return [(str(k), str(key)) for k, key in self._file.db.execute(sql + " ORDER BY position", args)]

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> SqliteJournal:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
