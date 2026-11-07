"""The SQLite file the server's stores share the handling of: private on creation, versioned by `user_version`,
one transaction at a time under a lock. Internal to `lantern.server`."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path


class StoreSchemaError(Exception):
    """The file was written by a newer version (its `schema` is above this one's): it is left as it is."""


class SqliteFile:
    """One SQLite file of a store. `path` is the file (created readable by its owner alone) or ``":memory:"``."""

    def __init__(self, path: str | os.PathLike[str], *, what: str, schema: int, tables: str, sentinel: str) -> None:
        name = os.fspath(path)
        if name != ":memory:" and not Path(name).exists():
            os.close(os.open(name, os.O_WRONLY | os.O_CREAT, 0o600))
        self.lock = threading.RLock()
        self.db = sqlite3.connect(name, check_same_thread=False, isolation_level=None)
        try:
            version = int(self.db.execute("PRAGMA user_version").fetchone()[0])
            if version > schema:
                raise StoreSchemaError(
                    f"This {what} file is of schema {version}, newer than the {schema} this version knows: "
                    "it is left as it is."
                )
            self.db.execute("PRAGMA busy_timeout = 5000")
            self.db.execute("PRAGMA journal_mode = WAL")
            if version == 0:
                with self.transaction():
                    if self.db.execute("SELECT 1 FROM sqlite_master WHERE name = ?", (sentinel,)).fetchone() is None:
                        for statement in tables.split(";"):
                            if statement.strip():
                                self.db.execute(statement)
                    self.db.execute(f"PRAGMA user_version = {schema}")
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        with self.lock:
            self.db.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Everything it does, or nothing: a write transaction taken at once, under the lock."""
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            else:
                self.db.execute("COMMIT")
