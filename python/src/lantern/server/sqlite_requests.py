"""Requests for games kept in a SQLite file (SPEC.md § 11): what `MemoryRequests` is, surviving a restart."""

from __future__ import annotations

import os

from lantern.server._sqlite import SqliteFile, StoreSchemaError
from lantern.server.title_requests import StoredRequest

__all__ = ["SCHEMA", "RequestsSchemaError", "SqliteRequests"]

#: The schema this version writes (SQLite's `user_version`).
SCHEMA = 1

RequestsSchemaError = StoreSchemaError

_TABLES = """
CREATE TABLE requests (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    platform TEXT NOT NULL,
    title_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created TEXT NOT NULL,
    name TEXT,
    updated TEXT,
    reason TEXT
);
CREATE INDEX requests_by_user ON requests(user)
"""

_COLUMNS = "id, user, platform, title_id, status, created, name, updated, reason"


def _request(row: tuple[object, ...]) -> StoredRequest:
    def text(i: int) -> str | None:
        value = row[i]
        return value if isinstance(value, str) else None

    return StoredRequest(
        id=str(row[0]),
        user=str(row[1]),
        platform=str(row[2]),
        title_id=str(row[3]),
        status=str(row[4]),
        created=str(row[5]),
        name=text(6),
        updated=text(7),
        reason=text(8),
    )


class SqliteRequests:
    """The same requests as `MemoryRequests`, in a SQLite file; safe from several threads of one process."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._file = SqliteFile(path, what="requests", schema=SCHEMA, tables=_TABLES, sentinel="requests")

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> SqliteRequests:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def requests(self, user: str | None = None) -> list[StoredRequest]:
        sql = f"SELECT {_COLUMNS} FROM requests"  # noqa: S608
        with self._file.lock:
            if user is None:
                rows = self._file.db.execute(sql + " ORDER BY rowid").fetchall()
            else:
                rows = self._file.db.execute(sql + " WHERE user = ? ORDER BY rowid", (user,)).fetchall()
        return [_request(r) for r in rows]

    def add(self, request: StoredRequest) -> None:
        with self._file.transaction() as db:
            db.execute(
                f"INSERT INTO requests ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "  # noqa: S608
                "ON CONFLICT(id) DO UPDATE SET user = excluded.user, platform = excluded.platform, "
                "title_id = excluded.title_id, status = excluded.status, created = excluded.created, "
                "name = excluded.name, updated = excluded.updated, reason = excluded.reason",
                (
                    request.id,
                    request.user,
                    request.platform,
                    request.title_id,
                    request.status,
                    request.created,
                    request.name,
                    request.updated,
                    request.reason,
                ),
            )

    def set_status(
        self, request_id: str, status: str, *, reason: str | None = None, updated: str | None = None
    ) -> StoredRequest | None:
        with self._file.transaction() as db:
            if db.execute("SELECT 1 FROM requests WHERE id = ?", (request_id,)).fetchone() is None:
                return None
            db.execute(
                "UPDATE requests SET status = ?, reason = ?, updated = ? WHERE id = ?",
                (status, reason, updated, request_id),
            )
            row = db.execute(f"SELECT {_COLUMNS} FROM requests WHERE id = ?", (request_id,)).fetchone()  # noqa: S608
        return _request(row)

    def remove(self, user: str, request_id: str) -> StoredRequest | None:
        with self._file.transaction() as db:
            row = db.execute(
                f"SELECT {_COLUMNS} FROM requests WHERE id = ? AND user = ?",  # noqa: S608
                (request_id, user),
            ).fetchone()
            if row is None:
                return None
            db.execute("DELETE FROM requests WHERE id = ?", (request_id,))
        return _request(row)

    def forget(self, user: str) -> None:
        with self._file.transaction() as db:
            db.execute("DELETE FROM requests WHERE user = ?", (user,))
