"""Accounts, devices and invitations kept in a SQLite file (SPEC.md § 5.1, § 5.5, § 5.7).

`SqliteAccounts` is the `Accounts` of a server that must remember its pairings: the same behaviour as
`MemoryAccounts`, in one file that survives a restart. It needs nothing but the standard library.

What is kept is what `MemoryAccounts` keeps: a token's hash only (never the token), the device's public key,
the scopes approved, its rating cap and its invitation. An invitation's code is kept as it was shown, since
the administration API shows it again; the file is created readable by its owner alone for that reason.

The file carries its `schema` as SQLite's `user_version`. A file of a newer schema is not opened (`AccountsSchemaError`)
and nothing is written to it; a column or a table this version does not know is left as it is. A file of the
schema before (1) gets the two columns schema 2 adds (an account's rating cap, a device's suspension) when it is
opened.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lantern._generated.models import RatingCap
from lantern.server.accounts import (
    ACCOUNT_NAME,
    INVITATION_SYMBOLS,
    UNSET,
    AccountError,
    Device,
    Invitation,
    User,
    _Unset,
    new_code,
    new_device_id,
    new_token,
    ordered_scopes,
    token_hash,
    typed_code,
    utc,
)

__all__ = ["SCHEMA", "AccountsSchemaError", "SqliteAccounts"]

#: The schema this version writes (SQLite's `user_version`).
SCHEMA = 2

_TABLES = """
CREATE TABLE users (
    name TEXT PRIMARY KEY,
    scopes TEXT NOT NULL,
    state TEXT NOT NULL,
    created TEXT NOT NULL,
    rating_cap TEXT
);
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    device TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created TEXT NOT NULL,
    key BLOB,
    rating_cap TEXT,
    invitation TEXT,
    expires TEXT,
    last_used TEXT,
    suspended INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX devices_by_user ON devices(user);
CREATE TABLE invitations (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    user TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    scopes TEXT NOT NULL,
    expires TEXT NOT NULL,
    devices INTEGER NOT NULL,
    used INTEGER NOT NULL,
    rating_cap TEXT,
    note TEXT,
    created TEXT NOT NULL
);
"""

_USER = "name, scopes, state, created, rating_cap"
_DEVICE = "id, token_hash, user, device, scopes, created, key, rating_cap, invitation, expires, last_used, suspended"
_INVITATION = "id, code, user, scopes, expires, devices, used, rating_cap, note, created"


class AccountsSchemaError(Exception):
    """The file was written by a newer version (its `schema` is above this one's): it is left as it is."""


def _cap_text(cap: RatingCap | None) -> str | None:
    return None if cap is None else json.dumps(cap.to_json())


def _cap(text: str | None) -> RatingCap | None:
    return None if text is None else RatingCap.from_json(json.loads(text))


def _user(row: tuple[object, ...]) -> User:
    return User(
        str(row[0]),
        tuple(json.loads(str(row[1]))),
        str(row[2]),
        str(row[3]),
        _cap(row[4] if isinstance(row[4], str) else None),
    )


def _device(row: tuple[object, ...]) -> Device:
    key = row[6]
    return Device(
        id=str(row[0]),
        token_hash=str(row[1]),
        user=str(row[2]),
        device=str(row[3]),
        scopes=tuple(json.loads(str(row[4]))),
        created=str(row[5]),
        key=bytes(key) if isinstance(key, bytes | bytearray | memoryview) else None,
        rating_cap=_cap(row[7] if isinstance(row[7], str) else None),
        invitation=row[8] if isinstance(row[8], str) else None,
        expires=row[9] if isinstance(row[9], str) else None,
        last_used=row[10] if isinstance(row[10], str) else None,
        suspended=bool(row[11]),
    )


def _invitation(row: tuple[object, ...]) -> Invitation:
    return Invitation(
        id=str(row[0]),
        code=str(row[1]),
        user=str(row[2]),
        scopes=tuple(json.loads(str(row[3]))),
        expires=str(row[4]),
        devices=int(str(row[5])),
        used=int(str(row[6])),
        rating_cap=_cap(row[7] if isinstance(row[7], str) else None),
        note=row[8] if isinstance(row[8], str) else None,
        created=str(row[9]),
    )


class SqliteAccounts:
    """Accounts, devices and invitations in a SQLite file; safe from several threads of one process.

    `path` is the file (created, readable by its owner alone, when it is not there) or ``":memory:"``.
    One process owns a file at a time for the writes of `LanternApp`'s locks to mean anything; SQLite itself
    serialises writers from several processes.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        name = os.fspath(path)
        if name != ":memory:":
            self._create_private(Path(name))
        self._lock = threading.RLock()
        self._db = sqlite3.connect(name, check_same_thread=False, isolation_level=None)
        try:
            self._open()
        except BaseException:
            self._db.close()
            raise

    @staticmethod
    def _create_private(path: Path) -> None:
        """Creates the file readable by its owner alone, before SQLite does with the process's umask."""
        if not path.exists():
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(descriptor)

    def _open(self) -> None:
        version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA:
            raise AccountsSchemaError(
                f"This accounts file is of schema {version}, newer than the {SCHEMA} this version knows: "
                "it is left as it is."
            )
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA busy_timeout = 5000")
        # Not for an in-memory database, which has no file to log to
        self._db.execute("PRAGMA journal_mode = WAL")
        if version < SCHEMA:
            with self._transaction():
                has_tables = self._db.execute("SELECT 1 FROM sqlite_master WHERE name = 'users'").fetchone()
                if has_tables is None:
                    for statement in _TABLES.split(";"):
                        if statement.strip():
                            self._db.execute(statement)
                else:
                    # Taking up a file of schema 1 (before an account had a rating cap and a device a suspension).
                    # Kept for the files written before schema 2; goes when no schema 1 file is left to open.
                    self._add_column("users", "rating_cap", "TEXT")
                    self._add_column("devices", "suspended", "INTEGER NOT NULL DEFAULT 0")
                self._db.execute(f"PRAGMA user_version = {SCHEMA}")

    def _add_column(self, table: str, column: str, definition: str) -> None:
        names = {str(r[1]) for r in self._db.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in names:
            self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> SqliteAccounts:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Everything it does, or nothing: a write transaction taken at once, under the lock."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    # Accounts.

    def user(self, name: str) -> User | None:
        with self._lock:
            row = self._db.execute(f"SELECT {_USER} FROM users WHERE name = ?", (name,)).fetchone()  # noqa: S608
        return None if row is None else _user(row)

    def users(self) -> list[User]:
        with self._lock:
            rows = self._db.execute(f"SELECT {_USER} FROM users ORDER BY name").fetchall()  # noqa: S608
        return [_user(r) for r in rows]

    def create_user(self, name: str, scopes: Sequence[str], state: str = "active") -> User:
        if not ACCOUNT_NAME.match(name):
            raise AccountError(400, "bad_request", "name is 1 to 64 letters, digits, '.', '_' and '-'.")
        user = User(name, ordered_scopes(scopes), state)
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM users WHERE name = ?", (name,)).fetchone() is not None:
                raise AccountError(409, "conflict", f"An account named {name} exists.")
            db.execute(
                "INSERT INTO users (name, scopes, state, created) VALUES (?, ?, ?, ?)",
                (user.name, json.dumps(user.scopes), user.state, user.created),
            )
        return user

    def update_user(
        self,
        name: str,
        *,
        state: str | None = None,
        scopes: Sequence[str] | None = None,
        rating_cap: RatingCap | None | _Unset = UNSET,
    ) -> User:
        with self._transaction() as db:
            row = db.execute(f"SELECT {_USER} FROM users WHERE name = ?", (name,)).fetchone()  # noqa: S608
            if row is None:
                raise AccountError(404, "not_found", "No such account.")
            user = _user(row)
            if state is not None:
                user = replace(user, state=state)
            if not isinstance(rating_cap, _Unset):
                user = replace(user, rating_cap=rating_cap)
            if scopes is not None:
                user = replace(user, scopes=ordered_scopes(scopes))
                # Its devices' scopes are cut back with its own
                for device_id, device_scopes in db.execute(
                    "SELECT id, scopes FROM devices WHERE user = ?", (name,)
                ).fetchall():
                    kept = [s for s in json.loads(device_scopes) if s in user.scopes]
                    db.execute("UPDATE devices SET scopes = ? WHERE id = ?", (json.dumps(kept), device_id))
            db.execute(
                "UPDATE users SET scopes = ?, state = ?, rating_cap = ? WHERE name = ?",
                (json.dumps(user.scopes), user.state, _cap_text(user.rating_cap), name),
            )
        return user

    def delete_user(self, name: str) -> None:
        with self._transaction() as db:
            # Its devices and invitations go with it (ON DELETE CASCADE)
            if db.execute("DELETE FROM users WHERE name = ?", (name,)).rowcount == 0:
                raise AccountError(404, "not_found", "No such account.")

    # Devices.

    def device_of(self, token: str) -> Device | None:
        with self._lock:
            row = self._db.execute(
                f"SELECT {_DEVICE} FROM devices WHERE token_hash = ?",  # noqa: S608
                (token_hash(token),),
            ).fetchone()
        if row is None:
            return None
        found = _device(row)
        return found if found.live() else None

    def issue(
        self,
        user: str,
        device: str,
        scopes: Sequence[str],
        *,
        key: bytes | None = None,
        rating_cap: RatingCap | None = None,
        invitation: str | None = None,
        lifetime: float | None = None,
    ) -> tuple[str, Device]:
        token = new_token()
        expires = utc(datetime.now(UTC) + timedelta(seconds=lifetime)) if lifetime else None
        record = self._keep(
            token, user, device, scopes, key=key, rating_cap=rating_cap, invitation=invitation, expires=expires
        )
        return token, record

    def add_token(
        self,
        token: str,
        user: str,
        device: str,
        scopes: Sequence[str],
        *,
        key: bytes | None = None,
        rating_cap: RatingCap | None = None,
    ) -> Device:
        """Keeps a token the server did not issue here (a demo's, or one moved from another store): its hash."""
        return self._keep(token, user, device, scopes, key=key, rating_cap=rating_cap, invitation=None, expires=None)

    def _keep(
        self,
        token: str,
        user: str,
        device: str,
        scopes: Sequence[str],
        *,
        key: bytes | None,
        rating_cap: RatingCap | None,
        invitation: str | None,
        expires: str | None,
    ) -> Device:
        record = Device(
            id=new_device_id(),
            token_hash=token_hash(token),
            user=user,
            device=device,
            scopes=ordered_scopes(scopes),
            created=utc(),
            key=key,
            rating_cap=rating_cap,
            invitation=invitation,
            expires=expires,
        )
        with self._transaction() as db:
            db.execute(
                "INSERT INTO devices (id, token_hash, user, device, scopes, created, key, rating_cap, invitation, "
                "expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.id,
                    record.token_hash,
                    record.user,
                    record.device,
                    json.dumps(record.scopes),
                    record.created,
                    record.key,
                    _cap_text(record.rating_cap),
                    record.invitation,
                    record.expires,
                ),
            )
        return record

    def devices(self, user: str | None = None) -> list[Device]:
        with self._lock:
            if user is None:
                rows = self._db.execute(f"SELECT {_DEVICE} FROM devices").fetchall()  # noqa: S608
            else:
                rows = self._db.execute(f"SELECT {_DEVICE} FROM devices WHERE user = ?", (user,)).fetchall()  # noqa: S608
        return sorted((d for d in map(_device, rows) if d.live()), key=lambda d: (d.user, d.created, d.id))

    def update_device(
        self,
        device_id: str,
        *,
        device: str | None = None,
        scopes: Sequence[str] | None = None,
        rating_cap: RatingCap | None | _Unset = UNSET,
        suspended: bool | None = None,
    ) -> Device:
        with self._transaction() as db:
            row = db.execute(f"SELECT {_DEVICE} FROM devices WHERE id = ?", (device_id,)).fetchone()  # noqa: S608
            if row is None:
                raise AccountError(404, "not_found", "No such device.")
            record = _device(row)
            if device is not None:
                record = replace(record, device=device)
            if scopes is not None:
                record = replace(record, scopes=tuple(s for s in record.scopes if s in scopes))
            if not isinstance(rating_cap, _Unset):
                record = replace(record, rating_cap=rating_cap)
            if suspended is not None:
                record = replace(record, suspended=suspended)
            db.execute(
                "UPDATE devices SET device = ?, scopes = ?, rating_cap = ?, suspended = ? WHERE id = ?",
                (
                    record.device,
                    json.dumps(record.scopes),
                    _cap_text(record.rating_cap),
                    int(record.suspended),
                    device_id,
                ),
            )
        return record

    def revoke(self, device_id: str) -> bool:
        with self._transaction() as db:
            return db.execute("DELETE FROM devices WHERE id = ?", (device_id,)).rowcount > 0

    # Invitations.

    def create_invitation(
        self,
        user: str,
        scopes: Sequence[str],
        expires: str,
        devices: int,
        *,
        rating_cap: RatingCap | None = None,
        note: str | None = None,
    ) -> Invitation:
        with self._transaction() as db:
            codes = {typed_code(r[0]) for r in db.execute("SELECT code FROM invitations").fetchall()}
            while typed_code(code := new_code(INVITATION_SYMBOLS)) in codes:
                pass
            inv = Invitation(
                id="i_" + secrets.token_urlsafe(9),
                code=code,
                user=user,
                scopes=ordered_scopes(scopes),
                expires=expires,
                devices=devices,
                rating_cap=rating_cap,
                note=note,
            )
            db.execute(
                "INSERT INTO invitations (id, code, user, scopes, expires, devices, used, rating_cap, note, created) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    inv.id,
                    inv.code,
                    inv.user,
                    json.dumps(inv.scopes),
                    inv.expires,
                    inv.devices,
                    inv.used,
                    _cap_text(inv.rating_cap),
                    inv.note,
                    inv.created,
                ),
            )
        return inv

    def invitations(self) -> list[Invitation]:
        with self._lock:
            rows = self._db.execute(f"SELECT {_INVITATION} FROM invitations").fetchall()  # noqa: S608
        return sorted((i for i in map(_invitation, rows) if i.redeemable()), key=lambda i: (i.created, i.id))

    def revoke_invitation(self, invitation_id: str) -> bool:
        with self._transaction() as db:
            return db.execute("DELETE FROM invitations WHERE id = ?", (invitation_id,)).rowcount > 0

    def redeem(self, code: str) -> Invitation | None:
        typed = typed_code(code)
        with self._transaction() as db:
            for row in db.execute(f"SELECT {_INVITATION} FROM invitations").fetchall():  # noqa: S608
                inv = _invitation(row)
                if hmac.compare_digest(typed_code(inv.code), typed):
                    if not inv.redeemable():
                        return None
                    db.execute("UPDATE invitations SET used = used + 1 WHERE id = ?", (inv.id,))
                    return replace(inv, used=inv.used + 1)
        return None
