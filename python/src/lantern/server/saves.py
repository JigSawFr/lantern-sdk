"""Save backups, on the server's side (SPEC.md § 9): what LanternApp keeps of
each account's backups and of the resumable uploads under way.

`SaveStore` is what LanternApp needs; `MemorySaveStore` keeps everything in
memory (tests, demos), `FileSaveStore` in a folder (an `index.json`, the
archives, the uploads' parts). LanternApp does the protocol's work: the
platform and the fields, Content-Digest and the whole archive's SHA-256, the
limits (`SaveLimits`), pruning beyond `saves_kept_per_title`, encrypted
backups kept as sent (§ 9.4, never decrypted), the events (§ 18.2), and
erasing an account's backups when it is deleted (§ 5.7). A store keeps
bytes and documents.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import secrets
import tempfile
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue
from lantern._generated.models import Save
from lantern.digest import sha256_file, sha256_hex
from lantern.server.files import FileRef
from lantern.server.http import ProblemError

#: A save's kinds (SPEC.md § 9.1).
SAVE_KINDS = ("account", "device", "bcat", "cache", "other")
#: A save's slot (SPEC.md § 9.1).
SLOT = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
#: The ids this toolkit gives: a backup's and an upload's (safe as file names).
SAVE_ID = re.compile(r"^s_[A-Za-z0-9_-]{1,64}$")
UPLOAD_ID = re.compile(r"^u_[A-Za-z0-9_-]{1,64}$")
#: The bytes of a zip's first record: a file's, or the end of an empty archive (SPEC.md § 9.1, Annex A).
ZIP_STARTS = (b"PK\x03\x04", b"PK\x05\x06")


def new_save_id() -> str:
    return "s_" + secrets.token_urlsafe(9)


def new_upload_id() -> str:
    return "u_" + secrets.token_urlsafe(18)


@dataclass(frozen=True)
class SaveLimits:
    """The handshake's limits of saves (SPEC.md § 4.2, § 9): `body`, the largest save sent in one request
    (limits.save_body); `size`, the largest at all (limits.save_size); `kept`, the backups kept per title,
    platform and account (limits.saves_kept_per_title); `chunk`, an upload's chunk_size; `upload_hours`,
    how long an upload may take before it is gone."""

    body: int = 8 << 20
    size: int = 1 << 30
    kept: int = 10
    chunk: int = 1 << 20
    upload_hours: int = 24

    def __post_init__(self) -> None:
        if not (1 <= self.body <= self.size and self.kept >= 1 and self.chunk >= 1 and self.upload_hours >= 1):
            raise ValueError("save limits: 1 <= body <= size, kept, chunk and upload_hours 1 or more")


@dataclass
class UploadSession:
    """A resumable upload (SPEC.md § 9.3): its id, the account that opened it, the backup it makes (`save`:
    its platform, title and fields, the `size` and `sha256` announced; `save_id` and `created` are given
    when it ends), when it is gone, and how many bytes the store holds (`offset`)."""

    id: str
    user: str
    save: Save
    expires: str
    offset: int = 0


class SaveStore(Protocol):
    """What LanternApp keeps of save backups. Every method is called under LanternApp's lock of saves."""

    def saves(self, user: str) -> list[Save]:
        """The account's backups, oldest kept first."""
        ...

    def archive(self, user: str, save_id: str) -> FileRef | None:
        """A backup's bytes, as kept."""
        ...

    def keep(self, user: str, save: Save, data: bytes) -> None:
        """Keeps a new backup, sent in one request."""
        ...

    def drop(self, user: str, save_id: str) -> bool:
        """Removes a backup; False when the account has none of that id."""
        ...

    def open_upload(self, session: UploadSession) -> None: ...

    def upload(self, upload_id: str) -> UploadSession | None:
        """An upload under way, with the bytes held now as its `offset`; None when unknown."""
        ...

    def uploads(self) -> list[UploadSession]: ...

    def append(self, upload_id: str, data: bytes) -> int:
        """Adds a chunk at the end of the upload; its new offset."""
        ...

    def upload_digest(self, upload_id: str) -> tuple[str, bytes]:
        """(the SHA-256 of the bytes received, lower-case hex; their first 16 bytes)."""
        ...

    def keep_upload(self, upload_id: str, save: Save) -> None:
        """The upload's bytes become the backup `save`; the upload is gone."""
        ...

    def abandon(self, upload_id: str) -> None:
        """Drops an upload and its bytes."""
        ...

    def forget(self, user: str) -> None:
        """Erases an account's backups and uploads (SPEC.md § 5.7)."""
        ...


def _public(save: Save) -> Save:
    """A backup as clients see it: without what another writer kept beside it."""
    return dataclasses.replace(save, schema=None, extra={})


class MemorySaveStore:
    """Save backups held in memory."""

    def __init__(self) -> None:
        self._saves: dict[str, list[tuple[Save, bytes]]] = {}
        self._uploads: dict[str, tuple[UploadSession, bytearray]] = {}
        self._lock = threading.RLock()

    def saves(self, user: str) -> list[Save]:
        with self._lock:
            return [s for s, _ in self._saves.get(user, [])]

    def archive(self, user: str, save_id: str) -> FileRef | None:
        with self._lock:
            found = next(((s, d) for s, d in self._saves.get(user, []) if s.save_id == save_id), None)
        if found is None:
            return None
        save, data = found
        ctype = "application/octet-stream" if save.encryption is not None else "application/zip"
        return FileRef.of_bytes(data, ctype)

    def keep(self, user: str, save: Save, data: bytes) -> None:
        with self._lock:
            self._saves.setdefault(user, []).append((_public(save), bytes(data)))

    def drop(self, user: str, save_id: str) -> bool:
        with self._lock:
            mine = self._saves.get(user, [])
            kept = [(s, d) for s, d in mine if s.save_id != save_id]
            self._saves[user] = kept
            return len(kept) != len(mine)

    def open_upload(self, session: UploadSession) -> None:
        with self._lock:
            self._uploads[session.id] = (dataclasses.replace(session, offset=0), bytearray())

    def upload(self, upload_id: str) -> UploadSession | None:
        with self._lock:
            found = self._uploads.get(upload_id)
            return dataclasses.replace(found[0], offset=len(found[1])) if found is not None else None

    def uploads(self) -> list[UploadSession]:
        with self._lock:
            return [dataclasses.replace(s, offset=len(d)) for s, d in self._uploads.values()]

    def append(self, upload_id: str, data: bytes) -> int:
        with self._lock:
            part = self._uploads[upload_id][1]
            part += data
            return len(part)

    def upload_digest(self, upload_id: str) -> tuple[str, bytes]:
        with self._lock:
            part = self._uploads[upload_id][1]
            return sha256_hex(bytes(part)), bytes(part[:16])

    def keep_upload(self, upload_id: str, save: Save) -> None:
        with self._lock:
            session, part = self._uploads.pop(upload_id)
            self.keep(session.user, save, bytes(part))

    def abandon(self, upload_id: str) -> None:
        with self._lock:
            self._uploads.pop(upload_id, None)

    def forget(self, user: str) -> None:
        with self._lock:
            self._saves.pop(user, None)
            for uid, (s, _) in list(self._uploads.items()):
                if s.user == user:
                    del self._uploads[uid]


class FileSaveStore:
    """Save backups kept in a folder: `index.json` (the backups' documents and the uploads under way, with
    its `schema`), `archives/<save id>` and `uploads/<upload id>`.

    The index follows the rule of versioned formats: an index of a newer `schema` than this toolkit's
    reads as no backup at all and is never written over (every write then answers 503); one this toolkit
    rewrites keeps the keys it does not know, its own and each entry's."""

    def __init__(self, folder: str | Path) -> None:
        self.folder = Path(folder)
        self.path = self.folder / "index.json"
        self._lock = threading.RLock()
        self.index: JSONObject = {"schema": SCHEMA, "saves": [], "uploads": {}}
        #: False when the index is of a newer schema: nothing is listed, nothing written.
        self.writable = True
        self._load()

    def _load(self) -> None:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return
        try:
            doc = json.loads(raw)
        except ValueError as e:
            raise DocumentError(f"not JSON ({e})", str(self.path)) from None
        version = doc.get("schema") if isinstance(doc, dict) else None
        if not isinstance(doc, dict) or not isinstance(version, int) or isinstance(version, bool):
            raise DocumentError("an object with an integer schema", str(self.path))
        if version > SCHEMA:  # a newer writer's: read as absent, never written over
            self.writable = False
            return
        if not isinstance(doc.get("saves"), list):
            doc["saves"] = []
        if not isinstance(doc.get("uploads"), dict):
            doc["uploads"] = {}
        self.index = doc

    def _write(self) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".index-", dir=self.folder)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.index, f, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def _check_writable(self) -> None:
        if not self.writable:
            raise ProblemError(
                503,
                "unavailable",
                "The saves' index is of a newer schema than this server: it keeps no backup now.",
                headers={"Retry-After": "3600"},
            )

    def _entries(self) -> list[JSONValue]:
        entries = self.index["saves"]
        assert isinstance(entries, list)
        return entries

    def _sessions(self) -> dict[str, JSONValue]:
        sessions = self.index["uploads"]
        assert isinstance(sessions, dict)
        return sessions

    def _archive_path(self, save_id: str) -> Path:
        return self.folder / "archives" / save_id

    def _part(self, upload_id: str) -> Path:
        return self.folder / "uploads" / upload_id

    def _mine(self, user: str) -> Iterator[tuple[JSONObject, Save]]:
        for raw in self._entries():
            if not isinstance(raw, dict) or raw.get("user") != user:
                continue
            doc = {k: v for k, v in raw.items() if k != "user"}
            try:
                save = Save.from_json(doc, "a backup of index.json")
            except DocumentError:
                continue
            if SAVE_ID.match(save.save_id):
                yield raw, save

    def saves(self, user: str) -> list[Save]:
        with self._lock:
            return [_public(s) for _, s in self._mine(user)]

    def archive(self, user: str, save_id: str) -> FileRef | None:
        with self._lock:
            found = next((s for _, s in self._mine(user) if s.save_id == save_id), None)
        if found is None:
            return None
        ctype = "application/octet-stream" if found.encryption is not None else "application/zip"
        path = self._archive_path(save_id)
        if not path.is_file():
            return None
        return FileRef(str(path), found.size, found.sha256, ctype)

    def _record(self, user: str, save: Save) -> None:
        self._entries().append({"user": user, **_public(save).to_json()})

    def keep(self, user: str, save: Save, data: bytes) -> None:
        with self._lock:
            self._check_writable()
            target = self._archive_path(save.save_id)
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(target.name + ".tmp")
            tmp.write_bytes(data)
            tmp.replace(target)
            self._record(user, save)
            self._write()

    def drop(self, user: str, save_id: str) -> bool:
        with self._lock:
            self._check_writable()
            mine = [raw for raw, s in self._mine(user) if s.save_id == save_id]
            if not mine:
                return False
            self.index["saves"] = [e for e in self._entries() if not any(e is m for m in mine)]
            self._archive_path(save_id).unlink(missing_ok=True)
            self._write()
            return True

    def _session(self, upload_id: str, raw: JSONValue) -> UploadSession | None:
        if not isinstance(raw, dict) or not UPLOAD_ID.match(upload_id):
            return None
        user, expires = raw.get("user"), raw.get("expires")
        if not isinstance(user, str) or not isinstance(expires, str):
            return None
        try:
            save = Save.from_json(raw.get("save"), "an upload of index.json")
        except DocumentError:
            return None
        try:
            offset = self._part(upload_id).stat().st_size
        except OSError:
            offset = 0
        return UploadSession(upload_id, user, save, expires, offset)

    def open_upload(self, session: UploadSession) -> None:
        with self._lock:
            self._check_writable()
            part = self._part(session.id)
            part.parent.mkdir(parents=True, exist_ok=True)
            part.write_bytes(b"")
            self._sessions()[session.id] = {
                "user": session.user,
                "save": _public(session.save).to_json(),
                "expires": session.expires,
            }
            self._write()

    def upload(self, upload_id: str) -> UploadSession | None:
        with self._lock:
            if not self.writable:
                return None
            return self._session(upload_id, self._sessions().get(upload_id))

    def uploads(self) -> list[UploadSession]:
        with self._lock:
            if not self.writable:
                return []
            found = [self._session(uid, raw) for uid, raw in self._sessions().items()]
            return [s for s in found if s is not None]

    def append(self, upload_id: str, data: bytes) -> int:
        with self._lock:
            self._check_writable()
            part = self._part(upload_id)
            with part.open("ab") as f:
                f.write(data)
            return part.stat().st_size

    def upload_digest(self, upload_id: str) -> tuple[str, bytes]:
        with self._lock:
            part = self._part(upload_id)
            with part.open("rb") as f:
                head = f.read(16)
            return sha256_file(part).hexdigest(), head

    def keep_upload(self, upload_id: str, save: Save) -> None:
        with self._lock:
            self._check_writable()
            session = self._session(upload_id, self._sessions().get(upload_id))
            if session is None:
                raise KeyError(upload_id)
            target = self._archive_path(save.save_id)
            target.parent.mkdir(parents=True, exist_ok=True)
            self._part(upload_id).replace(target)
            self._sessions().pop(upload_id, None)
            self._record(session.user, save)
            self._write()

    def abandon(self, upload_id: str) -> None:
        with self._lock:
            self._check_writable()
            self._sessions().pop(upload_id, None)
            if UPLOAD_ID.match(upload_id):
                self._part(upload_id).unlink(missing_ok=True)
            self._write()

    def forget(self, user: str) -> None:
        with self._lock:
            self._check_writable()
            for _, s in list(self._mine(user)):
                self._archive_path(s.save_id).unlink(missing_ok=True)
            self.index["saves"] = [e for e in self._entries() if not (isinstance(e, dict) and e.get("user") == user)]
            for uid, raw in list(self._sessions().items()):
                if isinstance(raw, dict) and raw.get("user") == user:
                    self._sessions().pop(uid, None)
                    if UPLOAD_ID.match(uid):
                        self._part(uid).unlink(missing_ok=True)
            self._write()


__all__ = [
    "SAVE_KINDS",
    "SLOT",
    "ZIP_STARTS",
    "FileSaveStore",
    "MemorySaveStore",
    "SaveLimits",
    "SaveStore",
    "UploadSession",
    "new_save_id",
    "new_upload_id",
]
