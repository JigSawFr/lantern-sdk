"""Sync data, on the server's side (SPEC.md § 20): each account's
collections, merged item by item by § 20.4's rule, with their revisions, the
deletions kept 30 days at least (§ 20.5), and a `generation` that changes
only when the data is deleted.

`SyncStore` is what LanternApp needs; `MemorySync` is one, held in memory, a
reference for a server's own store (a database table per item does).
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

from lantern import sync as syncing
from lantern.server.http import ProblemError, bad_request

#: limits.sync_items, by default.
ITEMS = 10_000


def new_generation() -> str:
    return "g_" + secrets.token_urlsafe(9)


class SyncStore(Protocol):
    """What LanternApp keeps of each account's sync data."""

    #: Items a collection holds at most (limits.sync_items, SPEC.md § 20.5).
    limit: int

    def overview(self, user: str) -> tuple[str, dict[str, tuple[int, int]]]:
        """(generation, {collection: (rev, live items)}) of every collection of this version."""
        ...

    def read(self, user: str, collection: str, since: int | None) -> tuple[str, int, list[syncing.Item]]:
        """(generation, rev, items): with `since`, every item changed after it, deletions included (410 when
        the deletions that far back are gone, 400 for a revision never given); without, every live item."""
        ...

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
        """Merges items sent (§ 20.4): (generation, rev, each item as then kept). 409 for another generation,
        412 when If-Match is not the collection's, 413 beyond `limit`."""
        ...

    def erase(self, user: str, collection: str | None = None) -> str:
        """Erases a collection, or every one, deletions included: a new generation (§ 20.5)."""
        ...

    def forget(self, user: str) -> None:
        """Erases an account's data, the account being deleted (§ 5.7, L-20.5-3)."""
        ...


@dataclass
class _Collection:
    rev: int = 0
    floor: int = 0  # the revision below which deletions were dropped
    items: dict[str, tuple[syncing.Item, datetime]] = field(default_factory=dict)


@dataclass
class _Account:
    generation: str = field(default_factory=new_generation)
    collections: dict[str, _Collection] = field(default_factory=dict)


class MemorySync:
    """Sync data held in memory."""

    def __init__(self, limit: int = ITEMS, *, retention: timedelta = timedelta(days=syncing.TOMBSTONE_DAYS)) -> None:
        if not 1 <= limit <= syncing.ITEMS_LIMIT:
            raise ValueError("limits.sync_items is 1 to 100,000 (SPEC.md § 13)")
        self.limit, self.retention = limit, retention
        self._accounts: dict[str, _Account] = {}
        self._lock = threading.RLock()

    def _account(self, user: str) -> _Account:
        return self._accounts.setdefault(user, _Account())

    def _collection(self, user: str, name: str) -> tuple[_Account, _Collection]:
        acc = self._account(user)
        col = acc.collections.setdefault(name, _Collection())
        limit = datetime.now(UTC) - self.retention
        for key, (item, kept) in list(col.items.items()):
            if item.deleted and kept < limit:
                col.floor = max(col.floor, item.rev or 0)
                del col.items[key]
        return acc, col

    def overview(self, user: str) -> tuple[str, dict[str, tuple[int, int]]]:
        with self._lock:
            out = {}
            for name in syncing.COLLECTIONS:
                _, col = self._collection(user, name)
                out[name] = (col.rev, sum(1 for i, _ in col.items.values() if not i.deleted))
            return self._account(user).generation, out

    def read(self, user: str, collection: str, since: int | None) -> tuple[str, int, list[syncing.Item]]:
        with self._lock:
            acc, col = self._collection(user, collection)
            if since is None:
                items = [i for i, _ in col.items.values() if not i.deleted]
            else:
                if since > col.rev:
                    raise bad_request("This revision was never given: read the collection whole.")
                if since < col.floor:
                    raise ProblemError(410, "gone", "Its deletions are gone: read the collection whole.")
                items = [i for i, _ in col.items.values() if (i.rev or 0) > since]
            return acc.generation, col.rev, items

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
        with self._lock:
            acc, col = self._collection(user, collection)
            if generation != acc.generation:
                raise ProblemError(
                    409, "conflict", "This sync data was deleted since: ask the user again (SPEC.md § 20.3)."
                )
            if if_match is not None and if_match.strip() != f'"{acc.generation}-{col.rev}"':
                raise ProblemError(
                    412,
                    "precondition_failed",
                    "The collection changed since it was read: read it again.",
                    title="Precondition failed",
                )
            fresh = sum(1 for i in items if i.key not in col.items)
            if len(col.items) + fresh > self.limit:
                raise ProblemError(413, "too_large", f"A collection holds {self.limit} items at most here.")
            out = []
            for sent in items:
                have = col.items.get(sent.key)
                kept, replaced = syncing.merge(have[0] if have else None, sent, now=now, skew=skew)
                if replaced:
                    col.rev += 1
                    kept = syncing.Item(kept.key, kept.updated, kept.value, kept.deleted, col.rev)
                    col.items[sent.key] = (kept, now)
                out.append(kept)
            return acc.generation, col.rev, out

    def erase(self, user: str, collection: str | None = None) -> str:
        with self._lock:
            acc = self._account(user)
            if collection is None:
                acc.collections.clear()
            else:
                acc.collections.pop(collection, None)
            acc.generation = new_generation()
            return acc.generation

    def forget(self, user: str) -> None:
        with self._lock:
            self._accounts.pop(user, None)


__all__ = ["ITEMS", "MemorySync", "SyncStore", "new_generation"]
