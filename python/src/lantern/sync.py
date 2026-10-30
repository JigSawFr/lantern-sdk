"""Sync (SPEC.md § 20): a user's wishes, and what each of their consoles has
installed, kept by their server so that every console of theirs sees them.
What both sides share: the times items carry, the merge rule, and the
consent a client asks for before anything leaves the console.

    consent = SyncConsent(server_uid, wishes=True)            # the user said yes, for this server
    client.sync_consent = consent                             # nothing of /v1/sync is read before
    kept = merge(have, sent, now=server_time, skew=300)       # the rule of § 20.4, item by item

The merge rule (§ 20.4): of two items, the later `updated` wins; on the same
time, a deletion wins; between two values, the one whose canonical JSON (keys
sorted, no space, non-ASCII as it is, UTF-8) is the greater string of bytes.
An `updated` more than `auth.skew` seconds ahead of the server's clock is the
server's time (L-20.4-2). Test vectors: vectors/sync-merge.json.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from lantern._base import JSONValue, LanternError

#: The collections of this version (SPEC.md § 20.2); a later one may add others, which a reader skips.
COLLECTIONS = ("wishes", "installed")
#: Items in one write (SPEC.md § 13), and a collection's largest `limits.sync_items`.
WRITE_LIMIT = 1000
ITEMS_LIMIT = 100_000
#: How long a deletion is kept at least (SPEC.md § 20.5).
TOMBSTONE_DAYS = 30
_UPDATED = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,3})?Z$")
#: A device's id, its key in `installed` (SPEC.md § 5.7, § 20.2).
DEVICE_ID = re.compile(r"^d_[0-9a-f]{16}$")


class ConsentRequired(LanternError):
    """A sync call the user did not agree to (SPEC.md § 20.1): no consent for this server, or none for
    `installed` by name. Ask the user first; nothing was sent."""


class SyncReset(LanternError):
    """The server's sync data was deleted since this client last read it (another `generation`, SPEC.md
    § 20.3, L-20.3-2): the client dropped its consent and its copy; it writes nothing back, and asks its user
    again before syncing anew."""

    def __init__(self, kept: str | None, found: str) -> None:
        super().__init__(f"the sync data was deleted (generation {found}, {kept} kept): ask the user again")
        self.kept, self.found = kept, found


def ms(when: datetime) -> str:
    """A time as an item's `updated` gives it: UTC, to the millisecond (`2026-10-30T09:12:03.250Z`)."""
    when = when.astimezone(UTC)
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"


def parse_updated(text: object) -> datetime | None:
    """An `updated` of SPEC.md § 20.2's form (milliseconds optional, read as .000); None otherwise."""
    m = _UPDATED.match(text) if isinstance(text, str) else None
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group(1) + (m.group(2) or ".0").ljust(4, "0") + "+00:00")
    except ValueError:
        return None


def server_updated(text: object, now: datetime, skew: int) -> str | None:
    """An item's `updated` as a server keeps it (SPEC.md § 20.4): to the millisecond, one more than `skew`
    seconds ahead of `now` taken as `now` (L-20.4-2); None when it is not such a time."""
    when = parse_updated(text)
    if when is None:
        return None
    if when > now + timedelta(seconds=skew):
        when = now
    return ms(when)


def canonical(value: JSONValue) -> bytes:
    """A value's canonical JSON (SPEC.md § 20.4): keys sorted, no space, non-ASCII as it is, in UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True)
class Item:
    """An item of a collection: a value, or a deletion (`deleted`), as of `updated`; `rev` once a server
    took it."""

    key: str
    updated: str
    value: JSONValue = None
    deleted: bool = False
    rev: int | None = None

    def to_json(self) -> dict[str, JSONValue]:
        out: dict[str, JSONValue] = {"key": self.key}
        if self.deleted:
            out["deleted"] = True
        else:
            out["value"] = self.value
        out["updated"] = self.updated
        if self.rev is not None:
            out["rev"] = self.rev
        return out


def wins(sent: Item, have: Item | None) -> bool:
    """Whether the item sent replaces the one kept (SPEC.md § 20.4): their `updated` already as the server
    keeps them. The same item again does not."""
    if have is None:
        return True
    a, b = parse_updated(sent.updated), parse_updated(have.updated)
    if a is None or b is None:
        raise ValueError("an updated not of SPEC.md § 20.2's form")
    if a != b:
        return a > b
    if sent.deleted != have.deleted:
        return sent.deleted
    return not sent.deleted and canonical(sent.value) > canonical(have.value)


def merge(have: Item | None, sent: Item, *, now: datetime, skew: int) -> tuple[Item, bool]:
    """(the item kept, whether it is the one sent) of the rule of § 20.4, at the server's time `now`."""
    updated = server_updated(sent.updated, now, skew)
    if updated is None:
        raise ValueError(f"{sent.updated!r} is not an updated of SPEC.md § 20.2's form")
    sent = Item(sent.key, updated, None if sent.deleted else sent.value, sent.deleted)
    if have is not None:  # as kept: to the millisecond (a time without them reads as .000)
        when = parse_updated(have.updated)
        have = Item(have.key, ms(when) if when is not None else have.updated, have.value, have.deleted, have.rev)
    if wins(sent, have):
        return sent, True
    assert have is not None
    return have, False


@dataclass
class SyncConsent:
    """What a console's user agreed to sync with one server (SPEC.md § 20.1): kept per console profile and
    per server, given by the app after asking in plain words (Annex B.12). `installed` must be agreed to by
    name: agreeing to sync wishes does not cover it (L-20.1-2). `generation` is the one this client last
    read: another one means the data was deleted since (L-20.3-2)."""

    server_uid: str
    wishes: bool = True
    installed: bool = False
    generation: str | None = None
    revs: dict[str, int] = field(default_factory=dict)

    def allows(self, collection: str, *, write: bool) -> bool:
        if collection == "installed" and write:
            return self.installed
        return self.wishes or self.installed


def consent_for(consent: SyncConsent | None, server_uid: str, collection: str | None, *, write: bool) -> SyncConsent:
    """The consent a sync call needs (L-20.1-1, L-20.1-2): ConsentRequired, before anything is sent, when the
    user did not agree to sync with this server, or to send `installed` by name."""
    if consent is None or consent.server_uid != server_uid:
        raise ConsentRequired("the user has not agreed to sync with this server (SPEC.md § 20.1)")
    if collection is not None and not consent.allows(collection, write=write):
        raise ConsentRequired(f"the user has not agreed to send {collection} (SPEC.md § 20.1)")
    return consent


def same_generation(consent: SyncConsent, found: str) -> bool:
    """Whether the generation read is the one kept (the first read keeps it): False means the data was
    deleted since, and the client drops its consent and copy (L-20.3-2)."""
    if consent.generation is None:
        consent.generation = found
    return consent.generation == found


__all__ = [
    "COLLECTIONS",
    "DEVICE_ID",
    "ITEMS_LIMIT",
    "TOMBSTONE_DAYS",
    "WRITE_LIMIT",
    "ConsentRequired",
    "Item",
    "SyncConsent",
    "SyncReset",
    "canonical",
    "consent_for",
    "merge",
    "ms",
    "parse_updated",
    "same_generation",
    "server_updated",
    "wins",
]
