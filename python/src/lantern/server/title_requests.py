"""Requests for games, on the server's side (SPEC.md § 11): what LanternApp
keeps of each account's requests.

`RequestStore` is what LanternApp needs; `MemoryRequests` keeps them in
memory. LanternApp does the protocol's work: a request per open title (the
same title asked again gives the open one), the platform and its title ids,
withdrawing, the events of each change (§ 18.2), a request marked `done`
when its title arrives in the library, and erasing an account's requests
when it is deleted (§ 5.7). The draft 0.5 defines no route for an
administrator to answer a request: a server marks one `done` or `declined`
with `LanternApp.answer_request()`, from its own pages.
"""

from __future__ import annotations

import dataclasses
import secrets
import threading
from dataclasses import dataclass
from typing import Protocol

from lantern._base import JSONObject

#: A request's statuses (SPEC.md § 11).
STATUSES = ("open", "done", "declined")
#: Open requests an account may hold at once.
OPEN_LIMIT = 1000


def new_request_id() -> str:
    return "r_" + secrets.token_urlsafe(9)


@dataclass(frozen=True)
class StoredRequest:
    """A request, as kept: the account that made it beside what clients read."""

    id: str
    user: str
    platform: str
    title_id: str
    status: str
    created: str
    name: str | None = None

    def to_json(self) -> JSONObject:
        doc: JSONObject = {"id": self.id, "platform": self.platform, "title_id": self.title_id}
        if self.name is not None:
            doc["name"] = self.name
        doc.update(status=self.status, created=self.created)
        return doc


class RequestStore(Protocol):
    """What LanternApp keeps of requests. Every method is called under LanternApp's lock of requests."""

    def requests(self, user: str | None = None) -> list[StoredRequest]:
        """An account's requests, or everyone's."""
        ...

    def add(self, request: StoredRequest) -> None: ...

    def set_status(self, request_id: str, status: str) -> StoredRequest | None:
        """The request with its new status; None when there is none of that id."""
        ...

    def remove(self, user: str, request_id: str) -> StoredRequest | None:
        """Removes the account's own request; None when it has none of that id."""
        ...

    def forget(self, user: str) -> None:
        """Erases an account's requests (SPEC.md § 5.7)."""
        ...


class MemoryRequests:
    """Requests held in memory."""

    def __init__(self) -> None:
        self._requests: dict[str, StoredRequest] = {}
        self._lock = threading.RLock()

    def requests(self, user: str | None = None) -> list[StoredRequest]:
        with self._lock:
            return [r for r in self._requests.values() if user is None or r.user == user]

    def add(self, request: StoredRequest) -> None:
        with self._lock:
            self._requests[request.id] = request

    def set_status(self, request_id: str, status: str) -> StoredRequest | None:
        with self._lock:
            found = self._requests.get(request_id)
            if found is None:
                return None
            found = dataclasses.replace(found, status=status)
            self._requests[request_id] = found
            return found

    def remove(self, user: str, request_id: str) -> StoredRequest | None:
        with self._lock:
            found = self._requests.get(request_id)
            if found is None or found.user != user:
                return None
            del self._requests[request_id]
            return found

    def forget(self, user: str) -> None:
        with self._lock:
            for rid in [r.id for r in self._requests.values() if r.user == user]:
                del self._requests[rid]


__all__ = ["OPEN_LIMIT", "STATUSES", "MemoryRequests", "RequestStore", "StoredRequest", "new_request_id"]
