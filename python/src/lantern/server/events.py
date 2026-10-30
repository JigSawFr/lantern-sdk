"""Events, on the server's side (SPEC.md § 18): a journal of what happened,
kept in memory, which streams and long polls read; and a stream's body, as
an adapter sends it.

`EventHub.emit()` records an event with who may see it: the scope it needs,
and the account, platform and title it is about (LanternApp applies the
caller's scopes, platform and rating cap, § 18.2). Each event's id is a token
of /v1/changes (`token_of`), so that `Last-Event-ID` and `changes?since=`
share their tokens (L-18.1-1). The last `keep` events are kept; an id older
than them is gone (410).

`EventStreamBody` is a stream's body: `retry`, the event `ready`, the events
after where it started, then the new ones as they come; a comment at least
every `heartbeat` seconds (L-18.1-6); a blank line every `probe` seconds
otherwise, so that the adapter learns at once that a client left and frees
its slot (§ 18.4); the end of the stream when its token no longer holds
(L-18.1-8), when the server stops (after `shutdown`, L-18.2-2) or after
`lifetime` seconds.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field

from lantern._base import JSONObject
from lantern._generated.models import Rating

#: The scope each event needs (SPEC.md § 18.2); ready and shutdown go to every stream.
EVENT_SCOPES = {"library": "library", "request": "requests", "save": "saves", "pairing": "admin", "sync": "sync.read"}


@dataclass(frozen=True)
class LibraryChange:
    """What changed in a library, for the event `library`: its family (`apps`, `titles`, `homebrew`,
    `cheats`) and platform, and what a rating cap reads it by: its title, or its own ratings."""

    family: str
    platform: str
    title_id: str | None = None
    ratings: tuple[Rating, ...] | None = None


@dataclass
class Recorded:
    """An event as kept: its sequence number and id, its type and data, and who may see it."""

    seq: int
    id: str
    event: str
    data: JSONObject
    scope: str | None = None
    user: str | None = None
    platform: str | None = None
    title_id: str | None = None
    changes: Sequence[LibraryChange] = field(default_factory=tuple)


class EventHub:
    """The events of a server, in memory: a sequence, the last `keep` events, and the streams open."""

    def __init__(self, keep: int = 10000) -> None:
        self.epoch = secrets.token_hex(4)  # an id does not outlive the process
        self.keep = keep
        self.seq = 0
        self.floor = 0  # the ids at or below it are gone
        self._events: deque[Recorded] = deque()
        self.changed = threading.Condition()
        self.stopping = threading.Event()
        self._streams: dict[str, int] = {}

    def emit(
        self,
        event: str,
        data: JSONObject,
        token_of: Callable[[int], str],
        *,
        scope: str | None = None,
        user: str | None = None,
        platform: str | None = None,
        title_id: str | None = None,
        changes: Sequence[LibraryChange] = (),
    ) -> Recorded:
        """Records an event, and wakes the streams and long polls. `token_of(seq)` gives its id."""
        with self.changed:
            self.seq += 1
            found = Recorded(self.seq, token_of(self.seq), event, data, scope, user, platform, title_id, tuple(changes))
            self._events.append(found)
            while len(self._events) > self.keep:
                self.floor = self._events.popleft().seq
            self.changed.notify_all()
            return found

    def after(self, seq: int) -> list[Recorded]:
        with self.changed:
            return [e for e in self._events if e.seq > seq]

    def wake(self) -> None:
        with self.changed:
            self.changed.notify_all()

    def wait(self, seq: int, timeout: float) -> None:
        """Waits at most `timeout` seconds for an event after `seq`, or a wake."""
        with self.changed:
            if self.seq <= seq and not self.stopping.is_set():
                self.changed.wait(timeout)

    def take_stream(self, key: str, limit: int) -> bool:
        """A slot for a stream of `key` (a token's hash, an address): False beyond `limit` (SPEC.md § 18.4)."""
        with self.changed:
            if self._streams.get(key, 0) >= limit:
                return False
            self._streams[key] = self._streams.get(key, 0) + 1
            return True

    def release_stream(self, key: str) -> None:
        with self.changed:
            left = self._streams.get(key, 0) - 1
            if left > 0:
                self._streams[key] = left
            else:
                self._streams.pop(key, None)

    @property
    def streams(self) -> int:
        with self.changed:
            return sum(self._streams.values())

    def stop(self) -> None:
        """The server stops: every stream sends `shutdown` and ends."""
        self.stopping.set()
        self.wake()


def sse(event_id: str | None, event: str, data: JSONObject) -> bytes:
    """An event as the stream writes it: its id, type, and data on one line of JSON."""
    line = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    head = f"id: {event_id}\n" if event_id is not None else ""
    return f"{head}event: {event}\ndata: {line}\n\n".encode()


class EventStreamBody:
    """A stream's body (SPEC.md § 18.1). `visible(recorded)` gives an event's data for this caller, or None;
    `alive()` says whether its token still holds; `release()` frees its slot, once."""

    def __init__(
        self,
        hub: EventHub,
        *,
        start: int,
        ready_id: str,
        visible: Callable[[Recorded], JSONObject | None],
        alive: Callable[[], bool],
        release: Callable[[], None],
        shutdown_id: Callable[[], str],
        heartbeat: float,
        probe: float = 1.0,
        retry_ms: int = 5000,
        lifetime: float = 3600.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.hub, self.start, self.ready_id = hub, start, ready_id
        self.visible, self.alive, self._release, self.shutdown_id = visible, alive, release, shutdown_id
        self.heartbeat, self.probe, self.retry_ms, self.lifetime = heartbeat, probe, retry_ms, lifetime
        self.clock = clock
        self._closed = threading.Event()
        self._released = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._release()

    def close(self) -> None:
        """The client left, or the adapter is done: the stream ends at its next wake, its slot freed now."""
        self._closed.set()
        self.release()
        self.hub.wake()

    def __iter__(self) -> Iterator[bytes]:
        return self._run()

    def _run(self) -> Iterator[bytes]:
        try:
            yield f"retry: {self.retry_ms}\n\n".encode() + sse(self.ready_id, "ready", {"schema": 1})
            last, beat, probed = self.start, self.clock(), self.clock()
            ends = self.clock() + self.lifetime
            while not self._closed.is_set():
                now = self.clock()
                wait = min(self.heartbeat - (now - beat), self.probe - (now - probed), ends - now)
                self.hub.wait(last, max(0.01, wait))
                if self._closed.is_set():
                    return
                if self.hub.stopping.is_set():
                    yield sse(self.shutdown_id(), "shutdown", {"schema": 1, "retry": max(1, self.retry_ms // 1000)})
                    return
                if not self.alive():
                    return
                out = bytearray()
                for e in self.hub.after(last):
                    last = e.seq
                    data = self.visible(e)
                    if data is not None and e.event not in ("ready", "shutdown"):
                        out += sse(e.id, e.event, data)
                now = self.clock()
                if out:
                    beat = probed = now
                    yield bytes(out)
                elif now - beat >= self.heartbeat:
                    beat = probed = now
                    yield b": heartbeat\n\n"
                elif now - probed >= self.probe:
                    probed = now
                    yield b"\n"  # a blank line: nothing for a reader, and a write that fails once the client left
                if now >= ends:
                    return
        finally:
            self.release()


__all__ = ["EVENT_SCOPES", "EventHub", "EventStreamBody", "LibraryChange", "Recorded", "sse"]
