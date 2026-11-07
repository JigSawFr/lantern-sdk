"""SqliteJournal, SqliteRequests and SqliteSync keep what their Memory counterparts do, and survive a restart;
SecretsFile draws a secret once."""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lantern import sync as syncing
from lantern.server import (
    MemoryLibrary,
    MemoryRequests,
    SecretsFile,
    SecretsSchemaError,
    SqliteJournal,
    SqliteRequests,
    SqliteSync,
    StoredRequest,
)
from lantern.server.http import ProblemError
from lantern.server.library import MemoryJournal
from lantern.server.sqlite_journal import JournalSchemaError
from lantern.server.sync import MemorySync, SyncStore
from lantern.server.title_requests import RequestStore

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


# Journal.


@pytest.fixture(params=["memory", "sqlite"])
def journal(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MemoryJournal | SqliteJournal]:
    if request.param == "memory":
        yield MemoryJournal(keep=3)
    else:
        with SqliteJournal(tmp_path / "journal.db", keep=3) as j:
            yield j


def test_journal_records_and_answers(journal: MemoryJournal | SqliteJournal) -> None:
    journal.record("added", "a1", "switch")
    journal.record("title", "switch/0100", "switch")
    journal.record("added", "a2", "ps5")
    assert journal.seq == 3 and journal.floor == 0
    assert journal.since(0, ("added",), None) == [("added", "a1"), ("added", "a2")]
    assert journal.since(0, ("added", "title"), "switch") == [("added", "a1"), ("title", "switch/0100")]
    assert journal.since(1, ("added",), None) == [("added", "a2")]


def test_journal_forgets_the_oldest(journal: MemoryJournal | SqliteJournal) -> None:
    for n in range(5):
        journal.record("added", f"a{n}", "switch")
    assert journal.seq == 5 and journal.floor == 2
    assert [k for _, k in journal.since(0, ("added",), None)] == ["a2", "a3", "a4"]


def test_journal_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "journal.db"
    with SqliteJournal(path, keep=3) as first:
        first.record("added", "a1", "switch")
        first.record("added", "a2", "switch")
        epoch = first.epoch
    with SqliteJournal(path, keep=3) as again:
        assert again.epoch == epoch and again.seq == 2
        again.record("added", "a3", "switch")
        assert again.seq == 3 and [k for _, k in again.since(1, ("added",), None)] == ["a2", "a3"]


def test_two_journals_have_two_epochs(tmp_path: Path) -> None:
    with SqliteJournal(tmp_path / "a.db") as a, SqliteJournal(tmp_path / "b.db") as b:
        assert a.epoch != b.epoch


def test_a_library_records_in_a_sqlite_journal(tmp_path: Path) -> None:
    from lantern.models import Title

    with SqliteJournal(tmp_path / "journal.db") as log:
        lib = MemoryLibrary(journal=log)
        lib.add_title(Title(platform="switch", title_id="0100ABCD00010000", name="Frost"))
        assert lib.position() == 1 and lib.epoch == log.epoch
        changed, removed = lib.title_changes(0, None, ["en"])
        assert [t.title_id for t in changed] == ["0100ABCD00010000"] and removed == []


def test_a_newer_journal_is_left_alone(tmp_path: Path) -> None:
    path = tmp_path / "journal.db"
    SqliteJournal(path).close()
    import sqlite3

    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA user_version = 99")
        db.commit()
        with pytest.raises(JournalSchemaError):
            SqliteJournal(path)
        assert db.execute("PRAGMA user_version").fetchone()[0] == 99
    finally:
        db.close()


@posix_only
def test_the_journal_file_is_private(tmp_path: Path) -> None:
    SqliteJournal(tmp_path / "journal.db").close()
    assert stat.S_IMODE(os.stat(tmp_path / "journal.db").st_mode) == 0o600


# Requests.


def req(rid: str, user: str = "mira", status: str = "open") -> StoredRequest:
    return StoredRequest(rid, user, "switch", "0100ABCD00010000", status, "2026-11-07T10:00:00.000Z", name="Frost")


@pytest.fixture(params=["memory", "sqlite"])
def requests(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[RequestStore]:
    if request.param == "memory":
        yield MemoryRequests()
    else:
        with SqliteRequests(tmp_path / "requests.db") as store:
            yield store


def test_requests_add_and_list(requests: RequestStore) -> None:
    requests.add(req("r_1"))
    requests.add(req("r_2", "noe"))
    requests.add(req("r_3"))
    assert [r.id for r in requests.requests()] == ["r_1", "r_2", "r_3"]
    assert [r.id for r in requests.requests("mira")] == ["r_1", "r_3"]
    assert requests.requests("nobody") == []


def test_requests_decide(requests: RequestStore) -> None:
    requests.add(req("r_1"))
    done = requests.set_status("r_1", "declined", reason="No.", updated="2026-11-07T11:00:00.000Z")
    assert done is not None and done.status == "declined" and done.reason == "No."
    assert requests.requests()[0] == done
    assert requests.set_status("r_9", "done") is None


def test_requests_remove_only_your_own(requests: RequestStore) -> None:
    requests.add(req("r_1"))
    assert requests.remove("noe", "r_1") is None
    removed = requests.remove("mira", "r_1")
    assert removed is not None and removed.id == "r_1" and requests.requests() == []


def test_requests_forget(requests: RequestStore) -> None:
    requests.add(req("r_1"))
    requests.add(req("r_2", "noe"))
    requests.forget("mira")
    assert [r.id for r in requests.requests()] == ["r_2"]


def test_requests_survive_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "requests.db"
    with SqliteRequests(path) as first:
        first.add(req("r_1"))
        first.set_status("r_1", "done", updated="2026-11-07T11:00:00.000Z")
    with SqliteRequests(path) as again:
        [kept] = again.requests()
        assert kept.status == "done" and kept.name == "Frost" and kept.updated == "2026-11-07T11:00:00.000Z"


# Sync.


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[SyncStore]:
    if request.param == "memory":
        yield MemorySync(limit=3)
    else:
        with SqliteSync(tmp_path / "sync.db", limit=3) as s:
            yield s


def item(key: str, value: object = 1, when: str = "2026-11-07T11:00:00.000Z", deleted: bool = False) -> syncing.Item:
    return syncing.Item(key, when, None if deleted else value, deleted)  # type: ignore[arg-type]


def merge(
    s: SyncStore, items: list[syncing.Item], generation: str | None = None, now: datetime = NOW
) -> tuple[str, int, list[syncing.Item]]:
    generation = generation or s.overview("mira")[0]
    return s.merge("mira", "wishes", generation, items, if_match=None, now=now, skew=300)


def test_sync_merges_and_reads(store: SyncStore) -> None:
    generation, rev, kept = merge(store, [item("a"), item("b", {"x": [1, 2]})])
    assert rev == 2 and [i.rev for i in kept] == [1, 2]
    got = store.read("mira", "wishes", None)
    assert got[0] == generation and got[1] == 2
    assert [(i.key, i.value) for i in got[2]] == [("a", 1), ("b", {"x": [1, 2]})]
    assert [i.key for i in store.read("mira", "wishes", 1)[2]] == ["b"]


def test_sync_last_writer_wins(store: SyncStore) -> None:
    merge(store, [item("a", 1, "2026-11-07T11:00:00.000Z")])
    _, rev, kept = merge(store, [item("a", 0, "2026-11-07T10:00:00.000Z")])
    assert rev == 1 and kept[0].value == 1
    _, rev, kept = merge(store, [item("a", 2, "2026-11-07T11:30:00.000Z")])
    assert rev == 2 and kept[0].value == 2


def test_sync_keeps_deletions_for_a_reader_since(store: SyncStore) -> None:
    merge(store, [item("a"), item("b")])
    merge(store, [item("a", deleted=True, when="2026-11-07T11:30:00.000Z")])
    assert [i.key for i in store.read("mira", "wishes", None)[2]] == ["b"]
    since = store.read("mira", "wishes", 2)[2]
    assert [(i.key, i.deleted) for i in since] == [("a", True)]
    _, live = store.overview("mira")
    assert live["wishes"] == (3, 1)


def test_sync_refuses_a_revision_never_given(store: SyncStore) -> None:
    merge(store, [item("a")])
    with pytest.raises(ProblemError) as caught:
        store.read("mira", "wishes", 9)
    assert caught.value.status == 400


def test_sync_conflicts(store: SyncStore) -> None:
    generation, _, _ = merge(store, [item("a")])
    with pytest.raises(ProblemError) as caught:
        merge(store, [item("b")], generation="g_other")
    assert caught.value.status == 409
    with pytest.raises(ProblemError) as caught:
        store.merge("mira", "wishes", generation, [item("b")], if_match='"nope"', now=NOW, skew=300)
    assert caught.value.status == 412
    store.merge("mira", "wishes", generation, [item("b")], if_match=f'"{generation}-1"', now=NOW, skew=300)


def test_sync_limit(store: SyncStore) -> None:
    merge(store, [item("a"), item("b"), item("c")])
    with pytest.raises(ProblemError) as caught:
        merge(store, [item("d")])
    assert caught.value.status == 413
    merge(store, [item("a", 5, "2026-11-07T11:30:00.000Z")])


def test_sync_erase_changes_the_generation(store: SyncStore) -> None:
    generation, _, _ = merge(store, [item("a")])
    fresh = store.erase("mira", "wishes")
    assert fresh != generation and store.read("mira", "wishes", None)[2] == []
    merge(store, [item("a")], generation=fresh)
    again = store.erase("mira")
    assert again != fresh and store.overview("mira")[0] == again


def test_sync_forget(store: SyncStore) -> None:
    generation, _, _ = merge(store, [item("a")])
    store.forget("mira")
    fresh, overview = store.overview("mira")
    assert fresh != generation and overview["wishes"] == (0, 0)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_sync_drops_old_deletions_and_says_gone(kind: str, tmp_path: Path) -> None:
    retention = timedelta(days=-1)  # every deletion is already past it
    s: SyncStore = (
        MemorySync(retention=retention) if kind == "memory" else SqliteSync(tmp_path / "s.db", retention=retention)
    )
    try:
        generation, _, _ = merge(s, [item("a"), item("b")])
        merge(s, [item("a", deleted=True, when="2026-11-07T11:30:00.000Z")])
        s.merge("mira", "wishes", generation, [], if_match=None, now=NOW, skew=300)
        with pytest.raises(ProblemError) as caught:
            s.read("mira", "wishes", 0)
        assert caught.value.status == 410
        assert s.read("mira", "wishes", 3)[2] == []
    finally:
        if isinstance(s, SqliteSync):
            s.close()


def test_sync_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "sync.db"
    with SqliteSync(path) as first:
        generation, _, _ = merge(first, [item("a", {"k": "v"})])
    with SqliteSync(path) as again:
        got = again.read("mira", "wishes", None)
        assert got[0] == generation and got[1] == 1 and got[2][0].value == {"k": "v"}


def test_sync_limit_is_checked() -> None:
    with pytest.raises(ValueError):
        SqliteSync(":memory:", limit=0)


# Secrets.


def test_a_secret_is_drawn_once(tmp_path: Path) -> None:
    path = tmp_path / "config" / "secrets.json"
    first = SecretsFile(path).get("cursor")
    assert len(first) == 32 and SecretsFile(path).get("cursor") == first
    assert SecretsFile(path).get("grant") != first and len(SecretsFile(path).get("short", 16)) == 16
    assert SecretsFile(path).get("cursor") == first


@posix_only
def test_the_secrets_file_is_private(tmp_path: Path) -> None:
    SecretsFile(tmp_path / "s.json").get("cursor")
    assert stat.S_IMODE(os.stat(tmp_path / "s.json").st_mode) == 0o600


def test_a_secret_of_another_size_is_not_replaced(tmp_path: Path) -> None:
    vault = SecretsFile(tmp_path / "s.json")
    vault.get("grant", 32)
    with pytest.raises(ValueError):
        vault.get("grant", 16)


def test_unknown_keys_are_kept_and_a_newer_schema_is_left_alone(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"schema": 1, "future": True, "secrets": {}}))
    SecretsFile(path).get("cursor")
    assert json.loads(path.read_text())["future"] is True
    newer = tmp_path / "newer.json"
    text = json.dumps({"schema": 99, "secrets": {}})
    newer.write_text(text)
    with pytest.raises(SecretsSchemaError):
        SecretsFile(newer).get("cursor")
    assert newer.read_text() == text
