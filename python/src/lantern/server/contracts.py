"""The contracts of the stores a server plugs into LanternApp, as checks a server runs against its own.

A server that keeps its accounts, requests, change log, sync data or file hashes in its own database writes an
`Accounts`, a `RequestStore`, a `ChangeLog`, a `SyncStore` or an `IndexStore` (SPEC.md § 5.5, § 5.7, § 6.4, § 11,
§ 20). Each check here takes a fresh, empty store and fails with an AssertionError when the store does not behave as
the toolkit's own do, which it relies on (a SyncStore is made with `limit=3`, a ChangeLog with `keep=3`):

    @pytest.mark.parametrize("check", ACCOUNTS_CONTRACT)
    def test_my_accounts(check, tmp_path):
        check(MyAccounts(tmp_path))

or, without pytest, `run_contract(ACCOUNTS_CONTRACT, lambda: MyAccounts(...))`. The checks write only what they
create, with the names `lea` and `ada`, so they need an empty store.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from lantern import sync as syncing
from lantern.models import RatingCap
from lantern.server.accounts import AccountError, Accounts, token_hash, typed_code
from lantern.server.file_index import Entry, IndexStore
from lantern.server.http import ProblemError
from lantern.server.library import ChangeLog
from lantern.server.sync import SyncStore
from lantern.server.title_requests import RequestStore, StoredRequest

S = TypeVar("S")


def run_contract(checks: Sequence[Callable[[S], None]], make: Callable[[], S]) -> None:
    """Every check of a contract, each on a store `make` gives anew."""
    for check in checks:
        check(make())


def _later(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _refused(status: int, call: Callable[[], object]) -> None:
    """`call` fails with AccountError `status`."""
    try:
        call()
    except AccountError as e:
        assert e.status == status, f"expected {status}, got {e.status}"
    else:
        raise AssertionError(f"expected AccountError {status}")


# Accounts.


def users(accounts: Accounts) -> None:
    created = accounts.create_user("lea", ["saves", "library"])
    assert created.scopes == ("library", "saves")  # in the handshake's order
    assert accounts.user("lea") == created and accounts.user("nobody") is None
    accounts.create_user("ada", ["library"])
    assert [u.name for u in accounts.users()] == ["ada", "lea"]
    _refused(409, lambda: accounts.create_user("lea", ["library"]))
    for bad in ("", "a b", "x" * 65, "é"):
        _refused(400, functools.partial(accounts.create_user, bad, ["library"]))


def updating_an_account_cuts_its_devices_back(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library", "saves", "cheats"])
    _, device = accounts.issue("lea", "console", ["library", "saves", "cheats"])
    frozen = accounts.update_user("lea", state="frozen")
    assert frozen.state == "frozen" and frozen.scopes == ("library", "saves", "cheats")
    assert accounts.user("lea") == frozen
    accounts.update_user("lea", scopes=["library"])
    assert accounts.devices("lea")[0].scopes == ("library",) and accounts.devices("lea")[0].id == device.id
    _refused(404, lambda: accounts.update_user("nobody", state="frozen"))


def an_account_has_a_rating_cap(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library"])
    fresh = accounts.user("lea")
    assert fresh is not None and fresh.rating_cap is None
    capped = accounts.update_user("lea", rating_cap=RatingCap(age=7, unrated="hide"))
    assert capped.rating_cap is not None and capped.rating_cap.age == 7 and capped.rating_cap.unrated == "hide"
    kept = accounts.update_user("lea", state="frozen")  # not named: left as it is
    assert kept.rating_cap == capped.rating_cap and kept.state == "frozen"
    stored = accounts.user("lea")
    assert stored is not None and stored.rating_cap == capped.rating_cap
    cleared = accounts.update_user("lea", rating_cap=None)
    assert cleared.rating_cap is None and cleared.state == "frozen"
    assert accounts.create_user("ada", ["library"]).rating_cap is None
    _refused(404, lambda: accounts.update_user("nobody", rating_cap=RatingCap(age=7)))


def changing_a_device(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library", "saves", "cheats"])
    accounts.create_user("ada", ["library"])
    token, device = accounts.issue("lea", "console", ["library", "saves"], key=b"k" * 32, rating_cap=RatingCap(age=12))
    _, other = accounts.issue("ada", "other", ["library"])
    assert device.suspended is False
    renamed = accounts.update_device(device.id, device="Salon")
    assert renamed.device == "Salon" and renamed.scopes == ("library", "saves") and renamed.suspended is False
    held = accounts.update_device(device.id, suspended=True)
    assert held.suspended is True and held.device == "Salon"
    found = accounts.device_of(token)  # still paired: the token, its key and its id are the same
    assert found is not None and found.suspended is True and found.id == device.id and found.key == b"k" * 32
    assert found.rating_cap is not None and found.rating_cap.age == 12
    cut = accounts.update_device(device.id, scopes=["library", "cheats"])  # only what it has, never more
    assert cut.scopes == ("library",)
    recapped = accounts.update_device(device.id, rating_cap=RatingCap(age=7))
    assert recapped.rating_cap is not None and recapped.rating_cap.age == 7
    assert accounts.update_device(device.id, rating_cap=None).rating_cap is None
    lifted = accounts.update_device(device.id, suspended=False)
    assert lifted.suspended is False and lifted.scopes == ("library",) and lifted.device == "Salon"
    assert [d.device for d in accounts.devices("ada")] == ["other"] and accounts.devices("ada")[0].id == other.id
    _refused(404, lambda: accounts.update_device("d_0000000000000000", device="x"))
    assert accounts.revoke(device.id) is True
    _refused(404, lambda: accounts.update_device(device.id, suspended=True))


def deleting_an_account_takes_its_devices_and_invitations(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library"])
    accounts.create_user("ada", ["library"])
    token, _ = accounts.issue("lea", "console", ["library"])
    accounts.issue("ada", "other", ["library"])
    mine = accounts.create_invitation("lea", ["library"], _later(3600), 2)
    accounts.create_invitation("ada", ["library"], _later(3600), 2)
    accounts.delete_user("lea")
    assert accounts.user("lea") is None and accounts.device_of(token) is None
    assert [d.user for d in accounts.devices()] == ["ada"]
    assert accounts.redeem(mine.code) is None and [i.user for i in accounts.invitations()] == ["ada"]
    _refused(404, lambda: accounts.delete_user("lea"))


def tokens(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library", "saves"])
    cap = RatingCap(age=12)
    token, device = accounts.issue("lea", "console", ["saves", "library"], key=b"k" * 32, rating_cap=cap)
    assert device.token_hash == token_hash(token) and device.id.startswith("d_") and device.bound
    found = accounts.device_of(token)
    assert found is not None and found.scopes == ("library", "saves") and found.key == b"k" * 32
    assert found.rating_cap is not None and found.rating_cap.age == 12
    assert accounts.device_of(token + "x") is None
    assert accounts.revoke(device.id) is True and accounts.revoke(device.id) is False
    assert accounts.device_of(token) is None


def a_token_expires(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library"])
    live, _ = accounts.issue("lea", "console", ["library"], lifetime=3600)
    dead, record = accounts.issue("lea", "old", ["library"], lifetime=-3600)
    assert accounts.device_of(live) is not None and accounts.device_of(dead) is None
    assert record.id not in [d.id for d in accounts.devices()]


def invitations(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library"])
    cap = RatingCap(age=7)
    inv = accounts.create_invitation("lea", ["library"], _later(3600), 2, rating_cap=cap, note="for Sam")
    assert len(inv.code.replace("-", "")) == 16 and inv.note == "for Sam"
    assert [i.id for i in accounts.invitations()] == [inv.id]
    first = accounts.redeem(" " + inv.code.lower().replace("-", " ") + " ")  # as a person typed it
    assert first is not None and first.used == 1 and first.rating_cap is not None and first.rating_cap.age == 7
    second = accounts.redeem(inv.code)
    assert second is not None and second.used == 2
    assert accounts.redeem(inv.code) is None  # two devices, used up
    assert accounts.invitations() == []
    assert accounts.redeem("AAAA-BBBB-CCCC-DDDD") is None


def an_expired_invitation_is_not_redeemed(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library"])
    inv = accounts.create_invitation("lea", ["library"], _later(-1), 1)
    assert accounts.redeem(inv.code) is None and accounts.invitations() == []


def revoking_an_invitation(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library"])
    inv = accounts.create_invitation("lea", ["library"], _later(3600), 1)
    assert accounts.revoke_invitation(inv.id) is True and accounts.revoke_invitation(inv.id) is False
    assert accounts.redeem(inv.code) is None


def codes_are_distinct(accounts: Accounts) -> None:
    accounts.create_user("lea", ["library"])
    codes = {typed_code(accounts.create_invitation("lea", ["library"], _later(3600), 1).code) for _ in range(50)}
    assert len(codes) == 50


ACCOUNTS_CONTRACT: tuple[Callable[[Accounts], None], ...] = (
    users,
    updating_an_account_cuts_its_devices_back,
    an_account_has_a_rating_cap,
    changing_a_device,
    deleting_an_account_takes_its_devices_and_invitations,
    tokens,
    a_token_expires,
    invitations,
    an_expired_invitation_is_not_redeemed,
    revoking_an_invitation,
    codes_are_distinct,
)


# Requests.


def _request(rid: str, user: str, title: str = "0100000000010000") -> StoredRequest:
    return StoredRequest(id=rid, user=user, platform="switch", title_id=title, status="open", created=_later(0))


def requests_are_kept_per_account(store: RequestStore) -> None:
    store.add(_request("r_1", "lea"))
    store.add(_request("r_2", "ada", "0100000000020000"))
    assert [r.id for r in store.requests("lea")] == ["r_1"]
    assert sorted(r.id for r in store.requests()) == ["r_1", "r_2"]
    assert store.requests("nobody") == []


def a_request_changes_status(store: RequestStore) -> None:
    store.add(_request("r_1", "lea"))
    done = store.set_status("r_1", "declined", reason="not for sale", updated="2026-11-07T10:00:00Z")
    assert done is not None and done.status == "declined" and done.reason == "not for sale"
    assert done.updated == "2026-11-07T10:00:00Z" and done.user == "lea" and done.title_id == "0100000000010000"
    assert store.requests("lea")[0].status == "declined"
    assert store.set_status("r_missing", "done") is None


def a_request_is_removed_by_its_owner_only(store: RequestStore) -> None:
    store.add(_request("r_1", "lea"))
    assert store.remove("ada", "r_1") is None and len(store.requests()) == 1
    removed = store.remove("lea", "r_1")
    assert removed is not None and removed.id == "r_1" and store.requests() == []
    assert store.remove("lea", "r_1") is None


def forgetting_an_account(store: RequestStore) -> None:
    store.add(_request("r_1", "lea"))
    store.add(_request("r_2", "lea", "0100000000020000"))
    store.add(_request("r_3", "ada", "0100000000030000"))
    store.forget("lea")
    assert [r.id for r in store.requests()] == ["r_3"]
    store.forget("lea")  # nothing left: no error


REQUESTS_CONTRACT: tuple[Callable[[RequestStore], None], ...] = (
    requests_are_kept_per_account,
    a_request_changes_status,
    a_request_is_removed_by_its_owner_only,
    forgetting_an_account,
)

# Change log (made with keep=3).


def a_log_records_and_answers(log: ChangeLog) -> None:
    log.record("added", "a1", "switch")
    log.record("title", "switch/0100", "switch")
    log.record("added", "a2", "ps5")
    assert log.seq == 3 and log.floor == 0
    assert log.since(0, ("added",), None) == [("added", "a1"), ("added", "a2")]
    assert log.since(0, ("added", "title"), "switch") == [("added", "a1"), ("title", "switch/0100")]
    assert log.since(1, ("added",), None) == [("added", "a2")]


def a_log_forgets_the_oldest(log: ChangeLog) -> None:
    for n in range(5):
        log.record("added", f"a{n}", "switch")
    assert log.seq == 5 and log.floor == 2
    assert [k for _, k in log.since(0, ("added",), None)] == ["a2", "a3", "a4"]


CHANGELOG_CONTRACT: tuple[Callable[[ChangeLog], None], ...] = (a_log_records_and_answers, a_log_forgets_the_oldest)


# Sync (made with limit=3).

_NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


def _item(key: str, value: object = 1, when: str = "2026-11-07T11:00:00.000Z", deleted: bool = False) -> syncing.Item:
    return syncing.Item(key, when, None if deleted else value, deleted)  # type: ignore[arg-type]


def _merge(
    store: SyncStore, items: list[syncing.Item], generation: str | None = None
) -> tuple[str, int, list[syncing.Item]]:
    generation = generation or store.overview("mira")[0]
    return store.merge("mira", "wishes", generation, items, if_match=None, now=_NOW, skew=300)


def _problem(status: int, call: Callable[[], object]) -> None:
    try:
        call()
    except ProblemError as e:
        assert e.status == status, f"expected {status}, got {e.status}"
    else:
        raise AssertionError(f"expected ProblemError {status}")


def sync_merges_and_reads(store: SyncStore) -> None:
    generation, rev, kept = _merge(store, [_item("a"), _item("b", {"x": [1, 2]})])
    assert rev == 2 and [i.rev for i in kept] == [1, 2]
    got = store.read("mira", "wishes", None)
    assert got[0] == generation and got[1] == 2
    assert [(i.key, i.value) for i in got[2]] == [("a", 1), ("b", {"x": [1, 2]})]
    assert [i.key for i in store.read("mira", "wishes", 1)[2]] == ["b"]


def sync_last_writer_wins(store: SyncStore) -> None:
    _merge(store, [_item("a", 1, "2026-11-07T11:00:00.000Z")])
    _, rev, kept = _merge(store, [_item("a", 0, "2026-11-07T10:00:00.000Z")])
    assert rev == 1 and kept[0].value == 1
    _, rev, kept = _merge(store, [_item("a", 2, "2026-11-07T11:30:00.000Z")])
    assert rev == 2 and kept[0].value == 2


def sync_keeps_deletions_for_a_reader_since(store: SyncStore) -> None:
    _merge(store, [_item("a"), _item("b")])
    _merge(store, [_item("a", deleted=True, when="2026-11-07T11:30:00.000Z")])
    assert [i.key for i in store.read("mira", "wishes", None)[2]] == ["b"]
    since = store.read("mira", "wishes", 2)[2]
    assert [(i.key, i.deleted) for i in since] == [("a", True)]
    assert store.overview("mira")[1]["wishes"] == (3, 1)


def sync_refuses_a_revision_never_given(store: SyncStore) -> None:
    _merge(store, [_item("a")])
    _problem(400, lambda: store.read("mira", "wishes", 9))


def sync_conflicts(store: SyncStore) -> None:
    generation, _, _ = _merge(store, [_item("a")])
    _problem(409, lambda: _merge(store, [_item("b")], generation="g_other"))
    _problem(
        412,
        lambda: store.merge("mira", "wishes", generation, [_item("b")], if_match='"nope"', now=_NOW, skew=300),
    )
    store.merge("mira", "wishes", generation, [_item("b")], if_match=f'"{generation}-1"', now=_NOW, skew=300)


def sync_limit(store: SyncStore) -> None:
    _merge(store, [_item("a"), _item("b"), _item("c")])
    _problem(413, lambda: _merge(store, [_item("d")]))
    _merge(store, [_item("a", 5, "2026-11-07T11:30:00.000Z")])


def sync_erase_changes_the_generation(store: SyncStore) -> None:
    generation, _, _ = _merge(store, [_item("a")])
    fresh = store.erase("mira", "wishes")
    assert fresh != generation and store.read("mira", "wishes", None)[2] == []
    _merge(store, [_item("a")], generation=fresh)
    again = store.erase("mira")
    assert again != fresh and store.overview("mira")[0] == again


def sync_forget(store: SyncStore) -> None:
    generation, _, _ = _merge(store, [_item("a")])
    store.forget("mira")
    fresh, overview = store.overview("mira")
    assert fresh != generation and overview["wishes"] == (0, 0)


SYNC_CONTRACT: tuple[Callable[[SyncStore], None], ...] = (
    sync_merges_and_reads,
    sync_last_writer_wins,
    sync_keeps_deletions_for_a_reader_since,
    sync_refuses_a_revision_never_given,
    sync_conflicts,
    sync_limit,
    sync_erase_changes_the_generation,
    sync_forget,
)


# File hashes.


def the_index_adds_changes_and_removes(index: IndexStore) -> None:
    assert index.sync("s", [Entry("a", 1, 10), Entry("b", 2, 10)]).added == 2
    [first] = index.pending(1)
    index.set_hash(first, "h")
    result = index.sync("s", [Entry("a", 1, 10), Entry("b", 3, 11), Entry("c", 1, 1)])
    assert (result.added, result.changed, result.removed) == (1, 1, 0)
    result = index.sync("s", [Entry("c", 1, 1)])
    assert result.removed == 2 and [r.path for r in index.rows()] == ["c"]


def the_queue_is_priority_then_smallest(index: IndexStore) -> None:
    index.sync(
        "s", [Entry("dlc", 1, 1, 2), Entry("big-base", 9, 1, 0), Entry("small-base", 2, 1, 0), Entry("up", 5, 1, 1)]
    )
    assert [r.path for r in index.pending()] == ["small-base", "big-base", "up", "dlc"]
    assert [r.path for r in index.pending(2)] == ["small-base", "big-base"]
    assert index.pending(10, ["other"]) == []


def a_hash_is_recorded_only_under_its_validators(index: IndexStore) -> None:
    index.sync("s", [Entry("a", 1, 10)])
    [row] = index.pending()
    index.sync("s", [Entry("a", 1, 11)])  # changed meanwhile
    assert index.set_hash(row, "h") is False
    assert index.hashed() == [] and index.counts() == {"hashed": 0, "pending": 1}
    [row] = index.pending()
    assert index.set_hash(row, "h") is True
    assert [r.sha256 for r in index.hashed("s")] == ["h"] and index.pending_bytes() == 0


def rehashing_queues_files_first(index: IndexStore) -> None:
    index.sync("s", [Entry("a", 1, 1), Entry("b", 2, 1)])
    for row in index.pending():
        index.set_hash(row, "h")
    assert index.rehash_files([("s", "b"), ("s", "missing")]) == 1
    assert [r.path for r in index.pending()] == ["b"] and index.counts() == {"hashed": 1, "pending": 1}


INDEX_CONTRACT: tuple[Callable[[IndexStore], None], ...] = (
    the_index_adds_changes_and_removes,
    the_queue_is_priority_then_smallest,
    a_hash_is_recorded_only_under_its_validators,
    rehashing_queues_files_first,
)

__all__ = [
    "ACCOUNTS_CONTRACT",
    "CHANGELOG_CONTRACT",
    "INDEX_CONTRACT",
    "REQUESTS_CONTRACT",
    "SYNC_CONTRACT",
    "run_contract",
]
