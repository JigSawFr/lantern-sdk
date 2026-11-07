"""The contracts of the stores a server plugs into LanternApp, as checks a server runs against its own.

A server that keeps its accounts or its requests in its own database writes an `Accounts` or a `RequestStore`
(SPEC.md § 5.5, § 5.7, § 11). Each check here takes a fresh, empty store and fails with an AssertionError when the
store does not behave as MemoryAccounts and MemoryRequests do, which the toolkit relies on:

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

from lantern.models import RatingCap
from lantern.server.accounts import AccountError, Accounts, token_hash, typed_code
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

__all__ = ["ACCOUNTS_CONTRACT", "REQUESTS_CONTRACT", "run_contract"]
