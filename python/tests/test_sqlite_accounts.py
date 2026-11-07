"""SqliteAccounts against the contract MemoryAccounts sets, then what only a file adds: it survives a
restart, keeps no token, is private, refuses a newer schema and leaves what it does not know alone."""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from demo import DEMO_KEY, DEMO_TOKEN, EVERY_SCOPE, build_library, make_lantern
from lantern import schema
from lantern.models import RatingCap
from lantern.server import Accounts, AccountsSchemaError, MemoryAccounts, SqliteAccounts
from lantern.server.contracts import ACCOUNTS_CONTRACT
from test_server_auth import BASE, call, doc, mira


@pytest.fixture(params=["memory", "sqlite"])
def accounts(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Accounts]:
    if request.param == "memory":
        yield MemoryAccounts()
    else:
        store = SqliteAccounts(tmp_path / "accounts.sqlite3")
        yield store
        store.close()


def later(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


# The contract, for both stores: the one the toolkit publishes for servers' own stores.


@pytest.mark.parametrize("check", ACCOUNTS_CONTRACT, ids=lambda c: c.__name__)
def test_the_contract(accounts: Accounts, check: Callable[[Accounts], None]) -> None:
    check(accounts)


# What a file adds.


def test_it_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "accounts.sqlite3"
    first = SqliteAccounts(path)
    first.create_user("lea", ["library", "saves"])
    token, device = first.issue("lea", "console", ["library"], key=b"k" * 32, rating_cap=RatingCap(age=12))
    inv = first.create_invitation("lea", ["library"], later(3600), 2, note="n")
    first.redeem(inv.code)
    first.close()

    second = SqliteAccounts(path)
    assert second.user("lea") is not None
    found = second.device_of(token)
    assert found == device
    assert [(i.id, i.used) for i in second.invitations()] == [(inv.id, 1)]
    second.close()


def test_the_token_itself_is_not_kept(tmp_path: Path) -> None:
    path = tmp_path / "accounts.sqlite3"
    store = SqliteAccounts(path)
    store.create_user("lea", ["library"])
    token, _ = store.issue("lea", "console", ["library"])
    store.close()
    assert token.encode() not in b"".join(p.read_bytes() for p in tmp_path.iterdir())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_the_file_is_private(tmp_path: Path) -> None:
    path = tmp_path / "accounts.sqlite3"
    store = SqliteAccounts(path)
    store.create_user("lea", ["library"])
    store.close()
    assert path.stat().st_mode & 0o777 == 0o600
    for extra in tmp_path.iterdir():
        assert extra.stat().st_mode & 0o077 == 0, extra.name


def test_an_existing_file_keeps_its_mode(tmp_path: Path) -> None:
    path = tmp_path / "accounts.sqlite3"
    path.touch()
    if sys.platform != "win32":
        os.chmod(path, 0o640)
    SqliteAccounts(path).close()
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o640


def test_a_newer_schema_is_refused_and_left_alone(tmp_path: Path) -> None:
    path = tmp_path / "accounts.sqlite3"
    store = SqliteAccounts(path)
    store.create_user("lea", ["library"])
    store.close()
    raw = sqlite3.connect(path)
    raw.execute("PRAGMA user_version = 99")
    raw.commit()
    raw.close()
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(AccountsSchemaError):
        SqliteAccounts(path).close()
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_what_it_does_not_know_is_left_alone(tmp_path: Path) -> None:
    path = tmp_path / "accounts.sqlite3"
    store = SqliteAccounts(path)
    store.create_user("lea", ["library"])
    store.close()
    raw = sqlite3.connect(path)
    raw.execute("ALTER TABLE users ADD COLUMN nickname TEXT")
    raw.execute("UPDATE users SET nickname = 'Le' WHERE name = 'lea'")
    raw.execute("CREATE TABLE audit (what TEXT)")
    raw.commit()
    raw.close()
    store = SqliteAccounts(path)
    assert store.user("lea") is not None
    store.update_user("lea", state="frozen")
    store.create_user("ada", ["library"])
    store.close()
    raw = sqlite3.connect(path)
    assert raw.execute("SELECT nickname FROM users WHERE name = 'lea'").fetchone() == ("Le",)
    assert raw.execute("SELECT count(*) FROM audit").fetchone() == (0,)
    raw.close()


def test_several_threads_at_once(tmp_path: Path) -> None:
    store = SqliteAccounts(tmp_path / "accounts.sqlite3")
    store.create_user("lea", ["library"])
    failures: list[BaseException] = []

    def work() -> None:
        try:
            for _ in range(25):
                token, _ = store.issue("lea", "console", ["library"])
                assert store.device_of(token) is not None
        except BaseException as error:
            failures.append(error)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert failures == [] and len(store.devices("lea")) == 200
    store.close()


def test_two_stores_on_one_file_see_each_other(tmp_path: Path) -> None:
    path = tmp_path / "accounts.sqlite3"
    with SqliteAccounts(path) as one, SqliteAccounts(path) as two:
        one.create_user("lea", ["library"])
        token, _ = one.issue("lea", "console", ["library"])
        assert two.user("lea") is not None and two.device_of(token) is not None


def test_an_in_memory_database(tmp_path: Path) -> None:
    with SqliteAccounts(":memory:") as store:
        store.create_user("lea", ["library"])
        assert store.user("lea") is not None


def test_a_failed_change_leaves_nothing(tmp_path: Path) -> None:
    store = SqliteAccounts(tmp_path / "accounts.sqlite3")
    with pytest.raises(sqlite3.IntegrityError):
        store.issue("nobody", "console", ["library"])  # the account is not there: a foreign key refuses it
    assert store.devices() == []
    store.create_user("lea", ["library"])  # and the store still works
    store.close()


# Through the toolkit: pairing's token and the administration API over the file, across a restart.


def test_the_administration_api_over_a_file(tmp_path: Path) -> None:
    path = tmp_path / "accounts.sqlite3"

    def serve() -> SqliteAccounts:
        store = SqliteAccounts(path)
        if store.user("mira") is None:
            store.create_user("mira", EVERY_SCOPE)
            store.add_token(DEMO_TOKEN, "mira", "Mira's console", EVERY_SCOPE, key=DEMO_KEY.public)
        return store

    with serve() as first:
        app = make_lantern(build_library(), accounts=first)
        made = mira(app, "POST", BASE + "/admin/users", body={"schema": 1, "name": "ines", "scopes": ["library"]})
        assert made.status == 201

    with serve() as second:  # a new process, the same file
        restarted = make_lantern(build_library(), accounts=second)
        users = doc(mira(restarted, "GET", BASE + "/admin/users"))
        assert schema.validate("admin-users", users) == []
        assert sorted(u["name"] for u in users["items"]) == ["ines", "mira"]
        assert call(restarted, "GET", BASE + "/admin/users").status == 401  # still no anonymous access
