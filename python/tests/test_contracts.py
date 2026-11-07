"""The contracts the toolkit publishes for a server's own stores, against the stores it ships, and against
stores that break them."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from lantern.server import MemoryAccounts, MemoryRequests
from lantern.server.accounts import Accounts
from lantern.server.contracts import ACCOUNTS_CONTRACT, REQUESTS_CONTRACT, run_contract
from lantern.server.title_requests import RequestStore, StoredRequest


@pytest.mark.parametrize("check", ACCOUNTS_CONTRACT, ids=lambda c: c.__name__)
def test_memory_accounts(check: Callable[[Accounts], None]) -> None:
    check(MemoryAccounts())


@pytest.mark.parametrize("check", REQUESTS_CONTRACT, ids=lambda c: c.__name__)
def test_memory_requests(check: Callable[[RequestStore], None]) -> None:
    check(MemoryRequests())


def test_run_contract_runs_every_check_on_a_fresh_store() -> None:
    made: list[MemoryRequests] = []

    def make() -> MemoryRequests:
        made.append(MemoryRequests())
        return made[-1]

    run_contract(REQUESTS_CONTRACT, make)
    assert len(made) == len(REQUESTS_CONTRACT)


class LeakyRequests(MemoryRequests):
    """A store that lets anyone remove a request: the contract must catch it."""

    def remove(self, user: str, request_id: str) -> StoredRequest | None:
        return self._requests.pop(request_id, None)


def test_a_store_that_breaks_the_contract_fails_it() -> None:
    with pytest.raises(AssertionError):
        run_contract(REQUESTS_CONTRACT, LeakyRequests)


class StubbornAccounts(MemoryAccounts):
    """A store whose revoked tokens still work."""

    def revoke(self, device_id: str) -> bool:
        return any(d.id == device_id for d in self.devices())


def test_accounts_that_keep_a_revoked_token_fail_the_contract() -> None:
    with pytest.raises(AssertionError):
        run_contract(ACCOUNTS_CONTRACT, StubbornAccounts)
