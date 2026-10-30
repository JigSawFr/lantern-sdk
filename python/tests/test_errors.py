"""Errors: a server's problem+json answers read by their status (SPEC.md § 12)."""

from __future__ import annotations

import json

import pytest

from lantern import errors


def body(**fields: object) -> bytes:
    return json.dumps({"schema": 1, **fields}).encode()


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (400, errors.BadRequest),
        (401, errors.Unauthorized),
        (403, errors.Forbidden),
        (404, errors.NotFound),
        (405, errors.BadRequest),
        (409, errors.Conflict),
        (410, errors.Gone),
        (413, errors.TooLarge),
        (416, errors.BadRequest),
        (422, errors.Unprocessable),
        (429, errors.SlowDown),
        (500, errors.ServerError),
        (502, errors.ServerError),
        (503, errors.Unavailable),
        (418, errors.ProblemError),
    ],
)
def test_class_by_status(status: int, cls: type) -> None:
    e = errors.problem_error(status, body(status=status, code="bad_request"))
    assert type(e) is cls and e.status == status


def test_an_unknown_code_is_read_by_its_status() -> None:
    e = errors.problem_error(410, body(status=410, code="cursor_moved_to_the_moon", detail="Read again."))
    assert isinstance(e, errors.Gone) and e.code is None and e.detail == "Read again."
    assert e.problem is not None and e.problem.code == "cursor_moved_to_the_moon"


def test_account_frozen_and_retry_after() -> None:
    e = errors.problem_error(
        403, body(status=403, code="account_frozen", detail="Paused\x1b until Sunday."), {"retry-after": "120"}
    )
    assert isinstance(e, errors.AccountFrozen) and isinstance(e, errors.Forbidden)
    assert e.code == "account_frozen" and e.detail == "Paused until Sunday." and e.retry_after == 120
    assert errors.problem_error(503, b"", {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}).retry_after is None


@pytest.mark.parametrize("raw", [b"", b"<html>oops</html>", b'{"schema": 1}', b"[1]"])
def test_an_unreadable_body_still_gives_the_status(raw: bytes) -> None:
    e = errors.problem_error(404, raw)
    assert isinstance(e, errors.NotFound) and e.code is None and e.problem is None


def test_detail_is_bounded() -> None:
    e = errors.problem_error(400, body(status=400, code="bad_request", detail="x" * 4000))
    assert e.detail is not None and len(e.detail) == errors.DETAIL_LIMIT
