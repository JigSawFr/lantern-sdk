"""Errors: a server's problem+json answers (SPEC.md § 12), as exceptions by
status, and the client's own.

A server's answer becomes the class of its status (NotFound for 404, Gone for
410…), whatever its `code`: a code this library does not know is read by its
status alone, as SPEC.md § 12 asks. `code` is then None; `problem` keeps the
document as the server sent it.

    try:
        client.title("0100ABCD00010000")
    except lantern.NotFound:
        ...
    except lantern.ProblemError as e:
        print(e.status, e.code, e.detail)
"""

from __future__ import annotations

from collections.abc import Mapping

from lantern._base import DocumentError, LanternError
from lantern._generated.models import ERROR_CODES, Problem
from lantern.limits import load_json, printable

__all__ = [
    "AccountFrozen",
    "BadRequest",
    "Conflict",
    "DocumentError",
    "Forbidden",
    "Gone",
    "InsecureTransport",
    "IntegrityError",
    "LanternError",
    "NewerSchema",
    "NotFound",
    "ProblemError",
    "ServerError",
    "SlowDown",
    "TooLarge",
    "TransportError",
    "Unauthorized",
    "Unavailable",
    "UnexpectedResponse",
    "Unprocessable",
    "problem_error",
]

DETAIL_LIMIT = 512


class ProblemError(LanternError):
    """A server's error answer (SPEC.md § 12): its `status`, its `code` when
    this library knows it (None otherwise: act on the status), `detail` for
    people (bounded, without control characters), and `retry_after` in
    seconds when the server said."""

    def __init__(self, status: int, problem: Problem | None = None, headers: Mapping[str, str] | None = None) -> None:
        self.status = status
        self.problem = problem
        self.headers = dict(headers or {})
        raw = problem.code if problem is not None else None
        self.code: str | None = raw if raw in ERROR_CODES else None
        text = (problem.detail or problem.title) if problem is not None else None
        self.detail: str | None = printable(text, DETAIL_LIMIT) if text else None
        self.retry_after: int | None = _seconds(_header(self.headers, "Retry-After"))
        super().__init__(f"{status} {self.code or 'error'}" + (f": {self.detail}" if self.detail else ""))


class BadRequest(ProblemError):
    """400, and 405 and 416 (`bad_request`)."""


class Unauthorized(ProblemError):
    """401: no token where one is needed, or one the server does not take."""


class Forbidden(ProblemError):
    """403: a scope missing."""


class AccountFrozen(Forbidden):
    """403 `account_frozen`: the account may do nothing for now."""


class NotFound(ProblemError):
    """404."""


class Conflict(ProblemError):
    """409."""


class Gone(ProblemError):
    """410: an expired cursor or `since` token (read the list again from its start), or a file id."""


class TooLarge(ProblemError):
    """413."""


class Unprocessable(ProblemError):
    """422: `unsupported_schema` or `digest_mismatch`."""


class SlowDown(ProblemError):
    """429: wait `retry_after` seconds."""


class ServerError(ProblemError):
    """500, or another 5xx: the server failed; try again later."""


class Unavailable(ServerError):
    """503: scanning or maintenance; `retry_after` says when to come back."""


_BY_STATUS: dict[int, type[ProblemError]] = {
    400: BadRequest,
    401: Unauthorized,
    403: Forbidden,
    404: NotFound,
    405: BadRequest,
    409: Conflict,
    410: Gone,
    413: TooLarge,
    416: BadRequest,
    422: Unprocessable,
    429: SlowDown,
    500: ServerError,
    503: Unavailable,
}


class NewerSchema(LanternError):
    """A document of a newer `schema` than this library reads: by SPEC.md
    § 3.2 it is absent (the feature is unavailable), not an error of the
    server. The caller treats what it asked for as missing."""

    def __init__(self, what: str, schema: int) -> None:
        super().__init__(f"{what}: schema {schema}, newer than this library reads: treated as absent")
        self.what, self.schema = what, schema


class IntegrityError(LanternError):
    """A download that is not what its document says: its SHA-256 or its size
    (SPEC.md § 6.6), or a `Repr-Digest` that contradicts the document. Nothing
    of it may be installed."""


class TransportError(LanternError):
    """The connection failed, or the server's certificate was refused."""


class InsecureTransport(TransportError):
    """Plain HTTP to an address that is not a loopback one (SPEC.md § 2)."""


class UnexpectedResponse(LanternError):
    """An answer the protocol does not allow here: a redirect, an unexpected
    status or content type."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lower = name.lower()
    return next((v for k, v in headers.items() if k.lower() == lower), None)


def _seconds(value: str | None) -> int | None:
    if value is None or not value.strip().isdigit():
        return None
    return int(value.strip())


def problem_error(status: int, body: bytes, headers: Mapping[str, str] | None = None) -> ProblemError:
    """The exception for an error answer: its class by status, its problem
    document when the body is one (an unreadable body still gives the status)."""
    problem: Problem | None = None
    try:
        problem = Problem.from_json(load_json(body, limit=1 << 16, where="problem"), "problem")
    except DocumentError:
        problem = None
    cls = _BY_STATUS.get(status) or (ServerError if status >= 500 else ProblemError)
    if cls is Forbidden and problem is not None and problem.code == "account_frozen":
        cls = AccountFrozen
    return cls(status, problem, headers)
