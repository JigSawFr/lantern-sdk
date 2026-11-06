"""A server's `uid` (SPEC.md § 4.2, L-4.2-9): a random UUID of version 4 or 7 (RFC 9562), in lower case.
Never a version 1 or 6, which carry a hardware address: § 1 keeps those out."""

from __future__ import annotations

import re
import uuid

__all__ = ["check_uid", "is_valid_uid", "new_uid"]

_UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def is_valid_uid(value: object) -> bool:
    """Whether `value` is a lower-case UUID of version 4 or 7, variant RFC 9562."""
    return isinstance(value, str) and _UID.fullmatch(value) is not None


def check_uid(value: object) -> str:
    """`value` when it is a valid uid; ValueError otherwise."""
    if not isinstance(value, str) or not is_valid_uid(value):
        raise ValueError(
            "uid is a random UUID of version 4 or 7 in lower case (SPEC.md § 4.2), never from a hardware address"
        )
    return value


def new_uid() -> str:
    """A fresh random uid (UUID version 4)."""
    return str(uuid.uuid4())
