"""What every other module of the library builds on: the JSON value type and
the error of a document that cannot be read."""

from __future__ import annotations

from typing import TypeAlias

JSONValue: TypeAlias = "None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]"
JSONObject: TypeAlias = "dict[str, JSONValue]"

#: The `schema` this library reads and writes, for every family (SPEC.md § 3.2).
SCHEMA = 1


class LanternError(Exception):
    """Every error this library raises."""


class DocumentError(LanternError, ValueError):
    """A document that breaks the specification: malformed JSON, a missing
    field, a field of the wrong type, or one beyond the limits of SPEC.md § 13.
    `where` says which field, as a path (`homebrew.package.manifest[2].path`)."""

    def __init__(self, message: str, where: str = "") -> None:
        super().__init__(f"{where}: {message}" if where else message)
        self.where = where
        self.reason = message
