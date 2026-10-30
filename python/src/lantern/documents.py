"""Reading a document by the `schema` rule (SPEC.md § 3.2): a document of a
newer `schema` than the reader knows is absent, not an error, and is never
written back; the fields a reader does not know are kept in each model's
`extra`, so that a document written back loses none of them."""

from __future__ import annotations

from typing import Protocol, Self, TypeVar

from lantern._base import SCHEMA, DocumentError, JSONObject, JSONValue
from lantern.limits import load_json


class Model(Protocol):
    @classmethod
    def from_json(cls, data: JSONValue, where: str = ...) -> Self: ...

    def to_json(self) -> JSONObject: ...


M = TypeVar("M", bound=Model)


def schema_of(data: JSONValue, where: str = "document") -> int:
    """A document's `schema`: an integer, 1 or more; DocumentError otherwise."""
    if not isinstance(data, dict):
        raise DocumentError("not an object", where)
    value = data.get("schema")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise DocumentError("no integer schema", where)
    return value


def is_newer(data: JSONValue, known: int = SCHEMA) -> bool:
    """Whether a document's `schema` is above what the reader knows."""
    return schema_of(data) > known


def read(model: type[M], data: JSONValue, *, known: int = SCHEMA, where: str | None = None) -> M | None:
    """`data` as a `model`, or None when its `schema` is newer than `known`
    (the document is absent: SPEC.md § 3.2). DocumentError when it is not one."""
    name = where or model.__name__
    if schema_of(data, name) > known:
        return None
    return model.from_json(data, name)


def parse(model: type[M], raw: bytes, *, known: int = SCHEMA, where: str | None = None) -> M | None:
    """read() of a JSON document's bytes, within SPEC.md § 13's limits."""
    name = where or model.__name__
    return read(model, load_json(raw, where=name), known=known, where=name)
