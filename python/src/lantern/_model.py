"""The small readers the generated models (`lantern._generated.models`) are
made of. A model keeps the fields it does not know (`extra`) so that a
document read and written back loses nothing (SPEC.md § 3.2)."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import TypeVar

from lantern._base import DocumentError, JSONObject, JSONValue

T = TypeVar("T")


def obj(data: JSONValue, where: str) -> JSONObject:
    if not isinstance(data, dict):
        raise DocumentError("not an object", where)
    return data


def _get(o: JSONObject, key: str, where: str) -> JSONValue:
    if key not in o:
        raise DocumentError(f"no {key}", where)
    return o[key]


def as_str(value: JSONValue, where: str) -> str:
    if not isinstance(value, str):
        raise DocumentError("not a string", where)
    return value


def as_int(value: JSONValue, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise DocumentError("not an integer", where)
    return value


def as_bool(value: JSONValue, where: str) -> bool:
    if not isinstance(value, bool):
        raise DocumentError("not true or false", where)
    return value


def as_any(value: JSONValue, where: str) -> JSONValue:
    return value


def as_list(value: JSONValue, where: str, item: Callable[[JSONValue, str], T]) -> list[T]:
    if not isinstance(value, list):
        raise DocumentError("not a list", where)
    return [item(v, f"{where}[{i}]") for i, v in enumerate(value)]


def as_map(value: JSONValue, where: str, item: Callable[[JSONValue, str], T]) -> dict[str, T]:
    o = obj(value, where)
    return {k: item(v, f"{where}.{k}") for k, v in o.items()}


def nullable(read: Callable[[JSONValue, str], T]) -> Callable[[JSONValue, str], T | None]:
    def reader(value: JSONValue, where: str) -> T | None:
        return None if value is None else read(value, where)

    return reader


def req(o: JSONObject, key: str, where: str, read: Callable[[JSONValue, str], T]) -> T:
    return read(_get(o, key, where), f"{where}.{key}")


def opt(o: JSONObject, key: str, where: str, read: Callable[[JSONValue, str], T]) -> T | None:
    """An optional field: None when absent. A field present as null is read as absent too."""
    value = o.get(key)
    return None if value is None else read(value, f"{where}.{key}")


def nulls(o: JSONObject, keys: tuple[str, ...]) -> frozenset[str]:
    """The optional fields of `keys` given as null, so that they are written back as null."""
    return frozenset(k for k in keys if k in o and o[k] is None)


def extras(o: JSONObject, known: frozenset[str]) -> JSONObject:
    """The fields a model does not know, kept as they are."""
    return {k: v for k, v in o.items() if k not in known}


def json_list(items: Iterable[JSONValue]) -> list[JSONValue]:
    return list(items)


def json_map(items: Mapping[str, JSONValue]) -> JSONObject:
    return dict(items)
