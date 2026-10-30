"""SPEC.md § 13's limits, and the JSON reader that keeps to them."""

from __future__ import annotations

import json
from typing import Any

import pytest

from lantern import limits
from lantern._base import DocumentError


def test_a_document_within_the_limits_reads() -> None:
    assert limits.load_json(b'{"schema": 1, "name": "Frostline"}') == {"schema": 1, "name": "Frostline"}


def test_size() -> None:
    with pytest.raises(DocumentError, match="above 10"):
        limits.load_json(b'{"schema": 1, "x": "......"}', limit=10)


def test_depth() -> None:
    sixteen = "[" * 15 + "{}" + "]" * 15
    assert limits.load_json(sixteen.encode()) is not None
    with pytest.raises(DocumentError, match="deeper than 16"):
        limits.load_json(("[" * 16 + "{}" + "]" * 16).encode())
    with pytest.raises(DocumentError, match="deeper"):
        limits.load_json(b"[" * 100000 + b"]" * 100000)


@pytest.mark.parametrize(("key", "cap"), [("name", 512), ("note", 120), ("profile", 64), ("summary", 4096)])
def test_strings_by_their_key(key: str, cap: int) -> None:
    assert limits.problems({key: "é" * (cap // 2)}) == []
    assert limits.problems({key: "a" * (cap + 1)})


def test_lists() -> None:
    assert limits.problems({"items": [{}] * 1001})
    assert limits.problems({"package": {"manifest": [{}] * 4097}})
    assert limits.problems({"packages": [{}] * 17})
    assert limits.problems({"tags": ["a"] * 33})
    assert limits.problems({"tags": ["a" * 65]})
    assert limits.problems({"tags": ["a" * 64] * 32}) == []
    data: list[Any] = [{"path": f"f{i}", "hint": "h"} for i in range(200)]
    group: Any = {"one_of": [[{"path": f"g{i}", "hint": "h"} for i in range(30)]] * 2}
    assert limits.problems({"port": {"requires_data": [*data, group]}})
    assert limits.problems({"port": {"requires_data": data}}) == []
    assert limits.problems({"accept": [{}] * 33})


@pytest.mark.parametrize("raw", [b"\xff\xfe", b'{"a": NaN}', b"{", b'{"a": Infinity}'])
def test_not_json(raw: bytes) -> None:
    with pytest.raises(DocumentError, match="not JSON"):
        limits.load_json(raw)


def test_beyond_the_limits_is_refused() -> None:
    with pytest.raises(DocumentError, match="13"):
        limits.load_json(json.dumps({"note": "n" * 121}).encode())


def test_printable_and_clip() -> None:
    assert limits.printable("Paused\x1b[31m until\x07 Sunday\u0085.") == "Paused[31m until Sunday."
    assert limits.clip("ééé", 3) == "é"
    assert limits.printable("a" * 10, 4) == "aaaa"
