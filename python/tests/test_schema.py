"""lantern.schema against the specification's examples and refused examples,
and against jsonschema itself on mutated documents."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path
from typing import Any

import pytest

from conftest import SPEC, examples, load, refused
from lantern import schema


@pytest.mark.parametrize("path", examples(), ids=lambda p: p.stem)
def test_every_example_is_valid(path: Path) -> None:
    assert schema.validate(path.stem, load(path)) == []


@pytest.mark.parametrize("path", refused(), ids=lambda p: p.name)
def test_every_refused_example_is_refused(path: Path) -> None:
    name = path.name.split(".")[0]
    assert schema.validate(name, load(path)), f"{path.name} should be refused"


def test_names_and_definitions() -> None:
    assert "homebrew" in schema.names() and "common" not in schema.names()
    assert schema.definition("sha256", "0" * 64) == []
    assert schema.definition("sha256", "0" * 63)
    with pytest.raises(KeyError):
        schema.validate("nothing", {})
    with pytest.raises(KeyError):
        schema.definition("nothing", {})


def test_formats() -> None:
    assert schema.definition("time", "2026-10-30T09:12:00Z") == []
    assert schema.definition("time", "2026-10-30T09:12:00.5+02:00") == []
    assert schema.definition("time", "2026-10-30 09:12")
    assert schema.definition("time", "2026-13-30T09:12:00Z")
    hello: Any = {
        "schema": 1,
        "uid": "not-a-uuid",
        "name": "x",
        "base": "/a",
        "versions": [1],
        "platforms": [],
        "account": {"state": "anonymous", "scopes": []},
        "features": {},
    }
    assert any("uuid" in e for e in schema.validate("handshake", hello))


def test_true_is_not_one() -> None:
    assert schema.validate("cheats", {"schema": True, "cheats": []})


def _mutations(doc: Any, rng: random.Random) -> Any:
    """A copy of `doc` with one value changed, removed or retyped."""
    out = copy.deepcopy(doc)
    paths: list[tuple[Any, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k in list(node):
                paths.append((node, k))
                walk(node[k])
        elif isinstance(node, list):
            for i in range(len(node)):
                paths.append((node, i))
                walk(node[i])

    walk(out)
    if not paths:
        return out
    parent, key = rng.choice(paths)
    choice = rng.randrange(6)
    if choice == 0 and isinstance(parent, dict):
        del parent[key]
    elif choice == 1:
        parent[key] = rng.choice([None, True, 0, -1, 1.5, "", "x" * 600, [], {}, "..", "/a/../b", "ZZ"])
    elif choice == 2 and isinstance(parent[key], str):
        parent[key] = parent[key].upper() + "!"
    elif choice == 3 and isinstance(parent[key], int) and not isinstance(parent[key], bool):
        parent[key] = parent[key] + rng.choice([-(1 << 40), 1, 1 << 70])
    elif choice == 4 and isinstance(parent, dict):
        parent["category"] = "tools"
    else:
        parent[key] = rng.choice(["switch", "linux", "zip", "nro", "base", "update", "port"])
    return out


def test_agrees_with_jsonschema_on_mutated_documents() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    pytest.importorskip("rfc3339_validator")
    folder = SPEC / "schemas" / "v1"
    docs = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in folder.glob("*.json")}
    registry = referencing.Registry().with_resources(
        (s["$id"], referencing.Resource.from_contents(s)) for s in docs.values()
    )
    validators = {
        n: jsonschema.Draft202012Validator(s, registry=registry, format_checker=jsonschema.FormatChecker())
        for n, s in docs.items()
    }
    rng = random.Random(20261030)
    checked = 0
    for path in examples():
        base = load(path)
        for _ in range(60):
            doc = _mutations(base, rng)
            expected = validators[path.stem].is_valid(doc)
            assert schema.is_valid(path.stem, doc) == expected, (path.stem, json.dumps(doc)[:300])
            checked += 1
    assert checked > 1000
