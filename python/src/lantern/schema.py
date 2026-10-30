"""Documents checked against the specification's JSON Schemas, without a
dependency: the subset of JSON Schema 2020-12 that spec/schemas/v1 uses
($ref, allOf, anyOf, oneOf, not, if/then/else, properties, required,
additionalProperties, propertyNames, items, enum, const, pattern, lengths,
bounds, uniqueItems, and the formats date-time, date and uuid).

    from lantern import schema
    problems = schema.validate("homebrew", document)   # [] when valid

A server validates what it is about to serve; a client may validate what it
reads. A reader stays lenient where the specification says so (an unknown
kind or genre, SPEC.md § 8.1, § 7.1): this is the writer's check, the strict
one, which every example of the specification passes and every refused one
fails.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from functools import cache
from importlib import resources
from typing import Any

from lantern._base import JSONValue

_FOLDER = "lantern._generated"
_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


@cache
def _schemas() -> dict[str, Any]:
    folder = resources.files(_FOLDER).joinpath("schemas", "v1")
    out: dict[str, Any] = {}
    for entry in folder.iterdir():
        if entry.name.endswith(".json"):
            out[entry.name.removesuffix(".json")] = json.loads(entry.read_text(encoding="utf-8"))
    return out


def names() -> list[str]:
    """The documents the schemas describe (`homebrew`, `apps`…), common.json aside."""
    return sorted(n for n in _schemas() if n != "common")


@cache
def _pattern(text: str) -> re.Pattern[str]:
    return re.compile(text)


def _equal(a: Any, b: Any) -> bool:
    """JSON equality: true is not 1."""
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def _is_type(value: Any, kind: str) -> bool:
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "null":
        return value is None
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _format_ok(value: str, fmt: str) -> bool:
    try:
        if fmt == "date-time":
            if not _DATE_TIME.match(value):
                return False
            datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
        elif fmt == "date":
            if not _DATE.match(value):
                return False
            date.fromisoformat(value)
        elif fmt == "uuid":
            return bool(_UUID.match(value))
    except ValueError:
        return False
    return True


class _Validator:
    def __init__(self) -> None:
        self.schemas = _schemas()

    def resolve(self, ref: str, base: str) -> tuple[Any, str]:
        target, _, pointer = ref.partition("#")
        doc_name = target.removesuffix(".json") if target else base
        node: Any = self.schemas[doc_name]
        for part in [p for p in pointer.split("/") if p]:
            node = node[part.replace("~1", "/").replace("~0", "~")]
        return node, doc_name

    def errors(self, value: Any, schema: Any, path: str, base: str) -> list[str]:
        if schema is True:
            return []
        if schema is False:
            return [f"{path}: not allowed"]
        out: list[str] = []
        if "$ref" in schema:
            target, doc = self.resolve(schema["$ref"], base)
            out += self.errors(value, target, path, doc)
        for part in schema.get("allOf", ()):
            out += self.errors(value, part, path, base)
        if "anyOf" in schema and not any(not self.errors(value, s, path, base) for s in schema["anyOf"]):
            out.append(f"{path}: matches none of anyOf")
        if "oneOf" in schema:
            n = sum(1 for s in schema["oneOf"] if not self.errors(value, s, path, base))
            if n != 1:
                out.append(f"{path}: matches {n} of oneOf, not exactly one")
        if "not" in schema and not self.errors(value, schema["not"], path, base):
            out.append(f"{path}: matches what is forbidden here")
        if "if" in schema:
            branch = "then" if not self.errors(value, schema["if"], path, base) else "else"
            if branch in schema:
                out += self.errors(value, schema[branch], path, base)
        if "type" in schema:
            kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_is_type(value, k) for k in kinds):
                return [*out, f"{path}: not of type {'/'.join(kinds)}"]
        if "const" in schema and not _equal(value, schema["const"]):
            out.append(f"{path}: not {json.dumps(schema['const'])}")
        if "enum" in schema and not any(_equal(value, e) for e in schema["enum"]):
            out.append(f"{path}: {json.dumps(value)[:60]} is not one of {', '.join(map(str, schema['enum']))[:200]}")
        if isinstance(value, str):
            out += self.string(value, schema, path)
        elif _is_type(value, "number"):
            if "minimum" in schema and value < schema["minimum"]:
                out.append(f"{path}: below {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                out.append(f"{path}: above {schema['maximum']}")
        elif isinstance(value, list):
            out += self.array(value, schema, path, base)
        elif isinstance(value, dict):
            out += self.object(value, schema, path, base)
        return out

    def string(self, value: str, schema: Any, path: str) -> list[str]:
        out = []
        if "minLength" in schema and len(value) < schema["minLength"]:
            out.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            out.append(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema and not _pattern(schema["pattern"]).search(value):
            out.append(f"{path}: {value[:60]!r} does not match {schema['pattern']}")
        if "format" in schema and not _format_ok(value, schema["format"]):
            out.append(f"{path}: {value[:60]!r} is not a {schema['format']}")
        return out

    def array(self, value: list[Any], schema: Any, path: str, base: str) -> list[str]:
        out = []
        if "minItems" in schema and len(value) < schema["minItems"]:
            out.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            out.append(f"{path}: more than {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            seen = [json.dumps(v, sort_keys=True) for v in value]
            if len(set(seen)) != len(seen):
                out.append(f"{path}: an item twice")
        if "items" in schema:
            for i, item in enumerate(value):
                out += self.errors(item, schema["items"], f"{path}[{i}]", base)
        return out

    def object(self, value: dict[str, Any], schema: Any, path: str, base: str) -> list[str]:
        out = [f"{path}: no {key}" for key in schema.get("required", ()) if key not in value]
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                out += self.errors(item, properties[key], f"{path}.{key}", base)
            elif "additionalProperties" in schema:
                out += self.errors(item, schema["additionalProperties"], f"{path}.{key}", base)
            if "propertyNames" in schema:
                out += [
                    e.replace(f"{path}.{key}:", f"{path}: the key {key!r}:")
                    for e in self.errors(key, schema["propertyNames"], f"{path}.{key}", base)
                ]
        return out


def validate(name: str, document: JSONValue) -> list[str]:
    """Every way `document` breaks schemas/v1/<name>.json (`homebrew`, `apps`,
    `problem`…), as "$.path: what"; [] when it is valid."""
    schemas = _schemas()
    if name not in schemas or name == "common":
        raise KeyError(f"no schema named {name!r}")
    return _Validator().errors(document, schemas[name], "$", name)


def is_valid(name: str, document: JSONValue) -> bool:
    return not validate(name, document)


def definition(name: str, value: JSONValue) -> list[str]:
    """Every way `value` breaks common.json's definition `name` (`app`, `homebrew`, `package`…)."""
    if name not in _schemas()["common"]["$defs"]:
        raise KeyError(f"no definition named {name!r}")
    return _Validator().errors(value, {"$ref": f"common.json#/$defs/{name}"}, "$", "common")
