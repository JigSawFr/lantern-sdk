#!/usr/bin/env python3
"""Generates the library's models from the specification's JSON Schemas.

    python3 tools/generate.py           # writes src/lantern/_generated/
    python3 tools/generate.py --check   # exits 1 when what is committed is stale

It reads spec/schemas/v1/*.json (the submodule at the repository's root) and
writes, under src/lantern/_generated/:

- models.py: a dataclass per object of the schemas, each with from_json()
  (which keeps the fields it does not know, in `extra`) and to_json();
  the vocabularies the schemas enumerate (genres, scopes, error codes…);
- schemas/v1/*.json: the schemas themselves, which lantern.schema validates
  documents against without the submodule.

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import keyword
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
SCHEMAS = PACKAGE.parent / "spec" / "schemas" / "v1"
OUT = PACKAGE / "src" / "lantern" / "_generated"

# Class names, by where the object is in the schemas: "<file>" for a document,
# "common#<def>" for a definition, then "/<property>" and "[]" for an array's items.
NAMES = {
    "common#page": "AppsPage",
    "common#title/players": "Players",
    "common#ratings[]": "Rating",
    "common#title/video": "Video",
    "common#request": "TitleRequest",
    "common#required_file/accept[]": "AcceptedVersion",
    "common#port/original": "PortOriginal",
    "common#port/original/stores[]": "PortStore",
    "common#port/original/title": "PortTitle",
    "common#port/engine": "PortEngine",
    "common#requires/homebrew[]": "RequiredHomebrew",
    "common#required_data": "RequiredDataGroup",
    "handshake/software": "Software",
    "handshake/account": "Account",
    "handshake/limits": "Limits",
    "sections/sections[]": "Section",
    "title-changes/removed[]": "RemovedTitle",
    "missing-request/installed[]": "InstalledApp",
    "homebrew-updates-request/installed[]": "InstalledHomebrew",
    "cheats": "CheatSets",
    "requests": "TitleRequests",
}
# Fields a reader takes even when a writer must give them (SPEC.md § 8.1: a
# kind it does not know, or none, is an app).
LENIENT = {("Homebrew", "kind")}
# Fields of an open vocabulary, read through a property that maps what the
# reader does not know to the value the specification says.
EFFECTIVE = {
    ("Homebrew", "kind"): ("effective_kind", "KINDS", '"app"', "8.1", "a kind it does not know, or none, is an app"),
    ("Port", "assets"): ("effective_assets", "ASSETS", '"user_owned"', "8.6", "a value it does not know is user_owned"),
}
GENRE_FIELDS = {("Homebrew", "genres"), ("Title", "genres")}
# The vocabularies the schemas enumerate, by where they are.
VOCABULARIES = {
    "GENRES": ("common", ["$defs", "genre", "enum"], "Genres of a title or a homebrew (SPEC.md § 7.1)."),
    "SCOPES": ("common", ["$defs", "scope", "enum"], "What a token may do (SPEC.md § 4.2)."),
    "SAVE_KINDS": ("common", ["$defs", "save_kind", "enum"], "A save's kinds (SPEC.md § 9.1)."),
    "GPU_NAMES": (
        "common",
        ["$defs", "requires", "properties", "gpu", "items", "enum"],
        "Graphics interfaces of requires.gpu (SPEC.md § 8.7).",
    ),
    "ERROR_CODES": ("problem", ["properties", "code", "enum"], "The error codes of SPEC.md § 12."),
    "ACCOUNT_STATES": (
        "handshake",
        ["properties", "account", "properties", "state", "enum"],
        "An account's states (SPEC.md § 4.2).",
    ),
    "REQUEST_STATUSES": (
        "common",
        ["$defs", "request", "properties", "status", "enum"],
        "A request's statuses (SPEC.md § 11).",
    ),
}


def pascal(text: str) -> str:
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"[^A-Za-z0-9]+", text) if p)


@dataclass
class Type:
    annotation: str
    reader: str  # an expression: a callable (value, where) -> the type
    writer: str  # a format string over {v}: the JSON value

    def write(self, value: str) -> str:
        return self.writer.format(v=value)


@dataclass
class Field:
    key: str
    attr: str
    type: Type
    required: bool
    nullable: bool = False


@dataclass
class Model:
    name: str
    where: str
    doc: str
    fields: list[Field] = field(default_factory=list)


class Generator:
    def __init__(self, folder: Path) -> None:
        self.schemas = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))}
        self.common = self.schemas["common"]["$defs"]
        self.models: dict[str, Model] = {}
        self.by_where: dict[str, str] = {}
        self.documents: dict[str, str] = {}
        self.unions: list[str] = []

    # Types.

    def ref(self, ref: str) -> tuple[str, dict[str, Any]]:
        m = re.fullmatch(r"(?:common\.json)?#/\$defs/([A-Za-z0-9_]+)", ref)
        if not m:
            raise SystemExit(f"generate: unknown $ref {ref}")
        return f"common#{m.group(1)}", self.common[m.group(1)]

    def type_of(self, node: Any, where: str) -> Type:
        if not isinstance(node, dict):
            return Type("JSONValue", "_m.as_any", "{v}")
        if "$ref" in node:
            target, schema = self.ref(node["$ref"])
            if target == "common#required_data":
                return self.required_data()
            if self.is_model(schema):
                return self.model_type(self.model(target, schema))
            return self.type_of(schema, target)
        if "allOf" in node:
            for part in node["allOf"]:
                if isinstance(part, dict) and "$ref" in part:
                    return self.type_of(part, where)
        if "oneOf" in node:
            options = node["oneOf"]
            nulls = [o for o in options if o == {"type": "null"}]
            rest = [o for o in options if o != {"type": "null"}]
            if nulls and len(rest) == 1:
                inner = self.type_of(rest[0], where)
                return Type(
                    f"{inner.annotation} | None",
                    f"_m.nullable({inner.reader})",
                    "None if {v} is None else " + inner.writer,
                )
            return Type("JSONValue", "_m.as_any", "{v}")
        if "const" in node:
            return self.scalar(type(node["const"]).__name__)
        if "enum" in node and all(isinstance(e, str) for e in node["enum"]):
            return self.scalar("str")
        kind = node.get("type")
        if kind == "string":
            return self.scalar("str")
        if kind == "integer":
            return self.scalar("int")
        if kind == "boolean":
            return self.scalar("bool")
        if kind == "array":
            item = self.type_of(node.get("items"), where + "[]")
            each = item.write("x")
            writer = "_m.json_list({v})" if each == "x" else f"_m.json_list({each} for x in {{v}})"
            return Type(f"list[{item.annotation}]", f"lambda v, w: _m.as_list(v, w, {item.reader})", writer)
        if kind == "object" and isinstance(node.get("additionalProperties"), dict):
            value = self.type_of(node["additionalProperties"], where + "{}")
            each = value.write("x")
            writer = "_m.json_map({v})" if each == "x" else f"_m.json_map({{{{k: {each} for k, x in {{v}}.items()}}}})"
            return Type(f"dict[str, {value.annotation}]", f"lambda v, w: _m.as_map(v, w, {value.reader})", writer)
        if self.is_model(node):
            return self.model_type(self.model(where, node))
        if kind == "object":
            return Type("dict[str, JSONValue]", "lambda v, w: _m.as_map(v, w, _m.as_any)", "_m.json_map({v})")
        return Type("JSONValue", "_m.as_any", "{v}")

    def scalar(self, name: str) -> Type:
        return Type(name, f"_m.as_{name}", "{v}")

    @staticmethod
    def is_model(node: Any) -> bool:
        return (
            isinstance(node, dict) and "properties" in node and not isinstance(node.get("additionalProperties"), dict)
        )

    def model_type(self, name: str) -> Type:
        return Type(name, f"{name}.from_json", "{v}.to_json()")

    def required_data(self) -> Type:
        """common.json's required_data: a file, or a group of alternatives (`one_of`)."""
        node = self.common["required_data"]["oneOf"]
        file_model = self.type_of(node[0], "common#required_data").annotation
        group = self.model("common#required_data", node[1])
        if "RequiredData" not in self.unions:
            self.unions.append("RequiredData")
        return Type(f"{file_model} | {group}", "read_required_data", "{v}.to_json()")

    # Models.

    def model(self, where: str, node: dict[str, Any]) -> str:
        if where in self.by_where:
            return self.by_where[where]
        name = NAMES.get(where) or pascal(where.rsplit("#", maxsplit=1)[-1].replace("[]", ""))
        if "/" in where and where not in NAMES:
            name = pascal(where.rsplit("#", maxsplit=1)[-1].replace("[]", ""))
        if name in self.models:
            raise SystemExit(f"generate: two models named {name} ({where}, {self.models[name].where})")
        model = Model(name, where, (node.get("description") or node.get("title") or "").strip())
        self.by_where[where] = name
        self.models[name] = model
        required = set(node.get("required", []))
        for key, prop in node.get("properties", {}).items():
            if isinstance(prop, dict) and prop.get("not") == {}:  # a field that must not be there
                continue
            attr = key + "_" if keyword.iskeyword(key) else key
            t = self.type_of(prop, f"{where}/{key}")
            nullable = t.annotation.endswith("| None")
            model.fields.append(Field(key, attr, t, key in required and (name, key) not in LENIENT, nullable))
        return name

    def run(self) -> None:
        for name in sorted(self.schemas):
            if name == "common":
                continue
            node = self.schemas[name]
            if "$ref" in node:
                _, target = self.ref(node["$ref"])
                self.documents[name] = self.model(self.ref(node["$ref"])[0], target)
            elif "allOf" in node:
                # A document is a definition of common.json (a $ref) or an object of its own, and then the
                # part that adds its `schema`.
                parts = [p for p in node["allOf"] if isinstance(p, dict)]
                ref = next((p["$ref"] for p in parts if "$ref" in p), None)
                if ref is not None:
                    where, target = self.ref(ref)
                    model = self.model(where, target)
                else:
                    own = next(p for p in parts if "schema" not in p.get("properties", {}))
                    model = self.model(name, {"description": node.get("description", ""), **own})
                self.documents[name] = model
                if not any(f.key == "schema" for f in self.models[model].fields):
                    self.models[model].fields.insert(0, Field("schema", "schema", self.scalar("int"), False))
            else:
                self.documents[name] = self.model(name, node)

    # Output.

    def vocabulary(self, path: tuple[str, list[str], str]) -> list[str]:
        node: Any = self.schemas[path[0]]
        for key in path[1]:
            node = node[key]
        return list(node)

    def source(self) -> str:
        lines = [
            "# Generated by tools/generate.py from spec/schemas/v1: do not edit.",
            '"""Lantern\'s documents, as typed models generated from the specification\'s',
            "JSON Schemas (spec/schemas/v1). Each reads with from_json(), which keeps the",
            "fields it does not know in `extra`, and writes back with to_json(), which",
            'gives them back (SPEC.md § 3.2)."""',
            "",
            "from __future__ import annotations",
            "",
            "from dataclasses import dataclass, field",
            "from typing import Any, ClassVar, TypeAlias",
            "",
            "from lantern import _model as _m",
            "from lantern._base import JSONObject, JSONValue",
            "from lantern.vocabulary import ASSETS, KINDS",
            "",
        ]
        for const, path in VOCABULARIES.items():
            values = self.vocabulary(path)
            lines.append(f"#: {path[2]}")
            lines.append(f"{const}: tuple[str, ...] = (")
            lines += [f'    "{v}",' for v in values]
            lines += [")", ""]
        lines.append("")
        for model in self.models.values():
            lines += self.model_source(model)
            lines += ["", ""]
        lines += [
            "RequiredData: TypeAlias = RequiredFile | RequiredDataGroup",
            "",
            "",
            "def read_required_data(data: JSONValue, where: str) -> RequiredData:",
            '    """A file the user supplies, or a group of alternatives (`one_of`) (SPEC.md § 8.6)."""',
            '    if isinstance(data, dict) and "one_of" in data:',
            "        return RequiredDataGroup.from_json(data, where)",
            "    return RequiredFile.from_json(data, where)",
            "",
            "",
            "#: Each document of spec/schemas/v1, by its file's name, and its model.",
            "DOCUMENTS: dict[str, type[Any]] = {",
        ]
        lines += [f'    "{doc}": {model},' for doc, model in self.documents.items()]
        lines += ["}", ""]
        names = sorted([*self.models, "RequiredData", "DOCUMENTS", "read_required_data", *VOCABULARIES])
        lines += ["__all__ = ["] + [f'    "{n}",' for n in names] + ["]", ""]
        return "\n".join(lines)

    def model_source(self, model: Model) -> list[str]:
        doc = model.doc.split(". ")[0].rstrip(".") if model.doc else f"{model.name}."
        where = model.where.replace("common#", "common.json#/$defs/")
        out = [
            "@dataclass(kw_only=True, slots=True)",
            f"class {model.name}:",
            f'    """{doc}.',
            "",
            f"    From {where}.",
            '    """',
            "",
        ]
        for f in model.fields:
            if f.required:
                out.append(f"    {f.attr}: {f.type.annotation}")
            else:
                annotation = f.type.annotation if f.nullable else f"{f.type.annotation} | None"
                out.append(f"    {f.attr}: {annotation} = None")
        out.append("    extra: JSONObject = field(default_factory=dict)")
        keys = ", ".join(f'"{f.key}"' for f in model.fields)
        out += ["", f"    KEYS: ClassVar[frozenset[str]] = frozenset({{{keys}}})", ""]
        out += [
            "    @classmethod",
            f'    def from_json(cls, data: JSONValue, where: str = "{model.name}") -> {model.name}:',
            "        o = _m.obj(data, where)",
            "        return cls(",
        ]
        for f in model.fields:
            fn = "req" if f.required else "opt"
            out.append(f'            {f.attr}=_m.{fn}(o, "{f.key}", where, {f.type.reader}),')
        out += ["            extra=_m.extras(o, cls.KEYS),", "        )", ""]
        out += ["    def to_json(self) -> JSONObject:", "        out: JSONObject = {}"]
        for f in model.fields:
            value = f.type.write(f"self.{f.attr}")
            if f.required:
                out.append(f'        out["{f.key}"] = {value}')
            else:
                out += [f"        if self.{f.attr} is not None:", f'            out["{f.key}"] = {value}']
        out += ["        out.update(self.extra)", "        return out"]
        for (cls, key), (prop, vocab, default, section, why) in EFFECTIVE.items():
            if cls == model.name:
                out += [
                    "",
                    "    @property",
                    f"    def {prop}(self) -> str:",
                    f'        """`{key}` as a reader reads it (SPEC.md § {section}): {why}."""',
                    f"        return self.{key} if self.{key} in {vocab} else {default}",
                ]
        if (model.name, "genres") in GENRE_FIELDS:
            out += [
                "",
                "    @property",
                "    def effective_genres(self) -> list[str]:",
                '        """`genres` as a reader reads them (SPEC.md § 7.1): one it does not know is other."""',
                '        return list(dict.fromkeys(g if g in GENRES else "other" for g in self.genres or ()))',
            ]
        return out


def generated(folder: Path) -> dict[str, str]:
    """Every file the generator writes, relative to OUT, and its content."""
    gen = Generator(folder)
    gen.run()
    files = {"models.py": gen.source(), "__init__.py": '"""Generated by tools/generate.py: do not edit."""\n'}
    for path in sorted(folder.glob("*.json")):
        files[f"schemas/v1/{path.name}"] = path.read_text(encoding="utf-8")
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the committed files are stale")
    parser.add_argument("--schemas", type=Path, default=SCHEMAS)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)
    if not (args.schemas / "common.json").exists():
        print(f"generate: no schemas in {args.schemas} (git submodule update --init)", file=sys.stderr)
        return 2
    files = generated(args.schemas)
    stale = []
    for rel, content in files.items():
        path = args.out / rel
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != content:
            stale.append(rel)
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="\n")
    known = set(files)
    extra = [
        str(p.relative_to(args.out)).replace("\\", "/")
        for p in args.out.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    ]
    extra = [p for p in extra if p not in known]
    for rel in extra:
        stale.append(rel)
        if not args.check:
            (args.out / rel).unlink()
    if args.check:
        for rel in stale:
            print(f"generate: {rel} is stale: run python3 tools/generate.py", file=sys.stderr)
        return 1 if stale else 0
    print(f"generate: {len(files)} files, {len(stale)} written or removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
