#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 JigSawFr
# SPDX-License-Identifier: MIT
"""Generates the Rust library's models from the specification's JSON Schemas.

    python3 tools/generate.py           # writes src/generated/
    python3 tools/generate.py --check   # exits 1 when what is committed is stale

It reads spec/schemas/v1/*.json (the submodule at the repository's root) and
writes, under src/generated/:

- models.rs: a struct per object of the schemas, each keeping the fields it
  does not know in `extra` (SPEC.md § 3.2), and the vocabularies the schemas
  enumerate (genres, scopes, error codes…) as constants;
- schemas.rs: the schemas themselves, as text the library embeds.

The graph of models (names, nesting, which fields are required) is the Python
generator's (python/tools/generate.py): the four libraries agree on it. Only
the types written are Rust's. Standard library only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent
ROOT = CRATE.parent
SCHEMAS = ROOT / "spec" / "schemas" / "v1"
OUT = CRATE / "src" / "generated"

_spec = importlib.util.spec_from_file_location("lantern_python_generate", ROOT / "python" / "tools" / "generate.py")
assert _spec is not None and _spec.loader is not None
py = importlib.util.module_from_spec(_spec)
sys.modules["lantern_python_generate"] = py
_spec.loader.exec_module(py)

KEYWORDS = {
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if", "impl",
    "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "static", "struct",
    "super", "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract",
    "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try",
    "gen",
}  # fmt: skip


def ident(key: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", key)
    return f"r#{name}" if name in KEYWORDS else name


class RustGenerator(py.Generator):  # type: ignore[misc]
    """The Python generator's graph of models, with Rust types."""

    def type_of(self, node: Any, where: str) -> Any:
        """Returns a Type whose `annotation` is the Rust type."""
        T = py.Type
        if not isinstance(node, dict):
            return T("Value", "", "")
        if "$ref" in node:
            target, schema = self.ref(node["$ref"])
            if target == "common#required_data":
                return self.required_data()
            if self.is_model(schema):
                return T(self.model(target, schema), "", "")
            return self.type_of(schema, target)
        if "allOf" in node:
            for part in node["allOf"]:
                if isinstance(part, dict) and "$ref" in part:
                    return self.type_of(part, where)
        if "oneOf" in node:
            options = node["oneOf"]
            rest = [o for o in options if o != {"type": "null"}]
            if len(rest) < len(options) and len(rest) == 1:
                inner = self.type_of(rest[0], where)
                return T(f"{inner.annotation} | None", "", "")
            return T("Value", "", "")
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
            return T(f"Vec<{item.annotation}>", "", "")
        if kind == "object" and isinstance(node.get("additionalProperties"), dict):
            value = self.type_of(node["additionalProperties"], where + "{}")
            return T(f"BTreeMap<String, {value.annotation}>", "", "")
        if self.is_model(node):
            return T(self.model(where, node), "", "")
        if kind == "object":
            return T("Map<String, Value>", "", "")
        return T("Value", "", "")

    def scalar(self, name: str) -> Any:
        return py.Type({"str": "String", "int": "i64", "bool": "bool", "float": "f64"}.get(name, "Value"), "", "")

    def required_data(self) -> Any:
        node = self.common["required_data"]["oneOf"]
        file_model = self.type_of(node[0], "common#required_data").annotation
        group = self.model("common#required_data", node[1])
        if "RequiredData" not in self.unions:
            self.unions.append("RequiredData")
        self.required_file = file_model
        self.required_group = group
        return py.Type("RequiredData", "", "")

    # Output.

    def rust(self) -> str:
        out = [
            "// Generated by tools/generate.py from spec/schemas/v1: do not edit.",
            "//! Lantern's documents, as typed structs generated from the specification's",
            "//! JSON Schemas (`spec/schemas/v1`). Each keeps the fields it does not know in",
            "//! `extra`, and writes them back (SPEC.md § 3.2).",
            "",
            "#![allow(missing_docs, clippy::option_option, clippy::large_enum_variant, clippy::struct_excessive_bools, clippy::doc_markdown)]",
            "",
            "use std::collections::BTreeMap;",
            "",
            "use serde::{Deserialize, Serialize};",
            "use serde_json::{Map, Value};",
            "",
            "use crate::nullable;",
            "",
        ]
        for const, path in py.VOCABULARIES.items():
            values = self.vocabulary(path)
            out.append(f"/// {path[2]}")
            out.append(f"pub const {const}: &[&str] = &[")
            out += [f'    "{v}",' for v in values]
            out += ["];", ""]
        for model in self.models.values():
            out += self.model_rust(model)
        out += [
            "/// A file the user supplies, or a group of alternatives (`one_of`) (SPEC.md § 8.6).",
            "#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]",
            "#[serde(untagged)]",
            "pub enum RequiredData {",
            f"    /// A group of alternatives.",
            f"    Group({self.required_group}),",
            f"    /// A file.",
            f"    File({self.required_file}),",
            "}",
            "",
            "/// Reads a document of `spec/schemas/v1` by its file's name (without `.json`) into its struct and writes it",
            "/// back as JSON. `None` when no document has that name. What it writes keeps every field it did not know.",
            "///",
            "/// # Errors",
            "///",
            "/// The document does not have the shape of its schema.",
            "#[must_use]",
            "pub fn round_trip(document: &str, value: Value) -> Option<Result<Value, serde_json::Error>> {",
            "    fn go<T: Serialize + for<'de> Deserialize<'de>>(value: Value) -> Result<Value, serde_json::Error> {",
            "        serde_json::to_value(serde_json::from_value::<T>(value)?)",
            "    }",
            "    Some(match document {",
        ]
        out += [f'        "{doc}" => go::<{model}>(value),' for doc, model in self.documents.items()]
        out += ["        _ => return None,", "    })", "}", ""]
        return "\n".join(out)

    def model_rust(self, model: Any) -> list[str]:
        doc = (model.doc.split(". ")[0].rstrip(".") if model.doc else model.name).replace("\n", " ")
        doc = re.sub(r"([<>\[\]])", r"\\\1", doc)
        where = model.where.replace("common#", "common.json#/$defs/")
        out = [
            f"/// {doc}.",
            "///",
            f"/// From `{where}`.",
            "#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]",
            "#[non_exhaustive]",
            f"pub struct {model.name} {{",
        ]
        for f in model.fields:
            annotation = f.type.annotation
            if f.required and annotation.endswith(" | None"):
                annotation = f"Option<{annotation.removesuffix(' | None')}>"
            name = ident(f.attr.rstrip("_") if f.attr.endswith("_") else f.attr)
            rename = ""
            if re.sub(r"[^A-Za-z0-9_]", "_", f.key) != f.key:
                rename = f'rename = "{f.key}"'
            if f.required:
                if rename:
                    out.append(f"    #[serde({rename})]")
                out.append(f"    pub {name}: {annotation},")
            elif f.nullable:
                inner = annotation.removesuffix(" | None")
                parts = ['default', 'with = "nullable"', 'skip_serializing_if = "Option::is_none"']
                if rename:
                    parts.insert(0, rename)
                out.append(f"    #[serde({', '.join(parts)})]")
                out.append(f"    pub {name}: Option<Option<{inner}>>,")
            else:
                parts = ["default", 'skip_serializing_if = "Option::is_none"']
                if rename:
                    parts.insert(0, rename)
                out.append(f"    #[serde({', '.join(parts)})]")
                out.append(f"    pub {name}: Option<{annotation}>,")
        out += [
            "    /// The fields this version does not know, kept (SPEC.md § 3.2).",
            "    #[serde(flatten)]",
            "    pub extra: Map<String, Value>,",
            "}",
            "",
        ]
        return out

    def schemas_rust(self, folder: Path) -> str:
        out = [
            "// Generated by tools/generate.py from spec/schemas/v1: do not edit.",
            "//! The specification's JSON Schemas, embedded.",
            "",
            "/// Each schema of `spec/schemas/v1`: its file's name (without `.json`) and its text.",
            "pub const SCHEMAS: &[(&str, &str)] = &[",
        ]
        for path in sorted(folder.glob("*.json")):
            out.append(f'    ("{path.stem}", include_str!("schemas/v1/{path.name}")),')
        out += ["];", ""]
        return "\n".join(out)


def generated(folder: Path) -> dict[str, str]:
    gen = RustGenerator(folder)
    gen.run()
    files = {
        "mod.rs": "//! Generated by `tools/generate.py` from the specification's schemas.\n\n"
        "#[rustfmt::skip]\npub mod models;\n#[rustfmt::skip]\npub mod schemas;\n\npub use models::*;\n",
        "models.rs": gen.rust(),
        "schemas.rs": gen.schemas_rust(folder),
    }
    for path in sorted(folder.glob("*.json")):
        files[f"schemas/v1/{path.name}"] = path.read_text(encoding="utf-8")
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
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
    for p in sorted(args.out.rglob("*")):
        rel = str(p.relative_to(args.out)).replace("\\", "/")
        if p.is_file() and rel not in known:
            stale.append(rel)
            if not args.check:
                p.unlink()
    if args.check:
        for rel in stale:
            print(f"generate: {rel} is stale: run python3 tools/generate.py", file=sys.stderr)
        return 1 if stale else 0
    print(f"generate: {len(files)} files, {len(stale)} written or removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
