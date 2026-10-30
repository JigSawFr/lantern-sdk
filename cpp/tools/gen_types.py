#!/usr/bin/env python3
"""Generates the C++ types of the documents a Lantern client reads and
writes, and their binding code, from the specification's JSON Schemas.

    python3 cpp/tools/gen_types.py           # writes the files
    python3 cpp/tools/gen_types.py --check   # fails when they are stale

It reads spec/schemas/v1/*.json (the submodule) and writes
cpp/include/lantern/types.hpp and cpp/src/generated/types.cpp, which are
committed. Standard library only.

How a schema becomes C++:
- an object is a struct, allocator-aware (std::pmr), named after its $defs
  entry (NAMED below) or after where it sits (Title.players: TitlePlayers);
- a string is a String, bounded by its maxLength (or SPEC.md § 13's 4 KiB);
  a SHA-256 (64 lower-case hex digits) is a Digest; an enum or a const stays
  a String, so that a value of a later version is read, not refused;
- an integer is a std::uint64_t (std::int64_t when it may be negative),
  checked against its minimum and maximum;
- a field that is not required is a std::optional, but strings and arrays,
  which are empty when absent;
- allOf, $ref and a oneOf of objects are merged; if/then/else, not and
  false (the profiles' forms, which a client checks by hand in profiles.hpp
  and paths.hpp) are left out;
- `schema` is checked once per document by read_document (document.hpp),
  never bound;
- an object with additionalProperties, and the few listed in KEEP_MEMBERS,
  keep the members they do not know, raw, in `extra`; RAW_OBJECTS are kept
  entirely as raw members (requires.min, whose values a client must be able
  to read as "of another form" rather than refuse, SPEC.md § 8.7).
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CPP = HERE.parent
SCHEMAS = CPP.parent / "spec" / "schemas" / "v1"
HEADER = CPP / "include" / "lantern" / "types.hpp"
SOURCE = CPP / "src" / "generated" / "types.cpp"

# The documents: (schema file, reader or writer function, C++ type when the
# document is not an object of its own, direction)
DOCUMENTS = [
    ("handshake.json", "read_handshake", "Handshake", "read"),
    ("discovery.json", "read_discovery_reply", "DiscoveryReply", "read"),
    ("apps.json", "read_apps_page", None, "read"),
    ("changes.json", "read_changes", "Changes", "read"),
    ("sections.json", "read_sections", "Sections", "read"),
    ("title.json", "read_title", None, "read"),
    ("titles.json", "read_titles", "Titles", "read"),
    ("title-changes.json", "read_title_changes", "TitleChanges", "read"),
    ("homebrew.json", "read_homebrew", None, "read"),
    ("homebrew-page.json", "read_homebrew_page", "HomebrewPage", "read"),
    ("saves.json", "read_saves", "Saves", "read"),
    ("save.json", "read_save", None, "read"),
    ("cheats.json", "read_cheat_sets", "CheatSets", "read"),
    ("cheat.json", "read_cheat_set", None, "read"),
    ("problem.json", "read_problem", "Problem", "read"),
    ("missing-request.json", "write_missing_request", "MissingRequest", "write"),
    ("homebrew-updates-request.json", "write_homebrew_updates_request", "HomebrewUpdatesRequest", "write"),
]

# common.json's $defs that become a type of that name.
NAMED = {
    "app": "App",
    "page": "AppsPage",
    "image": "Image",
    "title": "Title",
    "homebrew": "Homebrew",
    "package": "Package",
    "manifest_entry": "ManifestEntry",
    "signature": "Signature",
    "port": "Port",
    "required_data": "RequiredData",
    "required_file": "RequiredFile",
    "requires": "Requires",
    "save": "Save",
    "cheat_set": "CheatSet",
}

# Inline objects whose place-made name reads badly.
RENAME = {
    "RequiredDataAccept": "AcceptedVersion",
    "TitleRating": "Rating",
    "PortOriginalStore": "Store",
    "TitleChangesRemoved": "RemovedTitle",
    "SectionsSection": "Section",
    "MissingRequestInstalled": "InstalledApp",
    "HomebrewUpdatesRequestInstalled": "InstalledHomebrew",
    "RequiresHomebrew": "Dependency",
}

KEEP_MEMBERS = {"Requires"}
RAW_OBJECTS = {"RequiresMin"}
DEFAULT_MAX_STRING = 4096
SHA256 = "^[0-9a-f]{64}$"
UINT64_MAX = (1 << 64) - 1
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
KEYWORDS = {"default", "class", "delete", "new", "operator", "private", "public", "template", "this", "union",
            "register", "export", "module", "import", "char", "int", "long", "short", "auto", "case", "for",
            "requires", "concept", "co_await", "co_yield", "co_return", "namespace", "using", "virtual"}


class Schemas:
    def __init__(self, folder):
        self.files = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))}

    def resolve_ref(self, ref, current):
        """(schema, file, def name) of a $ref."""
        file, _, pointer = ref.partition("#")
        file = file or current
        node = self.files[file]
        name = None
        for part in pointer.strip("/").split("/") if pointer.strip("/") else []:
            node = node[part]
            name = part
        return node, file, name


class Field:
    def __init__(self, json_name, kind, required, **info):
        self.json_name = json_name
        self.name = json_name + "_" if json_name in KEYWORDS else json_name
        self.kind = kind            # string, digest, u64, i64, bool, object, array, raw, nullable, members
        self.required = required
        self.info = info


class Type:
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.fields = []
        self.extra = False


class Generator:
    def __init__(self, schemas):
        self.schemas = schemas
        self.types = {}       # name -> Type, in the order they are made
        self.made = {}        # (file, def) -> name

    # Merging: $ref, allOf and oneOf of objects; conditionals left out.
    def flatten(self, schema, file):
        if schema is True or schema is False:
            return {"_false": schema is False}, file
        out = {}
        if "$ref" in schema:
            target, target_file, _ = self.schemas.resolve_ref(schema["$ref"], file)
            base, _ = self.flatten(target, target_file)
            out.update(base)
            out["_file"] = target_file
        for key, value in schema.items():
            if key in ("$ref", "allOf", "oneOf", "anyOf", "if", "then", "else", "$schema", "$id", "title"):
                continue
            if key == "properties":
                out.setdefault("properties", {})
                for name, prop in value.items():
                    out["properties"][name] = (prop, file)
            elif key == "required":
                out["required"] = sorted(set(out.get("required", [])) | set(value))
            else:
                out[key] = value
        for branch in schema.get("allOf", []):
            merged, _ = self.flatten(branch, file)
            self.merge(out, merged, keep_required=True)
        alternatives = schema.get("oneOf") or schema.get("anyOf")
        if alternatives:
            flats = [self.flatten(b, file)[0] for b in alternatives]
            nulls = [f for f in flats if f.get("type") == "null"]
            others = [f for f in flats if f.get("type") != "null"]
            if nulls and len(others) == 1:
                self.merge(out, others[0], keep_required=True)
                out["_nullable"] = True
            elif all(f.get("type") == "object" or "properties" in f for f in others) and others:
                required = set(others[0].get("required", []))
                for f in others:
                    required &= set(f.get("required", []))
                    self.merge(out, f, keep_required=False)
                out["type"] = "object"
                out["required"] = sorted(set(out.get("required", [])) | required)
            elif all(f.get("type") in ("string", "integer") for f in others):
                out["_scalar_any"] = True
        out.setdefault("_file", file)
        return out, file

    @staticmethod
    def merge(out, other, keep_required):
        for key, value in other.items():
            if key == "properties":
                out.setdefault("properties", {})
                for name, prop in value.items():
                    out["properties"].setdefault(name, prop)
            elif key == "required":
                if keep_required:
                    out["required"] = sorted(set(out.get("required", [])) | set(value))
            elif key not in out:
                out[key] = value

    def ref_name(self, schema, file):
        """The type name a $ref to a named def gives, or None."""
        if not isinstance(schema, dict):
            return None
        refs = [schema] + [b for b in schema.get("allOf", []) if isinstance(b, dict)]
        for s in refs:
            if "$ref" in s:
                _, target_file, name = self.schemas.resolve_ref(s["$ref"], file)
                if name in NAMED and target_file == "common.json":
                    return name
        return None

    def object_type(self, schema, file, name):
        """Makes (once) the struct for an object schema; its name."""
        name = RENAME.get(name, name)
        key = (file, json.dumps(schema, sort_keys=True))
        if key in self.made:
            return self.made[key]
        self.made[key] = name
        flat, _ = self.flatten(schema, file)
        t = Type(name, (flat.get("description") or "").split(" (SPEC")[0].split(". ")[0].strip().rstrip(".:"))
        self.types[name] = t
        if name in RAW_OBJECTS:
            t.fields.append(Field("members", "members", False))
            t.raw = True
            return name
        t.raw = False
        required = set(flat.get("required", []))
        for prop_name, (prop, prop_file) in flat.get("properties", {}).items():
            if prop_name == "schema":
                continue
            field = self.field(prop_name, prop, prop_file, prop_name in required, name)
            if field is not None:
                t.fields.append(field)
        additional = flat.get("additionalProperties")
        t.extra = name in KEEP_MEMBERS or (isinstance(additional, dict))
        return name

    def field(self, json_name, prop, file, required, parent, type_name=None):
        if prop is False or (isinstance(prop, dict) and "not" in prop and len(set(prop) - {"not", "description"}) == 0):
            return None
        named = self.ref_name(prop, file)
        flat, flat_file = self.flatten(prop, file)
        if flat.get("_false"):
            return None
        if named:
            target, target_file, _ = self.schemas.resolve_ref(f"common.json#/$defs/{named}", file)
            type_name = self.object_type(target, "common.json", NAMED[named])
            return Field(json_name, "object", required, type=type_name)
        kind = flat.get("type")
        if kind is None and "const" in flat:
            kind = {bool: "boolean", str: "string", int: "integer"}.get(type(flat["const"]))
        if kind is None and "enum" in flat:
            kind = "string"
        if flat.get("_scalar_any"):
            return Field(json_name, "raw", required)
        if kind == "string":
            if flat.get("_nullable"):
                return Field(json_name, "nullable", required, max=flat.get("maxLength", DEFAULT_MAX_STRING))
            if flat.get("pattern") == SHA256:
                return Field(json_name, "digest", required)
            return Field(json_name, "string", required, max=min(flat.get("maxLength", DEFAULT_MAX_STRING), DEFAULT_MAX_STRING))
        if kind == "integer":
            low = flat.get("minimum", INT64_MIN)
            high = flat.get("maximum", UINT64_MAX if low >= 0 else INT64_MAX)
            return Field(json_name, "u64" if low >= 0 else "i64", required, min=low, max=high)
        if kind == "boolean":
            return Field(json_name, "bool", required)
        if kind == "object" or "properties" in flat:
            type_name = self.object_type(prop, file, type_name or parent + camel(json_name))
            return Field(json_name, "object", required, type=type_name)
        if kind == "array":
            items = flat.get("items", {})
            element = self.field(json_name, items, flat_file, True, parent,
                                 type_name=parent + camel(singular(json_name)))
            return Field(json_name, "array", required, element=element, max=flat.get("maxItems"))
        return Field(json_name, "raw", required)


def camel(name):
    return "".join(part[:1].upper() + part[1:] for part in name.replace("-", "_").split("_"))


def singular(name):
    if name.endswith("ies"):
        return name[:-3] + "y"
    if name.endswith("s") and not name.endswith("ss"):
        return name[:-1]
    return name


def cpp_type(field):
    if field.kind in ("string", "nullable"):
        return "String"
    if field.kind == "raw":
        return "String"
    if field.kind == "members":
        return "Vector<std::pair<String, String>>"
    if field.kind == "digest":
        return "Digest" if field.required else "std::optional<Digest>"
    if field.kind in ("u64", "i64"):
        base = "std::uint64_t" if field.kind == "u64" else "std::int64_t"
        return base if field.required else f"std::optional<{base}>"
    if field.kind == "bool":
        return "bool" if field.required else "std::optional<bool>"
    if field.kind == "object":
        return field.info["type"] if field.required else f"std::optional<{field.info['type']}>"
    if field.kind == "array":
        return f"Vector<{element_type(field.info['element'])}>"
    raise ValueError(field.kind)


def element_type(element):
    if element.kind == "array":
        return f"Vector<{element_type(element.info['element'])}>"
    if element.kind == "object":
        return element.info["type"]
    if element.kind == "digest":
        return "Digest"
    if element.kind == "u64":
        return "std::uint64_t"
    if element.kind == "i64":
        return "std::int64_t"
    if element.kind == "bool":
        return "bool"
    return "String"


def allocated(field):
    """Whether a member takes the allocator."""
    return field.kind in ("string", "nullable", "raw", "members", "array") or (field.kind == "object" and field.required)


def integer_literal(value, kind):
    if kind == "u64":
        return "UINT64_MAX" if value == UINT64_MAX else f"{value}U"
    if value == INT64_MIN:
        return "INT64_MIN"
    if value == INT64_MAX:
        return "INT64_MAX"
    return f"{value}"


def bind_call(field, target, where, depth=0):
    """The C++ that binds one value into `target`."""
    kind = field.kind
    if kind == "string":
        return f'c.string({target}, {field.info["max"]}, "{where}")'
    if kind == "nullable":
        return f'c.nullable_string({target}, {field.info["max"]}, "{where}")'
    if kind == "raw":
        return f'c.raw({target}, "{where}")'
    if kind == "digest":
        return f'c.digest({target}, "{where}")'
    if kind in ("u64", "i64"):
        return (f'c.{kind}({target}, {integer_literal(field.info["min"], kind)}, '
                f'{integer_literal(field.info["max"], kind)}, "{where}")')
    if kind == "bool":
        return f'c.boolean({target}, "{where}")'
    if kind == "object":
        if field.required:
            return f"bind(c, {target})"
        return f"({target}.emplace(c.allocator()), bind(c, *{target}))"
    if kind == "array":
        element = field.info["element"]
        limit = field.info["max"] if field.info["max"] is not None else "SIZE_MAX"
        if element.kind in ("string", "nullable"):
            return f'c.strings({target}, {limit}, {element.info["max"]}, "{where}")'
        item = element_type(element)
        name = "item" if depth == 0 else f"item{depth}"
        inner = bind_call(element, name, where, depth + 1)
        return f'c.array({target}, {limit}, "{where}", [&]({item}& {name}) {{ return {inner}; }})'
    raise ValueError(kind)


def emit_struct(t):
    lines = []
    if t.description:
        lines.append(f"// {t.description}.")
    lines.append(f"struct {t.name}")
    lines.append("{")
    lines.append("    using allocator_type = Allocator;")
    lines.append("")
    members = list(t.fields)
    if t.extra:
        members.append(Field("extra", "members", False))
    for f in members:
        lines.append(f"    {cpp_type(f)} {f.name}{default_init(f)};")
    lines.append("")
    alloc_members = [f for f in members if allocated(f)]
    lines.append(f"    {t.name}() : {t.name}(allocator_type{{}}) {{}}")
    if alloc_members:
        init = ",\n          ".join(f"{f.name}(allocator)" for f in alloc_members)
        lines.append(f"    explicit {t.name}(const allocator_type& allocator)\n        : {init}\n    {{\n    }}")
    else:
        lines.append(f"    explicit {t.name}(const allocator_type& /*allocator*/) {{}}")
    copy_init = ",\n          ".join(copy_member(f, "other", move=False) for f in members)
    move_init = ",\n          ".join(copy_member(f, "other", move=True) for f in members)
    uses = any(allocated(f) or f.kind == "object" for f in members)
    unused = "" if uses else " /*allocator*/"
    other = "other" if members else "/*other*/"
    lines.append(f"    {t.name}(const {t.name}& {other}, const allocator_type&{unused or ' allocator'})"
                 + (f"\n        : {copy_init}" if members else "") + "\n    {\n    }")
    lines.append(f"    {t.name}({t.name}&& {other}, const allocator_type&{unused or ' allocator'})"
                 + (f"\n        : {move_init}" if members else "") + "\n    {\n    }")
    lines.append(f"    {t.name}(const {t.name}&)            = default;")
    lines.append(f"    {t.name}({t.name}&&) noexcept        = default;")
    lines.append(f"    {t.name}& operator=(const {t.name}&) = default;")
    lines.append(f"    {t.name}& operator=({t.name}&&)      = default;")
    lines.append(f"    ~{t.name}()                          = default;")
    lines.append("};")
    return "\n".join(lines)


def default_init(field):
    if field.required and field.kind in ("u64", "i64"):
        return " = 0"
    if field.required and field.kind == "bool":
        return " = false"
    if field.required and field.kind == "digest":
        return "{}"
    return ""


def copy_member(field, other, move):
    source = f"std::move({other}.{field.name})" if move else f"{other}.{field.name}"
    if allocated(field):
        return f"{field.name}({source}, allocator)"
    if field.kind == "object":
        return f"{field.name}(with_allocator({source}, allocator))"
    return f"{field.name}({other}.{field.name})"


def emit_bind(t):
    lines = [f"bool bind(BindContext& c, {t.name}& out)", "{"]
    lines.append(f'    if (!c.begin_object("{t.name}"))')
    lines.append("        return false;")
    if t.raw:
        lines.append("    std::string_view key;")
        lines.append("    while (c.next_key(key))")
        lines.append("    {")
        lines.append(f'        if (!c.keep_member(out.members, key, "{t.name}"))')
        lines.append("            return false;")
        lines.append("    }")
        lines.append("    return !c.failed();")
        lines.append("}")
        return "\n".join(lines)
    if t.fields:
        lines.append("    std::uint64_t seen = 0;")
    lines.append("    std::string_view key;")
    lines.append("    while (c.next_key(key))")
    lines.append("    {")
    first = True
    for bit, f in enumerate(t.fields):
        where = f"{t.name}.{f.json_name}"
        keyword = "if" if first else "else if"
        first = False
        lines.append(f'        {keyword} (key == "{f.json_name}")')
        lines.append("        {")
        lines.append(f'            if (!c.once(seen, {bit}, "{where}") || !{bind_call(f, "out." + f.name, where)})')
        lines.append("                return false;")
        lines.append("        }")
    fallback = f'c.keep_member(out.extra, key, "{t.name}")' if t.extra else "c.skip()"
    if t.fields:
        lines.append(f"        else if (!{fallback})")
    else:
        lines.append(f"        if (!{fallback})")
    lines.append("            return false;")
    lines.append("    }")
    lines.append("    if (c.failed())")
    lines.append("        return false;")
    for bit, f in enumerate(t.fields):
        if f.required:
            lines.append(f"    if ((seen & (std::uint64_t{{1}} << {bit}U)) == 0)")
            lines.append(f'        return c.fail(Category::invalid_response, "{t.name}.{f.json_name}", "missing");')
    lines.append("    return true;")
    lines.append("}")
    return "\n".join(lines)


def write_value(field, expr, indent):
    pad = " " * indent
    kind = field.kind
    if kind in ("string", "nullable"):
        return [f"{pad}w.string({expr});"]
    if kind == "raw":
        return [f"{pad}w.raw({expr});"]
    if kind == "digest":
        return [f"{pad}{{", f"{pad}    const auto hex = to_hex({expr});", f"{pad}    w.string(std::string_view(hex.data(), hex.size()));", f"{pad}}}"]
    if kind in ("u64", "i64"):
        return [f"{pad}w.number({expr});"]
    if kind == "bool":
        return [f"{pad}w.boolean({expr});"]
    if kind == "object":
        return [f"{pad}write(w, {expr});"]
    if kind == "array":
        element = field.info["element"]
        return [f"{pad}w.begin_array();", f"{pad}for (const auto& item : {expr})", f"{pad}{{",
                *write_value(element, "item", indent + 4), f"{pad}}}", f"{pad}w.end_array();"]
    raise ValueError(kind)


def emit_write(t, top_level):
    lines = [f"void write(json::Writer& w, const {t.name}& value)", "{", "    w.begin_object();"]
    if top_level:
        lines.append('    w.key("schema");')
        lines.append("    w.number(std::uint64_t{1});")
    for f in t.fields:
        expr = f"value.{f.name}"
        optional = not f.required and f.kind in ("u64", "i64", "bool", "digest", "object")
        if f.required:
            lines.append(f'    w.key("{f.json_name}");')
            lines.extend(write_value(f, expr, 4))
        elif optional:
            lines.append(f"    if ({expr})")
            lines.append("    {")
            lines.append(f'        w.key("{f.json_name}");')
            lines.extend(write_value(f, "*" + expr, 8))
            lines.append("    }")
        else:
            lines.append(f"    if (!{expr}.empty())")
            lines.append("    {")
            lines.append(f'        w.key("{f.json_name}");')
            lines.extend(write_value(f, expr, 8))
            lines.append("    }")
    lines.append("    w.end_object();")
    lines.append("}")
    return "\n".join(lines)


def written_types(generator, root):
    """The types a writer of `root` needs, nested ones first."""
    order = []

    def visit(name):
        if name in order:
            return
        for f in generator.types[name].fields:
            for nested in nested_types(f):
                visit(nested)
        order.append(name)

    visit(root)
    return order


def nested_types(field):
    if field.kind == "object":
        return [field.info["type"]]
    if field.kind == "array":
        return nested_types(field.info["element"])
    return []


def ordered(generator):
    """Every type after the types its members hold by value."""
    order = []

    def visit(name):
        if name in order:
            return
        for f in generator.types[name].fields:
            for nested in nested_types(f):
                visit(nested)
        order.append(name)

    for name in generator.types:
        visit(name)
    return order


BANNER = """// Generated by cpp/tools/gen_types.py from spec/schemas/v1 (draft 0.3).
// Do not edit: change the generator or the schemas, then run it again.
"""


def generate():
    schemas = Schemas(SCHEMAS)
    g = Generator(schemas)
    documents = []
    for file, function, type_name, direction in DOCUMENTS:
        schema = schemas.files[file]
        named = g.ref_name(schema, file)
        if named:
            target, _, _ = schemas.resolve_ref(f"common.json#/$defs/{named}", file)
            name = g.object_type(target, "common.json", NAMED[named])
        else:
            name = g.object_type(schema, file, type_name)
        documents.append((file, function, name, direction))

    order = ordered(g)
    header = [BANNER, "#pragma once", "",
              "#include <cstdint>", "#include <optional>", "#include <string_view>", "#include <utility>", "",
              "#include <lantern/document.hpp>", "#include <lantern/json.hpp>", "#include <lantern/memory.hpp>",
              "#include <lantern/sha256.hpp>", "", "namespace lantern", "{", "",
              "// The `schema` of every document this library reads and writes (SPEC.md § 3.2).",
              "inline constexpr std::uint64_t known_schema = 1;", "",
              "// An optional member copied onto another allocator.",
              "template <class T> std::optional<T> with_allocator(const std::optional<T>& value, const Allocator& allocator)",
              "{", "    if (!value)", "        return std::nullopt;", "    return std::optional<T>(std::in_place, *value, allocator);", "}", "",
              "template <class T> std::optional<T> with_allocator(std::optional<T>&& value, const Allocator& allocator)",
              "{", "    if (!value)", "        return std::nullopt;", "    return std::optional<T>(std::in_place, std::move(*value), allocator);",
              "}", ""]
    for name in order:
        header.append(emit_struct(g.types[name]))
        header.append("")
    header.append("// Binding, member by member (BindContext, document.hpp).")
    for name in order:
        header.append(f"[[nodiscard]] bool bind(BindContext& c, {name}& out);")
    header.append("")
    header.append("// The documents, read with the `schema` rule: an empty optional for a newer schema.")
    writes = []
    for file, function, name, direction in documents:
        if direction == "read":
            header.append(f"// {file}")
            header.append(f"[[nodiscard]] Read<{name}> {function}(std::string_view text, const DecodeOptions& options = {{}});")
        else:
            writes.append((file, function, name))
    header.append("")
    header.append("// The documents a client sends, written with `schema` 1.")
    written = []
    for file, function, name in writes:
        for nested in written_types(g, name):
            if nested not in written:
                written.append(nested)
    for name in written:
        header.append(f"void write(json::Writer& w, const {name}& value);")
    for file, function, name in writes:
        header.append(f"// {file}")
        header.append(f"void {function}(const {name}& value, String& out);")
    header += ["", "} // namespace lantern", ""]

    roots = {name for _, _, name in writes}
    source = [BANNER, "#include <lantern/types.hpp>", "", "#include <cstdint>", "", "namespace lantern", "{", ""]
    for name in order:
        source.append(emit_bind(g.types[name]))
        source.append("")
    for file, function, name, direction in documents:
        if direction == "read":
            source.append(f"Read<{name}> {function}(std::string_view text, const DecodeOptions& options)")
            source.append("{")
            source.append(f"    return read_document<{name}>(text, known_schema, options,")
            source.append(f"                                 [](BindContext& c, {name}& value) {{ return bind(c, value); }});")
            source.append("}")
            source.append("")
    for name in written:
        source.append(emit_write(g.types[name], name in roots))
        source.append("")
    for file, function, name in writes:
        source.append(f"void {function}(const {name}& value, String& out)")
        source.append("{")
        source.append("    json::Writer w(out);")
        source.append("    write(w, value);")
        source.append("}")
        source.append("")
    source += ["} // namespace lantern", ""]
    return "\n".join(header), "\n".join(source)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--check", action="store_true", help="fail when the committed files differ")
    args = p.parse_args(argv)
    header, source = generate()
    if args.check:
        stale = [str(path.relative_to(CPP.parent)) for path, text in ((HEADER, header), (SOURCE, source))
                 if not path.exists() or path.read_text(encoding="utf-8") != text]
        if stale:
            print("stale, run python3 cpp/tools/gen_types.py: " + ", ".join(stale), file=sys.stderr)
            return 1
        print("generated types: up to date")
        return 0
    SOURCE.parent.mkdir(parents=True, exist_ok=True)
    HEADER.write_text(header, encoding="utf-8")
    SOURCE.write_text(source, encoding="utf-8")
    print(f"wrote {HEADER.relative_to(CPP.parent)} and {SOURCE.relative_to(CPP.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
