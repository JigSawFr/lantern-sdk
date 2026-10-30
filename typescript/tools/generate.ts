#!/usr/bin/env node
/**
 * Generates the library's types and readers from the specification's JSON Schemas.
 *
 *     node tools/generate.ts           # writes src/generated/
 *     node tools/generate.ts --check   # exits 1 when what is committed is stale
 *
 * It reads spec/schemas/v1/*.json (the submodule at the repository's root)
 * and writes, under src/generated/:
 *
 * - models.ts: an interface per object of the schemas, and its reader, which
 *   checks the type of every field it knows and keeps the others (SPEC.md
 *   § 3.2); the vocabularies the schemas enumerate (genres, scopes, error
 *   codes…); DOCUMENTS, each document's reader by its file's name;
 * - schemas.ts: the schemas themselves, which the library's validator
 *   (src/schema.ts) checks documents against, in a browser too.
 *
 * The names follow python/tools/generate.py's, so that both libraries say the
 * same things. Node alone, no dependency.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type Node = Record<string, unknown>;

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE = resolve(HERE, "..");
const SCHEMAS = resolve(PACKAGE, "..", "spec", "schemas", "v1");
const OUT = join(PACKAGE, "src", "generated");

// Type names, by where the object is in the schemas: "<file>" for a document,
// "common#<def>" for a definition, then "/<property>" and "[]" for an array's items.
const NAMES: Record<string, string> = {
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
  cheats: "CheatSets",
  requests: "TitleRequests",
};
// Fields a reader takes even when a writer must give them (SPEC.md § 8.1: a
// kind it does not know, or none, is an app).
const LENIENT = new Set(["Homebrew.kind"]);
// The vocabularies the schemas enumerate, by where they are.
const VOCABULARIES: Record<string, [string, string[], string]> = {
  GENRES: ["common", ["$defs", "genre", "enum"], "Genres of a title or a homebrew (SPEC.md § 7.1)."],
  SCOPES: ["common", ["$defs", "scope", "enum"], "What a token may do (SPEC.md § 4.2)."],
  SAVE_KINDS: ["common", ["$defs", "save_kind", "enum"], "A save's kinds (SPEC.md § 9.1)."],
  GPU_NAMES: [
    "common",
    ["$defs", "requires", "properties", "gpu", "items", "enum"],
    "Graphics interfaces of requires.gpu (SPEC.md § 8.7).",
  ],
  ERROR_CODES: ["problem", ["properties", "code", "enum"], "The error codes of SPEC.md § 12."],
  ACCOUNT_STATES: [
    "handshake",
    ["properties", "account", "properties", "state", "enum"],
    "An account's states (SPEC.md § 4.2).",
  ],
  REQUEST_STATUSES: [
    "common",
    ["$defs", "request", "properties", "status", "enum"],
    "A request's statuses (SPEC.md § 11).",
  ],
};

interface Type {
  ts: string;
  check: string;
}

interface Field {
  key: string;
  type: Type;
  required: boolean;
}

interface Model {
  name: string;
  where: string;
  doc: string;
  fields: Field[];
}

function pascal(text: string): string {
  return text
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join("");
}

function isNode(value: unknown): value is Node {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

class Generator {
  readonly schemas: Record<string, Node> = {};
  readonly common: Record<string, Node>;
  readonly models = new Map<string, Model>();
  readonly byWhere = new Map<string, string>();
  readonly documents = new Map<string, string>();

  constructor(folder: string) {
    for (const file of readdirSync(folder).sort()) {
      if (file.endsWith(".json")) {
        this.schemas[file.slice(0, -5)] = JSON.parse(readFileSync(join(folder, file), "utf8")) as Node;
      }
    }
    const common = this.schemas["common"];
    if (!common || !isNode(common["$defs"])) throw new Error("generate: no common.json");
    this.common = common["$defs"] as Record<string, Node>;
  }

  ref(ref: string): [string, Node] {
    const m = /^(?:common\.json)?#\/\$defs\/([A-Za-z0-9_]+)$/.exec(ref);
    const name = m?.[1];
    const node = name !== undefined ? this.common[name] : undefined;
    if (name === undefined || node === undefined) throw new Error(`generate: unknown $ref ${ref}`);
    return [`common#${name}`, node];
  }

  static isModel(node: unknown): node is Node {
    return isNode(node) && "properties" in node && !isNode(node["additionalProperties"]);
  }

  typeOf(node: unknown, where: string): Type {
    if (!isNode(node)) return { ts: "unknown", check: "m.any" };
    if (typeof node["$ref"] === "string") {
      const [target, schema] = this.ref(node["$ref"]);
      if (target === "common#required_data") return this.requiredData();
      if (Generator.isModel(schema)) return this.modelType(this.model(target, schema));
      return this.typeOf(schema, target);
    }
    if (Array.isArray(node["allOf"])) {
      for (const part of node["allOf"]) {
        if (isNode(part) && "$ref" in part) return this.typeOf(part, where);
      }
    }
    if (Array.isArray(node["oneOf"])) {
      const options = node["oneOf"] as unknown[];
      const isNull = (o: unknown) => isNode(o) && o["type"] === "null" && Object.keys(o).length === 1;
      const nulls = options.filter(isNull);
      const rest = options.filter((o) => !isNull(o));
      if (nulls.length > 0 && rest.length === 1) {
        const inner = this.typeOf(rest[0], where);
        return { ts: `${inner.ts} | null`, check: `m.nullable(${inner.check})` };
      }
      return { ts: "unknown", check: "m.any" };
    }
    if ("const" in node) {
      const c = node["const"];
      if (typeof c === "string") return scalar("string");
      if (typeof c === "boolean") return scalar("boolean");
      if (typeof c === "number") return Number.isInteger(c) ? scalar("integer") : scalar("number");
    }
    if (Array.isArray(node["enum"]) && node["enum"].every((e) => typeof e === "string")) return scalar("string");
    const kind = node["type"];
    if (kind === "string" || kind === "integer" || kind === "boolean" || kind === "number") return scalar(kind);
    if (kind === "array") {
      const item = this.typeOf(node["items"], `${where}[]`);
      const ts = item.ts.includes("|") ? `(${item.ts})[]` : `${item.ts}[]`;
      return { ts, check: `m.list(${item.check})` };
    }
    if (kind === "object" && isNode(node["additionalProperties"])) {
      const value = this.typeOf(node["additionalProperties"], `${where}{}`);
      return { ts: `Record<string, ${value.ts}>`, check: `m.map(${value.check})` };
    }
    if (Generator.isModel(node)) return this.modelType(this.model(where, node));
    if (kind === "object") return { ts: "Record<string, unknown>", check: "m.map(m.any)" };
    return { ts: "unknown", check: "m.any" };
  }

  modelType(name: string): Type {
    return { ts: name, check: `read${name}` };
  }

  requiredData(): Type {
    const node = this.common["required_data"]?.["oneOf"];
    if (!Array.isArray(node) || node.length !== 2) throw new Error("generate: required_data is not two options");
    this.typeOf(node[0], "common#required_data");
    this.model("common#required_data", node[1] as Node);
    return { ts: "RequiredData", check: "readRequiredData" };
  }

  model(where: string, node: Node): string {
    const known = this.byWhere.get(where);
    if (known !== undefined) return known;
    const tail = where.includes("#") ? (where.split("#").pop() ?? where) : where;
    const name = NAMES[where] ?? pascal(tail.replaceAll("[]", ""));
    const other = this.models.get(name);
    if (other) throw new Error(`generate: two types named ${name} (${where}, ${other.where})`);
    const doc = String(node["description"] ?? node["title"] ?? "").trim();
    const model: Model = { name, where, doc, fields: [] };
    this.byWhere.set(where, name);
    this.models.set(name, model);
    const required = new Set(Array.isArray(node["required"]) ? (node["required"] as string[]) : []);
    const properties = isNode(node["properties"]) ? node["properties"] : {};
    for (const [key, prop] of Object.entries(properties)) {
      if (isNode(prop) && isNode(prop["not"]) && Object.keys(prop["not"]).length === 0) continue; // must not be there
      const type = this.typeOf(prop, `${where}/${key}`);
      model.fields.push({ key, type, required: required.has(key) && !LENIENT.has(`${name}.${key}`) });
    }
    return name;
  }

  run(): void {
    for (const name of Object.keys(this.schemas).sort()) {
      if (name === "common") continue;
      const node = this.schemas[name] as Node;
      if (typeof node["$ref"] === "string") {
        const [where, target] = this.ref(node["$ref"]);
        this.documents.set(name, this.model(where, target));
      } else if (Array.isArray(node["allOf"])) {
        // A document is a definition of common.json (a $ref) or an object of its own, and then the part that
        // adds its `schema`.
        const parts = (node["allOf"] as unknown[]).filter(isNode);
        const withRef = parts.find((p) => typeof p["$ref"] === "string");
        let model: string;
        if (withRef !== undefined) {
          const [where, target] = this.ref(withRef["$ref"] as string);
          model = this.model(where, target);
        } else {
          const own = parts.find((p) => !(isNode(p["properties"]) && "schema" in p["properties"]));
          if (own === undefined) throw new Error(`generate: ${name} has no part of its own`);
          model = this.model(name, { description: node["description"] ?? "", ...own });
        }
        this.documents.set(name, model);
        const found = this.models.get(model);
        if (found && !found.fields.some((f) => f.key === "schema")) {
          found.fields.unshift({ key: "schema", type: scalar("integer"), required: false });
        }
      } else {
        this.documents.set(name, this.model(name, node));
      }
    }
  }

  vocabulary(path: [string, string[], string]): string[] {
    let node: unknown = this.schemas[path[0]];
    for (const key of path[1]) node = isNode(node) ? node[key] : undefined;
    if (!Array.isArray(node)) throw new Error(`generate: no vocabulary at ${path[0]} ${path[1].join("/")}`);
    return node as string[];
  }

  source(): string {
    const lines = [
      "// Generated by tools/generate.ts from spec/schemas/v1: do not edit.",
      "/**",
      " * Lantern's documents, as types generated from the specification's JSON",
      " * Schemas (spec/schemas/v1). Each reader checks the type of every field it",
      " * knows, recursively, and gives back the object it was given, the fields it",
      " * does not know kept on it (SPEC.md § 3.2).",
      " */",
      "",
      'import * as m from "../model.ts";',
      "",
    ];
    for (const [name, path] of Object.entries(VOCABULARIES)) {
      lines.push(`/** ${path[2]} */`);
      lines.push(`export const ${name} = [`);
      for (const v of this.vocabulary(path)) lines.push(`  ${JSON.stringify(v)},`);
      lines.push("] as const;", "");
    }
    for (const model of this.models.values()) lines.push(...this.modelSource(model), "");
    lines.push(
      "/** A file the user supplies, or a group of alternatives (`one_of`) (SPEC.md § 8.6). */",
      "export type RequiredData = RequiredFile | RequiredDataGroup;",
      "",
      'export function readRequiredData(value: unknown, where = "RequiredData"): RequiredData {',
      '  if (typeof value === "object" && value !== null && "one_of" in value) return readRequiredDataGroup(value, where);',
      "  return readRequiredFile(value, where);",
      "}",
      "",
      "/** Each document of spec/schemas/v1, by its file's name, and its type. */",
      "export interface Documents {",
    );
    for (const [doc, model] of this.documents) lines.push(`  ${JSON.stringify(doc)}: ${model};`);
    lines.push("}", "", "/** Each document's reader, by its file's name. */");
    lines.push("export const DOCUMENTS: { readonly [K in keyof Documents]: m.Check<Documents[K]> } = {");
    for (const [doc, model] of this.documents) lines.push(`  ${JSON.stringify(doc)}: read${model},`);
    lines.push("};", "");
    return lines.join("\n");
  }

  modelSource(model: Model): string[] {
    const first = model.doc ? (model.doc.split(". ")[0] ?? "").replace(/\.$/, "") : model.name;
    const where = model.where.replace("common#", "common.json#/$defs/");
    const out = ["/**", ` * ${first.replaceAll("*/", "* /")}.`, " *", ` * From ${where}.`, " */"];
    out.push(`export interface ${model.name} {`);
    for (const f of model.fields) {
      const key = /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(f.key) ? f.key : JSON.stringify(f.key);
      out.push(`  ${key}${f.required ? "" : "?"}: ${f.type.ts};`);
    }
    out.push("}", "");
    out.push(
      `export function read${model.name}(value: unknown, where = ${JSON.stringify(model.name)}): ${model.name} {`,
    );
    out.push("  const o = m.obj(value, where);");
    for (const f of model.fields) {
      out.push(`  m.${f.required ? "req" : "opt"}(o, ${JSON.stringify(f.key)}, where, ${f.type.check});`);
    }
    out.push(`  return o as unknown as ${model.name};`, "}");
    return out;
  }
}

function scalar(kind: "string" | "integer" | "boolean" | "number"): Type {
  switch (kind) {
    case "string":
      return { ts: "string", check: "m.str" };
    case "integer":
      return { ts: "number", check: "m.int" };
    case "number":
      return { ts: "number", check: "m.num" };
    case "boolean":
      return { ts: "boolean", check: "m.bool" };
  }
}

function schemasSource(folder: string): string {
  const lines = [
    "// Generated by tools/generate.ts from spec/schemas/v1: do not edit.",
    "/** The specification's JSON Schemas (spec/schemas/v1), by their file's name, for src/schema.ts. */",
    "",
    "export const SCHEMAS: Readonly<Record<string, unknown>> = {",
  ];
  for (const file of readdirSync(folder).sort()) {
    if (!file.endsWith(".json")) continue;
    const doc = JSON.parse(readFileSync(join(folder, file), "utf8")) as unknown;
    lines.push(`  ${JSON.stringify(file.slice(0, -5))}: ${JSON.stringify(doc)},`);
  }
  lines.push("};", "");
  return lines.join("\n");
}

export function generated(folder: string): Record<string, string> {
  const gen = new Generator(folder);
  gen.run();
  return { "models.ts": gen.source(), "schemas.ts": schemasSource(folder) };
}

function main(argv: string[]): number {
  const check = argv.includes("--check");
  if (!existsSync(join(SCHEMAS, "common.json"))) {
    console.error(`generate: no schemas in ${SCHEMAS} (git submodule update --init)`);
    return 2;
  }
  const files = generated(SCHEMAS);
  const stale: string[] = [];
  for (const [rel, content] of Object.entries(files)) {
    const path = join(OUT, rel);
    const current = existsSync(path) ? readFileSync(path, "utf8") : undefined;
    if (current !== content) {
      stale.push(rel);
      if (!check) {
        mkdirSync(OUT, { recursive: true });
        writeFileSync(path, content);
      }
    }
  }
  const extra = existsSync(OUT) ? readdirSync(OUT).filter((f) => !(f in files)) : [];
  stale.push(...extra);
  if (check) {
    for (const rel of stale) console.error(`generate: ${rel} is stale: run node tools/generate.ts`);
    return stale.length > 0 ? 1 : 0;
  }
  if (extra.length > 0) console.error(`generate: ${extra.join(", ")} not generated: remove it`);
  console.error(`generate: ${Object.keys(files).length} files, ${stale.length} written`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
