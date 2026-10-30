/**
 * Documents checked against the specification's JSON Schemas, without a
 * dependency: the subset of JSON Schema 2020-12 that spec/schemas/v1 uses
 * ($ref, allOf, anyOf, oneOf, not, if/then/else, properties, required,
 * additionalProperties, propertyNames, items, enum, const, pattern, lengths,
 * bounds, uniqueItems, and the formats date-time, date and uuid).
 *
 *     import { validate } from "lantern-protocol";
 *     const problems = validate("homebrew", document);   // [] when valid
 *
 * A server validates what it is about to serve; a client may validate what it
 * reads. This is the writer's check, the strict one.
 */

import { SCHEMAS } from "./generated/schemas.ts";

type Schema = boolean | Record<string, unknown>;

const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/;
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const patterns = new Map<string, RegExp>();

function pattern(text: string): RegExp {
  let p = patterns.get(text);
  if (p === undefined) {
    p = new RegExp(text, "u");
    patterns.set(text, p);
  }
  return p;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function isType(value: unknown, kind: string): boolean {
  switch (kind) {
    case "object":
      return typeof value === "object" && value !== null && !Array.isArray(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    default:
      return false;
  }
}

function validDay(y: number, m: number, d: number): boolean {
  if (m < 1 || m > 12 || d < 1) return false;
  const days = [31, y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return d <= (days[m - 1] ?? 0);
}

function formatOk(value: string, format: string): boolean {
  if (format === "date-time") {
    const m = DATE_TIME.exec(value);
    if (m === null || !validDay(Number(m[1]), Number(m[2]), Number(m[3]))) return false;
    if (Number(m[4]) > 23 || Number(m[5]) > 59 || Number(m[6]) > 59) return false;
    return m[7] === undefined || (Number(m[8]) <= 23 && Number(m[9]) <= 59);
  }
  if (format === "date") {
    const m = DATE.exec(value);
    return m !== null && validDay(Number(m[1]), Number(m[2]), Number(m[3]));
  }
  if (format === "uuid") return UUID.test(value);
  return true;
}

class Validator {
  resolve(ref: string, base: string): [Schema, string] {
    const hash = ref.indexOf("#");
    const target = hash < 0 ? ref : ref.slice(0, hash);
    const pointer = hash < 0 ? "" : ref.slice(hash + 1);
    const name = target ? target.replace(/\.json$/, "") : base;
    let node: unknown = SCHEMAS[name];
    for (const part of pointer.split("/").filter(Boolean)) {
      node = (node as Record<string, unknown>)[part.replaceAll("~1", "/").replaceAll("~0", "~")];
    }
    if (node === undefined) throw new Error(`no schema at ${ref}`);
    return [node as Schema, name];
  }

  errors(value: unknown, schema: Schema, path: string, base: string): string[] {
    if (schema === true) return [];
    if (schema === false) return [`${path}: not allowed`];
    const out: string[] = [];
    const s = schema;
    if (typeof s["$ref"] === "string") {
      const [target, doc] = this.resolve(s["$ref"], base);
      out.push(...this.errors(value, target, path, doc));
    }
    for (const part of (s["allOf"] as Schema[] | undefined) ?? []) out.push(...this.errors(value, part, path, base));
    const anyOf = s["anyOf"] as Schema[] | undefined;
    if (anyOf !== undefined && !anyOf.some((x) => this.errors(value, x, path, base).length === 0)) {
      out.push(`${path}: matches none of anyOf`);
    }
    const oneOf = s["oneOf"] as Schema[] | undefined;
    if (oneOf !== undefined) {
      const n = oneOf.filter((x) => this.errors(value, x, path, base).length === 0).length;
      if (n !== 1) out.push(`${path}: matches ${n} of oneOf, not exactly one`);
    }
    if (s["not"] !== undefined && this.errors(value, s["not"] as Schema, path, base).length === 0) {
      out.push(`${path}: matches what is forbidden here`);
    }
    if (s["if"] !== undefined) {
      const branch = this.errors(value, s["if"] as Schema, path, base).length === 0 ? "then" : "else";
      if (s[branch] !== undefined) out.push(...this.errors(value, s[branch] as Schema, path, base));
    }
    if (s["type"] !== undefined) {
      const kinds = Array.isArray(s["type"]) ? (s["type"] as string[]) : [s["type"] as string];
      if (!kinds.some((k) => isType(value, k))) return [...out, `${path}: not of type ${kinds.join("/")}`];
    }
    if ("const" in s && canonical(value) !== canonical(s["const"])) {
      out.push(`${path}: not ${JSON.stringify(s["const"])}`);
    }
    const choices = s["enum"] as unknown[] | undefined;
    if (choices !== undefined && !choices.some((e) => canonical(e) === canonical(value))) {
      out.push(`${path}: ${JSON.stringify(value)?.slice(0, 60)} is not one of ${choices.join(", ").slice(0, 200)}`);
    }
    if (typeof value === "string") out.push(...this.string(value, s, path));
    else if (typeof value === "number") {
      if (typeof s["minimum"] === "number" && value < s["minimum"]) out.push(`${path}: below ${s["minimum"]}`);
      if (typeof s["maximum"] === "number" && value > s["maximum"]) out.push(`${path}: above ${s["maximum"]}`);
    } else if (Array.isArray(value)) out.push(...this.array(value, s, path, base));
    else if (typeof value === "object" && value !== null) {
      out.push(...this.object(value as Record<string, unknown>, s, path, base));
    }
    return out;
  }

  string(value: string, s: Record<string, unknown>, path: string): string[] {
    const out: string[] = [];
    const length = [...value].length;
    if (typeof s["minLength"] === "number" && length < s["minLength"])
      out.push(`${path}: shorter than ${s["minLength"]}`);
    if (typeof s["maxLength"] === "number" && length > s["maxLength"])
      out.push(`${path}: longer than ${s["maxLength"]}`);
    if (typeof s["pattern"] === "string" && !pattern(s["pattern"]).test(value)) {
      out.push(`${path}: ${JSON.stringify(value.slice(0, 60))} does not match ${s["pattern"]}`);
    }
    if (typeof s["format"] === "string" && !formatOk(value, s["format"])) {
      out.push(`${path}: ${JSON.stringify(value.slice(0, 60))} is not a ${s["format"]}`);
    }
    return out;
  }

  array(value: unknown[], s: Record<string, unknown>, path: string, base: string): string[] {
    const out: string[] = [];
    if (typeof s["minItems"] === "number" && value.length < s["minItems"])
      out.push(`${path}: fewer than ${s["minItems"]} items`);
    if (typeof s["maxItems"] === "number" && value.length > s["maxItems"])
      out.push(`${path}: more than ${s["maxItems"]} items`);
    if (s["uniqueItems"] === true && new Set(value.map(canonical)).size !== value.length)
      out.push(`${path}: an item twice`);
    if (s["items"] !== undefined) {
      value.forEach((item, i) => {
        out.push(...this.errors(item, s["items"] as Schema, `${path}[${i}]`, base));
      });
    }
    return out;
  }

  object(value: Record<string, unknown>, s: Record<string, unknown>, path: string, base: string): string[] {
    const out: string[] = [];
    for (const key of (s["required"] as string[] | undefined) ?? [])
      if (!Object.hasOwn(value, key)) out.push(`${path}: no ${key}`);
    const properties = (s["properties"] as Record<string, Schema> | undefined) ?? {};
    for (const [key, item] of Object.entries(value)) {
      if (Object.hasOwn(properties, key))
        out.push(...this.errors(item, properties[key] as Schema, `${path}.${key}`, base));
      else if (s["additionalProperties"] !== undefined) {
        out.push(...this.errors(item, s["additionalProperties"] as Schema, `${path}.${key}`, base));
      }
      if (s["propertyNames"] !== undefined) {
        for (const e of this.errors(key, s["propertyNames"] as Schema, `${path}.${key}`, base)) {
          out.push(e.replace(`${path}.${key}:`, `${path}: the key ${JSON.stringify(key)}:`));
        }
      }
    }
    return out;
  }
}

/** The documents the schemas describe (`homebrew`, `apps`…), common.json aside. */
export function names(): string[] {
  return Object.keys(SCHEMAS)
    .filter((n) => n !== "common")
    .sort();
}

/** Every way `document` breaks schemas/v1/<name>.json, as "$.path: what"; [] when it is valid. */
export function validate(name: string, document: unknown): string[] {
  if (name === "common" || !Object.hasOwn(SCHEMAS, name)) throw new RangeError(`no schema named ${name}`);
  return new Validator().errors(document, SCHEMAS[name] as Schema, "$", name);
}

export function isValid(name: string, document: unknown): boolean {
  return validate(name, document).length === 0;
}

/** Every way `value` breaks common.json's definition `name` (`app`, `homebrew`, `package`…). */
export function definition(name: string, value: unknown): string[] {
  const defs = (SCHEMAS["common"] as Record<string, Record<string, unknown>>)["$defs"] ?? {};
  if (!Object.hasOwn(defs, name)) throw new RangeError(`no definition named ${name}`);
  return new Validator().errors(value, { $ref: `common.json#/$defs/${name}` }, "$", "common");
}
