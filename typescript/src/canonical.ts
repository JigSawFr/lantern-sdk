/**
 * Canonical JSON (SPEC.md § 2.3): RFC 8785's JSON Canonicalization Scheme.
 * No space; an object's members sorted by their names as UTF-16 code units
 * (what JavaScript's own sort does); a string with only what JSON must escape
 * escaped (the short escapes, the other control characters as `\u00xx`, the
 * rest as it is); a number as ECMAScript writes it (`1.0` is `1`, `-0` is `0`,
 * `1e21` is `1e+21`), which is what JavaScript's own number-to-string gives.
 * Sync's merge rule (§ 20.4) compares values by it and a chunk index (§ 22.1)
 * is written in it.
 */

import { DocumentError } from "./base.ts";
import { utf8 } from "./bytes.ts";

/** Nesting deeper than this is refused: a document is bounded long before (SPEC.md § 13). */
const DEPTH = 512;

/** A value's canonical JSON as text. DocumentError for a value JSON cannot hold (NaN, infinity, undefined, a function). */
export function canonicalJson(value: unknown): string {
  return write(value, 0);
}

/** A value's canonical JSON as UTF-8 bytes: what is compared, hashed and served. */
export function canonicalBytes(value: unknown): Uint8Array {
  return utf8(canonicalJson(value));
}

function write(value: unknown, depth: number): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new DocumentError("JSON has no NaN nor infinity", "value");
      return String(value === 0 ? 0 : value);
    case "object":
      break;
    default:
      throw new DocumentError(`not JSON: ${typeof value}`, "value");
  }
  if (depth > DEPTH) throw new DocumentError("nested too deep", "value");
  if (Array.isArray(value)) return `[${value.map((v) => write(v, depth + 1)).join(",")}]`;
  const o = value as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${write(o[k], depth + 1)}`).join(",")}}`;
}
