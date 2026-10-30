/**
 * The limits of SPEC.md § 13, which a client bounds what it reads with and a
 * server stays within, and a JSON reader that keeps to them.
 */

import { DocumentError, type JSONValue } from "./base.ts";
import { fromUtf8, utf8Length } from "./bytes.ts";

export const JSON_DOCUMENT = 32 << 20; // a JSON document, in bytes
export const DEPTH = 16; // a JSON document's nesting
export const STRING = 4096; // a string field, in UTF-8 bytes
export const NAME = 512;
export const NOTE = 120;
export const PROFILE = 64;
export const PAGE_ITEMS = 1000;
export const TITLES_AT_ONCE = 100;
export const MANIFEST_FILES = 4096;
export const PATH = 1024;
export const PATH_PART = 255;
export const PACKAGES = 16;
export const TAGS = 32;
export const TAG = 64;
export const REQUIRED_DATA = 256;
export const ACCEPT = 32;
export const CHEAT_SET = 1 << 20;
export const DATAGRAM = 1200;
export const SIGNATURE_HEADER = 1024;

/** The string fields whose bound is not STRING, by name. */
export const STRING_CAPS: Readonly<Record<string, number>> = { name: NAME, note: NOTE, profile: PROFILE };

const LIST_BOUNDS: Readonly<Record<string, number>> = {
  items: PAGE_ITEMS,
  manifest: MANIFEST_FILES,
  packages: PACKAGES,
  tags: TAGS,
  accept: ACCEPT,
};

/**
 * Every way `document` goes beyond SPEC.md § 13 ([] when it does not): its
 * depth, its strings (by their key's bound), and the lists the section bounds.
 */
export function problems(document: unknown, caps: Readonly<Record<string, number>> = STRING_CAPS): string[] {
  const out: string[] = [];
  const walk = (value: unknown, depth: number, key: string | undefined, path: string): void => {
    if (out.length > 20) return;
    if (typeof value === "object" && value !== null && depth > DEPTH) {
      out.push(`${path}: nested deeper than ${DEPTH}`);
      return;
    }
    if (Array.isArray(value)) {
      const bound = key !== undefined ? LIST_BOUNDS[key] : undefined;
      if (bound !== undefined && value.length > bound) out.push(`${path}: ${value.length} items, above ${bound}`);
      value.forEach((v, i) => {
        walk(v, depth + 1, key === "tags" ? "tag" : key, `${path}[${i}]`);
      });
    } else if (typeof value === "object" && value !== null) {
      const o = value as Record<string, unknown>;
      for (const [k, v] of Object.entries(o)) walk(v, depth + 1, k, `${path}.${k}`);
      const data = o["requires_data"];
      if (key === "port" && Array.isArray(data)) {
        let count = 0;
        for (const d of data) {
          const groups = typeof d === "object" && d !== null ? (d as Record<string, unknown>)["one_of"] : undefined;
          count += Array.isArray(groups)
            ? groups.reduce((n: number, g: unknown) => n + (Array.isArray(g) ? g.length : 0), 0)
            : 1;
        }
        if (count > REQUIRED_DATA) out.push(`${path}.requires_data: ${count} files, above ${REQUIRED_DATA}`);
      }
    } else if (typeof value === "string") {
      const cap = key === "tag" ? TAG : ((key !== undefined ? caps[key] : undefined) ?? STRING);
      if (value.length * 3 > cap) {
        const size = utf8Length(value);
        if (size > cap) out.push(`${path}: ${size} bytes, above ${cap}`);
      }
    }
  };
  walk(document, 1, undefined, "$");
  return out;
}

/** How deep a JSON text nests, read before it is parsed (so that a hostile depth never reaches the parser). */
export function jsonDepth(text: string): number {
  let depth = 0;
  let deepest = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++;
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) inString = true;
    else if (c === 0x7b || c === 0x5b) {
      depth++;
      if (depth > deepest) deepest = depth;
    } else if (c === 0x7d || c === 0x5d) depth--;
  }
  return deepest;
}

export interface LoadOptions {
  limit?: number;
  caps?: Readonly<Record<string, number>>;
  where?: string;
}

/**
 * A JSON document read within SPEC.md § 13: at most `limit` bytes, UTF-8,
 * nested 16 deep at most, its strings within their bounds; DocumentError otherwise.
 */
export function loadJson(raw: Uint8Array | string, options: LoadOptions = {}): JSONValue {
  const where = options.where ?? "document";
  const limit = options.limit ?? JSON_DOCUMENT;
  const size = typeof raw === "string" ? utf8Length(raw) : raw.length;
  if (size > limit) throw new DocumentError(`${size} bytes, above ${limit}`, where);
  let text: string;
  try {
    text = typeof raw === "string" ? raw : fromUtf8(raw);
  } catch {
    throw new DocumentError("not UTF-8", where);
  }
  if (jsonDepth(text) > DEPTH) throw new DocumentError(`nested deeper than ${DEPTH}`, where);
  let document: JSONValue;
  try {
    document = JSON.parse(text) as JSONValue;
  } catch (e) {
    throw new DocumentError(`not JSON (${e instanceof Error ? e.message.slice(0, 80) : "unreadable"})`, where);
  }
  const found = problems(document, options.caps ?? STRING_CAPS);
  if (found.length > 0) throw new DocumentError(`beyond SPEC.md § 13: ${found.slice(0, 3).join("; ")}`, where);
  return document;
}

/** `text` cut to `limit` UTF-8 bytes, on a character's boundary. */
export function clip(text: string, limit: number): string {
  if (utf8Length(text) <= limit) return text;
  let out = "";
  let size = 0;
  for (const c of text) {
    const n = utf8Length(c);
    if (size + n > limit) break;
    out += c;
    size += n;
  }
  return out;
}

/**
 * `text` without control characters, within `limit` bytes: what a client shows
 * of a server's `detail` or `motd` (SPEC.md § 12).
 */
export function printable(text: string, limit: number = STRING): string {
  let kept = "";
  for (const c of text) {
    const code = c.codePointAt(0) ?? 0;
    if (c === "\n" || (code >= 32 && !(code >= 127 && code < 160))) kept += c;
  }
  return clip(kept, limit);
}
