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

/** The largest integer an I-JSON document holds: what an IEEE double holds exactly (SPEC.md § 2.3). */
export const IJSON_INTEGER = 9007199254740991n;

/**
 * Why `text`, which JSON.parse read as `document`, is not I-JSON (RFC 7493; SPEC.md § 2.3): a member name given
 * twice in an object, an integer beyond 2**53 - 1, or a lone surrogate in a string. Undefined when it is.
 */
export function ijsonProblem(text: string, document: unknown): string | undefined {
  const names: (Set<string> | null)[] = [];
  let wantName = false;
  let i = 0;
  while (i < text.length) {
    const c = text[i] as string;
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = names[names.length - 1];
      if (wantName && top) {
        const name = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.has(name)) return "a member name is given twice";
        top.add(name);
        wantName = false;
      }
      i = j + 1;
    } else if (c === "{") {
      names.push(new Set());
      wantName = true;
      i++;
    } else if (c === "[") {
      names.push(null);
      wantName = false;
      i++;
    } else if (c === "}" || c === "]") {
      names.pop();
      wantName = false;
      i++;
    } else if (c === ",") {
      wantName = names[names.length - 1] instanceof Set;
      i++;
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i + 1;
      while (j < text.length && "0123456789.eE+-".includes(text[j] as string)) j++;
      const token = text.slice(i, j);
      if (/^-?\d+$/.test(token)) {
        const n = BigInt(token);
        if ((n < 0n ? -n : n) > IJSON_INTEGER) return `the integer ${token.slice(0, 20)} is beyond 2**53 - 1`;
      }
      i = j;
    } else {
      i++;
    }
  }
  if (/\\u[dD][89a-fA-F]/.test(text) && /\\u[dD][89a-fA-F]/.test(JSON.stringify(document))) {
    return "a lone surrogate";
  }
  return undefined;
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
  if (typeof raw !== "string" && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf)
    throw new DocumentError("not I-JSON (a byte order mark)", where);
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
  const notIJson = ijsonProblem(text, document);
  if (notIJson !== undefined) throw new DocumentError(`not I-JSON (${notIJson})`, where);
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

/** Chunks in a chunk index (SPEC.md § 13, § 22.1). */
export const CHUNKS = 100000;
/** A chunk index's bytes (SPEC.md § 13, § 22.1). */
export const CHUNK_INDEX = 8 << 20;
