/**
 * The digest fields of RFC 9530 that Lantern uses: `Repr-Digest` on every file
 * response (SPEC.md § 6.6) and `Content-Digest` on a request body (§ 5.4,
 * § 9.2), both `sha-256=:<base64>:`.
 */

import { fromBase64, fromHex, toBase64, toHex } from "./bytes.ts";
import { sha256 } from "./sha256.ts";

const KEY = /^[a-z*][a-z0-9_\-.*]*$/;

/** The field's value for a SHA-256 (hex, or its 32 bytes): `sha-256=:<base64>:`. */
export function formatDigest(digest: string | Uint8Array): string {
  let raw: Uint8Array;
  if (typeof digest === "string") {
    if (!/^[0-9a-fA-F]{64}$/.test(digest)) throw new RangeError(`${digest.slice(0, 70)} is not a SHA-256 in hex`);
    raw = fromHex(digest);
  } else {
    if (digest.length !== 32) throw new RangeError("a SHA-256 is 32 bytes");
    raw = digest;
  }
  return `sha-256=:${toBase64(raw)}:`;
}

/** The Content-Digest of a body. */
export function contentDigest(body: Uint8Array): string {
  return formatDigest(sha256(body));
}

/**
 * A `Repr-Digest` or `Content-Digest` value (an RFC 8941 dictionary of byte
 * sequences): each algorithm and its digest. Members that are not a byte
 * sequence, or not base64, are left out; parameters are ignored.
 */
export function parseDigest(value: string): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const member of value.split(",")) {
    const eq = member.indexOf("=");
    if (eq < 0) continue;
    const key = member.slice(0, eq).trim();
    const item = (member.slice(eq + 1).split(";")[0] ?? "").trim();
    if (!KEY.test(key) || item.length < 2 || !item.startsWith(":") || !item.endsWith(":")) continue;
    const raw = fromBase64(item.slice(1, -1));
    if (raw !== undefined) out.set(key, raw);
  }
  return out;
}

/** The SHA-256 a digest field gives, lower-case hex; undefined without one (or a malformed one). */
export function digestSha256(value: string | null | undefined): string | undefined {
  if (value === null || value === undefined) return undefined;
  const raw = parseDigest(value).get("sha-256");
  return raw !== undefined && raw.length === 32 ? toHex(raw) : undefined;
}
