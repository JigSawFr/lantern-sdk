/**
 * Bytes and their text forms: UTF-8, hex, base64 (with padding) and
 * base64url (without), the way the protocol writes them. No dependency:
 * the same code runs in a browser and in Node.
 */

const encoder = new TextEncoder();
const strict = new TextDecoder("utf-8", { fatal: true });

/** The UTF-8 bytes of `text`. */
export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

/** `bytes` as UTF-8 text; a TypeError when they are not UTF-8. */
export function fromUtf8(bytes: Uint8Array): string {
  return strict.decode(bytes);
}

/** How many bytes `text` takes in UTF-8. */
export function utf8Length(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        n += 4;
        i++;
      } else n += 3;
    } else n += 3;
  }
  return n;
}

const HEX = "0123456789abcdef";

/** Lower-case hex. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += (HEX[b >> 4] ?? "") + (HEX[b & 15] ?? "");
  return out;
}

/** The bytes of a hex string; a RangeError when it is not one. */
export function fromHex(text: string): Uint8Array {
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) throw new RangeError("not hex");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Base64, with padding (RFC 4648 § 4). */
export function toBase64(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += (B64[n >> 18] ?? "") + (B64[(n >> 12) & 63] ?? "") + (B64[(n >> 6) & 63] ?? "") + (B64[n & 63] ?? "");
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] ?? 0) << 16;
    out += `${B64[n >> 18] ?? ""}${B64[(n >> 12) & 63] ?? ""}==`;
  } else if (rest === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8);
    out += `${B64[n >> 18] ?? ""}${B64[(n >> 12) & 63] ?? ""}${B64[(n >> 6) & 63] ?? ""}=`;
  }
  return out;
}

/** Base64url, without padding (RFC 4648 § 5). */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/**
 * The bytes of a base64 text (RFC 4648 § 4), strictly: its alphabet alone,
 * its padding where it belongs, nothing else (no space, no line break).
 * `undefined` when it is not one.
 */
export function fromBase64(text: string): Uint8Array | undefined {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return undefined;
  const body = text.replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((body.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const c of body) {
    value = (value << 6) | B64.indexOf(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (value >> bits) & 255;
    }
  }
  // Bits left over must be zero (a canonical encoding).
  if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) return undefined;
  return out;
}

/** The bytes of a base64url text, with or without its padding; `undefined` when it is not one. */
export function fromBase64Url(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(text)) return undefined;
  const plain = text.replace(/=+$/, "").replaceAll("-", "+").replaceAll("_", "/");
  return fromBase64(plain + "=".repeat((4 - (plain.length % 4)) % 4));
}

/** Whether two byte strings are the same, in a time that does not depend on where they differ. */
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Byte strings put end to end. */
export function concat(parts: readonly Uint8Array[]): Uint8Array {
  let size = 0;
  for (const p of parts) size += p.length;
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** `n` random bytes, from the platform's cryptographic generator. */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** A view of `bytes` as an ArrayBuffer of their own, which WebCrypto and fetch take. */
export function buffer(bytes: Uint8Array): ArrayBuffer {
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength && bytes.buffer instanceof ArrayBuffer) {
    return bytes.buffer;
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
