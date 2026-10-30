/**
 * Mirrors, grants and peers (SPEC.md § 19): what a client checks of a mirror's
 * address, what a grant says and whether it verifies, and the addresses a
 * peer is reached at. A file comes from a mirror or a peer only by its hash:
 * whatever they serve is checked by its size and SHA-256 before anything is
 * kept (L-19.1-1), and they get no credential of the server (L-19.1-2).
 */

import { isObject } from "./base.ts";
import { fromBase64, fromBase64Url, fromUtf8, toBase64Url, utf8 } from "./bytes.ts";
import * as ed25519 from "./ed25519.ts";
import { isLoopback } from "./http.ts";
import { SHA256_HEX } from "./vocabulary.ts";

/** A grant's purpose (SPEC.md § 19.3). */
export const GRANT_PURPOSE = "lantern-grant-1";
/** A grant's longest text (SPEC.md § 13), and its longest life (§ 19.3). */
export const GRANT_LIMIT = 1024;
export const GRANT_LIFETIME_LIMIT = 900;
/** A file's mirrors at most (SPEC.md § 19.2, § 13). */
export const MIRRORS_LIMIT = 8;
/** The header a peer reads a grant from (SPEC.md § 19.4). */
export const GRANT_HEADER = "Lantern-Grant";

/** What a grant says (SPEC.md § 19.3). */
export interface GrantPayload {
  exp: number;
  purpose: string;
  sha256: string;
  size: number;
  uid: string;
}

/** A grant's payload: these keys in this order, no space (SPEC.md § 19.3). */
export function grantPayload(uid: string, sha256: string, size: number, exp: number): Uint8Array {
  if (!SHA256_HEX.test(sha256)) throw new RangeError("sha256 is 64 lower-case hex digits");
  if (!Number.isSafeInteger(size) || size < 0 || !Number.isSafeInteger(exp)) throw new RangeError("size and exp");
  return utf8(
    `{"exp":${exp},"purpose":"${GRANT_PURPOSE}","sha256":"${sha256}","size":${size},"uid":${JSON.stringify(uid)}}`,
  );
}

/** A grant signed by the server's grant key (its private CryptoKey): `<payload>.<signature>`, base64url. */
export async function signGrant(
  key: CryptoKey,
  uid: string,
  sha256: string,
  size: number,
  exp: number,
): Promise<string> {
  const payload = grantPayload(uid, sha256, size, exp);
  return `${toBase64Url(payload)}.${toBase64Url(await ed25519.sign(key, payload))}`;
}

/** A grant's payload as it reads, unverified; undefined when it is not of a grant's form. */
export function grantContents(grant: string): GrantPayload | undefined {
  if (typeof grant !== "string" || grant.length > GRANT_LIMIT) return undefined;
  const m = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{86})$/.exec(grant);
  if (m === null) return undefined;
  const payload = fromBase64Url(m[1] as string);
  if (payload === undefined) return undefined;
  let doc: unknown;
  try {
    doc = JSON.parse(fromUtf8(payload));
  } catch {
    return undefined;
  }
  if (!isObject(doc)) return undefined;
  const { exp, purpose, sha256, size, uid } = doc;
  if (purpose !== GRANT_PURPOSE || typeof uid !== "string" || typeof sha256 !== "string") return undefined;
  if (!Number.isSafeInteger(exp) || !Number.isSafeInteger(size) || !SHA256_HEX.test(sha256)) return undefined;
  const out: GrantPayload = { exp: exp as number, purpose, sha256, size: size as number, uid };
  // Only the canonical bytes are a grant: another spelling of the same object is not.
  const canonical = grantPayload(uid, sha256, out.size, out.exp);
  if (fromUtf8(canonical) !== fromUtf8(payload)) return undefined;
  return out;
}

/**
 * The payload of a grant that verifies (SPEC.md § 19.4): signed by the grant
 * key of the server whose `uid` it names, among `keys` ({uid: the 32 bytes of
 * its `peers.key`, or their base64}), and not expired at `now` (Unix seconds).
 * Undefined otherwise. Ed25519's strict checks come before WebCrypto.
 */
export async function verifyGrant(
  grant: string,
  keys: Readonly<Record<string, Uint8Array | string>>,
  now: number = Date.now() / 1000,
): Promise<GrantPayload | undefined> {
  const doc = grantContents(grant);
  if (doc === undefined) return undefined;
  const given = Object.hasOwn(keys, doc.uid) ? keys[doc.uid] : undefined;
  const key = typeof given === "string" ? fromBase64(given) : given;
  if (key === undefined || key.length !== 32 || doc.exp < now) return undefined;
  const [payload = "", signature = ""] = grant.split(".");
  const sig = fromBase64Url(signature);
  const bytes = fromBase64Url(payload);
  if (sig === undefined || bytes === undefined) return undefined;
  return (await ed25519.verify(key, bytes, sig)) ? doc : undefined;
}

function ipv4(host: string): number[] | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (m === null) return undefined;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p <= 255) ? parts : undefined;
}

/**
 * Whether `host` (an address, IPv6 in brackets or not) is of a private
 * network: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 or fe80::/10
 * (SPEC.md § 19.2). A name is not: what it resolves to is not known here.
 */
export function isPrivateAddress(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  const v4 = ipv4(h) ?? ipv4(/^::ffff:(.*)$/.exec(h)?.[1] ?? "");
  if (v4 !== undefined) {
    const [a = 0, b = 0] = v4;
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (!h.includes(":") || !/^[0-9a-f:.%a-z0-9]+$/.test(h)) return false;
  const first = h.split(":")[0] ?? "";
  if (first === "") return false;
  const word = Number.parseInt(first, 16);
  if (Number.isNaN(word) || first.length > 4) return false;
  return (word & 0xfe00) === 0xfc00 || (word & 0xffc0) === 0xfe80;
}

/** Whether plain HTTP may go to `host`: a private network's (§ 19.2), or loopback (§ 2, for testing). */
export function plainHttpToPeer(host: string): boolean {
  return isPrivateAddress(host) || isLoopback(host);
}

/**
 * Whether a client may read a mirror at `url` (SPEC.md § 19.2, L-19.2-1):
 * absolute, `https`, or `http` at an address of a private network (or
 * loopback, as § 2 allows for testing); no credentials, no fragment.
 */
export function mirrorAllowed(url: string): boolean {
  if (typeof url !== "string" || url.length > 4096) return false;
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.username || u.password || u.hash) return false;
  if (u.protocol === "https:") return u.hostname !== "";
  return u.protocol === "http:" && plainHttpToPeer(u.hostname);
}

/** The mirrors of a file a client may read, at most 8 (SPEC.md § 19.2); the others are passed by. */
export function usableMirrors(file: { mirrors?: readonly { url: string }[] | undefined }): string[] {
  return (file.mirrors ?? [])
    .slice(0, MIRRORS_LIMIT)
    .map((m) => m.url)
    .filter(mirrorAllowed);
}

/** A peer found on the LAN (SPEC.md § 19.5): where it serves, and whose grants it takes. */
export interface Peer {
  address: string;
  port: number;
  base: string;
  tls: boolean;
  uid: string;
  name: string;
  slots: number;
  servers: string[];
  /** `<scheme>://<address>:<port><base>`: where its route is. */
  url: string;
}

/** A peer's base URL: plain HTTP only at an address of a private network (L-19.4-6). */
export function peerUrl(address: string, port: number, base: string, tls: boolean): string {
  if (!tls && !plainHttpToPeer(address)) {
    throw new RangeError(`${address}: a grant goes over plain HTTP only to a private network (SPEC.md § 19.4)`);
  }
  const host = address.includes(":") ? `[${address}]` : address;
  return `${tls ? "https" : "http"}://${host}:${port}${base.replace(/\/+$/, "")}`;
}

/** The address of a file on a peer: `<peer base>/v1/blobs/sha256/<hex>`. */
export function blobUrl(peer: string, sha256: string): string {
  if (!SHA256_HEX.test(sha256)) throw new RangeError("sha256 is 64 lower-case hex digits");
  return `${peer.replace(/\/+$/, "")}/v1/blobs/sha256/${sha256}`;
}

/** The 32 bytes of a handshake's `peers.key`, or undefined when it is not one. */
export function grantKey(peers: { key?: string } | undefined): Uint8Array | undefined {
  const key = peers?.key !== undefined ? fromBase64(peers.key) : undefined;
  return key !== undefined && key.length === 32 ? key : undefined;
}
