/**
 * Device keys and signed requests (SPEC.md § 5.4, RFC 9421 HTTP Message
 * Signatures), for both sides.
 *
 * A token bound to a device key travels with a signature of the request, by
 * that key, under the label `lantern`:
 *
 * - its components, in this order: "@method", "@target-uri", then
 *   "authorization" when the request carries a token, then "content-digest"
 *   when it has a body (a poll of a keyed pairing carries no token);
 * - its parameters, in this order: created (Unix seconds), nonce (22 to 64
 *   characters of base64url, 128 random bits at least), keyid (the base64url
 *   of the SHA-256 of the key's 32 bytes, unpadded) and alg="ed25519";
 * - the signature base: one line per component, then "@signature-params",
 *   joined by a line feed, without one at the end.
 *
 * A client signs with `signRequest()` (a `DeviceKey`); a server checks with
 * `verifyRequest()`, which throws `Refused` with the code § 5.4 gives, in its
 * order. `vectors/signatures.json` spells out the bytes.
 */

import { fromBase64, randomBytes, toBase64, toBase64Url, toHex, utf8 } from "./bytes.ts";
import { contentDigest } from "./digest.ts";
import * as ed25519 from "./ed25519.ts";
import { sha256 } from "./sha256.ts";

export const LABEL = "lantern";
export const ALG = "ed25519";
/** auth.skew when a server announces none (SPEC.md § 5.4), and its bounds. */
export const SKEW = 300;
export const SKEW_RANGE = [60, 900] as const;
/** Signature-Input and Signature, each (SPEC.md § 13). */
export const HEADER_LIMIT = 1024;
export const CODES = ["signature_required", "signature_invalid", "signature_expired", "signature_replayed"] as const;
export type RefusalCode = (typeof CODES)[number];

const INPUT =
  /^lantern=\(((?:"[a-z@-]+")(?: "[a-z@-]+")*)\);created=([0-9]{1,12});nonce="([A-Za-z0-9_-]{22,64})";keyid="([A-Za-z0-9_-]{43})";alg="ed25519"$/;
const VALUE = /^lantern=:([A-Za-z0-9+/]{86}==):$/;
const NONCE = /^[A-Za-z0-9_-]{22,64}$/;

/** A key's thumbprint, its `keyid`: the base64url of the SHA-256 of its 32 bytes, without padding. */
export function keyid(publicKey: Uint8Array): string {
  return toBase64Url(sha256(publicKey));
}

/** A key's short fingerprint, for people (SPEC.md § 5.3's form): `21FE 31DF A154 A261`. */
export function shortFingerprint(publicKey: Uint8Array): string {
  const head = toHex(sha256(publicKey)).slice(0, 16).toUpperCase();
  return [0, 4, 8, 12].map((i) => head.slice(i, i + 4)).join(" ");
}

/** A nonce: 128 random bits, base64url, 22 characters. */
export function newNonce(): string {
  return toBase64Url(randomBytes(16));
}

/**
 * A device's Ed25519 key for one server (SPEC.md § 5.4): made at pairing, kept
 * with the token, never sent anywhere. Its private half is a WebCrypto
 * CryptoKey, non-extractable unless asked: a browser keeps it in IndexedDB as
 * it is; Node writes the seed of an extractable one to its store.
 */
export class DeviceKey {
  readonly privateKey: CryptoKey;
  readonly publicKey: Uint8Array;
  readonly keyid: string;
  readonly fingerprint: string;

  private constructor(pair: ed25519.KeyPair) {
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
    this.keyid = keyid(pair.publicKey);
    this.fingerprint = shortFingerprint(pair.publicKey);
  }

  /** A new key: a device that pairs again makes a new one. */
  static async generate(options: { extractable?: boolean } = {}): Promise<DeviceKey> {
    return new DeviceKey(await ed25519.generate(options.extractable ?? false));
  }

  /** A key from its 32-byte secret seed. */
  static async fromSeed(seed: Uint8Array, options: { extractable?: boolean } = {}): Promise<DeviceKey> {
    return new DeviceKey(await ed25519.fromSeed(seed, options.extractable ?? false));
  }

  /** A key from its seed in base64 (as a ServerRecord keeps it). */
  static async fromBase64(seed: string, options: { extractable?: boolean } = {}): Promise<DeviceKey> {
    const raw = fromBase64(seed);
    if (raw?.length !== 32) throw new RangeError("a device key is its 32-byte seed, in base64");
    return DeviceKey.fromSeed(raw, options);
  }

  /** A key from a CryptoKey kept by the app (IndexedDB) and its public key's 32 bytes. */
  static fromCryptoKey(privateKey: CryptoKey, publicKey: Uint8Array): DeviceKey {
    if (publicKey.length !== 32) throw new RangeError("an Ed25519 public key is 32 bytes");
    return new DeviceKey({ privateKey, publicKey });
  }

  get extractable(): boolean {
    return this.privateKey.extractable;
  }

  get publicKeyBase64(): string {
    return toBase64(this.publicKey);
  }

  /** The secret seed, in base64: for the place the device keeps its keys, and nowhere else. */
  async seedBase64(): Promise<string> {
    return toBase64(await ed25519.exportSeed(this.privateKey));
  }

  /** `key` of a pairing request: {"alg": "ed25519", "public_key": <base64>}. */
  document(): { alg: "ed25519"; public_key: string } {
    return { alg: ALG, public_key: this.publicKeyBase64 };
  }

  sign(message: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(this.privateKey, message);
  }

  toString(): string {
    return `DeviceKey(${this.keyid})`;
  }

  toJSON(): { keyid: string } {
    return { keyid: this.keyid };
  }
}

/**
 * `@target-uri` (RFC 9421 § 2.2.2, SPEC.md § 5.4): the scheme, the host in
 * lower case, its port only when not the scheme's default, then the path and
 * query exactly as sent (their percent-encoding unchanged).
 */
export function targetUri(url: string): string {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?/.exec(url);
  const scheme = m?.[1]?.toLowerCase();
  const authority = m?.[2] ?? "";
  if (m === null || (scheme !== "http" && scheme !== "https") || authority === "" || authority.includes("@")) {
    throw new TypeError(`${url.slice(0, 100)} is not an absolute http(s) URL`);
  }
  const hp = /^(\[[0-9A-Fa-f:.]+\]|[^:[\]]+)(?::(\d{1,5}))?$/.exec(authority);
  if (hp?.[1] === undefined) throw new TypeError(`${url.slice(0, 100)} has no host this library reads`);
  let host = hp[1].toLowerCase();
  const port = hp[2] !== undefined && hp[2] !== "" ? Number(hp[2]) : undefined;
  if (port !== undefined && port !== (scheme === "https" ? 443 : 80)) host += `:${port}`;
  const path = m[3] || "/";
  const query = m[4] !== undefined && m[4].length > 1 ? m[4] : "";
  return `${scheme}://${host}${path}${query}`;
}

/** `@target-uri` of a request a server received: its scheme, its `Host` header and its request target as sent. */
export function receivedUri(scheme: string, host: string, target: string): string {
  const h = host.trim();
  if (!h || /[/?#@ \t]/.test(h)) throw new TypeError("no Host this server can read");
  return targetUri(`${scheme}://${h}${target.startsWith("/") ? target : `/${target}`}`);
}

/** The components a request covers, in their order. */
export function components(withToken: boolean, withBody: boolean): string[] {
  return ["@method", "@target-uri", ...(withToken ? ["authorization"] : []), ...(withBody ? ["content-digest"] : [])];
}

/** `@signature-params`: the `lantern` member's value of Signature-Input. */
export function signatureParams(covered: readonly string[], created: number, nonce: string, keyId: string): string {
  const inner = covered.map((c) => `"${c}"`).join(" ");
  return `(${inner});created=${created};nonce="${nonce}";keyid="${keyId}";alg="${ALG}"`;
}

/** The signature base (RFC 9421 § 2.5) of SPEC.md § 5.4's components. */
export function signatureBase(
  method: string,
  uri: string,
  authorization: string | undefined,
  digest: string | undefined,
  params: string,
): string {
  const lines = [`"@method": ${method}`, `"@target-uri": ${uri}`];
  if (authorization !== undefined) lines.push(`"authorization": ${authorization}`);
  if (digest !== undefined) lines.push(`"content-digest": ${digest}`);
  lines.push(`"@signature-params": ${params}`);
  return lines.join("\n");
}

export interface SignOptions {
  /** Unix seconds; the clock's when absent. */
  created?: number;
  nonce?: string;
}

/**
 * Signs a request in place (SPEC.md § 5.4): adds Content-Digest when it has a
 * body and none, then Signature-Input and Signature. It covers `authorization`
 * when `headers` has an Authorization.
 */
export async function signRequest(
  key: DeviceKey,
  method: string,
  url: string,
  headers: Headers,
  body: Uint8Array | undefined,
  options: SignOptions = {},
): Promise<void> {
  const authorization = headers.get("Authorization") ?? undefined;
  let digest: string | undefined;
  const withBody = body !== undefined && body.length > 0;
  if (withBody) {
    digest = headers.get("Content-Digest") ?? undefined;
    if (digest === undefined) {
      digest = contentDigest(body);
      headers.set("Content-Digest", digest);
    }
  }
  const nonce = options.nonce ?? newNonce();
  if (!NONCE.test(nonce)) throw new RangeError("a nonce is 22 to 64 characters of base64url");
  const created = Math.trunc(options.created ?? Date.now() / 1000);
  const params = signatureParams(components(authorization !== undefined, withBody), created, nonce, key.keyid);
  const base = signatureBase(method.toUpperCase(), targetUri(url), authorization, digest, params);
  headers.set("Signature-Input", `${LABEL}=${params}`);
  headers.set("Signature", `${LABEL}=:${toBase64(await key.sign(utf8(base)))}:`);
}

/** A signature refused (SPEC.md § 5.4): the server answers 401 with `code`. */
export class Refused extends Error {
  override name = "Refused";
  readonly code: RefusalCode;
  readonly detail: string;

  constructor(code: RefusalCode, detail: string) {
    super(`${code}: ${detail}`);
    this.code = code;
    this.detail = detail;
  }
}

/**
 * The nonces taken, per key, kept `keep` seconds (twice auth.skew at least,
 * SPEC.md § 5.4): a nonce is never taken twice within them. Bounded: past
 * `limit` entries the expired go first, then the oldest.
 */
export class NonceCache {
  readonly keep: number;
  readonly limit: number;
  readonly clock: () => number;
  #seen = new Map<string, number>();

  constructor(keep: number = 2 * SKEW, limit = 200_000, clock: () => number = () => performance.now() / 1000) {
    this.keep = keep;
    this.limit = limit;
    this.clock = clock;
  }

  /** True the first time; false when it was taken within the window. */
  take(keyId: string, nonce: string): boolean {
    const now = this.clock();
    if (this.#seen.size >= this.limit) {
      for (const [k, t] of this.#seen) if (t <= now) this.#seen.delete(k);
      if (this.#seen.size >= this.limit) {
        const oldest = [...this.#seen.entries()].sort((a, b) => a[1] - b[1]);
        for (const [k] of oldest.slice(0, Math.max(1, Math.floor(this.limit / 10)))) this.#seen.delete(k);
      }
    }
    const entry = `${keyId} ${nonce}`;
    if ((this.#seen.get(entry) ?? 0) > now) return false;
    this.#seen.set(entry, now + this.keep);
    return true;
  }

  get size(): number {
    return this.#seen.size;
  }
}

/** A signature that verified: its key's id, created and nonce. */
export interface Verified {
  keyid: string;
  created: number;
  nonce: string;
}

export interface VerifyOptions {
  withToken: boolean;
  withBody: boolean;
  nonces: NonceCache;
  skew?: number;
  /** The server's clock, Unix seconds. */
  now?: number;
}

/**
 * Checks a request's signature by the key `publicKey` (32 bytes), in the order
 * of SPEC.md § 5.4; throws Refused. `uri` is the request's @target-uri
 * (receivedUri()). The body's match with its Content-Digest is the caller's
 * to check after (422 `digest_mismatch`).
 */
export async function verifyRequest(
  method: string,
  uri: string,
  headers: Headers,
  publicKey: Uint8Array,
  options: VerifyOptions,
): Promise<Verified> {
  const input = headers.get("Signature-Input");
  const value = headers.get("Signature");
  if (!input || !value) {
    throw new Refused(
      "signature_required",
      "This token is bound to a device key: sign the request (Signature-Input, Signature).",
    );
  }
  if (input.length > HEADER_LIMIT || value.length > HEADER_LIMIT) {
    throw new Refused("signature_invalid", "Signature-Input and Signature are 1 KiB at most.");
  }
  const m = INPUT.exec(input.trim());
  const v = VALUE.exec(value.trim());
  if (m === null || v === null) {
    throw new Refused(
      "signature_invalid",
      "Signature-Input or Signature is not of the form SPEC.md § 5.4 gives (the label lantern alone, its parameters in their order).",
    );
  }
  const covered = (m[1] ?? "").split(" ").map((c) => c.replaceAll('"', ""));
  const wanted = components(options.withToken, options.withBody);
  if (covered.join(" ") !== wanted.join(" ")) {
    throw new Refused("signature_invalid", `The signature covers ${covered.join(" ")}, not ${wanted.join(" ")}`);
  }
  const digest = headers.get("Content-Digest") ?? undefined;
  if (options.withBody && !digest) {
    throw new Refused("signature_invalid", "A signed request with a body carries its Content-Digest.");
  }
  const kid = m[4] ?? "";
  if (kid !== keyid(publicKey)) throw new Refused("signature_invalid", "keyid is not this token's key.");
  const params = input.trim().slice(LABEL.length + 1);
  const base = signatureBase(
    method.toUpperCase(),
    uri,
    options.withToken ? (headers.get("Authorization") ?? undefined) : undefined,
    options.withBody ? digest : undefined,
    params,
  );
  const signature = fromBase64(v[1] ?? "");
  if (signature === undefined || !(await ed25519.verify(publicKey, utf8(base), signature))) {
    throw new Refused("signature_invalid", "The signature does not verify over the signature base of SPEC.md § 5.4.");
  }
  const created = Number(m[2]);
  const clock = options.now ?? Date.now() / 1000;
  const skew = options.skew ?? SKEW;
  if (Math.abs(created - clock) > skew) {
    throw new Refused(
      "signature_expired",
      `created is ${Math.trunc(created - clock)} s from this server's clock: take its Date, and sign within ${skew} s.`,
    );
  }
  const nonce = m[3] ?? "";
  if (!options.nonces.take(kid, nonce)) {
    throw new Refused("signature_replayed", "This nonce was taken already: a new one for each request.");
  }
  return { keyid: kid, created, nonce };
}

/** Accept-Signature (RFC 9421 § 5.1) for a 401 of a signature: the components and parameters the server wants. */
export function acceptSignature(withToken: boolean, withBody: boolean, keyId?: string): string {
  const wanted = components(withToken, withBody)
    .map((c) => `"${c}"`)
    .join(" ");
  return `${LABEL}=(${wanted})${keyId ? `;keyid="${keyId}"` : ""};alg="${ALG}"`;
}

/** A server's Accept-Signature, read: the components it wants, and the keyid and alg it names. */
export interface AcceptSignature {
  components: string[];
  keyid: string | undefined;
  alg: string | undefined;
}

const ACCEPT = /^\s*lantern=\(((?:"[a-z@-]+"(?: "[a-z@-]+")*)?)\)((?:;[a-z]+=(?:"[^"]*"|[0-9]+))*)\s*$/;

/** The `lantern` member of an Accept-Signature, or undefined when there is none this library can read. */
export function parseAcceptSignature(value: string | undefined): AcceptSignature | undefined {
  if (!value || value.length > HEADER_LIMIT) return undefined;
  for (const member of value.split(/,(?=\s*[a-z][a-z0-9_-]*=)/)) {
    const m = ACCEPT.exec(member);
    if (m === null) continue;
    const covered = m[1] ? m[1].split(" ").map((c) => c.replaceAll('"', "")) : [];
    const params = new Map<string, string>();
    for (const p of (m[2] ?? "").matchAll(/;([a-z]+)=(?:"([^"]*)"|[0-9]+)/g)) params.set(p[1] ?? "", p[2] ?? "");
    return { components: covered, keyid: params.get("keyid") || undefined, alg: params.get("alg") || undefined };
  }
  return undefined;
}
