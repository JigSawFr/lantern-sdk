/**
 * Ed25519 (RFC 8032): the verification of a homebrew's signature (SPEC.md
 * § 8.4) and of a signed request (§ 5.4), and the device key a client makes
 * at pairing and signs its requests with (§ 5.4).
 *
 * Every verification first refuses what § 8.4 (L-8.4-4) refuses: a key or an R
 * that does not decode, is not encoded canonically, or is one of the 8 points
 * of small order, and an S of L or more. Those checks are this module's own,
 * in BigInt arithmetic over public data; only then is the equation checked,
 * by the platform's WebCrypto (Node 22 and later, and the browsers of 2025:
 * Chrome 137, Firefox 129, Safari 17). A platform without Ed25519 in its
 * WebCrypto gets an `Unsupported` error, never a silent fallback: this
 * library carries no Ed25519 of its own for secret keys.
 */

import { Unsupported } from "./base.ts";
import { buffer, concat } from "./bytes.ts";

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const D = mod(-121665n * inverse(121666n));
const SQRT_M1 = power(2n, (P - 1n) / 4n);
/** The fixed head of an Ed25519 private key's PKCS #8 (RFC 8410), before its 32-byte seed. */
const PKCS8_HEAD = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const ALGORITHM = { name: "Ed25519" } as const;

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

function inverse(a: bigint): bigint {
  return power(a, P - 2n);
}

function littleEndian(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] ?? 0);
  return n;
}

type Point = readonly [bigint, bigint, bigint, bigint];

/** The point of a 32-byte encoding, or undefined when it does not decode canonically. */
function decode(raw: Uint8Array): Point | undefined {
  if (raw.length !== 32) return undefined;
  let y = littleEndian(raw);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= P) return undefined; // not canonical: a y of p or more
  const x2 = mod((y * y - 1n) * inverse(D * y * y + 1n));
  if (x2 === 0n) {
    if (sign) return undefined; // not canonical: x = 0 with its sign bit set
    return [0n, y, 1n, 0n];
  }
  let x = power(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return undefined;
  if ((x & 1n) !== sign) x = P - x;
  return [x, y, 1n, mod(x * y)];
}

function add(a: Point, b: Point): Point {
  const [x1, y1, z1, t1] = a;
  const [x2, y2, z2, t2] = b;
  const pa = mod((y1 - x1) * (y2 - x2));
  const pb = mod((y1 + x1) * (y2 + x2));
  const pc = mod(2n * t1 * t2 * D);
  const pd = mod(2n * z1 * z2);
  const e = pb - pa;
  const f = pd - pc;
  const g = pd + pc;
  const h = pb + pa;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

/** Whether `point` is one of the eight points of small order: for them [8]P is the identity. */
function smallOrder(point: Point): boolean {
  let q = point;
  for (let i = 0; i < 3; i++) q = add(q, q);
  return mod(q[0]) === 0n && mod(q[1] - q[2]) === 0n;
}

/**
 * The checks every verification makes first: both points decode canonically,
 * neither has a small order, and S is reduced (SPEC.md § 8.4, L-8.4-4).
 */
export function strictlyEncoded(publicKey: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const a = decode(publicKey);
  const r = decode(signature.subarray(0, 32));
  if (a === undefined || r === undefined || smallOrder(a) || smallOrder(r)) return false;
  return littleEndian(signature.subarray(32)) < L;
}

/**
 * Whether `publicKey` is a key a server takes at pairing (SPEC.md § 5.4,
 * L-5.4-12): 32 bytes that decode canonically to a point not of small order.
 */
export function isPublicKey(publicKey: Uint8Array): boolean {
  const point = decode(publicKey);
  return point !== undefined && !smallOrder(point);
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (s === undefined) throw new Unsupported("no WebCrypto here (a secure context is needed in a browser)");
  return s;
}

function unsupported(e: unknown): never {
  if (e instanceof Error && (e.name === "NotSupportedError" || /not supported|unrecognized/i.test(e.message))) {
    throw new Unsupported("this platform's WebCrypto has no Ed25519 (Node 22 or later, or a browser of 2025)");
  }
  throw e;
}

/** Whether this platform's WebCrypto signs and verifies with Ed25519. */
export async function available(): Promise<boolean> {
  try {
    await subtle().importKey("raw", buffer(new Uint8Array(32).fill(0x11)), ALGORITHM, false, ["verify"]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether `signature` (64 bytes) is `publicKey`'s (32 bytes) over `message`,
 * after the checks of `strictlyEncoded`. Unsupported when this platform has no Ed25519.
 */
export async function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (!strictlyEncoded(publicKey, signature)) return false;
  let key: CryptoKey;
  try {
    key = await subtle().importKey("raw", buffer(publicKey), ALGORITHM, false, ["verify"]);
  } catch (e) {
    return unsupported(e);
  }
  try {
    return await subtle().verify(ALGORITHM, key, buffer(signature), buffer(message));
  } catch {
    return false;
  }
}

/** A key pair made or imported by WebCrypto, and its public key's 32 bytes. */
export interface KeyPair {
  privateKey: CryptoKey;
  publicKey: Uint8Array;
}

/**
 * A new key pair. `extractable` false (the default) keeps the private key
 * inside the platform's crypto: a browser stores such a CryptoKey in
 * IndexedDB as it is, never as bytes. A key that must be written to a file
 * (Node) is made extractable.
 */
export async function generate(extractable = false): Promise<KeyPair> {
  let pair: CryptoKeyPair;
  try {
    pair = (await subtle().generateKey(ALGORITHM, extractable, ["sign", "verify"])) as CryptoKeyPair;
  } catch (e) {
    return unsupported(e);
  }
  const raw = new Uint8Array(await subtle().exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicKey: raw };
}

/** The key pair of a 32-byte secret seed (RFC 8032 § 5.1.5). */
export async function fromSeed(seed: Uint8Array, extractable = false): Promise<KeyPair> {
  if (seed.length !== 32) throw new RangeError("an Ed25519 seed is 32 bytes");
  let privateKey: CryptoKey;
  try {
    privateKey = await subtle().importKey("pkcs8", buffer(concat([PKCS8_HEAD, seed])), ALGORITHM, true, ["sign"]);
  } catch (e) {
    return unsupported(e);
  }
  const jwk = await subtle().exportKey("jwk", privateKey);
  if (typeof jwk.x !== "string") throw new Unsupported("no public key from this platform's Ed25519");
  const publicJwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: jwk.x };
  const publicKey = new Uint8Array(
    await subtle().exportKey("raw", await subtle().importKey("jwk", publicJwk, ALGORITHM, true, ["verify"])),
  );
  if (!extractable) {
    privateKey = await subtle().importKey("pkcs8", buffer(concat([PKCS8_HEAD, seed])), ALGORITHM, false, ["sign"]);
  }
  return { privateKey, publicKey };
}

/** The 32-byte seed of an extractable private key. */
export async function exportSeed(privateKey: CryptoKey): Promise<Uint8Array> {
  if (!privateKey.extractable) throw new Unsupported("this device key is not extractable: it stays where it was made");
  const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", privateKey));
  return pkcs8.slice(pkcs8.length - 32);
}

/** An Ed25519 signature (deterministic: the same bytes on every platform). */
export async function sign(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().sign(ALGORITHM, privateKey, buffer(message)));
}
