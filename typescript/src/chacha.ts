/**
 * ChaCha20, HChaCha20, Poly1305 and the AEADs built on them, in TypeScript:
 * WebCrypto has none of them, and this library carries no dependency.
 *
 * - ChaCha20 and ChaCha20-Poly1305: RFC 8439;
 * - HChaCha20 and XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03.
 *
 * What end-to-end encrypted saves need (SPEC.md § 9.4, src/e2e.ts), tested
 * against the RFCs' vectors and the specification's. Every function that takes
 * a key leaves no copy of it behind in what it allocated: its working state is
 * zeroed before it returns. What JavaScript cannot promise about memory (a
 * copy the engine made, a page swapped out) is said in src/e2e.ts.
 */

import { DocumentError } from "./base.ts";

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] as const;

function u32(b: Uint8Array, i: number): number {
  return ((b[i] ?? 0) | ((b[i + 1] ?? 0) << 8) | ((b[i + 2] ?? 0) << 16) | ((b[i + 3] ?? 0) << 24)) >>> 0;
}

function put32(b: Uint8Array, i: number, v: number): void {
  b[i] = v & 0xff;
  b[i + 1] = (v >>> 8) & 0xff;
  b[i + 2] = (v >>> 16) & 0xff;
  b[i + 3] = (v >>> 24) & 0xff;
}

function need(value: Uint8Array, length: number, what: string): void {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new DocumentError(`${length} bytes expected`, what);
  }
}

/** The 20 rounds over `x` (16 words), in place. */
function rounds(x: Uint32Array): void {
  let x0 = x[0] as number,
    x1 = x[1] as number,
    x2 = x[2] as number,
    x3 = x[3] as number,
    x4 = x[4] as number,
    x5 = x[5] as number,
    x6 = x[6] as number,
    x7 = x[7] as number,
    x8 = x[8] as number,
    x9 = x[9] as number,
    x10 = x[10] as number,
    x11 = x[11] as number,
    x12 = x[12] as number,
    x13 = x[13] as number,
    x14 = x[14] as number,
    x15 = x[15] as number;
  for (let i = 0; i < 10; i++) {
    // Columns.
    x0 = (x0 + x4) | 0;
    x12 ^= x0;
    x12 = (x12 << 16) | (x12 >>> 16);
    x8 = (x8 + x12) | 0;
    x4 ^= x8;
    x4 = (x4 << 12) | (x4 >>> 20);
    x0 = (x0 + x4) | 0;
    x12 ^= x0;
    x12 = (x12 << 8) | (x12 >>> 24);
    x8 = (x8 + x12) | 0;
    x4 ^= x8;
    x4 = (x4 << 7) | (x4 >>> 25);

    x1 = (x1 + x5) | 0;
    x13 ^= x1;
    x13 = (x13 << 16) | (x13 >>> 16);
    x9 = (x9 + x13) | 0;
    x5 ^= x9;
    x5 = (x5 << 12) | (x5 >>> 20);
    x1 = (x1 + x5) | 0;
    x13 ^= x1;
    x13 = (x13 << 8) | (x13 >>> 24);
    x9 = (x9 + x13) | 0;
    x5 ^= x9;
    x5 = (x5 << 7) | (x5 >>> 25);

    x2 = (x2 + x6) | 0;
    x14 ^= x2;
    x14 = (x14 << 16) | (x14 >>> 16);
    x10 = (x10 + x14) | 0;
    x6 ^= x10;
    x6 = (x6 << 12) | (x6 >>> 20);
    x2 = (x2 + x6) | 0;
    x14 ^= x2;
    x14 = (x14 << 8) | (x14 >>> 24);
    x10 = (x10 + x14) | 0;
    x6 ^= x10;
    x6 = (x6 << 7) | (x6 >>> 25);

    x3 = (x3 + x7) | 0;
    x15 ^= x3;
    x15 = (x15 << 16) | (x15 >>> 16);
    x11 = (x11 + x15) | 0;
    x7 ^= x11;
    x7 = (x7 << 12) | (x7 >>> 20);
    x3 = (x3 + x7) | 0;
    x15 ^= x3;
    x15 = (x15 << 8) | (x15 >>> 24);
    x11 = (x11 + x15) | 0;
    x7 ^= x11;
    x7 = (x7 << 7) | (x7 >>> 25);

    // Diagonals.
    x0 = (x0 + x5) | 0;
    x15 ^= x0;
    x15 = (x15 << 16) | (x15 >>> 16);
    x10 = (x10 + x15) | 0;
    x5 ^= x10;
    x5 = (x5 << 12) | (x5 >>> 20);
    x0 = (x0 + x5) | 0;
    x15 ^= x0;
    x15 = (x15 << 8) | (x15 >>> 24);
    x10 = (x10 + x15) | 0;
    x5 ^= x10;
    x5 = (x5 << 7) | (x5 >>> 25);

    x1 = (x1 + x6) | 0;
    x12 ^= x1;
    x12 = (x12 << 16) | (x12 >>> 16);
    x11 = (x11 + x12) | 0;
    x6 ^= x11;
    x6 = (x6 << 12) | (x6 >>> 20);
    x1 = (x1 + x6) | 0;
    x12 ^= x1;
    x12 = (x12 << 8) | (x12 >>> 24);
    x11 = (x11 + x12) | 0;
    x6 ^= x11;
    x6 = (x6 << 7) | (x6 >>> 25);

    x2 = (x2 + x7) | 0;
    x13 ^= x2;
    x13 = (x13 << 16) | (x13 >>> 16);
    x8 = (x8 + x13) | 0;
    x7 ^= x8;
    x7 = (x7 << 12) | (x7 >>> 20);
    x2 = (x2 + x7) | 0;
    x13 ^= x2;
    x13 = (x13 << 8) | (x13 >>> 24);
    x8 = (x8 + x13) | 0;
    x7 ^= x8;
    x7 = (x7 << 7) | (x7 >>> 25);

    x3 = (x3 + x4) | 0;
    x14 ^= x3;
    x14 = (x14 << 16) | (x14 >>> 16);
    x9 = (x9 + x14) | 0;
    x4 ^= x9;
    x4 = (x4 << 12) | (x4 >>> 20);
    x3 = (x3 + x4) | 0;
    x14 ^= x3;
    x14 = (x14 << 8) | (x14 >>> 24);
    x9 = (x9 + x14) | 0;
    x4 ^= x9;
    x4 = (x4 << 7) | (x4 >>> 25);
  }
  x[0] = x0;
  x[1] = x1;
  x[2] = x2;
  x[3] = x3;
  x[4] = x4;
  x[5] = x5;
  x[6] = x6;
  x[7] = x7;
  x[8] = x8;
  x[9] = x9;
  x[10] = x10;
  x[11] = x11;
  x[12] = x12;
  x[13] = x13;
  x[14] = x14;
  x[15] = x15;
}

/** ChaCha20's initial state for `key` (32 bytes), `counter` and `nonce` (12 bytes). */
function state(key: Uint8Array, counter: number, nonce: Uint8Array): Uint32Array {
  const s = new Uint32Array(16);
  s.set(SIGMA);
  for (let i = 0; i < 8; i++) s[4 + i] = u32(key, 4 * i);
  s[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) s[13 + i] = u32(nonce, 4 * i);
  return s;
}

/** The ChaCha20 block function (RFC 8439 § 2.3): 64 bytes of key stream. */
export function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  need(key, 32, "chacha20.key");
  need(nonce, 12, "chacha20.nonce");
  const s = state(key, counter, nonce);
  const x = new Uint32Array(s);
  rounds(x);
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) put32(out, 4 * i, ((x[i] as number) + (s[i] as number)) >>> 0);
  s.fill(0);
  x.fill(0);
  return out;
}

/**
 * ChaCha20 (RFC 8439 § 2.4): `input` XORed with the key stream from block
 * `counter`, into `output` (which may be `input`). A message of 2^32 blocks or
 * more would reuse the counter: refused.
 */
export function chacha20(
  key: Uint8Array,
  nonce: Uint8Array,
  counter: number,
  input: Uint8Array,
  output: Uint8Array = new Uint8Array(input.length),
): Uint8Array {
  need(key, 32, "chacha20.key");
  need(nonce, 12, "chacha20.nonce");
  if (output.length < input.length) throw new RangeError("chacha20: the output is shorter than the input");
  if (counter + Math.ceil(input.length / 64) > 0x1_0000_0000) throw new RangeError("chacha20: the counter wraps");
  const s = state(key, counter, nonce);
  const x = new Uint32Array(16);
  const block = new Uint8Array(64);
  for (let at = 0; at < input.length; at += 64) {
    x.set(s);
    rounds(x);
    for (let i = 0; i < 16; i++) put32(block, 4 * i, ((x[i] as number) + (s[i] as number)) >>> 0);
    const n = Math.min(64, input.length - at);
    for (let i = 0; i < n; i++) output[at + i] = (input[at + i] as number) ^ (block[i] as number);
    s[12] = ((s[12] as number) + 1) >>> 0;
  }
  s.fill(0);
  x.fill(0);
  block.fill(0);
  return output;
}

/** HChaCha20 (draft-irtf-cfrg-xchacha-03 § 2.2): a 32-byte subkey of `key` and a 16-byte `nonce`. */
export function hchacha20(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  need(key, 32, "hchacha20.key");
  need(nonce, 16, "hchacha20.nonce");
  const x = new Uint32Array(16);
  x.set(SIGMA);
  for (let i = 0; i < 8; i++) x[4 + i] = u32(key, 4 * i);
  for (let i = 0; i < 4; i++) x[12 + i] = u32(nonce, 4 * i);
  rounds(x);
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) put32(out, 4 * i, x[i] as number);
  for (let i = 0; i < 4; i++) put32(out, 16 + 4 * i, x[12 + i] as number);
  x.fill(0);
  return out;
}

/**
 * Poly1305 (RFC 8439 § 2.5), over 13-bit limbs so that every product stays
 * exact in a double. Fed with update(), then finish() once.
 */
export class Poly1305 {
  readonly #r = new Float64Array(10);
  readonly #h = new Float64Array(10);
  readonly #d = new Float64Array(10);
  readonly #s: Uint8Array;
  readonly #buffer = new Uint8Array(16);
  #held = 0;
  #done = false;

  constructor(key: Uint8Array) {
    need(key, 32, "poly1305.key");
    const r = new Uint8Array(key.subarray(0, 16));
    // Clamping (RFC 8439 § 2.5.1).
    for (const i of [3, 7, 11, 15]) r[i] = (r[i] as number) & 0x0f;
    for (const i of [4, 8, 12]) r[i] = (r[i] as number) & 0xfc;
    Poly1305.limbs(r, 0, 0, this.#r);
    r.fill(0);
    this.#s = new Uint8Array(key.subarray(16, 32));
  }

  /** The 130-bit number of 16 bytes at `at`, plus `top` × 2^128, as 10 limbs of 13 bits. */
  static limbs(b: Uint8Array, at: number, top: number, out: Float64Array): void {
    for (let i = 0; i < 10; i++) {
      const bit = 13 * i;
      const byte = bit >>> 3;
      const word =
        (byte < 16 ? (b[at + byte] as number) : 0) |
        (byte + 1 < 16 ? (b[at + byte + 1] as number) << 8 : 0) |
        (byte + 2 < 16 ? (b[at + byte + 2] as number) << 16 : 0);
      out[i] = (word >>> (bit & 7)) & 0x1fff;
    }
    out[9] = (out[9] as number) + top * 2048; // bit 128 is bit 11 of limb 9 (bits 117 to 129)
  }

  #block(b: Uint8Array, at: number, top: number): void {
    const h = this.#h;
    const r = this.#r;
    const d = this.#d;
    Poly1305.limbs(b, at, top, d);
    for (let i = 0; i < 10; i++) h[i] = (h[i] as number) + (d[i] as number);
    for (let i = 0; i < 10; i++) {
      let sum = 0;
      for (let j = 0; j <= i; j++) sum += (h[j] as number) * (r[i - j] as number);
      for (let j = i + 1; j < 10; j++) sum += (h[j] as number) * 5 * (r[i - j + 10] as number);
      d[i] = sum;
    }
    let c = 0;
    for (let i = 0; i < 10; i++) {
      const v = (d[i] as number) + c;
      c = Math.floor(v / 8192);
      h[i] = v - c * 8192;
    }
    // 2^130 = 5 (mod 2^130 - 5).
    let v = (h[0] as number) + c * 5;
    c = Math.floor(v / 8192);
    h[0] = v - c * 8192;
    v = (h[1] as number) + c;
    c = Math.floor(v / 8192);
    h[1] = v - c * 8192;
    h[2] = (h[2] as number) + c;
  }

  update(data: Uint8Array): this {
    if (this.#done) throw new Error("poly1305: finished");
    let at = 0;
    if (this.#held > 0) {
      const n = Math.min(16 - this.#held, data.length);
      this.#buffer.set(data.subarray(0, n), this.#held);
      this.#held += n;
      at = n;
      if (this.#held < 16) return this;
      this.#block(this.#buffer, 0, 1);
      this.#held = 0;
    }
    for (; at + 16 <= data.length; at += 16) this.#block(data, at, 1);
    if (at < data.length) {
      this.#buffer.set(data.subarray(at));
      this.#held = data.length - at;
    }
    return this;
  }

  /** The 16-byte tag; the state is wiped. */
  finish(): Uint8Array {
    if (this.#done) throw new Error("poly1305: finished");
    this.#done = true;
    if (this.#held > 0) {
      this.#buffer[this.#held] = 1;
      this.#buffer.fill(0, this.#held + 1);
      this.#block(this.#buffer, 0, 0);
    }
    // Once per message: the exact sum, reduced, in BigInt.
    let acc = 0n;
    for (let i = 9; i >= 0; i--) acc = (acc << 13n) + BigInt(this.#h[i] as number);
    const p = (1n << 130n) - 5n;
    acc %= p;
    let s = 0n;
    for (let i = 15; i >= 0; i--) s = (s << 8n) + BigInt(this.#s[i] as number);
    acc = (acc + s) & ((1n << 128n) - 1n);
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      out[i] = Number(acc & 0xffn);
      acc >>= 8n;
    }
    this.#r.fill(0);
    this.#h.fill(0);
    this.#d.fill(0);
    this.#s.fill(0);
    this.#buffer.fill(0);
    return out;
  }
}

/** Poly1305 of `message` under a one-time `key` (32 bytes). */
export function poly1305(key: Uint8Array, message: Uint8Array): Uint8Array {
  return new Poly1305(key).update(message).finish();
}

/** Whether two byte strings are equal, in a time that does not depend on where they differ. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

const PAD = new Uint8Array(16);

function tag(otk: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const mac = new Poly1305(otk);
  mac.update(aad).update(PAD.subarray(0, (16 - (aad.length % 16)) % 16));
  mac.update(ciphertext).update(PAD.subarray(0, (16 - (ciphertext.length % 16)) % 16));
  const lengths = new Uint8Array(16);
  const view = new DataView(lengths.buffer);
  view.setBigUint64(0, BigInt(aad.length), true);
  view.setBigUint64(8, BigInt(ciphertext.length), true);
  return mac.update(lengths).finish();
}

/** ChaCha20-Poly1305 (RFC 8439 § 2.8): the ciphertext, then its 16-byte tag. */
export function chacha20poly1305Seal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(),
): Uint8Array {
  const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
  const out = new Uint8Array(plaintext.length + 16);
  const ciphertext = out.subarray(0, plaintext.length);
  chacha20(key, nonce, 1, plaintext, ciphertext);
  out.set(tag(otk, aad, ciphertext), plaintext.length);
  otk.fill(0);
  return out;
}

/** The plaintext of `sealed` (ciphertext and tag), or undefined when it does not open: nothing of it is decrypted. */
export function chacha20poly1305Open(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array = new Uint8Array(),
): Uint8Array | undefined {
  if (sealed.length < 16) return undefined;
  const ciphertext = sealed.subarray(0, sealed.length - 16);
  const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
  const expected = tag(otk, aad, ciphertext);
  otk.fill(0);
  if (!equalBytes(expected, sealed.subarray(sealed.length - 16))) return undefined;
  return chacha20(key, nonce, 1, ciphertext);
}

function xnonce(key: Uint8Array, nonce: Uint8Array): [Uint8Array, Uint8Array] {
  need(nonce, 24, "xchacha20.nonce");
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  const inner = new Uint8Array(12);
  inner.set(nonce.subarray(16, 24), 4);
  return [subkey, inner];
}

/** XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03 § 2.3): a 24-byte nonce; the ciphertext, then its tag. */
export function xchacha20poly1305Seal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(),
): Uint8Array {
  const [subkey, inner] = xnonce(key, nonce);
  try {
    return chacha20poly1305Seal(subkey, inner, plaintext, aad);
  } finally {
    subkey.fill(0);
  }
}

/** The plaintext of an XChaCha20-Poly1305 `sealed`, or undefined when it does not open. */
export function xchacha20poly1305Open(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array = new Uint8Array(),
): Uint8Array | undefined {
  const [subkey, inner] = xnonce(key, nonce);
  try {
    return chacha20poly1305Open(subkey, inner, sealed, aad);
  } finally {
    subkey.fill(0);
  }
}
