// node:crypto for the browser, as much of it as the SDK's server reaches in this page: SHA-256 by the SDK's own
// (typescript/src/sha256.ts) and randomness by the browser's. The playground builds the server with `node:crypto`
// pointed here (tools/build_playground.mjs).
import { Sha256 } from "../../typescript/src/sha256.ts";

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export function createHash(algorithm: string): {
  update(data: Uint8Array | string): ReturnType<typeof createHash>;
  digest(encoding?: "hex"): string | Uint8Array;
} {
  if (algorithm !== "sha256") throw new Error(`${algorithm}: only sha256 is here`);
  const hasher = new Sha256();
  const handle = {
    update(data: Uint8Array | string) {
      hasher.update(typeof data === "string" ? new TextEncoder().encode(data) : data);
      return handle;
    },
    digest(encoding?: "hex") {
      const out = hasher.digest();
      return encoding === "hex" ? hex(out) : out;
    },
  };
  return handle;
}

export function randomBytes(size: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(size));
}

export function randomInt(max: number): number {
  const range = 2 ** 32 - (2 ** 32 % max);
  for (;;) {
    const [n] = globalThis.crypto.getRandomValues(new Uint32Array(1));
    if (n !== undefined && n < range) return n % max;
  }
}

export function randomUUID(): string {
  return globalThis.crypto.randomUUID();
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** HMAC-SHA-256 (RFC 2104), by the SDK's SHA-256: what the server seals its cursors with. */
export function createHmac(algorithm: string, key: Uint8Array | string): ReturnType<typeof createHash> {
  if (algorithm !== "sha256") throw new Error(`${algorithm}: only sha256 is here`);
  const raw = typeof key === "string" ? new TextEncoder().encode(key) : key;
  const block = new Uint8Array(64);
  if (raw.length > 64) {
    const h = new Sha256();
    h.update(raw);
    block.set(h.digest());
  } else {
    block.set(raw);
  }
  const inner = new Sha256();
  inner.update(block.map((b) => b ^ 0x36));
  const handle = {
    update(data: Uint8Array | string) {
      inner.update(typeof data === "string" ? new TextEncoder().encode(data) : data);
      return handle;
    },
    digest(encoding?: "hex") {
      const outer = new Sha256();
      outer.update(block.map((b) => b ^ 0x5c));
      outer.update(inner.digest());
      const out = outer.digest();
      return encoding === "hex" ? hex(out) : out;
    },
  };
  return handle;
}
