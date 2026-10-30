/**
 * Cursors and `since` tokens a server can give without keeping them.
 *
 * A cursor (SPEC.md § 6.2) holds the sort key of a page's last item, the listing
 * it belongs to, and when it was given, sealed with the server's secret
 * (HMAC-SHA-256). The next page starts after that key, so reading while the
 * library changes neither skips nor repeats an item. A cursor the server never
 * gave (or gave for another listing) answers 400; an expired one, 410.
 *
 * A `since` token (§ 6.4, § 7.3) holds a position in the server's change
 * journal, sealed the same way: 400 when the server never gave it, 410 when the
 * journal no longer reaches back to it.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { fromBase64Url, toBase64Url, utf8 } from "../bytes.ts";
import { badRequest, gone } from "./http.ts";

export type SortKey = readonly (string | number)[];

/** Compares two sort keys as Python compares tuples: part by part, a shorter one first. */
export function compareKeys(a: SortKey, b: SortKey): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i];
    const y = b[i];
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x < y ? -1 : 1;
    const sx = String(x);
    const sy = String(y);
    if (sx !== sy) return sx < sy ? -1 : 1;
  }
  return a.length - b.length;
}

/** Seals small JSON payloads with an HMAC, so that they come back unchanged or not at all. */
export class Sealer {
  readonly #secret: Uint8Array;

  constructor(secret?: Uint8Array) {
    this.#secret = secret ?? new Uint8Array(randomBytes(32));
  }

  #mac(prefix: string, raw: Uint8Array): Uint8Array {
    return new Uint8Array(createHmac("sha256", this.#secret).update(`${prefix}.`).update(raw).digest()).slice(0, 16);
  }

  seal(prefix: string, payload: unknown): string {
    const raw = utf8(JSON.stringify(payload));
    return `${prefix}_${toBase64Url(raw)}.${toBase64Url(this.#mac(prefix, raw))}`;
  }

  /** The payload of a token this sealer gave with `prefix`; a RangeError otherwise. */
  open(prefix: string, token: string): unknown {
    const underscore = token.indexOf("_");
    const head = underscore < 0 ? token : token.slice(0, underscore);
    const rest = underscore < 0 ? "" : token.slice(underscore + 1);
    const [body = "", mac = ""] = rest.split(".", 2);
    if (head !== prefix || !body || !mac || token.length > 1024) throw new RangeError("not a token of this server");
    const raw = fromBase64Url(body);
    const given = fromBase64Url(mac);
    if (raw === undefined || given === undefined) throw new RangeError("not a token of this server");
    const expected = this.#mac(prefix, raw);
    if (given.length !== expected.length || !timingSafeEqual(given, expected))
      throw new RangeError("not a token of this server");
    return JSON.parse(new TextDecoder().decode(raw)) as unknown;
  }
}

export interface Page<T> {
  items: T[];
  next: string | null;
  total: number;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

/** Pages of a listing, by keyset: each item has a unique sort key (break ties with the item's id). */
export class Cursors {
  readonly sealer: Sealer;
  readonly lifetime: number;
  readonly clock: () => number;

  constructor(sealer: Sealer, lifetime = 3600, clock: () => number = () => Date.now() / 1000) {
    this.sealer = sealer;
    this.lifetime = lifetime;
    this.clock = clock;
  }

  /** A listing's identity, from its route and filters: a cursor of another listing is refused. */
  scope(...parts: unknown[]): string {
    return createHash("sha256").update(stable(parts)).digest("hex").slice(0, 16);
  }

  after(cursor: string, scope: string): SortKey {
    let payload: unknown;
    try {
      payload = this.sealer.open("c", cursor);
    } catch {
      throw badRequest("Unknown cursor: one this server never gave.");
    }
    const p = payload as Record<string, unknown> | null;
    const keys = typeof p === "object" && p !== null ? p["k"] : undefined;
    if (typeof p !== "object" || p === null || p["s"] !== scope || !Array.isArray(keys)) {
      throw badRequest("This cursor belongs to another listing.");
    }
    const issued = p["t"];
    if (typeof issued !== "number" || this.clock() - issued > this.lifetime) {
      throw gone("Cursor expired: read the list again from its start.");
    }
    return keys.filter((k): k is string | number => typeof k === "string" || typeof k === "number");
  }

  /** The page of `items` (any order) after `cursor`, of `size` items at most. */
  page<T>(
    items: readonly T[],
    key: (item: T) => SortKey,
    options: { size: number; cursor: string | undefined; scope: string },
  ): Page<T> {
    const keyed = items.map((item) => ({ item, key: key(item) })).sort((a, b) => compareKeys(a.key, b.key));
    let ordered = keyed;
    if (options.cursor !== undefined) {
      const last = this.after(options.cursor, options.scope);
      ordered = keyed.filter((x) => compareKeys(x.key, last) > 0);
    }
    const chosen = ordered.slice(0, options.size);
    let next: string | null = null;
    const tail = chosen.at(-1);
    if (ordered.length > options.size && tail !== undefined) {
      next = this.sealer.seal("c", { s: options.scope, k: [...tail.key], t: Math.trunc(this.clock()) });
    }
    return { items: chosen.map((x) => x.item), next, total: items.length };
  }
}

/** `since` tokens over a change journal's positions. */
export class SinceTokens {
  readonly sealer: Sealer;

  constructor(sealer: Sealer) {
    this.sealer = sealer;
  }

  give(kind: string, epoch: string, position: number): string {
    return this.sealer.seal(kind, { e: epoch, n: position });
  }

  /** The position a token names: 400 when the server never gave it, 410 when too old. */
  position(kind: string, token: string, epoch: string, oldest: number, current: number): number {
    let payload: unknown;
    try {
      payload = this.sealer.open(kind, token);
    } catch {
      throw badRequest("Unknown since token: one this server never gave.");
    }
    const p = payload as Record<string, unknown> | null;
    const n = typeof p === "object" && p !== null ? p["n"] : undefined;
    if (typeof n !== "number" || !Number.isInteger(n)) throw badRequest("Unknown since token.");
    if (p?.["e"] !== epoch || n < oldest || n > current)
      throw gone("Token too old for this server: read them all again.");
    return n;
  }
}

/** A listing's page_size (SPEC.md § 6.2): a positive integer, lowered to `limit`; 400 otherwise. */
export function pageSize(value: string | undefined, fallback: number, limit: number): number {
  if (value === undefined || value === "") return Math.min(fallback, limit);
  if (!/^\d{1,9}$/.test(value) || Number(value) < 1) throw badRequest("page_size is a positive integer.");
  return Math.min(Number(value), limit);
}
