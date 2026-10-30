/**
 * Sync on the server's side (SPEC.md § 20): each account's collections, merged
 * by § 20.4's rule item by item (src/sync.ts), deletions kept 30 days at least,
 * a generation that changes when the account's data is deleted. A server
 * implements `SyncStore` over its database; `MemorySyncStore` is a complete
 * one, in memory.
 */

import { randomBytes } from "node:crypto";
import { toBase64Url } from "../bytes.ts";
import { merge, TOMBSTONE_DAYS } from "../sync.ts";
import { HttpProblem } from "./http.ts";

type Maybe<T> = T | Promise<T>;

/** An item as kept: its key, its value or its deletion, its time, its revision, and when the server took it. */
export interface StoredItem {
  key: string;
  value?: unknown;
  deleted?: true;
  updated: string;
  rev: number;
  /** When the server took it (ms), for a deletion's retention. */
  kept: number;
}

/** An item as sent: a value or a deletion, and its time. */
export interface SentItem {
  key: string;
  value?: unknown;
  deleted?: true;
  updated: string;
}

/** Where a server keeps sync data. Every method may be async (a database). */
export interface SyncStore {
  /** The account's generation and each collection's revision and live items. */
  overview(
    user: string,
    collections: readonly string[],
  ): Maybe<{ generation: string; collections: Record<string, { rev: number; items: number }> }>;
  /**
   * A collection's items: with `since`, every item whose revision is above it,
   * deletions included; without, every live item. 410 when its deletions that
   * far back are gone, 400 for a revision it never gave.
   */
  read(
    user: string,
    collection: string,
    since: number | undefined,
  ): Maybe<{ generation: string; rev: number; items: StoredItem[] }>;
  /**
   * Items merged (§ 20.4), all or nothing: 409 for another generation, 412 for
   * an If-Match that is not the collection's, 413 beyond `limit` items. Each
   * item sent as it is then kept.
   */
  merge(
    user: string,
    collection: string,
    generation: string,
    items: readonly SentItem[],
    options: { ifMatch?: string; now: number; skew: number; limit: number },
  ): Maybe<{ generation: string; rev: number; items: StoredItem[] }>;
  /** Erases a collection of the account, or all its data: a new generation (§ 20.5). */
  erase(user: string, collection?: string): Maybe<void>;
  /** Erases an account's sync data, the account being deleted (§ 5.7, L-20.5-3). */
  forget(user: string): Maybe<void>;
}

interface Kept {
  rev: number;
  floor: number;
  items: Map<string, StoredItem>;
}

const newGeneration = (): string => `g_${toBase64Url(randomBytes(9))}`;

/** Sync data in memory. */
export class MemorySyncStore implements SyncStore {
  readonly #accounts = new Map<string, { generation: string; collections: Map<string, Kept> }>();
  /** Milliseconds a deletion is kept: 30 days at least (§ 20.5). */
  readonly retention: number;
  readonly clock: () => number;

  constructor(options: { retentionDays?: number; clock?: () => number } = {}) {
    const days = options.retentionDays ?? TOMBSTONE_DAYS;
    if (days < TOMBSTONE_DAYS) throw new RangeError(`deletions are kept ${TOMBSTONE_DAYS} days at least`);
    this.retention = days * 86400000;
    this.clock = options.clock ?? Date.now;
  }

  #account(user: string): { generation: string; collections: Map<string, Kept> } {
    let acc = this.#accounts.get(user);
    if (acc === undefined) {
      acc = { generation: newGeneration(), collections: new Map() };
      this.#accounts.set(user, acc);
    }
    return acc;
  }

  #collection(user: string, name: string): [{ generation: string }, Kept] {
    const acc = this.#account(user);
    let col = acc.collections.get(name);
    if (col === undefined) {
      col = { rev: 0, floor: 0, items: new Map() };
      acc.collections.set(name, col);
    }
    // Deletions kept longer than the retention go, and raise the floor.
    const limit = this.clock() - this.retention;
    for (const [key, item] of col.items) {
      if (item.deleted && item.kept < limit) {
        col.floor = Math.max(col.floor, item.rev);
        col.items.delete(key);
      }
    }
    return [acc, col];
  }

  overview(
    user: string,
    collections: readonly string[],
  ): { generation: string; collections: Record<string, { rev: number; items: number }> } {
    const out: Record<string, { rev: number; items: number }> = {};
    for (const name of collections) {
      const [, col] = this.#collection(user, name);
      out[name] = { rev: col.rev, items: [...col.items.values()].filter((i) => !i.deleted).length };
    }
    return { generation: this.#account(user).generation, collections: out };
  }

  read(
    user: string,
    collection: string,
    since: number | undefined,
  ): { generation: string; rev: number; items: StoredItem[] } {
    const [acc, col] = this.#collection(user, collection);
    let items: StoredItem[];
    if (since === undefined) items = [...col.items.values()].filter((i) => !i.deleted);
    else {
      if (since > col.rev)
        throw new HttpProblem(400, "bad_request", "This revision was never given: read the collection whole.");
      if (since < col.floor) throw new HttpProblem(410, "gone", "Its deletions are gone: read the collection whole.");
      items = [...col.items.values()].filter((i) => i.rev > since);
    }
    items.sort((a, b) => a.rev - b.rev);
    return { generation: acc.generation, rev: col.rev, items };
  }

  merge(
    user: string,
    collection: string,
    generation: string,
    items: readonly SentItem[],
    options: { ifMatch?: string; now: number; skew: number; limit: number },
  ): { generation: string; rev: number; items: StoredItem[] } {
    const [acc, col] = this.#collection(user, collection);
    if (generation !== acc.generation)
      throw new HttpProblem(409, "conflict", "This sync data was deleted since: ask the user again (SPEC.md § 20.3).");
    if (options.ifMatch !== undefined && options.ifMatch.trim() !== `"${acc.generation}-${col.rev}"`)
      throw new HttpProblem(412, "precondition_failed", "The collection changed since it was read: read it again.", {
        title: "Precondition failed",
      });
    const fresh = new Set(items.map((i) => i.key).filter((k) => !col.items.has(k))).size;
    if (col.items.size + fresh > options.limit)
      throw new HttpProblem(413, "too_large", `A collection holds ${options.limit} items at most here.`);
    const out: StoredItem[] = [];
    for (const sent of items) {
      const have = col.items.get(sent.key);
      const [kept, replaced] = merge<SentItem | StoredItem>(have, sent, options.now, options.skew);
      if (replaced) {
        col.rev++;
        const item: StoredItem = { key: sent.key, updated: kept.updated, rev: col.rev, kept: options.now };
        if (sent.deleted === true) item.deleted = true;
        else item.value = sent.value;
        col.items.set(sent.key, item);
        out.push(item);
      } else out.push(have as StoredItem);
    }
    return { generation: acc.generation, rev: col.rev, items: out };
  }

  erase(user: string, collection?: string): void {
    const acc = this.#account(user);
    if (collection === undefined) acc.collections.clear();
    else acc.collections.delete(collection);
    acc.generation = newGeneration();
  }

  forget(user: string): void {
    this.#accounts.delete(user);
  }
}

/** An item as a document gives it: without the server's own `kept`. */
export function publicItem(item: StoredItem): Record<string, unknown> {
  const out: Record<string, unknown> = { key: item.key };
  if (item.deleted) out["deleted"] = true;
  else out["value"] = item.value;
  out["updated"] = item.updated;
  out["rev"] = item.rev;
  return out;
}
