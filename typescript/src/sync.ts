/**
 * Sync (SPEC.md § 20): the merge rule a server applies item by item, which a
 * client also reads to know what its server will keep; the times items carry;
 * and the consent a client must hold before it reads or writes anything of
 * `<base>/v1/sync` (§ 20.1).
 *
 * The rule (§ 20.4): of the item kept and the one sent, the later `updated`
 * wins; on the same `updated`, a deletion wins; between two values, the one
 * whose canonical JSON (keys sorted, no space, characters other than ASCII as
 * they are, in UTF-8) is the greater string of bytes. An `updated` more than
 * the server's skew ahead of its clock is taken as its own time.
 */

import { DocumentError, isObject, LanternError } from "./base.ts";
import { utf8 } from "./bytes.ts";
import type { SyncItem } from "./generated/models.ts";

/** The collections of this version (SPEC.md § 20.2); a later one may add others, which a reader skips. */
export const COLLECTIONS = ["wishes", "installed"] as const;
export type Collection = (typeof COLLECTIONS)[number];
/** Items in one write at most (SPEC.md § 13). */
export const WRITE_LIMIT = 1000;
/** Deletions a server keeps at least this long (SPEC.md § 20.5). */
export const TOMBSTONE_DAYS = 30;
/** A sync time: UTC, to the millisecond at most (SPEC.md § 20.2). */
export const SYNC_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?Z$/;

/** An item's time in milliseconds since the epoch, or undefined when it is not a sync time. */
export function syncTime(text: string): number | undefined {
  const m = SYNC_TIME.exec(text);
  if (m === null) return undefined;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const ms = m[7] !== undefined ? Number(m[7].slice(1).padEnd(3, "0")) : 0;
  const t = Date.UTC(y, mo - 1, d, h, mi, s, ms);
  const back = new Date(t);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || h > 23 || mi > 59)
    return undefined;
  if (s > 59) return undefined;
  return t;
}

/** A time as items carry it: `2026-10-30T09:12:03.250Z`. */
export function formatSyncTime(ms: number): string {
  return new Date(Math.trunc(ms)).toISOString();
}

/** The canonical JSON of a value (SPEC.md § 20.4): keys sorted by their UTF-16 code units, as JSON sorts them. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new DocumentError("not a JSON number", "value");
    if (typeof value === "string") return quoteString(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort(compareCodePoints);
  return `{${keys.map((k) => `${quoteString(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`).join(",")}}`;
}

/** A JSON string with only what JSON must escape escaped: characters other than ASCII as they are. */
function quoteString(text: string): string {
  return JSON.stringify(text);
}

/** Keys sorted as Python's sort_keys does: by code point. */
function compareCodePoints(a: string, b: string): number {
  const x = [...a];
  const y = [...b];
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const p = (x[i] as string).codePointAt(0) as number;
    const q = (y[i] as string).codePointAt(0) as number;
    if (p !== q) return p - q;
  }
  return x.length - y.length;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  return a.length - b.length;
}

/** An item's state for the rule: a value, or a deletion, and when. */
export interface Versioned {
  value?: unknown;
  deleted?: boolean;
  updated: string;
}

/**
 * Whether the item `sent` replaces the item `have` (SPEC.md § 20.4), its
 * `updated` read by syncTime(); `have` undefined means nothing kept.
 * DocumentError for an `updated` that is not a sync time.
 */
export function replaces(have: Versioned | undefined, sent: Versioned): boolean {
  const t = syncTime(sent.updated);
  if (t === undefined) throw new DocumentError("updated is not a UTC time to the millisecond", "updated");
  if (have === undefined) return true;
  const u = syncTime(have.updated);
  if (u === undefined) return true;
  if (t !== u) return t > u;
  const sentDeleted = sent.deleted === true;
  const haveDeleted = have.deleted === true;
  if (sentDeleted || haveDeleted) return sentDeleted && !haveDeleted;
  return compareBytes(utf8(canonicalJson(sent.value)), utf8(canonicalJson(have.value))) > 0;
}

/**
 * The item a server keeps of `have` and `sent`, at its time `now` (ms) with
 * its `skew` (seconds): `sent` with its `updated` normalized (to the
 * millisecond, and the server's time when it is more than `skew` ahead), when
 * it replaces `have`; else `have`. `[kept, replaced]`.
 */
export function merge<T extends Versioned>(
  have: T | undefined,
  sent: T,
  now: number = Date.now(),
  skew = 300,
): [T, boolean] {
  const t = syncTime(sent.updated);
  if (t === undefined) throw new DocumentError("updated is not a UTC time to the millisecond", "updated");
  const normalized = { ...sent, updated: formatSyncTime(t > now + skew * 1000 ? now : t) };
  return replaces(have, normalized) ? [normalized, true] : [have as T, false];
}

/** The `If-Match` of a write made from the whole collection: `"<generation>-<rev>"` (SPEC.md § 20.4). */
export function ifMatch(generation: string, rev: number): string {
  return `"${generation}-${rev}"`;
}

/** A wish's key: `<platform>/<title_id>` (SPEC.md § 20.2). */
export function wishKey(platform: string, titleId: string): string {
  return `${platform}/${titleId}`;
}

/** Sync without its user's consent (SPEC.md § 20.1): the client reads and writes nothing of it. */
export class ConsentRequired extends LanternError {
  override name = "ConsentRequired";
  readonly collection: string;
  constructor(collection: string, detail: string) {
    super(detail);
    this.collection = collection;
  }
}

/**
 * The generation a client kept is no longer the server's (SPEC.md § 20.3,
 * L-20.3-2): its user's sync data was deleted. The client dropped its copy and
 * turned sync off: ask the user again before it syncs.
 */
export class GenerationChanged extends LanternError {
  override name = "GenerationChanged";
  readonly kept: string;
  readonly now: string;
  constructor(kept: string, now: string) {
    super(`the sync data was deleted on the server (generation ${kept} is now ${now}): sync is off until asked again`);
    this.kept = kept;
    this.now = now;
  }
}

/**
 * What one console profile agreed to sync with one server (SPEC.md § 20.1):
 * the collections by name, each given on its own (agreeing to `wishes` does not
 * cover `installed`, L-20.1-2), and the generation and revisions last read.
 * The app asks its user, then sets the consent; nothing of sync goes before.
 * A document of its own schema, kept by the app (a file, IndexedDB).
 */
export interface SyncState {
  schema: 1;
  /** The server's uid, and the profile it is for. */
  server: string;
  profile: string;
  /** The collections the user agreed to sync, by name. */
  consent: string[];
  generation?: string;
  /** Each collection's revision last read. */
  revs: Record<string, number>;
}

/** A state of no consent: sync off. */
export function syncOff(server: string, profile: string): SyncState {
  return { schema: 1, server, profile, consent: [], revs: {} };
}

/** A sync state as kept, by the `schema` rule: undefined when absent, of a newer schema, or not one. Unknown keys stay. */
export function readSyncState(value: unknown): SyncState | undefined {
  if (!isObject(value)) return undefined;
  const { schema, server, profile, consent, generation, revs } = value;
  if (schema !== 1) return undefined;
  if (typeof server !== "string" || typeof profile !== "string") return undefined;
  if (!Array.isArray(consent) || !consent.every((c) => typeof c === "string")) return undefined;
  if (generation !== undefined && typeof generation !== "string") return undefined;
  if (!isObject(revs) || !Object.values(revs).every((r) => Number.isSafeInteger(r))) return undefined;
  return value as unknown as SyncState;
}

/** An item to send: a value, or a deletion, at `updated` (the device's time corrected by its offset, Annex B.9). */
export function item(key: string, value: unknown, updated: number): SyncItem {
  return value === undefined
    ? { key, deleted: true, updated: formatSyncTime(updated) }
    : { key, value, updated: formatSyncTime(updated) };
}
