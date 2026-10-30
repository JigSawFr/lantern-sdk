/**
 * What a client pins: the servers it paired with (SPEC.md § 5.3, § 5.4: their
 * key's fingerprint, its token and device key: `ServerStore`), and the keys
 * of each homebrew (§ 8.4: `KeyPins`). Each is an interface with a memory
 * implementation here; the `node` entry adds files (`FileServerStore`,
 * `FileKeyPins`), and a browser app keeps its own in IndexedDB.
 */

import { isObject, type JSONObject } from "./base.ts";
import type { Homebrew } from "./generated/models.ts";
import { keyChange, keyFingerprint } from "./homebrew.ts";

/** Where a client keeps the key it pinned per homebrew id and platform. */
export interface KeyPins {
  /** The pinned key (base64), "" when the id was first installed unsigned, undefined when never installed. */
  pinned(platform: string, homebrewId: string): Promise<string | undefined> | string | undefined;
  /** Pin `publicKey` ("" for none) for the id, after an install the user accepted. */
  pin(platform: string, homebrewId: string, publicKey: string): Promise<void> | void;
  /** Forget the id's key, once it is uninstalled. */
  forget(platform: string, homebrewId: string): Promise<void> | void;
}

/** checkKey()'s answer: `change` is "pin", "same" or "changed", with both keys and their short fingerprints. */
export interface KeyDecision {
  change: "pin" | "same" | "changed";
  pinned: string | undefined;
  offered: string;
  needsConsent: boolean;
  pinnedFingerprint: string | undefined;
  offeredFingerprint: string | undefined;
}

/** Whether `entry`'s key is the one pinned for its id (SPEC.md § 8.4). */
export async function checkKey(pins: KeyPins, entry: Homebrew): Promise<KeyDecision> {
  const pinned = await pins.pinned(entry.platform, entry.id);
  const offered = entry.signature?.public_key ?? "";
  const change = keyChange(pinned, entry);
  return {
    change,
    pinned,
    offered,
    needsConsent: change === "changed",
    pinnedFingerprint: pinned ? keyFingerprint(pinned) : undefined,
    offeredFingerprint: offered ? keyFingerprint(offered) : undefined,
  };
}

/** Pins kept in memory. */
export class MemoryKeyPins implements KeyPins {
  #pins = new Map<string, string>();
  pinned(platform: string, homebrewId: string): string | undefined {
    return this.#pins.get(`${platform}/${homebrewId}`);
  }
  pin(platform: string, homebrewId: string, publicKey: string): void {
    this.#pins.set(`${platform}/${homebrewId}`, publicKey);
  }
  forget(platform: string, homebrewId: string): void {
    this.#pins.delete(`${platform}/${homebrewId}`);
  }
}

/**
 * What a client keeps of a server it paired with, by its `uid`: where it is,
 * the fingerprint of the key it pinned (`spki`, SHA-256 hex; absent when a CA
 * vouches for its certificate), its token, the device key the token is bound
 * to (`key`: its secret seed, base64; absent for a bearer-only token or a key
 * kept elsewhere, such as a non-extractable CryptoKey in IndexedDB), the
 * scopes and rating cap the token carries, and when it paired. Fields this
 * library does not know are kept, and written back.
 */
export interface ServerRecord {
  uid: string;
  url: string;
  token: string;
  name: string;
  spki?: string;
  key?: string;
  scopes: string[];
  bound: boolean;
  rating_cap?: JSONObject;
  paired: string;
  [other: string]: unknown;
}

/** A record read from a store, or undefined when it is not one this library can use. */
export function readServerRecord(data: unknown): ServerRecord | undefined {
  if (!isObject(data)) return undefined;
  const { uid, url, token } = data;
  if (typeof uid !== "string" || typeof url !== "string" || typeof token !== "string") return undefined;
  const out: ServerRecord = {
    ...data,
    uid,
    url,
    token,
    name: typeof data["name"] === "string" ? data["name"] : "",
    scopes: Array.isArray(data["scopes"]) ? data["scopes"].filter((s): s is string => typeof s === "string") : [],
    bound: data["bound"] === true,
    paired: typeof data["paired"] === "string" ? data["paired"] : "",
  };
  for (const key of ["spki", "key"] as const) if (typeof data[key] !== "string") delete out[key];
  if (!isObject(data["rating_cap"])) delete out.rating_cap;
  return out;
}

/**
 * Where a client keeps the servers it paired with: their tokens and device keys
 * are secrets, kept where the system protects them when it has such a place (SPEC.md § 5.4).
 */
export interface ServerStore {
  server(uid: string): Promise<ServerRecord | undefined> | ServerRecord | undefined;
  servers(): Promise<ServerRecord[]> | ServerRecord[];
  /** Keep `record` (a new pairing replaces the server's former one). */
  save(record: ServerRecord): Promise<void> | void;
  forget(uid: string): Promise<void> | void;
}

/** Servers kept in memory. */
export class MemoryServerStore implements ServerStore {
  #servers = new Map<string, ServerRecord>();
  server(uid: string): ServerRecord | undefined {
    return this.#servers.get(uid);
  }
  servers(): ServerRecord[] {
    return [...this.#servers.values()];
  }
  save(record: ServerRecord): void {
    this.#servers.set(record.uid, record);
  }
  forget(uid: string): void {
    this.#servers.delete(uid);
  }
}
