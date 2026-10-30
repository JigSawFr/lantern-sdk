/**
 * Accounts, devices and invitations (SPEC.md § 5.1, § 5.5, § 5.7): what a
 * server keeps so that LanternApp can issue tokens by pairing, check them and
 * their signatures, and answer the administration API.
 *
 * `Accounts` is the interface a server implements over its own store;
 * `MemoryAccounts` is a complete one, held in memory, for tests, demos and as a
 * reference to read. What is kept follows SPEC.md § 5: a token's hash only
 * (never the token), the device's public key when it paired with one, the
 * scopes approved (never more than its account's), its rating cap, and the
 * invitation it came by.
 */

import { createHash, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { toBase64Url } from "../bytes.ts";
import type { RatingCap } from "../generated/models.ts";

/** The pairing alphabet (SPEC.md § 5.2): no 0, O, 1 or I. */
export const CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
/** An account's name (SPEC.md § 5.7). */
export const ACCOUNT_NAME = /^[A-Za-z0-9._-]{1,64}$/;
/** The scopes, in the order the handshake lists them (SPEC.md § 4.2). */
export const SCOPES = ["library", "saves", "cheats", "cheats.write", "requests", "admin"] as const;
const INVITATION_SYMBOLS = 16; // 80 bits (SPEC.md § 5.5)

/** An RFC 3339 time, in UTC, to the second. */
export function utc(when: Date = new Date()): string {
  return when.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** A time of RFC 3339 with its offset, as milliseconds; undefined otherwise. */
export function parseTime(text: string | undefined): number | undefined {
  if (!text || !/^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/.test(text)) return undefined;
  const t = Date.parse(text);
  return Number.isNaN(t) ? undefined : t;
}

/** What a server keeps of a token (SPEC.md § 5.1): its SHA-256, hex. */
export function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** A new token: `et_` and 256 random bits. */
export function newToken(): string {
  return `et_${toBase64Url(randomBytes(32))}`;
}

export function newId(prefix: string, bytes = 9): string {
  return `${prefix}${toBase64Url(randomBytes(bytes))}`;
}

/** A code of the pairing alphabet, `symbols` long, in groups of 4 joined by `-` (SPEC.md § 5.2). */
export function newCode(symbols: number): string {
  let raw = "";
  for (let i = 0; i < symbols; i++) raw += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return (raw.match(/.{1,4}/g) ?? []).join("-");
}

/** A code as a user typed it, compared without case, spaces or dashes. */
export function typedCode(text: string): string {
  return text.replace(/[\s-]/g, "").toUpperCase();
}

export function sameCode(a: string, b: string): boolean {
  const x = Buffer.from(typedCode(a));
  const y = Buffer.from(typedCode(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

/** The scopes this text knows among `scopes`, in their order, each once. */
export function orderedScopes(scopes: Iterable<string>): string[] {
  const wanted = new Set(scopes);
  return SCOPES.filter((s) => wanted.has(s));
}

/** An account (SPEC.md § 5.7): its name, state and scopes. No password: a server's own means may give it one. */
export interface User {
  name: string;
  scopes: string[];
  state: "active" | "frozen";
  created: string;
}

/** A paired device and its token (SPEC.md § 5.1, § 5.7), as kept: the token's hash, never the token. */
export interface Device {
  id: string;
  tokenHash: string;
  user: string;
  device: string;
  scopes: string[];
  created: string;
  key?: Uint8Array;
  ratingCap?: RatingCap;
  invitation?: string;
  expires?: string;
}

/** An invitation (SPEC.md § 5.5). */
export interface Invitation {
  id: string;
  code: string;
  user: string;
  scopes: string[];
  expires: string;
  devices: number;
  used: number;
  ratingCap?: RatingCap;
  note?: string;
  created: string;
}

export function live(device: Device, now: number = Date.now()): boolean {
  if (device.expires === undefined) return true;
  const until = parseTime(device.expires);
  return until !== undefined && until > now;
}

export function redeemable(inv: Invitation, now: number = Date.now()): boolean {
  const until = parseTime(inv.expires);
  return until !== undefined && until > now && inv.used < inv.devices;
}

/** A change the store refuses: `status` (404, 409…) and why. */
export class AccountError extends Error {
  override name = "AccountError";
  readonly status: number;
  readonly code: string;
  readonly detail: string;

  constructor(status: number, code: string, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

type Maybe<T> = T | Promise<T>;

export interface IssueOptions {
  key?: Uint8Array;
  ratingCap?: RatingCap;
  invitation?: string;
  /** Seconds the token lives; until revoked without it. */
  lifetime?: number;
}

/** Where a server keeps its accounts, devices and invitations. Every method may be async (a database). */
export interface Accounts {
  user(name: string): Maybe<User | undefined>;
  users(): Maybe<User[]>;
  /** A new account; AccountError 409 `conflict` when the name is taken. */
  createUser(name: string, scopes: readonly string[], state?: "active" | "frozen"): Maybe<User>;
  /** An account changed; AccountError 404 when there is none. Its devices' scopes are cut back with its own. */
  updateUser(name: string, change: { state?: "active" | "frozen"; scopes?: readonly string[] }): Maybe<User>;
  /** The live device whose token is `token`, or undefined (unknown, revoked or expired). */
  deviceOf(token: string): Maybe<Device | undefined>;
  /** A new token for a device, and the device as kept (its hash only). */
  issue(user: string, device: string, scopes: readonly string[], options?: IssueOptions): Maybe<[string, Device]>;
  devices(user?: string): Maybe<Device[]>;
  /** Revokes a device's token, at once; false when there is none. */
  revoke(deviceId: string): Maybe<boolean>;
  createInvitation(
    user: string,
    scopes: readonly string[],
    expires: string,
    devices: number,
    options?: { ratingCap?: RatingCap; note?: string },
  ): Maybe<Invitation>;
  /** The invitations that can still be redeemed. */
  invitations(): Maybe<Invitation[]>;
  revokeInvitation(invitationId: string): Maybe<boolean>;
  /**
   * The invitation of `code` (as typed), its use counted at once, so that devices
   * redeeming it together never pass `devices`; undefined when it is unknown,
   * expired, revoked or used up.
   */
  redeem(code: string): Maybe<Invitation | undefined>;
}

/** Accounts, devices and invitations held in memory. */
export class MemoryAccounts implements Accounts {
  readonly #users = new Map<string, User>();
  readonly #devices = new Map<string, Device>(); // by token hash
  readonly #invitations = new Map<string, Invitation>();

  constructor(users: Iterable<{ name: string; scopes: readonly string[]; state?: "active" | "frozen" }> = []) {
    for (const u of users)
      this.#users.set(u.name, {
        name: u.name,
        scopes: orderedScopes(u.scopes),
        state: u.state ?? "active",
        created: utc(),
      });
  }

  user(name: string): User | undefined {
    return this.#users.get(name);
  }

  users(): User[] {
    return [...this.#users.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  }

  createUser(name: string, scopes: readonly string[], state: "active" | "frozen" = "active"): User {
    if (!ACCOUNT_NAME.test(name))
      throw new AccountError(400, "bad_request", "name is 1 to 64 letters, digits, '.', '_' and '-'.");
    if (this.#users.has(name)) throw new AccountError(409, "conflict", `An account named ${name} exists.`);
    const user: User = { name, scopes: orderedScopes(scopes), state, created: utc() };
    this.#users.set(name, user);
    return user;
  }

  updateUser(name: string, change: { state?: "active" | "frozen"; scopes?: readonly string[] }): User {
    const found = this.#users.get(name);
    if (found === undefined) throw new AccountError(404, "not_found", "No such account.");
    const user: User = { ...found };
    if (change.state !== undefined) user.state = change.state;
    if (change.scopes !== undefined) {
      user.scopes = orderedScopes(change.scopes);
      for (const [h, d] of this.#devices) {
        if (d.user === name) this.#devices.set(h, { ...d, scopes: d.scopes.filter((s) => user.scopes.includes(s)) });
      }
    }
    this.#users.set(name, user);
    return user;
  }

  deviceOf(token: string): Device | undefined {
    const found = this.#devices.get(tokenHash(token));
    return found !== undefined && live(found) ? found : undefined;
  }

  issue(user: string, device: string, scopes: readonly string[], options: IssueOptions = {}): [string, Device] {
    const token = newToken();
    const record = this.#record(token, user, device, scopes, options);
    if (options.lifetime) record.expires = utc(new Date(Date.now() + options.lifetime * 1000));
    if (options.invitation !== undefined) record.invitation = options.invitation;
    this.#devices.set(record.tokenHash, record);
    return [token, record];
  }

  #record(token: string, user: string, device: string, scopes: readonly string[], options: IssueOptions): Device {
    const record: Device = {
      id: newId("d_", 12),
      tokenHash: tokenHash(token),
      user,
      device,
      scopes: orderedScopes(scopes),
      created: utc(),
    };
    if (options.key !== undefined) record.key = options.key;
    if (options.ratingCap !== undefined) record.ratingCap = options.ratingCap;
    return record;
  }

  /** Keeps a token the server did not issue here (a demo's, or one moved from another store): its hash. */
  addToken(token: string, user: string, device: string, scopes: readonly string[], options: IssueOptions = {}): Device {
    const record = this.#record(token, user, device, scopes, options);
    this.#devices.set(record.tokenHash, record);
    return record;
  }

  devices(user?: string): Device[] {
    return [...this.#devices.values()]
      .filter((d) => live(d) && (user === undefined || d.user === user))
      .sort((a, b) => (a.user + a.created + a.id < b.user + b.created + b.id ? -1 : 1));
  }

  revoke(deviceId: string): boolean {
    let found = false;
    for (const [h, d] of this.#devices) {
      if (d.id === deviceId) {
        this.#devices.delete(h);
        found = true;
      }
    }
    return found;
  }

  createInvitation(
    user: string,
    scopes: readonly string[],
    expires: string,
    devices: number,
    options: { ratingCap?: RatingCap; note?: string } = {},
  ): Invitation {
    const codes = new Set([...this.#invitations.values()].map((i) => typedCode(i.code)));
    let code = newCode(INVITATION_SYMBOLS);
    while (codes.has(typedCode(code))) code = newCode(INVITATION_SYMBOLS);
    const inv: Invitation = {
      id: newId("i_"),
      code,
      user,
      scopes: orderedScopes(scopes),
      expires,
      devices,
      used: 0,
      created: utc(),
    };
    if (options.ratingCap !== undefined) inv.ratingCap = options.ratingCap;
    if (options.note !== undefined) inv.note = options.note;
    this.#invitations.set(inv.id, inv);
    return inv;
  }

  invitations(): Invitation[] {
    return [...this.#invitations.values()]
      .filter((i) => redeemable(i))
      .sort((a, b) => (a.created + a.id < b.created + b.id ? -1 : 1));
  }

  revokeInvitation(invitationId: string): boolean {
    return this.#invitations.delete(invitationId);
  }

  redeem(code: string): Invitation | undefined {
    for (const inv of this.#invitations.values()) {
      if (sameCode(inv.code, code)) {
        if (!redeemable(inv)) return undefined;
        const used = { ...inv, used: inv.used + 1 };
        this.#invitations.set(inv.id, used);
        return used;
      }
    }
    return undefined;
  }
}
