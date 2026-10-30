/**
 * Pairing (SPEC.md § 5.2), on the server's side: the codes waiting for the
 * user, their poll addresses, their approval on the server's own page or
 * through the administration API (§ 5.7), and the token given once. Held in
 * memory: a code lives 10 minutes at most.
 *
 *     const entry = desk.byCode(typed);              // on the server's approval page
 *     await desk.approve(entry, "lea");              // the scopes asked for that the account has
 */

import type { RatingCap } from "../generated/models.ts";
import { type Accounts, newCode, newId, orderedScopes, sameCode, typedCode, utc } from "./accounts.ts";
import { HttpProblem } from "./http.ts";

const CODE_SYMBOLS = 8; // 40 bits (SPEC.md § 5.2)
const PENDING_LIMIT = 1000;

export function slowDown(wait: number, detail: string): HttpProblem {
  return new HttpProblem(429, "slow_down", detail, {
    title: "Slow down",
    headers: { "Retry-After": String(Math.max(1, Math.ceil(wait))) },
  });
}

/** At most `count` events per `window` seconds per key (an address). */
export class Limiter {
  readonly count: number;
  readonly window: number;
  readonly clock: () => number;
  #hits = new Map<string, number[]>();

  constructor(count: number, window: number, clock: () => number = () => performance.now() / 1000) {
    this.count = count;
    this.window = window;
    this.clock = clock;
  }

  /** Seconds to wait before the next event of `key`; 0 when it may happen now. */
  wait(key: string): number {
    const now = this.clock();
    const hits = (this.#hits.get(key) ?? []).filter((t) => t > now - this.window);
    this.#hits.set(key, hits);
    if (this.#hits.size > 10000) {
      for (const [k, v] of this.#hits) if ((v.at(-1) ?? 0) <= now - this.window) this.#hits.delete(k);
    }
    return hits.length < this.count ? 0 : (hits[0] ?? now) + this.window - now;
  }

  record(key: string): void {
    const hits = this.#hits.get(key) ?? [];
    hits.push(this.clock());
    this.#hits.set(key, hits);
  }

  /** wait(), and the event recorded when it may happen. */
  hit(key: string): number {
    const wait = this.wait(key);
    if (wait === 0) this.record(key);
    return wait;
  }
}

/** A pairing waiting for the user. `poll` is its secret address's last part; `id` names it in the administration API. */
export interface Pending {
  poll: string;
  id: string;
  code: string;
  device: string;
  scopes: string[];
  key: Uint8Array | undefined;
  until: number;
  created: string;
  expires: string;
  interval: number;
  state: "pending" | "approved" | "refused";
  polled: number | undefined;
  token: string | undefined;
  granted: string[];
  ratingCap: RatingCap | undefined;
  lifetime: number | undefined;
}

/** The pairings waiting, and their approval. `accounts` issues the tokens. */
export class PairingDesk {
  readonly accounts: Accounts;
  interval: number;
  readonly expires: number;
  readonly lifetime: number | undefined;
  readonly clock: () => number;
  #pending = new Map<string, Pending>();

  constructor(
    accounts: Accounts,
    options: { interval?: number; expires?: number; lifetime?: number; clock?: () => number } = {},
  ) {
    const expires = options.expires ?? 600;
    if (expires < 1 || expires > 600) throw new RangeError("a code expires within 10 minutes (SPEC.md § 5.2)");
    this.accounts = accounts;
    this.interval = options.interval ?? 5;
    this.expires = expires;
    this.lifetime = options.lifetime;
    this.clock = options.clock ?? (() => performance.now() / 1000);
  }

  #purge(): void {
    const now = this.clock();
    for (const [poll, e] of this.#pending) if (e.until <= now) this.#pending.delete(poll);
  }

  start(device: string, scopes: readonly string[], key: Uint8Array | undefined): Pending {
    this.#purge();
    if (this.#pending.size >= PENDING_LIMIT)
      throw slowDown(this.interval, "Too many pairings are waiting; try again later.");
    const codes = new Set([...this.#pending.values()].map((e) => typedCode(e.code)));
    let code = newCode(CODE_SYMBOLS);
    while (codes.has(typedCode(code))) code = newCode(CODE_SYMBOLS);
    const entry: Pending = {
      poll: newId("p_", 24), // 192 bits: whoever has it collects the token
      id: newId("pr_"),
      code,
      device,
      scopes: orderedScopes(scopes),
      key,
      until: this.clock() + this.expires,
      created: utc(),
      expires: utc(new Date(Date.now() + this.expires * 1000)),
      interval: this.interval,
      state: "pending",
      polled: undefined,
      token: undefined,
      granted: [],
      ratingCap: undefined,
      lifetime: undefined,
    };
    this.#pending.set(entry.poll, entry);
    return entry;
  }

  /** The pairing waiting with this code, as the user typed it. */
  byCode(typed: string): Pending | undefined {
    this.#purge();
    return [...this.#pending.values()].find((e) => e.state === "pending" && sameCode(e.code, typed));
  }

  byId(pairingId: string): Pending | undefined {
    this.#purge();
    return [...this.#pending.values()].find((e) => e.state === "pending" && e.id === pairingId);
  }

  peek(poll: string): Pending | undefined {
    this.#purge();
    return this.#pending.get(poll);
  }

  waiting(): Pending[] {
    this.#purge();
    return [...this.#pending.values()]
      .filter((e) => e.state === "pending")
      .sort((a, b) => (a.created < b.created ? -1 : a.created > b.created ? 1 : 0));
  }

  /**
   * Approves `entry` for the account `user`: the scopes it asked for (or those of
   * `scopes` among them) that the account holds (SPEC.md § 5.2, § 5.7). Gives the
   * scopes granted; the token waits for the next poll.
   */
  async approve(
    entry: Pending,
    user: string,
    scopes?: readonly string[],
    ratingCap?: RatingCap,
    invitation?: string,
  ): Promise<string[]> {
    const account = await this.accounts.user(user);
    if (account === undefined) throw new RangeError(`no account named ${user}`);
    const wanted = scopes === undefined ? entry.scopes : entry.scopes.filter((s) => scopes.includes(s));
    const granted = wanted.filter((s) => account.scopes.includes(s));
    const options: Parameters<Accounts["issue"]>[3] = {};
    if (entry.key !== undefined) options.key = entry.key;
    if (ratingCap !== undefined) options.ratingCap = ratingCap;
    if (invitation !== undefined) options.invitation = invitation;
    if (this.lifetime !== undefined) options.lifetime = this.lifetime;
    const [token] = await this.accounts.issue(user, entry.device, granted, options);
    entry.state = "approved";
    entry.token = token;
    entry.granted = granted;
    entry.ratingCap = ratingCap;
    entry.lifetime = this.lifetime;
    return granted;
  }

  refuse(entry: Pending): void {
    entry.state = "refused";
  }

  /**
   * The token's document once approved (given once), undefined while waiting; an
   * HttpProblem 410 when refused, expired, collected or unknown, 429 when polled
   * faster than `interval`.
   */
  poll(poll: string): Record<string, unknown> | undefined {
    this.#purge();
    const entry = this.#pending.get(poll);
    if (entry === undefined)
      throw new HttpProblem(410, "gone", "Refused, expired, already collected or unknown.", { title: "Gone" });
    const now = this.clock();
    if (entry.polled !== undefined && now - entry.polled < entry.interval * 0.8) {
      entry.polled = now;
      throw slowDown(entry.interval, `Poll every ${entry.interval} seconds.`);
    }
    entry.polled = now;
    if (entry.state === "refused") {
      this.#pending.delete(poll);
      throw new HttpProblem(410, "gone", "The user refused this device.", { title: "Gone" });
    }
    if (entry.state !== "approved" || entry.token === undefined) return undefined;
    this.#pending.delete(poll);
    const doc: Record<string, unknown> = {
      schema: 1,
      token: entry.token,
      scopes: [...entry.granted],
      bound: entry.key !== undefined,
    };
    if (entry.lifetime) doc["expires"] = Math.trunc(entry.lifetime);
    if (entry.ratingCap !== undefined) doc["rating_cap"] = entry.ratingCap;
    return doc;
  }
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/**
 * A minimal page for a server's own approval step (SPEC.md § 5.2, § 5.3): it
 * shows the short fingerprint of the server's key, next to a form for the code.
 * Signing the user in, and approving, are the server's: this page approves
 * nothing by itself (L-5.2-11).
 */
export function approvalPage(options: {
  fingerprint?: string | undefined;
  code?: string;
  message?: string;
  action?: string;
}): string {
  const shown = options.fingerprint ? escapeHtml(options.fingerprint) : "(no TLS key: plain HTTP on loopback)";
  const note = options.message ? `<p>${escapeHtml(options.message)}</p>` : "";
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="referrer" content="no-referrer"><title>Pair a device</title></head><body>' +
    "<h1>Pair a device</h1>" +
    `<p>This server's key: <code>${shown}</code>. Compare it with the one the device shows.</p>${note}` +
    `<form method="post" action="${escapeHtml(options.action ?? "")}"><label>Code ` +
    `<input name="code" value="${escapeHtml(options.code ?? "")}" autocomplete="off"></label>` +
    "<button>Continue</button></form></body></html>"
  );
}
