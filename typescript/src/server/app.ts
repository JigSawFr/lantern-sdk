/**
 * The reference routes of Lantern, over a Library: what a server author mounts
 * in an existing app (node:http through `nodeHandler()`, or any framework of
 * web Requests through `fetchHandler()`) to serve Lantern.
 *
 *     const app = new LanternApp(library, { uid: "6f1c2a8e-…", name: "Living room shelf", accounts });
 *     const response = await app.handle(ServerRequest.fromTarget("GET", "/api/lantern/v1/apps", …));
 *
 * It answers the handshake (at /.well-known/lantern and <base>/v1/), the
 * families library (apps, what is missing, files), changes (with a journal),
 * titles, homebrew and cheats (reading), events (a stream and long polls,
 * § 18), peers (grants signed by the server's own key, § 19.3) and sync
 * (§ 20, over a SyncStore), and refuses the others with 404 (their features
 * are 0). Who calls is decided one of two ways:
 *
 * - with `accounts` (MemoryAccounts, or one over the server's database),
 *   LanternApp issues the tokens itself: pairing (§ 5.2) with or without a
 *   device key, signed requests checked with a replay cache and a skew (§ 5.4),
 *   invitations (§ 5.5), rating caps (§ 5.6) and the administration API (§ 5.7),
 *   deleting accounts included;
 * - with an `authenticate` hook, the server resolves its own tokens to an
 *   Account; one with a `key` is still checked for its signature.
 *
 * The same scope as python/src/lantern/server/app.py's LanternApp.
 */

import { createHash } from "node:crypto";
import { DocumentError, SCHEMA } from "../base.ts";
import { fromBase64, toBase64 } from "../bytes.ts";
import { digestSha256 } from "../digest.ts";
import * as ed25519 from "../ed25519.ts";
import type { App, CheatSet, Homebrew, Rating, RatingCap, Title } from "../generated/models.ts";
import * as models from "../generated/models.ts";
import { effectiveKind } from "../homebrew.ts";
import { NAME, NOTE, printable, TITLES_AT_ONCE } from "../limits.ts";
import { missing } from "../missing.ts";
import type { Check } from "../model.ts";
import { signGrant } from "../peers.ts";
import * as ratings from "../ratings.ts";
import { definition } from "../schema.ts";
import * as sig from "../signatures.ts";
import { short } from "../spki.ts";
import { COLLECTIONS, syncTime, WRITE_LIMIT } from "../sync.ts";
import { BUILD_ID, CORE_ID, FAMILIES, HOMEBREW_ID, isPlatform, SHA256_HEX, WORD } from "../vocabulary.ts";
import {
  ACCOUNT_NAME,
  AccountError,
  type Accounts,
  type Device,
  type Invitation,
  orderedScopes,
  parseTime,
  SCOPES,
  utc,
} from "./accounts.ts";
import { type Audience, EVENT_SCOPES, EventHub, type HubEvent, type LibraryChange, sseEvent } from "./events.ts";
import { fileResponse } from "./files.ts";
import {
  badRequest,
  emptyResponse,
  HttpProblem,
  htmlResponse,
  jsonResponse,
  methodNotAllowed,
  notFound,
  platformOf,
  problemResponse,
  readDocument,
  type ServerRequest,
  type ServerResponse,
  type StreamBody,
  unauthorized,
} from "./http.ts";
import type { Account, Authenticate, Library } from "./library.ts";
import { Cursors, pageSize, Sealer, SinceTokens, type SortKey } from "./paging.ts";
import { approvalPage, Limiter, PairingDesk, slowDown } from "./pairing.ts";
import { MemorySyncStore, publicItem, type SentItem, type SyncStore } from "./sync.ts";

/** The scope each family needs (SPEC.md § 4.2); pairing needs none. */
const SCOPE_OF: Readonly<Record<string, string>> = {
  library: "library",
  titles: "library",
  changes: "library",
  homebrew: "library",
  cheats: "cheats",
  admin: "admin",
  peers: "library",
  sync: "sync.read",
};
/** How long an invitation may live (SPEC.md § 5.5), and how many may wait at once. */
const INVITATION_DAYS = 30;
const INVITATIONS_LIMIT = 1000;
const APP_SORTS = ["name", "added", "release"];

type Handler = (request: ServerRequest, account: Account, args: string[]) => Promise<ServerResponse>;

interface Route {
  pattern: string[];
  methods: string[];
  family: string;
  handler: keyof LanternApp & `h${string}`;
}

const ROUTES: Route[] = [
  { pattern: ["apps"], methods: ["GET", "HEAD"], family: "library", handler: "hApps" },
  { pattern: ["apps", "missing"], methods: ["POST"], family: "library", handler: "hMissing" },
  { pattern: ["files", "{}"], methods: ["GET", "HEAD"], family: "library", handler: "hFile" },
  { pattern: ["changes"], methods: ["GET", "HEAD"], family: "changes|events", handler: "hChanges" },
  { pattern: ["events"], methods: ["GET"], family: "events", handler: "hEvents" },
  { pattern: ["grants", "sha256", "{}"], methods: ["GET", "HEAD"], family: "peers", handler: "hGrant" },
  { pattern: ["sync"], methods: ["GET", "HEAD", "DELETE"], family: "sync", handler: "hSync" },
  { pattern: ["sync", "{}"], methods: ["GET", "HEAD", "PATCH", "DELETE"], family: "sync", handler: "hSyncCollection" },
  { pattern: ["titles"], methods: ["GET", "HEAD"], family: "titles", handler: "hTitles" },
  { pattern: ["titles", "changes"], methods: ["GET", "HEAD"], family: "titles", handler: "hTitleChanges" },
  { pattern: ["titles", "{}"], methods: ["GET", "HEAD"], family: "titles", handler: "hTitle" },
  { pattern: ["homebrew"], methods: ["GET", "HEAD"], family: "homebrew", handler: "hHomebrewList" },
  { pattern: ["homebrew", "updates"], methods: ["POST"], family: "homebrew", handler: "hHomebrewUpdates" },
  { pattern: ["homebrew", "{}"], methods: ["GET", "HEAD"], family: "homebrew", handler: "hHomebrewEntry" },
  { pattern: ["cheats"], methods: ["GET", "HEAD"], family: "cheats", handler: "hCheats" },
  { pattern: ["cheats", "{}"], methods: ["GET", "HEAD"], family: "cheats", handler: "hCheatText" },
  { pattern: ["pairing"], methods: ["POST"], family: "pairing", handler: "hPairStart" },
  { pattern: ["pairing", "{}"], methods: ["GET"], family: "pairing", handler: "hPairPoll" },
  { pattern: ["admin", "users"], methods: ["GET", "HEAD", "POST"], family: "admin", handler: "hAdminUsers" },
  { pattern: ["admin", "users", "{}"], methods: ["PATCH", "DELETE"], family: "admin", handler: "hAdminUser" },
  { pattern: ["admin", "devices"], methods: ["GET", "HEAD"], family: "admin", handler: "hAdminDevices" },
  { pattern: ["admin", "devices", "{}"], methods: ["DELETE"], family: "admin", handler: "hAdminDevice" },
  { pattern: ["admin", "pairings"], methods: ["GET", "HEAD"], family: "admin", handler: "hAdminPairings" },
  { pattern: ["admin", "pairings", "{}"], methods: ["POST"], family: "admin", handler: "hAdminPairing" },
  {
    pattern: ["admin", "invitations"],
    methods: ["GET", "HEAD", "POST"],
    family: "admin",
    handler: "hAdminInvitations",
  },
  { pattern: ["admin", "invitations", "{}"], methods: ["DELETE"], family: "admin", handler: "hAdminInvitation" },
];

function epoch(text: string | undefined): number | undefined {
  const t = text !== undefined ? Date.parse(text) : Number.NaN;
  return Number.isNaN(t) ? undefined : Math.trunc(t / 1000);
}

function dayOf(text: string | undefined): number | undefined {
  if (text === undefined || !/^\d{4}-\d{2}-\d{2}$/.test(text)) return undefined;
  const t = Date.parse(`${text}T00:00:00Z`);
  return Number.isNaN(t) ? undefined : Math.trunc(t / 86400000);
}

function fold(text: string | undefined): string {
  return (text ?? "").toLowerCase();
}

function parse<T>(check: Check<T>, doc: unknown, what: string): T {
  try {
    return check(doc, "the body");
  } catch (e) {
    if (e instanceof DocumentError) throw badRequest(`${what}: ${e.message}`);
    throw e;
  }
}

function one<T>(found: T[], what: string): T {
  const [first] = found;
  if (first === undefined) throw notFound(`No such ${what} on this server.`);
  if (found.length > 1) throw badRequest("Several platforms have it: name one (Lantern-Platform).");
  return first;
}

function cap(value: RatingCap | undefined): RatingCap | undefined {
  if (value === undefined) return undefined;
  const problem = ratings.capProblem(value);
  if (problem !== undefined) throw badRequest(`${problem} (SPEC.md § 5.6).`);
  return value;
}

/** A device's public key from a pairing request (SPEC.md § 5.4): 400 unless it decodes canonically and is not of small order. */
function deviceKey(alg: string, publicKey: string): Uint8Array {
  const raw = fromBase64(publicKey) ?? new Uint8Array();
  if (alg !== "ed25519" || !ed25519.isPublicKey(raw)) {
    throw badRequest("key is {alg: ed25519, public_key: the 32 bytes of an Ed25519 key, base64}.");
  }
  return raw;
}

/** A body against its Content-Digest (RFC 9530): 400 when it is not one this server reads, 422 `digest_mismatch` when it does not match. */
export function checkContentDigest(request: ServerRequest): void {
  const header = request.header("Content-Digest");
  if (header === undefined) return;
  const announced = digestSha256(header);
  if (announced === undefined) throw badRequest("Content-Digest gives no sha-256 this server reads.");
  if (announced !== createHash("sha256").update(request.body).digest("hex")) {
    throw new HttpProblem(422, "digest_mismatch", "The body does not match its Content-Digest.", {
      title: "Digest mismatch",
    });
  }
}

export interface LanternAppOptions {
  /** The server's UUID, which never changes. */
  uid: string;
  /** What clients show. */
  name: string;
  base?: string;
  software?: [string, string];
  motd?: string;
  /** Without `accounts`: resolves a request's Authorization to an Account, or undefined (401). */
  authenticate?: Authenticate;
  /** Whether a caller without credentials gets `anonymousScopes` (true) or nothing (false). */
  public?: boolean;
  anonymousScopes?: readonly string[];
  /** limits.page_size, 1 to 1000 (SPEC.md § 13). */
  pageLimit?: number;
  defaultPageSize?: number;
  /** Seals cursors and since tokens: the same for every process of the server, kept across restarts. */
  secret?: Uint8Array;
  cursorLifetime?: number;
  /** The platforms of the handshake, when the library should not decide them. */
  platforms?: readonly string[];
  /** The server's accounts, devices and invitations: LanternApp pairs devices and issues their tokens. */
  accounts?: Accounts;
  /** Issue and take only tokens bound to a device key (SPEC.md § 5.4). */
  boundOnly?: boolean;
  /** auth.skew, 60 to 900 seconds. */
  skew?: number;
  /** The server's approval page (a path on its origin, or an absolute URL), `/pair` by default. */
  verify?: string;
  /** The SHA-256 of the server's TLS key (hex), which invitation links carry when no CA vouches for it (§ 5.5). */
  spki?: string;
  /** Seconds a new token lives (none: until revoked). */
  tokenLifetime?: number;
  /** The scheme clients reach the server by, when a proxy in front of it changes it (a signature covers it). */
  scheme?: string;
  /** The server's approval page at `verify` (signing the user in, then `app.desk.approve()`). */
  pairPage?: (request: ServerRequest) => Promise<ServerResponse> | ServerResponse;
  /** Where a failure of the server goes (console.error by default); it answers 500 `internal`. */
  onError?: (error: unknown) => void;
  /**
   * Events (SPEC.md § 18), on by default: `heartbeat` (5 to 60 seconds, 15 by
   * default), `streams` a token holds at once (2), the longest `wait` of a long
   * poll (30 to 300, 60), `retry` (ms, 5000) and a stream's longest life
   * (`maxSeconds`, an hour). false turns the family off.
   */
  events?: false | { heartbeat?: number; streams?: number; wait?: number; retry?: number; maxSeconds?: number };
  /**
   * Grants (SPEC.md § 19.3): the seed (32 bytes) of the server's grant key,
   * kept with its secrets (a new key when absent, its grants then void at a
   * restart), and a grant's lifetime (at most 900 seconds; 600). Without it,
   * the family `peers` is off.
   */
  peers?: { seed?: Uint8Array; lifetime?: number };
  /** Sync (SPEC.md § 20): where it is kept (true: MemorySyncStore), and limits.sync_items (10,000). */
  sync?: SyncStore | true;
  syncItems?: number;
}

/** What a stream counts, and a stream's account checked again at each wake. */
interface Streams {
  heartbeat: number;
  streams: number;
  wait: number;
  retry: number;
  maxSeconds: number;
}

/** Lantern's routes over a `library` (see the module's comment). */
export class LanternApp {
  readonly library: Library;
  readonly uid: string;
  readonly name: string;
  readonly base: string;
  readonly software: [string, string] | undefined;
  readonly motd: string | undefined;
  readonly authenticate: Authenticate | undefined;
  readonly public: boolean;
  readonly anonymousScopes: ReadonlySet<string>;
  readonly pageLimit: number;
  readonly defaultPageSize: number;
  readonly cursors: Cursors;
  readonly since: SinceTokens;
  readonly fixedPlatforms: readonly string[] | undefined;
  readonly accounts: Accounts | undefined;
  readonly boundOnly: boolean;
  readonly skew: number;
  readonly verify: string;
  readonly spki: string | undefined;
  readonly scheme: string | undefined;
  readonly pairPage: LanternAppOptions["pairPage"];
  readonly nonces: sig.NonceCache;
  readonly desk: PairingDesk | undefined;
  /** Pairing requests per address. */
  readonly pairLimiter = new Limiter(30, 60);
  /** Wrong invitation codes per address. */
  readonly attempts = new Limiter(10, 600);
  /** The journal of events, when the family `events` is on. */
  readonly hub: EventHub | undefined;
  readonly streams: Streams;
  readonly syncStore: SyncStore | undefined;
  readonly syncItems: number;
  readonly grantLifetime: number;
  readonly #grantKey: Promise<ed25519.KeyPair> | undefined;
  readonly #open = new Map<string, number>();
  onError: (error: unknown) => void;

  constructor(library: Library, options: LanternAppOptions) {
    const skew = options.skew ?? sig.SKEW;
    if (skew < sig.SKEW_RANGE[0] || skew > sig.SKEW_RANGE[1])
      throw new RangeError("skew is 60 to 900 seconds (SPEC.md § 5.4)");
    if (options.accounts !== undefined && options.authenticate !== undefined)
      throw new TypeError("accounts or authenticate, not both");
    const base = options.base ?? "/api/lantern";
    if (!base.startsWith("/")) throw new RangeError("base is a path, such as /api/lantern");
    const pageLimit = options.pageLimit ?? 500;
    if (pageLimit < 1 || pageLimit > 1000) throw new RangeError("pageLimit is 1 to 1000 (SPEC.md § 13)");
    this.library = library;
    this.uid = options.uid;
    this.name = options.name;
    this.base = base.replace(/\/+$/, "");
    this.software = options.software;
    this.motd = options.motd;
    this.authenticate = options.authenticate;
    this.public = options.public ?? true;
    this.anonymousScopes = new Set(options.anonymousScopes ?? ["library", "cheats"]);
    this.pageLimit = pageLimit;
    this.defaultPageSize = options.defaultPageSize ?? 100;
    const sealer = new Sealer(options.secret);
    this.cursors = new Cursors(sealer, options.cursorLifetime ?? 3600);
    this.since = new SinceTokens(sealer);
    this.fixedPlatforms = options.platforms;
    this.accounts = options.accounts;
    this.boundOnly = options.boundOnly ?? false;
    this.skew = skew;
    this.verify = options.verify ?? "/pair";
    this.spki = options.spki?.toLowerCase();
    this.scheme = options.scheme;
    this.pairPage = options.pairPage;
    this.nonces = new sig.NonceCache(2 * skew);
    this.desk =
      options.accounts !== undefined
        ? new PairingDesk(
            options.accounts,
            options.tokenLifetime !== undefined ? { lifetime: options.tokenLifetime } : {},
          )
        : undefined;
    this.onError = options.onError ?? ((e) => console.error(e));
    const ev = options.events === false ? undefined : (options.events ?? {});
    this.streams = {
      heartbeat: ev?.heartbeat ?? 15,
      streams: ev?.streams ?? 2,
      wait: ev?.wait ?? 60,
      retry: ev?.retry ?? 5000,
      maxSeconds: ev?.maxSeconds ?? 3600,
    };
    const st = this.streams;
    if (st.heartbeat < 5 || st.heartbeat > 60) throw new RangeError("heartbeat is 5 to 60 seconds (SPEC.md § 18.4)");
    if (st.wait < 30 || st.wait > 300) throw new RangeError("wait is 30 to 300 seconds (SPEC.md § 18.4)");
    if (!Number.isInteger(st.streams) || st.streams < 1) throw new RangeError("streams is 1 or more");
    this.hub = ev !== undefined ? new EventHub() : undefined;
    this.syncStore = options.sync === true ? new MemorySyncStore() : options.sync;
    this.syncItems = options.syncItems ?? 10000;
    if (this.syncItems < 1 || this.syncItems > 100000) throw new RangeError("syncItems is 1 to 100,000 (SPEC.md § 13)");
    this.grantLifetime = options.peers?.lifetime ?? 600;
    if (this.grantLifetime < 1 || this.grantLifetime > 900)
      throw new RangeError("a grant lives 900 seconds at most (SPEC.md § 19.3)");
    this.#grantKey =
      options.peers !== undefined
        ? options.peers.seed !== undefined
          ? ed25519.fromSeed(options.peers.seed)
          : ed25519.generate()
        : undefined;
    this.#grantKey?.catch(() => undefined);
    if (this.hub !== undefined) library.subscribe?.((changes) => void this.libraryChanged(changes));
  }

  // Events (SPEC.md § 18).

  async #position(): Promise<number> {
    const journal = this.library.journal();
    return journal !== undefined ? await journal.position() : 0;
  }

  /**
   * Records an event of the server's own (a request done, a backup kept): each
   * caller gets it when its scopes, account and platform allow (§ 18.2).
   * Its scope is its type's (EVENT_SCOPES) unless `audience.scope` says.
   */
  async emit(event: string, data: Record<string, unknown>, audience: Audience = {}): Promise<void> {
    if (this.hub === undefined) return;
    this.hub.emit(event, data, audience, [], await this.#position());
  }

  /** What changed in the library (the event `library`): a Library with subscribe() tells it by itself. */
  async libraryChanged(changes: readonly LibraryChange[]): Promise<void> {
    if (this.hub === undefined || changes.length === 0) return;
    this.hub.emit("library", {}, {}, [...changes], await this.#position());
  }

  /** The server stops: every stream gets `shutdown` and ends (§ 18.2, L-18.2-2). */
  shutdown(retry = 30): void {
    this.hub?.shutdown(retry);
  }

  /** A token of /v1/changes and of events: the journal's position and the event's place. */
  #token(seq: number, position: number): string {
    const journal = this.library.journal();
    return this.since.sealer.seal("s", { e: journal?.epoch ?? "", n: position, h: this.hub?.epoch ?? "", v: seq });
  }

  /** The event a stream or a long poll starts after: `since`'s, or now's; 400 for one never given, 410 too old. */
  #eventStart(since: string | undefined): number {
    const hub = this.hub as EventHub;
    if (since === undefined) return hub.seq;
    let payload: unknown;
    try {
      payload = this.since.sealer.open("s", since);
    } catch {
      throw badRequest("Unknown event id: one this server never gave.");
    }
    const p = payload as Record<string, unknown> | null;
    const v = typeof p === "object" && p !== null ? p["v"] : undefined;
    if (typeof v !== "number" || !Number.isInteger(v)) throw badRequest("Unknown event id.");
    if (p?.["h"] !== hub.epoch || v < hub.floor)
      throw new HttpProblem(410, "gone", "This id is too old: read again, then connect without it.");
    if (v > hub.seq) throw badRequest("Unknown event id.");
    return v;
  }

  /** The events after `after` this caller may see (§ 18.2), each with its data for it. */
  async #visible(
    account: Account,
    platform: string | undefined,
    after: number,
  ): Promise<[HubEvent, Record<string, unknown>][]> {
    const hub = this.hub as EventHub;
    const out: [HubEvent, Record<string, unknown>][] = [];
    let hide: ((platform: string, titleId: string) => boolean) | undefined;
    for (const e of hub.after(after)) {
      if (e.event === "shutdown" || e.event === "ready") continue;
      const scope = e.audience.scope ?? EVENT_SCOPES[e.event];
      if (scope === undefined || !account.scopes.has(scope) || account.state === "frozen") continue;
      if (e.audience.user !== undefined && e.audience.user !== account.name) continue;
      if (platform !== undefined && e.audience.platform !== undefined && e.audience.platform !== platform) continue;
      if (account.ratingCap !== undefined && e.audience.titleId !== undefined && e.audience.platform !== undefined) {
        hide ??= await this.hides(account);
        if (hide(e.audience.platform, e.audience.titleId)) continue;
      }
      if (e.event === "library") {
        const families = new Set<string>();
        const platforms = new Set<string>();
        for (const c of e.changes) {
          if (platform !== undefined && c.platform !== platform) continue;
          if (account.ratingCap !== undefined) {
            hide ??= await this.hides(account);
            if (c.titleId !== undefined && hide(c.platform, c.titleId)) continue;
            if (c.ratings !== undefined && ratings.hidden(c.ratings as Rating[], account.ratingCap)) continue;
          }
          families.add(c.family);
          platforms.add(c.platform);
        }
        if (families.size === 0) continue;
        out.push([e, { schema: SCHEMA, families: [...families].sort(), platforms: [...platforms].sort() }]);
        continue;
      }
      out.push([e, e.data]);
    }
    return out;
  }

  /** Whether a stream's caller may still read events (§ 18.1, L-18.1-8): its token not revoked, its account not frozen nor gone. */
  async #stillAllowed(request: ServerRequest): Promise<Account | undefined> {
    try {
      const account = await this.account(request);
      this.allow(account, "events");
      return account;
    } catch {
      return undefined;
    }
  }

  async hEvents(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const hub = this.hub as EventHub;
    const platform = platformOf(request);
    const since = request.query.get("since") || request.header("Last-Event-ID")?.trim() || undefined;
    let last = this.#eventStart(since);
    const key = request.header("Authorization")
      ? `t:${createHash("sha256")
          .update(request.header("Authorization") ?? "")
          .digest("hex")}`
      : `a:${request.remote}`;
    const held = this.#open.get(key) ?? 0;
    if (held >= this.streams.streams)
      throw slowDown(
        Math.min(this.streams.heartbeat, 5),
        `At most ${this.streams.streams} event streams at once for a token (SPEC.md § 18.4).`,
      );
    this.#open.set(key, held + 1);
    const abort = new AbortController();
    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      const n = (this.#open.get(key) ?? 1) - 1;
      if (n <= 0) this.#open.delete(key);
      else this.#open.set(key, n);
    };
    const encoder = new TextEncoder();
    const startPosition = await this.#position();
    const app = this;
    let caller = account;
    async function* stream(): AsyncGenerator<Uint8Array> {
      try {
        yield encoder.encode(`retry: ${app.streams.retry}

`);
        const readyAt = hub.after(last - 1).find((e) => e.seq === last)?.position ?? startPosition;
        yield encoder.encode(sseEvent(app.#token(last, readyAt), "ready", { schema: SCHEMA }));
        const ends = Date.now() + app.streams.maxSeconds * 1000;
        let beat = Date.now();
        while (!abort.signal.aborted) {
          const top = hub.seq;
          for (const [e, data] of await app.#visible(caller, platform, last)) {
            if (e.seq > top) break;
            yield encoder.encode(sseEvent(app.#token(e.seq, e.position), e.event, data));
            beat = Date.now();
          }
          last = top;
          if (hub.stopping) {
            const end = hub
              .after(0)
              .filter((e) => e.event === "shutdown")
              .at(-1);
            yield encoder.encode(
              sseEvent(
                app.#token(end?.seq ?? hub.seq, end?.position ?? 0),
                "shutdown",
                end?.data ?? { schema: SCHEMA, retry: 30 },
              ),
            );
            return;
          }
          const still = await app.#stillAllowed(request);
          if (still === undefined) return;
          caller = still;
          if (Date.now() - beat >= app.streams.heartbeat * 1000) {
            yield encoder.encode(": heartbeat\n\n");
            beat = Date.now();
          }
          if (Date.now() >= ends) return;
          await hub.wait(Math.max(50, app.streams.heartbeat * 1000 - (Date.now() - beat)), abort.signal);
        }
      } finally {
        release();
      }
    }
    const headers = new Headers({
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Accel-Buffering": "no",
      Vary: "Authorization, Lantern-Platform",
    });
    const body: StreamBody = {
      stream: stream(),
      cancel: () => {
        abort.abort();
        release();
      },
    };
    return { status: 200, headers, body };
  }

  // Dispatch.

  /** The answer to `request`: never throws (a failure of the server answers 500 `internal`). */
  async handle(request: ServerRequest): Promise<ServerResponse> {
    try {
      return await this.route(request);
    } catch (e) {
      if (e instanceof HttpProblem) return problemResponse(request, e);
      this.onError(e);
      return problemResponse(request, new HttpProblem(500, "internal", "The server failed; try again later."));
    }
  }

  /** Whether `path` is one of Lantern's: the handshake, below <base>/v1/, or the approval page. */
  owns(path: string): boolean {
    return (
      path === "/.well-known/lantern" ||
      path === `${this.base}/v1` ||
      path.startsWith(`${this.base}/v1/`) ||
      (this.verifyPath !== undefined && path === this.verifyPath)
    );
  }

  /** The approval page's path, when it is on this server and LanternApp pairs. */
  get verifyPath(): string | undefined {
    return this.accounts !== undefined && this.verify.startsWith("/") ? this.verify : undefined;
  }

  async approval(request: ServerRequest): Promise<ServerResponse> {
    if (this.pairPage !== undefined) return this.pairPage(request);
    if (request.method !== "GET" && request.method !== "HEAD") throw methodNotAllowed(["GET", "HEAD"]);
    const code = (request.query.get("code") || request.query.get("invitation") || "").slice(0, 64);
    const page = approvalPage({
      fingerprint: this.spki !== undefined ? short(this.spki) : undefined,
      code,
      message: "Sign in on this server to approve a device: an administrator approves it from an admin app.",
      action: this.verify,
    });
    return htmlResponse(request, page);
  }

  async route(request: ServerRequest): Promise<ServerResponse> {
    const path = request.path;
    if (this.verifyPath !== undefined && path === this.verifyPath) return this.approval(request);
    if (path === "/.well-known/lantern" || path === `${this.base}/v1` || path === `${this.base}/v1/`) {
      const account = await this.account(request);
      await this.checkSignature(request, account);
      if (request.method !== "GET" && request.method !== "HEAD") throw methodNotAllowed(["GET", "HEAD"]);
      return jsonResponse(request, await this.handshake(account));
    }
    const prefix = `${this.base}/v1/`;
    if (!path.startsWith(prefix)) throw notFound("No such route on this server.");
    const segments = path.slice(prefix.length).split("/");
    const matched = ROUTES.filter(
      (r) =>
        r.pattern.length === segments.length &&
        r.pattern.every((p, i) => p === segments[i] || (p === "{}" && segments[i] !== "")),
    ).map((r) => ({ route: r, args: segments.filter((_, i) => r.pattern[i] === "{}") }));
    if (matched.length === 0) throw notFound("No such route on this server.");
    if (!matched.some((m) => this.offered(m.route.family))) throw notFound("This server does not offer it.");
    const account = await this.account(request);
    await this.checkSignature(request, account);
    const chosen = matched.find((m) => m.route.methods.includes(request.method));
    if (chosen === undefined) throw methodNotAllowed([...new Set(matched.flatMap((m) => m.route.methods))]);
    this.allow(account, chosen.route.family);
    const handler = this[chosen.route.handler] as Handler;
    return handler.call(this, request, account, chosen.args);
  }

  // Who calls, and what they may do (SPEC.md § 4.2, § 5.1).

  async account(request: ServerRequest): Promise<Account> {
    const header = request.header("Authorization");
    if (!header) return { scopes: this.public ? this.anonymousScopes : new Set(), state: "anonymous" };
    const space = header.trim().indexOf(" ");
    const scheme = space < 0 ? header.trim() : header.trim().slice(0, space);
    const value =
      space < 0
        ? ""
        : header
            .trim()
            .slice(space + 1)
            .trim();
    if (scheme.toLowerCase() !== "bearer" || !value) throw unauthorized("Send a token: Authorization: Bearer <token>.");
    const account = this.accounts !== undefined ? await this.accountOf(value) : await this.authenticate?.(request);
    if (account === undefined) throw unauthorized("Unknown, revoked or expired token.", true);
    return account;
  }

  /** The caller of a token the server issued: its device's scopes, cut back to its account's. */
  async accountOf(token: string): Promise<Account | undefined> {
    if (this.accounts === undefined) return undefined;
    const device = await this.accounts.deviceOf(token);
    const user = device !== undefined ? await this.accounts.user(device.user) : undefined;
    if (device === undefined || user === undefined) return undefined;
    const account: Account = {
      scopes: new Set(device.scopes.filter((s) => user.scopes.includes(s))),
      state: user.state === "frozen" ? "frozen" : "active",
      name: user.name,
      device: device.id,
    };
    if (device.key !== undefined) account.key = device.key;
    if (device.ratingCap !== undefined) account.ratingCap = device.ratingCap;
    return account;
  }

  // Signed requests (SPEC.md § 5.4).

  signatureProblem(
    request: ServerRequest,
    code: sig.RefusalCode,
    detail: string,
    withToken: boolean,
    keyId?: string,
  ): HttpProblem {
    const titles: Record<sig.RefusalCode, string> = {
      signature_required: "Signature required",
      signature_invalid: "Signature invalid",
      signature_expired: "Signature expired",
      signature_replayed: "Signature replayed",
    };
    return new HttpProblem(401, code, detail, {
      title: titles[code],
      headers: {
        "WWW-Authenticate": `Bearer realm="lantern"${withToken ? ', error="invalid_token"' : ""}`,
        "Accept-Signature": sig.acceptSignature(withToken, request.body.length > 0, keyId),
      },
    });
  }

  /** Checks the request's signature by `publicKey`, or throws its 401; then its body against its Content-Digest. */
  async verifySignature(request: ServerRequest, publicKey: Uint8Array, withToken: boolean): Promise<void> {
    let uri: string;
    try {
      uri = request.targetUri(this.scheme);
    } catch {
      throw badRequest("No Host this server can read.");
    }
    try {
      await sig.verifyRequest(request.method, uri, request.headers, publicKey, {
        withToken,
        withBody: request.body.length > 0,
        nonces: this.nonces,
        skew: this.skew,
      });
    } catch (e) {
      if (e instanceof sig.Refused)
        throw this.signatureProblem(request, e.code, e.detail, withToken, sig.keyid(publicKey));
      throw e;
    }
    if (request.body.length > 0) checkContentDigest(request);
  }

  async checkSignature(request: ServerRequest, account: Account): Promise<void> {
    if (account.key !== undefined) await this.verifySignature(request, account.key, true);
    else if (this.boundOnly && account.state !== "anonymous") {
      throw this.signatureProblem(
        request,
        "signature_required",
        "This server takes only tokens bound to a device key: pair this device again, with a key.",
        true,
      );
    }
  }

  offered(family: string): boolean {
    if (family === "changes|events") return this.offered("changes") || this.offered("events");
    if (family === "events") return this.hub !== undefined;
    if (family === "peers") return this.#grantKey !== undefined && this.library.families.has("library");
    if (family === "sync") return this.syncStore !== undefined;
    if (family === "pairing" || family === "signatures" || family === "admin") return this.accounts !== undefined;
    if (family === "changes") return this.library.families.has("library") && this.library.journal() !== undefined;
    return this.library.families.has(family);
  }

  allow(account: Account, family: string): void {
    if (family === "changes|events") {
      try {
        this.allow(account, "changes");
      } catch (e) {
        if (!(e instanceof HttpProblem)) throw e;
        this.allow(account, "events");
      }
      return;
    }
    if (!this.offered(family)) throw notFound("This server does not offer it.");
    if (family === "pairing") return; // whoever reaches the server may ask to pair (SPEC.md § 4.2, § 5.2)
    if (account.state === "anonymous" && (!this.public || family === "admin" || family === "sync"))
      throw unauthorized("This server asks for a token.");
    if (account.state === "frozen")
      throw new HttpProblem(403, "account_frozen", "This account may do nothing for now.", { title: "Account frozen" });
    if (family === "events") {
      // Offered to whoever may read one kind of event (SPEC.md § 18.2).
      if (![...new Set(Object.values(EVENT_SCOPES))].some((s) => account.scopes.has(s)))
        throw new HttpProblem(403, "forbidden", "This account may read no event.");
      return;
    }
    const scope = SCOPE_OF[family];
    if (scope === undefined || !account.scopes.has(scope))
      throw new HttpProblem(403, "forbidden", `This account lacks the scope ${scope}.`);
  }

  features(account: Account): Record<string, number> {
    const out: Record<string, number> = {};
    for (const family of FAMILIES) {
      try {
        if (!(family in SCOPE_OF) && family !== "events") throw notFound();
        this.allow(account, family);
        out[family] = SCHEMA;
      } catch (e) {
        if (!(e instanceof HttpProblem)) throw e;
        out[family] = 0;
      }
    }
    // The same for every caller (SPEC.md § 4.2): whoever reaches the server may pair, with a key.
    out["pairing"] = out["signatures"] = this.accounts !== undefined ? SCHEMA : 0;
    return out;
  }

  /** The platforms the server has something for (SPEC.md § 4.2). */
  async platforms(): Promise<string[]> {
    if (this.fixedPlatforms !== undefined) return [...new Set(this.fixedPlatforms)].sort();
    const found = new Set<string>();
    const lib = this.library;
    if (lib.families.has("library")) for (const a of await lib.apps()) found.add(a.platform);
    if (lib.families.has("titles")) for (const t of await lib.titles([])) found.add(t.platform);
    if (lib.families.has("homebrew")) for (const h of await lib.homebrew([])) found.add(h.platform);
    if (lib.families.has("cheats")) for (const c of await lib.cheats()) found.add(c.platform);
    return [...found].sort();
  }

  /** The handshake document (SPEC.md § 4.2) for `account`. */
  async handshake(account: Account): Promise<Record<string, unknown>> {
    const acc: Record<string, unknown> = { state: account.state, scopes: [...account.scopes].sort() };
    if (account.name) acc["name"] = account.name;
    if (account.state !== "anonymous") acc["bound"] = account.key !== undefined;
    if (account.ratingCap !== undefined) acc["rating_cap"] = account.ratingCap;
    const doc: Record<string, unknown> = { schema: SCHEMA, uid: this.uid, name: this.name };
    if (this.software) doc["software"] = { name: this.software[0], version: this.software[1] };
    doc["base"] = this.base;
    doc["versions"] = [1];
    doc["platforms"] = await this.platforms();
    if (this.motd) {
      doc["motd"] = this.motd;
      doc["language"] = "en";
    }
    const features = this.features(account);
    doc["account"] = acc;
    doc["features"] = features;
    if (features["signatures"]) doc["auth"] = { bearer_only: !this.boundOnly, skew: this.skew };
    if (features["peers"] && this.#grantKey !== undefined) {
      doc["peers"] = { key: toBase64((await this.#grantKey).publicKey), grant_lifetime: this.grantLifetime };
    }
    const limits: Record<string, number> = { page_size: this.pageLimit };
    if (features["events"]) {
      limits["heartbeat"] = this.streams.heartbeat;
      limits["event_streams"] = this.streams.streams;
      limits["wait"] = this.streams.wait;
    }
    if (features["sync"]) limits["sync_items"] = this.syncItems;
    doc["limits"] = limits;
    return doc;
  }

  // Rating caps (SPEC.md § 5.6).

  /** Whether the caller's rating cap hides the title (platform, title_id), its apps and cheat sets. */
  async hides(account: Account): Promise<(platform: string, titleId: string) => boolean> {
    const capOf = account.ratingCap;
    if (capOf === undefined) return () => false;
    const rated = new Map<string, readonly Rating[]>();
    if (this.library.families.has("titles")) {
      for (const t of await this.library.titles([])) rated.set(`${t.platform}/${t.title_id}`, t.ratings ?? []);
    }
    return (platform, titleId) => ratings.hidden(rated.get(`${platform}/${titleId}`) ?? [], capOf);
  }

  /** Whether the file is a hidden app's or a hidden homebrew's (SPEC.md § 5.6). */
  async fileHidden(account: Account, fileId: string): Promise<boolean> {
    if (account.ratingCap === undefined) return false;
    const hide = await this.hides(account);
    const tail = `/files/${fileId}`;
    for (const a of await this.library.apps()) if (a.file.endsWith(tail) && hide(a.platform, a.title_id)) return true;
    if (this.library.families.has("homebrew")) {
      for (const e of await this.library.homebrew([])) {
        const files = [e.package, ...(e.packages ?? [])].map((p) => p.file);
        if (files.some((f) => f.endsWith(tail)) && ratings.hidden(e.ratings, account.ratingCap)) return true;
      }
    }
    return false;
  }

  // Library (SPEC.md § 6).

  #size(request: ServerRequest): number {
    return pageSize(request.query.get("page_size"), this.defaultPageSize, this.pageLimit);
  }

  #appKey(sort: string, releases: ReadonlyMap<string, number>): (a: App) => SortKey {
    if (sort === "added") return (a) => [-(epoch(a.added) ?? 0), a.id];
    if (sort === "release") {
      return (a) => {
        const day = releases.get(`${a.platform}/${a.title_id}`);
        return day !== undefined ? [0, -day, a.id] : [1, 0, a.id];
      };
    }
    return (a) => [fold(a.name), a.id];
  }

  async #releases(): Promise<Map<string, number>> {
    const out = new Map<string, number>();
    if (!this.library.families.has("titles")) return out;
    for (const t of await this.library.titles([])) {
      const day = dayOf(t.release);
      if (day !== undefined) out.set(`${t.platform}/${t.title_id}`, day);
    }
    return out;
  }

  #sort(request: ServerRequest): string {
    const sort = request.query.get("sort") || "name";
    if (!APP_SORTS.includes(sort)) throw badRequest(`sort is ${APP_SORTS.join(", ")}.`);
    return sort;
  }

  async #appsPage(request: ServerRequest, apps: App[], scope: string, sort: string): Promise<ServerResponse> {
    const key = this.#appKey(sort, sort === "release" ? await this.#releases() : new Map());
    const page = this.cursors.page(apps, key, {
      size: this.#size(request),
      cursor: request.query.get("cursor"),
      scope,
    });
    return jsonResponse(request, { schema: SCHEMA, items: page.items, total: page.total, next: page.next });
  }

  async hApps(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const platform = platformOf(request);
    const kind = request.query.get("type");
    const titleId = request.query.get("title_id");
    const text = request.query.get("q");
    if (kind !== undefined && !WORD.test(kind))
      throw badRequest("type is a lower-case word, such as base, update or dlc.");
    if (titleId !== undefined && !CORE_ID.test(titleId))
      throw badRequest("title_id is 1 to 128 letters, digits, '.', '_' and '-'.");
    const sort = this.#sort(request);
    const hide = await this.hides(account);
    const apps = (await this.library.apps()).filter(
      (a) =>
        !hide(a.platform, a.title_id) &&
        (platform === undefined || a.platform === platform) &&
        (kind === undefined || a.type === kind) &&
        (titleId === undefined || a.title_id === titleId) &&
        (!text || fold(a.name).includes(fold(text))),
    );
    return this.#appsPage(request, apps, this.cursors.scope("apps", platform, kind, titleId, text, sort), sort);
  }

  async hMissing(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const doc = parse(
      models.readMissingRequest,
      readDocument(request),
      "installed is a list of {app_id, version_code}, want a list",
    );
    const platform = platformOf(request, true) as string;
    if (doc.installed.some((i) => !CORE_ID.test(i.app_id) || i.version_code < 0))
      throw badRequest("installed is a list of {app_id, version_code}.");
    if (doc.want.length === 0 || doc.want.some((w) => !["base", "update", "dlc"].includes(w)))
      throw badRequest("want lists base, update or dlc.");
    const sort = this.#sort(request);
    const hide = await this.hides(account);
    const pairs = doc.installed.map((i): [string, number] => [i.app_id, i.version_code]);
    const found = missing(
      (await this.library.apps()).filter((a) => a.platform === platform && !hide(a.platform, a.title_id)),
      platform,
      pairs,
      new Set(doc.want),
    );
    const scope = this.cursors.scope("missing", platform, [...pairs].sort(), [...new Set(doc.want)].sort(), sort);
    return this.#appsPage(request, found, scope, sort);
  }

  async hFile(request: ServerRequest, account: Account, args: string[]): Promise<ServerResponse> {
    const id = args[0] ?? "";
    const file = await this.library.file(id);
    if (file === undefined || (await this.fileHidden(account, id))) throw notFound("No such file; read the app again.");
    return fileResponse(request, file);
  }

  async hChanges(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const wait = request.query.get("wait");
    if (wait !== undefined) return this.#longPoll(request, account, wait);
    this.allow(account, "changes");
    const journal = this.library.journal() as NonNullable<ReturnType<Library["journal"]>>;
    const platform = platformOf(request);
    const current = await journal.position();
    const token = this.#token(this.hub?.seq ?? 0, current);
    const since = request.query.get("since");
    if (since === undefined) return jsonResponse(request, { schema: SCHEMA, added: [], removed: [], since: token });
    const after = this.since.position("s", since, journal.epoch, await journal.oldest(), current);
    const [added, removed] = await journal.appChanges(after, platform);
    const hide = await this.hides(account);
    return jsonResponse(request, {
      schema: SCHEMA,
      added: added.filter((a) => !hide(a.platform, a.title_id)),
      removed,
      since: token,
    });
  }

  /** A long poll (SPEC.md § 18.3): the events after `since` the caller may see, as soon as one comes or `wait` ran out. */
  async #longPoll(request: ServerRequest, account: Account, wait: string): Promise<ServerResponse> {
    this.allow(account, "events");
    const hub = this.hub as EventHub;
    const since = request.query.get("since");
    if (since === undefined || !/^\d{1,9}$/.test(wait))
      throw badRequest("wait is a whole number of seconds, from 0, with since (SPEC.md § 18.3).");
    const platform = platformOf(request);
    const start = this.#eventStart(since);
    const deadline = Date.now() + Math.min(Number(wait), this.streams.wait) * 1000;
    let found: [HubEvent, Record<string, unknown>][] = [];
    let top = hub.seq;
    for (;;) {
      top = hub.seq;
      found = (await this.#visible(account, platform, start)).filter(([e]) => e.seq <= top);
      const left = deadline - Date.now();
      if (found.length > 0 || left <= 0 || hub.stopping) break;
      await hub.wait(left);
    }
    const doc: Record<string, unknown> = { schema: SCHEMA, added: [], removed: [] };
    const journal = this.library.journal();
    let position = await this.#position();
    let changesAllowed = false;
    try {
      this.allow(account, "changes");
      changesAllowed = journal !== undefined;
    } catch (e) {
      if (!(e instanceof HttpProblem)) throw e;
    }
    if (changesAllowed && journal !== undefined) {
      const opened = this.since.sealer.open("s", since) as Record<string, unknown>;
      const n = typeof opened["n"] === "number" ? opened["n"] : 0;
      if (opened["e"] === journal.epoch && n >= (await journal.oldest()) && n <= position) {
        const [added, removed] = await journal.appChanges(n, platform);
        const hide = await this.hides(account);
        doc["added"] = added.filter((a) => !hide(a.platform, a.title_id));
        doc["removed"] = removed;
      }
    }
    const lastFound = found.at(-1)?.[0];
    if (lastFound !== undefined) position = lastFound.position;
    doc["since"] = this.#token(lastFound?.seq ?? top, position);
    doc["events"] = found.map(([e, data]) => ({ id: this.#token(e.seq, e.position), event: e.event, data }));
    const response = jsonResponse(request, doc);
    response.headers.set("Cache-Control", "no-store");
    response.headers.delete("ETag");
    return response;
  }

  // Grants (SPEC.md § 19.3).

  async hGrant(request: ServerRequest, account: Account, args: string[]): Promise<ServerResponse> {
    const sha = args[0] ?? "";
    if (!SHA256_HEX.test(sha)) throw notFound("No such file on this server.");
    const platform = platformOf(request);
    const hide = await this.hides(account);
    let size: number | undefined;
    for (const a of await this.library.apps()) {
      if (a.sha256 === sha && (platform === undefined || a.platform === platform) && !hide(a.platform, a.title_id)) {
        size = a.size;
        break;
      }
    }
    if (size === undefined && this.library.families.has("homebrew")) {
      for (const e of await this.library.homebrew(request.languages)) {
        if ((platform !== undefined && e.platform !== platform) || ratings.hidden(e.ratings, account.ratingCap))
          continue;
        const p = [e.package, ...(e.packages ?? [])].find((x) => x.sha256 === sha);
        if (p !== undefined) {
          size = p.size;
          break;
        }
      }
    }
    if (size === undefined) throw notFound("No such file on this server, or not for this caller.");
    const key = await (this.#grantKey as Promise<ed25519.KeyPair>);
    const exp = Math.trunc(Date.now() / 1000) + this.grantLifetime;
    const grant = await signGrant(key.privateKey, this.uid, sha, size, exp);
    const response = jsonResponse(request, {
      schema: SCHEMA,
      sha256: sha,
      size,
      grant,
      expires: utc(new Date(exp * 1000)),
    });
    response.headers.set("Cache-Control", "no-store");
    response.headers.delete("ETag");
    return response;
  }

  // Sync (SPEC.md § 20).

  #syncUser(account: Account, write: boolean): string {
    if (write && !account.scopes.has("sync.write"))
      throw new HttpProblem(403, "forbidden", "This account lacks the scope sync.write.");
    if (account.name === undefined)
      throw new HttpProblem(403, "forbidden", "Sync is kept per account: this caller has none.");
    return account.name;
  }

  async hSync(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const store = this.syncStore as SyncStore;
    if (request.method === "DELETE") {
      const user = this.#syncUser(account, true);
      await store.erase(user);
      for (const c of COLLECTIONS) await this.emit("sync", { collection: c, rev: 0 }, { user });
      return emptyResponse(request);
    }
    const user = this.#syncUser(account, false);
    const { generation, collections } = await store.overview(user, COLLECTIONS);
    const doc: Record<string, unknown> = { schema: SCHEMA, generation };
    if (account.device !== undefined) doc["device"] = account.device;
    doc["collections"] = collections;
    const response = jsonResponse(request, doc);
    response.headers.set("Cache-Control", "private, no-store");
    return response;
  }

  /** An item sent, of its collection's form (SPEC.md § 20.2, § 20.4): 400 otherwise, 403 for another device's. */
  #syncItem(collection: string, item: models.SyncItem, account: Account): SentItem {
    if (syncTime(item.updated) === undefined)
      throw badRequest("updated is a UTC time to the millisecond, such as 2026-10-30T09:12:03.250Z.");
    const deleted = item.deleted === true;
    if (deleted === "value" in item || (item.deleted !== undefined && item.deleted !== true))
      throw badRequest("An item has a value, or deleted: true, not both.");
    if (collection === "wishes") {
      const slash = item.key.indexOf("/");
      const platform = item.key.slice(0, slash);
      const titleId = item.key.slice(slash + 1);
      if (slash < 1 || !isPlatform(platform) || !CORE_ID.test(titleId))
        throw badRequest("A wish's key is <platform>/<title_id>.");
      if (!deleted) {
        const v = item.value as Record<string, unknown>;
        if (definition("wish", v).length > 0 || v["platform"] !== platform || v["title_id"] !== titleId)
          throw badRequest("A wish is {platform, title_id, name?, note?}, of its key.");
      }
    } else {
      if (!/^d_[A-Za-z0-9_-]{1,64}$/.test(item.key)) throw badRequest("An installed item's key is a device's id, d_….");
      if (item.key !== account.device)
        throw new HttpProblem(403, "forbidden", "A device writes its own item of installed only (SPEC.md § 20.4).");
      if (!deleted && definition("installed", item.value).length > 0)
        throw badRequest("An installed item is {device, platform, apps, homebrew}.");
    }
    const out: SentItem = { key: item.key, updated: item.updated };
    if (deleted) out.deleted = true;
    else out.value = item.value;
    return out;
  }

  async hSyncCollection(request: ServerRequest, account: Account, args: string[]): Promise<ServerResponse> {
    const store = this.syncStore as SyncStore;
    const collection = args[0] ?? "";
    if (!(COLLECTIONS as readonly string[]).includes(collection)) throw notFound("No such collection.");
    if (request.method === "DELETE") {
      const user = this.#syncUser(account, true);
      await store.erase(user, collection);
      await this.emit("sync", { collection, rev: 0 }, { user });
      return emptyResponse(request);
    }
    if (request.method === "PATCH") {
      const user = this.#syncUser(account, true);
      const raw = readDocument(request);
      if (Array.isArray(raw["items"]) && raw["items"].length > WRITE_LIMIT)
        throw new HttpProblem(413, "too_large", `A write holds ${WRITE_LIMIT} items at most (SPEC.md § 13).`);
      const doc = parse(models.readSyncWrite, raw, "A write is {schema, generation, items}");
      if (doc.items.length === 0) throw badRequest("items lists the items written.");
      if (new Set(doc.items.map((i) => i.key)).size !== doc.items.length) throw badRequest("Each key once in a write.");
      const items = doc.items.map((i) => this.#syncItem(collection, i, account));
      const options: { ifMatch?: string; now: number; skew: number; limit: number } = {
        now: Date.now(),
        skew: this.skew,
        limit: this.syncItems,
      };
      const ifMatch = request.header("If-Match");
      if (ifMatch !== undefined) options.ifMatch = ifMatch;
      const before = (await store.overview(user, [collection])).collections[collection]?.rev ?? 0;
      const kept = await store.merge(user, collection, doc.generation, items, options);
      if (kept.rev !== before) await this.emit("sync", { collection, rev: kept.rev }, { user });
      return jsonResponse(request, {
        schema: SCHEMA,
        collection,
        generation: kept.generation,
        rev: kept.rev,
        items: kept.items.map(publicItem),
      });
    }
    const user = this.#syncUser(account, false);
    const sinceText = request.query.get("since");
    if (sinceText !== undefined && !/^\d{1,15}$/.test(sinceText)) throw badRequest("since is a revision, an integer.");
    const read = await store.read(user, collection, sinceText !== undefined ? Number(sinceText) : undefined);
    const page = this.cursors.page(read.items, (i) => [i.rev, i.key], {
      size: this.#size(request),
      cursor: request.query.get("cursor"),
      scope: this.cursors.scope("sync", user, collection, sinceText),
    });
    const response = jsonResponse(request, {
      schema: SCHEMA,
      collection,
      generation: read.generation,
      rev: read.rev,
      items: page.items.map(publicItem),
      next: page.next,
    });
    response.headers.set("Cache-Control", "private, no-store");
    return response;
  }

  // Titles (SPEC.md § 7).

  async hTitles(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const platform = platformOf(request);
    const ids = (request.query.get("ids") ?? "").split(",").filter(Boolean);
    if (ids.length === 0) throw badRequest("ids lists the title ids, comma-separated.");
    if (ids.length > TITLES_AT_ONCE) throw badRequest(`At most ${TITLES_AT_ONCE} ids at once.`);
    if (!ids.every((i) => CORE_ID.test(i)))
      throw badRequest("A title id is 1 to 128 letters, digits, '.', '_' and '-'.");
    const wanted = new Set(ids);
    const hide = await this.hides(account);
    const titles = (await this.library.titles(request.languages))
      .filter(
        (t) =>
          wanted.has(t.title_id) &&
          (platform === undefined || t.platform === platform) &&
          !hide(t.platform, t.title_id),
      )
      .sort((a, b) => (a.platform + "/" + a.title_id < b.platform + "/" + b.title_id ? -1 : 1));
    const known = new Set(titles.map((t) => t.title_id));
    return jsonResponse(request, { schema: SCHEMA, titles, unknown: [...new Set(ids)].filter((i) => !known.has(i)) });
  }

  async hTitle(request: ServerRequest, account: Account, args: string[]): Promise<ServerResponse> {
    const platform = platformOf(request);
    const hide = await this.hides(account);
    const found = (await this.library.titles(request.languages)).filter(
      (t) =>
        t.title_id === args[0] && (platform === undefined || t.platform === platform) && !hide(t.platform, t.title_id),
    );
    const title: Title = one(found, "title");
    return jsonResponse(request, { schema: SCHEMA, ...title });
  }

  async hTitleChanges(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const platform = platformOf(request);
    const journal = this.library.journal();
    const since = request.query.get("since");
    if (journal === undefined) {
      if (since !== undefined)
        throw new HttpProblem(410, "gone", "This server keeps no journal: read the titles again.");
      return jsonResponse(request, {
        schema: SCHEMA,
        titles: [],
        removed: [],
        since: this.since.give("t", "", 0),
        more: false,
      });
    }
    const current = await journal.position();
    const token = this.since.give("t", journal.epoch, current);
    const doc: Record<string, unknown> = { schema: SCHEMA, titles: [], removed: [], since: token, more: false };
    if (since !== undefined) {
      const after = this.since.position("t", since, journal.epoch, await journal.oldest(), current);
      const [titles, removed] = await journal.titleChanges(after, platform, request.languages);
      const hide = await this.hides(account);
      doc["titles"] = titles.filter((t) => !hide(t.platform, t.title_id));
      doc["removed"] = removed;
    }
    return jsonResponse(request, doc);
  }

  // Homebrew (SPEC.md § 8).

  /** An entry as a listing shows it: without its manifests (SPEC.md § 8.2). */
  static listed(entry: Homebrew): Record<string, unknown> {
    const strip = (p: object): object => {
      const { manifest: _manifest, ...rest } = p as { manifest?: unknown };
      return rest;
    };
    const out: Record<string, unknown> = { ...entry, package: strip(entry.package) };
    if (entry.packages !== undefined) out["packages"] = entry.packages.map(strip);
    return out;
  }

  static homebrewKey(e: Homebrew): SortKey {
    return [fold(e.name), e.platform, e.id];
  }

  async hHomebrewList(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const platform = platformOf(request);
    const text = request.query.get("q");
    const kind = request.query.get("kind");
    const genre = request.query.get("genre");
    if (kind !== undefined && !WORD.test(kind))
      throw badRequest("kind is a lower-case word, such as app, game, port or tool.");
    if (genre !== undefined && !WORD.test(genre))
      throw badRequest("genre is a lower-case word, such as adventure or puzzle.");
    if ((request.query.get("sort") || "name") !== "name") throw badRequest("homebrew is sorted by name.");
    const entries = (await this.library.homebrew(request.languages)).filter(
      (e) =>
        !ratings.hidden(e.ratings, account.ratingCap) &&
        (platform === undefined || e.platform === platform) &&
        (kind === undefined || effectiveKind(e) === kind) &&
        (genre === undefined || (e.genres ?? []).includes(genre)) &&
        (!text || fold(e.name).includes(fold(text))),
    );
    const scope = this.cursors.scope("homebrew", platform, text, kind, genre);
    const page = this.cursors.page(entries, LanternApp.homebrewKey, {
      size: this.#size(request),
      cursor: request.query.get("cursor"),
      scope,
    });
    return jsonResponse(request, {
      schema: SCHEMA,
      items: page.items.map(LanternApp.listed),
      total: page.total,
      next: page.next,
    });
  }

  async hHomebrewEntry(request: ServerRequest, account: Account, args: string[]): Promise<ServerResponse> {
    const platform = platformOf(request);
    const id = args[0] ?? "";
    if (!HOMEBREW_ID.test(id)) throw notFound("No such homebrew.");
    const found = (await this.library.homebrew(request.languages)).filter(
      (e) =>
        e.id === id &&
        (platform === undefined || e.platform === platform) &&
        !ratings.hidden(e.ratings, account.ratingCap),
    );
    const entry: Homebrew = one(found, "homebrew");
    return jsonResponse(request, { schema: SCHEMA, ...entry });
  }

  async hHomebrewUpdates(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const doc = parse(models.readHomebrewUpdatesRequest, readDocument(request), "installed is a list of {id, build}");
    const platform = platformOf(request, true);
    if (doc.installed.some((i) => !HOMEBREW_ID.test(i.id) || i.build < 0))
      throw badRequest("installed is a list of {id, build}.");
    const builds = new Map<string, number>();
    for (const i of doc.installed) builds.set(i.id, Math.max(builds.get(i.id) ?? -1, i.build));
    const newer = (await this.library.homebrew(request.languages)).filter(
      (e) =>
        e.platform === platform &&
        builds.has(e.id) &&
        e.build > (builds.get(e.id) ?? 0) &&
        !ratings.hidden(e.ratings, account.ratingCap),
    );
    const scope = this.cursors.scope("updates", platform, [...builds.entries()].sort());
    const page = this.cursors.page(newer, LanternApp.homebrewKey, {
      size: this.#size(request),
      cursor: request.query.get("cursor"),
      scope,
    });
    return jsonResponse(request, {
      schema: SCHEMA,
      items: page.items.map(LanternApp.listed),
      total: page.total,
      next: page.next,
    });
  }

  // Cheats (SPEC.md § 10).

  async hCheats(request: ServerRequest, account: Account): Promise<ServerResponse> {
    const platform = platformOf(request);
    const titleId = request.query.get("title_id");
    const buildId = request.query.get("build_id");
    if (titleId !== undefined && !CORE_ID.test(titleId))
      throw badRequest("title_id is 1 to 128 letters, digits, '.', '_' and '-'.");
    if (buildId !== undefined && !BUILD_ID.test(buildId))
      throw badRequest("build_id is 1 to 64 letters, digits, '.', '_' and '-'.");
    const hide = await this.hides(account);
    const key = (c: CheatSet): string =>
      [c.platform, c.title_id, c.build_id ?? "", fold(c.source), c.id].join("\u0000");
    const sets = (await this.library.cheats())
      .filter(
        (c) =>
          !hide(c.platform, c.title_id) &&
          (platform === undefined || c.platform === platform) &&
          (titleId === undefined || c.title_id === titleId) &&
          (buildId === undefined || c.build_id === buildId),
      )
      .sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
    return jsonResponse(request, { schema: SCHEMA, cheats: sets });
  }

  async hCheatText(request: ServerRequest, account: Account, args: string[]): Promise<ServerResponse> {
    const platform = platformOf(request);
    const hide = await this.hides(account);
    const found = (await this.library.cheats()).filter(
      (c) => c.id === args[0] && (platform === undefined || c.platform === platform) && !hide(c.platform, c.title_id),
    );
    const file = found.length > 0 ? await this.library.cheatFile(args[0] ?? "") : undefined;
    if (file === undefined) throw notFound("No such cheat set.");
    return fileResponse(request, file);
  }

  // Pairing (SPEC.md § 5.2, § 5.4, § 5.5).

  verifyUrl(request: ServerRequest): string {
    if (this.verify.includes("://")) return this.verify;
    try {
      return request.origin(this.scheme) + this.verify;
    } catch {
      throw badRequest("No Host this server can read.");
    }
  }

  async hPairStart(request: ServerRequest): Promise<ServerResponse> {
    const desk = this.desk;
    const accounts = this.accounts;
    if (desk === undefined || accounts === undefined) throw notFound("This server does not offer it.");
    const doc = parse(
      models.readPairingRequest,
      readDocument(request),
      "A pairing request is {schema, device, scopes, key?, invitation?}",
    );
    const device = doc.device.trim();
    if (!device || printable(device, NAME) !== device) {
      throw badRequest("device is the device's name, 512 bytes at most, without control characters.");
    }
    const known = orderedScopes(doc.scopes);
    if (known.length === 0) throw badRequest(`scopes names none of ${SCOPES.join(", ")}.`);
    let key: Uint8Array | undefined;
    if (doc.key !== undefined) key = deviceKey(doc.key.alg, doc.key.public_key);
    else if (this.boundOnly) {
      throw new HttpProblem(
        400,
        "key_required",
        "This server binds every token to a device key: send one (key: {alg: ed25519, public_key}).",
        {
          title: "Device key required",
        },
      );
    }
    const wait = this.pairLimiter.hit(request.remote);
    if (wait > 0) throw slowDown(wait, "Too many pairing requests from this address.");
    let invitation: Invitation | undefined;
    if (doc.invitation !== undefined) {
      const attempts = this.attempts.wait(request.remote);
      if (attempts > 0) throw slowDown(attempts, "Too many attempts at invitations from this address.");
      invitation = await accounts.redeem(doc.invitation);
      if (invitation === undefined) {
        this.attempts.record(request.remote);
        throw new HttpProblem(410, "gone", "This invitation is unknown, expired, revoked or used up.", {
          title: "Invitation gone",
        });
      }
    }
    const entry = desk.start(device, known, key);
    if (invitation !== undefined) {
      // Approved at once, as the invitation says (SPEC.md § 5.5).
      await desk.approve(entry, invitation.user, invitation.scopes, invitation.ratingCap, invitation.id);
    } else {
      const data: Record<string, unknown> = { id: entry.id, code: entry.code, device: entry.device };
      if (entry.key !== undefined) data["key"] = sig.shortFingerprint(entry.key);
      data["expires"] = entry.expires;
      await this.emit("pairing", data);
    }
    const verify = this.verifyUrl(request);
    const response = jsonResponse(request, {
      schema: SCHEMA,
      code: entry.code,
      verify,
      verify_complete: `${verify}${verify.includes("?") ? "&" : "?"}code=${entry.code}`,
      poll: `${this.base}/v1/pairing/${entry.poll}`,
      interval: entry.interval,
      expires: desk.expires,
    });
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  async hPairPoll(request: ServerRequest, _account: Account, args: string[]): Promise<ServerResponse> {
    const desk = this.desk;
    if (desk === undefined) throw notFound("This server does not offer it.");
    const poll = args[0] ?? "";
    const entry = desk.peek(poll);
    if (entry?.key !== undefined) await this.verifySignature(request, entry.key, false); // a pairing with a key polls signed by it
    const doc = desk.poll(poll);
    if (doc === undefined) {
      const waiting = emptyResponse(request, 202);
      waiting.headers.set("Cache-Control", "no-store");
      return waiting;
    }
    const response = jsonResponse(request, doc);
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  // Administration (SPEC.md § 5.7).

  #adminPage(
    request: ServerRequest,
    docs: Record<string, unknown>[],
    scope: string,
    key: (d: Record<string, unknown>) => SortKey,
  ): ServerResponse {
    const page = this.cursors.page(docs, key, {
      size: this.#size(request),
      cursor: request.query.get("cursor"),
      scope,
    });
    return jsonResponse(request, { schema: SCHEMA, items: page.items, total: page.total, next: page.next });
  }

  async #userDoc(name: string): Promise<Record<string, unknown>> {
    const accounts = this.accounts as Accounts;
    const user = await accounts.user(name);
    if (user === undefined) throw notFound("No such account.");
    return {
      name: user.name,
      state: user.state === "frozen" ? "frozen" : "active",
      scopes: [...user.scopes],
      devices: (await accounts.devices(user.name)).length,
      created: user.created,
    };
  }

  static scopes(values: readonly string[] | undefined, what = "scopes"): string[] {
    if (
      values === undefined ||
      values.some((v) => !(SCOPES as readonly string[]).includes(v)) ||
      new Set(values).size !== values.length
    ) {
      throw badRequest(`${what} is a list of scopes: ${SCOPES.join(", ")}.`);
    }
    return orderedScopes(values);
  }

  async hAdminUsers(request: ServerRequest): Promise<ServerResponse> {
    const accounts = this.accounts as Accounts;
    if (request.method !== "POST") {
      const docs = await Promise.all((await accounts.users()).map((u) => this.#userDoc(u.name)));
      return this.#adminPage(request, docs, this.cursors.scope("admin-users"), (d) => [String(d["name"])]);
    }
    const raw = readDocument(request);
    if ("password" in raw) throw badRequest("An account made here has no password (SPEC.md § 5.7).");
    const doc = parse(models.readAdminUserCreate, raw, "An account is {schema, name, scopes, state?}");
    const state = doc.state ?? "active";
    if (!ACCOUNT_NAME.test(doc.name) || (state !== "active" && state !== "frozen")) {
      throw badRequest("name is 1 to 64 letters, digits, '.', '_' and '-'; state is active or frozen.");
    }
    try {
      await accounts.createUser(doc.name, LanternApp.scopes(doc.scopes), state);
    } catch (e) {
      if (e instanceof AccountError) throw new HttpProblem(e.status, e.code, e.detail);
      throw e;
    }
    return jsonResponse(request, { schema: SCHEMA, ...(await this.#userDoc(doc.name)) }, 201);
  }

  async hAdminUser(request: ServerRequest, account: Account, args: string[]): Promise<ServerResponse> {
    const accounts = this.accounts as Accounts;
    if (request.method === "DELETE") return this.#deleteUser(request, account, args[0] ?? "");
    const doc = parse(models.readAdminUserUpdate, readDocument(request), "A change is {schema, state?, scopes?}");
    if (doc.state === undefined && doc.scopes === undefined)
      throw badRequest("Give state (active or frozen), scopes, or both.");
    if (doc.state !== undefined && doc.state !== "active" && doc.state !== "frozen")
      throw badRequest("state is active or frozen.");
    const change: { state?: "active" | "frozen"; scopes?: string[] } = {};
    if (doc.state !== undefined) change.state = doc.state as "active" | "frozen";
    if (doc.scopes !== undefined) change.scopes = LanternApp.scopes(doc.scopes);
    const name = args[0] ?? "";
    try {
      await accounts.updateUser(name, change);
    } catch (e) {
      if (e instanceof AccountError) throw new HttpProblem(e.status, e.code, e.detail);
      throw e;
    }
    this.hub?.wake(); // a frozen account's streams end (SPEC.md § 18.1)
    return jsonResponse(request, { schema: SCHEMA, ...(await this.#userDoc(name)) });
  }

  /**
   * Deletes an account (SPEC.md § 5.7): `confirm` repeats its name (400
   * otherwise), never the caller's own (409); at once and whole, its devices,
   * invitations and sync data with it.
   */
  async #deleteUser(request: ServerRequest, account: Account, name: string): Promise<ServerResponse> {
    const accounts = this.accounts as Accounts;
    if (request.query.get("confirm") !== name)
      throw badRequest("confirm repeats the account's name: ?confirm=<name> (SPEC.md § 5.7).");
    if (account.name === name) throw new HttpProblem(409, "conflict", "An account cannot delete itself.");
    if ((await accounts.user(name)) === undefined) throw notFound("No such account.");
    if (accounts.deleteUser === undefined)
      throw new HttpProblem(
        409,
        "conflict",
        "This server's accounts are not deleted here: remove it where it is defined.",
      );
    try {
      if (!(await accounts.deleteUser(name))) throw notFound("No such account.");
    } catch (e) {
      if (e instanceof AccountError) throw new HttpProblem(e.status, e.code, e.detail);
      throw e;
    }
    await this.syncStore?.forget(name);
    this.hub?.wake(); // its streams end (SPEC.md § 18.1)
    return emptyResponse(request);
  }

  /** A device as the administration API shows it: never its token, nor the token's hash. */
  static deviceDoc(device: Device): Record<string, unknown> {
    const doc: Record<string, unknown> = {
      id: device.id,
      user: device.user,
      device: device.device,
      scopes: [...device.scopes],
      created: device.created,
      bound: device.key !== undefined,
    };
    if (device.key !== undefined) doc["key"] = sig.shortFingerprint(device.key);
    if (device.ratingCap !== undefined) doc["rating_cap"] = device.ratingCap;
    if (device.invitation !== undefined) doc["invitation"] = device.invitation;
    if (device.expires !== undefined) doc["expires"] = device.expires;
    return doc;
  }

  async hAdminDevices(request: ServerRequest): Promise<ServerResponse> {
    const accounts = this.accounts as Accounts;
    const user = request.query.get("user");
    const docs = (await accounts.devices(user)).map(LanternApp.deviceDoc);
    return this.#adminPage(request, docs, this.cursors.scope("admin-devices", user), (d) => [
      String(d["user"]),
      String(d["created"]),
      String(d["id"]),
    ]);
  }

  async hAdminDevice(request: ServerRequest, _account: Account, args: string[]): Promise<ServerResponse> {
    if (!(await (this.accounts as Accounts).revoke(args[0] ?? ""))) throw notFound("No such device.");
    this.hub?.wake(); // its streams end (SPEC.md § 18.1)
    return emptyResponse(request);
  }

  async hAdminPairings(request: ServerRequest): Promise<ServerResponse> {
    const desk = this.desk as PairingDesk;
    const docs = desk.waiting().map((e) => {
      const doc: Record<string, unknown> = {
        id: e.id,
        code: e.code,
        device: e.device,
        scopes: [...e.scopes],
        created: e.created,
        expires: e.expires,
      };
      if (e.key !== undefined) doc["key"] = sig.shortFingerprint(e.key);
      return doc;
    });
    return this.#adminPage(request, docs, this.cursors.scope("admin-pairings"), (d) => [
      String(d["created"]),
      String(d["id"]),
    ]);
  }

  async hAdminPairing(request: ServerRequest, account: Account, args: string[]): Promise<ServerResponse> {
    const desk = this.desk as PairingDesk;
    const accounts = this.accounts as Accounts;
    const doc = parse(
      models.readAdminPairingDecision,
      readDocument(request),
      "A decision is {schema, decision, user?, scopes?, rating_cap?}",
    );
    const entry = desk.byId(args[0] ?? "");
    if (entry === undefined) throw notFound("No such pairing waiting: approved, refused or expired.");
    if (doc.decision === "refuse") {
      desk.refuse(entry);
      return emptyResponse(request);
    }
    if (doc.decision !== "approve") throw badRequest("decision is approve or refuse.");
    const name = doc.user ?? account.name;
    if (name === undefined || (await accounts.user(name)) === undefined)
      throw badRequest(`No account named ${String(name).slice(0, 64)}.`);
    const scopes = doc.scopes === undefined ? undefined : LanternApp.scopes(doc.scopes);
    await desk.approve(entry, name, scopes, cap(doc.rating_cap));
    return emptyResponse(request);
  }

  invitationDoc(request: ServerRequest, inv: Invitation): Record<string, unknown> {
    const verify = this.verifyUrl(request);
    const query = `invitation=${inv.code}${this.spki !== undefined ? `&spki=${this.spki}` : ""}`;
    const doc: Record<string, unknown> = {
      id: inv.id,
      code: inv.code,
      link: `${verify}${verify.includes("?") ? "&" : "?"}${query}`,
      user: inv.user,
      scopes: [...inv.scopes],
      expires: inv.expires,
      devices: inv.devices,
      used: inv.used,
      created: inv.created,
    };
    if (inv.ratingCap !== undefined) doc["rating_cap"] = inv.ratingCap;
    if (inv.note !== undefined) doc["note"] = inv.note;
    return doc;
  }

  async hAdminInvitations(request: ServerRequest): Promise<ServerResponse> {
    const accounts = this.accounts as Accounts;
    if (request.method !== "POST") {
      const docs = (await accounts.invitations()).map((i) => this.invitationDoc(request, i));
      return this.#adminPage(request, docs, this.cursors.scope("admin-invitations"), (d) => [
        String(d["created"]),
        String(d["id"]),
      ]);
    }
    const doc = parse(
      models.readInvitationCreate,
      readDocument(request),
      "An invitation is {schema, user, scopes, expires, devices, …}",
    );
    const user = await accounts.user(doc.user);
    if (user === undefined) throw badRequest("user is the account the devices join, which exists.");
    const scopes = LanternApp.scopes(doc.scopes);
    if (scopes.length === 0 || scopes.some((s) => !user.scopes.includes(s)))
      throw badRequest("scopes are some of the account's own (SPEC.md § 5.5).");
    const expires = parseTime(doc.expires);
    const now = Date.now();
    if (expires === undefined || !(now < expires && expires <= now + INVITATION_DAYS * 86400000)) {
      throw badRequest(`expires is an RFC 3339 time in the next ${INVITATION_DAYS} days (SPEC.md § 5.5).`);
    }
    const devices = doc.devices ?? 1;
    if (!Number.isInteger(devices) || devices < 1 || devices > 100)
      throw badRequest("devices is how many devices may redeem it, 1 to 100.");
    if (doc.note !== undefined && (printable(doc.note, NOTE) !== doc.note || doc.note.includes("\n"))) {
      throw badRequest("note: 120 bytes at most, without control characters.");
    }
    if ((await accounts.invitations()).length >= INVITATIONS_LIMIT)
      throw slowDown(3600, `At most ${INVITATIONS_LIMIT} invitations at once.`);
    const options: { ratingCap?: RatingCap; note?: string } = {};
    const capOf = cap(doc.rating_cap);
    if (capOf !== undefined) options.ratingCap = capOf;
    if (doc.note !== undefined) options.note = doc.note;
    const inv = await accounts.createInvitation(user.name, scopes, utc(new Date(expires)), devices, options);
    return jsonResponse(request, { schema: SCHEMA, ...this.invitationDoc(request, inv) }, 201);
  }

  async hAdminInvitation(request: ServerRequest, _account: Account, args: string[]): Promise<ServerResponse> {
    if (!(await (this.accounts as Accounts).revokeInvitation(args[0] ?? ""))) throw notFound("No such invitation.");
    return emptyResponse(request);
  }
}
