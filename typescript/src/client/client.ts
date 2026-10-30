/**
 * The client of one Lantern server: every route of draft 0.5, in a browser and
 * in Node, over a Transport (fetch() by default).
 *
 *     const client = new LanternClient("https://shelf.example.org/", { platform: "switch", userAgent: "MyShelf/1.0" });
 *     const hello = await client.handshake();
 *     for await (const app of client.iterApps({ type: "base" })) console.log(app.name);
 *
 * Errors: a server's error answer throws the ProblemError of its status
 * (NotFound, Gone…); a document of a newer schema throws NewerSchema (treat it
 * as absent); a malformed one, DocumentError; a download that is not what its
 * document says, IntegrityError.
 */

import { DocumentError, LanternError, SCHEMA } from "../base.ts";
import { utf8Length } from "../bytes.ts";
import { contentDigest } from "../digest.ts";
import { schemaOf } from "../documents.ts";
import { type EncryptedBackup, encryptionHeader } from "../e2e.ts";
import {
  Conflict,
  Gone,
  InsecureTransport,
  IntegrityError,
  NewerSchema,
  problemError,
  SignatureExpired,
  SignatureReplayed,
  SlowDown,
  UnexpectedResponse,
  Unsupported,
} from "../errors.ts";
import { EVENT_TYPES, type ServerEvent } from "../events.ts";
import type {
  AdminDevice,
  AdminDevices,
  AdminPairing,
  AdminPairings,
  AdminUser,
  AdminUsers,
  App,
  AppsPage,
  Changes,
  CheatSet,
  CheatSets,
  Encryption,
  Grant,
  Handshake,
  Homebrew,
  HomebrewPage,
  Invitation,
  Invitations,
  Package,
  PairingCode,
  PairingToken,
  RatingCap,
  Save,
  Saves,
  Sections,
  Sync,
  SyncCollection,
  SyncItem,
  Title,
  TitleChanges,
  TitleRequest,
  TitleRequests,
  Titles,
  Upload,
} from "../generated/models.ts";
import * as models from "../generated/models.ts";
import { JSON_TYPE, mediaType, origin, PLATFORM_HEADER, plainHttpAllowed, quote } from "../http.ts";
import { CHEAT_SET, JSON_DOCUMENT, loadJson, NOTE, PROFILE, printable, TITLES_AT_ONCE } from "../limits.ts";
import type { Check } from "../model.ts";
import { blobUrl, GRANT_HEADER, type GrantPayload, grantKey, type Peer, usableMirrors, verifyGrant } from "../peers.ts";
import type { ServerRecord, ServerStore } from "../pinning.ts";
import { type Hasher, type HasherFactory, sha256Factory } from "../sha256.ts";
import { DeviceKey, SKEW } from "../signatures.ts";
import {
  COLLECTIONS,
  ConsentRequired,
  GenerationChanged,
  readSyncState,
  type SyncState,
  ifMatch as syncIfMatch,
  WRITE_LIMIT,
} from "../sync.ts";
import { BUILD_ID, CORE_ID, FAMILIES, HOMEBREW_ID, isPlatform } from "../vocabulary.ts";
import { type DownloadSink, MemorySink, type UploadSource, Verifier } from "./download.ts";
import { EventStream, type EventStreamOptions } from "./events.ts";
import { checkPairingCode, invitationLink, Pairing } from "./pairing.ts";
import {
  BearerToken,
  type Credentials,
  DeviceSigner,
  FetchTransport,
  Pipeline,
  type RequestSigner,
  readBody,
  type Transport,
  type TransportRequest,
} from "./transport.ts";

export const VERSION = "0.1.0";
const USER_AGENT = `LanternTypeScript/${VERSION}`;
const ERROR_BODY = 1 << 16;
const MISSING_WANTS = ["base", "update", "dlc"] as const;
/** The `schema` this library reads, per family (sent as Accept-Schema, SPEC.md § 3.2). */
const ACCEPT_SCHEMA = FAMILIES.map((f) => `${f}=${SCHEMA}`).join(", ");

/** A route or schema a server said is going away (SPEC.md § 3.4). */
export interface Deprecation {
  what: string;
  /** `Deprecation`: a Structured Fields date such as `@1793318400`. */
  since: string;
  sunset: string | undefined;
  link: string | undefined;
}

/** Makes the transport of a client that asked to pin a key, or to read one no CA vouches for. */
export type TransportFactory = (options: { pin?: string; verify: boolean }) => Transport;

export interface ClientOptions {
  /** `<Name>/<version>` (SPEC.md § 2); a browser sends its own whatever this says. */
  userAgent?: string;
  /** Sent as Lantern-Platform on every call (SPEC.md § 4.3). */
  platform?: string;
  /** `Authorization: Bearer`, sent to the server's origin only. */
  token?: string;
  /** The device key the token is bound to: every request is then signed (SPEC.md § 5.4). */
  key?: DeviceKey;
  credentials?: Credentials;
  signer?: RequestSigner;
  transport?: Transport;
  /** A LAN server's key (SHA-256 of its SPKI, hex), pinned: needs a transport that can (NodeTransport). */
  pin?: string;
  /** false: talk to a server no CA vouches for, reading its key's fingerprint to pin it (needs NodeTransport). */
  verify?: boolean;
  /** Makes the transport for `pin` and `verify`; the `node` entry's client gives NodeTransport. */
  transportFactory?: TransportFactory;
  acceptLanguage?: string;
  /** The base path, when the handshake should not decide it. */
  base?: string;
  /** Seconds to wait for an answer, then between two chunks of its body. */
  timeout?: number;
  /** The SHA-256 downloads and uploads are hashed with (the `node` entry plugs node:crypto in). */
  hash?: HasherFactory;
  /** Make device keys extractable at pairing, so that a store can keep their seed (Node does; a browser keeps the CryptoKey). */
  extractableKeys?: boolean;
  /** Called once per deprecation a server announces (SPEC.md § 3.4); console.warn by default. */
  onDeprecation?: (deprecation: Deprecation) => void;
  /**
   * The transport of mirrors and peers (SPEC.md § 19), never the server's
   * pinned one: FetchTransport by default; the `node` entry's gives a
   * NodeTransport, which also reaches a peer's HTTPS that nobody pins.
   */
  elsewhere?: (options: { verify: boolean }) => Transport;
}

/** One request below <base>/v1 (or the handshake, or an address a document gave), and how its answer reads. */
interface Call<T> {
  method: string;
  what: string;
  path?: string;
  url?: string;
  wellKnown?: boolean;
  query?: [string, string][];
  body?: object;
  raw?: Uint8Array;
  headers?: Record<string, string>;
  read?: Check<T>;
  statuses?: readonly number[];
  emptyStatuses?: readonly number[];
  empty?: (status: number, headers: Headers) => T;
  anonymous?: boolean;
  signer?: RequestSigner;
  /** Seconds to wait for the answer, when not the client's (a long poll). */
  timeout?: number;
}

export interface ListOptions {
  platform?: string;
  pageSize?: number;
  cursor?: string;
}

export interface AppsOptions extends ListOptions {
  type?: string;
  titleId?: string;
  q?: string;
  sort?: "name" | "added" | "release";
}

export interface HomebrewOptions extends ListOptions {
  q?: string;
  kind?: string;
  genre?: string;
}

export interface DownloadOptions {
  sha256: string;
  size: number;
  /** Go on from what the sink holds (true by default). */
  resume?: boolean;
  progress?: (done: number, total: number) => void;
}

export interface SaveOptions {
  /** A backup encrypted on the device (SPEC.md § 9.4): its scheme and key id, sent in clear. */
  encryption?: Encryption;
  kind?: string;
  slot?: string;
  gameVersionCode?: number;
  profile?: string;
  note?: string;
  platform?: string;
}

/** Where else a file may come from (SPEC.md § 19): its mirrors, peers that hold it; the server last. */
export interface SourceOptions {
  /** Try the file's mirrors first (false by default). */
  mirrors?: boolean;
  /** Peers to ask first, with a grant of the server (at most 2 are read from). */
  peers?: readonly Peer[];
  /** Told where the file came from, and why each source before it was passed by. */
  onSource?: (source: "peer" | "mirror" | "server", url: string, passed: { url: string; error: unknown }[]) => void;
}

export interface UploadOptions extends SaveOptions {
  /** The address of an upload opened before: it goes on from where HEAD says. */
  resume?: string;
  progress?: (done: number, total: number) => void;
}

function platformQuery(platform: string | undefined): [string, string][] {
  if (platform === undefined) return [];
  if (!isPlatform(platform)) throw new RangeError(`${platform} is not a platform's name`);
  return [["platform", platform]];
}

function listing(
  pageSize: number | undefined,
  cursor: string | undefined,
  filters: Record<string, string | undefined> = {},
): [string, string][] {
  const out: [string, string][] = [];
  for (const [k, v] of Object.entries(filters)) if (v !== undefined) out.push([k, v]);
  if (pageSize !== undefined) {
    if (!Number.isInteger(pageSize) || pageSize < 1) throw new RangeError("pageSize is 1 or more");
    out.push(["page_size", String(pageSize)]);
  }
  if (cursor !== undefined) out.push(["cursor", cursor]);
  return out;
}

function segment(value: string): string {
  if (!value || value.length > 128) throw new RangeError("an id is 1 to 128 characters");
  return quote(value);
}

/** Whether `text` has a control character (C0, or DEL). */
export function hasControl(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 32 || c === 127) return true;
  }
  return false;
}

function headerText(value: string, limit: number, what: string): string {
  if (utf8Length(value) > limit || hasControl(value)) {
    throw new RangeError(`${what}: at most ${limit} bytes, without control characters`);
  }
  return quote(value);
}

function asciiWord(value: string, what: string): string {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(value)) throw new RangeError(`${what}: 1 to 64 letters, digits, '.', '_' and '-'`);
  return value;
}

function uploadOffset(status: number, headers: Headers): number {
  const value = headers.get("Upload-Offset")?.trim() ?? "";
  if (!/^\d{1,15}$/.test(value)) throw new UnexpectedResponse(`status ${status} without an Upload-Offset`, status);
  return Number(value);
}

function reject(): never {
  throw new UnexpectedResponse("a document where the protocol gives none");
}

/** The apps that fit in `free` bytes, and those that do not (SPEC.md § 6.3): each by its `installed_size`, or its `size`. */
export function whatFits(apps: Iterable<App>, free: number): [App[], App[]] {
  const fit: App[] = [];
  const tooBig: App[] = [];
  for (const app of apps) ((app.installed_size ?? app.size) <= free ? fit : tooBig).push(app);
  return [fit, tooBig];
}

export class LanternClient {
  readonly root: string;
  readonly userAgent: string;
  readonly transport: Transport;
  readonly timeout: number;
  readonly hash: HasherFactory;
  platform: string | undefined;
  acceptLanguage: string | undefined;
  base: string | undefined;
  /** The last handshake read. */
  hello: Handshake | undefined;
  /** Seconds to add to this device's clock to read the server's (SPEC.md § 5.4, Annex B.9). */
  clockOffset = 0;
  /** The fingerprint of the key of the last TLS connection, when the transport said. */
  lastSpki: string | undefined;
  /** What the server said is deprecated (SPEC.md § 3.4), once each. */
  readonly deprecations: Deprecation[] = [];
  /** The address of the last upload left unfinished, to resume (uploadSave(…, { resume })). */
  lastUpload: string | undefined;
  readonly pipeline: Pipeline;
  readonly #elsewhere: (options: { verify: boolean }) => Transport;
  #sync: SyncState | undefined;
  readonly #extractable: boolean;
  readonly #onDeprecation: (d: Deprecation) => void;
  #key: DeviceKey | undefined;

  constructor(url: string, options: ClientOptions = {}) {
    const full = url.includes("://") ? url : `https://${url}`;
    if (!plainHttpAllowed(full))
      throw new InsecureTransport(`${full}: plain HTTP is allowed only to a loopback address (SPEC.md § 2)`);
    if (options.token !== undefined && options.credentials !== undefined)
      throw new TypeError("token or credentials, not both");
    if (options.key !== undefined && options.signer !== undefined) throw new TypeError("key or signer, not both");
    if (options.transport !== undefined && (options.pin !== undefined || options.verify === false)) {
      throw new TypeError("pin and verify make the default transport: set them on the transport given");
    }
    const parsed = new URL(full);
    this.root = `${parsed.protocol}//${parsed.host}`;
    const userAgent = options.userAgent ?? USER_AGENT;
    const [name = ""] = userAgent.split("/");
    if (!userAgent.includes("/") || name === "" || name.includes(" "))
      throw new RangeError("User-Agent is <Name>/<version> (SPEC.md § 2)");
    this.userAgent = userAgent;
    if (options.platform !== undefined && !isPlatform(options.platform))
      throw new RangeError(`${options.platform} is not a platform's name`);
    this.platform = options.platform;
    this.acceptLanguage = options.acceptLanguage;
    this.base = options.base !== undefined ? LanternClient.checkBase(options.base) : undefined;
    this.timeout = options.timeout ?? 30;
    this.hash = options.hash ?? sha256Factory;
    this.#extractable = options.extractableKeys ?? false;
    this.#onDeprecation =
      options.onDeprecation ??
      ((d) =>
        console.warn(
          `lantern: ${d.what} is deprecated since ${d.since}, sunset ${d.sunset ?? "unknown"} ${d.link ?? ""}`,
        ));
    if (options.transport !== undefined) this.transport = options.transport;
    else if (options.pin !== undefined || options.verify === false) {
      if (options.transportFactory === undefined) {
        throw new Unsupported(
          "pinning a key needs a transport that can: NodeTransport (lantern-protocol/node); a browser trusts its CA store alone",
        );
      }
      this.transport = options.transportFactory({
        ...(options.pin !== undefined ? { pin: options.pin } : {}),
        verify: options.verify ?? true,
      });
    } else this.transport = options.transportFactory?.({ verify: true }) ?? new FetchTransport();
    this.#elsewhere = options.elsewhere ?? (() => new FetchTransport());
    const credentials = options.token !== undefined ? new BearerToken(options.token) : options.credentials;
    this.pipeline = new Pipeline(origin(full), credentials, options.signer);
    if (options.key !== undefined) this.setToken(options.token, options.key);
  }

  /**
   * A client of a server the device paired with: its token, signed with its
   * device key when bound, over its pinned key when no CA vouches for it
   * (SPEC.md § 5.3, § 5.4). `key` is the device key when the record does not
   * hold its seed (a CryptoKey kept in IndexedDB).
   */
  static async paired<C extends LanternClient>(
    this: new (
      url: string,
      options?: ClientOptions,
    ) => C,
    record: ServerRecord,
    options: ClientOptions = {},
  ): Promise<C> {
    const key = options.key ?? (record.key !== undefined ? await DeviceKey.fromBase64(record.key) : undefined);
    const extra: ClientOptions = {};
    if (record.spki !== undefined && options.transport === undefined) extra.pin = record.spki;
    if (key !== undefined) extra.key = key;
    return new this(record.url, { ...options, ...extra, token: record.token });
  }

  static checkBase(base: string): string {
    if (!base.startsWith("/") || base.startsWith("//") || base.includes("?") || base.includes("#")) {
      throw new DocumentError(`base ${JSON.stringify(base.slice(0, 80))} is not a path on the server's origin`);
    }
    return base.replace(/\/+$/, "");
  }

  /** Set or clear the token of later calls, and the device key it is bound to. */
  setToken(token: string | undefined, key?: DeviceKey): void {
    if (token !== undefined) this.pipeline.credentials = new BearerToken(token);
    else if (key === undefined) this.pipeline.credentials = undefined;
    this.#key = key;
    this.pipeline.signer = key !== undefined ? new DeviceSigner(key, () => this.now()) : undefined;
  }

  /** The device key requests are signed with, if any. */
  get key(): DeviceKey | undefined {
    return this.#key;
  }

  /** The rating cap the token carries, as the last handshake showed it (SPEC.md § 5.6). */
  get ratingCap(): RatingCap | undefined {
    return this.hello?.account.rating_cap;
  }

  async close(): Promise<void> {
    await this.transport.close?.();
  }

  /** The time to sign with: this device's clock, corrected by its offset to the server's. */
  now(): number {
    return Date.now() / 1000 + this.clockOffset;
  }

  // Plumbing.

  /** An absolute URL for a path or URL a document gave (`file`, `poll`…), on the server's origin unless it names another. */
  url(path: string): string {
    return new URL(path, `${this.root}/`).toString();
  }

  /** An address a document gave, made absolute: it must be on the server's origin. */
  onOrigin(address: string, what: string): string {
    const url = this.url(address);
    let same = false;
    try {
      const o = origin(url);
      same =
        o.scheme === this.pipeline.server.scheme &&
        o.host === this.pipeline.server.host &&
        o.port === this.pipeline.server.port;
    } catch {
      same = false;
    }
    if (!same)
      throw new UnexpectedResponse(`${what}: ${JSON.stringify(address.slice(0, 100))} is not on the server's origin`);
    return url;
  }

  v1(path: string): string {
    if (this.base === undefined) throw new LanternError("no base yet: read the handshake first");
    return `${this.root}${this.base}/v1${path}`;
  }

  async #ensureBase(): Promise<void> {
    if (this.base === undefined) await this.handshake();
  }

  /** A request, its headers set, then its credentials and signature (for the server's origin only). */
  async prepare(
    method: string,
    url: string,
    options: {
      body?: object;
      raw?: Uint8Array;
      headers?: Record<string, string>;
      anonymous?: boolean;
      signer?: RequestSigner;
    } = {},
  ): Promise<TransportRequest> {
    if (!plainHttpAllowed(url))
      throw new InsecureTransport(`${url}: plain HTTP is allowed only to a loopback address (SPEC.md § 2)`);
    const h = new Headers({
      "User-Agent": this.userAgent,
      Accept: JSON_TYPE,
      "Accept-Encoding": "identity",
      "Accept-Schema": ACCEPT_SCHEMA,
    });
    if (this.acceptLanguage) h.set("Accept-Language", this.acceptLanguage);
    if (this.platform) h.set(PLATFORM_HEADER, this.platform);
    let raw = options.raw;
    if (options.body !== undefined) {
      raw = new TextEncoder().encode(JSON.stringify(options.body));
      h.set("Content-Type", JSON_TYPE);
    }
    for (const [k, v] of Object.entries(options.headers ?? {})) h.set(k, v);
    const request: TransportRequest = { method, url, headers: h, body: raw };
    if (options.anonymous || options.signer !== undefined) {
      const pipeline = new Pipeline(
        this.pipeline.server,
        options.anonymous ? undefined : this.pipeline.credentials,
        options.signer,
      );
      return pipeline.prepare(request);
    }
    return this.pipeline.prepare(request);
  }

  #note(what: string, headers: Headers): void {
    const since = headers.get("Deprecation");
    if (!since) return;
    const links = (headers.get("Link") ?? "").split(",").filter((p) => p.includes('rel="deprecation"'));
    const link = links[0]?.split(";")[0]?.trim().replace(/^<|>$/g, "");
    const sunset = headers.get("Sunset");
    const found: Deprecation = {
      what,
      since: printable(since, 64),
      sunset: sunset ? printable(sunset, 64) : undefined,
      link: link || undefined,
    };
    if (!this.deprecations.some((d) => d.what === found.what && d.since === found.since && d.sunset === found.sunset)) {
      this.deprecations.push(found);
      this.#onDeprecation(found);
    }
  }

  #serverOffset(headers: Headers): number | undefined {
    const value = headers.get("Date");
    if (!value) return undefined;
    const when = Date.parse(value);
    return Number.isNaN(when) ? undefined : when / 1000 - Date.now() / 1000;
  }

  /** Takes the offset of the server's Date after a 401 signature_expired (SPEC.md § 5.4); false when it changes nothing. */
  adjustClock(headers: Headers): boolean {
    const offset = this.#serverOffset(headers);
    if (offset === undefined || Math.abs(offset - this.clockOffset) < 1) return false;
    this.clockOffset = offset;
    return true;
  }

  skew(): number {
    return this.hello?.auth?.skew ?? SKEW;
  }

  #error(what: string, status: number, headers: Headers, body: Uint8Array): LanternError {
    if (status >= 300 && status < 400)
      return new UnexpectedResponse(`${what}: a redirect (${status}), which Lantern never sends`, status);
    if (status >= 400) return problemError(status, body, headers);
    return new UnexpectedResponse(`${what}: status ${status}`, status);
  }

  async #send<T>(call: Call<T>): Promise<T> {
    if (!call.wellKnown && call.url === undefined && this.base === undefined) await this.handshake();
    let url = call.url ?? (call.wellKnown ? `${this.root}/.well-known/lantern` : this.v1(call.path ?? ""));
    if (call.query !== undefined && call.query.length > 0) {
      url += `?${call.query.map(([k, v]) => `${quote(k)}=${quote(v).replaceAll("%2C", ",")}`).join("&")}`;
    }
    for (let attempt = 0; ; attempt++) {
      const options: Parameters<LanternClient["prepare"]>[2] = {};
      if (call.body !== undefined) options.body = call.body;
      if (call.raw !== undefined) options.raw = call.raw;
      if (call.headers !== undefined) options.headers = call.headers;
      if (call.anonymous) options.anonymous = true;
      if (call.signer !== undefined) options.signer = call.signer;
      const request = await this.prepare(call.method, url, options);
      const response = await this.transport.send(request, { timeout: call.timeout ?? this.timeout });
      this.lastSpki = response.spki;
      try {
        return await this.#finish(call, response.status, response.headers, async (ok) => {
          if (ok) return readBody(response, JSON_DOCUMENT, call.what);
          try {
            return await readBody(response, ERROR_BODY, call.what);
          } catch (e) {
            if (e instanceof DocumentError) return new Uint8Array();
            throw e;
          }
        });
      } catch (e) {
        if (!(e instanceof LanternError) || attempt > 0 || !request.headers.has("Signature")) throw e;
        if (e instanceof SignatureExpired) {
          if (!this.adjustClock(e.headers)) throw e;
        } else if (!(e instanceof SignatureReplayed)) throw e;
      } finally {
        await response.cancel();
      }
    }
  }

  async #finish<T>(
    call: Call<T>,
    status: number,
    headers: Headers,
    body: (ok: boolean) => Promise<Uint8Array>,
  ): Promise<T> {
    this.#note(call.what, headers);
    if ((call.statuses ?? [200]).includes(status)) {
      if (mediaType(headers.get("Content-Type")) !== JSON_TYPE) {
        throw new UnexpectedResponse(
          `${call.what}: Content-Type ${JSON.stringify(headers.get("Content-Type"))}, not JSON`,
          status,
        );
      }
      const doc = loadJson(await body(true), { where: call.what });
      const schema = schemaOf(doc, call.what);
      if (schema > SCHEMA) throw new NewerSchema(call.what, schema);
      if (call.read === undefined) return reject();
      const result = call.read(doc, call.what);
      if (call.wellKnown) {
        this.hello = this.#acceptHandshake(result as Handshake);
        this.#observeClock(headers);
      }
      return result;
    }
    if (call.emptyStatuses?.includes(status) && call.empty !== undefined) return call.empty(status, headers);
    throw this.#error(call.what, status, headers, await body(false));
  }

  #acceptHandshake(hello: Handshake): Handshake {
    if (!hello.versions.includes(1)) throw new LanternError("the server does not serve version 1 of the protocol");
    if (this.base === undefined) this.base = LanternClient.checkBase(hello.base);
    return hello;
  }

  /** After the handshake (Annex B.9): a clock off by half the server's window or more signs with the server's time. */
  #observeClock(headers: Headers): void {
    const offset = this.#serverOffset(headers);
    if (offset !== undefined && Math.abs(offset - this.clockOffset) >= this.skew() / 2) this.clockOffset = offset;
  }

  async *#pages<P, I>(
    call: Call<P>,
    items: (page: P) => I[],
    next: (page: P) => string | null | undefined,
  ): AsyncGenerator<I> {
    const seen = new Set<string>();
    let current = call;
    for (;;) {
      const page = await this.#send(current);
      yield* items(page);
      const following = next(page);
      if (following === null || following === undefined) return;
      if (seen.has(following)) throw new UnexpectedResponse(`${call.what}: the server gave the same cursor twice`);
      seen.add(following);
      current = {
        ...current,
        query: [...(current.query ?? []).filter(([k]) => k !== "cursor"), ["cursor", following]],
      };
    }
  }

  #needsPlatform(platform: string | undefined, what: string): void {
    if (platform === undefined && this.platform === undefined)
      throw new RangeError(`${what} needs a platform (SPEC.md § 4.3)`);
  }

  // The handshake (SPEC.md § 4.2).

  /** GET /.well-known/lantern: the server, the caller's account and what it is offered. */
  handshake(): Promise<Handshake> {
    return this.#send({ method: "GET", what: "handshake", wellKnown: true, read: models.readHandshake });
  }

  /** Whether the server offers `family` to this caller, in a schema this library reads (the handshake read first if need be). */
  async offers(family: string): Promise<boolean> {
    const hello = this.hello ?? (await this.handshake());
    const level = (hello.features as Record<string, unknown>)[family];
    return typeof level === "number" && level > 0 && level <= SCHEMA;
  }

  // Library (SPEC.md § 6).

  #apps(o: AppsOptions): Call<AppsPage> {
    if (o.sort !== undefined && !["name", "added", "release"].includes(o.sort))
      throw new RangeError("sort is name, added or release");
    const query = [
      ...platformQuery(o.platform),
      ...listing(o.pageSize, o.cursor, { type: o.type, title_id: o.titleId, q: o.q, sort: o.sort }),
    ];
    return { method: "GET", path: "/apps", what: "apps", query, read: models.readAppsPage };
  }

  /** One page of apps; `next` is the cursor of the following page. */
  apps(options: AppsOptions = {}): Promise<AppsPage> {
    return this.#send(this.#apps(options));
  }

  /** Every app, page by page. An expired cursor throws Gone: read the list again from its start. */
  iterApps(options: Omit<AppsOptions, "cursor"> = {}): AsyncGenerator<App> {
    return this.#pages(
      this.#apps(options),
      (p) => p.items,
      (p) => p.next,
    );
  }

  #missing(
    installed: Iterable<[string, number] | models.InstalledApp>,
    want: Iterable<string>,
    o: ListOptions,
  ): Call<AppsPage> {
    this.#needsPlatform(o.platform, "what is missing");
    const wants = [...new Set(want)];
    if (wants.length === 0 || wants.some((w) => !(MISSING_WANTS as readonly string[]).includes(w)))
      throw new RangeError("want lists base, update or dlc");
    const items = [...installed].map((i) => (Array.isArray(i) ? { app_id: i[0], version_code: i[1] } : i));
    return {
      method: "POST",
      path: "/apps/missing",
      what: "missing",
      query: [...platformQuery(o.platform), ...listing(o.pageSize, o.cursor)],
      body: { schema: SCHEMA, installed: items, want: wants },
      read: models.readAppsPage,
    };
  }

  /** What the device is missing (SPEC.md § 6.3): `installed` as [app_id, version_code]. */
  missing(
    installed: Iterable<[string, number] | models.InstalledApp>,
    want: Iterable<string> = ["update", "dlc"],
    options: ListOptions = {},
  ): Promise<AppsPage> {
    return this.#send(this.#missing(installed, want, options));
  }

  iterMissing(
    installed: Iterable<[string, number] | models.InstalledApp>,
    want: Iterable<string> = ["update", "dlc"],
    options: Omit<ListOptions, "cursor"> = {},
  ): AsyncGenerator<App> {
    return this.#pages(
      this.#missing([...installed], want, options),
      (p) => p.items,
      (p) => p.next,
    );
  }

  /** The apps added and removed since a token (none, and the current token, without one). A token too old throws Gone. */
  changes(since?: string, options: { platform?: string } = {}): Promise<Changes> {
    const query = [
      ...platformQuery(options.platform),
      ...(since !== undefined ? ([["since", since]] as [string, string][]) : []),
    ];
    return this.#send({ method: "GET", path: "/changes", what: "changes", query, read: models.readChanges });
  }

  sections(options: { platform?: string } = {}): Promise<Sections> {
    return this.#send({
      method: "GET",
      path: "/sections",
      what: "sections",
      query: platformQuery(options.platform),
      read: models.readSections,
    });
  }

  // Titles (SPEC.md § 7).

  title(titleId: string, options: { platform?: string } = {}): Promise<Title> {
    if (!CORE_ID.test(titleId) || titleId === "changes") throw new RangeError(`${titleId} is not a title id`);
    return this.#send({
      method: "GET",
      path: `/titles/${quote(titleId)}`,
      what: "title",
      query: platformQuery(options.platform),
      read: models.readTitle,
    });
  }

  /** Many titles at once: asked for by 100 at most per request, and put together. */
  async titles(ids: Iterable<string>, options: { platform?: string } = {}): Promise<Titles> {
    const unique = [...new Set(ids)];
    const bad = unique.find((i) => !CORE_ID.test(i));
    if (bad !== undefined) throw new RangeError(`${bad} is not a title id`);
    const out: Titles = { schema: SCHEMA, titles: [], unknown: [] };
    for (let i = 0; i < unique.length; i += TITLES_AT_ONCE) {
      const part = unique.slice(i, i + TITLES_AT_ONCE);
      const got = await this.#send<Titles>({
        method: "GET",
        path: "/titles",
        what: "titles",
        query: [["ids", part.join(",")], ...platformQuery(options.platform)],
        read: models.readTitles,
      });
      out.titles.push(...got.titles);
      out.unknown.push(...got.unknown);
    }
    return out;
  }

  titleChanges(since?: string, options: { platform?: string } = {}): Promise<TitleChanges> {
    const query = [
      ...platformQuery(options.platform),
      ...(since !== undefined ? ([["since", since]] as [string, string][]) : []),
    ];
    return this.#send({
      method: "GET",
      path: "/titles/changes",
      what: "title changes",
      query,
      read: models.readTitleChanges,
    });
  }

  /** Title changes until `more` is false; the last one's `since` is the next token. */
  async *iterTitleChanges(since?: string, options: { platform?: string } = {}): AsyncGenerator<TitleChanges> {
    let token = since;
    for (;;) {
      const changes = await this.titleChanges(token, options);
      yield changes;
      if (!changes.more || changes.since === token) return;
      token = changes.since;
    }
  }

  // Homebrew (SPEC.md § 8).

  #homebrew(o: HomebrewOptions): Call<HomebrewPage> {
    const query = [
      ...platformQuery(o.platform),
      ...listing(o.pageSize, o.cursor, { q: o.q, kind: o.kind, genre: o.genre }),
    ];
    return { method: "GET", path: "/homebrew", what: "homebrew", query, read: models.readHomebrewPage };
  }

  /** One page of entries, without their manifests (read an entry for them). */
  homebrew(options: HomebrewOptions = {}): Promise<HomebrewPage> {
    return this.#send(this.#homebrew(options));
  }

  iterHomebrew(options: Omit<HomebrewOptions, "cursor"> = {}): AsyncGenerator<Homebrew> {
    return this.#pages(
      this.#homebrew(options),
      (p) => p.items,
      (p) => p.next,
    );
  }

  /** An entry, with its manifests. */
  homebrewEntry(id: string, options: { platform?: string } = {}): Promise<Homebrew> {
    if (!HOMEBREW_ID.test(id)) throw new RangeError(`${id} is not a homebrew id`);
    return this.#send({
      method: "GET",
      path: `/homebrew/${quote(id)}`,
      what: "homebrew entry",
      query: platformQuery(options.platform),
      read: models.readHomebrew,
    });
  }

  #updates(installed: Iterable<[string, number] | models.InstalledHomebrew>, o: ListOptions): Call<HomebrewPage> {
    this.#needsPlatform(o.platform, "homebrew updates");
    const items = [...installed].map((i) => (Array.isArray(i) ? { id: i[0], build: i[1] } : i));
    return {
      method: "POST",
      path: "/homebrew/updates",
      what: "homebrew updates",
      query: [...platformQuery(o.platform), ...listing(o.pageSize, o.cursor)],
      body: { schema: SCHEMA, installed: items },
      read: models.readHomebrewPage,
    };
  }

  /** The entries newer than what is installed: `installed` as [id, build]. */
  homebrewUpdates(
    installed: Iterable<[string, number] | models.InstalledHomebrew>,
    options: ListOptions = {},
  ): Promise<HomebrewPage> {
    return this.#send(this.#updates(installed, options));
  }

  iterHomebrewUpdates(
    installed: Iterable<[string, number] | models.InstalledHomebrew>,
    options: Omit<ListOptions, "cursor"> = {},
  ): AsyncGenerator<Homebrew> {
    return this.#pages(
      this.#updates([...installed], options),
      (p) => p.items,
      (p) => p.next,
    );
  }

  // Cheats (SPEC.md § 10).

  cheats(options: { titleId?: string; buildId?: string; platform?: string } = {}): Promise<CheatSets> {
    const query = [
      ...platformQuery(options.platform),
      ...listing(undefined, undefined, { title_id: options.titleId, build_id: options.buildId }),
    ];
    return this.#send({ method: "GET", path: "/cheats", what: "cheats", query, read: models.readCheatSets });
  }

  /** A set's text, checked against its size and SHA-256 (1 MiB at most). */
  async cheatText(cheat: CheatSet): Promise<string> {
    if (cheat.size > CHEAT_SET)
      throw new DocumentError(`cheat set ${cheat.id}: ${cheat.size} bytes, above ${CHEAT_SET}`);
    await this.#ensureBase();
    const data = await this.fetchFile(this.v1(`/cheats/${segment(cheat.id)}`), {
      sha256: cheat.sha256,
      size: cheat.size,
    });
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(data);
    } catch {
      throw new DocumentError(`cheat set ${cheat.id}: not UTF-8 text`);
    }
  }

  // Pairing (SPEC.md § 5.2 to § 5.5).

  /**
   * Asks to pair: makes a device key (`key: true`, a new one; a DeviceKey given;
   * or false for a bearer-only token), sends it with the device's name, the
   * scopes asked for and an invitation's code when there is one, and gives what
   * the device shows. The key of the server's connection is pinned from then on
   * when no CA vouched for it.
   */
  async pair(
    device: string,
    scopes: readonly string[],
    options: { key?: DeviceKey | boolean; invitation?: string } = {},
  ): Promise<Pairing> {
    if (this.hello === undefined) await this.handshake();
    if (!device.trim() || utf8Length(device) > 512)
      throw new RangeError("device is the device's name, 512 bytes at most");
    if (scopes.length === 0) throw new RangeError("ask for one scope at least");
    const want = options.key ?? true;
    const key =
      want === true ? await DeviceKey.generate({ extractable: this.#extractable }) : want === false ? undefined : want;
    const body: Record<string, unknown> = { schema: SCHEMA, device, scopes: [...new Set(scopes)] };
    if (key !== undefined) body["key"] = key.document();
    if (options.invitation !== undefined) body["invitation"] = options.invitation;
    const doc = await this.#send<PairingCode>({
      method: "POST",
      path: "/pairing",
      what: "pairing",
      body,
      anonymous: true,
      read: models.readPairingCode,
    });
    checkPairingCode(doc, this.root);
    const spki = this.lastSpki;
    if (spki !== undefined) this.transport.pinSeen?.(spki);
    return new Pairing(doc, key, spki, this.onOrigin(doc.poll, "pairing poll"));
  }

  /** One poll: the token's document once approved (the client then uses it), undefined while waiting; Gone when refused, expired or collected. */
  async pollPairing(pairing: Pairing): Promise<PairingToken | undefined> {
    const signer = pairing.key !== undefined ? new DeviceSigner(pairing.key, () => this.now()) : undefined;
    const call: Call<PairingToken | undefined> = {
      method: "GET",
      what: "pairing poll",
      url: this.onOrigin(pairing.pollUrl, "pairing poll"),
      read: models.readPairingToken,
      emptyStatuses: [202],
      empty: () => undefined,
      anonymous: true,
    };
    if (signer !== undefined) call.signer = signer;
    const token = await this.#send(call);
    if (token !== undefined) this.setToken(token.token, token.bound !== false ? pairing.key : undefined);
    return token;
  }

  /**
   * Polls every `interval` until the user approves (or refuses: Gone), within the
   * code's life; then keeps the server in `store` and gives its record. A 429
   * slows the polls down (RFC 8628 § 3.5).
   */
  async waitForPairing(
    pairing: Pairing,
    options: { store?: ServerStore; sleep?: (seconds: number) => Promise<void> } = {},
  ): Promise<ServerRecord> {
    const sleep = options.sleep ?? ((s: number) => new Promise<void>((r) => setTimeout(r, s * 1000)));
    let interval = pairing.interval;
    for (;;) {
      if (pairing.expired) throw new Gone(410);
      let token: PairingToken | undefined;
      try {
        token = await this.pollPairing(pairing);
      } catch (e) {
        if (!(e instanceof SlowDown)) throw e;
        interval = Math.max(interval + 5, e.retryAfter ?? 0);
      }
      if (token !== undefined) {
        const hello = await this.handshake();
        const record: ServerRecord = {
          uid: hello.uid,
          url: `${this.root}/`,
          token: token.token,
          name: hello.name,
          scopes: [...token.scopes],
          bound: token.bound !== false && pairing.key !== undefined,
          paired: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        };
        if (pairing.spki !== undefined) record.spki = pairing.spki;
        if (pairing.key !== undefined && token.bound !== false && pairing.key.extractable)
          record.key = await pairing.key.seedBase64();
        if (token.rating_cap !== undefined) record.rating_cap = { ...token.rating_cap } as never;
        await options.store?.save(record);
        return record;
      }
      await sleep(interval);
    }
  }

  /**
   * Redeems an invitation's link (SPEC.md § 5.5): the key it names is pinned
   * without asking the user, and the pairing is approved at once.
   */
  static async fromInvitation<C extends LanternClient>(
    this: new (
      url: string,
      options?: ClientOptions,
    ) => C,
    link: string,
    device: string,
    scopes: readonly string[],
    options: ClientOptions & { store?: ServerStore } = {},
  ): Promise<[C, ServerRecord]> {
    const found = invitationLink(link);
    const { store, ...rest } = options;
    const client = new this(
      found.url,
      found.spki !== undefined && rest.transport === undefined ? { ...rest, pin: found.spki } : rest,
    );
    const pairing = await client.pair(device, scopes, { invitation: found.code });
    const record = await client.waitForPairing(pairing, {
      ...(store !== undefined ? { store } : {}),
      sleep: (s) => new Promise((r) => setTimeout(r, Math.min(s, 1) * 1000)),
    });
    return [client, record];
  }

  // Saves (SPEC.md § 9).

  /** The account's backups, newest first per title. */
  saves(options: { titleId?: string; platform?: string } = {}): Promise<Saves> {
    const query = [...platformQuery(options.platform), ...listing(undefined, undefined, { title_id: options.titleId })];
    return this.#send({ method: "GET", path: "/saves", what: "saves", query, read: models.readSaves });
  }

  #savePath(titleId: string, saveId?: string): string {
    if (!CORE_ID.test(titleId) || (saveId !== undefined && !CORE_ID.test(saveId))) {
      throw new RangeError("a title id and a save id are 1 to 128 letters, digits, '.', '_' and '-'");
    }
    return `/saves/${quote(titleId)}${saveId !== undefined ? `/${quote(saveId)}` : ""}`;
  }

  /** A save of at most limits.save_body bytes, in one request with its Content-Digest (SPEC.md § 9.2). */
  save(titleId: string, data: Uint8Array, options: SaveOptions = {}): Promise<Save> {
    this.#needsPlatform(options.platform, "writing a save");
    const headers: Record<string, string> = {
      "Content-Type": options.encryption !== undefined ? "application/octet-stream" : "application/zip",
      "Content-Digest": contentDigest(data),
    };
    if (options.encryption !== undefined) headers["Lantern-Save-Encryption"] = encryptionHeader(options.encryption);
    if (options.kind !== undefined) headers["Lantern-Save-Kind"] = asciiWord(options.kind, "kind");
    if (options.slot !== undefined) headers["Lantern-Save-Slot"] = asciiWord(options.slot, "slot");
    if (options.gameVersionCode !== undefined) {
      if (!Number.isInteger(options.gameVersionCode) || options.gameVersionCode < 0)
        throw new RangeError("gameVersionCode is 0 or more");
      headers["Lantern-Game-Version"] = String(options.gameVersionCode);
    }
    if (options.profile !== undefined) headers["Lantern-Profile"] = headerText(options.profile, PROFILE, "profile");
    if (options.note !== undefined) headers["Lantern-Note"] = headerText(options.note, NOTE, "note");
    return this.#send({
      method: "POST",
      path: this.#savePath(titleId),
      what: "save",
      query: platformQuery(options.platform),
      raw: data,
      headers,
      statuses: [201],
      read: models.readSave,
    });
  }

  async #sha256Of(source: UploadSource): Promise<string> {
    const h = this.hash();
    for (let at = 0; at < source.size; at += 1 << 20)
      h.update(await source.read(at, Math.min(1 << 20, source.size - at)));
    return [...h.digest()].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  #chunk(upload: string, offset: number, chunk: Uint8Array): Promise<number | Save> {
    return this.#send<number | Save>({
      method: "PATCH",
      what: "upload chunk",
      url: this.onOrigin(upload, "upload"),
      raw: chunk,
      headers: {
        "Content-Type": "application/offset+octet-stream",
        "Upload-Offset": String(offset),
        "Content-Digest": contentDigest(chunk),
      },
      statuses: [201],
      read: models.readSave,
      emptyStatuses: [204],
      empty: uploadOffset,
    });
  }

  /**
   * A save of any size, by resumable upload (SPEC.md § 9.3): opened, then sent in
   * chunks of the server's `chunk_size`, each with its Content-Digest; `resume`
   * is the address of an upload opened before, which goes on from where HEAD
   * says. A lost connection throws TransportError: call again with the same
   * `resume` (`client.lastUpload`).
   */
  async uploadSave(titleId: string, source: UploadSource, options: UploadOptions = {}): Promise<Save> {
    let address: string;
    let chunkSize: number;
    let offset: number;
    if (options.resume === undefined) {
      this.#needsPlatform(options.platform, "writing a save");
      const body: Record<string, unknown> = { schema: SCHEMA, size: source.size, sha256: await this.#sha256Of(source) };
      if (options.kind !== undefined) body["kind"] = options.kind;
      if (options.slot !== undefined) body["slot"] = options.slot;
      if (options.gameVersionCode !== undefined) body["game_version_code"] = options.gameVersionCode;
      if (options.profile !== undefined) body["profile"] = options.profile;
      if (options.note !== undefined) body["note"] = options.note;
      if (options.encryption !== undefined) {
        encryptionHeader(options.encryption); // of this scheme, or a RangeError
        body["encryption"] = { scheme: options.encryption.scheme, key_id: options.encryption.key_id };
      }
      const upload = await this.#send<Upload>({
        method: "POST",
        path: `${this.#savePath(titleId)}/uploads`,
        what: "upload",
        query: platformQuery(options.platform),
        body,
        statuses: [201],
        read: models.readUpload,
      });
      address = upload.upload;
      chunkSize = upload.chunk_size;
      offset = upload.offset;
    } else {
      address = options.resume;
      chunkSize = 1 << 20;
      [offset] = await this.uploadOffset(address);
    }
    if (chunkSize < 1) throw new UnexpectedResponse("upload: a chunk_size under 1");
    this.lastUpload = address;
    for (;;) {
      const chunk = await source.read(offset, Math.min(chunkSize, source.size - offset));
      const result = await this.#chunk(address, offset, chunk);
      if (typeof result !== "number") {
        this.lastUpload = undefined;
        options.progress?.(source.size, source.size);
        return result;
      }
      if (!(offset < result && result <= source.size)) {
        throw new UnexpectedResponse(`upload: the server's offset ${result}, after ${offset} of ${source.size}`);
      }
      offset = result;
      options.progress?.(offset, source.size);
    }
  }

  /** Where an upload stands: its Upload-Offset and Upload-Length (HEAD). */
  uploadOffset(upload: string): Promise<[number, number | undefined]> {
    return this.#send<[number, number | undefined]>({
      method: "HEAD",
      what: "upload state",
      url: this.onOrigin(upload, "upload"),
      statuses: [],
      emptyStatuses: [200, 204],
      empty: (status, headers) => {
        const length = headers.get("Upload-Length")?.trim() ?? "";
        return [uploadOffset(status, headers), /^\d{1,15}$/.test(length) ? Number(length) : undefined];
      },
    });
  }

  #delete(url: string, what: string): Promise<void> {
    return this.#send<void>({
      method: "DELETE",
      what,
      url: this.onOrigin(url, what),
      statuses: [],
      emptyStatuses: [204],
      empty: () => undefined,
    });
  }

  abandonUpload(upload: string): Promise<void> {
    return this.#delete(upload, "upload");
  }

  /** A backup's archive, checked against its sha256, into `sink`. */
  async downloadSave(
    save: Save,
    sink: DownloadSink,
    options: Omit<DownloadOptions, "sha256" | "size"> = {},
  ): Promise<void> {
    await this.#ensureBase();
    await this.download(this.v1(this.#savePath(save.title_id, save.save_id)), sink, {
      ...options,
      sha256: save.sha256,
      size: save.size,
    });
  }

  async deleteSave(save: Save): Promise<void> {
    await this.#ensureBase();
    await this.#delete(this.v1(this.#savePath(save.title_id, save.save_id)), "save");
  }

  // Cheats, written (SPEC.md § 10).

  #cheatWrite(
    platform: string,
    titleId: string,
    text: string,
    o: { buildId?: string; source?: string; note?: string },
  ): object {
    if (!isPlatform(platform) || !CORE_ID.test(titleId)) throw new RangeError("a platform's name and a title id");
    if (o.buildId !== undefined && !BUILD_ID.test(o.buildId))
      throw new RangeError("buildId is 1 to 64 letters, digits, '.', '_' and '-'");
    if (utf8Length(text) > CHEAT_SET) throw new RangeError(`a cheat set is ${CHEAT_SET} bytes at most`);
    const doc: Record<string, unknown> = { schema: SCHEMA, platform, title_id: titleId };
    if (o.buildId !== undefined) doc["build_id"] = o.buildId;
    if (o.source !== undefined) doc["source"] = o.source;
    if (o.note !== undefined) doc["note"] = o.note;
    doc["text"] = text;
    return doc;
  }

  /** A new set (scope cheats.write): the set; Conflict when the same one exists (replace it). */
  createCheat(
    platform: string,
    titleId: string,
    text: string,
    options: { buildId?: string; source?: string; note?: string } = {},
  ): Promise<CheatSet> {
    const body = this.#cheatWrite(platform, titleId, text, options);
    return this.#send({
      method: "POST",
      path: "/cheats",
      what: "cheat set",
      body,
      statuses: [201],
      read: models.readCheatSet,
    });
  }

  replaceCheat(
    cheatId: string,
    platform: string,
    titleId: string,
    text: string,
    options: { buildId?: string; source?: string; note?: string } = {},
  ): Promise<void> {
    const body = this.#cheatWrite(platform, titleId, text, options);
    return this.#send<void>({
      method: "PUT",
      path: `/cheats/${segment(cheatId)}`,
      what: "cheat set",
      body,
      statuses: [],
      emptyStatuses: [204],
      empty: () => undefined,
    });
  }

  async deleteCheat(cheatId: string): Promise<void> {
    await this.#ensureBase();
    await this.#delete(this.v1(`/cheats/${segment(cheatId)}`), "cheat set");
  }

  // Requests (SPEC.md § 11).

  requests(options: { platform?: string } = {}): Promise<TitleRequests> {
    return this.#send({
      method: "GET",
      path: "/requests",
      what: "requests",
      query: platformQuery(options.platform),
      read: models.readTitleRequests,
    });
  }

  /** Asks for a title: the new request, or the open one for the same title. */
  requestTitle(titleId: string, options: { platform?: string } = {}): Promise<TitleRequest> {
    if (!CORE_ID.test(titleId)) throw new RangeError(`${titleId} is not a title id`);
    const body: Record<string, unknown> = { schema: SCHEMA, title_id: titleId };
    if (options.platform !== undefined) {
      if (!isPlatform(options.platform)) throw new RangeError(`${options.platform} is not a platform's name`);
      body["platform"] = options.platform;
    }
    return this.#send({
      method: "POST",
      path: "/requests",
      what: "request",
      body,
      statuses: [200, 201],
      read: models.readTitleRequest,
    });
  }

  async withdrawRequest(requestId: string): Promise<void> {
    await this.#ensureBase();
    await this.#delete(this.v1(`/requests/${segment(requestId)}`), "request");
  }

  // Administration (SPEC.md § 5.7, scope admin).

  #adminUsers(o: ListOptions): Call<AdminUsers> {
    return {
      method: "GET",
      path: "/admin/users",
      what: "accounts",
      query: listing(o.pageSize, o.cursor),
      read: models.readAdminUsers,
    };
  }
  adminUsers(options: ListOptions = {}): Promise<AdminUsers> {
    return this.#send(this.#adminUsers(options));
  }
  iterAdminUsers(options: Omit<ListOptions, "cursor"> = {}): AsyncGenerator<AdminUser> {
    return this.#pages(
      this.#adminUsers(options),
      (p) => p.items,
      (p) => p.next,
    );
  }
  createUser(
    name: string,
    scopes: readonly string[],
    options: { state?: "active" | "frozen" } = {},
  ): Promise<AdminUser> {
    const body: Record<string, unknown> = { schema: SCHEMA, name, scopes: [...scopes] };
    if (options.state !== undefined) body["state"] = options.state;
    return this.#send({
      method: "POST",
      path: "/admin/users",
      what: "account",
      body,
      statuses: [201],
      read: models.readAdminUser,
    });
  }
  updateUser(name: string, change: { state?: "active" | "frozen"; scopes?: readonly string[] }): Promise<AdminUser> {
    if (change.state === undefined && change.scopes === undefined)
      throw new RangeError("change the state, the scopes, or both");
    const body: Record<string, unknown> = { schema: SCHEMA };
    if (change.state !== undefined) body["state"] = change.state;
    if (change.scopes !== undefined) body["scopes"] = [...change.scopes];
    return this.#send({
      method: "PATCH",
      path: `/admin/users/${segment(name)}`,
      what: "account",
      body,
      read: models.readAdminUser,
    });
  }

  /**
   * Deletes an account (SPEC.md § 5.7), at once and whole: its devices,
   * invitations, waiting pairings, backups, requests and sync data. `confirm`
   * repeats its name, as its user typed it (a slip of the finger deletes
   * nothing); it cannot be undone.
   */
  async deleteUser(name: string, confirm: string): Promise<void> {
    if (confirm !== name) throw new RangeError("confirm repeats the account's name, as typed by the user");
    await this.#ensureBase();
    await this.#delete(this.v1(`/admin/users/${segment(name)}?confirm=${quote(confirm)}`), "account");
  }

  #adminDevices(o: ListOptions & { user?: string }): Call<AdminDevices> {
    return {
      method: "GET",
      path: "/admin/devices",
      what: "devices",
      query: listing(o.pageSize, o.cursor, { user: o.user }),
      read: models.readAdminDevices,
    };
  }
  adminDevices(options: ListOptions & { user?: string } = {}): Promise<AdminDevices> {
    return this.#send(this.#adminDevices(options));
  }
  iterAdminDevices(options: Omit<ListOptions, "cursor"> & { user?: string } = {}): AsyncGenerator<AdminDevice> {
    return this.#pages(
      this.#adminDevices(options),
      (p) => p.items,
      (p) => p.next,
    );
  }
  async revokeDevice(deviceId: string): Promise<void> {
    await this.#ensureBase();
    await this.#delete(this.v1(`/admin/devices/${segment(deviceId)}`), "device");
  }

  #adminPairings(o: ListOptions): Call<AdminPairings> {
    return {
      method: "GET",
      path: "/admin/pairings",
      what: "pairings",
      query: listing(o.pageSize, o.cursor),
      read: models.readAdminPairings,
    };
  }
  /** The pairings waiting: show each one's code next to the short fingerprint of the server's key as this app pinned it (L-5.7-5). */
  adminPairings(options: ListOptions = {}): Promise<AdminPairings> {
    return this.#send(this.#adminPairings(options));
  }
  iterAdminPairings(options: Omit<ListOptions, "cursor"> = {}): AsyncGenerator<AdminPairing> {
    return this.#pages(
      this.#adminPairings(options),
      (p) => p.items,
      (p) => p.next,
    );
  }
  #decide(pairingId: string, body: Record<string, unknown>): Promise<void> {
    return this.#send<void>({
      method: "POST",
      path: `/admin/pairings/${segment(pairingId)}`,
      what: "pairing decision",
      body: { schema: SCHEMA, ...body },
      statuses: [],
      emptyStatuses: [204],
      empty: () => undefined,
    });
  }
  approvePairing(
    pairingId: string,
    options: { user?: string; scopes?: readonly string[]; ratingCap?: RatingCap } = {},
  ): Promise<void> {
    const body: Record<string, unknown> = { decision: "approve" };
    if (options.user !== undefined) body["user"] = options.user;
    if (options.scopes !== undefined) body["scopes"] = [...options.scopes];
    if (options.ratingCap !== undefined) body["rating_cap"] = options.ratingCap;
    return this.#decide(pairingId, body);
  }
  refusePairing(pairingId: string): Promise<void> {
    return this.#decide(pairingId, { decision: "refuse" });
  }

  #adminInvitations(o: ListOptions): Call<Invitations> {
    return {
      method: "GET",
      path: "/admin/invitations",
      what: "invitations",
      query: listing(o.pageSize, o.cursor),
      read: models.readInvitations,
    };
  }
  adminInvitations(options: ListOptions = {}): Promise<Invitations> {
    return this.#send(this.#adminInvitations(options));
  }
  iterAdminInvitations(options: Omit<ListOptions, "cursor"> = {}): AsyncGenerator<Invitation> {
    return this.#pages(
      this.#adminInvitations(options),
      (p) => p.items,
      (p) => p.next,
    );
  }
  createInvitation(
    user: string,
    scopes: readonly string[],
    options: { expires: string; devices?: number; ratingCap?: RatingCap; note?: string },
  ): Promise<Invitation> {
    const body: Record<string, unknown> = {
      schema: SCHEMA,
      user,
      scopes: [...scopes],
      expires: options.expires,
      devices: options.devices ?? 1,
    };
    if (options.ratingCap !== undefined) body["rating_cap"] = options.ratingCap;
    if (options.note !== undefined) body["note"] = options.note;
    return this.#send({
      method: "POST",
      path: "/admin/invitations",
      what: "invitation",
      body,
      statuses: [201],
      read: models.readInvitation,
    });
  }
  async revokeInvitation(invitationId: string): Promise<void> {
    await this.#ensureBase();
    await this.#delete(this.v1(`/admin/invitations/${segment(invitationId)}`), "invitation");
  }

  // End-to-end encrypted saves (SPEC.md § 9.4).

  /**
   * An encrypted backup (an EncryptedBackup made with the user's save key),
   * by resumable upload: its bytes are encrypted again chunk by chunk as the
   * upload reads them, the same each time, never kept (L-9.4-3). Its
   * `encryption` (scheme and key id) goes in clear; nothing of the key does.
   * Wipe the backup once this resolves or is given up.
   */
  uploadEncryptedSave(titleId: string, backup: EncryptedBackup, options: UploadOptions = {}): Promise<Save> {
    return this.uploadSave(titleId, backup, { ...options, encryption: backup.encryption });
  }

  /** An encrypted backup's bytes, checked against its sha256, in memory: decrypt them with e2e.decryptBytes(). */
  async fetchSave(save: Save): Promise<Uint8Array> {
    const sink = new MemorySink();
    await this.downloadSave(save, sink, { resume: false });
    return sink.bytes();
  }

  // Events (SPEC.md § 18).

  #heartbeat(): number {
    const beat = this.hello?.limits?.heartbeat;
    return typeof beat === "number" && beat >= 5 && beat <= 60 ? beat : 60;
  }

  /**
   * The event stream (SPEC.md § 18.1), read over this client's transport
   * (fetch() in a browser: EventSource cannot send a token nor a signature),
   * opened again as it ends, after `retry`, with Last-Event-ID. Iterate it;
   * keep `stream.lastId` to resume after a restart (`since`). A Gone means
   * the id is too old: read the library again, then open one without `since`.
   */
  async events(options: EventStreamOptions & { platform?: string } = {}): Promise<EventStream> {
    await this.#ensureBase();
    if (this.hello === undefined) await this.handshake();
    const query = platformQuery(options.platform);
    const url =
      this.v1("/events") + (query.length > 0 ? `?${query.map(([k, v]) => `${k}=${quote(v)}`).join("&")}` : "");
    const connect = async (lastId: string | undefined) => {
      for (let attempt = 0; ; attempt++) {
        const headers: Record<string, string> = { Accept: "text/event-stream", "Cache-Control": "no-store" };
        if (lastId !== undefined) headers["Last-Event-ID"] = lastId;
        const request = await this.prepare("GET", url, { headers });
        // Nothing for twice limits.heartbeat: the stream is dead, connect again (§ 18.1).
        const response = await this.transport.send(request, { timeout: 2 * this.#heartbeat() + 1 });
        this.lastSpki = response.spki;
        const type = mediaType(response.headers.get("Content-Type"));
        if (response.status === 200 && type === "text/event-stream") {
          if (response.headers.get("Content-Encoding")) {
            await response.cancel();
            throw new UnexpectedResponse("events: a stream with a Content-Encoding (SPEC.md § 18.1)", 200);
          }
          return response;
        }
        let body: Uint8Array = new Uint8Array();
        try {
          body = await readBody(response, ERROR_BODY, "events");
        } catch (e) {
          if (!(e instanceof DocumentError)) throw e;
        } finally {
          await response.cancel();
        }
        const error = this.#error("events", response.status, response.headers, body);
        if (attempt === 0 && error instanceof SignatureExpired && this.adjustClock(error.headers)) continue;
        if (attempt === 0 && error instanceof SignatureReplayed) continue;
        throw error;
      }
    };
    const streamOptions: EventStreamOptions = {};
    if (options.since !== undefined) streamOptions.since = options.since;
    if (options.tries !== undefined) streamOptions.tries = options.tries;
    if (options.onReconnect !== undefined) streamOptions.onReconnect = options.onReconnect;
    return new EventStream(connect, streamOptions);
  }

  /**
   * A long poll (SPEC.md § 18.3): the changes and events after `since`, as
   * soon as one comes, or `wait` seconds later (lowered to limits.wait by the
   * server). Events of a type or schema this library does not read are left
   * out. Ask again at once with the answer's `since`.
   */
  async poll(
    since: string,
    wait: number,
    options: { platform?: string } = {},
  ): Promise<Omit<Changes, "events"> & { events: ServerEvent[] }> {
    if (!Number.isInteger(wait) || wait < 0) throw new RangeError("wait is a whole number of seconds, from 0");
    const query: [string, string][] = [...platformQuery(options.platform), ["since", since], ["wait", String(wait)]];
    const doc = await this.#send({
      method: "GET",
      path: "/changes",
      what: "changes",
      query,
      read: models.readChanges,
      timeout: this.timeout + wait,
    });
    const events: ServerEvent[] = [];
    for (const e of doc.events ?? []) {
      if (!(EVENT_TYPES as readonly string[]).includes(e.event)) continue;
      if (e.data.schema > SCHEMA) continue;
      events.push(e as unknown as ServerEvent);
    }
    return { ...doc, events };
  }

  // Grants, mirrors and peers (SPEC.md § 19).

  /**
   * A grant for the file whose SHA-256 is `sha256` (SPEC.md § 19.3), checked
   * before it goes to any peer: it names that file and this server's uid, it
   * is not expired, and it verifies by the handshake's `peers.key`. One that
   * does not throws IntegrityError: a peer would refuse it too.
   */
  async grant(sha256: string): Promise<Grant & { payload: GrantPayload }> {
    if (!/^[0-9a-f]{64}$/.test(sha256)) throw new RangeError("sha256 is 64 lower-case hex digits");
    const hello = this.hello ?? (await this.handshake());
    const key = grantKey(hello.peers);
    if (key === undefined) throw new Unsupported("this server gives no grants (no peers.key in its handshake)");
    const doc = await this.#send({
      method: "GET",
      path: `/grants/sha256/${sha256}`,
      what: "grant",
      read: models.readGrant,
    });
    const payload = await verifyGrant(doc.grant, { [hello.uid]: key }, this.now());
    if (payload === undefined || payload.sha256 !== sha256 || doc.sha256 !== sha256 || payload.size !== doc.size) {
      throw new IntegrityError(
        `grant for ${sha256.slice(0, 12)}…: it does not verify by peers.key, names another file or server, or expired`,
      );
    }
    return { ...doc, payload };
  }

  /**
   * Whether a peer holds a file (SPEC.md § 19.5): HEAD with its grant; a hint,
   * as any answer of a peer. No credential of the server goes to it (L-19.1-2).
   */
  async peerHolds(peer: Peer, sha256: string, grant: string): Promise<boolean> {
    const transport = this.#elsewhere({ verify: false });
    const request = this.#elsewhereRequest("HEAD", blobUrl(peer.url, sha256), { [GRANT_HEADER]: grant });
    const response = await transport.send(request, { timeout: Math.min(this.timeout, 10) });
    try {
      return response.status === 200;
    } finally {
      await response.cancel();
      await transport.close?.();
    }
  }

  /** A request to a mirror or a peer: nothing of the server's, no credential, no signature. */
  #elsewhereRequest(method: string, url: string, extra: Record<string, string> = {}): TransportRequest {
    const headers = new Headers({ "User-Agent": this.userAgent, Accept: "*/*", "Accept-Encoding": "identity" });
    for (const [k, v] of Object.entries(extra)) headers.set(k, v);
    return { method, url, headers };
  }

  /**
   * A file from a mirror or a peer into `sink`, checked as from the server:
   * more bytes than its size stop the reading (L-19.1-3), and nothing it says
   * decides anything; IntegrityError (and the sink emptied) when it is not the file.
   */
  async #downloadElsewhere(
    url: string,
    sink: DownloadSink,
    file: { sha256: string; size: number },
    options: { verify: boolean; headers?: Record<string, string>; progress?: DownloadOptions["progress"] },
  ): Promise<void> {
    const verifier = new Verifier(file.sha256, file.size, url);
    await sink.reset();
    const transport = this.#elsewhere({ verify: options.verify });
    try {
      const response = await transport.send(this.#elsewhereRequest("GET", url, options.headers), {
        timeout: this.timeout,
      });
      try {
        if (response.status !== 200) throw new UnexpectedResponse(`${url}: status ${response.status}`, response.status);
        verifier.start(200, response.headers, 0);
        const hasher = this.hash();
        for await (const chunk of response.body()) {
          verifier.feed(hasher, chunk);
          await sink.append(chunk);
          options.progress?.(hasher.size, file.size);
        }
        verifier.finish(hasher);
      } finally {
        await response.cancel();
      }
    } catch (e) {
      await sink.reset();
      throw e;
    } finally {
      await transport.close?.();
    }
    await sink.commit();
  }

  /**
   * A file of the library (an app's, a package's) into `sink`: from peers
   * holding it (with a grant), then its mirrors, then the server, each checked
   * by the file's size and SHA-256 before anything is kept (SPEC.md § 19.1);
   * a source that fails is passed by, and the server is the last.
   */
  async downloadFile(
    file: { file: string; sha256: string; size: number; mirrors?: readonly { url: string }[] | undefined },
    sink: DownloadSink,
    options: Omit<DownloadOptions, "sha256" | "size"> & SourceOptions = {},
  ): Promise<void> {
    const passed: { url: string; error: unknown }[] = [];
    const progress = options.progress !== undefined ? { progress: options.progress } : {};
    if (options.peers !== undefined && options.peers.length > 0) {
      const hello = this.hello ?? (await this.handshake());
      const asked = options.peers.filter((p) => p.servers.includes(hello.uid)).slice(0, 2);
      if (asked.length > 0) {
        let granted: string | undefined;
        try {
          granted = (await this.grant(file.sha256)).grant;
        } catch (e) {
          if (e instanceof IntegrityError || !(e instanceof LanternError)) throw e;
          passed.push({ url: this.v1(`/grants/sha256/${file.sha256}`), error: e });
        }
        for (const peer of granted !== undefined ? asked : []) {
          const url = blobUrl(peer.url, file.sha256);
          try {
            await this.#downloadElsewhere(url, sink, file, {
              verify: false,
              headers: { [GRANT_HEADER]: granted as string },
              ...progress,
            });
            options.onSource?.("peer", url, passed);
            return;
          } catch (e) {
            if (!(e instanceof LanternError)) throw e;
            passed.push({ url, error: e });
          }
        }
      }
    }
    if (options.mirrors) {
      for (const url of usableMirrors(file)) {
        try {
          await this.#downloadElsewhere(url, sink, file, { verify: true, ...progress });
          options.onSource?.("mirror", url, passed);
          return;
        } catch (e) {
          if (!(e instanceof LanternError)) throw e;
          passed.push({ url, error: e });
        }
      }
    }
    if (passed.length > 0) await sink.reset();
    const { peers: _p, mirrors: _m, onSource: _o, ...rest } = options;
    await this.download(file.file, sink, { ...rest, sha256: file.sha256, size: file.size });
    options.onSource?.("server", this.url(file.file), passed);
  }

  // Sync (SPEC.md § 20).

  /**
   * What the user agreed to (SPEC.md § 20.1): the app asks its user, saying
   * which collections go to which server, then sets it here. Nothing of
   * `<base>/v1/sync` is read or written before, nor any collection the user
   * did not agree to by name (L-20.1-2). `undefined` (or no collection) turns
   * sync off: nothing more is sent (L-20.1-3). The state is the app's to keep
   * (`syncState`), per console profile and per server.
   */
  setSyncConsent(state: SyncState | undefined): void {
    if (state !== undefined && readSyncState(state) === undefined) throw new RangeError("not a sync state");
    this.#sync = state;
  }

  /** The sync state as it stands (revisions read, generation kept), to keep for the next run. */
  get syncState(): SyncState | undefined {
    return this.#sync;
  }

  #consent(collection?: string): SyncState {
    const state = this.#sync;
    if (state === undefined || state.consent.length === 0)
      throw new ConsentRequired(collection ?? "", "sync is off: ask the user first (SPEC.md § 20.1)");
    if (collection !== undefined && !state.consent.includes(collection))
      throw new ConsentRequired(collection, `the user did not agree to sync ${collection} (SPEC.md § 20.1)`);
    return state;
  }

  /** A generation other than the one kept: drop the copy, turn sync off, and say so (L-20.3-2). */
  #generation(state: SyncState, generation: string): void {
    if (state.generation === undefined) {
      state.generation = generation;
      return;
    }
    if (state.generation === generation) return;
    const kept = state.generation;
    state.consent = [];
    state.revs = {};
    delete state.generation;
    throw new GenerationChanged(kept, generation);
  }

  /** GET <base>/v1/sync: the account's collections, and this device's id (its key in `installed`). */
  async syncOverview(): Promise<Sync> {
    const state = this.#consent();
    const doc = await this.#send({ method: "GET", path: "/sync", what: "sync", read: models.readSync });
    this.#generation(state, doc.generation);
    return doc;
  }

  /**
   * A collection's items (SPEC.md § 20.3): those changed since the revision
   * last read, deletions included, or the whole collection the first time,
   * and after a 410 (deletions dropped that far back). The revision is kept.
   */
  async syncPull(collection: string, options: { whole?: boolean } = {}): Promise<SyncCollection> {
    const state = this.#consent(collection);
    const since = options.whole ? undefined : state.revs[collection];
    const read = async (from: number | undefined): Promise<SyncCollection> => {
      const items: SyncItem[] = [];
      let first: SyncCollection | undefined;
      let cursor: string | undefined;
      const seen = new Set<string>();
      for (;;) {
        const query: [string, string][] = [];
        if (from !== undefined) query.push(["since", String(from)]);
        if (cursor !== undefined) query.push(["cursor", cursor]);
        const page = await this.#send({
          method: "GET",
          path: `/sync/${segment(collection)}`,
          what: "sync collection",
          query,
          read: models.readSyncCollection,
        });
        this.#generation(state, page.generation);
        first ??= page;
        items.push(...page.items);
        if (page.next === null || page.next === undefined) break;
        if (seen.has(page.next)) throw new UnexpectedResponse("sync: the server gave the same cursor twice");
        seen.add(page.next);
        cursor = page.next;
      }
      return { ...(first as SyncCollection), items, next: null };
    };
    let doc: SyncCollection;
    try {
      doc = await read(since);
    } catch (e) {
      if (!(e instanceof Gone) || since === undefined) throw e;
      doc = await read(undefined);
    }
    state.revs[collection] = Math.max(doc.rev, ...doc.items.map((i) => i.rev ?? 0));
    return doc;
  }

  /**
   * Items written (SPEC.md § 20.4), each as the server then keeps it. With
   * `whole` (items written from the whole collection as last read), the write
   * is all or nothing: If-Match, and PreconditionFailed (412) when the
   * collection changed since; else the server merges item by item. A
   * Conflict (409) means the data was deleted since: sync goes off.
   */
  async syncPush(
    collection: string,
    items: readonly SyncItem[],
    options: { whole?: boolean } = {},
  ): Promise<SyncCollection> {
    const state = this.#consent(collection);
    if (items.length === 0 || items.length > WRITE_LIMIT)
      throw new RangeError(`a write holds 1 to ${WRITE_LIMIT} items (SPEC.md § 13)`);
    if (state.generation === undefined) await this.syncOverview();
    const generation = state.generation as string;
    const headers: Record<string, string> = {};
    if (options.whole) {
      const rev = state.revs[collection];
      if (rev === undefined) throw new RangeError("a write of the whole collection follows a read of it");
      headers["If-Match"] = syncIfMatch(generation, rev);
    }
    const sent = items.map((i) => {
      const out: Record<string, unknown> = { key: i.key, updated: i.updated };
      if (i.deleted === true) out["deleted"] = true;
      else out["value"] = i.value;
      return out;
    });
    let doc: SyncCollection;
    try {
      doc = await this.#send({
        method: "PATCH",
        path: `/sync/${segment(collection)}`,
        what: "sync write",
        body: { schema: SCHEMA, generation, items: sent },
        headers,
        read: models.readSyncCollection,
      });
    } catch (e) {
      if (e instanceof Conflict) {
        state.consent = [];
        state.revs = {};
        delete state.generation;
        throw new GenerationChanged(generation, "?");
      }
      throw e;
    }
    this.#generation(state, doc.generation);
    if (options.whole) state.revs[collection] = doc.rev;
    return doc;
  }

  /**
   * Deletes what the server keeps of a collection, or of every one (SPEC.md
   * § 20.5): what a client offers when its user turns sync off. The server
   * gives a new generation: the state forgets the one it kept.
   */
  async syncErase(collection?: string): Promise<void> {
    const state = this.#sync;
    if (state === undefined)
      throw new ConsentRequired(collection ?? "", "no sync state: nothing of the user's to erase");
    if (
      collection !== undefined &&
      !(COLLECTIONS as readonly string[]).includes(collection) &&
      !/^[a-z][a-z0-9_]{0,31}$/.test(collection)
    )
      throw new RangeError("a collection is a lower-case word");
    await this.#ensureBase();
    await this.#delete(this.v1(collection !== undefined ? `/sync/${segment(collection)}` : "/sync"), "sync");
    delete state.generation;
    if (collection !== undefined) delete state.revs[collection];
    else state.revs = {};
  }

  // Files (SPEC.md § 6.6).

  /** A small file, whole in memory, checked against its SHA-256 and size. */
  async fetchFile(url: string, file: { sha256: string; size: number }): Promise<Uint8Array> {
    const sink = new MemorySink();
    await this.download(url, sink, { ...file, resume: false });
    return sink.bytes();
  }

  /**
   * Downloads a file into `sink`: resumed with a Range from what it already
   * holds, hashed as it arrives, and committed only once its size and SHA-256
   * are right. A file that is not throws IntegrityError, and the sink is reset;
   * a cut connection throws TransportError and keeps what arrived for the next try.
   */
  async download(url: string, sink: DownloadSink, options: DownloadOptions): Promise<void> {
    const verifier = new Verifier(options.sha256, options.size, url);
    const resume = options.resume ?? true;
    for (let tries = 0; tries < 3; tries++) {
      let offset = resume ? await sink.heldSize() : 0;
      if (!resume || offset > options.size) {
        await sink.reset();
        offset = 0;
      }
      let hasher: Hasher = this.hash();
      if (offset > 0) for await (const chunk of sink.held()) hasher.update(chunk);
      if (offset === options.size) {
        try {
          verifier.finish(hasher);
        } catch {
          await sink.reset();
          continue;
        }
        await sink.commit();
        return;
      }
      const headers: Record<string, string> = { Accept: "*/*" };
      if (offset > 0) headers["Range"] = `bytes=${offset}-`;
      const request = await this.prepare("GET", this.url(url), { headers });
      const response = await this.transport.send(request, { timeout: this.timeout });
      this.lastSpki = response.spki;
      try {
        if (response.status === 416 && offset > 0) {
          await sink.reset();
          continue;
        }
        if (response.status !== 200 && response.status !== 206) {
          let body: Uint8Array = new Uint8Array();
          try {
            body = await readBody(response, ERROR_BODY, url);
          } catch (e) {
            if (!(e instanceof DocumentError)) throw e;
          }
          throw this.#error(url, response.status, response.headers, body);
        }
        const start = verifier.start(response.status, response.headers, offset);
        if (start === 0 && offset > 0) {
          await sink.reset();
          hasher = this.hash();
        }
        try {
          for await (const chunk of response.body()) {
            verifier.feed(hasher, chunk);
            await sink.append(chunk);
            options.progress?.(hasher.size, options.size);
          }
          verifier.finish(hasher);
        } catch (e) {
          if (!(e instanceof Error) || e.name !== "TransportError") await sink.reset();
          throw e;
        }
      } catch (e) {
        if (e instanceof Error && (e.name === "UnexpectedResponse" || e.name === "IntegrityError")) await sink.reset();
        throw e;
      } finally {
        await response.cancel();
      }
      await sink.commit();
      return;
    }
    throw new LanternError(`${url}: the download could not be resumed`);
  }

  /** An app's file, checked against its sha256 (SPEC.md § 6.1, § 6.6). */
  downloadApp(
    app: App,
    sink: DownloadSink,
    options: Omit<DownloadOptions, "sha256" | "size"> & SourceOptions = {},
  ): Promise<void> {
    return this.downloadFile(app, sink, options);
  }

  /** A homebrew package, checked against its sha256 (SPEC.md § 8.2). */
  downloadPackage(
    p: Package,
    sink: DownloadSink,
    options: Omit<DownloadOptions, "sha256" | "size"> & SourceOptions = {},
  ): Promise<void> {
    return this.downloadFile(p, sink, options);
  }
}
