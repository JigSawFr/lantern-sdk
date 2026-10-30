/**
 * Static libraries (SPEC.md § 21): a library served as files, on a web host or
 * on a storage read with no server at all. This module holds the layout (each
 * read route's file below the library's root), the rule for the paths its
 * documents hold, and a reader of one over any `StaticSource`: HTTP(S) here
 * (fetch), a folder in `lantern-protocol/node`.
 *
 * What a static library cannot answer, the reader computes from its pages
 * (§ 21.3): what a device is missing (§ 6.3's rules, L-21.3-2), the updates
 * of homebrew, filters. Every file it reads is checked by its size and SHA-256,
 * as from a server (L-21.3-1), and its documents are JSON whatever their
 * Content-Type.
 */

import { DocumentError, LanternError, SCHEMA } from "./base.ts";
import { type DownloadSink, MemorySink, Verifier } from "./client/download.ts";
import { schemaOf } from "./documents.ts";
import { InsecureTransport, NewerSchema, TransportError, UnexpectedResponse } from "./errors.ts";
import type {
  App,
  AppsPage,
  CheatSet,
  CheatSets,
  Handshake,
  Homebrew,
  HomebrewPage,
  Title,
  Titles,
} from "./generated/models.ts";
import * as models from "./generated/models.ts";
import { plainHttpAllowed } from "./http.ts";
import { CHEAT_SET, JSON_DOCUMENT, loadJson } from "./limits.ts";
import { missing } from "./missing.ts";
import type { Check } from "./model.ts";
import { type HasherFactory, sha256Factory } from "./sha256.ts";
import { isPlatform } from "./vocabulary.ts";

/** The handshake's file (SPEC.md § 21.1). */
export const HANDSHAKE = "lantern.json";
/** The families a static library cannot offer (SPEC.md § 21.2, L-21.2-1). */
export const NOT_STATIC = [
  "changes",
  "sections",
  "saves",
  "encrypted_saves",
  "requests",
  "pairing",
  "signatures",
  "admin",
  "events",
  "peers",
  "sync",
] as const;

/** The routes a static library has a file for. */
export type LayoutKind = "handshake" | "apps" | "titles" | "homebrew" | "title" | "entry" | "cheats" | "cheat" | "blob";

/** The file of a read route, relative to the root (SPEC.md § 21.1). */
export function layoutPath(kind: LayoutKind, options: { platform?: string; id?: string; page?: number } = {}): string {
  const { platform, id, page } = options;
  const need = (value: string | undefined, what: string): string => {
    if (value === undefined || value === "" || /[/\\]|^\.\.?$/.test(value)) throw new RangeError(`a ${what} is needed`);
    return value;
  };
  switch (kind) {
    case "handshake":
      return HANDSHAKE;
    case "apps":
    case "titles":
    case "homebrew":
      if (page === undefined || !Number.isInteger(page) || page < 1) throw new RangeError("pages count from 1");
      return `v1/${kind}/${need(platform, "platform")}/pages/${page}.json`;
    case "title":
      return `v1/titles/${need(platform, "platform")}/${need(id, "title id")}.json`;
    case "entry":
      return `v1/homebrew/${need(platform, "platform")}/${need(id, "homebrew id")}.json`;
    case "cheats":
      return `v1/cheats/${need(platform, "platform")}/${need(id, "title id")}.json`;
    case "cheat":
      return `v1/cheats/${need(id, "cheat set id")}.txt`;
    case "blob":
      if (id === undefined || !/^[0-9a-f]{64}$/.test(id)) throw new RangeError("a blob is named by its SHA-256");
      return `v1/blobs/sha256/${id}`;
  }
}

const RELATIVE = /^(?![a-zA-Z][a-zA-Z0-9+.-]*:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\\?#]+$/;

/**
 * Whether a document's `file` or image `url` is a path relative to the root
 * (SPEC.md § 21.1, L-21.1-2): no scheme, no leading `/`, no `..` part, no `\`,
 * no query.
 */
export function relativeOk(path: string): boolean {
  return typeof path === "string" && path.length > 0 && path.length <= 4096 && RELATIVE.test(path);
}

/** Where a static library's files are read from: a web host, a folder. */
export interface StaticSource {
  /** What it is, for errors. */
  readonly describe: string;
  /** A file's bytes, `limit` at most (DocumentError beyond); undefined when it is not there. */
  read(rel: string, limit: number): Promise<Uint8Array | undefined>;
  /** A file's bytes as a stream; undefined when it is not there. */
  stream(rel: string): Promise<AsyncIterable<Uint8Array> | undefined>;
}

/**
 * A static library over HTTP(S), by fetch(): HTTPS, or plain HTTP on loopback
 * (SPEC.md § 2, § 21.3). No redirect is followed, no cookie sent; whatever the
 * Content-Type, a document is read as JSON.
 */
export class HttpStaticSource implements StaticSource {
  readonly root: string;
  readonly describe: string;
  readonly fetch: typeof globalThis.fetch;
  readonly timeout: number;

  constructor(root: string, options: { fetch?: typeof globalThis.fetch; timeout?: number } = {}) {
    const url = new URL(root.endsWith("/") ? root : `${root}/`);
    if (!plainHttpAllowed(url.toString()))
      throw new InsecureTransport(`${url}: plain HTTP is allowed only to a loopback address (SPEC.md § 2)`);
    if (url.search || url.hash) throw new RangeError("a static library's root has no query");
    this.root = url.toString();
    this.describe = this.root;
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeout = options.timeout ?? 30;
  }

  async #get(rel: string): Promise<Response | undefined> {
    if (!relativeOk(rel)) throw new DocumentError(`${JSON.stringify(rel.slice(0, 80))} is not a path below the root`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout * 1000);
    let response: Response;
    try {
      response = await this.fetch(new URL(rel, this.root).toString(), {
        redirect: "manual",
        credentials: "omit",
        signal: controller.signal,
      });
    } catch (e) {
      throw new TransportError(`${rel}: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
    } finally {
      clearTimeout(timer);
    }
    if (response.status === 404 || response.status === 410) {
      await response.body?.cancel();
      return undefined;
    }
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new UnexpectedResponse(`${rel}: status ${response.status}`, response.status);
    }
    return response;
  }

  async read(rel: string, limit: number): Promise<Uint8Array | undefined> {
    const response = await this.#get(rel);
    if (response === undefined) return undefined;
    const chunks: Uint8Array[] = [];
    let size = 0;
    for await (const chunk of streamOf(response)) {
      size += chunk.length;
      if (size > limit) throw new DocumentError(`more than ${limit} bytes`, rel);
      chunks.push(chunk);
    }
    const out = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) {
      out.set(c, at);
      at += c.length;
    }
    return out;
  }

  async stream(rel: string): Promise<AsyncIterable<Uint8Array> | undefined> {
    const response = await this.#get(rel);
    return response === undefined ? undefined : streamOf(response);
  }
}

async function* streamOf(response: Response): AsyncGenerator<Uint8Array> {
  const reader = response.body?.getReader();
  if (reader === undefined) return;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) return;
      yield next.value;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

/** A static library's handshake: one with `static` (SPEC.md § 21.2). */
export function isStatic(hello: Handshake): boolean {
  return hello.static !== undefined;
}

/**
 * A static library read as a client reads a server (SPEC.md § 21.3): its
 * handshake, pages, titles, homebrew and cheat sets, and its files checked by
 * their size and SHA-256. A document of a newer schema throws NewerSchema
 * (treat it as absent), one not of its form DocumentError.
 */
export class StaticLibrary {
  readonly source: StaticSource;
  readonly hello: Handshake;
  readonly hash: HasherFactory;

  private constructor(source: StaticSource, hello: Handshake, hash: HasherFactory) {
    this.source = source;
    this.hello = hello;
    this.hash = hash;
  }

  /** Reads a static library's `lantern.json`; an address gives an HttpStaticSource. */
  static async open(source: StaticSource | string, options: { hash?: HasherFactory } = {}): Promise<StaticLibrary> {
    const src = typeof source === "string" ? new HttpStaticSource(source) : source;
    const hello = await StaticLibrary.document(src, HANDSHAKE, models.readHandshake);
    if (hello === undefined) throw new UnexpectedResponse(`${src.describe}: no ${HANDSHAKE}`, 404);
    if (!isStatic(hello)) throw new DocumentError("a handshake without static: not a static library", HANDSHAKE);
    if (!hello.versions.includes(1)) throw new LanternError("the library does not follow version 1 of the protocol");
    return new StaticLibrary(src, hello, options.hash ?? sha256Factory);
  }

  static async document<T>(source: StaticSource, rel: string, check: Check<T>): Promise<T | undefined> {
    const raw = await source.read(rel, JSON_DOCUMENT);
    if (raw === undefined) return undefined;
    const doc = loadJson(raw, { where: rel });
    const schema = schemaOf(doc, rel);
    if (schema > SCHEMA) throw new NewerSchema(rel, schema);
    return check(doc, rel);
  }

  /** When its files were written: a client reads its pages again when this changed (§ 21.3). */
  get generated(): string {
    return this.hello.static?.generated ?? "";
  }

  get platforms(): string[] {
    return this.hello.platforms;
  }

  #platform(platform: string): string {
    if (!isPlatform(platform)) throw new RangeError(`${platform} is not a platform's name`);
    return platform;
  }

  async *#pages<P, I>(
    kind: "apps" | "titles" | "homebrew",
    platform: string,
    check: Check<P>,
    items: (page: P) => I[],
    next: (page: P) => string | null | undefined,
  ): AsyncGenerator<I> {
    if (!this.hello.platforms.includes(platform)) return;
    for (let n = 1; ; n++) {
      const rel = layoutPath(kind, { platform: this.#platform(platform), page: n });
      const page = await StaticLibrary.document(this.source, rel, check);
      if (page === undefined) {
        if (n === 1) return; // a family it does not have
        throw new DocumentError(`page ${n - 1} points at page ${n}, which is not there`, rel);
      }
      yield* items(page);
      const following = next(page);
      if (following === null || following === undefined) return;
      if (following !== String(n + 1))
        throw new DocumentError(`next is ${JSON.stringify(following)}, not "${n + 1}"`, rel);
      if (n >= 100000) throw new DocumentError("too many pages", rel);
    }
  }

  #checkFile(file: string, where: string): void {
    if (!relativeOk(file))
      throw new DocumentError(`${JSON.stringify(file.slice(0, 80))} is not a path below the root`, where);
  }

  /** Every app of a platform. */
  async *apps(platform: string): AsyncGenerator<App> {
    for await (const app of this.#pages<AppsPage, App>(
      "apps",
      platform,
      models.readAppsPage,
      (p) => p.items,
      (p) => p.next,
    )) {
      this.#checkFile(app.file, `app ${app.id}`);
      yield app;
    }
  }

  /** Every title of a platform. */
  titles(platform: string): AsyncGenerator<Title> {
    return this.#pages<Titles, Title>(
      "titles",
      platform,
      models.readTitles,
      (p) => p.titles,
      (p) => p.next,
    );
  }

  /** A title, or undefined. */
  title(platform: string, titleId: string): Promise<Title | undefined> {
    return StaticLibrary.document(
      this.source,
      layoutPath("title", { platform: this.#platform(platform), id: titleId }),
      models.readTitle,
    );
  }

  /** Every homebrew entry of a platform, as its listing gives it (without manifests). */
  async *homebrew(platform: string): AsyncGenerator<Homebrew> {
    for await (const entry of this.#pages<HomebrewPage, Homebrew>(
      "homebrew",
      platform,
      models.readHomebrewPage,
      (p) => p.items,
      (p) => p.next,
    )) {
      for (const p of [entry.package, ...(entry.packages ?? [])]) this.#checkFile(p.file, `homebrew ${entry.id}`);
      yield entry;
    }
  }

  /** A homebrew entry, with its manifests, or undefined. */
  async homebrewEntry(platform: string, id: string): Promise<Homebrew | undefined> {
    const entry = await StaticLibrary.document(
      this.source,
      layoutPath("entry", { platform: this.#platform(platform), id }),
      models.readHomebrew,
    );
    if (entry !== undefined)
      for (const p of [entry.package, ...(entry.packages ?? [])]) this.#checkFile(p.file, `homebrew ${entry.id}`);
    return entry;
  }

  /** A title's cheat sets (none when it has no file of them). */
  async cheats(platform: string, titleId: string): Promise<CheatSet[]> {
    const doc = await StaticLibrary.document<CheatSets>(
      this.source,
      layoutPath("cheats", { platform: this.#platform(platform), id: titleId }),
      models.readCheatSets,
    );
    return doc?.cheats ?? [];
  }

  /** A cheat set's text, checked by its size and SHA-256. */
  async cheatText(cheat: CheatSet): Promise<string> {
    if (cheat.size > CHEAT_SET) throw new DocumentError(`a cheat set is ${CHEAT_SET} bytes at most`);
    const sink = new MemorySink();
    await this.download({ file: layoutPath("cheat", { id: cheat.id }), sha256: cheat.sha256, size: cheat.size }, sink);
    return new TextDecoder("utf-8", { fatal: true }).decode(sink.bytes());
  }

  /**
   * What a device of `platform` is missing (SPEC.md § 6.3), computed over the
   * whole listing as a server would (L-21.3-2): `installed` as [app_id, version_code].
   */
  async missing(
    platform: string,
    installed: Iterable<[string, number]>,
    want: Iterable<string> = ["update", "dlc"],
  ): Promise<App[]> {
    const apps: App[] = [];
    for await (const app of this.apps(platform)) apps.push(app);
    const found = missing(apps, platform, [...installed], new Set(want));
    const byName = (a: App, b: App): number => {
      const x = (a.name ?? "").toLowerCase();
      const y = (b.name ?? "").toLowerCase();
      return x < y ? -1 : x > y ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    };
    return found.sort(byName);
  }

  /** The homebrew of `platform` newer than what is installed (SPEC.md § 8.5), by `build`. */
  async homebrewUpdates(platform: string, installed: Iterable<[string, number]>): Promise<Homebrew[]> {
    const builds = new Map<string, number>();
    for (const [id, build] of installed) builds.set(id, Math.max(builds.get(id) ?? -1, build));
    const out: Homebrew[] = [];
    for await (const entry of this.homebrew(platform)) {
      const have = builds.get(entry.id);
      if (have !== undefined && entry.build > have) out.push(entry);
    }
    return out;
  }

  /**
   * A file of the library (`file`, relative to the root) into `sink`, checked
   * as it arrives: more bytes than its size, or another SHA-256, throw
   * IntegrityError and empty the sink; it is committed only once whole.
   */
  async download(doc: { file: string; sha256: string; size: number }, sink: DownloadSink): Promise<void> {
    this.#checkFile(doc.file, "file");
    const verifier = new Verifier(doc.sha256, doc.size, doc.file);
    await sink.reset();
    const stream = await this.source.stream(doc.file);
    if (stream === undefined) throw new UnexpectedResponse(`${doc.file}: not in the library`, 404);
    const hasher = this.hash();
    try {
      for await (const chunk of stream) {
        verifier.feed(hasher, chunk);
        await sink.append(chunk);
      }
      verifier.finish(hasher);
    } catch (e) {
      await sink.reset();
      throw e;
    }
    await sink.commit();
  }

  /** An app's file. */
  downloadApp(app: App, sink: DownloadSink): Promise<void> {
    return this.download(app, sink);
  }
}
