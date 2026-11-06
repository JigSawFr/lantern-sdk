/**
 * lantern-protocol/node: what only Node can do. A client over NodeTransport
 * (the server's key pinned, SHA-256 by node:crypto, device keys whose seed a
 * file store keeps), downloads to files through a `.part` resumed with a
 * Range, uploads from files, the stores of servers and homebrew keys as JSON
 * files (by the `schema` rule), and LAN discovery on UDP 47115.
 */

import { createHash } from "node:crypto";
import * as dgram from "node:dgram";
import { createReadStream } from "node:fs";
import { chmod, type FileHandle, mkdir, open, readFile, rename, stat, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { isObject, type JSONObject, LanternError, SCHEMA } from "../base.ts";
import {
  type ClientOptions,
  type DownloadOptions,
  LanternClient,
  type SourceOptions,
  type UploadOptions,
} from "../client/client.ts";
import type { DownloadSink, UploadSource } from "../client/download.ts";
import { type Found, PEERS_REQUEST, PORT, REQUEST, readPeerReply, readReply } from "../discovery.ts";
import {
  Browse,
  instanceQuestion,
  MDNS_ADDRESS,
  MDNS_PORT,
  PEER_SERVICE,
  PTR,
  question,
  SERVER_SERVICE,
} from "../dnssd.ts";
import type { App, Package, Save } from "../generated/models.ts";
import type { FileHashes } from "../homebrew.ts";
import { DATAGRAM, loadJson } from "../limits.ts";
import type { Peer } from "../peers.ts";
import { type KeyPins, readServerRecord, type ServerRecord, type ServerStore } from "../pinning.ts";
import { nodeSha256 } from "./hash.ts";
import { NodeTransport, type NodeTransportOptions } from "./transport.ts";

export { NodeTransport, type NodeTransportOptions, socketSpki } from "./transport.ts";

export { nodeSha256 };

/** The hashes a client compares a port's data file with, for launchCheck() (SPEC.md § 8.6). */
export function fileHashes(data: Uint8Array): FileHashes {
  return {
    sha256: createHash("sha256").update(data).digest("hex"),
    sha1: createHash("sha1").update(data).digest("hex"),
    md5: createHash("md5").update(data).digest("hex"),
  };
}

/** The SHA-256 of a file, read in chunks; of its first `limit` bytes only when given. */
export async function sha256File(path: string, limit?: number): Promise<string> {
  const h = createHash("sha256");
  if (limit === 0) return h.digest("hex");
  const options = limit !== undefined ? { end: limit - 1 } : {};
  for await (const chunk of createReadStream(path, options)) h.update(chunk as Buffer);
  return h.digest("hex");
}

/**
 * A download into `dest` through `dest + ".part"`: resumed from what the part
 * holds, renamed to `dest` once the client checked it whole, deleted when it is
 * not its document's.
 */
export class FileSink implements DownloadSink {
  readonly dest: string;
  readonly part: string;
  #handle: FileHandle | undefined;

  constructor(dest: string) {
    this.dest = dest;
    this.part = `${dest}.part`;
  }

  async *held(): AsyncIterable<Uint8Array> {
    try {
      for await (const chunk of createReadStream(this.part)) yield chunk as Buffer;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
  }

  async heldSize(): Promise<number> {
    try {
      return (await stat(this.part)).size;
    } catch {
      return 0;
    }
  }

  async append(chunk: Uint8Array): Promise<void> {
    if (this.#handle === undefined) {
      await mkdir(dirname(this.part), { recursive: true });
      this.#handle = await open(this.part, "a");
    }
    await this.#handle.write(chunk);
  }

  async #close(): Promise<void> {
    const h = this.#handle;
    this.#handle = undefined;
    await h?.close();
  }

  async reset(): Promise<void> {
    await this.#close();
    await unlink(this.part).catch(() => undefined);
  }

  async commit(): Promise<void> {
    await this.#close();
    try {
      await rename(this.part, this.dest);
    } catch (e) {
      // A file of size 0 never had a chunk appended: make it.
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      await mkdir(dirname(this.dest), { recursive: true });
      await writeFile(this.dest, new Uint8Array());
    }
  }

  /** `dest + ".seed"`: the part a differential download set aside to take chunks from (see takeLeftover()). */
  get seed(): string {
    return `${this.dest}.seed`;
  }

  async #sizeOf(path: string): Promise<number> {
    try {
      return (await stat(path)).size;
    } catch {
      return 0;
    }
  }

  async leftoverSize(): Promise<number> {
    return Math.max(await this.#sizeOf(this.part), await this.#sizeOf(this.seed));
  }

  /**
   * The part, or the `.seed` an interrupted resume left (the larger when both exist; the other is deleted), moved
   * to `.seed` and read: a verified prefix of the file, or bytes of no use that the chunks' SHA-256 will not
   * accept. Undefined when there is none, or it is over `max` bytes. `releaseLeftover()` deletes the `.seed`.
   */
  async takeLeftover(max: number): Promise<Uint8Array | undefined> {
    await this.#close();
    const [part, seed] = [await this.#sizeOf(this.part), await this.#sizeOf(this.seed)];
    if (part >= seed && part > 0)
      await rename(this.part, this.seed); // replaces a smaller .seed
    else await unlink(this.part).catch(() => undefined); // empty, or smaller than the .seed
    if (Math.max(part, seed) === 0 || Math.max(part, seed) > max) return undefined;
    return new Uint8Array(await readFile(this.seed));
  }

  async releaseLeftover(restore: boolean): Promise<void> {
    if (restore && (await this.#sizeOf(this.part)) === 0) {
      try {
        await rename(this.seed, this.part);
        return;
      } catch {
        // no .seed: nothing to put back
      }
    }
    await unlink(this.seed).catch(() => undefined);
  }

  /** Closes the part's file (after a TransportError, before trying again). */
  async close(): Promise<void> {
    await this.#close();
  }
}

/** An upload from a file. */
export async function fileSource(path: string): Promise<UploadSource> {
  const size = (await stat(path)).size;
  return {
    size,
    read: async (offset, length) => {
      const h = await open(path, "r");
      try {
        const out = new Uint8Array(length);
        const { bytesRead } = await h.read(out, 0, length, offset);
        return out.subarray(0, bytesRead);
      } finally {
        await h.close();
      }
    },
  };
}

/** The `node` entry's client: NodeTransport (pin, verify), node:crypto's SHA-256, and files. */
export class NodeLanternClient extends LanternClient {
  constructor(url: string, options: ClientOptions & { ca?: NodeTransportOptions["ca"] } = {}) {
    const { ca, ...rest } = options;
    super(url, {
      hash: nodeSha256,
      extractableKeys: true,
      transportFactory: (o) => {
        const t: NodeTransportOptions = { verify: o.verify };
        if (o.pin !== undefined) t.pin = o.pin;
        if (ca !== undefined) t.ca = ca;
        return new NodeTransport(t);
      },
      // Mirrors and peers: never the server's pinned key; a peer's HTTPS is checked by the file's hash (§ 19.4).
      elsewhere: (o) => new NodeTransport({ verify: o.verify, keepAlive: false }),
      ...rest,
    });
  }

  /** Downloads a file to `dest`, through `dest + ".part"` (see FileSink); gives `dest`. */
  async downloadToFile(url: string, dest: string, options: DownloadOptions): Promise<string> {
    const sink = new FileSink(dest);
    try {
      await this.download(url, sink, options);
    } finally {
      await sink.close();
    }
    return dest;
  }

  /** An app's file to `dest`, from its peers or mirrors when asked (SPEC.md § 19), else the server; checked whole. */
  async downloadAppTo(
    app: App,
    dest: string,
    options: Omit<DownloadOptions, "sha256" | "size"> & SourceOptions = {},
  ): Promise<string> {
    const sink = new FileSink(dest);
    try {
      await this.downloadFile(app, sink, options);
    } finally {
      await sink.close();
    }
    return dest;
  }

  async downloadPackageTo(
    p: Package,
    dest: string,
    options: Omit<DownloadOptions, "sha256" | "size"> & SourceOptions = {},
  ): Promise<string> {
    const sink = new FileSink(dest);
    try {
      await this.downloadFile(p, sink, options);
    } finally {
      await sink.close();
    }
    return dest;
  }

  async downloadSaveTo(
    save: Save,
    dest: string,
    options: Omit<DownloadOptions, "sha256" | "size"> = {},
  ): Promise<string> {
    const sink = new FileSink(dest);
    try {
      await this.downloadSave(save, sink, options);
    } finally {
      await sink.close();
    }
    return dest;
  }

  /** A save from a file, by resumable upload (SPEC.md § 9.3). */
  async uploadSaveFile(titleId: string, path: string, options: UploadOptions = {}): Promise<Save> {
    return this.uploadSave(titleId, await fileSource(path), options);
  }
}

// Files kept by the `schema` rule (SPEC.md § 3.2).

/** The file holds a newer `schema` than this program writes: it is left as it is. */
export class NewerOnDisk extends LanternError {
  override name = "NewerOnDisk";
}

async function readRaw(path: string): Promise<JSONObject | undefined> {
  let raw: Buffer;
  try {
    raw = await readFile(path);
  } catch {
    return undefined;
  }
  try {
    const doc = loadJson(raw, { where: path });
    const schema = isObject(doc) ? doc["schema"] : undefined;
    return isObject(doc) && typeof schema === "number" && Number.isInteger(schema) ? (doc as JSONObject) : undefined;
  } catch {
    return undefined;
  }
}

/** The file's document; undefined when it is absent, unreadable, without a `schema`, or of a newer one than `known`. */
export async function loadDocument(path: string, known: number = SCHEMA): Promise<JSONObject | undefined> {
  const doc = await readRaw(path);
  const schema = doc?.["schema"];
  return typeof schema === "number" && schema >= 1 && schema <= known ? doc : undefined;
}

/**
 * Writes `document` to `path`, atomically, keeping the keys of the file already
 * there that `document` lacks. NewerOnDisk when that file is of a newer schema
 * than `known`: it is never written over.
 */
export async function saveDocument(
  path: string,
  document: JSONObject,
  options: { known?: number; mode?: number } = {},
): Promise<void> {
  const known = options.known ?? SCHEMA;
  const current = await readRaw(path);
  let out: JSONObject = { ...document };
  if (current !== undefined) {
    const schema = current["schema"];
    if (typeof schema === "number" && schema > known)
      throw new NewerOnDisk(`${path}: schema ${schema}, newer than ${known}: left as it is`);
    out = { ...Object.fromEntries(Object.entries(current).filter(([k]) => !(k in document))), ...document };
  }
  if (!("schema" in out)) out = { schema: known, ...out };
  await mkdir(dirname(path), { recursive: true });
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}.tmp`);
  try {
    await writeFile(tmp, `${JSON.stringify(out, null, 1)}\n`, { mode: options.mode ?? 0o600 });
    await rename(tmp, path);
  } catch (e) {
    await unlink(tmp).catch(() => undefined);
    throw e;
  }
}

/**
 * Servers kept in a JSON file, readable by its owner alone: {"schema": 1,
 * "servers": {"<uid>": {…}}}. A file of a newer schema is read as absent and
 * never written over (save() throws NewerOnDisk); keys this library does not
 * know, the file's and each record's, are kept.
 */
export class FileServerStore implements ServerStore {
  readonly path: string;
  #queue: Promise<unknown> = Promise.resolve();

  constructor(path: string) {
    this.path = path;
  }

  async #records(): Promise<Record<string, unknown>> {
    const servers = (await loadDocument(this.path))?.["servers"];
    return isObject(servers) ? servers : {};
  }

  async server(uid: string): Promise<ServerRecord | undefined> {
    return readServerRecord((await this.#records())[uid]);
  }

  async servers(): Promise<ServerRecord[]> {
    return Object.values(await this.#records())
      .map(readServerRecord)
      .filter((r): r is ServerRecord => r !== undefined);
  }

  #update(uid: string, value: ServerRecord | undefined): Promise<void> {
    const run = this.#queue.then(async () => {
      const doc = (await loadDocument(this.path)) ?? { schema: SCHEMA, servers: {} };
      const servers = isObject(doc["servers"]) ? { ...(doc["servers"] as JSONObject) } : {};
      if (value === undefined) delete servers[uid];
      else servers[uid] = value as unknown as JSONObject;
      await saveDocument(this.path, { ...doc, servers });
      await chmod(this.path, 0o600).catch(() => undefined);
    });
    this.#queue = run.catch(() => undefined);
    return run;
  }

  save(record: ServerRecord): Promise<void> {
    return this.#update(record.uid, record);
  }

  forget(uid: string): Promise<void> {
    return this.#update(uid, undefined);
  }
}

/** Homebrew keys kept in a JSON file: {"schema": 1, "pins": {"<platform>/<id>": "<key>"}}, by the same rule. */
export class FileKeyPins implements KeyPins {
  readonly path: string;
  #queue: Promise<unknown> = Promise.resolve();

  constructor(path: string) {
    this.path = path;
  }

  async pinned(platform: string, homebrewId: string): Promise<string | undefined> {
    const pins = (await loadDocument(this.path))?.["pins"];
    const value = isObject(pins) ? pins[`${platform}/${homebrewId}`] : undefined;
    return typeof value === "string" ? value : undefined;
  }

  #update(key: string, value: string | undefined): Promise<void> {
    const run = this.#queue.then(async () => {
      const doc = (await loadDocument(this.path)) ?? { schema: SCHEMA, pins: {} };
      const pins = isObject(doc["pins"]) ? { ...(doc["pins"] as JSONObject) } : {};
      if (value === undefined) delete pins[key];
      else pins[key] = value;
      await saveDocument(this.path, { ...doc, pins });
    });
    this.#queue = run.catch(() => undefined);
    return run;
  }

  pin(platform: string, homebrewId: string, publicKey: string): Promise<void> {
    return this.#update(`${platform}/${homebrewId}`, publicKey);
  }

  forget(platform: string, homebrewId: string): Promise<void> {
    return this.#update(`${platform}/${homebrewId}`, undefined);
  }
}

// LAN discovery (SPEC.md § 4.1).

/**
 * Sends the discovery datagram to each of `addresses` (directed broadcasts, or
 * a server's own address) and gathers the replies for `timeout` seconds; each
 * server once, by uid and address. A reply is a hint, never a proof.
 */
export function discover(
  addresses: readonly string[] = ["255.255.255.255"],
  options: { port?: number; timeout?: number } = {},
): Promise<Found[]> {
  return gather(addresses, REQUEST, readReply, options);
}

/**
 * Asks the peers of the network (SPEC.md § 19.5): the datagram with
 * `"peers": true`, and the replies of consoles that share files, each once.
 * `server`, a server's uid, keeps those that take its grants. A client asks at
 * most once a minute (L-19.5-2); a reply is a hint.
 */
export async function discoverPeers(
  addresses: readonly string[] = ["255.255.255.255"],
  options: { port?: number; timeout?: number; server?: string } = {},
): Promise<Peer[]> {
  const found = await gather(addresses, PEERS_REQUEST, readPeerReply, options);
  return options.server === undefined ? found : found.filter((p) => p.servers.includes(options.server as string));
}

async function gather<T extends { uid: string; address: string }>(
  addresses: readonly string[],
  request: Uint8Array,
  read: (data: Uint8Array, address: string) => T | undefined,
  options: { port?: number; timeout?: number },
): Promise<T[]> {
  const port = options.port ?? PORT;
  const socket = dgram.createSocket("udp4");
  const found = new Map<string, T>();
  socket.on("message", (data, remote) => {
    if (data.length > DATAGRAM) return;
    const reply = read(new Uint8Array(data), remote.address);
    if (reply !== undefined && !found.has(`${reply.uid} ${reply.address}`))
      found.set(`${reply.uid} ${reply.address}`, reply);
  });
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, () => {
      socket.off("error", reject);
      resolve();
    });
  });
  try {
    socket.setBroadcast(true);
    for (const address of addresses) {
      await new Promise<void>((resolve, reject) =>
        socket.send(request, port, address, (e) => (e ? reject(e) : resolve())),
      );
    }
    await new Promise((r) => setTimeout(r, (options.timeout ?? 2) * 1000));
  } finally {
    socket.close();
  }
  return [...found.values()];
}

/** What a browse of multicast DNS takes: the group and port to ask (the defaults are RFC 6762's) and how long to listen, in seconds. */
export interface BrowseOptions {
  address?: string;
  port?: number;
  timeout?: number;
}

/**
 * The servers advertised with DNS-SD as `_lantern._tcp` (SPEC.md § 4.1): a
 * single question to the multicast group from a port of the client's own,
 * which responders answer straight back (RFC 6762 § 6.7), so no group is
 * joined. Each server once, by uid. The advertisement is a hint, never a proof;
 * a network that does not carry multicast, or a responder that ignores such a
 * question, is the datagram's (`discover()`).
 */
export function browseDnssd(options: BrowseOptions = {}): Promise<Found[]> {
  return browse(SERVER_SERVICE, options).then((b) => b.servers());
}

/**
 * The peers advertised as `_lantern-peer._tcp` (SPEC.md § 19.5), as `browseDnssd()` asks.
 * `server`, a server's uid, keeps those that take its grants.
 */
export async function browseDnssdPeers(options: BrowseOptions & { server?: string } = {}): Promise<Peer[]> {
  const peers = (await browse(PEER_SERVICE, options)).peers();
  return options.server === undefined ? peers : peers.filter((p) => p.servers.includes(options.server as string));
}

async function browse(service: string, options: BrowseOptions): Promise<Browse> {
  const address = options.address ?? MDNS_ADDRESS;
  const port = options.port ?? MDNS_PORT;
  const wait = (options.timeout ?? 2) * 1000;
  const socket = dgram.createSocket("udp4");
  const seen = new Browse(service);
  socket.on("message", (data, remote) => seen.add(new Uint8Array(data), remote.address));
  const send = (message: Uint8Array): Promise<void> =>
    new Promise<void>((resolve, reject) => socket.send(message, port, address, (e) => (e ? reject(e) : resolve())));
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, () => {
      socket.off("error", reject);
      resolve();
    });
  });
  try {
    await send(question(service, PTR));
    // An answer that came without an instance's port or TXT: ask for them once
    await new Promise((r) => setTimeout(r, wait / 3));
    for (const instance of seen.incomplete()) await send(instanceQuestion(instance));
    await new Promise((r) => setTimeout(r, (wait * 2) / 3));
  } finally {
    socket.close();
  }
  return seen;
}

export { directedBroadcast, type Found, readPeerReply, readReply } from "../discovery.ts";
export { decryptSaveFile } from "./saves.ts";
export { clientInput, FileStaticSource, libraryInput, type StaticInput, StaticWriter, writeStatic } from "./static.ts";
