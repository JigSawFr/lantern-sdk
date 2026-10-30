/**
 * A peer (SPEC.md § 19.4): a paired console's sharing, the files it holds
 * served to the other devices of its network, by their SHA-256, to the holders
 * of a grant of its server. Off until its user turns it on.
 *
 *     const peer = new PeerServer({ files, keys: { [hello.uid]: grantKey } });
 *     const { url } = await peer.listen({ host: "192.168.1.20" });
 *
 * One route, `GET <base>/v1/blobs/sha256/<hex>` with `Lantern-Grant`, served as
 * § 6.6 says (ranges, a strong ETag, Repr-Digest), and HEAD alike:
 *
 * - a grant that does not verify by the `peers.key` of the server it names,
 *   names another file, or expired: 403 (L-19.4-1);
 * - a file it does not hold whole, checked: 404 (L-19.4-2);
 * - an address outside its own networks: 403 (L-19.4-3);
 * - beyond `slots` downloads at once, or a few requests a second per
 *   address: 429 with Retry-After (L-19.4-4);
 * - errors as problem+json, never WWW-Authenticate: a peer takes no token (L-19.4-5).
 *
 * `peerFiles()` reads, as a client, which of a folder's files are its
 * server's apps and packages; `PeerServer.discovery()` answers the datagrams
 * that ask for peers (§ 19.5).
 */

import { randomUUID } from "node:crypto";
import * as dgram from "node:dgram";
import { createReadStream } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { isObject } from "../base.ts";
import { fromUtf8, utf8 } from "../bytes.ts";
import type { LanternClient } from "../client/client.ts";
import { DATAGRAM, NAME, printable } from "../limits.ts";
import { GRANT_HEADER, grantKey, plainHttpToPeer, verifyGrant } from "../peers.ts";
import { isLocalAddress } from "./discovery.ts";
import { FileRef, fileResponse } from "./files.ts";
import { HttpProblem, isStream, problemResponse, ServerRequest, type ServerResponse } from "./http.ts";
import { Limiter, slowDown } from "./pairing.ts";

export interface PeerOptions {
  /** The files it holds and checked, by SHA-256: each one's path and size. */
  files: ReadonlyMap<string, { path: string; size: number }>;
  /** The grant keys of the servers it paired with: {uid: their `peers.key`, 32 bytes or base64}. */
  keys: Readonly<Record<string, Uint8Array | string>>;
  /** Downloads at once, 1 to 8 (2). */
  slots?: number;
  /** Its base path (`/lantern`). */
  base?: string;
  /** What its discovery reply calls it. */
  name?: string;
  /** Its own uid (a new one by default). */
  uid?: string;
  /** Requests per address per second (10). */
  rate?: number;
  /** Its clock, Unix seconds (a grant's exp is read by it). */
  clock?: () => number;
}

const ROUTE = /^\/v1\/blobs\/sha256\/([0-9a-f]{64})$/;

/** A peer: answers its route over node:http (listen()), and discovery datagrams that ask for peers. */
export class PeerServer {
  readonly files: ReadonlyMap<string, { path: string; size: number }>;
  readonly keys: Readonly<Record<string, Uint8Array | string>>;
  readonly slots: number;
  readonly base: string;
  readonly name: string;
  readonly uid: string;
  readonly clock: () => number;
  readonly #limiter: Limiter;
  #active = 0;
  #port = 0;
  #tls = false;

  constructor(options: PeerOptions) {
    const slots = options.slots ?? 2;
    if (!Number.isInteger(slots) || slots < 1 || slots > 8) throw new RangeError("slots is 1 to 8 (SPEC.md § 19.4)");
    this.files = options.files;
    this.keys = options.keys;
    this.slots = slots;
    this.base = (options.base ?? "/lantern").replace(/\/+$/, "");
    this.name = printable(options.name ?? "Lantern peer", NAME);
    this.uid = options.uid ?? randomUUID();
    this.clock = options.clock ?? (() => Date.now() / 1000);
    this.#limiter = new Limiter(options.rate ?? 10, 1);
  }

  #problem(
    request: ServerRequest,
    status: number,
    code: string,
    detail: string,
    headers: Record<string, string> = {},
  ): ServerResponse {
    const response = problemResponse(request, new HttpProblem(status, code, detail, { headers }));
    response.headers.set("Cache-Control", "no-store");
    response.headers.delete("Vary");
    return response;
  }

  /** The answer to a request; `release()` once its body is sent (a slot is held while it is). */
  async handle(request: ServerRequest): Promise<{ response: ServerResponse; release: () => void }> {
    const none = (): void => undefined;
    if (!isLocalAddress(request.remote))
      return {
        response: this.#problem(request, 403, "forbidden", "A peer answers its own networks only."),
        release: none,
      };
    const wait = this.#limiter.hit(request.remote);
    if (wait > 0) {
      const slow = slowDown(wait, "Too many requests from this address.");
      return { response: this.#problem(request, 429, "slow_down", slow.detail ?? "", slow.headers), release: none };
    }
    if (!request.path.startsWith(`${this.base}/`))
      return {
        response: this.#problem(request, 404, "not_found", "A peer serves <base>/v1/blobs/sha256/<hex> alone."),
        release: none,
      };
    const m = ROUTE.exec(request.path.slice(this.base.length));
    if (m === null)
      return {
        response: this.#problem(request, 404, "not_found", "A peer serves <base>/v1/blobs/sha256/<hex> alone."),
        release: none,
      };
    if (request.method !== "GET" && request.method !== "HEAD") {
      const response = this.#problem(request, 405, "bad_request", "GET or HEAD.", { Allow: "GET, HEAD" });
      return { response, release: none };
    }
    const sha = m[1] as string;
    const grant = await verifyGrant(request.header(GRANT_HEADER) ?? "", this.keys, this.clock());
    if (grant === undefined || grant.sha256 !== sha) {
      const detail = "A grant of a server this peer paired with, for this file, not expired (SPEC.md § 19.4).";
      return { response: this.#problem(request, 403, "forbidden", detail), release: none };
    }
    const held = this.files.get(sha);
    if (held === undefined || held.size !== grant.size)
      return {
        response: this.#problem(request, 404, "not_found", "This peer does not hold that file."),
        release: none,
      };
    if (this.#active >= this.slots) {
      const detail = `${this.slots} downloads at once at most.`;
      return { response: this.#problem(request, 429, "slow_down", detail, { "Retry-After": "5" }), release: none };
    }
    this.#active++;
    let released = false;
    const release = (): void => {
      if (!released) this.#active--;
      released = true;
    };
    try {
      const response = fileResponse(request, new FileRef({ path: held.path, size: held.size, sha256: sha }));
      response.headers.set("Cache-Control", "no-store");
      response.headers.delete("Vary");
      return { response, release };
    } catch (e) {
      release();
      if (e instanceof HttpProblem)
        return { response: this.#problem(request, e.status, e.code, e.detail ?? "", e.headers), release: none };
      throw e;
    }
  }

  /** A node:http handler. */
  handler(): (req: http.IncomingMessage, res: http.ServerResponse) => void {
    return (req, res) => {
      req.resume();
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined) continue;
        for (const one of Array.isArray(v) ? v : [v]) headers.append(k, one);
      }
      const request = ServerRequest.fromTarget(req.method ?? "GET", req.url ?? "/", {
        headers,
        scheme: "http",
        remote: req.socket.remoteAddress ?? "",
      });
      this.handle(request).then(
        ({ response, release }) => {
          res.statusCode = response.status;
          response.headers.forEach((value, key) => {
            res.setHeader(key, value);
          });
          res.on("close", release);
          const body = response.body;
          if (body instanceof Uint8Array) res.end(body.length > 0 ? body : undefined);
          else if (isStream(body)) res.destroy();
          else {
            const stream = createReadStream(body.path, { start: body.start, end: body.start + body.length - 1 });
            stream.on("error", () => res.destroy());
            stream.pipe(res);
          }
        },
        () => res.destroy(),
      );
    };
  }

  /**
   * Serves over plain HTTP, on a loopback or private address only (a grant
   * goes nowhere else in clear, L-19.4-6); resolves with its URL and a close().
   */
  async listen(
    options: { host?: string; port?: number } = {},
  ): Promise<{ url: string; port: number; close(): Promise<void> }> {
    const host = options.host ?? "127.0.0.1";
    if (!plainHttpToPeer(host)) throw new RangeError(`${host}: a peer speaks plain HTTP on a private network only`);
    const server = http.createServer(this.handler());
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(options.port ?? 0, host, () => resolve());
    });
    const address = server.address() as AddressInfo;
    this.#port = address.port;
    this.#tls = false;
    const shown = address.family === "IPv6" ? `[${address.address}]` : address.address;
    return {
      url: `http://${shown}:${address.port}${this.base}`,
      port: address.port,
      close: () =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        }),
    };
  }

  /** Its reply to a discovery datagram (§ 19.5): only to one that asks for peers, from its own networks. */
  reply(data: Uint8Array, address: string): Uint8Array | undefined {
    if (data.length > DATAGRAM || !isLocalAddress(address)) return undefined;
    let doc: unknown;
    try {
      doc = JSON.parse(fromUtf8(data));
    } catch {
      return undefined;
    }
    if (!isObject(doc) || doc["schema"] !== 1 || doc["lantern"] !== "discover" || doc["peers"] !== true)
      return undefined;
    return utf8(
      JSON.stringify({
        schema: 1,
        lantern: "peer",
        uid: this.uid,
        name: this.name,
        port: this.#port,
        base: this.base,
        tls: this.#tls,
        slots: this.slots,
        servers: Object.keys(this.keys).sort().slice(0, 16),
      }),
    );
  }

  /** Answers discovery datagrams that ask for peers on UDP `port` (47115), a few a second per address. */
  async discovery(port = 47115, host = "0.0.0.0"): Promise<{ close(): void; port: number }> {
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    const limiter = new Limiter(5, 1);
    socket.on("message", (data, remote) => {
      const out = this.reply(new Uint8Array(data), remote.address);
      if (out !== undefined && limiter.hit(remote.address) === 0) socket.send(out, remote.port, remote.address);
    });
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(port, host, () => resolve());
    });
    return { close: () => socket.close(), port: socket.address().port };
  }
}

/**
 * Which files of `folder` a peer may share for a server: those whose SHA-256
 * and size are an app's or a homebrew package's of that server, read as a
 * client (with the device's token and key when it is private); and the
 * server's uid and grant key, for `PeerServer`'s `keys`.
 */
export async function peerFiles(
  client: LanternClient,
  folder: string,
  sha256File: (path: string) => Promise<string>,
): Promise<{ uid: string; key: Uint8Array; files: Map<string, { path: string; size: number }> }> {
  const hello = await client.handshake();
  const key = grantKey(hello.peers);
  if (key === undefined) throw new RangeError("the server gives no peers.key: it gives no grants (SPEC.md § 19.3)");
  const wanted = new Set<string>();
  if (await client.offers("library"))
    for await (const a of client.iterApps({ pageSize: 500 })) wanted.add(`${a.sha256}/${a.size}`);
  if (await client.offers("homebrew")) {
    for await (const e of client.iterHomebrew({ pageSize: 500 })) {
      for (const p of [e.package, ...(e.packages ?? [])]) wanted.add(`${p.sha256}/${p.size}`);
    }
  }
  const files = new Map<string, { path: string; size: number }>();
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.name.startsWith(".")) continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) {
        const size = (await stat(path)).size;
        const sha = await sha256File(path);
        if (wanted.has(`${sha}/${size}`)) files.set(sha, { path, size });
      }
    }
  };
  await walk(folder);
  return { uid: hello.uid, key, files };
}
