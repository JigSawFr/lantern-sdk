/**
 * The Node transport: node:http and node:https, with the server's key pinned
 * (SPEC.md § 5.3). Each TLS connection is made by this transport's own agent,
 * which reads the certificate's key once the handshake is done and before a
 * byte of the request is written: a key other than the one pinned closes the
 * connection, and the request fails with PinMismatch, nothing sent.
 *
 * Why not `checkServerIdentity`: Node calls it only for a chain its CA store
 * accepted, and not on a resumed session; a LAN server's self-signed key never
 * reaches it. The agent does the check itself, on `secureConnect`.
 */

import { createHash, type X509Certificate } from "node:crypto";
import * as http from "node:http";
import * as https from "node:https";
import { isIP } from "node:net";
import type { Duplex } from "node:stream";
import * as tls from "node:tls";
import {
  describe,
  type SendOptions,
  type Transport,
  type TransportRequest,
  type TransportResponse,
} from "../client/transport.ts";
import { PinMismatch, TransportError } from "../errors.ts";
import { SHA256_HEX } from "../spki.ts";

const SPKI = Symbol("lantern.spki");

type PinnedSocket = tls.TLSSocket & { [SPKI]?: string };

/** The fingerprint of a connection's key: the SHA-256 of its certificate's SPKI, hex. */
export function socketSpki(socket: tls.TLSSocket): string | undefined {
  const cert: X509Certificate | undefined = socket.getPeerX509Certificate();
  if (cert === undefined) return undefined;
  const der = cert.publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

export interface NodeTransportOptions {
  /** false: a server no CA vouches for, whose key the client reads to pin it (pairing, SPEC.md § 5.3). */
  verify?: boolean;
  /** The key pinned (SHA-256 of its SPKI, hex): every connection is over it, or fails. */
  pin?: string;
  /** CA certificates to trust beyond the system's (PEM). */
  ca?: string | Buffer | (string | Buffer)[];
  /** Keep connections open between requests (true by default). */
  keepAlive?: boolean;
}

/** Sends requests with node:http and node:https; pins a LAN server's key. */
export class NodeTransport implements Transport {
  verify: boolean;
  pin: string | undefined;
  readonly #http: http.Agent;
  readonly #https: https.Agent;

  constructor(options: NodeTransportOptions = {}) {
    if (options.pin !== undefined && !SHA256_HEX.test(options.pin.toLowerCase())) {
      throw new RangeError("pin is the SHA-256 of the server key's SPKI, hex");
    }
    this.verify = options.verify ?? true;
    this.pin = options.pin?.toLowerCase();
    const keepAlive = options.keepAlive ?? true;
    this.#http = new http.Agent({ keepAlive });
    const transport = this;
    const base: https.AgentOptions = { keepAlive, maxCachedSessions: 0 };
    if (options.ca !== undefined) base.ca = options.ca;
    class PinningAgent extends https.Agent {
      override createConnection(
        connect: tls.ConnectionOptions,
        callback?: (err: Error | null, socket: Duplex) => void,
      ): Duplex | undefined {
        const pinned = transport.pin;
        const strict = transport.verify && pinned === undefined;
        const tlsOptions: tls.ConnectionOptions = { ...connect, rejectUnauthorized: strict };
        if (typeof tlsOptions.servername !== "string" || tlsOptions.servername === "" || isIP(tlsOptions.servername)) {
          delete tlsOptions.servername;
        }
        if (typeof connect.host === "string" && isIP(connect.host) === 0 && tlsOptions.servername === undefined) {
          tlsOptions.servername = connect.host;
        }
        const socket: PinnedSocket = tls.connect(tlsOptions);
        let done = false;
        const finish = (err: Error | null): void => {
          if (done) return;
          done = true;
          if (err !== null) {
            socket.destroy();
            callback?.(err, socket);
          } else callback?.(null, socket);
        };
        socket.once("secureConnect", () => {
          const seen = socketSpki(socket);
          if (seen !== undefined) socket[SPKI] = seen;
          if (pinned !== undefined && seen !== pinned) {
            finish(new PinMismatch(seen ?? "0".repeat(64), pinned, `${connect.host ?? ""}:${connect.port ?? ""}`));
            return;
          }
          finish(null);
        });
        socket.once("error", (e) => finish(e));
        return undefined;
      }
    }
    this.#https = new PinningAgent(base);
  }

  /** A key seen without a CA to vouch for it is the one requests go over from then on (L-5.3-4). */
  pinSeen(spki: string): void {
    if (!this.verify && this.pin === undefined) this.pin = spki.toLowerCase();
  }

  send(request: TransportRequest, options: SendOptions): Promise<TransportResponse> {
    const url = new URL(request.url);
    const secure = url.protocol === "https:";
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => {
      headers[key] = value;
    });
    if (request.body !== undefined) headers["content-length"] = String(request.body.length);
    const ms = Math.max(1, options.timeout * 1000);
    return new Promise((resolve, reject) => {
      const req = (secure ? https : http).request(url, {
        method: request.method,
        headers,
        agent: secure ? this.#https : this.#http,
      });
      req.setTimeout(ms, () =>
        req.destroy(new TransportError(`${request.method} ${request.url}: no answer within ${options.timeout} s`)),
      );
      req.once("error", (e) => {
        if (e instanceof PinMismatch || e instanceof TransportError) reject(e);
        else reject(new TransportError(`${request.method} ${request.url}: ${describe(e)}`, { cause: e }));
      });
      req.once("response", (res) => {
        const h = new Headers();
        for (const [k, v] of Object.entries(res.headers)) {
          if (v === undefined) continue;
          for (const one of Array.isArray(v) ? v : [v]) h.append(k, one);
        }
        const socket = res.socket as PinnedSocket | null;
        let used = false;
        resolve({
          status: res.statusCode ?? 0,
          headers: h,
          spki: socket?.[SPKI],
          body: () => {
            if (used) throw new Error("a body is read once");
            used = true;
            return chunks(res);
          },
          cancel: async () => {
            if (!res.complete) res.destroy();
          },
        });
      });
      req.end(
        request.body !== undefined
          ? Buffer.from(request.body.buffer, request.body.byteOffset, request.body.byteLength)
          : undefined,
      );
    });
  }

  close(): void {
    this.#http.destroy();
    this.#https.destroy();
  }
}

async function* chunks(res: http.IncomingMessage): AsyncGenerator<Uint8Array> {
  try {
    for await (const chunk of res) {
      const b = chunk as Buffer;
      yield new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    }
  } catch (e) {
    throw new TransportError(`the connection failed: ${describe(e)}`, { cause: e });
  }
  if (!res.complete) throw new TransportError("the connection closed before the whole body");
}
