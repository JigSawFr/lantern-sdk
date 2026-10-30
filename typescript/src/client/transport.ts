/**
 * How a request reaches the server: built by the client, given its
 * credentials and its signature (for the server's origin only, SPEC.md § 2),
 * then sent by a Transport.
 *
 * - `FetchTransport`: the platform's fetch(), in a browser and in Node. It
 *   follows no redirect, sends no cookie, and cannot pin a key: a browser
 *   trusts its CA store alone, and Node's fetch takes no TLS options without
 *   the undici package. Pinning a LAN server's key is NodeTransport's
 *   (`lantern-protocol/node`).
 * - any object with the same `send()`.
 */

import { DocumentError } from "../base.ts";
import { TransportError, UnexpectedResponse } from "../errors.ts";
import { type Origin, onOrigin } from "../http.ts";
import type { DeviceKey } from "../signatures.ts";
import { newNonce, signRequest } from "../signatures.ts";

/** A request, as a transport sends it. */
export interface TransportRequest {
  method: string;
  url: string;
  headers: Headers;
  body?: Uint8Array | undefined;
}

/** An answer: its status and headers, and its body, read once. */
export interface TransportResponse {
  status: number;
  headers: Headers;
  /** The fingerprint (SHA-256 of the SPKI, hex) of the TLS key it came over, when the transport can tell. */
  spki?: string | undefined;
  /** The body, chunk by chunk; a TransportError when the connection fails under it. */
  body(): AsyncIterable<Uint8Array>;
  /** Drops what is left of the body. */
  cancel(): Promise<void>;
}

export interface SendOptions {
  /** Seconds to wait for the answer's headers, then between two chunks of its body. */
  timeout: number;
}

/** Sends requests. `pinSeen()` pins a key seen without a CA to vouch for it, when the transport can (L-5.3-4). */
export interface Transport {
  send(request: TransportRequest, options: SendOptions): Promise<TransportResponse>;
  pinSeen?(spki: string): void;
  close?(): void | Promise<void>;
}

/** Gives a request its credentials: `Authorization: Bearer <token>` by default (BearerToken). */
export interface Credentials {
  apply(request: TransportRequest): void;
}

/** Signs a request (DeviceSigner): SPEC.md § 5.4. */
export interface RequestSigner {
  sign(request: TransportRequest): Promise<void>;
}

/** `Authorization: Bearer <token>` (SPEC.md § 5.1). */
export class BearerToken implements Credentials {
  readonly #token: string;
  constructor(token: string) {
    if (!token || /\s/.test(token) || [...token].some((c) => c.charCodeAt(0) < 32))
      throw new RangeError("a token is opaque text without spaces");
    this.#token = token;
  }
  apply(request: TransportRequest): void {
    request.headers.set("Authorization", `Bearer ${this.#token}`);
  }
  toString(): string {
    return "BearerToken(…)";
  }
}

/**
 * Signs each request with the device key (SPEC.md § 5.4): `@method`,
 * `@target-uri`, then `authorization` when it carries a token and
 * `content-digest` when it has a body. `clock` gives the time to sign with, in
 * Unix seconds: the client's, corrected by its offset to the server's Date.
 */
export class DeviceSigner implements RequestSigner {
  readonly key: DeviceKey;
  readonly clock: () => number;
  constructor(key: DeviceKey, clock: () => number = () => Date.now() / 1000) {
    this.key = key;
    this.clock = clock;
  }
  async sign(request: TransportRequest): Promise<void> {
    await signRequest(this.key, request.method, request.url, request.headers, request.body, {
      created: Math.trunc(this.clock()),
      nonce: newNonce(),
    });
  }
}

/**
 * The step between a request and its transport: credentials and the signer,
 * for the server's origin alone (L-2-8, L-7.1-4). A request elsewhere (a file
 * a document points at on another host) goes without either.
 */
export class Pipeline {
  readonly server: Origin;
  credentials: Credentials | undefined;
  signer: RequestSigner | undefined;

  constructor(server: Origin, credentials?: Credentials, signer?: RequestSigner) {
    this.server = server;
    this.credentials = credentials;
    this.signer = signer;
  }

  async prepare(request: TransportRequest): Promise<TransportRequest> {
    if (!onOrigin(request.url, this.server)) {
      request.headers.delete("Authorization");
      return request;
    }
    this.credentials?.apply(request);
    if (this.signer !== undefined) await this.signer.sign(request);
    return request;
  }
}

/** A body read whole, `limit` bytes at most: DocumentError beyond it (the rest is dropped). */
export async function readBody(response: TransportResponse, limit: number, what: string): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of response.body()) {
    size += chunk.length;
    if (size > limit) {
      await response.cancel();
      throw new DocumentError(`more than ${limit} bytes`, what);
    }
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

/**
 * The platform's fetch(). It never follows a redirect (Lantern sends none: an
 * UnexpectedResponse), sends no cookie, and lets the platform handle
 * compression (a browser decides Accept-Encoding and User-Agent itself).
 */
export class FetchTransport implements Transport {
  readonly fetch: typeof globalThis.fetch;

  constructor(options: { fetch?: typeof globalThis.fetch } = {}) {
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async send(request: TransportRequest, options: SendOptions): Promise<TransportResponse> {
    const controller = new AbortController();
    const ms = Math.max(1, options.timeout * 1000);
    let timer = setTimeout(() => controller.abort(), ms);
    const arm = (): void => {
      clearTimeout(timer);
      timer = setTimeout(() => controller.abort(), ms);
    };
    let response: Response;
    try {
      const init: RequestInit = {
        method: request.method,
        headers: request.headers,
        redirect: "manual",
        credentials: "omit",
        cache: "no-store",
        signal: controller.signal,
      };
      if (request.body !== undefined) init.body = request.body as BodyInit;
      response = await this.fetch(request.url, init);
    } catch (e) {
      clearTimeout(timer);
      throw new TransportError(`${request.method} ${request.url}: ${describe(e)}`, { cause: e });
    }
    if (response.type === "opaqueredirect" || response.status === 0) {
      clearTimeout(timer);
      throw new UnexpectedResponse(`${request.url}: a redirect, which Lantern never sends`, 302);
    }
    arm();
    let used = false;
    return {
      status: response.status,
      headers: response.headers,
      body: () => {
        if (used) throw new Error("a body is read once");
        used = true;
        return chunks(response, arm, () => clearTimeout(timer));
      },
      cancel: async () => {
        clearTimeout(timer);
        try {
          await response.body?.cancel();
        } catch {
          // already closed
        }
      },
    };
  }
}

async function* chunks(response: Response, arm: () => void, done: () => void): AsyncGenerator<Uint8Array> {
  const reader = response.body?.getReader();
  if (reader === undefined) {
    done();
    return;
  }
  try {
    for (;;) {
      let next: ReadableStreamReadResult<Uint8Array>;
      try {
        next = await reader.read();
      } catch (e) {
        throw new TransportError(`the connection failed: ${describe(e)}`, { cause: e });
      }
      if (next.done) return;
      arm();
      yield next.value;
    }
  } finally {
    done();
    reader.releaseLock();
  }
}

export function describe(e: unknown): string {
  if (e instanceof Error) {
    const cause = e.cause instanceof Error ? ` (${e.cause.message})` : "";
    return `${e.message}${cause}`.slice(0, 300);
  }
  return String(e).slice(0, 300);
}
