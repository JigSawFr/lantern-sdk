/**
 * LanternApp served: on node:http (`nodeHandler()`, or `listen()` for a whole
 * server), and through any framework of web Requests and Responses
 * (`fetchHandler()`: Hono, Deno, Bun, a service worker…).
 *
 *     import { createServer } from "node:http";
 *     createServer(nodeHandler(app)).listen(8080);
 *
 *     // Hono:
 *     const lantern = fetchHandler(app);
 *     hono.all("*", (c) => lantern(c.req.raw));
 */

import { createReadStream } from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import type { TLSSocket } from "node:tls";
import type { LanternApp } from "./app.ts";
import { HttpProblem, isStream, problemResponse, ServerRequest, type ServerResponse } from "./http.ts";

export interface AdapterOptions {
  /** The largest body read; above it the request is answered 413 (its body read and dropped). */
  bodyLimit?: number;
  /** The scheme clients reach the server by, when a proxy in front of it ends TLS. */
  scheme?: string;
}

/** A node:http request handler that answers every request with `app` (a route that is not Lantern's answers 404). */
export function nodeHandler(
  app: LanternApp,
  options: AdapterOptions & { fallback?: (req: http.IncomingMessage, res: http.ServerResponse) => void } = {},
): (req: http.IncomingMessage, res: http.ServerResponse) => void {
  const limit = options.bodyLimit ?? app.bodyLimit;
  return (req, res) => {
    const target = req.url ?? "/";
    const path = target.split("?")[0] ?? "/";
    if (options.fallback !== undefined && !app.owns(safeDecode(path))) {
      options.fallback(req, res);
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= limit) chunks.push(chunk);
    });
    req.on("error", () => res.destroy());
    req.on("end", () => {
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined) continue;
        for (const one of Array.isArray(v) ? v : [v]) headers.append(k, one);
      }
      const scheme = options.scheme ?? ((req.socket as TLSSocket).encrypted ? "https" : "http");
      const request = ServerRequest.fromTarget(req.method ?? "GET", target, {
        headers,
        body: new Uint8Array(Buffer.concat(chunks)),
        scheme,
        remote: req.socket.remoteAddress ?? "",
      });
      const answer: Promise<ServerResponse> =
        size > limit
          ? Promise.resolve(problemResponse(request, new HttpProblem(413, "too_large", `At most ${limit} bytes here.`)))
          : app.handle(request);
      answer.then(
        (response) => send(res, response),
        () => res.destroy(),
      );
    });
  };
}

function safeDecode(path: string): string {
  try {
    return decodeURIComponent(path);
  } catch {
    return path;
  }
}

function send(res: http.ServerResponse, response: ServerResponse): void {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => {
    res.setHeader(key, value);
  });
  const body = response.body;
  if (body instanceof Uint8Array) {
    res.end(body.length > 0 ? body : undefined);
    return;
  }
  if (isStream(body)) {
    // Each chunk at once (an event stream, SPEC.md § 18.1): no buffering, and its end when the client goes.
    res.socket?.setNoDelay(true);
    res.flushHeaders();
    let gone = false;
    res.on("close", () => {
      gone = true;
      body.cancel();
    });
    (async () => {
      try {
        for await (const chunk of body.stream) {
          if (gone) break;
          if (!res.write(chunk)) await new Promise((r) => res.once("drain", r));
        }
      } finally {
        res.end();
      }
    })().catch(() => res.destroy());
    return;
  }
  const stream = createReadStream(body.path, { start: body.start, end: body.start + body.length - 1 });
  stream.on("error", () => res.destroy());
  stream.pipe(res);
}

/** Serves `app` alone on node:http, on loopback by default; resolves once it listens, with its URL and a close(). */
export async function listen(
  app: LanternApp,
  options: AdapterOptions & { port?: number; host?: string } = {},
): Promise<{ url: string; server: http.Server; close(): Promise<void> }> {
  const server = http.createServer(nodeHandler(app, options));
  server.keepAliveTimeout = 5000;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, options.host ?? "127.0.0.1", () => resolve());
  });
  const address = server.address() as AddressInfo;
  const host = address.family === "IPv6" ? `[${address.address}]` : address.address;
  return {
    url: `http://${host}:${address.port}/`,
    server,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

/**
 * A handler of web Requests (the Fetch API's), for Hono and its kind. The
 * request target a signature covers is the URL's path and query as the
 * framework gives them; `remote` gives the caller's address (for the limits of
 * pairing), when the framework knows it.
 */
export function fetchHandler(
  app: LanternApp,
  options: AdapterOptions & { remote?: (request: Request) => string | undefined } = {},
): (request: Request) => Promise<Response> {
  const limit = options.bodyLimit ?? app.bodyLimit;
  return async (request) => {
    const url = new URL(request.url);
    const target = url.pathname + url.search;
    let body = new Uint8Array();
    let tooLarge = Number(request.headers.get("Content-Length") ?? 0) > limit;
    if (!tooLarge && request.body !== null) {
      body = new Uint8Array(await request.arrayBuffer());
      tooLarge = body.length > limit;
    }
    const headers = new Headers(request.headers);
    if (!headers.has("Host")) headers.set("Host", url.host);
    const lantern = ServerRequest.fromTarget(request.method, target, {
      headers,
      body: tooLarge ? new Uint8Array() : body,
      scheme: options.scheme ?? url.protocol.slice(0, -1),
      remote: options.remote?.(request) ?? "",
    });
    const response = tooLarge
      ? problemResponse(lantern, new HttpProblem(413, "too_large", `At most ${limit} bytes here.`))
      : await app.handle(lantern);
    if (!response.headers.has("Date")) response.headers.set("Date", new Date().toUTCString());
    const out = response.body;
    if (out instanceof Uint8Array) {
      const init: ResponseInit = { status: response.status, headers: response.headers };
      return new Response(
        out.length > 0 && response.status !== 204 && response.status !== 304 ? (out as BodyInit) : null,
        init,
      );
    }
    if (isStream(out)) {
      const iterator = out.stream[Symbol.asyncIterator]();
      const stream = new ReadableStream<Uint8Array>({
        async pull(controller) {
          try {
            const next = await iterator.next();
            if (next.done) controller.close();
            else controller.enqueue(next.value);
          } catch (e) {
            controller.error(e);
          }
        },
        cancel() {
          out.cancel();
          void iterator.return?.();
        },
      });
      return new Response(stream, { status: response.status, headers: response.headers });
    }
    const stream = Readable.toWeb(
      createReadStream(out.path, { start: out.start, end: out.start + out.length - 1 }),
    ) as ReadableStream<Uint8Array>;
    return new Response(stream, { status: response.status, headers: response.headers });
  };
}
