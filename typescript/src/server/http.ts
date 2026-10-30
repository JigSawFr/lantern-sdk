/**
 * The server toolkit's HTTP layer, independent of any framework: a request as
 * an adapter hands it over, a response as it hands it back, problem+json errors
 * (SPEC.md § 12), JSON documents with their ETag and caching headers (§ 14),
 * the platform a client names (§ 4.3), and request documents read by the
 * `schema` rule (§ 3.2).
 */

import { createHash } from "node:crypto";
import * as zlib from "node:zlib";
import { DocumentError, isObject, SCHEMA } from "../base.ts";
import { acceptLanguages, JSON_TYPE, mediaType, PLATFORM_HEADER, PROBLEM_JSON } from "../http.ts";
import { loadJson } from "../limits.ts";
import { receivedUri } from "../signatures.ts";
import { isPlatform } from "../vocabulary.ts";

/** A request document's largest body here, well within SPEC.md § 13's 32 MiB. */
export const BODY_LIMIT = 1 << 20;
export const CHALLENGE = 'Bearer realm="lantern"';
export const TITLES: Readonly<Record<number, string>> = {
  400: "Bad request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not found",
  405: "Method not allowed",
  409: "Conflict",
  410: "Gone",
  413: "Too large",
  416: "Range not satisfiable",
  422: "Unprocessable",
  429: "Slow down",
  500: "Internal error",
  503: "Unavailable",
};
export const PROBLEM_TYPE = "https://lantern.boreale.dev/errors/";
/** The language of the toolkit's own texts (titles and details of errors): English (SPEC.md § 2.2). */
export const LANGUAGE = "en";

/**
 * A request, as an adapter hands it to the toolkit: the path (decoded, without
 * the query), the query's parameters (the last value of each), the headers and
 * the body; then the scheme it came by, its request target as sent (path and
 * query, their percent-encoding unchanged: a signature covers it, SPEC.md
 * § 5.4), and the caller's address (for the limits of pairing, § 5.2).
 */
export class ServerRequest {
  readonly method: string;
  readonly path: string;
  readonly query: ReadonlyMap<string, string>;
  readonly headers: Headers;
  readonly body: Uint8Array;
  readonly scheme: string;
  readonly target: string;
  readonly remote: string;

  constructor(init: {
    method: string;
    path: string;
    query?: Iterable<[string, string]>;
    headers?: Headers | Record<string, string>;
    body?: Uint8Array;
    scheme?: string;
    target?: string;
    remote?: string;
  }) {
    this.method = init.method.toUpperCase();
    this.path = init.path;
    this.query = new Map(init.query ?? []);
    this.headers = init.headers instanceof Headers ? init.headers : new Headers(init.headers ?? {});
    this.body = init.body ?? new Uint8Array();
    this.scheme = init.scheme ?? "https";
    this.target = init.target ?? "";
    this.remote = init.remote ?? "";
  }

  /** A request from a target as sent (`/api/lantern/v1/apps?page_size=5`). */
  static fromTarget(
    method: string,
    target: string,
    init: { headers?: Headers | Record<string, string>; body?: Uint8Array; scheme?: string; remote?: string } = {},
  ): ServerRequest {
    const q = target.indexOf("?");
    const rawPath = q < 0 ? target : target.slice(0, q);
    let path: string;
    try {
      path = decodeURIComponent(rawPath);
    } catch {
      path = rawPath;
    }
    const query = new URLSearchParams(q < 0 ? "" : target.slice(q + 1));
    const last = new Map<string, string>();
    for (const [k, v] of query) last.set(k, v);
    return new ServerRequest({ ...init, method, path, query: last, target });
  }

  header(name: string): string | undefined {
    return this.headers.get(name) ?? undefined;
  }

  /** `@target-uri` (SPEC.md § 5.4): the scheme, the Host header, the target as sent. */
  targetUri(scheme?: string): string {
    return receivedUri(scheme ?? this.scheme, this.header("Host") ?? "", this.target || this.path);
  }

  /** `<scheme>://<Host>`: where the server's own pages are, for the documents it writes. */
  origin(scheme?: string): string {
    const uri = this.targetUri(scheme);
    return uri.slice(0, uri.indexOf("/", uri.indexOf("//") + 2));
  }

  /** Accept-Language, best first. */
  get languages(): string[] {
    return acceptLanguages(this.header("Accept-Language"));
  }
}

/** A response's body read from a file: `length` bytes from `start`. */
export interface FileBody {
  path: string;
  start: number;
  length: number;
}

/** A response for an adapter to send. Content-Length is always among the headers, HEAD included (whose body is empty). */
export interface ServerResponse {
  status: number;
  headers: Headers;
  body: Uint8Array | FileBody;
}

/** Throw it in a handler: answered as application/problem+json (SPEC.md § 12). */
export class HttpProblem extends Error {
  override name = "HttpProblem";
  readonly status: number;
  readonly code: string;
  readonly detail: string | undefined;
  readonly title: string;
  readonly headers: Record<string, string>;

  constructor(
    status: number,
    code: string,
    detail?: string,
    options: { title?: string; headers?: Record<string, string> } = {},
  ) {
    super(`${status} ${code}: ${detail ?? ""}`);
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.title = options.title ?? TITLES[status] ?? "Error";
    this.headers = options.headers ?? {};
  }

  document(): Record<string, unknown> {
    const doc: Record<string, unknown> = {
      schema: SCHEMA,
      type: PROBLEM_TYPE + this.code.replaceAll("_", "-"),
      title: this.title,
      status: this.status,
      code: this.code,
    };
    if (this.detail) doc["detail"] = this.detail;
    doc["language"] = LANGUAGE;
    return doc;
  }
}

export const badRequest = (detail: string): HttpProblem => new HttpProblem(400, "bad_request", detail);
export const notFound = (detail = "Not on this server."): HttpProblem => new HttpProblem(404, "not_found", detail);
export const gone = (detail: string): HttpProblem => new HttpProblem(410, "gone", detail);

export function unauthorized(detail: string, invalidToken = false): HttpProblem {
  const challenge = CHALLENGE + (invalidToken ? ', error="invalid_token"' : "");
  return new HttpProblem(401, "unauthorized", detail, { headers: { "WWW-Authenticate": challenge } });
}

export function methodNotAllowed(allowed: readonly string[]): HttpProblem {
  return new HttpProblem(405, "bad_request", "This route does not take that method.", {
    title: "Method not allowed",
    headers: { Allow: allowed.join(", ") },
  });
}

/** Vary and Cache-Control for an answer to `request` (SPEC.md § 14). */
export function cachingHeaders(request: ServerRequest): Headers {
  const h = new Headers({ Vary: `Authorization, ${PLATFORM_HEADER}, Accept-Language` });
  h.set("Cache-Control", request.header("Authorization") ? "private" : "no-cache");
  return h;
}

const encoder = new TextEncoder();

export function problemResponse(request: ServerRequest, error: HttpProblem): ServerResponse {
  const body = encoder.encode(JSON.stringify(error.document()));
  const headers = cachingHeaders(request);
  for (const [k, v] of Object.entries(error.headers)) headers.set(k, v);
  headers.set("Content-Type", PROBLEM_JSON);
  headers.set("Content-Language", LANGUAGE);
  headers.set("Content-Length", String(body.length));
  return { status: error.status, headers, body: request.method === "HEAD" ? new Uint8Array() : body };
}

/** The coding a JSON answer takes for an Accept-Encoding (SPEC.md § 2.1): zstd when Node has it, else gzip. */
export function contentCoding(acceptEncoding: string | undefined): "zstd" | "gzip" | undefined {
  const accepted = new Map<string, number>();
  for (const part of (acceptEncoding ?? "").split(",")) {
    const [name = "", ...params] = part.trim().split(";");
    let q = 1;
    for (const p of params) {
      const [k = "", v = ""] = p.trim().split("=");
      if (k.trim().toLowerCase() === "q") {
        const n = Number(v);
        q = Number.isFinite(n) ? n : 0;
      }
    }
    if (name.trim()) accepted.set(name.trim().toLowerCase(), q);
  }
  const wants = (c: string): boolean => (accepted.get(c) ?? accepted.get("*") ?? 0) > 0;
  if (wants("zstd") && typeof zlib.zstdCompressSync === "function") return "zstd";
  if (wants("gzip")) return "gzip";
  return undefined;
}

/** JSON smaller than this goes as it is: compressing it would gain nothing. */
export const COMPRESS_FROM = 512;

/**
 * A JSON document, with a strong ETag on a 200 to GET or HEAD, honouring
 * If-None-Match with 304 (SPEC.md § 14), and the caching headers. It is
 * compressed as Accept-Encoding asks (zstd, gzip), with an ETag of its own (§ 2.1).
 */
export function jsonResponse(request: ServerRequest, document: unknown, status = 200): ServerResponse {
  let body: Uint8Array = encoder.encode(JSON.stringify(document));
  const headers = cachingHeaders(request);
  headers.set("Vary", `${headers.get("Vary") ?? ""}, Accept-Encoding`);
  headers.set("Content-Type", JSON_TYPE);
  const coding = body.length >= COMPRESS_FROM ? contentCoding(request.header("Accept-Encoding")) : undefined;
  let tag = createHash("sha256").update(body).digest("hex").slice(0, 32);
  if (coding !== undefined) {
    body = new Uint8Array(coding === "zstd" ? zlib.zstdCompressSync(body) : zlib.gzipSync(body, { level: 6 }));
    headers.set("Content-Encoding", coding);
    tag += `-${coding}`;
  }
  if (status === 200 && (request.method === "GET" || request.method === "HEAD")) {
    const etag = `"${tag}"`;
    headers.set("ETag", etag);
    const asked = (request.header("If-None-Match") ?? "").split(",").map((t) => t.trim());
    if (asked.includes(etag)) {
      headers.delete("Content-Type");
      headers.delete("Content-Encoding");
      headers.set("Content-Length", "0");
      return { status: 304, headers, body: new Uint8Array() };
    }
  }
  headers.set("Content-Length", String(body.length));
  return { status, headers, body: request.method === "HEAD" ? new Uint8Array() : body };
}

/** An HTML page of the server's own (its approval page), never cached, never framed. */
export function htmlResponse(request: ServerRequest, page: string, status = 200): ServerResponse {
  const body = encoder.encode(page);
  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Language": LANGUAGE,
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
    "Content-Length": String(body.length),
  });
  return { status, headers, body: request.method === "HEAD" ? new Uint8Array() : body };
}

/** An answer without a body (204, 202…), with the caching headers. */
export function emptyResponse(request: ServerRequest, status = 204): ServerResponse {
  const headers = cachingHeaders(request);
  if (status !== 204) headers.set("Content-Length", "0");
  return { status, headers, body: new Uint8Array() };
}

/**
 * The platform the client named (SPEC.md § 4.3): ?platform=, else the
 * Lantern-Platform header; undefined for every platform. 400 for a name that is
 * not a platform's, or for none where `required`.
 */
export function platformOf(request: ServerRequest, required = false): string | undefined {
  const name = request.query.get("platform") || (request.header(PLATFORM_HEADER) ?? "").trim();
  if (!name) {
    if (required) throw badRequest("Name a platform: Lantern-Platform or ?platform= (SPEC.md § 4.3).");
    return undefined;
  }
  if (!isPlatform(name)) throw badRequest(`${JSON.stringify(name.slice(0, 40))} is not a platform's name.`);
  return name;
}

/**
 * A client's JSON document (SPEC.md § 3.2, § 12): 413 above `limit`, 400 when it
 * is not JSON or has no integer `schema`, 422 `unsupported_schema` for a schema
 * this server cannot read.
 */
export function readDocument(request: ServerRequest, limit: number = BODY_LIMIT): Record<string, unknown> {
  if (request.body.length > limit) throw new HttpProblem(413, "too_large", `At most ${limit} bytes here.`);
  if (mediaType(request.header("Content-Type")) !== JSON_TYPE) throw badRequest("The body is application/json.");
  let doc: unknown;
  try {
    doc = loadJson(request.body, { where: "the body" });
  } catch (e) {
    if (e instanceof DocumentError) throw badRequest(`The body is not a document this server can read: ${e.reason}`);
    throw e;
  }
  const schema = isObject(doc) ? doc["schema"] : undefined;
  if (!isObject(doc) || typeof schema !== "number" || !Number.isInteger(schema) || schema < 1) {
    throw badRequest("The body is an object with an integer schema.");
  }
  if (schema > SCHEMA) {
    throw new HttpProblem(422, "unsupported_schema", `This server reads schema ${SCHEMA} here, not ${schema}.`, {
      title: "Unsupported schema",
    });
  }
  return doc;
}
