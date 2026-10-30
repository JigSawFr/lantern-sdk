/**
 * Files as SPEC.md § 6.6 wants them served: a strong ETag, Repr-Digest (the
 * whole file's SHA-256) on every answer, ranged or not and on HEAD,
 * Accept-Ranges, single byte ranges (206), 416 with Content-Range outside the
 * file, and If-Range.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { formatDigest } from "../digest.ts";
import { SHA256_HEX } from "../vocabulary.ts";
import { cachingHeaders, HttpProblem, type ServerRequest, type ServerResponse } from "./http.ts";

/**
 * A file the server serves: where it is (`path`, or its bytes in `data` for a
 * small one), its size and SHA-256, known beforehand (a server hashes a file
 * before it lists it, SPEC.md § 6.1).
 */
export class FileRef {
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
  readonly contentType: string;
  readonly data: Uint8Array | undefined;

  constructor(init: { path?: string; size: number; sha256: string; contentType?: string; data?: Uint8Array }) {
    if (!SHA256_HEX.test(init.sha256)) throw new RangeError("sha256 is lower-case hex");
    this.path = init.path ?? "";
    this.size = init.size;
    this.sha256 = init.sha256;
    this.contentType = init.contentType ?? "application/octet-stream";
    this.data = init.data;
  }

  /** A file, hashed now. */
  static async of(path: string, contentType?: string): Promise<FileRef> {
    const h = createHash("sha256");
    for await (const chunk of createReadStream(path)) h.update(chunk as Buffer);
    const size = (await stat(path)).size;
    return new FileRef({ path, size, sha256: h.digest("hex"), ...(contentType !== undefined ? { contentType } : {}) });
  }

  /** A file held in memory. */
  static ofBytes(data: Uint8Array, contentType?: string): FileRef {
    const sha256 = createHash("sha256").update(data).digest("hex");
    return new FileRef({ size: data.length, sha256, data, ...(contentType !== undefined ? { contentType } : {}) });
  }

  /** A strong ETag, from the content: the same file gives the same one. */
  get etag(): string {
    return `"${this.sha256.slice(0, 32)}"`;
  }
}

const RANGE = /^\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*$/;

/** [first, last] byte of a single range (RFC 9110 § 14), "unsatisfiable", or undefined to ignore it. */
export function parseRange(header: string, size: number): [number, number] | "unsatisfiable" | undefined {
  const m = RANGE.exec(header);
  if (m === null || (m[1] === "" && m[2] === "")) return undefined;
  if (m[1] === "") {
    const n = Number(m[2]);
    return n > 0 && size > 0 ? [Math.max(0, size - n), size - 1] : "unsatisfiable";
  }
  const first = Number(m[1]);
  const last = m[2] !== "" ? Number(m[2]) : size - 1;
  if (m[2] !== "" && last < first) return undefined;
  if (first >= size) return "unsatisfiable";
  return [first, Math.min(last, size - 1)];
}

/** A file's answer to GET or HEAD, with a Range honoured when given. */
export function fileResponse(request: ServerRequest, file: FileRef): ServerResponse {
  let status = 200;
  let first = 0;
  let last = file.size - 1;
  const headers = cachingHeaders(request);
  headers.set("Content-Type", file.contentType);
  headers.set("Accept-Ranges", "bytes");
  headers.set("ETag", file.etag);
  headers.set("Repr-Digest", formatDigest(file.sha256));
  const asked = request.header("Range");
  const ifRange = request.header("If-Range");
  if (asked && (ifRange === undefined || ifRange.trim() === file.etag)) {
    const parsed = parseRange(asked, file.size);
    if (parsed === "unsatisfiable") {
      throw new HttpProblem(416, "bad_request", `The file is ${file.size} bytes.`, {
        title: "Range not satisfiable",
        headers: { "Content-Range": `bytes */${file.size}` },
      });
    }
    if (parsed !== undefined) {
      [first, last] = parsed;
      status = 206;
      headers.set("Content-Range", `bytes ${first}-${last}/${file.size}`);
    }
  }
  const length = file.size > 0 ? last - first + 1 : 0;
  headers.set("Content-Length", String(length));
  if (request.method === "HEAD" || length === 0) return { status, headers, body: new Uint8Array() };
  if (file.data !== undefined) return { status, headers, body: file.data.subarray(first, last + 1) };
  return { status, headers, body: { path: file.path, start: first, length } };
}
