/**
 * What a download checks (SPEC.md § 6.6): the answer's `Repr-Digest` against the
 * document's SHA-256, its range when resuming, its size as it arrives, and the
 * whole file's SHA-256 at the end. Nothing is done until that last check passes.
 * A download writes into a `DownloadSink`; the `node` entry's is a `.part`
 * file renamed once checked, `MemorySink` holds the bytes.
 */

import { toHex } from "../bytes.ts";
import { digestSha256 } from "../digest.ts";
import { IntegrityError, UnexpectedResponse } from "../errors.ts";
import type { Hasher } from "../sha256.ts";
import { SHA256_HEX } from "../vocabulary.ts";

const CONTENT_RANGE = /^\s*bytes\s+(\d+)-(\d+)\/(\d+)\s*$/;

/** Checks one file's download against its `sha256` and `size`. */
export class Verifier {
  readonly sha256: string;
  readonly size: number;
  readonly what: string;

  constructor(sha256: string, size: number, what: string) {
    if (!SHA256_HEX.test(sha256))
      throw new RangeError(`${what}: ${sha256.slice(0, 70)} is not a lower-case hex SHA-256`);
    if (!Number.isInteger(size) || size < 0) throw new RangeError(`${what}: a size that is not one`);
    this.sha256 = sha256;
    this.size = size;
    this.what = what;
  }

  /** Checks an answer's headers; gives the offset its body starts at (0 for the whole file, `offset` for the rest). */
  start(status: number, headers: Headers, offset: number): number {
    const digest = digestSha256(headers.get("Repr-Digest"));
    if (digest !== undefined && digest !== this.sha256) {
      throw new IntegrityError(`${this.what}: the server's Repr-Digest is ${digest}, the document says ${this.sha256}`);
    }
    if (status === 206) {
      const range = headers.get("Content-Range") ?? "";
      const m = CONTENT_RANGE.exec(range);
      if (m === null || Number(m[1]) !== offset || Number(m[2]) !== this.size - 1 || Number(m[3]) !== this.size) {
        throw new UnexpectedResponse(
          `${this.what}: Content-Range ${JSON.stringify(range)}, asked bytes ${offset}-${this.size - 1}/${this.size}`,
          status,
        );
      }
      return offset;
    }
    if (status === 200) {
      const length = headers.get("Content-Length")?.trim();
      if (length !== undefined && /^\d+$/.test(length) && Number(length) !== this.size) {
        throw new IntegrityError(`${this.what}: ${length} bytes, the document says ${this.size}`);
      }
      return 0;
    }
    throw new UnexpectedResponse(`${this.what}: status ${status}`, status);
  }

  feed(hasher: Hasher, chunk: Uint8Array): void {
    if (hasher.size + chunk.length > this.size)
      throw new IntegrityError(`${this.what}: more bytes than its size, ${this.size}`);
    hasher.update(chunk);
  }

  /** Throws IntegrityError unless what arrived is the whole file, of its SHA-256. */
  finish(hasher: Hasher): void {
    if (hasher.size !== this.size)
      throw new IntegrityError(`${this.what}: ${hasher.size} bytes, the document says ${this.size}`);
    const got = toHex(hasher.digest());
    if (got !== this.sha256) throw new IntegrityError(`${this.what}: SHA-256 ${got}, the document says ${this.sha256}`);
  }
}

/**
 * Where a download goes. `held()` gives the bytes already there (a part of a
 * download cut before), read again to hash them; `append()` adds a chunk;
 * `reset()` drops everything (a download that is not its document's, or a
 * server that sent the whole file again). The client calls `commit()` only once
 * the whole file checked out.
 */
export interface DownloadSink {
  held(): AsyncIterable<Uint8Array>;
  heldSize(): Promise<number>;
  append(chunk: Uint8Array): Promise<void>;
  reset(): Promise<void>;
  commit(): Promise<void>;
}

/** A download held in memory: `bytes()` once committed. */
export class MemorySink implements DownloadSink {
  #chunks: Uint8Array[] = [];
  #size = 0;
  #committed = false;

  async *held(): AsyncIterable<Uint8Array> {
    yield* this.#chunks;
  }
  async heldSize(): Promise<number> {
    return this.#size;
  }
  async append(chunk: Uint8Array): Promise<void> {
    this.#chunks.push(chunk);
    this.#size += chunk.length;
  }
  async reset(): Promise<void> {
    this.#chunks = [];
    this.#size = 0;
    this.#committed = false;
  }
  async commit(): Promise<void> {
    this.#committed = true;
  }

  /** The whole file, once the client committed it; a TypeError before. */
  bytes(): Uint8Array {
    if (!this.#committed) throw new TypeError("not a checked download yet");
    const out = new Uint8Array(this.#size);
    let at = 0;
    for (const c of this.#chunks) {
      out.set(c, at);
      at += c.length;
    }
    return out;
  }
}

/** What an upload reads its save from: its size, and its bytes by range. */
export interface UploadSource {
  readonly size: number;
  read(offset: number, length: number): Promise<Uint8Array>;
}

/** An upload from bytes in memory. */
export function bytesSource(data: Uint8Array): UploadSource {
  return { size: data.length, read: async (offset, length) => data.subarray(offset, offset + length) };
}

/** An upload from a Blob (a File the user picked, in a browser). */
export function blobSource(blob: Blob): UploadSource {
  return {
    size: blob.size,
    read: async (offset, length) => new Uint8Array(await blob.slice(offset, offset + length).arrayBuffer()),
  };
}
