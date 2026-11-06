/**
 * Differential updates (SPEC.md § 22): the chunker `lantern-cdc-1` (§ 22.2), a
 * file's chunk index (§ 22.1), the check a client makes before it uses one
 * (§ 22.3, L-22.3-1), and the putting together of a newer file from the bytes
 * a client holds (its seeds) and the ranges it reads (§ 22.3, L-22.3-2 to
 * L-22.3-4).
 *
 * Nothing here is Node's: it runs in a browser. SHA-256 is the library's own
 * (`sha256.ts`) unless a `hash` factory is given (the Node entries plug in
 * node:crypto's). The gear hash is 64 bits wide, kept as two 32-bit halves.
 *
 *     const { document, bytes } = chunkIndex(file);              // a server's
 *     const index = readChunkIndex(raw, app.chunks, app.sha256, app.size);   // a client's
 *     const data = await assemble(index, [oldFile], readRange, app.sha256, app.size);
 */

import { DocumentError, LanternError } from "./base.ts";
import { toHex } from "./bytes.ts";
import { canonicalBytes } from "./canonical.ts";
import { IntegrityError } from "./errors.ts";
import type { ChunkIndex, ChunksRef } from "./generated/models.ts";
import { CHUNK_INDEX, CHUNKS, loadJson } from "./limits.ts";
import { type HasherFactory, sha256Factory } from "./sha256.ts";
import { SHA256_HEX } from "./vocabulary.ts";

/** The chunker of this version (SPEC.md § 22.2). */
export const ALGORITHM = "lantern-cdc-1";
/** A chunker's sizes: the powers of two from 64 KiB to 4 MiB. */
export const SIZES: readonly number[] = [16, 17, 18, 19, 20, 21, 22].map((b) => 2 ** b);
/** Chunks in an index, at most (SPEC.md § 13). */
export const CHUNKS_LIMIT = CHUNKS;
/** An index's bytes, at most (SPEC.md § 13). */
export const INDEX_LIMIT = CHUNK_INDEX;
/** The `schema` of the chunk indexes this library writes and reads (`features.deltas`, SPEC.md § 4.2). */
export const INDEX_SCHEMA = 1;

/** A chunk index whose chunks are typed: `[size, sha256]` each. */
export interface ChunkList extends Omit<ChunkIndex, "chunks"> {
  chunks: [number, string][];
}

/** Options of the functions that hash. */
export interface HashOptions {
  /** The SHA-256 to use (the library's own by default). */
  hash?: HasherFactory;
}

function digestOf(data: Uint8Array, hash: HasherFactory = sha256Factory): string {
  const h = hash();
  h.update(data);
  return toHex(h.digest());
}

let gearHigh: Uint32Array | undefined;
let gearLow: Uint32Array | undefined;

/** The gear table G of SPEC.md § 22.2, as 256 halves of 32 bits: the first 8 bytes of SHA-256(`lantern-cdc-1` ‖ i). */
export function gearTable(): { high: Uint32Array; low: Uint32Array } {
  if (gearHigh === undefined || gearLow === undefined) {
    const high = new Uint32Array(256);
    const low = new Uint32Array(256);
    const prefix = new TextEncoder().encode(ALGORITHM);
    const input = new Uint8Array(prefix.length + 1);
    input.set(prefix);
    for (let i = 0; i < 256; i++) {
      input[prefix.length] = i;
      const d = digestBytes(input);
      high[i] =
        ((d[0] as number) * 2 ** 24 + ((d[1] as number) << 16) + ((d[2] as number) << 8) + (d[3] as number)) >>> 0;
      low[i] =
        ((d[4] as number) * 2 ** 24 + ((d[5] as number) << 16) + ((d[6] as number) << 8) + (d[7] as number)) >>> 0;
    }
    gearHigh = high;
    gearLow = low;
  }
  return { high: gearHigh, low: gearLow };
}

function digestBytes(data: Uint8Array): Uint8Array {
  const h = sha256Factory();
  h.update(data);
  return h.digest();
}

/** `min` and `max` of a chunker of `size`, and its mask's top bits (SPEC.md § 22.2). RangeError for a size that is not one. */
export function bounds(size: number): { min: number; max: number; bits: number } {
  if (!SIZES.includes(size))
    throw new RangeError(`a chunker's size is a power of two from 65536 to 4194304, not ${size}`);
  return { min: size / 4, max: size * 4, bits: Math.log2(size) };
}

/** A chunk: its `offset` in the file and its `length`. */
export interface Cut {
  offset: number;
  length: number;
}

/**
 * lantern-cdc-1's chunks of `data` for a chunker of `size` (SPEC.md § 22.2): a chunk ends at the end of the data,
 * after the first byte from its min-th on whose gear hash has its top bits clear, or at its max-th. The hash is
 * 64 bits wide, in two halves of 32; the mask is within the high one (b is 22 at most).
 */
export function cut(data: Uint8Array, size: number): Cut[] {
  const { min, max, bits } = bounds(size);
  const { high: gh, low: gl } = gearTable();
  const mask = (((1 << bits) - 1) << (32 - bits)) | 0;
  const out: Cut[] = [];
  const n = data.length;
  let start = 0;
  while (start < n) {
    if (n - start <= min) {
      out.push({ offset: start, length: n - start });
      break;
    }
    const end = Math.min(start + max, n);
    let at = end;
    let hi = 0;
    let lo = 0;
    for (let i = start + min; i < end; i++) {
      const b = data[i] as number;
      const sum = ((lo << 1) >>> 0) + (gl[b] as number); // 2h + G[b]: the low half's carry goes into the high one
      hi = (((hi << 1) | (lo >>> 31)) + (gh[b] as number) + (sum > 0xffffffff ? 1 : 0)) >>> 0;
      lo = sum >>> 0;
      if ((hi & mask) === 0) {
        at = i + 1;
        break;
      }
    }
    out.push({ offset: start, length: at - start });
    start = at;
  }
  return out;
}

/**
 * The chunker's size a server may choose for a file of `length` bytes (SPEC.md § 22.1): the smallest from 64 KiB
 * whose chunks stay about 16,384 and, whatever the bytes, within the limit of 100,000; undefined for a file too
 * large for any.
 */
export function chunkSizeFor(length: number): number | undefined {
  const fits = (size: number): boolean => Math.floor(length / (size / 4 + 1)) + 1 <= CHUNKS_LIMIT;
  for (const size of SIZES) if (fits(size) && length <= size * 16384) return size;
  const last = SIZES[SIZES.length - 1] as number;
  return fits(last) ? last : undefined;
}

/**
 * A file's chunk index (SPEC.md § 22.1): its document and its canonical bytes (§ 2.3), those whose size and
 * SHA-256 the app's or package's `chunks` gives. `size` is the chunker's, by default chunkSizeFor()'s;
 * RangeError for a file too large for an index.
 */
export function chunkIndex(
  data: Uint8Array,
  size?: number,
  options: HashOptions = {},
): { document: ChunkList; bytes: Uint8Array } {
  const chosen = size ?? chunkSizeFor(data.length);
  if (chosen === undefined) throw new RangeError("a file too large for a chunk index");
  const chunks = cut(data, chosen).map(({ offset, length }): [number, string] => [
    length,
    digestOf(data.subarray(offset, offset + length), options.hash),
  ]);
  const document: ChunkList = {
    schema: INDEX_SCHEMA,
    sha256: digestOf(data, options.hash),
    size: data.length,
    chunker: { alg: ALGORITHM, size: chosen },
    chunks,
  };
  return { document, bytes: canonicalBytes(document) };
}

/** An app's or package's `chunks` (SPEC.md § 22.1): where its index is, and the index's size and SHA-256. */
export function chunksRef(url: string, indexBytes: Uint8Array, options: HashOptions = {}): ChunksRef {
  return { url, size: indexBytes.length, sha256: digestOf(indexBytes, options.hash) };
}

/** A chunk index a client cannot use: it reads the whole file instead (SPEC.md § 22.3, L-22.3-4). */
export class UnusableIndex extends LanternError {
  override name = "UnusableIndex";
}

/** A chunk, or the file put together, that is not what its index says (L-22.3-2): the file is read whole. */
export class ChunkRefused extends IntegrityError {
  override name = "ChunkRefused";
}

/**
 * The index a client may use for the file of `sha256` and `size`, from the bytes `raw` it read at `ref.url`
 * (SPEC.md § 22.3, L-22.3-1): their size and SHA-256 those of `ref`, a document of schema 1 (above it: absent),
 * naming that file, by a chunker it knows, with chunks of 1 byte to the chunker's max whose sizes add up to the
 * file's, 100,000 at most. UnusableIndex otherwise.
 */
export function readChunkIndex(
  raw: Uint8Array,
  ref: ChunksRef | undefined,
  sha256: string,
  size: number,
  options: HashOptions = {},
): ChunkList {
  if (ref === undefined || typeof ref.sha256 !== "string" || !Number.isInteger(ref.size))
    throw new UnusableIndex("no chunk index to compare it with");
  if (raw.length !== ref.size || raw.length > INDEX_LIMIT)
    throw new UnusableIndex(`${raw.length} bytes, not the ${ref.size} the document gives (or above ${INDEX_LIMIT})`);
  if (digestOf(raw, options.hash) !== ref.sha256)
    throw new UnusableIndex("its SHA-256 is not the one the document gives");
  let doc: unknown;
  try {
    doc = loadJson(raw, { limit: INDEX_LIMIT, where: "chunk index" });
  } catch (e) {
    throw new UnusableIndex(e instanceof DocumentError ? e.reason : "not JSON");
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw new UnusableIndex("not a document");
  const d = doc as Record<string, unknown>;
  if (!Number.isInteger(d["schema"])) throw new UnusableIndex("not a document");
  if (d["schema"] !== INDEX_SCHEMA)
    throw new UnusableIndex(`schema ${String(d["schema"])}, which this client does not read`);
  const chunker = d["chunker"] as Record<string, unknown> | null | undefined;
  if (
    typeof chunker !== "object" ||
    chunker === null ||
    chunker["alg"] !== ALGORITHM ||
    typeof chunker["size"] !== "number" ||
    !SIZES.includes(chunker["size"])
  )
    throw new UnusableIndex("a chunker this client does not know");
  if (d["sha256"] !== sha256 || d["size"] !== size || !Number.isInteger(d["size"]))
    throw new UnusableIndex("the index of another file");
  const chunks = d["chunks"];
  if (!Array.isArray(chunks) || chunks.length > CHUNKS_LIMIT)
    throw new UnusableIndex(`chunks: a list of ${CHUNKS_LIMIT} at most`);
  const { max } = bounds(chunker["size"]);
  let total = 0;
  for (const c of chunks as unknown[]) {
    if (
      !Array.isArray(c) ||
      c.length !== 2 ||
      !Number.isInteger(c[0]) ||
      (c[0] as number) < 1 ||
      (c[0] as number) > max ||
      typeof c[1] !== "string" ||
      !SHA256_HEX.test(c[1])
    )
      throw new UnusableIndex(`a chunk of another form: ${JSON.stringify(c)?.slice(0, 80)}`);
    total += c[0] as number;
  }
  if (total !== size) throw new UnusableIndex(`its chunks add up to ${total} bytes, not the file's ${size}`);
  return doc as unknown as ChunkList;
}

/** Where a chunk of a seed is: SHA-256 → `[offset, length]` of the first one of those bytes. */
export function seedChunks(seed: Uint8Array, size: number, options: HashOptions = {}): Map<string, [number, number]> {
  const out = new Map<string, [number, number]>();
  for (const { offset, length } of cut(seed, size)) {
    const digest = digestOf(seed.subarray(offset, offset + length), options.hash);
    if (!out.has(digest)) out.set(digest, [offset, length]);
  }
  return out;
}

/** One chunk of the index: where its bytes are in the file, and where to take them from. */
export interface PlanEntry {
  offset: number;
  length: number;
  sha256: string;
  /** The seed (`seed`) and the offset in it (`at`) to take it from; undefined: a range of the file to read. */
  from: { seed: number; at: number } | undefined;
}

/**
 * What a client takes from where (SPEC.md § 22.3): each chunk of the index, from the seed that has a chunk of
 * the same size and SHA-256 (cut by the index's chunker), or to read. The first seed that has it wins.
 */
export function deltaPlan(index: ChunkList, seeds: readonly Uint8Array[], options: HashOptions = {}): PlanEntry[] {
  const found = seeds.map((s) => seedChunks(s, index.chunker.size, options));
  const plan: PlanEntry[] = [];
  let offset = 0;
  for (const [length, sha256] of index.chunks) {
    let from: PlanEntry["from"];
    for (let n = 0; n < found.length && from === undefined; n++) {
      const hit = (found[n] as Map<string, [number, number]>).get(sha256);
      if (hit !== undefined && hit[1] === length) from = { seed: n, at: hit[0] };
    }
    plan.push({ offset, length, sha256, from });
    offset += length;
  }
  return plan;
}

/** A range to read: the file's bytes `start` to `end`, inclusive. */
export interface ByteRange {
  start: number;
  end: number;
}

/**
 * The ranges a client asks for: the chunks to read, neighbours joined when at most `gap` bytes apart (0: only
 * those that touch) and a range at most `limit` bytes long (a range is held in memory while it is checked).
 */
export function rangesOf(plan: readonly PlanEntry[], gap = 0, limit = Number.POSITIVE_INFINITY): ByteRange[] {
  const out: ByteRange[] = [];
  for (const { offset, length, from } of plan) {
    if (from !== undefined) continue;
    const last = out[out.length - 1];
    if (last !== undefined && offset - last.end - 1 <= gap && offset + length - last.start <= limit)
      last.end = offset + length - 1;
    else out.push({ start: offset, end: offset + length - 1 });
  }
  return out;
}

/** Reads the file's bytes `start` to `end`, inclusive: exactly those, from its server, a mirror or a peer. */
export type ReadRange = (start: number, end: number) => Promise<Uint8Array>;

/** What `assembleInto` takes besides the index. */
export interface AssembleOptions extends HashOptions {
  /** Ranges of at most this many bytes are read (8 MiB by default). */
  rangeLimit?: number;
  /** A plan already made by deltaPlan(). */
  plan?: readonly PlanEntry[];
}

/**
 * The file an index describes (SPEC.md § 22.3), given to `write` piece by piece in order: each chunk from a seed
 * or from a range `readRange` gives, its SHA-256 checked as it comes (L-22.3-2); then the whole file's size and
 * SHA-256, `expect`ed, checked. `write` receives nothing past the file's size (L-22.3-3). ChunkRefused when a
 * range, a chunk or the file does not match: what was written is to be dropped and the file read whole
 * (L-22.3-4). The file is trusted only when this returns.
 */
export async function assembleInto(
  index: ChunkList,
  seeds: readonly Uint8Array[],
  readRange: ReadRange,
  write: (piece: Uint8Array) => void | Promise<void>,
  expect: { sha256: string; size: number },
  options: AssembleOptions = {},
): Promise<void> {
  if (index.size !== expect.size || index.sha256 !== expect.sha256) throw new ChunkRefused("the index of another file");
  const plan = options.plan ?? deltaPlan(index, seeds, options);
  const ranges = rangesOf(plan, 0, options.rangeLimit ?? 8 << 20);
  const whole = (options.hash ?? sha256Factory)();
  let written = 0;
  let next = 0;
  let held: { start: number; data: Uint8Array } | undefined;
  for (const entry of plan) {
    let piece: Uint8Array;
    if (entry.from !== undefined) {
      const seed = seeds[entry.from.seed] as Uint8Array;
      piece = seed.subarray(entry.from.at, entry.from.at + entry.length);
    } else {
      if (held === undefined || entry.offset >= held.start + held.data.length) {
        const range = ranges[next++] as ByteRange;
        const data = await readRange(range.start, range.end);
        if (data.length !== range.end - range.start + 1)
          throw new ChunkRefused(`the range ${range.start}-${range.end} gave ${data.length} bytes`);
        held = { start: range.start, data };
      }
      piece = held.data.subarray(entry.offset - held.start, entry.offset - held.start + entry.length);
    }
    if (piece.length !== entry.length || digestOf(piece, options.hash) !== entry.sha256)
      throw new ChunkRefused(`the chunk at ${entry.offset} does not match its SHA-256`);
    if (written + piece.length > expect.size) throw new ChunkRefused("more bytes than the file's size");
    whole.update(piece);
    await write(piece);
    written += piece.length;
  }
  if (written !== expect.size || toHex(whole.digest()) !== expect.sha256)
    throw new ChunkRefused("the file put together does not match its sha256: read it whole");
}

/** The file an index describes, in memory (see assembleInto()). */
export async function assemble(
  index: ChunkList,
  seeds: readonly Uint8Array[],
  readRange: ReadRange,
  sha256: string,
  size: number,
  options: AssembleOptions = {},
): Promise<Uint8Array> {
  if (!SHA256_HEX.test(sha256)) throw new RangeError("a lower-case hex SHA-256 is needed");
  const out = new Uint8Array(size);
  let at = 0;
  await assembleInto(
    index,
    seeds,
    readRange,
    (piece) => {
      out.set(piece, at);
      at += piece.length;
    },
    { sha256, size },
    options,
  );
  return out;
}
