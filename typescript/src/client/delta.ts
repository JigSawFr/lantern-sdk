/**
 * A file put together from the bytes a client holds and the ranges it reads
 * (SPEC.md § 22.3): the steps every reader of a chunk index shares, whether the
 * server's client (`LanternClient.downloadWithSeeds`) or a static library's
 * (`StaticLibrary.downloadWithSeeds`). The index is checked before it is used
 * (L-22.3-1), each chunk and then the whole file are checked before anything is
 * committed (L-22.3-2), nothing is written beyond the file's size (L-22.3-3),
 * and any failure leaves the sink empty and gives the caller the cue to read
 * the whole file (L-22.3-4).
 */

import { assembleInto, deltaPlan, type ReadRange, readChunkIndex } from "../chunks.ts";
import type { ChunksRef } from "../generated/models.ts";
import type { HasherFactory } from "../sha256.ts";
import type { DownloadSink } from "./download.ts";

/** What a delta download saved: bytes taken from the seeds, bytes read, and the ranges asked for. */
export interface DeltaReport {
  /** Bytes taken from the seeds, those of `resumed` included. */
  reused: number;
  /**
   * Bytes taken from what a download cut before left in the sink (its `.part`, or the `.seed` of a resume cut
   * in turn): the chunks already there, found again by their SHA-256 and not read a second time. 0 when there
   * was nothing, or nothing of it was of this file.
   */
  resumed: number;
  /** Bytes read from sources, in `ranges` requests. */
  read: number;
  ranges: number;
  /** The file's size. */
  size: number;
}

/** A file that may carry a chunk index (an app, a homebrew package). */
export interface DeltaFile {
  sha256: string;
  size: number;
  chunks?: ChunksRef | undefined;
}

async function leftoverSize(sink: DownloadSink): Promise<number> {
  return sink.leftoverSize ? sink.leftoverSize() : sink.heldSize();
}

async function takeLeftover(sink: DownloadSink, max: number): Promise<Uint8Array | undefined> {
  if (sink.takeLeftover) return sink.takeLeftover(max);
  const size = await sink.heldSize();
  if (size === 0 || size > max) return undefined;
  const out = new Uint8Array(size);
  let at = 0;
  for await (const chunk of sink.held()) {
    if (at + chunk.length > size) return undefined;
    out.set(chunk, at);
    at += chunk.length;
  }
  return at === size ? out : undefined;
}

/**
 * Puts `file` together into `sink` from `seeds`, what the sink still holds of a download cut before, and
 * `readRange`, committed only once its size and SHA-256 are right. What the sink holds (a `.part` of verified
 * pieces, or the `.seed` of a resume cut in turn) is one more seed, the last: its chunks are taken from it, each
 * checked by its SHA-256, so a stale or foreign one is harmless; with no seed of the caller's, it alone lets the
 * delta go on. Undefined, with `sink` empty (untouched when it was not written to), when it could not be done or
 * would gain nothing: no index, none usable, no chunk found in the seeds or the leftover, a source that failed,
 * a chunk or a file that does not match: the caller then reads the whole file (L-22.3-4).
 */
export async function deltaDownload(args: {
  file: DeltaFile;
  seeds: readonly Uint8Array[];
  sink: DownloadSink;
  /** The bytes of the index `ref` names, or undefined when there are none. */
  readIndex: (ref: ChunksRef) => Promise<Uint8Array | undefined>;
  readRange: ReadRange;
  hash: HasherFactory;
  progress?: ((done: number, total: number) => void) | undefined;
}): Promise<DeltaReport | undefined> {
  const { file, sink, hash } = args;
  if (file.chunks === undefined) return undefined;
  if (args.seeds.length === 0 && (await leftoverSize(sink)) === 0) return undefined;
  let took = false;
  let touched = false;
  try {
    const raw = await args.readIndex(file.chunks);
    if (raw === undefined) return undefined;
    const index = readChunkIndex(raw, file.chunks, file.sha256, file.size, { hash });
    took = true;
    const left = await takeLeftover(sink, file.size); // never more than the file: no prefix of it otherwise
    const seeds = left === undefined ? args.seeds : [...args.seeds, left];
    const plan = deltaPlan(index, seeds, { hash });
    if (!plan.some((p) => p.from !== undefined)) {
      // Nothing found in the seeds: the file whole. A leftover none of whose chunks is the file's is no prefix of
      // it: dropped, as a download that is not its document's is, not resumed by a range.
      if (left !== undefined) {
        touched = true;
        await sink.reset();
      }
      return undefined;
    }
    const report: DeltaReport = { reused: 0, resumed: 0, read: 0, ranges: 0, size: file.size };
    for (const p of plan) {
      if (p.from === undefined) continue;
      report.reused += p.length;
      if (left !== undefined && p.from.seed === seeds.length - 1) report.resumed += p.length;
    }
    touched = true;
    await sink.reset();
    let written = 0;
    await assembleInto(
      index,
      seeds,
      async (start, end) => {
        const data = await args.readRange(start, end);
        report.ranges++;
        report.read += data.length;
        return data;
      },
      async (piece) => {
        await sink.append(new Uint8Array(piece)); // a copy: a seed is the caller's, a range is not kept
        written += piece.length;
        args.progress?.(written, file.size);
      },
      { sha256: file.sha256, size: file.size },
      { hash, plan },
    );
    await sink.commit();
    return report;
  } catch {
    if (touched) await sink.reset();
    return undefined;
  } finally {
    if (took) await sink.releaseLeftover?.(!touched);
  }
}
