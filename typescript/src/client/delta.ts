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
  /** Bytes taken from the seeds. */
  reused: number;
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

/**
 * Puts `file` together into `sink` from `seeds` and `readRange`, committed only once its size and SHA-256 are
 * right. Undefined, with `sink` empty, when it could not be done or would gain nothing: no index, none usable,
 * no chunk found in the seeds, a source that failed, a chunk or a file that does not match: the caller then
 * reads the whole file (L-22.3-4).
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
  const { file, seeds, sink, hash } = args;
  if (file.chunks === undefined || seeds.length === 0) return undefined;
  try {
    const raw = await args.readIndex(file.chunks);
    if (raw === undefined) return undefined;
    const index = readChunkIndex(raw, file.chunks, file.sha256, file.size, { hash });
    const plan = deltaPlan(index, seeds, { hash });
    if (!plan.some((p) => p.from !== undefined)) return undefined; // nothing found in the seeds: the file whole
    const report: DeltaReport = { reused: 0, read: 0, ranges: 0, size: file.size };
    for (const p of plan) if (p.from !== undefined) report.reused += p.length;
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
    await sink.reset();
    return undefined;
  }
}
