/**
 * Draft 0.7: canonical JSON (SPEC.md § 2.3, vectors/canonical-json.json) and differential updates (§ 22,
 * vectors/chunks.json): the gear table, the chunker, the index's canonical bytes, a newer file put together from an
 * older one, the indexes a client refuses, and the hostile cases (a chunk of other bytes, a short range).
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import { bytes, canonicalBytes, canonicalJson, chunks, DocumentError } from "../../src/index.ts";
import { vectors } from "../helpers.ts";

const hex = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");

/** A vector file's bytes: SHA-256(seed ‖ i, 8 bytes big-endian) for i = 0, 1, …, cut to `size`. */
function stream(seed: string, size: number): Uint8Array {
  const out = new Uint8Array(Math.ceil(size / 32) * 32);
  for (let i = 0; i * 32 < size; i++) {
    const n = Buffer.alloc(8);
    n.writeBigUInt64BE(BigInt(i));
    out.set(createHash("sha256").update(seed).update(n).digest(), i * 32);
  }
  return out.subarray(0, size);
}

interface CanonicalVectors {
  cases: { name: string; json: string; canonical: string; sha256: string }[];
}

describe("canonical-json.json (SPEC.md § 2.3)", () => {
  for (const c of vectors<CanonicalVectors>("canonical-json").cases) {
    test(`[L-2.3-1] ${c.name}`, () => {
      const out = canonicalJson(JSON.parse(c.json));
      assert.equal(out, c.canonical);
      assert.equal(hex(canonicalBytes(JSON.parse(c.json))), c.sha256);
    });
  }

  test("a value JSON cannot hold is refused", () => {
    assert.throws(() => canonicalJson({ a: Number.NaN }), DocumentError);
    assert.throws(() => canonicalJson({ a: Number.POSITIVE_INFINITY }), DocumentError);
    assert.throws(() => canonicalJson({ a: undefined }), DocumentError);
    let deep: unknown = 1;
    for (let i = 0; i < 2000; i++) deep = [deep];
    assert.throws(() => canonicalJson(deep), DocumentError);
  });
});

interface Case {
  name: string;
  file: { seed?: string; size?: number; zeros?: number; edit?: string };
  file_sha256: string;
  file_size: number;
  chunker: { alg: string; size: number };
  cuts: number[];
  chunks: [number, string][];
  index_size: number;
  index_sha256: string;
  index: string;
}
interface ChunkVectors {
  gear: { first: string[]; last: string; sha256: string };
  cases: Case[];
  update: {
    plan: { offset: number; size: number; sha256: string; from: string }[];
    ranges: string[];
    read: number;
  };
  refused: {
    name: string;
    file_sha256: string;
    file_size: number;
    chunks: { url: string; size: number; sha256: string };
    index: string;
    usable: boolean;
  }[];
}

const v = vectors<ChunkVectors>("chunks");
const BASE = stream("lantern-cdc-1 vector", 1000000);
const EDITED = (() => {
  const insert = stream("an insertion", 777);
  const out = new Uint8Array(990777);
  out.set(BASE.subarray(0, 300000), 0);
  out.set(insert, 300000);
  out.set(BASE.subarray(300000, 700000), 300777);
  out.set(BASE.subarray(710000), 300777 + 400000);
  return out;
})();

function fileOf(c: Case): Uint8Array {
  if (c.file.zeros !== undefined) return new Uint8Array(c.file.zeros);
  if (c.file.edit !== undefined) return EDITED;
  return stream(c.file.seed as string, c.file.size as number);
}

describe("chunks.json (SPEC.md § 22)", () => {
  test("[L-22.2-1] the gear table: first values, last, and the SHA-256 of the whole table", () => {
    const { high, low } = chunks.gearTable();
    const at = (i: number): string =>
      high[i]?.toString(16).padStart(8, "0") + (low[i]?.toString(16).padStart(8, "0") ?? "");
    assert.deepEqual([0, 1, 2, 3].map(at), v.gear.first);
    assert.equal(at(255), v.gear.last);
    const table = new Uint8Array(256 * 8);
    for (let i = 0; i < 256; i++) {
      new DataView(table.buffer).setUint32(i * 8, high[i] as number);
      new DataView(table.buffer).setUint32(i * 8 + 4, low[i] as number);
    }
    assert.equal(hex(table), v.gear.sha256);
  });

  for (const c of v.cases) {
    test(`[L-22.1-1] ${c.name}: cuts, chunks, index bytes`, () => {
      const data = fileOf(c);
      assert.equal(data.length, c.file_size);
      assert.equal(hex(data), c.file_sha256);
      assert.deepEqual(
        chunks.cut(data, c.chunker.size).map((x) => x.offset),
        c.cuts,
      );
      const { document, bytes: raw } = chunks.chunkIndex(data, c.chunker.size);
      assert.deepEqual(document.chunks, c.chunks);
      assert.equal(bytes.fromUtf8(raw), c.index);
      assert.equal(raw.length, c.index_size);
      assert.equal(hex(raw), c.index_sha256);
      // The index a client reads back, from its reference.
      const ref = chunks.chunksRef("v1/chunks/sha256/x.json", raw);
      assert.deepEqual(chunks.readChunkIndex(raw, ref, c.file_sha256, c.file_size), document);
    });
  }

  test("a file's size picks the least chunker that stays within 16,384 chunks and 100,000 whatever the bytes", () => {
    assert.equal(chunks.chunkSizeFor(0), 65536);
    assert.equal(chunks.chunkSizeFor(65536 * 16384), 65536);
    assert.equal(chunks.chunkSizeFor(65536 * 16384 + 1), 131072);
    assert.equal(chunks.chunkSizeFor(2 ** 40), undefined);
    assert.equal(chunks.chunkSizeFor(4194304 * 16384), 4194304);
  });

  test("[L-22.3-1] the newer version from the older: the plan and the ranges of the vector, and the file", async () => {
    const newer = v.cases[4] as Case;
    const raw = chunks.chunkIndex(EDITED, newer.chunker.size).bytes;
    const index = chunks.readChunkIndex(raw, chunks.chunksRef("u", raw), newer.file_sha256, newer.file_size);
    const plan = chunks.deltaPlan(index, [BASE]);
    assert.deepEqual(
      plan.map((p) => ({
        offset: p.offset,
        size: p.length,
        sha256: p.sha256,
        from: p.from === undefined ? "read" : `seed at ${p.from.at}`,
      })),
      v.update.plan,
    );
    assert.deepEqual(
      chunks.rangesOf(plan).map((r) => `bytes=${r.start}-${r.end}`),
      v.update.ranges,
    );
    const asked: string[] = [];
    let read = 0;
    const data = await chunks.assemble(
      index,
      [BASE],
      async (start, end) => {
        asked.push(`bytes=${start}-${end}`);
        read += end - start + 1;
        return EDITED.subarray(start, end + 1);
      },
      newer.file_sha256,
      newer.file_size,
    );
    assert.deepEqual(asked, v.update.ranges);
    assert.equal(read, v.update.read);
    assert.equal(hex(data), newer.file_sha256);
  });

  test("ranges are joined across a gap and split at a limit", () => {
    const plan = chunks.deltaPlan(chunks.chunkIndex(EDITED, 65536).document, [BASE]);
    const whole = chunks.rangesOf(plan, Number.POSITIVE_INFINITY);
    assert.deepEqual(whole, [{ start: 223418, end: 757525 }]);
    assert.equal(chunks.rangesOf(plan, Number.POSITIVE_INFINITY, 300000).length, 2);
  });

  for (const r of v.refused) {
    test(`[L-22.3-1] refused: ${r.name}`, () => {
      assert.equal(r.usable, false);
      assert.throws(
        () => chunks.readChunkIndex(bytes.utf8(r.index), r.chunks, r.file_sha256, r.file_size),
        chunks.UnusableIndex,
      );
    });
  }

  test("[L-22.3-1] an index without a reference, of a wrong size, or past the limit is unusable", () => {
    const { bytes: raw } = chunks.chunkIndex(BASE.subarray(0, 1000), 65536);
    const sha = hex(BASE.subarray(0, 1000));
    const ref = chunks.chunksRef("u", raw);
    assert.throws(() => chunks.readChunkIndex(raw, undefined, sha, 1000), chunks.UnusableIndex);
    assert.throws(() => chunks.readChunkIndex(raw, { ...ref, size: ref.size + 1 }, sha, 1000), chunks.UnusableIndex);
    assert.throws(() => chunks.readChunkIndex(raw, ref, sha, 1001), chunks.UnusableIndex);
    assert.throws(() => chunks.readChunkIndex(raw, ref, "0".repeat(64), 1000), chunks.UnusableIndex);
    assert.ok(chunks.readChunkIndex(raw, ref, sha, 1000));
  });
});

describe("a file put together, hostile sources (SPEC.md § 22.3)", () => {
  const newer = v.cases[4] as Case;
  const { document: index } = chunks.chunkIndex(EDITED, newer.chunker.size);
  const serve = (start: number, end: number): Uint8Array => EDITED.subarray(start, end + 1);

  test("[L-22.3-2] a range of other bytes is refused, and so is a file of other bytes", async () => {
    await assert.rejects(
      chunks.assemble(
        index,
        [BASE],
        async (start, end) => {
          const wrong = new Uint8Array(serve(start, end));
          wrong[5] = (wrong[5] as number) ^ 1;
          return wrong;
        },
        newer.file_sha256,
        newer.file_size,
      ),
      chunks.ChunkRefused,
    );
    await assert.rejects(
      chunks.assemble(index, [BASE], async (s, e) => serve(s, e), "0".repeat(64), newer.file_size),
      chunks.ChunkRefused,
    );
  });

  test("[L-22.3-2] a seed whose chunks are not those of the index is not taken", async () => {
    const other = stream("another file", 1000000);
    const plan = chunks.deltaPlan(index, [other]);
    assert.ok(plan.every((p) => p.from === undefined));
    const data = await chunks.assemble(index, [other], async (s, e) => serve(s, e), newer.file_sha256, newer.file_size);
    assert.equal(hex(data), newer.file_sha256);
  });

  test("[L-22.3-3] a short or a long range is refused, nothing is written past the size", async () => {
    await assert.rejects(
      chunks.assemble(index, [BASE], async (s, e) => serve(s, e - 1), newer.file_sha256, newer.file_size),
      chunks.ChunkRefused,
    );
    await assert.rejects(
      chunks.assemble(index, [BASE], async (s, e) => serve(s, e + 10), newer.file_sha256, newer.file_size),
      chunks.ChunkRefused,
    );
    let written = 0;
    await assert.rejects(
      chunks.assembleInto(
        index,
        [BASE],
        async (s, e) => serve(s, e),
        (piece) => {
          written += piece.length;
        },
        { sha256: newer.file_sha256, size: newer.file_size - 1 },
      ),
      chunks.ChunkRefused,
    );
    assert.equal(written, 0);
  });

  test("[L-22.3-2] a source that fails fails the whole assembly", async () => {
    await assert.rejects(
      chunks.assemble(
        index,
        [BASE],
        async () => {
          throw new Error("gone");
        },
        newer.file_sha256,
        newer.file_size,
      ),
      /gone/,
    );
  });
});
