/**
 * A differential download resumes from the chunks a cut one left (SPEC.md § 22.3): the `.part` of verified
 * pieces, or the `.seed` of a resume cut in turn, is one more seed whose chunks are taken, each checked by its
 * SHA-256; a garbage part is harmless; the `.seed` is gone when the call ends.
 */

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { type App, type DeltaReport, MemorySink } from "../../src/index.ts";
import { FileSink, NodeLanternClient } from "../../src/node/index.ts";
import { LanternApp, listen } from "../../src/server/index.ts";
import { buildLibrary, UID } from "../demo.ts";
import { AGENT } from "../helpers.ts";

let app: LanternApp;
let close: () => Promise<void>;
let client: NodeLanternClient;
let seed: App;
let newer: App;
let seedBytes: Uint8Array;
let newerBytes: Uint8Array;
let folder: string;
let n = 0;

/** A sink that dies, as a process would, once `limit` bytes were appended: every later call throws. */
class Dying extends FileSink {
  #total = 0;
  #dead = false;
  readonly limit: number;
  constructor(dest: string, limit: number) {
    super(dest);
    this.limit = limit;
  }
  #check(): void {
    if (this.#dead) throw new Error("killed");
  }
  override async append(chunk: Uint8Array): Promise<void> {
    this.#check();
    await super.append(chunk);
    this.#total += chunk.length;
    if (this.#total >= this.limit) this.#dead = true;
  }
  override async reset(): Promise<void> {
    this.#check();
    await super.reset();
  }
  override async heldSize(): Promise<number> {
    this.#check();
    return super.heldSize();
  }
  override async commit(): Promise<void> {
    this.#check();
    await super.commit();
  }
}

function dest(): string {
  return join(folder, `file-${n++}.bin`);
}

before(async () => {
  const library = await buildLibrary({ deltas: true });
  app = new LanternApp(library, { uid: UID, name: "Delta shelf", base: "/api/lantern" });
  const served = await listen(app);
  close = served.close;
  const ferry = (await library.apps())
    .filter((a) => a.app_id === "0100AB1200020800")
    .sort((a, b) => a.version_code - b.version_code);
  seed = ferry[0] as App;
  newer = ferry[1] as App;
  client = new NodeLanternClient(served.url, { userAgent: AGENT });
  const s = new MemorySink();
  await client.downloadApp(seed, s);
  seedBytes = s.bytes();
  const m = new MemorySink();
  await client.downloadApp(newer, m);
  newerBytes = m.bytes();
  folder = mkdtempSync(join(tmpdir(), "lantern-delta-resume-"));
});

after(async () => {
  await client.close();
  app.shutdown(1);
  await close();
  rmSync(folder, { recursive: true, force: true });
});

/** Runs a delta download that is cut once `limit` bytes are written; what it leaves at `<dest>.part`. */
async function cut(path: string, limit: number): Promise<number> {
  const sink = new Dying(path, limit);
  await assert.rejects(client.downloadWithSeeds(newer, sink, [seedBytes]), /killed/);
  await sink.close();
  assert.ok(existsSync(`${path}.part`), "the cut run left its part");
  assert.ok(!existsSync(path), "nothing at dest yet");
  const size = statSync(`${path}.part`).size;
  assert.ok(size >= limit && size < newer.size, `${size} bytes held`);
  return size;
}

async function run(path: string, seeds: Uint8Array[]): Promise<DeltaReport> {
  const sink = new FileSink(path);
  let report: DeltaReport | undefined;
  try {
    await client.downloadWithSeeds(newer, sink, seeds, { onDelta: (r) => (report = r) });
  } finally {
    await sink.close();
  }
  assert.ok(report, "a delta download");
  assert.deepEqual(new Uint8Array(readFileSync(path)), newerBytes);
  assert.ok(!existsSync(`${path}.part`) && !existsSync(`${path}.seed`), "no part, no seed left");
  return report;
}

describe("a delta download resumes from the chunks a cut one left (SPEC.md § 22.3)", () => {
  test("[L-22.3-2] a retry with the same seeds reads less than a fresh run", async () => {
    const fresh = await run(dest(), [seedBytes]);
    const path = dest();
    const held = await cut(path, Math.floor(newer.size * 0.7));
    const again = await run(path, [seedBytes]);
    assert.ok(again.read < fresh.read, `${again.read} bytes read, ${fresh.read} for a fresh run`);
    assert.equal(again.reused + again.read, newer.size);
    assert.ok(again.size === newer.size && held > 0);
  });

  test("[L-22.3-3] a retry with no seeds of the caller's resumes from the part alone", async () => {
    const path = dest();
    const held = await cut(path, Math.floor(newer.size * 0.6));
    const again = await run(path, []);
    assert.ok(again.resumed >= held, `${again.resumed} bytes resumed of ${held} held`);
    assert.equal(again.reused, again.resumed);
    assert.equal(again.read, newer.size - again.resumed);
    assert.ok(again.read < newer.size);
  });

  test("[L-22.3-2] a garbage part is ignored: the file is right, nothing is taken from it", async () => {
    const path = dest();
    writeFileSync(`${path}.part`, randomBytes(70000));
    const again = await run(path, [seedBytes]);
    assert.equal(again.resumed, 0);
    assert.ok(again.reused > 0);
  });

  test("[L-22.3-4] a garbage part and no seeds: the whole file, as without the family", async () => {
    const path = dest();
    writeFileSync(`${path}.part`, randomBytes(70000));
    const sink = new FileSink(path);
    let told = false;
    try {
      await client.downloadWithSeeds(newer, sink, [], { onDelta: () => (told = true) });
    } finally {
      await sink.close();
    }
    assert.equal(told, false);
    assert.deepEqual(new Uint8Array(readFileSync(path)), newerBytes);
    assert.ok(!existsSync(`${path}.part`) && !existsSync(`${path}.seed`));
  });

  test("a .seed left by a cut resume is used, the larger of it and the part kept, and it is deleted", async () => {
    const path = dest();
    const held = await cut(path, Math.floor(newer.size * 0.5));
    // A resume cut in turn: its .seed holds the larger prefix, the new .part a smaller one.
    writeFileSync(`${path}.seed`, readFileSync(`${path}.part`));
    writeFileSync(`${path}.part`, readFileSync(`${path}.part`).subarray(0, Math.floor(held / 3)));
    const again = await run(path, []);
    assert.ok(again.resumed >= held, `${again.resumed} bytes resumed of ${held} held`);
  });

  test("a part larger than the file is no prefix of it: ignored, still right", async () => {
    const path = dest();
    writeFileSync(`${path}.part`, new Uint8Array(newer.size + 10));
    const again = await run(path, [seedBytes]);
    assert.equal(again.resumed, 0);
  });

  test("[L-22.3-3] a file the sink holds nothing of is put together as before", async () => {
    const again = await run(dest(), [seedBytes]);
    assert.equal(again.resumed, 0);
    assert.ok(again.read < newer.size / 2);
  });
});
