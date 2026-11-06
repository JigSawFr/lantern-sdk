/**
 * What draft 0.7 adds, against the specification's reference server (started by test/fixtures/reference.py):
 * the client reads its chunk indexes, checks that this library cuts a file as the reference does, and puts a
 * newer version together from an older one reading only the ranges it lacks (SPEC.md § 22).
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { type App, chunks as chunkTools, type DeltaReport, MemorySink } from "../../src/index.ts";
import { NodeLanternClient } from "../../src/node/index.ts";
import { AGENT, PACKAGE, type Served, servePython } from "../helpers.ts";

interface Reference {
  url: string;
  token?: string;
}

const hex = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");

describe("differential updates against the reference server (SPEC.md § 22)", () => {
  let server: Served<Reference>;
  let c: NodeLanternClient;
  before(async () => {
    server = await servePython<Reference>([join(PACKAGE, "test", "fixtures", "reference.py"), "--public"]);
    c = new NodeLanternClient(server.info.url, {
      userAgent: AGENT,
      token: server.info.token ?? "",
      platform: "switch",
    });
  });
  after(async () => {
    await c.close();
    await server.stop();
  });

  async function pair(): Promise<{ older: App; newer: App }> {
    const apps: App[] = [];
    for await (const a of c.iterApps({ platform: "switch" })) apps.push(a);
    const same = apps.filter((a) => a.chunks !== undefined && a.app_id === "0100ABCD00010800");
    same.sort((a, b) => a.version_code - b.version_code);
    return { older: same[0] as App, newer: same[1] as App };
  }

  test("[L-22.1-1] the handshake offers deltas, and the index of the reference is the one this library cuts", async () => {
    assert.equal((await c.handshake()).features["deltas"], 1);
    const { older, newer } = await pair();
    assert.ok(older && newer, "two versions with chunks");
    for (const app of [older, newer]) {
      const sink = new MemorySink();
      await c.downloadApp(app, sink);
      const raw = (await c.chunkIndexBytes(app)) as Uint8Array;
      const index = (await c.chunkIndex(app)) as chunkTools.ChunkList;
      assert.deepEqual(chunkTools.chunkIndex(sink.bytes(), index.chunker.size).bytes, raw);
    }
  });

  test("[L-22.3-2] the newer version from the older reads only the ranges it lacks", async () => {
    const { older, newer } = await pair();
    const seed = new MemorySink();
    await c.downloadApp(older, seed);
    const sink = new MemorySink();
    let report: DeltaReport | undefined;
    await c.downloadWithSeeds(newer, sink, [seed.bytes()], { onDelta: (r) => (report = r) });
    assert.equal(hex(sink.bytes()), newer.sha256);
    assert.ok(report, "a delta download");
    assert.ok(report.read < newer.size / 2, `${report.read} bytes read of ${newer.size}`);
    assert.equal(report.reused + report.read, newer.size);
  });
});
