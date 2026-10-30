/**
 * The client's calls of the families that write against the toolkit's own
 * server (the demo of test/demo.ts), in this process over HTTP on loopback,
 * with the demo's token bound to its key (every request signed): save backups
 * whole and by resumable upload (cut, then resumed), encrypted backups,
 * cheats written, requests, sections, and their events on the stream.
 */

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import {
  BadRequest,
  bytesSource,
  Conflict,
  DeviceKey,
  EncryptedBackup,
  e2e,
  type LanternClient,
  NotFound,
  SaveKey,
  type ServerEvent,
  TooLarge,
  TransportError,
} from "../../src/index.ts";
import { decryptSaveFile, NodeLanternClient } from "../../src/node/index.ts";
import { type LanternApp, listen, writeZip } from "../../src/server/index.ts";
import { DEMO_SEED, DEMO_TOKEN, makeLantern } from "../demo.ts";
import { AGENT } from "../helpers.ts";

let served: Awaited<ReturnType<typeof listen>>;
let app: LanternApp;
let key: DeviceKey;
const clients: LanternClient[] = [];
const folder = mkdtempSync(join(tmpdir(), "lantern-client-toolkit-"));
const TITLE = "0500AB12CD030000"; // a Switch title the demo's library does not have

before(async () => {
  // chunk_size stays 1 MiB: a client that resumes an upload does not know the server's, and sends chunks of 1 MiB.
  app = await makeLantern({ saveBody: 256 << 10 });
  served = await listen(app);
  key = await DeviceKey.fromSeed(DEMO_SEED);
});

after(async () => {
  for (const c of clients) await c.close();
  app.shutdown(1);
  await served.close();
  rmSync(folder, { recursive: true, force: true });
});

function mira(): NodeLanternClient {
  const c = new NodeLanternClient(served.url, { userAgent: AGENT, token: DEMO_TOKEN, key, platform: "switch" });
  clients.push(c);
  return c;
}

const zip = (label: string, size: number): Uint8Array =>
  writeZip([{ name: `save/${label}.bin`, data: new Uint8Array(randomBytes(size)) }]);

/** The next events of a stream, `n` of them or what came within `seconds`. */
async function take(stream: AsyncIterable<ServerEvent>, n: number, seconds = 5): Promise<ServerEvent[]> {
  const out: ServerEvent[] = [];
  const iterator = stream[Symbol.asyncIterator]();
  const deadline = Date.now() + seconds * 1000;
  while (out.length < n && Date.now() < deadline) {
    const next = await Promise.race([
      iterator.next(),
      new Promise<undefined>((r) => setTimeout(() => r(undefined), Math.max(1, deadline - Date.now()))),
    ]);
    if (next === undefined || next.done) break;
    out.push(next.value);
  }
  return out;
}

describe("saves against the toolkit (SPEC.md § 9)", () => {
  test("whole, and by an upload cut then resumed; listed, read back and deleted", async () => {
    const c = mira();
    const hello = await c.handshake();
    assert.equal(hello.features["saves"], 1);
    assert.equal(hello.limits?.save_body, 256 << 10);
    const small = zip("small", 2000);
    const one = await c.save(TITLE, small, { kind: "account", gameVersionCode: 65536, profile: "Léa", note: "Ch. 4" });
    assert.equal(one.size, small.length);
    assert.equal(one.profile, "Léa");
    assert.equal(one.device, "Mira's console");
    await assert.rejects(c.save(TITLE, zip("big", 300 << 10)), TooLarge);
    await assert.rejects(c.save(TITLE, small, { kind: "photos" }), BadRequest);
    const big = join(folder, "world.zip");
    writeFileSync(big, zip("world", 1536 << 10));
    const whole = readFileSync(big);
    let opened = "";
    await assert.rejects(
      c.uploadSaveFile(TITLE, big, {
        progress: (n) => {
          if (n < whole.length) {
            opened = c.lastUpload ?? "";
            throw new TransportError("a lost connection");
          }
        },
      }),
      TransportError,
    );
    const [offset, length] = await c.uploadOffset(opened);
    assert.equal(offset, 1 << 20);
    assert.equal(length, whole.length);
    const seen: number[] = [];
    const resumed = await c.uploadSaveFile(TITLE, big, { resume: opened, progress: (n) => seen.push(n) });
    assert.equal(resumed.size, whole.length);
    assert.equal(seen.at(-1), whole.length);
    const listed = (await c.saves({ titleId: TITLE })).saves.map((s) => s.save_id);
    assert.deepEqual(listed, [resumed.save_id, one.save_id]);
    await c.downloadSaveTo(resumed, join(folder, "back.zip"));
    assert.deepEqual(readFileSync(join(folder, "back.zip")), whole);
    const abandoned = await (async () => {
      await assert.rejects(
        c.uploadSaveFile(TITLE, big, {
          progress: () => {
            throw new TransportError("gone again");
          },
        }),
        TransportError,
      );
      return c.lastUpload ?? "";
    })();
    await c.abandonUpload(abandoned);
    await assert.rejects(c.uploadOffset(abandoned), NotFound);
    for (const s of [one, resumed]) await c.deleteSave(s);
    await assert.rejects(c.deleteSave(one), NotFound);
  });

  test("encrypted: uploaded and sent in one request, read back and decrypted", async () => {
    const c = mira();
    assert.equal((await c.handshake()).features["encrypted_saves"], 1);
    const saveKey = SaveKey.generate();
    const archive = zip("frost", 150000);
    const backup = await EncryptedBackup.create(saveKey, bytesSource(archive));
    let uploaded: Awaited<ReturnType<typeof c.uploadEncryptedSave>>;
    try {
      uploaded = await c.uploadEncryptedSave(TITLE, backup, { kind: "account" });
    } finally {
      backup.wipe();
    }
    assert.deepEqual(uploaded.encryption, await saveKey.encryption());
    assert.equal(uploaded.size, e2e.encryptedSize(archive.length));
    const small = zip("small", 500);
    const single = await c.save(TITLE, await e2e.encryptBytes(saveKey, small), {
      encryption: await saveKey.encryption(),
    });
    assert.equal(single.encryption?.key_id, await saveKey.keyId());
    assert.deepEqual(await e2e.decryptBytes(saveKey, await c.fetchSave(uploaded)), archive);
    const dest = join(folder, "restored.zip");
    await decryptSaveFile(saveKey, await c.fetchSave(single), dest);
    assert.deepEqual(new Uint8Array(readFileSync(dest)), small);
    await c.deleteSave(uploaded);
    await c.deleteSave(single);
  });
});

describe("cheats, requests and sections against the toolkit", () => {
  test("a cheat set created, refused twice, replaced, read and deleted", async () => {
    const c = mira();
    const text = "[Endless lamp oil]\n04000000 00ABCDEF 00000063\n";
    const made = await c.createCheat("switch", TITLE, text, { buildId: "4A1B2C3D4E5F6071", source: "Mira tests" });
    assert.equal(made.source, "Mira tests");
    await assert.rejects(
      c.createCheat("switch", TITLE, text, { buildId: "4A1B2C3D4E5F6071", source: "Mira tests" }),
      Conflict,
    );
    await assert.rejects(c.createCheat("switch", TITLE, "not a cheat\n", { buildId: "4A1B2C3D4E5F6071" }), BadRequest);
    const more = `${text}[Brighter lamp]\n04000000 00ABCDF0 00000001\n`;
    await c.replaceCheat(made.id, "switch", TITLE, more, { buildId: "4A1B2C3D4E5F6071", source: "Mira tests" });
    const listed = (await c.cheats({ titleId: TITLE })).cheats.find((s) => s.id === made.id);
    assert.ok(listed);
    assert.equal(await c.cheatText(listed), more);
    await c.deleteCheat(made.id);
    assert.ok(!(await c.cheats()).cheats.some((s) => s.id === made.id));
    await assert.rejects(c.deleteCheat(made.id), NotFound);
  });

  test("a request made, made again, listed, its events on the stream, withdrawn", async () => {
    const c = mira();
    const stream = await c.events();
    try {
      await take(stream, 1); // ready
      const first = await c.requestTitle(TITLE);
      assert.equal(first.status, "open");
      assert.equal(first.platform, "switch");
      assert.equal((await c.requestTitle(TITLE)).id, first.id);
      assert.ok((await c.requests()).requests.some((r) => r.id === first.id));
      await c.withdrawRequest(first.id);
      await assert.rejects(c.withdrawRequest(first.id), NotFound);
      const got = (await take(stream, 2)).filter((e) => e.event === "request");
      assert.deepEqual(
        got.map((e) => [e.data["id"], e.data["status"] ?? "withdrawn"]),
        [
          [first.id, "open"],
          [first.id, "withdrawn"],
        ],
      );
    } finally {
      await stream.close();
    }
  });

  test("a save kept: its event on the stream", async () => {
    const c = mira();
    const stream = await c.events();
    try {
      await take(stream, 1);
      const saved = await c.save(TITLE, zip("evented", 300));
      const got = (await take(stream, 1)).filter((e) => e.event === "save");
      assert.equal(got[0]?.data["save_id"], saved.save_id);
      await c.deleteSave(saved);
    } finally {
      await stream.close();
    }
  });

  test("sections, of the client's platform", async () => {
    const c = mira();
    const { sections } = await c.sections();
    assert.deepEqual(
      sections.map((s) => s.id),
      ["new", "together"],
    );
    const android = await c.sections({ platform: "android" });
    assert.deepEqual(
      android.sections.map((s) => [s.id, s.apps.length]),
      [["new", 1]],
    );
  });
});
