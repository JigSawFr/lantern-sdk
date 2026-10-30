/**
 * Draft 0.5's client against the specification's reference server (spec/server,
 * started by test/fixtures/reference.py --v05) over its fictional library:
 * events (the stream, Last-Event-ID, a long poll), sync with its consent,
 * end-to-end encrypted saves sent both ways and decrypted, grants and a file
 * from the reference peer (spec/server/peer.py), the server's own static export
 * read as a static library, lantern-static from the server checked by the
 * suite's --static, and deleting an account.
 */

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { promisify } from "node:util";
import { bytesSource } from "../../src/client/download.ts";
import {
  ConsentRequired,
  DeviceKey,
  EncryptedBackup,
  e2e,
  GenerationChanged,
  NotFound,
  type Peer,
  PreconditionFailed,
  SaveKey,
  type ServerEvent,
  StaticLibrary,
  sync,
} from "../../src/index.ts";
import { decryptSaveFile, FileStaticSource, NodeLanternClient } from "../../src/node/index.ts";
import { writeZip } from "../../src/server/zip.ts";
import { AGENT, PACKAGE, PYTHON, type Served, SPEC, servePython } from "../helpers.ts";

interface Reference {
  url: string;
  admin_token: string;
  admin_seed: string;
  lea_token: string;
  lea_seed: string;
  export: string;
  peer: string;
  peer_uid: string;
  library_root: string;
}

const run = promisify(execFile);
const HARNESS = join(PACKAGE, "test", "fixtures", "reference.py");
const folder = mkdtempSync(join(tmpdir(), "lantern-reference-v05-"));
const clients: NodeLanternClient[] = [];
let server: Served<Reference>;
let ref: Reference;

async function lea(): Promise<NodeLanternClient> {
  const c = new NodeLanternClient(ref.url, {
    userAgent: AGENT,
    platform: "switch",
    token: ref.lea_token,
    key: await DeviceKey.fromBase64(ref.lea_seed),
  });
  clients.push(c);
  return c;
}

async function ada(): Promise<NodeLanternClient> {
  const c = new NodeLanternClient(ref.url, {
    userAgent: AGENT,
    token: ref.admin_token,
    key: await DeviceKey.fromBase64(ref.admin_seed),
  });
  clients.push(c);
  return c;
}

before(async () => {
  server = await servePython<Reference>([HARNESS, "--v05"]);
  ref = server.info;
});

after(async () => {
  for (const c of clients) await c.close();
  await server?.stop();
  rmSync(folder, { recursive: true, force: true });
});

async function next(iterator: AsyncIterator<ServerEvent>, seconds = 8): Promise<ServerEvent | undefined> {
  const result = await Promise.race([
    iterator.next(),
    new Promise<undefined>((r) => setTimeout(() => r(undefined), seconds * 1000)),
  ]);
  return result === undefined || result.done ? undefined : result.value;
}

describe("events (SPEC.md § 18)", () => {
  test("a request's event on the stream, again after Last-Event-ID, and in a long poll", async () => {
    const c = await lea();
    const hello = await c.handshake();
    assert.equal(hello.features["events"], 1);
    assert.equal(hello.limits?.heartbeat, 5);
    const stream = await c.events();
    const it = stream[Symbol.asyncIterator]();
    const ready = await next(it);
    assert.equal(ready?.event, "ready");
    const request = await c.requestTitle("0100FFFF00090000");
    let seen: ServerEvent | undefined;
    for (let i = 0; i < 5 && seen === undefined; i++) {
      const e = await next(it);
      if (e?.event === "request" && e.data["id"] === request.id) seen = e;
    }
    assert.ok(seen, "the request's event on the stream");
    assert.equal(seen.data["status"], "open");
    await stream.close();
    const again = await c.events({ since: ready?.id ?? "" });
    const it2 = again[Symbol.asyncIterator]();
    assert.equal((await next(it2))?.id, ready?.id);
    let replayed: ServerEvent | undefined;
    for (let i = 0; i < 5 && replayed === undefined; i++) {
      const e = await next(it2);
      if (e?.id === seen.id) replayed = e;
    }
    assert.ok(replayed, "the event again, with its id");
    await again.close();
    const polled = await c.poll(ready?.id ?? "", 5);
    assert.ok(polled.events.some((e) => e.id === seen?.id));
    await c.withdrawRequest(request.id);
  });
});

describe("sync (SPEC.md § 20)", () => {
  test("consent first; wishes written and read; If-Match; erased, then off", async () => {
    const c = await lea();
    await assert.rejects(c.syncPull("wishes"), ConsentRequired);
    const hello = await c.handshake();
    c.setSyncConsent({ ...sync.syncOff(hello.uid, "Lea"), consent: ["wishes"] });
    const overview = await c.syncOverview();
    assert.match(overview.device ?? "", /^d_[0-9a-f]{16}$/);
    await c.syncPull("wishes");
    const value = { platform: "switch", title_id: "0100ABCD00010000", name: "Frostline Tales" };
    const written = await c.syncPush("wishes", [sync.item("switch/0100ABCD00010000", value, c.now() * 1000)]);
    assert.deepEqual(written.items[0]?.value, value);
    const pulled = await c.syncPull("wishes");
    assert.ok(pulled.items.length >= 1);
    const other = await lea();
    other.setSyncConsent({ ...sync.syncOff(hello.uid, "Lea"), consent: ["wishes"] });
    await other.syncPull("wishes");
    await c.syncPush("wishes", [
      sync.item("switch/0100EFEF00020000", { platform: "switch", title_id: "0100EFEF00020000" }, c.now() * 1000),
    ]);
    await assert.rejects(
      other.syncPush("wishes", [sync.item("switch/0100ABCD00010000", undefined, other.now() * 1000)], { whole: true }),
      PreconditionFailed,
    );
    await assert.rejects(c.syncPull("installed"), ConsentRequired);
    await other.syncErase();
    await assert.rejects(c.syncPull("wishes"), GenerationChanged);
    assert.deepEqual(c.syncState?.consent, []);
  });
});

describe("end-to-end encrypted saves (SPEC.md § 9.4)", () => {
  test("uploaded and sent in one request, listed with their key id, read back and decrypted", async () => {
    const c = await lea();
    assert.equal((await c.handshake()).features["encrypted_saves"], 1);
    const key = SaveKey.generate();
    const archive = writeZip([{ name: "save/frost.bin", data: new Uint8Array(200000).map((_, i) => (i * 7) % 251) }]);
    const backup = await EncryptedBackup.create(key, bytesSource(archive));
    let uploaded: Awaited<ReturnType<typeof c.uploadEncryptedSave>>;
    try {
      uploaded = await c.uploadEncryptedSave("0100ABCD00010000", backup, { kind: "account" });
    } finally {
      backup.wipe();
    }
    assert.deepEqual(uploaded.encryption, await key.encryption());
    assert.equal(uploaded.size, e2e.encryptedSize(archive.length));
    const small = writeZip([{ name: "save/small.bin", data: new TextEncoder().encode("chapter 5") }]);
    const sealed = await e2e.encryptBytes(key, small);
    const single = await c.save("0100ABCD00010000", sealed, { encryption: await key.encryption() });
    assert.equal(single.encryption?.key_id, await key.keyId());
    const listed = (await c.saves({ titleId: "0100ABCD00010000" })).saves.filter((s) => s.encryption !== undefined);
    assert.ok(listed.length >= 2);
    const back = await c.fetchSave(uploaded);
    assert.deepEqual(await e2e.decryptBytes(key, back), archive);
    const dest = join(folder, "restored.zip");
    await decryptSaveFile(key, await c.fetchSave(single), dest);
    assert.deepEqual(new Uint8Array(readFileSync(dest)), small);
    // Another key opens nothing of it.
    await assert.rejects(e2e.decryptBytes(SaveKey.generate(), back), e2e.DecryptionError);
    await c.deleteSave(uploaded);
    await c.deleteSave(single);
  });
});

describe("grants and the reference peer (SPEC.md § 19)", () => {
  test("a grant verified by peers.key, then the file from the peer, checked", async () => {
    const c = await lea();
    const hello = await c.handshake();
    const apps = [];
    for await (const a of c.iterApps()) apps.push(a);
    const app = apps.find((a) => a.size > 1000);
    assert.ok(app);
    const grant = await c.grant(app.sha256);
    assert.equal(grant.payload.uid, hello.uid);
    const url = new URL(ref.peer);
    const peer: Peer = {
      address: "127.0.0.1",
      port: Number(url.port),
      base: url.pathname,
      tls: false,
      uid: ref.peer_uid,
      name: "Lea's Switch",
      slots: 2,
      servers: [hello.uid],
      url: ref.peer,
    };
    assert.ok(await c.peerHolds(peer, app.sha256, grant.grant));
    const sources: string[] = [];
    const dest = join(folder, "from-peer.nsp");
    await c.downloadAppTo(app, dest, { peers: [peer], onSource: (s) => sources.push(s) });
    assert.deepEqual(sources, ["peer"]);
    assert.equal(createHash("sha256").update(readFileSync(dest)).digest("hex"), app.sha256);
    await assert.rejects(c.grant("0".repeat(64)), NotFound);
  });
});

describe("static libraries (SPEC.md § 21)", () => {
  test("the reference server's own export, read from its folder: what is missing as the server says", async () => {
    const lib = await StaticLibrary.open(new FileStaticSource(ref.export));
    assert.equal(lib.hello.static?.page_size, 4);
    const apps = [];
    for await (const a of lib.apps("switch")) apps.push(a);
    const c = await lea();
    const installed: [string, number][] = [
      ["0100ABCD00010000", 0],
      ["0100EFEF00020000", 0],
    ];
    const mine = (await lib.missing("switch", installed, ["update", "dlc"])).map((a) => a.id).sort();
    const theirs = [];
    for await (const a of c.iterMissing(installed, ["update", "dlc"])) theirs.push(a.id);
    assert.deepEqual(mine, theirs.sort());
    const titles = [];
    for await (const t of lib.titles("switch")) titles.push(t);
    assert.ok(titles.length > 0);
  });

  test("lantern-static from the server: the suite's --static passes it", async () => {
    const out = join(folder, "exported");
    const keyFile = join(folder, "lea.key");
    const { writeFileSync } = await import("node:fs");
    writeFileSync(keyFile, ref.lea_seed);
    await run(process.execPath, [
      join(PACKAGE, "src", "node", "lantern-static.ts"),
      "--from",
      ref.url,
      "--out",
      out,
      "--token",
      ref.lea_token,
      "--key",
      keyFile,
      "--page-size",
      "3",
    ]);
    const lib = await StaticLibrary.open(new FileStaticSource(out));
    assert.ok(lib.hello.platforms.includes("switch"));
    let report = "";
    try {
      ({ stdout: report } = await run(PYTHON, [join(SPEC, "conformance", "run.py"), "--static", out], {
        maxBuffer: 1 << 24,
      }));
    } catch (e) {
      assert.fail(String((e as { stdout?: string }).stdout ?? e));
    }
    assert.match(report, /Levels reached.*Lantern Static/);
    assert.deepEqual(
      report.split("\n").filter((l) => l.startsWith("FAIL")),
      [],
    );
  });
});

describe("deleting an account (SPEC.md § 5.7)", () => {
  test("confirmed by its name; then 404", async () => {
    const a = await ada();
    await a.createUser("sam", ["library"]);
    await a.deleteUser("sam", "sam");
    await assert.rejects(a.deleteUser("sam", "sam"), NotFound);
  });
});
