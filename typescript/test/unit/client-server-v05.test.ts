/**
 * Draft 0.5's client against the toolkit's own server (the demo of
 * test/demo.ts), in this process over HTTP on loopback: the event stream and
 * long polls, sync with its consent, grants and a peer of the toolkit's
 * (PeerServer), mirrors that lie, deleting an account, and a static library
 * written from the demo's library, read from its folder and over HTTP.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import {
  BadRequest,
  ConsentRequired,
  DeviceKey,
  GenerationChanged,
  IntegrityError,
  type LanternClient,
  MemorySink,
  NotFound,
  type Peer,
  PreconditionFailed,
  type ServerEvent,
  StaticLibrary,
  sync,
  Unauthorized,
} from "../../src/index.ts";
import { FileStaticSource, libraryInput, NodeLanternClient, writeStatic } from "../../src/node/index.ts";
import { type LanternApp, listen, type MemoryLibrary, missing, PeerServer } from "../../src/server/index.ts";
import { DEMO_SEED, DEMO_TOKEN, makeLantern, UID } from "../demo.ts";
import { AGENT } from "../helpers.ts";

let served: Awaited<ReturnType<typeof listen>>;
let app: LanternApp;
let adminKey: DeviceKey;
const clients: LanternClient[] = [];
const folder = mkdtempSync(join(tmpdir(), "lantern-v05-"));

function client(options: ConstructorParameters<typeof NodeLanternClient>[1] = {}): NodeLanternClient {
  const c = new NodeLanternClient(served.url, { userAgent: AGENT, ...options });
  clients.push(c);
  return c;
}

const admin = (options: ConstructorParameters<typeof NodeLanternClient>[1] = {}): NodeLanternClient =>
  client({ token: DEMO_TOKEN, key: adminKey, ...options });

before(async () => {
  app = await makeLantern();
  served = await listen(app);
  adminKey = await DeviceKey.fromSeed(DEMO_SEED);
});

after(async () => {
  for (const c of clients) await c.close();
  await served.close();
  rmSync(folder, { recursive: true, force: true });
});

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

describe("events (SPEC.md § 18)", () => {
  test("ready, then a pairing waiting, to an admin; again after Last-Event-ID; in a long poll", async () => {
    const mira = admin();
    const stream = await mira.events();
    const iterator = stream[Symbol.asyncIterator]();
    const ready = (await iterator.next()).value as ServerEvent;
    assert.equal(ready.event, "ready");
    const start = ready.id;
    const console1 = client({ platform: "switch" });
    const pairing = await console1.pair("Ines's console", ["library"]);
    const next = (await iterator.next()).value as ServerEvent;
    assert.equal(next.event, "pairing");
    assert.equal(next.data["code"], pairing.code);
    assert.equal(stream.lastId, next.id);
    await stream.close();
    // Resumed from ready's id: the pairing again, with the same id.
    const again = await mira.events({ since: start });
    const [r2, p2] = await take(again, 2);
    assert.equal(r2?.id, start);
    assert.equal(p2?.id, next.id);
    await again.close();
    // A long poll from the same id lists it.
    const polled = await mira.poll(start, 5);
    assert.ok(polled.events.some((e) => e.id === next.id && e.event === "pairing"));
    const quick = await mira.poll(next.id, 0);
    assert.deepEqual(quick.events, []);
  });

  test("library events: of the caller's platform only", async () => {
    const lib = app.library as MemoryLibrary;
    const onSwitch = client({ platform: "switch" });
    const onAndroid = client({ platform: "android" });
    const a = await onSwitch.events();
    const b = await onAndroid.events();
    await take(a, 1);
    await take(b, 1);
    lib.addAppFile({
      data: new TextEncoder().encode("Brass Lantern, chapter 1"),
      platform: "switch",
      title_id: "0100AA0000990000",
      app_id: "0100AA0000990000",
      type: "base",
      version_code: 0,
      name: "Brass Lantern",
      format: "nsp",
    });
    const [seen] = await take(a, 1);
    assert.equal(seen?.event, "library");
    assert.deepEqual(seen?.data, { schema: 1, families: ["apps"], platforms: ["switch"] });
    assert.deepEqual(await take(b, 1, 1.5), []);
    await a.close();
    await b.close();
  });

  test("an id the server never gave: 400; a long poll without since: 400", async () => {
    const mira = admin();
    const stream = await mira.events({ since: "s_lantern-test.AAAA" });
    await assert.rejects(take(stream, 1), BadRequest);
    await assert.rejects(mira.poll("", 1), BadRequest);
  });

  test("a revoked device's stream ends; connecting again is refused", async () => {
    const mira = admin();
    const c = client({ platform: "switch", verify: true });
    const pairing = await c.pair("Noor's console", ["library"]);
    for await (const p of mira.iterAdminPairings())
      if (p.code === pairing.code) await mira.approvePairing(p.id, { user: "noor" });
    await c.waitForPairing(pairing, { sleep: (s) => new Promise((r) => setTimeout(r, Math.min(s, 1) * 1000)) });
    const stream = await c.events({ tries: 1 });
    await take(stream, 1);
    let id = "";
    for await (const d of mira.iterAdminDevices({ user: "noor" })) id = d.id;
    await mira.revokeDevice(id);
    await assert.rejects(take(stream, 1, 20), Unauthorized);
  });

  test("beyond limits.event_streams: 429, then the stream waits and connects", async () => {
    const mira = admin();
    const held = [await mira.events(), await mira.events()];
    for (const s of held) await take(s, 1);
    const third = await mira.events({ tries: 1 });
    await assert.rejects(take(third, 1), /Slow|429|event streams/);
    for (const s of held) await s.close();
  });
});

describe("sync (SPEC.md § 20)", () => {
  test("nothing before the user's consent, and a collection agreed to by name only", async () => {
    const mira = admin();
    await assert.rejects(mira.syncOverview(), ConsentRequired);
    mira.setSyncConsent({ ...sync.syncOff(UID, "Mira"), consent: ["wishes"] });
    const overview = await mira.syncOverview();
    assert.match(overview.device ?? "", /^d_[0-9a-f]{16}$/);
    await assert.rejects(mira.syncPull("installed"), ConsentRequired);
  });

  test("a wish written, read since, merged by the rule; If-Match of another revision: 412", async () => {
    const mira = admin();
    mira.setSyncConsent({ ...sync.syncOff(UID, "Mira"), consent: ["wishes", "installed"] });
    await mira.syncPull("wishes");
    const t = Date.now();
    const value = { platform: "switch", title_id: "0100AB1200010000", note: "For the holidays" };
    const [kept] = (await mira.syncPush("wishes", [sync.item("switch/0100AB1200010000", value, t)])).items;
    assert.deepEqual(kept?.value, value);
    const older = await mira.syncPush("wishes", [
      sync.item("switch/0100AB1200010000", { ...value, note: "x" }, t - 60000),
    ]);
    assert.deepEqual(older.items[0]?.value, value);
    const pulled = await mira.syncPull("wishes");
    assert.ok(pulled.items.some((i) => i.key === "switch/0100AB1200010000"));
    const other = admin();
    other.setSyncConsent({ ...sync.syncOff(UID, "Mira"), consent: ["wishes"] });
    await other.syncPull("wishes");
    await mira.syncPush("wishes", [
      sync.item("switch/0100CD3400020000", { platform: "switch", title_id: "0100CD3400020000" }, t),
    ]);
    await assert.rejects(
      other.syncPush("wishes", [sync.item("switch/0100AB1200010000", undefined, t + 1)], { whole: true }),
      PreconditionFailed,
    );
    // Its own item of installed, and only its own.
    const device = (await mira.syncOverview()).device ?? "";
    const mine = {
      device: "Mira's console",
      platform: "switch",
      apps: [{ app_id: "0100AB1200010000", version_code: 0 }],
      homebrew: [],
    };
    await mira.syncPush("installed", [sync.item(device, mine, t)]);
    await assert.rejects(
      mira.syncPush("installed", [sync.item("d_0000000000000000", mine, t)]),
      /forbidden|another device|403/i,
    );
  });

  test("erased: a new generation; a client that kept the old one turns sync off", async () => {
    const mira = admin();
    mira.setSyncConsent({ ...sync.syncOff(UID, "Mira"), consent: ["wishes"] });
    await mira.syncPull("wishes");
    const other = admin();
    other.setSyncConsent({ ...sync.syncOff(UID, "Mira"), consent: ["wishes"] });
    await other.syncOverview();
    await other.syncErase();
    await assert.rejects(mira.syncPull("wishes"), GenerationChanged);
    assert.deepEqual(mira.syncState?.consent, []);
    await assert.rejects(mira.syncPull("wishes"), ConsentRequired);
  });
});

/** The demo's files on disk, for a peer: by SHA-256. */
function writeFiles(lib: MemoryLibrary): Map<string, { path: string; size: number }> {
  const out = new Map<string, { path: string; size: number }>();
  for (const a of lib.apps()) {
    const ref = lib.file(/\/files\/([^/]+)$/.exec(a.file)?.[1] ?? "");
    if (ref?.data === undefined) continue;
    const path = join(folder, a.sha256);
    writeFileSync(path, ref.data);
    out.set(a.sha256, { path, size: ref.size });
  }
  return out;
}

describe("grants, peers and mirrors (SPEC.md § 19)", () => {
  test("a grant verified by peers.key; a file from a peer, checked; the server when the peer fails", async () => {
    const lib = app.library as MemoryLibrary;
    const c = admin({ platform: "switch" });
    const hello = await c.handshake();
    const appOf = lib.apps().find((a) => a.size > 1000 && a.platform === "switch");
    assert.ok(appOf);
    const grant = await c.grant(appOf.sha256);
    assert.equal(grant.payload.uid, hello.uid);
    assert.equal(grant.payload.size, appOf.size);
    await assert.rejects(c.grant("0".repeat(64)), NotFound);
    const peer = new PeerServer({ files: writeFiles(lib), keys: { [hello.uid]: hello.peers?.key ?? "" } });
    const listening = await peer.listen();
    try {
      const found: Peer = {
        address: "127.0.0.1",
        port: listening.port,
        base: "/lantern",
        tls: false,
        uid: peer.uid,
        name: "Ines's console",
        slots: 2,
        servers: [hello.uid],
        url: listening.url,
      };
      assert.ok(await c.peerHolds(found, appOf.sha256, grant.grant));
      const sources: string[] = [];
      const sink = new MemorySink();
      await c.downloadApp(appOf, sink, { peers: [found], onSource: (s) => sources.push(s) });
      assert.deepEqual(sources, ["peer"]);
      assert.equal(createHash("sha256").update(sink.bytes()).digest("hex"), appOf.sha256);
      // A peer that does not hold it, then the server.
      const empty = new PeerServer({ files: new Map(), keys: { [hello.uid]: hello.peers?.key ?? "" } });
      const other = await empty.listen();
      const passed: number[] = [];
      await c.downloadApp(appOf, new MemorySink(), {
        peers: [{ ...found, url: other.url }],
        onSource: (s, _u, p) => {
          sources.push(s);
          passed.push(p.length);
        },
      });
      assert.deepEqual(sources.slice(1), ["server"]);
      assert.deepEqual(passed, [1]);
      await other.close();
      // A peer refuses what is not a grant of its server, or of another file.
      const raw = await fetch(`${listening.url}/v1/blobs/sha256/${appOf.sha256}`);
      assert.equal(raw.status, 403);
      assert.equal(raw.headers.get("WWW-Authenticate"), null);
      const wrong = await fetch(`${listening.url}/v1/blobs/sha256/${"e".repeat(64)}`, {
        headers: { "Lantern-Grant": grant.grant },
      });
      assert.equal(wrong.status, 403);
    } finally {
      await listening.close();
    }
  });

  test("a mirror that lies is passed by, sent no credential; one that serves the bytes is taken", async () => {
    const lib = app.library as MemoryLibrary;
    const appOf = lib.apps().find((a) => a.size > 1000 && a.platform === "switch");
    assert.ok(appOf);
    const good = lib.file(/\/files\/([^/]+)$/.exec(appOf.file)?.[1] ?? "")?.data ?? new Uint8Array();
    const seen: (string | undefined)[] = [];
    const mirror = http.createServer((req, res) => {
      seen.push(req.headers.authorization);
      res.end(req.url === "/good" ? good : Buffer.alloc(good.length, 1));
    });
    await new Promise<void>((r) => mirror.listen(0, "127.0.0.1", () => r()));
    const port = (mirror.address() as AddressInfo).port;
    try {
      const c = admin({ platform: "switch" });
      const sources: [string, string][] = [];
      const sink = new MemorySink();
      const doc = {
        ...appOf,
        mirrors: [{ url: `http://127.0.0.1:${port}/bad` }, { url: `http://127.0.0.1:${port}/good` }],
      };
      await c.downloadFile(doc, sink, { mirrors: true, onSource: (s, url) => sources.push([s, url]) });
      assert.deepEqual(sources, [["mirror", `http://127.0.0.1:${port}/good`]]);
      assert.deepEqual(seen, [undefined, undefined]);
      const lying = { ...appOf, mirrors: [{ url: `http://127.0.0.1:${port}/bad` }] };
      await c.downloadFile(lying, new MemorySink(), { mirrors: true, onSource: (s) => sources.push([s, ""]) });
      assert.equal(sources.at(-1)?.[0], "server");
    } finally {
      mirror.close();
    }
  });
});

describe("deleting an account (SPEC.md § 5.7)", () => {
  test("confirmed by its name; never one's own; then 404", async () => {
    const mira = admin();
    await mira.createUser("sam", ["library"]);
    await assert.rejects(mira.deleteUser("sam", "sma"), RangeError);
    await assert.rejects(mira.deleteUser("mira", "mira"), /conflict|itself|409/i);
    await mira.deleteUser("sam", "sam");
    const names: string[] = [];
    for await (const u of mira.iterAdminUsers()) names.push(u.name);
    assert.ok(!names.includes("sam"));
    await assert.rejects(mira.deleteUser("sam", "sam"), NotFound);
  });
});

describe("a static library written from the demo (SPEC.md § 21)", () => {
  let out: string;
  before(async () => {
    out = join(folder, "static");
    const input = await libraryInput(app.library, { uid: UID, name: "Demo shelf, static" });
    const done = await writeStatic(input, out, { pageSize: 2 });
    assert.ok(done.files > 0);
  });

  test("read from its folder: pages chained, what is missing as the server computes it", async () => {
    const lib = await StaticLibrary.open(new FileStaticSource(out));
    assert.equal(lib.hello.base, ".");
    assert.equal(lib.hello.features["sync"], 0);
    const apps = [];
    for await (const a of lib.apps("switch")) apps.push(a);
    const served = (app.library as MemoryLibrary).apps().filter((a) => a.platform === "switch");
    assert.equal(apps.length, served.length);
    const installed: [string, number][] = [["0100AB1200010000", 0]];
    const mine = (await lib.missing("switch", installed, ["update", "dlc"])).map((a) => a.app_id).sort();
    const theirs = missing(served, "switch", installed, new Set(["update", "dlc"]))
      .map((a) => a.app_id)
      .sort();
    assert.deepEqual(mine, theirs);
    const one = apps.find((a) => a.size > 0);
    assert.ok(one);
    const sink = new MemorySink();
    await lib.downloadApp(one, sink);
    assert.equal(createHash("sha256").update(sink.bytes()).digest("hex"), one.sha256);
    // A blob changed on the storage: refused, nothing kept.
    const path = join(out, one.file);
    const bytes = readFileSync(path);
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    writeFileSync(path, bytes);
    const bad = new MemorySink();
    await assert.rejects(lib.downloadApp(one, bad), IntegrityError);
    assert.equal(await bad.heldSize(), 0);
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    writeFileSync(path, bytes);
  });

  test("over HTTP, whatever the Content-Type", async () => {
    const server = http.createServer((req, res) => {
      try {
        const data = readFileSync(join(out, decodeURIComponent((req.url ?? "/").split("?")[0] ?? "/")));
        res.setHeader("Content-Type", "application/octet-stream");
        res.end(data);
      } catch {
        res.statusCode = 404;
        res.end();
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    try {
      const lib = await StaticLibrary.open(`http://127.0.0.1:${(server.address() as AddressInfo).port}/`);
      const entries = [];
      for await (const e of lib.homebrew("switch")) entries.push(e);
      assert.ok(entries.length > 0);
      const full = await lib.homebrewEntry("switch", entries[0]?.id ?? "");
      assert.ok(full?.package.manifest !== undefined || full?.package.format !== "zip");
      assert.deepEqual(await lib.homebrewUpdates("switch", [[entries[0]?.id ?? "", 0]]), [entries[0]]);
    } finally {
      server.close();
    }
  });

  test("a path leading out of the folder is refused", async () => {
    await assert.rejects(new FileStaticSource(out).read("../static/lantern.json", 1000), /below the root/);
  });
});
