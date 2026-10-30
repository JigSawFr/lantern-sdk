/**
 * The server toolkit's families of draft 0.5 that write (the conformance suite
 * checks them whole, in test/integration): save backups in one request and by
 * resumable upload (SPEC.md § 9), encrypted ones kept as sent (§ 9.4), the
 * stores that keep them (FileSaveStore's index read by the `schema` rule),
 * cheat writes (§ 10), requests (§ 11), sections (§ 6.5), their events, their
 * limits, rating caps, deleting an account, and both adapters.
 */

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import { e2e, SaveKey } from "../../src/index.ts";
import {
  FileSaveStore,
  fetchHandler,
  type LanternApp,
  type LanternAppOptions,
  type Library,
  listen,
  MemoryAccounts,
  MemoryLibrary,
  MemorySaveStore,
  ServerRequest,
  type ServerResponse,
  writeZip,
} from "../../src/server/index.ts";
import { DEMO_TOKEN, makeLantern } from "../demo.ts";

const folder = mkdtempSync(join(tmpdir(), "lantern-toolkit-"));
after(() => rmSync(folder, { recursive: true, force: true }));

/** Unbound tokens of the demo's accounts, for calls made straight to app.handle(). */
const LEA = "et_test-lea-0123456789abcdef0123456789abcdef";
const NOOR = "et_test-noor-0123456789abcdef0123456789abcdef";
const CAPPED = "et_test-capped-0123456789abcdef0123456789abcd";
const READER = "et_test-reader-0123456789abcdef0123456789abcd";
const ALL = ["library", "saves", "cheats", "cheats.write", "requests", "sync.read", "sync.write"];
const LUMEN = "0100AB1200010000"; // the demo's game rated PEGI 7
const OWN = "0500AB12CD010000"; // a Switch title id the library does not have

async function lantern(options: Partial<LanternAppOptions> = {}): Promise<LanternApp> {
  const accounts = new MemoryAccounts([
    { name: "mira", scopes: [...ALL, "admin"] },
    { name: "lea", scopes: ALL },
    { name: "noor", scopes: ALL },
  ]);
  accounts.addToken(DEMO_TOKEN, "mira", "Mira's console", [...ALL, "admin"]);
  accounts.addToken(LEA, "lea", "Lea's Switch", ALL);
  accounts.addToken(NOOR, "noor", "Noor's Switch", ALL);
  accounts.addToken(CAPPED, "lea", "Lea's small Switch", ALL, { ratingCap: { age: 3, unrated: "show" } });
  accounts.addToken(READER, "lea", "Lea's reader", ["library", "cheats", "saves"]);
  return makeLantern({ accounts, ...options });
}

interface Answer {
  status: number;
  headers: Headers;
  bytes: Uint8Array;
  json: Record<string, unknown>;
}

async function call(
  app: LanternApp,
  method: string,
  path: string,
  init: { token?: string; platform?: string; headers?: Record<string, string>; body?: Uint8Array; json?: unknown } = {},
): Promise<Answer> {
  const headers: Record<string, string> = { Host: "shelf.example.org", ...(init.headers ?? {}) };
  if (init.token !== undefined) headers["Authorization"] = `Bearer ${init.token}`;
  if (init.platform !== undefined) headers["Lantern-Platform"] = init.platform;
  let body = init.body;
  if (init.json !== undefined) {
    body = new TextEncoder().encode(JSON.stringify(init.json));
    headers["Content-Type"] = "application/json";
  }
  const target = path.startsWith("/") ? path : `/api/lantern/v1/${path}`;
  const r: ServerResponse = await app.handle(
    ServerRequest.fromTarget(method, target, { headers, body: body ?? new Uint8Array(), scheme: "https" }),
  );
  assert.ok(r.body instanceof Uint8Array, "a body in memory");
  const bytes = r.body as Uint8Array;
  let json: Record<string, unknown> = {};
  if ((r.headers.get("Content-Type") ?? "").includes("json") && bytes.length > 0)
    json = JSON.parse(new TextDecoder().decode(bytes));
  return { status: r.status, headers: r.headers, bytes, json };
}

const sha = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");
const digest = (data: Uint8Array): string => `sha-256=:${createHash("sha256").update(data).digest("base64")}:`;
/** A save's zip of `size` random bytes (which no compression shrinks), named after `label`. */
const archive = (label: string, size = 300): Uint8Array =>
  writeZip([{ name: `save/${label}.bin`, data: new Uint8Array(randomBytes(size)) }]);

/** A backup in one request (SPEC.md § 9.2). */
function post(app: LanternApp, data: Uint8Array, headers: Record<string, string> = {}, token = LEA, title = OWN) {
  return call(app, "POST", `saves/${title}`, {
    token,
    platform: "switch",
    body: data,
    headers: { "Content-Type": "application/zip", "Content-Digest": digest(data), ...headers },
  });
}

/** The events a long poll gives a token after `since`. */
async function events(app: LanternApp, token: string, since: string, platform?: string) {
  const r = await call(app, "GET", `changes?since=${encodeURIComponent(since)}&wait=0`, {
    token,
    ...(platform !== undefined ? { platform } : {}),
  });
  assert.equal(r.status, 200);
  return r.json["events"] as { event: string; data: Record<string, unknown> }[];
}

async function since(app: LanternApp, token: string): Promise<string> {
  return (await call(app, "GET", "changes", { token })).json["since"] as string;
}

describe("the handshake of the families that write", () => {
  test("features and limits with a token; refused without one", async () => {
    const app = await lantern({ saveBody: 1000, saveSize: 5000, saveChunk: 500, savesKept: 3 });
    const hello = (await call(app, "GET", "/api/lantern/v1/", { token: LEA })).json;
    const features = hello["features"] as Record<string, number>;
    for (const f of ["saves", "encrypted_saves", "requests", "sections", "cheats"]) assert.equal(features[f], 1, f);
    assert.deepEqual(
      { ...(hello["limits"] as Record<string, number>) },
      {
        page_size: 500,
        heartbeat: 5,
        event_streams: 2,
        wait: 60,
        sync_items: 10000,
        save_body: 1000,
        save_size: 5000,
        saves_kept_per_title: 3,
      },
    );
    const anon = (await call(app, "GET", "/api/lantern/v1/")).json["features"] as Record<string, number>;
    for (const f of ["saves", "encrypted_saves", "requests"]) assert.equal(anon[f], 0, f);
    assert.equal(anon["sections"], 1);
    for (const path of ["saves", "requests"]) assert.equal((await call(app, "GET", path)).status, 401);
    const reader = (await call(app, "GET", "/api/lantern/v1/", { token: READER })).json["features"] as Record<
      string,
      number
    >;
    assert.equal(reader["requests"], 0);
    assert.equal((await call(app, "GET", "requests", { token: READER })).status, 403);
  });

  test("without their stores, the families are at 0 and their routes 404", async () => {
    const lib = new MemoryLibrary({ families: ["library", "titles", "homebrew", "cheats"] });
    const { LanternApp: App } = await import("../../src/server/index.ts");
    const app = new App(lib, { uid: "a1b2c3d4-0000-4000-8000-000000000001", name: "Bare shelf" });
    const features = (await call(app, "GET", "/api/lantern/v1/")).json["features"] as Record<string, number>;
    for (const f of ["saves", "encrypted_saves", "requests", "sections"]) assert.equal(features[f], 0, f);
    for (const path of ["saves", "requests", "sections", "uploads/u_x"])
      assert.equal((await call(app, "GET", path)).status, 404, path);
  });

  test("the adapters read a body as large as the largest the app takes", async () => {
    const app = await lantern({ saveBody: 3 << 20 });
    assert.equal(app.bodyLimit, (3 << 20) + 1024);
    const data = archive("big", 2 << 20);
    const init = (body: Uint8Array): RequestInit => ({
      method: "POST",
      headers: {
        Authorization: `Bearer ${LEA}`,
        "Lantern-Platform": "switch",
        "Content-Type": "application/zip",
        "Content-Digest": digest(body),
      },
      body: body as BodyInit,
    });
    const handler = fetchHandler(app);
    const target = `api/lantern/v1/saves/${OWN}`;
    assert.equal((await handler(new Request(`http://shelf.example.org/${target}`, init(data)))).status, 201);
    assert.equal(
      (await handler(new Request(`http://shelf.example.org/${target}`, init(new Uint8Array(4 << 20))))).status,
      413,
    );
    const served = await listen(app);
    try {
      assert.equal((await fetch(`${served.url}${target}`, init(data))).status, 201);
      assert.equal((await fetch(`${served.url}${target}`, init(new Uint8Array(4 << 20)))).status, 413);
    } finally {
      await served.close();
    }
  });
});

describe("save backups in one request (SPEC.md § 9.2)", () => {
  test("Content-Digest required and checked; the fields kept; a zip in clear", async () => {
    const app = await lantern();
    const data = archive("one");
    const bare = await call(app, "POST", `saves/${OWN}`, { token: LEA, platform: "switch", body: data });
    assert.equal(bare.status, 400);
    const wrong = await post(app, data, { "Content-Digest": digest(archive("other")) });
    assert.equal(wrong.status, 422);
    assert.equal(wrong.json["code"], "digest_mismatch");
    assert.equal(
      (await call(app, "POST", `saves/${OWN}`, { token: LEA, body: data, headers: { "Content-Digest": digest(data) } }))
        .status,
      400,
    ); // no platform
    assert.equal(
      (
        await call(app, "POST", "saves/0100AB1200010800", {
          token: LEA,
          platform: "switch",
          body: data,
          headers: { "Content-Digest": digest(data) },
        })
      ).status,
      400,
    ); // an update's id, not a title's
    const notZip = new TextEncoder().encode("not a zip at all");
    assert.equal((await post(app, notZip)).status, 400);
    const ok = await post(app, data, {
      "Lantern-Save-Kind": "account",
      "Lantern-Game-Version": "196608",
      "Lantern-Profile": encodeURIComponent("Léa"),
      "Lantern-Note": encodeURIComponent("Chapter 4"),
    });
    assert.equal(ok.status, 201, JSON.stringify(ok.json));
    const { save_id: id, created, ...rest } = ok.json;
    assert.match(String(id), /^s_/);
    assert.match(String(created), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    assert.deepEqual(rest, {
      schema: 1,
      platform: "switch",
      title_id: OWN,
      size: data.length,
      sha256: sha(data),
      kind: "account",
      game_version_code: 196608,
      profile: "Léa",
      note: "Chapter 4",
      device: "Lea's Switch",
    });
  });

  test("kinds, slots, texts and sizes beyond their limits give 400 or 413", async () => {
    const app = await lantern({ saveBody: 2000 });
    const data = archive("limits");
    for (const headers of [
      { "Lantern-Save-Kind": "photos" },
      { "Lantern-Save-Slot": "a slot" },
      { "Lantern-Game-Version": "-1" },
      { "Lantern-Profile": encodeURIComponent("p".repeat(65)) },
      { "Lantern-Note": encodeURIComponent("n".repeat(121)) },
      { "Lantern-Note": "%E9" },
      { "Lantern-Note": encodeURIComponent("two\nlines") },
    ])
      assert.equal((await post(app, data, headers)).status, 400, JSON.stringify(headers));
    // A kind the platform's profile does not have (Annex A.2: the 3DS has device and other).
    const n3ds = await call(app, "POST", "saves/0004000000ABCD00", {
      token: LEA,
      platform: "3ds",
      body: data,
      headers: { "Content-Digest": digest(data), "Lantern-Save-Kind": "account" },
    });
    assert.equal(n3ds.status, 400);
    const big = archive("big", 3000);
    const r = await post(app, big);
    assert.equal(r.status, 413);
    assert.equal(r.json["code"], "too_large");
  });

  test("kept per title up to saves_kept_per_title, newest first; read with ranges; deleted", async () => {
    const app = await lantern({ savesKept: 2 });
    const made = [];
    for (const label of ["first", "second", "third"]) made.push((await post(app, archive(label))).json);
    await post(app, archive("elsewhere"), {}, LEA, "0500AB12CD020000");
    const listed = (await call(app, "GET", `saves?title_id=${OWN}`, { token: LEA })).json["saves"] as {
      save_id: string;
    }[];
    assert.deepEqual(
      listed.map((s) => s.save_id),
      [made[2]?.["save_id"], made[1]?.["save_id"]],
    );
    const every = (await call(app, "GET", "saves", { token: LEA })).json["saves"] as { title_id: string }[];
    assert.equal(every.length, 3);
    assert.deepEqual((await call(app, "GET", "saves", { token: NOOR })).json["saves"], []);
    const third = made[2] as { save_id: string; size: number; sha256: string };
    const path = `saves/${OWN}/${third.save_id}`;
    const whole = await call(app, "GET", path, { token: LEA });
    assert.equal(whole.status, 200);
    assert.equal(sha(whole.bytes), third.sha256);
    assert.equal(whole.headers.get("Repr-Digest"), `sha-256=:${Buffer.from(third.sha256, "hex").toString("base64")}:`);
    const part = await call(app, "GET", path, { token: LEA, headers: { Range: "bytes=0-9" } });
    assert.equal(part.status, 206);
    assert.deepEqual(part.bytes, whole.bytes.subarray(0, 10));
    assert.equal((await call(app, "GET", path, { token: NOOR })).status, 404);
    assert.equal((await call(app, "GET", path, { token: LEA, platform: "3ds" })).status, 404);
    assert.equal((await call(app, "GET", `saves/${OWN}/${made[0]?.["save_id"]}`, { token: LEA })).status, 404); // dropped
    assert.equal((await call(app, "DELETE", path, { token: NOOR })).status, 404);
    assert.equal((await call(app, "DELETE", path, { token: LEA })).status, 204);
    assert.equal((await call(app, "GET", path, { token: LEA })).status, 404);
  });

  test("the event save, to the account's own devices of its platform", async () => {
    const app = await lantern();
    const [mine, others] = [await since(app, LEA), await since(app, NOOR)];
    const saved = (await post(app, archive("event"))).json;
    const got = await events(app, LEA, mine);
    assert.deepEqual(
      got.map((e) => [e.event, e.data]),
      [
        [
          "save",
          {
            schema: 1,
            platform: "switch",
            title_id: OWN,
            save_id: saved["save_id"],
            created: saved["created"],
            device: "Lea's Switch",
          },
        ],
      ],
    );
    assert.deepEqual(await events(app, NOOR, others), []);
    assert.deepEqual(await events(app, LEA, mine, "android"), []);
  });
});

describe("resumable uploads (SPEC.md § 9.3)", () => {
  async function open(app: LanternApp, data: Uint8Array, extra: Record<string, unknown> = {}, token = LEA) {
    return call(app, "POST", `saves/${OWN}/uploads`, {
      token,
      platform: "switch",
      json: { schema: 1, size: data.length, sha256: sha(data), kind: "account", ...extra },
    });
  }
  const patch = (app: LanternApp, upload: string, offset: number, chunk: Uint8Array, headers = {}, token = LEA) =>
    call(app, "PATCH", upload, {
      token,
      body: chunk,
      headers: { "Content-Type": "application/offset+octet-stream", "Upload-Offset": String(offset), ...headers },
    });

  test("opened, sent in chunks, resumed from HEAD, finished; refused as § 9.3 says", async () => {
    const app = await lantern({ saveChunk: 400, saveSize: 4000 });
    const data = archive("upload", 900);
    const opened = await open(app, data, { slot: "slot-1", profile: "Lea", note: "Before the boss" });
    assert.equal(opened.status, 201);
    const upload = opened.json["upload"] as string;
    assert.match(upload, /^\/api\/lantern\/v1\/uploads\/u_/);
    assert.equal(opened.headers.get("Location"), upload);
    assert.equal(opened.json["chunk_size"], 400);
    assert.equal(opened.json["offset"], 0);
    assert.equal((await patch(app, upload, 0, data.subarray(0, 401))).status, 413);
    assert.equal(
      (await call(app, "PATCH", upload, { token: LEA, body: data.subarray(0, 10), headers: { "Upload-Offset": "0" } }))
        .status,
      400,
    );
    const first = await patch(app, upload, 0, data.subarray(0, 400));
    assert.equal(first.status, 204);
    assert.equal(first.headers.get("Upload-Offset"), "400");
    const wrong = await patch(app, upload, 0, data.subarray(0, 400));
    assert.equal(wrong.status, 409);
    assert.equal(wrong.headers.get("Upload-Offset"), "400");
    // A chunk whose Content-Digest does not match is not kept.
    const bad = await patch(app, upload, 400, data.subarray(400, 800), { "Content-Digest": digest(data) });
    assert.equal(bad.status, 422);
    const head = await call(app, "HEAD", upload, { token: LEA });
    assert.equal(head.status, 204);
    assert.equal(head.headers.get("Upload-Offset"), "400");
    assert.equal(head.headers.get("Upload-Length"), String(data.length));
    assert.equal((await call(app, "HEAD", upload, { token: NOOR })).status, 404); // another account's
    assert.equal(
      (await patch(app, upload, 400, data.subarray(400, 800), { "Content-Digest": digest(data.subarray(400, 800)) }))
        .status,
      204,
    );
    const last = await patch(app, upload, 800, data.subarray(800));
    assert.equal(last.status, 201);
    assert.equal(last.headers.get("Upload-Offset"), String(data.length));
    assert.equal(last.json["sha256"], sha(data));
    assert.equal(last.json["slot"], "slot-1");
    assert.equal(last.json["note"], "Before the boss");
    assert.equal((await call(app, "HEAD", upload, { token: LEA })).status, 404);
    const back = await call(app, "GET", `saves/${OWN}/${last.json["save_id"]}`, { token: LEA });
    assert.deepEqual(back.bytes, data);
  });

  test("a whole archive of another SHA-256 gives 422 and is discarded; DELETE abandons", async () => {
    const app = await lantern();
    const data = archive("digest");
    const opened = await open(app, data, { sha256: sha(archive("else")) });
    const upload = opened.json["upload"] as string;
    const r = await patch(app, upload, 0, data);
    assert.equal(r.status, 422);
    assert.equal(r.json["code"], "digest_mismatch");
    assert.equal((await call(app, "HEAD", upload, { token: LEA })).status, 404);
    const again = (await open(app, data)).json["upload"] as string;
    assert.equal((await call(app, "DELETE", again, { token: LEA })).status, 204);
    assert.equal((await call(app, "HEAD", again, { token: LEA })).status, 404);
    assert.deepEqual((await call(app, "GET", "saves", { token: LEA })).json["saves"], []);
  });

  test("its document: schema, size and sha256, limits, and what is not a zip", async () => {
    const app = await lantern({ saveSize: 1000 });
    const data = archive("doc");
    const schema2 = await call(app, "POST", `saves/${OWN}/uploads`, {
      token: LEA,
      platform: "switch",
      json: { schema: 2, size: 1, sha256: "0".repeat(64) },
    });
    assert.equal(schema2.status, 422);
    assert.equal(schema2.json["code"], "unsupported_schema");
    assert.equal((await open(app, data, { size: 1001 })).status, 413);
    assert.equal((await open(app, data, { size: 0 })).status, 400);
    assert.equal((await open(app, data, { sha256: "ABC" })).status, 400);
    assert.equal((await open(app, data, { kind: "photos" })).status, 400);
    const noPlatform = await call(app, "POST", `saves/${OWN}/uploads`, {
      token: LEA,
      json: { schema: 1, size: data.length, sha256: sha(data) },
    });
    assert.equal(noPlatform.status, 400);
    const text = new TextEncoder().encode("plain text, no zip");
    const upload = (await open(app, text)).json["upload"] as string;
    assert.equal((await patch(app, upload, 0, text)).status, 400);
    assert.equal((await call(app, "HEAD", upload, { token: LEA })).status, 404);
  });

  test("an upload past its expiry is gone", async () => {
    const store = new MemorySaveStore();
    const app = await lantern({ saves: store });
    const data = archive("late");
    const upload = (await open(app, data)).json["upload"] as string;
    const id = upload.split("/").at(-1) ?? "";
    // The store keeps it; the app sees its time is up.
    const kept = store.upload(id);
    assert.ok(kept);
    store.abandon(id);
    store.open({ ...kept, expires: "2020-01-01T00:00:00Z" });
    assert.ok([404, 410].includes((await call(app, "HEAD", upload, { token: LEA })).status));
  });
});

describe("encrypted backups (SPEC.md § 9.4)", () => {
  test("kept as sent with their encryption, whether uploaded or sent in one request; never opened", async () => {
    const app = await lantern();
    const key = SaveKey.generate();
    const encryption = await key.encryption();
    const sealed = await e2e.encryptBytes(key, archive("secret"));
    const one = await post(app, sealed, {
      "Content-Type": "application/octet-stream",
      "Lantern-Save-Encryption": `${e2e.SCHEME}; key_id=${encryption.key_id}`,
    });
    assert.equal(one.status, 201, JSON.stringify(one.json));
    assert.deepEqual(one.json["encryption"], encryption);
    const opened = await call(app, "POST", `saves/${OWN}/uploads`, {
      token: LEA,
      platform: "switch",
      json: { schema: 1, size: sealed.length, sha256: sha(sealed), encryption },
    });
    const done = await call(app, "PATCH", opened.json["upload"] as string, {
      token: LEA,
      body: sealed,
      headers: { "Content-Type": "application/offset+octet-stream", "Upload-Offset": "0" },
    });
    assert.equal(done.status, 201);
    assert.deepEqual(done.json["encryption"], encryption);
    const back = await call(app, "GET", `saves/${OWN}/${done.json["save_id"]}`, { token: LEA });
    assert.deepEqual(back.bytes, sealed);
    assert.equal(back.headers.get("Content-Type"), "application/octet-stream");
    const listed = (await call(app, "GET", "saves", { token: LEA })).json["saves"] as { encryption?: unknown }[];
    assert.equal(listed.filter((s) => s.encryption !== undefined).length, 2);
  });

  test("another scheme, a malformed key id, or bytes of another key's header give 400", async () => {
    const app = await lantern();
    const key = SaveKey.generate();
    const sealed = await e2e.encryptBytes(key, archive("secret"));
    for (const header of [
      "lantern-save-e2e-2; key_id=0a1b2c3d4e5f6071",
      `${e2e.SCHEME}; key_id=0A1B2C3D4E5F6071`,
      `${e2e.SCHEME}`,
      `${e2e.SCHEME}; key_id=0a1b2c3d4e5f6071`, // not this backup's key
    ])
      assert.equal((await post(app, sealed, { "Lantern-Save-Encryption": header })).status, 400, header);
    // A zip in clear announced as encrypted.
    const clear = archive("clear");
    const id = (await key.encryption()).key_id;
    assert.equal((await post(app, clear, { "Lantern-Save-Encryption": `${e2e.SCHEME}; key_id=${id}` })).status, 400);
  });

  test("a server without the family refuses a backup with an encryption (L-9.4-5)", async () => {
    const app = await lantern({ encryptedSaves: false });
    const features = (await call(app, "GET", "/api/lantern/v1/", { token: LEA })).json["features"] as Record<
      string,
      number
    >;
    assert.equal(features["saves"], 1);
    assert.equal(features["encrypted_saves"], 0);
    const key = SaveKey.generate();
    const sealed = await e2e.encryptBytes(key, archive("secret"));
    const header = `${e2e.SCHEME}; key_id=${(await key.encryption()).key_id}`;
    assert.equal((await post(app, sealed, { "Lantern-Save-Encryption": header })).status, 400);
    const upload = await call(app, "POST", `saves/${OWN}/uploads`, {
      token: LEA,
      platform: "switch",
      json: { schema: 1, size: sealed.length, sha256: sha(sealed), encryption: await key.encryption() },
    });
    assert.equal(upload.status, 400);
  });
});

describe("FileSaveStore: backups in a folder, its index read by the schema rule", () => {
  test("kept across a restart, served from the disk through node:http", async () => {
    const dir = join(folder, "saves-restart");
    const app = await lantern({ saves: await FileSaveStore.open(dir) });
    const data = archive("disk", 2000);
    const saved = (await post(app, data)).json;
    const upload = (
      await call(app, "POST", `saves/${OWN}/uploads`, {
        token: LEA,
        platform: "switch",
        json: { schema: 1, size: data.length, sha256: sha(data) },
      })
    ).json["upload"] as string;
    await call(app, "PATCH", upload, {
      token: LEA,
      body: data.subarray(0, 1000),
      headers: { "Content-Type": "application/offset+octet-stream", "Upload-Offset": "0" },
    });
    const again = await lantern({ saves: await FileSaveStore.open(dir) });
    const listed = (await call(again, "GET", "saves", { token: LEA })).json["saves"] as { save_id: string }[];
    assert.deepEqual(
      listed.map((s) => s.save_id),
      [saved["save_id"]],
    );
    assert.equal((await call(again, "HEAD", upload, { token: LEA })).headers.get("Upload-Offset"), "1000");
    const served = await listen(again);
    try {
      const r = await fetch(`${served.url}api/lantern/v1/saves/${OWN}/${saved["save_id"]}`, {
        headers: { Authorization: `Bearer ${LEA}`, Range: "bytes=100-199" },
      });
      assert.equal(r.status, 206);
      assert.deepEqual(new Uint8Array(await r.arrayBuffer()), data.subarray(100, 200));
    } finally {
      await served.close();
    }
  });

  test("an index without one, of a newer schema, or with fields it does not know", async () => {
    // Absent: a new store.
    const fresh = await FileSaveStore.open(join(folder, "saves-absent"));
    assert.equal(fresh.available, true);
    assert.deepEqual(fresh.saves("lea"), []);
    // Newer: read as absent, the family off, the file never written over.
    const newer = join(folder, "saves-newer");
    rmSync(newer, { recursive: true, force: true });
    const newerIndex = `${JSON.stringify({ schema: 2, saves: [{ user: "lea", save_id: "s_x" }] })}\n`;
    const { mkdirSync } = await import("node:fs");
    mkdirSync(newer, { recursive: true });
    writeFileSync(join(newer, "index.json"), newerIndex);
    const store = await FileSaveStore.open(newer);
    assert.equal(store.available, false);
    const app = await lantern({ saves: store });
    const features = (await call(app, "GET", "/api/lantern/v1/", { token: LEA })).json["features"] as Record<
      string,
      number
    >;
    assert.equal(features["saves"], 0);
    assert.equal((await post(app, archive("x"))).status, 404);
    assert.equal(readFileSync(join(newer, "index.json"), "utf8"), newerIndex);
    // Unknown fields, at the top and in an entry, kept when the index is written again.
    const known = join(folder, "saves-unknown");
    mkdirSync(join(known, "archives"), { recursive: true });
    const data = archive("old");
    writeFileSync(join(known, "archives", "s_old"), data);
    writeFileSync(
      join(known, "index.json"),
      JSON.stringify({
        schema: 1,
        written_by: "a later version",
        saves: [
          {
            user: "lea",
            platform: "switch",
            title_id: OWN,
            save_id: "s_old",
            created: "2026-10-01T10:00:00Z",
            size: data.length,
            sha256: sha(data),
            mood: "sunny",
          },
        ],
        uploads: {},
      }),
    );
    const kept = await lantern({ saves: await FileSaveStore.open(known) });
    const listed = (await call(kept, "GET", "saves", { token: LEA })).json["saves"] as Record<string, unknown>[];
    assert.equal(listed.length, 1);
    assert.equal(listed[0]?.["mood"], undefined); // a reader skips what it does not know
    assert.equal((await post(kept, archive("new"))).status, 201);
    const index = JSON.parse(readFileSync(join(known, "index.json"), "utf8"));
    assert.equal(index.written_by, "a later version");
    assert.equal(index.saves[0].mood, "sunny");
    assert.equal(index.saves.length, 2);
  });
});

describe("cheats written (SPEC.md § 10)", () => {
  const body = (text: string, extra: Record<string, unknown> = {}) => ({
    schema: 1,
    platform: "switch",
    title_id: OWN,
    build_id: "0123456789ABCDEF",
    source: "Lea tests",
    text,
    ...extra,
  });
  const TEXT = "[Endless lamp oil]\n04000000 00ABCDEF 00000063\n";

  test("posted, conflicting, replaced, deleted; each with its event library", async () => {
    const app = await lantern();
    const start = await since(app, LEA);
    const made = await call(app, "POST", "cheats", { token: LEA, json: body(TEXT, { note: "Lamp" }) });
    assert.equal(made.status, 201);
    assert.equal(made.json["sha256"], sha(new TextEncoder().encode(TEXT)));
    assert.equal(made.json["note"], "Lamp");
    const id = made.json["id"] as string;
    const twice = await call(app, "POST", "cheats", { token: LEA, json: body(TEXT, { source: "LEA TESTS" }) });
    assert.equal(twice.status, 409);
    const more = `${TEXT}[Slow comets]\n04000000 00ABCDF0 00000001\n`;
    assert.equal((await call(app, "PUT", `cheats/${id}`, { token: LEA, json: body(more) })).status, 204);
    const text = await call(app, "GET", `cheats/${id}`, { token: LEA });
    assert.equal(new TextDecoder().decode(text.bytes), more);
    const other = await call(app, "POST", "cheats", { token: LEA, json: body(TEXT, { source: "Noor" }) });
    assert.equal((await call(app, "PUT", `cheats/${other.json["id"]}`, { token: LEA, json: body(TEXT) })).status, 409);
    assert.equal((await call(app, "DELETE", `cheats/${id}`, { token: LEA })).status, 204);
    assert.equal((await call(app, "GET", `cheats/${id}`, { token: LEA })).status, 404);
    assert.equal((await call(app, "DELETE", `cheats/${id}`, { token: LEA })).status, 404);
    const got = await events(app, LEA, start);
    assert.ok(got.length >= 4 && got.every((e) => e.event === "library"));
    assert.deepEqual(got[0]?.data, { schema: 1, families: ["cheats"], platforms: ["switch"] });
  });

  test("its form: platform, title, build, source, note, size and the profile's format", async () => {
    const app = await lantern();
    const refused: [Record<string, unknown>, number][] = [
      [{ platform: "android" }, 400], // no cheats on Android (Annex A.5)
      [{ title_id: "0100AB1200010800" }, 400], // an update's id
      [{ build_id: undefined }, 400], // a Switch set is per build
      [{ build_id: "not hex" }, 400],
      [{ source: " spaced" }, 400],
      [{ source: "under_score" }, 400],
      [{ note: "n".repeat(121) }, 400],
      [{ text: "[Name]\nnot hex words\n" }, 400],
      [{ text: "[Name]\u0007\n" }, 400],
      [{ text: `[Big]\n${"04000000 00000000 00000000\n".repeat(40000)}` }, 413],
      [{ schema: 2 }, 422],
    ];
    for (const [extra, status] of refused)
      assert.equal(
        (await call(app, "POST", "cheats", { token: LEA, json: body(TEXT, extra) })).status,
        status,
        JSON.stringify(extra).slice(0, 80),
      );
    // Another profile's format, and a platform without a profile: the text is the platform's own.
    const vita = await call(app, "POST", "cheats", {
      token: LEA,
      json: {
        schema: 1,
        platform: "vita",
        title_id: "PCSE00001",
        text: "_V0 Infinite lamp oil\n$0200 8100A000 00000063\n",
      },
    });
    assert.equal(vita.status, 201);
    assert.equal(vita.json["source"], "Lantern");
    assert.equal(vita.json["build_id"], undefined);
  });

  test("refused without cheats.write, or by a library that does not write (405), or beyond a rating cap", async () => {
    const app = await lantern();
    assert.equal((await call(app, "POST", "cheats", { token: READER, json: body(TEXT) })).status, 403);
    assert.equal((await call(app, "POST", "cheats", { json: body(TEXT) })).status, 403); // anonymous
    const capped = await call(app, "POST", "cheats", { token: CAPPED, json: body(TEXT, { title_id: LUMEN }) });
    assert.equal(capped.status, 403);
    const set = (await call(app, "GET", `cheats?title_id=${LUMEN}`, { token: LEA })).json["cheats"] as { id: string }[];
    assert.equal((await call(app, "DELETE", `cheats/${set[0]?.id}`, { token: CAPPED })).status, 404);
    const lib = (await makeLantern()).library;
    const readOnly: Library = {
      families: lib.families,
      apps: () => lib.apps(),
      titles: (l) => lib.titles(l),
      homebrew: (l) => lib.homebrew(l),
      cheats: () => lib.cheats(),
      file: (id) => lib.file(id),
      cheatFile: (id) => lib.cheatFile(id),
      journal: () => undefined,
    };
    const { LanternApp: App } = await import("../../src/server/index.ts");
    const bare = new App(readOnly, {
      uid: "a1b2c3d4-0000-4000-8000-000000000002",
      name: "Read only",
      anonymousScopes: ["library", "cheats", "cheats.write"],
    });
    const r = await call(bare, "POST", "cheats", { json: body(TEXT) });
    assert.equal(r.status, 405);
    assert.equal(r.headers.get("Allow"), "GET, HEAD");
    assert.equal((await call(bare, "DELETE", `cheats/${set[0]?.id}`)).status, 405);
  });
});

describe("requests (SPEC.md § 11)", () => {
  test("made, made again, listed newest first, withdrawn; another account's is unknown", async () => {
    const app = await lantern();
    const start = await since(app, LEA);
    const first = await call(app, "POST", "requests", {
      token: LEA,
      platform: "switch",
      json: { schema: 1, title_id: OWN },
    });
    assert.equal(first.status, 201);
    assert.deepEqual(Object.keys(first.json), ["schema", "id", "platform", "title_id", "status", "created"]);
    assert.equal(first.json["status"], "open");
    const again = await call(app, "POST", "requests", {
      token: LEA,
      platform: "switch",
      json: { schema: 1, title_id: OWN },
    });
    assert.equal(again.status, 200);
    assert.equal(again.json["id"], first.json["id"]);
    const named = await call(app, "POST", "requests", {
      token: LEA,
      json: { schema: 1, platform: "switch", title_id: "0100CD3400020000" },
    });
    assert.equal(named.json["name"], "Copper Moth");
    assert.equal((await call(app, "POST", "requests", { token: LEA, json: { schema: 1, title_id: OWN } })).status, 400); // no platform
    assert.equal(
      (await call(app, "POST", "requests", { token: LEA, json: { schema: 1, platform: "switch", title_id: "nope" } }))
        .status,
      400,
    );
    const listed = (await call(app, "GET", "requests", { token: LEA })).json["requests"] as { id: string }[];
    assert.deepEqual(new Set(listed.map((r) => r.id)), new Set([first.json["id"], named.json["id"]]));
    assert.deepEqual((await call(app, "GET", "requests", { token: LEA, platform: "android" })).json["requests"], []);
    assert.deepEqual((await call(app, "GET", "requests", { token: NOOR })).json["requests"], []);
    const path = `requests/${first.json["id"]}`;
    assert.equal((await call(app, "DELETE", path, { token: NOOR })).status, 404);
    assert.equal((await call(app, "DELETE", path, { token: LEA })).status, 204);
    assert.equal((await call(app, "DELETE", path, { token: LEA })).status, 404);
    const got = await events(app, LEA, start);
    assert.deepEqual(
      got.map((e) => [e.event, e.data["status"] ?? (e.data["deleted"] ? "deleted" : "")]),
      [
        ["request", "open"],
        ["request", "open"],
        ["request", "deleted"],
      ],
    );
    assert.deepEqual(await events(app, NOOR, start), []);
  });

  test("done when its title comes, or as the server decides; a hidden title's name left out", async () => {
    const app = await lantern();
    const start = await since(app, LEA);
    const made = await call(app, "POST", "requests", {
      token: LEA,
      platform: "switch",
      json: { schema: 1, title_id: OWN },
    });
    const id = made.json["id"] as string;
    (app.library as MemoryLibrary).addAppFile({
      data: new Uint8Array(64),
      platform: "switch",
      title_id: OWN,
      app_id: OWN,
      type: "base",
      version_code: 0,
      name: "Glass Orchard",
      format: "nsp",
    });
    await new Promise((r) => setTimeout(r, 20));
    const now = (await call(app, "GET", "requests", { token: LEA })).json["requests"] as Record<string, unknown>[];
    assert.equal(now[0]?.["status"], "done");
    assert.equal(now[0]?.["name"], "Glass Orchard");
    assert.ok((await events(app, LEA, start)).some((e) => e.event === "request" && e.data["status"] === "done"));
    assert.equal(await app.setRequestStatus(id, "declined"), true);
    assert.equal(
      ((await call(app, "GET", "requests", { token: LEA })).json["requests"] as { status: string }[])[0]?.status,
      "declined",
    );
    assert.equal(await app.setRequestStatus("r_nothing", "done"), false);
    // A device capped below the title's rating sees the request, not its name (SPEC.md § 5.6).
    await call(app, "POST", "requests", { token: LEA, platform: "switch", json: { schema: 1, title_id: LUMEN } });
    const capped = (await call(app, "GET", "requests", { token: CAPPED })).json["requests"] as Record<
      string,
      unknown
    >[];
    const lumen = capped.find((r) => r["title_id"] === LUMEN);
    assert.ok(lumen);
    assert.equal(lumen["name"], undefined);
  });
});

describe("sections (SPEC.md § 6.5)", () => {
  test("their apps of the caller's platform, within its rating cap", async () => {
    const app = await lantern();
    const all = (await call(app, "GET", "sections", { token: LEA })).json["sections"] as {
      id: string;
      apps: string[];
    }[];
    assert.deepEqual(
      all.map((s) => [s.id, s.apps.length]),
      [
        ["new", 3],
        ["together", 1],
      ],
    );
    const android = (await call(app, "GET", "sections", { token: LEA, platform: "android" })).json["sections"] as {
      id: string;
      apps: string[];
    }[];
    assert.deepEqual(
      android.map((s) => [s.id, s.apps.length]),
      [["new", 1]],
    );
    const capped = (await call(app, "GET", "sections", { token: CAPPED })).json["sections"] as { id: string }[];
    assert.deepEqual(
      capped.map((s) => s.id),
      ["new"],
    );
  });
});

describe("deleting an account (SPEC.md § 5.7)", () => {
  test("its backups, uploads and requests erased with it", async () => {
    const app = await lantern();
    await post(app, archive("gone"), {}, NOOR);
    const data = archive("upload");
    const upload = (
      await call(app, "POST", `saves/${OWN}/uploads`, {
        token: NOOR,
        platform: "switch",
        json: { schema: 1, size: data.length, sha256: sha(data) },
      })
    ).json["upload"] as string;
    await call(app, "POST", "requests", { token: NOOR, platform: "switch", json: { schema: 1, title_id: OWN } });
    const store = app.saveStore as MemorySaveStore;
    assert.equal(store.saves("noor").length, 1);
    assert.equal((await call(app, "DELETE", "admin/users/noor?confirm=noor", { token: DEMO_TOKEN })).status, 204);
    assert.equal(store.saves("noor").length, 0);
    assert.equal(store.uploads("noor").length, 0);
    assert.equal(store.upload(upload.split("/").at(-1) ?? ""), undefined);
    assert.deepEqual(await app.requestStore?.requests("noor"), []);
  });
});
