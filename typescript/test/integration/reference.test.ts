/**
 * The client against the specification's reference server (spec/server, started
 * by test/fixtures/reference.py) over its fictional library: reading over plain
 * HTTP on loopback; pairing with a device key over a self-signed TLS key that
 * the client pins; bound tokens and signed requests, the clock's offset, saves
 * sent whole and by resumable upload, cheat writes, requests, the
 * administration API, invitations and rating caps.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import {
  BadRequest,
  Conflict,
  DeviceKey,
  Forbidden,
  Gone,
  homebrew as hb,
  IntegrityError,
  MemoryServerStore,
  NotFound,
  PinMismatch,
  SignatureRequired,
  short,
  TransportError,
  Unauthorized,
} from "../../src/index.ts";
import { FileServerStore, fileHashes, NodeLanternClient, NodeTransport } from "../../src/node/index.ts";
import { writeZip } from "../../src/server/zip.ts";
import { AGENT, PACKAGE, type Served, servePython } from "../helpers.ts";

interface Reference {
  url: string;
  spki: string | null;
  switch: number;
  served: number;
  served_homebrew: number;
  frostline: string;
  paperlamp: string;
  harbor: string;
  port: string;
  token?: string;
  admin_token?: string;
  admin_seed?: string;
  old_token?: string;
}

const HARNESS = join(PACKAGE, "test", "fixtures", "reference.py");
const LEA = ["library", "saves", "cheats", "cheats.write", "requests"];
const folder = mkdtempSync(join(tmpdir(), "lantern-reference-"));
const clients: NodeLanternClient[] = [];
const fast = (s: number) => new Promise<void>((r) => setTimeout(r, Math.min(s, 1.1) * 1000));

function track<C extends NodeLanternClient>(c: C): C {
  clients.push(c);
  return c;
}

async function admin(ref: Reference): Promise<NodeLanternClient> {
  const key = await DeviceKey.fromBase64(ref.admin_seed ?? "");
  return track(
    new NodeLanternClient(ref.url, {
      userAgent: AGENT,
      token: ref.admin_token ?? "",
      key,
      ...(ref.spki ? { pin: ref.spki } : {}),
    }),
  );
}

/** A device paired with `ref` by its admin, its token bound to a new key. */
async function pair(
  ref: Reference,
  scopes: string[],
  options: { ratingCap?: { age: number } } = {},
): Promise<NodeLanternClient> {
  const c = track(
    new NodeLanternClient(ref.url, { userAgent: AGENT, platform: "switch", ...(ref.spki ? { verify: false } : {}) }),
  );
  const pairing = await c.pair("Lea's console", scopes);
  const a = await admin(ref);
  const waiting = [];
  for await (const p of a.iterAdminPairings()) if (p.code === pairing.code) waiting.push(p);
  assert.equal(waiting.length, 1);
  assert.equal(waiting[0]?.key, pairing.key?.fingerprint);
  await a.approvePairing(waiting[0]?.id ?? "", {
    user: "lea",
    ...(options.ratingCap ? { ratingCap: options.ratingCap } : {}),
  });
  await c.waitForPairing(pairing, { sleep: fast });
  return c;
}

after(async () => {
  for (const c of clients) await c.close();
  rmSync(folder, { recursive: true, force: true });
});

describe("a public reference server, read over plain HTTP", () => {
  let server: Served<Reference>;
  let ref: Reference;
  let c: NodeLanternClient;
  before(async () => {
    server = await servePython<Reference>([HARNESS, "--public"]);
    ref = server.info;
    c = track(new NodeLanternClient(ref.url, { userAgent: AGENT, token: ref.token ?? "" }));
  });
  after(() => server.stop());

  test("the handshake", async () => {
    const hello = await c.handshake();
    assert.equal(hello.base, "/api/lantern");
    assert.equal(hello.account.state, "active");
    assert.deepEqual([...hello.platforms].sort(), ["3ds", "android", "linux", "switch"]);
    for (const family of ["library", "titles", "changes", "homebrew", "cheats"])
      assert.ok(await c.offers(family), family);
    assert.ok(!(await c.offers("saves")));
    assert.ok(await c.offers("pairing"));
  });

  test("apps, pages and platforms", async () => {
    const every = [];
    for await (const a of c.iterApps({ pageSize: 2 })) every.push(a);
    assert.equal(every.length, ref.served);
    assert.equal(new Set(every.map((a) => a.id)).size, ref.served);
    let switchApps = 0;
    for await (const _ of c.iterApps({ platform: "switch" })) switchApps++;
    assert.equal(switchApps, ref.switch);
    const page = await c.apps({ pageSize: 3, sort: "added" });
    assert.equal(page.items.length, 3);
    assert.ok(page.next);
    assert.equal(page.total, ref.served);
  });

  test("what is missing", async () => {
    const got = [];
    for await (const a of c.iterMissing([["0100ABCD00010000", 0]], ["update", "dlc"], { platform: "switch" }))
      got.push(`${a.app_id} ${a.version_code}`);
    assert.deepEqual(got.sort(), ["0100ABCD00010800 196608", "0100ABCD00011001 0"]);
    const bases = [];
    for await (const a of c.iterMissing([], ["base"], { platform: "android" })) bases.push(a.title_id);
    assert.deepEqual(bases, ["org.example.frostlinetales"]);
  });

  test("changes", async () => {
    const first = await c.changes();
    assert.deepEqual([first.added, first.removed], [[], []]);
    assert.ok((await c.changes(first.since)).since);
    await assert.rejects(c.changes("s_never_given"), BadRequest);
  });

  test("titles", async () => {
    const title = await c.title("0100ABCD00010000", { platform: "switch" });
    assert.equal(title.name, "Frostline Tales");
    assert.deepEqual(hb.effectiveGenres(title.genres), ["adventure", "puzzle"]);
    assert.equal(title.video?.external, true);
    const bulk = await c.titles(["0100ABCD00010000", "0100EFEF00020000", "0500000000000000"], { platform: "switch" });
    assert.deepEqual(new Set(bulk.titles.map((t) => t.title_id)), new Set(["0100ABCD00010000", "0100EFEF00020000"]));
    assert.deepEqual(bulk.unknown, ["0500000000000000"]);
    await assert.rejects(c.title("0500000000000000", { platform: "switch" }), NotFound);
  });

  test("homebrew: entries, signatures, install plans, requirements", async () => {
    const entries = [];
    for await (const e of c.iterHomebrew({ pageSize: 2 })) entries.push(e);
    assert.equal(entries.length, ref.served_homebrew);
    assert.ok(entries.every((e) => e.package.manifest === undefined));
    const kinds = new Map(entries.filter((e) => e.platform === "switch").map((e) => [e.id, hb.effectiveKind(e)]));
    assert.equal(kinds.get("org.example.ember-widget"), "app"); // a kind this library does not know
    const lamp = await c.homebrewEntry(ref.paperlamp, { platform: "switch" });
    assert.equal(await hb.verifySignature(lamp), true);
    assert.deepEqual(hb.installPlan(lamp), { free: [`/switch/${ref.paperlamp}/${ref.paperlamp}.nro`], consent: [] });
    const frost = await c.homebrewEntry(ref.frostline, { platform: "switch" });
    assert.ok(hb.installPlan(frost).free.length > 0);
    assert.equal(hb.offer(frost, { atmosphere: "1.8.0" }).decision, "offer");
    assert.equal(hb.offer(frost, { atmosphere: "1.6.2" }).decision, "refuse");
    const overlay = await c.homebrewEntry("org.example.ember-overlay", { platform: "switch" });
    assert.ok(hb.installPlan(overlay).consent.length > 0);
    await assert.rejects(c.homebrewEntry(ref.frostline), BadRequest); // on two platforms: name one
  });

  test("ports and architectures", async () => {
    const harbor = await c.homebrewEntry(ref.harbor, { platform: "linux" });
    assert.deepEqual(hb.portProblems(harbor), []);
    for (const p of [harbor.package, ...(harbor.packages ?? [])]) {
      assert.equal(await hb.verifySignature(harbor, p), true);
      assert.deepEqual(hb.installPlan(harbor, p).consent, ["/Harbor Lights.sh"]);
    }
    assert.deepEqual(hb.pickPackage(harbor, "x86_64")?.arch, ["x86_64"]);
    assert.equal(hb.pickPackage(harbor, "x86"), undefined);
    const offer = hb.offer(harbor, { glibc: "2.31", ram_mb: 2048, screen: "1280x720", gpu: ["gles2"] });
    assert.equal(offer.decision, "warn");
    assert.ok(offer.reasons.some((r) => r.includes("kernel")));
    const port = await c.homebrewEntry(ref.port, { platform: "switch" });
    const pak = new TextEncoder().encode("frost.pak 1.1 ".repeat(64));
    const ok = hb.launchCheck(
      port,
      new Map([
        ["data/frost.pak", fileHashes(pak)],
        ["music/demo.pak", fileHashes(new TextEncoder().encode("demo"))],
      ]),
    );
    assert.ok(ok.ok, JSON.stringify(ok));
    assert.ok(!hb.launchCheck(port, new Map([["data/frost.pak", fileHashes(new TextEncoder().encode("another"))]])).ok);
  });

  test("homebrew updates", async () => {
    const got = [];
    for await (const e of c.iterHomebrewUpdates(
      [
        [ref.frostline, 10000],
        [ref.paperlamp, 902],
      ],
      { platform: "switch" },
    ))
      got.push(e.id);
    assert.deepEqual(got, [ref.frostline]);
  });

  test("cheats", async () => {
    assert.equal((await c.cheats({ platform: "switch" })).cheats.length, 3);
    const some = await c.cheats({ titleId: "0100ABCD00010000", buildId: "4A1B2C3D4E5F6071" });
    assert.deepEqual(new Set(some.cheats.map((s) => s.source)), new Set(["Community list", "Noor"]));
    assert.ok(some.cheats[0]);
    assert.ok((await c.cheatText(some.cheats[0])).startsWith("["));
  });

  test("downloads, resumed, and refused when not their document's", async () => {
    const apps = [];
    for await (const a of c.iterApps({ platform: "switch" })) apps.push(a);
    const app = apps.sort((a, b) => a.size - b.size).at(-1);
    assert.ok(app);
    const dest = await c.downloadAppTo(app, join(folder, "game.nsp"));
    const data = readFileSync(dest);
    assert.equal(createHash("sha256").update(data).digest("hex"), app.sha256);
    writeFileSync(join(folder, "again.nsp.part"), data.subarray(0, Math.floor(data.length / 3)));
    await c.downloadAppTo(app, join(folder, "again.nsp"));
    assert.deepEqual(readFileSync(join(folder, "again.nsp")), data);
    const lamp = await c.homebrewEntry(ref.paperlamp, { platform: "switch" });
    await c.downloadPackageTo(lamp.package, join(folder, "lamp.nro"));
    assert.equal(statSync(join(folder, "lamp.nro")).size, lamp.package.size);
    await assert.rejects(
      c.downloadToFile(app.file, join(folder, "wrong.nsp"), { sha256: "0".repeat(64), size: app.size }),
      IntegrityError,
    );
  });

  test("credentials", async () => {
    await assert.rejects(
      track(new NodeLanternClient(ref.url, { userAgent: AGENT, token: "et_not-a-token" })).handshake(),
      Unauthorized,
    );
    const anonymous = track(new NodeLanternClient(ref.url, { userAgent: AGENT }));
    assert.equal((await anonymous.handshake()).account.state, "anonymous");
    assert.ok(!(await anonymous.offers("cheats")));
    await assert.rejects(anonymous.cheats(), Forbidden);
  });
});

describe("a private reference server over TLS, its key pinned", () => {
  let server: Served<Reference>;
  let ref: Reference;
  before(async () => {
    server = await servePython<Reference>([HARNESS, "--tls"]);
    ref = server.info;
  });
  after(() => server.stop());

  test("pairing with a key, over a key the client reads and pins", async () => {
    const spki = ref.spki ?? "";
    const c = track(new NodeLanternClient(ref.url, { userAgent: AGENT, verify: false, platform: "switch" }));
    assert.equal((await c.handshake()).account.state, "anonymous");
    const pairing = await c.pair("Lea's console", LEA);
    assert.equal(pairing.fingerprint, short(spki)); // what the console shows next to the code
    assert.equal(await c.pollPairing(pairing), undefined);
    const a = await admin(ref);
    const found = (await a.adminPairings()).items.find((p) => p.code === pairing.code);
    await a.approvePairing(found?.id ?? "", { user: "lea" });
    const store = new FileServerStore(join(folder, "servers.json"));
    const record = await c.waitForPairing(pairing, { store, sleep: fast });
    assert.ok(record.bound && record.spki === spki && record.key !== undefined);
    assert.deepEqual([...record.scopes].sort(), [...LEA].sort());
    const hello = await c.handshake();
    assert.ok(hello.account.bound);
    assert.equal(hello.account.name, "lea");
    let n = 0;
    for await (const _ of c.iterApps({ pageSize: 4 })) n++;
    assert.equal(n, ref.switch);
    assert.equal(statSync(join(folder, "servers.json")).mode & 0o077, 0);
    const kept = await store.server(record.uid);
    assert.ok(kept);
    const again = await NodeLanternClient.paired(kept, { userAgent: AGENT });
    clients.push(again);
    assert.ok((await again.handshake()).account.bound);
    const stolen = track(new NodeLanternClient(ref.url, { userAgent: AGENT, pin: spki, token: kept.token }));
    await assert.rejects(stolen.apps(), Unauthorized); // the token without its key is worth nothing
  });

  test("a pinned key that is not the server's, and no CA for a self-signed one", async () => {
    const wrong = track(
      new NodeLanternClient(ref.url, { userAgent: AGENT, transport: new NodeTransport({ pin: "0".repeat(64) }) }),
    );
    await assert.rejects(wrong.handshake(), PinMismatch);
    const strict = track(new NodeLanternClient(ref.url, { userAgent: AGENT }));
    await assert.rejects(
      strict.handshake(),
      (e: unknown) => e instanceof TransportError && !(e instanceof PinMismatch),
    );
  });

  test("an invitation's link pins its key, and its rating cap applies", async () => {
    const a = await admin(ref);
    const expires = new Date(Date.now() + 2 * 86400000).toISOString().replace(/\.\d{3}Z$/, "Z");
    const invitation = await a.createInvitation("lea", ["library"], {
      expires,
      devices: 1,
      ratingCap: { age: 6 },
      note: "Ines's console",
    });
    assert.ok(invitation.link.includes(ref.spki ?? "") && invitation.link.includes(invitation.code));
    const [child, record] = await NodeLanternClient.fromInvitation(
      invitation.link,
      "Ines's console",
      ["library", "cheats"],
      {
        store: new MemoryServerStore(),
        userAgent: AGENT,
      },
    );
    clients.push(child);
    assert.equal(record.spki, ref.spki);
    assert.deepEqual(record.scopes, ["library"]);
    assert.deepEqual(record.rating_cap, { age: 6 });
    await child.handshake();
    assert.equal(child.ratingCap?.age, 6);
    const seen = new Set<string>();
    for await (const app of child.iterApps()) seen.add(app.title_id);
    const every = new Set<string>();
    for await (const app of a.iterApps()) every.add(app.title_id);
    assert.ok(seen.size < every.size && [...seen].every((t) => every.has(t)));
    await assert.rejects(
      NodeLanternClient.fromInvitation(invitation.link, "Another console", ["library"], { userAgent: AGENT }),
      Gone,
    );
    const listed = [];
    for await (const i of a.iterAdminInvitations()) listed.push(i.id);
    assert.ok(!listed.includes(invitation.id));
  });
});

describe("a private reference server over plain HTTP: writes and administration", () => {
  let server: Served<Reference>;
  let ref: Reference;
  before(async () => {
    server = await servePython<Reference>([HARNESS]);
    ref = server.info;
  });
  after(() => server.stop());

  test("the clock's offset", async () => {
    const a = await admin(ref);
    a.clockOffset = -3600; // a console's clock an hour late
    assert.ok((await a.handshake()).account.bound); // refused signature_expired, then signed again with the server's Date
    assert.ok(Math.abs(a.clockOffset) < 60);
  });

  test("saves, whole and by resumable upload", async () => {
    const c = await pair(ref, LEA);
    const text = new TextEncoder();
    const small = writeZip([{ name: "save/data.bin", data: text.encode("chapter 4".repeat(100)) }]);
    const one = await c.save("0100ABCD00010000", small, {
      kind: "account",
      gameVersionCode: 196608,
      profile: "Léa",
      note: "Ch. 4",
    });
    assert.equal(one.size, small.length);
    assert.equal(one.profile, "Léa");
    assert.equal(one.note, "Ch. 4");
    const world = new Uint8Array(
      createHash("shake256", { outputLength: 5 << 19 })
        .update("Noor's world")
        .digest(),
    );
    const big = join(folder, "big.zip");
    writeFileSync(big, writeZip([{ name: "save/world.bin", data: world }]));
    const hello = await c.handshake();
    assert.ok(hello.limits?.save_body);
    // An upload cut after its first chunk, then resumed from HEAD's offset.
    const whole = readFileSync(big);
    const seen: number[] = [];
    let opened = "";
    await assert.rejects(
      c.uploadSaveFile("0100ABCD00010000", big, {
        progress: (n) => {
          if (n < whole.length) {
            opened = c.lastUpload ?? "";
            throw new TransportError("a lost connection");
          }
        },
      }),
      TransportError,
    );
    assert.ok(opened);
    const [offset, length] = await c.uploadOffset(opened);
    assert.ok(offset > 0 && offset < whole.length);
    assert.equal(length, whole.length);
    const resumed = await c.uploadSaveFile("0100ABCD00010000", big, { resume: opened, progress: (n) => seen.push(n) });
    assert.equal(resumed.size, whole.length);
    assert.equal(seen.at(-1), whole.length);
    const again = await c.uploadSaveFile("0100ABCD00010000", big, { kind: "account", profile: "Noor" });
    const listed = (await c.saves({ titleId: "0100ABCD00010000" })).saves.map((s) => s.save_id);
    for (const s of [one, resumed, again]) assert.ok(listed.includes(s.save_id));
    await c.downloadSaveTo(again, join(folder, "back.zip"));
    assert.deepEqual(readFileSync(join(folder, "back.zip")), whole);
    for (const s of [one, resumed, again]) await c.deleteSave(s);
    await assert.rejects(c.deleteSave(one), NotFound);
  });

  test("cheats written", async () => {
    const c = await pair(ref, LEA);
    const text = "[Endless lamp oil]\n04000000 00ABCDEF 00000063\n";
    const made = await c.createCheat("switch", "0100ABCD00010000", text, {
      buildId: "4A1B2C3D4E5F6071",
      source: "Lea tests",
    });
    assert.equal(made.source, "Lea tests");
    await assert.rejects(
      c.createCheat("switch", "0100ABCD00010000", text, { buildId: "4A1B2C3D4E5F6071", source: "Lea tests" }),
      Conflict,
    );
    const more = `${text}[Brighter lamp]\n04000000 00ABCDF0 00000001\n`;
    await c.replaceCheat(made.id, "switch", "0100ABCD00010000", more, {
      buildId: "4A1B2C3D4E5F6071",
      source: "Lea tests",
    });
    const listed = (await c.cheats({ titleId: "0100ABCD00010000" })).cheats.find((s) => s.id === made.id);
    assert.ok(listed);
    assert.equal(await c.cheatText(listed), more);
    await c.deleteCheat(made.id);
    assert.ok(!(await c.cheats()).cheats.some((s) => s.id === made.id));
  });

  test("requests", async () => {
    const c = await pair(ref, LEA);
    const first = await c.requestTitle("0100FFFF00090000");
    assert.equal(first.status, "open");
    assert.equal(first.platform, "switch");
    assert.equal((await c.requestTitle("0100FFFF00090000")).id, first.id); // the open one again
    assert.ok((await c.requests()).requests.some((r) => r.id === first.id));
    await c.withdrawRequest(first.id);
    await assert.rejects(c.withdrawRequest(first.id), NotFound);
  });

  test("administration", async () => {
    const a = await admin(ref);
    const name = `noor-${Date.now().toString(36)}`;
    assert.equal((await a.createUser(name, ["library"])).state, "active");
    await assert.rejects(a.createUser(name, ["library"]), Conflict);
    const names = [];
    for await (const u of a.iterAdminUsers({ pageSize: 1 })) names.push(u.name);
    assert.ok(names.includes(name));
    assert.equal((await a.updateUser(name, { state: "frozen" })).state, "frozen");
    const device = await pair(ref, ["library"]);
    const mine = [];
    for await (const d of a.iterAdminDevices({ user: "lea" })) if (d.device === "Lea's console") mine.push(d);
    assert.ok(mine.length > 0 && mine.every((d) => d.bound && d.key));
    for (const d of mine) await a.revokeDevice(d.id);
    await assert.rejects(device.apps(), Unauthorized);
    const refused = track(new NodeLanternClient(ref.url, { userAgent: AGENT }));
    const pairing = await refused.pair("Someone's console", ["library"]);
    const waiting = (await a.adminPairings()).items.find((p) => p.code === pairing.code);
    await a.refusePairing(waiting?.id ?? "");
    await assert.rejects(refused.pollPairing(pairing), Gone);
  });
});

describe("a reference server that takes only bound tokens", () => {
  let server: Served<Reference>;
  before(async () => {
    server = await servePython<Reference>([HARNESS, "--bound-only"]);
  });
  after(() => server.stop());

  test("a pairing without a key, and an old bearer-only token, are refused", async () => {
    const ref = server.info;
    const c = track(new NodeLanternClient(ref.url, { userAgent: AGENT }));
    const hello = await c.handshake();
    assert.equal(hello.auth?.bearer_only, false);
    await assert.rejects(
      c.pair("Lea's console", ["library"], { key: false }),
      (e: unknown) => e instanceof BadRequest && e.code === "key_required",
    );
    const old = track(new NodeLanternClient(ref.url, { userAgent: AGENT, token: ref.old_token ?? "" }));
    await assert.rejects(old.apps(), SignatureRequired);
  });
});
