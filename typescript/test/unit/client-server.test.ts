/**
 * The client against the toolkit's own server (the demo of test/demo.ts), in
 * this process over HTTP on loopback: listings and cursors, what is missing,
 * files, titles, homebrew, cheats, pairing with a device key, signed requests
 * and the clock, the administration API, invitations and rating caps. Then the
 * client alone, over a fetch() of the test's: the token sent to the server's
 * origin only, and the Deprecation and Sunset headers.
 */

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import {
  BadRequest,
  Conflict,
  DeviceKey,
  FetchTransport,
  Forbidden,
  Gone,
  homebrew as hb,
  IntegrityError,
  LanternClient,
  MemoryServerStore,
  MemorySink,
  NotFound,
  SignatureRequired,
  Unauthorized,
} from "../../src/index.ts";
import { NodeLanternClient } from "../../src/node/index.ts";
import { type LanternApp, listen } from "../../src/server/index.ts";
import { DEMO_SEED, DEMO_TOKEN, makeLantern } from "../demo.ts";
import { AGENT } from "../helpers.ts";

let served: Awaited<ReturnType<typeof listen>>;
let app: LanternApp;
let adminKey: DeviceKey;
const clients: LanternClient[] = [];

function client(options: ConstructorParameters<typeof NodeLanternClient>[1] = {}): NodeLanternClient {
  const c = new NodeLanternClient(served.url, { userAgent: AGENT, ...options });
  clients.push(c);
  return c;
}

function admin(): NodeLanternClient {
  return client({ token: DEMO_TOKEN, key: adminKey });
}

before(async () => {
  app = await makeLantern();
  app.desk?.accounts; // the toolkit pairs
  if (app.desk) app.desk.interval = 1;
  served = await listen(app);
  adminKey = await DeviceKey.fromSeed(DEMO_SEED);
});

after(async () => {
  for (const c of clients) await c.close();
  await served.close();
});

const fast = (s: number) => new Promise<void>((r) => setTimeout(r, Math.min(s, 1.05) * 1000));

describe("reading", () => {
  test("the handshake, anonymous and with a bound token", async () => {
    const anonymous = client();
    const hello = await anonymous.handshake();
    assert.equal(hello.account.state, "anonymous");
    assert.deepEqual(hello.platforms, ["3ds", "android", "linux", "switch"]);
    assert.ok(await anonymous.offers("library"));
    assert.ok(!(await anonymous.offers("admin")));
    const mira = admin();
    const bound = await mira.handshake();
    assert.equal(bound.account.bound, true);
    assert.ok(await mira.offers("admin"));
  });

  test("apps, page by page, sorted and filtered", async () => {
    const c = client({ platform: "switch" });
    const every = [];
    for await (const a of c.iterApps({ pageSize: 2 })) every.push(a);
    assert.equal(every.length, 7);
    assert.equal(new Set(every.map((a) => a.id)).size, 7);
    const added = await c.apps({ sort: "added", pageSize: 3 });
    assert.equal(added.items[0]?.name, "Quiet Tide");
    assert.ok(added.next);
    await assert.rejects(c.apps({ cursor: `${added.next}x` }), BadRequest);
    const updates = [];
    for await (const a of c.iterApps({ type: "update" })) updates.push(a.type);
    assert.deepEqual(new Set(updates), new Set(["update"]));
    assert.equal((await c.apps({ platform: "android" })).items.length, 1);
  });

  test("what is missing, and changes", async () => {
    const c = client({ platform: "switch" });
    const got = [];
    for await (const a of c.iterMissing([["0100AB1200010000", 65536]], ["update", "dlc"]))
      got.push([a.app_id, a.version_code]);
    assert.deepEqual(got.sort(), [
      ["0100AB1200010800", 131072],
      ["0100AB1200011001", 0],
    ]);
    const first = await c.changes();
    assert.deepEqual([first.added, first.removed], [[], []]);
    assert.ok((await c.changes(first.since)).since);
    await assert.rejects(c.changes("s_never_given"), BadRequest);
  });

  test("files: whole, resumed, and refused when not their document's", async () => {
    const c = client({ platform: "switch" });
    const app = (await c.apps({ sort: "added" })).items.find((a) => a.size === 900);
    assert.ok(app);
    const whole = new MemorySink();
    await c.downloadApp(app, whole);
    const data = whole.bytes();
    assert.equal(data.length, 900);
    const part = new MemorySink();
    await part.append(data.subarray(0, 300));
    let progress = 0;
    await c.downloadApp(app, part, { progress: (n) => (progress = n) });
    assert.deepEqual(part.bytes(), data);
    assert.equal(progress, 900);
    const wrong = new MemorySink();
    await assert.rejects(c.download(app.file, wrong, { sha256: "0".repeat(64), size: app.size }), IntegrityError);
    assert.equal(await wrong.heldSize(), 0);
  });

  test("titles", async () => {
    const c = client({ platform: "switch" });
    assert.equal((await c.title("0100AB1200010000")).name, "Lumen Drift");
    const bulk = await c.titles(["0100AB1200010000", "0100CD3400020000", "0500000000000000"]);
    assert.deepEqual(bulk.unknown, ["0500000000000000"]);
    await assert.rejects(c.title("0500000000000000"), NotFound);
    const changes = [];
    for await (const x of c.iterTitleChanges()) changes.push(x);
    assert.equal(changes.at(-1)?.more, false);
  });

  test("homebrew: listings without manifests, entries with them, signatures and plans", async () => {
    const c = client();
    const entries = [];
    for await (const e of c.iterHomebrew({ pageSize: 2 })) entries.push(e);
    assert.equal(entries.length, 7);
    assert.ok(entries.every((e) => e.package.manifest === undefined));
    const star = await c.homebrewEntry("org.example.starjar", { platform: "switch" });
    assert.equal(await hb.verifySignature(star), true);
    assert.equal(hb.installPlan(star).free.length, 2);
    await assert.rejects(c.homebrewEntry("org.example.starjar"), BadRequest); // on two platforms
    const harbor = await c.homebrewEntry("org.example.harborglow", { platform: "linux" });
    assert.deepEqual(hb.pickPackage(harbor, "x86_64")?.arch, ["x86_64"]);
    const updates = [];
    for await (const e of c.iterHomebrewUpdates([["org.example.starjar", 1]], { platform: "switch" }))
      updates.push(e.id);
    assert.deepEqual(updates, ["org.example.starjar"]);
  });

  test("cheats", async () => {
    const c = client({ platform: "switch" });
    const sets = (await c.cheats({ titleId: "0100AB1200010000" })).cheats;
    assert.equal(sets.length, 2);
    assert.ok(sets[0]);
    assert.ok((await c.cheatText(sets[0])).startsWith("["));
  });

  test("credentials", async () => {
    await assert.rejects(client({ token: "et_not-a-token" }).handshake(), Unauthorized);
    await assert.rejects(client({ token: DEMO_TOKEN }).apps(), SignatureRequired); // the token without its key is worth nothing
    await assert.rejects(client().adminUsers(), Unauthorized);
  });
});

describe("pairing, signed requests and administration", () => {
  test("pairing with a key, approved by the admin, then signed requests", async () => {
    const store = new MemoryServerStore();
    const c = client({ platform: "switch" });
    const pairing = await c.pair("Lea's console", ["library", "cheats"]);
    assert.match(pairing.code, /^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/);
    assert.ok(pairing.verifyComplete.includes(pairing.code));
    assert.equal(await c.pollPairing(pairing), undefined); // 202: waiting
    const mira = admin();
    const waiting = [];
    for await (const p of mira.iterAdminPairings()) if (p.code === pairing.code) waiting.push(p);
    assert.equal(waiting.length, 1);
    assert.equal(waiting[0]?.key, pairing.key?.fingerprint);
    await mira.approvePairing(waiting[0]?.id ?? "", { user: "noor" });
    const record = await c.waitForPairing(pairing, { store, sleep: fast });
    assert.equal(record.bound, true);
    assert.deepEqual(record.scopes, ["library"]); // what noor holds of what was asked
    assert.ok(record.key); // Node keeps the seed
    assert.equal((await c.handshake()).account.bound, true);
    const again = await NodeLanternClient.paired((await store.server(record.uid)) ?? record, { userAgent: AGENT });
    clients.push(again);
    assert.equal((await again.handshake()).account.name, "noor");
    await assert.rejects(again.cheats(), Forbidden);
  });

  test("the clock: a console an hour late signs again with the server's Date", async () => {
    const mira = admin();
    mira.clockOffset = -3600;
    assert.equal((await mira.handshake()).account.bound, true);
    assert.ok(Math.abs(mira.clockOffset) < 60);
  });

  test("a refused pairing gives 410", async () => {
    const c = client();
    const pairing = await c.pair("Someone's console", ["library"], { key: false });
    const mira = admin();
    const found = (await mira.adminPairings()).items.find((p) => p.code === pairing.code);
    assert.ok(found);
    await mira.refusePairing(found.id);
    await assert.rejects(c.pollPairing(pairing), Gone);
  });

  test("accounts and devices", async () => {
    const mira = admin();
    const made = await mira.createUser("ines", ["library"]);
    assert.equal(made.state, "active");
    await assert.rejects(mira.createUser("ines", ["library"]), Conflict);
    assert.equal((await mira.updateUser("ines", { state: "frozen" })).state, "frozen");
    const names = [];
    for await (const u of mira.iterAdminUsers({ pageSize: 1 })) names.push(u.name);
    assert.ok(names.includes("ines"));
    const c = client();
    const pairing = await c.pair("Noor's tablet", ["library"]);
    const found = (await mira.adminPairings()).items.find((p) => p.code === pairing.code);
    await mira.approvePairing(found?.id ?? "", { user: "noor" });
    await c.waitForPairing(pairing, { sleep: fast });
    const devices = [];
    for await (const d of mira.iterAdminDevices({ user: "noor" })) if (d.device === "Noor's tablet") devices.push(d);
    assert.equal(devices.length, 1);
    assert.equal(devices[0]?.bound, true);
    await mira.revokeDevice(devices[0]?.id ?? "");
    await assert.rejects(c.apps(), Unauthorized);
  });

  test("an invitation, redeemed once, with a rating cap", async () => {
    const mira = admin();
    const expires = new Date(Date.now() + 2 * 86400000).toISOString().replace(/\.\d{3}Z$/, "Z");
    const invitation = await mira.createInvitation("noor", ["library"], {
      expires,
      devices: 1,
      ratingCap: { age: 6 },
      note: "Ines's console",
    });
    assert.ok(invitation.link.includes(invitation.code));
    const store = new MemoryServerStore();
    const [child, record] = await NodeLanternClient.fromInvitation(
      invitation.link,
      "Ines's console",
      ["library", "cheats"],
      {
        store,
        userAgent: AGENT,
        platform: "switch",
      },
    );
    clients.push(child);
    assert.deepEqual(record.scopes, ["library"]);
    assert.deepEqual(record.rating_cap, { age: 6 });
    await child.handshake();
    assert.equal(child.ratingCap?.age, 6);
    const seen = new Set<string>();
    for await (const a of child.iterApps()) seen.add(a.title_id);
    assert.ok(!seen.has("0100AB1200010000")); // PEGI 7, above the cap
    assert.ok(seen.has("0100CD3400020000")); // unrated, shown
    await assert.rejects(child.title("0100AB1200010000"), NotFound);
    await assert.rejects(
      NodeLanternClient.fromInvitation(invitation.link, "Another console", ["library"], { userAgent: AGENT }),
      Gone,
    );
  });
});

describe("the client alone", () => {
  function stub(answer: (request: Request) => Response): { fetch: typeof fetch; seen: Request[] } {
    const seen: Request[] = [];
    return {
      seen,
      fetch: async (input, init) => {
        const request = new Request(input, init);
        seen.push(request);
        return answer(request);
      },
    };
  }

  const hello = {
    schema: 1,
    uid: "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f",
    name: "Stub shelf",
    base: "/api/lantern",
    versions: [1],
    platforms: ["switch"],
    account: { state: "active", scopes: ["library"], bound: false },
    features: { library: 1 },
  };
  const json = (doc: unknown, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(doc), { headers: { "Content-Type": "application/json", ...headers } });

  test("the token goes to the server's origin only", async () => {
    const file = new TextEncoder().encode("frost");
    const sha256 = "a1d71dcd0a39c2b0a7ff0e5ea2e1c11fa3eecf5d4cbff1e9fe13a6ddfd3c4e53";
    const { fetch, seen } = stub((r) => (r.url.endsWith("/.well-known/lantern") ? json(hello) : new Response(file)));
    const key = await DeviceKey.generate();
    const c = new LanternClient("https://shelf.example.org/", {
      userAgent: AGENT,
      token: "et_lea",
      key,
      transport: new FetchTransport({ fetch }),
    });
    await c.handshake();
    await assert.rejects(c.fetchFile("https://media.example.org/frost.bin", { sha256, size: 5 }), IntegrityError);
    const [own, other] = seen;
    assert.equal(own?.headers.get("Authorization"), "Bearer et_lea");
    assert.ok(own?.headers.get("Signature"));
    assert.equal(other?.headers.get("Authorization"), null);
    assert.equal(other?.headers.get("Signature"), null);
    assert.equal(other?.headers.get("Signature-Input"), null);
  });

  test("Deprecation and Sunset are recorded once", async () => {
    const found: string[] = [];
    const { fetch } = stub(() =>
      json(hello, {
        Deprecation: "@1793318400",
        Sunset: "Sun, 01 Aug 2027 00:00:00 GMT",
        Link: '<https://lantern.boreale.dev/spec/#34-deprecation-and-sunset>; rel="deprecation"',
      }),
    );
    const c = new LanternClient("https://shelf.example.org/", {
      userAgent: AGENT,
      transport: new FetchTransport({ fetch }),
      onDeprecation: (d) => found.push(d.what),
    });
    await c.handshake();
    await c.handshake();
    assert.deepEqual(found, ["handshake"]);
    assert.deepEqual(c.deprecations[0], {
      what: "handshake",
      since: "@1793318400",
      sunset: "Sun, 01 Aug 2027 00:00:00 GMT",
      link: "https://lantern.boreale.dev/spec/#34-deprecation-and-sunset",
    });
  });

  test("plain HTTP is refused off loopback, and a pin needs a transport that can", () => {
    assert.throws(() => new LanternClient("http://192.0.2.10/"), /loopback/);
    assert.throws(() => new LanternClient("https://192.0.2.10/", { pin: "0".repeat(64) }), /NodeTransport/);
  });
});
