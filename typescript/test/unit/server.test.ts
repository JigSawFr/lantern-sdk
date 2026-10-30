/**
 * The server toolkit's pieces on their own (the conformance suite checks the
 * whole, in test/integration): sealed cursors, ranges, request documents,
 * missing apps, the adapters' limits, zip archives, and LAN discovery.
 */

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { type App, discovery } from "../../src/index.ts";
import { discover } from "../../src/node/index.ts";
import {
  Cursors,
  DiscoveryResponder,
  HttpProblem,
  isLocalAddress,
  listen,
  missing,
  parseRange,
  readDocument,
  readZip,
  Sealer,
  ServerRequest,
  writeZip,
} from "../../src/server/index.ts";
import { makeLantern } from "../demo.ts";
import { AGENT } from "../helpers.ts";

describe("cursors and since tokens", () => {
  test("a sealed cursor comes back unchanged, or not at all", () => {
    const sealer = new Sealer();
    const token = sealer.seal("c", { s: "scope", k: ["a", 1], t: 1 });
    assert.deepEqual(sealer.open("c", token), { s: "scope", k: ["a", 1], t: 1 });
    assert.throws(() => sealer.open("c", `${token.slice(0, -2)}AA`), RangeError);
    assert.throws(() => sealer.open("s", token), RangeError);
    assert.throws(() => new Sealer().open("c", token), RangeError);
  });

  test("pages by keyset, neither skipping nor repeating while the list changes", () => {
    let now = 1000;
    const cursors = new Cursors(new Sealer(), 60, () => now);
    const items = ["d", "a", "c", "b", "e"];
    const first = cursors.page(items, (x) => [x], { size: 2, cursor: undefined, scope: "s" });
    assert.deepEqual(first.items, ["a", "b"]);
    const next = cursors.page(["a0", ...items], (x) => [x], { size: 2, cursor: first.next ?? "", scope: "s" });
    assert.deepEqual(next.items, ["c", "d"]);
    assert.throws(
      () => cursors.page(items, (x) => [x], { size: 2, cursor: first.next ?? "", scope: "other" }),
      (e: unknown) => e instanceof HttpProblem && e.status === 400,
    );
    now += 61;
    assert.throws(
      () => cursors.page(items, (x) => [x], { size: 2, cursor: first.next ?? "", scope: "s" }),
      (e: unknown) => e instanceof HttpProblem && e.status === 410,
    );
  });
});

describe("files and documents", () => {
  test("ranges", () => {
    assert.deepEqual(parseRange("bytes=0-9", 100), [0, 9]);
    assert.deepEqual(parseRange("bytes=90-", 100), [90, 99]);
    assert.deepEqual(parseRange("bytes=-10", 100), [90, 99]);
    assert.equal(parseRange("bytes=100-", 100), "unsatisfiable");
    assert.equal(parseRange("bytes=5-1", 100), undefined);
    assert.equal(parseRange("items=0-1", 100), undefined);
  });

  test("a request document by the schema rule", () => {
    const doc = (body: string, type = "application/json") =>
      readDocument(
        new ServerRequest({
          method: "POST",
          path: "/",
          headers: { "Content-Type": type },
          body: new TextEncoder().encode(body),
        }),
      );
    assert.deepEqual(doc('{"schema":1}'), { schema: 1 });
    assert.throws(
      () => doc('{"schema":2}'),
      (e: unknown) => e instanceof HttpProblem && e.code === "unsupported_schema",
    );
    assert.throws(
      () => doc("{}"),
      (e: unknown) => e instanceof HttpProblem && e.status === 400,
    );
    assert.throws(
      () => doc('{"schema":1}', "text/plain"),
      (e: unknown) => e instanceof HttpProblem && e.status === 400,
    );
  });

  test("what a device is missing (SPEC.md § 6.3)", () => {
    const app = (id: string, appId: string, type: string, version: number): App => ({
      id,
      platform: "switch",
      title_id: "0100AB1200010000",
      app_id: appId,
      type,
      version_code: version,
      size: 1,
      format: "nsp",
      sha256: "0".repeat(64),
      file: "/f",
    });
    const apps = [
      app("a1", "0100AB1200010000", "base", 0),
      app("a2", "0100AB1200010800", "update", 65536),
      app("a3", "0100AB1200010800", "update", 131072),
      app("a4", "0100AB1200011001", "dlc", 0),
    ];
    const ids = (found: App[]) => found.map((a) => a.id).sort();
    assert.deepEqual(ids(missing(apps, "switch", [["0100AB1200010000", 0]], new Set(["update", "dlc"]))), ["a3", "a4"]);
    assert.deepEqual(ids(missing(apps, "switch", [["0100AB1200010800", 131072]], new Set(["update"]))), []);
    assert.deepEqual(ids(missing(apps, "switch", [], new Set(["base"]))), ["a1"]);
  });

  test("zip archives, written and read", () => {
    const files = [
      { name: "switch/x/a.nro", data: new Uint8Array(1000).fill(7) },
      { name: "config/x/é.ini", data: new TextEncoder().encode("[x]\n") },
    ];
    assert.deepEqual(readZip(writeZip(files)), files);
    assert.throws(() => readZip(new Uint8Array(30)), RangeError);
  });
});

describe("the node:http adapter", () => {
  let served: Awaited<ReturnType<typeof listen>>;
  before(async () => {
    served = await listen(await makeLantern(), { bodyLimit: 64 });
  });
  after(() => served.close());

  test("a body above the limit is answered 413", async () => {
    const response = await fetch(`${served.url}api/lantern/v1/apps/missing`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": AGENT },
      body: JSON.stringify({ schema: 1, installed: [], want: ["base"], pad: "x".repeat(100) }),
    });
    assert.equal(response.status, 413);
    assert.equal(response.headers.get("Content-Type"), "application/problem+json");
  });

  test("every response carries Date, and an unknown route 404", async () => {
    const response = await fetch(`${served.url}nothing/here`);
    assert.equal(response.status, 404);
    assert.ok(response.headers.get("Date"));
    assert.equal((await response.json()).code, "not_found");
  });
});

describe("LAN discovery (SPEC.md § 4.1)", () => {
  test("local networks only", () => {
    for (const a of ["192.168.1.20", "10.0.0.1", "172.20.1.1", "127.0.0.1", "fe80::1", "::ffff:192.168.0.2"])
      assert.ok(isLocalAddress(a), a);
    for (const a of ["8.8.8.8", "192.0.2.10", "2001:db8::1", "not an address"]) assert.ok(!isLocalAddress(a), a);
  });

  test("a datagram on loopback, answered with the handshake's uid and base", async () => {
    const app = await makeLantern();
    const responder = await DiscoveryResponder.start(app, { httpsPort: 8443, port: 0, host: "127.0.0.1" });
    try {
      const found = await discover(["127.0.0.1"], { port: responder.port, timeout: 0.5 });
      assert.equal(found.length, 1);
      assert.equal(found[0]?.uid, app.uid);
      assert.equal(found[0]?.base, "/api/lantern");
      assert.equal(found[0]?.url, "https://127.0.0.1:8443/");
      assert.deepEqual(discovery.readReply(new TextEncoder().encode("{"), "127.0.0.1"), undefined);
    } finally {
      await responder.stop();
    }
  });
});
