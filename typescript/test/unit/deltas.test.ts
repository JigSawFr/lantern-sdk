/**
 * Draft 0.7 against the toolkit's own server: differential updates (SPEC.md § 22: the chunk index of an app and of a
 * package, its route, the client's download with seeds and its fallbacks to the whole file when a source or an index
 * is hostile), Lantern-Chunk-Size on an upload's HEAD (§ 9.3), the answers to a browser's page (§ 2.5), and a
 * static library's chunk indexes and ranges (§ 21, § 22).
 */

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, mkdtempSync, rmSync, statSync } from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import {
  type App,
  bytesSource,
  type ChunksRef,
  chunks as chunkTools,
  type DeltaReport,
  HttpStaticSource,
  MemorySink,
  StaticLibrary,
  TransportError,
} from "../../src/index.ts";
import { FileStaticSource, libraryInput, NodeLanternClient, writeStatic } from "../../src/node/index.ts";
import {
  FileRef,
  LanternApp,
  type LanternAppOptions,
  listen,
  MemoryAccounts,
  MemoryLibrary,
  makePackage,
  nodeHandler,
  ServerRequest,
  type ServerResponse,
  writeZip,
} from "../../src/server/index.ts";
import { addDeltaApps, blob, buildLibrary, DEMO_ORIGIN, UID } from "../demo.ts";
import { AGENT } from "../helpers.ts";

const hex = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");
const SEED_TOKEN = "et_test-deltas-0123456789abcdef0123456789abcdef";
const HIDDEN = "et_test-hidden-0123456789abcdef0123456789abcdef";
const SHOWN = "et_test-shown-0123456789abcdef0123456789abcdef";

function accounts(): MemoryAccounts {
  const a = new MemoryAccounts([{ name: "mira", scopes: ["library"] }]);
  a.addToken(SEED_TOKEN, "mira", "Mira's console", ["library"]);
  a.addToken(HIDDEN, "mira", "Mira's small console", ["library"], { ratingCap: { age: 3, unrated: "hide" } });
  a.addToken(SHOWN, "mira", "Mira's other console", ["library"], { ratingCap: { age: 3, unrated: "show" } });
  return a;
}

/** What a hostile server does to the ranges, or to the index, it serves. */
type Mode = "honest" | "flip" | "short" | "long" | "ignore-range" | "bad-index" | "other-file" | "gone";

/** The toolkit's app, with the answers a hostile server would give. */
class Hostile extends LanternApp {
  mode: Mode = "honest";
  ranges = 0;
  /** The platform each request named: [target, Lantern-Platform header]. */
  readonly named: [string, string | undefined][] = [];

  override async handle(request: ServerRequest): Promise<ServerResponse> {
    this.named.push([request.target, request.header("Lantern-Platform")]);
    const ranged = request.header("Range") !== undefined && request.path.includes("/files/");
    if (ranged) this.ranges++;
    let asked = request;
    if (ranged && this.mode === "ignore-range") {
      const headers = new Headers(request.headers);
      headers.delete("Range");
      asked = new ServerRequest({ method: request.method, path: request.path, headers, scheme: request.scheme });
    }
    const response = await super.handle(asked);
    if (ranged && response.status === 206 && response.body instanceof Uint8Array) {
      const body = new Uint8Array(response.body);
      if (this.mode === "flip") body[Math.floor(body.length / 2)] = (body[Math.floor(body.length / 2)] as number) ^ 1;
      if (this.mode === "short") response.body = body.subarray(0, body.length - 1);
      else if (this.mode === "long") {
        const longer = new Uint8Array(body.length + 100);
        longer.set(body);
        response.body = longer;
      } else response.body = body;
      response.headers.set("Content-Length", String((response.body as Uint8Array).length));
    }
    if (request.path.includes("/chunks/") && response.status === 200 && response.body instanceof Uint8Array) {
      if (this.mode === "bad-index") {
        const body = new Uint8Array(response.body);
        body[20] = (body[20] as number) ^ 1;
        response.body = body;
      }
      if (this.mode === "other-file") {
        const other = await (this.library.chunks as NonNullable<MemoryLibrary["chunks"]>)(
          (await this.library.apps()).find((a) => a.title_id !== "0100AB1200020000")?.sha256 ?? "",
        );
        response.body = other ?? new Uint8Array();
      }
      response.headers.delete("ETag");
      response.headers.set("Content-Length", String((response.body as Uint8Array).length));
    }
    return response;
  }
}

async function hostile(): Promise<{ app: Hostile; url: string; close(): Promise<void>; seed: App; newer: App }> {
  const library = await buildLibrary({ deltas: true });
  const app = new Hostile(library, {
    uid: UID,
    name: "Delta shelf",
    base: "/api/lantern",
    accounts: accounts(),
    corsOrigins: [DEMO_ORIGIN],
  });
  const served = await listen(app);
  const ferry = (await library.apps())
    .filter((a) => a.app_id === "0100AB1200020800")
    .sort((a, b) => a.version_code - b.version_code);
  return { app, url: served.url, close: served.close, seed: ferry[0] as App, newer: ferry[1] as App };
}

let shelf: Awaited<ReturnType<typeof hostile>>;
let seedBytes: Uint8Array;
let newerBytes: Uint8Array;
const clients: NodeLanternClient[] = [];

function client(token?: string): NodeLanternClient {
  const c = new NodeLanternClient(shelf.url, { userAgent: AGENT, ...(token !== undefined ? { token } : {}) });
  clients.push(c);
  return c;
}

before(async () => {
  shelf = await hostile();
  const c = client();
  const sink = new MemorySink();
  await c.downloadApp(shelf.seed, sink);
  seedBytes = sink.bytes();
  const n = new MemorySink();
  await c.downloadApp(shelf.newer, n);
  newerBytes = n.bytes();
  shelf.app.ranges = 0;
});

after(async () => {
  for (const c of clients) await c.close();
  shelf.app.shutdown(1);
  await shelf.close();
});

describe("chunk indexes served by the toolkit (SPEC.md § 22.1)", () => {
  test("[L-4.2-4] the handshake offers features.deltas, and the apps carry chunks", async () => {
    const hello = await client().handshake();
    assert.equal(hello.features["deltas"], 1);
    assert.ok(shelf.newer.chunks, "the big app has an index");
    const small = (await client().apps({ platform: "switch" })).items.find((a) => a.size < 128 << 10);
    assert.ok(small && small.chunks === undefined, "a small file gains nothing: no chunks");
  });

  test("[L-22.1-1][L-22.1-2] the index at chunks.url is the bytes chunks gives, and cut as the chunker cuts", async () => {
    const c = client();
    for (const app of [shelf.seed, shelf.newer]) {
      const ref = app.chunks as ChunksRef;
      assert.equal(ref.url, `/api/lantern/v1/chunks/sha256/${app.sha256}`);
      const raw = await c.chunkIndexBytes(app);
      assert.ok(raw);
      assert.equal(raw.length, ref.size);
      assert.equal(hex(raw), ref.sha256);
      const data = app === shelf.seed ? seedBytes : newerBytes;
      const index = chunkTools.chunkIndex(data, (await c.chunkIndex(app))?.chunker.size);
      assert.deepEqual(index.bytes, raw);
    }
  });

  test("[L-22.1-2] an unknown file, one named in upper case, or one without an index: 404", async () => {
    const get = (path: string, token?: string) =>
      fetch(`${shelf.url}api/lantern/v1/chunks/sha256/${path}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
    assert.equal((await get("0".repeat(64))).status, 404);
    assert.equal((await get(shelf.newer.sha256.toUpperCase())).status, 404);
    assert.equal((await get("zz")).status, 404);
    const small = (await client().apps({ platform: "switch" })).items.find((a) => a.size < 128 << 10) as App;
    assert.equal((await get(small.sha256)).status, 404);
    assert.equal((await get(shelf.newer.sha256)).status, 200);
  });

  test("[L-22.1-2] a rating cap that hides the title hides its index too (SPEC.md § 5.6)", async () => {
    const get = (token: string) =>
      fetch(`${shelf.url}api/lantern/v1/chunks/sha256/${shelf.newer.sha256}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
    assert.equal((await get(HIDDEN)).status, 404);
    assert.equal((await get(SHOWN)).status, 200);
  });

  test("a library with deltas off offers no family and no route", async () => {
    const library = new MemoryLibrary({ deltas: false });
    library.addAppFile({
      data: blob("big", 300000),
      platform: "linux",
      title_id: "org.example.big",
      app_id: "org.example.big",
      type: "base",
      version_code: 1,
      name: "Big",
      format: "deb",
    });
    const app = new LanternApp(library, { uid: UID, name: "No deltas" });
    const hello = (await app.handle(ServerRequest.fromTarget("GET", "/.well-known/lantern"))).body as Uint8Array;
    assert.equal(JSON.parse(new TextDecoder().decode(hello)).features.deltas, 0);
    const r = await app.handle(ServerRequest.fromTarget("GET", `/api/lantern/v1/chunks/sha256/${"0".repeat(64)}`));
    assert.equal(r.status, 404);
    assert.equal((await library.apps())[0]?.chunks, undefined);
  });

  test("a package carries chunks too, from its file's bytes", async () => {
    const library = new MemoryLibrary({ deltas: { min: 1000 } });
    const data = blob("a-big.nro", 200000);
    const [pkg, file] = makePackage(data, "nro", { platform: "switch", homebrewId: "org.example.bignro" });
    await library.addHomebrew(
      {
        id: "org.example.bignro",
        platform: "switch",
        kind: "game",
        name: "Big Nro",
        author: "Oren",
        version: "1.0.0",
        build: 1,
        package: pkg,
      },
      new Map([[pkg.file, file]]),
    );
    const entry = library.homebrew()[0];
    const ref = entry?.package.chunks as ChunksRef;
    assert.ok(ref);
    const raw = library.chunks(file.sha256) as Uint8Array;
    assert.equal(ref.size, raw.length);
    assert.deepEqual(raw, chunkTools.chunkIndex(data).bytes);
    // The size limits: below `min` or above `max`, none.
    assert.equal(new MemoryLibrary({ deltas: { min: 300000 } }).chunkReference(FileRef.ofBytes(data)), undefined);
    assert.equal(new MemoryLibrary({ deltas: { max: 1000 } }).chunkReference(FileRef.ofBytes(data)), undefined);
  });
});

describe("a download with seeds (SPEC.md § 22.3)", () => {
  test("[L-22.3-2] the newer version from the older: only the ranges it lacks are read, the file is whole and checked", async () => {
    shelf.app.mode = "honest";
    shelf.app.ranges = 0;
    const c = client();
    const sink = new MemorySink();
    let report: DeltaReport | undefined;
    const seen: number[] = [];
    await c.downloadWithSeeds(shelf.newer, sink, [seedBytes], {
      onDelta: (r) => {
        report = r;
      },
      progress: (done) => seen.push(done),
    });
    assert.deepEqual(sink.bytes(), newerBytes);
    assert.ok(report);
    assert.equal(report.size, shelf.newer.size);
    assert.equal(report.reused + report.read, shelf.newer.size);
    assert.ok(report.read < shelf.newer.size / 2, `${report.read} bytes read of ${shelf.newer.size}`);
    assert.ok(report.reused > shelf.newer.size / 2);
    assert.equal(shelf.app.ranges, report.ranges);
    assert.equal(seen.at(-1), shelf.newer.size);
  });

  test("[L-22.3-4] seeds that share no chunk, or none: the whole file, without a range", async () => {
    shelf.app.ranges = 0;
    for (const seeds of [[blob("unrelated", 100000)], []]) {
      const sink = new MemorySink();
      let told = false;
      await client().downloadWithSeeds(shelf.newer, sink, seeds, { onDelta: () => (told = true) });
      assert.deepEqual(sink.bytes(), newerBytes);
      assert.equal(told, false);
    }
    assert.equal(shelf.app.ranges, 0);
  });

  test("[L-22.3-4] a file without an index is read whole", async () => {
    const small = (await client().apps({ platform: "switch" })).items.find(
      (a) => a.size > 1000 && a.size < 128 << 10,
    ) as App;
    const sink = new MemorySink();
    await client().downloadWithSeeds(small, sink, [blob("any", 100)]);
    assert.equal(hex(sink.bytes()), small.sha256);
  });

  const cases: [Mode, string][] = [
    ["flip", "[L-22.3-2] a range of other bytes"],
    ["short", "[L-22.3-3] a range one byte short"],
    ["long", "[L-22.3-3] a range longer than asked"],
    ["ignore-range", "[L-22.3-3] a source that sends the whole file for a range"],
    ["bad-index", "[L-22.3-1] an index whose bytes are not those chunks gives"],
    ["other-file", "[L-22.3-1] the index of another file"],
  ];
  for (const [mode, name] of cases) {
    test(`${name}: refused, and the whole file read`, async () => {
      shelf.app.mode = mode;
      shelf.app.ranges = 0;
      try {
        const sink = new MemorySink();
        let told = false;
        await client().downloadWithSeeds(shelf.newer, sink, [seedBytes], { onDelta: () => (told = true) });
        assert.deepEqual(sink.bytes(), newerBytes, "the file is whole and right");
        assert.equal(told, false, "no delta download is reported");
        if (mode !== "bad-index" && mode !== "other-file") assert.ok(shelf.app.ranges > 0, "a range was tried");
      } finally {
        shelf.app.mode = "honest";
      }
    });
  }

  test("[L-22.3-3] nothing is committed nor written past the size when the whole file fails too", async () => {
    const lies = { ...shelf.newer, sha256: "f".repeat(64) } as App;
    const sink = new MemorySink();
    await assert.rejects(client().downloadWithSeeds(lies, sink, [seedBytes]));
    assert.throws(() => sink.bytes(), TypeError);
  });

  test("an index on another origin is not read", async () => {
    const away = {
      ...shelf.newer,
      chunks: { ...(shelf.newer.chunks as ChunksRef), url: "https://elsewhere.example.org/x" },
    };
    const sink = new MemorySink();
    await client().downloadWithSeeds(away, sink, [seedBytes]);
    assert.deepEqual(sink.bytes(), newerBytes);
    assert.equal(
      await client()
        .chunkIndex(away)
        .catch(() => "refused"),
      "refused",
    );
  });
});

describe("a browser client names its platform in the query (Annex A.7)", () => {
  test("[L-4.3-5] ?platform= on the routes below v1, no Lantern-Platform header, the platform filter honoured", async () => {
    shelf.app.named.length = 0;
    const c = new NodeLanternClient(shelf.url, { userAgent: AGENT, platform: "switch", platformInQuery: true });
    clients.push(c);
    const page = await c.apps();
    assert.ok(page.items.length > 0 && page.items.every((a) => a.platform === "switch"));
    await c.downloadApp(shelf.newer, new MemorySink());
    const v1 = shelf.app.named.filter(([t]) => t.includes("/v1/") && !t.includes("/files/"));
    assert.ok(v1.length > 0 && v1.every(([t]) => /[?&]platform=switch\b/.test(t)));
    assert.ok(shelf.app.named.every(([, header]) => header === undefined));
  });

  test("[L-A.7-1] web is not a platform of the handshake, and nothing is listed for it", async () => {
    const c = client();
    assert.ok(!(await c.handshake()).platforms.includes("web"));
    assert.deepEqual((await c.apps({ platform: "web" })).items, []);
  });
});

describe("a resumable upload resumes in the server's chunks (SPEC.md § 9.3, L-9.3-3)", () => {
  test("HEAD gives Lantern-Chunk-Size, and a resume sends chunks of that size", async () => {
    const SAVER = "et_test-saver-0123456789abcdef0123456789abcdef";
    const users = new MemoryAccounts([{ name: "mira", scopes: ["library", "saves"] }]);
    users.addToken(SAVER, "mira", "Mira's console", ["library", "saves"]);
    const app = new LanternApp(new MemoryLibrary(), {
      uid: UID,
      name: "Small chunks",
      accounts: users,
      saves: true,
      saveChunk: 256 << 10,
    });
    const served = await listen(app);
    const c = new NodeLanternClient(served.url, { userAgent: AGENT, token: SAVER, platform: "switch" });
    try {
      const data = writeZip([{ name: "save/world.bin", data: new Uint8Array(randomBytes(900 << 10)) }]);
      let opened = "";
      await assert.rejects(
        c.uploadSave("0500AB12CD030000", bytesSource(data), {
          progress: (done) => {
            if (done < data.length) {
              opened = c.lastUpload ?? "";
              throw new TransportError("a lost connection");
            }
          },
        }),
        TransportError,
      );
      const [offset, length, chunk] = await c.uploadOffset(opened);
      assert.equal(offset, 256 << 10);
      assert.equal(length, data.length);
      assert.equal(chunk, 256 << 10);
      const seen: number[] = [];
      const save = await c.uploadSave("0500AB12CD030000", bytesSource(data), {
        resume: opened,
        progress: (done) => seen.push(done),
      });
      assert.equal(save.size, data.length);
      assert.deepEqual(seen.slice(0, 3), [512 << 10, 768 << 10, data.length]);
    } finally {
      await c.close();
      app.shutdown(1);
      await served.close();
    }
  });
});

describe("answers to a browser's page (SPEC.md § 2.5)", () => {
  const ORIGIN = "https://app.example.org";
  const lib = new MemoryLibrary();
  const make = (corsOrigins?: string[], extra: Partial<LanternAppOptions> = {}) =>
    new LanternApp(lib, { uid: UID, name: "CORS shelf", ...(corsOrigins ? { corsOrigins } : {}), ...extra });
  const ask = (app: LanternApp, method: string, path: string, headers: Record<string, string> = {}) =>
    app.handle(ServerRequest.fromTarget(method, path, { headers: { Host: "shelf.example.org", ...headers } }));
  const preflight = (
    app: LanternApp,
    origin = ORIGIN,
    path = "/api/lantern/v1/apps",
    asked = "authorization, lantern-platform, x-nothing",
  ) =>
    ask(app, "OPTIONS", path, {
      Origin: origin,
      "Access-Control-Request-Method": "GET",
      "Access-Control-Request-Headers": asked,
    });

  test("[L-2.5-3] a preflight is 204 without a token, naming the method and the headers asked, never Allow-Credentials", async () => {
    const app = make([ORIGIN], { public: false, accounts: accounts() });
    for (const path of [
      "/api/lantern/v1/apps",
      "/api/lantern/v1/sync/wishes",
      "/api/lantern/v1/no-such-route",
      "/.well-known/lantern",
    ]) {
      const r = await preflight(app, ORIGIN, path);
      assert.equal(r.status, 204, path);
      assert.equal(r.headers.get("Access-Control-Allow-Origin"), ORIGIN);
      assert.match(r.headers.get("Vary") ?? "", /Origin/);
      assert.match(r.headers.get("Access-Control-Allow-Methods") ?? "", /\bGET\b.*\bPATCH\b/);
      assert.equal(r.headers.get("Access-Control-Allow-Headers"), "Authorization, Lantern-Platform");
      assert.equal(r.headers.get("Access-Control-Allow-Credentials"), null);
      assert.equal(r.headers.get("Set-Cookie"), null);
    }
  });

  test("[L-2.5-4] a preflight is kept for 600 seconds at least, and a private network may be allowed", async () => {
    const r = await ask(make([ORIGIN]), "OPTIONS", "/api/lantern/v1/apps", {
      Origin: ORIGIN,
      "Access-Control-Request-Method": "GET",
      "Access-Control-Request-Private-Network": "true",
    });
    assert.ok(Number(r.headers.get("Access-Control-Max-Age")) >= 600);
    assert.equal(r.headers.get("Access-Control-Allow-Private-Network"), "true");
  });

  test("[L-2.5-2] every answer to the allowed origin, errors included, names it and exposes the headers a page reads", async () => {
    const app = make([ORIGIN]);
    for (const [path, status] of [
      ["/.well-known/lantern", 200],
      ["/api/lantern/v1/apps", 200],
      ["/api/lantern/v1/no-such-route", 404],
    ] as const) {
      const r = await ask(app, "GET", path, { Origin: ORIGIN });
      assert.equal(r.status, status);
      assert.equal(r.headers.get("Access-Control-Allow-Origin"), ORIGIN);
      assert.match(r.headers.get("Vary") ?? "", /Origin/);
      const exposed = (r.headers.get("Access-Control-Expose-Headers") ?? "").split(",").map((h) => h.trim());
      for (const h of [
        "ETag",
        "Content-Range",
        "Repr-Digest",
        "Retry-After",
        "Upload-Offset",
        "Lantern-Chunk-Size",
        "Link",
      ])
        assert.ok(exposed.includes(h), h);
      assert.equal(r.headers.get("Access-Control-Allow-Credentials"), null);
    }
  });

  test("[L-2.5-1] none by default, and an origin not allowed gets nothing of CORS", async () => {
    const plain = await ask(make(), "GET", "/api/lantern/v1/apps", { Origin: ORIGIN });
    assert.equal(plain.headers.get("Access-Control-Allow-Origin"), null);
    const other = await ask(make([ORIGIN]), "GET", "/api/lantern/v1/apps", { Origin: "https://evil.example.net" });
    assert.equal(other.status, 200);
    assert.equal(other.headers.get("Access-Control-Allow-Origin"), null);
    assert.equal(other.headers.get("Access-Control-Expose-Headers"), null);
    assert.match(other.headers.get("Vary") ?? "", /Origin/, "a cache keeps the answers apart");
    // Its preflight, or an OPTIONS that is none: a method no route takes.
    assert.equal((await preflight(make([ORIGIN]), "https://evil.example.net")).status, 405);
    assert.equal((await ask(make([ORIGIN]), "OPTIONS", "/api/lantern/v1/apps", { Origin: ORIGIN })).status, 405);
    assert.equal((await ask(make(), "OPTIONS", "/api/lantern/v1/apps")).status, 405);
  });

  test("every origin: * and no Vary: Origin; a page outside Lantern's routes gets nothing", async () => {
    const app = make(["*"]);
    const r = await ask(app, "GET", "/api/lantern/v1/apps", { Origin: "https://any.example.net" });
    assert.equal(r.headers.get("Access-Control-Allow-Origin"), "*");
    assert.doesNotMatch(r.headers.get("Vary") ?? "", /Origin/);
    assert.equal((await preflight(app, "https://any.example.net")).status, 204);
    const away = await ask(app, "GET", "/elsewhere", { Origin: "https://any.example.net" });
    assert.equal(away.headers.get("Access-Control-Allow-Origin"), null);
  });

  test("an origin that is not one is refused when the app is made", () => {
    for (const bad of ["app.example.org", "https://app.example.org/path", "https://", "ftp://x.example.org"])
      assert.throws(() => make([bad]), RangeError, bad);
    assert.doesNotThrow(() => make(["http://localhost:5173", "https://[::1]:8443", "*"]));
  });

  test("an over-limit body is answered with the page's headers too", async () => {
    const app = make([ORIGIN]);
    const server = http.createServer(nodeHandler(app, { bodyLimit: 10 }));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    try {
      const port = (server.address() as AddressInfo).port;
      const r = await fetch(`http://127.0.0.1:${port}/api/lantern/v1/requests`, {
        method: "POST",
        headers: { Origin: ORIGIN },
        body: "x".repeat(100),
      });
      assert.equal(r.status, 413);
      assert.equal(r.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    } finally {
      server.close();
      server.closeAllConnections();
    }
  });
});

describe("a static library's chunk indexes (SPEC.md § 21.1, § 22)", () => {
  const folder = mkdtempSync(join(tmpdir(), "lantern-static-deltas-"));
  after(() => rmSync(folder, { recursive: true, force: true }));
  let library: MemoryLibrary;

  before(async () => {
    library = await buildLibrary();
    addDeltaApps(library);
    await writeStatic(await libraryInput(library, { uid: UID, name: "Static deltas" }), folder, { pageSize: 50 });
  });

  test("[L-21.1-1] the index of each file is written as it is kept, its path in chunks.url, and features.deltas is 1", async () => {
    const lib = await StaticLibrary.open(new FileStaticSource(folder));
    assert.equal(lib.hello.features["deltas"], 1);
    const apps: App[] = [];
    for await (const a of lib.apps("switch")) apps.push(a);
    const big = apps.filter((a) => a.chunks !== undefined);
    assert.equal(big.length, 2);
    for (const a of big) {
      const ref = a.chunks as ChunksRef;
      assert.equal(ref.url, `v1/chunks/sha256/${a.sha256}.json`);
      const raw = await new FileStaticSource(folder).read(ref.url, ref.size);
      assert.deepEqual(raw, library.chunks(a.sha256));
      assert.ok(await lib.chunkIndex(a));
    }
    assert.ok(apps.some((a) => a.chunks === undefined));
  });

  async function seedsAndNewer(lib: StaticLibrary): Promise<{ seed: Uint8Array; newer: App }> {
    const apps: App[] = [];
    for await (const a of lib.apps("switch")) if (a.app_id === "0100AB1200020800") apps.push(a);
    apps.sort((a, b) => a.version_code - b.version_code);
    const sink = new MemorySink();
    await lib.download(apps[0] as App, sink);
    return { seed: sink.bytes(), newer: apps[1] as App };
  }

  test("[L-22.3-2] a folder: the newer version from the older, by ranges", async () => {
    const lib = await StaticLibrary.open(new FileStaticSource(folder));
    const { seed, newer } = await seedsAndNewer(lib);
    const sink = new MemorySink();
    let report: DeltaReport | undefined;
    await lib.downloadWithSeeds(newer, sink, [seed], { onDelta: (r) => (report = r) });
    assert.equal(hex(sink.bytes()), newer.sha256);
    assert.ok(report && report.read < newer.size / 2);
  });

  test("[L-22.3-2][L-22.3-3] over HTTP: ranges are 206 with their Content-Range; a server without them gives the whole file", async () => {
    let ranges = 0;
    const serve = (honour: boolean) =>
      http.createServer((req, res) => {
        const path = join(folder, decodeURIComponent((req.url ?? "/").split("?")[0] ?? "/"));
        let size: number;
        try {
          size = statSync(path).size;
        } catch {
          res.statusCode = 404;
          res.end();
          return;
        }
        const m = /^bytes=(\d+)-(\d+)$/.exec(req.headers.range ?? "");
        if (m && honour) {
          ranges++;
          const [start, end] = [Number(m[1]), Number(m[2])];
          res.writeHead(206, { "Content-Range": `bytes ${start}-${end}/${size}`, "Content-Length": end - start + 1 });
          createReadStream(path, { start, end }).pipe(res);
        } else {
          res.writeHead(200, { "Content-Length": size });
          createReadStream(path).pipe(res);
        }
      });
    for (const honour of [true, false]) {
      const server = serve(honour);
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      try {
        const port = (server.address() as AddressInfo).port;
        const lib = await StaticLibrary.open(new HttpStaticSource(`http://127.0.0.1:${port}/`));
        const { seed, newer } = await seedsAndNewer(lib);
        const sink = new MemorySink();
        let report: DeltaReport | undefined;
        ranges = 0;
        await lib.downloadWithSeeds(newer, sink, [seed], { onDelta: (r) => (report = r) });
        assert.equal(hex(sink.bytes()), newer.sha256);
        assert.equal(report !== undefined, honour);
        assert.equal(ranges > 0, honour);
      } finally {
        server.close();
        server.closeAllConnections();
      }
    }
  });

  test("[L-22.3-1] an index that was changed on the disk is not used: the file is read whole", async () => {
    const copy = mkdtempSync(join(tmpdir(), "lantern-static-bad-"));
    try {
      await writeStatic(await libraryInput(library, { uid: UID, name: "Bad" }), copy);
      const lib = await StaticLibrary.open(new FileStaticSource(copy));
      const { seed, newer } = await seedsAndNewer(lib);
      const { writeFileSync, readFileSync } = await import("node:fs");
      const file = join(copy, "v1", "chunks", "sha256", `${newer.sha256}.json`);
      const raw = readFileSync(file);
      raw[30] = (raw[30] as number) ^ 1;
      writeFileSync(file, raw);
      assert.equal(await lib.chunkIndex(newer), undefined);
      const sink = new MemorySink();
      let told = false;
      await lib.downloadWithSeeds(newer, sink, [seed], { onDelta: () => (told = true) });
      assert.equal(hex(sink.bytes()), newer.sha256);
      assert.equal(told, false);
    } finally {
      rmSync(copy, { recursive: true, force: true });
    }
  });
});
