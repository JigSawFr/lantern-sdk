/**
 * Packages a device cannot use, and variants of one game (SPEC.md § 6.1, § 6.2, § 6.3, Annex B.15): the vectors of
 * app-requires.json against the helpers and the toolkit's missing(), then the toolkit's server read by the client
 * and by hostile requests, and a static export that keeps `requires` and `includes`.
 */

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import {
  type App,
  BadRequest,
  included,
  installDecision,
  LanternClient,
  missing,
  preferVariant,
  requiresOfName,
  StaticLibrary,
  type VariantApp,
} from "../../src/index.ts";
import { FileStaticSource, libraryInput, writeStatic } from "../../src/node/index.ts";
import { LanternApp, listen, MemoryLibrary } from "../../src/server/index.ts";
import { AGENT, vectors } from "../helpers.ts";

interface Vectors {
  install: {
    name: string;
    app: VariantApp;
    formats: string[];
    satisfies: string[];
    installed: VariantApp[];
    decision: string;
    reasons: number;
  }[];
  variants: { apps: VariantApp[]; preferred: string };
  library: (VariantApp & { platform: string; title_id: string; type: string; format: string })[];
  missing: {
    name: string;
    installed: { app_id: string; version_code: number }[];
    want: string[];
    formats?: string[];
    satisfies?: string[];
    missing: string[];
  }[];
}
const v = vectors<Vectors>("app-requires");

describe("app-requires.json: install decisions (SPEC.md § 6.1)", () => {
  for (const c of v.install)
    test(`[L-6.1-3] [L-6.1-4] [L-6.1-5] ${c.name}`, () => {
      const got = installDecision(c.app, c.formats, c.satisfies, c.installed);
      assert.equal(got.decision, c.decision);
      assert.equal(got.reasons.length, c.reasons);
      assert.equal(got.reasons.length === 0, got.decision === "install");
    });

  test("the reasons name the format, the tokens and the include, as the reference client does", () => {
    const app = { ...v.variants.apps[0], format: "zzz", requires: ["a", "b"] } as VariantApp;
    assert.deepEqual(installDecision(app, ["nsp"], ["a"]).reasons, ["format 'zzz'", "requires 'b'"]);
    const update = { ...app, format: "nsp", requires: [], type: "update", version_code: 1 } as VariantApp;
    const holder = { ...app, includes: [{ app_id: app.app_id, version_code: 1 }] } as VariantApp;
    assert.deepEqual(installDecision(update, ["nsp"], [], [holder]).reasons, ["already included by an installed app"]);
  });

  test("[L-6.1-5] only an update is ever included, and a version that is not a number includes nothing", () => {
    const base = { ...v.install[0]?.app, type: "base" } as VariantApp;
    const holder = (version_code: unknown) =>
      ({ ...base, includes: [{ app_id: base.app_id, version_code }] }) as VariantApp;
    assert.equal(included(base, [holder(99)]), false);
    const update = { ...base, type: "update", version_code: 5 } as VariantApp;
    assert.equal(included(update, [holder(5)]), true);
    assert.equal(included(update, [holder(4)]), false);
    assert.equal(included(update, [holder("9")]), false);
    assert.equal(included(update, [holder(Number.NaN)]), false);
    assert.equal(included(update, []), false);
  });

  test("an app that is not a document asks nothing it cannot answer", () => {
    assert.equal(
      installDecision({ ...v.variants.apps[0], format: undefined } as unknown as VariantApp, ["nsp"], []).decision,
      "unavailable",
    );
  });
});

describe("app-requires.json: the variant a client prefers (Annex B.15)", () => {
  test("the fewest requires, then the smallest size, then the smaller id", () => {
    assert.equal(preferVariant(v.variants.apps).id, v.variants.preferred);
    assert.equal(preferVariant([...v.variants.apps].reverse()).id, v.variants.preferred);
    const tie = v.variants.apps.filter((a) => a.size === 500);
    assert.equal(tie.length, 2);
    assert.equal(preferVariant(tie).id, "a_small");
    assert.equal(preferVariant(new Set(tie)).id, "a_small");
  });
  test("no variant is a RangeError", () => assert.throws(() => preferVariant([]), RangeError));
});

describe("[Annex A.1] requires of a package's name", () => {
  const lz4 = ["fs-compression", "sigpatch"];
  test("a Switch .nsp with [LZ4], in any case", () => {
    assert.deepEqual(requiresOfName("switch", "Game [0100ABCD00010000][v0][LZ4].nsp"), lz4);
    assert.deepEqual(requiresOfName("switch", "games/Game [lz4].NSP"), lz4);
  });
  test("nothing for another format, platform or name", () => {
    assert.equal(requiresOfName("switch", "Game [LZ4].nsz"), undefined);
    assert.equal(requiresOfName("switch", "Game.nsp"), undefined);
    assert.equal(requiresOfName("android", "Game [LZ4].nsp"), undefined);
    assert.equal(requiresOfName("switch", "[LZ4]/Game.nsp"), undefined);
  });
  test("each call gives a list of its own", () => {
    const a = requiresOfName("switch", "x [LZ4].nsp") as string[];
    a.push("y");
    assert.deepEqual(requiresOfName("switch", "x [LZ4].nsp"), lz4);
  });
});

const sizeOf = (a: VariantApp): App =>
  ({ name: a.id, sha256: "0".repeat(64), file: "/x", added: "2026-01-01T00:00:00Z", ...a }) as App;

describe("app-requires.json: what is missing (SPEC.md § 6.3)", () => {
  const apps = v.library.map(sizeOf);
  for (const c of v.missing)
    test(`[L-6.3-3] [L-6.3-4] missing(): ${c.name}`, () => {
      const got = missing(
        apps,
        "switch",
        c.installed.map((i): [string, number] => [i.app_id, i.version_code]),
        new Set(c.want),
        { formats: c.formats, satisfies: c.satisfies },
      );
      assert.deepEqual(got.map((a) => a.id).sort(), [...c.missing].sort());
    });
});

describe("the toolkit's server and the client", () => {
  let lib: MemoryLibrary;
  let app: LanternApp;
  let served: Awaited<ReturnType<typeof listen>>;
  let client: LanternClient;
  const ids = new Map<string, string>(); // the vectors' ids, to the library's
  const named = (list: readonly App[]): string[] =>
    list.map((a) => [...ids].find(([, id]) => id === a.id)?.[0] ?? a.id).sort();

  before(async () => {
    lib = new MemoryLibrary();
    for (const a of v.library) {
      const { id, ...rest } = a;
      const made = lib.addAppFile({
        ...(rest as object),
        data: new TextEncoder().encode(id),
        name: "Paper Kite",
      } as never);
      ids.set(id, made.id);
    }
    app = new LanternApp(lib, { uid: "a1b2c3d4-0000-4000-8000-0000000000a1", name: "Variants", base: "/api/lantern" });
    served = await listen(app);
    client = new LanternClient(served.url, { userAgent: AGENT, platform: "switch" });
  });
  after(async () => {
    app.shutdown(1);
    await served.close();
  });

  const raw = async (path: string, body?: unknown): Promise<Response> =>
    fetch(`${served.url.replace(/\/$/, "")}/api/lantern/v1${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "Lantern-Platform": "switch", "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });

  test("[L-6.1-1] [L-6.1-3] every variant is listed, with its requires and includes", async () => {
    const page = await client.apps();
    assert.equal(page.items.length, v.library.length);
    const lz4 = page.items.find((a) => a.id === ids.get("b_lz4"));
    assert.deepEqual(lz4?.requires, ["fs-compression", "sigpatch"]);
    assert.deepEqual(lz4?.includes, [{ app_id: "0100ABCD00010800", version_code: 196608 }]);
    assert.equal(page.items.find((a) => a.id === ids.get("b_base"))?.requires, undefined);
  });

  test("[L-6.2-7] format filters; a format no app has gives an empty list, not an error", async () => {
    assert.deepEqual(named((await client.apps({ format: "nsz" })).items), ["b_up2"]);
    assert.deepEqual(named((await client.apps({ format: "nsp" })).items), ["b_base", "b_lz4", "b_up1"]);
    for (const format of ["zzz", "x-lantern-conformance", "NSP", ""]) {
      const r = await raw(`/apps?format=${encodeURIComponent(format)}`);
      if (format === "") continue;
      assert.equal(r.status, 200, format);
      assert.deepEqual(((await r.json()) as { items: unknown[] }).items, []);
    }
  });

  test("[L-6.2-7] a cursor of one format is not read for another", async () => {
    const first = await client.apps({ format: "nsp", pageSize: 1 });
    assert.ok(first.next);
    await assert.rejects(client.apps({ format: "nsz", pageSize: 1, cursor: first.next ?? "" }), BadRequest);
    const all: string[] = [];
    for await (const a of client.iterApps({ format: "nsp", pageSize: 1 })) all.push(a.id);
    assert.equal(all.length, 3);
  });

  for (const c of v.missing)
    test(`[L-6.3-1] [L-6.3-3] [L-6.3-4] ${c.name}`, async () => {
      const page = await client.missing(
        c.installed.map((i): [string, number] => [i.app_id, i.version_code]),
        c.want,
        { formats: c.formats, satisfies: c.satisfies },
      );
      assert.deepEqual(named(page.items), [...c.missing].sort());
    });

  test("[L-6.3-2] the filters are paged under a cursor of their own", async () => {
    const ask = (formats?: string[], cursor?: string) =>
      client.missing([], ["base", "update"], {
        pageSize: 1,
        ...(formats ? { formats } : {}),
        ...(cursor ? { cursor } : {}),
      });
    const first = await ask(["nsp", "nsz"]);
    assert.ok(first.next);
    await assert.rejects(ask(["nsp"], first.next ?? ""), BadRequest);
    await assert.rejects(ask(undefined, first.next ?? ""), BadRequest);
    const walked: string[] = [];
    for await (const a of client.iterMissing([], ["base", "update"], { pageSize: 1, formats: ["nsp", "nsz"] }))
      walked.push(a.id);
    assert.deepEqual(walked.sort(), [ids.get("b_base"), ids.get("b_lz4")].sort());
  });

  test("[L-6.3-2] hostile formats and satisfies give 400 bad_request", async () => {
    const long = Array.from({ length: 17 }, (_, n) => `w${n}`);
    const cases: [string, unknown][] = [
      ["formats", "nsp"],
      ["formats", [1]],
      ["formats", ["NSP"]],
      ["formats", ["a".repeat(17)]],
      ["formats", long],
      ["formats", { nsp: 1 }],
      ["formats", null],
      ["formats", [null]],
      ["formats", [""]],
      ["satisfies", "sigpatch"],
      ["satisfies", ["Sig_Patch"]],
      ["satisfies", ["-x"]],
      ["satisfies", ["a".repeat(33)]],
      ["satisfies", long],
      ["satisfies", [["x"]]],
      ["satisfies", [{}]],
    ];
    for (const [key, value] of cases) {
      const r = await raw("/apps/missing", { schema: 1, installed: [], want: ["base"], [key]: value });
      assert.equal(r.status, 400, `${key}: ${JSON.stringify(value)}`);
      assert.equal(((await r.json()) as { code: string }).code, "bad_request");
    }
    const ok = await raw("/apps/missing", {
      schema: 1,
      installed: [],
      want: ["base"],
      formats: Array.from({ length: 16 }, (_, n) => `f${n}`),
      satisfies: Array.from({ length: 16 }, (_, n) => `t${n}`),
    });
    assert.equal(ok.status, 200);
  });

  test("the client refuses the same words before sending", async () => {
    await assert.rejects(async () => client.missing([], ["base"], { formats: ["NSP"] }), RangeError);
    await assert.rejects(async () => client.missing([], ["base"], { satisfies: Array(17).fill("a") }), RangeError);
  });

  test("[L-6.3-4] an unknown installed app includes nothing", async () => {
    const page = await client.missing([["0100ABCD00010000", 65537]], ["update"]);
    assert.ok(Array.isArray(page.items));
  });
});

describe("the library keeps requires and includes in order (SPEC.md § 6.1)", () => {
  const init = (extra: Record<string, unknown>) => ({
    data: new Uint8Array([1]),
    platform: "switch",
    title_id: "0100ABCD00010000",
    app_id: "0100ABCD00010000",
    type: "base",
    version_code: 0,
    name: "X",
    format: "nsp",
    ...extra,
  });

  test("[L-6.1-3] duplicates are dropped, and an empty list is no list", () => {
    const lib = new MemoryLibrary();
    assert.deepEqual(lib.addAppFile(init({ requires: ["sigpatch", "fs-compression", "sigpatch"] }) as never).requires, [
      "sigpatch",
      "fs-compression",
    ]);
    const plain = lib.addAppFile(init({ requires: [], includes: [] }) as never);
    assert.equal("requires" in plain, false);
    assert.equal("includes" in plain, false);
  });

  test("hostile requires and includes are refused", () => {
    const lib = new MemoryLibrary();
    const tokens = (n: number) => Array.from({ length: n }, (_, i) => `t${i}`);
    const includes = (n: number) => Array.from({ length: n }, (_, i) => ({ app_id: `a${i}`, version_code: 1 }));
    for (const bad of [
      { requires: tokens(9) },
      { requires: ["Upper"] },
      { requires: ["-x"] },
      { requires: ["a".repeat(33)] },
      { requires: "sigpatch" },
      { requires: [1] },
      { includes: includes(17) },
      { includes: [{ app_id: "x" }] },
      { includes: [{ app_id: "bad id", version_code: 1 }] },
      { includes: [{ app_id: "x", version_code: -1 }] },
      { includes: "x" },
    ])
      assert.throws(() => lib.addAppFile(init(bad) as never), RangeError, JSON.stringify(bad).slice(0, 40));
    assert.equal(lib.apps().length, 0);
  });

  test("8 requires and 16 includes are the most", () => {
    const lib = new MemoryLibrary();
    const made = lib.addAppFile(
      init({
        requires: Array.from({ length: 8 }, (_, i) => `t${i}`),
        includes: Array.from({ length: 16 }, (_, i) => ({ app_id: `a${i}`, version_code: i })),
      }) as never,
    );
    assert.equal(made.requires?.length, 8);
    assert.equal(made.includes?.length, 16);
  });

  test("[L-6.1-3] variants of one app_id and version_code are all listed", () => {
    const lib = new MemoryLibrary();
    for (const [format, n] of [
      ["nsp", 1],
      ["nsz", 2],
      ["xci", 3],
    ] as const)
      lib.addAppFile(init({ format, data: new Uint8Array([n]) }) as never);
    assert.equal(lib.apps().length, 3);
  });
});

describe("a static export keeps requires and includes", () => {
  let folder: string;
  before(async () => {
    folder = await mkdtemp(join(tmpdir(), "lantern-variants-"));
  });
  after(() => rm(folder, { recursive: true, force: true }));

  test("[L-21.3-2] the pages hold them, and what is missing is filtered as a server does", async () => {
    const lib = new MemoryLibrary();
    for (const a of v.library) {
      const { id, ...rest } = a;
      lib.addAppFile({ ...(rest as object), data: new TextEncoder().encode(id), name: "Paper Kite" } as never);
    }
    await writeStatic(
      await libraryInput(lib, { uid: "a1b2c3d4-0000-4000-8000-0000000000a1", name: "Variants" }),
      folder,
      { pageSize: 2 },
    );
    const staticLib = await StaticLibrary.open(new FileStaticSource(folder));
    const apps: App[] = [];
    for await (const a of staticLib.apps("switch")) apps.push(a);
    assert.equal(apps.length, v.library.length);
    assert.deepEqual(apps.find((a) => a.includes !== undefined)?.requires, ["fs-compression", "sigpatch"]);
    assert.equal(apps.filter((a) => a.requires !== undefined).length, 2);
    const mine = await staticLib.missing("switch", [["0100ABCD00010000", 0]], ["update"], { formats: ["nsz"] });
    assert.deepEqual(
      mine.map((a) => a.format),
      ["nsz"],
    );
    const none = await staticLib.missing("switch", [["0100ABCD00010000", 65536]], ["update"]);
    assert.deepEqual(none, []);
  });
});
