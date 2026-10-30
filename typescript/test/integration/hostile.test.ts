/**
 * The client against the malicious test server (python/tools/hostile_server.py),
 * started from its command line as any language's CI does: for each scenario,
 * the client refuses what it must, and sends nothing it must not.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import {
  DeviceKey,
  DocumentError,
  FetchTransport,
  homebrew as hb,
  IntegrityError,
  LanternClient,
  MemorySink,
  NewerSchema,
  PinMismatch,
  SignatureExpired,
  SignatureReplayed,
  TransportError,
  UnexpectedResponse,
} from "../../src/index.ts";
import { NodeLanternClient, NodeTransport } from "../../src/node/index.ts";
import { AGENT, PYTHON, REPOSITORY, requestsOf, type Served, servePython, until } from "../helpers.ts";

const TOOL = join(REPOSITORY, "python", "tools", "hostile_server.py");
const KEY_SEED = new Uint8Array(32).map((_, i) => i); // a fictional device's

interface Hostile {
  scenario: string;
  url: string;
  token: string;
  pin: string | null;
}

interface Scenario {
  name: string;
  tls: boolean;
}

const SCENARIOS = JSON.parse(execFileSync(PYTHON, [TOOL, "--list"], { encoding: "utf8" })) as Scenario[];
const folder = mkdtempSync(join(tmpdir(), "lantern-hostile-"));
after(() => rmSync(folder, { recursive: true, force: true }));

async function scenario(name: string, run: (server: Served<Hostile>) => Promise<void>): Promise<void> {
  const server = await servePython<Hostile>([TOOL, name, "--port", "0"]);
  try {
    await run(server);
  } finally {
    await server.stop();
  }
}

function client(
  server: Served<Hostile>,
  options: ConstructorParameters<typeof NodeLanternClient>[1] = {},
): NodeLanternClient {
  return new NodeLanternClient(server.info.url, {
    userAgent: AGENT,
    platform: "switch",
    token: server.info.token,
    ...options,
  });
}

const TESTED = new Set<string>();

function covers(...names: string[]): void {
  for (const n of names) TESTED.add(n);
}

describe("the malicious test server", () => {
  covers("spki-wrong");
  test("a key other than the pinned one: refused before a byte is sent", async () => {
    await scenario("spki-wrong", async (server) => {
      const pin = server.info.pin ?? "";
      const c = client(server, { key: await DeviceKey.fromSeed(KEY_SEED), pin });
      await assert.rejects(
        c.handshake(),
        (e: unknown) => e instanceof PinMismatch && e.pinned === pin && e.seen !== pin,
      );
      await c.close();
      await until(() => false, 0.2);
      assert.deepEqual(requestsOf(server.log), []);
    });
  });

  covers("key-changed");
  test("a key that changed: the first request goes, the next is refused", async () => {
    await scenario("key-changed", async (server) => {
      const pin = server.info.pin ?? "";
      const c = client(server, { transport: new NodeTransport({ pin, keepAlive: false }) });
      assert.ok((await c.handshake()).uid);
      await assert.rejects(c.apps(), PinMismatch);
      await c.close();
      await until(() => requestsOf(server.log).length >= 1);
      assert.deepEqual(
        requestsOf(server.log).map((r) => r.path),
        ["/.well-known/lantern"],
      );
    });
  });

  covers("manifest-dotdot", "manifest-relative", "manifest-outside");
  for (const name of ["manifest-dotdot", "manifest-relative", "manifest-outside"]) {
    test(`a hostile manifest: ${name}`, async () => {
      await scenario(name, async (server) => {
        const c = client(server);
        const entry = await c.homebrewEntry("org.example.paperlamp");
        assert.ok(hb.manifestProblems(hb.manifestOf(entry.package)).length > 0 || name === "manifest-outside");
        assert.throws(() => hb.installPlan(entry), hb.Refused);
        await c.close();
      });
    });
  }

  covers("newer-schema");
  test("a newer schema is absent, never an error of the server", async () => {
    await scenario("newer-schema", async (server) => {
      const c = client(server);
      await assert.rejects(c.handshake(), (e: unknown) => e instanceof NewerSchema && e.schema === 2);
      assert.equal(c.hello, undefined);
      await assert.rejects(c.homebrewEntry("org.example.paperlamp", { platform: "switch" }), NewerSchema);
      await c.close();
    });
  });

  covers("oversized-document", "deep-document", "long-string", "page-too-long");
  for (const name of ["oversized-document", "deep-document", "long-string", "page-too-long"]) {
    test(`a document beyond SPEC.md § 13: ${name}`, async () => {
      await scenario(name, async (server) => {
        const c = client(server);
        await c.handshake();
        await assert.rejects(c.apps(), DocumentError);
        await c.close();
      });
    });
  }

  covers("manifest-too-long");
  test("a manifest beyond the limits", async () => {
    await scenario("manifest-too-long", async (server) => {
      const c = client(server);
      await assert.rejects(c.homebrewEntry("org.example.paperlamp"), DocumentError);
      await c.close();
    });
  });

  covers("bad-digest", "wrong-bytes", "extra-bytes");
  for (const name of ["bad-digest", "wrong-bytes", "extra-bytes"]) {
    test(`a download that is not its document's: ${name}`, async () => {
      await scenario(name, async (server) => {
        const dest = join(folder, `${name}.nsp`);
        const c = client(server);
        const app = (await c.apps()).items[0];
        assert.ok(app);
        await assert.rejects(c.downloadAppTo(app, dest), IntegrityError);
        await assert.rejects(c.fetchFile(app.file, app), IntegrityError);
        assert.ok(!existsSync(dest) && !existsSync(`${dest}.part`));
        await c.close();
      });
    });
  }

  covers("truncated");
  test("a truncated download: refused, then resumed with a Range and checked whole", async () => {
    await scenario("truncated", async (server) => {
      const dest = join(folder, "truncated.nsp");
      const c = client(server);
      const app = (await c.apps()).items[0];
      assert.ok(app);
      await assert.rejects(c.downloadAppTo(app, dest), TransportError);
      assert.ok(!existsSync(dest));
      assert.equal(statSync(`${dest}.part`).size, app.size / 2);
      await c.downloadAppTo(app, dest);
      assert.equal(createHash("sha256").update(readFileSync(dest)).digest("hex"), app.sha256);
      assert.equal(requestsOf(server.log).at(-1)?.path, "/api/lantern/v1/files/f_frost");
      await c.close();
    });
  });

  covers("wrong-content-range");
  test("a wrong Content-Range", async () => {
    await scenario("wrong-content-range", async (server) => {
      const dest = join(folder, "range.nsp");
      const c = client(server);
      const app = (await c.apps()).items[0];
      assert.ok(app);
      writeFileSync(`${dest}.part`, new Uint8Array(100).fill(3));
      await assert.rejects(c.downloadAppTo(app, dest), UnexpectedResponse);
      assert.ok(!existsSync(dest));
      await c.close();
    });
  });

  covers("small-order-key");
  test("a forged signature of a small-order key never verifies", async () => {
    await scenario("small-order-key", async (server) => {
      const c = client(server);
      const entry = await c.homebrewEntry("org.example.paperlamp");
      assert.ok(entry.signature);
      assert.equal(await hb.verifySignature(entry), false);
      await c.close();
    });
  });

  covers("expired-challenge", "replayed-challenge");
  for (const name of ["expired-challenge", "replayed-challenge"]) {
    test(`a signature refused again and again: ${name}`, async () => {
      await scenario(name, async (server) => {
        const c = client(server, { key: await DeviceKey.fromSeed(KEY_SEED) });
        const expected = name === "expired-challenge" ? SignatureExpired : SignatureReplayed;
        await assert.rejects(
          c.handshake(),
          (e: unknown) => e instanceof expected && e.acceptSignature?.components[0] === "@method",
        );
        await c.close();
        await until(() => requestsOf(server.log).length >= 2);
        assert.equal(requestsOf(server.log).length, 2); // signed again once, then given up
      });
    });
  }

  covers("pairing-elsewhere");
  test("a pairing code that points elsewhere", async () => {
    await scenario("pairing-elsewhere", async (server) => {
      const c = new NodeLanternClient(server.info.url, { userAgent: AGENT, platform: "switch" });
      await assert.rejects(c.pair("Lea's console", ["library"]), DocumentError);
      await c.close();
      await until(() => requestsOf(server.log).length >= 2);
      const seen = requestsOf(server.log);
      assert.deepEqual(
        seen.map((r) => r.path),
        ["/.well-known/lantern", "/api/lantern/v1/pairing"],
      );
      assert.ok(seen.every((r) => r.authorization === null));
    });
  });

  covers("redirect");
  test("a redirect is never followed", async () => {
    await scenario("redirect", async (server) => {
      const c = client(server);
      await assert.rejects(c.handshake(), UnexpectedResponse);
      await c.close();
      await until(() => requestsOf(server.log).length >= 1);
      assert.equal(requestsOf(server.log).length, 1);
    });
  });

  describe("over fetch(), as in a browser", () => {
    const fetched = (server: Served<Hostile>) =>
      new LanternClient(server.info.url, {
        userAgent: AGENT,
        platform: "switch",
        token: server.info.token,
        transport: new FetchTransport(),
      });
    for (const [name, expected] of [
      ["redirect", UnexpectedResponse],
      ["oversized-document", DocumentError],
      ["newer-schema", NewerSchema],
    ] as const) {
      test(name, async () => {
        await scenario(name, async (server) => {
          const c = fetched(server);
          if (name === "oversized-document") await c.handshake();
          await assert.rejects(name === "oversized-document" ? c.apps() : c.handshake(), expected);
        });
      });
    }
    for (const name of ["bad-digest", "wrong-bytes", "extra-bytes", "truncated"]) {
      test(name, async () => {
        await scenario(name, async (server) => {
          const c = fetched(server);
          const app = (await c.apps()).items[0];
          assert.ok(app);
          const sink = new MemorySink();
          await assert.rejects(c.downloadApp(app, sink), name === "truncated" ? TransportError : IntegrityError);
          if (name === "truncated") {
            await c.downloadApp(app, sink); // resumed with a Range
            assert.equal(sink.bytes().length, app.size);
          } else assert.equal(await sink.heldSize(), 0);
        });
      });
    }
  });

  test("every scenario is tested", () => {
    assert.deepEqual(SCENARIOS.map((s) => s.name).sort(), [...TESTED].sort());
  });
});
