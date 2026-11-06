/**
 * Draft 0.11: the TLS floor of the Node client and of the toolkit's TLS server (SPEC.md § 2), Strict-Transport-
 * Security, a uid that is a lower-case UUID of version 4 or 7 (§ 4.2) and a long lifetime with `immutable` for what an
 * address names by its SHA-256 (§ 14).
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import * as https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { NodeTransport } from "../../src/node/index.ts";
import {
  LanternApp,
  listen,
  MemoryAccounts,
  MemoryLibrary,
  PeerServer,
  ServerRequest,
} from "../../src/server/index.ts";
import { buildLibrary, UID } from "../demo.ts";

const dir = mkdtempSync(join(tmpdir(), "lantern-v011-"));
after(() => rmSync(dir, { recursive: true, force: true }));
let key = "";
let cert = "";
before(() => {
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2"].concat([
      "-subj",
      "/CN=localhost",
      "-keyout",
      join(dir, "k.pem"),
      "-out",
      join(dir, "c.pem"),
    ]),
    { stdio: "ignore" },
  );
  key = readFileSync(join(dir, "k.pem"), "utf8");
  cert = readFileSync(join(dir, "c.pem"), "utf8");
});

const get = (app: LanternApp, path: string, headers: Record<string, string> = {}) =>
  app.handle(ServerRequest.fromTarget("GET", path, { headers: { Host: "shelf.example.org", ...headers } }));

describe("a uid is a lower-case UUID of version 4 or 7 (SPEC.md § 4.2)", () => {
  const make = (uid: string) => new LanternApp(new MemoryLibrary(), { uid, name: "Uid shelf" });

  test("[L-4.2-9] versions 4 and 7 in lower case are kept", () => {
    for (const uid of [
      "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f",
      "01890a5d-ac96-7ab2-80e2-4536629c90de",
      crypto.randomUUID(),
    ])
      assert.equal(make(uid).uid, uid);
  });

  test("[L-4.2-9] upper case, other versions, a v1 (hardware address) and free text throw at configuration", () => {
    for (const uid of [
      "3D5C7E1A-0B2F-4C6D-9E8A-1F2B3C4D5E6F",
      "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "6ba7b810-9dad-61d1-80b4-00c04fd430c8",
      "3d5c7e1a-0b2f-4c6d-ce8a-1f2b3c4d5e6f",
      "Den console",
      "",
    ])
      assert.throws(() => make(uid), RangeError, uid);
    assert.throws(() => new PeerServer({ files: new Map(), keys: {}, uid: "NOT-A-UID" }), RangeError);
  });

  test("[L-4.2-9] a generated peer uid is a random v4", () => {
    assert.match(new PeerServer({ files: new Map(), keys: {} }).uid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab]/);
  });
});

describe("Strict-Transport-Security (SPEC.md § 2)", () => {
  const make = (extra: Record<string, unknown> = {}) =>
    new LanternApp(new MemoryLibrary(), { uid: UID, name: "Hsts shelf", ...extra });

  test("[L-2-11] off by default, on with hsts or scheme https, for answers and errors alike", async () => {
    assert.equal((await get(make(), "/.well-known/lantern")).headers.get("Strict-Transport-Security"), null);
    for (const extra of [{ hsts: true }, { scheme: "https" }]) {
      const app = make(extra);
      for (const path of ["/.well-known/lantern", "/api/lantern/v1/nothing"]) {
        const value = (await get(app, path)).headers.get("Strict-Transport-Security") ?? "";
        assert.ok(Number(/max-age=(\d+)/.exec(value)?.[1]) >= 15552000, `${path}: ${value}`);
      }
    }
    assert.equal(
      (await get(make({ hsts: false, scheme: "https" }), "/.well-known/lantern")).headers.get(
        "Strict-Transport-Security",
      ),
      null,
    );
  });

  test("[L-2-10][L-2-11] listen({ tls }) serves HTTPS with the header, and refuses TLS 1.1", async () => {
    const served = await listen(make(), { tls: { key, cert } });
    try {
      assert.match(served.url, /^https:/);
      assert.equal((served.server as https.Server).constructor.name, "Server");
      const transport = new NodeTransport({ verify: false });
      const res = await transport.send(
        { method: "GET", url: `${served.url}.well-known/lantern`, headers: new Headers() },
        { timeout: 5 },
      );
      assert.equal(res.status, 200);
      assert.match(res.headers.get("Strict-Transport-Security") ?? "", /max-age=31536000/);
      transport.close();
      const old = await new Promise<string>((resolve) => {
        const req = https.get(
          `${served.url}.well-known/lantern`,
          {
            rejectUnauthorized: false,
            minVersion: "TLSv1",
            maxVersion: "TLSv1.1",
            ciphers: "ALL:@SECLEVEL=0",
            agent: false,
          },
          () => resolve("answered"),
        );
        req.on("error", (e) => resolve(`refused: ${e.message}`));
      });
      assert.match(old, /^refused/);
    } finally {
      await served.close();
    }
  });
});

describe("the Node client's TLS floor (SPEC.md § 2)", () => {
  test("[L-2-9] a server that speaks TLS 1.1 at most is refused, one of TLS 1.2 is reached", async () => {
    const run = async (maxVersion: "TLSv1.1" | "TLSv1.2"): Promise<string> => {
      const server = https.createServer(
        { key, cert, minVersion: "TLSv1", maxVersion, ciphers: "ALL:@SECLEVEL=0" },
        (_req, res) => res.end("ok"),
      );
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
      const port = (server.address() as { port: number }).port;
      const transport = new NodeTransport({ verify: false });
      try {
        const res = await transport.send(
          { method: "GET", url: `https://localhost:${port}/`, headers: new Headers() },
          { timeout: 5 },
        );
        return `status ${res.status}`;
      } catch (e) {
        return `failed ${e instanceof Error ? e.message : String(e)}`;
      } finally {
        transport.close();
        server.close();
        server.closeAllConnections();
      }
    };
    assert.equal(await run("TLSv1.2"), "status 200");
    assert.match(await run("TLSv1.1"), /^failed/);
  });
});

describe("what an address names by its SHA-256 is immutable (SPEC.md § 14)", () => {
  let app: LanternApp;
  let sha = "";
  before(async () => {
    const library = await buildLibrary({ deltas: true });
    const accounts = new MemoryAccounts([{ name: "mira", scopes: ["library"] }]);
    accounts.addToken("et_v011-0123456789abcdef0123456789abcdef", "mira", "Mira's console", ["library"]);
    app = new LanternApp(library, { uid: UID, name: "Immutable shelf", accounts });
    sha = (await library.apps()).find((a) => a.chunks !== undefined)?.sha256 ?? "";
    assert.ok(sha);
  });
  const path = () => `/api/lantern/v1/chunks/sha256/${sha}`;

  test("[L-14-5] a chunk index: public, a year, immutable, with its ETag; 304 on revalidation", async () => {
    const r = await get(app, path());
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("Cache-Control"), "public, max-age=31536000, immutable");
    const etag = r.headers.get("ETag") as string;
    assert.ok(etag);
    assert.equal((await get(app, path(), { "If-None-Match": etag })).status, 304);
  });

  test("[L-14-5] private when the caller's token decides", async () => {
    const r = await get(app, path(), { Authorization: "Bearer et_v011-0123456789abcdef0123456789abcdef" });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("Cache-Control"), "private, max-age=31536000, immutable");
  });

  test("[L-14-5] an answer that is not found is never immutable", async () => {
    const r = await get(app, `/api/lantern/v1/chunks/sha256/${"0".repeat(64)}`);
    assert.equal(r.status, 404);
    assert.ok(!/immutable/.test(r.headers.get("Cache-Control") ?? ""));
  });
});
