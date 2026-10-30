/**
 * The specification's conformance suite (spec/conformance/run.py) against the
 * demo server built from the toolkit (test/demo.ts), served by node:http and
 * through fetchHandler() (web Requests, as Hono hands them over), anonymously
 * and with a token bound to its key, with `--admin-writes` (an account made,
 * then deleted) and `--peer` (a PeerServer of the toolkit's, holding the
 * demo's files). The demo offers every family of draft 0.5: sections, save
 * backups (encrypted ones too), cheat writes and requests among them, which
 * the suite writes then deletes. With its token, which holds every scope, the
 * demo reaches every level LEVELS says. Then lantern-static writes
 * the demo as a static library, which the suite's `--static` checks.
 */

import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { after, describe, test } from "node:test";
import { promisify } from "node:util";
import * as ed25519 from "../../src/ed25519.ts";
import { bytes } from "../../src/index.ts";
import { fetchHandler, type LanternApp, listen, type MemoryLibrary, PeerServer } from "../../src/server/index.ts";
import { DEMO_SEED, DEMO_TOKEN, GRANT_SEED, makeLantern, UID } from "../demo.ts";
import { PACKAGE, PYTHON, SPEC } from "../helpers.ts";

const run = promisify(execFile);
const folder = mkdtempSync(join(tmpdir(), "lantern-conformance-"));
const keyFile = join(folder, "demo.key");
writeFileSync(keyFile, bytes.toBase64(DEMO_SEED));
after(() => rmSync(folder, { recursive: true, force: true }));

// The read-side checks of the families the toolkit offers, and pairing: each must pass, not be skipped.
const REQUIRED = [
  "handshake.well-known",
  "handshake.v1",
  "handshake.anonymous",
  "handshake.platforms",
  "handshake.auth",
  "auth.unknown-token",
  "auth.unknown-handshake",
  "auth.basic-refused",
  "auth.no-basic",
  "apps.first-page",
  "apps.pages.name",
  "apps.pages.added",
  "apps.pages.release",
  "apps.sha256",
  "apps.platforms",
  "apps.page-size",
  "apps.bad-cursor",
  "apps.filters",
  "apps.etag",
  "platforms.filter",
  "platforms.query",
  "platforms.unknown",
  "platforms.bad-name",
  "platforms.vary",
  "missing.no-platform",
  "missing.installed",
  "missing.up-to-date",
  "missing.base",
  "missing.malformed",
  "files.whole",
  "files.ranges",
  "files.unsatisfiable",
  "files.unknown",
  "changes.token",
  "changes.bad-token",
  "titles.known",
  "titles.unknown",
  "titles.bulk",
  "titles.bulk-limit",
  "titles.changes",
  "titles.bad-token",
  "homebrew.pages",
  "homebrew.entries",
  "homebrew.manifests",
  "homebrew.kinds",
  "homebrew.filters",
  "homebrew.requires",
  "homebrew.ports",
  "homebrew.packages",
  "homebrew.signatures",
  "homebrew.updates",
  "homebrew.updates-platform",
  "homebrew.unknown",
  "cheats.sets",
  "cheats.text",
  "cheats.unknown",
  "schema.refused.library",
  "schema.refused.homebrew",
  "errors.unknown-route",
  "errors.problem",
  "errors.never-200",
  "errors.www-authenticate",
  "documents.type",
  "documents.date",
  "pairing.offered",
  "pairing.code",
  "pairing.verify-complete",
  "pairing.waiting",
  "pairing.slow-down",
  "pairing.unknown",
  "pairing.key",
  "admin.refused",
  "language.problem",
  "compression.files",
  "compression.json",
  ...["library", "titles", "changes", "sections", "homebrew", "saves", "cheats", "requests", "pairing", "admin"].map(
    (f) => `features.${f}`,
  ),
];
// Anonymously: the writes a caller without cheats.write is refused.
const ANONYMOUS = ["cheats.write"];
// With the demo's token, bound to its key, and every scope the demo serves.
const WITH_TOKEN = [
  "handshake.account",
  "features.anonymous",
  "caching.private",
  "signatures.unsigned",
  "signatures.invalid",
  "signatures.stale",
  "signatures.replayed",
  "signatures.digest",
  "signatures.accept-signature",
  "admin.users",
  "admin.pairings",
  "admin.rating-cap",
  "admin.refuse",
  "admin.devices",
  "admin.invitations",
  "admin.users-write",
  "admin.users-delete",
  "compression.etag",
  "cheats.write-cycle",
  "requests.list",
  "requests.create",
  "requests.delete",
  "saves.limits",
  "saves.list",
  "saves.no-platform",
  "saves.upload",
  "saves.read",
  "saves.upload-digest",
  "saves.upload-too-large",
  "saves.single",
  "saves.cleanup",
  "schema.refused.saves",
  "schema.refused.requests",
  // Draft 0.5.
  "e2e.upload",
  "events.stream",
  "events.resume",
  "events.bad-token",
  "events.long-poll",
  "events.heartbeat",
  "events.limit",
  "events.revoked",
  "peers.handshake",
  "peers.grant",
  "peer.refused",
  "peer.serves",
  "peer.rate",
  "sync.overview",
  "sync.write",
  "sync.future",
  "sync.if-match",
  "sync.generation",
  "sync.installed",
  "sync.malformed",
  "sync.limits",
  ...["events", "peers", "sync"].map((f) => `features.${f}`),
];
/**
 * The demo compresses JSON with zstd when asked (Node has it); the suite reads it on Python 3.14 (CI), and leaves
 * the checks that read every document as skipped on an older Python: those two are then SKIP, for that reason alone.
 */
const SUITE_READS_ZSTD = spawnSync(PYTHON, ["-c", "import compression.zstd"]).status === 0;
const NEEDS_ZSTD = ["documents.schema", "documents.limits"];
/** The levels the demo reaches with its token (SPEC.md § 17). */
const LEVELS = "Lantern Core +titles +homebrew +saves +cheats +requests +admin +events +peers +sync +encrypted_saves";

/** A peer of the toolkit's holding the demo's files (written to disk), taking the demo's grants (SPEC.md § 19.4). */
async function demoPeer(app: LanternApp): Promise<{ url: string; close(): Promise<void> }> {
  const lib = app.library as MemoryLibrary;
  const files = new Map<string, { path: string; size: number }>();
  for (const a of lib.apps()) {
    const ref = lib.file(/\/files\/([^/]+)$/.exec(a.file)?.[1] ?? "");
    if (ref?.data === undefined) continue;
    const path = join(folder, a.sha256);
    writeFileSync(path, ref.data);
    files.set(a.sha256, { path, size: ref.size });
  }
  const key = (await ed25519.fromSeed(GRANT_SEED)).publicKey;
  const peer = new PeerServer({ files, keys: { [UID]: key } });
  return peer.listen();
}

/** The demo served through fetchHandler(), bridged from node:http as a framework's server does. */
async function overFetch(app: LanternApp): Promise<{ url: string; close(): Promise<void> }> {
  const handler = fetchHandler(app, { remote: () => "127.0.0.1" });
  const server = http.createServer((req, res) => {
    const url = `http://${req.headers.host ?? "127.0.0.1"}${req.url ?? "/"}`;
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers))
      for (const one of Array.isArray(v) ? v : v !== undefined ? [v] : []) headers.append(k, one);
    const init: RequestInit & { duplex?: "half" } = { method: req.method ?? "GET", headers };
    if (req.method !== "GET" && req.method !== "HEAD") {
      init.body = Readable.toWeb(req) as ReadableStream<Uint8Array>;
      init.duplex = "half";
    }
    handler(new Request(url, init)).then(
      async (response) => {
        res.statusCode = response.status;
        response.headers.forEach((v, k) => {
          res.setHeader(k, v);
        });
        if (response.body === null) res.end();
        else {
          // As a framework's server does: a client gone cancels the body (an event stream frees its slot).
          const body = Readable.fromWeb(response.body as never);
          res.on("close", () => body.destroy());
          body.pipe(res);
        }
      },
      () => res.destroy(),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/`,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

async function suite(url: string, token: boolean, peer?: string): Promise<{ code: number; report: string }> {
  const args = [
    join(SPEC, "conformance", "run.py"),
    url,
    ...(token ? ["--token", DEMO_TOKEN, "--key", keyFile, "--admin-writes"] : []),
    ...(peer !== undefined ? ["--peer", peer] : []),
  ];
  try {
    const { stdout } = await run(PYTHON, args, { maxBuffer: 1 << 24, timeout: 300_000 });
    return { code: 0, report: stdout };
  } catch (e) {
    const failed = e as { code?: number; stdout?: string };
    return { code: failed.code ?? 1, report: failed.stdout ?? String(e) };
  }
}

for (const adapter of ["node:http", "fetchHandler"]) {
  describe(`the conformance suite against the demo, through ${adapter}`, () => {
    for (const token of [false, true]) {
      test(token ? "with a token bound to its key" : "anonymously", async () => {
        const app = await makeLantern();
        const served = adapter === "node:http" ? await listen(app) : await overFetch(app);
        const peer = token ? await demoPeer(app) : undefined;
        let result: { code: number; report: string };
        try {
          result = await suite(served.url, token, peer?.url);
        } finally {
          app.shutdown(1);
          await served.close();
          await peer?.close();
        }
        const { code, report } = result;
        const status = new Map(
          [...report.matchAll(/^(PASS|FAIL|WARN|SKIP)\s+§ \S+\s+(\S+)/gm)].map((m) => [m[2], m[1]]),
        );
        const failed = report.split("\n").filter((l) => l.startsWith("FAIL"));
        assert.equal(code, 0, report);
        assert.deepEqual(failed, [], report);
        for (const check of [
          ...REQUIRED,
          ...(token ? WITH_TOKEN : ANONYMOUS),
          ...(SUITE_READS_ZSTD ? NEEDS_ZSTD : []),
        ]) {
          assert.equal(status.get(check), "PASS", `${check}\n${report}`);
        }
        if (!SUITE_READS_ZSTD) {
          for (const check of NEEDS_ZSTD)
            assert.match(
              report,
              new RegExp(`SKIP .*${check.replace(".", "\\.")}.*\\n.*zstd, which this Python cannot read`),
            );
        }
        // Plain HTTP on loopback is the one warning.
        assert.deepEqual(
          [...status].filter(([, s]) => s === "WARN").map(([c]) => c),
          ["transport.https"],
          report,
        );
        if (token) assert.ok(report.includes(`Levels reached (SPEC.md § 17, draft 0.5): ${LEVELS}`), report);
      });
    }
  });
}

describe("lantern-static: the demo as a static library, checked by the suite's --static", () => {
  test("Lantern Static reached, nothing failed", async () => {
    const app = await makeLantern();
    const served = await listen(app);
    const out = join(folder, "static");
    try {
      await run(process.execPath, [
        join(PACKAGE, "src", "node", "lantern-static.ts"),
        "--from",
        served.url,
        "--out",
        out,
        "--token",
        DEMO_TOKEN,
        "--key",
        keyFile,
        "--page-size",
        "2",
      ]);
    } finally {
      app.shutdown(1);
      await served.close();
    }
    let report: string;
    try {
      ({ stdout: report } = await run(PYTHON, [join(SPEC, "conformance", "run.py"), "--static", out], {
        maxBuffer: 1 << 24,
        timeout: 300_000,
      }));
    } catch (e) {
      report = String((e as { stdout?: string }).stdout ?? e);
    }
    assert.deepEqual(
      report.split("\n").filter((l) => l.startsWith("FAIL")),
      [],
      report,
    );
    assert.match(report, /Levels reached.*Lantern Static/, report);
  });
});
