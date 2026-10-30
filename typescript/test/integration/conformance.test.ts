/**
 * The specification's conformance suite (spec/conformance/run.py) against the
 * demo server built from the toolkit (test/demo.ts), served by node:http and
 * through fetchHandler() (web Requests, as Hono hands them over), anonymously
 * and with a token bound to its key. Families the toolkit does not offer
 * (sections, saves, requests) are at 0: the suite checks that their routes are
 * refused. With its token the demo reaches the levels LEVELS says, as the
 * Python toolkit's demo does.
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
import { bytes } from "../../src/index.ts";
import { fetchHandler, listen } from "../../src/server/index.ts";
import { DEMO_SEED, DEMO_TOKEN, makeLantern } from "../demo.ts";
import { PYTHON, SPEC } from "../helpers.ts";

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
  "cheats.write",
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
  "compression.etag",
];
/**
 * The demo compresses JSON with zstd when asked (Node has it); the suite reads it on Python 3.14 (CI), and leaves
 * the checks that read every document as skipped on an older Python: those two are then SKIP, for that reason alone.
 */
const SUITE_READS_ZSTD = spawnSync(PYTHON, ["-c", "import compression.zstd"]).status === 0;
const NEEDS_ZSTD = ["documents.schema", "documents.limits"];
/** The levels the demo reaches with its token (SPEC.md § 17). */
const LEVELS = "Lantern Core +titles +homebrew +cheats +admin";

/** The demo served through fetchHandler(), bridged from node:http as a framework's server does. */
async function overFetch(): Promise<{ url: string; close(): Promise<void> }> {
  const handler = fetchHandler(await makeLantern(), { remote: () => "127.0.0.1" });
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
        else Readable.fromWeb(response.body as never).pipe(res);
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

async function suite(url: string, token: boolean): Promise<{ code: number; report: string }> {
  const args = [join(SPEC, "conformance", "run.py"), url, ...(token ? ["--token", DEMO_TOKEN, "--key", keyFile] : [])];
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
        const served = adapter === "node:http" ? await listen(await makeLantern()) : await overFetch();
        let result: { code: number; report: string };
        try {
          result = await suite(served.url, token);
        } finally {
          await served.close();
        }
        const { code, report } = result;
        const status = new Map(
          [...report.matchAll(/^(PASS|FAIL|WARN|SKIP)\s+§ \S+\s+(\S+)/gm)].map((m) => [m[2], m[1]]),
        );
        const failed = report.split("\n").filter((l) => l.startsWith("FAIL"));
        assert.equal(code, 0, report);
        assert.deepEqual(failed, [], report);
        for (const check of [...REQUIRED, ...(token ? WITH_TOKEN : []), ...(SUITE_READS_ZSTD ? NEEDS_ZSTD : [])]) {
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
