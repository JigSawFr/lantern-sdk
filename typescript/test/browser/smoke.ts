#!/usr/bin/env node
/**
 * The library in a browser (Chromium, by Playwright): the built ESM of dist/,
 * loaded by a page served by the demo server itself (one origin, so no CORS),
 * reads the handshake, pages through the apps, downloads a file and a cheat
 * set (SHA-256 in TypeScript, as it streams), verifies a homebrew's signature
 * and pairs with a non-extractable device key (WebCrypto Ed25519), then makes
 * signed requests with it.
 *
 *     npm run build && node test/browser/smoke.ts
 *
 * PLAYWRIGHT_CHROMIUM names a Chromium to run instead of Playwright's own.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, normalize } from "node:path";
import { chromium } from "playwright-core";
import { listen, nodeHandler } from "../../src/server/index.ts";
import { makeLantern } from "../demo.ts";
import { PACKAGE } from "../helpers.ts";

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>Lantern smoke</title></head><body><script type="module">
import { DeviceKey, LanternClient, MemorySink, ed25519, homebrew } from "/dist/index.js";
const out = {};
try {
  const c = new LanternClient(location.origin, { platform: "switch", userAgent: "LanternBrowserSmoke/1.0" });
  out.name = (await c.handshake()).name;
  let n = 0;
  for await (const _ of c.iterApps({ pageSize: 2 })) n++;
  out.apps = n;
  const app = (await c.apps({ sort: "added" })).items.find((a) => a.size > 0);
  const sink = new MemorySink();
  await c.downloadApp(app, sink);
  out.download = sink.bytes().length === app.size;
  const sets = (await c.cheats()).cheats;
  out.cheat = (await c.cheatText(sets[0])).startsWith("[");
  const entry = await c.homebrewEntry("org.example.starjar");
  out.signature = await homebrew.verifySignature(entry);
  out.ed25519 = await ed25519.available();
  const key = await DeviceKey.generate();
  out.extractable = key.extractable;
  const pairing = await c.pair("A browser's tab", ["library"], { key });
  document.title = "code " + pairing.code;
  await c.waitForPairing(pairing, { sleep: (s) => new Promise((r) => setTimeout(r, Math.min(s, 0.3) * 1000)) });
  const hello = await c.handshake();
  out.bound = hello.account.bound;
  out.signed = (await c.apps({ pageSize: 1 })).items.length;
} catch (e) {
  out.error = String(e && e.stack || e);
}
window.result = out;
</script></body></html>`;

async function main(): Promise<void> {
  const app = await makeLantern();
  if (app.desk) app.desk.interval = 1;
  const dist = join(PACKAGE, "dist");
  const handler = nodeHandler(app, {
    fallback: (req, res) => {
      const path = (req.url ?? "/").split("?")[0] ?? "/";
      if (path === "/smoke.html") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }).end(PAGE);
        return;
      }
      const file = normalize(join(dist, path.replace(/^\/dist\//, "")));
      if (!path.startsWith("/dist/") || !file.startsWith(dist)) {
        res.writeHead(404).end();
        return;
      }
      readFile(file).then(
        (data) =>
          res
            .writeHead(200, { "Content-Type": file.endsWith(".js") ? "text/javascript" : "application/json" })
            .end(data),
        () => res.writeHead(404).end(),
      );
    },
  });
  const served = await listen(app);
  served.server.removeAllListeners("request");
  served.server.on("request", handler);
  const executablePath = process.env["PLAYWRIGHT_CHROMIUM"];
  const browser = await chromium.launch(executablePath ? { executablePath } : {});
  try {
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(String(e)));
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });
    await page.goto(`${served.url}smoke.html`);
    // The user approves the tab's pairing on the server's side.
    for (let i = 0; i < 200; i++) {
      const waiting = app.desk?.waiting() ?? [];
      const first = waiting[0];
      if (first !== undefined) {
        await app.desk?.approve(first, "mira");
        break;
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    await page.waitForFunction(() => (window as unknown as { result?: unknown }).result !== undefined, undefined, {
      timeout: 30_000,
    });
    const result = (await page.evaluate(() => (window as unknown as { result: unknown }).result)) as Record<
      string,
      unknown
    >;
    assert.equal(result["error"], undefined, String(result["error"]));
    assert.deepEqual(result, {
      name: "Demo shelf",
      apps: 7,
      download: true,
      cheat: true,
      signature: true,
      ed25519: true,
      extractable: false,
      bound: true,
      signed: 1,
    });
    assert.deepEqual(errors, []);
    console.warn("browser smoke: the client read, downloaded, verified, paired and signed in Chromium");
  } finally {
    await browser.close();
    await served.close();
  }
}

await main();
