#!/usr/bin/env node
/**
 * The library in a browser (Chromium, by Playwright): the built ESM of dist/,
 * loaded by a page served by the demo server itself (one origin, so no CORS),
 * reads the handshake, pages through the apps, downloads a file and a cheat
 * set (SHA-256 in TypeScript, as it streams), verifies a homebrew's signature
 * and pairs with a non-extractable device key (WebCrypto Ed25519), then makes
 * signed requests with it; holds an event stream over fetch() (the library
 * event of an app the server adds) and long-polls; and decrypts an encrypted
 * backup of the specification's vectors (XChaCha20-Poly1305 in TypeScript,
 * HKDF by WebCrypto), then encrypts and decrypts one of its own.
 *
 *     npm run build && node test/browser/smoke.ts
 *
 * PLAYWRIGHT_CHROMIUM names a Chromium to run instead of Playwright's own.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, normalize } from "node:path";
import { chromium } from "playwright-core";
import { listen, type MemoryLibrary, nodeHandler } from "../../src/server/index.ts";
import { makeLantern } from "../demo.ts";
import { PACKAGE } from "../helpers.ts";

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>Lantern smoke</title></head><body><script type="module">
import { DeviceKey, LanternClient, MemorySink, SaveKey, bytes, e2e, ed25519, homebrew } from "/dist/index.js";
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
  await c.waitForPairing(pairing, { sleep: (s) => new Promise((r) => setTimeout(r, Math.min(s, 1.05) * 1000)) });
  const hello = await c.handshake();
  out.bound = hello.account.bound;
  out.signed = (await c.apps({ pageSize: 1 })).items.length;
  // Events over fetch(): ready, then the library event of an app the server adds (window.ready tells it).
  const stream = await c.events();
  const it = stream[Symbol.asyncIterator]();
  const ready = (await it.next()).value;
  window.ready = true;
  const seen = (await it.next()).value;
  out.events = [ready.event, seen.event, seen.data.platforms.join(",")];
  await stream.close();
  out.polled = (await c.poll(ready.id, 5)).events.some((e) => e.id === seen.id);
  // An encrypted backup of the specification's vectors, decrypted; then one of the tab's own.
  const saveKey = new SaveKey(bytes.fromHex("392a8c10ab886703b2eae2d48b383195341285689a82579912dd225398671a31"));
  const archive = await e2e.decryptBytes(saveKey, bytes.fromHex("4c544e453245303115d65cfba86a1bce6465666768696a6b6c6d6e6f707172737475767778797a7b75ef6248e9716a3dab9287f319c3efb9fc4ec2f400063bdc669ca64c2bacdf0bf8ce8bc7042ec30915c2bb4e1571f65641ca30fa7a883f2f94406eb997c0bdd6846aa404cf48684b601ca91a4296f8acabc7449935f0"));
  out.decrypted = bytes.toHex(archive) === "504b0506000000000000000000000000000000000000";
  out.keyId = await saveKey.keyId();
  const mine = SaveKey.generate();
  const again = SaveKey.fromPhrase(mine.phrase());
  const sealed = await e2e.encryptBytes(mine, new TextEncoder().encode("Frostline Tales, chapter 7"));
  out.roundTrip = new TextDecoder().decode(await e2e.decryptBytes(again, sealed));
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
    // The user approves the tab's pairing on the server's side, once it waits.
    const done = () => page.evaluate(() => (window as unknown as { result?: unknown }).result !== undefined);
    const ready = () => page.evaluate(() => (window as unknown as { ready?: boolean }).ready === true);
    let approved = false;
    let added = false;
    for (let i = 0; i < 600 && !(await done()); i++) {
      const first = app.desk?.waiting()[0];
      if (!approved && first !== undefined) {
        await app.desk?.approve(first, "mira");
        approved = true;
      }
      if (!added && (await ready())) {
        (app.library as MemoryLibrary).addAppFile({
          data: new TextEncoder().encode("Brass Lantern, a fictional game"),
          platform: "switch",
          title_id: "0100AA0000990000",
          app_id: "0100AA0000990000",
          type: "base",
          version_code: 0,
          name: "Brass Lantern",
          format: "nsp",
        });
        added = true;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    if (!(await done())) throw new Error(`no result within 60 s: ${await page.title()}; ${errors.join("; ")}`);
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
      events: ["ready", "library", "switch"],
      polled: true,
      decrypted: true,
      keyId: "15d65cfba86a1bce",
      roundTrip: "Frostline Tales, chapter 7",
    });
    assert.deepEqual(errors, []);
    console.warn(
      "browser smoke: the client read, downloaded, verified, paired, signed, held an event stream and decrypted in Chromium",
    );
  } finally {
    await browser.close();
    await served.close();
  }
}

await main();
