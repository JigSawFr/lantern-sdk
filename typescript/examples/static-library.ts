/**
 * A static library: a library written as JSON files (GitHub Pages, a NAS, a USB stick), then read back (`StaticLibrary.open("https://…")` reads one over HTTP).
 *
 *     node --conditions=source examples/static-library.ts out/
 *
 * SPEC.md § 21. The files are the same documents a live server sends, with their SHA-256 and a handshake in
 * `lantern.json`, so a client reads them with no server code behind them.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StaticLibrary } from "lantern-protocol";
import { FileStaticSource, libraryInput, writeStatic } from "lantern-protocol/node";
import { MemoryLibrary } from "lantern-protocol/server";

const library = new MemoryLibrary({ base: "/api/lantern" });
library.addAppFile({
  data: new TextEncoder().encode("a made-up game"),
  platform: "switch",
  title_id: "0100ABCD00010000",
  app_id: "0100ABCD00010000",
  type: "base",
  version_code: 0,
  version_name: "1.0.0",
  name: "Frost Garden",
  format: "nsp",
});

const given = process.argv[2];
const out = given ?? join(mkdtempSync(join(tmpdir(), "lantern-static-")), "shelf");
try {
  const summary = await writeStatic(
    await libraryInput(library, { uid: "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f", name: "Shelf on a stick" }),
    out,
  );
  console.log(`wrote ${JSON.stringify(summary)}`);
  const shelf = await StaticLibrary.open(new FileStaticSource(out));
  const names: string[] = [];
  for await (const app of shelf.apps("switch")) names.push(app.name ?? app.app_id);
  console.log(shelf.hello.name, JSON.stringify(names));
} finally {
  if (given === undefined) rmSync(join(out, ".."), { recursive: true, force: true });
}
