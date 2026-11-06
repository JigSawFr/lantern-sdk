/**
 * Adds Lantern to a Node server: a library of one made-up game, served anonymously by node:http.
 *
 *     node --conditions=source examples/serve-node.ts 8080   # then: curl http://127.0.0.1:8080/.well-known/lantern
 *
 * `MemoryLibrary` holds apps in memory; a real server implements `Library` over its own files and database.
 * For tokens, pairing and signed requests, pass `accounts: new MemoryAccounts(...)` (or `authenticate`) to
 * `LanternApp`. Behind Hono or any framework of web Requests, use `fetchHandler(app)` instead of `listen()`:
 * `hono.all("/*", (c) => handler(c.req.raw))`.
 */

import { LanternApp, listen, MemoryLibrary } from "lantern-protocol/server";

export function makeApp(): LanternApp {
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
  return new LanternApp(library, { uid: "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f", name: "Living room shelf" });
}

const served = await listen(makeApp(), { port: Number(process.argv[2] ?? 8080), host: "127.0.0.1" });
console.log(`serving ${served.url}`);
process.on("SIGTERM", () => void served.close().then(() => process.exit(0)));
process.on("SIGINT", () => void served.close().then(() => process.exit(0)));
