/** A title's images on the server's own origin (SPEC.md § 7.1, L-7.1-2): content-addressed, served for a year,
 * immutable, and hidden with the titles that show them. */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { before, describe, test } from "node:test";
import { FileRef, LanternApp, MemoryAccounts, type MemoryLibrary, ServerRequest } from "../../src/server/index.ts";
import { buildLibrary, UID } from "../demo.ts";

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array<number>(64).fill(0)]);
const TOKEN = "et_media-0123456789abcdef0123456789abcdef";
const get = (app: LanternApp, path: string, headers: Record<string, string> = {}) =>
  app.handle(ServerRequest.fromTarget("GET", path, { headers: { Host: "shelf.example.org", ...headers } }));

describe("an image of a title on this origin (SPEC.md § 7.1)", () => {
  let library: MemoryLibrary;
  let name = "";
  let stray = "";
  before(async () => {
    library = await buildLibrary();
    name = library.addMedia(FileRef.ofBytes(PNG, "image/png"), "png");
    stray = library.addMedia(FileRef.ofBytes(new Uint8Array([...PNG, 1]), "image/png"), "png");
    library.addTitle({
      schema: 1,
      platform: "switch",
      title_id: "0100FF0000010000",
      name: "Pictured",
      ratings: [{ system: "PEGI", rating: "18" }],
      icon: { url: `/api/lantern/v1/media/${name}`, sha256: createHash("sha256").update(PNG).digest("hex") },
    } as never);
  });

  test("[L-7.1-2] served by its hash: a year, immutable, public without a token", async () => {
    const app = new LanternApp(library, { uid: UID, name: "Media shelf" });
    const r = await get(app, `/api/lantern/v1/media/${name}`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("Content-Type"), "image/png");
    assert.equal(r.headers.get("Cache-Control"), "public, max-age=31536000, immutable");
    assert.ok(name.startsWith(createHash("sha256").update(PNG).digest("hex")));
  });

  test("an unknown image, or one no title shows, is 404 and never immutable", async () => {
    const app = new LanternApp(library, { uid: UID, name: "Media shelf" });
    for (const missing of [`${"0".repeat(64)}.png`, stray]) {
      const r = await get(app, `/api/lantern/v1/media/${missing}`);
      assert.equal(r.status, 404);
      assert.ok(!/immutable/.test(r.headers.get("Cache-Control") ?? ""));
    }
  });

  test("private with a token, and hidden by a rating cap that hides the title", async () => {
    const accounts = new MemoryAccounts([{ name: "mira", scopes: ["library"] }]);
    accounts.addToken(TOKEN, "mira", "Mira's console", ["library"]);
    accounts.addToken("et_capped-0123456789abcdef0123456789abcdef", "mira", "Child", ["library"], {
      ratingCap: { age: 12 },
    });
    const app = new LanternApp(library, { uid: UID, name: "Media shelf", accounts });
    const path = `/api/lantern/v1/media/${name}`;
    const open = await get(app, path, { Authorization: `Bearer ${TOKEN}` });
    assert.equal(open.status, 200);
    assert.equal(open.headers.get("Cache-Control"), "private, max-age=31536000, immutable");
    const capped = await get(app, path, { Authorization: "Bearer et_capped-0123456789abcdef0123456789abcdef" });
    assert.equal(capped.status, 404);
  });
});
