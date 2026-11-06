/**
 * Reads a Lantern library: who serves it, its apps, what a console is missing, and one verified download.
 *
 *     node --conditions=source examples/read-library.ts https://shelf.example.org/ [platform]
 *
 * (In your own project, `npm install lantern-protocol` and run it with plain `node`.) The download is checked
 * against the SHA-256 the server lists and renamed only when it matches; a `.part` file is resumed with a Range
 * request after a cut (SPEC.md § 6.6).
 */

import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NodeLanternClient } from "lantern-protocol/node";

const [url, platform = "switch"] = process.argv.slice(2);
if (url === undefined) {
  console.error("usage: read-library.ts <url> [platform]");
  process.exit(2);
}

const client = new NodeLanternClient(url, { platform, userAgent: "ReadLibrary/1.0" });
const hello = await client.handshake();
console.log(`${hello.name}: ${Object.keys(hello.features).sort().join(", ")}`);

const apps = [];
for await (const app of client.iterApps({ pageSize: 5 })) {
  // every page, cursor by cursor
  apps.push(app);
  console.log(`  ${app.name} ${app.version_name ?? app.version_code} (${app.size} bytes)`);
}

// What a console that holds the first app, at version 0, is missing.
const first = apps[0];
if (first !== undefined) {
  const page = await client.missing([[first.app_id, 0]]);
  console.log(`missing: ${page.items.length} on the first page`);
}

// The smallest non-empty file, downloaded to a temporary folder and checked on the way.
const smallest = apps.filter((a) => a.size > 0).sort((a, b) => a.size - b.size)[0];
if (smallest !== undefined) {
  const folder = mkdtempSync(join(tmpdir(), "lantern-"));
  try {
    const saved = await client.downloadAppTo(smallest, join(folder, `${smallest.app_id}.pkg`));
    console.log(
      `downloaded ${smallest.name}: ${statSync(saved).size} bytes, sha256 ${smallest.sha256.slice(0, 12)}… matched`,
    );
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
}
