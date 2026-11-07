// Builds the page's playground, site/assets/sdk-playground.js: LanternClient and LanternApp (typescript/src/) with the
// page's glue (site/playground/playground.ts), in one script for the browser.
//
//     node tools/build_playground.mjs          # writes the bundle
//     node tools/build_playground.mjs --check  # fails unless the bundle is the one these sources give
//
// Needs esbuild 0.25.5 (npm i esbuild@0.25.5 anywhere, and NODE_PATH or run it from there). tools/check_site.py checks,
// without esbuild, that the bundle's recorded SHA-256 of its sources (its first line) is that of the sources now:
// change typescript/src/ or site/playground/ and CI says to run this again.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "site/assets/sdk-playground.js");

function sources(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return path.endsWith(".ts") ? [path] : [];
  });
}
// the same list and the same digest as tools/check_site.py
const files = [...sources(join(root, "typescript/src")), ...sources(join(root, "site/playground"))]
  .map((p) => relative(root, p).split("\\").join("/"))
  .sort();
const hash = createHash("sha256");
for (const f of files) hash.update(`${f}\0`).update(readFileSync(join(root, f))).update("\0");
const digest = hash.digest("hex");

const { build } = createRequire(import.meta.url)("esbuild");
const result = await build({
  entryPoints: [join(root, "site/playground/playground.ts")],
  bundle: true,
  minify: true,
  format: "iife",
  globalName: "lanternPlayground",
  platform: "browser",
  target: "es2022",
  alias: { "node:crypto": join(root, "site/playground/node-crypto.ts") },
  external: ["node:*"],
  write: false,
  legalComments: "none",
  // The server reaches node:fs, node:http and the like only to serve files from disk or a socket; in this page it holds
  // its files in memory. Those imports are met by a stand-in that says so if it is ever called.
  banner: {
    js: 'var require=(id)=>new Proxy({},{get:(_,name)=>name==="__esModule"?false:()=>{throw new Error(id+" is not in the browser")}});',
  },
});
const text = `/* sdk-playground source-sha256:${digest} (tools/build_playground.mjs) */\n${result.outputFiles[0].text}`;
if (process.argv.includes("--check")) {
  if (readFileSync(out, "utf8") !== text) {
    console.error("site/assets/sdk-playground.js is not what its sources give: node tools/build_playground.mjs");
    process.exit(1);
  }
  console.log("sdk-playground.js: up to date");
} else {
  writeFileSync(out, text);
  console.log(`site/assets/sdk-playground.js (${text.length} bytes, sources ${digest.slice(0, 12)})`);
}
