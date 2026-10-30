#!/usr/bin/env node
/**
 * A demo server built from the toolkit, over a small fictional library: games,
 * homebrew and cheat sets that do not exist, for the tests and the conformance
 * runs. The same library as python/tests/demo.py.
 *
 *     node test/demo.ts --port 8080 --key-file /tmp/demo.key
 *     python3 ../spec/conformance/run.py http://127.0.0.1:8080/ --token et_demo-… --key /tmp/demo.key
 *
 * It offers events (a heartbeat every 5 seconds), grants of a fixed key and
 * sync in memory. Its accounts are the toolkit's own: mira holds every scope it serves, and
 * DEMO_TOKEN, her console's, is bound to the device key DEMO_KEY: every
 * request it carries is signed. `--key-file` writes DEMO_KEY's seed (base64)
 * where the conformance suite's `--key` reads it. It prints one JSON line
 * ({"url", "token"}) once it listens, then serves until it is stopped.
 */

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import * as ed25519 from "../src/ed25519.ts";
import { bytes, DeviceKey, type Homebrew, homebrew as hb, type Package, type Title } from "../src/index.ts";
import {
  type FileRef,
  LanternApp,
  type LanternAppOptions,
  listen,
  MemoryAccounts,
  MemoryLibrary,
  makePackage,
  writeZip,
} from "../src/server/index.ts";

export const UID = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";
export const DEMO_TOKEN = "et_demo-0123456789abcdef0123456789abcdef";
/** The demo device's key, made from a fixed phrase: for the demo only, never a real device's. */
export const DEMO_SEED = new Uint8Array(createHash("sha256").update("Mira's fictional console key").digest());
/** Every scope the demo serves: its admin's. */
export const EVERY_SCOPE = ["library", "cheats", "admin", "sync.read", "sync.write"];
/** The demo's grant key (SPEC.md § 19.3), from a fixed phrase: the demo's alone. */
export const GRANT_SEED = new Uint8Array(createHash("sha256").update("Demo shelf's fictional grant key").digest());
const AUTHOR_SEED = new Uint8Array(createHash("sha256").update("Mira's fictional signing key").digest()); // for the demo only
const BASE = "/api/lantern";

/** `size` bytes, the same each run, that are no real game's. */
export function blob(label: string, size: number): Uint8Array {
  const out = new Uint8Array(size);
  let at = 0;
  for (let counter = 0; at < size; counter++) {
    const d = createHash("sha256").update(`${label}:${counter}`).digest();
    out.set(d.subarray(0, Math.min(32, size - at)), at);
    at += 32;
  }
  return out;
}

const text = (s: string): Uint8Array => new TextEncoder().encode(s);

async function sign(entry: Homebrew): Promise<void> {
  const author = await ed25519.fromSeed(AUTHOR_SEED);
  const publicKey = bytes.toBase64(author.publicKey);
  const signature = async (p: Package) => ({
    alg: "ed25519",
    public_key: publicKey,
    value: bytes.toBase64(await ed25519.sign(author.privateKey, hb.signedMessage(entry, p))),
  });
  entry.signature = await signature(entry.package);
  for (const p of entry.packages ?? []) p.signature = await signature(p);
}

export async function buildLibrary(): Promise<MemoryLibrary> {
  const lib = new MemoryLibrary({ base: BASE });
  // Switch games: a base, two updates and an add-on; a second game; an Android app.
  const games: [string, string, string, string, number, string | undefined, string, number][] = [
    ["Lumen Drift", "0100AB1200010000", "0100AB1200010000", "base", 0, "1.0.0", "nsp", 5000],
    ["Lumen Drift", "0100AB1200010000", "0100AB1200010800", "update", 65536, "1.1.0", "nsz", 1200],
    ["Lumen Drift", "0100AB1200010000", "0100AB1200010800", "update", 131072, "1.2.0", "nsz", 1500],
    ["Lumen Drift: Comet Pack", "0100AB1200010000", "0100AB1200011001", "dlc", 0, undefined, "nsp", 600],
    ["Copper Moth", "0100CD3400020000", "0100CD3400020000", "base", 0, "1.0.0", "xci", 4000],
    ["Copper Moth", "0100CD3400020000", "0100CD3400020800", "update", 196608, "1.3.0", "nsp", 900],
    ["Quiet Tide", "0100EF5600030000", "0100EF5600030000", "base", 0, "1.0.0", "nsp", 0],
  ];
  games.forEach(([name, titleId, appId, type, version, versionName, format, size], i) => {
    lib.addAppFile({
      data: blob(`${appId}v${version}`, size),
      platform: "switch",
      title_id: titleId,
      app_id: appId,
      type,
      version_code: version,
      ...(versionName !== undefined ? { version_name: versionName } : {}),
      name,
      format,
      added: `2026-10-${String(10 + i).padStart(2, "0")}T12:00:00Z`,
    });
  });
  lib.addAppFile({
    data: blob("lumen-android", 2048),
    platform: "android",
    title_id: "org.example.lumendrift",
    app_id: "org.example.lumendrift",
    type: "base",
    version_code: 12,
    version_name: "1.2.0",
    name: "Lumen Drift",
    format: "apk",
    added: "2026-10-20T12:00:00Z",
  });
  const titles: Title[] = [
    {
      platform: "switch",
      title_id: "0100AB1200010000",
      name: "Lumen Drift",
      language: "en",
      publisher: "Northwind Toys",
      developer: "Northwind Toys",
      release: "2025-11-02",
      genres: ["adventure", "puzzle"],
      tags: ["co-op", "space"],
      players: { min: 1, max: 2, online: false },
      ratings: [{ system: "PEGI", rating: "7" }],
      languages: ["en", "fr"],
      summary: "Guide a drifting lantern between quiet planets.",
    },
    {
      platform: "switch",
      title_id: "0100CD3400020000",
      name: "Copper Moth",
      release: "2026-02-14",
      genres: ["platformer"],
      summary: "A moth of copper looks for the moon.",
    },
    {
      platform: "switch",
      title_id: "0100EF5600030000",
      name: "Quiet Tide",
      release: "2024-06-30",
      genres: ["simulation"],
    },
    {
      platform: "android",
      title_id: "org.example.lumendrift",
      name: "Lumen Drift",
      release: "2026-03-01",
      genres: ["adventure"],
    },
  ];
  for (const t of titles) lib.addTitle(t);
  await addHomebrew(lib);
  lib.addCheat({
    platform: "switch",
    title_id: "0100AB1200010000",
    build_id: "AB12CD34EF560789",
    source: "Community list",
    note: "Endless lamp oil",
    text: "[Endless lamp oil]\n04000000 0011A0B0 00000063\n",
  });
  lib.addCheat({
    platform: "switch",
    title_id: "0100AB1200010000",
    build_id: "AB12CD34EF560789",
    source: "Mira",
    text: "[Slow comets]\n04000000 0011A0C8 00000001\n",
  });
  lib.addCheat({
    platform: "switch",
    title_id: "0100CD3400020000",
    build_id: "0123456789ABCDEF",
    source: "Community list",
    text: "[Moon jump]\n04000000 00ABC010 0000FFFF\n",
  });
  return lib;
}

async function add(lib: MemoryLibrary, entry: Homebrew, files: [Package, FileRef][]): Promise<void> {
  await lib.addHomebrew(entry, new Map(files.map(([p, f]) => [p.file, f])));
}

async function addHomebrew(lib: MemoryLibrary): Promise<void> {
  // A signed archive, with a manifest under the Switch's free roots.
  const star = "org.example.starjar";
  let [pkg, file] = makePackage(
    writeZip([
      { name: `switch/${star}/starjar.nro`, data: blob("starjar.nro", 700) },
      { name: `config/${star}/settings.ini`, data: text("[jar]\nstars=12\n") },
    ]),
    "zip",
    { platform: "switch", homebrewId: star },
  );
  const starJar: Homebrew = {
    id: star,
    platform: "switch",
    kind: "tool",
    name: "Star Jar",
    author: "Mira",
    version: "1.2.0",
    build: 10200,
    license: "MIT",
    summary: "Keep the stars you saw tonight.",
    genres: ["education"],
    tags: ["notes"],
    requires: { text: "Atmosphère 1.7 or later", min: { atmosphere: "1.7.0" } },
    updated: "2026-10-29T08:00:00Z",
    package: pkg,
  };
  await sign(starJar);
  await add(lib, starJar, [[pkg, file]]);
  // The same id built for the 3DS: a single .3dsx.
  [pkg, file] = makePackage(blob("starjar.3dsx", 300), "3dsx", { platform: "3ds", homebrewId: star });
  await add(
    lib,
    {
      id: star,
      platform: "3ds",
      kind: "tool",
      name: "Star Jar",
      author: "Mira",
      version: "1.1.0",
      build: 10100,
      package: pkg,
    },
    [[pkg, file]],
  );
  // A single .nro, a game.
  const clock = "org.example.mothclock";
  [pkg, file] = makePackage(blob("mothclock.nro", 400), "nro", { platform: "switch", homebrewId: clock });
  await add(
    lib,
    {
      id: clock,
      platform: "switch",
      kind: "game",
      name: "Moth Clock",
      author: "Oren",
      version: "0.4.0",
      build: 400,
      genres: ["puzzle"],
      package: pkg,
    },
    [[pkg, file]],
  );
  // An overlay: a root that needs consent, and a loader it needs.
  const glow = "org.example.glowmeter";
  [pkg, file] = makePackage(blob("glow.ovl", 256), "ovl", {
    platform: "switch",
    homebrewId: glow,
    fileName: "glowmeter.ovl",
  });
  await add(
    lib,
    {
      id: glow,
      platform: "switch",
      kind: "overlay",
      name: "Glow Meter",
      author: "Oren",
      version: "1.0.0",
      build: 100,
      requires: { text: "An overlay loader", homebrew: [{ id: "org.example.overlay-loader", min_build: 1 }] },
      package: pkg,
    },
    [[pkg, file]],
  );
  // A port: the user brings the original game's data.
  const portId = "org.example.tidewalk-port";
  [pkg, file] = makePackage(
    writeZip([
      { name: `switch/${portId}/tidewalk.nro`, data: blob("tidewalk.nro", 500) },
      { name: `switch/${portId}/readme.txt`, data: text("Bring tide.pak from your own copy.\n") },
    ]),
    "zip",
    { platform: "switch", homebrewId: portId },
  );
  const pak = blob("tide.pak 1.0", 512);
  await add(
    lib,
    {
      id: portId,
      platform: "switch",
      kind: "port",
      name: "Tidewalk Port",
      author: "Oren",
      version: "0.3.0",
      build: 300,
      genres: ["adventure"],
      license: "GPL-2.0-or-later",
      package: pkg,
      port: {
        original: { name: "Tidewalk", year: 1999, developer: "Northwind Toys" },
        engine: { name: "Shoreline", version: "0.3.0" },
        data_root: "/switch/tidewalk/",
        assets: "user_owned",
        requires_data: [
          {
            path: "data/tide.pak",
            size: pak.length,
            accept: [{ label: "1.0", sha256: createHash("sha256").update(pak).digest("hex") }],
            hint: "tide.pak, in the folder where Tidewalk is installed.",
          },
          {
            one_of: [
              [{ path: "music/full.pak", hint: "From the soundtrack." }],
              [{ path: "music/demo.pak", hint: "From the free demo." }],
            ],
            optional: true,
          },
        ],
      },
    },
    [[pkg, file]],
  );
  // A Linux port, a package per architecture, signed.
  const harbor = "org.example.harborglow";
  const packages: [Package, FileRef][] = [["aarch64", "armhf"], ["x86_64"]].map((arch) =>
    makePackage(
      writeZip([
        { name: "Harbor Glow.sh", data: text("#!/bin/sh\nexec ./org.example.harborglow/harbor\n") },
        { name: `${harbor}/harbor.${arch[0]}`, data: blob(`harbor.${arch[0]}`, 300) },
      ]),
      "zip",
      { platform: "linux", homebrewId: harbor, arch },
    ),
  );
  const [first, ...others] = packages;
  if (first === undefined) throw new Error("no package");
  const harborGlow: Homebrew = {
    id: harbor,
    platform: "linux",
    kind: "port",
    name: "Harbor Glow",
    author: "Mira",
    version: "2.0.0",
    build: 20000,
    genres: ["simulation"],
    requires: { text: "glibc 2.30, OpenGL ES 2, 512 MiB", min: { glibc: "2.30", ram_mb: 512 }, gpu: ["gles2"] },
    package: first[0],
    packages: others.map(([p]) => p),
    port: {
      original: { name: "Harbor Glow" },
      engine: { name: "Beacon" },
      data_root: `/${harbor}/data/`,
      assets: "user_owned",
      requires_data: [{ path: "HARBOR.PAK", hint: "From your own copy." }],
    },
  };
  await sign(harborGlow);
  await add(lib, harborGlow, packages);
  // An Android app, installed by the system.
  const remote = "org.example.mothremote";
  [pkg, file] = makePackage(blob("remote.apk", 300), "apk", {
    platform: "android",
    homebrewId: remote,
    arch: ["aarch64", "armhf"],
  });
  await add(
    lib,
    {
      id: remote,
      platform: "android",
      kind: "tool",
      name: "Moth Remote",
      author: "Oren",
      version: "3.0",
      build: 30,
      system_id: remote,
      package: pkg,
    },
    [[pkg, file]],
  );
}

/** The demo's accounts: mira, who holds every scope, and DEMO_TOKEN, her console's, bound to DEMO_KEY. */
export async function demoAccounts(): Promise<MemoryAccounts> {
  const accounts = new MemoryAccounts([
    { name: "mira", scopes: EVERY_SCOPE },
    { name: "noor", scopes: ["library"] },
  ]);
  const key = await DeviceKey.fromSeed(DEMO_SEED);
  accounts.addToken(DEMO_TOKEN, "mira", "Mira's console", EVERY_SCOPE, { key: key.publicKey });
  return accounts;
}

export async function makeLantern(options: Partial<LanternAppOptions> = {}): Promise<LanternApp> {
  return new LanternApp(await buildLibrary(), {
    uid: UID,
    name: "Demo shelf",
    base: BASE,
    software: ["lantern-protocol demo (TypeScript)", "0.1"],
    accounts: await demoAccounts(),
    // Events with the shortest heartbeat (the suite waits for one), grants, and sync in memory.
    events: { heartbeat: 5 },
    peers: { seed: GRANT_SEED },
    sync: true,
    ...options,
  });
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: { port: { type: "string", default: "8080" }, "key-file": { type: "string" } },
  });
  if (values["key-file"] !== undefined) writeFileSync(values["key-file"], `${bytes.toBase64(DEMO_SEED)}\n`);
  const app = await makeLantern();
  const served = await listen(app, { port: Number(values.port) });
  console.warn(`demo: ${served.url}; token ${DEMO_TOKEN}, bound to its key`);
  process.stdout.write(`${JSON.stringify({ url: served.url, token: DEMO_TOKEN })}\n`);
  const stop = (): void => {
    app.shutdown(1);
    void served.close().then(() => process.exit(0));
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) await main();
