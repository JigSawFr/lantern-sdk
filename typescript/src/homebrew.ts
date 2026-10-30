/**
 * What a client checks of a homebrew before it installs or starts it (SPEC.md
 * § 8), and what a server checks before it serves one:
 *
 * - pathProblem() and manifestProblems(): the paths of § 8.2;
 * - manifestOf(), manifestSha256() and signedMessage(): a package's manifest,
 *   and the canonical bytes of § 8.2 and § 8.4;
 * - verifySignature() and keyFingerprint(): § 8.4's signature;
 * - installPlan(): where a manifest writes, by the profile's roots (Annex A);
 * - archOk() and pickPackage(): the package of the device's architecture;
 * - portProblems() and launchCheck(): a port's data (§ 8.6);
 * - requiresProblems() and offer(): the requirements of § 8.7.
 *
 * The same rules as python/src/lantern/homebrew.py.
 */

import { fromBase64, toHex, utf8, utf8Length } from "./bytes.ts";
import * as ed25519 from "./ed25519.ts";
import {
  GENRES,
  GPU_NAMES,
  type Homebrew,
  type ManifestEntry,
  type Package,
  type RequiredData,
  type RequiredDataGroup,
  type RequiredFile,
} from "./generated/models.ts";
import * as limits from "./limits.ts";
import { ARCHIVE, profile, roots, SYSTEM } from "./profiles.ts";
import { sha256, sha256Hex } from "./sha256.ts";
import { ARCH, ARCH_NAMES, ASSETS, KINDS, SHA256_HEX } from "./vocabulary.ts";

export const PURPOSE = "lantern-homebrew-1";
/** requires.min's keys that are dotted versions (SPEC.md § 8.7, Annex A). */
export const DOTTED_KEYS = ["glibc", "firmware", "atmosphere", "luma", "goldhen", "sdk"] as const;
/** The hashes a port's accepted version may give, and their length in hex. */
export const HASH_FORMS = { sha256: 64, sha1: 40, md5: 32 } as const;
const DOTTED = /^[0-9]+(\.[0-9]+){0,3}$/;
const SCREEN = /^([1-9][0-9]{0,5})x([1-9][0-9]{0,5})$/;

/** A homebrew a client must not install; the message says why. */
export class Refused extends Error {
  override name = "Refused";
}

/** `kind` as a reader reads it (SPEC.md § 8.1): a kind it does not know, or none, is an app. */
export function effectiveKind(entry: Homebrew): string {
  return entry.kind !== undefined && (KINDS as readonly string[]).includes(entry.kind) ? entry.kind : "app";
}

/** A port's `assets` as a reader reads it (SPEC.md § 8.6): a value it does not know is user_owned. */
export function effectiveAssets(assets: string | undefined): string {
  return assets !== undefined && (ASSETS as readonly string[]).includes(assets) ? assets : "user_owned";
}

/** Genres as a reader reads them (SPEC.md § 7.1): one it does not know is other. */
export function effectiveGenres(genres: readonly string[] | undefined): string[] {
  const known: readonly string[] = GENRES;
  return [...new Set((genres ?? []).map((g) => (known.includes(g) ? g : "other")))];
}

// Paths and manifests (SPEC.md § 8.2).

/** Why `path` breaks SPEC.md § 8.2, or undefined. */
export function pathProblem(path: string): string | undefined {
  const shown = JSON.stringify(path.slice(0, 80));
  if (!path.startsWith("/")) return `${shown} is not absolute`;
  if (utf8Length(path) > limits.PATH) return `${shown}…: above ${limits.PATH} bytes`;
  for (const part of path.slice(1).split("/")) {
    if (part === "" || part === "." || part === "..") return `${shown} has an empty, . or .. part`;
    if (utf8Length(part) > limits.PATH_PART) return `${shown} has a part above ${limits.PATH_PART} bytes`;
    for (const c of part) {
      const code = c.codePointAt(0) ?? 0;
      if (c === "\\" || c === ":" || c === '"' || code < 32 || code === 127) {
        return `${shown} has a \\, :, " or control character`;
      }
    }
  }
  return undefined;
}

/** Every way a manifest breaks SPEC.md § 8.2 ([] when it does not). */
export function manifestProblems(manifest: readonly ManifestEntry[]): string[] {
  const out: string[] = [];
  if (manifest.length > limits.MANIFEST_FILES) out.push(`${manifest.length} files, above ${limits.MANIFEST_FILES}`);
  const seen = new Set<string>();
  for (const entry of manifest) {
    const problem = pathProblem(entry.path);
    if (problem !== undefined) {
      out.push(problem);
      continue;
    }
    const folded = entry.path.toLowerCase();
    if (seen.has(folded)) out.push(`${JSON.stringify(entry.path)} twice, when case is ignored`);
    seen.add(folded);
    if (entry.size < 0 || !SHA256_HEX.test(entry.sha256)) {
      out.push(`${JSON.stringify(entry.path)}: its size or sha256 is not of its form`);
    }
  }
  return out;
}

/** A package's manifest: its own, a single file's (its `path`), or none (the platform's installer installs it). */
export function manifestOf(p: Package): ManifestEntry[] {
  if (p.manifest !== undefined) return [...p.manifest];
  if (p.path !== undefined) return [{ path: p.path, size: p.size, sha256: p.sha256 }];
  return [];
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * The SHA-256 of a manifest's canonical form (SPEC.md § 8.2): its entries sorted
 * by path as UTF-8 bytes, each {"path","sha256","size"}, no space, characters
 * other than ASCII as they are.
 */
export function manifestSha256(manifest: readonly ManifestEntry[]): string {
  const entries = manifest
    .map((e) => ({ e, key: utf8(e.path) }))
    .sort((a, b) => compareBytes(a.key, b.key))
    .map(({ e }) => `{"path":${JSON.stringify(e.path)},"sha256":"${e.sha256}","size":${e.size}}`);
  return sha256Hex(utf8(`[${entries.join(",")}]`));
}

// Signatures (SPEC.md § 8.4).

/** The bytes an author signs for `p` (the entry's own package by default). */
export function signedMessage(entry: Homebrew, p: Package = entry.package): Uint8Array {
  return utf8(
    `{"build":${entry.build},"id":"${entry.id}","manifest_sha256":"${p.manifest_sha256}",` +
      `"platform":"${entry.platform}","purpose":"${PURPOSE}","sha256":"${p.sha256}"}`,
  );
}

/**
 * Whether a package's signature (the entry's, for its own package; the
 * package's, for one of `packages`) verifies; undefined when it is unsigned.
 * A package of `packages` must be signed by the entry's key.
 */
export async function verifySignature(entry: Homebrew, p: Package = entry.package): Promise<boolean | undefined> {
  const sig = p === entry.package ? entry.signature : p.signature;
  if (sig === undefined) return entry.signature === undefined ? undefined : false;
  if (entry.signature !== undefined && sig.public_key !== entry.signature.public_key) return false;
  const publicKey = fromBase64(sig.public_key);
  const value = fromBase64(sig.value);
  if (sig.alg !== "ed25519" || publicKey === undefined || value === undefined) return false;
  return ed25519.verify(publicKey, signedMessage(entry, p), value);
}

/** A key's short fingerprint, for people (SPEC.md § 8.4, in the form of § 5.3). */
export function keyFingerprint(publicKey: string): string {
  const raw = fromBase64(publicKey);
  if (raw === undefined) throw new RangeError("not a base64 key");
  const head = toHex(sha256(raw)).slice(0, 16).toUpperCase();
  return [0, 4, 8, 12].map((i) => head.slice(i, i + 4)).join(" ");
}

/**
 * SPEC.md § 8.4: "pin" on a first install (`pinned` undefined), "same", or
 * "changed": another key, or none after one, or one after none; installed only
 * when the user explicitly accepts it. `pinned` is "" for an id first installed unsigned.
 */
export function keyChange(pinned: string | undefined, entry: Homebrew): "pin" | "same" | "changed" {
  const offered = entry.signature?.public_key ?? "";
  if (pinned === undefined) return "pin";
  return offered === pinned ? "same" : "changed";
}

// Installing (SPEC.md § 8.3, Annex A).

/** The paths a client writes without asking, and those it shows the user and writes only once they agree. */
export interface InstallPlan {
  free: string[];
  consent: string[];
}

function under(path: string, root: string): boolean {
  return root.endsWith("/") ? path.startsWith(root) : path === root;
}

/**
 * Where `p` (the entry's own package by default) writes, by the profile's
 * roots. Refused when the platform has no profile (or none for homebrew), when
 * a path breaks § 8.2, or when one lies outside every root.
 */
export function installPlan(entry: Homebrew, p: Package = entry.package): InstallPlan {
  const prof = profile(entry.platform);
  if (prof === undefined || Object.keys(prof.homebrewFormats).length === 0) {
    throw new Refused(`no profile for ${entry.platform} homebrew: nothing of it is installed`);
  }
  const place = Object.hasOwn(prof.homebrewFormats, p.format) ? prof.homebrewFormats[p.format] : undefined;
  if (place === undefined) throw new Refused(`${p.format} is not a homebrew format of ${entry.platform}`);
  if (place === ARCHIVE && p.manifest === undefined) throw new Refused("an archive without its manifest");
  if (place === SYSTEM && (p.path !== undefined || (p.manifest !== undefined && p.manifest.length > 0))) {
    throw new Refused(`${p.format} is installed by the platform's installer: no path, an empty manifest`);
  }
  if (place !== ARCHIVE && place !== SYSTEM && p.path === undefined) {
    throw new Refused(`a single ${p.format} file without its path`);
  }
  if (p.path !== undefined && p.manifest !== undefined) {
    const one = p.manifest[0];
    if (p.manifest.length !== 1 || one?.path !== p.path || one.size !== p.size || one.sha256 !== p.sha256) {
      throw new Refused("a path, and a manifest that is not that one file");
    }
  }
  const manifest = manifestOf(p);
  const problems = manifestProblems(manifest);
  if (problems.length > 0) throw new Refused(problems.slice(0, 3).join("; "));
  if (manifestSha256(manifest) !== p.manifest_sha256) {
    throw new Refused("manifest_sha256 is not the digest of the manifest");
  }
  const [free, consent] = roots(prof, entry.id);
  const plan: InstallPlan = { free: [], consent: [] };
  for (const e of manifest) {
    if (free.some((r) => under(e.path, r))) plan.free.push(e.path);
    else if (consent.some((r) => under(e.path, r))) plan.consent.push(e.path);
    else throw new Refused(`${JSON.stringify(e.path)} is outside ${entry.platform}'s roots`);
  }
  return plan;
}

/**
 * Without `mine`, whether a package's arch is well formed for its platform
 * (none on a platform of one architecture, a list otherwise); with `mine`
 * (the device's), whether it may run there. A name a reader does not know is
 * never its own (SPEC.md § 8.2).
 */
export function archOk(p: Package, platform: string, mine?: string): boolean {
  const arch = p.arch;
  if (arch === undefined) return true;
  const prof = profile(platform);
  if ((prof !== undefined && prof.arches === undefined) || arch.length === 0 || !arch.every((a) => ARCH.test(a))) {
    return false;
  }
  return mine === undefined || ((ARCH_NAMES as readonly string[]).includes(mine) && arch.includes(mine));
}

/** The package a device of architecture `mine` installs (SPEC.md § 8.2): one whose arch lists it, else one without arch. */
export function pickPackage(entry: Homebrew, mine: string | undefined): Package | undefined {
  const packages = [entry.package, ...(entry.packages ?? [])];
  if (mine !== undefined) {
    const own = packages.find((p) => p.arch !== undefined && archOk(p, entry.platform, mine));
    if (own !== undefined) return own;
  }
  return packages.find((p) => p.arch === undefined);
}

// Ports (SPEC.md § 8.6).

function isGroup(d: RequiredData): d is RequiredDataGroup {
  return "one_of" in d;
}

/** Every file a requires_data names, those of each alternative included. */
export function dataFiles(items: readonly RequiredData[]): RequiredFile[] {
  const out: RequiredFile[] = [];
  for (const d of items) {
    if (isGroup(d)) for (const option of d.one_of) out.push(...option);
    else out.push(d);
  }
  return out;
}

/** Every way a port's `port` object breaks SPEC.md § 8.6. */
export function portProblems(entry: Homebrew): string[] {
  const port = entry.port;
  if (port === undefined) return entry.kind === "port" ? ["no port object"] : [];
  const out: string[] = [];
  if (!port.original.name) out.push("original has no name");
  if (!port.engine.name) out.push("engine has no name");
  const root = port.data_root;
  if (!(root.endsWith("/") && root.length > 1 && pathProblem(root.slice(0, -1)) === undefined)) {
    return [...out, `data_root ${JSON.stringify(root.slice(0, 80))} is not a folder's path`];
  }
  const prof = profile(entry.platform);
  const areas = prof !== undefined ? prof.dataAreas : undefined;
  if (areas !== undefined && !areas.some((a) => root.startsWith(a) && root !== a)) {
    out.push(`data_root ${JSON.stringify(root)} is not under ${areas.join(", ") || "any area of the profile"}`);
  }
  for (const d of port.requires_data) {
    if (isGroup(d) && (d.one_of.length < 2 || !d.one_of.every((o) => o.length > 0))) {
      out.push("one_of has fewer than two alternatives, or an empty one");
    }
  }
  const files = dataFiles(port.requires_data);
  if (files.length > limits.REQUIRED_DATA) out.push(`more than ${limits.REQUIRED_DATA} data files`);
  const single = port.requires_data.filter((d): d is RequiredFile => !isGroup(d)).map((d) => d.path);
  const groups = port.requires_data
    .filter(isGroup)
    .flatMap((d) => d.one_of.map((option) => [...single, ...option.map((f) => f.path)]));
  if ([single, ...groups].some((g) => new Set(g).size !== g.length)) out.push("a data path twice");
  const served = [entry.package, ...(entry.packages ?? [])];
  const shipped = new Set(served.flatMap((p) => manifestOf(p).map((m) => m.path)));
  const hashes = new Set([
    ...served.map((p) => p.sha256),
    ...served.flatMap((p) => manifestOf(p).map((m) => m.sha256)),
  ]);
  for (const f of files) {
    if (f.path.startsWith("/")) {
      out.push(`data path ${JSON.stringify(f.path.slice(0, 80))} is not relative to data_root`);
      continue;
    }
    const problem = pathProblem(root + f.path);
    if (problem !== undefined) {
      out.push(`data path ${JSON.stringify(f.path.slice(0, 80))}: ${problem}`);
      continue;
    }
    if (shipped.has(root + f.path)) {
      out.push(`data ${JSON.stringify(root + f.path)} is in the package: Lantern never serves a port's data`);
    }
    if (!f.hint) out.push(`data ${JSON.stringify(f.path)}: no hint saying where the user finds it`);
    if (f.accept !== undefined && f.accept.length > limits.ACCEPT) {
      out.push(`data ${JSON.stringify(f.path)}: more than ${limits.ACCEPT} accepted versions`);
    }
    for (const a of f.accept ?? []) {
      const given = (["sha256", "sha1", "md5"] as const).filter((k) => a[k] !== undefined);
      const wellFormed = given.every((k) => new RegExp(`^[0-9a-f]{${HASH_FORMS[k]}}$`).test(a[k] ?? ""));
      if (given.length === 0 || !wellFormed) {
        out.push(`data ${JSON.stringify(f.path)}: an accepted version without a hash of a known form`);
      } else if (a.sha256 !== undefined && hashes.has(a.sha256)) {
        out.push(`data ${JSON.stringify(f.path)}: the package serves a file of an accepted hash`);
      }
    }
  }
  return out;
}

/** The hashes of a data file a client has, by algorithm (`sha256`, and `sha1` or `md5` where it can compute them). */
export type FileHashes = Readonly<Partial<Record<keyof typeof HASH_FORMS, string>>>;

function accepted(f: RequiredFile, hashes: FileHashes): boolean {
  if (f.accept === undefined || f.accept.length === 0) return true;
  return f.accept.some((a) => {
    const given = (["sha256", "sha1", "md5"] as const).filter((k) => a[k] !== undefined);
    return given.length > 0 && given.every((k) => hashes[k] === a[k]);
  });
}

/** What launchCheck() found: the port starts only when `ok`. */
export interface LaunchCheck {
  missing: string[];
  wrong: string[];
  absentOptional: string[];
  /** For each group none of whose alternatives is complete: every alternative's paths. */
  choices: string[][][];
  ok: boolean;
}

/**
 * What a client checks before it starts a port (SPEC.md § 8.6). `present` maps
 * a path relative to data_root (exact, case included) to the hashes of the file there.
 */
export function launchCheck(entry: Homebrew, present: ReadonlyMap<string, FileHashes>): LaunchCheck {
  const out = {
    missing: [] as string[],
    wrong: [] as string[],
    absentOptional: [] as string[],
    choices: [] as string[][][],
  };
  const check = (files: readonly RequiredFile[], into: typeof out): void => {
    for (const f of files) {
      const hashes = present.get(f.path);
      if (hashes === undefined) (f.optional ? into.absentOptional : into.missing).push(f.path);
      else if (!accepted(f, hashes)) into.wrong.push(f.path);
    }
  };
  for (const d of entry.port?.requires_data ?? []) {
    if (!isGroup(d)) {
      check([d], out);
      continue;
    }
    const tries = d.one_of.map((option) => {
      const result = { missing: [] as string[], wrong: [] as string[], absentOptional: [] as string[], choices: [] };
      check(option, result);
      return result;
    });
    if (tries.some((t) => t.missing.length === 0 && t.wrong.length === 0)) continue;
    const first = (d.one_of[0] ?? []).map((f) => f.path);
    if (d.optional && !tries.some((t) => t.wrong.length > 0)) {
      out.absentOptional.push(...first);
      continue;
    }
    const firstMissing = tries[0]?.missing ?? [];
    out.missing.push(...(firstMissing.length > 0 ? firstMissing : first));
    out.wrong.push(...tries.flatMap((t) => t.wrong));
    out.choices.push(d.one_of.map((option) => option.map((f) => f.path)));
  }
  return { ...out, ok: out.missing.length === 0 && out.wrong.length === 0 };
}

// Requirements (SPEC.md § 8.7).

const KNOWN_REQUIRES = new Set(["text", "min", "gpu", "homebrew"]);

/** Every way an entry's `requires` breaks SPEC.md § 8.7's shapes, for the keys this library knows. */
export function requiresProblems(entry: Homebrew): string[] {
  const requires = entry.requires;
  if (requires === undefined) return [];
  const out: string[] = [];
  if (!requires.text) out.push("requires has no text");
  for (const [k, v] of Object.entries(requires.min ?? {})) {
    if (k === "ram_mb" && !(typeof v === "number" && Number.isInteger(v) && v >= 1)) {
      out.push(`requires.min.ram_mb ${JSON.stringify(v)} is not a positive integer`);
    } else if (k === "screen" && !(typeof v === "string" && SCREEN.test(v))) {
      out.push(`requires.min.screen ${JSON.stringify(v)} is not <width>x<height>`);
    } else if ((DOTTED_KEYS as readonly string[]).includes(k) && !(typeof v === "string" && DOTTED.test(v))) {
      out.push(`requires.min.${k} ${JSON.stringify(v)} is not a dotted version`);
    }
  }
  if (requires.gpu !== undefined && requires.gpu.length === 0) out.push("requires.gpu is empty");
  return out;
}

/** -1, 0 or 1: two dotted versions compared part by part, as numbers, a missing part being 0. */
export function compareDotted(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d > 0 ? 1 : -1;
  }
  return 0;
}

/**
 * Whether a client offers a package (SPEC.md § 8.7): "offer", "warn" (with the
 * conditions it cannot read, and `text` shown) or "refuse" (with the conditions
 * that fail, and why).
 */
export interface Offer {
  decision: "offer" | "warn" | "refuse";
  reasons: string[];
}

/** What a device knows of itself, each key absent when it does not know it. */
export type DeviceFacts = Readonly<Record<string, unknown>>;

/**
 * Whether a client offers `entry`'s package on `device`: {"glibc": "2.31",
 * "ram_mb": 1024, "screen": "1280x720", "gpu": ["gles2", "gles3"]}, and the
 * profile's keys ("firmware": "18.0.0"). A refusal wins over a warning.
 */
export function offer(entry: Homebrew, device: DeviceFacts): Offer {
  const requires = entry.requires;
  if (requires === undefined) return { decision: "offer", reasons: [] };
  const fails: string[] = [];
  const unknown: string[] = [];
  for (const [k, v] of Object.entries(requires.min ?? {})) {
    const mine = device[k];
    const want = typeof v === "string" ? SCREEN.exec(v) : null;
    if (k === "ram_mb" && typeof v === "number" && Number.isInteger(v)) {
      if (typeof mine !== "number" || !Number.isInteger(mine))
        unknown.push(`ram_mb ${v} (this device's memory is unknown)`);
      else if (mine < v) fails.push(`ram_mb: ${v} MiB or more; this device has ${mine}`);
    } else if (k === "screen" && typeof v === "string" && want !== null) {
      const have = typeof mine === "string" ? SCREEN.exec(mine) : null;
      if (have === null) unknown.push(`screen ${v} (this device's screen is unknown)`);
      else if (Number(have[1]) < Number(want[1]) || Number(have[2]) < Number(want[2])) {
        fails.push(`screen: ${v} or larger; this device's is ${mine as string}`);
      }
    } else if ((DOTTED_KEYS as readonly string[]).includes(k) && typeof v === "string" && DOTTED.test(v)) {
      if (!(typeof mine === "string" && DOTTED.test(mine))) unknown.push(`${k} ${v} (this device's is unknown)`);
      else if (compareDotted(mine, v) < 0) fails.push(`${k}: ${v} or later; this device has ${mine}`);
    } else {
      unknown.push(`min.${k} ${JSON.stringify(v)}`);
    }
  }
  if (requires.gpu !== undefined) {
    const names: readonly string[] = GPU_NAMES;
    const known = requires.gpu.filter((g) => names.includes(g));
    const mine = device["gpu"];
    if (!Array.isArray(mine)) {
      unknown.push(`gpu ${requires.gpu.join(", ")} (this device's graphics are unknown)`);
    } else if (!known.some((g) => mine.includes(g))) {
      if (known.length > 0 && known.length === requires.gpu.length) {
        fails.push(`gpu: one of ${requires.gpu.join(", ")}; this device has ${mine.map(String).join(", ") || "none"}`);
      } else {
        unknown.push(`gpu ${requires.gpu.filter((g) => !names.includes(g)).join(", ")}`);
      }
    }
  }
  for (const k of Object.keys(requires)) {
    if (!KNOWN_REQUIRES.has(k) && !k.startsWith("x-")) unknown.push(k);
  }
  if (fails.length > 0) return { decision: "refuse", reasons: fails };
  return unknown.length > 0 ? { decision: "warn", reasons: unknown } : { decision: "offer", reasons: [] };
}
