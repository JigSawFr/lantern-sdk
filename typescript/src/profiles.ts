/**
 * Platform profiles (SPEC.md Annex A): what the core leaves open, per
 * platform. The Switch's is complete; the 3DS's, the Vita's, the PS4's,
 * Android's and Linux's are drafts (`draft` is true), still to be reviewed by
 * someone who knows the platform. The other platforms have no profile yet:
 * `profile()` gives undefined, and a client installs nothing of them (§ 4.3).
 * The same tables as python/src/lantern/profiles.py.
 */

import { ARCH_NAMES, CORE_ID } from "./vocabulary.ts";

/** A homebrew format the platform's own installer installs: no path, an empty manifest (SPEC.md § 8.2). */
export const SYSTEM = "system";
/** A homebrew format that is an archive with a manifest (SPEC.md § 8.2). */
export const ARCHIVE = "archive";

/** Where a client writes a cheat set (Annex A): `path` with {title_id}, {build_id} and {format}. */
export interface Cheats {
  format: string;
  path: string;
  buildId: RegExp | undefined;
}

/** One platform's profile (Annex A). */
export interface Profile {
  platform: string;
  draft: boolean;
  titleId: RegExp | undefined;
  /** An app's id, by its type ("": any type). */
  appIds: Readonly<Record<string, RegExp>>;
  /** The app types and the package formats; undefined where the profile has no apps (Linux). */
  types: readonly string[] | undefined;
  formats: readonly string[] | undefined;
  /** A newer package of the same app_id replaces the base: it is the update (Android, SPEC.md § 6.3). */
  newerBaseReplaces: boolean;
  /** Each homebrew format: a single file's path ({id}, {file}), ARCHIVE or SYSTEM. */
  homebrewFormats: Readonly<Record<string, string>>;
  /** The roots a homebrew writes to without asking ({id}: its id), and those that need consent. */
  freeRoots: readonly string[];
  consentRoots: readonly string[];
  /** Where a port's data_root may lie; undefined where the user picks a folder (Android). */
  dataAreas: readonly string[] | undefined;
  /** The architectures of `arch`; undefined on a platform of one architecture, where a package has none. */
  arches: readonly string[] | undefined;
  /** The platform's own keys of requires.min (SPEC.md § 8.7). */
  requiresMin: readonly string[];
  /** The platform's own id of installed software (SPEC.md § 8.1). */
  systemId: boolean;
  /** The save kinds (SPEC.md § 9.1). */
  saveKinds: readonly string[];
  cheats: Cheats | undefined;
  /** Whether a client may install apps of it (Linux: homebrew only, Annex A.6). */
  installsApps: boolean;
}

const SWITCH_ID = /^[0-9A-F]{16}$/;
const SWITCH_TITLE = /^[0-9A-F]{12}[02468ACE]000$/;
const N3DS_TITLE = /^0004000[02][0-9A-F]{8}$/;
const VITA_TITLE = /^[A-Z0-9]{9}$/;
const VITA_CONTENT = /^[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Z0-9]{16}$/;
const PS4_TITLE = /^[A-Z]{4}[0-9]{5}$/;
const PS4_CONTENT = /^[A-Z]{2}[0-9]{4}-[A-Z]{4}[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}$/;
const ANDROID = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;
const BASE_TYPES = ["base", "update", "dlc"] as const;

function either(a: RegExp, b: RegExp): RegExp {
  return new RegExp(`${a.source}|${b.source}`);
}

const DEFAULTS = {
  newerBaseReplaces: false,
  homebrewFormats: {},
  freeRoots: [],
  consentRoots: [],
  dataAreas: [],
  arches: undefined,
  requiresMin: [],
  systemId: false,
  saveKinds: [],
  cheats: undefined,
  installsApps: true,
} satisfies Partial<Profile>;

export const SWITCH: Profile = {
  ...DEFAULTS,
  platform: "switch",
  draft: false,
  titleId: SWITCH_TITLE,
  appIds: { "": SWITCH_ID, base: SWITCH_TITLE, update: /^[0-9A-F]{12}[02468ACE]800$/ },
  types: BASE_TYPES,
  formats: ["nsp", "nsz", "xci", "xcz"],
  homebrewFormats: { nro: "/switch/{id}/{id}.nro", ovl: "/switch/.overlays/{file}", zip: ARCHIVE },
  freeRoots: ["/switch/{id}/", "/config/{id}/"],
  consentRoots: ["/atmosphere/", "/switch/.overlays/"],
  dataAreas: ["/switch/", "/config/"],
  requiresMin: ["firmware", "atmosphere"],
  saveKinds: ["account", "device", "bcat", "cache", "other"],
  cheats: {
    format: "atmosphere",
    path: "/atmosphere/contents/{title_id}/cheats/{build_id}.txt",
    buildId: /^[0-9A-F]{1,64}$/,
  },
};

export const N3DS: Profile = {
  ...DEFAULTS,
  platform: "3ds",
  draft: true,
  titleId: N3DS_TITLE,
  appIds: {
    "": /^0004(0000|0002|000E|008C)[0-9A-F]{8}$/,
    base: N3DS_TITLE,
    update: /^0004000E[0-9A-F]{8}$/,
    dlc: /^0004008C[0-9A-F]{8}$/,
  },
  types: BASE_TYPES,
  formats: ["cia"],
  homebrewFormats: { "3dsx": "/3ds/{id}/{id}.3dsx", zip: ARCHIVE, cia: SYSTEM },
  freeRoots: ["/3ds/{id}/"],
  consentRoots: ["/luma/", "/boot.firm", "/boot.3dsx", "/gm9/"],
  dataAreas: ["/3ds/"],
  requiresMin: ["firmware", "luma"],
  systemId: true,
  saveKinds: ["device", "other"],
  cheats: { format: "gateshark", path: "/cheats/{title_id}.txt", buildId: undefined },
};

export const VITA: Profile = {
  ...DEFAULTS,
  platform: "vita",
  draft: true,
  titleId: VITA_TITLE,
  appIds: { "": either(VITA_TITLE, VITA_CONTENT), base: VITA_TITLE, update: VITA_TITLE, dlc: VITA_CONTENT },
  types: BASE_TYPES,
  formats: ["vpk", "pkg"],
  homebrewFormats: { vpk: SYSTEM },
  freeRoots: ["/ux0/data/{id}/"],
  consentRoots: ["/ux0/tai/", "/ur0/tai/"],
  dataAreas: ["/ux0/data/"],
  systemId: true,
  saveKinds: ["device"],
  cheats: { format: "psv", path: "/ux0/vitacheat/db/{title_id}.psv", buildId: undefined },
};

export const PS4: Profile = {
  ...DEFAULTS,
  platform: "ps4",
  draft: true,
  titleId: PS4_TITLE,
  appIds: { "": either(PS4_TITLE, PS4_CONTENT), base: PS4_TITLE, update: PS4_TITLE, dlc: PS4_CONTENT },
  types: BASE_TYPES,
  formats: ["pkg"],
  homebrewFormats: { pkg: SYSTEM },
  freeRoots: ["/data/{id}/"],
  consentRoots: ["/data/GoldHEN/"],
  dataAreas: ["/data/"],
  requiresMin: ["firmware", "goldhen"],
  systemId: true,
  saveKinds: ["account"],
  cheats: {
    format: "json",
    path: "/data/GoldHEN/cheats/{format}/{title_id}_{build_id}.{format}",
    buildId: /^[0-9]{2}\.[0-9]{2}(_.+)?$/,
  },
};

export const ANDROID_PROFILE: Profile = {
  ...DEFAULTS,
  platform: "android",
  draft: true,
  titleId: ANDROID,
  appIds: { "": ANDROID },
  types: ["base"],
  formats: ["apk", "apks"],
  newerBaseReplaces: true,
  homebrewFormats: { apk: SYSTEM, apks: SYSTEM },
  dataAreas: undefined,
  arches: ["aarch64", "armhf", "x86", "x86_64"],
  requiresMin: ["sdk"],
  systemId: true,
};

export const LINUX: Profile = {
  ...DEFAULTS,
  platform: "linux",
  draft: true,
  titleId: undefined,
  appIds: {},
  types: undefined,
  formats: undefined,
  homebrewFormats: { zip: ARCHIVE },
  freeRoots: ["/{id}/"],
  consentRoots: ["/"],
  dataAreas: ["/"],
  arches: ARCH_NAMES,
  requiresMin: ["glibc", "ram_mb", "screen"],
  installsApps: false,
};

export const PROFILES: Readonly<Record<string, Profile>> = {
  switch: SWITCH,
  "3ds": N3DS,
  vita: VITA,
  ps4: PS4,
  android: ANDROID_PROFILE,
  linux: LINUX,
};
/** Platforms named by SPEC.md § 4.3 that have no profile yet (Annex A.7). */
export const OPEN_PLATFORMS = ["ios", "windows", "macos", "web", "steam", "gog", "xbox"] as const;

/** The platform's profile, or undefined when it has none (a client installs nothing of it). */
export function profile(platform: string): Profile | undefined {
  return Object.hasOwn(PROFILES, platform) ? PROFILES[platform] : undefined;
}

/** A title id of the core's form, and of the platform's profile when it has one. */
export function titleIdOk(platform: string, titleId: string): boolean {
  const p = profile(platform);
  return CORE_ID.test(titleId) && (p?.titleId === undefined || p.titleId.test(titleId));
}

/** An app id of the core's form, and of the platform's profile (for its type, when given). */
export function appIdOk(platform: string, appId: string, appType?: string): boolean {
  if (!CORE_ID.test(appId)) return false;
  const p = profile(platform);
  if (p === undefined) return true;
  const pattern = (appType !== undefined ? p.appIds[appType] : undefined) ?? p.appIds[""];
  return pattern === undefined || pattern.test(appId);
}

/** Where a single-file package of `format` goes (Annex A), or undefined for an archive or the system's installer. */
export function singleFilePath(p: Profile, format: string, homebrewId: string, fileName = ""): string | undefined {
  const place = Object.hasOwn(p.homebrewFormats, format) ? p.homebrewFormats[format] : undefined;
  if (place === undefined || place === SYSTEM || place === ARCHIVE) return undefined;
  return place.replaceAll("{id}", homebrewId).replaceAll("{file}", fileName);
}

/** [free, consent]: the roots of a homebrew's manifest, its id put in. */
export function roots(p: Profile, homebrewId: string): [string[], string[]] {
  return [
    p.freeRoots.map((r) => r.replaceAll("{id}", homebrewId)),
    p.consentRoots.map((r) => r.replaceAll("{id}", homebrewId)),
  ];
}

/**
 * [title_id, type] of a Switch app id (Annex A.1): the base's id ends in 000
 * (its lowest 13 bits zero), its update's in 800, an add-on's otherwise.
 */
export function switchIds(appId: string): [string, "base" | "update" | "dlc"] {
  if (!SWITCH_ID.test(appId)) throw new RangeError(`${appId} is not a Switch id`);
  const n = BigInt(`0x${appId}`);
  const low = n & 0x1fffn;
  const kind = low === 0n ? "base" : low === 0x800n ? "update" : "dlc";
  return [(n & ~0x1fffn).toString(16).toUpperCase().padStart(16, "0"), kind];
}

/** The app id of a Switch game's update: its title id plus 800 (hex). */
export function switchUpdateId(titleId: string): string {
  if (!SWITCH_TITLE.test(titleId)) throw new RangeError(`${titleId} is not a Switch game's title id`);
  return (BigInt(`0x${titleId}`) + 0x800n).toString(16).toUpperCase().padStart(16, "0");
}

/** A Switch title version as the system reads it, from `v196608` or `196608` (Annex A.1). */
export function switchVersionCode(text: string): number {
  const m = /^v?(\d{1,10})$/.exec(text.trim());
  const n = m?.[1] !== undefined ? Number(m[1]) : Number.NaN;
  if (!(n <= 0xffffffff)) throw new RangeError(`${text} is not a Switch title version`);
  return n;
}

/** `APP_VER` `XX.YY` as XX*100+YY: a Vita's or a PS4's version_code (Annex A.3, A.4). */
export function appVerCode(appVer: string): number {
  const m = /^(\d{2})\.(\d{2})$/.exec(appVer.trim());
  if (m === null) throw new RangeError(`${appVer} is not an APP_VER (XX.YY)`);
  return Number(m[1]) * 100 + Number(m[2]);
}

/** A 3DS title version's name (Annex A.2): its top 6 bits, next 6 and low 4, `2069` being `2.1.5`. */
export function n3dsVersionName(versionCode: number): string {
  if (!Number.isInteger(versionCode) || versionCode < 0 || versionCode > 0xffff) {
    throw new RangeError(`${versionCode} is not a 16-bit title version`);
  }
  return `${versionCode >> 10}.${(versionCode >> 4) & 0x3f}.${versionCode & 0xf}`;
}

/** Where a client writes a cheat set (Annex A). On a Switch, Atmosphère names the file with the first 16 digits of the build id. */
export function cheatPath(platform: string, titleId: string, buildId?: string, format?: string): string {
  const p = profile(platform);
  if (p?.cheats === undefined) throw new RangeError(`no cheats on ${platform}`);
  if (p.cheats.buildId !== undefined && (buildId === undefined || !p.cheats.buildId.test(buildId))) {
    throw new RangeError(`${buildId} is not a ${platform} build id`);
  }
  if (!titleIdOk(platform, titleId)) throw new RangeError(`${titleId} is not a ${platform} title id`);
  const build = platform === "switch" ? (buildId ?? "").slice(0, 16) : (buildId ?? "");
  return p.cheats.path
    .replaceAll("{title_id}", titleId)
    .replaceAll("{build_id}", build)
    .replaceAll("{format}", format ?? p.cheats.format);
}
