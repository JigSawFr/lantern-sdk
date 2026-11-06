/**
 * Packages a device cannot use, and variants of one game (SPEC.md § 6.1,
 * Annex A.1 and B.15): whether a client installs an app, the update an
 * installed app already includes, which variant it prefers by default, and
 * the `requires` of a Switch `.nsp` stored with the firmware's compression layer.
 */

import type { App } from "./generated/models.ts";

/** A package format (SPEC.md § 6.1): the words of `formats`, and of the listing's `format` filter. */
export const FORMAT_WORD = /^[a-z0-9]{1,16}$/;
/** A token of an app's `requires` (SPEC.md § 6.1), and of a request's `satisfies`. */
export const REQUIRES_TOKEN = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** At most this many tokens in an app's `requires` (§ 6.1). */
export const REQUIRES_MAX = 8;
/** At most this many entries in an app's `includes` (§ 6.1). */
export const INCLUDES_MAX = 16;
/** At most this many words in a missing request's `formats` or `satisfies` (§ 6.3). */
export const WORDS_MAX = 16;
/** What a Switch `.nsp` stored with the firmware's compression layer takes (Annex A.1). */
export const SWITCH_LZ4_REQUIRES: readonly string[] = ["fs-compression", "sigpatch"];

/** The apps' fields these helpers read: a document as listed, or less. */
export type VariantApp = Pick<App, "app_id" | "version_code" | "size" | "id"> &
  Partial<Pick<App, "type" | "format" | "requires" | "includes">>;

export interface InstallDecision {
  decision: "install" | "unavailable";
  /** Why the app is unavailable; empty when it is installed. */
  reasons: string[];
}

/**
 * Whether an update that an installed app `includes`, at its version or above, is `app` (L-6.1-5): only an app of
 * type `update` is ever one.
 */
export function included(app: VariantApp, installed: Iterable<VariantApp>): boolean {
  if (app.type !== "update") return false;
  for (const a of installed)
    for (const i of a.includes ?? [])
      if (i.app_id === app.app_id && Number.isInteger(i.version_code) && i.version_code >= app.version_code)
        return true;
  return false;
}

/**
 * Whether a client installs `app` (SPEC.md § 6.1). `formats`: the package formats the client knows; `satisfies`: the
 * `requires` tokens it knows and the device provides; `installed`: the apps the device has installed. A format or a
 * token the client does not know is refused as one it cannot satisfy (L-6.1-3, L-6.1-4), and so is an update that an
 * installed app includes (L-6.1-5). The reasons are those of the reference client.
 */
export function installDecision(
  app: VariantApp,
  formats: Iterable<string>,
  satisfies: Iterable<string>,
  installed: Iterable<VariantApp> = [],
): InstallDecision {
  const known = new Set(formats);
  const provided = new Set(satisfies);
  const reasons: string[] = [];
  if (app.format === undefined || !known.has(app.format)) reasons.push(`format ${quote(app.format)}`);
  for (const t of app.requires ?? []) if (!provided.has(t)) reasons.push(`requires ${quote(t)}`);
  if (included(app, installed)) reasons.push("already included by an installed app");
  return reasons.length > 0 ? { decision: "unavailable", reasons } : { decision: "install", reasons };
}

function quote(value: string | undefined): string {
  return value === undefined ? "None" : `'${value}'`;
}

/**
 * The variant a client installs by default among apps that share an app_id and a version_code (Annex B.15): the
 * fewest `requires`, then the smallest `size`, then the smaller `id`, so that two clients agree. A RangeError for no variant.
 */
export function preferVariant<T extends VariantApp>(variants: Iterable<T>): T {
  let best: T | undefined;
  for (const v of variants) {
    if (best === undefined) best = v;
    else {
      const a = [v.requires?.length ?? 0, v.size] as const;
      const b = [best.requires?.length ?? 0, best.size] as const;
      if (a[0] < b[0] || (a[0] === b[0] && (a[1] < b[1] || (a[1] === b[1] && v.id < best.id)))) best = v;
    }
  }
  if (best === undefined) throw new RangeError("no variant to choose from");
  return best;
}

/**
 * The `requires` of a package a toolkit finds by its file name (Annex A.1): a Switch `.nsp` whose name holds `[LZ4]`
 * (any case) is stored with the firmware's compression layer and takes fs-compression and sigpatch; undefined for any
 * other file.
 */
export function requiresOfName(platform: string, fileName: string): string[] | undefined {
  const name = fileName.slice(fileName.lastIndexOf("/") + 1);
  return platform === "switch" && /\.nsp$/i.test(name) && /\[LZ4\]/i.test(name) ? [...SWITCH_LZ4_REQUIRES] : undefined;
}

/** `requires` without duplicates, in order (§ 6.1). */
export function uniqueTokens(tokens: readonly string[]): string[] {
  return [...new Set(tokens)];
}
