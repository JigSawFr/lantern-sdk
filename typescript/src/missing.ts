/**
 * What a device is missing (SPEC.md § 6.3), by the rules a server applies and
 * a client of a static library applies itself (§ 21.3, L-21.3-2).
 */

import type { App } from "./generated/models.ts";
import { profile, switchIds } from "./profiles.ts";

/**
 * What a device of `platform` is missing (SPEC.md § 6.3), among `apps` (of that
 * platform): with `update`, each installed game's newest update above its
 * highest installed version; with `dlc`, its add-ons not installed; with
 * `base`, the games not installed.
 */
export function missing(
  apps: readonly App[],
  platform: string,
  installed: readonly [string, number][],
  want: ReadonlySet<string>,
): App[] {
  const replaces = profile(platform)?.newerBaseReplaces ?? false;
  const byApp = new Map(apps.map((a) => [a.app_id, a]));
  const have = new Map<string, number>();
  for (const [appId, version] of installed) {
    const known = byApp.get(appId);
    let title: string;
    let kind: string;
    if (known !== undefined) {
      title = known.title_id;
      kind = known.type;
    } else if (platform === "switch" && appId.length === 16) {
      try {
        [title, kind] = switchIds(appId);
      } catch {
        continue;
      }
    } else continue; // a game this server does not know
    if (kind === "base" || kind === "update") have.set(title, Math.max(have.get(title) ?? -1, version));
  }
  const ids = new Set(installed.map(([id]) => id));
  const out = new Map<string, App>();
  for (const [title, version] of have) {
    const mine = apps.filter((a) => a.title_id === title);
    const updates = replaces
      ? mine.filter((a) => a.type === "base" && ids.has(a.app_id))
      : mine.filter((a) => a.type === "update");
    const newest = updates.reduce((n, a) => Math.max(n, a.version_code), -1);
    if (want.has("update") && newest > version)
      for (const a of updates) if (a.version_code === newest) out.set(a.id, a);
    if (want.has("dlc")) for (const a of mine) if (a.type === "dlc" && !ids.has(a.app_id)) out.set(a.id, a);
  }
  if (want.has("base")) for (const a of apps) if (a.type === "base" && !have.has(a.title_id)) out.set(a.id, a);
  return [...out.values()];
}
