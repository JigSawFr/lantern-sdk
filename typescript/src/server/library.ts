/**
 * What a server's app implements for the toolkit's routes: a `Library` (its
 * apps, titles, homebrew, cheat sets and files), optionally a `Journal` of its
 * changes, and an `authenticate` hook. `MemoryLibrary` is a complete one, held
 * in memory: a reference to read, and the base of tests and demos.
 *
 * The toolkit checks nothing it is given is served wrong: MemoryLibrary refuses
 * an app, title, homebrew or cheat set that breaks the schemas or SPEC.md § 8
 * (paths, roots, manifests, signatures, ports, requirements).
 */

import { createHash, randomBytes } from "node:crypto";
import { toBase64Url } from "../bytes.ts";
import type {
  App,
  CheatSet,
  Homebrew,
  ManifestEntry,
  Package,
  RatingCap,
  RemovedTitle,
  Section,
  Title,
} from "../generated/models.ts";
import * as hb from "../homebrew.ts";
import { CHEAT_SET } from "../limits.ts";
import { profile, singleFilePath } from "../profiles.ts";
import { definition } from "../schema.ts";
import { utc } from "./accounts.ts";
import type { LibraryChange } from "./events.ts";
import { FileRef } from "./files.ts";
import type { ServerRequest } from "./http.ts";
import { readZip } from "./zip.ts";

/** The families a Library may offer, beyond `changes` (which needs a Journal). */
export const LIBRARY_FAMILIES = ["library", "titles", "sections", "homebrew", "cheats"] as const;

/**
 * The caller, as `authenticate` (or the server's Accounts) resolves it: its
 * state, its scopes (SPEC.md § 4.2) and the name the handshake shows; `key`,
 * the device key its token is bound to (LanternApp then checks the request's
 * signature, § 5.4); `ratingCap`, the cap its token carries (§ 5.6); `device`,
 * its device's id (§ 5.7), and `deviceName` the name it paired with (a save
 * backup's `device`, § 9.1).
 */
export interface Account {
  scopes: ReadonlySet<string>;
  state: "anonymous" | "active" | "frozen";
  name?: string;
  key?: Uint8Array;
  ratingCap?: RatingCap;
  device?: string;
  deviceName?: string;
}

/** A cheat set to write (SPEC.md § 10), as LanternApp checked it. */
export interface CheatInit {
  platform: string;
  title_id: string;
  text: string;
  source: string;
  build_id?: string;
  note?: string;
  updated?: string;
}

/** Resolves a request's credentials to an account, or undefined when they are not valid ones. */
export type Authenticate = (request: ServerRequest) => Account | undefined | Promise<Account | undefined>;

type Maybe<T> = T | Promise<T>;

/**
 * A library's change journal, for /v1/changes and /v1/titles/changes (SPEC.md
 * § 6.4, § 7.3). Positions grow with each change; `epoch` changes when the
 * journal starts over (a token of another epoch is too old).
 */
export interface Journal {
  readonly epoch: string;
  position(): Maybe<number>;
  /** The oldest position the journal still answers from. */
  oldest(): Maybe<number>;
  /** The apps added since `after` and still there, and the ids of those removed. */
  appChanges(after: number, platform: string | undefined): Maybe<[App[], string[]]>;
  titleChanges(
    after: number,
    platform: string | undefined,
    languages: readonly string[],
  ): Maybe<[Title[], RemovedTitle[]]>;
}

/** What a server serves. Every method is called per request: return what is there now (a database query…). */
export interface Library {
  /** The families offered, among library, titles, sections, homebrew and cheats. */
  readonly families: ReadonlySet<string>;
  apps(): Maybe<readonly App[]>;
  /** Every title, its texts in the best of `languages` it has. */
  titles(languages: readonly string[]): Maybe<readonly Title[]>;
  /** Every entry, with its manifests (the toolkit leaves them out of listings). */
  homebrew(languages: readonly string[]): Maybe<readonly Homebrew[]>;
  cheats(): Maybe<readonly CheatSet[]>;
  /** The shelves the server curates (SPEC.md § 6.5), with the families' `sections`; the toolkit filters their apps. */
  sections?(languages: readonly string[]): Maybe<readonly Section[]>;
  /**
   * Writes a cheat set (SPEC.md § 10, scope `cheats.write`): a new one, or the
   * set `replacing` changed in place (its id kept); the set as listed. Both
   * this and `deleteCheat` make the writes offered; without them, they answer 405.
   */
  writeCheat?(init: CheatInit, replacing?: string): Maybe<CheatSet>;
  /** Removes a cheat set; false when there is none of that id. */
  deleteCheat?(cheatId: string): Maybe<boolean>;
  /** The file of <base>/v1/files/{fileId}: an app's or a homebrew package's. */
  file(fileId: string): Maybe<FileRef | undefined>;
  /** A cheat set's text. */
  cheatFile(cheatId: string): Maybe<FileRef | undefined>;
  /** The change journal, or undefined: the family `changes` is then not offered. */
  journal(): Journal | undefined;
  /**
   * Tells `listener` what changes, as it changes (the event `library`, SPEC.md
   * § 18.2). Optional: without it, a server calls `app.libraryChanged()` itself.
   */
  subscribe?(listener: (changes: LibraryChange[]) => void): void;
}

function token(bytes: number): string {
  return toBase64Url(randomBytes(bytes));
}

/** An archive's manifest (SPEC.md § 8.2): each of its files at "/" + its name. */
export function zipManifest(data: Uint8Array): ManifestEntry[] {
  return readZip(data).map((f) => ({
    path: `/${f.name}`,
    size: f.data.length,
    sha256: createHash("sha256").update(f.data).digest("hex"),
  }));
}

/**
 * Every reason a server must not serve `entry`: its schema, its manifests
 * (paths, digest, the profile's roots), its signatures, its port's data and its
 * requirements' shapes.
 */
export async function checkHomebrew(entry: Homebrew): Promise<string[]> {
  const problems = definition("homebrew", entry).map((p) => `schema: ${p}`);
  for (const p of [entry.package, ...(entry.packages ?? [])]) {
    problems.push(...hb.manifestProblems(hb.manifestOf(p)));
    if (hb.manifestSha256(hb.manifestOf(p)) !== p.manifest_sha256)
      problems.push("manifest_sha256 is not the digest of the manifest");
    if (!hb.archOk(p, entry.platform)) problems.push(`arch ${JSON.stringify(p.arch)} on ${entry.platform}`);
    if (profile(entry.platform) !== undefined && problems.length === 0) {
      try {
        hb.installPlan(entry, p);
      } catch (e) {
        if (!(e instanceof hb.Refused)) throw e;
        problems.push(e.message);
      }
    }
    if (entry.signature !== undefined && (await hb.verifySignature(entry, p)) !== true)
      problems.push("a signature that does not verify");
  }
  problems.push(...hb.portProblems(entry), ...hb.requiresProblems(entry));
  return problems;
}

/** A journal kept in memory, of the last `keep` changes. */
export class MemoryJournal {
  readonly epoch = token(4);
  readonly keep: number;
  events: [number, string, string, string][] = []; // [position, kind, key, platform]
  seq = 0;
  floor = 0;

  constructor(keep = 10000) {
    this.keep = keep;
  }

  record(kind: string, key: string, platform: string): void {
    this.seq += 1;
    this.events.push([this.seq, kind, key, platform]);
    if (this.events.length > this.keep) {
      const dropped = this.events.splice(0, this.events.length - this.keep);
      this.floor = dropped.at(-1)?.[0] ?? this.floor;
    }
  }

  since(after: number, kinds: readonly string[], platform: string | undefined): [string, string][] {
    return this.events
      .filter(([n, kind, , p]) => n > after && kinds.includes(kind) && (platform === undefined || p === platform))
      .map(([, kind, key]) => [kind, key]);
  }
}

/**
 * A Library held in memory, with its journal. Files are served from their path,
 * or from memory when given as bytes.
 *
 *     const lib = new MemoryLibrary({ base: "/api/lantern" });
 *     lib.addAppFile({ data, platform: "switch", title_id: "0100ABCD00010000", … });
 */
export class MemoryLibrary implements Library, Journal {
  readonly base: string;
  readonly families: ReadonlySet<string>;
  readonly #apps = new Map<string, App>();
  readonly #titles = new Map<string, Title>();
  readonly #homebrew = new Map<string, Homebrew>();
  readonly #cheats = new Map<string, CheatSet>();
  readonly #files = new Map<string, FileRef>();
  readonly #cheatFiles = new Map<string, FileRef>();
  readonly #sections = new Map<string, Section>();
  readonly #journal: MemoryJournal | undefined;
  readonly #listeners: ((changes: LibraryChange[]) => void)[] = [];

  constructor(options: { base?: string; families?: Iterable<string>; journal?: boolean } = {}) {
    this.base = (options.base ?? "/api/lantern").replace(/\/+$/, "");
    this.families = new Set(options.families ?? LIBRARY_FAMILIES);
    this.#journal = options.journal === false ? undefined : new MemoryJournal();
  }

  subscribe(listener: (changes: LibraryChange[]) => void): void {
    this.#listeners.push(listener);
  }

  #changed(change: LibraryChange): void {
    for (const l of this.#listeners) l([change]);
  }

  // Adding and removing.

  fileUrl(fileId: string): string {
    return `${this.base}/v1/files/${fileId}`;
  }

  /** Serves a file under a new, unguessable id; its URL (SPEC.md § 6.6). */
  addFile(file: FileRef): string {
    const id = `f_${token(12)}`;
    this.#files.set(id, file);
    return this.fileUrl(id);
  }

  /** Serves an app (its `file` URL one of this library's when `file` is given). */
  addApp(app: App, file?: FileRef): App {
    if (file !== undefined) {
      if (file.size !== app.size || file.sha256 !== app.sha256)
        throw new RangeError(`app ${app.id}: its size and sha256 are not its file's`);
      app.file = this.addFile(file);
    }
    const problems = definition("app", app);
    if (problems.length > 0) throw new RangeError(`app ${app.id}: ${problems.slice(0, 3).join("; ")}`);
    this.#apps.set(app.id, app);
    this.#journal?.record("added", app.id, app.platform);
    this.#changed({ family: "apps", platform: app.platform, titleId: app.title_id });
    return app;
  }

  /** An app from bytes, given its identity (SPEC.md § 6.1). */
  addAppFile(init: Omit<App, "id" | "size" | "sha256" | "file" | "added"> & { data: Uint8Array; added?: string }): App {
    const { data, ...rest } = init;
    const file = FileRef.ofBytes(data);
    const app: App = {
      id: `a_${token(9)}`,
      ...rest,
      size: file.size,
      sha256: file.sha256,
      added: init.added ?? utc(),
      file: "",
    };
    return this.addApp(app, file);
  }

  removeApp(appId: string): void {
    const app = this.#apps.get(appId);
    if (app === undefined) return;
    this.#apps.delete(appId);
    this.#journal?.record("removed", appId, app.platform);
    this.#changed({ family: "apps", platform: app.platform, titleId: app.title_id });
  }

  addTitle(title: Title): Title {
    const { schema: _schema, ...rest } = title as Title & { schema?: number };
    const problems = definition("title", rest);
    if (problems.length > 0)
      throw new RangeError(`title ${title.platform}/${title.title_id}: ${problems.slice(0, 3).join("; ")}`);
    this.#titles.set(`${title.platform}/${title.title_id}`, rest as Title);
    this.#journal?.record("title", `${title.platform}/${title.title_id}`, title.platform);
    this.#changed({ family: "titles", platform: title.platform, titleId: title.title_id });
    return rest as Title;
  }

  removeTitle(platform: string, titleId: string): void {
    if (this.#titles.delete(`${platform}/${titleId}`)) {
      this.#journal?.record("title", `${platform}/${titleId}`, platform);
      this.#changed({ family: "titles", platform, titleId });
    }
  }

  /**
   * Serves a homebrew entry. `files` maps each package's `file` to the file it
   * serves, which is checked against the package and given a URL of this
   * library. A RangeError when checkHomebrew() finds a reason, or a file is not its package's.
   */
  async addHomebrew(entry: Homebrew, files: ReadonlyMap<string, FileRef> = new Map()): Promise<Homebrew> {
    for (const p of [entry.package, ...(entry.packages ?? [])]) {
      const file = files.get(p.file);
      if (file !== undefined) {
        if (file.size !== p.size || file.sha256 !== p.sha256)
          throw new RangeError(`homebrew ${entry.id}: ${p.file} is not its package's file`);
        p.file = this.addFile(file);
      }
    }
    delete (entry as { schema?: number }).schema;
    const problems = await checkHomebrew(entry);
    if (problems.length > 0)
      throw new RangeError(`homebrew ${entry.platform}/${entry.id}: ${problems.slice(0, 3).join("; ")}`);
    this.#homebrew.set(`${entry.platform}/${entry.id}`, entry);
    this.#changed({ family: "homebrew", platform: entry.platform, ratings: entry.ratings ?? [] });
    return entry;
  }

  /** A cheat set from its text (SPEC.md § 10). */
  addCheat(init: CheatInit): CheatSet {
    return this.writeCheat(init);
  }

  /** A cheat set written: a new one, or `replacing` changed in place, its id kept (SPEC.md § 10). */
  writeCheat(init: CheatInit, replacing?: string): CheatSet {
    const data = new TextEncoder().encode(init.text);
    if (data.length > CHEAT_SET) throw new RangeError(`a cheat set is ${CHEAT_SET} bytes at most`);
    if (replacing !== undefined && !this.#cheats.has(replacing)) throw new RangeError(`no cheat set ${replacing}`);
    const file = FileRef.ofBytes(data, "text/plain; charset=utf-8");
    const cheat: CheatSet = {
      id: replacing ?? `cs_${token(9)}`,
      platform: init.platform,
      title_id: init.title_id,
      source: init.source,
      updated: init.updated ?? utc(),
      size: file.size,
      sha256: file.sha256,
    };
    if (init.build_id !== undefined) cheat.build_id = init.build_id;
    if (init.note !== undefined) cheat.note = init.note;
    const problems = definition("cheat_set", cheat);
    if (problems.length > 0) throw new RangeError(`cheat set: ${problems.slice(0, 3).join("; ")}`);
    const before = replacing !== undefined ? this.#cheats.get(replacing) : undefined;
    this.#cheats.set(cheat.id, cheat);
    this.#cheatFiles.set(cheat.id, file);
    if (before !== undefined && (before.platform !== cheat.platform || before.title_id !== cheat.title_id))
      this.#changed({ family: "cheats", platform: before.platform, titleId: before.title_id });
    this.#changed({ family: "cheats", platform: cheat.platform, titleId: cheat.title_id });
    return cheat;
  }

  deleteCheat(cheatId: string): boolean {
    const cheat = this.#cheats.get(cheatId);
    if (cheat === undefined) return false;
    this.#cheats.delete(cheatId);
    this.#cheatFiles.delete(cheatId);
    this.#changed({ family: "cheats", platform: cheat.platform, titleId: cheat.title_id });
    return true;
  }

  /** A shelf the server curates (SPEC.md § 6.5): its apps by id, in order; one of the same id is replaced. */
  addSection(section: { id?: string; title: string; apps: readonly string[] }): Section {
    const out: Section = { id: section.id ?? `sec_${token(6)}`, title: section.title, apps: [...section.apps] };
    const before = this.#sections.get(out.id);
    this.#sections.set(out.id, out);
    this.#sectionChanged([...(before?.apps ?? []), ...out.apps]);
    return out;
  }

  removeSection(sectionId: string): void {
    const before = this.#sections.get(sectionId);
    if (before === undefined) return;
    this.#sections.delete(sectionId);
    this.#sectionChanged(before.apps);
  }

  /** The event `library` of a shelf changed, for the platforms of its apps. */
  #sectionChanged(appIds: readonly string[]): void {
    const platforms = new Set(appIds.map((id) => this.#apps.get(id)?.platform).filter((p) => p !== undefined));
    for (const platform of [...platforms].sort()) this.#changed({ family: "sections", platform });
  }

  // Library.

  apps(): App[] {
    return [...this.#apps.values()];
  }
  titles(): Title[] {
    return [...this.#titles.values()];
  }
  homebrew(): Homebrew[] {
    return [...this.#homebrew.values()];
  }
  cheats(): CheatSet[] {
    return [...this.#cheats.values()];
  }
  sections(): Section[] {
    return [...this.#sections.values()].map((x) => ({ ...x, apps: [...x.apps] }));
  }
  file(fileId: string): FileRef | undefined {
    return this.#files.get(fileId);
  }
  cheatFile(cheatId: string): FileRef | undefined {
    return this.#cheatFiles.get(cheatId);
  }
  journal(): Journal | undefined {
    return this.#journal !== undefined ? this : undefined;
  }

  // Journal.

  get epoch(): string {
    return this.#journal?.epoch ?? "";
  }
  position(): number {
    return this.#journal?.seq ?? 0;
  }
  oldest(): number {
    return this.#journal?.floor ?? 0;
  }

  appChanges(after: number, platform: string | undefined): [App[], string[]] {
    const events = this.#journal?.since(after, ["added", "removed"], platform) ?? [];
    const added = [...new Set(events.filter(([k, id]) => k === "added" && this.#apps.has(id)).map(([, id]) => id))];
    const removed = [
      ...new Set(events.filter(([k, id]) => k === "removed" && !this.#apps.has(id)).map(([, id]) => id)),
    ].sort();
    return [added.map((id) => this.#apps.get(id) as App), removed];
  }

  titleChanges(after: number, platform: string | undefined): [Title[], RemovedTitle[]] {
    const keys = [...new Set((this.#journal?.since(after, ["title"], platform) ?? []).map(([, k]) => k))].sort();
    const changed: Title[] = [];
    const removed: RemovedTitle[] = [];
    for (const key of keys) {
      const title = this.#titles.get(key);
      const slash = key.indexOf("/");
      if (title !== undefined) changed.push(title);
      else removed.push({ platform: key.slice(0, slash), title_id: key.slice(slash + 1) });
    }
    return [changed, removed];
  }
}

/**
 * A homebrew's package from its file's bytes, and the file to serve: an
 * archive's manifest read from it, a single file's path given by the profile
 * (Annex A), none for a format the platform's installer installs. Its `file` is
 * a placeholder that MemoryLibrary.addHomebrew() replaces: pass
 * new Map([[package.file, file]]) as its `files`.
 */
export function makePackage(
  data: Uint8Array,
  format: string,
  options: { platform: string; homebrewId: string; fileName?: string; arch?: string[] },
): [Package, FileRef] {
  const ref = FileRef.ofBytes(data);
  const placeholder = `sha256:${ref.sha256}`;
  const base: Package = { format, file: placeholder, size: ref.size, sha256: ref.sha256, manifest_sha256: "" };
  if (options.arch !== undefined) base.arch = options.arch;
  if (format === "zip") {
    const manifest = zipManifest(data);
    return [{ ...base, manifest_sha256: hb.manifestSha256(manifest), manifest }, ref];
  }
  const prof = profile(options.platform);
  const path =
    prof !== undefined ? singleFilePath(prof, format, options.homebrewId, options.fileName ?? "") : undefined;
  const entries: ManifestEntry[] = path !== undefined ? [{ path, size: ref.size, sha256: ref.sha256 }] : [];
  const out: Package = { ...base, manifest_sha256: hb.manifestSha256(entries) };
  if (path !== undefined) out.path = path;
  return [out, ref];
}
