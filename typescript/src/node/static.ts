/**
 * Static libraries in Node (SPEC.md § 21): a folder read as one (a USB key,
 * an SD card), and the generator that writes one, as the reference server's
 * export does (spec/server/static.py): from a toolkit Library, or from any
 * Lantern server read as a client (`lantern-static --from <url>`).
 *
 * An export replaces the `lantern.json` and `v1/` of an earlier one, and
 * nothing else in its folder; the same library gives the same pages. Its
 * texts are in one language; an image is kept only when external or a path
 * below the root (L-21.1-2).
 */

import { createReadStream } from "node:fs";
import { copyFile, mkdir, readFile, realpath, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { DocumentError, SCHEMA } from "../base.ts";
import type { LanternClient } from "../client/client.ts";
import type { App, CheatSet, Homebrew, Image, Package, Title } from "../generated/models.ts";
import type { Library } from "../server/library.ts";
import { HANDSHAKE, layoutPath, relativeOk, type StaticSource } from "../static.ts";
import { FAMILIES } from "../vocabulary.ts";
import { FileSink, sha256File } from "./index.ts";

/** A static library in a folder: its files read below it, never outside (no `..`, no link out). */
export class FileStaticSource implements StaticSource {
  readonly root: string;
  readonly describe: string;
  #real: string | undefined;

  constructor(folder: string) {
    this.root = resolve(folder);
    this.describe = this.root;
  }

  async #path(rel: string): Promise<string | undefined> {
    if (!relativeOk(rel)) throw new DocumentError(`${JSON.stringify(rel.slice(0, 80))} is not a path below the root`);
    this.#real ??= await realpath(this.root);
    let real: string;
    try {
      real = await realpath(join(this.root, ...rel.split("/")));
    } catch {
      return undefined;
    }
    const inside = relative(this.#real, real);
    if (inside === "" || inside.startsWith(`..${sep}`) || inside === ".." || resolve(this.#real, inside) !== real)
      throw new DocumentError(`${rel} leads outside the library's folder`);
    return real;
  }

  async read(rel: string, limit: number): Promise<Uint8Array | undefined> {
    const path = await this.#path(rel);
    if (path === undefined) return undefined;
    const info = await stat(path);
    if (!info.isFile()) return undefined;
    if (info.size > limit) throw new DocumentError(`more than ${limit} bytes`, rel);
    return new Uint8Array(await readFile(path));
  }

  async stream(rel: string): Promise<AsyncIterable<Uint8Array> | undefined> {
    const path = await this.#path(rel);
    if (path === undefined || !(await stat(path)).isFile()) return undefined;
    return createReadStream(path) as AsyncIterable<Uint8Array>;
  }
}

/** What a static library is written from: documents, and a way to copy each file, checked. */
export interface StaticInput {
  uid: string;
  name: string;
  software?: { name: string; version: string };
  platforms: string[];
  apps: App[];
  titles: Title[];
  /** Entries with their manifests. */
  homebrew: Homebrew[];
  cheats: CheatSet[];
  /** Writes the file of an app or a package (its `file`, `sha256` and `size`) to `dest`, checked. */
  copy(doc: { file: string; sha256: string; size: number }, dest: string): Promise<void>;
  /** Writes a cheat set's text to `dest`. */
  cheatText(cheat: CheatSet, dest: string): Promise<void>;
}

const fold = (text: string | undefined): string => (text ?? "").toLowerCase();
const byKeys = (a: (string | number)[], b: (string | number)[]): number => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? "";
    const y = b[i] ?? "";
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
};

function pages<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out.length > 0 ? out : [[]];
}

function image(value: Image | undefined): Image | undefined {
  if (value === undefined) return undefined;
  return value.external === true || relativeOk(value.url) ? value : undefined;
}

/** A title's images kept as § 21.1 allows: external, or below the root; the others left out. */
function titleImages(title: Title): Title {
  const out: Title = { ...title };
  const icon = image(title.icon);
  const banner = image(title.banner);
  if (icon !== undefined) out.icon = icon;
  else delete out.icon;
  if (banner !== undefined) out.banner = banner;
  else delete out.banner;
  if (title.screenshots !== undefined) {
    const shots = title.screenshots.map(image).filter((i): i is Image => i !== undefined);
    if (shots.length > 0) out.screenshots = shots;
    else delete out.screenshots;
  }
  return out;
}

/** Writes a static library (SPEC.md § 21) into `out`; what it wrote. */
export class StaticWriter {
  readonly out: string;
  readonly pageSize: number;
  readonly language: string;
  #documents = 0;
  #files = 0;
  #written = new Set<string>();

  constructor(out: string, options: { pageSize?: number; language?: string } = {}) {
    const size = options.pageSize ?? 100;
    if (!Number.isInteger(size) || size < 1 || size > 1000) throw new RangeError("a page holds 1 to 1000 items");
    this.out = resolve(out);
    this.pageSize = size;
    this.language = options.language ?? "en";
  }

  async #put(rel: string, doc: unknown): Promise<void> {
    const target = join(this.out, ...rel.split("/"));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, JSON.stringify(doc));
    this.#documents++;
  }

  async #blob(doc: { file: string; sha256: string; size: number }, input: StaticInput): Promise<string> {
    const rel = layoutPath("blob", { id: doc.sha256 });
    if (!this.#written.has(rel)) {
      const target = join(this.out, ...rel.split("/"));
      await mkdir(dirname(target), { recursive: true });
      await input.copy(doc, target);
      this.#written.add(rel);
      this.#files++;
    }
    return rel;
  }

  async write(input: StaticInput): Promise<{ documents: number; files: number; platforms: string[] }> {
    await mkdir(this.out, { recursive: true });
    await rm(join(this.out, "v1"), { recursive: true, force: true }); // the earlier export's: replaced whole
    const platforms = [...new Set(input.platforms)].sort();
    const total = (n: number) => n;
    for (const p of platforms) {
      const apps = input.apps
        .filter((a) => a.platform === p)
        .sort((a, b) => byKeys([fold(a.name), a.id], [fold(b.name), b.id]));
      const docs: App[] = [];
      for (const a of apps) {
        const { schema: _s, ...rest } = a as App & { schema?: number };
        docs.push({ ...rest, file: await this.#blob(a, input) });
      }
      const appPages = pages(docs, this.pageSize);
      for (const [i, chunk] of appPages.entries()) {
        await this.#put(layoutPath("apps", { platform: p, page: i + 1 }), {
          schema: SCHEMA,
          items: chunk,
          total: total(docs.length),
          next: i + 1 < appPages.length ? String(i + 2) : null,
        });
      }
      const titles = input.titles
        .filter((t) => t.platform === p)
        .sort((a, b) => byKeys([fold(a.name), a.title_id], [fold(b.name), b.title_id]))
        .map(titleImages);
      for (const t of titles)
        await this.#put(layoutPath("title", { platform: p, id: t.title_id }), { schema: SCHEMA, ...t });
      const titlePages = pages(titles, this.pageSize);
      for (const [i, chunk] of titlePages.entries()) {
        await this.#put(layoutPath("titles", { platform: p, page: i + 1 }), {
          schema: SCHEMA,
          titles: chunk,
          unknown: [],
          next: i + 1 < titlePages.length ? String(i + 2) : null,
        });
      }
      const entries = input.homebrew
        .filter((e) => e.platform === p)
        .sort((a, b) => byKeys([fold(a.name), a.id], [fold(b.name), b.id]));
      const listed: Homebrew[] = [];
      for (const e of entries) {
        const { schema: _s, ...rest } = e as Homebrew & { schema?: number };
        const full: Homebrew = structuredClone(rest);
        for (const pkg of [full.package, ...(full.packages ?? [])]) pkg.file = await this.#blob(pkg, input);
        await this.#put(layoutPath("entry", { platform: p, id: e.id }), { schema: SCHEMA, ...full });
        const strip = (pkg: Package): Package => {
          const { manifest: _m, ...out } = pkg;
          return out as Package;
        };
        const short: Homebrew = { ...full, package: strip(full.package) };
        if (full.packages !== undefined) short.packages = full.packages.map(strip);
        listed.push(short);
      }
      const brewPages = pages(listed, this.pageSize);
      for (const [i, chunk] of brewPages.entries()) {
        await this.#put(layoutPath("homebrew", { platform: p, page: i + 1 }), {
          schema: SCHEMA,
          items: chunk,
          total: listed.length,
          next: i + 1 < brewPages.length ? String(i + 2) : null,
        });
      }
    }
    const byTitle = new Map<string, CheatSet[]>();
    const sets = input.cheats
      .filter((c) => platforms.includes(c.platform))
      .sort((a, b) =>
        byKeys(
          [a.platform, a.title_id, a.build_id ?? "", fold(a.source), a.id],
          [b.platform, b.title_id, b.build_id ?? "", fold(b.source), b.id],
        ),
      );
    for (const c of sets) {
      const key = `${c.platform}/${c.title_id}`;
      byTitle.set(key, [...(byTitle.get(key) ?? []), c]);
      const rel = layoutPath("cheat", { id: c.id });
      const target = join(this.out, ...rel.split("/"));
      await mkdir(dirname(target), { recursive: true });
      await input.cheatText(c, target);
      this.#files++;
    }
    for (const [key, cheats] of byTitle) {
      const [platform = "", titleId = ""] = key.split("/");
      await this.#put(layoutPath("cheats", { platform, id: titleId }), { schema: SCHEMA, cheats });
    }
    const features: Record<string, number> = {};
    for (const f of FAMILIES) features[f] = 0;
    Object.assign(features, { library: 1, titles: 1, homebrew: 1, cheats: byTitle.size > 0 ? 1 : 0 });
    const generated = `${new Date().toISOString().slice(0, 19)}Z`;
    const hello: Record<string, unknown> = { schema: SCHEMA, uid: input.uid, name: input.name };
    if (input.software !== undefined) hello["software"] = input.software;
    Object.assign(hello, {
      base: ".",
      versions: [1],
      platforms,
      language: this.language,
      account: { state: "anonymous", scopes: byTitle.size > 0 ? ["library", "cheats"] : ["library"] },
      features,
      limits: { page_size: this.pageSize },
      static: { generated, page_size: this.pageSize },
    });
    // The handshake last, through a temporary file: a reader never sees one before its pages.
    const temp = join(this.out, `.${HANDSHAKE}.part`);
    await writeFile(temp, JSON.stringify(hello));
    await rename(temp, join(this.out, HANDSHAKE));
    this.#documents++;
    return { documents: this.#documents, files: this.#files, platforms };
  }
}

/** writeStatic(): StaticWriter's write() at once. */
export function writeStatic(
  input: StaticInput,
  out: string,
  options: { pageSize?: number; language?: string } = {},
): Promise<{ documents: number; files: number; platforms: string[] }> {
  return new StaticWriter(out, options).write(input);
}

/** A toolkit Library as a static library's input: its files copied from where they are, checked by their SHA-256. */
export async function libraryInput(
  library: Library,
  options: { uid: string; name: string; software?: { name: string; version: string }; language?: string },
): Promise<StaticInput> {
  const languages = [options.language ?? "en"];
  const has = (f: string): boolean => library.families.has(f);
  const apps = has("library") ? [...(await library.apps())] : [];
  const titles = has("titles") ? [...(await library.titles(languages))] : [];
  const homebrew = has("homebrew") ? [...(await library.homebrew(languages))] : [];
  const cheats = has("cheats") ? [...(await library.cheats())] : [];
  const platforms = new Set<string>([...apps, ...titles, ...homebrew, ...cheats].map((x) => x.platform));
  const write = async (ref: { path: string; data: Uint8Array | undefined; sha256: string }, dest: string) => {
    if (ref.data !== undefined) await writeFile(dest, ref.data);
    else await copyFile(ref.path, dest);
    if ((await sha256File(dest)) !== ref.sha256) throw new DocumentError(`${dest}: not the file's SHA-256`);
  };
  const input: StaticInput = {
    uid: options.uid,
    name: options.name,
    platforms: [...platforms],
    apps,
    titles,
    homebrew,
    cheats,
    async copy(doc, dest) {
      const id = /\/files\/([^/?#]+)$/.exec(doc.file)?.[1];
      const ref = id !== undefined ? await library.file(id) : undefined;
      if (ref === undefined || ref.sha256 !== doc.sha256 || ref.size !== doc.size)
        throw new DocumentError(`${doc.file}: no file of this library`);
      await write(ref, dest);
    },
    async cheatText(cheat, dest) {
      const ref = await library.cheatFile(cheat.id);
      if (ref === undefined) throw new DocumentError(`cheat set ${cheat.id}: no text`);
      await write(ref, dest);
    },
  };
  if (options.software !== undefined) input.software = options.software;
  return input;
}

/**
 * Any Lantern server, read as a client, as a static library's input: its
 * apps, titles, homebrew (with manifests) and cheat sets, every file
 * downloaded and checked. What the caller may read is what is exported.
 */
export async function clientInput(client: LanternClient & { downloadToFile?: unknown }): Promise<StaticInput> {
  const hello = await client.handshake();
  const offers = (f: string): boolean => (hello.features as Record<string, number>)[f] === 1;
  const apps: App[] = [];
  if (offers("library")) for await (const a of client.iterApps({ pageSize: 500 })) apps.push(a);
  const titles: Title[] = [];
  if (offers("titles")) {
    for (const p of hello.platforms) {
      const ids = [...new Set(apps.filter((a) => a.platform === p).map((a) => a.title_id))];
      for (let i = 0; i < ids.length; i += 100) {
        titles.push(...(await client.titles(ids.slice(i, i + 100), { platform: p })).titles);
      }
    }
  }
  const homebrew: Homebrew[] = [];
  if (offers("homebrew")) {
    for await (const e of client.iterHomebrew({ pageSize: 500 })) {
      homebrew.push(await client.homebrewEntry(e.id, { platform: e.platform }));
    }
  }
  const cheats: CheatSet[] = [];
  if (offers("cheats")) for (const p of hello.platforms) cheats.push(...(await client.cheats({ platform: p })).cheats);
  const fetchTo = async (doc: { file: string; sha256: string; size: number }, dest: string) => {
    const sink = new FileSink(dest);
    try {
      await client.download(doc.file, sink, { sha256: doc.sha256, size: doc.size, resume: false });
    } finally {
      await sink.close();
    }
  };
  const input: StaticInput = {
    uid: hello.uid,
    name: hello.name,
    platforms: hello.platforms,
    apps,
    titles,
    homebrew,
    cheats,
    copy: fetchTo,
    async cheatText(cheat, dest) {
      await writeFile(dest, await client.cheatText(cheat));
    },
  };
  const { name, version } = hello.software ?? {};
  if (name !== undefined && version !== undefined) input.software = { name, version };
  return input;
}
