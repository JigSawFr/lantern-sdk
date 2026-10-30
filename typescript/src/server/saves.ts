/**
 * Save backups on the server's side (SPEC.md § 9): where LanternApp keeps
 * them. `SaveStore` is the interface a server implements over its own storage;
 * `MemorySaveStore` keeps everything in memory (tests, demos, a reference to
 * read) and `FileSaveStore` in a folder: `index.json` (schema 1: every
 * backup and upload, with its account), `archives/` and `uploads/`.
 *
 * A store keeps bytes and entries as LanternApp hands them over: it checks
 * nothing of the protocol (digests, kinds, limits, pruning) but the SHA-256
 * of an upload's whole archive, which only it can read back. An encrypted
 * backup (§ 9.4) is kept like any other: its bytes as sent, its `encryption`
 * in its entry, never opened.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { appendFile, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { isObject, SCHEMA } from "../base.ts";
import type { Save } from "../generated/models.ts";
import { FileRef } from "./files.ts";

type Maybe<T> = T | Promise<T>;

/** What a backup is sent with (SPEC.md § 9.2, § 9.3): what its entry shows besides what the server gives it. */
export type SaveFields = Omit<Save, "schema" | "save_id" | "created" | "size" | "sha256">;

/** An upload under way (SPEC.md § 9.3): its account, the backup's fields, its size and SHA-256, how much is in. */
export interface UploadState {
  id: string;
  user: string;
  fields: SaveFields;
  size: number;
  sha256: string;
  offset: number;
  /** RFC 3339, UTC: when it is gone if not finished. */
  expires: string;
}

/** Where LanternApp keeps backups. Every method may be async. */
export interface SaveStore {
  /** False when the store cannot be read (a file of a newer schema): the family `saves` is then not offered. */
  readonly available?: boolean;
  /** Every backup of `user`, oldest first (in the order they were kept). */
  saves(user: string): Maybe<readonly Save[]>;
  /** A backup's bytes, as a file (SPEC.md § 6.6). */
  file(user: string, saveId: string): Maybe<FileRef | undefined>;
  /** Keeps `data` as the backup `save` of `user`. */
  add(user: string, save: Save, data: Uint8Array): Maybe<void>;
  /** Removes a backup and its bytes; false when `user` has none of that id. */
  delete(user: string, saveId: string): Maybe<boolean>;
  /** Opens an upload (its offset 0). A store drops the uploads whose `expires` has passed. */
  open(upload: UploadState): Maybe<void>;
  /** An upload, with its offset now; undefined when it is gone (finished, abandoned or expired). */
  upload(id: string): Maybe<UploadState | undefined>;
  /** The uploads `user` has open. */
  uploads(user: string): Maybe<readonly UploadState[]>;
  /** Appends a chunk at the upload's offset; the new offset. */
  append(id: string, chunk: Uint8Array): Maybe<number>;
  /**
   * Ends an upload whose bytes are all in: they become the backup `save` when
   * their SHA-256 is the upload's (true), and are discarded otherwise (false).
   * Either way the upload is gone.
   */
  finish(id: string, save: Save): Maybe<boolean>;
  /** Drops an upload and what it holds. */
  abandon(id: string): Maybe<void>;
  /** Every backup and upload of `user` erased (an account deleted, SPEC.md § 5.7). */
  forget(user: string): Maybe<void>;
}

/** The content type a backup is served with: a zip in clear, bytes when encrypted (§ 9.4). */
export function saveContentType(save: Save): string {
  return save.encryption !== undefined ? "application/octet-stream" : "application/zip";
}

function expired(upload: { expires: string }, now: number): boolean {
  const t = Date.parse(upload.expires);
  return Number.isNaN(t) || t <= now;
}

/** Backups and uploads held in memory. */
export class MemorySaveStore implements SaveStore {
  readonly available = true;
  readonly #saves = new Map<string, { save: Save; data: Uint8Array }[]>();
  readonly #uploads = new Map<string, { state: UploadState; chunks: Uint8Array[] }>();

  #purge(): void {
    const now = Date.now();
    for (const [id, u] of this.#uploads) if (expired(u.state, now)) this.#uploads.delete(id);
  }

  saves(user: string): Save[] {
    return (this.#saves.get(user) ?? []).map((s) => s.save);
  }

  file(user: string, saveId: string): FileRef | undefined {
    const found = (this.#saves.get(user) ?? []).find((s) => s.save.save_id === saveId);
    if (found === undefined) return undefined;
    return new FileRef({
      size: found.data.length,
      sha256: found.save.sha256,
      data: found.data,
      contentType: saveContentType(found.save),
    });
  }

  add(user: string, save: Save, data: Uint8Array): void {
    const mine = this.#saves.get(user) ?? [];
    mine.push({ save, data: new Uint8Array(data) });
    this.#saves.set(user, mine);
  }

  delete(user: string, saveId: string): boolean {
    const mine = this.#saves.get(user) ?? [];
    const kept = mine.filter((s) => s.save.save_id !== saveId);
    if (kept.length === mine.length) return false;
    this.#saves.set(user, kept);
    return true;
  }

  open(upload: UploadState): void {
    this.#purge();
    this.#uploads.set(upload.id, { state: { ...upload, offset: 0 }, chunks: [] });
  }

  upload(id: string): UploadState | undefined {
    this.#purge();
    const u = this.#uploads.get(id);
    return u !== undefined ? { ...u.state } : undefined;
  }

  uploads(user: string): UploadState[] {
    this.#purge();
    return [...this.#uploads.values()].filter((u) => u.state.user === user).map((u) => ({ ...u.state }));
  }

  append(id: string, chunk: Uint8Array): number {
    const u = this.#uploads.get(id);
    if (u === undefined) throw new RangeError("no such upload");
    u.chunks.push(new Uint8Array(chunk));
    u.state.offset += chunk.length;
    return u.state.offset;
  }

  finish(id: string, save: Save): boolean {
    const u = this.#uploads.get(id);
    this.#uploads.delete(id);
    if (u === undefined) return false;
    const data = Buffer.concat(u.chunks);
    if (createHash("sha256").update(data).digest("hex") !== u.state.sha256) return false;
    this.add(u.state.user, save, new Uint8Array(data));
    return true;
  }

  abandon(id: string): void {
    this.#uploads.delete(id);
  }

  forget(user: string): void {
    this.#saves.delete(user);
    for (const [id, u] of this.#uploads) if (u.state.user === user) this.#uploads.delete(id);
  }
}

/** The fields of a backup's entry the protocol shows (SPEC.md § 9.1), in order. */
const PUBLIC = [
  "platform",
  "title_id",
  "save_id",
  "created",
  "size",
  "sha256",
  "slot",
  "kind",
  "game_version_code",
  "profile",
  "note",
  "device",
  "encryption",
] as const;

const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** A record of the index as a backup's entry: its known fields, the others left in the file (SPEC.md § 3.2). */
function entryOf(record: Record<string, unknown>): Save | undefined {
  if (typeof record["save_id"] !== "string" || !SAFE_ID.test(record["save_id"])) return undefined;
  if (typeof record["platform"] !== "string" || typeof record["title_id"] !== "string") return undefined;
  if (typeof record["created"] !== "string" || typeof record["sha256"] !== "string") return undefined;
  if (typeof record["size"] !== "number") return undefined;
  const out: Record<string, unknown> = {};
  for (const k of PUBLIC) if (record[k] !== undefined) out[k] = record[k];
  return out as unknown as Save;
}

function uploadOf(id: string, record: unknown, offset: number): UploadState | undefined {
  if (!isObject(record) || !SAFE_ID.test(id)) return undefined;
  const { user, fields, size, sha256, expires } = record;
  if (typeof user !== "string" || !isObject(fields) || typeof size !== "number") return undefined;
  if (typeof sha256 !== "string" || typeof expires !== "string") return undefined;
  return { id, user, fields: fields as unknown as SaveFields, size, sha256, offset, expires };
}

/**
 * Backups in a folder: `index.json`, of `schema` 1, lists each backup (its
 * account, then its entry) and each upload under way; `archives/<save_id>`
 * and `uploads/<id>.part` hold the bytes. The index follows SPEC.md § 3.2's
 * rule: a field it does not know is kept when it is written again, and an
 * index of a newer schema makes the store unavailable (the family is then not
 * offered) and is never written over. Open it with `FileSaveStore.open()`.
 */
export class FileSaveStore implements SaveStore {
  readonly folder: string;
  readonly available: boolean;
  #index: Record<string, unknown>;
  #chain: Promise<unknown> = Promise.resolve();

  private constructor(folder: string, index: Record<string, unknown> | undefined) {
    this.folder = folder;
    this.available = index !== undefined;
    this.#index = index ?? { schema: SCHEMA };
    if (!Array.isArray(this.#index["saves"])) this.#index["saves"] = [];
    if (!isObject(this.#index["uploads"])) this.#index["uploads"] = {};
  }

  /** The store of `folder`, made when absent. */
  static async open(folder: string): Promise<FileSaveStore> {
    let index: Record<string, unknown> | undefined = { schema: SCHEMA };
    let text: string | undefined;
    try {
      text = await readFile(join(folder, "index.json"), "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    if (text !== undefined) {
      let doc: unknown;
      try {
        doc = JSON.parse(text);
      } catch {
        doc = undefined;
      }
      const schema = isObject(doc) ? doc["schema"] : undefined;
      // An index this version cannot read (a newer schema, or none) reads as absent and is never written over.
      index =
        isObject(doc) && typeof schema === "number" && Number.isInteger(schema) && schema >= 1 && schema <= SCHEMA
          ? doc
          : undefined;
    }
    return new FileSaveStore(folder, index);
  }

  get #records(): Record<string, unknown>[] {
    return this.#index["saves"] as Record<string, unknown>[];
  }

  get #pending(): Record<string, unknown> {
    return this.#index["uploads"] as Record<string, unknown>;
  }

  #archive(saveId: string): string {
    return join(this.folder, "archives", saveId);
  }

  #part(id: string): string {
    return join(this.folder, "uploads", `${id}.part`);
  }

  /** Runs `job` after every write before it: one change at a time. */
  #serial<T>(job: () => Promise<T>): Promise<T> {
    const next = this.#chain.then(job, job);
    this.#chain = next.catch(() => undefined);
    return next;
  }

  async #write(): Promise<void> {
    if (!this.available) throw new Error("this store's index is of a newer schema: it is never written over");
    await mkdir(this.folder, { recursive: true });
    const path = join(this.folder, "index.json");
    const tmp = `${path}.${process.pid}.tmp`;
    await writeFile(tmp, `${JSON.stringify(this.#index, null, 1)}\n`);
    await rename(tmp, path);
  }

  async #purge(): Promise<void> {
    const now = Date.now();
    let changed = false;
    for (const [id, record] of Object.entries(this.#pending)) {
      const u = uploadOf(id, record, 0);
      if (u === undefined || !expired(u, now)) continue; // a record not of this version's form is left as it is
      delete this.#pending[id];
      await rm(this.#part(id), { force: true });
      changed = true;
    }
    if (changed) await this.#write();
  }

  #mine(user: string): Record<string, unknown>[] {
    return this.#records.filter((r) => isObject(r) && r["user"] === user && entryOf(r) !== undefined);
  }

  saves(user: string): Save[] {
    return this.#mine(user).map((r) => entryOf(r) as Save);
  }

  async file(user: string, saveId: string): Promise<FileRef | undefined> {
    const record = this.#mine(user).find((r) => r["save_id"] === saveId);
    const save = record !== undefined ? entryOf(record) : undefined;
    if (save === undefined) return undefined;
    const path = this.#archive(save.save_id);
    try {
      if ((await stat(path)).size !== save.size) return undefined;
    } catch {
      return undefined;
    }
    return new FileRef({ path, size: save.size, sha256: save.sha256, contentType: saveContentType(save) });
  }

  add(user: string, save: Save, data: Uint8Array): Promise<void> {
    return this.#serial(async () => {
      await mkdir(join(this.folder, "archives"), { recursive: true });
      const path = this.#archive(save.save_id);
      await writeFile(`${path}.tmp`, data);
      await rename(`${path}.tmp`, path);
      this.#records.push({ user, ...save });
      await this.#write();
    });
  }

  delete(user: string, saveId: string): Promise<boolean> {
    return this.#serial(async () => {
      const record = this.#mine(user).find((r) => r["save_id"] === saveId);
      if (record === undefined) return false;
      this.#index["saves"] = this.#records.filter((r) => r !== record);
      await this.#write();
      await rm(this.#archive(saveId), { force: true });
      return true;
    });
  }

  open(upload: UploadState): Promise<void> {
    return this.#serial(async () => {
      await this.#purge();
      await mkdir(join(this.folder, "uploads"), { recursive: true });
      await writeFile(this.#part(upload.id), new Uint8Array());
      const { id: _id, offset: _offset, ...kept } = upload;
      this.#pending[upload.id] = kept;
      await this.#write();
    });
  }

  async #offset(id: string): Promise<number> {
    try {
      return (await stat(this.#part(id))).size;
    } catch {
      return 0;
    }
  }

  upload(id: string): Promise<UploadState | undefined> {
    return this.#serial(async () => {
      await this.#purge();
      if (!Object.hasOwn(this.#pending, id)) return undefined;
      return uploadOf(id, this.#pending[id], await this.#offset(id));
    });
  }

  uploads(user: string): Promise<UploadState[]> {
    return this.#serial(async () => {
      await this.#purge();
      const out: UploadState[] = [];
      for (const [id, record] of Object.entries(this.#pending)) {
        const u = uploadOf(id, record, await this.#offset(id));
        if (u?.user === user) out.push(u);
      }
      return out;
    });
  }

  append(id: string, chunk: Uint8Array): Promise<number> {
    return this.#serial(async () => {
      if (!Object.hasOwn(this.#pending, id)) throw new RangeError("no such upload");
      await appendFile(this.#part(id), chunk);
      return this.#offset(id);
    });
  }

  finish(id: string, save: Save): Promise<boolean> {
    return this.#serial(async () => {
      const u = Object.hasOwn(this.#pending, id) ? uploadOf(id, this.#pending[id], 0) : undefined;
      const part = this.#part(id);
      delete this.#pending[id];
      try {
        if (u === undefined) return false;
        const h = createHash("sha256");
        for await (const c of createReadStream(part)) h.update(c as Buffer);
        if (h.digest("hex") !== u.sha256) return false;
        await mkdir(join(this.folder, "archives"), { recursive: true });
        await rename(part, this.#archive(save.save_id));
        this.#records.push({ user: u.user, ...save });
        return true;
      } finally {
        await rm(part, { force: true });
        await this.#write();
      }
    });
  }

  abandon(id: string): Promise<void> {
    return this.#serial(async () => {
      if (!Object.hasOwn(this.#pending, id)) return;
      delete this.#pending[id];
      await rm(this.#part(id), { force: true });
      await this.#write();
    });
  }

  forget(user: string): Promise<void> {
    return this.#serial(async () => {
      const gone = this.#mine(user);
      this.#index["saves"] = this.#records.filter((r) => !gone.includes(r));
      for (const [id, record] of Object.entries(this.#pending)) {
        if (isObject(record) && record["user"] === user) {
          delete this.#pending[id];
          await rm(this.#part(id), { force: true });
        }
      }
      await this.#write();
      for (const r of gone) await rm(this.#archive(String(r["save_id"])), { force: true });
    });
  }
}
