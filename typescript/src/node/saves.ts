/**
 * Encrypted saves (SPEC.md § 9.4) with files: a backup decrypted into a file
 * through a `.part` renamed only once every chunk opened, and its last one
 * was the last (L-9.4-1): a backup cut, changed or extended restores nothing.
 */

import { createReadStream } from "node:fs";
import { mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import { decrypt, type SaveKey } from "../e2e.ts";

/**
 * Decrypts a backup (a file's path, or its bytes) into `dest`, through
 * `dest + ".part"`; DecryptionError, and nothing at `dest`, when any of it does
 * not open. Each chunk of the archive is zeroed once written.
 */
export async function decryptSaveFile(key: SaveKey, backup: string | Uint8Array, dest: string): Promise<string> {
  const part = `${dest}.part`;
  await mkdir(dirname(part), { recursive: true });
  const handle = await open(part, "w", 0o600);
  let ok = false;
  try {
    const source = typeof backup === "string" ? createReadStream(backup) : [backup];
    for await (const chunk of decrypt(key, source as AsyncIterable<Uint8Array> | Iterable<Uint8Array>)) {
      await handle.write(chunk);
      chunk.fill(0);
    }
    ok = true;
  } finally {
    await handle.close();
    if (!ok) await unlink(part).catch(() => undefined);
  }
  await rename(part, dest);
  return dest;
}
