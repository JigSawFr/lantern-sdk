/** SHA-256 by node:crypto, as a HasherFactory (what the Node entries plug in). */

import { createHash } from "node:crypto";
import type { Hasher, HasherFactory } from "../sha256.ts";

/** SHA-256 by node:crypto. */
export const nodeSha256: HasherFactory = (): Hasher => {
  const h = createHash("sha256");
  let size = 0;
  return {
    update(data: Uint8Array): void {
      h.update(data);
      size += data.length;
    },
    digest: () => new Uint8Array(h.digest()),
    get size() {
      return size;
    },
  };
};
