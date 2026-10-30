/**
 * The client's side of SPEC.md § 5.2 to § 5.5: a pairing under way, the checks
 * a client makes on a pairing code before it shows anything, and what an
 * invitation's link carries.
 */

import { DocumentError } from "../base.ts";
import type { PairingCode } from "../generated/models.ts";
import { origin, plainHttpAllowed, sameOrigin } from "../http.ts";
import type { DeviceKey } from "../signatures.ts";
import { SHA256_HEX, short } from "../spki.ts";

/**
 * A pairing under way (SPEC.md § 5.2). Show `code`, `verify` and `fingerprint`
 * (the short fingerprint of the key of the server the client talks to: the user
 * compares it with the one the server's page shows), and `verifyComplete` as a
 * QR code the client draws, the code and the fingerprint kept next to it. Then poll.
 */
export class Pairing {
  readonly document: PairingCode;
  readonly key: DeviceKey | undefined;
  /** The fingerprint of the server's TLS key as this client saw it (hex), when the transport could tell. */
  readonly spki: string | undefined;
  readonly pollUrl: string;
  readonly started: number;
  interval: number;

  constructor(document: PairingCode, key: DeviceKey | undefined, spki: string | undefined, pollUrl: string) {
    this.document = document;
    this.key = key;
    this.spki = spki;
    this.pollUrl = pollUrl;
    this.started = performance.now() / 1000;
    this.interval = document.interval;
  }

  get code(): string {
    return this.document.code;
  }

  get verify(): string {
    return this.document.verify;
  }

  /** The QR code's text: `verify` with the code in its query. */
  get verifyComplete(): string {
    return this.document.verify_complete ?? this.document.verify;
  }

  /** The short fingerprint of the server's key, as this client sees it; undefined when the transport cannot tell. */
  get fingerprint(): string | undefined {
    return this.spki !== undefined ? short(this.spki) : undefined;
  }

  get deadline(): number {
    return this.started + this.document.expires;
  }

  get expired(): boolean {
    return performance.now() / 1000 >= this.deadline;
  }
}

function safeOrigin(url: string): ReturnType<typeof origin> | undefined {
  try {
    return origin(url);
  } catch {
    return undefined;
  }
}

/**
 * The checks a client makes on a pairing code before it shows anything (SPEC.md
 * § 5.2): `verify` an address it may open (HTTPS, or HTTP on loopback);
 * `verify_complete` on verify's origin with the code in its query; the poll
 * address on the server's origin.
 */
export function checkPairingCode(doc: PairingCode, root: string): void {
  const where = "pairing code";
  let verifyOk = false;
  try {
    verifyOk = plainHttpAllowed(doc.verify);
  } catch {
    verifyOk = false;
  }
  if (!verifyOk)
    throw new DocumentError(`verify ${JSON.stringify(doc.verify.slice(0, 100))} is not an HTTPS address`, where);
  if (doc.verify_complete !== undefined) {
    const a = safeOrigin(doc.verify_complete);
    const b = safeOrigin(doc.verify);
    const typed = doc.code.toUpperCase().replace(/[^A-Z0-9]/g, "");
    let query = "";
    try {
      query = new URL(doc.verify_complete).search.toUpperCase().replace(/[^A-Z0-9]/g, "");
    } catch {
      query = "";
    }
    if (a === undefined || b === undefined || !sameOrigin(a, b) || !query.includes(typed)) {
      throw new DocumentError("verify_complete is not verify's address with the code in it", where);
    }
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(doc.poll) || doc.poll.startsWith("//")) {
    const poll = safeOrigin(doc.poll);
    const server = safeOrigin(root);
    if (poll === undefined || server === undefined || !sameOrigin(poll, server)) {
      throw new DocumentError("the poll address is not on the server's origin", where);
    }
  }
  if (!(doc.expires >= 1 && doc.expires <= 600) || doc.interval < 1) {
    throw new DocumentError("expires is 1 to 600 seconds, interval 1 or more", where);
  }
}

/**
 * What an invitation's link carries (SPEC.md § 5.5): the server's origin, the
 * invitation's code, and the fingerprint of its key (SHA-256 hex) when no CA
 * vouches for its certificate: a client pins that one, without asking the user.
 */
export interface InvitationLink {
  url: string;
  code: string;
  spki: string | undefined;
}

/** Reads an invitation's link; a RangeError when it is not one. */
export function invitationLink(link: string): InvitationLink {
  let parsed: URL;
  try {
    parsed = new URL(link);
  } catch {
    throw new RangeError("an invitation's link is an HTTPS address");
  }
  if (!plainHttpAllowed(link)) throw new RangeError("an invitation's link is an HTTPS address");
  const codes = parsed.searchParams.getAll("invitation");
  const spkis = parsed.searchParams.getAll("spki");
  if (codes.length !== 1 || spkis.length > 1) throw new RangeError("an invitation's link carries one invitation code");
  const code = (codes[0] ?? "").trim().toUpperCase();
  const symbols = code.replaceAll("-", "").length;
  if (symbols < 16 || symbols > 32) throw new RangeError("an invitation's code is 16 to 32 symbols");
  const spki = spkis[0]?.toLowerCase();
  if (spki !== undefined && !SHA256_HEX.test(spki)) throw new RangeError("spki is the server key's SHA-256, hex");
  return { url: `${parsed.protocol}//${parsed.host}/`, code, spki };
}
