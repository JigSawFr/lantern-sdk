/**
 * A server's key fingerprint (SPEC.md § 5.3): the SHA-256 of its certificate's
 * DER SubjectPublicKeyInfo, and its short form for people (`3F9A 1C07 B2E4
 * 55D0`). Test vectors: `vectors/spki.json`. The certificate is read with a
 * small DER reader of its own: only the structure that leads to the key.
 */

import { fromBase64, toHex } from "./bytes.ts";
import { sha256 } from "./sha256.ts";

export const SHA256_HEX = /^[0-9a-f]{64}$/;

/** A certificate this reader cannot find the key of. */
export class CertificateError extends Error {
  override name = "CertificateError";
}

function element(data: Uint8Array, at: number): [tag: number, start: number, end: number] {
  if (at + 2 > data.length) throw new CertificateError("a truncated certificate");
  const tag = data[at] ?? 0;
  let length = data[at + 1] ?? 0;
  let pos = at + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || pos + count > data.length) {
      throw new CertificateError("a length this reader does not take");
    }
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + (data[pos + i] ?? 0);
    pos += count;
  }
  const end = pos + length;
  if (end > data.length) throw new CertificateError("a truncated certificate");
  return [tag, pos, end];
}

/** The DER SubjectPublicKeyInfo of a DER certificate (RFC 5280 § 4.1). */
export function spkiDer(certificate: Uint8Array): Uint8Array {
  const [tag, start] = element(certificate, 0);
  if (tag !== 0x30) throw new CertificateError("not a certificate");
  const [tbsTag, tbsStart, tbsEnd] = element(certificate, start);
  if (tbsTag !== 0x30) throw new CertificateError("not a certificate");
  let fields: [number, number, number][] = [];
  let pos = tbsStart;
  while (pos < tbsEnd && fields.length < 7) {
    const [t, , end] = element(certificate, pos);
    fields.push([t, pos, end]);
    pos = end;
  }
  if (fields[0]?.[0] === 0xa0) fields = fields.slice(1); // [0] version, when present
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  const spki = fields[5];
  if (spki === undefined || spki[0] !== 0x30) throw new CertificateError("no SubjectPublicKeyInfo");
  return certificate.slice(spki[1], spki[2]);
}

/** The DER bytes of a PEM certificate (its first). */
export function pemToDer(pem: string): Uint8Array {
  const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pem);
  const der = m?.[1] !== undefined ? fromBase64(m[1].replace(/\s+/g, "")) : undefined;
  if (der === undefined) throw new CertificateError("not a PEM certificate");
  return der;
}

/** The fingerprint of a certificate (DER bytes, or PEM text): lower-case hex. */
export function spkiSha256(certificate: Uint8Array | string): string {
  const der = typeof certificate === "string" ? pemToDer(certificate) : certificate;
  return toHex(sha256(spkiDer(der)));
}

/** The fingerprint of a DER SubjectPublicKeyInfo itself. */
export function spkiDigest(spki: Uint8Array): string {
  return toHex(sha256(spki));
}

/** A fingerprint's short form, for people: its first 16 hex digits, upper-case, in groups of 4. */
export function short(fingerprint: string): string {
  if (!SHA256_HEX.test(fingerprint.toLowerCase())) throw new RangeError("a fingerprint is a SHA-256 in hex");
  const head = fingerprint.slice(0, 16).toUpperCase();
  return [0, 4, 8, 12].map((i) => head.slice(i, i + 4)).join(" ");
}

/** Whether the key `seen` is the one `pinned` (both hex). */
export function checkPin(seen: string, pinned: string): boolean {
  return seen.toLowerCase() === pinned.toLowerCase();
}
