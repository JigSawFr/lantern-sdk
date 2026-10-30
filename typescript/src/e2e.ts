/**
 * End-to-end encrypted save backups, scheme `lantern-save-e2e-1` (SPEC.md
 * § 9.4): the save key and its id, the recovery phrase and its QR text, and
 * backups encrypted and decrypted in chunks of 64 KiB, as a stream.
 *
 * XChaCha20-Poly1305 is this library's own (src/chacha.ts): WebCrypto has no
 * ChaCha20. HKDF-SHA-256 is WebCrypto's. Nothing here sends anything: of the
 * key, only its id may leave the device (§ 9.4, L-9.4-2).
 *
 * **Wiping, and what JavaScript cannot promise.** The keys this module makes
 * (the wrapping key, each file key, ChaCha20's subkeys and states) live in
 * typed arrays it zeroes once it is done with them, and `SaveKey.wipe()`
 * zeroes the save key. JavaScript gives no more than that: the engine may have
 * copied a buffer while it moved it (a garbage collector compacting the
 * heap), WebCrypto keeps its own copy of the key HKDF imports until it is
 * collected, a string (a recovery phrase, a QR text) cannot be wiped at all,
 * and nothing keeps a page of memory from the swap. Keep a save key where the
 * system protects keys (a non-extractable store, the keychain), show its phrase
 * only when the user asks (L-9.4-8), and let it go out of scope as soon as a
 * backup is made or read.
 */

import { DocumentError, LanternError, Unsupported } from "./base.ts";
import { concat, fromHex, randomBytes, toHex, utf8 } from "./bytes.ts";
import { equalBytes, xchacha20poly1305Open, xchacha20poly1305Seal } from "./chacha.ts";
import type { Encryption } from "./generated/models.ts";
import { sha256 } from "./sha256.ts";
import { CODE_ALPHABET } from "./vocabulary.ts";

/** The scheme's name, as a backup's `encryption.scheme` says it. */
export const SCHEME = "lantern-save-e2e-1";
/** The first 8 bytes of every encrypted backup. */
export const MAGIC = utf8("LTNE2E01");
/** The header's length: magic, key id, wrap nonce, the file key sealed. */
export const HEADER = 88;
/** An archive's chunk, before it is sealed. */
export const CHUNK = 65536;
/** A tag's length. */
export const TAG = 16;
/** What a QR code of a save key begins with. */
export const QR_PREFIX = "LANTERN-SAVE-KEY-1:";
/** A key id: 16 lower-case hex digits. */
export const KEY_ID = /^[0-9a-f]{16}$/;

const INFO_KEY_ID = utf8("lantern-save-e2e-1 key id");
const INFO_WRAP = utf8("lantern-save-e2e-1 wrap");
const CHECK_PREFIX = utf8("lantern-save-key");
const SYMBOLS = 56;

/** A backup that does not open (SPEC.md § 9.4, L-9.4-1): restore nothing of it. */
export class DecryptionError extends LanternError {
  override name = "DecryptionError";
}

/** A recovery phrase or a QR text whose form or check does not match (L-9.4-7): say so before anything else. */
export class KeyPhraseError extends LanternError {
  override name = "KeyPhraseError";
}

/** HKDF-SHA-256 (RFC 5869) by WebCrypto: `length` bytes of `ikm`, with `salt` and `info`. */
export async function hkdfSha256(
  ikm: Uint8Array,
  info: Uint8Array,
  length: number,
  salt: Uint8Array = new Uint8Array(),
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) throw new Unsupported("HKDF needs WebCrypto (crypto.subtle), which this platform lacks");
  const key = await subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: info as BufferSource },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** The size of a backup of `n` bytes once encrypted: 88 + n + 16 × its chunks (one at least). */
export function encryptedSize(n: number): number {
  return HEADER + n + TAG * chunkCount(n);
}

/** How many chunks an archive of `n` bytes is cut into: an empty one is one empty chunk. */
export function chunkCount(n: number): number {
  return n === 0 ? 1 : Math.ceil(n / CHUNK);
}

/** Chunk `i`'s nonce: 16 zero bytes, `i` on 7 bytes big-endian, then 01 for the last chunk, 00 otherwise. */
export function chunkNonce(i: number, last: boolean): Uint8Array {
  if (!Number.isSafeInteger(i) || i < 0) throw new RangeError("chunk index");
  const nonce = new Uint8Array(24);
  let v = i;
  for (let at = 22; at >= 16; at--) {
    nonce[at] = v % 256;
    v = Math.floor(v / 256);
  }
  nonce[23] = last ? 1 : 0;
  return nonce;
}

function symbols(data: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const byte of data) {
    acc = ((acc << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CODE_ALPHABET[(acc >>> bits) & 31];
    }
  }
  if (bits > 0) out += CODE_ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

function checksum(key: Uint8Array): Uint8Array {
  const digest = sha256(concat([CHECK_PREFIX, key]));
  const out = new Uint8Array(digest.subarray(0, 3));
  digest.fill(0);
  return out;
}

/**
 * A save key (SPEC.md § 9.4): 32 random bytes, made once by the user's first
 * device that encrypts, carried to the others as a phrase or a QR code, never
 * sent to a server.
 */
export class SaveKey {
  readonly #key: Uint8Array;
  #wiped = false;

  constructor(key: Uint8Array) {
    if (!(key instanceof Uint8Array) || key.length !== 32) throw new DocumentError("32 bytes expected", "save key");
    this.#key = new Uint8Array(key);
  }

  /** A new save key, from the platform's secure random source. */
  static generate(): SaveKey {
    const raw = randomBytes(32);
    try {
      return new SaveKey(raw);
    } finally {
      raw.fill(0);
    }
  }

  /** The key a recovery phrase carries; KeyPhraseError when it is not one, or its check does not match. */
  static fromPhrase(phrase: string): SaveKey {
    const text = phrase.toUpperCase().replace(/[\s-]+/g, "");
    if (text.length !== SYMBOLS)
      throw new KeyPhraseError(`a recovery phrase has ${SYMBOLS} symbols, not ${text.length}`);
    const raw = new Uint8Array(35);
    let acc = 0;
    let bits = 0;
    let at = 0;
    for (const symbol of text) {
      const v = CODE_ALPHABET.indexOf(symbol);
      if (v < 0) throw new KeyPhraseError(`${JSON.stringify(symbol)} is not a symbol of a recovery phrase`);
      acc = ((acc << 5) | v) & 0xfff;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        raw[at++] = (acc >>> bits) & 0xff;
      }
    }
    const key = raw.subarray(0, 32);
    const check = checksum(key);
    try {
      if (!equalBytes(check, raw.subarray(32))) {
        throw new KeyPhraseError("the recovery phrase's check does not match: a symbol is mistyped");
      }
      return new SaveKey(key);
    } finally {
      raw.fill(0);
      check.fill(0);
    }
  }

  /** The key a QR code's text carries (`LANTERN-SAVE-KEY-1:` and its 56 symbols). */
  static fromQr(text: string): SaveKey {
    if (!text.startsWith(QR_PREFIX)) throw new KeyPhraseError(`a save key's QR text begins with ${QR_PREFIX}`);
    const rest = text.slice(QR_PREFIX.length);
    if (!/^[0-9A-Z]{56}$/.test(rest)) throw new KeyPhraseError("a save key's QR text is 56 symbols after its prefix");
    return SaveKey.fromPhrase(rest);
  }

  #raw(): Uint8Array {
    if (this.#wiped) throw new LanternError("this save key was wiped");
    return this.#key;
  }

  /** A copy of the key's 32 bytes, to keep where the system protects keys; wipe it after. */
  bytes(): Uint8Array {
    return new Uint8Array(this.#raw());
  }

  /** The 56 symbols of key and check. */
  #symbols(): string {
    const raw = concat([this.#raw(), checksum(this.#raw())]);
    try {
      return symbols(raw);
    } finally {
      raw.fill(0);
    }
  }

  /** The recovery phrase: 14 groups of 4 symbols. Show it only when the user asks (L-9.4-8). */
  phrase(): string {
    return (this.#symbols().match(/.{4}/g) ?? []).join("-");
  }

  /** The QR code's text, in the QR code's alphanumeric mode. Show it only when the user asks (L-9.4-8). */
  qr(): string {
    return QR_PREFIX + this.#symbols();
  }

  /** Its id: the first 8 bytes of HKDF(info `lantern-save-e2e-1 key id`), 16 hex digits, the one thing sent. */
  async keyId(): Promise<string> {
    const id = await hkdfSha256(this.#raw(), INFO_KEY_ID, 8);
    return toHex(id);
  }

  /** The wrapping key: 32 bytes of HKDF(info `lantern-save-e2e-1 wrap`). Wipe it after. */
  wrappingKey(): Promise<Uint8Array> {
    return hkdfSha256(this.#raw(), INFO_WRAP, 32);
  }

  /** The `encryption` a backup made with this key is sent with. */
  async encryption(): Promise<Encryption> {
    return { scheme: SCHEME, key_id: await this.keyId() };
  }

  /** Zeroes the key: it can no longer be used. */
  wipe(): void {
    this.#key.fill(0);
    this.#wiped = true;
  }
}

/** For the specification's test vectors alone: a backup's file key and wrap nonce, which are random otherwise. */
export interface FixedRandom {
  fileKey?: Uint8Array;
  wrapNonce?: Uint8Array;
}

/** The header of a backup, and its file key (wipe it after). */
async function makeHeader(key: SaveKey, fixed: FixedRandom = {}): Promise<{ header: Uint8Array; fileKey: Uint8Array }> {
  const fileKey = fixed.fileKey !== undefined ? new Uint8Array(fixed.fileKey) : randomBytes(32);
  const nonce = fixed.wrapNonce !== undefined ? new Uint8Array(fixed.wrapNonce) : randomBytes(24);
  if (fileKey.length !== 32 || nonce.length !== 24) throw new RangeError("a file key of 32 bytes, a nonce of 24");
  const id = fromHex(await key.keyId());
  const head = concat([MAGIC, id]);
  const wrapping = await key.wrappingKey();
  try {
    const sealed = xchacha20poly1305Seal(wrapping, nonce, fileKey, head);
    return { header: concat([head, nonce, sealed]), fileKey };
  } finally {
    wrapping.fill(0);
  }
}

/**
 * An encrypted backup in the making, with random access to its bytes: what a
 * resumable upload (§ 9.3) reads, again and again, to the same bytes, without
 * the encrypted file kept anywhere (L-9.4-3). It holds the file key until
 * wipe(): call it once the upload is done or given up.
 */
export class EncryptedBackup {
  readonly header: Uint8Array;
  readonly encryption: Encryption;
  /** The archive's size. */
  readonly archiveSize: number;
  /** The encrypted backup's size. */
  readonly size: number;
  readonly #fileKey: Uint8Array;
  readonly #archive: (offset: number, length: number) => Promise<Uint8Array>;
  #wiped = false;

  private constructor(
    header: Uint8Array,
    fileKey: Uint8Array,
    encryption: Encryption,
    archiveSize: number,
    archive: (offset: number, length: number) => Promise<Uint8Array>,
  ) {
    this.header = header;
    this.#fileKey = fileKey;
    this.encryption = encryption;
    this.archiveSize = archiveSize;
    this.size = encryptedSize(archiveSize);
    this.#archive = archive;
  }

  /**
   * A backup of an archive read by range (`read(offset, length)`, as an
   * UploadSource gives it), with a new file key and wrap nonce (L-9.4-3).
   */
  static async create(
    key: SaveKey,
    archive: { size: number; read(offset: number, length: number): Promise<Uint8Array> },
    fixed?: FixedRandom,
  ): Promise<EncryptedBackup> {
    const { header, fileKey } = await makeHeader(key, fixed);
    return new EncryptedBackup(header, fileKey, await key.encryption(), archive.size, (o, l) => archive.read(o, l));
  }

  /** Chunk `i` sealed: its bytes, then its tag. */
  async sealedChunk(i: number): Promise<Uint8Array> {
    if (this.#wiped) throw new LanternError("this backup's file key was wiped");
    const count = chunkCount(this.archiveSize);
    if (i < 0 || i >= count) throw new RangeError("no such chunk");
    const start = i * CHUNK;
    const length = Math.min(CHUNK, this.archiveSize - start);
    const plain = length > 0 ? await this.#archive(start, length) : new Uint8Array();
    if (plain.length !== length)
      throw new LanternError(`the archive gave ${plain.length} bytes at ${start}, not ${length}`);
    return xchacha20poly1305Seal(this.#fileKey, chunkNonce(i, i === count - 1), plain, this.header);
  }

  /** `length` bytes of the encrypted backup from `offset`: an UploadSource's read(). */
  async read(offset: number, length: number): Promise<Uint8Array> {
    const end = Math.min(this.size, offset + length);
    const parts: Uint8Array[] = [];
    let at = offset;
    if (at < HEADER) {
      parts.push(this.header.subarray(at, Math.min(HEADER, end)));
      at = HEADER;
    }
    const record = CHUNK + TAG;
    while (at < end) {
      const i = Math.floor((at - HEADER) / record);
      const first = HEADER + i * record;
      const sealed = await this.sealedChunk(i);
      parts.push(sealed.subarray(at - first, Math.min(sealed.length, end - first)));
      at = first + sealed.length;
    }
    return concat(parts);
  }

  /** The whole backup, chunk after chunk, header first. */
  async *stream(): AsyncGenerator<Uint8Array> {
    yield this.header;
    for (let i = 0; i < chunkCount(this.archiveSize); i++) yield await this.sealedChunk(i);
  }

  /** Zeroes the file key. */
  wipe(): void {
    this.#fileKey.fill(0);
    this.#wiped = true;
  }
}

/** An archive as chunks of any size, cut again into the scheme's chunks of 64 KiB. */
async function* rechunk(source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>): AsyncGenerator<Uint8Array> {
  let buffer = new Uint8Array(CHUNK);
  let held = 0;
  for await (const piece of source) {
    let at = 0;
    while (at < piece.length) {
      const n = Math.min(CHUNK - held, piece.length - at);
      buffer.set(piece.subarray(at, at + n), held);
      held += n;
      at += n;
      if (held === CHUNK) {
        yield buffer;
        buffer = new Uint8Array(CHUNK);
        held = 0;
      }
    }
  }
  if (held > 0) yield buffer.subarray(0, held);
  else buffer.fill(0);
}

/**
 * Encrypts an archive as a stream (the header, then each chunk sealed), with
 * a new file key and wrap nonce (`fixed` is for the test vectors alone). Each
 * plaintext chunk is zeroed once sealed; so is the file key at the end.
 */
export async function* encrypt(
  key: SaveKey,
  archive: AsyncIterable<Uint8Array> | Iterable<Uint8Array> | Uint8Array,
  fixed?: FixedRandom,
): AsyncGenerator<Uint8Array> {
  const { header, fileKey } = await makeHeader(key, fixed);
  try {
    yield header;
    const source = archive instanceof Uint8Array ? [archive] : archive;
    let i = 0;
    let pending: Uint8Array | undefined;
    for await (const chunk of rechunk(source)) {
      if (pending !== undefined) {
        yield xchacha20poly1305Seal(fileKey, chunkNonce(i++, false), pending, header);
        pending.fill(0);
      }
      pending = chunk;
    }
    yield xchacha20poly1305Seal(fileKey, chunkNonce(i, true), pending ?? new Uint8Array(), header);
    pending?.fill(0);
  } finally {
    fileKey.fill(0);
  }
}

/** encrypt() into one array. */
export async function encryptBytes(key: SaveKey, archive: Uint8Array, fixed?: FixedRandom): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const part of encrypt(key, archive, fixed)) parts.push(part);
  return concat(parts);
}

/** The key id a backup's header names, or undefined when it is not a backup of this scheme. */
export function keyIdOf(header: Uint8Array): string | undefined {
  if (header.length < 16 || !equalBytes(header.subarray(0, 8), MAGIC)) return undefined;
  return toHex(header.subarray(8, 16));
}

/**
 * Decrypts a backup as a stream, each chunk given once its tag verified. The
 * last chunk is known only at the end, so a backup cut short or that goes on
 * after its last chunk throws DecryptionError only then: keep what this gives
 * aside (a `.part` file, memory) and restore it only once the iteration ended
 * without an error (L-9.4-1); decryptBytes() does so in memory.
 */
export async function* decrypt(
  key: SaveKey,
  backup: AsyncIterable<Uint8Array> | Iterable<Uint8Array> | Uint8Array,
): AsyncGenerator<Uint8Array> {
  const source = backup instanceof Uint8Array ? [backup] : backup;
  const record = CHUNK + TAG;
  let buffer: Uint8Array = new Uint8Array(0);
  let header: Uint8Array | undefined;
  let fileKey: Uint8Array | undefined;
  let i = 0;
  const take = (n: number): Uint8Array => {
    const out = buffer.slice(0, n);
    buffer = buffer.slice(n);
    return out;
  };
  try {
    for await (const piece of source) {
      buffer = buffer.length === 0 ? new Uint8Array(piece) : concat([buffer, piece]);
      if (header === undefined) {
        if (buffer.length < HEADER) continue;
        header = take(HEADER);
        fileKey = await openHeader(key, header);
      }
      // A full record followed by more bytes is not the last one.
      while (buffer.length > record) {
        const plain = xchacha20poly1305Open(fileKey as Uint8Array, chunkNonce(i, false), take(record), header);
        if (plain === undefined) throw new DecryptionError(`chunk ${i} does not open: the backup was changed`);
        i++;
        yield plain;
      }
    }
    if (header === undefined) throw new DecryptionError("not an encrypted backup: shorter than its header");
    if (buffer.length < TAG) throw new DecryptionError("the backup ends without its last chunk");
    const plain = xchacha20poly1305Open(fileKey as Uint8Array, chunkNonce(i, true), buffer, header);
    if (plain === undefined) {
      throw new DecryptionError(`the last chunk (${i}) does not open: the backup was cut, changed or goes on after it`);
    }
    yield plain;
  } finally {
    fileKey?.fill(0);
  }
}

async function openHeader(key: SaveKey, header: Uint8Array): Promise<Uint8Array> {
  if (!equalBytes(header.subarray(0, 8), MAGIC))
    throw new DecryptionError("not an encrypted backup of lantern-save-e2e-1");
  const id = toHex(header.subarray(8, 16));
  const mine = await key.keyId();
  if (id !== mine) throw new DecryptionError(`the backup needs the key ${id}, not this one (${mine})`);
  const wrapping = await key.wrappingKey();
  try {
    const fileKey = xchacha20poly1305Open(
      wrapping,
      header.subarray(16, 40),
      header.subarray(40, 88),
      header.subarray(0, 16),
    );
    if (fileKey === undefined) throw new DecryptionError("the backup's header does not open: it was changed");
    return fileKey;
  } finally {
    wrapping.fill(0);
  }
}

/** The archive of a backup, all or nothing: DecryptionError when any of it does not open. */
export async function decryptBytes(key: SaveKey, backup: Uint8Array): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  try {
    for await (const part of decrypt(key, backup)) parts.push(part);
  } catch (e) {
    for (const part of parts) part.fill(0);
    throw e;
  }
  const out = concat(parts);
  for (const part of parts) part.fill(0);
  return out;
}

/** The `Lantern-Save-Encryption` header of a backup sent in one request (§ 9.2). */
export function encryptionHeader(encryption: Encryption): string {
  if (encryption.scheme !== SCHEME || !KEY_ID.test(encryption.key_id))
    throw new RangeError("not an encryption of this scheme");
  return `${encryption.scheme}; key_id=${encryption.key_id}`;
}
