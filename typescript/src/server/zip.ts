/**
 * Zip archives, just enough for a server: reading the files of an archive (to
 * make a homebrew package's manifest, SPEC.md § 8.2) and writing one (demos
 * and tests). Stored and deflated entries; no zip64, no encryption.
 */

import * as zlib from "node:zlib";

export interface ZipFile {
  name: string;
  data: Uint8Array;
}

const MAX_ENTRIES = 65535;

/** The files of an archive (folders left out); a RangeError for one this reader cannot read. */
export function readZip(archive: Uint8Array): ZipFile[] {
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  let end = -1;
  for (let i = archive.length - 22; i >= Math.max(0, archive.length - 22 - 65535); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      end = i;
      break;
    }
  }
  if (end < 0) throw new RangeError("not a zip archive");
  const count = view.getUint16(end + 10, true);
  let at = view.getUint32(end + 16, true);
  if (count > MAX_ENTRIES) throw new RangeError("too many entries");
  const out: ZipFile[] = [];
  const decoder = new TextDecoder();
  for (let i = 0; i < count; i++) {
    if (at + 46 > archive.length || view.getUint32(at, true) !== 0x02014b50)
      throw new RangeError("a broken central directory");
    const method = view.getUint16(at + 10, true);
    const compressed = view.getUint32(at + 20, true);
    const size = view.getUint32(at + 24, true);
    const nameLength = view.getUint16(at + 28, true);
    const extra = view.getUint16(at + 30, true);
    const comment = view.getUint16(at + 32, true);
    const local = view.getUint32(at + 42, true);
    const name = decoder.decode(archive.subarray(at + 46, at + 46 + nameLength));
    at += 46 + nameLength + extra + comment;
    if (name.endsWith("/")) continue;
    if (local + 30 > archive.length || view.getUint32(local, true) !== 0x04034b50)
      throw new RangeError("a broken local header");
    const start = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true);
    const raw = archive.subarray(start, start + compressed);
    let data: Uint8Array;
    if (method === 0) data = raw;
    else if (method === 8) data = new Uint8Array(zlib.inflateRawSync(raw, { maxOutputLength: Math.max(size, 1) }));
    else throw new RangeError(`compression method ${method}`);
    if (data.length !== size) throw new RangeError(`${name}: not its size`);
    out.push({ name, data });
  }
  return out;
}

/** An archive of `files`, deflated, with a fixed time (the same bytes each run). */
export function writeZip(files: readonly ZipFile[]): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const time = (12 << 11) | (0 << 5);
  const date = ((2026 - 1980) << 9) | (10 << 5) | 30;
  for (const f of files) {
    const name = encoder.encode(f.name);
    const deflated = new Uint8Array(zlib.deflateRawSync(f.data));
    const crc = zlib.crc32(f.data);
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, 0x0800, true);
    local.setUint16(8, 8, true);
    local.setUint16(10, time, true);
    local.setUint16(12, date, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, deflated.length, true);
    local.setUint32(22, f.data.length, true);
    local.setUint16(26, name.length, true);
    parts.push(new Uint8Array(local.buffer), name, deflated);
    const c = new DataView(new ArrayBuffer(46));
    c.setUint32(0, 0x02014b50, true);
    c.setUint16(4, (3 << 8) | 20, true);
    c.setUint16(6, 20, true);
    c.setUint16(8, 0x0800, true);
    c.setUint16(10, 8, true);
    c.setUint16(12, time, true);
    c.setUint16(14, date, true);
    c.setUint32(16, crc, true);
    c.setUint32(20, deflated.length, true);
    c.setUint32(24, f.data.length, true);
    c.setUint16(28, name.length, true);
    c.setUint32(38, 0o100644 << 16, true);
    c.setUint32(42, offset, true);
    central.push(new Uint8Array(c.buffer), name);
    offset += 30 + name.length + deflated.length;
  }
  const size = central.reduce((n, p) => n + p.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, files.length, true);
  end.setUint16(10, files.length, true);
  end.setUint32(12, size, true);
  end.setUint32(16, offset, true);
  const all = [...parts, ...central, new Uint8Array(end.buffer)];
  const out = new Uint8Array(all.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of all) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
