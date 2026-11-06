/**
 * DNS-SD (RFC 6763) over multicast DNS (RFC 6762), the client's side of
 * SPEC.md § 4.1 (`_lantern._tcp`: `uid=`, `path=`, `v=`) and § 19.5
 * (`_lantern-peer._tcp`: `servers=`, `path=`, `v=`, `tls=`): the questions a
 * client asks and the answers it reads, with no socket and no dependency.
 *
 * A client asks once, from a port that is not 5353: RFC 6762 § 6.7 has a
 * responder answer such a question straight back to its sender (a "legacy
 * unicast" answer), so the client joins no multicast group and keeps no
 * state between two browses. What it reads is a hint, as any discovery:
 * nothing is trusted but through TLS and pairing (L-4.1-5). A message that
 * is cut, loops, or says more than it can hold is left out, never an error.
 */

import { fromUtf8, utf8 } from "./bytes.ts";
import type { Found } from "./discovery.ts";
import { NAME, printable } from "./limits.ts";
import { type Peer, peerUrl } from "./peers.ts";

/** The service of a server (§ 4.1). */
export const SERVER_SERVICE = "_lantern._tcp.local.";
/** The service of a peer (§ 19.5). */
export const PEER_SERVICE = "_lantern-peer._tcp.local.";
/** The group multicast DNS questions go to, and its port (RFC 6762 § 3). */
export const MDNS_ADDRESS = "224.0.0.251";
export const MDNS_PORT = 5353;

const A = 1;
/** The record type of a service's instances. */
export const PTR = 12;
const TXT = 16;
const AAAA = 28;
const SRV = 33;
/** Any record: what asks an instance for its SRV and its TXT at once. */
export const ANY = 255;

/** What a message may hold: bytes, records, and the instances a browse keeps. */
const MAX_MESSAGE = 9000;
const MAX_RECORDS = 512;
const MAX_INSTANCES = 64;
const MAX_JUMPS = 64;
const MAX_NAME = 255;

type Name = readonly string[];

/** A question: `name` (dotted, `.local.` at its end) of record type `type`, class IN, with the ID given. */
export function question(name: string, type: number, id = 1): Uint8Array {
  const labels = name.split(".").filter((l) => l.length > 0);
  const parts: Uint8Array[] = [];
  for (const label of labels) {
    const bytes = utf8(label);
    if (bytes.length > 63) throw new RangeError(`${label}: a DNS label is at most 63 bytes`);
    parts.push(Uint8Array.of(bytes.length), bytes);
  }
  const head = new Uint8Array(12);
  new DataView(head.buffer).setUint16(0, id);
  new DataView(head.buffer).setUint16(4, 1);
  const tail = new Uint8Array(5);
  new DataView(tail.buffer).setUint16(1, type);
  new DataView(tail.buffer).setUint16(3, 1);
  const out = new Uint8Array(12 + parts.reduce((n, p) => n + p.length, 0) + 5);
  let at = 0;
  for (const part of [head, ...parts, tail]) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** A question for one instance whose SRV or TXT an answer did not carry: its labels are kept as they came. */
export function instanceQuestion(instance: Name, id = 1): Uint8Array {
  return question(instance.map((l) => l.replaceAll(".", "\\.")).join("."), ANY, id);
}

interface Answer {
  name: Name;
  type: number;
  ttl: number;
  rdata: Uint8Array;
  /** Where the RDATA starts in the message: a name in it may point back. */
  start: number;
  message: Uint8Array;
}

const lenient = new TextDecoder("utf-8", { fatal: false });

/** A name at `at` of `message`, compressed or not (RFC 1035 § 4.1.4), and where the next field starts. */
function readName(message: Uint8Array, at: number): { name: Name; next: number } | undefined {
  const labels: string[] = [];
  let next = -1;
  let size = 0;
  let jumps = 0;
  let pos = at;
  for (;;) {
    if (pos >= message.length) return undefined;
    const length = message[pos] as number;
    if ((length & 0xc0) === 0xc0) {
      if (pos + 1 >= message.length) return undefined;
      const target = ((length & 0x3f) << 8) | (message[pos + 1] as number);
      if (next < 0) next = pos + 2;
      // A pointer goes back, and not for ever: a loop is a message to drop
      if (target >= pos || ++jumps > MAX_JUMPS) return undefined;
      pos = target;
    } else if ((length & 0xc0) !== 0) {
      return undefined;
    } else if (length === 0) {
      return { name: labels, next: next < 0 ? pos + 1 : next };
    } else {
      if (pos + 1 + length > message.length) return undefined;
      size += length + 1;
      if (size > MAX_NAME || labels.length >= 127) return undefined;
      labels.push(lenient.decode(message.subarray(pos + 1, pos + 1 + length)));
      pos += 1 + length;
    }
  }
}

/** The records of an answer of multicast DNS (RFC 6762 § 6): from its answers, authority and additional sections. */
export function readMessage(message: Uint8Array): Answer[] | undefined {
  if (message.length < 12 || message.length > MAX_MESSAGE) return undefined;
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
  // A response, of the standard query's opcode, with no error
  const flags = view.getUint16(2);
  if ((flags & 0x8000) === 0 || (flags & 0x7800) !== 0 || (flags & 0x000f) !== 0) return undefined;
  const questions = view.getUint16(4);
  const total = view.getUint16(6) + view.getUint16(8) + view.getUint16(10);
  if (questions > 16 || total > MAX_RECORDS) return undefined;
  let at = 12;
  for (let i = 0; i < questions; i++) {
    const name = readName(message, at);
    if (name === undefined || name.next + 4 > message.length) return undefined;
    at = name.next + 4;
  }
  const records: Answer[] = [];
  for (let i = 0; i < total; i++) {
    const name = readName(message, at);
    if (name === undefined || name.next + 10 > message.length) return undefined;
    const type = view.getUint16(name.next);
    const ttl = view.getUint32(name.next + 4);
    const length = view.getUint16(name.next + 8);
    const start = name.next + 10;
    if (start + length > message.length) return undefined;
    records.push({ name: name.name, type, ttl, rdata: message.subarray(start, start + length), start, message });
    at = start + length;
  }
  return records;
}

/** A name, as a key: DNS names are not case-sensitive. */
function key(name: Name): string {
  return name.map((l) => l.toLowerCase().replaceAll(".", "\\.")).join(".");
}

function ipv4(rdata: Uint8Array): string | undefined {
  return rdata.length === 4 ? [...rdata].join(".") : undefined;
}

/** An IPv6 address as text, its longest run of zero groups as `::` (RFC 5952). */
export function ipv6(rdata: Uint8Array): string | undefined {
  if (rdata.length !== 16) return undefined;
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((rdata[i] as number) << 8) | (rdata[i + 1] as number));
  let best = -1;
  let bestLength = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) [best, bestLength] = [i, j - i];
    i = j;
  }
  const hex = (g: number[]): string => g.map((n) => n.toString(16)).join(":");
  if (bestLength < 2) return hex(groups);
  return `${hex(groups.slice(0, best))}::${hex(groups.slice(best + bestLength))}`;
}

/** A TXT record's pairs (RFC 6763 § 6): keys in lower case, a key with no `=` having no value. */
function readTxt(rdata: Uint8Array): Map<string, Uint8Array | undefined> {
  const pairs = new Map<string, Uint8Array | undefined>();
  let at = 0;
  while (at < rdata.length && pairs.size < 64) {
    const length = rdata[at] as number;
    const entry = rdata.subarray(at + 1, at + 1 + length);
    at += 1 + length;
    if (entry.length !== length || length === 0) break;
    const eq = entry.indexOf(0x3d);
    const name = lenient.decode(eq < 0 ? entry : entry.subarray(0, eq)).toLowerCase();
    // The first of a key counts (RFC 6763 § 6.4)
    if (name.length > 0 && !pairs.has(name)) pairs.set(name, eq < 0 ? undefined : entry.slice(eq + 1));
  }
  return pairs;
}

function text(txt: ReadonlyMap<string, Uint8Array | undefined>, name: string): string | undefined {
  const value = txt.get(name);
  if (value === undefined) return undefined;
  try {
    return fromUtf8(value);
  } catch {
    return undefined;
  }
}

function baseOk(base: unknown): base is string {
  return (
    typeof base === "string" &&
    base.startsWith("/") &&
    !base.startsWith("//") &&
    base.length <= 256 &&
    /^[\x21-\x7e]*$/.test(base) &&
    !/[?#\\]/.test(base)
  );
}

function urlOf(address: string, port: number): string {
  const host = address.includes(":") ? `[${address}]` : address;
  return port === 443 ? `https://${host}/` : `https://${host}:${port}/`;
}

/**
 * A server's advertisement (SPEC.md § 4.1: `uid=`, `path=`, `v=`), or undefined
 * when it is not one this library reads.
 */
export function fromTxt(
  address: string,
  port: number,
  txt: ReadonlyMap<string, Uint8Array | undefined>,
  name: string,
): Found | undefined {
  const uid = text(txt, "uid");
  const path = text(txt, "path");
  const v = text(txt, "v");
  if (!uid || uid.length > 64 || !baseOk(path) || !v || !Number.isInteger(port) || port < 1 || port > 65535)
    return undefined;
  const versions = v.split(",").map((s) => (/^[0-9]+$/.test(s) ? Number(s) : Number.NaN));
  if (versions.length === 0 || versions.some((n) => !Number.isInteger(n) || n < 1)) return undefined;
  return {
    address,
    port,
    uid,
    name: printable(name, NAME).replaceAll("\n", " "),
    base: path,
    versions,
    url: urlOf(address, port),
  };
}

/** A peer's advertisement (SPEC.md § 19.5: `servers=`, `path=`, `v=`, `tls=`), or undefined. */
export function peerFromTxt(
  address: string,
  port: number,
  txt: ReadonlyMap<string, Uint8Array | undefined>,
  name: string,
): Peer | undefined {
  const servers = text(txt, "servers");
  const path = text(txt, "path");
  const v = text(txt, "v");
  const tls = text(txt, "tls");
  if (
    !servers ||
    !baseOk(path) ||
    !v ||
    (tls !== "0" && tls !== "1") ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535
  )
    return undefined;
  const uids = servers.split(",").filter((u) => u.length > 0);
  if (uids.length < 1 || uids.length > 16 || uids.some((u) => u.length > 64) || !v.split(",").includes("1"))
    return undefined;
  const label = printable(name, NAME).replaceAll("\n", " ");
  let url: string;
  try {
    url = peerUrl(address, port, path, tls === "1");
  } catch {
    return undefined;
  }
  return {
    address,
    port,
    base: path.replace(/\/+$/, ""),
    tls: tls === "1",
    uid: label,
    name: label,
    slots: 1,
    servers: uids,
    url,
  };
}

interface Seen {
  labels: Name;
  from: string;
  port?: number;
  target?: string;
  txt?: Map<string, Uint8Array | undefined>;
}

/**
 * What the answers to a browse say, gathered: each is added with the address
 * it came from, which stands for a server whose answer holds no address of its
 * own. A goodbye (a TTL of 0) forgets an instance.
 */
export class Browse {
  readonly service: string;
  readonly #instances = new Map<string, Seen>();
  readonly #addresses = new Map<string, { v4: string[]; v6: string[] }>();
  readonly #suffix: string;

  constructor(service: string) {
    this.service = service;
    this.#suffix = key(service.split(".").filter((l) => l.length > 0));
  }

  add(message: Uint8Array, from: string): void {
    const records = readMessage(message);
    if (records === undefined) return;
    for (const record of records) {
      const owner = key(record.name);
      if (record.type === PTR && owner === this.#suffix) {
        const instance = readName(record.message, record.start);
        if (instance === undefined || instance.name.length < 1 || key(instance.name.slice(1)) !== this.#suffix)
          continue;
        const name = key(instance.name);
        if (record.ttl === 0) this.#instances.delete(name);
        else if (this.#instances.has(name) || this.#instances.size < MAX_INSTANCES)
          this.#instances.set(name, { ...this.#instances.get(name), labels: instance.name, from });
      } else if (record.type === SRV && record.rdata.length >= 7) {
        const seen = this.#instances.get(owner);
        const target = readName(record.message, record.start + 6);
        if (seen === undefined || target === undefined) continue;
        seen.port = new DataView(record.rdata.buffer, record.rdata.byteOffset, 6).getUint16(4);
        seen.target = key(target.name);
        seen.from = from;
      } else if (record.type === TXT) {
        const seen = this.#instances.get(owner);
        if (seen !== undefined) seen.txt = readTxt(record.rdata);
      } else if (record.type === A || record.type === AAAA) {
        const address = record.type === A ? ipv4(record.rdata) : ipv6(record.rdata);
        if (address === undefined) continue;
        const kept = this.#addresses.get(owner) ?? { v4: [], v6: [] };
        const list = record.type === A ? kept.v4 : kept.v6;
        if (!list.includes(address) && list.length < 8) list.push(address);
        this.#addresses.set(owner, kept);
      }
    }
  }

  /** The instances whose port or TXT has not come: ask each for them. */
  incomplete(): Name[] {
    return [...this.#instances.values()]
      .filter((s) => s.port === undefined || s.txt === undefined)
      .map((s) => s.labels);
  }

  #addressOf(seen: Seen): string {
    const kept = seen.target === undefined ? undefined : this.#addresses.get(seen.target);
    return kept?.v4[0] ?? kept?.v6[0] ?? seen.from;
  }

  /** The servers found: one a uid, by the first instance that says it. */
  servers(): Found[] {
    const found = new Map<string, Found>();
    for (const seen of this.#instances.values()) {
      if (seen.port === undefined || seen.txt === undefined) continue;
      const server = fromTxt(this.#addressOf(seen), seen.port, seen.txt, seen.labels[0] ?? "");
      if (server !== undefined && !found.has(server.uid)) found.set(server.uid, server);
    }
    return [...found.values()];
  }

  /** The peers found: one for each instance, which names it. */
  peers(): Peer[] {
    const found = new Map<string, Peer>();
    for (const seen of this.#instances.values()) {
      if (seen.port === undefined || seen.txt === undefined) continue;
      const peer = peerFromTxt(this.#addressOf(seen), seen.port, seen.txt, seen.labels[0] ?? "");
      if (peer !== undefined && !found.has(`${peer.name} ${peer.address}`))
        found.set(`${peer.name} ${peer.address}`, peer);
    }
    return [...found.values()];
  }
}
