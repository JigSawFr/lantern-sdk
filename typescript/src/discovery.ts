/**
 * LAN discovery (SPEC.md § 4.1): the datagram a client sends on UDP 47115, and
 * the replies it reads. The sockets are Node's (`lantern-protocol/node`'s
 * `discover()`); a browser has no UDP.
 *
 * Discovery is a hint: it gives an address and a name, nothing more. A reply
 * proves nothing; the client trusts a server only through TLS and pairing
 * (§ 5, L-4.1-5). A reply is read by the `schema` rule: one of a newer schema
 * is absent, and a reply this library cannot read is left out.
 */

import { isObject, SCHEMA } from "./base.ts";
import { fromUtf8, utf8 } from "./bytes.ts";
import { DATAGRAM, NAME, printable } from "./limits.ts";
import { type Peer, peerUrl } from "./peers.ts";

export const PORT = 47115;
/** The request a client sends (SPEC.md § 4.1). */
export const REQUEST: Uint8Array = utf8(JSON.stringify({ schema: SCHEMA, lantern: "discover" }));
/** The DNS-SD service type (RFC 6763). */
export const SERVICE = "_lantern._tcp.local.";

/** A server that answered: the reply's source `address`, its HTTPS `port`, and its handshake's `uid`, `name`, `base` and `versions`. */
export interface Found {
  address: string;
  port: number;
  uid: string;
  name: string;
  base: string;
  versions: number[];
  /** The server's address, for the handshake over TLS. */
  url: string;
}

/**
 * The broadcast address of `address`'s network (`192.168.1.255` for
 * `192.168.1.20`/24): where a client sends the datagram, since some consoles
 * drop `255.255.255.255`.
 */
export function directedBroadcast(address: string, prefix: number): string {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255) || prefix < 0 || prefix > 32) {
    throw new RangeError(`${address}/${prefix} is not an IPv4 network`);
  }
  const n = parts.reduce((acc, p) => acc * 256 + p, 0);
  const hostBits = 2 ** (32 - prefix);
  const broadcast = Math.floor(n / hostBits) * hostBits + hostBits - 1;
  return [24, 16, 8, 0].map((s) => Math.floor(broadcast / 2 ** s) % 256).join(".");
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

/**
 * A server's reply (SPEC.md § 4.1), or undefined when it is not one this library
 * reads: above 1200 bytes, not UTF-8 JSON, of a newer schema, not a server's,
 * or with a field not of its form.
 */
export function readReply(data: Uint8Array, address: string): Found | undefined {
  if (data.length > DATAGRAM) return undefined;
  let doc: unknown;
  try {
    doc = JSON.parse(fromUtf8(data));
  } catch {
    return undefined;
  }
  if (!isObject(doc)) return undefined;
  const { schema, port, versions, uid, name, base } = doc;
  if (typeof schema !== "number" || !Number.isInteger(schema) || schema < 1 || schema > SCHEMA) return undefined;
  if (doc["lantern"] !== "server" || typeof uid !== "string" || uid.length < 1 || uid.length > 64) return undefined;
  if (typeof name !== "string" || !baseOk(base) || typeof port !== "number" || !Number.isInteger(port))
    return undefined;
  if (port < 1 || port > 65535 || !Array.isArray(versions) || versions.length === 0) return undefined;
  if (!versions.every((v) => typeof v === "number" && Number.isInteger(v) && v >= 1)) return undefined;
  const host = address.includes(":") ? `[${address}]` : address;
  return {
    address,
    port,
    uid,
    name: printable(name, NAME).replaceAll("\n", " "),
    base,
    versions: versions as number[],
    url: port === 443 ? `https://${host}/` : `https://${host}:${port}/`,
  };
}

/** The request that also asks the peers of the network (SPEC.md § 19.5). */
export const PEERS_REQUEST: Uint8Array = utf8(JSON.stringify({ schema: SCHEMA, lantern: "discover", peers: true }));

/**
 * A peer's reply (SPEC.md § 19.5), or undefined when it is not one this
 * library reads: above 1200 bytes, of a newer schema, not a peer's, with a
 * field not of its form, or plain HTTP from an address outside a private
 * network (a grant never goes there, L-19.4-6). A hint, as any reply.
 */
export function readPeerReply(data: Uint8Array, address: string): Peer | undefined {
  if (data.length > DATAGRAM) return undefined;
  let doc: unknown;
  try {
    doc = JSON.parse(fromUtf8(data));
  } catch {
    return undefined;
  }
  if (!isObject(doc)) return undefined;
  const { schema, port, uid, name, base, tls, slots, servers } = doc;
  if (typeof schema !== "number" || !Number.isInteger(schema) || schema < 1 || schema > SCHEMA) return undefined;
  if (doc["lantern"] !== "peer" || typeof uid !== "string" || uid.length < 1 || uid.length > 64) return undefined;
  if (typeof name !== "string" || !baseOk(base) || typeof tls !== "boolean") return undefined;
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  if (typeof slots !== "number" || !Number.isInteger(slots) || slots < 1 || slots > 8) return undefined;
  if (!Array.isArray(servers) || servers.length > 16 || !servers.every((s) => typeof s === "string" && s.length <= 64))
    return undefined;
  let url: string;
  try {
    url = peerUrl(address, port, base, tls);
  } catch {
    return undefined;
  }
  return {
    address,
    port,
    base,
    tls,
    uid,
    name: printable(name, NAME).replaceAll("\n", " "),
    slots,
    servers: servers as string[],
    url,
  };
}
