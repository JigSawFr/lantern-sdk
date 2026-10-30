/**
 * LAN discovery, on the server's side (SPEC.md § 4.1): the reply to a client's
 * datagram, and a responder on UDP 47115.
 *
 *     const responder = await DiscoveryResponder.start(app, { httpsPort: 443 });
 *     …
 *     await responder.stop();
 *
 * A server answers only a datagram it can read, only to addresses of local
 * networks (L-4.1-2), a few times a second at most per address (L-4.1-3), with
 * its handshake's uid, base and versions and its HTTPS port (L-4.1-1). DNS-SD
 * needs an mDNS stack, which Node has not: it is left to the server's own.
 */

import * as dgram from "node:dgram";
import { isIP } from "node:net";
import { isObject, SCHEMA } from "../base.ts";
import { fromUtf8, utf8 } from "../bytes.ts";
import { PORT } from "../discovery.ts";
import { clip, DATAGRAM, NAME } from "../limits.ts";
import type { LanternApp } from "./app.ts";
import { Limiter } from "./pairing.ts";

function v4(address: string): number[] | undefined {
  const parts = address.split(".").map(Number);
  return parts.length === 4 && parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255) ? parts : undefined;
}

/** Whether `address` is of a local network: private, link-local, loopback or shared (never a global one). */
export function isLocalAddress(address: string): boolean {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  const plain = mapped?.[1] ?? address;
  const kind = isIP(plain);
  if (kind === 4) {
    const [a = 0, b = 0] = v4(plain) ?? [];
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (kind === 6) {
    const lower = plain.toLowerCase();
    return lower === "::1" || /^f[cd]/.test(lower) || /^fe[89ab]/.test(lower);
  }
  return false;
}

/** The reply to one datagram from `address`, or undefined to stay silent. */
export function discoveryReply(
  app: LanternApp,
  httpsPort: number,
  data: Uint8Array,
  address: string,
  limiter: Limiter,
): Uint8Array | undefined {
  if (data.length > DATAGRAM || !isLocalAddress(address)) return undefined;
  let doc: unknown;
  try {
    doc = JSON.parse(fromUtf8(data));
  } catch {
    return undefined;
  }
  if (!isObject(doc) || doc["lantern"] !== "discover" || doc["schema"] !== SCHEMA) return undefined; // not one this server can read
  if (limiter.hit(address) > 0) return undefined;
  const raw = utf8(
    JSON.stringify({
      schema: SCHEMA,
      lantern: "server",
      uid: app.uid,
      name: clip(app.name, NAME),
      port: httpsPort,
      base: app.base,
      versions: [1],
    }),
  );
  return raw.length <= DATAGRAM ? raw : undefined;
}

/** Answers discovery datagrams on UDP `port` (47115). */
export class DiscoveryResponder {
  readonly socket: dgram.Socket;
  readonly port: number;

  private constructor(socket: dgram.Socket, port: number) {
    this.socket = socket;
    this.port = port;
  }

  static async start(
    app: LanternApp,
    options: { httpsPort: number; port?: number; host?: string },
  ): Promise<DiscoveryResponder> {
    const limiter = new Limiter(5, 1);
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    socket.on("message", (data, remote) => {
      const reply = discoveryReply(app, options.httpsPort, new Uint8Array(data), remote.address, limiter);
      if (reply !== undefined) socket.send(reply, remote.port, remote.address);
    });
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(options.port ?? PORT, options.host, () => {
        socket.off("error", reject);
        resolve();
      });
    });
    return new DiscoveryResponder(socket, socket.address().port);
  }

  stop(): Promise<void> {
    return new Promise((resolve) => this.socket.close(() => resolve()));
  }
}
