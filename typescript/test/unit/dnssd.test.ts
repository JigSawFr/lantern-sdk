/** DNS-SD (SPEC.md § 4.1, § 19.5): the answers a client reads, hostile ones included, and a browse over loopback. */

import assert from "node:assert/strict";
import * as dgram from "node:dgram";
import { describe, test } from "node:test";
import { dnssd } from "../../src/index.ts";
import { browseDnssd, browseDnssdPeers } from "../../src/node/index.ts";

const enc = new TextEncoder();

/** A name as DNS writes it, each label with its length; `pointer` ends it with a compression pointer instead. */
function name(labels: string[], pointer?: number): number[] {
  const out: number[] = [];
  for (const label of labels) out.push(label.length, ...enc.encode(label));
  return pointer === undefined ? [...out, 0] : [...out, 0xc0 | (pointer >> 8), pointer & 0xff];
}

function u16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}

function u32(n: number): number[] {
  return [...u16(Math.floor(n / 65536)), ...u16(n % 65536)];
}

function record(owner: number[], type: number, rdata: number[], ttl = 120): number[] {
  return [...owner, ...u16(type), ...u16(1), ...u32(ttl), ...u16(rdata.length), ...rdata];
}

function txt(pairs: string[]): number[] {
  return pairs.flatMap((p) => [enc.encode(p).length, ...enc.encode(p)]);
}

/** A response with `records` in its answer section. */
function response(records: number[][], flags = 0x8400): Uint8Array {
  return Uint8Array.from([
    ...u16(0),
    ...u16(flags),
    ...u16(0),
    ...u16(records.length),
    ...u16(0),
    ...u16(0),
    ...records.flat(),
  ]);
}

const SERVICE = ["_lantern", "_tcp", "local"];
const INSTANCE = ["Living room shelf", ...SERVICE];
const HOST = ["shelf", "local"];
const UID = "6f1c2a8e-0000-4000-8000-000000000001";

function srv(port: number, host: number[]): number[] {
  return [...u16(0), ...u16(0), ...u16(port), ...host];
}

/** The whole advertisement of a server: PTR, SRV, TXT and A in one message. */
function advertisement(options: { address?: number[]; port?: number; pairs?: string[] } = {}): Uint8Array {
  return response([
    record(name(SERVICE), 12, name(INSTANCE)),
    record(name(INSTANCE), 33, srv(options.port ?? 8443, name(HOST))),
    record(name(INSTANCE), 16, txt(options.pairs ?? [`uid=${UID}`, "path=/api/lantern", "v=1"])),
    ...(options.address === undefined
      ? [record(name(HOST), 1, [192, 168, 1, 20])]
      : [record(name(HOST), 1, options.address)]),
  ]);
}

describe("DNS-SD answers", () => {
  test("a server's advertisement is a server found, at the address its host says", () => {
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    browse.add(advertisement(), "192.168.1.99");
    assert.deepEqual(browse.servers(), [
      {
        address: "192.168.1.20",
        port: 8443,
        uid: UID,
        name: "Living room shelf",
        base: "/api/lantern",
        versions: [1],
        url: "https://192.168.1.20:8443/",
      },
    ]);
  });

  test("with no address of its own, the one the answer came from stands for it", () => {
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    browse.add(
      response([
        record(name(SERVICE), 12, name(INSTANCE)),
        record(name(INSTANCE), 33, srv(443, name(HOST))),
        record(name(INSTANCE), 16, txt([`uid=${UID}`, "path=/api/lantern", "v=1,2"])),
      ]),
      "192.168.1.77",
    );
    const [found] = browse.servers();
    assert.equal(found?.address, "192.168.1.77");
    assert.equal(found?.url, "https://192.168.1.77/");
    assert.deepEqual(found?.versions, [1, 2]);
  });

  test("an IPv6 address is written short, and names are not case-sensitive", () => {
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    const groups = [0xfe80, 0, 0, 0, 0x1234, 0, 0, 1];
    const rdata = groups.flatMap(u16);
    browse.add(
      response([
        record(name(["_LANTERN", "_TCP", "LOCAL"]), 12, name(["Shelf", "_Lantern", "_tcp", "local"])),
        record(name(["shelf", "_lantern", "_tcp", "LOCAL"]), 33, srv(8443, name(["Shelf", "Local"]))),
        record(name(["SHELF", "_lantern", "_tcp", "local"]), 16, txt([`UID=${UID}`, "Path=/api/lantern", "V=1"])),
        record(name(["shelf", "local"]), 28, rdata),
      ]),
      "fe80::1",
    );
    const [found] = browse.servers();
    assert.equal(found?.address, "fe80::1234:0:0:1");
    assert.equal(found?.url, "https://[fe80::1234:0:0:1]:8443/");
  });

  test("names are compressed as responders write them", () => {
    // PTR, then the instance's SRV and TXT with their owner pointing at the PTR's RDATA
    const head = [...u16(0), ...u16(0x8400), ...u16(0), ...u16(3), ...u16(0), ...u16(0)];
    const ptrOwner = name(SERVICE);
    const ptrData = name(["Shelf"], 12); // "Shelf" then a pointer to the service name at 12
    const ptr = record(ptrOwner, 12, ptrData);
    const instanceAt = 12 + ptrOwner.length + 10; // where the PTR's RDATA, the instance name, starts
    const message = Uint8Array.from([
      ...head,
      ...ptr,
      ...record(name([], instanceAt), 33, srv(8443, name(HOST))),
      ...record(name([], instanceAt), 16, txt([`uid=${UID}`, "path=/api/lantern", "v=1"])),
    ]);
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    browse.add(message, "10.0.0.5");
    assert.equal(browse.servers()[0]?.name, "Shelf");
    assert.equal(browse.servers()[0]?.port, 8443);
  });

  test("a goodbye forgets the instance", () => {
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    browse.add(advertisement(), "192.168.1.99");
    browse.add(response([record(name(SERVICE), 12, name(INSTANCE), 0)]), "192.168.1.99");
    assert.deepEqual(browse.servers(), []);
  });

  test("an instance without its port or its TXT is asked for them", () => {
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    browse.add(response([record(name(SERVICE), 12, name(INSTANCE))]), "192.168.1.99");
    assert.deepEqual(browse.servers(), []);
    assert.deepEqual(browse.incomplete(), [INSTANCE]);
    browse.add(advertisement(), "192.168.1.99");
    assert.deepEqual(browse.incomplete(), []);
    assert.equal(browse.servers().length, 1);
  });

  test("a TXT that is not a server's is left out", () => {
    const bad = [
      [`uid=${UID}`, "v=1"], // no path
      [`uid=${UID}`, "path=//evil", "v=1"],
      [`uid=${UID}`, "path=/a?b", "v=1"],
      ["path=/api/lantern", "v=1"], // no uid
      [`uid=${UID}`, "path=/api/lantern"], // no versions
      [`uid=${UID}`, "path=/api/lantern", "v=one"],
      [`uid=${UID}`, "path=/api/lantern", "v=0"],
      [`uid=${"x".repeat(65)}`, "path=/api/lantern", "v=1"],
    ];
    for (const pairs of bad) {
      const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
      browse.add(advertisement({ pairs }), "192.168.1.99");
      assert.deepEqual(browse.servers(), [], pairs.join(" "));
    }
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    browse.add(advertisement({ port: 0 }), "192.168.1.99");
    assert.deepEqual(browse.servers(), []);
  });

  test("another service's instances are not this one's", () => {
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    browse.add(
      response([
        record(name(["_http", "_tcp", "local"]), 12, name(["Printer", "_http", "_tcp", "local"])),
        record(name(["Printer", "_http", "_tcp", "local"]), 33, srv(80, name(HOST))),
        record(name(["Printer", "_http", "_tcp", "local"]), 16, txt([`uid=${UID}`, "path=/x", "v=1"])),
      ]),
      "192.168.1.5",
    );
    assert.deepEqual(browse.servers(), []);
  });

  test("a peer's advertisement", () => {
    const service = ["_lantern-peer", "_tcp", "local"];
    const instance = ["Den console", ...service];
    const message = (tls: string): Uint8Array =>
      response([
        record(name(service), 12, name(instance)),
        record(name(instance), 33, srv(47116, name(HOST))),
        record(name(instance), 16, txt([`servers=${UID},b`, "path=/peer/", "v=1", `tls=${tls}`])),
        record(name(HOST), 1, [192, 168, 1, 30]),
      ]);
    const browse = new dnssd.Browse(dnssd.PEER_SERVICE);
    browse.add(message("0"), "192.168.1.30");
    assert.deepEqual(browse.peers(), [
      {
        address: "192.168.1.30",
        port: 47116,
        base: "/peer",
        tls: false,
        uid: "Den console",
        name: "Den console",
        slots: 1,
        servers: [UID, "b"],
        url: "http://192.168.1.30:47116/peer",
      },
    ]);
    // Plain HTTP to an address outside a private network is never a peer (L-19.4-6)
    const outside = new dnssd.Browse(dnssd.PEER_SERVICE);
    outside.add(
      response([
        record(name(service), 12, name(instance)),
        record(name(instance), 33, srv(47116, name(HOST))),
        record(name(instance), 16, txt([`servers=${UID}`, "path=/peer", "v=1", "tls=0"])),
        record(name(HOST), 1, [8, 8, 8, 8]),
      ]),
      "8.8.8.8",
    );
    assert.deepEqual(outside.peers(), []);
    const secure = new dnssd.Browse(dnssd.PEER_SERVICE);
    secure.add(message("1"), "192.168.1.30");
    assert.equal(secure.peers()[0]?.url, "https://192.168.1.30:47116/peer");
  });
});

describe("DNS-SD hostile answers", () => {
  const good = advertisement();

  function nothing(message: Uint8Array): void {
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    browse.add(message, "192.168.1.99");
    assert.deepEqual(browse.servers(), []);
  }

  test("a question, or an answer with an error, is not an answer", () => {
    nothing(response([...[record(name(SERVICE), 12, name(INSTANCE))]], 0x0400));
    nothing(Uint8Array.from(good.map((b, i) => (i === 3 ? 0x03 : b))));
    nothing(Uint8Array.from(good.map((b, i) => (i === 2 ? 0xa4 : b))));
  });

  test("a compression pointer that loops, or goes forward, is dropped", () => {
    const self = Uint8Array.from([
      ...u16(0),
      ...u16(0x8400),
      ...u16(0),
      ...u16(1),
      ...u16(0),
      ...u16(0),
      0xc0,
      12,
      ...u16(12),
      ...u16(1),
      ...u32(1),
      ...u16(0),
    ]);
    nothing(self);
    const forward = Uint8Array.from([
      ...u16(0),
      ...u16(0x8400),
      ...u16(0),
      ...u16(1),
      ...u16(0),
      ...u16(0),
      0xc0,
      40,
      ...u16(12),
      ...u16(1),
      ...u32(1),
      ...u16(0),
      ...new Array(40).fill(0),
    ]);
    nothing(forward);
  });

  test("counts the message cannot hold, and labels that do not fit, are dropped", () => {
    nothing(Uint8Array.from(good.map((b, i) => (i === 6 ? 0xff : i === 7 ? 0xff : b))));
    nothing(Uint8Array.from([...good.slice(0, 12), 0x80, 1, 2, 3]));
    nothing(Uint8Array.from([...good.slice(0, 12), 63, ...new Array(10).fill(97)]));
    nothing(new Uint8Array(9001).fill(0x80));
    nothing(new Uint8Array(0));
    nothing(Uint8Array.of(1, 2, 3));
  });

  test("a message cut anywhere, or flipped anywhere, is never an error", () => {
    for (let n = 0; n < good.length; n++) {
      const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
      browse.add(good.slice(0, n), "192.168.1.99");
      browse.servers();
    }
    for (let n = 0; n < good.length; n++) {
      for (const x of [0x01, 0x80, 0xff]) {
        const flipped = good.slice();
        flipped[n] = (flipped[n] as number) ^ x;
        const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
        browse.add(flipped, "192.168.1.99");
        browse.servers();
        browse.incomplete();
      }
    }
  });

  test("a network of instances is bounded", () => {
    const browse = new dnssd.Browse(dnssd.SERVER_SERVICE);
    for (let i = 0; i < 200; i++) {
      browse.add(response([record(name(SERVICE), 12, name([`n${i}`, ...SERVICE]))]), "192.168.1.99");
    }
    assert.ok(browse.incomplete().length <= 64);
  });
});

describe("a browse over loopback", () => {
  /** A responder on 127.0.0.1: what it answers to each question, as (name, type). */
  function responder(answer: (question: { labels: string[]; type: number }) => Uint8Array | undefined): Promise<{
    port: number;
    asked: { labels: string[]; type: number }[];
    close: () => void;
  }> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket("udp4");
      const asked: { labels: string[]; type: number }[] = [];
      socket.on("message", (data, remote) => {
        const labels: string[] = [];
        let at = 12;
        while (data[at] !== 0 && at < data.length) {
          labels.push(data.subarray(at + 1, at + 1 + (data[at] as number)).toString());
          at += 1 + (data[at] as number);
        }
        const type = data.readUInt16BE(at + 1);
        asked.push({ labels, type });
        const reply = answer({ labels, type });
        if (reply !== undefined) socket.send(reply, remote.port, remote.address);
      });
      socket.bind(0, "127.0.0.1", () => resolve({ port: socket.address().port, asked, close: () => socket.close() }));
    });
  }

  test("a server that answers whole is found", async () => {
    const r = await responder(() => advertisement());
    try {
      const found = await browseDnssd({ address: "127.0.0.1", port: r.port, timeout: 0.3 });
      assert.equal(found.length, 1);
      assert.equal(found[0]?.uid, UID);
      assert.equal(found[0]?.address, "192.168.1.20");
      assert.equal(r.asked[0]?.type, 12);
      assert.deepEqual(r.asked[0]?.labels, SERVICE);
      // Whole: nothing to ask again
      assert.equal(r.asked.length, 1);
    } finally {
      r.close();
    }
  });

  test("an instance that came without its port and TXT is asked for them", async () => {
    const r = await responder(({ type }) =>
      type === 12 ? response([record(name(SERVICE), 12, name(INSTANCE))]) : advertisement({ address: [10, 1, 2, 3] }),
    );
    try {
      const found = await browseDnssd({ address: "127.0.0.1", port: r.port, timeout: 0.6 });
      assert.equal(found.length, 1);
      assert.equal(found[0]?.address, "10.1.2.3");
      assert.deepEqual(
        r.asked.map((q) => q.type),
        [12, 255],
      );
      assert.deepEqual(r.asked[1]?.labels, INSTANCE);
    } finally {
      r.close();
    }
  });

  test("nobody answering is no server, and so are answers that are not", async () => {
    const silent = await responder(() => undefined);
    const noise = await responder(() => Uint8Array.of(1, 2, 3, 4));
    try {
      assert.deepEqual(await browseDnssd({ address: "127.0.0.1", port: silent.port, timeout: 0.2 }), []);
      assert.deepEqual(await browseDnssd({ address: "127.0.0.1", port: noise.port, timeout: 0.2 }), []);
    } finally {
      silent.close();
      noise.close();
    }
  });

  test("peers are browsed as their own service, and filtered by the server they take", async () => {
    const service = ["_lantern-peer", "_tcp", "local"];
    const instance = ["Den console", ...service];
    const r = await responder(() =>
      response([
        record(name(service), 12, name(instance)),
        record(name(instance), 33, srv(47116, name(HOST))),
        record(name(instance), 16, txt([`servers=${UID}`, "path=/peer", "v=1", "tls=1"])),
        record(name(HOST), 1, [192, 168, 1, 30]),
      ]),
    );
    try {
      const options = { address: "127.0.0.1", port: r.port, timeout: 0.3 };
      assert.equal((await browseDnssdPeers(options)).length, 1);
      assert.equal((await browseDnssdPeers({ ...options, server: UID })).length, 1);
      assert.equal((await browseDnssdPeers({ ...options, server: "another" })).length, 0);
      assert.deepEqual(r.asked[0]?.labels, service);
    } finally {
      r.close();
    }
  });
});
