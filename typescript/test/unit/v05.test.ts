/**
 * What draft 0.5 adds, alone: the specification's vectors of grants
 * (§ 19.3), sync's merge rule (§ 20.4) and the static layout (§ 21.1); the
 * bounded Server-Sent Events reader (§ 18); mirrors and peers' addresses
 * (§ 19.2, § 19.4); a sync state kept by the `schema` rule.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { DocumentError, discovery, events, peers, staticLibrary, sync } from "../../src/index.ts";
import { vectors } from "../helpers.ts";

interface GrantVectors {
  key: { seed: string; public_key: string };
  payload: string;
  grant: string;
  cases: {
    name: string;
    grant: string;
    path_sha256: string;
    peer_time: number;
    servers: Record<string, string>;
    serves: boolean;
  }[];
}

describe("grants.json (SPEC.md § 19.3, § 19.4)", () => {
  const v = vectors<GrantVectors>("grants");

  test("the payload, byte for byte, and the grant signed by its key", async () => {
    const doc = JSON.parse(v.payload) as { uid: string; sha256: string; size: number; exp: number };
    assert.equal(new TextDecoder().decode(peers.grantPayload(doc.uid, doc.sha256, doc.size, doc.exp)), v.payload);
    const { fromSeed } = await import("../../src/ed25519.ts");
    const key = await fromSeed(Buffer.from(v.key.seed, "hex"));
    assert.equal(Buffer.from(key.publicKey).toString("base64"), v.key.public_key);
    assert.equal(await peers.signGrant(key.privateKey, doc.uid, doc.sha256, doc.size, doc.exp), v.grant);
  });

  for (const c of v.cases) {
    test(`a peer decides: ${c.name}`, async () => {
      const payload = await peers.verifyGrant(c.grant, c.servers, c.peer_time);
      const serves = payload !== undefined && payload.sha256 === c.path_sha256;
      assert.equal(serves, c.serves);
    });
  }

  test("a grant above 1 KiB, or of another spelling, is not one", () => {
    assert.equal(peers.grantContents(`${"a".repeat(1100)}.${"b".repeat(86)}`), undefined);
    const spaced = Buffer.from(v.payload.replace(":", ": ")).toString("base64url");
    assert.equal(peers.grantContents(`${spaced}.${v.grant.split(".")[1]}`), undefined);
  });
});

interface MergeVectors {
  server_time: string;
  skew: number;
  cases: {
    name: string;
    have: sync.Versioned | null;
    sent: sync.Versioned;
    replaced: boolean;
    kept: sync.Versioned;
    canonical?: { have: string; sent: string };
  }[];
}

describe("sync-merge.json (SPEC.md § 20.4)", () => {
  const v = vectors<MergeVectors>("sync-merge");
  const now = Date.parse(v.server_time);
  for (const c of v.cases) {
    test(c.name, () => {
      const [kept, replaced] = sync.merge(c.have ?? undefined, c.sent, now, v.skew);
      assert.equal(replaced, c.replaced);
      assert.deepEqual(kept, c.kept);
      if (c.canonical !== undefined) {
        assert.equal(sync.canonicalJson(c.have?.value), c.canonical.have);
        assert.equal(sync.canonicalJson(c.sent.value), c.canonical.sent);
      }
    });
  }

  test("canonical JSON: keys sorted, no space, characters other than ASCII as they are", () => {
    assert.equal(sync.canonicalJson({ b: [1, "é"], a: { d: null, c: true } }), '{"a":{"c":true,"d":null},"b":[1,"é"]}');
  });

  test("a time that is not a sync time is refused", () => {
    for (const bad of ["yesterday", "2026-10-30T09:00:00+01:00", "2026-02-30T09:00:00Z", "2026-10-30T09:00:00.1234Z"])
      assert.throws(() => sync.merge(undefined, { value: 1, updated: bad }), DocumentError, bad);
  });
});

interface LayoutVectors {
  routes: { name: string; route: string; file: string }[];
  paths: { path: string; accepted: boolean }[];
}

describe("static-layout.json (SPEC.md § 21.1)", () => {
  const v = vectors<LayoutVectors>("static-layout");
  const { layoutPath } = staticLibrary;
  const mine: Record<string, string> = {
    "The handshake": layoutPath("handshake"),
    "Apps of the Switch, page 1": layoutPath("apps", { platform: "switch", page: 1 }),
    "Apps of the Switch, the page after cursor 2": layoutPath("apps", { platform: "switch", page: 2 }),
    "A title": layoutPath("title", { platform: "switch", id: "0100ABCD00010000" }),
    "Every title of Android, page 1": layoutPath("titles", { platform: "android", page: 1 }),
    "Homebrew of Linux, page 1": layoutPath("homebrew", { platform: "linux", page: 1 }),
    "A homebrew entry": layoutPath("entry", { platform: "switch", id: "org.example.frostline" }),
    "A title's cheat sets": layoutPath("cheats", { platform: "switch", id: "0100ABCD00010000" }),
    "A cheat set's text": layoutPath("cheat", { id: "cs_Jt3Vx0" }),
    "A file": layoutPath("blob", { id: "3a7bd3e2b4c1f0a9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a392817" }),
  };
  test("every route of the vectors is known here", () => {
    assert.deepEqual(v.routes.map((r) => r.name).sort(), Object.keys(mine).sort());
  });
  for (const r of v.routes) test(`a route's file: ${r.name}`, () => assert.equal(mine[r.name], r.file));
  for (const p of v.paths) test(`a path: ${p.path}`, () => assert.equal(staticLibrary.relativeOk(p.path), p.accepted));
});

describe("the event stream's reader (SPEC.md § 18.1)", () => {
  const blocks = (text: string | Uint8Array, options?: { lineLimit?: number; dataLimit?: number }) =>
    new events.SseParser(options).push(typeof text === "string" ? new TextEncoder().encode(text) : text);

  test("the specification's example: retry, ready, a comment, a request", () => {
    const parser = new events.SseParser();
    const text =
      'retry: 5000\n\nid: s_9f2c01aa_1042\nevent: ready\ndata: {"schema":1}\n\n: heartbeat\n\n' +
      'id: s_9f2c01aa_1043\nevent: request\ndata: {"schema":1,"id":"r_7Qm2","platform":"switch","title_id":"0100ABCD00010000","status":"done"}\n\n';
    const out = parser.push(new TextEncoder().encode(text));
    assert.deepEqual(out[0], { retry: 5000 });
    assert.deepEqual(events.readEvent(out[1] ?? {}), { id: "s_9f2c01aa_1042", event: "ready", data: { schema: 1 } });
    assert.equal(events.readEvent(out[2] ?? {})?.data["status"], "done");
    assert.equal(parser.comments, 1);
    assert.equal(parser.lastEventId, "s_9f2c01aa_1043");
  });

  test("CR, LF and CRLF, split anywhere, and a BOM", () => {
    const text = '﻿id: a\r\nevent: library\rdata: {"schema":1,\ndata: "families":["apps"]}\r\n\r\n';
    const bytes = new TextEncoder().encode(text);
    const parser = new events.SseParser();
    const out = [];
    for (const b of bytes) out.push(...parser.push(new Uint8Array([b])));
    assert.equal(out.length, 1);
    assert.deepEqual(events.readEvent(out[0] ?? {})?.data, { schema: 1, families: ["apps"] });
  });

  test("a line beyond its bound is refused as soon as it passes it", () => {
    assert.throws(() => blocks(`data: ${"x".repeat(10000)}`), DocumentError);
    assert.throws(() => blocks(`data: ${"x".repeat(3000)}\ndata: ${"x".repeat(3000)}\n`), /4096/);
  });

  test("an event a reader ignores: no id, a type unknown, a newer schema", () => {
    assert.equal(events.readEvent({ event: "library", data: '{"schema":1}' }), undefined);
    assert.equal(events.readEvent({ id: "x", event: "x-other", data: '{"schema":1}' }), undefined);
    assert.equal(events.readEvent({ id: "x", event: "library", data: '{"schema":2}' }), undefined);
    assert.throws(() => events.readEvent({ id: "x", event: "library", data: "[1]" }), DocumentError);
  });

  test("a retry that is not digits is ignored; an id with NUL keeps the last", () => {
    const parser = new events.SseParser();
    assert.deepEqual(parser.push(new TextEncoder().encode("retry: soon\n\nid: a\0b\ndata: {}\n\n")), [{ data: "{}" }]);
    assert.equal(parser.lastEventId, "");
  });

  test("backoff with full jitter, Retry-After a floor (Annex B.2)", () => {
    for (let n = 0; n < 10; n++) {
      const wait = events.backoff(n, 3);
      assert.ok(wait >= 3 && wait <= Math.max(3, Math.min(60, 2 ** n)));
    }
  });
});

describe("mirrors and peers' addresses (SPEC.md § 19.2, § 19.4, § 19.5)", () => {
  test("a mirror: HTTPS, or HTTP on a private network (or loopback, for testing)", () => {
    for (const ok of [
      "https://mirror.example.org/frostline.nsz",
      "http://192.168.1.20/f",
      "http://10.0.0.2:8080/f",
      "http://172.20.1.1/f",
      "http://[fd00::1]/f",
      "http://[fe80::1]/f",
      "http://127.0.0.1:8000/f",
    ])
      assert.ok(peers.mirrorAllowed(ok), ok);
    for (const bad of [
      "http://mirror.example.org/f",
      "http://8.8.8.8/f",
      "http://172.32.0.1/f",
      "ftp://192.168.1.2/f",
      "https://user:secret@mirror.example.org/f",
      "/relative",
      "http://[2001:db8::1]/f",
    ])
      assert.ok(!peers.mirrorAllowed(bad), bad);
    assert.deepEqual(
      peers.usableMirrors({ mirrors: [{ url: "http://8.8.8.8/f" }, { url: "https://mirror.example.org/f" }] }),
      ["https://mirror.example.org/f"],
    );
  });

  test("a peer's reply: of its form, and plain HTTP only from a private network", () => {
    const reply = (doc: unknown) => new TextEncoder().encode(JSON.stringify(doc));
    const doc = {
      schema: 1,
      lantern: "peer",
      uid: "2b9e4d71-0c3a-4f6e-8a15-7d2c9e0b1f43",
      name: "Lea's Switch",
      port: 47116,
      base: "/lantern",
      tls: false,
      slots: 2,
      servers: ["6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14"],
    };
    assert.equal(discovery.readPeerReply(reply(doc), "192.168.1.30")?.url, "http://192.168.1.30:47116/lantern");
    assert.equal(discovery.readPeerReply(reply(doc), "203.0.113.5"), undefined);
    assert.equal(
      discovery.readPeerReply(reply({ ...doc, tls: true }), "203.0.113.5")?.url,
      "https://203.0.113.5:47116/lantern",
    );
    assert.equal(discovery.readPeerReply(reply({ ...doc, slots: 9 }), "192.168.1.30"), undefined);
    assert.equal(discovery.readPeerReply(reply({ ...doc, schema: 2 }), "192.168.1.30"), undefined);
    assert.equal(discovery.readPeerReply(reply({ ...doc, lantern: "server" }), "192.168.1.30"), undefined);
    assert.equal(
      peers.blobUrl("http://192.168.1.30:47116/lantern", "a".repeat(64)),
      `http://192.168.1.30:47116/lantern/v1/blobs/sha256/${"a".repeat(64)}`,
    );
  });
});

describe("a sync state, kept by the schema rule (SPEC.md § 3.2, § 20.1)", () => {
  const state = { schema: 1, server: "6f1c2a8e", profile: "Lea", consent: ["wishes"], revs: { wishes: 4 } };
  test("absent, or not one: undefined", () => {
    assert.equal(sync.readSyncState(undefined), undefined);
    assert.equal(sync.readSyncState({ ...state, consent: "wishes" }), undefined);
  });
  test("of a newer schema: undefined, never written over", () => {
    assert.equal(sync.readSyncState({ ...state, schema: 2 }), undefined);
  });
  test("an unknown field is kept", () => {
    const read = sync.readSyncState({ ...state, "x-shelf": 1 }) as unknown as Record<string, unknown>;
    assert.equal(read["x-shelf"], 1);
  });
  test("sync off: no consent", () => {
    assert.deepEqual(sync.syncOff("6f1c2a8e", "Lea").consent, []);
  });
});
