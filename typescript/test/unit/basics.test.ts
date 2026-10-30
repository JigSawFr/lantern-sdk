/** Bytes, SHA-256, digests, origins, Ed25519 keys, target URIs, discovery datagrams and profiles. */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import {
  bytes,
  DeviceKey,
  digestSha256,
  discovery,
  formatDigest,
  homebrew as hb,
  http,
  parseDigest,
  profiles,
  Sha256,
  sha256Hex,
  signatures as sig,
} from "../../src/index.ts";
import { nodeSha256 } from "../../src/node/index.ts";

describe("bytes", () => {
  test("base64 and base64url, strictly", () => {
    for (let n = 0; n < 70; n++) {
      const data = new Uint8Array(n).map((_, i) => (i * 37 + n) % 256);
      const b64 = bytes.toBase64(data);
      assert.equal(b64, Buffer.from(data).toString("base64"));
      assert.deepEqual(bytes.fromBase64(b64), data);
      assert.equal(bytes.toBase64Url(data), Buffer.from(data).toString("base64url"));
      assert.deepEqual(bytes.fromBase64Url(bytes.toBase64Url(data)), data);
    }
    assert.equal(bytes.fromBase64("AB=="), undefined); // bits left over
    assert.equal(bytes.fromBase64("A B="), undefined);
    assert.equal(bytes.fromBase64("abc"), undefined);
  });
  test("hex and UTF-8", () => {
    assert.equal(bytes.toHex(bytes.fromHex("00ff7a")), "00ff7a");
    assert.throws(() => bytes.fromHex("0g"));
    assert.equal(bytes.utf8Length("aé€😀"), 1 + 2 + 3 + 4);
  });
});

describe("SHA-256", () => {
  test("the library's own against node:crypto, fed in pieces", () => {
    for (const size of [0, 1, 55, 56, 63, 64, 65, 1000, 70000]) {
      const data = new Uint8Array(size).map((_, i) => (i * 7 + 3) % 251);
      const expected = createHash("sha256").update(data).digest("hex");
      assert.equal(sha256Hex(data), expected);
      for (const factory of [() => new Sha256(), nodeSha256]) {
        const h = factory();
        for (let at = 0; at < size; at += 17) h.update(data.subarray(at, at + 17));
        assert.equal(h.size, size);
        assert.equal(bytes.toHex(h.digest()), expected);
      }
    }
  });
});

describe("digest fields (RFC 9530)", () => {
  test("format and parse", () => {
    const hex = sha256Hex(bytes.utf8("Frostline"));
    const field = formatDigest(hex);
    assert.equal(digestSha256(field), hex);
    assert.equal(digestSha256(`md5=:AAAA:, ${field};x=1`), hex);
    assert.equal(digestSha256("sha-256=:not base64:"), undefined);
    assert.equal(digestSha256(undefined), undefined);
    assert.equal(parseDigest("sha-512=:AAAA:").size, 1);
  });
});

describe("origins and loopback (SPEC.md § 2)", () => {
  test("plain HTTP to loopback only", () => {
    assert.ok(http.plainHttpAllowed("http://127.0.0.1:8080/"));
    assert.ok(http.plainHttpAllowed("http://[::1]/"));
    assert.ok(http.plainHttpAllowed("http://localhost/"));
    assert.ok(http.plainHttpAllowed("https://192.0.2.10/"));
    assert.ok(!http.plainHttpAllowed("http://192.0.2.10/"));
    assert.ok(!http.plainHttpAllowed("http://127.0.0.1.example.org/"));
    assert.throws(() => http.origin("ftp://a.example.org/"));
    assert.deepEqual(http.origin("HTTPS://Shelf.Example.org/x"), {
      scheme: "https",
      host: "shelf.example.org",
      port: 443,
    });
  });
  test("Accept-Language, best first", () => {
    assert.deepEqual(http.acceptLanguages("fr;q=0.5, en, de;q=0, *"), ["en", "fr"]);
  });
});

describe("target URIs (SPEC.md § 5.4)", () => {
  for (const [url, uri] of [
    ["HTTPS://Shelf.Example.org:443/a?b=%20c", "https://shelf.example.org/a?b=%20c"],
    ["http://127.0.0.1:80/x", "http://127.0.0.1/x"],
    ["http://127.0.0.1:8080/x", "http://127.0.0.1:8080/x"],
    ["https://[::1]:8443/v1/", "https://[::1]:8443/v1/"],
    ["https://shelf.example.org", "https://shelf.example.org/"],
  ]) {
    test(url ?? "", () => assert.equal(sig.targetUri(url ?? ""), uri));
  }
  test("what is not one", () => {
    for (const url of ["ftp://shelf.example.org/", "/relative", "https://lea@shelf.example.org/"])
      assert.throws(() => sig.targetUri(url));
    assert.throws(() => sig.receivedUri("https", "evil/host", "/x"));
    assert.equal(sig.receivedUri("https", "Shelf.example.org:443", "/a?b"), "https://shelf.example.org/a?b");
  });
  test("Accept-Signature, written and read", () => {
    const value = sig.acceptSignature(true, true, "kid");
    assert.deepEqual(sig.parseAcceptSignature(value), {
      components: ["@method", "@target-uri", "authorization", "content-digest"],
      keyid: "kid",
      alg: "ed25519",
    });
    assert.equal(sig.parseAcceptSignature('other=("@method")'), undefined);
  });
  test("the replay cache", () => {
    let now = 0;
    const cache = new sig.NonceCache(10, 4, () => now);
    assert.ok(cache.take("k", "n1"));
    assert.ok(!cache.take("k", "n1"));
    assert.ok(cache.take("other", "n1"));
    now = 11;
    assert.ok(cache.take("k", "n1"));
    for (let i = 0; i < 10; i++) cache.take("k", `m${i}`);
    assert.ok(cache.size <= 4);
  });
});

describe("device keys (SPEC.md § 5.4)", () => {
  test("a key not extractable stays where it was made", async () => {
    const key = await DeviceKey.generate();
    assert.equal(key.extractable, false);
    await assert.rejects(key.seedBase64(), /not extractable/);
    assert.equal(key.publicKey.length, 32);
    assert.deepEqual(JSON.parse(JSON.stringify({ key })), { key: { keyid: key.keyid } }); // never its secret
  });
  test("an extractable key gives its seed, and comes back from it", async () => {
    const key = await DeviceKey.generate({ extractable: true });
    const again = await DeviceKey.fromBase64(await key.seedBase64());
    assert.equal(again.keyid, key.keyid);
    const signed = await key.sign(bytes.utf8("Lantern"));
    assert.deepEqual(await again.sign(bytes.utf8("Lantern")), signed);
  });
});

describe("discovery datagrams (SPEC.md § 4.1)", () => {
  const reply = (doc: unknown) => bytes.utf8(JSON.stringify(doc));
  const good = {
    schema: 1,
    lantern: "server",
    uid: "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f",
    name: "Shelf",
    port: 8443,
    base: "/api/lantern",
    versions: [1],
  };
  test("a reply, read", () => {
    const found = discovery.readReply(reply(good), "192.168.1.20");
    assert.equal(found?.url, "https://192.168.1.20:8443/");
  });
  test("what is left out", () => {
    for (const bad of [
      { ...good, schema: 2 },
      { ...good, lantern: "discover" },
      { ...good, port: 0 },
      { ...good, base: "//evil" },
      { ...good, versions: [] },
      { ...good, name: "x".repeat(1300) },
    ]) {
      assert.equal(discovery.readReply(reply(bad), "192.168.1.20"), undefined);
    }
  });
  test("directed broadcasts", () => {
    assert.equal(discovery.directedBroadcast("192.168.1.20", 24), "192.168.1.255");
    assert.equal(discovery.directedBroadcast("10.1.2.3", 8), "10.255.255.255");
    assert.equal(discovery.directedBroadcast("10.1.2.3", 32), "10.1.2.3");
  });
});

describe("profiles (Annex A)", () => {
  test("Switch ids", () => {
    assert.deepEqual(profiles.switchIds("0100ABCD00010800"), ["0100ABCD00010000", "update"]);
    assert.deepEqual(profiles.switchIds("0100ABCD00011001"), ["0100ABCD00010000", "dlc"]);
    assert.equal(profiles.switchUpdateId("0100ABCD00010000"), "0100ABCD00010800");
    assert.ok(profiles.appIdOk("switch", "0100ABCD00010800", "update"));
    assert.ok(!profiles.appIdOk("switch", "0100abcd00010800"));
  });
  test("cheat paths", () => {
    assert.equal(
      profiles.cheatPath("switch", "0100ABCD00010000", "4A1B2C3D4E5F6071AB"),
      "/atmosphere/contents/0100ABCD00010000/cheats/4A1B2C3D4E5F6071.txt",
    );
    assert.throws(() => profiles.cheatPath("linux", "x"));
  });
  test("install plans by the profile's roots", () => {
    const entry = (path: string, format = "nro") => {
      const manifest = [{ path, size: 1, sha256: "1".repeat(64) }];
      return {
        id: "org.example.lamp",
        platform: "switch",
        name: "Lamp",
        version: "1",
        build: 1,
        package: {
          format,
          file: "/f",
          size: 1,
          sha256: "1".repeat(64),
          path,
          manifest_sha256: hb.manifestSha256(manifest),
        },
      };
    };
    assert.deepEqual(hb.installPlan(entry("/switch/org.example.lamp/org.example.lamp.nro")).free, [
      "/switch/org.example.lamp/org.example.lamp.nro",
    ]);
    assert.deepEqual(hb.installPlan(entry("/switch/.overlays/lamp.ovl", "ovl")).consent, [
      "/switch/.overlays/lamp.ovl",
    ]);
    assert.throws(() => hb.installPlan(entry("/bootloader/lamp.nro")), hb.Refused);
    assert.throws(() => hb.installPlan({ ...entry("/x/y"), platform: "ios" }), /no profile/);
  });
});
