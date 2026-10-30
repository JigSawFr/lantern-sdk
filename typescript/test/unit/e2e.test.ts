/**
 * The ciphers of end-to-end encrypted saves (src/chacha.ts) against RFC 8439's
 * and draft-irtf-cfrg-xchacha-03's vectors and against node:crypto, then the
 * scheme lantern-save-e2e-1 (src/e2e.ts) against the specification's vectors
 * (spec/vectors/encrypted-saves.json), byte for byte.
 */

import assert from "node:assert/strict";
import { createCipheriv, randomBytes } from "node:crypto";
import { describe, test } from "node:test";
import * as chacha from "../../src/chacha.ts";
import * as e2e from "../../src/e2e.ts";
import { bytes, sha256Hex } from "../../src/index.ts";
import { vectors } from "../helpers.ts";

const { fromHex, toHex, utf8 } = bytes;
const h = (text: string): Uint8Array => fromHex(text.replace(/[\s:]/g, ""));
const SUNSCREEN = utf8(
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
);
const KEY_00_1F = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const KEY_80_9F = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");

describe("ChaCha20 and Poly1305 (RFC 8439)", () => {
  test("§ 2.3.2: the block function", () => {
    const block = chacha.chacha20Block(KEY_00_1F, 1, h("000000090000004a00000000"));
    assert.equal(
      toHex(block),
      "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    );
  });

  test("§ 2.4.2: encryption", () => {
    const out = chacha.chacha20(KEY_00_1F, h("000000000000004a00000000"), 1, SUNSCREEN);
    assert.equal(
      toHex(out),
      "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab" +
        "8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
    );
    assert.deepEqual(chacha.chacha20(KEY_00_1F, h("000000000000004a00000000"), 1, out), SUNSCREEN);
  });

  test("§ 2.5.2: Poly1305", () => {
    const key = h("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    assert.equal(
      toHex(chacha.poly1305(key, utf8("Cryptographic Forum Research Group"))),
      "a8061dc1305136c6c22b8baf0c0127a9",
    );
  });

  // RFC 8439 Appendix A.3: the edge cases of the reduction modulo 2^130 - 5.
  const zeros = (n: number) => "00".repeat(n);
  const ff = (n: number) => "ff".repeat(n);
  const edges: [string, string, string, string][] = [
    ["#1: all zero", zeros(32), zeros(64), zeros(16)],
    ["#5: h reaches p", `02${zeros(31)}`, ff(16), `03${zeros(15)}`],
    ["#6: h + s overflows", `02${zeros(15)}${ff(16)}`, `02${zeros(15)}`, `03${zeros(15)}`],
    ["#7: a carry through every limb", `01${zeros(31)}`, `${ff(16)}f0${ff(15)}11${zeros(15)}`, `05${zeros(15)}`],
    ["#8: h exactly p", `01${zeros(31)}`, `${ff(16)}fb${"fe".repeat(15)}${"01".repeat(16)}`, zeros(16)],
    ["#9: h is p - 5 + 2^128", `02${zeros(31)}`, `fd${ff(15)}`, `fa${ff(15)}`],
    [
      "#10: a final reduction",
      `0100000000000000040000000000000000${zeros(15)}`,
      `e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001${zeros(15)}`,
      "14000000000000005500000000000000",
    ],
    [
      "#11: another",
      `0100000000000000040000000000000000${zeros(15)}`,
      `e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000`,
      "13000000000000000000000000000000",
    ],
  ];
  for (const [name, key, message, tag] of edges) {
    test(`A.3 ${name}`, () => {
      assert.equal(toHex(chacha.poly1305(h(key), h(message))), tag);
    });
  }

  test("Poly1305 fed in pieces is Poly1305 of the whole", () => {
    const key = randomBytes(32);
    const message = randomBytes(1000);
    const whole = chacha.poly1305(key, message);
    const mac = new chacha.Poly1305(key);
    for (let at = 0; at < message.length; at += 7) mac.update(message.subarray(at, at + 7));
    assert.deepEqual(mac.finish(), whole);
  });

  test("§ 2.8.2: ChaCha20-Poly1305", () => {
    const nonce = h("070000004041424344454647");
    const aad = h("50515253c0c1c2c3c4c5c6c7");
    const sealed = chacha.chacha20poly1305Seal(KEY_80_9F, nonce, SUNSCREEN, aad);
    assert.equal(
      toHex(sealed),
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b29" +
        "05d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" +
        "1ae10b594f09e26a7e902ecbd0600691",
    );
    assert.deepEqual(chacha.chacha20poly1305Open(KEY_80_9F, nonce, sealed, aad), SUNSCREEN);
    sealed[0] = (sealed[0] as number) ^ 1;
    assert.equal(chacha.chacha20poly1305Open(KEY_80_9F, nonce, sealed, aad), undefined);
  });

  test("ChaCha20-Poly1305 is node:crypto's, at every length up to two chunks", () => {
    for (const length of [0, 1, 15, 16, 17, 63, 64, 65, 1000, 65535, 65536, 65537, 131072]) {
      const key = randomBytes(32);
      const nonce = randomBytes(12);
      const plaintext = randomBytes(length);
      const aad = randomBytes(length % 37);
      const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
      cipher.setAAD(aad, { plaintextLength: length });
      const want = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
      const got = chacha.chacha20poly1305Seal(key, nonce, plaintext, aad);
      assert.equal(toHex(got), want.toString("hex"), `length ${length}`);
      assert.deepEqual(chacha.chacha20poly1305Open(key, nonce, got, aad), new Uint8Array(plaintext));
    }
  });

  test("a counter that would wrap is refused", () => {
    assert.throws(() => chacha.chacha20(KEY_00_1F, new Uint8Array(12), 0xffffffff, new Uint8Array(65)), RangeError);
  });
});

describe("HChaCha20 and XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)", () => {
  test("§ 2.2.1: HChaCha20", () => {
    assert.equal(
      toHex(chacha.hchacha20(KEY_00_1F, h("000000090000004a0000000031415927"))),
      "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
    );
  });

  test("A.3.1: XChaCha20-Poly1305", () => {
    const nonce = h("404142434445464748494a4b4c4d4e4f5051525354555657");
    const aad = h("50515253c0c1c2c3c4c5c6c7");
    const sealed = chacha.xchacha20poly1305Seal(KEY_80_9F, nonce, SUNSCREEN, aad);
    assert.equal(
      toHex(sealed),
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb" +
        "96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e" +
        "c0875924c1c7987947deafd8780acf49",
    );
    assert.deepEqual(chacha.xchacha20poly1305Open(KEY_80_9F, nonce, sealed, aad), SUNSCREEN);
    assert.equal(chacha.xchacha20poly1305Open(KEY_80_9F, nonce, sealed, utf8("other")), undefined);
  });
});

interface E2eVectors {
  chunk: number;
  header: number;
  primitives: {
    hkdf_sha256: { ikm: string; salt: string; info: string; length: number; okm: string }[];
    hchacha20: { key: string; nonce: string; subkey: string }[];
    xchacha20poly1305: { key: string; nonce: string; aad: string; plaintext: string; sealed: string }[];
  };
  keys: { save_key: string; key_id: string; wrapping_key: string; phrase: string; qr: string }[];
  backups: {
    name: string;
    save_key: string;
    file_key: string;
    wrap_nonce: string;
    archive: string | { size: number; byte_i: string };
    header: string;
    size: number;
    sha256: string;
    chunk_tags: string[];
    encrypted?: string;
  }[];
  refused: {
    name: string;
    backup: string | null;
    operation: string;
    save_key: string;
    sha256: string;
    opens: boolean;
  }[];
  phrases: { name: string; phrase: string; accepted: boolean }[];
}

describe("encrypted-saves.json (SPEC.md § 9.4)", async () => {
  const v = vectors<E2eVectors>("encrypted-saves");

  test("the chunk and header sizes", () => {
    assert.equal(v.chunk, e2e.CHUNK);
    assert.equal(v.header, e2e.HEADER);
  });

  for (const c of v.primitives.hkdf_sha256) {
    test(`HKDF-SHA-256, info ${c.info}`, async () => {
      assert.equal(toHex(await e2e.hkdfSha256(h(c.ikm), utf8(c.info), c.length, h(c.salt))), c.okm);
    });
  }
  for (const c of v.primitives.hchacha20) {
    test("HChaCha20", () => assert.equal(toHex(chacha.hchacha20(h(c.key), h(c.nonce))), c.subkey));
  }
  for (const c of v.primitives.xchacha20poly1305) {
    test(`XChaCha20-Poly1305, ${c.plaintext.length / 2} bytes`, () => {
      const sealed = chacha.xchacha20poly1305Seal(h(c.key), h(c.nonce), h(c.plaintext), h(c.aad));
      assert.equal(toHex(sealed), c.sealed);
      assert.equal(
        toHex(chacha.xchacha20poly1305Open(h(c.key), h(c.nonce), sealed, h(c.aad)) ?? new Uint8Array([1])),
        c.plaintext,
      );
    });
  }

  for (const k of v.keys) {
    test(`a save key: its id, wrapping key, phrase and QR text (${k.key_id})`, async () => {
      const key = new e2e.SaveKey(h(k.save_key));
      assert.equal(await key.keyId(), k.key_id);
      assert.equal(toHex(await key.wrappingKey()), k.wrapping_key);
      assert.equal(key.phrase(), k.phrase);
      assert.equal(key.qr(), k.qr);
      assert.equal(toHex(e2e.SaveKey.fromPhrase(k.phrase).bytes()), k.save_key);
      assert.equal(toHex(e2e.SaveKey.fromQr(k.qr).bytes()), k.save_key);
      key.wipe();
      assert.throws(() => key.phrase(), /wiped/);
    });
  }

  for (const p of v.phrases) {
    test(`a phrase: ${p.name}`, () => {
      if (p.accepted) assert.equal(toHex(e2e.SaveKey.fromPhrase(p.phrase).bytes()), v.keys[0]?.save_key);
      else assert.throws(() => e2e.SaveKey.fromPhrase(p.phrase), e2e.KeyPhraseError);
    });
  }

  test("a QR text of another form is refused", () => {
    assert.throws(() => e2e.SaveKey.fromQr("LANTERN-SAVE-KEY-2:96PA"), e2e.KeyPhraseError);
    assert.throws(() => e2e.SaveKey.fromQr(`${v.keys[0]?.qr.toLowerCase()}`), e2e.KeyPhraseError);
  });

  const archiveOf = (b: E2eVectors["backups"][number]): Uint8Array => {
    if (typeof b.archive === "string") return h(b.archive);
    assert.equal(b.archive.byte_i, "i % 251");
    return Uint8Array.from({ length: b.archive.size }, (_, i) => i % 251);
  };
  const made = new Map<string, Uint8Array>();

  for (const b of v.backups) {
    test(`a backup, byte for byte: ${b.name}`, async () => {
      const key = new e2e.SaveKey(h(b.save_key));
      const archive = archiveOf(b);
      const fixed = { fileKey: h(b.file_key), wrapNonce: h(b.wrap_nonce) };
      const out = await e2e.encryptBytes(key, archive, fixed);
      made.set(b.name, out);
      assert.equal(toHex(out.subarray(0, e2e.HEADER)), b.header);
      assert.equal(out.length, b.size);
      assert.equal(e2e.encryptedSize(archive.length), b.size);
      assert.equal(sha256Hex(out), b.sha256);
      if (b.encrypted !== undefined) assert.equal(toHex(out), b.encrypted);
      // Each chunk's tag, at the end of its record.
      const record = e2e.CHUNK + e2e.TAG;
      b.chunk_tags.forEach((t, i) => {
        const end = Math.min(e2e.HEADER + (i + 1) * record, out.length);
        assert.equal(toHex(out.subarray(end - 16, end)), t, `chunk ${i}`);
      });
      // The same bytes in pieces of any size, and by random access (a resumed upload).
      const pieces = (function* () {
        for (let at = 0; at < archive.length; at += 1000) yield archive.subarray(at, at + 1000);
      })();
      let streamed: Uint8Array = new Uint8Array();
      for await (const part of e2e.encrypt(key, pieces, fixed)) streamed = bytes.concat([streamed, part]);
      assert.deepEqual(streamed, out);
      const backup = await e2e.EncryptedBackup.create(
        key,
        { size: archive.length, read: async (o, l) => archive.subarray(o, o + l) },
        fixed,
      );
      assert.equal(backup.size, b.size);
      for (const [o, l] of [
        [0, 10],
        [80, 20],
        [0, b.size],
        [b.size - 17, 40],
        [65000, 2000],
      ] as const) {
        assert.deepEqual(await backup.read(o, l), out.subarray(o, o + l), `read(${o}, ${l})`);
      }
      backup.wipe();
      await assert.rejects(backup.read(100, 10), /wiped/);
      // Decrypted back, whole and in pieces.
      assert.deepEqual(await e2e.decryptBytes(key, out), archive);
      const parts: Uint8Array[] = [];
      const sliced = (function* () {
        for (let at = 0; at < out.length; at += 777) yield out.subarray(at, at + 777);
      })();
      for await (const part of e2e.decrypt(key, sliced)) parts.push(part);
      assert.deepEqual(bytes.concat(parts), archive);
      assert.equal(e2e.keyIdOf(out), await key.keyId());
    });
  }

  for (const r of v.refused) {
    test(`refused: ${r.name}`, async () => {
      const source = r.backup === null ? undefined : made.get(r.backup);
      if (r.backup !== null) assert.ok(source, "its backup was made above");
      const base = source ?? new Uint8Array();
      const op = r.operation;
      const record = e2e.CHUNK + e2e.TAG;
      const flip = (at: number): Uint8Array => {
        const out = base.slice();
        out[at] = (out[at] as number) ^ 1;
        return out;
      };
      const flipAt = /^flip bit 0 of byte (\d+)$/.exec(op);
      const keep = /^keep the first 88 \+ (\d+) bytes$/.exec(op);
      const append = /^append (\d+) zero bytes$/.exec(op);
      let data: Uint8Array;
      if (flipAt !== null) data = flip(Number(flipAt[1]));
      else if (op === "flip bit 0 of the last byte") data = flip(base.length - 1);
      else if (op === "read with the second key") data = base.slice();
      else if (op === "a zip in clear") data = h("504b0506000000000000000000000000000000000000");
      else if (op === "drop the last byte") data = base.slice(0, -1);
      else if (keep !== null) data = base.slice(0, 88 + Number(keep[1]));
      else if (append !== null) data = bytes.concat([base, new Uint8Array(Number(append[1]))]);
      else if (op === "swap the two chunks")
        data = bytes.concat([base.subarray(0, 88), base.subarray(88 + record), base.subarray(88, 88 + record)]);
      else assert.fail(`an operation this test does not know: ${op}`);
      if (op !== "a zip in clear") assert.equal(sha256Hex(data), r.sha256);
      assert.equal(r.opens, false);
      await assert.rejects(e2e.decryptBytes(new e2e.SaveKey(h(r.save_key)), data), e2e.DecryptionError);
    });
  }

  test("a new file key and wrap nonce for each backup (L-9.4-3)", async () => {
    const key = e2e.SaveKey.generate();
    const archive = utf8("Frostline Tales, chapter 3");
    const a = await e2e.encryptBytes(key, archive);
    const b = await e2e.encryptBytes(key, archive);
    assert.notDeepEqual(a.subarray(16, 88), b.subarray(16, 88));
    assert.deepEqual(await e2e.decryptBytes(key, b), archive);
    assert.equal(e2e.encryptionHeader(await key.encryption()), `lantern-save-e2e-1; key_id=${await key.keyId()}`);
  });
});
