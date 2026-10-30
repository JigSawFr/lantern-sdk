/**
 * The specification's test vectors (spec/vectors), byte for byte: signed
 * requests, refused Ed25519 signatures, SPKI fingerprints, rating caps, paths
 * and manifests, homebrew signatures, version codes and requirements.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import * as ed25519 from "../../src/ed25519.ts";
import {
  bytes,
  DeviceKey,
  type Homebrew,
  homebrew as hb,
  profiles,
  type RatingCap,
  ratings,
  signatures as sig,
} from "../../src/index.ts";
import { short, spkiSha256 } from "../../src/spki.ts";
import { vectors } from "../helpers.ts";

const { fromHex, utf8 } = bytes;

interface SignedRequest {
  name?: string;
  method: string;
  uri: string;
  body: string;
  headers: Record<string, string>;
  signature_base: string;
}

interface SignatureVectors {
  key: { seed: string; public_key: string; keyid: string; short_fingerprint: string };
  token: string;
  server_time: number;
  skew: number;
  accepted: SignedRequest[];
  refused: { name: string; code: string; after?: string[]; request: SignedRequest }[];
}

describe("signatures.json (SPEC.md § 5.4)", async () => {
  const v = vectors<SignatureVectors>("signatures");
  const key = await DeviceKey.fromSeed(fromHex(v.key.seed));

  test("the key, its keyid and its short fingerprint", () => {
    assert.equal(key.publicKeyBase64, v.key.public_key);
    assert.equal(key.keyid, v.key.keyid);
    assert.equal(key.fingerprint, v.key.short_fingerprint);
  });

  for (const a of v.accepted) {
    test(`signed as the vector: ${a.name}`, async () => {
      const headers = new Headers();
      if (a.headers["Authorization"] !== undefined) headers.set("Authorization", a.headers["Authorization"]);
      const nonce = /nonce="([^"]+)"/.exec(a.headers["Signature-Input"] ?? "")?.[1] ?? "";
      await sig.signRequest(key, a.method, a.uri, headers, a.body ? utf8(a.body) : undefined, {
        created: v.server_time,
        nonce,
      });
      assert.equal(headers.get("Signature-Input"), a.headers["Signature-Input"]);
      assert.equal(headers.get("Signature"), a.headers["Signature"]);
      assert.equal(headers.get("Content-Digest") ?? undefined, a.headers["Content-Digest"]);
      const params = (a.headers["Signature-Input"] ?? "").slice("lantern=".length);
      const base = sig.signatureBase(
        a.method,
        sig.targetUri(a.uri),
        a.headers["Authorization"],
        a.headers["Content-Digest"],
        params,
      );
      assert.equal(base, a.signature_base);
    });

    test(`verified as the vector: ${a.name}`, async () => {
      const result = await sig.verifyRequest(a.method, sig.targetUri(a.uri), new Headers(a.headers), key.publicKey, {
        withToken: a.headers["Authorization"] !== undefined,
        withBody: a.body.length > 0,
        nonces: new sig.NonceCache(),
        skew: v.skew,
        now: v.server_time,
      });
      assert.equal(result.keyid, v.key.keyid);
    });
  }

  test("what a server refuses, in its order, with its code", async () => {
    const nonces = new sig.NonceCache();
    const check = (r: SignedRequest) =>
      sig.verifyRequest(r.method, sig.targetUri(r.uri), new Headers(r.headers), key.publicKey, {
        withToken: r.headers["Authorization"] !== undefined,
        withBody: r.body.length > 0,
        nonces,
        skew: v.skew,
        now: v.server_time,
      });
    for (const r of v.refused) {
      for (const before of r.after ?? []) {
        const first = v.accepted.find((a) => a.name === before);
        assert.ok(first);
        await check(first);
      }
      await assert.rejects(check(r.request), (e: unknown) => e instanceof sig.Refused && e.code === r.code, r.name);
    }
  });
});

interface RefusedVectors {
  small_order: string[];
  messages: string[];
  cases: { name: string; public_key: string; message: string; signature: string; verifies: boolean }[];
}

describe("ed25519-refused.json (SPEC.md § 8.4)", () => {
  const v = vectors<RefusedVectors>("ed25519-refused");
  for (const c of v.cases) {
    test(c.name, async () => {
      assert.equal(await ed25519.verify(fromHex(c.public_key), utf8(c.message), fromHex(c.signature)), c.verifies);
    });
  }

  test("every pair of small-order encodings, as the key and as R with S = 0, never verifies", async () => {
    for (const k of v.small_order) {
      assert.equal(ed25519.isPublicKey(fromHex(k)), false);
      for (const r of v.small_order) {
        const signature = bytes.concat([fromHex(r), new Uint8Array(32)]);
        for (const m of v.messages)
          assert.equal(await ed25519.verify(fromHex(k), utf8(m), signature), false, `${k} ${r} ${m}`);
      }
    }
  });
});

describe("spki.json (SPEC.md § 5.3)", () => {
  const v = vectors<{ certificates: { name: string; pem: string; spki_sha256: string; short: string }[] }>("spki");
  for (const c of v.certificates) {
    test(c.name, () => {
      assert.equal(spkiSha256(c.pem), c.spki_sha256);
      assert.equal(short(c.spki_sha256), c.short);
    });
  }
});

describe("rating-caps.json (SPEC.md § 5.6)", () => {
  const v = vectors<{
    ages: Record<string, Record<string, number>>;
    cases: {
      name: string;
      ratings: { system: string; rating: string }[];
      cap: RatingCap;
      age: number | null;
      hidden: boolean;
    }[];
  }>("rating-caps");
  test("the table", () => {
    assert.deepEqual(ratings.AGES, v.ages);
  });
  for (const c of v.cases) {
    test(c.name, () => {
      assert.equal(ratings.ageOf(c.ratings, c.cap) ?? null, c.age);
      assert.equal(ratings.hidden(c.ratings, c.cap), c.hidden);
    });
  }
});

describe("paths.json (SPEC.md § 8.2)", () => {
  const v = vectors<{
    paths: { path: string; accepted: boolean; why: string }[];
    manifests: { manifest: { path: string; size: number; sha256: string }[]; accepted: boolean; why: string }[];
  }>("paths");
  test("paths", () => {
    for (const p of v.paths) assert.equal(hb.pathProblem(p.path) === undefined, p.accepted, `${p.path}: ${p.why}`);
  });
  test("manifests", () => {
    for (const m of v.manifests) assert.equal(hb.manifestProblems(m.manifest).length === 0, m.accepted, m.why);
  });
});

describe("homebrew-signatures.json (SPEC.md § 8.2, § 8.4)", () => {
  const v = vectors<{
    manifests: {
      manifest: { path: string; size: number; sha256: string }[];
      canonical: string;
      manifest_sha256: string;
    }[];
    signed: {
      entry: Homebrew;
      signed_bytes: string;
      signature: { alg: string; public_key: string; value: string };
      key_short_fingerprint: string;
      verifies: boolean;
    }[];
  }>("homebrew-signatures");
  test("canonical manifests and their digest", () => {
    for (const m of v.manifests) assert.equal(hb.manifestSha256(m.manifest), m.manifest_sha256);
  });
  for (const [i, s] of v.signed.entries()) {
    test(`a signed entry (${i})`, async () => {
      const entry = { ...s.entry, signature: s.signature } as Homebrew;
      assert.equal(new TextDecoder().decode(hb.signedMessage(entry)), s.signed_bytes);
      assert.equal(hb.keyFingerprint(s.signature.public_key), s.key_short_fingerprint);
      assert.equal(await hb.verifySignature(entry), s.verifies);
    });
  }
});

describe("version-codes.json (Annex A)", () => {
  const v = vectors<{
    cases: { platform: string; version: number | string; version_code: number; version_name: string | null }[];
    refused: { platform: string; version: number | string; why: string }[];
  }>("version-codes");
  const code = (platform: string, version: number | string): number => {
    if (platform === "switch") return profiles.switchVersionCode(String(version));
    if (platform === "vita" || platform === "ps4") return profiles.appVerCode(String(version));
    if (platform === "3ds") {
      profiles.n3dsVersionName(Number(version));
      return Number(version);
    }
    if (typeof version !== "number" || !Number.isInteger(version) || version < 0) throw new RangeError("not a version");
    return version;
  };
  for (const c of v.cases) {
    test(`${c.platform} ${c.version}`, () => {
      assert.equal(code(c.platform, c.version), c.version_code);
      if (c.platform === "3ds") assert.equal(profiles.n3dsVersionName(c.version_code), c.version_name);
    });
  }
  for (const r of v.refused)
    test(`refused: ${r.why}`, () => assert.throws(() => code(r.platform, r.version), RangeError));
});

describe("requires.json (SPEC.md § 8.7)", () => {
  const v = vectors<{
    cases: {
      name: string;
      requires: Homebrew["requires"];
      device: Record<string, unknown>;
      decision: string;
      conditions: number;
    }[];
  }>("requires");
  for (const c of v.cases) {
    test(c.name, () => {
      const entry = {
        id: "org.example.x",
        platform: "switch",
        name: "X",
        version: "1",
        build: 1,
        requires: c.requires,
      } as Homebrew;
      const got = hb.offer(entry, c.device);
      assert.equal(got.decision, c.decision);
      assert.equal(got.reasons.length, c.conditions);
    });
  }
});
