/**
 * The generated readers against the specification's examples, the `schema`
 * rule (SPEC.md § 3.2: absent, newer, unknown fields), the validator, the
 * limits of § 13, and the files a client keeps.
 */

import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import {
  DOCUMENTS,
  DocumentError,
  type Documents,
  definition,
  isNewer,
  limits,
  parse,
  read,
  readHomebrew,
  readNamed,
  readServerRecord,
  schemaOf,
  validate,
} from "../../src/index.ts";
import { FileKeyPins, FileServerStore, loadDocument, NewerOnDisk, saveDocument } from "../../src/node/index.ts";
import { example, SPEC } from "../helpers.ts";

const EXAMPLES = join(SPEC, "examples", "v1");
const names = readdirSync(EXAMPLES)
  .filter((f) => f.endsWith(".json"))
  .map((f) => f.slice(0, -5)) as (keyof Documents)[];

describe("the generated readers", () => {
  test("every document of the schemas has its reader", () => {
    assert.deepEqual(Object.keys(DOCUMENTS).sort(), [...names].sort());
  });

  for (const name of names) {
    test(`${name}: the example reads, and writes back unchanged`, () => {
      const doc = example(name);
      const read = DOCUMENTS[name](structuredClone(doc), name);
      assert.deepEqual(JSON.parse(JSON.stringify(read)), doc);
    });

    test(`${name}: an unknown field is kept on a rewrite`, () => {
      const doc = { ...example(name), "x-example-shelf": { kept: [1, 2] } };
      const got = readNamed(name, structuredClone(doc)) as Record<string, unknown>;
      assert.deepEqual(got["x-example-shelf"], { kept: [1, 2] });
      assert.deepEqual(JSON.parse(JSON.stringify(got)), doc);
    });

    // An event carries its schema in its data (SPEC.md § 18.1); every other document at its top.
    const holder = (doc: Record<string, unknown>): Record<string, unknown> =>
      name === "event" ? (doc["data"] as Record<string, unknown>) : doc;

    test(`${name}: a newer schema is absent`, () => {
      const doc = example<Record<string, unknown>>(name);
      holder(doc)["schema"] = 2;
      assert.equal(readNamed(name, doc), undefined);
      assert.equal(isNewer(holder(doc)), true);
    });

    test(`${name}: an absent schema is not a document`, () => {
      const doc = example<Record<string, unknown>>(name);
      delete holder(doc)["schema"];
      assert.throws(
        () => readNamed(name, doc),
        (e: unknown) => e instanceof DocumentError && /schema/.test(e.message),
      );
    });
  }

  test("nested unknown fields are kept", () => {
    const doc = example<Record<string, Record<string, unknown>>>("homebrew");
    const pkg = doc["package"] as { manifest: Record<string, unknown>[] };
    (pkg.manifest[0] as Record<string, unknown>)["x-vendor-mode"] = "0644";
    const entry = readHomebrew(structuredClone(doc));
    assert.deepEqual(JSON.parse(JSON.stringify(entry)), doc);
  });

  test("a missing required field is refused, with its place", () => {
    const doc = example<{ items: Record<string, unknown>[] }>("apps");
    delete doc.items[0]?.["sha256"];
    assert.throws(() => DOCUMENTS.apps(doc, "apps"), /items\[0\]: no sha256/);
  });

  for (const [key, value] of [
    ["build", "10400"],
    ["build", true],
    ["name", 7],
    ["tags", "journal"],
  ] as const) {
    test(`a field of the wrong type is refused: ${key} ${JSON.stringify(value)}`, () => {
      assert.throws(
        () => readHomebrew({ ...example<Record<string, unknown>>("homebrew"), [key]: value }),
        DocumentError,
      );
    });
  }

  for (const schema of [null, "1", 0, true, -1, 1.5]) {
    test(`a schema that is not a positive integer: ${JSON.stringify(schema)}`, () => {
      assert.throws(() => schemaOf({ schema }), /schema/);
    });
  }

  test("read() and parse() by the rule", () => {
    assert.equal(read(DOCUMENTS.cheats, { schema: 3, cheats: "anything" }), undefined);
    assert.deepEqual(parse(DOCUMENTS.cheats, '{"schema":1,"cheats":[]}'), { schema: 1, cheats: [] });
    assert.throws(() => parse(DOCUMENTS.cheats, "[1"), DocumentError);
  });
});

describe("the validator (src/schema.ts)", () => {
  for (const name of names) {
    test(`${name}: the example is valid`, () => assert.deepEqual(validate(name, example(name)), []));
  }
  for (const file of readdirSync(join(EXAMPLES, "invalid")).sort()) {
    test(`refused: ${file}`, () => {
      const doc = JSON.parse(readFileSync(join(EXAMPLES, "invalid", file), "utf8")) as unknown;
      assert.ok(validate(file.split(".")[0] ?? "", doc).length > 0, `${file} should be refused`);
    });
  }
  test("formats, and true is not 1", () => {
    assert.deepEqual(definition("time", "2026-10-30T09:12:00Z"), []);
    assert.deepEqual(definition("time", "2026-10-30T09:12:00.5+02:00"), []);
    assert.ok(definition("time", "2026-10-30 09:12").length > 0);
    assert.ok(definition("time", "2026-13-30T09:12:00Z").length > 0);
    assert.ok(definition("sha256", "0".repeat(63)).length > 0);
    assert.ok(validate("cheats", { schema: true, cheats: [] }).length > 0);
    assert.throws(() => validate("nothing", {}), RangeError);
  });
});

describe("the limits of SPEC.md § 13", () => {
  test("a document too large, too deep, or with a string too long", () => {
    assert.throws(() => limits.loadJson("[1]", { limit: 2 }), /above 2/);
    assert.throws(() => limits.loadJson(`${"[".repeat(17)}${"]".repeat(17)}`), /deeper than 16/);
    assert.doesNotThrow(() => limits.loadJson(`${"[".repeat(16)}${"]".repeat(16)}`));
    assert.throws(() => limits.loadJson(JSON.stringify({ name: "é".repeat(257) })), /514 bytes, above 512/);
    assert.throws(() => limits.loadJson(JSON.stringify({ tags: Array(33).fill("x") })), /33 items/);
    assert.throws(() => limits.loadJson(new Uint8Array([0xff, 0xfe])), /not UTF-8/);
    assert.throws(() => limits.loadJson('{"a": NaN}'), /not JSON/);
  });
  test("a depth hidden in a string is not a depth", () => {
    assert.equal(limits.jsonDepth(JSON.stringify({ a: "[[[[[[[[[[[[[[[[[[[[" })), 1);
  });
  test("printable() drops control characters and bounds the bytes", () => {
    assert.equal(limits.printable("a\u0007b\u009bc\nd", 100), "abc\nd");
    assert.equal(limits.printable("ééé", 5), "éé");
  });
});

describe("files kept by the schema rule", () => {
  const folder = mkdtempSync(join(tmpdir(), "lantern-store-"));
  after(() => rmSync(folder, { recursive: true, force: true }));

  test("absent, then written, then read", async () => {
    const path = join(folder, "doc.json");
    assert.equal(await loadDocument(path), undefined);
    await saveDocument(path, { schema: 1, pins: {} });
    assert.deepEqual(await loadDocument(path), { schema: 1, pins: {} });
  });

  test("a newer file is absent, and never written over", async () => {
    const path = join(folder, "newer.json");
    writeFileSync(path, '{"schema": 2, "pins": {"switch/org.example.a": "k"}}');
    assert.equal(await loadDocument(path), undefined);
    await assert.rejects(saveDocument(path, { schema: 1, pins: {} }), NewerOnDisk);
    assert.equal(JSON.parse(readFileSync(path, "utf8")).schema, 2);
    const pins = new FileKeyPins(path);
    assert.equal(await pins.pinned("switch", "org.example.a"), undefined);
    await assert.rejects(pins.pin("switch", "org.example.a", "x"), NewerOnDisk);
  });

  test("unknown keys are kept, the file's and each record's", async () => {
    const path = join(folder, "servers.json");
    writeFileSync(
      path,
      JSON.stringify({
        schema: 1,
        "x-shelf": 7,
        servers: { u1: { uid: "u1", url: "https://a.example.org/", token: "t", "x-note": "kept" } },
      }),
    );
    const store = new FileServerStore(path);
    const record = await store.server("u1");
    assert.equal(record?.["x-note"], "kept");
    await store.save({
      uid: "u2",
      url: "https://b.example.org/",
      token: "t2",
      name: "",
      scopes: ["library"],
      bound: false,
      paired: "",
    });
    const doc = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(doc["x-shelf"], 7);
    assert.equal(doc.servers.u1["x-note"], "kept");
    assert.equal((await store.servers()).length, 2);
    assert.equal(statSync(path).mode & 0o077, 0);
    await store.forget("u1");
    assert.equal(await store.server("u1"), undefined);
  });

  test("an unreadable or schemaless file is absent", async () => {
    for (const [name, content] of [
      ["broken.json", "{"],
      ["noschema.json", "{}"],
      ["list.json", "[]"],
    ] as const) {
      const path = join(folder, name);
      writeFileSync(path, content);
      assert.equal(await loadDocument(path), undefined);
    }
    assert.equal(readServerRecord({ uid: 1 }), undefined);
  });
});
