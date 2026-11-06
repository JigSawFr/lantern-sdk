/**
 * The files of examples/, run as a user would run them: the reader against the demo server, the server from
 * its command line (answering the handshake), the static library written then read. The site and the README
 * show these files, so they cannot drift from the library.
 */

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import { promisify } from "node:util";
import { listen } from "../../src/server/index.ts";
import { makeLantern } from "../demo.ts";
import { PACKAGE } from "../helpers.ts";

const run = promisify(execFile);
const EXAMPLES = join(PACKAGE, "examples");
const folder = mkdtempSync(join(tmpdir(), "lantern-examples-"));
after(() => rmSync(folder, { recursive: true, force: true }));

function node(name: string, ...args: string[]): readonly string[] {
  return ["--conditions=source", join(EXAMPLES, name), ...args];
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const { port } = server.address() as AddressInfo;
  await new Promise((done) => server.close(done));
  return port;
}

describe("examples", () => {
  test("read-library against the demo", async () => {
    const served = await listen(await makeLantern(), { port: 0, host: "127.0.0.1" });
    try {
      const { stdout } = await run(process.execPath, node("read-library.ts", served.url), { timeout: 60_000 });
      assert.match(stdout, /^Demo shelf: /);
      assert.match(stdout, /Copper Moth/);
      assert.match(stdout, /matched/);
    } finally {
      await served.close();
    }
  });

  test("static-library writes a library, then reads it", async () => {
    const out = join(folder, "shelf");
    const { stdout } = await run(process.execPath, node("static-library.ts", out), { timeout: 60_000 });
    assert.match(stdout, /Shelf on a stick \["Frost Garden"\]/);
    assert.equal(
      (JSON.parse(readFileSync(join(out, "lantern.json"), "utf8")) as { name: string }).name,
      "Shelf on a stick",
    );
  });

  test("serve-node answers the handshake", async () => {
    const port = await freePort();
    const child = spawn(process.execPath, node("serve-node.ts", String(port)), { stdio: "ignore" });
    try {
      let hello: { name: string } | undefined;
      for (let i = 0; i < 100 && hello === undefined; i++) {
        try {
          hello = (await (await fetch(`http://127.0.0.1:${port}/.well-known/lantern`)).json()) as { name: string };
        } catch {
          await new Promise((done) => setTimeout(done, 200));
        }
      }
      assert.equal(hello?.name, "Living room shelf");
    } finally {
      child.kill();
    }
  });
});
