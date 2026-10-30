/**
 * The command lantern-static (lantern-static.ts runs it): writes a Lantern server's library as a static library
 * (SPEC.md § 21), for a web host, a NAS's web server, a USB key or an SD card.
 *
 *     lantern-static --from https://shelf.example.org/ --out ./library [--token T --key FILE]
 *                    [--pin SPKI | --insecure] [--page-size 100] [--language en] [--name NAME]
 *
 * It reads the server as a client does (what the token may read is what is
 * written), downloads every file it lists and checks it by its SHA-256, then
 * writes `lantern.json` and `v1/` into the folder, replacing those of an
 * earlier export and nothing else. Check the result with the specification's
 * suite: `python3 spec/conformance/run.py --static ./library`.
 */

import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { DeviceKey } from "../signatures.ts";
import { NodeLanternClient } from "./index.ts";
import { clientInput, writeStatic } from "./static.ts";

const USAGE =
  "usage: lantern-static --from URL --out DIR [--token T --key FILE] [--pin SPKI | --insecure] " +
  "[--page-size N] [--language TAG] [--name NAME]";

export async function main(argv: string[]): Promise<number> {
  let values: Record<string, string | boolean | undefined>;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        from: { type: "string" },
        out: { type: "string" },
        token: { type: "string" },
        key: { type: "string" },
        pin: { type: "string" },
        insecure: { type: "boolean" },
        "page-size": { type: "string" },
        language: { type: "string" },
        name: { type: "string" },
        help: { type: "boolean", short: "h" },
      },
      strict: true,
    }));
  } catch (e) {
    console.error(`lantern-static: ${e instanceof Error ? e.message : String(e)}\n${USAGE}`);
    return 2;
  }
  if (values["help"]) {
    console.error(USAGE);
    return 0;
  }
  const from = values["from"];
  const out = values["out"];
  if (typeof from !== "string" || typeof out !== "string") {
    console.error(`lantern-static: --from and --out are needed\n${USAGE}`);
    return 2;
  }
  const pageSize = values["page-size"] !== undefined ? Number(values["page-size"]) : 100;
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 1000) {
    console.error("lantern-static: --page-size is 1 to 1000");
    return 2;
  }
  const options: ConstructorParameters<typeof NodeLanternClient>[1] = { userAgent: "lantern-static/0.1" };
  if (typeof values["token"] === "string") options.token = values["token"];
  if (typeof values["key"] === "string") {
    options.key = await DeviceKey.fromBase64((await readFile(values["key"], "utf8")).trim());
  }
  if (typeof values["pin"] === "string") options.pin = values["pin"];
  if (values["insecure"]) options.verify = false;
  if (typeof values["language"] === "string") options.acceptLanguage = values["language"];
  const client = new NodeLanternClient(from, options);
  try {
    const input = await clientInput(client);
    if (typeof values["name"] === "string") input.name = values["name"];
    const language = typeof values["language"] === "string" ? values["language"] : "en";
    const done = await writeStatic(input, out, { pageSize, language });
    console.error(
      `lantern-static: ${done.documents} documents and ${done.files} files of ${done.platforms.join(", ") || "no platform"} in ${out}`,
    );
    return 0;
  } catch (e) {
    console.error(`lantern-static: ${e instanceof Error ? e.message : String(e)}`);
    return 1;
  } finally {
    await client.close();
  }
}
