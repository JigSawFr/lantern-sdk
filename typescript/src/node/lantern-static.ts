#!/usr/bin/env node
/** The `lantern-static` command: see static-cli.ts. */

import { main } from "./static-cli.ts";

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    console.error(e);
    process.exitCode = 1;
  },
);
