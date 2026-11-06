/**
 * The families the toolkit's demo offers a caller who holds every scope, as
 * JSON: what the SDK's table of families (README.md) is checked against
 * (tools/check_matrix.py). Run from typescript/.
 */

import { FAMILIES } from "../src/vocabulary.ts";
import { demoAccounts, EVERY_SCOPE, makeLantern } from "../test/demo.ts";

const app = await makeLantern({ accounts: await demoAccounts() });
const offered = app.features({ scopes: new Set(EVERY_SCOPE), state: "active" });
process.stdout.write(
  `${JSON.stringify({ families: [...FAMILIES], server: FAMILIES.filter((f) => (offered[f] ?? 0) > 0) })}\n`,
);
