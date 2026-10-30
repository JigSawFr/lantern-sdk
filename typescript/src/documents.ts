/**
 * Reading a document by the `schema` rule (SPEC.md § 3.2): a document of a
 * newer `schema` than the reader knows is absent, not an error, and is never
 * written back; the fields a reader does not know stay on the object it gives,
 * so that a document written back loses none of them.
 */

import { DocumentError, isObject, SCHEMA } from "./base.ts";
import { DOCUMENTS, type Documents } from "./generated/models.ts";
import { loadJson } from "./limits.ts";
import type { Check } from "./model.ts";

/** A document's `schema`: an integer, 1 or more; DocumentError otherwise. */
export function schemaOf(data: unknown, where = "document"): number {
  if (!isObject(data)) throw new DocumentError("not an object", where);
  const value = data["schema"];
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new DocumentError("no integer schema", where);
  }
  return value;
}

/** Whether a document's `schema` is above what the reader knows. */
export function isNewer(data: unknown, known: number = SCHEMA): boolean {
  return schemaOf(data) > known;
}

/**
 * `data` read by `check`, or undefined when its `schema` is newer than `known`
 * (the document is absent: SPEC.md § 3.2). DocumentError when it is not one.
 */
export function read<T>(
  check: Check<T>,
  data: unknown,
  options: { known?: number; where?: string } = {},
): T | undefined {
  const where = options.where ?? "document";
  if (schemaOf(data, where) > (options.known ?? SCHEMA)) return undefined;
  return check(data, where);
}

/**
 * Where a document carries its `schema` when not at its top: an event's is
 * its `data`'s (SPEC.md § 18.1), the document the event names.
 */
const SCHEMA_AT: Partial<Record<keyof Documents, string>> = { event: "data" };

/** A document of spec/schemas/v1 by its name (`homebrew`, `apps`…), read by the `schema` rule. */
export function readNamed<K extends keyof Documents>(
  name: K,
  data: unknown,
  known: number = SCHEMA,
): Documents[K] | undefined {
  const at = SCHEMA_AT[name];
  if (at !== undefined) {
    if (!isObject(data)) throw new DocumentError("not an object", name);
    if (schemaOf(data[at], `${name}.${at}`) > known) return undefined;
    return (DOCUMENTS[name] as Check<Documents[K]>)(data, name);
  }
  return read(DOCUMENTS[name] as Check<Documents[K]>, data, { known, where: name });
}

/** read() of a JSON document's bytes, within SPEC.md § 13's limits. */
export function parse<T>(
  check: Check<T>,
  raw: Uint8Array | string,
  options: { known?: number; where?: string } = {},
): T | undefined {
  const where = options.where ?? "document";
  return read(check, loadJson(raw, { where }), options);
}
