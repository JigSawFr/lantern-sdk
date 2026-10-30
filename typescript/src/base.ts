/** What every other module builds on: JSON values, the schema this library reads, and its root errors. */

/** A JSON value, as JSON.parse() gives it. */
export type JSONValue = null | boolean | number | string | JSONValue[] | { [key: string]: JSONValue };
/** A JSON object. */
export type JSONObject = { [key: string]: JSONValue };

/** The `schema` this library reads and writes, for every family (SPEC.md § 3.2). */
export const SCHEMA = 1;

/** Every error this library throws. */
export class LanternError extends Error {
  override name = "LanternError";
}

/**
 * A document that breaks the specification: malformed JSON, a missing field,
 * a field of the wrong type, or one beyond the limits of SPEC.md § 13.
 * `where` says which field, as a path (`homebrew.package.manifest[2].path`).
 */
export class DocumentError extends LanternError {
  override name = "DocumentError";
  readonly where: string;
  readonly reason: string;

  constructor(reason: string, where = "") {
    super(where ? `${where}: ${reason}` : reason);
    this.where = where;
    this.reason = reason;
  }
}

/** What this platform cannot do: Ed25519 missing from its WebCrypto, say. */
export class Unsupported extends LanternError {
  override name = "Unsupported";
}

/** Whether `value` is a JSON object (not an array, not null). */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
