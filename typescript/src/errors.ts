/**
 * Errors: a server's problem+json answers (SPEC.md § 12), as classes by
 * status, and the client's own.
 *
 * A server's answer becomes the class of its status (NotFound for 404, Gone
 * for 410…), whatever its `code`: a code this library does not know is read
 * by its status alone, as SPEC.md § 12 asks. `code` is then undefined;
 * `problem` keeps the document as the server sent it.
 */

import { DocumentError, LanternError, Unsupported } from "./base.ts";
import { ERROR_CODES, type Problem, readProblem } from "./generated/models.ts";
import { loadJson, printable } from "./limits.ts";
import { type AcceptSignature, parseAcceptSignature } from "./signatures.ts";
import { short } from "./spki.ts";

export { DocumentError, LanternError, Unsupported };

const DETAIL_LIMIT = 512;
const KNOWN_CODES: ReadonlySet<string> = new Set(ERROR_CODES);

/**
 * A server's error answer (SPEC.md § 12): its `status`, its `code` when this
 * library knows it (undefined otherwise: act on the status), `detail` for
 * people (bounded, without control characters), and `retryAfter` in seconds
 * when the server said.
 */
export class ProblemError extends LanternError {
  override name = "ProblemError";
  readonly status: number;
  readonly problem: Problem | undefined;
  readonly headers: Headers;
  readonly code: string | undefined;
  readonly detail: string | undefined;
  readonly retryAfter: number | undefined;

  constructor(status: number, problem?: Problem, headers?: Headers) {
    const raw = problem?.code;
    const code = raw !== undefined && KNOWN_CODES.has(raw) ? raw : undefined;
    const text = problem?.detail ?? problem?.title;
    const detail = text ? printable(text, DETAIL_LIMIT) : undefined;
    super(`${status} ${code ?? "error"}${detail ? `: ${detail}` : ""}`);
    this.status = status;
    this.problem = problem;
    this.headers = headers ?? new Headers();
    this.code = code;
    this.detail = detail;
    this.retryAfter = seconds(this.headers.get("Retry-After"));
  }
}

/** 400, and 405 and 416 (`bad_request`). */
export class BadRequest extends ProblemError {
  override name = "BadRequest";
}
/** 401: no token where one is needed, or one the server does not take. */
export class Unauthorized extends ProblemError {
  override name = "Unauthorized";
}

/**
 * 401 for a request's signature (SPEC.md § 5.4). `acceptSignature` is what the
 * server's Accept-Signature asks for, when it sent one; `date` is its Date header.
 */
export class SignatureRefused extends Unauthorized {
  override name = "SignatureRefused";
  readonly acceptSignature: AcceptSignature | undefined;
  readonly date: string | undefined;

  constructor(status: number, problem?: Problem, headers?: Headers) {
    super(status, problem, headers);
    this.acceptSignature = parseAcceptSignature(this.headers.get("Accept-Signature") ?? undefined);
    this.date = this.headers.get("Date") ?? undefined;
  }
}
/** 401 `signature_required`: the token is bound to a key, or the server takes only bound tokens. */
export class SignatureRequired extends SignatureRefused {
  override name = "SignatureRequired";
}
/** 401 `signature_invalid`: not the token's key, or not the form of SPEC.md § 5.4. Pair again rather than retry. */
export class SignatureInvalid extends SignatureRefused {
  override name = "SignatureInvalid";
}
/** 401 `signature_expired`: `created` was outside the server's window. */
export class SignatureExpired extends SignatureRefused {
  override name = "SignatureExpired";
}
/** 401 `signature_replayed`: a nonce the server saw: the request was not taken. */
export class SignatureReplayed extends SignatureRefused {
  override name = "SignatureReplayed";
}
/** 403: a scope missing. */
export class Forbidden extends ProblemError {
  override name = "Forbidden";
}
/** 403 `account_frozen`: the account may do nothing for now. */
export class AccountFrozen extends Forbidden {
  override name = "AccountFrozen";
}
/** 404. */
export class NotFound extends ProblemError {
  override name = "NotFound";
}
/** 409. */
export class Conflict extends ProblemError {
  override name = "Conflict";
}
/** 410: an expired cursor or `since` token (read the list again from its start), a pairing, a file id. */
export class Gone extends ProblemError {
  override name = "Gone";
}
/** 413. */
export class TooLarge extends ProblemError {
  override name = "TooLarge";
}
/** 422: `unsupported_schema` or `digest_mismatch`. */
export class Unprocessable extends ProblemError {
  override name = "Unprocessable";
}
/** 429: wait `retryAfter` seconds. */
export class SlowDown extends ProblemError {
  override name = "SlowDown";
}
/** 500, or another 5xx: the server failed; try again later. */
export class ServerError extends ProblemError {
  override name = "ServerError";
}
/** 503: scanning or maintenance; `retryAfter` says when to come back. */
export class Unavailable extends ServerError {
  override name = "Unavailable";
}

type ProblemClass = new (status: number, problem?: Problem, headers?: Headers) => ProblemError;

const BY_STATUS: Readonly<Record<number, ProblemClass>> = {
  400: BadRequest,
  401: Unauthorized,
  403: Forbidden,
  404: NotFound,
  405: BadRequest,
  409: Conflict,
  410: Gone,
  413: TooLarge,
  416: BadRequest,
  422: Unprocessable,
  429: SlowDown,
  500: ServerError,
  503: Unavailable,
};

const SIGNATURE_ERRORS: Readonly<Record<string, ProblemClass>> = {
  signature_required: SignatureRequired,
  signature_invalid: SignatureInvalid,
  signature_expired: SignatureExpired,
  signature_replayed: SignatureReplayed,
};

/**
 * A document of a newer `schema` than this library reads: by SPEC.md § 3.2 it
 * is absent (the feature is unavailable), not an error of the server.
 */
export class NewerSchema extends LanternError {
  override name = "NewerSchema";
  readonly what: string;
  readonly schema: number;

  constructor(what: string, schema: number) {
    super(`${what}: schema ${schema}, newer than this library reads: treated as absent`);
    this.what = what;
    this.schema = schema;
  }
}

/**
 * A download that is not what its document says: its SHA-256 or its size
 * (SPEC.md § 6.6), or a `Repr-Digest` that contradicts the document. Nothing of it may be installed.
 */
export class IntegrityError extends LanternError {
  override name = "IntegrityError";
}

/** The connection failed, or the server's certificate was refused. */
export class TransportError extends LanternError {
  override name = "TransportError";
}

/**
 * The server's key is not the one pinned at pairing (SPEC.md § 5.3): an alarm,
 * not an error to retry. Nothing was sent over the connection. `seen` and
 * `pinned` are the two fingerprints (SHA-256, hex), to show the user.
 */
export class PinMismatch extends TransportError {
  override name = "PinMismatch";
  readonly seen: string;
  readonly pinned: string;

  constructor(seen: string, pinned: string, where = "") {
    super(`${where ? `${where}: ` : ""}the server's key changed: ${short(seen)}, pinned ${short(pinned)}`);
    this.seen = seen;
    this.pinned = pinned;
  }
}

/** Plain HTTP to an address that is not a loopback one (SPEC.md § 2). */
export class InsecureTransport extends TransportError {
  override name = "InsecureTransport";
}

/** An answer the protocol does not allow here: a redirect, an unexpected status or content type. */
export class UnexpectedResponse extends LanternError {
  override name = "UnexpectedResponse";
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

function seconds(value: string | null): number | undefined {
  const v = value?.trim();
  return v && /^\d{1,10}$/.test(v) ? Number(v) : undefined;
}

/**
 * The error for an answer: its class by status, its problem document when the
 * body is one (an unreadable body still gives the status).
 */
export function problemError(status: number, body: Uint8Array, headers?: Headers): ProblemError {
  let problem: Problem | undefined;
  try {
    problem = readProblem(loadJson(body, { limit: 1 << 16, where: "problem" }), "problem");
  } catch (e) {
    if (!(e instanceof DocumentError)) throw e;
    problem = undefined;
  }
  let cls: ProblemClass = BY_STATUS[status] ?? (status >= 500 ? ServerError : ProblemError);
  if (cls === Forbidden && problem?.code === "account_frozen") cls = AccountFrozen;
  if (cls === Unauthorized && problem?.code !== undefined) cls = SIGNATURE_ERRORS[problem.code] ?? cls;
  return new cls(status, problem, headers);
}
