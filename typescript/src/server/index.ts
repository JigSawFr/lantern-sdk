/**
 * lantern-protocol/server: the server toolkit for Node, what a server author
 * needs to add Lantern to an existing app. LanternApp answers the routes over a
 * Library the app implements (MemoryLibrary is one) and, with an Accounts store
 * (MemoryAccounts is one), pairs devices, checks signed requests, redeems
 * invitations, applies rating caps and answers the administration API. The
 * pieces it is made of (problem+json, cursors, files with ranges and digests,
 * the platform filter, the pairing desk, LAN discovery) are usable on their own.
 */

export {
  ACCOUNT_NAME,
  AccountError,
  type Accounts,
  CODE_ALPHABET,
  type Device,
  type Invitation,
  type IssueOptions,
  MemoryAccounts,
  newCode,
  newToken,
  orderedScopes,
  SCOPES,
  tokenHash,
  typedCode,
  type User,
  utc,
} from "./accounts.ts";
export { type AdapterOptions, fetchHandler, listen, nodeHandler } from "./adapters.ts";
export { checkContentDigest, LanternApp, type LanternAppOptions, missing } from "./app.ts";
export { DiscoveryResponder, discoveryReply, isLocalAddress } from "./discovery.ts";
export { FileRef, fileResponse, parseRange } from "./files.ts";
export {
  BODY_LIMIT,
  badRequest,
  cachingHeaders,
  contentCoding,
  emptyResponse,
  type FileBody,
  HttpProblem,
  htmlResponse,
  jsonResponse,
  notFound,
  platformOf,
  problemResponse,
  readDocument,
  ServerRequest,
  type ServerResponse,
} from "./http.ts";
export {
  type Account,
  type Authenticate,
  checkHomebrew,
  type Journal,
  LIBRARY_FAMILIES,
  type Library,
  MemoryJournal,
  MemoryLibrary,
  makePackage,
  zipManifest,
} from "./library.ts";
export { Cursors, compareKeys, type Page, pageSize, Sealer, SinceTokens, type SortKey } from "./paging.ts";
export { approvalPage, Limiter, PairingDesk, type Pending, slowDown } from "./pairing.ts";
export { readZip, writeZip, type ZipFile } from "./zip.ts";
