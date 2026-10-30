/**
 * lantern-protocol/server: the server toolkit for Node, what a server author
 * needs to add Lantern to an existing app. LanternApp answers the routes over a
 * Library the app implements (MemoryLibrary is one: sections and cheat writes
 * included) and, with an Accounts store (MemoryAccounts is one), pairs
 * devices, checks signed requests, redeems invitations, applies rating caps,
 * answers the administration API (deleting accounts included), streams
 * events, signs grants, and keeps sync data, save backups (encrypted ones as
 * sent; MemorySaveStore, FileSaveStore) and requests (MemoryRequestStore);
 * PeerServer is a console's sharing (§ 19.4). The
 * pieces it is made of (problem+json, cursors, files with ranges and digests,
 * the platform filter, the pairing desk, LAN discovery) are usable on their own.
 */

export { missing } from "../missing.ts";
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
export { CHEAT_BODY, checkContentDigest, LanternApp, type LanternAppOptions } from "./app.ts";
export { DiscoveryResponder, discoveryReply, isLocalAddress } from "./discovery.ts";
export {
  type Audience,
  EVENT_SCOPES,
  EventHub,
  type HubEvent,
  type LibraryChange,
  sseEvent,
} from "./events.ts";
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
  isStream,
  jsonResponse,
  notFound,
  platformOf,
  problemResponse,
  readDocument,
  ServerRequest,
  type ServerResponse,
  type StreamBody,
} from "./http.ts";
export {
  type Account,
  type Authenticate,
  type CheatInit,
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
export { type PeerOptions, PeerServer, peerFiles } from "./peer.ts";
export {
  MemoryRequestStore,
  REQUEST_STATUSES,
  type RequestStatus,
  type RequestStore,
  type StoredRequest,
} from "./requests.ts";
export {
  FileSaveStore,
  MemorySaveStore,
  type SaveFields,
  type SaveStore,
  saveContentType,
  type UploadState,
} from "./saves.ts";
export { MemorySyncStore, publicItem, type SentItem, type StoredItem, type SyncStore } from "./sync.ts";
export { readZip, writeZip, type ZipFile } from "./zip.ts";
