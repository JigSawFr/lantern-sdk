/**
 * lantern-protocol: the TypeScript library of the Lantern protocol
 * (https://lantern.boreale.dev/), for a browser and Node. This entry holds
 * nothing of Node's: the client over fetch(), the documents and their checks,
 * signatures, pinning, profiles and homebrew rules. `lantern-protocol/node`
 * adds the Node transport that pins keys, files and discovery;
 * `lantern-protocol/server`, the server toolkit.
 */

export * from "./base.ts";
export * as bytes from "./bytes.ts";
export {
  type AppsOptions,
  type ClientOptions,
  type Deprecation,
  type DownloadOptions,
  type HomebrewOptions,
  LanternClient,
  type ListOptions,
  type SaveOptions,
  type TransportFactory,
  type UploadOptions,
  VERSION,
  whatFits,
} from "./client/client.ts";
export {
  blobSource,
  bytesSource,
  type DownloadSink,
  MemorySink,
  type UploadSource,
  Verifier,
} from "./client/download.ts";
export { checkPairingCode, type InvitationLink, invitationLink, Pairing } from "./client/pairing.ts";
export {
  BearerToken,
  type Credentials,
  DeviceSigner,
  FetchTransport,
  Pipeline,
  type RequestSigner,
  readBody,
  type SendOptions,
  type Transport,
  type TransportRequest,
  type TransportResponse,
} from "./client/transport.ts";
export { contentDigest, digestSha256, formatDigest, parseDigest } from "./digest.ts";
export * as discovery from "./discovery.ts";
export { isNewer, parse, read, readNamed, schemaOf } from "./documents.ts";
export * as ed25519 from "./ed25519.ts";
export * from "./errors.ts";
export * from "./generated/models.ts";
export * as homebrew from "./homebrew.ts";
export * as http from "./http.ts";
export * as limits from "./limits.ts";
export type { Check } from "./model.ts";
export * from "./pinning.ts";
export * as profiles from "./profiles.ts";
export * as ratings from "./ratings.ts";
export { definition, isValid, names as schemaNames, validate } from "./schema.ts";
export { type Hasher, type HasherFactory, Sha256, sha256, sha256Factory, sha256Hex } from "./sha256.ts";
export * as signatures from "./signatures.ts";
export { DeviceKey } from "./signatures.ts";
export { CertificateError, checkPin, short, spkiDer, spkiDigest, spkiSha256 } from "./spki.ts";
export * as vocabulary from "./vocabulary.ts";
