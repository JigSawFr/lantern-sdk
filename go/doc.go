// SPDX-License-Identifier: MIT

// Package lantern is the Go side of the Lantern protocol (https://lantern.boreale.dev/spec/):
// one protocol between homebrews on consoles and a library server you run.
//
// This package holds what the client and the server share: the documents of
// the specification as typed values generated from its JSON Schemas (and kept
// whole when they hold fields this version does not know), the vocabularies,
// the errors, the rule of the `schema` field (SPEC.md § 3.2), canonical JSON
// (SPEC.md § 2.3), digests and the limits of SPEC.md § 13, the checks of a homebrew and the
// end-to-end encryption of save backups, the reader of an event stream, grants, sync's merge rule and the chunker of differential updates. Its one dependency beyond the standard library is
// golang.org/x/crypto, for XChaCha20-Poly1305.
//
// The documents are generated: run `go generate ./...` after the
// specification's schemas change.
package lantern

//go:generate go run ./internal/gen
