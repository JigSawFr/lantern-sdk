# lantern-protocol (Rust)

The Rust library of the [Lantern protocol](https://lantern.boreale.dev/), the
open protocol between console homebrews and the library servers people run at
home. Draft 0.11, nothing released yet. The plan is in the workbench; this
README says what is there.

## What is there

- **The documents** as typed structs, generated from the specification's JSON
  Schemas (`spec/schemas/v1`) by `tools/generate.py`: a struct per object,
  every field it does not know kept in `extra` and written back (SPEC.md
  § 3.2), a `null` kept as `null`. `generated::round_trip(name, value)` reads a
  document by its schema's name and writes it back. The vocabularies the
  schemas enumerate (genres, scopes, error codes…) are constants.
- Every example of the specification reads and writes back unchanged
  (`tests/examples.rs`).
- **The core, without input or output**: canonical JSON (RFC 8785), SHA-256
  digests, key fingerprints (SPKI), hex and base64; the limits of SPEC.md § 13
  and the I-JSON checks a reader applies; the `schema` rule (an unknown field
  kept, a newer `schema` read as absent); the server's problem+json answers as
  errors by status; the vocabulary, the variants and the platform profiles
  (title ids, paths, version codes); UUID v4 and v7 from bytes the caller
  draws and a clock the caller reads. The specification's vectors pass
  (`tests/vectors.rs`, `tests/rules.rs`, `tests/profiles.rs`).
- The readers are fuzzed (`fuzz/`, cargo-fuzz): `cargo +nightly fuzz run
  documents` (or `answers`, `fields`), run for 30 seconds each in CI.

What follows, a slice at a time, the same as the other languages: the client
(signatures, pairing, downloads), then the server toolkit. The table of families in the repository's README says where each
stands.

## Checks

```sh
python3 tools/generate.py --check   # the generated files are those of the pinned specification
cargo fmt --check
cargo clippy --locked --all-targets --all-features
cargo test --locked --all-features
cargo doc --locked --no-deps
cargo deny check                     # licences and advisories (cargo install cargo-deny)
```

The library forbids `unsafe`, and denies `unwrap`, `expect`, indexing and
`panic!` outside the tests: what comes from the network never panics.

Rust 1.90 or later (`rust-version`); CI also runs the newest stable
(`rust-toolchain.toml`) and builds for `wasm32-unknown-unknown`.
