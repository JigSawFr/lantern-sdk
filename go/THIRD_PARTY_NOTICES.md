<!-- SPDX-License-Identifier: MIT -->
# Third-party notices

The Go library's source is MIT. It depends on one module outside the standard library, fetched by
the Go toolchain and not copied into this repository:

| Module | Used for | Licence |
|---|---|---|
| `golang.org/x/crypto` | XChaCha20-Poly1305, the AEAD of encrypted saves (SPEC.md § 9.4) | BSD-3-Clause, Copyright 2009 The Go Authors |
| `golang.org/x/sys` | what `x/crypto` itself needs (CPU feature detection) | BSD-3-Clause, Copyright 2009 The Go Authors |

Their licence text is in each module (`LICENSE`), and in the Go module cache next to the sources.
A program that builds on this library should carry it with its own notices.
