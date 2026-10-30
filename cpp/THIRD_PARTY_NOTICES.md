# Third-party notices

What the C++ library vendors, as published, never edited. Each file's
licence is also in the repository's `REUSE.toml`, and each licence's text
in `LICENSES/`.

## Monocypher 4.0.2 (in the library)

- Files: `third_party/monocypher/monocypher.c`, `monocypher.h`,
  `monocypher-ed25519.c` and `monocypher-ed25519.h` (from `src/` and
  `src/optional/` of the release), and its `LICENCE.md`.
- Used for: ed25519 (RFC 8032), with the SHA-512 of `monocypher-ed25519.c`:
  signature checks (`crypto_ed25519_check`), and the device key of SPEC.md
  § 5.4 (`crypto_ed25519_key_pair`, `crypto_ed25519_sign`, and
  `crypto_wipe` for its private half). Nothing else of it is called.
- From: <https://monocypher.org/download/monocypher-4.0.2.tar.gz>, checked
  against the SHA-512 the site publishes next to it:
  `bf275d4c53ff94af6cdc723a4e002e9f080f4d1436c86c76bb37870b34807f1d7b32331d8ff8a1aeb369e946f3769021e03e63efac25b82efc5abf54dc084714`.
- Licence: `BSD-2-Clause OR CC0-1.0`, at the user's choice.
  Copyright (c) 2017-2023 Loup Vaillant, 2017-2019 Michael Savage,
  2017-2023 Fabio Scotoni.

## doctest 2.4.12 (tests only, never in the library)

- File: `third_party/doctest/doctest.h` (the single header), and its
  `LICENSE.txt`.
- From: <https://raw.githubusercontent.com/doctest/doctest/v2.4.12/doctest/doctest.h>,
  SHA-256 `94029a7d32da24a56249658147dbd2b33ff0b9ed665295cbbaf19aafff5b0ced`.
- Licence: MIT. Copyright (c) 2016-2023 Viktor Kirilov.
