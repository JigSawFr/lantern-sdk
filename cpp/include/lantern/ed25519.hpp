// Ed25519 (RFC 8032) verification, by Monocypher (third_party/monocypher),
// and the homebrew signature of SPEC.md § 8.4.
#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/types.hpp>

namespace lantern
{

using PublicKey      = std::array<std::uint8_t, 32>;
using SignatureBytes = std::array<std::uint8_t, 64>;

// Whether `signature` is `public_key`'s over `message`.
[[nodiscard]] bool ed25519_verify(const SignatureBytes& signature, const PublicKey& public_key,
    std::span<const std::uint8_t> message) noexcept;

// A package's signature: its key, when it has one.
struct PackageSignature
{
    bool is_signed = false;
    PublicKey public_key {};
};

// § 8.4: checks the signature that covers `package` (the entry's for
// entry.package, the package's own for one of entry.packages) over the
// canonical bytes, with the entry's id, platform and build and the
// package's sha256 and manifest_sha256. An unsigned package is not an
// error (is_signed is false), unless the entry is signed and the package,
// one of `packages`, is not. A signature that does not verify, of another
// algorithm, or whose key or value is not base64 of 32 and 64 bytes, is
// refused (Category::signature): install nothing.
[[nodiscard]] Result<PackageSignature> verify_package_signature(
    const Homebrew& entry, const Package& package);

// The short fingerprint of § 5.3 and § 8.4, "3F9A 1C07 B2E4 55D0": the first
// 16 hex digits of the SHA-256 of `bytes`, upper case, in groups of 4.
[[nodiscard]] std::array<char, 19> short_fingerprint(std::span<const std::uint8_t> bytes) noexcept;

} // namespace lantern
