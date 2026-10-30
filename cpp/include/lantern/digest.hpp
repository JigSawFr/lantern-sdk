// The digest fields of RFC 9530: Repr-Digest on every file a server sends
// (SPEC.md § 6.6), Content-Digest on a save sent in one request (§ 9.2).
// Both are Structured Field dictionaries of byte sequences:
//     Repr-Digest: sha-256=:<base64>:
#pragma once

#include <optional>
#include <string_view>

#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>

namespace lantern
{

// `sha-256=:<base64>:`, the value of either header.
void format_digest_field(const Digest& digest, String& out);

// What a Repr-Digest or Content-Digest says of SHA-256.
enum class DigestField : std::uint8_t
{
    sha256, // a sha-256 member, well formed
    absent, // no sha-256 member (another algorithm only, or no header)
    malformed, // a sha-256 member that is not 32 bytes of base64, or a field that is not a dictionary
};

struct ParsedDigest
{
    DigestField state = DigestField::absent;
    Digest sha256 {};
};

// Reads the sha-256 member of the field, skipping other algorithms and
// parameters (`sha-512=:…:, sha-256=:…:;x=1`).
[[nodiscard]] ParsedDigest parse_digest_field(std::string_view value) noexcept;

} // namespace lantern
