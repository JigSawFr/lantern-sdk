// Base64 (RFC 4648 § 4, with padding) and percent-encoding: the forms the
// protocol's keys, signatures, digests and query strings take.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/memory.hpp>

namespace lantern
{

void base64_encode(std::span<const std::uint8_t> bytes, String& out);
// Decodes into `out`, which must be exactly the decoded size: a key of 32
// bytes, a signature of 64. Refuses anything not canonical (missing or
// extra padding, bits set past the end, characters outside the alphabet).
[[nodiscard]] bool base64_decode(std::string_view text, std::span<std::uint8_t> out) noexcept;
// The decoded size of a well-padded text, or nothing.
[[nodiscard]] std::optional<std::size_t> base64_decoded_size(std::string_view text) noexcept;

// Percent-encodes everything but RFC 3986's unreserved characters.
void percent_encode(std::string_view text, String& out);

} // namespace lantern
