// gzip (RFC 1952) for a JSON answer a server offers compressed (SPEC.md
// § 2.1): deflate (RFC 1951) with LZ77 over a window of 32 KiB and the fixed
// Huffman code, written in the library itself, so a platform without zlib
// needs nothing more. The same input always gives the same bytes. The reader
// is gunzip() (lantern/inflate.hpp).
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/memory.hpp>

namespace lantern
{

// Appends `data` as one gzip member to `output`. Working tables of about
// 192 KiB come from the allocator of `output`, for the time of the call.
void gzip(std::span<const std::byte> data, String& output);

// The CRC-32 of RFC 1952 (the one gzip checks).
[[nodiscard]] std::uint32_t gzip_crc32(std::span<const std::byte> data) noexcept;

// Whether an `Accept-Encoding` header (RFC 9110 § 12.5.3) lets a server answer
// with gzip: `gzip` (or `x-gzip`) with a q-value above 0, or `*` with one when
// gzip is not named, and not ranked below `identity` when the client names it.
// A q-value that is malformed counts as 0.
[[nodiscard]] bool accepts_gzip(std::string_view accept_encoding) noexcept;

} // namespace lantern
