// gzip (RFC 1952) for a JSON answer a server compressed (SPEC.md § 2.1): the
// client asks for `Content-Encoding: gzip` and reads it with this, in the
// library itself, so a platform without zlib needs nothing more. The limits of
// § 13 apply to the document once decompressed, so the output is bounded:
// a body that expands without end is refused at the limit, not after it.
#pragma once

#include <cstddef>
#include <span>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>

namespace lantern
{

// Appends what `gzip` decompresses to, members one after the other as the
// format allows, each checked against its CRC-32 and its size. Category::limit
// when the output would pass `max_output` bytes; Category::invalid_response
// for a body that is not gzip, is cut, or does not check.
[[nodiscard]] Result<void> gunzip(std::span<const std::byte> gzip, std::size_t max_output, String& output);

} // namespace lantern
