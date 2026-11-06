// A `Range` request header (RFC 9110 § 14), as SPEC.md § 6.6 asks a file
// to honour it: one range of bytes, from a start, to an end or from the
// end. Shared by what serves files (a peer, a server).
#pragma once

#include <cstdint>
#include <string_view>

namespace lantern
{

enum class RangeVerdict : std::uint8_t
{
    ignored, // not a range this reader honours (another unit, several ranges, nonsense): send the whole file
    satisfiable, // `first` to `last`, both inside the file
    unsatisfiable, // outside the file: 416 with `Content-Range: bytes */size`
};

struct RangeParse
{
    RangeVerdict verdict = RangeVerdict::ignored;
    std::uint64_t first  = 0;
    std::uint64_t last   = 0; // inclusive
};

// "bytes=a-b", "bytes=a-" or "bytes=-n" over a file of `size` bytes; `last`
// is cut to the file's end.
[[nodiscard]] RangeParse parse_range_header(std::string_view value, std::uint64_t size) noexcept;

} // namespace lantern
