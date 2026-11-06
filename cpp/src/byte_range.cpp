// SPEC.md § 6.6: the Range header of a file.
#include <lantern/byte_range.hpp>

#include <algorithm>
#include <charconv>
#include <system_error>

namespace lantern
{

namespace
{

bool number(std::string_view text, std::uint64_t& out) noexcept
{
    const auto result = std::from_chars(text.data(), text.data() + text.size(), out);
    return !text.empty() && result.ec == std::errc {} && result.ptr == text.data() + text.size();
}

} // namespace

RangeParse parse_range_header(std::string_view value, std::uint64_t size) noexcept
{
    constexpr std::string_view unit = "bytes=";
    RangeParse out;
    if (!value.starts_with(unit))
        return out;
    value.remove_prefix(unit.size());
    if (value.contains(','))
        return out;
    const std::size_t dash = value.find('-');
    if (dash == std::string_view::npos)
        return out;
    const std::string_view a = value.substr(0, dash);
    const std::string_view b = value.substr(dash + 1);
    std::uint64_t first      = 0;
    std::uint64_t last       = 0;
    if (a.empty())
    {
        std::uint64_t suffix = 0;
        if (!number(b, suffix))
            return out;
        if (suffix == 0 || size == 0)
        {
            out.verdict = RangeVerdict::unsatisfiable;
            return out;
        }
        first = size - std::min(size, suffix);
        last  = size - 1;
    }
    else
    {
        if (!number(a, first))
            return out;
        if (b.empty())
            last = size == 0 ? 0 : size - 1;
        else if (!number(b, last) || last < first)
            return out;
        if (first >= size)
        {
            out.verdict = RangeVerdict::unsatisfiable;
            return out;
        }
        last = std::min(last, size - 1);
    }
    out.verdict = RangeVerdict::satisfiable;
    out.first   = first;
    out.last    = last;
    return out;
}

} // namespace lantern
