#include <lantern/encoding.hpp>

#include <algorithm>
#include <array>

namespace lantern
{

namespace
{

constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int sextet(char c) noexcept
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

} // namespace

void base64_encode(std::span<const std::uint8_t> bytes, String& out)
{
    std::size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3)
    {
        const std::uint32_t group
            = (std::uint32_t { bytes[i] } << 16U) | (std::uint32_t { bytes[i + 1] } << 8U) | bytes[i + 2];
        out.push_back(alphabet[(group >> 18U) & 63U]);
        out.push_back(alphabet[(group >> 12U) & 63U]);
        out.push_back(alphabet[(group >> 6U) & 63U]);
        out.push_back(alphabet[group & 63U]);
    }
    const std::size_t rest = bytes.size() - i;
    if (rest == 1)
    {
        const std::uint32_t group = std::uint32_t { bytes[i] } << 16U;
        out.push_back(alphabet[(group >> 18U) & 63U]);
        out.push_back(alphabet[(group >> 12U) & 63U]);
        out.append("==");
    }
    else if (rest == 2)
    {
        const std::uint32_t group
            = (std::uint32_t { bytes[i] } << 16U) | (std::uint32_t { bytes[i + 1] } << 8U);
        out.push_back(alphabet[(group >> 18U) & 63U]);
        out.push_back(alphabet[(group >> 12U) & 63U]);
        out.push_back(alphabet[(group >> 6U) & 63U]);
        out.push_back('=');
    }
}

std::optional<std::size_t> base64_decoded_size(std::string_view text) noexcept
{
    if (text.size() % 4 != 0)
        return std::nullopt;
    std::size_t padding = 0;
    if (!text.empty() && text.back() == '=')
        padding = (text.size() >= 2 && text[text.size() - 2] == '=') ? 2 : 1;
    return text.size() / 4 * 3 - padding;
}

void base64url_encode(std::span<const std::uint8_t> bytes, String& out)
{
    const std::size_t start = out.size();
    base64_encode(bytes, out);
    while (out.size() > start && out.back() == '=')
        out.pop_back();
    for (std::size_t i = start; i < out.size(); ++i)
    {
        if (out[i] == '+')
            out[i] = '-';
        else if (out[i] == '/')
            out[i] = '_';
    }
}

std::size_t base64url_encode(std::span<const std::uint8_t> bytes, std::span<char> out) noexcept
{
    static constexpr std::string_view url
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const std::size_t size = (bytes.size() * 4 + 2) / 3;
    if (out.size() < size)
        return 0;
    std::size_t at      = 0;
    std::uint32_t group = 0;
    unsigned bits       = 0;
    for (const std::uint8_t byte : bytes)
    {
        group = (group << 8U) | byte;
        bits += 8;
        while (bits >= 6)
        {
            bits -= 6;
            out[at++] = url[(group >> bits) & 63U];
        }
    }
    if (bits > 0)
        out[at++] = url[(group << (6 - bits)) & 63U];
    return at;
}

bool is_base64url(std::string_view text, std::size_t min, std::size_t max) noexcept
{
    return text.size() >= min && text.size() <= max
        && std::ranges::all_of(text,
            [](char c)
            {
                return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
                    || c == '_';
            });
}

bool base64_decode(std::string_view text, std::span<std::uint8_t> out) noexcept
{
    const auto size = base64_decoded_size(text);
    if (!size || *size != out.size())
        return false;
    std::size_t written = 0;
    for (std::size_t i = 0; i < text.size(); i += 4)
    {
        const bool last = i + 4 == text.size();
        std::array<int, 4> values {};
        std::size_t padding = 0;
        for (std::size_t k = 0; k < 4; ++k)
        {
            const char c = text[i + k];
            if (c == '=')
            {
                // Only at the end, and only as the last one or two characters
                if (!last || k < 2)
                    return false;
                ++padding;
                values[k] = 0;
                continue;
            }
            if (padding != 0)
                return false;
            values[k] = sextet(c);
            if (values[k] < 0)
                return false;
        }
        const std::uint32_t group = (static_cast<std::uint32_t>(values[0]) << 18U)
            | (static_cast<std::uint32_t>(values[1]) << 12U) | (static_cast<std::uint32_t>(values[2]) << 6U)
            | static_cast<std::uint32_t>(values[3]);
        // Canonical: the bits past the end are zero
        if ((padding == 1 && (group & 0xFFU) != 0) || (padding == 2 && (group & 0xFFFFU) != 0))
            return false;
        out[written++] = static_cast<std::uint8_t>(group >> 16U);
        if (padding < 2)
            out[written++] = static_cast<std::uint8_t>(group >> 8U);
        if (padding < 1)
            out[written++] = static_cast<std::uint8_t>(group);
    }
    return written == out.size();
}

void percent_encode(std::string_view text, String& out)
{
    static constexpr std::string_view hex = "0123456789ABCDEF";
    for (const char c : text)
    {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '.' || c == '_' || c == '~';
        if (unreserved)
        {
            out.push_back(c);
            continue;
        }
        const auto byte = static_cast<unsigned char>(c);
        out.push_back('%');
        out.push_back(hex[byte >> 4U]);
        out.push_back(hex[byte & 0x0FU]);
    }
}

} // namespace lantern
