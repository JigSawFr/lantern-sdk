#include <lantern/error.hpp>

#include <array>
#include <utility>

namespace lantern
{

namespace
{

struct CodeName
{
    Code code;
    std::string_view name;
};

constexpr std::array<CodeName, 13> code_names { {
    { Code::bad_request, "bad_request" },
    { Code::unauthorized, "unauthorized" },
    { Code::forbidden, "forbidden" },
    { Code::account_frozen, "account_frozen" },
    { Code::not_found, "not_found" },
    { Code::conflict, "conflict" },
    { Code::gone, "gone" },
    { Code::too_large, "too_large" },
    { Code::unsupported_schema, "unsupported_schema" },
    { Code::digest_mismatch, "digest_mismatch" },
    { Code::slow_down, "slow_down" },
    { Code::internal, "internal" },
    { Code::unavailable, "unavailable" },
} };

// The length of a UTF-8 sequence from its first byte, 0 when it is not one.
std::size_t sequence_length(unsigned char lead) noexcept
{
    if (lead < 0x80U)
        return 1;
    if ((lead & 0xE0U) == 0xC0U)
        return 2;
    if ((lead & 0xF0U) == 0xE0U)
        return 3;
    if ((lead & 0xF8U) == 0xF0U)
        return 4;
    return 0;
}

} // namespace

template <std::size_t N> void FixedText<N>::assign(std::string_view text) noexcept
{
    std::size_t out = 0;
    std::size_t i   = 0;
    while (i < text.size())
    {
        const auto lead          = static_cast<unsigned char>(text[i]);
        const std::size_t length = sequence_length(lead);
        if (length == 0 || i + length > text.size())
        {
            // Not UTF-8: shown as a replacement, one byte at a time
            if (out + 1 > N)
                break;
            data_[out++] = '?';
            ++i;
            continue;
        }
        if (out + length > N)
            break;
        if (length == 1)
        {
            data_[out++] = (lead < 0x20U || lead == 0x7FU) ? ' ' : static_cast<char>(lead);
        }
        else if (length == 2 && lead == 0xC2U && static_cast<unsigned char>(text[i + 1]) < 0xA0U)
        {
            // C1 control characters (U+0080 to U+009F)
            data_[out++] = ' ';
        }
        else
        {
            for (std::size_t k = 0; k < length; ++k)
                data_[out++] = text[i + k];
        }
        i += length;
    }
    size_ = out;
}

template class FixedText<200>;
template class FixedText<96>;
template class FixedText<32>;

Code code_for_status(std::uint16_t status) noexcept
{
    switch (status)
    {
        case 400:
        case 405:
        case 416:
            return Code::bad_request;
        case 401:
            return Code::unauthorized;
        case 403:
            return Code::forbidden;
        case 404:
            return Code::not_found;
        case 409:
            return Code::conflict;
        case 410:
            return Code::gone;
        case 413:
            return Code::too_large;
        case 429:
            return Code::slow_down;
        case 500:
            return Code::internal;
        case 503:
            return Code::unavailable;
        default:
            break;
    }
    if (status == 422)
        return Code::unknown;
    if (status >= 400 && status < 500)
        return Code::bad_request;
    if (status >= 500 && status < 600)
        return Code::internal;
    return Code::unknown;
}

std::string_view code_name(Code code) noexcept
{
    for (const auto& entry : code_names)
    {
        if (entry.code == code)
            return entry.name;
    }
    return code == Code::unknown ? "unknown" : "";
}

Code code_from_name(std::string_view name) noexcept
{
    for (const auto& entry : code_names)
    {
        if (entry.name == name)
            return entry.code;
    }
    return Code::unknown;
}

std::string_view category_name(Category category) noexcept
{
    switch (category)
    {
        case Category::protocol:
            return "protocol";
        case Category::transport:
            return "transport";
        case Category::invalid_response:
            return "invalid_response";
        case Category::limit:
            return "limit";
        case Category::integrity:
            return "integrity";
        case Category::signature:
            return "signature";
        case Category::refused:
            return "refused";
        case Category::unsupported:
            return "unsupported";
        case Category::usage:
            return "usage";
        case Category::storage:
            return "storage";
        case Category::memory:
            return "memory";
    }
    return "";
}

Error Error::make(Category category, std::string_view detail) noexcept
{
    Error error;
    error.category_ = category;
    error.detail_.assign(detail);
    return error;
}

Error Error::from_status(std::uint16_t status) noexcept
{
    Error error;
    error.category_ = Category::protocol;
    error.status_   = status;
    return error;
}

void Error::set_code(Code code, std::string_view text) noexcept
{
    code_ = code;
    code_text_.assign(text);
}

Code Error::effective_code() const noexcept
{
    if (code_ != Code::none && code_ != Code::unknown)
        return code_;
    if (status_ != 0)
        return code_for_status(status_);
    return code_;
}

} // namespace lantern
