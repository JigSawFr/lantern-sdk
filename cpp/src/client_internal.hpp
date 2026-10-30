// What the client's sources share: the shape of a call and of an answer,
// and the small checks of headers and queries. Not installed.
#pragma once

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/client.hpp>
#include <lantern/encoding.hpp>
#include <lantern/memory.hpp>
#include <lantern/transport.hpp>

namespace lantern
{

// One request, as the client's routes describe it.
struct Client::Call
{
    Method method = Method::get;
    std::string_view url;
    std::span<const std::byte> body;
    std::string_view content_type = "application/json";
    std::span<const Header> extra;
    // Sent without the token (pairing).
    bool anonymous = false;
    // A poll of a pairing made with a key: signed by `poll_signer`, without
    // Authorization (§ 5.4).
    DeviceSigner* poll_signer = nullptr;
    // The handshake: its Date sets the clock's offset (Annex B.9).
    bool take_date = false;
};

// A whole answer, for the documents and the errors.
struct Client::Response
{
    std::uint16_t status = 0;
    String body;
    String content_type;
    String retry_after;
    String upload_offset;

    explicit Response(Allocator allocator)
        : body(allocator)
        , content_type(allocator)
        , retry_after(allocator)
        , upload_offset(allocator)
    {
    }
};

namespace detail
{

inline constexpr std::size_t max_headers      = 64;
inline constexpr std::size_t max_header_bytes = std::size_t { 8 } * 1024;

inline char lower(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

inline bool equal_ignoring_case(std::string_view a, std::string_view b) noexcept
{
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) { return lower(x) == lower(y); });
}

// A header value the app gives: printable ASCII and spaces, nothing that
// could end the line.
inline bool header_value(std::string_view value) noexcept
{
    return std::ranges::all_of(value,
        [](char c)
        {
            const auto byte = static_cast<unsigned char>(c);
            return byte >= 0x20U && byte < 0x7FU;
        });
}

// Text for people sent in a document or a header: UTF-8 without control
// characters (§ 13's strings).
inline bool plain_text(std::string_view text, std::size_t max_bytes) noexcept
{
    return text.size() <= max_bytes
        && std::ranges::none_of(text,
            [](char c)
            {
                const auto byte = static_cast<unsigned char>(c);
                return byte < 0x20U || byte == 0x7FU;
            });
}

// RFC 6750's b64token: what a bearer token may hold.
inline bool bearer_token(std::string_view token) noexcept
{
    if (token.empty() || token.size() > 4096)
        return false;
    const std::size_t end = token.find_last_not_of('=') + 1;
    return std::all_of(token.begin(), token.begin() + static_cast<std::ptrdiff_t>(end),
        [](char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
                || c == '.' || c == '_' || c == '~' || c == '+' || c == '/';
        });
}

inline bool json_media_type(std::string_view content_type) noexcept
{
    std::string_view type = content_type.substr(0, content_type.find(';'));
    while (!type.empty() && type.back() == ' ')
        type.remove_suffix(1);
    return equal_ignoring_case(type, "application/json")
        || (type.size() > 5 && equal_ignoring_case(type.substr(type.size() - 5), "+json"));
}

inline void add_query(String& url, bool& first, std::string_view name, std::string_view value)
{
    if (value.empty())
        return;
    url.push_back(first ? '?' : '&');
    first = false;
    url.append(name);
    url.push_back('=');
    percent_encode(value, url);
}

inline void add_query(String& url, bool& first, std::string_view name, std::optional<std::uint32_t> value)
{
    if (!value)
        return;
    std::array<char, 12> buffer {};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), *value);
    add_query(url, first, name,
        std::string_view(buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data())));
}

inline std::optional<std::uint64_t> parse_u64(std::string_view text) noexcept
{
    std::uint64_t value = 0;
    const char* end     = text.data() + text.size();
    const auto result   = std::from_chars(text.data(), end, value);
    if (text.empty() || result.ec != std::errc {} || result.ptr != end)
        return std::nullopt;
    return value;
}

inline std::span<const std::byte> bytes_of(std::string_view text) noexcept
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

// A path segment of an id the app gives: what it holds is percent-encoded,
// but an empty one is no id.
inline Result<void> append_segment(String& url, std::string_view id)
{
    if (id.empty() || id.size() > 512)
        return fail(Category::usage, "an empty or overlong id");
    percent_encode(id, url);
    return {};
}

} // namespace detail

// The documents' reads, for every source of the client.
template <class T, class Reader> Read<T> Client::read(const Call& call, Reader reader)
{
    const auto response = fetch(call);
    if (!response)
        return std::unexpected(response.error());
    if (response->status < 200 || response->status >= 300)
        return std::unexpected(problem(*response));
    if (!detail::json_media_type(response->content_type))
        return fail(Category::invalid_response, "a document that is not application/json");
    return reader(response->body, decode_);
}

template <class T, class Reader>
Read<T> Client::read(Method method, std::string_view url, Reader reader, std::string_view body)
{
    Call call;
    call.method = method;
    call.url    = url;
    call.body   = detail::bytes_of(body);
    return read<T>(call, reader);
}

} // namespace lantern
