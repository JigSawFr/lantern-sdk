#include "http1.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <system_error>

namespace lantern::http1
{

namespace
{

constexpr std::size_t max_head       = std::size_t { 64 } * 1024;
constexpr std::uint64_t max_chunk    = std::uint64_t { 1 } << 40U;
constexpr std::size_t receive_buffer = std::size_t { 16 } * 1024;

bool equal_ignoring_case(std::string_view a, std::string_view b) noexcept
{
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(),
            [](char x, char y)
            {
                const auto lower
                    = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
                return lower(x) == lower(y);
            });
}

bool clean(std::string_view text) noexcept
{
    return std::ranges::none_of(text, [](char c) { return c == '\r' || c == '\n' || c == '\0'; });
}

std::string_view trim(std::string_view text) noexcept
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.remove_suffix(1);
    return text;
}

std::unexpected<Error> transport_error(std::string_view what)
{
    return fail(Category::transport, what);
}

// Reads what the stream has, appended to `buffer`; 0 at the end.
Result<std::size_t> receive(Stream& stream, std::string& buffer)
{
    std::array<char, receive_buffer> chunk {};
    const auto got = stream.read(chunk);
    if (!got)
        return got;
    buffer.append(chunk.data(), *got);
    return *got;
}

std::span<const std::byte> bytes_of(std::string_view text) noexcept
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

std::span<const char> chars_of(std::string_view text) noexcept
{
    return { text.data(), text.size() };
}

} // namespace

Result<void> exchange(Stream& stream, const UrlParts& url, const Request& request, ResponseHandler& handler)
{
    std::string head;
    head.append(method_name(request.method));
    head.push_back(' ');
    head.append(url.target);
    head.append(" HTTP/1.1\r\nHost: ");
    head.append(url.authority);
    head.append("\r\n");
    for (const Header& header : request.headers)
    {
        if (!clean(header.name) || !clean(header.value) || header.name.contains(':') || header.name.empty())
            return fail(Category::usage, "a header that would break the request");
        head.append(header.name);
        head.append(": ");
        head.append(header.value);
        head.append("\r\n");
    }
    if (!request.body.empty() || request.method == Method::post || request.method == Method::put
        || request.method == Method::patch)
    {
        std::array<char, 24> length {};
        const auto result = std::to_chars(length.data(), length.data() + length.size(), request.body.size());
        head.append("Content-Length: ");
        head.append(length.data(), result.ptr);
        head.append("\r\n");
    }
    head.append("Connection: close\r\n\r\n");

    if (auto sent = stream.write(chars_of(head)); !sent)
        return sent;
    if (!request.body.empty())
    {
        const std::span<const char> body(
            reinterpret_cast<const char*>(request.body.data()), request.body.size());
        if (auto sent = stream.write(body); !sent)
            return sent;
    }

    // The status line and the headers
    std::string buffer;
    std::size_t end_of_head = std::string::npos;
    while ((end_of_head = buffer.find("\r\n\r\n")) == std::string::npos)
    {
        if (buffer.size() > max_head)
            return transport_error("an answer whose headers do not end");
        const auto got = receive(stream, buffer);
        if (!got)
            return std::unexpected(got.error());
        if (*got == 0)
            return transport_error("the connection closed before the headers ended");
    }
    const std::string_view head_text(buffer.data(), end_of_head);
    const std::size_t line_end         = head_text.find("\r\n");
    const std::string_view status_line = head_text.substr(0, line_end);
    if (!status_line.starts_with("HTTP/1.") || status_line.size() < 12 || status_line[8] != ' ')
        return transport_error("not an HTTP/1 answer");
    unsigned status   = 0;
    const auto parsed = std::from_chars(status_line.data() + 9, status_line.data() + 12, status);
    if (parsed.ec != std::errc {} || status < 100 || status > 599)
        return transport_error("an answer without a status");
    if (!handler.on_status(static_cast<std::uint16_t>(status)))
        return {};

    bool chunked = false;
    std::optional<std::uint64_t> content_length;
    std::size_t at = line_end == std::string_view::npos ? head_text.size() : line_end + 2;
    while (at < head_text.size())
    {
        const std::size_t next      = std::min(head_text.find("\r\n", at), head_text.size());
        const std::string_view line = head_text.substr(at, next - at);
        at                          = next + 2;
        const std::size_t colon     = line.find(':');
        if (colon == std::string_view::npos)
            return transport_error("a malformed header line");
        const std::string_view name  = line.substr(0, colon);
        const std::string_view value = trim(line.substr(colon + 1));
        if (equal_ignoring_case(name, "Transfer-Encoding") && equal_ignoring_case(value, "chunked"))
            chunked = true;
        if (equal_ignoring_case(name, "Content-Length"))
        {
            std::uint64_t length = 0;
            const auto result    = std::from_chars(value.data(), value.data() + value.size(), length);
            if (result.ec != std::errc {} || result.ptr != value.data() + value.size())
                return transport_error("a malformed Content-Length");
            content_length = length;
        }
        if (!handler.on_header(name, value))
            return {};
    }
    buffer.erase(0, end_of_head + 4);

    if (request.method == Method::head || status == 204 || status == 304 || (status >= 100 && status < 200))
        return {};

    if (chunked)
    {
        for (;;)
        {
            std::size_t line = std::string::npos;
            while ((line = buffer.find("\r\n")) == std::string::npos)
            {
                if (buffer.size() > max_head)
                    return transport_error("a malformed chunk");
                const auto got = receive(stream, buffer);
                if (!got)
                    return std::unexpected(got.error());
                if (*got == 0)
                    return transport_error("the connection closed in a chunk");
            }
            std::uint64_t size = 0;
            const std::string_view size_text(buffer.data(), std::min(line, buffer.find(';')));
            const auto result
                = std::from_chars(size_text.data(), size_text.data() + size_text.size(), size, 16);
            if (result.ec != std::errc {} || size > max_chunk)
                return transport_error("a malformed chunk size");
            buffer.erase(0, line + 2);
            if (size == 0)
                return {};
            // A chunk is handed over in pieces, as it comes
            std::uint64_t left = size;
            while (left != 0)
            {
                if (buffer.empty())
                {
                    const auto got = receive(stream, buffer);
                    if (!got)
                        return std::unexpected(got.error());
                    if (*got == 0)
                        return transport_error("the connection closed in a chunk");
                }
                const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), left));
                if (!handler.on_body(bytes_of(std::string_view(buffer.data(), take))))
                    return {};
                buffer.erase(0, take);
                left -= take;
            }
            while (buffer.size() < 2)
            {
                const auto got = receive(stream, buffer);
                if (!got)
                    return std::unexpected(got.error());
                if (*got == 0)
                    return transport_error("the connection closed in a chunk");
            }
            if (!buffer.starts_with("\r\n"))
                return transport_error("a chunk not followed by its line end");
            buffer.erase(0, 2);
        }
    }

    std::uint64_t remaining = content_length.value_or(UINT64_MAX);
    for (;;)
    {
        if (!buffer.empty())
        {
            const auto take = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), remaining));
            if (!handler.on_body(bytes_of(std::string_view(buffer.data(), take))))
                return {};
            remaining -= take;
            buffer.clear();
        }
        if (remaining == 0)
            return {};
        const auto got = receive(stream, buffer);
        if (!got)
            return std::unexpected(got.error());
        if (*got == 0)
        {
            if (content_length)
                return transport_error("the connection closed before the body ended");
            return {};
        }
    }
}

} // namespace lantern::http1
