#include "posix_http.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <string>
#include <system_error>
#include <utility>

#include <lantern/url.hpp>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace lantern::posix
{

namespace
{

constexpr std::size_t max_head = std::size_t { 64 } * 1024;

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

class Socket
{
  public:
    Socket() = default;
    explicit Socket(int fd) noexcept
        : fd_(fd)
    {
    }
    Socket(const Socket&)            = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept
        : fd_(std::exchange(other.fd_, -1))
    {
    }
    Socket& operator=(Socket&& other) noexcept
    {
        std::swap(fd_, other.fd_);
        return *this;
    }
    ~Socket()
    {
        if (fd_ >= 0)
            ::close(fd_);
    }
    [[nodiscard]] int fd() const noexcept { return fd_; }

  private:
    int fd_ = -1;
};

std::unexpected<Error> transport_error(std::string_view what)
{
    return fail(Category::transport, what);
}

Result<Socket> connect_to(const UrlParts& url, std::chrono::milliseconds timeout)
{
    addrinfo hints {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_NUMERICHOST | AI_NUMERICSERV;
    std::array<char, 8> port {};
    std::to_chars(port.data(), port.data() + port.size() - 1, url.port);
    const std::string host(url.host);
    addrinfo* found = nullptr;
    if (::getaddrinfo(host.c_str(), port.data(), &hints, &found) != 0 || found == nullptr)
        return transport_error("the loopback address does not resolve");
    Socket socket(::socket(found->ai_family, found->ai_socktype, found->ai_protocol));
    if (socket.fd() < 0)
    {
        ::freeaddrinfo(found);
        return transport_error("no socket");
    }
    timeval tv {};
    tv.tv_sec  = static_cast<decltype(tv.tv_sec)>(timeout.count() / 1000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((timeout.count() % 1000) * 1000);
    ::setsockopt(socket.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(socket.fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#ifdef SO_NOSIGPIPE
    int one = 1;
    ::setsockopt(socket.fd(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    const int connected = ::connect(socket.fd(), found->ai_addr, found->ai_addrlen);
    ::freeaddrinfo(found);
    if (connected != 0)
        return transport_error("the server does not answer");
    return socket;
}

Result<void> send_all(const Socket& socket, std::string_view bytes)
{
    while (!bytes.empty())
    {
        const ssize_t sent = ::send(socket.fd(), bytes.data(), bytes.size(), MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            return transport_error("the connection broke while sending");
        bytes.remove_prefix(static_cast<std::size_t>(sent));
    }
    return {};
}

// Reads what the socket has into `buffer` (appending); 0 at the end.
Result<std::size_t> receive(const Socket& socket, std::string& buffer)
{
    std::array<char, std::size_t { 16 } * 1024> chunk {};
    for (;;)
    {
        const ssize_t got = ::recv(socket.fd(), chunk.data(), chunk.size(), 0);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return transport_error("the connection broke, or timed out");
        buffer.append(chunk.data(), static_cast<std::size_t>(got));
        return static_cast<std::size_t>(got);
    }
}

std::span<const std::byte> bytes_of(std::string_view text) noexcept
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

} // namespace

Result<void> LoopbackTransport::send(const Request& request, ResponseHandler& handler)
{
    ++requests_;
    const auto url = split_url(request.url);
    if (!url)
        return std::unexpected(url.error());
    if (url->scheme != "http" || !is_loopback_host(url->host))
        return fail(Category::usage, "this adapter speaks plain HTTP to a loopback address only");

    std::string head;
    head.append(method_name(request.method));
    head.push_back(' ');
    head.append(url->target);
    head.append(" HTTP/1.1\r\nHost: ");
    head.append(url->authority);
    head.append("\r\n");
    for (const Header& header : request.headers)
    {
        if (!clean(header.name) || !clean(header.value) || header.name.contains(':'))
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

    auto socket = connect_to(*url, timeout_);
    if (!socket)
        return std::unexpected(socket.error());
    if (auto sent = send_all(*socket, head); !sent)
        return sent;
    const std::string_view body(reinterpret_cast<const char*>(request.body.data()), request.body.size());
    if (auto sent = send_all(*socket, body); !sent)
        return sent;

    // The status line and the headers
    std::string buffer;
    std::size_t end_of_head = std::string::npos;
    while ((end_of_head = buffer.find("\r\n\r\n")) == std::string::npos)
    {
        if (buffer.size() > max_head)
            return transport_error("an answer whose headers do not end");
        const auto got = receive(*socket, buffer);
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
                const auto got = receive(*socket, buffer);
                if (!got)
                    return std::unexpected(got.error());
                if (*got == 0)
                    return transport_error("the connection closed in a chunk");
            }
            std::uint64_t size = 0;
            const std::string_view size_text(buffer.data(), std::min(line, buffer.find(';')));
            const auto result
                = std::from_chars(size_text.data(), size_text.data() + size_text.size(), size, 16);
            if (result.ec != std::errc {} || size > (std::uint64_t { 1 } << 40))
                return transport_error("a malformed chunk size");
            buffer.erase(0, line + 2);
            if (size == 0)
                return {};
            while (buffer.size() < size + 2)
            {
                const auto got = receive(*socket, buffer);
                if (!got)
                    return std::unexpected(got.error());
                if (*got == 0)
                    return transport_error("the connection closed in a chunk");
            }
            if (!handler.on_body(bytes_of(std::string_view(buffer.data(), static_cast<std::size_t>(size)))))
                return {};
            buffer.erase(0, static_cast<std::size_t>(size) + 2);
        }
    }

    std::uint64_t remaining = content_length.value_or(UINT64_MAX);
    for (;;)
    {
        if (!buffer.empty())
        {
            const std::size_t take
                = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), remaining));
            if (!handler.on_body(bytes_of(std::string_view(buffer.data(), take))))
                return {};
            remaining -= take;
            buffer.clear();
        }
        if (remaining == 0)
            return {};
        const auto got = receive(*socket, buffer);
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

} // namespace lantern::posix
