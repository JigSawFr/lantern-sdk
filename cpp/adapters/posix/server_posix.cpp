#include "server_posix.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <optional>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcp.hpp"

namespace lantern::posix
{

namespace
{

constexpr std::size_t max_head    = std::size_t { 64 } * 1024;
constexpr std::size_t max_headers = 100;
constexpr std::size_t file_buffer = std::size_t { 64 } * 1024;

bool same_name(std::string_view a, std::string_view b) noexcept
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

std::string_view trim(std::string_view text) noexcept
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.remove_suffix(1);
    return text;
}

// An IMF-fixdate (RFC 9110 § 5.6.7), which no locale changes.
std::string http_date(std::time_t when)
{
    static constexpr std::array days { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static constexpr std::array months { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
        "Nov", "Dec" };
    std::tm parts {};
    gmtime_r(&when, &parts);
    std::array<char, 40> out {};
    const int written = std::snprintf(out.data(), out.size(), "%s, %02d %s %04d %02d:%02d:%02d GMT",
        days.at(static_cast<std::size_t>(parts.tm_wday)), parts.tm_mday,
        months.at(static_cast<std::size_t>(parts.tm_mon)), parts.tm_year + 1900, parts.tm_hour, parts.tm_min,
        parts.tm_sec);
    return { out.data(), written > 0 ? static_cast<std::size_t>(written) : 0 };
}

bool clean(std::string_view text) noexcept
{
    return std::ranges::none_of(text, [](char c) { return c == '\r' || c == '\n' || c == '\0'; });
}

// Writes the answer: the status line, the headers, `Date`, `Connection: close`,
// then the body, or the file's bytes read piece by piece.
void send_response(http1::TcpSocket& socket, const ServerResponse& response)
{
    std::string head("HTTP/1.1 ");
    head.append(std::to_string(response.status));
    head.push_back(' ');
    head.append(status_text(response.status));
    head.append("\r\n");
    for (const auto& [name, value] : response.headers.entries())
    {
        if (!clean(name) || !clean(value))
            continue;
        head.append(name);
        head.append(": ");
        head.append(value);
        head.append("\r\n");
    }
    head.append("Date: ");
    head.append(http_date(std::time(nullptr)));
    head.append("\r\nConnection: close\r\n\r\n");
    if (!socket.write(std::span<const char>(head.data(), head.size())))
        return;
    if (!response.file)
    {
        if (!response.body.empty())
            std::ignore = socket.write(std::span<const char>(response.body.data(), response.body.size()));
        return;
    }
    std::string buffer(file_buffer, '\0');
    std::uint64_t offset = response.file->offset;
    std::uint64_t left   = response.file->length;
    while (left != 0)
    {
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(left, buffer.size()));
        const auto got
            = response.file->reader->read(offset, std::as_writable_bytes(std::span(buffer.data(), want)));
        // The file shrank under us: stop rather than lie about the length
        if (!got || *got == 0)
            return;
        if (!socket.write(std::span<const char>(buffer.data(), *got)))
            return;
        offset += *got;
        left -= *got;
    }
}

void set_timeouts(int fd, std::chrono::milliseconds timeout) noexcept
{
    timeval tv {};
    tv.tv_sec  = static_cast<decltype(tv.tv_sec)>(timeout.count() / 1000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((timeout.count() % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#ifdef SO_NOSIGPIPE
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

std::string peer_address(int fd)
{
    sockaddr_storage address {};
    socklen_t length = sizeof address;
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0)
        return {};
    std::array<char, INET6_ADDRSTRLEN> text {};
    if (address.ss_family == AF_INET)
        ::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&address)->sin_addr, text.data(),
            static_cast<socklen_t>(text.size()));
    else if (address.ss_family == AF_INET6)
        ::inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&address)->sin6_addr, text.data(),
            static_cast<socklen_t>(text.size()));
    return text.data();
}

// A body left on the connection, read when the server asks: first what came
// with the head, then the socket's.
class SocketBody final : public BodyReader
{
  public:
    SocketBody(http1::TcpSocket& socket, std::string_view arrived) noexcept
        : socket_(&socket)
        , arrived_(arrived)
    {
    }

    Result<std::size_t> read(std::span<std::byte> buffer) override
    {
        if (!arrived_.empty())
        {
            const std::size_t take = std::min(buffer.size(), arrived_.size());
            std::memcpy(buffer.data(), arrived_.data(), take);
            arrived_.remove_prefix(take);
            return take;
        }
        const auto got
            = socket_->read(std::span<char>(reinterpret_cast<char*>(buffer.data()), buffer.size()));
        if (!got)
            return fail(Category::transport, "the connection was cut");
        return *got;
    }

  private:
    http1::TcpSocket* socket_;
    std::string_view arrived_;
};

} // namespace

HttpListener::HttpListener(HttpListener&& other) noexcept
    : server_(other.server_)
    , timeout_(other.timeout_)
    , max_body_(other.max_body_)
    , max_stream_(other.max_stream_)
    , fd_(std::exchange(other.fd_, -1))
    , port_(other.port_)
{
}

HttpListener& HttpListener::operator=(HttpListener&& other) noexcept
{
    std::swap(server_, other.server_);
    std::swap(timeout_, other.timeout_);
    std::swap(max_body_, other.max_body_);
    std::swap(max_stream_, other.max_stream_);
    std::swap(fd_, other.fd_);
    std::swap(port_, other.port_);
    return *this;
}

HttpListener::~HttpListener()
{
    if (fd_ >= 0)
        ::close(fd_);
}

Result<HttpListener> HttpListener::listen(const Server& server, const ListenOptions& options)
{
    addrinfo hints {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;
    std::array<char, 8> port_text {};
    std::to_chars(port_text.data(), port_text.data() + port_text.size() - 1, options.port);
    const std::string host(options.host);
    addrinfo* found = nullptr;
    if (::getaddrinfo(host.c_str(), port_text.data(), &hints, &found) != 0 || found == nullptr)
        return fail(Category::usage, "the address to listen on is not an address");
    int fd = -1;
    for (const addrinfo* at = found; at != nullptr && fd < 0; at = at->ai_next)
    {
        const int candidate = ::socket(at->ai_family, at->ai_socktype, at->ai_protocol);
        if (candidate < 0)
            continue;
        const int one = 1;
        ::setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (::bind(candidate, at->ai_addr, at->ai_addrlen) == 0 && ::listen(candidate, 16) == 0)
            fd = candidate;
        else
            ::close(candidate);
    }
    ::freeaddrinfo(found);
    if (fd < 0)
        return fail(Category::transport, "cannot listen on that address and port");
    sockaddr_storage bound {};
    socklen_t length   = sizeof bound;
    std::uint16_t port = options.port;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &length) == 0)
    {
        if (bound.ss_family == AF_INET)
            port = ntohs(reinterpret_cast<const sockaddr_in*>(&bound)->sin_port);
        else if (bound.ss_family == AF_INET6)
            port = ntohs(reinterpret_cast<const sockaddr_in6*>(&bound)->sin6_port);
    }
    return HttpListener(server, options, fd, port);
}

Result<bool> HttpListener::serve_one(std::chrono::milliseconds wait)
{
    pollfd watched {};
    watched.fd     = fd_;
    watched.events = POLLIN;
    int ready      = 0;
    do
        ready = ::poll(&watched, 1, static_cast<int>(wait.count()));
    while (ready < 0 && errno == EINTR);
    if (ready < 0)
        return fail(Category::transport, "waiting for a connection failed");
    if (ready == 0)
        return false;
    const int connection = ::accept(fd_, nullptr, nullptr);
    if (connection < 0)
        return false; // the client gave up between the poll and the accept
    set_timeouts(connection, timeout_);
    answer(connection);
    return true;
}

void HttpListener::serve(const std::atomic<bool>& stop)
{
    while (!stop.load())
    {
        if (!serve_one(std::chrono::milliseconds(100)))
            return;
    }
}

bool HttpListener::answer(int connection) const
{
    http1::TcpSocket socket(connection);
    const auto refuse = [&](std::uint16_t status, Code code, std::string_view why)
    {
        send_response(socket, problem_response(status, code, why));
        return false;
    };

    // The head: up to the empty line
    std::string buffer;
    std::size_t end_of_head = std::string::npos;
    std::array<char, 8192> chunk {};
    while ((end_of_head = buffer.find("\r\n\r\n")) == std::string::npos)
    {
        if (buffer.size() > max_head)
            return refuse(400, Code::bad_request, "The request's head is too long.");
        const auto got = socket.read(chunk);
        if (!got || *got == 0)
            return false; // the client left, or stalled
        buffer.append(chunk.data(), *got);
    }

    // The request line, then the headers; the body is what came after
    const std::string head_text(buffer, 0, end_of_head);
    std::string body(buffer, end_of_head + 4);
    const std::string_view head(head_text);
    const std::size_t line_end    = head.find("\r\n");
    const std::string_view line   = head.substr(0, line_end);
    const std::size_t first_space = line.find(' ');
    const std::size_t second_space
        = first_space == std::string_view::npos ? first_space : line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos || !line.substr(second_space + 1).starts_with("HTTP/1."))
        return refuse(400, Code::bad_request, "Not an HTTP/1 request.");
    const std::string_view method = line.substr(0, first_space);
    const std::string_view target = line.substr(first_space + 1, second_space - first_space - 1);
    if (method.empty() || !std::ranges::all_of(method, [](char c) { return c >= 'A' && c <= 'Z'; }))
        return refuse(400, Code::bad_request, "Not an HTTP method.");

    std::vector<Header> headers;
    std::size_t at = line_end == std::string_view::npos ? head.size() : line_end + 2;
    std::optional<std::uint64_t> content_length;
    bool chunked = false;
    bool expect  = false;
    while (at < head.size())
    {
        const std::size_t next      = std::min(head.find("\r\n", at), head.size());
        const std::string_view text = head.substr(at, next - at);
        at                          = next + 2;
        const std::size_t colon     = text.find(':');
        if (colon == std::string_view::npos || colon == 0 || headers.size() >= max_headers)
            return refuse(400, Code::bad_request, "A malformed header.");
        const std::string_view name  = text.substr(0, colon);
        const std::string_view value = trim(text.substr(colon + 1));
        if (name.find_first_of(" \t") != std::string_view::npos)
            return refuse(400, Code::bad_request, "A malformed header name.");
        if (same_name(name, "Content-Length"))
        {
            std::uint64_t length = 0;
            const auto parsed    = std::from_chars(value.data(), value.data() + value.size(), length);
            if (value.empty() || parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size()
                || (content_length && *content_length != length))
                return refuse(400, Code::bad_request, "A malformed Content-Length.");
            content_length = length;
        }
        else if (same_name(name, "Transfer-Encoding"))
            chunked = true;
        else if (same_name(name, "Expect") && same_name(value, "100-continue"))
            expect = true;
        headers.push_back({ name, value });
    }
    if (chunked)
        return refuse(400, Code::bad_request, "A request body of unknown length is not taken here.");
    const std::uint64_t body_size = content_length.value_or(0);
    const bool streamed           = body_size > max_body_;
    if (streamed && body_size > max_stream_)
        return refuse(413, Code::too_large, "That body is larger than this server takes.");

    // The body: what came with the head, then the rest
    constexpr std::string_view go_on = "HTTP/1.1 100 Continue\r\n\r\n";
    if (expect && body.size() < body_size)
        std::ignore = socket.write(std::span<const char>(go_on.data(), go_on.size()));
    // A streamed body stays on the connection, but for what came with the head
    while (!streamed && body.size() < body_size)
    {
        const auto got = socket.read(chunk);
        if (!got || *got == 0)
            return false;
        body.append(chunk.data(), *got);
    }
    body.resize(static_cast<std::size_t>(std::min<std::uint64_t>(body.size(), body_size)));
    SocketBody source(socket, body);

    const auto parsed = parse_target(target);
    if (!parsed)
        return refuse(400, Code::bad_request, "The request target is not a path this server can read.");
    std::vector<QueryParam> query;
    query.reserve(parsed->query.size());
    for (const auto& [name, value] : parsed->query)
        query.push_back({ name, value });
    const std::string remote = peer_address(connection);

    ServerRequest request;
    request.method  = method;
    request.path    = parsed->path;
    request.query   = query;
    request.headers = headers;
    if (streamed)
    {
        request.stream        = &source;
        request.stream_length = body_size;
    }
    else
    {
        request.body = std::as_bytes(std::span(body.data(), body.size()));
    }
    request.scheme = "http";
    request.target = target;
    request.remote = remote;
    send_response(socket, server_->handle(request));
    return true;
}

} // namespace lantern::posix
