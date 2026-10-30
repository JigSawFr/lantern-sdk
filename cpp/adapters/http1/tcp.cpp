#include "tcp.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <string>
#include <utility>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace lantern::http1
{

TcpSocket::TcpSocket(TcpSocket&& other) noexcept
    : fd_(std::exchange(other.fd_, -1))
{
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept
{
    std::swap(fd_, other.fd_);
    return *this;
}

TcpSocket::~TcpSocket()
{
    if (fd_ >= 0)
        ::close(fd_);
}

Result<TcpSocket> TcpSocket::connect(
    std::string_view host, std::uint16_t port, std::chrono::milliseconds timeout, bool numeric_only)
{
    addrinfo hints {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_NUMERICSERV | (numeric_only ? AI_NUMERICHOST : 0);
    std::array<char, 8> port_text {};
    std::to_chars(port_text.data(), port_text.data() + port_text.size() - 1, port);
    const std::string name(host);
    addrinfo* found = nullptr;
    if (::getaddrinfo(name.c_str(), port_text.data(), &hints, &found) != 0 || found == nullptr)
        return fail(Category::transport, "the server's address does not resolve");
    timeval tv {};
    tv.tv_sec  = static_cast<decltype(tv.tv_sec)>(timeout.count() / 1000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((timeout.count() % 1000) * 1000);
    TcpSocket out;
    for (const addrinfo* at = found; at != nullptr; at = at->ai_next)
    {
        TcpSocket socket(::socket(at->ai_family, at->ai_socktype, at->ai_protocol));
        if (socket.fd_ < 0)
            continue;
#ifdef SO_RCVTIMEO // where the system has them (a 3DS has not: its reads are polled)
        ::setsockopt(socket.fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ::setsockopt(socket.fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif
#ifdef SO_NOSIGPIPE
        int one = 1;
        ::setsockopt(socket.fd_, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        if (::connect(socket.fd_, at->ai_addr, at->ai_addrlen) == 0)
        {
            out = std::move(socket);
            break;
        }
    }
    ::freeaddrinfo(found);
    if (out.fd_ < 0)
        return fail(Category::transport, "the server does not answer");
    return out;
}

Result<void> TcpSocket::write(std::span<const char> bytes)
{
    while (!bytes.empty())
    {
        const ssize_t sent = ::send(fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            return fail(Category::transport, "the connection broke while sending");
        bytes = bytes.subspan(static_cast<std::size_t>(sent));
    }
    return {};
}

Result<std::size_t> TcpSocket::read(std::span<char> buffer)
{
    for (;;)
    {
        const ssize_t got = ::recv(fd_, buffer.data(), buffer.size(), 0);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return fail(Category::transport, "the connection broke, or timed out");
        return static_cast<std::size_t>(got);
    }
}

} // namespace lantern::http1
