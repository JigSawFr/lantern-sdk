#include "posix_system.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace lantern::posix
{

Result<void> SystemRandom::fill(std::span<std::uint8_t> out)
{
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return fail(Category::storage, "no /dev/urandom");
    while (!out.empty())
    {
        const ssize_t got = ::read(fd, out.data(), out.size());
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
        {
            ::close(fd);
            return fail(Category::storage, "/dev/urandom gave nothing");
        }
        out = out.subspan(static_cast<std::size_t>(got));
    }
    ::close(fd);
    return {};
}

UdpBroadcastSocket::UdpBroadcastSocket(UdpBroadcastSocket&& other) noexcept
    : fd_(std::exchange(other.fd_, -1))
{
}

UdpBroadcastSocket& UdpBroadcastSocket::operator=(UdpBroadcastSocket&& other) noexcept
{
    std::swap(fd_, other.fd_);
    return *this;
}

UdpBroadcastSocket::~UdpBroadcastSocket()
{
    if (fd_ >= 0)
        ::close(fd_);
}

Result<UdpBroadcastSocket> UdpBroadcastSocket::open()
{
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return fail(Category::transport, "no UDP socket");
    UdpBroadcastSocket socket(fd);
    int one = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one) != 0)
        return fail(Category::transport, "a UDP socket that may not broadcast");
    sockaddr_in any {};
    any.sin_family      = AF_INET;
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    any.sin_port        = 0;
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&any), sizeof any) != 0)
        return fail(Category::transport, "a UDP socket that cannot bind");
    return socket;
}

Result<void> UdpBroadcastSocket::send_to(
    std::string_view address, std::uint16_t port, std::span<const std::byte> bytes)
{
    sockaddr_in to {};
    to.sin_family = AF_INET;
    to.sin_port   = htons(port);
    const std::string text(address);
    if (::inet_pton(AF_INET, text.c_str(), &to.sin_addr) != 1)
        return fail(Category::usage, "discovery takes an IPv4 address (a broadcast address)");
    const ssize_t sent
        = ::sendto(fd_, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&to), sizeof to);
    if (sent < 0 || static_cast<std::size_t>(sent) != bytes.size())
        return fail(Category::transport, "the discovery datagram was not sent");
    return {};
}

Result<std::optional<Datagram>> UdpBroadcastSocket::receive(
    std::span<std::byte> buffer, std::chrono::milliseconds timeout)
{
    pollfd wanted {};
    wanted.fd       = fd_;
    wanted.events   = POLLIN;
    const int ready = ::poll(&wanted, 1, static_cast<int>(timeout.count()));
    if (ready < 0 && errno != EINTR)
        return fail(Category::transport, "the UDP socket broke");
    if (ready <= 0)
        return std::optional<Datagram> {};
    sockaddr_in from {};
    socklen_t from_size = sizeof from;
    const ssize_t got
        = ::recvfrom(fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&from), &from_size);
    if (got < 0)
        return std::optional<Datagram> {};
    Datagram datagram;
    datagram.size = static_cast<std::size_t>(got);
    datagram.port = ntohs(from.sin_port);
    if (::inet_ntop(
            AF_INET, &from.sin_addr, datagram.address.data(), static_cast<socklen_t>(datagram.address.size()))
        == nullptr)
        return std::optional<Datagram> {};
    datagram.address_size = std::strlen(datagram.address.data());
    return std::optional<Datagram>(datagram);
}

} // namespace lantern::posix
