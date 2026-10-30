// Discovery on the LAN (SPEC.md § 4.1): the datagram
// {"schema":1,"lantern":"discover"} sent to UDP 47115 as a directed
// broadcast (192.168.1.255: some consoles drop 255.255.255.255), and the
// servers' unicast replies, each with its uid, name, HTTPS port, base path
// and versions; the server's address is the reply's source.
//
// A reply is a hint, nothing more: it proves nothing, and a client trusts a
// server only through TLS and pairing (L-4.1-5). Every datagram is bounded
// (1200 bytes) and read with the `schema` rule; one that is not a reply is
// dropped, never an error.
//
// The library has no sockets: the app gives a UdpSocket (adapters/posix
// has one for POSIX systems).
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/document.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/types.hpp>

namespace lantern
{

inline constexpr std::uint16_t discovery_port       = 47115;
inline constexpr std::size_t max_discovery_datagram = 1200;

// The request, as it is sent.
[[nodiscard]] std::string_view discovery_request() noexcept;

// A datagram received: its bytes are in the caller's buffer.
struct Datagram
{
    std::size_t size = 0;
    // The source address, as text ("192.168.1.20"), and its port.
    std::array<char, 64> address {};
    std::size_t address_size = 0;
    std::uint16_t port       = 0;

    [[nodiscard]] std::string_view address_view() const noexcept { return { address.data(), address_size }; }
};

class UdpSocket
{
  public:
    UdpSocket()                            = default;
    UdpSocket(const UdpSocket&)            = default;
    UdpSocket(UdpSocket&&)                 = default;
    UdpSocket& operator=(const UdpSocket&) = default;
    UdpSocket& operator=(UdpSocket&&)      = default;
    virtual ~UdpSocket()                   = default;

    // Sends one datagram to an address (a broadcast address included).
    [[nodiscard]] virtual Result<void> send_to(
        std::string_view address, std::uint16_t port, std::span<const std::byte> bytes)
        = 0;
    // The next datagram into `buffer` (a longer one is cut and dropped by
    // the caller), or nothing when none came within `timeout`.
    [[nodiscard]] virtual Result<std::optional<Datagram>> receive(
        std::span<std::byte> buffer, std::chrono::milliseconds timeout)
        = 0;
};

// A server found: where to reach it, and what it said of itself.
struct DiscoveredServer
{
    std::string_view address; // the reply's source
    const DiscoveryReply* reply = nullptr;
    // "https://<address>:<port>", the origin a ClientConfig takes.
    std::string_view origin;
};

class DiscoveryHandler
{
  public:
    DiscoveryHandler()                                   = default;
    DiscoveryHandler(const DiscoveryHandler&)            = default;
    DiscoveryHandler(DiscoveryHandler&&)                 = default;
    DiscoveryHandler& operator=(const DiscoveryHandler&) = default;
    DiscoveryHandler& operator=(DiscoveryHandler&&)      = default;
    virtual ~DiscoveryHandler()                          = default;

    // Once per server (by uid) per call of discover(); false to stop.
    [[nodiscard]] virtual bool on_server(const DiscoveredServer& server) = 0;
};

// A datagram read as a reply: absent for one of a newer schema; an error
// for one that is not a reply of § 4.1 (too long, not `"lantern":"server"`,
// a base that is not a path, no version 1, a uid that is not a UUID).
[[nodiscard]] Read<DiscoveryReply> read_discovery_datagram(
    std::span<const std::byte> datagram, const DecodeOptions& options = {});

// "https://<address>:<port>" (IPv6 addresses in brackets).
[[nodiscard]] Result<String> discovered_origin(
    std::string_view address, std::uint16_t port, Allocator allocator = {});

struct DiscoveryOptions
{
    // The subnet's broadcast address ("192.168.1.255"), or a server's own
    // address to ask it alone.
    std::string_view address;
    std::uint16_t port = discovery_port;
    // How long to listen for replies after sending.
    std::chrono::milliseconds wait { 1500 };
    // How many requests to send over the wait, for a datagram lost.
    unsigned attempts = 2;
    DecodeOptions decode {};
};

// Sends the request, listens for `wait`, and hands each server found once
// to `handler`.
[[nodiscard]] Result<void> discover(
    UdpSocket& socket, const DiscoveryOptions& options, DiscoveryHandler& handler);

} // namespace lantern
