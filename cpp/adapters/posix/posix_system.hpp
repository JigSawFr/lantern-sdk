// What a POSIX system gives the library besides HTTP: cryptographic random
// bytes (/dev/urandom) and a UDP socket for discovery (SPEC.md § 4.1).
// Linux, the BSDs and macOS; a console's SDK has its own (README.md).
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/device_key.hpp>
#include <lantern/discovery.hpp>

namespace lantern::posix
{

// /dev/urandom, the kernel's generator.
class SystemRandom final : public RandomSource
{
  public:
    [[nodiscard]] Result<void> fill(std::span<std::uint8_t> out) override;
};

// An IPv4 UDP socket that may send to a broadcast address.
class UdpBroadcastSocket final : public UdpSocket
{
  public:
    UdpBroadcastSocket()                                     = default;
    UdpBroadcastSocket(const UdpBroadcastSocket&)            = delete;
    UdpBroadcastSocket& operator=(const UdpBroadcastSocket&) = delete;
    UdpBroadcastSocket(UdpBroadcastSocket&& other) noexcept;
    UdpBroadcastSocket& operator=(UdpBroadcastSocket&& other) noexcept;
    ~UdpBroadcastSocket() override;

    [[nodiscard]] static Result<UdpBroadcastSocket> open();

    [[nodiscard]] Result<void> send_to(
        std::string_view address, std::uint16_t port, std::span<const std::byte> bytes) override;
    [[nodiscard]] Result<std::optional<Datagram>> receive(
        std::span<std::byte> buffer, std::chrono::milliseconds timeout) override;

  private:
    explicit UdpBroadcastSocket(int fd) noexcept
        : fd_(fd)
    {
    }
    int fd_ = -1;
};

} // namespace lantern::posix
