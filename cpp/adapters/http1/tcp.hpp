// A TCP connection over POSIX sockets (Linux, the BSDs, macOS, and the
// consoles whose SDKs give BSD sockets, the Switch's libnx among them), for
// the adapters that bring their own connection. Not installed on its own.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/error.hpp>

#include "http1.hpp"

namespace lantern::http1
{

class TcpSocket final : public Stream
{
  public:
    TcpSocket() = default;
    explicit TcpSocket(int fd) noexcept
        : fd_(fd)
    {
    }
    TcpSocket(const TcpSocket&)            = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;
    ~TcpSocket() override;

    // Connects to `host` (an address; a name too unless `numeric_only`),
    // with `timeout` for the connection and for each read and write after.
    [[nodiscard]] static Result<TcpSocket> connect(
        std::string_view host, std::uint16_t port, std::chrono::milliseconds timeout, bool numeric_only);

    [[nodiscard]] Result<void> write(std::span<const char> bytes) override;
    [[nodiscard]] Result<std::size_t> read(std::span<char> buffer) override;
    [[nodiscard]] int fd() const noexcept { return fd_; }

  private:
    int fd_ = -1;
};

} // namespace lantern::http1
