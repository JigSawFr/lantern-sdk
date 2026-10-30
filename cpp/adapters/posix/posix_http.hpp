// A minimal blocking HTTP/1.1 client over POSIX sockets, for the tests and
// the example only: plain HTTP to a loopback address (SPEC.md § 2), one
// connection per request (Connection: close), Content-Length, chunked or
// close-delimited bodies. Never for an app: no TLS, no proxy, no redirect;
// an app takes adapters/curl or adapters/mbedtls.
#pragma once

#include <chrono>

#include <lantern/transport.hpp>

namespace lantern::posix
{

class LoopbackTransport final : public Transport
{
  public:
    explicit LoopbackTransport(std::chrono::milliseconds timeout = std::chrono::seconds(30)) noexcept
        : timeout_(timeout)
    {
    }

    [[nodiscard]] Result<void> send(const Request& request, ResponseHandler& handler) override;

    // The number of requests sent, for the tests.
    [[nodiscard]] std::size_t requests() const noexcept { return requests_; }

  private:
    std::chrono::milliseconds timeout_;
    std::size_t requests_ = 0;
};

} // namespace lantern::posix
