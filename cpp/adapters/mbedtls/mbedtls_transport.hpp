// A Transport over mbedTLS (2.28 or 3.x) and POSIX sockets: for the
// consoles whose SDK ships mbedTLS (devkitPro's switch-mbedtls among them)
// and anywhere else libcurl is not wanted. Optional: built when CMake finds
// mbedTLS (LANTERN_MBEDTLS), linked as Lantern::mbedtls; the library itself
// needs none of it.
//
// HTTP/1.1, one request per connection (Connection: close). The server's
// key (SPEC.md § 5.3) goes through a ServerTrust (tls.hpp): mbedTLS's
// verification callback hands the adapter each certificate of the chain;
// the leaf's SPKI goes to ServerTrust::accept(), which decides with a pin,
// or before pairing; without a ServerTrust, or in its CA mode, the chain
// and the name must verify against `ca_pem`. A key refused ends the
// request with Category::refused.
//
// mbedTLS draws its randomness from the app's RandomSource, so that no
// entropy module of the platform is needed. On a Switch, the app calls
// socketInitializeDefault() first, as for any socket.
#pragma once

#include <chrono>
#include <memory>
#include <string_view>

#include <lantern/device_key.hpp>
#include <lantern/error.hpp>
#include <lantern/tls.hpp>
#include <lantern/transport.hpp>

namespace lantern::mbedtls
{

struct Options
{
    // Required: the TLS handshake's randomness.
    RandomSource* random = nullptr;
    // The server's key, as the app keeps it; null: the CA store alone.
    ServerTrust* trust = nullptr;
    // The CAs the client trusts, in PEM (a bundle the app ships); empty:
    // none, and only a pinned key, or one before pairing, is taken.
    std::string_view ca_pem;
    // Annex B.1: the connection, the TLS handshake, and each read after.
    std::chrono::milliseconds timeout { 10000 };
};

class MbedTlsTransport final : public Transport
{
  public:
    [[nodiscard]] static Result<MbedTlsTransport> create(const Options& options);

    MbedTlsTransport(const MbedTlsTransport&)            = delete;
    MbedTlsTransport& operator=(const MbedTlsTransport&) = delete;
    MbedTlsTransport(MbedTlsTransport&& other) noexcept;
    MbedTlsTransport& operator=(MbedTlsTransport&& other) noexcept;
    ~MbedTlsTransport() override;

    [[nodiscard]] Result<void> send(const Request& request, ResponseHandler& handler) override;

  private:
    struct State;
    MbedTlsTransport() = default;
    std::unique_ptr<State> state_;
};

} // namespace lantern::mbedtls
