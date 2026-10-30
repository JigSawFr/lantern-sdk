// A Transport over libcurl and the TLS library it was built with (OpenSSL,
// GnuTLS, Schannel, Secure Transport…): for desktops and phones, and any
// console whose SDK ships libcurl. Optional: built when CMake finds libcurl
// (LANTERN_CURL), linked as Lantern::curl; the library itself needs none of
// it.
//
// The server's key (SPEC.md § 5.3) goes through a ServerTrust (tls.hpp):
// libcurl gives the leaf certificate (CURLOPT_CERTINFO), the adapter reads
// its SPKI and asks ServerTrust::accept() before the request is sent
// (CURLOPT_PREREQFUNCTION). With a pin, the CA store is not asked; without
// one, libcurl checks the chain and the name as usual. A key refused ends
// the request with Category::refused.
//
// The app calls curl_global_init() once before making one. One transport
// is one easy handle: one request at a time, its connection kept between
// requests.
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/tls.hpp>
#include <lantern/transport.hpp>

namespace lantern::curl
{

struct Options
{
    // The server's key, as the app keeps it; null: the CA store alone.
    ServerTrust* trust = nullptr;
    // A CA bundle (PEM file) instead of the system's; empty: the system's.
    // Copied: it need not outlive create().
    std::string_view ca_file;
    // Annex B.1: 10 seconds to connect (3 on the LAN is the app's choice),
    // and a request given up after this long without a byte.
    std::chrono::milliseconds connect_timeout { 10000 };
    std::chrono::seconds stall_timeout { 60 };
};

class CurlTransport final : public Transport
{
  public:
    [[nodiscard]] static Result<CurlTransport> create(const Options& options);

    CurlTransport(const CurlTransport&)            = delete;
    CurlTransport& operator=(const CurlTransport&) = delete;
    CurlTransport(CurlTransport&& other) noexcept;
    CurlTransport& operator=(CurlTransport&& other) noexcept;
    ~CurlTransport() override;

    [[nodiscard]] Result<void> send(const Request& request, ResponseHandler& handler) override;

  private:
    CurlTransport() = default;
    void* handle_   = nullptr; // CURL*
    Options options_ {};
    std::string ca_file_;
    std::uint32_t trust_generation_ = 0;
};

} // namespace lantern::curl
