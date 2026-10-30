// The TLS adapter under test: tls_curl.cpp or tls_mbedtls.cpp gives it.
#pragma once

#include <memory>
#include <string>

#include <lantern/lantern.hpp>

namespace lantern::test
{

// A transport of the adapter, checking the server's key through `trust`,
// with the PEM file `ca_file` as its CAs (empty: none, or the system's).
std::unique_ptr<Transport> make_tls_transport(
    ServerTrust* trust, const std::string& ca_file, RandomSource& random);

// Whether the adapter checks a certificate's IP address names (mbedTLS 2
// does not: a CA's certificate for 127.0.0.1 is then refused by name).
bool tls_checks_ip_names();

} // namespace lantern::test
