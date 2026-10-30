#include "tls_support.hpp"

#include <fstream>
#include <iterator>

#include <mbedtls/version.h>

#include "mbedtls_transport.hpp"

namespace lantern::test
{

std::unique_ptr<Transport> make_tls_transport(
    ServerTrust* trust, const std::string& ca_file, RandomSource& random)
{
    // The adapter takes its CAs as PEM text, as a console app ships them
    static std::string pem;
    pem.clear();
    if (!ca_file.empty())
    {
        std::ifstream file(ca_file, std::ios::binary);
        pem.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    }
    mbedtls::Options options;
    options.random = &random;
    options.trust  = trust;
    options.ca_pem = pem;
    auto made      = mbedtls::MbedTlsTransport::create(options);
    if (!made)
        return nullptr;
    return std::make_unique<mbedtls::MbedTlsTransport>(std::move(*made));
}

bool tls_checks_ip_names()
{
    return MBEDTLS_VERSION_MAJOR >= 3;
}

} // namespace lantern::test
