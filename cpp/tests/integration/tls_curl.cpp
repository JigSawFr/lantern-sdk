#include "tls_support.hpp"

#include <curl/curl.h>

#include "curl_transport.hpp"

namespace lantern::test
{

std::unique_ptr<Transport> make_tls_transport(
    ServerTrust* trust, const std::string& ca_file, RandomSource& /*random*/)
{
    static const bool initialised = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    if (!initialised)
        return nullptr;
    curl::Options options;
    options.trust   = trust;
    options.ca_file = ca_file;
    auto made       = curl::CurlTransport::create(options);
    if (!made)
        return nullptr;
    return std::make_unique<curl::CurlTransport>(std::move(*made));
}

bool tls_checks_ip_names()
{
    return true;
}

} // namespace lantern::test
