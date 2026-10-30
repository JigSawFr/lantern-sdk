// A TLS adapter against the reference server over HTTPS, with a
// self-signed certificate made for the run (run_server.py --tls): the key
// pinned, a wrong pin refused, the CA store's verdict, and what a client
// sends before pairing (SPEC.md § 5.3). Fictional library, as everywhere.
#include <doctest.h>

#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>

#include <lantern/lantern.hpp>

#include "posix_system.hpp"
#include "tls_support.hpp"

using namespace lantern;

namespace
{

std::string env(const char* name)
{
    const char* value = std::getenv(name);
    REQUIRE_MESSAGE(value != nullptr, "run through run_server.py --tls: ", name, " is not set");
    return value;
}

Digest server_spki()
{
    const auto digest = digest_from_hex(env("LANTERN_TEST_TLS_SPKI"));
    REQUIRE(digest);
    return *digest;
}

ClientConfig config(RandomSource& random, ServerTrust* trust)
{
    ClientConfig c;
    static std::string origin;
    origin       = env("LANTERN_TEST_TLS");
    c.origin     = origin;
    c.user_agent = "LanternCppTests/0.4";
    c.platform   = "switch";
    c.random     = &random;
    c.trust      = trust;
    return c;
}

class Sink final : public DownloadSink
{
  public:
    std::string bytes;
    Result<void> write(std::span<const std::byte> chunk) override
    {
        bytes.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return {};
    }
    Result<void> restart() override
    {
        bytes.clear();
        return {};
    }
};

} // namespace

TEST_CASE("tls: the server's key pinned: the library, a download; a wrong pin refused")
{
    posix::SystemRandom random;
    ServerTrust trust;
    trust.pin(server_spki());
    auto transport = test::make_tls_transport(&trust, {}, random);
    REQUIRE(transport);
    auto client = Client::create(*transport, config(random, &trust));
    REQUIRE(client);
    const auto shake = client->handshake();
    REQUIRE(shake);
    REQUIRE(*shake);
    REQUIRE(trust.seen());
    CHECK(same_digest(*trust.seen(), server_spki()));

    AppsQuery query;
    query.page_size = 2;
    const auto page = client->apps(query);
    REQUIRE(page);
    REQUIRE(*page);
    REQUIRE_FALSE((*page)->items.empty());
    const App& app = (*page)->items.front();
    Sink sink;
    DownloadState state;
    REQUIRE(client->download({ app.file, app.size, app.sha256 }, state, sink));
    CHECK(sink.bytes.size() == app.size);

    // Another key than the one pinned: refused, whatever its certificate (L-5.3-4)
    Digest other = server_spki();
    other[0] ^= 0x80U;
    trust.pin(other);
    const auto refused = client->apps(query);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().category() == Category::refused);
    trust.pin(server_spki());
    CHECK(client->apps(query));
}

TEST_CASE("tls: the CA store decides when nothing is pinned")
{
    posix::SystemRandom random;
    ServerTrust trust;
    {
        // A self-signed certificate no CA vouches for
        auto transport = test::make_tls_transport(&trust, {}, random);
        REQUIRE(transport);
        auto client = Client::create(*transport, config(random, &trust));
        REQUIRE(client);
        const auto shake = client->handshake();
        REQUIRE_FALSE(shake);
        CHECK(shake.error().category() == Category::refused);
    }
    if (test::tls_checks_ip_names())
    {
        // The certificate itself as the CA: taken, its name (IP:127.0.0.1) checked
        auto transport = test::make_tls_transport(&trust, env("LANTERN_TEST_TLS_CERT"), random);
        REQUIRE(transport);
        auto client = Client::create(*transport, config(random, &trust));
        REQUIRE(client);
        const auto shake = client->handshake();
        CHECK_MESSAGE(shake, (shake ? std::string_view() : shake.error().detail()));
    }
}

TEST_CASE("tls: before pairing, any key is taken and shown; no token goes over it")
{
    posix::SystemRandom random;
    ServerTrust trust;
    trust.allow_unverified();
    auto transport = test::make_tls_transport(&trust, {}, random);
    REQUIRE(transport);
    auto client = Client::create(*transport, config(random, &trust));
    REQUIRE(client);
    REQUIRE(client->handshake());
    REQUIRE(trust.seen());
    CHECK(same_digest(*trust.seen(), server_spki()));
    const auto short_text = short_form(*trust.seen());
    CHECK(std::string_view(short_text.data(), short_text.size()).size() == 19);

    REQUIRE(client->set_bearer_token("et_never-sent"));
    const auto page = client->apps();
    REQUIRE_FALSE(page);
    CHECK(page.error().category() == Category::refused);

    // Pinned as seen: the same connection's key goes on
    trust.pin(*trust.seen());
    client->clear_bearer_token();
    CHECK(client->handshake());
}
