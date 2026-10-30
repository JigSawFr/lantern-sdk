// The README's pairing example: a device key, the code and the QR code's
// address shown, the polls signed, the token kept.
//
//     pair_device http://127.0.0.1:8080 "Lea's Switch"
//
// Over the loopback adapter (plain HTTP on 127.0.0.1 only); an app gives
// its own Transport, with TLS and a ServerTrust (adapters/curl,
// adapters/mbedtls), and keeps the credentials where its system keeps
// secrets.
#include <array>
#include <chrono>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include <lantern/lantern.hpp>

#include "posix_http.hpp"
#include "posix_system.hpp"

namespace
{

// Kept in memory here; an app writes them where its system protects secrets.
class Kept final : public lantern::CredentialStore
{
  public:
    lantern::Result<std::optional<lantern::Credentials>> load(std::string_view, lantern::Allocator) override
    {
        return std::optional<lantern::Credentials> {};
    }
    lantern::Result<void> store(std::string_view uid, const lantern::Credentials& credentials) override
    {
        std::printf("kept for %.*s: a token%s\n", static_cast<int>(uid.size()), uid.data(),
            credentials.key ? " and its device key" : "");
        return {};
    }
    lantern::Result<void> erase(std::string_view) override { return {}; }
};

int report(const lantern::Error& error)
{
    std::fprintf(stderr, "error (%u): %.*s\n", static_cast<unsigned>(error.status()),
        static_cast<int>(error.detail().size()), error.detail().data());
    return 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::fprintf(stderr, "usage: pair_device ORIGIN DEVICE-NAME\n");
        return 2;
    }
    lantern::posix::LoopbackTransport transport;
    lantern::posix::SystemRandom random;
    lantern::ClientConfig config;
    config.origin     = argv[1];
    config.user_agent = "PairDevice/0.5";
    config.platform   = "switch";
    config.random     = &random;
    auto client       = lantern::Client::create(transport, config);
    if (!client)
        return report(client.error());
    if (const auto server = client->handshake(); !server || !*server)
        return server ? 1 : report(server.error());

    const std::array<std::string_view, 2> scopes { "library", "saves" };
    lantern::PairingOptions options;
    options.device = argv[2];
    options.scopes = scopes;
    auto pairing   = client->start_pairing(options); // with a new device key
    if (!pairing)
        return report(pairing.error());
    // The code, and the address a QR code holds (the app draws it): the
    // user approves on the server's page, or an admin's device
    std::printf("code %s\nopen %s\n", pairing->code.code.c_str(), pairing->code.verify_complete.c_str());

    Kept store;
    for (;;)
    {
        std::this_thread::sleep_for(std::chrono::seconds(pairing->wait));
        const auto polled = client->poll_pairing(*pairing, &store); // signed by the device key
        if (!polled)
            return report(polled.error());
        if (*polled == lantern::PollState::paired)
            break;
    }
    const auto server = client->handshake(); // signed from now on
    if (!server || !*server)
        return server ? 1 : report(server.error());
    std::printf("paired as %s\n", (*server)->account.name.c_str());
    return 0;
}
