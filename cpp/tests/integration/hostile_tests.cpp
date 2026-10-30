// The repository's malicious test server (python/tools/hostile_server.py),
// one scenario per run (run_server.py --hostile-server): the C++ client
// refuses each as the Python client does, and the server's log of what it
// read says what the client sent. A scenario this file does not know fails:
// each one the server gains is answered here too.
//
// The plain HTTP scenarios run in the integration binary, over the loopback
// adapter; the TLS ones in each TLS adapter's binary (LANTERN_HOSTILE_TLS).
#include <doctest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lantern/lantern.hpp>

#include "posix_system.hpp"
#ifdef LANTERN_HOSTILE_TLS
#include "tls_support.hpp"
#else
#include "posix_http.hpp"
#endif

using namespace lantern;

namespace
{

struct Scenario
{
    std::string text; // the JSON line, which the DOM's views point into
    std::optional<json::Document> document;
    std::string name;
    std::string url;
    std::string token;
    std::string pin;
    std::string entry;
    std::string static_root;
};

Scenario scenario()
{
    const char* line = std::getenv("LANTERN_TEST_HOSTILE");
    Scenario s;
    if (line == nullptr)
        return s;
    s.text      = line;
    auto parsed = json::parse(s.text);
    REQUIRE(parsed);
    s.document.emplace(std::move(*parsed));
    const json::Value& root = s.document->root();
    const auto text         = [&](std::string_view key) -> std::string
    {
        const json::Value* value = root.find(key);
        return value != nullptr && value->is_string() ? std::string(value->text()) : std::string();
    };
    s.name        = text("scenario");
    s.url         = text("url");
    s.token       = text("token");
    s.pin         = text("pin");
    s.entry       = text("entry");
    s.static_root = text("static");
    while (!s.url.empty() && s.url.back() == '/')
        s.url.pop_back(); // an origin, as a ClientConfig takes it
    return s;
}

// What the server read: one JSON line per request.
struct Logged
{
    std::string method;
    std::string path;
    std::string authorization;
};

std::vector<Logged> server_log()
{
    std::vector<Logged> out;
    const char* path = std::getenv("LANTERN_TEST_HOSTILE_LOG");
    REQUIRE(path != nullptr);
    std::FILE* file = std::fopen(path, "rb");
    if (file == nullptr)
        return out;
    std::string text;
    char buffer[4096];
    std::size_t got = 0;
    while ((got = std::fread(buffer, 1, sizeof buffer, file)) > 0)
        text.append(buffer, got);
    std::fclose(file);
    std::size_t start = 0;
    while (start < text.size())
    {
        std::size_t end = text.find('\n', start);
        if (end == std::string::npos)
            end = text.size();
        const std::string line = text.substr(start, end - start);
        start                  = end + 1;
        auto parsed            = json::parse(line);
        if (!parsed || !parsed->root().is_object())
            continue; // a line of the server's own, not a request
        const json::Value& root   = parsed->root();
        const json::Value* method = root.find("method");
        if (method == nullptr || !method->is_string())
            continue;
        Logged entry;
        entry.method = std::string(method->text());
        if (const json::Value* p = root.find("path"); p != nullptr && p->is_string())
            entry.path = std::string(p->text());
        if (const json::Value* a = root.find("authorization"); a != nullptr && a->is_string())
            entry.authorization = std::string(a->text());
        out.push_back(std::move(entry));
    }
    return out;
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

struct Device
{
    posix::SystemRandom random;
    ServerTrust trust;
    std::unique_ptr<Transport> transport;
    std::optional<Client> client;

    Device(const Device&)            = delete;
    Device& operator=(const Device&) = delete;

    explicit Device(const Scenario& s, bool pinned)
    {
        if (pinned)
        {
            const auto spki = digest_from_hex(s.pin);
            REQUIRE(spki);
            trust.pin(*spki);
        }
#ifdef LANTERN_HOSTILE_TLS
        transport = test::make_tls_transport(&trust, {}, random);
#else
        transport = std::make_unique<posix::LoopbackTransport>(std::chrono::seconds(30));
#endif
        REQUIRE(transport);
        ClientConfig config;
        config.origin     = s.url;
        config.user_agent = "LanternCppTests/0.5";
        config.platform   = "switch";
        config.random     = &random;
        config.trust      = pinned ? &trust : nullptr;
        auto made         = Client::create(*transport, config);
        REQUIRE(made);
        client.emplace(std::move(*made));
    }

    Client* operator->() { return &*client; }

    void shake_with_token(const Scenario& s)
    {
        REQUIRE(client->set_bearer_token(s.token));
        const auto shaken = client->handshake();
        REQUIRE(shaken);
        REQUIRE(*shaken);
    }
};

#ifndef LANTERN_HOSTILE_TLS
// The plain HTTP scenarios' helpers.
App first_app(Device& device)
{
    const auto page = device->apps();
    REQUIRE(page);
    REQUIRE(*page);
    REQUIRE(!(*page)->items.empty());
    return (*page)->items.front();
}

Homebrew entry_of(Device& device, const Scenario& s)
{
    const auto entry = device->homebrew_entry(s.entry);
    REQUIRE(entry);
    REQUIRE(*entry);
    return **entry;
}

void refuses_install(Device& device, const Scenario& s)
{
    const Homebrew entry = entry_of(device, s);
    const auto plan      = plan_install(entry, entry.package);
    REQUIRE_FALSE(plan);
    CHECK(plan.error().category() == Category::refused);
}

void refuses_listing(Device& device)
{
    const auto page = device->apps();
    REQUIRE_FALSE(page);
    CHECK((page.error().category() == Category::limit || page.error().category() == Category::invalid_response
        || page.error().category() == Category::memory));
}

// The token went to this server only, and nothing was sent to another.
void token_only_here(const Scenario& s)
{
    for (const Logged& entry : server_log())
        CHECK((entry.authorization.empty() || entry.authorization == "Bearer " + s.token));
}
#endif

} // namespace

TEST_CASE("hostile: the scenario run_server.py serves, refused as the Python client refuses it")
{
    const Scenario s = scenario();
    if (s.name.empty())
        return; // not a hostile run
    CAPTURE(s.name);
#ifdef LANTERN_HOSTILE_TLS
    if (s.name == "spki-wrong")
    {
        // Refused before the request is sent: the server reads none
        Device device(s, true);
        const auto shaken = device->handshake();
        REQUIRE_FALSE(shaken);
        CHECK(shaken.error().category() == Category::refused);
        CHECK(server_log().empty());
    }
    else if (s.name == "key-changed")
    {
        // The first connection goes; the next, of another key, is refused
        Device first(s, true);
        first.shake_with_token(s);
        Device next(s, true);
        const auto refused = next->handshake();
        REQUIRE_FALSE(refused);
        CHECK(refused.error().category() == Category::refused);
        CHECK(server_log().size() == 1);
    }
    else
        FAIL("a TLS scenario this client does not know: answer it in hostile_tests.cpp");
#else
    if (s.name == "manifest-dotdot" || s.name == "manifest-relative" || s.name == "manifest-outside")
    {
        Device device(s, false);
        device.shake_with_token(s);
        refuses_install(device, s);
    }
    else if (s.name == "manifest-too-long")
    {
        Device device(s, false);
        device.shake_with_token(s);
        const auto entry = device->homebrew_entry(s.entry);
        REQUIRE_FALSE(entry);
        CHECK(entry.error().category() == Category::limit);
    }
    else if (s.name == "newer-schema")
    {
        // Absent, not an error; and nothing written back
        Device device(s, false);
        REQUIRE(device->set_bearer_token(s.token));
        const auto shaken = device->handshake();
        REQUIRE(shaken);
        CHECK_FALSE(*shaken);
        CHECK(device->server() == nullptr);
        for (const Logged& entry : server_log())
            CHECK((entry.method == "GET" || entry.method == "HEAD"));
    }
    else if (s.name == "oversized-document" || s.name == "deep-document" || s.name == "long-string"
        || s.name == "page-too-long")
    {
        Device device(s, false);
        device.shake_with_token(s);
        refuses_listing(device);
    }
    else if (s.name == "bad-digest" || s.name == "wrong-bytes" || s.name == "extra-bytes")
    {
        Device device(s, false);
        device.shake_with_token(s);
        const App app = first_app(device);
        DownloadState state;
        Sink sink;
        const auto done = device->download({ app.file, app.size, app.sha256 }, state, sink);
        REQUIRE_FALSE(done);
        CHECK(done.error().category() == Category::integrity);
        CHECK(state.received == 0); // nothing kept to resume from
    }
    else if (s.name == "truncated")
    {
        // Cut: a transport error, nothing to install; resumed with a Range
        Device device(s, false);
        device.shake_with_token(s);
        const App app = first_app(device);
        DownloadState state;
        Sink sink;
        const auto cut = device->download({ app.file, app.size, app.sha256 }, state, sink);
        REQUIRE_FALSE(cut);
        CHECK(cut.error().category() == Category::transport);
        CHECK(state.received > 0);
        CHECK(state.received < app.size);
        REQUIRE(device->download({ app.file, app.size, app.sha256 }, state, sink));
        CHECK(sink.bytes.size() == app.size);
        const auto ranges = server_log();
        REQUIRE(!ranges.empty());
    }
    else if (s.name == "wrong-content-range")
    {
        // A resumed download answered with another range: refused, nothing kept
        Device device(s, false);
        device.shake_with_token(s);
        const App app = first_app(device);
        // A download stopped after 100 bytes of the server's file
        // (hostile_server.py's FILE: byte i is (7i + 3) % 251)
        DownloadState state;
        Sink sink;
        Sha256 hash;
        for (unsigned i = 0; i < 100; ++i)
        {
            sink.bytes.push_back(static_cast<char>((i * 7 + 3) % 251));
            const std::byte b { static_cast<unsigned char>((i * 7 + 3) % 251) };
            hash.update(std::span(&b, 1));
        }
        state.received     = 100;
        state.hash         = hash.state();
        const auto resumed = device->download({ app.file, app.size, app.sha256 }, state, sink);
        REQUIRE_FALSE(resumed);
        CHECK(resumed.error().category() == Category::invalid_response);
    }
    else if (s.name == "small-order-key")
    {
        Device device(s, false);
        device.shake_with_token(s);
        const Homebrew entry = entry_of(device, s);
        const auto verdict   = verify_package_signature(entry, entry.package);
        REQUIRE_FALSE(verdict);
        CHECK(verdict.error().category() == Category::signature);
    }
    else if (s.name == "expired-challenge" || s.name == "replayed-challenge")
    {
        // Signed again once, then given up: two requests, no loop
        Device device(s, false);
        const auto key = DeviceKey::generate(device.random);
        REQUIRE(key);
        REQUIRE(device->set_credentials(s.token, *key));
        const auto shaken = device->handshake();
        REQUIRE_FALSE(shaken);
        CHECK(shaken.error().status() == 401);
        CHECK(shaken.error().code()
            == (s.name == "expired-challenge" ? Code::signature_expired : Code::signature_replayed));
        CHECK(server_log().size() == 2);
        if (s.name == "expired-challenge")
            CHECK(device->clock_offset() > std::int64_t { 3600 } * 24 * 365);
    }
    else if (s.name == "pairing-elsewhere")
    {
        // A code whose poll is on another origin: shown nowhere, polled never
        Device device(s, false);
        REQUIRE(device->handshake());
        const std::array<std::string_view, 1> scopes { "library" };
        PairingOptions options;
        options.device     = "Ines's Switch";
        options.scopes     = scopes;
        const auto pairing = device->start_pairing(options);
        REQUIRE_FALSE(pairing);
        CHECK(pairing.error().category() == Category::invalid_response);
        for (const Logged& entry : server_log())
            CHECK(entry.path.find("/pairing/p_hostile") == std::string::npos);
    }
    else if (s.name == "redirect")
    {
        // Never followed: an error, and the token nowhere else
        Device device(s, false);
        REQUIRE(device->set_bearer_token(s.token));
        const auto shaken = device->handshake();
        REQUIRE_FALSE(shaken);
        CHECK(shaken.error().status() == 302);
        CHECK(server_log().size() == 1);
        token_only_here(s);
    }
    else if (s.name == "forged-grant" || s.name == "expired-grant")
    {
        // Refused before it goes to any peer
        Device device(s, false);
        device.shake_with_token(s);
        const App app    = first_app(device);
        const auto grant = device->grant(app.sha256);
        REQUIRE_FALSE(grant);
        CHECK(grant.error().category() == Category::integrity);
    }
    else if (s.name == "oversized-event")
    {
        // Stopped at the bound, never holding the whole line
        Device device(s, false);
        device.shake_with_token(s);
        struct Seen final : EventHandler
        {
            unsigned events = 0;
            bool on_event(const StreamEvent& /*event*/) override
            {
                ++events;
                return true;
            }
        } seen;
        EventStreamState state;
        const auto streamed = device->events(state, seen);
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().category() == Category::limit);
        CHECK(seen.events <= 1);
    }
    else if (s.name == "mirror-wrong-bytes")
    {
        // The mirror's bytes refused, the file from the server, no token to the mirror
        Device device(s, false);
        device.shake_with_token(s);
        const App app = first_app(device);
        REQUIRE(!app.mirrors.empty());
        DownloadState state;
        Sink sink;
        REQUIRE(device->download_with_mirrors(app.mirrors, { app.file, app.size, app.sha256 }, state, sink));
        CHECK(sink.bytes.size() == app.size);
        bool asked_mirror = false;
        for (const Logged& entry : server_log())
        {
            if (entry.path.starts_with("/mirror/"))
            {
                asked_mirror = true;
                CHECK(entry.authorization.empty());
            }
        }
        CHECK(asked_mirror);
    }
    else if (s.name == "static-newer-schema")
    {
        // Absent, not an error
        REQUIRE(!s.static_root.empty());
        posix::LoopbackTransport transport(std::chrono::seconds(30));
        auto files = HttpStaticFiles::create(transport, s.static_root, "LanternCppTests/0.5");
        REQUIRE(files);
        const auto library = StaticLibrary::open(*files);
        REQUIRE(library);
        CHECK_FALSE(*library);
    }
    else
        FAIL("a scenario this client does not know: answer it in hostile_tests.cpp");
#endif
}
