// The server core behind the POSIX listener, read by this library's own client
// over plain HTTP on loopback: the handshake, the listing, what is missing and
// a checked download with a resume; and the listener alone, with what no
// client sends (a head that is not HTTP, a body too large, one of unknown
// length). The demo's library (examples/demo_library.hpp) is the one served.
#include <doctest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <lantern/lantern.hpp>

#include "demo_library.hpp"
#include "posix_http.hpp"
#include "posix_system.hpp"
#include "server_posix.hpp"
#include "tcp.hpp"

using namespace lantern;

namespace
{

// The demo served on a free loopback port, by a thread, for one test.
class Running
{
  public:
    Running()
        : library_(demo::base)
    {
        REQUIRE(demo::fill(library_));
        options_.uid    = demo::uid;
        options_.name   = "Demo shelf";
        options_.base   = demo::base;
        options_.scheme = "http";
        auto server     = Server::create(library_, options_, random_, clock_);
        REQUIRE(server);
        server_.emplace(std::move(*server));
        auto listener = posix::HttpListener::listen(*server_);
        REQUIRE(listener);
        listener_.emplace(std::move(*listener));
        origin_ = "http://127.0.0.1:" + std::to_string(listener_->port());
        thread_ = std::thread([this] { listener_->serve(stop_); });
    }
    Running(const Running&)            = delete;
    Running& operator=(const Running&) = delete;
    Running(Running&&)                 = delete;
    Running& operator=(Running&&)      = delete;
    ~Running()
    {
        stop_.store(true);
        thread_.join();
    }

    [[nodiscard]] const std::string& origin() const { return origin_; }
    [[nodiscard]] std::uint16_t port() const { return listener_->port(); }

  private:
    MemoryLibrary library_;
    posix::SystemRandom random_;
    SystemClock clock_;
    ServerOptions options_;
    std::optional<Server> server_;
    std::optional<posix::HttpListener> listener_;
    std::string origin_;
    std::atomic<bool> stop_ { false };
    std::thread thread_;
};

class Collecting final : public DownloadSink
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

// What a socket answers to `request`, bytes as they are written, until it closes.
std::string raw_exchange(std::uint16_t port, std::string_view request)
{
    auto socket = http1::TcpSocket::connect("127.0.0.1", port, std::chrono::seconds(5), true);
    REQUIRE(socket);
    REQUIRE(socket->write(std::span<const char>(request.data(), request.size())));
    std::string answer;
    std::array<char, 4096> chunk {};
    for (;;)
    {
        const auto got = socket->read(chunk);
        if (!got || *got == 0)
            break;
        answer.append(chunk.data(), *got);
    }
    return answer;
}

} // namespace

TEST_CASE("server over HTTP: the client reads the handshake, the listing and what is missing")
{
    Running running;
    posix::LoopbackTransport transport;
    ClientConfig config;
    config.origin     = running.origin();
    config.user_agent = "ServerTests/1";
    config.platform   = "switch";
    auto client       = Client::create(transport, config);
    REQUIRE(client);

    const auto hello = client->handshake();
    REQUIRE(hello);
    REQUIRE(*hello);
    CHECK((*hello)->uid == demo::uid);
    CHECK((*hello)->name == "Demo shelf");
    CHECK((*hello)->base == demo::base);
    CHECK((*hello)->features.library == 1);
    CHECK((*hello)->features.pairing == 0);
    REQUIRE((*hello)->platforms.size() == 3);
    CHECK((*hello)->features.homebrew == 1);
    CHECK((*hello)->features.cheats == 1);

    AppsQuery query;
    query.page_size = 3;
    std::vector<App> all;
    std::string cursor;
    do
    {
        query.cursor    = cursor;
        const auto page = client->apps(query);
        REQUIRE(page);
        REQUIRE(*page);
        for (const App& app : (*page)->items)
            all.push_back(app);
        cursor.assign((*page)->next);
    } while (!cursor.empty());
    CHECK(all.size() == 9); // the Switch's, for Lantern-Platform: switch

    MissingRequest request;
    request.want.emplace_back("base");
    request.want.emplace_back("update");
    InstalledApp lumen;
    lumen.app_id       = "0100AB1200010000";
    lumen.version_code = 0;
    request.installed.push_back(lumen);
    const auto missing = client->missing(request);
    REQUIRE(missing);
    REQUIRE(*missing);
    bool newest = false;
    for (const App& app : (*missing)->items)
        newest = newest || (app.app_id == "0100AB1200010800" && app.version_code == 131072);
    CHECK(newest);
}

TEST_CASE("server over HTTP: the client reads the homebrew, checks what it installs, and the cheat sets")
{
    Running running;
    posix::LoopbackTransport transport;
    ClientConfig config;
    config.origin     = running.origin();
    config.user_agent = "ServerTests/1";
    config.platform   = "switch";
    auto client       = Client::create(transport, config);
    REQUIRE(client);
    REQUIRE(client->handshake());

    const auto page = client->homebrew();
    REQUIRE(page);
    REQUIRE(*page);
    REQUIRE((*page)->items.size() == 4);
    std::size_t signed_entries = 0;
    for (const Homebrew& listed : (*page)->items)
    {
        // The entry, with its manifests: what installing writes is the profile's and the manifest's
        const auto read = client->homebrew_entry(listed.id);
        REQUIRE(read);
        REQUIRE(*read);
        const Homebrew& entry = **read;
        const auto package    = pick_package(entry, "aarch64");
        REQUIRE(package);
        const auto plan = plan_install(entry, **package);
        REQUIRE(plan);
        CHECK_FALSE(plan->files.empty());
        REQUIRE(check_port(entry));
        const auto signature = verify_package_signature(entry, **package);
        REQUIRE(signature);
        if (signature->is_signed)
            ++signed_entries;

        // The package is a file, checked by its size and SHA-256
        Collecting whole;
        DownloadState state;
        REQUIRE(client->download({ (*package)->file, (*package)->size, (*package)->sha256 }, state, whole));
        CHECK(whole.bytes.size() == (*package)->size);
    }
    CHECK(signed_entries == 1);

    // The entry of the other platform carries a package per architecture
    HomebrewQuery linux_query;
    linux_query.platform  = "linux";
    const auto linux_page = client->homebrew(linux_query);
    REQUIRE(linux_page);
    REQUIRE(*linux_page);
    REQUIRE((*linux_page)->items.size() == 1);
    CHECK((*linux_page)->items[0].packages.size() == 1);

    const auto sets = client->cheats();
    REQUIRE(sets);
    REQUIRE(*sets);
    REQUIRE((*sets)->cheats.size() == 3);
    const auto text = client->cheat_text((*sets)->cheats[0]);
    REQUIRE(text);
    CHECK(text->starts_with("[Endless lamp oil]"));
}

TEST_CASE("server over HTTP: a download is checked by its size and SHA-256, and resumes with a range")
{
    Running running;
    posix::LoopbackTransport transport;
    ClientConfig config;
    config.origin     = running.origin();
    config.user_agent = "ServerTests/1";
    config.platform   = "switch";
    auto client       = Client::create(transport, config);
    REQUIRE(client);
    REQUIRE(client->handshake());
    AppsQuery query;
    query.q         = "comet";
    const auto page = client->apps(query);
    REQUIRE(page);
    REQUIRE(*page);
    REQUIRE((*page)->items.size() == 1);
    const App& app = (*page)->items[0];
    CHECK(app.size == 600);

    Collecting whole;
    DownloadState state;
    REQUIRE(client->download({ app.file, app.size, app.sha256 }, state, whole));
    CHECK(whole.bytes.size() == 600);

    // Half of it kept, then the rest by Range, and the whole file's digest checked
    const std::string half = whole.bytes.substr(0, 300);
    Collecting resumed;
    resumed.bytes = half;
    DownloadState partial;
    partial.received = half.size();
    Sha256 hash;
    hash.update(half);
    partial.hash = hash.state();
    REQUIRE(client->download({ app.file, app.size, app.sha256 }, partial, resumed));
    CHECK(resumed.bytes == whole.bytes);

    // The empty file is a file
    AppsQuery tide;
    tide.q           = "quiet tide";
    const auto empty = client->apps(tide);
    REQUIRE(empty);
    REQUIRE(*empty);
    REQUIRE_FALSE((*empty)->items.empty());
    Collecting nothing;
    DownloadState none;
    const App& quiet = (*empty)->items[0];
    CHECK(quiet.size == 0);
    REQUIRE(client->download({ quiet.file, quiet.size, quiet.sha256 }, none, nothing));
    CHECK(nothing.bytes.empty());
}

TEST_CASE("server over HTTP: the listener answers what is not a request of the protocol")
{
    Running running;
    const std::uint16_t port = running.port();
    const auto status_of = [](const std::string& answer) { return answer.substr(0, answer.find("\r\n")); };

    // A GET, as a browser or curl writes it
    std::string answer = raw_exchange(port, "GET /.well-known/lantern HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(status_of(answer) == "HTTP/1.1 200 OK");
    CHECK(answer.contains("Content-Type: application/json\r\n"));
    CHECK(answer.contains("Date: "));
    CHECK(answer.contains("Connection: close\r\n"));
    CHECK(answer.contains("\"uid\":\"3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f\""));

    // HEAD: the headers of the GET, no body
    answer = raw_exchange(port, "HEAD /.well-known/lantern HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(status_of(answer) == "HTTP/1.1 200 OK");
    CHECK(answer.ends_with("\r\n\r\n"));
    CHECK(answer.contains("Content-Length: "));

    // HTTP/1.0 too
    CHECK(status_of(raw_exchange(port, "GET /.well-known/lantern HTTP/1.0\r\n\r\n")) == "HTTP/1.1 200 OK");

    // Not HTTP, a head that does not end, bad headers, a body of unknown length, one too large
    CHECK(status_of(raw_exchange(port, "hello\r\n\r\n")).starts_with("HTTP/1.1 400"));
    CHECK(status_of(raw_exchange(port, "GET / HTTP/2\r\n\r\n")).starts_with("HTTP/1.1 400"));
    CHECK(status_of(raw_exchange(port, "get / HTTP/1.1\r\n\r\n")).starts_with("HTTP/1.1 400"));
    CHECK(
        status_of(raw_exchange(port, "GET / HTTP/1.1\r\nno colon here\r\n\r\n")).starts_with("HTTP/1.1 400"));
    CHECK(status_of(raw_exchange(port, "GET / HTTP/1.1\r\nBad Name: x\r\n\r\n")).starts_with("HTTP/1.1 400"));
    CHECK(status_of(raw_exchange(port, "GET /%zz HTTP/1.1\r\n\r\n")).starts_with("HTTP/1.1 400"));
    CHECK(status_of(raw_exchange(port,
                        "POST /api/lantern/v1/apps/missing?platform=switch HTTP/1.1\r\nTransfer-Encoding: "
                        "chunked\r\n\r\n0\r\n\r\n"))
              .starts_with("HTTP/1.1 400"));
    CHECK(status_of(raw_exchange(port,
                        "POST /api/lantern/v1/apps/missing?platform=switch HTTP/1.1\r\nContent-Length: "
                        "5\r\nContent-Length: 6\r\n\r\n"))
              .starts_with("HTTP/1.1 400"));
    answer = raw_exchange(port,
        "POST /api/lantern/v1/apps/missing?platform=switch HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n");
    CHECK(status_of(answer).starts_with("HTTP/1.1 413"));
    CHECK(answer.contains("application/problem+json"));

    // A body in two pieces, with the head
    const std::string body = R"({"schema":1,"installed":[],"want":["base"]})";
    answer                 = raw_exchange(port,
                        "POST /api/lantern/v1/apps/missing?platform=android HTTP/1.1\r\nContent-Type: "
                                        "application/json\r\nContent-Length: "
                            + std::to_string(body.size()) + "\r\n\r\n" + body);
    CHECK(status_of(answer) == "HTTP/1.1 200 OK");
    CHECK(answer.contains("\"total\":1"));

    // The listener goes on after all of that
    CHECK(status_of(raw_exchange(port, "GET /.well-known/lantern HTTP/1.1\r\n\r\n")) == "HTTP/1.1 200 OK");
}
