// The server core behind the POSIX listener, read by this library's own client
// over plain HTTP on loopback: the handshake, the listing, what is missing and
// a checked download with a resume; and the listener alone, with what no
// client sends (a head that is not HTTP, a body too large, one of unknown
// length). The demo's library (examples/demo_library.hpp) is the one served.
// Saves larger than the listener buffers go to the store from the socket.
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

constexpr std::string_view lea_token = "et_lea-0123456789abcdef0123456789abcdef";

// The demo served on a free loopback port, by a thread, for one test.
class Running
{
  public:
    // `saves`: an account, `lea`, with the token `lea_token` and the scope saves, whose backups are kept
    // in memory; chunks of up to 2 MiB, streamed from the socket above 1 MiB.
    explicit Running(bool saves = false)
        : library_(demo::base)
    {
        REQUIRE(demo::fill(library_));
        options_.uid    = demo::uid;
        options_.name   = "Demo shelf";
        options_.base   = demo::base;
        options_.scheme = "http";
        posix::ListenOptions listen;
        if (saves)
        {
            constexpr std::array<std::string_view, 2> scopes { "library", "saves" };
            REQUIRE(accounts_.add_account("lea", scopes));
            REQUIRE(accounts_.add_token(lea_token, "lea", "A console", scopes));
            options_.accounts          = &accounts_;
            options_.saves             = &saves_;
            options_.save_limits.chunk = std::uint64_t { 2 } << 20U;
            listen.max_stream          = options_.save_limits.size;
        }
        auto server = Server::create(library_, options_, random_, clock_);
        REQUIRE(server);
        server_.emplace(std::move(*server));
        auto listener = posix::HttpListener::listen(*server_, listen);
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
    MemoryAccountStore accounts_;
    MemorySaveStore saves_;
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

// The text between `before` and the next `"` after it: a JSON string's value, found without parsing.
std::string quoted_after(const std::string& answer, std::string_view before)
{
    const std::size_t at = answer.find(before);
    REQUIRE(at != std::string::npos);
    const std::size_t from = at + before.size();
    return answer.substr(from, answer.find('"', from) - from);
}

std::string status_line(const std::string& answer)
{
    return answer.substr(0, answer.find("\r\n"));
}

// A request to the saves of Running(true): the head with the token, then `body`; the whole of it
// is sent, or, with `declared`, a head that announces more than `body` and the connection closes.
std::string saves_exchange(std::uint16_t port, std::string_view method, std::string_view target,
    std::string_view extra, std::string_view body, std::uint64_t declared = 0)
{
    std::string head(method);
    head += " /api/lantern/v1";
    head += target;
    head += " HTTP/1.1\r\nHost: x\r\nLantern-Platform: switch\r\nAuthorization: Bearer ";
    head += lea_token;
    head += "\r\n";
    head += extra;
    head += "Content-Length: " + std::to_string(declared != 0 ? declared : body.size()) + "\r\n\r\n";
    if (declared != 0)
    {
        // Sent and closed, no answer read
        auto socket = http1::TcpSocket::connect("127.0.0.1", port, std::chrono::seconds(5), true);
        REQUIRE(socket);
        REQUIRE(socket->write(std::span<const char>(head.data(), head.size())));
        REQUIRE(socket->write(std::span<const char>(body.data(), body.size())));
        return {};
    }
    return raw_exchange(port, head + std::string(body));
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

TEST_CASE(
    "server over HTTP: a save above the listener's buffer is streamed to the store, and a cut chunk resumes")
{
    Running running(true);
    const std::uint16_t port = running.port();
    const std::string title  = "0100ABCD00010000";

    // 3 MiB in one request: more than the listener buffers (1 MiB), less than limits.save_body
    std::string archive = "PK\x03\x04";
    for (std::size_t i = archive.size(); i < (std::size_t { 3 } << 20U); ++i)
        archive.push_back(static_cast<char>((i * 2654435761ULL) >> 13U));
    String digest;
    format_digest_field(Sha256::of(std::string_view(archive)), digest);
    std::string answer = saves_exchange(port, "POST", "/saves/" + title,
        "Content-Type: application/zip\r\nContent-Digest: " + std::string(digest) + "\r\n", archive);
    CHECK(status_line(answer) == "HTTP/1.1 201 Created");
    const std::string save_id = quoted_after(answer, "\"save_id\":\"");
    CHECK(save_id.starts_with("s_"));
    answer = saves_exchange(port, "GET", "/saves/" + title + "/" + save_id, "", {});
    CHECK(status_line(answer) == "HTTP/1.1 200 OK");
    CHECK(answer.ends_with(archive));
    // A body of another digest is refused whole
    answer = saves_exchange(port, "POST", "/saves/" + title,
        "Content-Type: application/zip\r\nContent-Digest: "
        "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:\r\n",
        archive);
    CHECK(status_line(answer).starts_with("HTTP/1.1 422"));

    // An upload of 1.5 MiB whose only chunk is cut after 1.25 MiB: the server keeps what came
    const std::string whole = archive.substr(0, std::size_t { 3 } << 19U);
    const auto hex          = to_hex(Sha256::of(std::string_view(whole)));
    answer
        = saves_exchange(port, "POST", "/saves/" + title + "/uploads", "Content-Type: application/json\r\n",
            R"({"schema":1,"size":)" + std::to_string(whole.size()) + R"(,"sha256":")"
                + std::string(hex.data(), hex.size()) + "\"}");
    CHECK(status_line(answer) == "HTTP/1.1 201 Created");
    const std::string upload
        = quoted_after(answer, "\"upload\":\"").substr(std::string("/api/lantern/v1").size());
    const std::size_t cut  = std::size_t { 5 } << 18U; // 1.25 MiB
    const std::string kept = whole.substr(0, cut);
    saves_exchange(port, "PATCH", upload,
        "Content-Type: application/offset+octet-stream\r\nUpload-Offset: 0\r\n", kept, whole.size());
    answer = saves_exchange(port, "HEAD", upload, "", {});
    CHECK(status_line(answer) == "HTTP/1.1 204 No Content");
    CHECK(answer.contains("Upload-Offset: " + std::to_string(cut) + "\r\n"));
    // Resumed from there
    answer = saves_exchange(port, "PATCH", upload,
        "Content-Type: application/offset+octet-stream\r\nUpload-Offset: " + std::to_string(cut) + "\r\n",
        std::string_view(whole).substr(cut));
    CHECK(status_line(answer) == "HTTP/1.1 201 Created");
}
