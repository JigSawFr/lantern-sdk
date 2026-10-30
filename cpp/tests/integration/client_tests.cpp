// The client against the specification's reference server (spec/server),
// on the fictional library of spec/tests/library.py, started by
// run_server.py. Every name and game here is made up.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <lantern/lantern.hpp>

#include "posix_http.hpp"

using namespace lantern;

namespace
{

std::string env(const char* name)
{
    const char* value = std::getenv(name);
    REQUIRE_MESSAGE(value != nullptr, "run through run_server.py: ", name, " is not set");
    return value;
}

struct Connection
{
    posix::LoopbackTransport transport;
    std::string origin;
    Client client;

    static Client make(
        posix::LoopbackTransport& transport, const std::string& origin, std::string_view platform)
    {
        ClientConfig config;
        config.origin     = origin;
        config.user_agent = "LanternCppTests/0.3";
        config.platform   = platform;
        auto client       = Client::create(transport, config);
        REQUIRE(client);
        return std::move(*client);
    }

    Connection(const char* origin_variable, std::string_view platform)
        : origin(env(origin_variable))
        , client(make(transport, origin, platform))
    {
        const auto shake = client.handshake();
        REQUIRE(shake);
        REQUIRE(*shake);
    }
};

// A transport that cuts every answer's body after `limit` bytes, as a lost
// connection would.
class Flaky final : public Transport
{
  public:
    Flaky(Transport& inner, std::size_t limit)
        : inner_(inner)
        , limit_(limit)
    {
    }

    Result<void> send(const Request& request, ResponseHandler& handler) override
    {
        Cutter cutter(handler, limit_);
        auto sent = inner_.send(request, cutter);
        if (cutter.cut)
            return fail(Category::transport, "connection reset (by the test)");
        return sent;
    }

  private:
    struct Cutter final : ResponseHandler
    {
        Cutter(ResponseHandler& wrapped, std::size_t limit)
            : inner(wrapped)
            , left(limit)
        {
        }
        bool on_status(std::uint16_t status) override { return inner.on_status(status); }
        bool on_header(std::string_view name, std::string_view value) override
        {
            return inner.on_header(name, value);
        }
        bool on_body(std::span<const std::byte> chunk) override
        {
            if (chunk.size() > left)
            {
                static_cast<void>(inner.on_body(chunk.first(left)));
                cut = true;
                return false;
            }
            left -= chunk.size();
            return inner.on_body(chunk);
        }
        ResponseHandler& inner;
        std::size_t left;
        bool cut = false;
    };

    Transport& inner_;
    std::size_t limit_;
};

class FileSink final : public DownloadSink
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

std::string repeat(std::string_view text, int times)
{
    std::string out;
    for (int i = 0; i < times; ++i)
        out += text;
    return out;
}

} // namespace

TEST_CASE("handshake: a public server, anonymous")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    const Handshake& server = *c.client.server();
    CHECK(server.base == "/api/lantern");
    CHECK(server.account.state == "anonymous");
    CHECK(c.client.offers(Family::library) == 1);
    CHECK(c.client.offers(Family::homebrew) == 1);
    const std::set<std::string> platforms(server.platforms.begin(), server.platforms.end());
    CHECK(platforms.contains("switch"));
    CHECK(platforms.contains("android"));
    CHECK(platforms.contains("linux"));
}

TEST_CASE("apps: every page, by its cursors, each app of the Switch's profile")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    const Profile& profile = *find_profile("switch");
    std::set<std::string> seen;
    std::string cursor;
    int pages           = 0;
    std::uint64_t total = 0;
    do
    {
        AppsQuery query;
        query.page_size = 3;
        query.cursor    = cursor;
        const auto page = c.client.apps(query);
        REQUIRE(page);
        REQUIRE(*page);
        total = (*page)->total.value_or(0);
        for (const App& app : (*page)->items)
        {
            CAPTURE(app.app_id);
            CHECK(app.platform == "switch");
            CHECK(profile.title_id(app.title_id));
            CHECK(profile.app_id(app.type, app.title_id, app.app_id));
            CHECK(has_app_format(profile, app.format));
            CHECK(seen.insert(std::string(app.id)).second);
        }
        cursor = std::string((*page)->next);
        ++pages;
    } while (!cursor.empty() && pages < 20);
    CHECK(seen.size() == 10); // library.py's SWITCH
    CHECK(total == 10);
    CHECK(pages == 4);
    // A cursor the server never gave: 400, or 410 when the server cannot
    // tell it from an expired one (SPEC.md 6.2)
    for (const char* never_given : { "bogus", "c_never-given" })
    {
        AppsQuery bogus;
        bogus.cursor    = never_given;
        const auto read = c.client.apps(bogus);
        REQUIRE_FALSE(read);
        CHECK((read.error().status() == 400 || read.error().status() == 410));
        CHECK((read.error().effective_code() == Code::bad_request
            || read.error().effective_code() == Code::gone));
        CHECK_FALSE(read.error().detail().empty());
    }

    // Another platform through the query
    AppsQuery android;
    android.platform = "android";
    const auto apps  = c.client.apps(android);
    REQUIRE(apps);
    REQUIRE((*apps)->items.size() == 1);
    CHECK((*apps)->items[0].title_id == "org.example.frostlinetales");
    CHECK(find_profile("android")->title_id((*apps)->items[0].title_id));
}

TEST_CASE("apps: what a Switch with Frostline Tales 1.0 is missing")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    MissingRequest request;
    request.installed.emplace_back();
    request.installed.back().app_id       = "0100ABCD00010000";
    request.installed.back().version_code = 0;
    request.want.emplace_back("update");
    request.want.emplace_back("dlc");
    const auto page = c.client.missing(request);
    REQUIRE(page);
    REQUIRE(*page);
    std::map<std::string, std::uint64_t> found;
    for (const App& app : (*page)->items)
        found[std::string(app.app_id)] = app.version_code;
    CHECK(found.size() == 2);
    CHECK(found["0100ABCD00010800"] == 196608); // the newest update
    CHECK(found.contains("0100ABCD00011001")); // the Harbor Pack
}

TEST_CASE("changes and titles")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    const auto start = c.client.changes();
    REQUIRE(start);
    REQUIRE(*start);
    CHECK((*start)->added.empty());
    CHECK_FALSE((*start)->since.empty());
    const auto since = c.client.changes((*start)->since);
    REQUIRE(since);

    const auto title = c.client.title("0100ABCD00010000");
    REQUIRE(title);
    REQUIRE(*title);
    CHECK((*title)->name == "Frostline Tales");
    CHECK((*title)->publisher == "Fjord Works");
    REQUIRE((*title)->players);
    CHECK((*title)->players->max == 4U);
    // library.py's "dating-sim" is not a genre: the server drops it
    CHECK((*title)->genres.size() == 2);

    const std::array<std::string_view, 2> ids { "0100ABCD00010000", "0100FFFF00000000" };
    const auto bulk = c.client.titles(ids);
    REQUIRE(bulk);
    REQUIRE(*bulk);
    CHECK((*bulk)->titles.size() == 1);
    REQUIRE((*bulk)->unknown.size() == 1);
    CHECK((*bulk)->unknown[0] == "0100FFFF00000000");

    const auto unknown = c.client.title("0100FFFF00000000");
    REQUIRE_FALSE(unknown);
    CHECK(unknown.error().effective_code() == Code::not_found);

    const auto title_changes = c.client.title_changes();
    REQUIRE(title_changes);
    REQUIRE(*title_changes);
}

TEST_CASE("downloads: an app, whole, then cut and resumed")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    AppsQuery query;
    query.title_id  = "0100ABCD00010000";
    query.type      = "base";
    const auto page = c.client.apps(query);
    REQUIRE(page);
    REQUIRE((*page)->items.size() == 1);
    const App& app = (*page)->items[0];
    REQUIRE(app.size == 6000);
    const DownloadTarget target { app.file, app.size, app.sha256 };

    FileSink whole;
    DownloadState state;
    REQUIRE(c.client.download(target, state, whole));
    CHECK(whole.bytes.size() == 6000);
    CHECK(Sha256::of(whole.bytes) == app.sha256);

    // Cut at 2500 bytes, then resumed with Range over a good connection
    Flaky flaky(c.transport, 2500);
    ClientConfig config;
    config.origin     = c.origin;
    config.user_agent = "LanternCppTests/0.3";
    config.platform   = "switch";
    auto cut_client   = Client::create(flaky, config);
    REQUIRE(cut_client);
    REQUIRE(cut_client->handshake());
    FileSink part;
    DownloadState partial;
    const auto cut = cut_client->download(target, partial, part);
    REQUIRE_FALSE(cut);
    CHECK(cut.error().category() == Category::transport);
    CHECK(partial.received == 2500);
    const std::size_t before = c.transport.requests();
    REQUIRE(c.client.download(target, partial, part));
    CHECK(c.transport.requests() == before + 1);
    CHECK(part.bytes == whole.bytes);

    // The listing's digest is not this file's: refused
    DownloadTarget wrong = target;
    wrong.sha256[0] ^= 1U;
    FileSink refused;
    DownloadState fresh;
    const auto mismatch = c.client.download(wrong, fresh, refused);
    REQUIRE_FALSE(mismatch);
    CHECK(mismatch.error().category() == Category::integrity);
}

TEST_CASE("homebrew: the Switch's listing, an entry, its plan and its download")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    HomebrewQuery query;
    query.page_size = 100;
    const auto page = c.client.homebrew(query);
    REQUIRE(page);
    REQUIRE(*page);
    std::set<std::string> ids;
    for (const Homebrew& entry : (*page)->items)
    {
        ids.insert(std::string(entry.id));
        // A listing leaves the manifests out (SPEC.md 8.2)
        CHECK(entry.package.manifest.empty());
    }
    CHECK(ids.contains("org.example.frostline"));
    CHECK(ids.contains("org.example.paperlamp"));
    CHECK(ids.contains("org.example.frostline-port"));

    // Frostline: a zip and its manifest, in the roots that need no consent
    const auto read = c.client.homebrew_entry("org.example.frostline");
    REQUIRE(read);
    REQUIRE(*read);
    const Homebrew& frostline = **read;
    const auto package        = pick_package(frostline, "aarch64");
    REQUIRE(package);
    const auto plan = plan_install(frostline, **package);
    REQUIRE(plan);
    CHECK(plan->files.size() == 2);
    CHECK(plan->consent_count == 0);
    FileSink zip;
    DownloadState state;
    REQUIRE(c.client.download({ (*package)->file, (*package)->size, (*package)->sha256 }, state, zip));
    CHECK(zip.bytes.starts_with("PK"));

    // The listing's own entry has no manifest: planning it is refused
    for (const Homebrew& entry : (*page)->items)
    {
        if (entry.id == "org.example.frostline")
            CHECK_FALSE(plan_install(entry, entry.package));
    }
}

TEST_CASE("homebrew: Ines's signed Paper Lamp, verified and pinned")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    const auto read = c.client.homebrew_entry("org.example.paperlamp");
    REQUIRE(read);
    REQUIRE(*read);
    const Homebrew& lamp = **read;
    const auto signature = verify_package_signature(lamp, lamp.package);
    REQUIRE(signature);
    CHECK(signature->is_signed);
    const auto plan = plan_install(lamp, lamp.package);
    REQUIRE(plan);
    CHECK(plan->placement == Placement::single_file);

    // The file itself, as the manifest says
    FileSink nro;
    DownloadState state;
    REQUIRE(c.client.download({ lamp.package.file, lamp.package.size, lamp.package.sha256 }, state, nro));
    CHECK(nro.bytes.size() == lamp.package.size);
}

TEST_CASE("homebrew: the port of Frostline Tales and its data")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    const auto read = c.client.homebrew_entry("org.example.frostline-port");
    REQUIRE(read);
    REQUIRE(*read);
    const Homebrew& port = **read;
    REQUIRE(check_port(port));
    REQUIRE(port.port);
    CHECK(port.port->data_root == "/switch/frostline/");

    class Sd final : public DataProbe
    {
      public:
        std::map<std::string, std::string> files;
        Result<std::optional<std::uint64_t>> size(std::string_view path) override
        {
            const auto found = files.find(std::string(path));
            if (found == files.end())
                return std::optional<std::uint64_t> {};
            return std::optional<std::uint64_t>(found->second.size());
        }
        Result<Digest> sha256(std::string_view path) override
        {
            return Sha256::of(files.at(std::string(path)));
        }
    } sd;
    auto check = launch_check(*port.port, sd);
    REQUIRE(check);
    CHECK_FALSE(check->ready);
    // frost.pak 1.1 (library.py's FROST_PAK[1]) and the demo's music
    sd.files["/switch/frostline/data/frost.pak"] = repeat("frost.pak 1.1 ", 64);
    sd.files["/switch/frostline/music/demo.pak"] = "demo";
    check                                        = launch_check(*port.port, sd);
    REQUIRE(check);
    CHECK(check->ready);
    CHECK_FALSE(check->unverified);
}

TEST_CASE("homebrew: Harbor Lights for Linux, a package per architecture")
{
    Connection c("LANTERN_TEST_PUBLIC", "linux");
    const auto read = c.client.homebrew_entry("org.example.harborlights");
    REQUIRE(read);
    REQUIRE(*read);
    const Homebrew& harbor = **read;
    REQUIRE(check_port(harbor));
    for (const char* arch : { "aarch64", "armhf", "x86_64", "riscv64" })
    {
        CAPTURE(arch);
        const auto package = pick_package(harbor, arch);
        REQUIRE(package);
        CHECK(std::ranges::find((*package)->arch, std::string_view(arch)) != (*package)->arch.end());
        CHECK(verify_package_signature(harbor, **package));
        const auto plan = plan_install(harbor, **package);
        REQUIRE(plan);
        // The launcher next to the ports' folders needs consent (A.6)
        CHECK(plan->consent_count == 1);
    }
    CHECK_FALSE(pick_package(harbor, "x86"));
    REQUIRE(harbor.requires_);
    const std::array<DeviceFacts::Version, 1> glibc { { { "glibc", "2.36" } } };
    DeviceFacts device;
    device.versions = glibc;
    device.ram_mb   = 2048;
    // min.kernel and vram_mb: conditions this client cannot read
    CHECK(check_requires(*harbor.requires_, *find_profile("linux"), device).offer == Offer::warn);
}

TEST_CASE("homebrew: updates of what is installed")
{
    Connection c("LANTERN_TEST_PUBLIC", "switch");
    HomebrewUpdatesRequest request;
    request.installed.emplace_back();
    request.installed.back().id    = "org.example.frostline";
    request.installed.back().build = 10300;
    request.installed.emplace_back();
    request.installed.back().id    = "org.example.paperlamp";
    request.installed.back().build = 902;
    const auto page                = c.client.homebrew_updates(request);
    REQUIRE(page);
    REQUIRE(*page);
    REQUIRE((*page)->items.size() == 1);
    CHECK((*page)->items[0].id == "org.example.frostline");
    CHECK((*page)->items[0].build == 10400U);
}

TEST_CASE("a private server: anonymous, then with the paired device's token")
{
    Connection anonymous("LANTERN_TEST_PRIVATE", "switch");
    CHECK(anonymous.client.server()->account.state == "anonymous");
    CHECK(anonymous.client.offers(Family::library) == 0);
    CHECK(anonymous.client.offers(Family::pairing) == 1);
    CHECK(anonymous.client.apps().error().category() == Category::unsupported);

    // A token the server never gave: 401 (SPEC.md 5.1)
    {
        posix::LoopbackTransport transport;
        ClientConfig config;
        config.origin     = anonymous.origin;
        config.user_agent = "LanternCppTests/0.3";
        auto client       = Client::create(transport, config);
        REQUIRE(client);
        REQUIRE(client->set_bearer_token("et_never-given"));
        const auto shake = client->handshake();
        REQUIRE_FALSE(shake);
        CHECK(shake.error().status() == 401);
        CHECK(shake.error().code() == Code::unauthorized);
    }

    posix::LoopbackTransport transport;
    ClientConfig config;
    config.origin     = anonymous.origin;
    config.user_agent = "LanternCppTests/0.3";
    config.platform   = "switch";
    auto client       = Client::create(transport, config);
    REQUIRE(client);
    REQUIRE(client->set_bearer_token(env("LANTERN_TEST_TOKEN")));
    REQUIRE(client->handshake());
    CHECK(client->server()->account.state == "active");
    CHECK(client->offers(Family::cheats) == 1);

    // Cheats: two sets for Frostline Tales' build, each text checked
    CheatsQuery query;
    query.title_id  = "0100ABCD00010000";
    const auto sets = client->cheats(query);
    REQUIRE(sets);
    REQUIRE(*sets);
    REQUIRE((*sets)->cheats.size() == 2);
    for (const CheatSet& set : (*sets)->cheats)
    {
        CAPTURE(set.source);
        CHECK(set.build_id == "4A1B2C3D4E5F6071");
        const auto text = client->cheat_text(set);
        REQUIRE(text);
        CHECK(text->starts_with("["));
    }
}
