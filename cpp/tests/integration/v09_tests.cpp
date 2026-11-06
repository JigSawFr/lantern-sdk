// Draft 0.9 against the reference server: the variants of one game (an
// `[LZ4]` .nsp with its `requires` and `includes`, an update stored twice),
// the listing's `format` filter, `formats` and `satisfies` of what is
// missing, the install decision, and the same answers from the library
// exported as static files. Fictional names and games: Moss and Ember.
#include <doctest.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lantern/lantern.hpp>

#include "posix_http.hpp"
#include "posix_system.hpp"

using namespace lantern;

namespace
{

constexpr std::string_view moss_base   = "0100EFEF00020000";
constexpr std::string_view moss_update = "0100EFEF00020800";

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

    static Client make(posix::LoopbackTransport& transport, const std::string& origin)
    {
        ClientConfig config;
        config.origin     = origin;
        config.user_agent = "LanternCppTests/0.9";
        config.platform   = "switch";
        auto client       = Client::create(transport, config);
        REQUIRE(client);
        return std::move(*client);
    }

    Connection()
        : origin(env("LANTERN_TEST_PUBLIC"))
        , client(make(transport, origin))
    {
        const auto shake = client.handshake();
        REQUIRE(shake);
        REQUIRE(*shake);
    }
};

std::vector<App> all_apps(Client& client, std::string_view format = {})
{
    std::vector<App> out;
    std::string cursor;
    for (int pages = 0; pages < 100; ++pages)
    {
        AppsQuery query;
        query.format    = format;
        query.cursor    = cursor;
        const auto page = client.apps(query);
        REQUIRE(page);
        REQUIRE(*page);
        for (const App& app : (*page)->items)
            out.push_back(app);
        if ((*page)->next.empty())
            break;
        cursor = (*page)->next;
    }
    return out;
}

MissingRequest request_of(
    std::uint64_t installed_version, std::string_view installed_app, std::string_view want)
{
    MissingRequest request;
    if (!installed_app.empty())
    {
        request.installed.emplace_back();
        request.installed.back().app_id       = installed_app;
        request.installed.back().version_code = installed_version;
    }
    request.want.emplace_back(want);
    return request;
}

// The ids of a result, as a sorted set of "app_id/version_code/format".
std::set<std::string> keys(std::span<const App> apps)
{
    std::set<std::string> out;
    for (const App& app : apps)
        out.insert(
            std::string(app.app_id) + "/" + std::to_string(app.version_code) + "/" + std::string(app.format));
    return out;
}

} // namespace

TEST_CASE("v09: the variants the server lists carry their requires and includes")
{
    Connection c;
    const auto apps = all_apps(c.client);
    const App* lz4  = nullptr;
    const App* alt  = nullptr;
    for (const App& app : apps)
    {
        if (app.app_id == moss_base && app.version_code == 65536)
            lz4 = &app;
        if (app.app_id == moss_update && app.format == "nsz")
            alt = &app;
    }
    REQUIRE(lz4 != nullptr);
    REQUIRE(alt != nullptr);
    REQUIRE(lz4->requires_.size() == 2);
    CHECK(lz4->requires_[0] == "fs-compression");
    CHECK(lz4->requires_[1] == "sigpatch");
    REQUIRE(lz4->includes.size() == 1);
    CHECK(lz4->includes[0].app_id == moss_update);
    CHECK(lz4->includes[0].version_code == 131072);
    REQUIRE(alt->requires_.size() == 1);
    CHECK(alt->requires_[0] == "ncz-lz4");
    CHECK(alt->includes.empty());
}

TEST_CASE("v09: the format filter keeps the apps of one format, an unknown one gives an empty list")
{
    Connection c;
    const auto apps = all_apps(c.client);
    std::set<std::string> formats;
    for (const App& app : apps)
        formats.insert(std::string(app.format));
    REQUIRE(formats.size() >= 3);
    for (const std::string& format : formats)
    {
        CAPTURE(format);
        const auto filtered  = all_apps(c.client, format);
        std::size_t expected = 0;
        for (const App& app : apps)
            expected += std::string_view(app.format) == format ? 1U : 0U;
        CHECK(filtered.size() == expected);
        for (const App& app : filtered)
            CHECK(std::string_view(app.format) == format);
    }
    for (const char* unknown : { "zzlantern", "x-lantern-conformance" })
    {
        AppsQuery query;
        query.format    = unknown;
        const auto page = c.client.apps(query);
        REQUIRE(page);
        REQUIRE(*page);
        CHECK((*page)->items.empty());
    }
}

TEST_CASE(
    "v09: what is missing, with the formats and the tokens the device has, and the update already inside")
{
    Connection c;
    // Moss and Ember 1.0 installed: the newest update, in each of its variants
    auto request     = request_of(0, moss_base, "update");
    const auto every = c.client.missing(request);
    REQUIRE(every);
    REQUIRE(*every);
    CHECK(keys((*every)->items)
        == std::set<std::string> { "0100EFEF00020800/131072/nsp", "0100EFEF00020800/131072/nsz" });

    request.formats.emplace().emplace_back("nsp");
    auto only = c.client.missing(request);
    REQUIRE(only);
    REQUIRE(*only);
    CHECK(keys((*only)->items) == std::set<std::string> { "0100EFEF00020800/131072/nsp" });

    request.formats.emplace(); // present and empty: nothing the device reads
    only = c.client.missing(request);
    REQUIRE(only);
    REQUIRE(*only);
    CHECK((*only)->items.empty());

    request.formats.reset();
    request.satisfies.emplace(); // provides nothing: the variant without requires only
    only = c.client.missing(request);
    REQUIRE(only);
    REQUIRE(*only);
    CHECK(keys((*only)->items) == std::set<std::string> { "0100EFEF00020800/131072/nsp" });
    request.satisfies.emplace().emplace_back("ncz-lz4");
    only = c.client.missing(request);
    REQUIRE(only);
    REQUIRE(*only);
    CHECK(keys((*only)->items).size() == 2);

    // The base stored with its update merged in (v65536 includes the update at 131072): nothing to update
    const auto merged = c.client.missing(request_of(65536, moss_base, "update"));
    REQUIRE(merged);
    REQUIRE(*merged);
    CHECK((*merged)->items.empty());

    // Nothing installed: the base games, minus the one that needs tokens the device lacks
    auto bases = request_of(0, {}, "base");
    bases.satisfies.emplace();
    const auto plain = c.client.missing(bases);
    REQUIRE(plain);
    REQUIRE(*plain);
    for (const App& app : (*plain)->items)
        CHECK(app.requires_.empty());
    CHECK_FALSE(keys((*plain)->items).contains("0100EFEF00020000/65536/nsp"));
    bases.satisfies.reset();
    const auto all = c.client.missing(bases);
    REQUIRE(all);
    REQUIRE(*all);
    CHECK(keys((*all)->items).contains("0100EFEF00020000/65536/nsp"));
}

TEST_CASE("v09: a client installs what it can and says why it does not")
{
    Connection c;
    const auto apps = all_apps(c.client);
    const std::vector<std::string_view> formats { "nsp", "nsz", "xci", "xcz" };
    const std::vector<std::string_view> tokens { "fs-compression", "ncz-lz4" }; // not sigpatch
    const std::span<const App> none;
    std::size_t refused = 0;
    for (const App& app : apps)
    {
        CAPTURE(app.id);
        const auto decision       = install_decision(app, formats, tokens, none);
        const bool needs_sigpatch = std::ranges::find(app.requires_, "sigpatch") != app.requires_.end();
        CHECK((decision.verdict == Install::unavailable) == needs_sigpatch);
        refused += decision.verdict == Install::unavailable ? 1U : 0U;
        if (needs_sigpatch)
        {
            REQUIRE(decision.reasons.size() == 1);
            CHECK(decision.reasons[0] == "requires 'sigpatch'");
        }
    }
    CHECK(refused == 1); // the [LZ4] .nsp
    // A device that has the LZ4 base installed does not install the update inside it
    const App* lz4 = nullptr;
    for (const App& app : apps)
    {
        if (app.app_id == moss_base && app.version_code == 65536)
            lz4 = &app;
    }
    REQUIRE(lz4 != nullptr);
    const std::vector<App> installed { *lz4 };
    for (const App& app : apps)
    {
        if (app.app_id != moss_update)
            continue;
        CAPTURE(app.id);
        const bool inside = app.version_code <= 131072;
        CHECK(included(app, installed) == inside);
        CHECK((install_decision(app, formats, tokens, installed).verdict == Install::unavailable) == inside);
    }
}

TEST_CASE("v09: the preferred variant of the same game")
{
    Connection c;
    const auto apps = all_apps(c.client);
    std::vector<App> update; // Moss and Ember's update: a plain .nsp and a smaller .nsz that needs a token
    std::vector<App> comets; // Paper Comets: an .xcz and a smaller-by-size .nsp, both without requires
    for (const App& app : apps)
    {
        if (app.app_id == moss_update && app.version_code == 131072)
            update.push_back(app);
        if (app.title_id == "0100A1B200030000")
            comets.push_back(app);
    }
    REQUIRE(update.size() == 2);
    REQUIRE(comets.size() == 2);
    const App* chosen = prefer_variant(update);
    REQUIRE(chosen != nullptr);
    CHECK(chosen->format == "nsp"); // fewer requires wins over the size
    chosen = prefer_variant(comets);
    REQUIRE(chosen != nullptr);
    CHECK(chosen->format == "nsp"); // the smaller size
}

TEST_CASE("v09: the library as a static library answers what is missing as the server does")
{
    Connection c;
    posix::LoopbackTransport transport;
    auto files = HttpStaticFiles::create(transport, env("LANTERN_TEST_STATIC"), "LanternCppTests/0.9");
    REQUIRE(files);
    auto opened = StaticLibrary::open(*files);
    REQUIRE(opened);
    REQUIRE(*opened);
    StaticLibrary& library = **opened;

    const auto agree = [&](const MissingRequest& request)
    {
        const auto from_server = c.client.missing(request);
        REQUIRE(from_server);
        REQUIRE(*from_server);
        const auto computed = library.missing("switch", request);
        REQUIRE(computed);
        CHECK(keys(*computed) == keys((*from_server)->items));
        return computed->size();
    };
    auto update = request_of(0, moss_base, "update");
    CHECK(agree(update) == 2);
    update.formats.emplace().emplace_back("nsz");
    CHECK(agree(update) == 1);
    update.formats.reset();
    update.satisfies.emplace();
    CHECK(agree(update) == 1);
    CHECK(agree(request_of(65536, moss_base, "update")) == 0);
    auto bases            = request_of(0, {}, "base");
    const auto everything = agree(bases);
    bases.satisfies.emplace();
    CHECK(agree(bases) < everything);
    bases.formats.emplace();
    CHECK(agree(bases) == 0);
}
