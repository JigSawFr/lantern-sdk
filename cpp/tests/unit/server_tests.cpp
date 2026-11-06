// The server core (include/lantern/server.hpp), Lantern Core anonymous and
// read-only: the handshake, the apps' listing with its filters, sorts, pages
// and cursors, what a device is missing, the files with their ranges,
// errors, browsers (CORS) and HSTS. The core is called in memory, with no
// socket; the conformance suite plays the same against the demo server.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lantern/byte_range.hpp>
#include <lantern/lantern.hpp>

using namespace lantern;

namespace
{

constexpr std::string_view uid    = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";
constexpr std::string_view origin = "https://app.example.org";

class FixedRandom final : public RandomSource
{
  public:
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        std::ranges::fill(out, std::uint8_t { 0x42 });
        return {};
    }
};

class FakeClock final : public Clock
{
  public:
    std::int64_t now = 1'793'000'000;
    std::int64_t unix_seconds() override { return now; }
};

std::vector<std::byte> bytes(std::string_view text)
{
    const auto view = std::as_bytes(std::span(text.data(), text.size()));
    return { view.begin(), view.end() };
}

// A library of five apps over two platforms, and a server over it.
struct Fixture
{
    MemoryLibrary library { "/api/lantern" };
    FixedRandom random;
    FakeClock clock;
    std::vector<std::string_view> origins { origin };
    ServerOptions options;
    std::optional<Server> server;

    explicit Fixture(bool cors = true, bool https_only = false)
    {
        static constexpr std::array<std::string_view, 1> tokens { "fs-compression" };
        const auto add
            = [&](std::string_view name, std::string_view title, std::string_view app, std::string_view type,
                  std::uint64_t code, std::string_view format, std::string_view content,
                  std::string_view added, std::span<const std::string_view> requires_ = {})
        {
            AppDraft draft;
            draft.platform     = "switch";
            draft.title_id     = title;
            draft.app_id       = app;
            draft.type         = type;
            draft.version_code = code;
            draft.name         = name;
            draft.format       = format;
            draft.added        = added;
            draft.requires_    = requires_;
            REQUIRE(library.add_app(draft, bytes(content)));
        };
        add("Zeta Run", "0100AA0000010000", "0100AA0000010000", "base", 0, "nsp", "zeta-base-0123456789",
            "2026-10-01T10:00:00Z");
        add("Zeta Run", "0100AA0000010000", "0100AA0000010800", "update", 65536, "nsz", "zeta-update-1",
            "2026-10-05T10:00:00Z");
        add("Zeta Run", "0100AA0000010000", "0100AA0000010800", "update", 131072, "nsz", "zeta-update-2",
            "2026-10-06T10:00:00Z");
        add("Alpha Café", "0100BB0000020000", "0100BB0000020000", "base", 0, "xci", "alpha",
            "2026-10-03T10:00:00Z");
        add("Alpha Café", "0100BB0000020000", "0100BB0000020000", "base", 0, "xcz", "alpha-z",
            "2026-10-04T10:00:00Z", tokens);
        add("Empty", "0100CC0000030000", "0100CC0000030000", "base", 0, "nsp", "", "2026-10-02T10:00:00Z");
        AppDraft android;
        android.platform     = "android";
        android.title_id     = "org.example.moth";
        android.app_id       = "org.example.moth";
        android.type         = "base";
        android.version_code = 3;
        android.name         = "Moth";
        android.format       = "apk";
        REQUIRE(library.add_app(android, bytes("moth-apk")));
        options.uid    = uid;
        options.name   = "Test shelf";
        options.scheme = https_only ? "https" : "http";
        if (cors)
            options.cors_origins = origins;
        options.software_name    = "tests";
        options.software_version = "1";
        options.page_limit       = 50;
        remake();
    }

    void remake()
    {
        auto made = Server::create(library, options, random, clock);
        REQUIRE(made);
        server.emplace(std::move(*made));
    }
};

struct Call
{
    std::string method = "GET";
    std::string target;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string scheme = "http";
};

ServerResponse send(const Server& server, const Call& call)
{
    const auto parsed = parse_target(call.target);
    REQUIRE(parsed);
    std::vector<QueryParam> query;
    for (const auto& [name, value] : parsed->query)
        query.push_back({ name, value });
    std::vector<Header> headers;
    for (const auto& [name, value] : call.headers)
        headers.push_back({ name, value });
    ServerRequest request;
    request.method  = call.method;
    request.path    = parsed->path;
    request.query   = query;
    request.headers = headers;
    request.body    = std::as_bytes(std::span(call.body.data(), call.body.size()));
    request.scheme  = call.scheme;
    request.target  = call.target;
    return server.handle(request);
}

ServerResponse get(
    const Fixture& f, std::string target, std::vector<std::pair<std::string, std::string>> headers = {})
{
    Call call;
    call.target  = std::move(target);
    call.headers = std::move(headers);
    return send(*f.server, call);
}

ServerResponse post(const Fixture& f, std::string target, std::string body,
    std::vector<std::pair<std::string, std::string>> headers = { { "Content-Type", "application/json" } })
{
    Call call;
    call.method  = "POST";
    call.target  = std::move(target);
    call.headers = std::move(headers);
    call.body    = std::move(body);
    return send(*f.server, call);
}

// The body of a response: in memory, or read from its file.
std::string body_of(const ServerResponse& response)
{
    if (!response.file)
        return std::string(response.body);
    std::string out(static_cast<std::size_t>(response.file->length), '\0');
    std::size_t done = 0;
    while (done < out.size())
    {
        const auto got = response.file->reader->read(response.file->offset + done,
            std::as_writable_bytes(std::span(out.data() + done, out.size() - done)));
        REQUIRE(got);
        REQUIRE(*got > 0);
        done += *got;
    }
    return out;
}

std::string_view header(const ServerResponse& response, std::string_view name)
{
    return response.headers.get(name).value_or(std::string_view {});
}

bool has_header(const ServerResponse& response, std::string_view name)
{
    return response.headers.get(name).has_value();
}

// The listing's page as the client library reads it.
AppsPage page_of(const ServerResponse& response)
{
    REQUIRE(response.status == 200);
    auto page = read_apps_page(response.body);
    REQUIRE(page);
    REQUIRE(*page);
    return std::move(**page);
}

std::vector<std::string> names_of(const AppsPage& page)
{
    std::vector<std::string> out;
    for (const App& app : page.items)
        out.emplace_back(app.name);
    return out;
}

// Every page of a listing, by its cursors.
std::vector<App> walk(const Fixture& f, const std::string& query, std::size_t& pages)
{
    std::vector<App> all;
    std::string cursor;
    pages = 0;
    do
    {
        std::string target = "/api/lantern/v1/apps?" + query;
        if (!cursor.empty())
            target += "&cursor=" + cursor;
        const AppsPage page = page_of(get(f, target));
        for (const App& app : page.items)
            all.push_back(app);
        cursor.assign(page.next);
        ++pages;
        REQUIRE(pages < 50);
    } while (!cursor.empty());
    return all;
}

Problem problem_of(const ServerResponse& response, std::uint16_t status, std::string_view code)
{
    CHECK(response.status == status);
    CHECK(header(response, "Content-Type") == "application/problem+json");
    CHECK(header(response, "Content-Language") == "en");
    auto read = read_problem(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->status == status);
    CHECK((*read)->code == code);
    CHECK((*read)->language == "en");
    return std::move(**read);
}

} // namespace

TEST_CASE("server: create refuses options that break the protocol")
{
    MemoryLibrary library;
    FixedRandom random;
    FakeClock clock;
    const auto make = [&](auto change)
    {
        ServerOptions options;
        options.uid  = uid;
        options.name = "Shelf";
        change(options);
        return Server::create(library, options, random, clock);
    };
    CHECK(make([](ServerOptions&) {}));
    CHECK_FALSE(make([](ServerOptions& o) { o.uid = "6f1c2a8e-0b3d-1c5e-9a7f-1d2e3f4a5b6c"; })); // version 1
    CHECK_FALSE(make([](ServerOptions& o) { o.uid = "3D5C7E1A-0B2F-4C6D-9E8A-1F2B3C4D5E6F"; })); // upper case
    CHECK_FALSE(make([](ServerOptions& o) { o.name = ""; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.base = "api/lantern"; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.hsts_max_age = 3600; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.page_limit = 0; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.page_limit = 1001; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.scheme = "ftp"; }));
    const std::array<std::string_view, 1> path { "https://app.example.org/x" };
    CHECK_FALSE(make([&](ServerOptions& o) { o.cors_origins = path; }));
    const std::array<std::string_view, 2> good { "https://app.example.org:8443", "*" };
    CHECK(make([&](ServerOptions& o) { o.cors_origins = good; }));
}

TEST_CASE("server: the handshake lists only what this slice serves")
{
    Fixture f;
    for (const char* path : { "/.well-known/lantern", "/api/lantern/v1", "/api/lantern/v1/" })
    {
        const ServerResponse response = get(f, path);
        CHECK(response.status == 200);
        CHECK(header(response, "Content-Type") == "application/json");
        auto read = read_handshake(response.body);
        REQUIRE(read);
        REQUIRE(*read);
        const Handshake& hello = **read;
        CHECK(hello.uid == uid);
        CHECK(hello.name == "Test shelf");
        CHECK(hello.base == "/api/lantern");
        CHECK(hello.versions == Vector<std::uint64_t> { 1 });
        REQUIRE(hello.platforms.size() == 2);
        CHECK(hello.platforms[0] == "android");
        CHECK(hello.platforms[1] == "switch");
        CHECK(hello.account.state == "anonymous");
        REQUIRE(hello.account.scopes.size() == 1);
        CHECK(hello.account.scopes[0] == "library");
        CHECK(hello.features.library == 1);
        for (const auto& family :
            { hello.features.titles, hello.features.changes, hello.features.sections, hello.features.homebrew,
                hello.features.saves, hello.features.cheats, hello.features.requests, hello.features.pairing,
                hello.features.signatures, hello.features.admin, hello.features.events, hello.features.peers,
                hello.features.sync, hello.features.encrypted_saves, hello.features.deltas })
            CHECK(family == 0);
        REQUIRE(hello.limits);
        CHECK(hello.limits->page_size == 50);
        REQUIRE(hello.software);
        CHECK(hello.software->name == "tests");
        CHECK_FALSE(hello.auth);
        CHECK_FALSE(hello.peers);
    }
}

TEST_CASE(
    "server: the handshake has a strong ETag, honours If-None-Match and HEAD, and takes GET and HEAD alone")
{
    Fixture f;
    const ServerResponse first = get(f, "/.well-known/lantern");
    const std::string tag(header(first, "ETag"));
    CHECK(tag.size() == 34);
    CHECK(tag.front() == '"');
    CHECK(header(first, "Cache-Control") == "no-cache");
    CHECK(header(first, "Vary").contains("Lantern-Platform"));
    CHECK(header(first, "Vary").contains("Accept-Encoding"));
    CHECK(header(first, "Content-Length") == std::to_string(first.body.size()));
    for (const std::string& given : { tag, "W/" + tag, "\"other\", " + tag, std::string("*") })
    {
        const ServerResponse again = get(f, "/.well-known/lantern", { { "If-None-Match", given } });
        CHECK(again.status == 304);
        CHECK(again.body.empty());
        CHECK(header(again, "ETag") == tag);
        CHECK(header(again, "Content-Length") == "0");
        CHECK(header(again, "Vary") == header(first, "Vary"));
        CHECK(header(again, "Cache-Control") == "no-cache");
        CHECK_FALSE(has_header(again, "Content-Type"));
    }
    CHECK(get(f, "/.well-known/lantern", { { "If-None-Match", "\"other\"" } }).status == 200);

    Call head;
    head.method                 = "HEAD";
    head.target                 = "/.well-known/lantern";
    const ServerResponse headed = send(*f.server, head);
    CHECK(headed.status == 200);
    CHECK(headed.body.empty());
    CHECK(header(headed, "ETag") == tag);
    CHECK(header(headed, "Content-Length") == header(first, "Content-Length"));

    Call put;
    put.method                   = "PUT";
    put.target                   = "/.well-known/lantern";
    const ServerResponse refused = send(*f.server, put);
    problem_of(refused, 405, "bad_request");
    CHECK(header(refused, "Allow") == "GET, HEAD");
}

TEST_CASE("server: the library lists its platforms once each, and refuses web, which installs nothing")
{
    Fixture f;
    const auto listed = f.library.platforms({});
    REQUIRE(listed);
    REQUIRE(listed->size() == 2);
    CHECK((*listed)[0] == "android");
    CHECK((*listed)[1] == "switch");
    AppDraft web;
    web.platform = "web";
    web.title_id = "x";
    web.app_id   = "x";
    web.type     = "base";
    web.format   = "zip";
    CHECK_FALSE(f.library.add_app(web, bytes("x")));
}

TEST_CASE("server: the listing is paged by cursors that neither skip nor repeat, whatever the page size")
{
    Fixture f;
    std::size_t pages            = 0;
    const std::vector<App> whole = walk(f, "page_size=50", pages);
    CHECK(pages == 1);
    CHECK(whole.size() == 7);
    for (const std::string sort : { "name", "added", "release" })
    {
        std::size_t by_two         = 0;
        const std::vector<App> two = walk(f, "page_size=2&sort=" + sort, by_two);
        CHECK(by_two == 4);
        std::size_t by_one         = 0;
        const std::vector<App> one = walk(f, "page_size=1&sort=" + sort, by_one);
        CHECK(by_one == 7);
        REQUIRE(two.size() == 7);
        REQUIRE(one.size() == 7);
        std::size_t unused         = 0;
        const std::vector<App> all = walk(f, "page_size=50&sort=" + sort, unused);
        for (std::size_t i = 0; i < all.size(); ++i)
        {
            CHECK(two[i].id == all[i].id);
            CHECK(one[i].id == all[i].id);
        }
        auto ids = std::vector<std::string>();
        for (const App& app : all)
            ids.emplace_back(app.id);
        std::ranges::sort(ids);
        CHECK(std::ranges::adjacent_find(ids) == ids.end());
    }
    // Without sort: by name
    std::size_t unused             = 0;
    const std::vector<App> by_name = walk(f, "page_size=50&sort=name", unused);
    for (std::size_t i = 0; i < whole.size(); ++i)
        CHECK(whole[i].id == by_name[i].id);
}

TEST_CASE("server: sorts by name (ignoring case), newest first, and by release")
{
    Fixture f;
    const AppsPage by_name = page_of(get(f, "/api/lantern/v1/apps?platform=switch"));
    REQUIRE(by_name.items.size() == 6);
    CHECK(names_of(by_name)
        == std::vector<std::string> {
            "Alpha Café", "Alpha Café", "Empty", "Zeta Run", "Zeta Run", "Zeta Run" });
    CHECK(by_name.total == 6);
    CHECK(by_name.next.empty());
    const AppsPage by_added = page_of(get(f, "/api/lantern/v1/apps?platform=switch&sort=added"));
    REQUIRE(by_added.items.size() == 6);
    for (std::size_t i = 1; i < by_added.items.size(); ++i)
        CHECK(by_added.items[i - 1].added >= by_added.items[i].added);
    CHECK(by_added.items.front().added == "2026-10-06T10:00:00Z");
    // No title has a release date on this server: every app is without one, in the order of their ids
    const AppsPage by_release = page_of(get(f, "/api/lantern/v1/apps?platform=switch&sort=release"));
    REQUIRE(by_release.items.size() == 6);
    for (std::size_t i = 1; i < by_release.items.size(); ++i)
        CHECK(by_release.items[i - 1].id < by_release.items[i].id);
    problem_of(get(f, "/api/lantern/v1/apps?sort=popular"), 400, "bad_request");
}

TEST_CASE("server: an app is written with the fields of § 6.1 and its file is a path of the server")
{
    Fixture f;
    const AppsPage page = page_of(get(f, "/api/lantern/v1/apps?title_id=0100BB0000020000&format=xcz"));
    REQUIRE(page.items.size() == 1);
    const App& app = page.items[0];
    CHECK(app.platform == "switch");
    CHECK(app.app_id == "0100BB0000020000");
    CHECK(app.type == "base");
    CHECK(app.format == "xcz");
    CHECK(app.size == 7);
    CHECK(app.name == "Alpha Café");
    REQUIRE(app.requires_.size() == 1);
    CHECK(app.requires_[0] == "fs-compression");
    CHECK(app.file.starts_with("/api/lantern/v1/files/f_"));
    CHECK(app.sha256 == Sha256::of(std::string_view("alpha-z")));
}

TEST_CASE("server: filters narrow the listing, and a value no app has gives an empty page")
{
    Fixture f;
    CHECK(page_of(get(f, "/api/lantern/v1/apps?type=update")).items.size() == 2);
    CHECK(page_of(get(f, "/api/lantern/v1/apps?type=dlc")).items.empty());
    CHECK(page_of(get(f, "/api/lantern/v1/apps?format=xci")).items.size() == 1);
    CHECK(page_of(get(f, "/api/lantern/v1/apps?format=nope")).items.empty());
    CHECK(page_of(get(f, "/api/lantern/v1/apps?title_id=0100AA0000010000")).items.size() == 3);
    const AppsPage none = page_of(get(f, "/api/lantern/v1/apps?title_id=unknown-title"));
    CHECK(none.items.empty());
    CHECK(none.next.empty());
    CHECK(none.total == 0);
    // q: a part of the name, whatever its case
    CHECK(page_of(get(f, "/api/lantern/v1/apps?q=ZETA")).items.size() == 3);
    CHECK(page_of(get(f, "/api/lantern/v1/apps?q=a%20r")).items.size() == 3);
    CHECK(page_of(get(f, "/api/lantern/v1/apps?q=zeta+run")).items.size() == 3);
    CHECK(page_of(get(f, "/api/lantern/v1/apps?q=caf%C3%A9")).items.size() == 2);
    // Empty values are absent, unknown parameters ignored
    CHECK(page_of(get(f, "/api/lantern/v1/apps?platform=&type=&title_id=&q=&sort=&cursor=&x=1")).items.size()
        == 7);
    // Bad values
    problem_of(get(f, "/api/lantern/v1/apps?type=Base"), 400, "bad_request");
    problem_of(get(f, "/api/lantern/v1/apps?title_id=a/b"), 400, "bad_request");
    problem_of(get(f, "/api/lantern/v1/apps?platform=Not%20a%20platform!"), 400, "bad_request");
    problem_of(get(f, "/api/lantern/v1/apps?sort=name&sort=added"), 400, "bad_request");
    problem_of(get(f, "/api/lantern/v1/apps?platform=&platform=switch"), 400, "bad_request");
}

TEST_CASE(
    "server: the platform is ?platform=, else Lantern-Platform, and a platform nothing is served of is empty")
{
    Fixture f;
    CHECK(page_of(get(f, "/api/lantern/v1/apps", { { "Lantern-Platform", "android" } })).items.size() == 1);
    CHECK(page_of(get(f, "/api/lantern/v1/apps", { { "Lantern-Platform", " switch " } })).items.size() == 6);
    // The query wins
    CHECK(page_of(get(f, "/api/lantern/v1/apps?platform=android", { { "Lantern-Platform", "switch" } }))
              .items.size()
        == 1);
    CHECK(page_of(get(f, "/api/lantern/v1/apps?platform=web")).items.empty());
    CHECK(page_of(get(f, "/api/lantern/v1/apps?platform=x-no-such")).items.empty());
    problem_of(get(f, "/api/lantern/v1/apps", { { "Lantern-Platform", "SWITCH" } }), 400, "bad_request");
}

TEST_CASE("server: page_size is lowered to the limit, and 0 or a word is a 400")
{
    Fixture f;
    CHECK(page_of(get(f, "/api/lantern/v1/apps?page_size=1")).items.size() == 1);
    CHECK(page_of(get(f, "/api/lantern/v1/apps?page_size=51")).items.size() == 7);
    CHECK(page_of(get(f, "/api/lantern/v1/apps?page_size=99999999999999999999")).items.size() == 7);
    problem_of(get(f, "/api/lantern/v1/apps?page_size=0"), 400, "bad_request");
    problem_of(get(f, "/api/lantern/v1/apps?page_size=-1"), 400, "bad_request");
    problem_of(get(f, "/api/lantern/v1/apps?page_size=ten"), 400, "bad_request");
    f.options.page_limit        = 3;
    f.options.default_page_size = 100;
    f.remake();
    CHECK(page_of(get(f, "/api/lantern/v1/apps")).items.size() == 3);
}

TEST_CASE("server: a cursor the server never gave is a 400, one of another listing too, and an old one a 410")
{
    Fixture f;
    const AppsPage first = page_of(get(f, "/api/lantern/v1/apps?page_size=2"));
    REQUIRE_FALSE(first.next.empty());
    CHECK(first.next.size() <= 512);
    const std::string cursor(first.next);
    CHECK(get(f, "/api/lantern/v1/apps?page_size=2&cursor=" + cursor).status == 200);
    // Never given
    problem_of(get(f, "/api/lantern/v1/apps?cursor=lantern-conformance-0123"), 400, "bad_request");
    problem_of(get(f, "/api/lantern/v1/apps?cursor=c_"), 400, "bad_request");
    std::string tampered          = cursor;
    tampered[tampered.size() / 2] = tampered[tampered.size() / 2] == 'A' ? 'B' : 'A';
    problem_of(get(f, "/api/lantern/v1/apps?page_size=2&cursor=" + tampered), 400, "bad_request");
    // Of another listing
    problem_of(get(f, "/api/lantern/v1/apps?page_size=2&sort=added&cursor=" + cursor), 400, "bad_request");
    problem_of(get(f, "/api/lantern/v1/apps?page_size=2&type=base&cursor=" + cursor), 400, "bad_request");
    // Expired
    f.clock.now += 3601;
    problem_of(get(f, "/api/lantern/v1/apps?page_size=2&cursor=" + cursor), 410, "gone");
}

TEST_CASE("server: two identical requests give the same page and the same ETag; each page has its own")
{
    Fixture f;
    const ServerResponse a = get(f, "/api/lantern/v1/apps?page_size=2");
    const ServerResponse b = get(f, "/api/lantern/v1/apps?page_size=2");
    CHECK(header(a, "ETag") == header(b, "ETag"));
    const AppsPage page       = page_of(a);
    const ServerResponse next = get(f, "/api/lantern/v1/apps?page_size=2&cursor=" + std::string(page.next));
    CHECK(header(next, "ETag") != header(a, "ETag"));
    CHECK(header(get(f, "/api/lantern/v1/apps?platform=android"), "ETag")
        != header(get(f, "/api/lantern/v1/apps?platform=switch"), "ETag"));
    const ServerResponse again
        = get(f, "/api/lantern/v1/apps?page_size=2", { { "If-None-Match", std::string(header(a, "ETag")) } });
    CHECK(again.status == 304);
    CHECK(header(again, "ETag") == header(a, "ETag"));
}

TEST_CASE("server: a cursor stays good when the app it ended with is gone from the listing")
{
    Fixture f;
    // Sorted by name, pages of 1: after Alpha Café (xci) comes Alpha Café (xcz)
    const AppsPage first = page_of(get(f, "/api/lantern/v1/apps?platform=switch&page_size=1"));
    REQUIRE(first.items.size() == 1);
    const AppsPage second = page_of(
        get(f, "/api/lantern/v1/apps?platform=switch&page_size=1&cursor=" + std::string(first.next)));
    REQUIRE(second.items.size() == 1);
    CHECK(second.items[0].id != first.items[0].id);
}

TEST_CASE("server: a long name still pages, found again by its id")
{
    MemoryLibrary library;
    for (int i = 0; i < 3; ++i)
    {
        AppDraft draft;
        draft.platform       = "gog"; // a platform with no profile: its ids are the core's
        const std::string id = "org.example.long" + std::string(1, static_cast<char>('a' + i));
        draft.title_id       = id;
        draft.app_id         = id;
        draft.type           = "base";
        draft.version_code   = 1;
        draft.format         = "zip";
        const std::string name(300, static_cast<char>('a' + i));
        draft.name = name;
        REQUIRE(library.add_app(draft, bytes("x")));
    }
    FixedRandom random;
    FakeClock clock;
    ServerOptions options;
    options.uid  = uid;
    options.name = "Long";
    auto server  = Server::create(library, options, random, clock);
    REQUIRE(server);
    std::string cursor;
    std::size_t seen = 0;
    for (int page = 0; page < 5; ++page)
    {
        Call call;
        call.target
            = "/api/lantern/v1/apps?page_size=1" + (cursor.empty() ? std::string {} : "&cursor=" + cursor);
        const ServerResponse response = send(*server, call);
        auto read                     = read_apps_page(response.body);
        REQUIRE(read);
        REQUIRE(*read);
        seen += (*read)->items.size();
        cursor.assign((*read)->next);
        CHECK(cursor.size() <= 512);
        if (cursor.empty())
            break;
    }
    CHECK(seen == 3);
}

TEST_CASE("server: missing, for a platform and what is installed")
{
    Fixture f;
    const auto missing = [&](const std::string& body,
                             const std::string& target = "/api/lantern/v1/apps/missing?platform=switch")
    { return post(f, target, body); };
    // Base only: the games not installed
    AppsPage page = page_of(missing(R"({"schema":1,"installed":[],"want":["base"]})"));
    CHECK(page.total == 4); // Zeta Run, Alpha Café (two variants), Empty
    // Zeta Run's base is installed: its newest update
    page = page_of(missing(
        R"({"schema":1,"installed":[{"app_id":"0100AA0000010000","version_code":0}],"want":["update"]})"));
    REQUIRE(page.items.size() == 1);
    CHECK(page.items[0].version_code == 131072);
    // Installed up to date: nothing
    page = page_of(missing(
        R"({"schema":1,"installed":[{"app_id":"0100AA0000010000","version_code":0},{"app_id":"0100AA0000010800","version_code":131072}],"want":["update","dlc"]})"));
    CHECK(page.items.empty());
    // A game this library does not know does not change what is missing
    page = page_of(missing(
        R"({"schema":1,"installed":[{"app_id":"0100DD0000099000","version_code":1}],"want":["base"]})"));
    CHECK(page.total == 4);
    // The formats a device reads, the tokens it provides
    page = page_of(missing(R"({"schema":1,"installed":[],"want":["base"],"formats":["nsp","xci"]})"));
    CHECK(page.total == 3);
    page = page_of(missing(R"({"schema":1,"installed":[],"want":["base"],"satisfies":[]})"));
    CHECK(page.total == 3); // the variant that needs a token is left out
    page = page_of(missing(R"({"schema":1,"installed":[],"want":["base"],"satisfies":["fs-compression"]})"));
    CHECK(page.total == 4);
    // Paged, with cursors of the listing
    page = page_of(missing(R"({"schema":1,"installed":[],"want":["base"]})",
        "/api/lantern/v1/apps/missing?platform=switch&page_size=3"));
    REQUIRE_FALSE(page.next.empty());
    CHECK(page.items.size() == 3);
    const AppsPage rest = page_of(missing(R"({"schema":1,"installed":[],"want":["base"]})",
        "/api/lantern/v1/apps/missing?platform=switch&page_size=3&cursor=" + std::string(page.next)));
    CHECK(rest.items.size() == 1);
    // The cursor of another request is refused
    problem_of(
        missing(R"({"schema":1,"installed":[],"want":["dlc"]})",
            "/api/lantern/v1/apps/missing?platform=switch&page_size=3&cursor=" + std::string(page.next)),
        400, "bad_request");
    // Lantern-Platform names the platform too
    const ServerResponse by_header
        = post(f, "/api/lantern/v1/apps/missing", R"({"schema":1,"installed":[],"want":["base"]})",
            { { "Content-Type", "application/json" }, { "Lantern-Platform", "android" } });
    CHECK(page_of(by_header).total == 1);
}

TEST_CASE("server: a missing request that is not a document of the protocol is refused as § 12 says")
{
    Fixture f;
    const std::string target = "/api/lantern/v1/apps/missing?platform=switch";
    const auto code          = [&](const std::string& body) { return post(f, target, body).status; };
    const std::string good   = R"({"schema":1,"installed":[],"want":["base"]})";
    CHECK(code(good) == 200);
    // No platform
    problem_of(post(f, "/api/lantern/v1/apps/missing", good), 400, "bad_request");
    // Not JSON, not I-JSON
    CHECK(code("{") == 400);
    CHECK(code("") == 400);
    CHECK(code("[]") == 400);
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"schema":1})") == 400); // a name twice
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"x":9007199254740993})")
        == 400); // beyond 2^53 - 1
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"x":9007199254740991})") == 200);
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"x":1e300})") == 400);
    CHECK(code("\xEF\xBB\xBF" + good) == 400); // a byte order mark
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"x":"\ud800"})") == 400); // a lone surrogate
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"x":[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]})")
        == 400); // deeper than 16
    // schema
    CHECK(code(R"({"installed":[],"want":["base"]})") == 400);
    CHECK(code(R"({"schema":"1","installed":[],"want":["base"]})") == 400);
    CHECK(code(R"({"schema":0,"installed":[],"want":["base"]})") == 400);
    const ServerResponse newer = post(f, target, R"({"schema":2,"installed":[],"want":["base"]})");
    problem_of(newer, 422, "unsupported_schema");
    // Content-Type
    problem_of(post(f, target, good, { { "Content-Type", "text/plain" } }), 400, "bad_request");
    problem_of(post(f, target, good, {}), 400, "bad_request");
    CHECK(post(f, target, good, { { "content-type", "Application/JSON; charset=utf-8" } }).status == 200);
    // Too large
    problem_of(post(f, target, std::string(2 << 20, ' ')), 413, "too_large");
    // want and installed
    CHECK(code(R"({"schema":1,"installed":[],"want":[]})") == 400);
    CHECK(code(R"({"schema":1,"installed":[],"want":["base","patch"]})") == 400);
    CHECK(code(R"({"schema":1,"installed":[{"app_id":"a/b","version_code":1}],"want":["base"]})") == 400);
    CHECK(code(R"({"schema":1,"installed":[{"app_id":"a"}],"want":["base"]})") == 400);
    CHECK(code(R"({"schema":1,"want":["base"]})") == 400);
    // formats and satisfies: at most 16 words of their forms
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"formats":["NSP"]})") == 400);
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"formats":"nsp"})") == 400);
    CHECK(code(R"({"schema":1,"installed":[],"want":["base"],"satisfies":["-bad"]})") == 400);
    std::string many = R"({"schema":1,"installed":[],"want":["base"],"formats":[)";
    for (int i = 0; i < 17; ++i)
        many += std::string(i == 0 ? "" : ",") + "\"f" + std::to_string(i) + "\"";
    many += "]}";
    CHECK(code(many) == 400);
    // GET is not the route's method
    const ServerResponse wrong = get(f, target);
    problem_of(wrong, 405, "bad_request");
    CHECK(header(wrong, "Allow") == "POST");
}

TEST_CASE("server: a file is served whole, with its validators and the digest of the whole file")
{
    Fixture f;
    const AppsPage page = page_of(get(f, "/api/lantern/v1/apps?q=zeta&type=base"));
    REQUIRE(page.items.size() == 1);
    const App& app                = page.items[0];
    const ServerResponse response = get(f, std::string(app.file));
    CHECK(response.status == 200);
    CHECK(body_of(response) == "zeta-base-0123456789");
    CHECK(header(response, "Content-Length") == "20");
    CHECK(header(response, "Content-Type") == "application/octet-stream");
    CHECK(header(response, "Accept-Ranges") == "bytes");
    CHECK_FALSE(has_header(response, "Content-Encoding"));
    CHECK(header(response, "ETag").size() == 34);
    String digest;
    format_digest_field(app.sha256, digest);
    CHECK(header(response, "Repr-Digest") == digest);
    CHECK(header(response, "Cache-Control") == "no-cache");
    // A token would make it private (§ 14)
    CHECK(header(get(f, std::string(app.file), { { "Authorization", "Basic abc" } }), "WWW-Authenticate")
        == R"(Bearer realm="lantern")");

    Call head;
    head.method                 = "HEAD";
    head.target                 = std::string(app.file);
    const ServerResponse headed = send(*f.server, head);
    CHECK(headed.status == 200);
    CHECK_FALSE(headed.file);
    CHECK(headed.body.empty());
    CHECK(header(headed, "Content-Length") == "20");
    CHECK(header(headed, "ETag") == header(response, "ETag"));
    CHECK(header(headed, "Repr-Digest") == digest);

    // The file is never read by the core: the adapter reads it, piece by piece
    REQUIRE(response.file);
    CHECK(response.file->offset == 0);
    CHECK(response.file->length == 20);
    std::array<std::byte, 8> piece {};
    const auto got = response.file->reader->read(16, piece);
    REQUIRE(got);
    CHECK(*got == 4); // the file ends there
}

TEST_CASE("server: ranges, If-Range and the ranges outside the file")
{
    Fixture f;
    const std::string file
        = std::string(page_of(get(f, "/api/lantern/v1/apps?q=zeta&type=base")).items[0].file);
    const std::string whole = "zeta-base-0123456789";
    const auto ranged = [&](std::string range, std::vector<std::pair<std::string, std::string>> more = {})
    {
        more.emplace_back("Range", std::move(range));
        return get(f, file, std::move(more));
    };
    String digest;
    format_digest_field(Sha256::of(std::string_view(whole)), digest);

    ServerResponse r = ranged("bytes=5-8");
    CHECK(r.status == 206);
    CHECK(body_of(r) == whole.substr(5, 4));
    CHECK(header(r, "Content-Range") == "bytes 5-8/20");
    CHECK(header(r, "Content-Length") == "4");
    CHECK(header(r, "Repr-Digest") == digest); // the whole file's, on a part
    r = ranged("bytes=15-");
    CHECK(r.status == 206);
    CHECK(body_of(r) == whole.substr(15));
    CHECK(header(r, "Content-Range") == "bytes 15-19/20");
    r = ranged("bytes=-4");
    CHECK(r.status == 206);
    CHECK(body_of(r) == whole.substr(16));
    r = ranged("bytes=-400");
    CHECK(r.status == 206);
    CHECK(body_of(r) == whole);
    r = ranged("bytes=10-400");
    CHECK(header(r, "Content-Range") == "bytes 10-19/20");
    // Outside the file
    r = ranged("bytes=20-");
    problem_of(r, 416, "bad_request");
    CHECK(header(r, "Content-Range") == "bytes */20");
    problem_of(ranged("bytes=100-200"), 416, "bad_request");
    problem_of(ranged("bytes=-0"), 416, "bad_request");
    // Ranges this server does not honour: the whole file, never multipart
    for (const std::string odd : { "bytes=0-0,2-2", "items=1-2", "bytes=5-2", "bytes=a-b", "bytes", "" })
    {
        r = ranged(odd);
        CHECK(r.status == 200);
        CHECK(body_of(r) == whole);
        CHECK(header(r, "Content-Type") == "application/octet-stream");
    }
    // If-Range: of its ETag, the range; of another, the whole file
    const std::string tag(header(get(f, file), "ETag"));
    r = ranged("bytes=1-", { { "If-Range", tag } });
    CHECK(r.status == 206);
    CHECK(body_of(r) == whole.substr(1));
    r = ranged("bytes=1-", { { "If-Range", "\"other\"" } });
    CHECK(r.status == 200);
    CHECK(body_of(r) == whole);
    // HEAD of a range
    Call head;
    head.method                 = "HEAD";
    head.target                 = file;
    head.headers                = { { "Range", "bytes=0-3" } };
    const ServerResponse headed = send(*f.server, head);
    CHECK(headed.status == 206);
    CHECK(headed.body.empty());
    CHECK(header(headed, "Content-Length") == "4");
    CHECK(header(headed, "Content-Range") == "bytes 0-3/20");
}

TEST_CASE("server: an empty file, and a file nobody has")
{
    Fixture f;
    const std::string empty = std::string(page_of(get(f, "/api/lantern/v1/apps?q=empty")).items[0].file);
    ServerResponse r        = get(f, empty);
    CHECK(r.status == 200);
    CHECK(r.body.empty());
    CHECK_FALSE(r.file);
    CHECK(header(r, "Content-Length") == "0");
    String digest;
    format_digest_field(Sha256::of(std::string_view("")), digest);
    CHECK(header(r, "Repr-Digest") == digest);
    problem_of(get(f, empty, { { "Range", "bytes=0-" } }), 416, "bad_request");
    problem_of(get(f, "/api/lantern/v1/files/f_nobody"), 404, "not_found");
    problem_of(get(f, "/api/lantern/v1/files/"), 404, "not_found");
    problem_of(get(f, "/api/lantern/v1/files/a/b"), 404, "not_found");
    // POST is not a file's method
    Call post_file;
    post_file.method             = "POST";
    post_file.target             = empty;
    const ServerResponse refused = send(*f.server, post_file);
    problem_of(refused, 405, "bad_request");
    CHECK(header(refused, "Allow") == "GET, HEAD");
}

TEST_CASE(
    "server: errors are problem+json with the code of § 12, and the routes of families not served are 404")
{
    Fixture f;
    const Problem missing = problem_of(get(f, "/api/lantern/v1/no-such-route"), 404, "not_found");
    CHECK(missing.title == "Not found");
    CHECK(missing.type == "https://lantern.boreale.dev/errors/not-found");
    CHECK_FALSE(missing.detail.empty());
    problem_of(get(f, "/api/lantern/v1/apps/"), 404, "not_found");
    problem_of(get(f, "/api/lantern/v1/apps/missing/x"), 404, "not_found");
    problem_of(get(f, "/api/lantern/v1/titles?ids=x"), 404, "not_found");
    problem_of(get(f, "/api/lantern/v1/homebrew"), 404, "not_found");
    problem_of(get(f, "/api/lantern/v1/saves"), 404, "not_found");
    problem_of(get(f, "/api/lantern/v1/pairing"), 404, "not_found");
    problem_of(get(f, "/api/lantern/v1/admin/users"), 404, "not_found");
    problem_of(get(f, "/elsewhere"), 404, "not_found");
    problem_of(get(f, "/api/lantern"), 404, "not_found");
    problem_of(get(f, "/api/lanternv1/apps"), 404, "not_found");
    // Every error carries the caching headers, and a HEAD of one has no body
    const ServerResponse r = get(f, "/api/lantern/v1/no-such-route");
    CHECK(header(r, "Vary").starts_with("Authorization, Lantern-Platform, Accept-Language"));
    CHECK(header(r, "Cache-Control") == "no-cache");
    CHECK(header(r, "Content-Length") == std::to_string(r.body.size()));
    Call head;
    head.method                 = "HEAD";
    head.target                 = "/api/lantern/v1/no-such-route";
    const ServerResponse headed = send(*f.server, head);
    CHECK(headed.status == 404);
    CHECK(headed.body.empty());
    CHECK(header(headed, "Content-Length") == header(r, "Content-Length"));
    // A server with another base
    f.options.base = "/lantern/";
    f.remake();
    CHECK(get(f, "/lantern/v1/apps").status == 200);
    CHECK(get(f, "/lantern/v1").status == 200);
    CHECK(get(f, "/api/lantern/v1/apps").status == 404);
    CHECK(f.server->base() == "/lantern");
}

TEST_CASE("server: a token is refused, as this server issues none, and no Basic challenge is ever sent")
{
    Fixture f;
    for (const char* path : { "/.well-known/lantern", "/api/lantern/v1/apps" })
    {
        ServerResponse r = get(f, path, { { "Authorization", "Bearer et_unknown-token" } });
        problem_of(r, 401, "unauthorized");
        CHECK(header(r, "WWW-Authenticate") == R"(Bearer realm="lantern", error="invalid_token")");
        r = get(f, path, { { "Authorization", "Basic YTpi" } });
        problem_of(r, 401, "unauthorized");
        CHECK(header(r, "WWW-Authenticate") == R"(Bearer realm="lantern")");
        CHECK(header(r, "Cache-Control") == "private");
        r = get(f, path, { { "Authorization", "Bearer " } });
        problem_of(r, 401, "unauthorized");
    }
    // An unknown route is a 404 before it is a question of who calls
    problem_of(get(f, "/api/lantern/v1/nothing", { { "Authorization", "Bearer x" } }), 404, "not_found");
}

TEST_CASE("server: an adapter answers what it cannot read as problem+json")
{
    const ServerResponse r
        = problem_response(413, Code::too_large, "That body is larger than this server takes.");
    CHECK(r.status == 413);
    CHECK(header(r, "Content-Type") == "application/problem+json");
    CHECK(header(r, "Content-Length") == std::to_string(r.body.size()));
    auto read = read_problem(r.body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->code == "too_large");
    CHECK((*read)->title == "Too large");
    CHECK(status_text(416) == "Range Not Satisfiable");
    CHECK(status_text(299) == "Unknown");
}

TEST_CASE("server: browsers (§ 2.5): an allowed origin reads every answer, errors included")
{
    Fixture f;
    const std::vector<std::pair<std::string, std::string>> from_page { { "Origin", std::string(origin) } };
    for (const char* path : { "/.well-known/lantern", "/api/lantern/v1/apps?page_size=1",
             "/api/lantern/v1/no-such-route", "/api/lantern/v1/apps?page_size=0" })
    {
        const ServerResponse r = get(f, path, from_page);
        CHECK(header(r, "Access-Control-Allow-Origin") == origin);
        const std::string_view exposed = header(r, "Access-Control-Expose-Headers");
        for (const char* name : { "ETag", "Content-Range", "Accept-Ranges", "Repr-Digest", "WWW-Authenticate",
                 "Retry-After", "Date" })
            CHECK(exposed.contains(name));
        CHECK(header(r, "Vary").contains("Origin"));
        CHECK_FALSE(has_header(r, "Access-Control-Allow-Credentials"));
        CHECK_FALSE(has_header(r, "Set-Cookie"));
    }
    // A file, its HEAD too
    const std::string file
        = std::string(page_of(get(f, "/api/lantern/v1/apps?q=zeta&type=base")).items[0].file);
    Call head;
    head.method  = "HEAD";
    head.target  = file;
    head.headers = from_page;
    CHECK(header(send(*f.server, head), "Access-Control-Allow-Origin") == origin);
    // Another origin, or none: nothing of CORS, but the Vary that tells caches the answer depends on it
    const ServerResponse other
        = get(f, "/api/lantern/v1/apps?page_size=1", { { "Origin", "https://evil.example.org" } });
    CHECK_FALSE(has_header(other, "Access-Control-Allow-Origin"));
    CHECK(header(other, "Vary").contains("Origin"));
    const ServerResponse none = get(f, "/api/lantern/v1/apps?page_size=1");
    CHECK_FALSE(has_header(none, "Access-Control-Allow-Origin"));
    // Not a route of the text
    CHECK_FALSE(has_header(get(f, "/elsewhere", from_page), "Access-Control-Allow-Origin"));
    // A server with no origin allowed sends none
    Fixture closed(false);
    CHECK_FALSE(has_header(get(closed, "/.well-known/lantern", from_page), "Access-Control-Allow-Origin"));
    CHECK_FALSE(header(get(closed, "/.well-known/lantern", from_page), "Vary").contains("Origin"));
}

TEST_CASE("server: a preflight is answered 204 without a token, on any route, for the headers a page asks")
{
    Fixture f;
    const auto preflight = [&](std::string target, std::string method, std::string asked)
    {
        Call call;
        call.method = "OPTIONS";
        call.target = std::move(target);
        call.headers
            = { { "Origin", std::string(origin) }, { "Access-Control-Request-Method", std::move(method) },
                  { "Access-Control-Request-Headers", std::move(asked) } };
        return send(*f.server, call);
    };
    for (const char* target : { "/api/lantern/v1/apps?page_size=1", "/api/lantern/v1/apps/missing",
             "/api/lantern/v1/sync/wishes", "/api/lantern/v1/no-such-route", "/.well-known/lantern" })
    {
        const ServerResponse r
            = preflight(target, "POST", "content-type, authorization, lantern-platform, signature-input");
        CHECK(r.status == 204);
        CHECK(r.body.empty());
        CHECK(header(r, "Access-Control-Allow-Origin") == origin);
        CHECK(header(r, "Access-Control-Allow-Methods").contains("POST"));
        CHECK(header(r, "Access-Control-Allow-Methods").contains("PATCH"));
        const std::string_view allowed = header(r, "Access-Control-Allow-Headers");
        for (const char* name : { "Content-Type", "Authorization", "Lantern-Platform", "Signature-Input" })
            CHECK(allowed.contains(name));
        CHECK(std::stoi(std::string(header(r, "Access-Control-Max-Age"))) >= 600);
        CHECK(header(r, "Content-Length") == "0");
        CHECK_FALSE(has_header(r, "Access-Control-Allow-Credentials"));
        CHECK_FALSE(has_header(r, "Access-Control-Expose-Headers"));
    }
    // Headers it names: only ours, once; none of ours: all of them
    CHECK(header(preflight("/api/lantern/v1/apps", "GET", "range, X-Nope, RANGE"),
              "Access-Control-Allow-Headers")
        == "Range");
    CHECK(header(preflight("/api/lantern/v1/apps", "GET", ""), "Access-Control-Allow-Headers")
              .contains("If-None-Match"));
    // Another origin, or no method asked: an OPTIONS no route takes
    Call other;
    other.method  = "OPTIONS";
    other.target  = "/api/lantern/v1/apps";
    other.headers = { { "Origin", "https://evil.example.org" }, { "Access-Control-Request-Method", "GET" } };
    ServerResponse r = send(*f.server, other);
    problem_of(r, 405, "bad_request");
    CHECK_FALSE(has_header(r, "Access-Control-Allow-Origin"));
    other.headers = { { "Origin", std::string(origin) } };
    problem_of(send(*f.server, other), 405, "bad_request");
    // Not a route of the text
    Call elsewhere;
    elsewhere.method  = "OPTIONS";
    elsewhere.target  = "/elsewhere";
    elsewhere.headers = { { "Origin", std::string(origin) }, { "Access-Control-Request-Method", "GET" } };
    problem_of(send(*f.server, elsewhere), 404, "not_found");
}

TEST_CASE("server: * allows every origin, once, and never with credentials")
{
    Fixture f(false);
    const std::array<std::string_view, 1> any { "*" };
    f.options.cors_origins = any;
    f.remake();
    const ServerResponse r
        = get(f, "/api/lantern/v1/apps?page_size=1", { { "Origin", "https://anything.example.net" } });
    CHECK(header(r, "Access-Control-Allow-Origin") == "*");
    CHECK_FALSE(header(r, "Vary").contains("Origin"));
    CHECK_FALSE(has_header(r, "Access-Control-Allow-Credentials"));
}

TEST_CASE("server: Strict-Transport-Security goes over HTTPS, or when told, and never over plain HTTP")
{
    Fixture f;
    const auto hsts = [&](const Fixture& fixture, std::string scheme)
    {
        Call call;
        call.target = "/.well-known/lantern";
        call.scheme = std::move(scheme);
        return std::string(header(send(*fixture.server, call), "Strict-Transport-Security"));
    };
    CHECK(hsts(f, "https") == "max-age=31536000");
    CHECK(hsts(f, "http").empty());
    // Errors too
    Call missing;
    missing.target = "/nothing";
    missing.scheme = "https";
    CHECK(header(send(*f.server, missing), "Strict-Transport-Security") == "max-age=31536000");
    f.options.hsts = true;
    f.remake();
    CHECK(hsts(f, "http") == "max-age=31536000");
    f.options.hsts_max_age = 15552000;
    f.remake();
    CHECK(hsts(f, "https") == "max-age=15552000");
    // A request that names no scheme has the server's
    Fixture secure(true, true);
    Call bare;
    bare.target = "/.well-known/lantern";
    bare.scheme = "";
    CHECK(has_header(send(*secure.server, bare), "Strict-Transport-Security"));
}

TEST_CASE("server: a request target is split and decoded, and a bad one is refused")
{
    auto parsed = parse_target("/api/lantern/v1/apps?q=caf%C3%A9+au%20lait&type=base&empty=&flag&a=b=c&&");
    REQUIRE(parsed);
    CHECK(parsed->path == "/api/lantern/v1/apps");
    REQUIRE(parsed->query.size() == 5);
    CHECK(parsed->query[0].first == "q");
    CHECK(parsed->query[0].second == "café au lait");
    CHECK(parsed->query[2].first == "empty");
    CHECK(parsed->query[2].second.empty());
    CHECK(parsed->query[3].first == "flag");
    CHECK(parsed->query[4].second == "b=c");
    parsed = parse_target("/a%2Fb/c%20d");
    REQUIRE(parsed);
    CHECK(parsed->path == "/a/b/c d");
    parsed = parse_target("/a+b");
    REQUIRE(parsed);
    CHECK(parsed->path == "/a+b"); // a plus is a space in a query alone
    CHECK_FALSE(parse_target("api/lantern"));
    CHECK_FALSE(parse_target("*"));
    CHECK_FALSE(parse_target("/bad%zz"));
    CHECK_FALSE(parse_target("/bad%2"));
    CHECK_FALSE(parse_target("/nul%00"));
    CHECK_FALSE(parse_target("/tab%09"));
    CHECK_FALSE(parse_target("/ok?q=%01"));
}

TEST_CASE("server: response headers are set by name, ignoring case")
{
    ResponseHeaders headers;
    headers.set("Content-Type", "a");
    headers.set("content-type", "b");
    headers.add("Link", "1");
    headers.add("Link", "2");
    CHECK(headers.get("CONTENT-TYPE") == "b");
    CHECK(headers.entries().size() == 3);
    headers.erase("link");
    CHECK(headers.entries().size() == 1);
    CHECK_FALSE(headers.get("Link"));
}

TEST_CASE("server: a Range header is read as RFC 9110 and § 6.6 want")
{
    const auto parse
        = [](std::string_view value, std::uint64_t size) { return parse_range_header(value, size); };
    CHECK(parse("bytes=0-9", 100).verdict == RangeVerdict::satisfiable);
    CHECK(parse("bytes=0-9", 100).last == 9);
    CHECK(parse("bytes=90-", 100).first == 90);
    CHECK(parse("bytes=90-", 100).last == 99);
    CHECK(parse("bytes=-10", 100).first == 90);
    CHECK(parse("bytes=-1000", 100).first == 0);
    CHECK(parse("bytes=0-1000", 100).last == 99);
    CHECK(parse("bytes=100-", 100).verdict == RangeVerdict::unsatisfiable);
    CHECK(parse("bytes=-0", 100).verdict == RangeVerdict::unsatisfiable);
    CHECK(parse("bytes=0-", 0).verdict == RangeVerdict::unsatisfiable);
    CHECK(parse("bytes=-5", 0).verdict == RangeVerdict::unsatisfiable);
    for (const std::string_view odd :
        { "bytes=0-1,3-4", "items=0-1", "bytes=9-2", "bytes=x-", "bytes=-", "bytes=1", "", "bytes=0-1 " })
        CHECK(parse(odd, 100).verdict == RangeVerdict::ignored);
}

TEST_CASE("server: the memory library refuses what breaks § 6.1 and its platform's profile")
{
    MemoryLibrary library;
    AppDraft draft;
    draft.platform     = "switch";
    draft.title_id     = "0100AB1200010000";
    draft.app_id       = "0100AB1200010000";
    draft.type         = "base";
    draft.version_code = 0;
    draft.name         = "Lumen";
    draft.format       = "nsp";
    const auto content = bytes("content");
    CHECK(library.add_app(draft, content));
    CHECK(library.size() == 1);
    CHECK_FALSE(library.add_app(draft, content)); // the same app twice
    AppDraft bad     = draft;
    bad.version_code = 1;
    bad.title_id     = "not-a-switch-id";
    CHECK_FALSE(library.add_app(bad, content));
    bad              = draft;
    bad.version_code = 1;
    bad.format       = "exe"; // not a Switch format
    CHECK_FALSE(library.add_app(bad, content));
    bad.format = "NSP";
    CHECK_FALSE(library.add_app(bad, content));
    bad          = draft;
    bad.platform = "web";
    CHECK_FALSE(library.add_app(bad, content));
    bad              = draft;
    bad.version_code = 2;
    bad.added        = "yesterday";
    CHECK_FALSE(library.add_app(bad, content));
    const std::array<std::string_view, 2> twice { "a", "a" };
    bad.added     = "";
    bad.requires_ = twice;
    CHECK_FALSE(library.add_app(bad, content));
    const std::array<std::string_view, 1> insecure { "http://mirror.example.org/x" };
    bad.requires_ = {};
    bad.mirrors   = insecure;
    CHECK_FALSE(library.add_app(bad, content));
    const std::array<std::string_view, 1> secure { "https://mirror.example.org/x" };
    bad.mirrors = secure;
    CHECK(library.add_app(bad, content));
    // The same bytes under two apps are one file
    AppDraft again     = draft;
    again.version_code = 9;
    const auto added   = library.add_app(again, content);
    REQUIRE(added);
    CHECK(library.file(std::string(added->file.substr(added->file.rfind('/') + 1)), {})->has_value());
    CHECK_FALSE(library.file("f_none", {})->has_value());
}
