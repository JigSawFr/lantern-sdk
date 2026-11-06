// The library's other families on the server core (SPEC.md § 6.4, § 6.5,
// § 7): the changes and their `since` tokens, the sections, the titles one
// by one, many at once and by their changes, and the images they show. The
// core is called in memory; the conformance suite plays the same against the
// demo server.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lantern/lantern.hpp>

using namespace lantern;

namespace
{

constexpr std::string_view uid = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";

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

Title title_of(std::string_view platform, std::string_view id, std::string_view name)
{
    Title title;
    title.platform = platform;
    title.title_id = id;
    title.name     = name;
    return title;
}

AppDraft draft_of(std::string_view platform, std::string_view id, std::string_view name)
{
    AppDraft draft;
    draft.platform     = platform;
    draft.title_id     = id;
    draft.app_id       = id;
    draft.type         = "base";
    draft.version_code = 1;
    draft.name         = name;
    draft.format       = platform == "switch" ? "nsp" : "apk";
    return draft;
}

// Two switch games and an android one, a title for each, a shelf, a journal.
struct Fixture
{
    MemoryLibrary library { "/api/lantern" };
    FixedRandom random;
    FakeClock clock;
    ServerOptions options;
    std::optional<Server> server;
    String alpha;
    String zeta;
    String moth;

    explicit Fixture(bool journal = true)
    {
        if (journal)
            REQUIRE(library.keep_journal(5));
        const auto add = [&](std::string_view platform, std::string_view id, std::string_view name)
        {
            auto app = library.add_app(draft_of(platform, id, name), bytes(name));
            REQUIRE(app);
            return app->id;
        };
        alpha          = add("switch", "0100AA0000010000", "Alpha");
        zeta           = add("switch", "0100BB0000020000", "Zeta");
        moth           = add("android", "org.example.moth", "Moth");
        Title first    = title_of("switch", "0100AA0000010000", "Alpha");
        first.language = "en";
        first.summary  = "A fictional game.";
        first.genres   = { "puzzle" };
        REQUIRE(library.add_title(first));
        REQUIRE(library.add_title(title_of("switch", "0100BB0000020000", "Zeta")));
        REQUIRE(library.add_title(title_of("android", "org.example.moth", "Moth")));
        options.uid    = uid;
        options.name   = "Test shelf";
        options.scheme = "http";
        remake();
    }

    void remake()
    {
        auto made = Server::create(library, options, random, clock);
        REQUIRE(made);
        server.emplace(std::move(*made));
    }
};

ServerResponse get(
    const Fixture& f, std::string_view target, std::vector<std::pair<std::string, std::string>> headers = {})
{
    const auto parsed = parse_target(target);
    REQUIRE(parsed);
    std::vector<QueryParam> query;
    for (const auto& [name, value] : parsed->query)
        query.push_back({ name, value });
    std::vector<Header> sent;
    for (const auto& [name, value] : headers)
        sent.push_back({ name, value });
    ServerRequest request;
    request.method  = "GET";
    request.path    = parsed->path;
    request.query   = query;
    request.headers = sent;
    request.scheme  = "http";
    request.target  = target;
    return f.server->handle(request);
}

std::string_view header(const ServerResponse& response, std::string_view name)
{
    return response.headers.get(name).value_or(std::string_view {});
}

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

void refused(const ServerResponse& response, std::uint16_t status, std::string_view code)
{
    CHECK(response.status == status);
    CHECK(header(response, "Content-Type") == "application/problem+json");
    auto read = read_problem(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->code == code);
}

Changes changes_of(const ServerResponse& response)
{
    REQUIRE(response.status == 200);
    auto read = read_changes(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

TitleChanges title_changes_of(const ServerResponse& response)
{
    REQUIRE(response.status == 200);
    auto read = read_title_changes(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

Titles titles_of(const ServerResponse& response)
{
    REQUIRE(response.status == 200);
    auto read = read_titles(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

// A token in a query: its characters need no escape.
std::string since_of(const Fixture& f, const char* route)
{
    const std::string path = std::string("/api/lantern/v1/") + route;
    return std::string(changes_of(get(f, path)).since);
}

} // namespace

TEST_CASE("catalog: the handshake lists the families the library offers")
{
    Fixture f;
    auto read = read_handshake(get(f, "/api/lantern/v1").body);
    REQUIRE(read);
    REQUIRE(*read);
    const Handshake& hello = **read;
    CHECK(hello.features.library == 1);
    CHECK(hello.features.titles == 1);
    CHECK(hello.features.changes == 1);
    CHECK(hello.features.sections == 0); // no shelf yet
    CHECK(hello.features.homebrew == 0);

    REQUIRE(f.library.add_section("new", "New", {}));
    auto again = read_handshake(get(f, "/api/lantern/v1").body);
    REQUIRE(again);
    REQUIRE(*again);
    CHECK((*again)->features.sections == 1);

    // Without a journal, no changes; without titles, none
    MemoryLibrary bare;
    FixedRandom random;
    FakeClock clock;
    ServerOptions options;
    options.uid  = uid;
    options.name = "Bare";
    auto server  = Server::create(bare, options, random, clock);
    REQUIRE(server);
    ServerRequest request;
    request.method = "GET";
    request.path   = "/api/lantern/v1/changes";
    refused(server->handle(request), 404, "not_found");
    request.path = "/api/lantern/v1/sections";
    refused(server->handle(request), 404, "not_found");
    request.path = "/api/lantern/v1/titles/changes";
    refused(server->handle(request), 404, "not_found");
    request.path = "/api/lantern/v1/media/x.png";
    refused(server->handle(request), 404, "not_found");
}

TEST_CASE("catalog: changes give no app without a token, then what happened since it")
{
    Fixture f;
    const Changes first = changes_of(get(f, "/api/lantern/v1/changes"));
    CHECK(first.added.empty());
    CHECK(first.removed.empty());
    CHECK_FALSE(first.since.empty());

    const std::string token = std::string(first.since);
    const Changes nothing   = changes_of(get(f, "/api/lantern/v1/changes?since=" + token));
    CHECK(nothing.added.empty());
    CHECK(nothing.removed.empty());
    CHECK(nothing.since == first.since); // the same position, the same token

    auto fresh = f.library.add_app(draft_of("switch", "0100CC0000030000", "Gamma"), bytes("gamma"));
    REQUIRE(fresh);
    REQUIRE(f.library.remove_app(f.zeta));
    const Changes later = changes_of(get(f, "/api/lantern/v1/changes?since=" + token));
    REQUIRE(later.added.size() == 1);
    CHECK(later.added[0].id == fresh->id);
    CHECK(later.added[0].name == "Gamma");
    REQUIRE(later.removed.size() == 1);
    CHECK(later.removed[0] == f.zeta);
    CHECK(later.since != first.since);

    // The platform the client names narrows them
    const Changes android = changes_of(get(f, "/api/lantern/v1/changes?platform=android&since=" + token));
    CHECK(android.added.empty());
    CHECK(android.removed.empty());
    refused(get(f, "/api/lantern/v1/changes?platform=Not%20One&since=" + token), 400, "bad_request");

    // An app added and removed in the same stretch is nowhere
    auto brief = f.library.add_app(draft_of("switch", "0100DD0000040000", "Brief"), bytes("brief"));
    REQUIRE(brief);
    REQUIRE(f.library.remove_app(brief->id));
    const Changes after = changes_of(get(f, "/api/lantern/v1/changes?since=" + later.since));
    CHECK(after.added.empty());
    REQUIRE(after.removed.size() == 1);
    CHECK(after.removed[0] == brief->id);
}

TEST_CASE("catalog: a since token the server never gave is 400, one that is too old 410")
{
    Fixture f;
    refused(get(f, "/api/lantern/v1/changes?since=lantern-conformance-0123"), 400, "bad_request");
    refused(get(f, "/api/lantern/v1/changes?since=s_AAAA.AAAA"), 400, "bad_request");
    refused(get(f, "/api/lantern/v1/titles/changes?since=lantern-conformance-0123"), 400, "bad_request");

    // A token of the titles' changes is no token of the apps': the kinds differ
    const std::string titles_token
        = std::string(title_changes_of(get(f, "/api/lantern/v1/titles/changes")).since);
    refused(get(f, "/api/lantern/v1/changes?since=" + titles_token), 400, "bad_request");
    const std::string apps_token = since_of(f, "changes");
    refused(get(f, "/api/lantern/v1/titles/changes?since=" + apps_token), 400, "bad_request");
    // A token tampered with does not verify
    std::string tampered          = apps_token;
    tampered[tampered.size() - 2] = tampered[tampered.size() - 2] == 'A' ? 'B' : 'A';
    refused(get(f, "/api/lantern/v1/changes?since=" + tampered), 400, "bad_request");

    // The journal keeps 5 changes: three titles and three apps were made, so the start is gone
    const std::string recent = since_of(f, "changes");
    for (int i = 0; i < 6; ++i)
        REQUIRE(f.library.add_title(title_of("switch", "0100AA0000010000", "Alpha " + std::to_string(i))));
    CHECK(changes_of(get(f, "/api/lantern/v1/changes?since=" + since_of(f, "changes"))).added.empty());
    refused(get(f, "/api/lantern/v1/changes?since=" + recent), 410, "gone");

    // A token of another journal (another epoch) is too old as well
    Fixture other;
    const std::string foreign = since_of(other, "changes");
    refused(get(f, "/api/lantern/v1/changes?since=" + foreign), 410, "gone");
}

TEST_CASE("catalog: a title, by its id and the platform")
{
    Fixture f;
    auto read = read_title(get(f, "/api/lantern/v1/titles/0100AA0000010000").body);
    REQUIRE(read);
    REQUIRE(*read);
    const Title& title = **read;
    CHECK(title.platform == "switch");
    CHECK(title.name == "Alpha");
    CHECK(title.language == "en");
    CHECK(title.summary == "A fictional game.");
    REQUIRE(title.genres.size() == 1);
    CHECK(title.genres[0] == "puzzle");

    const ServerResponse again = get(f, "/api/lantern/v1/titles/0100AA0000010000");
    CHECK_FALSE(header(again, "ETag").empty());
    CHECK(get(f, "/api/lantern/v1/titles/0100AA0000010000",
              { { "If-None-Match", std::string(header(again, "ETag")) } })
              .status
        == 304);

    refused(get(f, "/api/lantern/v1/titles/0100FF0000050000"), 404, "not_found");
    refused(get(f, "/api/lantern/v1/titles/0100AA0000010000?platform=android"), 404, "not_found");
    CHECK(get(f, "/api/lantern/v1/titles/org.example.moth?platform=android").status == 200);

    // The same id on two platforms: the client names one
    REQUIRE(f.library.add_title(title_of("mystery", "0100AA0000010000", "Alpha (elsewhere)")));
    refused(get(f, "/api/lantern/v1/titles/0100AA0000010000"), 400, "bad_request");
    CHECK(get(f, "/api/lantern/v1/titles/0100AA0000010000?platform=switch").status == 200);
    // An id of the routes' own is no title, but a route of its own
    CHECK(get(f, "/api/lantern/v1/titles/changes").status == 200);
}

TEST_CASE("catalog: many titles at once, the known and the unknown")
{
    Fixture f;
    const Titles all = titles_of(get(f,
        "/api/lantern/v1/titles?ids=org.example.moth,0100BB0000020000,0100FF0000050000,0100AA0000010000,"
        "0100BB0000020000,,0100EE0000060000"));
    REQUIRE(all.titles.size() == 3);
    // By platform, then id
    CHECK(all.titles[0].platform == "android");
    CHECK(all.titles[1].title_id == "0100AA0000010000");
    CHECK(all.titles[2].title_id == "0100BB0000020000");
    // Every id once, in the order asked
    REQUIRE(all.unknown.size() == 2);
    CHECK(all.unknown[0] == "0100FF0000050000");
    CHECK(all.unknown[1] == "0100EE0000060000");

    // A platform narrows: the others' titles are unknown to it
    const Titles switch_only
        = titles_of(get(f, "/api/lantern/v1/titles?platform=switch&ids=org.example.moth,0100AA0000010000"));
    REQUIRE(switch_only.titles.size() == 1);
    CHECK(switch_only.titles[0].title_id == "0100AA0000010000");
    REQUIRE(switch_only.unknown.size() == 1);
    CHECK(switch_only.unknown[0] == "org.example.moth");

    // 100 at most, one at least, each a title id
    refused(get(f, "/api/lantern/v1/titles"), 400, "bad_request");
    refused(get(f, "/api/lantern/v1/titles?ids=,,"), 400, "bad_request");
    refused(get(f, "/api/lantern/v1/titles?ids=0100AA0000010000,not%20an%20id"), 400, "bad_request");
    std::string many = "/api/lantern/v1/titles?ids=";
    for (int i = 0; i < 100; ++i)
        many += (i == 0 ? "" : ",") + std::to_string(1000 + i);
    CHECK(titles_of(get(f, many)).unknown.size() == 100);
    refused(get(f, many + ",9999"), 400, "bad_request");
    // An id asked twice counts twice towards the limit, as it is read
    std::string twice = "/api/lantern/v1/titles?ids=";
    for (int i = 0; i < 101; ++i)
        twice += (i == 0 ? "" : ",") + std::string("1000");
    refused(get(f, twice), 400, "bad_request");
}

TEST_CASE("catalog: the titles' changes follow the same rules")
{
    Fixture f;
    const TitleChanges first = title_changes_of(get(f, "/api/lantern/v1/titles/changes"));
    CHECK(first.titles.empty());
    CHECK(first.removed.empty());
    CHECK_FALSE(first.more);
    const std::string token = std::string(first.since);

    Title changed = title_of("switch", "0100AA0000010000", "Alpha, renamed");
    REQUIRE(f.library.add_title(changed));
    REQUIRE(f.library.add_title(title_of("switch", "0100CC0000030000", "Gamma")));
    REQUIRE(f.library.remove_title("android", "org.example.moth"));
    REQUIRE(f.library.remove_title("switch", "0100BB0000020000"));
    CHECK_FALSE(f.library.remove_title("switch", "0100BB0000020000"));

    const TitleChanges later = title_changes_of(get(f, "/api/lantern/v1/titles/changes?since=" + token));
    REQUIRE(later.titles.size() == 2);
    CHECK(later.titles[0].title_id == "0100AA0000010000");
    CHECK(later.titles[0].name == "Alpha, renamed");
    CHECK(later.titles[1].title_id == "0100CC0000030000");
    REQUIRE(later.removed.size() == 2);
    CHECK(later.removed[0].platform == "android");
    CHECK(later.removed[1].title_id == "0100BB0000020000");
    CHECK(later.since != first.since);
    CHECK_FALSE(later.more);

    const TitleChanges switch_only
        = title_changes_of(get(f, "/api/lantern/v1/titles/changes?platform=switch&since=" + token));
    CHECK(switch_only.titles.size() == 2);
    REQUIRE(switch_only.removed.size() == 1);
    CHECK(switch_only.removed[0].platform == "switch");
}

TEST_CASE("catalog: titles without a journal give a token that no one can use")
{
    Fixture f(false);
    const TitleChanges first = title_changes_of(get(f, "/api/lantern/v1/titles/changes"));
    CHECK(first.titles.empty());
    CHECK_FALSE(first.since.empty());
    refused(get(f, "/api/lantern/v1/titles/changes?since=" + std::string(first.since)), 410, "gone");
    refused(get(f, "/api/lantern/v1/changes"), 404, "not_found");
    auto read = read_handshake(get(f, "/api/lantern/v1").body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->features.titles == 1);
    CHECK((*read)->features.changes == 0);
}

TEST_CASE("catalog: sections hold the apps a caller sees, in order, each once")
{
    Fixture f;
    const std::array<std::string_view, 4> mixed { f.zeta, f.alpha, "a_unknown", f.zeta };
    REQUIRE(f.library.add_section("picks", "Picks", mixed));
    const std::array<std::string_view, 1> phone { f.moth };
    REQUIRE(f.library.add_section("phone", "On the phone", phone));
    const std::array<std::string_view, 1> nothing { "a_gone" };
    REQUIRE(f.library.add_section("empty", "Nothing", nothing));

    auto read = read_sections(get(f, "/api/lantern/v1/sections").body);
    REQUIRE(read);
    REQUIRE(*read);
    const Sections& all = **read;
    REQUIRE(all.sections.size() == 2); // a shelf of nothing is left out
    CHECK(all.sections[0].id == "picks");
    CHECK(all.sections[0].title == "Picks");
    REQUIRE(all.sections[0].apps.size() == 2);
    CHECK(all.sections[0].apps[0] == f.zeta);
    CHECK(all.sections[0].apps[1] == f.alpha);

    auto android = read_sections(get(f, "/api/lantern/v1/sections?platform=android").body);
    REQUIRE(android);
    REQUIRE(*android);
    REQUIRE((*android)->sections.size() == 1);
    CHECK((*android)->sections[0].id == "phone");

    // Adding a shelf of the same id replaces it
    REQUIRE(f.library.add_section("phone", "Pocket", phone));
    auto renamed = read_sections(get(f, "/api/lantern/v1/sections?platform=android").body);
    REQUIRE(renamed);
    REQUIRE(*renamed);
    CHECK((*renamed)->sections[0].title == "Pocket");
    CHECK(f.library.remove_section("phone"));
    CHECK_FALSE(f.library.remove_section("phone"));
    refused(get(f, "/api/lantern/v1/sections?platform=Not%20One"), 400, "bad_request");
}

TEST_CASE("catalog: an image on this origin is served for good, and only if a title shows it")
{
    Fixture f;
    const std::string png = "\x89PNG fictional image";
    auto image            = f.library.add_media(bytes(png), "png");
    REQUIRE(image);
    REQUIRE(image->sha256);
    CHECK(image->url.starts_with("/api/lantern/v1/media/"));
    CHECK(image->url.ends_with(".png"));

    // Nothing shows it yet
    refused(get(f, image->url), 404, "not_found");

    Title shown = title_of("switch", "0100AA0000010000", "Alpha");
    shown.icon  = *image;
    shown.icon->width.emplace(1);
    shown.icon->height.emplace(1);
    shown.banner.emplace();
    shown.banner->url      = "https://images.example.org/alpha.jpg";
    shown.banner->external = true;
    REQUIRE(f.library.add_title(shown));

    const ServerResponse served = get(f, image->url);
    CHECK(served.status == 200);
    CHECK(body_of(served) == png);
    CHECK(header(served, "Content-Type") == "image/png");
    CHECK(header(served, "Cache-Control") == "public, max-age=31536000, immutable");
    CHECK(header(served, "Content-Length") == std::to_string(png.size()));
    CHECK(get(f, image->url, { { "Authorization", "Bearer et_x" } }).status == 401);

    // The title carries it as the server wrote it
    auto read = read_title(get(f, "/api/lantern/v1/titles/0100AA0000010000").body);
    REQUIRE(read);
    REQUIRE(*read);
    REQUIRE((*read)->icon);
    CHECK((*read)->icon->url == image->url);
    CHECK((*read)->icon->sha256 == image->sha256);
    CHECK((*read)->icon->width == 1);
    REQUIRE((*read)->banner);
    CHECK((*read)->banner->external == true);

    const ServerResponse ranged = get(f, image->url, { { "Range", "bytes=1-3" } });
    CHECK(ranged.status == 206);
    CHECK(body_of(ranged) == png.substr(1, 3));
    refused(get(f, "/api/lantern/v1/media/" + std::string(65, 'a') + ".png"), 404, "not_found");

    // Not an image type, and the same bytes give the same address
    CHECK_FALSE(f.library.add_media(bytes(png), "svg"));
    auto same = f.library.add_media(bytes(png), "png");
    REQUIRE(same);
    CHECK(same->url == image->url);
}

TEST_CASE("catalog: a MemoryLibrary refuses a title, a section or a journal that breaks the protocol")
{
    MemoryLibrary library;
    const auto refuses = [&](auto change)
    {
        Title title = title_of("switch", "0100AA0000010000", "Alpha");
        change(title);
        return !library.add_title(title);
    };
    CHECK_FALSE(refuses([](Title&) {}));
    CHECK(refuses([](Title& t) { t.platform = "web"; }));
    CHECK(refuses([](Title& t) { t.platform = "Not One"; }));
    CHECK(refuses([](Title& t) { t.title_id = "not a switch id"; }));
    CHECK(refuses([](Title& t) { t.name = ""; }));
    CHECK(refuses([](Title& t) { t.name = std::string(513, 'a'); }));
    CHECK(refuses([](Title& t) { t.summary = "Texts say their language."; }));
    CHECK(refuses([](Title& t) { t.release = "March 2025"; }));
    CHECK(refuses([](Title& t) { t.updated = "2026-10-10"; }));
    CHECK(refuses([](Title& t) { t.atlas = "900001"; }));
    CHECK(refuses([](Title& t) { t.genres = { "puzzle", "puzzle" }; }));
    CHECK(refuses([](Title& t) { t.genres = { "no such genre" }; }));
    CHECK(refuses([](Title& t) { t.tags.assign(33, "tag"); }));
    CHECK(refuses([](Title& t) { t.ratings.emplace_back(); }));
    CHECK(refuses(
        [](Title& t)
        {
            t.icon.emplace();
            t.icon->url = "https://images.example.org/a.png"; // elsewhere, not marked external
        }));
    CHECK(refuses(
        [](Title& t)
        {
            t.icon.emplace();
            t.icon->url      = "/media/a.png";
            t.icon->external = true; // marked external, but a path
        }));
    CHECK(refuses(
        [](Title& t)
        {
            t.video.emplace();
            t.video->url = "https://video.example.org/a"; // a video is always external
        }));
    CHECK(refuses([](Title& t) { t.screenshots.assign(17, Image {}); }));

    CHECK_FALSE(library.add_section("", "Nameless", {}));
    CHECK_FALSE(library.add_section(std::string(513, 'a'), "Long", {}));
    CHECK_FALSE(library.keep_journal(0));
    CHECK_FALSE(library.keep_journal(1'000'001));
    CHECK(library.journal() == nullptr);
    CHECK(library.keep_journal(10));
    CHECK(library.journal() != nullptr);
    CHECK(library.platforms(Allocator {}).value().empty() == false); // the title's platform
}
