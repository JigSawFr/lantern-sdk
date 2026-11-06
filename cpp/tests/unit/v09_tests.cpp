// Draft 0.9: an app's `requires` and `includes`, the format filter, and
// `formats` and `satisfies` of what is missing, against
// vectors/app-requires.json; and the variant a client prefers (Annex B.15).
#include <doctest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "support.hpp"

using namespace lantern;
using lantern::test::Answer;
using lantern::test::FakeTransport;
using lantern::test::Recorded;
using lantern::test::spec_file;

namespace
{

json::Document vectors()
{
    const std::string text = spec_file("vectors/app-requires.json");
    REQUIRE(!text.empty());
    static std::deque<std::string> keep; // the DOM's views live as long as the text, which never moves
    keep.push_back(text);
    auto parsed = json::parse(keep.back());
    REQUIRE(parsed);
    return std::move(*parsed);
}

std::string quoted(std::string_view text)
{
    return "\"" + std::string(text) + "\""; // the vectors' words need no escape
}

// A vector's JSON, written again; an app gets the `sha256` and `file` that the vectors leave out.
std::string render(const json::Value& value, bool app = false)
{
    std::string out;
    if (value.is_string())
        return quoted(value.text());
    if (value.is_number())
        return std::string(value.text());
    if (value.is_array())
    {
        out = "[";
        for (const json::Value& item : value.items())
            out += (out.size() > 1 ? "," : "") + render(item, false);
        return out + "]";
    }
    out = "{";
    for (const json::Member& member : value.members())
        out += (out.size() > 1 ? "," : "") + quoted(member.key) + ":" + render(member.value);
    if (app)
        out += ",\"sha256\":\"" + std::string(64, '0') + "\",\"file\":\"v1/blobs/sha256/"
            + std::string(64, '0') + "\"";
    return out + "}";
}

std::string page_of(const json::Value& apps)
{
    std::string items;
    for (const json::Value& app : apps.items())
        items += (items.empty() ? "" : ",") + render(app, true);
    return R"({"schema":1,"items":[)" + items + R"(],"total":)" + std::to_string(apps.items().size())
        + R"(,"next":null})";
}

std::vector<App> apps_of(const std::string& text)
{
    auto page = read_apps_page(text);
    if (!page)
        MESSAGE(page.error().detail());
    REQUIRE(page);
    REQUIRE(*page);
    return { (*page)->items.begin(), (*page)->items.end() };
}

std::vector<App> apps_of(const json::Value& apps)
{
    return apps_of(page_of(apps));
}

std::vector<std::string_view> words_of(const json::Value* list)
{
    std::vector<std::string_view> out;
    if (list != nullptr)
    {
        for (const json::Value& word : list->items())
            out.push_back(word.text());
    }
    return out;
}

constexpr std::string_view handshake_json = R"({"schema":1,"uid":"6f1c2a8e-0000-4000-8000-000000000001",
    "name":"Living room shelf","base":"/api/lantern","versions":[1],"platforms":["switch"],
    "account":{"state":"active","scopes":["library"]},
    "features":{"library":2,"titles":0,"changes":0,"sections":0,"homebrew":0,"saves":0,"cheats":0,"requests":0,
                "pairing":0}})";

Answer ok_json(std::string_view body)
{
    Answer a;
    a.body = std::string(body);
    return a;
}

class MemoryFiles final : public StaticFiles
{
  public:
    std::map<std::string, std::string> files;
    Result<void> read(std::string_view path, std::uint64_t offset, DownloadSink& sink) override
    {
        const auto found = files.find(std::string(path));
        if (found == files.end())
            return std::unexpected(Error::from_status(404));
        const std::string_view rest
            = std::string_view(found->second).substr(static_cast<std::size_t>(offset));
        return sink.write(std::as_bytes(std::span(rest.data(), rest.size())));
    }
};

} // namespace

TEST_CASE("variants: the vectors' install decisions, and how many reasons they give")
{
    const auto doc = vectors();
    for (const json::Value& v : doc.root().find("install")->items())
    {
        INFO(v.find("name")->text());
        const auto apps = apps_of(
            R"({"schema":1,"items":[)" + render(*v.find("app"), true) + R"(],"total":1,"next":null})");
        const auto installed = apps_of(*v.find("installed"));
        REQUIRE(apps.size() == 1);
        const auto formats   = words_of(v.find("formats"));
        const auto satisfies = words_of(v.find("satisfies"));
        const auto decision  = install_decision(apps[0], formats, satisfies, installed);
        const bool expected  = v.find("decision")->text() == "install";
        CHECK((decision.verdict == Install::install) == expected);
        CHECK(decision.reasons.size() == *v.find("reasons")->to_u64());
        CHECK(included(apps[0], installed)
            == (decision.verdict == Install::unavailable && decision.reasons.size() == 1
                && decision.reasons[0] == "already included by an installed app"));
    }
}

TEST_CASE("variants: reasons say the format, the token and the update already inside")
{
    const auto doc  = vectors();
    const auto apps = apps_of(*doc.root().find("variants")->find("apps"));
    const std::vector<std::string_view> formats { "nsp" };
    const auto decision = install_decision(apps[0], formats, {}); // a_big: nsz
    REQUIRE(decision.reasons.size() == 1);
    CHECK(decision.reasons[0] == "format 'nsz'");
    const std::vector<std::string_view> both { "nsp", "nsz" };
    const auto lacking = install_decision(apps[1], both, {}); // a_req: sigpatch
    REQUIRE(lacking.verdict == Install::unavailable);
    REQUIRE(lacking.reasons.size() == 1);
    CHECK(lacking.reasons[0] == "requires 'sigpatch'");
    CHECK(install_decision(apps[1], both, std::vector<std::string_view> { "sigpatch" }).verdict
        == Install::install);
}

TEST_CASE(
    "variants: the preferred variant is the one with the fewest requires, the smallest size, the smaller id")
{
    const auto doc  = vectors();
    const auto& set = *doc.root().find("variants");
    const auto apps = apps_of(*set.find("apps"));
    const App* best = prefer_variant(apps);
    REQUIRE(best != nullptr);
    CHECK(best->id == set.find("preferred")->text());
    // The order of the list does not matter
    std::vector<App> reversed(apps.rbegin(), apps.rend());
    const App* again = prefer_variant(reversed);
    REQUIRE(again != nullptr);
    CHECK(again->id == best->id);
    CHECK(prefer_variant(std::span<const App> {}) == nullptr);
}

TEST_CASE(
    "static libraries: what is missing, with the formats and tokens of the device, and the versions included")
{
    const auto doc = vectors();
    MemoryFiles files;
    files.files["lantern.json"]
        = R"({"schema":1,"uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14","name":"Lea's library",
        "base":".","versions":[1],"platforms":["switch"],"language":"en",
        "account":{"state":"anonymous","scopes":["library"]},
        "features":{"library":1,"titles":0,"homebrew":0,"cheats":0,"changes":0,"sections":0,"saves":0,"encrypted_saves":0,
                    "requests":0,"pairing":0,"signatures":0,"admin":0,"events":0,"peers":0,"sync":0},
        "limits":{"page_size":10},"static":{"generated":"2026-10-30T18:00:00Z","page_size":10}})";
    files.files["v1/apps/switch/pages/1.json"] = page_of(*doc.root().find("library"));
    auto opened                                = StaticLibrary::open(files);
    REQUIRE(opened);
    REQUIRE(*opened);
    StaticLibrary& library = **opened;

    for (const json::Value& v : doc.root().find("missing")->items())
    {
        INFO(v.find("name")->text());
        MissingRequest request;
        for (const json::Value& item : v.find("installed")->items())
        {
            InstalledApp installed;
            installed.app_id       = item.find("app_id")->text();
            installed.version_code = *item.find("version_code")->to_u64();
            request.installed.push_back(installed);
        }
        for (const json::Value& want : v.find("want")->items())
            request.want.emplace_back(want.text());
        if (const json::Value* formats = v.find("formats"))
        {
            auto& list = request.formats.emplace();
            for (const json::Value& word : formats->items())
                list.emplace_back(word.text());
        }
        if (const json::Value* satisfies = v.find("satisfies"))
        {
            auto& list = request.satisfies.emplace();
            for (const json::Value& word : satisfies->items())
                list.emplace_back(word.text());
        }
        const auto missing = library.missing("switch", request);
        REQUIRE(missing);
        std::vector<std::string> got;
        for (const App& app : *missing)
            got.emplace_back(app.id);
        std::vector<std::string> expected;
        for (const json::Value& id : v.find("missing")->items())
            expected.emplace_back(id.text());
        std::ranges::sort(got);
        std::ranges::sort(expected);
        CHECK(got == expected);
    }
}

TEST_CASE("client: the format filter of the listing, and formats and satisfies of the request, an empty list "
          "included")
{
    FakeTransport transport;
    transport.respond = [](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        return ok_json(spec_file("examples/v1/apps.json"));
    };
    ClientConfig config;
    config.origin     = "https://shelf.example.org";
    config.user_agent = "LanternTests/0.9";
    config.platform   = "switch";
    auto client       = Client::create(transport, config);
    REQUIRE(client);
    REQUIRE(client->handshake());
    AppsQuery query;
    query.format = "nsz";
    REQUIRE(client->apps(query));
    CHECK(transport.requests.back().url.ends_with("/v1/apps?format=nsz"));

    MissingRequest request;
    request.want.emplace_back("update");
    REQUIRE(client->missing(request));
    CHECK(transport.requests.back().body.find("formats") == std::string::npos);
    request.formats.emplace(); // present and empty: leaves out every app
    request.satisfies.emplace().emplace_back("fs-compression");
    REQUIRE(client->missing(request));
    const std::string& body = transport.requests.back().body;
    CHECK(body.find(R"("formats":[])") != std::string::npos);
    CHECK(body.find(R"("satisfies":["fs-compression"])") != std::string::npos);
}
