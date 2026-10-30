#include <doctest.h>

#include <array>
#include <optional>
#include <string>
#include <string_view>

#include "support.hpp"

using namespace lantern;
using lantern::test::spec_file;

TEST_CASE("schema: every example of the specification is read")
{
    const auto ok = [](auto read)
    {
        REQUIRE(read);
        CHECK(read->has_value());
    };
    ok(read_handshake(spec_file("examples/v1/handshake.json")));
    ok(read_discovery_reply(spec_file("examples/v1/discovery.json")));
    ok(read_apps_page(spec_file("examples/v1/apps.json")));
    ok(read_changes(spec_file("examples/v1/changes.json")));
    ok(read_sections(spec_file("examples/v1/sections.json")));
    ok(read_title(spec_file("examples/v1/title.json")));
    ok(read_titles(spec_file("examples/v1/titles.json")));
    ok(read_title_changes(spec_file("examples/v1/title-changes.json")));
    ok(read_homebrew(spec_file("examples/v1/homebrew.json")));
    ok(read_homebrew_page(spec_file("examples/v1/homebrew-page.json")));
    ok(read_saves(spec_file("examples/v1/saves.json")));
    ok(read_save(spec_file("examples/v1/save.json")));
    ok(read_cheat_sets(spec_file("examples/v1/cheats.json")));
    ok(read_cheat_set(spec_file("examples/v1/cheat.json")));
    ok(read_problem(spec_file("examples/v1/problem.json")));
}

TEST_CASE("schema: the handshake's fields")
{
    const auto read = read_handshake(spec_file("examples/v1/handshake.json"));
    REQUIRE(read);
    REQUIRE(*read);
    const Handshake& h = **read;
    CHECK(h.base == "/api/lantern");
    CHECK(h.versions.size() == 1);
    CHECK(h.versions[0] == 1);
    CHECK(h.features.library == 1U);
    REQUIRE(h.limits);
    CHECK(h.limits->page_size == 500U);
    CHECK(h.account.state == "active");
}

TEST_CASE("schema: a newer schema is absent, never an error")
{
    // save.schema-2: a document a later version writes
    const auto save = read_save(spec_file("examples/v1/invalid/save.schema-2.json"));
    REQUIRE(save);
    CHECK_FALSE(save->has_value());

    // Whatever its fields are, even ones of another type
    const auto page = read_apps_page(R"({"items":"not a list","schema":7,"next":3})");
    REQUIRE(page);
    CHECK_FALSE(page->has_value());

    // The same document at schema 1 is an error
    const auto broken = read_apps_page(R"({"items":"not a list","schema":1,"next":3})");
    REQUIRE_FALSE(broken);
    CHECK(broken.error().category() == Category::invalid_response);
}

TEST_CASE("schema: missing or malformed schema breaks SPEC.md 3.2")
{
    for (const char* text : { R"({"items":[],"next":null})", R"({"schema":0,"items":[],"next":null})",
             R"({"schema":"1","items":[],"next":null})", R"({"schema":1.5,"items":[],"next":null})",
             R"({"schema":-1,"items":[],"next":null})", R"({"schema":1,"schema":1,"items":[],"next":null})",
             R"([{"schema":1}])", "null" })
    {
        CAPTURE(text);
        const auto read = read_apps_page(text);
        REQUIRE_FALSE(read);
        CHECK(read.error().category() == Category::invalid_response);
    }
}

TEST_CASE("schema: unknown fields are skipped, wherever they are")
{
    const auto read = read_apps_page(R"({"x-example-shelf":{"deep":[1,{"a":null}]},"schema":1,"items":[
        {"id":"a_1","platform":"switch","title_id":"0100ABCD00010000","app_id":"0100ABCD00010000","type":"base",
         "version_code":0,"size":6000,"format":"nsp","file":"/f","future":[true],
         "sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"}],
        "total":1,"next":null,"later":"field"})");
    REQUIRE(read);
    REQUIRE(*read);
    REQUIRE((*read)->items.size() == 1);
    CHECK((*read)->items[0].id == "a_1");
    CHECK((*read)->items[0].sha256
        == *digest_from_hex("fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"));
    CHECK((*read)->next.empty());
    CHECK((*read)->total == 1U);
}

TEST_CASE("schema: required fields, types and forms")
{
    // The specification's invalid examples a reader refuses by itself
    for (const char* file : { "examples/v1/invalid/apps.no-sha256.json",
             "examples/v1/invalid/apps.text-version.json", "examples/v1/invalid/handshake.no-features.json",
             "examples/v1/invalid/handshake.no-platforms.json", "examples/v1/invalid/homebrew.no-sha256.json",
             "examples/v1/invalid/save.no-sha256.json", "examples/v1/invalid/apps.no-platform.json",
             "examples/v1/invalid/homebrew.arch-not-a-list.json",
             "examples/v1/invalid/homebrew.ram-as-text.json" })
    {
        CAPTURE(file);
        const std::string text = spec_file(file);
        REQUIRE_FALSE(text.empty());
        bool refused = false;
        if (std::string_view(file).find("/apps.") != std::string_view::npos)
            refused = !read_apps_page(text).has_value();
        else if (std::string_view(file).find("/handshake.") != std::string_view::npos)
            refused = !read_handshake(text).has_value();
        else if (std::string_view(file).find("/save.") != std::string_view::npos)
            refused = !read_save(text).has_value();
        else
        {
            // ram_mb as text: not refused by the reader (a value of
            // another form is a warning, SPEC.md 8.7), checked in
            // requires_tests.cpp
            const auto read = read_homebrew(text);
            refused         = !read.has_value() || std::string_view(file).ends_with("ram-as-text.json");
        }
        CHECK(refused);
    }
    // A SHA-256 in upper case, a key twice, an integer out of its range
    CHECK_FALSE(
        read_apps_page(R"({"schema":1,"items":[{"id":"a","platform":"switch","title_id":"t","app_id":"t",
        "type":"base","version_code":0,"size":1,"format":"nsp","file":"/f",
        "sha256":"FA17DE19989D9C203230B0689AC3BC22537D25F22013D02A104FBCFF494733D4"}],"next":null})"));
    CHECK_FALSE(read_apps_page(R"({"schema":1,"items":[],"items":[],"next":null})"));
    CHECK_FALSE(read_problem(R"({"schema":1,"status":200,"code":"internal"})"));
    CHECK_FALSE(read_apps_page(R"({"schema":1,"items":[],"next":null,"total":-1})"));
}

TEST_CASE("schema: a page holds 1000 items at most")
{
    std::string text = R"({"schema":1,"next":null,"items":[)";
    for (int i = 0; i < 1001; ++i)
    {
        text += i == 0 ? "" : ",";
        text
            += R"({"id":"a","platform":"switch","title_id":"t","app_id":"t","type":"base","version_code":0,"size":1,
            "format":"nsp","file":"/f","sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"})";
    }
    text += "]}";
    const auto read = read_apps_page(text);
    REQUIRE_FALSE(read);
    CHECK(read.error().category() == Category::limit);
}

TEST_CASE("schema: values a later version may add are read, not refused")
{
    // A kind, a genre, an assets value and a gpu name this version does
    // not know: kept as they are, for the client to read as § 8 says
    const auto read = read_homebrew(R"({"schema":1,"id":"org.example.ember-widget","platform":"switch",
        "kind":"widget","name":"Ember Widget","version":"1.0.0","build":100,"genres":["roguelite"],
        "requires":{"text":"Metal","gpu":["metal"],"min":{"kernel":"5.10","ram_mb":"lots"},"vram_mb":256},
        "package":{"format":"nro","file":"/f","size":1,"path":"/switch/org.example.ember-widget/org.example.ember-widget.nro",
        "sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4",
        "manifest_sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"}})");
    REQUIRE(read);
    REQUIRE(*read);
    const Homebrew& entry = **read;
    CHECK(entry.kind == "widget");
    CHECK(entry.genres[0] == "roguelite");
    REQUIRE(entry.requires_);
    REQUIRE(entry.requires_->min);
    CHECK(entry.requires_->min->members.size() == 2);
    CHECK(entry.requires_->min->members[1].second == "\"lots\"");
    REQUIRE(entry.requires_->extra.size() == 1);
    CHECK(entry.requires_->extra[0].first == "vram_mb");
    CHECK(entry.requires_->extra[0].second == "256");
}

TEST_CASE("schema: the documents a client sends")
{
    MissingRequest request;
    request.installed.emplace_back();
    request.installed.back().app_id       = "0100ABCD00010000";
    request.installed.back().version_code = 0;
    request.installed.emplace_back();
    request.installed.back().app_id       = "0100ABCD00010800";
    request.installed.back().version_code = 131072;
    request.want.emplace_back("update");
    request.want.emplace_back("dlc");
    String out;
    write_missing_request(request, out);
    CHECK(out
        == R"({"schema":1,"installed":[{"app_id":"0100ABCD00010000","version_code":0},{"app_id":"0100ABCD00010800","version_code":131072}],"want":["update","dlc"]})");

    HomebrewUpdatesRequest updates;
    updates.installed.emplace_back();
    updates.installed.back().id    = "org.example.frostline";
    updates.installed.back().build = 10300;
    String body;
    write_homebrew_updates_request(updates, body);
    CHECK(body == R"({"schema":1,"installed":[{"id":"org.example.frostline","build":10300}]})");
}

TEST_CASE("schema: rewriting keeps the keys it does not know")
{
    const std::string original
        = R"({"schema":1,"x-example":{"kept":[1,2]},"name":"Lea's Switch","note":"old"})";
    const std::array<Patch, 3> patches { { { "note", R"("Chapter 4")" }, { "name", std::nullopt },
        { "added", "42" } } };
    const auto rewritten = rewrite(original, 1, patches, {});
    REQUIRE(rewritten);
    REQUIRE(*rewritten);
    CHECK(**rewritten == R"({"schema":1,"x-example":{"kept":[1,2]},"note":"Chapter 4","added":42})");

    // A newer schema: never written back
    const auto newer = rewrite(R"({"schema":2,"note":"from a later version"})", 1, patches, {});
    REQUIRE(newer);
    CHECK_FALSE(newer->has_value());

    // Without schema: an error for a protocol document, schema 1 for an
    // app's file that predates it
    CHECK_FALSE(rewrite(R"({"note":"x"})", 1, patches, {}));
    const auto old_file = rewrite(R"({"note":"x"})", 1, patches, {}, MissingSchema::as_one);
    REQUIRE(old_file);
    CHECK(**old_file == R"({"note":"Chapter 4","added":42})");

    // A patch that is not JSON
    const std::array<Patch, 1> bad { { { "note", "not json" } } };
    CHECK_FALSE(rewrite(original, 1, bad, {}));
}

TEST_CASE("schema: decoding stays within the memory budget")
{
    const std::string text = spec_file("examples/v1/homebrew.json");
    DecodeOptions options;
    options.limits.max_memory = 256;
    const auto read           = read_homebrew(text, options);
    REQUIRE_FALSE(read);
    CHECK(read.error().category() == Category::memory);

    // Everything on the resource the app gives
    CountingResource counting;
    options.limits.max_memory = 1 << 20;
    options.memory            = &counting;
    {
        const auto ok = read_homebrew(text, options);
        REQUIRE(ok);
        CHECK(counting.current() > 0);
        CHECK(counting.peak() <= options.limits.max_memory + options.limits.max_string + 4096);
    }
    CHECK(counting.current() == 0);
}

TEST_CASE("schema: problem documents")
{
    const auto read = read_problem(spec_file("examples/v1/problem.json"));
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->code == "account_frozen");
    CHECK((*read)->status == 403U);
    // No code: § 12 requires one
    CHECK_FALSE(read_problem(spec_file("examples/v1/invalid/problem.no-code.json")));
}
