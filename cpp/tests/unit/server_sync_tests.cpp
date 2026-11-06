// The server core's sync and grants for peers (include/lantern/server.hpp,
// sync_store.hpp; SPEC.md § 19.3, § 20): the overview, the merge rule, the
// generation, If-Match, a device's own item of `installed`, the limit, the
// revisions read after, erasing, the event `sync`, and an account deleted
// whole. The core is called in memory, with no socket; the conformance suite
// plays the same against the demo server.
#include <doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
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

constexpr std::string_view uid       = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";
constexpr std::int64_t start         = 1'793'000'000;
constexpr std::string_view base      = "/api/lantern/v1";
constexpr std::string_view root      = "et_root-0123456789abcdef0123456789abcdef";
constexpr std::string_view lea       = "et_lea-0123456789abcdef0123456789abcdef";
constexpr std::string_view lea2      = "et_lea2-0123456789abcdef0123456789abcde";
constexpr std::string_view kim       = "et_kim-0123456789abcdef0123456789abcdef";
constexpr std::string_view read_only = "et_read-0123456789abcdef0123456789abcde";
constexpr std::string_view plain     = "et_plain-0123456789abcdef0123456789abc";
constexpr std::string_view gentle    = "0100AA0000010000";
constexpr std::string_view wished    = "0100BB0000020000";
constexpr std::string_view wished2   = "0100CC0000030000";

class CountingRandom final : public RandomSource
{
  public:
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        for (std::size_t at = 0; at < out.size(); at += 32)
        {
            const std::string seed = "sync-test-random:" + std::to_string(counter_++);
            const Digest block     = Sha256::of(std::string_view(seed));
            for (std::size_t i = 0; i < 32 && at + i < out.size(); ++i)
                out[at + i] = block[i];
        }
        return {};
    }

  private:
    std::uint64_t counter_ = 0;
};

class FakeClock final : public Clock
{
  public:
    std::int64_t now = start;
    std::int64_t unix_seconds() override { return now; }
};

std::vector<std::byte> bytes(std::string_view text)
{
    const auto view = std::as_bytes(std::span(text.data(), text.size()));
    return { view.begin(), view.end() };
}

AppDraft draft_of(std::string_view id, std::string_view name)
{
    AppDraft draft;
    draft.platform     = "switch";
    draft.title_id     = id;
    draft.app_id       = id;
    draft.type         = "base";
    draft.version_code = 1;
    draft.name         = name;
    draft.format       = "nsp";
    return draft;
}

// The first string under `key` in a JSON text written without spaces; empty when there is none.
std::string text_of(std::string_view json, std::string_view key)
{
    const std::string needle = "\"" + std::string(key) + "\":\"";
    const std::size_t at     = json.find(needle);
    if (at == std::string_view::npos)
        return {};
    const std::size_t from = at + needle.size();
    return std::string(json.substr(from, json.find('"', from) - from));
}

// The first whole number under `key`.
std::uint64_t number_of(std::string_view json, std::string_view key)
{
    const std::string needle = "\"" + std::string(key) + "\":";
    const std::size_t at     = json.find(needle);
    REQUIRE(at != std::string_view::npos);
    std::uint64_t value = 0;
    for (std::size_t i = at + needle.size(); i < json.size() && json[i] >= '0' && json[i] <= '9'; ++i)
        value = value * 10 + static_cast<std::uint64_t>(json[i] - '0');
    return value;
}

// A sync time, `offset` milliseconds after the clock's start.
std::string at(std::int64_t offset)
{
    String text;
    format_sync_time(start * 1000 + offset, text);
    return std::string(text);
}

struct Call
{
    std::string method = "GET";
    std::string target;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

struct Fixture
{
    MemoryLibrary library { "/api/lantern" };
    CountingRandom random;
    FakeClock clock;
    MemoryAccountStore store;
    MemorySyncStore sync;
    ServerOptions options;
    std::optional<Server> server;

    explicit Fixture(std::uint32_t limit = 100, std::int64_t retention = 30 * 86400, bool offered = true,
        bool peers = true, bool events = false)
        : sync(random, limit, retention)
    {
        constexpr std::array<std::string_view, 6> all { "library", "saves", "requests", "admin", "sync.read",
            "sync.write" };
        constexpr std::array<std::string_view, 3> member { "library", "sync.read", "sync.write" };
        constexpr std::array<std::string_view, 2> reading { "library", "sync.read" };
        constexpr std::array<std::string_view, 1> writing { "sync.write" };
        constexpr std::array<std::string_view, 1> only_library { "library" };
        REQUIRE(store.add_account("root", all, false, start));
        REQUIRE(store.add_account("lea", member, false, start));
        REQUIRE(store.add_account("kim", member, false, start));
        REQUIRE(store.add_account("reader", reading, false, start));
        REQUIRE(store.add_account("writer", writing, false, start));
        REQUIRE(store.add_account("plain", only_library, false, start));
        REQUIRE(store.add_token(root, "root", "Root's console", all, std::nullopt, start));
        REQUIRE(store.add_token(lea, "lea", "Lea's console", member, std::nullopt, start));
        REQUIRE(store.add_token(lea2, "lea", "Lea's tablet", member, std::nullopt, start));
        REQUIRE(store.add_token(kim, "kim", "Kim's console", member, std::nullopt, start));
        REQUIRE(store.add_token(read_only, "reader", "A tablet", reading, std::nullopt, start));
        REQUIRE(store.add_token(plain, "plain", "A phone", only_library, std::nullopt, start));
        REQUIRE(library.add_app(draft_of(gentle, "Gentle"), bytes("gentle")));
        options.uid      = uid;
        options.name     = "Test shelf";
        options.scheme   = "http";
        options.accounts = &store;
        options.events   = events;
        if (offered)
            options.sync = &sync;
        if (peers)
            options.grant_seed = Sha256::of(std::string_view("a grant key for the tests"));
        remake();
    }

    void remake()
    {
        server.reset();
        auto made = Server::create(library, options, random, clock);
        REQUIRE(made);
        server.emplace(std::move(*made));
    }

    [[nodiscard]] ServerResponse go(Call call, std::string_view token) const
    {
        call.target = std::string(base) + call.target;
        call.headers.emplace_back("Host", "shelf.example.org");
        if (!token.empty())
            call.headers.emplace_back("Authorization", "Bearer " + std::string(token));
        call.headers.emplace_back("Lantern-Platform", "switch");
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
        request.scheme  = "http";
        request.target  = call.target;
        request.remote  = "192.0.2.10";
        return server->handle(request);
    }

    [[nodiscard]] ServerResponse get(std::string route, std::string_view token = lea) const
    {
        Call call;
        call.target = std::move(route);
        return go(std::move(call), token);
    }

    [[nodiscard]] ServerResponse send(std::string method, std::string route, std::string body = {},
        std::string_view token = lea, std::vector<std::pair<std::string, std::string>> headers = {}) const
    {
        Call call;
        call.method  = std::move(method);
        call.target  = std::move(route);
        call.body    = std::move(body);
        call.headers = std::move(headers);
        if (!call.body.empty())
            call.headers.emplace_back("Content-Type", "application/json");
        return go(std::move(call), token);
    }

    [[nodiscard]] std::string generation(std::string_view token = lea) const
    {
        return text_of(get("/sync", token).body, "generation");
    }

    // PATCH the collection with `items` (a JSON array's members), of the generation read, or `given`.
    [[nodiscard]] ServerResponse patch(std::string_view collection, std::string_view items,
        std::string_view token = lea, std::string given = {},
        std::vector<std::pair<std::string, std::string>> headers = {}) const
    {
        const std::string gen = given.empty() ? generation(token) : given;
        return send("PATCH", "/sync/" + std::string(collection),
            R"({"schema":1,"generation":")" + gen + R"(","items":[)" + std::string(items) + "]}", token,
            std::move(headers));
    }

    // A wish's item, `offset` milliseconds after the start.
    [[nodiscard]] static std::string wish(
        std::string_view title_id, std::int64_t offset, std::string_view note = "x")
    {
        return R"({"key":"switch/)" + std::string(title_id) + R"(","value":{"platform":"switch","title_id":")"
            + std::string(title_id) + R"(","note":")" + std::string(note) + R"("},"updated":")" + at(offset)
            + R"("})";
    }

    [[nodiscard]] static std::string unwish(std::string_view title_id, std::int64_t offset)
    {
        return R"({"key":"switch/)" + std::string(title_id) + R"(","deleted":true,"updated":")" + at(offset)
            + R"("})";
    }
};

void refused(const ServerResponse& response, std::uint16_t status, std::string_view code)
{
    CHECK(response.status == status);
    const auto read = read_problem(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->code == code);
}

} // namespace

TEST_CASE("sync: offered only with a store, to the scopes sync.read and sync.write")
{
    const Fixture off(100, 30 * 86400, false);
    CHECK(off.get("/").body.contains(R"("sync":0)"));
    refused(off.get("/sync"), 404, "not_found");
    refused(off.get("/sync/wishes"), 404, "not_found");

    const Fixture f;
    const ServerResponse hello = f.get("/");
    CHECK(hello.body.contains(R"("sync":1)"));
    CHECK(hello.body.contains(R"("sync_items":100)"));
    // A token without sync.read is not told of the family, and may not use it
    CHECK(f.get("/", plain).body.contains(R"("sync":0)"));
    refused(f.get("/sync", plain), 403, "forbidden");
    refused(f.get("/sync", ""), 401, "unauthorized");
    // Writing is another scope: sync.read alone reads, and does not write
    CHECK(f.get("/sync", read_only).status == 200);
    refused(f.send("DELETE", "/sync", {}, read_only), 403, "forbidden");
    refused(f.patch("wishes", Fixture::wish(wished, 0), read_only, "g_x"), 403, "forbidden");
    // The routes take their methods only
    refused(f.send("POST", "/sync", "{}"), 405, "bad_request");
    refused(f.send("PUT", "/sync/wishes", "{}"), 405, "bad_request");
    refused(f.get("/sync/stars"), 404, "not_found");
    refused(f.send("DELETE", "/sync/stars"), 404, "not_found");
}

TEST_CASE("sync: the overview gives the generation, the collections and the device's own id")
{
    const Fixture f;
    const ServerResponse first = f.get("/sync");
    REQUIRE(first.status == 200);
    CHECK(text_of(first.body, "generation").starts_with("g_"));
    CHECK(first.body.contains(R"("wishes":{"rev":0,"items":0})"));
    CHECK(first.body.contains(R"("installed":{"rev":0,"items":0})"));
    const std::string device = text_of(first.body, "device");
    CHECK(device.starts_with("d_"));
    CHECK(device.size() == 18);
    // Each device of the account has its own id; the generation is the account's
    CHECK(text_of(f.get("/sync", lea2).body, "device") != device);
    CHECK(f.generation(lea2) == text_of(first.body, "generation"));
    // Another account has its own data
    CHECK(f.generation(kim) != text_of(first.body, "generation"));
}

TEST_CASE("sync: items merged by the rule, revisions, reading whole and after a revision, pages")
{
    const Fixture f;
    const std::string gen = f.generation();
    // A new item is kept, with the next revision
    const ServerResponse first = f.patch("wishes", Fixture::wish(wished, -2000));
    REQUIRE(first.status == 200);
    CHECK(text_of(first.body, "generation") == gen);
    CHECK(number_of(first.body, "rev") == 1);
    CHECK(first.body.contains(R"("collection":"wishes")"));
    CHECK(first.body.contains(R"("rev":1})"));
    CHECK(first.body.contains(at(-2000)));

    // An older item does not replace it, and is answered as the server has it
    const ServerResponse older = f.patch("wishes", Fixture::wish(wished, -5000, "older"));
    REQUIRE(older.status == 200);
    CHECK(older.body.contains(R"("note":"x")"));
    CHECK_FALSE(older.body.contains("older"));
    CHECK(number_of(older.body, "rev") == 1);
    // A later one does, with the next revision
    const ServerResponse later = f.patch("wishes", Fixture::wish(wished, -1000, "later"));
    CHECK(later.body.contains(R"("note":"later")"));
    CHECK(number_of(later.body, "rev") == 2);
    // On the same time: the greater canonical JSON, then a deletion
    const ServerResponse greater = f.patch("wishes", Fixture::wish(wished, -1000, "zzz"));
    CHECK(greater.body.contains(R"("note":"zzz")"));
    const ServerResponse lesser = f.patch("wishes", Fixture::wish(wished, -1000, "aaa"));
    CHECK(lesser.body.contains(R"("note":"zzz")"));
    CHECK(number_of(lesser.body, "rev") == 3);
    const ServerResponse deleted = f.patch("wishes", Fixture::unwish(wished, -1000));
    CHECK(deleted.body.contains(R"("deleted":true)"));
    CHECK(number_of(deleted.body, "rev") == 4);
    // The same item again changes nothing: the rev stays
    CHECK(number_of(f.patch("wishes", Fixture::unwish(wished, -1000)).body, "rev") == 4);

    // Two items at once, each answered as kept
    const ServerResponse both
        = f.patch("wishes", Fixture::wish(wished2, 0) + "," + Fixture::wish(gentle, 0, "kept"));
    REQUIRE(both.status == 200);
    CHECK(number_of(both.body, "rev") == 6);

    // Whole: no deletion; the overview counts the live ones
    const ServerResponse whole = f.get("/sync/wishes");
    REQUIRE(whole.status == 200);
    CHECK(whole.body.contains(wished2));
    CHECK(whole.body.contains(gentle));
    CHECK_FALSE(whole.body.contains(wished));
    CHECK(whole.body.contains(R"("next":null)"));
    CHECK(f.get("/sync").body.contains(R"("wishes":{"rev":6,"items":2})"));
    // After a revision: every item changed since, deletions included
    const ServerResponse since = f.get("/sync/wishes?since=3");
    CHECK(since.body.contains(R"("deleted":true)"));
    CHECK(since.body.contains(gentle));
    CHECK_FALSE(f.get("/sync/wishes?since=4").body.contains(R"("deleted":true)"));
    CHECK(f.get("/sync/wishes?since=6").body.contains(R"("items":[])"));
    // A revision never given, or not a number
    refused(f.get("/sync/wishes?since=7"), 400, "bad_request");
    refused(f.get("/sync/wishes?since=-1"), 400, "bad_request");

    // Pages: one item at a time, the cursor of one listing is no other's
    const ServerResponse page = f.get("/sync/wishes?page_size=1");
    REQUIRE(page.status == 200);
    const std::string cursor = text_of(page.body, "next");
    REQUIRE_FALSE(cursor.empty());
    const ServerResponse rest = f.get("/sync/wishes?page_size=1&cursor=" + cursor);
    CHECK(rest.status == 200);
    CHECK(rest.body.contains(R"("next":null)"));
    CHECK_FALSE(rest.body.contains(text_of(page.body, "key")));
    refused(f.get("/sync/wishes?since=3&page_size=1&cursor=" + cursor), 400, "bad_request");
    // Another account sees none of it
    CHECK(f.get("/sync/wishes", kim).body.contains(R"("items":[])"));
}

TEST_CASE("sync: a date far ahead is the server's time (L-20.4-2)")
{
    const Fixture f;
    const ServerResponse r = f.patch("wishes",
        R"({"key":"switch/0100BB0000020000","value":{"platform":"switch","title_id":"0100BB0000020000"},)"
        R"("updated":"2100-01-01T00:00:00.000Z"})");
    REQUIRE(r.status == 200);
    CHECK(text_of(r.body, "updated") == at(0));
    // So a later deletion still wins
    const ServerResponse gone = f.patch("wishes", Fixture::unwish(wished, 1000));
    CHECK(gone.body.contains(R"("deleted":true)"));
}

TEST_CASE("sync: the generation, If-Match and the limit of items")
{
    const Fixture f(2);
    const std::string gen = f.generation();
    REQUIRE(f.patch("wishes", Fixture::wish(wished, 0)).status == 200);
    // Another generation: 409, nothing written
    refused(f.patch("wishes", Fixture::wish(wished2, 0), lea, "g_other"), 409, "conflict");
    CHECK(f.get("/sync").body.contains(R"("wishes":{"rev":1,"items":1})"));
    // If-Match: the collection's as a read gave it, else 412 and nothing changed
    const std::string current = "\"" + gen + "-1\"";
    const ServerResponse stale
        = f.patch("wishes", Fixture::wish(wished2, 0), lea, {}, { { "If-Match", "\"" + gen + "-0\"" } });
    refused(stale, 412, "precondition_failed");
    CHECK(f.get("/sync").body.contains(R"("wishes":{"rev":1,"items":1})"));
    CHECK(f.patch("wishes", Fixture::wish(wished2, 0), lea, {}, { { "If-Match", current } }).status == 200);
    // The collection holds two items here: a third is 413, a change to a held one is not
    refused(f.patch("wishes", Fixture::wish(gentle, 0)), 413, "too_large");
    CHECK(f.patch("wishes", Fixture::wish(wished2, 100, "again")).status == 200);
    // A deletion is an item too, kept until it is old enough to be dropped
    refused(f.patch("wishes", Fixture::unwish(gentle, 0)), 413, "too_large");
}

TEST_CASE("sync: a device writes its own item of installed only, items of the form of their collection")
{
    const Fixture f;
    const std::string device = text_of(f.get("/sync").body, "device");
    const std::string value  = R"("value":{"device":"Lea's Switch","platform":"switch",)"
                               R"("apps":[{"app_id":"0100AA0000010000","version_code":1}],"homebrew":[]})";
    const auto item          = [&](std::string_view key)
    { return R"({"key":")" + std::string(key) + R"(",)" + value + R"(,"updated":")" + at(0) + R"("})"; };
    const ServerResponse own = f.patch("installed", item(device));
    REQUIRE(own.status == 200);
    CHECK(own.body.contains(device));
    CHECK(f.get("/sync").body.contains(R"("installed":{"rev":1,"items":1})"));
    // Another device of the same account reads it, and may not write it
    CHECK(f.get("/sync/installed", lea2).body.contains(device));
    refused(f.patch("installed", item(device), lea2), 403, "forbidden");
    refused(f.patch("installed", item("d_0000000000000000")), 403, "forbidden");
    // A key that is no device's id, a value of another form
    refused(f.patch("installed", item("Lea's Switch")), 400, "bad_request");
    refused(f.patch("installed",
                R"({"key":")" + device + R"(","value":{"platform":3},"updated":")" + at(0) + R"("})"),
        400, "bad_request");

    // Wishes: a key of a platform and a title id, a value of those of its key
    refused(f.patch("wishes", R"({"key":"Frostline Tales","value":{},"updated":")" + at(0) + R"("})"), 400,
        "bad_request");
    refused(
        f.patch("wishes",
            R"({"key":"switch/0100BB0000020000","value":{"platform":"switch","title_id":"0100CC0000030000"},)"
            R"("updated":")"
                + at(0) + R"("})"),
        400, "bad_request");
    // An updated that is no time, a value with a deletion, neither, a rev, nothing, too many
    refused(f.patch("wishes", R"({"key":"switch/0100BB0000020000","deleted":true,"updated":"yesterday"})"),
        400, "bad_request");
    refused(f.patch("wishes",
                R"({"key":"switch/0100BB0000020000","deleted":false,"updated":")" + at(0) + R"("})"),
        400, "bad_request");
    refused(
        f.patch("wishes",
            R"({"key":"switch/0100BB0000020000","deleted":true,"value":{},"updated":")" + at(0) + R"("})"),
        400, "bad_request");
    refused(f.patch("wishes", R"({"key":"switch/0100BB0000020000","updated":")" + at(0) + R"("})"), 400,
        "bad_request");
    refused(f.patch("wishes",
                R"({"key":"switch/0100BB0000020000","deleted":true,"rev":3,"updated":")" + at(0) + R"("})"),
        400, "bad_request");
    refused(f.patch("wishes", ""), 400, "bad_request");
    refused(f.patch("wishes", Fixture::wish(wished, 0) + "," + Fixture::wish(wished, 5)), 400, "bad_request");
    refused(f.send("PATCH", "/sync/wishes", R"({"schema":1,"items":[]})"), 400, "bad_request");
    refused(f.send("PATCH", "/sync/wishes", R"({"schema":9,"generation":"g_x","items":[]})"), 422,
        "unsupported_schema");
    // Nothing of that was kept
    CHECK(f.get("/sync").body.contains(R"("wishes":{"rev":0,"items":0})"));
}

TEST_CASE("sync: erasing a collection, or all of them, gives a new generation (L-20.5-1)")
{
    const Fixture f;
    const std::string gen = f.generation();
    REQUIRE(f.patch("wishes", Fixture::wish(wished, 0)).status == 200);
    REQUIRE(f.patch("installed",
                 R"({"key":")" + text_of(f.get("/sync").body, "device")
                     + R"(","value":{"device":"Lea's Switch","platform":"switch","apps":[],"homebrew":[]},)"
                       R"("updated":")"
                     + at(0) + R"("})")
                .status
        == 200);
    const ServerResponse one = f.send("DELETE", "/sync/wishes");
    CHECK(one.status == 204);
    CHECK(one.body.empty());
    const std::string next = f.generation();
    CHECK(next != gen);
    // The other collection is not touched, its items still there
    CHECK(f.get("/sync").body.contains(R"("installed":{"rev":1,"items":1})"));
    CHECK(f.get("/sync").body.contains(R"("wishes":{"rev":0,"items":0})"));
    // A console that read the generation before cannot write its items back
    refused(f.patch("wishes", Fixture::wish(wished, 0), lea, gen), 409, "conflict");
    // Every collection, deletions included
    REQUIRE(f.patch("wishes", Fixture::wish(wished, 0)).status == 200);
    REQUIRE(f.patch("wishes", Fixture::unwish(wished, 10)).status == 200);
    CHECK(f.send("DELETE", "/sync").status == 204);
    CHECK(f.generation() != next);
    CHECK(f.get("/sync").body.contains(R"("installed":{"rev":0,"items":0})"));
    CHECK(f.get("/sync/wishes?since=0").body.contains(R"("items":[])"));
    // The other account's data is its own
    CHECK(f.send("DELETE", "/sync", {}, kim).status == 204);
}

TEST_CASE("sync: deletions are kept, then dropped; a read after a revision they hide is 410 (L-20.3-1)")
{
    Fixture f(100, 10);
    REQUIRE(f.patch("wishes", Fixture::wish(wished, 0)).status == 200);
    REQUIRE(f.patch("wishes", Fixture::unwish(wished, 10)).status == 200);
    REQUIRE(f.patch("wishes", Fixture::wish(wished2, 20)).status == 200);
    // Within the retention: the deletion is there
    f.clock.now = start + 5;
    CHECK(f.get("/sync/wishes?since=1").body.contains(R"("deleted":true)"));
    // Beyond it: a reader that has not seen the deletion cannot be told of it
    f.clock.now = start + 100;
    refused(f.get("/sync/wishes?since=1"), 410, "gone");
    // One that has seen it, or reads whole, is served
    CHECK(f.get("/sync/wishes?since=2").status == 200);
    CHECK(f.get("/sync/wishes").status == 200);
    CHECK(f.get("/sync/wishes").body.contains(wished2));
}

TEST_CASE("sync: the event sync tells the account's devices, and only them")
{
    const Fixture f(100, 30 * 86400, true, true, true);
    const auto open = [&](std::string_view token)
    {
        Call call;
        call.target             = "/events";
        ServerResponse response = f.go(std::move(call), token);
        REQUIRE(response.status == 200);
        REQUIRE(response.stream != nullptr);
        return response.stream;
    };
    const auto step = [](EventStream& stream)
    {
        String out;
        stream.step(0, out);
        return std::string(out);
    };
    const auto mine         = open(lea2);
    const auto other        = open(kim);
    const auto plain_stream = open(read_only);
    CHECK(step(*mine).contains("event: ready"));
    step(*other);
    step(*plain_stream);

    REQUIRE(f.patch("wishes", Fixture::wish(wished, 0)).status == 200);
    const std::string told = step(*mine);
    CHECK(told.contains("event: sync"));
    CHECK(told.contains(R"("collection":"wishes")"));
    CHECK(told.contains(R"("rev":1)"));
    CHECK_FALSE(step(*other).contains("event: sync"));
    // Not told of an item that changed nothing
    REQUIRE(f.patch("wishes", Fixture::wish(wished, -5000)).status == 200);
    CHECK_FALSE(step(*mine).contains("event: sync"));
    // Erasing: each collection at revision 0
    REQUIRE(f.send("DELETE", "/sync").status == 204);
    const std::string erased = step(*mine);
    CHECK(erased.contains(R"("collection":"wishes","rev":0)"));
    CHECK(erased.contains(R"("collection":"installed","rev":0)"));
    // Another account with sync.read is told of its own account's changes only
    CHECK_FALSE(step(*plain_stream).contains("event: sync"));
}

TEST_CASE("sync: deleting an account erases its sync data (L-20.5-3)")
{
    Fixture f;
    REQUIRE(f.patch("wishes", Fixture::wish(wished, 0)).status == 200);
    const std::string gen = f.generation();
    auto held             = f.sync.read("lea", "wishes", start, {});
    REQUIRE(held);
    CHECK(held->items.size() == 1);
    CHECK(f.send("DELETE", "/admin/users/lea?confirm=lea", {}, root).status == 204);
    held = f.sync.read("lea", "wishes", start, {});
    REQUIRE(held);
    CHECK(held->items.empty());
    CHECK(held->rev == 0);
    // The store forgot the account: if it came back it would have a generation of its own
    CHECK(std::string_view(held->generation) != gen);
}

TEST_CASE("peers: the grant key in the handshake, and grants for the files the caller may read")
{
    const Fixture off(100, 30 * 86400, true, false);
    CHECK(off.get("/").body.contains(R"("peers":0)"));
    CHECK_FALSE(off.get("/").body.contains(R"("grant_lifetime")"));
    refused(off.get("/grants/sha256/" + std::string(64, '0')), 404, "not_found");

    const Fixture f;
    const ServerResponse hello = f.get("/");
    CHECK(hello.body.contains(R"("peers":1)"));
    CHECK(number_of(hello.body, "grant_lifetime") == 600);
    // The same key for every caller (L-19.3-3)
    const std::string key = text_of(hello.body, "key");
    REQUIRE_FALSE(key.empty());
    CHECK(text_of(f.get("/", "").body, "key") == key);
    CHECK(text_of(f.get("/", kim).body, "key") == key);
    PublicKey raw {};
    REQUIRE(base64_decode(key, raw));
    CHECK(raw == ed25519_public_key(Sha256::of(std::string_view("a grant key for the tests"))));

    // A file of the library: a grant that verifies, for this file, this server and this lifetime
    const Digest sha             = Sha256::of(std::string_view("gentle"));
    const auto hex               = to_hex(sha);
    const std::string path       = "/grants/sha256/" + std::string(hex.data(), hex.size());
    const ServerResponse granted = f.get(path);
    REQUIRE(granted.status == 200);
    CHECK(text_of(granted.body, "sha256") == std::string(hex.data(), hex.size()));
    CHECK(number_of(granted.body, "size") == 6);
    CHECK(text_of(granted.body, "expires") == "2026-10-26T07:43:20Z");
    CHECK(granted.headers.get("Cache-Control").value_or("") == "no-store");
    const std::string grant = text_of(granted.body, "grant");
    const std::array<GrantKey, 1> servers { GrantKey { uid, raw } };
    const auto claims = verify_grant(grant, sha, start, servers);
    REQUIRE(claims);
    CHECK(claims->exp == start + 600);
    CHECK(claims->size == 6);
    // Expired by the peer's clock, or for another file: refused
    CHECK_FALSE(verify_grant(grant, sha, start + 601, servers));
    CHECK_FALSE(verify_grant(grant, Sha256::of(std::string_view("other")), start, servers));
    // A grant needs the scope library, and a file the server has
    CHECK(f.get(path, "").status == 200);
    refused(f.get("/grants/sha256/" + std::string(64, '0')), 404, "not_found");
    refused(f.get("/grants/sha256/" + std::string(64, 'A')), 404, "not_found");
    refused(f.get("/grants/sha256/abc"), 404, "not_found");
    refused(f.send("POST", path), 405, "bad_request");
    // Another platform than the file's: the file is not there for the caller
    Call other;
    other.target = path + "?platform=android";
    refused(f.go(std::move(other), lea), 404, "not_found");
}
