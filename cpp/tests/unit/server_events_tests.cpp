// The server core's events (include/lantern/server.hpp; SPEC.md § 18): the
// stream, resumed with Last-Event-ID or ?since=, the long poll of `changes`,
// each caller told only of what it may read, and the events the other
// families record. The core is called in memory with a clock of the test's
// own: a stream is stepped at the milliseconds the test names, a held long
// poll is asked again with the time it waited, so that nothing here sleeps.
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

constexpr std::string_view uid    = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";
constexpr std::int64_t start      = 1'793'000'000;
constexpr std::string_view base   = "/api/lantern/v1";
constexpr std::string_view root   = "et_root-0123456789abcdef0123456789abcdef";
constexpr std::string_view lea    = "et_lea-0123456789abcdef0123456789abcdef";
constexpr std::string_view kim    = "et_kim-0123456789abcdef0123456789abcdef";
constexpr std::string_view reader = "et_reader-0123456789abcdef0123456789ab";
constexpr std::string_view gentle = "0100AA0000010000"; // rated PEGI 3
constexpr std::string_view mature = "0100BB0000020000"; // rated PEGI 18
constexpr std::string_view absent = "0100CC0000030000"; // not in the library

class CountingRandom final : public RandomSource
{
  public:
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        for (std::size_t at = 0; at < out.size(); at += 32)
        {
            const std::string seed = "events-test-random:" + std::to_string(counter_++);
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

Title title_of(std::string_view id, std::string_view name, std::string_view pegi)
{
    Title title;
    title.platform = "switch";
    title.title_id = id;
    title.name     = name;
    Rating rating;
    rating.system = "PEGI";
    rating.rating = pegi;
    title.ratings.push_back(rating);
    return title;
}

AppDraft draft_of(std::string_view id, std::string_view name, std::string_view platform = "switch")
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

// The id of the first event after `marker` in a stream's text, or of `ready` for an empty marker.
std::string id_of(std::string_view stream, std::string_view marker)
{
    const std::size_t at = stream.find(marker);
    REQUIRE(at != std::string_view::npos);
    const std::size_t id = stream.rfind("id: ", at);
    REQUIRE(id != std::string_view::npos);
    return std::string(stream.substr(id + 4, stream.find('\n', id) - id - 4));
}

std::string digest_of(std::string_view bytes)
{
    String text;
    format_digest_field(Sha256::of(bytes), text);
    return std::string(text);
}

struct Call
{
    std::string method = "GET";
    std::string target;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    // A request the server held, asked again
    std::uint64_t waited_ms = 0;
    bool resumed            = false;
};

// What a stream says at one step.
struct Said
{
    bool more = false;
    std::string text;
};

Said step(EventStream& stream, std::uint64_t now_ms)
{
    String out;
    Said said;
    said.more = stream.step(now_ms, out);
    said.text = std::string(out);
    return said;
}

struct Fixture
{
    MemoryLibrary library { "/api/lantern" };
    CountingRandom random;
    FakeClock clock;
    MemoryAccountStore store;
    MemoryRequestStore requests;
    MemorySaveStore saves;
    ServerOptions options;
    std::optional<Server> server;

    explicit Fixture(bool events = true, std::uint32_t kept = 10000, bool journal = true)
    {
        constexpr std::array<std::string_view, 4> all { "library", "saves", "requests", "admin" };
        constexpr std::array<std::string_view, 3> member { "library", "saves", "requests" };
        constexpr std::array<std::string_view, 1> plain { "library" };
        REQUIRE(store.add_account("root", all, false, start));
        REQUIRE(store.add_account("lea", member, false, start));
        REQUIRE(store.add_account("kim", member, false, start));
        REQUIRE(store.add_account("reader", plain, false, start));
        REQUIRE(store.add_token(root, "root", "Root's console", all, std::nullopt, start));
        REQUIRE(store.add_token(lea, "lea", "Lea's console", member, std::nullopt, start));
        REQUIRE(store.add_token(kim, "kim", "Kim's console", member, std::nullopt, start));
        REQUIRE(store.add_token(reader, "reader", "A tablet", plain, std::nullopt, start));
        if (journal)
            REQUIRE(library.keep_journal());
        REQUIRE(library.add_app(draft_of(gentle, "Gentle"), bytes("gentle")));
        REQUIRE(library.add_title(title_of(gentle, "Gentle", "3")));
        REQUIRE(library.add_title(title_of(mature, "Mature", "18")));
        options.uid         = uid;
        options.name        = "Test shelf";
        options.scheme      = "http";
        options.accounts    = &store;
        options.requests    = &requests;
        options.saves       = &saves;
        options.events      = events;
        options.events_kept = kept;
        remake();
    }

    void remake()
    {
        server.reset();
        auto made = Server::create(library, options, random, clock);
        REQUIRE(made);
        server.emplace(std::move(*made));
    }

    [[nodiscard]] ServerResponse go(Call call, std::string_view token = root,
        std::string_view platform = "switch", std::string_view remote = "192.0.2.10") const
    {
        call.target = std::string(base) + call.target;
        call.headers.emplace_back("Host", "shelf.example.org");
        if (!token.empty())
            call.headers.emplace_back("Authorization", "Bearer " + std::string(token));
        if (!platform.empty())
            call.headers.emplace_back("Lantern-Platform", std::string(platform));
        const auto parsed = parse_target(call.target);
        REQUIRE(parsed);
        std::vector<QueryParam> query;
        for (const auto& [name, value] : parsed->query)
            query.push_back({ name, value });
        std::vector<Header> headers;
        for (const auto& [name, value] : call.headers)
            headers.push_back({ name, value });
        ServerRequest request;
        request.method    = call.method;
        request.path      = parsed->path;
        request.query     = query;
        request.headers   = headers;
        request.body      = std::as_bytes(std::span(call.body.data(), call.body.size()));
        request.scheme    = "http";
        request.target    = call.target;
        request.remote    = remote;
        request.resumed   = call.resumed;
        request.waited_ms = call.waited_ms;
        return server->handle(request);
    }

    [[nodiscard]] ServerResponse get(std::string route, std::string_view token = root,
        std::string_view platform = "switch", std::uint64_t waited_ms = 0) const
    {
        Call call;
        call.target    = std::move(route);
        call.waited_ms = waited_ms;
        call.resumed   = waited_ms != 0;
        return go(std::move(call), token, platform);
    }

    [[nodiscard]] ServerResponse send(std::string method, std::string route, std::string body = {},
        std::string_view token = root, std::string_view platform = "switch") const
    {
        Call call;
        call.method = std::move(method);
        call.target = std::move(route);
        call.body   = std::move(body);
        if (!call.body.empty())
            call.headers.emplace_back("Content-Type", "application/json");
        return go(std::move(call), token, platform);
    }

    // A stream opened with `route` (after the base) and the headers given.
    [[nodiscard]] ServerResponse open(std::string_view token = root, std::string route = "/events",
        std::vector<std::pair<std::string, std::string>> headers = {}, std::string_view platform = "switch",
        std::string_view remote = "192.0.2.10") const
    {
        Call call;
        call.target  = std::move(route);
        call.headers = std::move(headers);
        return go(std::move(call), token, platform, remote);
    }

    // The stream of a call that opened one.
    [[nodiscard]] std::shared_ptr<EventStream> stream(std::string_view token = root,
        std::string route = "/events", std::vector<std::pair<std::string, std::string>> headers = {},
        std::string_view platform = "switch") const
    {
        ServerResponse response = open(token, std::move(route), std::move(headers), platform);
        REQUIRE(response.status == 200);
        REQUIRE(response.stream != nullptr);
        return response.stream;
    }

    [[nodiscard]] ServerResponse ask(
        std::string_view title_id, std::string_view token = lea, std::string_view platform = "switch") const
    {
        return send("POST", "/requests", R"({"schema":1,"title_id":")" + std::string(title_id) + "\"}", token,
            platform);
    }

    // The only pairing waiting, approved by the admin with `members` of the decision.
    [[nodiscard]] ServerResponse decide(std::string_view members) const
    {
        const std::string id = text_of(get("/admin/pairings").body, "id");
        return send("POST", "/admin/pairings/" + id, R"({"schema":1,)" + std::string(members) + "}");
    }

    // A pairing started anonymously: its poll address, without the base.
    [[nodiscard]] std::string pair() const
    {
        const ServerResponse r = send(
            "POST", "/pairing", R"({"schema":1,"device":"Lea's tablet","scopes":["library"]})", {}, {});
        REQUIRE(r.status == 200);
        return text_of(r.body, "poll").substr(base.size());
    }

    // The token of a device paired and approved with `cap` (a JSON object), for `lea`, the scope library.
    [[nodiscard]] std::string capped_token(std::string_view cap) const
    {
        const std::string poll = pair();
        REQUIRE(decide(R"("decision":"approve","user":"lea","scopes":["library"],"rating_cap":)"
                    + std::string(cap))
                    .status
            == 204);
        const std::string token = text_of(get(poll, "").body, "token");
        REQUIRE_FALSE(token.empty());
        return token;
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

TEST_CASE("events: offered only when asked, with their limits, to whoever may read one kind")
{
    const Fixture off(false);
    CHECK(off.get("/").body.contains(R"("events":0)"));
    refused(off.get("/events"), 404, "not_found");
    // Without events, `wait` is not heard: the plain document of changes
    CHECK(off.get("/changes?since=x&wait=5").status == 400);

    const Fixture f;
    const ServerResponse hello = f.get("/", reader);
    CHECK(hello.body.contains(R"("events":1)"));
    CHECK(hello.body.contains(R"("heartbeat":15,"event_streams":2,"wait":60)"));
    // Anonymously, on a public server, the library's events
    CHECK(f.get("/", "").body.contains(R"("events":1)"));
    CHECK(f.open("").status == 200);
    // A server that asks for a token: 401 to an anonymous stream
    Fixture strict;
    strict.options.require_auth = true;
    strict.remake();
    refused(strict.open(""), 401, "unauthorized");
    CHECK(strict.get("/", "").body.contains(R"("events":0)"));

    // A stream is for GET alone
    refused(f.send("POST", "/events"), 405, "bad_request");

    // The limits are checked (§ 18.4)
    Fixture g;
    ServerOptions odd = g.options;
    odd.heartbeat     = 4;
    CHECK_FALSE(Server::create(g.library, odd, g.random, g.clock));
    odd            = g.options;
    odd.wait_limit = 301;
    CHECK_FALSE(Server::create(g.library, odd, g.random, g.clock));
    odd               = g.options;
    odd.event_streams = 0;
    CHECK_FALSE(Server::create(g.library, odd, g.random, g.clock));
}

TEST_CASE(
    "events: a stream begins with retry and ready, gives what happens, and a heartbeat when nothing does")
{
    const Fixture f;
    // never a Content-Encoding on a stream, whatever the client accepts (§ 2.1)
    const ServerResponse opened = f.open(root, "/events", { { "Accept-Encoding", "gzip" } });
    REQUIRE(opened.stream != nullptr);
    CHECK(opened.headers.get("Content-Type") == "text/event-stream; charset=utf-8");
    CHECK(opened.headers.get("Cache-Control") == "no-store");
    CHECK_FALSE(opened.headers.get("Content-Encoding").has_value());
    CHECK_FALSE(opened.headers.get("Content-Length").has_value());
    EventStream& stream = *opened.stream;

    const Said first = step(stream, 0);
    CHECK(first.more);
    CHECK(first.text.starts_with("retry: 5000\n\n"));
    CHECK(first.text.contains("event: ready\ndata: {\"schema\":1}\n\n"));
    // The id of ready is a token of changes (L-18.1-1)
    const std::string ready = id_of(first.text, "event: ready");
    CHECK(f.get("/changes?since=" + ready).status == 200);

    // Nothing to say, then a request made: the event, at once
    CHECK(step(stream, 100).text.empty());
    const ServerResponse made = f.ask(absent);
    REQUIRE(made.status == 201);
    const Said event = step(stream, 200);
    CHECK(event.text.contains("event: request\n"));
    CHECK(event.text.contains(R"("status":"open")"));
    CHECK(event.text.contains(R"("title_id":"0100CC0000030000")"));
    // Its id resumes just after it
    CHECK(f.get("/changes?since=" + id_of(event.text, "event: request")).status == 200);

    // A comment at least every heartbeat seconds (L-18.1-6), counted from the last thing written
    CHECK(step(stream, 15'199).text.empty());
    CHECK(step(stream, 15'200).text == ": heartbeat\n\n");
    CHECK(step(stream, 15'300).text.empty());
    CHECK(step(stream, 30'200).text == ": heartbeat\n\n");

    // Withdrawn: the request again, `deleted` instead of `status`
    REQUIRE(f.send("DELETE", "/requests/" + text_of(made.body, "id"), {}, lea).status == 204);
    const Said gone = step(stream, 30'300);
    CHECK(gone.text.contains(R"("deleted":true)"));
    CHECK_FALSE(gone.text.contains("status"));

    // A stream lives its hour, then the client resumes with the last id it read
    CHECK_FALSE(step(stream, 3'600'000).more);
    CHECK_FALSE(step(stream, 3'600'100).more);
}

TEST_CASE("events: a stream resumes after an id, its events before the first heartbeat")
{
    Fixture f;
    f.options.event_streams = 8;
    f.remake();
    const auto first           = f.stream();
    const Said opening         = step(*first, 0);
    const std::string start_id = id_of(opening.text, "event: ready");

    REQUIRE(f.ask(absent, lea).status == 201);
    REQUIRE(f.ask(mature, lea).status == 201);
    const std::string seen = step(*first, 10).text;
    CHECK(seen.contains(absent));
    const std::string second_id = id_of(seen, mature);

    // Last-Event-ID: ready names the token resumed from, every event after it follows, before any heartbeat
    const auto again   = f.stream(root, "/events", { { "Last-Event-ID", start_id } });
    const Said resumed = step(*again, 0);
    CHECK(id_of(resumed.text, "event: ready") == start_id);
    CHECK(resumed.text.contains(absent));
    CHECK(resumed.text.contains(mature));
    CHECK_FALSE(resumed.text.contains("heartbeat"));
    CHECK(resumed.text.find(absent) < resumed.text.find(mature));

    // From the second event on: only what comes after it
    const auto later = f.stream(root, "/events", { { "Last-Event-ID", second_id } });
    const Said rest  = step(*later, 0);
    CHECK_FALSE(rest.text.contains(absent));
    CHECK(rest.text.contains("event: ready"));

    // ?since= wins over the header
    const auto query = f.stream(root, "/events?since=" + start_id, { { "Last-Event-ID", second_id } });
    CHECK(step(*query, 0).text.contains(absent));

    // The same token resumes the long poll, with the same events
    const std::string polled(f.get("/changes?since=" + start_id + "&wait=0").body);
    CHECK(polled.contains(absent));
    CHECK(polled.contains(mature));
    CHECK(polled.contains(R"("events":[{"id":")"));
    CHECK(text_of(polled, "since") != start_id);

    // A token the server never gave: 400; one of another process, or older than what is kept: 410
    refused(f.open(root, "/events", { { "Last-Event-ID", "lantern-conformance" } }), 400, "bad_request");
    refused(f.open(root, "/events?since=" + start_id.substr(0, start_id.size() - 2)), 400, "bad_request");
    Fixture small(true, 2);
    const std::string old_id = id_of(step(*small.stream(), 0).text, "event: ready");
    for (const std::string_view id : { gentle, mature, absent })
        REQUIRE(small.ask(id).status == 201);
    refused(small.open(root, "/events?since=" + old_id), 410, "gone");
    refused(small.get("/changes?since=" + old_id + "&wait=0"), 410, "gone");
}

TEST_CASE("events: each caller gets only the events it may read")
{
    Fixture f;
    const auto lea_stream     = f.stream(lea);
    const auto kim_stream     = f.stream(kim);
    const auto admin_stream   = f.stream(root);
    const auto reader_stream  = f.stream(reader);
    const auto anon_stream    = f.stream("");
    const auto android_stream = f.stream(lea, "/events", {}, "android");
    for (const auto& s : { lea_stream, kim_stream, admin_stream, reader_stream, anon_stream, android_stream })
        CHECK(step(*s, 0).more);

    REQUIRE(f.ask(absent, lea).status == 201);
    const std::string leas = step(*lea_stream, 1).text;
    CHECK(leas.contains(absent));
    CHECK_FALSE(leas.contains("\"user\""));
    // Another account's request is none of kim's business, nor of a token without the scope
    CHECK(step(*kim_stream, 1).text.empty());
    CHECK(step(*reader_stream, 1).text.empty());
    CHECK(step(*anon_stream, 1).text.empty());
    // Nor of a stream that named another platform
    CHECK(step(*android_stream, 1).text.empty());
    // The admin reads every account's, with its user
    const std::string admins = step(*admin_stream, 1).text;
    CHECK(admins.contains(absent));
    CHECK(admins.contains(R"("user":"lea")"));

    // The library: whoever may read it, for the platform it follows
    REQUIRE(f.library.add_app(draft_of(absent, "Absent"), bytes("absent")));
    for (const auto& s : { lea_stream, kim_stream, admin_stream, reader_stream, anon_stream })
    {
        const std::string said = step(*s, 2).text;
        CHECK(said.contains("event: library\n"));
        CHECK(said.contains(R"("families":["apps"],"platforms":["switch"])"));
    }
    CHECK(step(*android_stream, 2).text.empty());
    REQUIRE(f.library.add_app(draft_of("org.example.tool", "Tool", "android"), bytes("tool")));
    CHECK(step(*android_stream, 3).text.contains(R"("platforms":["android"])"));
    CHECK(step(*kim_stream, 3).text.empty()); // a stream of switch hears nothing of android

    // A caller whose rating cap hides a title is not told of its changes (L-18.2-1)
    const std::string capped = f.capped_token(R"({"age":6})");
    const auto capped_stream = f.stream(capped);
    CHECK(step(*capped_stream, 0).more);
    REQUIRE(f.library.add_app(draft_of(mature, "Mature"), bytes("mature")));
    CHECK(step(*capped_stream, 1).text.empty());
    CHECK(step(*admin_stream, 4).text.contains("event: library"));
    REQUIRE(f.library.add_title(title_of(gentle, "Gentle again", "3")));
    CHECK(step(*capped_stream, 2).text.contains(R"("families":["titles"])"));
    // The pairing events, and none to an account that is not an admin's
    CHECK_FALSE(step(*lea_stream, 4).text.contains("event: pairing"));
}

TEST_CASE("events: a pairing waiting, a backup kept, a request decided or settled")
{
    Fixture f;
    const auto admin_stream = f.stream(root);
    const auto lea_stream   = f.stream(lea);
    CHECK(step(*admin_stream, 0).more);
    CHECK(step(*lea_stream, 0).more);

    // A pairing waiting goes to the scope admin, with its code (§ 18.2)
    static_cast<void>(f.pair());
    const std::string said = step(*admin_stream, 1).text;
    CHECK(said.contains("event: pairing\n"));
    CHECK(said.contains(R"("device":"Lea's tablet")"));
    CHECK(said.contains(R"("code":")"));
    CHECK(said.contains(R"("expires":")"));
    CHECK(step(*lea_stream, 1).text.empty());
    CHECK(f.decide(R"("decision":"refuse")").status == 204);

    // A backup kept goes to its owner, with the scope saves
    std::string archive = "PK\x03\x04";
    archive.resize(500, 'a');
    Call call;
    call.method = "POST";
    call.target = "/saves/" + std::string(gentle);
    call.body   = archive;
    call.headers.emplace_back("Content-Type", "application/zip");
    call.headers.emplace_back("Content-Digest", digest_of(archive));
    call.headers.emplace_back("Lantern-Save-Kind", "account");
    REQUIRE(f.go(call, lea).status == 201);
    const std::string kept = step(*lea_stream, 2).text;
    CHECK(kept.contains("event: save\n"));
    CHECK(kept.contains(R"("title_id":"0100AA0000010000")"));
    CHECK(kept.contains(R"("save_id":")"));
    CHECK_FALSE(step(*admin_stream, 2).text.contains("event: save"));

    // A request decided by the admin: its new status, to its owner and to the admin
    const ServerResponse made = f.ask(absent, lea);
    const std::string id      = text_of(made.body, "id");
    CHECK(step(*lea_stream, 3).text.contains(R"("status":"open")"));
    CHECK(step(*admin_stream, 3).text.contains(R"("status":"open")"));
    REQUIRE(
        f.send("POST", "/admin/requests/" + id, R"({"schema":1,"decision":"decline","reason":"No."})").status
        == 200);
    CHECK(step(*lea_stream, 4).text.contains(R"("status":"declined")"));

    // The library gains the title: settle_requests() marks the open request done, and says so
    const ServerResponse again = f.ask(absent, lea);
    const std::string next     = text_of(again.body, "id");
    CHECK(step(*lea_stream, 5).text.contains(R"("status":"open")"));
    REQUIRE(f.library.add_app(draft_of(absent, "Absent"), bytes("absent")));
    CHECK(step(*lea_stream, 6).text.contains("event: library"));
    const auto settled = f.server->settle_requests();
    REQUIRE(settled);
    CHECK(*settled == 1);
    const std::string done = step(*lea_stream, 7).text;
    CHECK(done.contains(R"("status":"done")"));
    CHECK(done.contains(next));
}

TEST_CASE("events: the long poll answers at once, or is held until its time, whatever the clock")
{
    Fixture f;
    const std::string ready = id_of(step(*f.stream(), 0).text, "event: ready");
    const std::string route = "/changes?since=" + ready + "&wait=";

    // Nothing yet: not an answer, a hold for the whole wait, until the mark of the events changes
    const ServerResponse held = f.get(route + "30");
    CHECK(held.hold_ms == 30'000);
    CHECK(held.hold_mark == f.server->event_mark());
    // Asked again after 12 seconds: the rest of the wait
    CHECK(f.get(route + "30", root, "switch", 12'000).hold_ms == 18'000);
    // After the whole wait: the document, `[]` for its events, a token to ask again with (L-18.3-2)
    const ServerResponse timed_out = f.get(route + "30", root, "switch", 30'000);
    CHECK(timed_out.hold_ms == 0);
    CHECK(timed_out.status == 200);
    CHECK(timed_out.body.contains(R"("events":[])"));
    CHECK(timed_out.headers.get("Cache-Control") == "no-store");
    CHECK(f.get("/changes?since=" + text_of(timed_out.body, "since")).status == 200);
    // A wait of 0 does not wait; one above limits.wait is lowered to it
    CHECK(f.get(route + "0").hold_ms == 0);
    CHECK(f.get(route + "9999").hold_ms == 60'000);
    CHECK(f.get(route + "9999", root, "switch", 60'000).hold_ms == 0);
    CHECK(f.get(route + "99999999999999999999999").hold_ms == 60'000);

    // An event: the mark moves, and the held request, asked again, answers with it
    REQUIRE(f.ask(absent, lea).status == 201);
    CHECK(f.server->event_mark() != held.hold_mark);
    const ServerResponse woken = f.get(route + "30", root, "switch", 2'000);
    CHECK(woken.hold_ms == 0);
    CHECK(woken.body.contains(R"("event":"request")"));
    CHECK(woken.body.contains(absent));
    CHECK(woken.body.contains(R"("user":"lea")"));
    // An event the caller may not read does not end the wait
    const ServerResponse kims = f.get(route + "30", kim);
    CHECK(kims.hold_ms == 30'000);
    // The apps added meanwhile come in `added`, as changes gives them
    REQUIRE(f.library.add_app(draft_of(absent, "Absent"), bytes("absent")));
    const ServerResponse added = f.get(route + "30", kim);
    CHECK(added.hold_ms == 0);
    CHECK(added.body.contains(R"("added":[{)"));
    CHECK(added.body.contains(R"("event":"library")"));

    // `wait` without since, or that is not a whole number of seconds from 0: 400 (L-18.3-3)
    refused(f.get("/changes?wait=5"), 400, "bad_request");
    refused(f.get("/changes?since=x&wait=soon"), 400, "bad_request");
    refused(f.get("/changes?since=" + ready + "&wait=-1"), 400, "bad_request");
    refused(f.get("/changes?since=" + ready + "&wait=1.5"), 400, "bad_request");
    refused(f.get("/changes?since=lantern-conformance&wait=5"), 400, "bad_request");
    // The token must be an authenticated caller's
    refused(f.get(route + "5", "et_nobody-0123456789abcdef0123456789abcdef"), 401, "unauthorized");

    // A server that stops answers a held request at once
    f.server->shutdown();
    const ServerResponse stopped = f.get(route + "30", kim, "switch", 100);
    CHECK(stopped.hold_ms == 0);
    CHECK(stopped.status == 200);
}

TEST_CASE("events: a token holds so many streams, an anonymous caller's address as many")
{
    const Fixture f;
    ServerResponse one = f.open(lea);
    ServerResponse two = f.open(lea);
    REQUIRE(one.stream != nullptr);
    REQUIRE(two.stream != nullptr);
    const ServerResponse third = f.open(lea);
    refused(third, 429, "slow_down");
    CHECK(third.headers.get("Retry-After") == "15");
    // Another token has its own
    CHECK(f.open(kim).stream != nullptr);
    // A stream let go frees its slot at once
    one.stream.reset();
    const ServerResponse replaced = f.open(lea);
    CHECK(replaced.stream != nullptr);
    refused(f.open(lea), 429, "slow_down");
    two.stream.reset();

    const ServerResponse here  = f.open("", "/events", {}, "switch", "192.0.2.50");
    const ServerResponse there = f.open("", "/events", {}, "switch", "192.0.2.50");
    CHECK(here.stream != nullptr);
    CHECK(there.stream != nullptr);
    refused(f.open("", "/events", {}, "switch", "192.0.2.50"), 429, "slow_down");
    CHECK(f.open("", "/events", {}, "switch", "192.0.2.51").stream != nullptr);
}

TEST_CASE("events: a stream ends by its heartbeat when its token is revoked or its account frozen")
{
    Fixture f;
    const auto revoked = f.stream(lea);
    const auto frozen  = f.stream(kim);
    const auto stays   = f.stream(root);
    CHECK(step(*revoked, 0).more);
    CHECK(step(*frozen, 0).more);
    CHECK(step(*stays, 0).more);

    auto devices = f.store.all_devices("lea", start, Allocator());
    REQUIRE(devices);
    REQUIRE(devices->size() == 1);
    REQUIRE(f.store.revoke_device((*devices)[0].id));
    REQUIRE(f.store.set_frozen("kim", true));

    // Before the heartbeat nothing has been looked at; at it, the stream ends (L-18.1-8)
    CHECK(step(*revoked, 14'999).more);
    CHECK(step(*frozen, 14'999).more);
    const Said over = step(*revoked, 15'000);
    CHECK_FALSE(over.more);
    CHECK_FALSE(over.text.contains("heartbeat"));
    CHECK_FALSE(step(*frozen, 15'000).more);
    const Said alive = step(*stays, 15'000);
    CHECK(alive.more);
    CHECK(alive.text == ": heartbeat\n\n");

    // A revoked token's stream is told no event either: it ends at the first
    const auto second = f.stream(reader);
    CHECK(step(*second, 0).more);
    auto tablets = f.store.all_devices("reader", start, Allocator());
    REQUIRE(tablets);
    REQUIRE(f.store.revoke_device((*tablets)[0].id));
    REQUIRE(f.library.add_app(draft_of(absent, "Absent"), bytes("absent")));
    const Said cut = step(*second, 1);
    CHECK_FALSE(cut.more);
    CHECK_FALSE(cut.text.contains("event: library"));
}

TEST_CASE("events: shutdown reaches every stream, before it ends")
{
    const Fixture f;
    const auto one = f.stream(lea);
    const auto two = f.stream("");
    CHECK(step(*one, 0).more);
    CHECK(step(*two, 0).more);
    f.server->shutdown();
    for (const auto& s : { one, two })
    {
        const Said last = step(*s, 10);
        CHECK_FALSE(last.more);
        CHECK(last.text.contains("event: shutdown\ndata: {\"schema\":1,\"retry\":5}\n\n"));
        // Its id is a token like the others
        CHECK(f.get("/changes?since=" + id_of(last.text, "event: shutdown")).status == 200);
        CHECK_FALSE(step(*s, 11).more);
    }
    // A stream opened after it begins, then says it
    const auto late = f.stream(lea);
    CHECK(step(*late, 0).text.contains("event: shutdown"));
}

TEST_CASE("events: a library that tells the server itself, and one that does not")
{
    Fixture f;
    {
        const auto stream = f.stream(lea);
        CHECK(step(*stream, 0).more);

        // Any library: its app says what changed
        const std::array<LibraryChange, 2> changes { LibraryChange { "cheats", "switch", gentle, nullptr },
            LibraryChange { "homebrew", "switch", {}, nullptr } };
        f.server->library_changed(changes);
        const std::string said = step(*stream, 1).text;
        CHECK(said.contains(R"("families":["cheats","homebrew"],"platforms":["switch"])"));
        f.server->library_changed({});
        CHECK(step(*stream, 2).text.empty());

        // Homebrew is read by its own ratings
        const std::string capped = f.capped_token(R"({"age":6})");
        const auto kid           = f.stream(capped);
        CHECK(step(*kid, 3).more);
        Vector<Rating> adult;
        Rating rating;
        rating.system = "PEGI";
        rating.rating = "18";
        adult.push_back(rating);
        const std::array<LibraryChange, 1> hidden { LibraryChange { "homebrew", "switch", {}, &adult } };
        f.server->library_changed(hidden);
        CHECK(step(*kid, 4).text.empty());
        CHECK(step(*stream, 4).text.contains(R"("families":["homebrew"])"));
    }

    // The server gone before its library: the library keeps no pointer to it
    f.server.reset();
    REQUIRE(f.library.add_app(draft_of(absent, "Absent"), bytes("absent")));
}

TEST_CASE("events: a library with no journal has them too, and no apps to list")
{
    const Fixture f(true, 10000, false);
    CHECK(f.get("/", reader).body.contains(R"("changes":0)"));
    CHECK(f.get("/", reader).body.contains(R"("events":1)"));
    // `changes` is not offered without `wait`
    refused(f.get("/changes"), 404, "not_found");

    const auto stream       = f.stream(lea);
    const std::string ready = id_of(step(*stream, 0).text, "event: ready");
    REQUIRE(f.ask(absent, lea).status == 201);
    CHECK(step(*stream, 1).text.contains(R"("status":"open")"));

    const ServerResponse polled = f.get("/changes?since=" + ready + "&wait=0", lea);
    CHECK(polled.status == 200);
    CHECK(polled.body.contains(R"("added":[],"removed":[])"));
    CHECK(polled.body.contains(R"("event":"request")"));
    const ServerResponse held = f.get("/changes?since=" + text_of(polled.body, "since") + "&wait=30", lea);
    CHECK(held.hold_ms == 30'000);
}
