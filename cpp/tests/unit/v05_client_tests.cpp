// Draft 0.5's client, against a transport that answers from memory: the
// event stream's parser and the stream itself, long polling, sync and its
// consent, mirrors and peers, a peer's gate, discovery of peers, deleting an
// account and static libraries. Every name here is made up.
#include <doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
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

constexpr std::string_view handshake_json = R"({"schema":1,"uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14",
    "name":"Living room shelf","base":"/api/lantern","versions":[1],"platforms":["switch"],
    "account":{"state":"active","scopes":["library","saves","sync.read","sync.write","admin"],"bound":false},
    "features":{"library":1,"titles":1,"changes":1,"sections":0,"homebrew":1,"saves":1,"cheats":1,"requests":1,
                "pairing":1,"signatures":1,"admin":1,"events":1,"peers":1,"sync":1,"encrypted_saves":1},
    "auth":{"bearer_only":true,"skew":300},
    "peers":{"key":"FkDVKwFG57y5KAWiHAahZeQ1pO2FxI5AehF/nZjLXq8=","grant_lifetime":600},
    "limits":{"page_size":500,"save_body":1048576,"save_size":1048576,"saves_kept_per_title":10,
              "heartbeat":15,"event_streams":2,"wait":60,"sync_items":10000}})";

constexpr std::string_view vector_grant = "eyJleHAiOjE3OTMzNDYwMDAsInB1cnBvc2UiOiJsYW50ZXJuLWdyYW50LTEiLCJzaG"
                                          "EyNTYiOiIzYTdiZDNlMmI0YzFmMGE5ZThkN2M2YjVhND"
                                          "kzODI3MTYwNWY0ZTNkMmMxYjBhOWY4ZTdkNmM1YjRhMzkyODE3Iiwic2l6ZSI6NzM0"
                                          "MDAzMjAwLCJ1aWQiOiI2ZjFjMmE4ZS00YjdkLTRlMm"
                                          "EtOWMzMS04ZDVlMmYwYTdiMTQifQ.-4SQt-G8QN_sjMzKfaBGDl7b7Z-"
                                          "tW2qHaeC8bSwe70tHH4lVsyhxnMVMrb3r4y3RVBzbhOTeWdP4d6jFjex5Bg";
constexpr std::string_view vector_sha   = "3a7bd3e2b4c1f0a9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a392817";

Answer json_answer(std::string_view body, std::uint16_t status = 200)
{
    Answer a;
    a.status  = status;
    a.headers = { { "Content-Type", "application/json" } };
    a.body    = std::string(body);
    return a;
}

Answer problem_answer(std::uint16_t status, std::string_view code)
{
    Answer a;
    a.status  = status;
    a.headers = { { "Content-Type", "application/problem+json" } };
    a.body    = R"({"schema":1,"title":"Refused","status":)" + std::to_string(status) + R"(,"code":")"
        + std::string(code) + R"("})";
    return a;
}

struct Setup
{
    FakeTransport transport;
    std::optional<Client> client;

    Setup(const Setup&)            = delete;
    Setup& operator=(const Setup&) = delete;

    Setup()
    {
        ClientConfig config;
        config.origin     = "https://shelf.example.org";
        config.user_agent = "LanternTests/0.5";
        config.platform   = "switch";
        auto made         = Client::create(transport, config);
        REQUIRE(made);
        client.emplace(std::move(*made));
        transport.respond = [](const Recorded&) { return json_answer(handshake_json); };
        REQUIRE(client->handshake());
        REQUIRE(client->set_bearer_token("lt_lea-0123456789"));
    }
};

struct Events final : SseHandler
{
    std::vector<std::tuple<std::string, std::string, std::string>> seen;
    std::vector<std::string> comments;
    std::vector<std::uint32_t> retries;
    std::size_t stop_after = SIZE_MAX;
    bool on_event(const SseEvent& event) override
    {
        seen.emplace_back(std::string(event.id), std::string(event.event), std::string(event.data));
        return seen.size() < stop_after;
    }
    bool on_comment(std::string_view text) override
    {
        comments.emplace_back(text);
        return true;
    }
    void on_retry(std::uint32_t ms) override { retries.push_back(ms); }
};

Result<void> feed(SseParser& parser, std::string_view text, SseHandler& handler, std::size_t step)
{
    for (std::size_t i = 0; i < text.size(); i += step)
    {
        const std::string_view piece = text.substr(i, step);
        if (auto fed = parser.feed(std::as_bytes(std::span(piece.data(), piece.size())), handler); !fed)
            return fed;
    }
    return {};
}

struct AppHandler final : EventHandler
{
    std::vector<std::pair<EventKind, std::string>> events;
    unsigned heartbeats    = 0;
    std::size_t stop_after = SIZE_MAX;
    bool on_event(const StreamEvent& event) override
    {
        events.emplace_back(event.kind, std::string(event.data));
        return events.size() < stop_after;
    }
    bool on_heartbeat() override
    {
        ++heartbeats;
        return true;
    }
};

class Collect final : public DownloadSink
{
  public:
    std::string bytes;
    unsigned restarts = 0;
    Result<void> write(std::span<const std::byte> chunk) override
    {
        bytes.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return {};
    }
    Result<void> restart() override
    {
        bytes.clear();
        ++restarts;
        return {};
    }
};

std::string repr_digest(std::string_view body)
{
    const Digest digest = Sha256::of(body);
    String b64;
    base64_encode(digest, b64);
    return "sha-256=:" + std::string(b64) + ":";
}

} // namespace

TEST_CASE("events: the stream's parser, in every cut")
{
    const std::string_view stream
        = "\xEF\xBB\xBFretry: 5000\r\n\r\nid: s_1\nevent: ready\ndata: {\"schema\":1}\n\n"
          ": heartbeat\r\rdata: one\ndata:two\n\nid: s_2\nevent: request\r\n"
          "data: {\"schema\":1}\r\n\r\nid\nevent: x\n\nunknown: field\n\n";
    for (const std::size_t step :
        { std::size_t { 1 }, std::size_t { 2 }, std::size_t { 3 }, std::size_t { 7 }, stream.size() })
    {
        CAPTURE(step);
        SseParser parser;
        Events events;
        REQUIRE(feed(parser, stream, events, step));
        REQUIRE(events.seen.size() == 3);
        CHECK(events.retries == std::vector<std::uint32_t> { 5000 });
        CHECK(events.seen[0]
            == std::make_tuple(std::string("s_1"), std::string("ready"), std::string("{\"schema\":1}")));
        // The id carries over; no event name is "message"; two data lines join
        CHECK(events.seen[1]
            == std::make_tuple(std::string("s_1"), std::string("message"), std::string("one\ntwo")));
        CHECK(events.seen[2]
            == std::make_tuple(std::string("s_2"), std::string("request"), std::string("{\"schema\":1}")));
        CHECK(events.comments == std::vector<std::string> { " heartbeat" });
        // An empty id field sets it empty; an event without data is none
        CHECK(parser.last_event_id().empty());
    }
}

TEST_CASE("events: the parser's bounds, and a handler that stops it")
{
    SseLimits limits;
    limits.max_line = 64;
    limits.max_data = 32;
    {
        SseParser parser({}, limits);
        Events events;
        const std::string line = "data: " + std::string(100, 'x');
        const auto fed         = feed(parser, line, events, 5);
        REQUIRE_FALSE(fed);
        CHECK(fed.error().category() == Category::limit);
        // The error stays
        CHECK_FALSE(feed(parser, "\n\n", events, 1));
    }
    {
        SseParser parser({}, limits);
        Events events;
        const auto fed = feed(parser, "data: 0123456789\ndata: 0123456789\ndata: 0123456789\n\n", events, 4);
        REQUIRE_FALSE(fed);
        CHECK(fed.error().category() == Category::limit);
    }
    {
        SseParser parser;
        Events events;
        events.stop_after = 1;
        REQUIRE(feed(parser, "data: a\n\ndata: b\n\n", events, 1));
        CHECK(parser.stopped());
        CHECK(events.seen.size() == 1);
    }
    SseParser parser;
    Events events;
    REQUIRE(feed(parser, "retry: 12x\nretry: 2500\nid: a\0b\n\n", events, 3));
    CHECK(events.retries == std::vector<std::uint32_t> { 2500 });
}

TEST_CASE("events: the documents of § 18.2's events, and their schema rule")
{
    const auto library
        = read_library_event(R"({"schema":1,"families":["apps","titles"],"platforms":["switch"]})");
    REQUIRE(library);
    REQUIRE(*library);
    CHECK((*library)->families.size() == 2);
    const auto newer = read_library_event(R"({"schema":2,"whatever":true})");
    REQUIRE(newer);
    CHECK_FALSE(*newer);
    CHECK_FALSE(read_library_event(R"({"schema":1,"families":[]})"));
    const auto request
        = read_request_event(R"({"schema":1,"id":"r_7Qm2","platform":"switch","deleted":true})");
    REQUIRE(request);
    REQUIRE(*request);
    CHECK((*request)->deleted);
    CHECK_FALSE(read_request_event(R"({"schema":1,"id":"r_7Qm2"})"));
    const auto sync = read_sync_event(R"({"schema":1,"collection":"wishes","rev":42})");
    REQUIRE(sync);
    REQUIRE(*sync);
    CHECK((*sync)->rev == 42);
    const auto pairing = read_pairing_event(
        R"({"schema":1,"id":"pr_1","code":"KQ4M-7TXD","device":"Lea's Switch","key":"3F9A 1C07 B2E4 55D0","expires":"2026-10-30T09:40:00Z"})");
    REQUIRE(pairing);
    REQUIRE(*pairing);
    CHECK((*pairing)->code == "KQ4M-7TXD");
    const auto save = read_save_event(
        R"({"schema":1,"platform":"switch","title_id":"0100ABCD00010000","save_id":"sv_1"})");
    REQUIRE(save);
    REQUIRE(*save);
    const auto shutdown = read_shutdown_event(R"({"schema":1,"retry":30})");
    REQUIRE(shutdown);
    REQUIRE(*shutdown);
    CHECK((*shutdown)->retry == 30U);
    CHECK(event_kind("library") == EventKind::library);
    CHECK_FALSE(event_kind("message"));
    CHECK(event_kind_name(EventKind::shutdown) == "shutdown");
}

TEST_CASE("events: the stream, resumed from its last id, unknown events and newer schemas ignored")
{
    Setup setup;
    std::string body
        = "retry: 3000\n\nid: s_9f2c01aa_1042\nevent: ready\ndata: {\"schema\":1}\n\n: heartbeat\n\n"
          "id: s_9f2c01aa_1043\nevent: library\ndata: "
          "{\"schema\":1,\"families\":[\"apps\"],\"platforms\":[\"switch\"]}\n\n"
          "id: s_9f2c01aa_1044\nevent: comet\ndata: {\"schema\":1}\n\n"
          "id: s_9f2c01aa_1045\nevent: request\ndata: {\"schema\":2,\"id\":\"r_1\"}\n\n"
          "id: s_9f2c01aa_1046\nevent: shutdown\ndata: {\"schema\":1,\"retry\":30}\n\n";
    setup.transport.respond = [&](const Recorded&)
    {
        Answer a;
        a.headers = { { "Content-Type", "text/event-stream" }, { "Cache-Control", "no-store" } };
        a.body    = body;
        return a;
    };
    EventStreamState state;
    state.set_last_id("s_9f2c01aa_1041");
    state.failures = 2;
    AppHandler handler;
    REQUIRE(setup.client->events(state, handler));
    const Recorded& sent = setup.transport.requests.back();
    CHECK(sent.url == "https://shelf.example.org/api/lantern/v1/events");
    REQUIRE(sent.header("Accept"));
    CHECK(*sent.header("Accept") == "text/event-stream");
    REQUIRE(sent.header("Last-Event-ID"));
    CHECK(*sent.header("Last-Event-ID") == "s_9f2c01aa_1041");
    REQUIRE(handler.events.size() == 3);
    CHECK(handler.events[0].first == EventKind::ready);
    CHECK(handler.events[1].first == EventKind::library);
    CHECK(handler.events[2].first == EventKind::shutdown);
    CHECK(handler.heartbeats == 1);
    // Every event moved the position, the ones ignored too
    CHECK(state.last_id_view() == "s_9f2c01aa_1046");
    CHECK(state.failures == 0);
    CHECK(state.retry_ms == 30000);
    CHECK(state.reconnect_delay().count() == 30000);
    CHECK(setup.client->event_silence_limit().count() == 30);

    // 410: the position is forgotten; a stream that is not one is refused
    setup.transport.respond = [](const Recorded&) { return problem_answer(410, "gone"); };
    const auto gone         = setup.client->events(state, handler);
    REQUIRE_FALSE(gone);
    CHECK(gone.error().effective_code() == Code::gone);
    CHECK(state.last_id_view().empty());
    CHECK(state.failures == 1);
    CHECK(state.reconnect_delay().count() >= 60000);
    setup.transport.respond = [](const Recorded&) { return json_answer(R"({"schema":1})"); };
    CHECK_FALSE(setup.client->events(state, handler));
    CHECK(setup.transport.requests.back().header("Last-Event-ID") == nullptr);
}

TEST_CASE("events: long polling with wait, lowered to the server's limit")
{
    Setup setup;
    setup.transport.respond = [](const Recorded&)
    {
        return json_answer(R"({"schema":1,"added":[],"removed":[],"since":"s_1_5","events":[
            {"id":"s_1_5","event":"sync","data":{"schema":1,"collection":"wishes","rev":3}}]})");
    };
    const auto changes = setup.client->wait_changes("s_1_4", 600);
    REQUIRE(changes);
    REQUIRE(*changes);
    REQUIRE((*changes)->events.size() == 1);
    CHECK((*changes)->events[0].event == "sync");
    const auto sync = read_sync_event((*changes)->events[0].data);
    REQUIRE(sync);
    REQUIRE(*sync);
    CHECK((*sync)->rev == 3);
    CHECK(setup.transport.requests.back().url
        == "https://shelf.example.org/api/lantern/v1/changes?since=s_1_4&wait=60");
    CHECK_FALSE(setup.client->wait_changes("", 30));
}

TEST_CASE("sync: nothing before consent, installed by name, the generation kept, If-Match")
{
    Setup setup;
    setup.transport.respond = [](const Recorded&) { return json_answer("{}"); };
    const auto refused      = setup.client->sync_state();
    REQUIRE_FALSE(refused);
    CHECK(refused.error().category() == Category::refused);
    CHECK(setup.transport.requests.size() == 1); // the handshake alone

    REQUIRE(setup.client->set_sync_consent({ true, false }));
    std::string generation  = "g_4Rz1";
    setup.transport.respond = [&](const Recorded& r)
    {
        if (r.method == "GET" && r.url.ends_with("/v1/sync"))
            return json_answer(R"({"schema":1,"generation":")" + generation
                + R"(","device":"d_3f9a1c07b2e455d0","collections":{"wishes":{"rev":42,"items":12}}})");
        if (r.method == "PATCH")
            return json_answer(R"({"schema":1,"collection":"wishes","generation":"g_4Rz1","rev":43,"items":[
                {"key":"switch/0100ABCD00010000","value":{"platform":"switch","title_id":"0100ABCD00010000"},
                 "updated":"2026-10-30T09:12:03.250Z","rev":43}]})");
        return json_answer(
            R"({"schema":1,"collection":"wishes","generation":"g_4Rz1","rev":42,"items":[],"next":null})");
    };
    const auto state = setup.client->sync_state();
    REQUIRE(state);
    REQUIRE(*state);
    CHECK(setup.client->sync_generation() == "g_4Rz1");
    REQUIRE((*state)->collections.extra.size() == 1);
    CHECK((*state)->collections.extra[0].first == "wishes");

    const auto page = setup.client->sync_items("wishes", 40);
    REQUIRE(page);
    CHECK(setup.transport.requests.back().url
        == "https://shelf.example.org/api/lantern/v1/sync/wishes?since=40");

    SyncItem item;
    item.key           = "switch/0100ABCD00010000";
    item.value         = R"({"platform":"switch","title_id":"0100ABCD00010000"})";
    item.updated       = "2026-10-30T09:12:03.250Z";
    item.rev           = 7; // never sent
    const auto written = setup.client->sync_write("wishes", std::span(&item, 1), 42);
    REQUIRE(written);
    const Recorded& patch = setup.transport.requests.back();
    REQUIRE(patch.header("If-Match"));
    CHECK(*patch.header("If-Match") == "\"g_4Rz1-42\"");
    CHECK(patch.body.find("\"rev\"") == std::string::npos);
    CHECK(patch.body.find("\"generation\":\"g_4Rz1\"") != std::string::npos);

    // installed: by name, and the device's own key only
    SyncItem mine;
    mine.key             = "d_3f9a1c07b2e455d0";
    mine.value           = R"({"device":"Lea's Switch","platform":"switch"})";
    mine.updated         = "2026-10-30T09:12:03Z";
    const auto not_asked = setup.client->sync_write("installed", std::span(&mine, 1));
    REQUIRE_FALSE(not_asked);
    CHECK(not_asked.error().category() == Category::refused);
    REQUIRE(setup.client->set_sync_consent({ true, true }, setup.client->sync_generation()));
    SyncItem other = mine;
    other.key      = "d_0000000000000000";
    CHECK_FALSE(setup.client->sync_write("installed", std::span(&other, 1)));

    // Another generation: the data was deleted; sync turns off
    generation         = "g_new";
    const auto deleted = setup.client->sync_state();
    REQUIRE_FALSE(deleted);
    CHECK(deleted.error().category() == Category::refused);
    CHECK_FALSE(setup.client->sync_consent().sync);
    CHECK(setup.client->sync_generation().empty());

    // 412, as the server says it
    REQUIRE(setup.client->set_sync_consent({ true, false }, "g_4Rz1"));
    setup.transport.respond = [](const Recorded&) { return problem_answer(412, "precondition_failed"); };
    const auto stale        = setup.client->sync_write("wishes", std::span(&item, 1), 41);
    REQUIRE_FALSE(stale);
    CHECK(stale.error().effective_code() == Code::precondition_failed);
    CHECK(setup.client->sync_consent().sync);
    setup.transport.respond = [](const Recorded&) { return problem_answer(409, "conflict"); };
    CHECK_FALSE(setup.client->sync_write("wishes", std::span(&item, 1)));
    CHECK_FALSE(setup.client->sync_consent().sync);
}

TEST_CASE("mirrors: nothing of the server's sent, checked by the server's document, then the server")
{
    Setup setup;
    const std::string file = "Frostline Tales, the whole file";
    const Digest sha       = Sha256::of(file);
    std::map<std::string, std::string> served { { "https://mirror.example.org/frost.nsz",
                                                    "Another file entirely!!!!!!!!!" },
        { "http://192.168.1.20:8000/frost.nsz", file },
        { "https://shelf.example.org/api/lantern/v1/files/f_1", file } };
    setup.transport.respond = [&](const Recorded& r)
    {
        Answer a;
        a.headers = { { "Content-Type", "application/octet-stream" } };
        a.body    = served.at(r.url);
        return a;
    };
    const DownloadTarget target { "/api/lantern/v1/files/f_1", file.size(), sha };
    std::vector<Mirror> mirrors(3);
    mirrors[0].url = "http://203.0.113.9/frost.nsz"; // plain HTTP on a public address: refused
    mirrors[1].url = "https://mirror.example.org/frost.nsz"; // other bytes
    mirrors[2].url = "http://192.168.1.20:8000/frost.nsz";
    DownloadState state;
    Collect sink;
    REQUIRE(setup.client->download_with_mirrors(mirrors, target, state, sink));
    CHECK(sink.bytes == file);
    const std::size_t asked = setup.transport.requests.size();
    REQUIRE(asked == 3); // the handshake, then two mirrors; the public HTTP one never asked
    for (std::size_t i = 1; i < asked; ++i)
    {
        const Recorded& r = setup.transport.requests[i];
        CHECK(r.header("Authorization") == nullptr);
        CHECK(r.header("Lantern-Platform") == nullptr);
        CHECK(r.header("Signature") == nullptr);
        REQUIRE(r.header("User-Agent"));
    }
    // Every mirror failing: the server
    mirrors.resize(2);
    state.reset();
    Collect again;
    REQUIRE(setup.client->download_with_mirrors(mirrors, target, state, again));
    CHECK(again.bytes == file);
    REQUIRE(setup.transport.requests.back().header("Authorization"));
    CHECK(setup.transport.requests.back().url == "https://shelf.example.org/api/lantern/v1/files/f_1");
    // A mirror that says more than the size is stopped at it
    served["https://mirror.example.org/frost.nsz"] = file + "and more";
    state.reset();
    Collect third;
    const auto longer
        = setup.client->download_from_mirror("https://mirror.example.org/frost.nsz", target, state, third);
    REQUIRE_FALSE(longer);
    CHECK(longer.error().category() == Category::integrity);
}

TEST_CASE("peers: a grant asked, then the file from a peer with the grant alone")
{
    Setup setup;
    const std::string file      = "Moss and Ember, a homebrew package";
    const Digest sha            = Sha256::of(file);
    const auto hex              = to_hex(sha);
    const std::string grant_doc = R"({"schema":1,"sha256":")" + std::string(hex.data(), hex.size())
        + R"(","size":)" + std::to_string(file.size()) + R"(,"grant":")" + std::string(vector_grant)
        + R"(","expires":"2026-10-30T09:40:00Z"})";
    setup.transport.respond = [&](const Recorded& r)
    {
        if (r.url.contains("/v1/grants/"))
            return json_answer(grant_doc);
        Answer a;
        a.headers = { { "Content-Type", "application/octet-stream" }, { "Repr-Digest", repr_digest(file) } };
        if (r.method == "HEAD")
            return a;
        a.body = file;
        return a;
    };
    const auto grant = setup.client->grant(sha);
    REQUIRE(grant);
    REQUIRE(*grant);
    CHECK(setup.transport.requests.back().url
        == "https://shelf.example.org/api/lantern/v1/grants/sha256/" + std::string(hex.data(), hex.size()));
    PeerEndpoint peer { "192.168.1.30", 47116, "/lantern", false };
    const auto holds = setup.client->peer_holds(peer, **grant);
    REQUIRE(holds);
    CHECK(*holds);
    DownloadState state;
    Collect sink;
    REQUIRE(setup.client->download_from_peer(peer, **grant, { "", file.size(), sha }, state, sink));
    CHECK(sink.bytes == file);
    const Recorded& asked = setup.transport.requests.back();
    CHECK(asked.url
        == "http://192.168.1.30:47116/lantern/v1/blobs/sha256/" + std::string(hex.data(), hex.size()));
    REQUIRE(asked.header("Lantern-Grant"));
    CHECK(*asked.header("Lantern-Grant") == vector_grant);
    CHECK(asked.header("Authorization") == nullptr);
    // L-19.4-6: no grant over plain HTTP outside a private network
    PeerEndpoint outside { "203.0.113.5", 47116, "/lantern", false };
    CHECK_FALSE(setup.client->peer_holds(outside, **grant));
    PeerEndpoint tls { "203.0.113.5", 47116, "/lantern", true };
    CHECK(peer_blob_url(tls, sha));
    // A grant answered for another file is refused
    setup.transport.respond = [&](const Recorded&) { return json_answer(grant_doc); };
    CHECK_FALSE(setup.client->grant(Digest {}));
    const auto key = grant_key_of(*setup.client->server());
    REQUIRE(key);
}

TEST_CASE("peers: the private networks of § 19.2")
{
    for (const std::string_view host : { "10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.20",
             "fd12:3456::1", "fc00::1", "fe80::1", "fe80::1%eth0", "FE80::abcd" })
    {
        CAPTURE(host);
        CHECK(is_private_host(host));
    }
    for (const std::string_view host : { "8.8.8.8", "172.32.0.1", "192.169.0.1", "127.0.0.1", "2001:db8::1",
             "fec0::1", "shelf.example.org", "10.0.0", "010.0.0.1", "" })
    {
        CAPTURE(host);
        CHECK_FALSE(is_private_host(host));
    }
}

namespace
{

class Held final : public HeldFiles
{
  public:
    std::optional<std::uint64_t> size_of(const Digest& sha256) override
    {
        if (to_hex(sha256) == to_hex(*digest_from_hex(vector_sha)))
            return 734003200;
        return std::nullopt;
    }
};

class Fixed final : public Clock
{
  public:
    std::int64_t now = 1793345400;
    std::int64_t unix_seconds() override { return now; }
};

} // namespace

TEST_CASE("peers: the gate of a console that shares (§ 19.4)")
{
    GrantKey server;
    server.uid = "6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14";
    REQUIRE(base64_decode("FkDVKwFG57y5KAWiHAahZeQ1pO2FxI5AehF/nZjLXq8=", server.key));
    Held held;
    Fixed clock;
    PeerLimits limits;
    limits.slots      = 1;
    limits.per_second = 5;
    PeerGate gate(std::span(&server, 1), held, clock, limits);
    const std::string target = "/lantern/v1/blobs/sha256/" + std::string(vector_sha);
    PeerRequest request { "GET", target, vector_grant, "", "", "192.168.1.40" };

    auto answer = gate.handle(request);
    CHECK(answer.status == 200);
    CHECK(answer.serve);
    CHECK(answer.slot);
    CHECK(answer.length == 734003200);
    const auto headers = answer.headers();
    const auto header  = [&](std::string_view name) -> std::string_view
    {
        for (const Header& h : headers)
        {
            if (h.name == name)
                return h.value;
        }
        return {};
    };
    CHECK(header("Content-Length") == "734003200");
    CHECK(header("ETag") == "\"3a7bd3e2b4c1f0a9e8d7c6b5a4938271\"");
    CHECK(header("Repr-Digest").starts_with("sha-256=:"));
    // One slot: the next download waits
    const auto busy = gate.handle(request);
    CHECK(busy.status == 429);
    gate.release();

    request.range     = "bytes=100-";
    const auto ranged = gate.handle(request);
    CHECK(ranged.status == 206);
    CHECK(ranged.offset == 100);
    gate.release();
    request.range = "bytes=734003200-";
    CHECK(gate.handle(request).status == 416);
    request.range = "";

    // Refused: a global address, another file, an expired grant, sharing off
    clock.now              = 1793345401;
    request.remote_address = "203.0.113.4";
    CHECK(gate.handle(request).status == 403);
    request.remote_address  = "192.168.1.41";
    const std::string other = "/lantern/v1/blobs/sha256/" + std::string(64, '0');
    PeerRequest elsewhere   = request;
    elsewhere.target        = other;
    CHECK(gate.handle(elsewhere).status == 403);
    request.method = "POST";
    CHECK(gate.handle(request).status == 405);
    request.method  = "HEAD";
    const auto head = gate.handle(request);
    CHECK(head.status == 200);
    CHECK_FALSE(head.serve);
    request.method = "GET";
    clock.now      = 1793346001;
    CHECK(gate.handle(request).status == 403);
    clock.now = 1793345402;
    gate.set_enabled(false);
    CHECK(gate.handle(request).status == 403);
    gate.set_enabled(true);
    // A few requests a second per address
    clock.now      = 1793345403;
    request.method = "HEAD";
    for (int i = 0; i < 5; ++i)
        CHECK(gate.handle(request).status == 200);
    auto limited = gate.handle(request);
    CHECK(limited.status == 429);
    CHECK_FALSE(limited.body.empty());
    CHECK(read_problem(limited.body));
}

TEST_CASE("discovery: a peer's reply (§ 19.5)")
{
    CHECK(discovery_request(true) == R"({"schema":1,"lantern":"discover","peers":true})");
    const std::string example = spec_file("examples/v1/discovery-peer.json");
    REQUIRE(!example.empty());
    const auto read = read_peer_datagram(std::as_bytes(std::span(example.data(), example.size())));
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->lantern == "peer");
    CHECK(peer_serves(**read, (*read)->servers.front()));
    for (const char* name : { "examples/v1/invalid/discovery-peer.as-a-server.json",
             "examples/v1/invalid/discovery-peer.no-servers.json",
             "examples/v1/invalid/discovery-peer.too-many-slots.json" })
    {
        CAPTURE(name);
        const std::string bad = spec_file(name);
        REQUIRE(!bad.empty());
        const auto refused = read_peer_datagram(std::as_bytes(std::span(bad.data(), bad.size())));
        CHECK((!refused || !*refused));
    }
    // A server's reply is not a peer's
    const std::string server
        = R"({"schema":1,"lantern":"server","uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14","name":"Shelf","port":8443,"base":"/api/lantern","versions":[1]})";
    CHECK_FALSE(read_peer_datagram(std::as_bytes(std::span(server.data(), server.size()))));
}

TEST_CASE("admin: deleting an account, its name typed again")
{
    Setup setup;
    setup.transport.respond = [](const Recorded&)
    {
        Answer a;
        a.status  = 204;
        a.headers = {};
        return a;
    };
    REQUIRE(setup.client->admin_delete_user("sam", "sam"));
    CHECK(setup.transport.requests.back().method == "DELETE");
    CHECK(setup.transport.requests.back().url
        == "https://shelf.example.org/api/lantern/v1/admin/users/sam?confirm=sam");
    const auto slip = setup.client->admin_delete_user("sam", "san");
    REQUIRE_FALSE(slip);
    CHECK(slip.error().category() == Category::usage);
    setup.transport.respond = [](const Recorded&) { return problem_answer(409, "conflict"); };
    const auto own          = setup.client->admin_delete_user("lea", "lea");
    REQUIRE_FALSE(own);
    CHECK(own.error().effective_code() == Code::conflict);
}

TEST_CASE("saves: an encrypted backup's metadata, only to a server that offers the family")
{
    Setup setup;
    setup.transport.respond = [](const Recorded&)
    {
        return json_answer(R"({"schema":1,"platform":"switch","title_id":"0100ABCD00010000","save_id":"sv_1",
            "created":"2026-10-30T09:00:00Z","size":104,"sha256":"d67e40784c9e5a779481726bf9fd49198e254e763c7bdcafb4e514eef6b12b41",
            "encryption":{"scheme":"lantern-save-e2e-1","key_id":"15d65cfba86a1bce"}})",
            201);
    };
    const std::string archive(104, 'x');
    SaveInfo info;
    info.encryption_key_id = "15d65cfba86a1bce";
    const auto save        = setup.client->upload_save(
        "0100ABCD00010000", std::as_bytes(std::span(archive.data(), archive.size())), info);
    REQUIRE(save);
    REQUIRE(*save);
    REQUIRE((*save)->encryption);
    REQUIRE(setup.transport.requests.back().header("Lantern-Save-Encryption"));
    CHECK(*setup.transport.requests.back().header("Lantern-Save-Encryption")
        == "lantern-save-e2e-1; key_id=15d65cfba86a1bce");
    info.encryption_key_id = "15D65CFBA86A1BCE";
    CHECK_FALSE(setup.client->upload_save(
        "0100ABCD00010000", std::as_bytes(std::span(archive.data(), archive.size())), info));
}

namespace
{

// A static library in memory: path -> bytes.
class MemoryFiles final : public StaticFiles
{
  public:
    std::map<std::string, std::string> files;
    std::vector<std::string> read_paths;
    Result<void> read(std::string_view path, std::uint64_t offset, DownloadSink& sink) override
    {
        read_paths.emplace_back(path);
        const auto found = files.find(std::string(path));
        if (found == files.end())
            return std::unexpected(Error::from_status(404));
        const std::string_view rest
            = std::string_view(found->second).substr(static_cast<std::size_t>(offset));
        return sink.write(std::as_bytes(std::span(rest.data(), rest.size())));
    }
};

std::string app_json(std::string_view id, std::string_view title, std::string_view app_id,
    std::string_view type, std::uint64_t version, std::string_view body)
{
    const auto hex = to_hex(Sha256::of(body));
    return R"({"id":")" + std::string(id) + R"(","platform":"switch","title_id":")" + std::string(title)
        + R"(","app_id":")" + std::string(app_id) + R"(","type":")" + std::string(type)
        + R"(","version_code":)" + std::to_string(version) + R"(,"name":"Frostline Tales","size":)"
        + std::to_string(body.size()) + R"(,"format":"nsp","sha256":")" + std::string(hex.data(), hex.size())
        + R"(","file":"v1/blobs/sha256/)" + std::string(hex.data(), hex.size()) + R"("})";
}

} // namespace

TEST_CASE("static libraries: lantern.json, pages chained by their cursors, files checked, missing computed")
{
    MemoryFiles files;
    files.files["lantern.json"]
        = R"({"schema":1,"uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14","name":"Lea's library",
        "base":".","versions":[1],"platforms":["switch"],"language":"en",
        "account":{"state":"anonymous","scopes":["library"]},
        "features":{"library":1,"titles":1,"homebrew":1,"cheats":0,"changes":0,"sections":0,"saves":0,"encrypted_saves":0,
                    "requests":0,"pairing":0,"signatures":0,"admin":0,"events":0,"peers":0,"sync":0},
        "limits":{"page_size":1},"static":{"generated":"2026-10-30T18:00:00Z","page_size":1}})";
    const std::string base_body = "the base game", update_body = "the update", dlc_body = "an add-on";
    files.files["v1/apps/switch/pages/1.json"] = R"({"schema":1,"items":[)"
        + app_json("a_1", "0100ABCD00010000", "0100ABCD00010000", "base", 0, base_body)
        + R"(],"total":3,"next":"2"})";
    files.files["v1/apps/switch/pages/2.json"] = R"({"schema":1,"items":[)"
        + app_json("a_2", "0100ABCD00010000", "0100ABCD00010800", "update", 131072, update_body)
        + R"(],"total":3,"next":"3"})";
    files.files["v1/apps/switch/pages/3.json"] = R"({"schema":1,"items":[)"
        + app_json("a_3", "0100ABCD00010000", "0100ABCD00011001", "dlc", 0, dlc_body)
        + R"(],"total":3,"next":null})";
    const auto base_hex = to_hex(Sha256::of(base_body));
    files.files["v1/blobs/sha256/" + std::string(base_hex.data(), base_hex.size())] = base_body;

    auto opened = StaticLibrary::open(files);
    REQUIRE(opened);
    REQUIRE(*opened);
    StaticLibrary& library = **opened;
    CHECK(library.handshake().static_->page_size == 1);
    const auto first = library.apps("switch");
    REQUIRE(first);
    REQUIRE(*first);
    CHECK((*first)->next == "2");
    CHECK(library.apps("switch", "2"));
    CHECK_FALSE(library.apps("3ds"));
    CHECK_FALSE(library.apps("switch", "0"));

    // What the console is missing: the update and the add-on of the base it has
    MissingRequest request;
    InstalledApp installed;
    installed.app_id       = "0100ABCD00010000";
    installed.version_code = 0;
    request.installed.push_back(installed);
    request.want       = { "update", "dlc", "base" };
    const auto missing = library.missing("switch", request);
    REQUIRE(missing);
    REQUIRE(missing->size() == 2);
    CHECK((*missing)[0].type == "update");
    CHECK((*missing)[1].type == "dlc");
    request.installed.clear();
    const auto everything = library.missing("switch", request);
    REQUIRE(everything);
    REQUIRE(everything->size() == 1);
    CHECK((*everything)[0].type == "base");

    // A file, checked; one that lies, refused
    DownloadState state;
    Collect sink;
    const App& base = (*first)->items.front();
    REQUIRE(library.download({ base.file, base.size, base.sha256 }, state, sink));
    CHECK(sink.bytes == base_body);
    files.files["v1/blobs/sha256/" + std::string(base_hex.data(), base_hex.size())] = "the base gamX";
    state.reset();
    const auto lied = library.download({ base.file, base.size, base.sha256 }, state, sink);
    REQUIRE_FALSE(lied);
    CHECK(lied.error().category() == Category::integrity);
    CHECK_FALSE(library.download({ "/etc/passwd", 1, base.sha256 }, state, sink));

    // A title without cheat sets has no file of them: none
    const auto cheats = library.cheats("switch", "0100ABCD00010000");
    REQUIRE(cheats);
    REQUIRE(*cheats);
    CHECK((*cheats)->cheats.empty());
    CHECK_FALSE(library.title("switch", ".."));

    // A page whose next is not the page after it, and an absolute file
    files.files["v1/apps/switch/pages/1.json"] = R"({"schema":1,"items":[],"total":3,"next":"5"})";
    CHECK_FALSE(library.apps("switch"));
    std::string absolute = app_json("a_1", "0100ABCD00010000", "0100ABCD00010000", "base", 0, base_body);
    absolute.replace(absolute.find("\"file\":\"") + 8, 0, "/");
    files.files["v1/apps/switch/pages/1.json"]
        = R"({"schema":1,"items":[)" + absolute + R"(],"total":3,"next":null})";
    CHECK_FALSE(library.apps("switch"));

    // A server's handshake is not a static library's, nor one with families it cannot offer
    files.files["lantern.json"] = std::string(handshake_json);
    CHECK_FALSE(StaticLibrary::open(files));
}
