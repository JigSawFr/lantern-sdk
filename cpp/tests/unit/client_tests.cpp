#include <doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "support.hpp"

using namespace lantern;
using lantern::test::Answer;
using lantern::test::FakeTransport;
using lantern::test::Recorded;
using lantern::test::spec_file;

namespace
{

constexpr std::string_view handshake_json = R"({"schema":1,"uid":"6f1c2a8e-0000-4000-8000-000000000001",
    "name":"Living room shelf","base":"/api/lantern","versions":[1],"platforms":["switch"],
    "account":{"state":"active","scopes":["library","cheats"]},
    "features":{"library":2,"titles":1,"changes":1,"sections":0,"homebrew":1,"saves":0,"cheats":1,"requests":0,
                "pairing":1,"x-example":3}})";

constexpr std::string_view origin = "https://shelf.example.org";

ClientConfig config()
{
    ClientConfig c;
    c.origin          = origin;
    c.user_agent      = "LanternTests/0.3";
    c.platform        = "switch";
    c.accept_language = "fr, en;q=0.5";
    return c;
}

Answer ok_json(std::string_view body, std::uint16_t status = 200)
{
    Answer a;
    a.status = status;
    a.body   = std::string(body);
    return a;
}

Answer problem(std::uint16_t status, std::string_view body)
{
    Answer a;
    a.status  = status;
    a.headers = { { "Content-Type", "application/problem+json" } };
    a.body    = std::string(body);
    return a;
}

Client connected(FakeTransport& transport)
{
    auto client = Client::create(transport, config());
    REQUIRE(client);
    auto shake = client->handshake();
    REQUIRE(shake);
    REQUIRE(*shake);
    return std::move(*client);
}

} // namespace

TEST_CASE("client: the configuration")
{
    FakeTransport transport;
    CHECK(Client::create(transport, config()));
    auto c   = config();
    c.origin = "http://shelf.example.org";
    CHECK_FALSE(Client::create(transport, c)); // plain HTTP off loopback (SPEC.md 2)
    c.origin = "http://127.0.0.1:8080";
    CHECK(Client::create(transport, c));
    c.origin = "http://[::1]:8080";
    CHECK(Client::create(transport, c));
    c.origin = "http://localhost:8080";
    CHECK_FALSE(Client::create(transport, c)); // a name, not an address
    c.origin = "https://shelf.example.org/api/lantern";
    CHECK_FALSE(Client::create(transport, c));
    c            = config();
    c.user_agent = "Lantern Tests";
    CHECK_FALSE(Client::create(transport, c));
    c          = config();
    c.platform = "Switch";
    CHECK_FALSE(Client::create(transport, c));
    c                 = config();
    c.accept_language = "fr\r\nX-Evil: 1";
    CHECK_FALSE(Client::create(transport, c));
}

TEST_CASE("client: the handshake, then a listing, with every header SPEC.md asks")
{
    FakeTransport transport;
    transport.respond = [](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        return ok_json(spec_file("examples/v1/apps.json"));
    };
    auto client = Client::create(transport, config());
    REQUIRE(client);
    CHECK_FALSE(client->apps()); // no handshake yet
    CHECK(transport.requests.empty());
    REQUIRE(client->handshake());
    CHECK(client->offers(Family::library) == 2);
    CHECK(client->offers(Family::saves) == 0);
    REQUIRE(client->set_bearer_token("et_Zk81Qp-fictional"));

    AppsQuery query;
    query.type      = "update";
    query.q         = "Frostline Tales & co";
    query.page_size = 50;
    query.cursor    = "c_VRe3N9v8";
    const auto page = client->apps(query);
    REQUIRE(page);
    REQUIRE(*page);
    CHECK_FALSE((*page)->items.empty());

    REQUIRE(transport.requests.size() == 2);
    const Recorded& shake = transport.requests[0];
    CHECK(shake.url == "https://shelf.example.org/.well-known/lantern");
    CHECK(shake.header("Authorization") == nullptr);
    const Recorded& list = transport.requests[1];
    CHECK(list.method == "GET");
    CHECK(list.url
        == "https://shelf.example.org/api/lantern/v1/"
           "apps?type=update&q=Frostline%20Tales%20%26%20co&page_size=50&cursor=c_VRe3N9v8");
    CHECK(*list.header("User-Agent") == "LanternTests/0.3");
    CHECK(*list.header("Lantern-Platform") == "switch");
    CHECK(*list.header("Accept-Language") == "fr, en;q=0.5");
    CHECK(*list.header("Authorization") == "Bearer et_Zk81Qp-fictional");
    // The server writes library at schema 2: the client asks for 1 (SPEC.md 3.2)
    CHECK(*list.header("Accept-Schema") == "library=1");
}

TEST_CASE("client: a family the server does not offer is not asked for")
{
    FakeTransport transport;
    transport.respond   = [](const Recorded&) { return ok_json(handshake_json); };
    Client client       = connected(transport);
    const auto sections = client.sections();
    REQUIRE_FALSE(sections);
    CHECK(sections.error().category() == Category::unsupported);
    CHECK(transport.requests.size() == 1);
}

TEST_CASE("client: a handshake of a newer schema is absent")
{
    FakeTransport transport;
    transport.respond = [](const Recorded&) { return ok_json(R"({"schema":2,"base":42})"); };
    auto client       = Client::create(transport, config());
    REQUIRE(client);
    const auto shake = client->handshake();
    REQUIRE(shake);
    CHECK_FALSE(shake->has_value());
    CHECK(client->server() == nullptr);
    CHECK_FALSE(client->apps());
}

TEST_CASE("client: errors are problem+json, read by their code or their status")
{
    FakeTransport transport;
    Answer next;
    transport.respond = [&](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        return next;
    };
    Client client = connected(transport);

    next      = problem(403, spec_file("examples/v1/problem.json"));
    auto read = client.apps();
    REQUIRE_FALSE(read);
    CHECK(read.error().category() == Category::protocol);
    CHECK(read.error().status() == 403);
    CHECK(read.error().code() == Code::account_frozen);
    CHECK(read.error().effective_code() == Code::account_frozen);
    CHECK_FALSE(read.error().detail().empty());

    // A code of a later version: acted on by the status
    next = problem(429, R"({"schema":1,"status":429,"code":"too_eager","detail":"Easy\nnow"})");
    next.headers.emplace_back("Retry-After", "30");
    read = client.apps();
    REQUIRE_FALSE(read);
    CHECK(read.error().code() == Code::unknown);
    CHECK(read.error().code_text() == "too_eager");
    CHECK(read.error().effective_code() == Code::slow_down);
    CHECK(read.error().retry_after() == 30);
    CHECK(read.error().detail() == "Easy now"); // no control character

    // A problem of a newer schema, or no problem at all: the status alone
    next = problem(410, R"({"schema":9,"code":"gone"})");
    read = client.apps();
    REQUIRE_FALSE(read);
    CHECK(read.error().code() == Code::none);
    CHECK(read.error().effective_code() == Code::gone);
    next = Answer { 503, { { "Content-Type", "text/html" } }, "<h1>Down</h1>" };
    read = client.apps();
    REQUIRE_FALSE(read);
    CHECK(read.error().effective_code() == Code::unavailable);

    // A success that is not JSON, or not a document
    next = Answer { 200, { { "Content-Type", "text/plain" } }, "{}" };
    CHECK(client.apps().error().category() == Category::invalid_response);
    next = ok_json(R"({"schema":1,"items":[],"next":null})");
    CHECK(client.apps());
    next = ok_json(R"({"items":[],"next":null})");
    CHECK(client.apps().error().category() == Category::invalid_response);
}

TEST_CASE("client: a document beyond the limits")
{
    FakeTransport transport;
    std::string big   = R"({"schema":1,"next":null,"items":[],"pad":")" + std::string(5000, 'x') + "\"}";
    transport.respond = [&](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        return ok_json(big);
    };
    auto c                       = config();
    c.decode.limits.max_document = 4096;
    auto client                  = Client::create(transport, c);
    REQUIRE(client);
    REQUIRE(client->handshake());
    const auto read = client->apps();
    REQUIRE_FALSE(read);
    CHECK(read.error().category() == Category::limit);
}

TEST_CASE("client: what is missing, titles and homebrew updates")
{
    FakeTransport transport;
    transport.respond = [](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        if (r.url.find("/titles?") != std::string::npos)
            return ok_json(spec_file("examples/v1/titles.json"));
        if (r.url.find("/homebrew/updates") != std::string::npos)
            return ok_json(spec_file("examples/v1/homebrew-page.json"));
        return ok_json(spec_file("examples/v1/apps.json"));
    };
    Client client = connected(transport);

    MissingRequest missing;
    missing.installed.emplace_back();
    missing.installed.back().app_id = "0100ABCD00010000";
    missing.want.emplace_back("update");
    REQUIRE(client.missing(missing, "c_1"));
    const Recorded& post = transport.requests.back();
    CHECK(post.method == "POST");
    CHECK(post.url == "https://shelf.example.org/api/lantern/v1/apps/missing?cursor=c_1");
    CHECK(*post.header("Content-Type") == "application/json");
    CHECK(post.body
        == R"({"schema":1,"installed":[{"app_id":"0100ABCD00010000","version_code":0}],"want":["update"]})");

    const std::array<std::string_view, 2> ids { "0100ABCD00010000", "0100EFEF00020000" };
    REQUIRE(client.titles(ids));
    CHECK(transport.requests.back().url
        == "https://shelf.example.org/api/lantern/v1/titles?ids=0100ABCD00010000,0100EFEF00020000");
    CHECK_FALSE(client.titles(std::span<const std::string_view> {}));
    const std::array<std::string_view, 1> bad { "a/b" };
    CHECK_FALSE(client.titles(bad));
    CHECK_FALSE(client.title("changes"));

    HomebrewUpdatesRequest updates;
    updates.installed.emplace_back();
    updates.installed.back().id    = "org.example.frostline";
    updates.installed.back().build = 10300;
    REQUIRE(client.homebrew_updates(updates, {}, "3ds"));
    CHECK(transport.requests.back().url
        == "https://shelf.example.org/api/lantern/v1/homebrew/updates?platform=3ds");
    CHECK_FALSE(client.homebrew_entry("not an id"));
}

namespace
{

// A file of the server's, served as SPEC.md 6.6 says: ranges, Repr-Digest,
// a strong ETag.
struct FileServer
{
    std::string data;
    bool ignore_range       = false;
    bool lie_about_digest   = false;
    std::size_t cut_after   = std::string::npos;
    std::size_t extra_bytes = 0;

    Answer serve(const Recorded& r) const
    {
        Answer a;
        a.headers.clear();
        String digest;
        format_digest_field(lie_about_digest ? Sha256::of("other") : Sha256::of(data), digest);
        a.headers.emplace_back("Repr-Digest", std::string(digest));
        a.headers.emplace_back("ETag", "\"v1\"");
        a.headers.emplace_back("Accept-Ranges", "bytes");
        std::size_t from = 0;
        if (const std::string* range = r.header("Range"); range != nullptr && !ignore_range)
        {
            from     = std::stoul(range->substr(6));
            a.status = 206;
            a.headers.emplace_back("Content-Range",
                "bytes " + std::to_string(from) + "-" + std::to_string(data.size() - 1) + "/"
                    + std::to_string(data.size()));
        }
        a.body = data.substr(from) + std::string(extra_bytes, '!');
        a.headers.emplace_back("Content-Length", std::to_string(a.body.size()));
        a.cut_after = cut_after;
        return a;
    }
};

class FileSink final : public DownloadSink
{
  public:
    std::string bytes;
    int restarts = 0;
    Result<void> write(std::span<const std::byte> chunk) override
    {
        bytes.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return {};
    }
    Result<void> restart() override
    {
        ++restarts;
        bytes.clear();
        return {};
    }
};

} // namespace

TEST_CASE("downloads: verified as they stream, resumed with Range")
{
    FileServer server;
    for (int i = 0; i < 3000; ++i)
        server.data += static_cast<char>('a' + i % 26);
    FakeTransport transport;
    transport.respond = [&](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        return server.serve(r);
    };
    Client client = connected(transport);
    REQUIRE(client.set_bearer_token("et_fictional"));
    const DownloadTarget target { "/api/lantern/v1/files/f_Zk81Qp", server.data.size(),
        Sha256::of(server.data) };

    // Cut after 1000 bytes: an error, but what came is kept
    DownloadState state;
    FileSink sink;
    server.cut_after = 1000;
    const auto cut   = client.download(target, state, sink);
    REQUIRE_FALSE(cut);
    CHECK(cut.error().category() == Category::transport);
    CHECK(state.received == 1000);
    CHECK(sink.bytes.size() == 1000);
    CHECK(state.etag_view() == "\"v1\"");

    // Resumed: only the rest is asked, with If-Range
    server.cut_after = std::string::npos;
    REQUIRE(client.download(target, state, sink));
    CHECK(sink.bytes == server.data);
    const Recorded& resumed = transport.requests.back();
    CHECK(resumed.url == "https://shelf.example.org/api/lantern/v1/files/f_Zk81Qp");
    CHECK(*resumed.header("Range") == "bytes=1000-");
    CHECK(*resumed.header("If-Range") == "\"v1\"");
    CHECK(*resumed.header("Authorization") == "Bearer et_fictional");

    // The server ignores the range: the sink starts over
    DownloadState again;
    FileSink again_sink;
    server.cut_after = 500;
    CHECK_FALSE(client.download(target, again, again_sink));
    server.cut_after    = std::string::npos;
    server.ignore_range = true;
    REQUIRE(client.download(target, again, again_sink));
    CHECK(again_sink.restarts == 1);
    CHECK(again_sink.bytes == server.data);
}

TEST_CASE("downloads: nothing is done until the digest matches")
{
    FileServer server;
    server.data = "Frostline Tales, fictional bytes";
    FakeTransport transport;
    transport.respond = [&](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        return server.serve(r);
    };
    Client client = connected(transport);

    // The listing's sha256 is not the file's
    DownloadState state;
    FileSink sink;
    const DownloadTarget wrong { "/f", server.data.size(), Sha256::of("another file") };
    auto done = client.download(wrong, state, sink);
    REQUIRE_FALSE(done);
    CHECK(done.error().category() == Category::integrity);
    CHECK(state.received == 0); // reset: the app throws the bytes away

    // Repr-Digest says another file: stopped before the first byte is kept
    const DownloadTarget target { "/f", server.data.size(), Sha256::of(server.data) };
    server.lie_about_digest = true;
    FileSink untouched;
    done = client.download(target, state, untouched);
    REQUIRE_FALSE(done);
    CHECK(done.error().category() == Category::integrity);
    CHECK(untouched.bytes.empty());
    server.lie_about_digest = false;

    // More bytes than the listing's size
    server.extra_bytes = 4;
    done               = client.download(target, state, sink);
    REQUIRE_FALSE(done);
    CHECK(done.error().category() == Category::integrity);
    server.extra_bytes = 0;

    // Fine
    FileSink good;
    DownloadState fresh;
    CHECK(client.download(target, fresh, good));
    CHECK(good.bytes == server.data);
}

TEST_CASE("downloads: tokens go to the server's origin only (SPEC.md 2)")
{
    FakeTransport transport;
    transport.respond = [](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        Answer a;
        a.headers = {};
        a.body    = "x";
        return a;
    };
    Client client = connected(transport);
    REQUIRE(client.set_bearer_token("et_fictional"));
    DownloadState state;
    MemorySink sink(16);
    REQUIRE(client.download({ "https://cdn.example.org/f_1", 1, Sha256::of("x") }, state, sink));
    CHECK(transport.requests.back().header("Authorization") == nullptr);
    // Plain HTTP elsewhere than loopback: refused before anything is sent
    const std::size_t sent = transport.requests.size();
    DownloadState other;
    CHECK_FALSE(client.download({ "http://cdn.example.org/f_1", 1, Sha256::of("x") }, other, sink));
    CHECK(transport.requests.size() == sent);
    // A token that could break a header
    CHECK_FALSE(client.set_bearer_token("et_x\r\nX-Evil: 1"));
    CHECK_FALSE(client.set_bearer_token(""));
}

TEST_CASE("client: a cheat set's text, checked")
{
    const std::string text = "[Endless lamp oil]\n04000000 0123A4B0 00000063\n";
    FakeTransport transport;
    transport.respond = [&](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        Answer a;
        a.headers = { { "Content-Type", "text/plain" } };
        a.body    = text;
        return a;
    };
    Client client = connected(transport);
    CheatSet set;
    set.id         = "cs_1";
    set.size       = text.size();
    set.sha256     = Sha256::of(text);
    const auto got = client.cheat_text(set);
    REQUIRE(got);
    CHECK(std::string_view(*got) == text);
    CHECK(transport.requests.back().url == "https://shelf.example.org/api/lantern/v1/cheats/cs_1");
    set.sha256 = Sha256::of("another");
    CHECK_FALSE(client.cheat_text(set));
    set.size = 2 * 1024 * 1024;
    CHECK(client.cheat_text(set).error().category() == Category::limit);
}

namespace
{

class RecordingSigner final : public RequestSigner
{
  public:
    std::string method;
    std::string path;
    std::string authority;
    std::optional<Digest> digest;
    std::size_t headers = 0;

    Result<void> sign(const SigningInput& input, HeaderSink& sink) override
    {
        method    = std::string(input.method);
        path      = std::string(input.path);
        authority = std::string(input.authority);
        digest    = input.content_digest;
        headers   = input.headers.size();
        return sink.add("Signature-Input", "sig1=(\"@method\" \"@path\");keyid=\"device\"");
    }
};

} // namespace

TEST_CASE("client: the request signer hook (draft 0.4)")
{
    FakeTransport transport;
    transport.respond = [](const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return ok_json(handshake_json);
        return ok_json(spec_file("examples/v1/homebrew-page.json"));
    };
    RecordingSigner signer;
    auto c      = config();
    c.signer    = &signer;
    auto client = Client::create(transport, c);
    REQUIRE(client);
    REQUIRE(client->handshake());
    HomebrewUpdatesRequest updates;
    REQUIRE(client->homebrew_updates(updates));
    CHECK(signer.method == "POST");
    CHECK(signer.path == "/api/lantern/v1/homebrew/updates");
    CHECK(signer.authority == "shelf.example.org");
    REQUIRE(signer.digest);
    CHECK(*signer.digest == Sha256::of(transport.requests.back().body));
    CHECK(signer.headers >= 4);
    CHECK(transport.requests.back().header("Signature-Input") != nullptr);
}
