// The client of draft 0.4, against a transport that answers from memory:
// signed requests and their 401s, the clock's correction, the server's key
// at pairing, pairing and its polls, a resumable upload's conflicts,
// Deprecation, and discovery. Every name here is made up.
#include <doctest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
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

constexpr std::string_view handshake_json = R"({"schema":1,"uid":"6f1c2a8e-0000-4000-8000-000000000001",
    "name":"Living room shelf","base":"/api/lantern","versions":[1],"platforms":["switch"],
    "account":{"state":"active","scopes":["library","saves","admin"],"bound":true},
    "features":{"library":1,"titles":1,"changes":1,"sections":0,"homebrew":1,"saves":1,"cheats":1,"requests":1,
                "pairing":1,"signatures":1,"admin":1},
    "auth":{"bearer_only":false,"skew":300},
    "limits":{"page_size":500,"save_body":64,"save_size":1048576,"saves_kept_per_title":10}})";

constexpr std::string_view server_date = "Fri, 30 Oct 2026 16:00:00 GMT";
constexpr std::int64_t server_time     = 1793376000;

class CountingRandom final : public RandomSource
{
  public:
    std::uint8_t next = 1;
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        for (auto& byte : out)
            byte = next++;
        return {};
    }
};

class FixedClock final : public Clock
{
  public:
    std::int64_t now = server_time;
    std::int64_t unix_seconds() override { return now; }
};

Answer json_answer(std::string_view body, std::uint16_t status = 200)
{
    Answer a;
    a.status  = status;
    a.headers = { { "Content-Type", "application/json" }, { "Date", std::string(server_date) } };
    a.body    = std::string(body);
    return a;
}

Answer problem_answer(
    std::uint16_t status, std::string_view code, std::vector<std::pair<std::string, std::string>> extra = {})
{
    Answer a;
    a.status  = status;
    a.headers = { { "Content-Type", "application/problem+json" }, { "Date", std::string(server_date) } };
    for (auto& header : extra)
        a.headers.push_back(std::move(header));
    a.body = R"({"schema":1,"title":"Refused","status":)" + std::to_string(status) + R"(,"code":")"
        + std::string(code) + R"(","detail":"The server's own words."})";
    return a;
}

Answer status_answer(std::uint16_t status, std::vector<std::pair<std::string, std::string>> headers = {})
{
    Answer a;
    a.status  = status;
    a.headers = std::move(headers);
    return a;
}

struct Setup
{
    FakeTransport transport;
    CountingRandom random;
    FixedClock clock;
    ServerTrust trust;
    std::optional<Client> client;

    Setup(const Setup&)            = delete;
    Setup& operator=(const Setup&) = delete;

    explicit Setup(bool with_trust = false)
    {
        ClientConfig config;
        config.origin     = "https://shelf.example.org";
        config.user_agent = "LanternTests/0.4";
        config.platform   = "switch";
        config.random     = &random;
        config.clock      = &clock;
        if (with_trust)
            config.trust = &trust;
        auto made = Client::create(transport, config);
        REQUIRE(made);
        client.emplace(std::move(*made));
    }

    void shake()
    {
        auto previous     = transport.respond;
        transport.respond = [](const Recorded&) { return json_answer(handshake_json); };
        REQUIRE(client->handshake());
        transport.respond = previous;
    }
};

const DeviceKey& lea_key()
{
    static const DeviceKey key = DeviceKey::from_seed(KeySeed { 7, 7, 7 });
    return key;
}

} // namespace

TEST_CASE("client: a bound token's requests are signed, to the server's origin alone")
{
    Setup s;
    s.shake();
    REQUIRE(s.client->set_credentials("et_Zk81Qp-fictional", lea_key()));
    s.transport.respond = [](const Recorded& r)
    {
        if (r.url.ends_with("/apps"))
            return json_answer(spec_file("examples/v1/apps.json"));
        Answer file = status_answer(200, { { "Content-Length", "3" } });
        file.body   = "abc";
        return file;
    };
    REQUIRE(s.client->apps());
    const Recorded& list = s.transport.requests.back();
    REQUIRE(list.header("Signature-Input") != nullptr);
    CHECK(
        list.header("Signature-Input")
            ->starts_with(R"(lantern=("@method" "@target-uri" "authorization");created=1793376000;nonce=")"));
    CHECK(list.header("Signature")->starts_with("lantern=:"));
    CHECK(list.header("Content-Digest") == nullptr);
    // The signature verifies as a server checks it
    SignatureCheck check;
    check.method          = "GET";
    check.target_uri      = "https://shelf.example.org/api/lantern/v1/apps";
    check.authorization   = *list.header("Authorization");
    check.signature_input = *list.header("Signature-Input");
    check.signature       = *list.header("Signature");
    check.key             = lea_key().public_key();
    check.now             = server_time;
    CHECK(check_signature(check).code == Code::none);

    // A file elsewhere: neither the token nor a signature goes there (SPEC.md 2)
    const DownloadTarget elsewhere { "https://cdn.example.org/f/abc", 3,
        Sha256::of(std::string_view("abc")) };
    DownloadState state;
    MemorySink sink(16);
    REQUIRE(s.client->download(elsewhere, state, sink));
    const Recorded& file = s.transport.requests.back();
    CHECK(file.header("Authorization") == nullptr);
    CHECK(file.header("Signature-Input") == nullptr);

    // A body carries its Content-Digest, covered
    MissingRequest missing;
    missing.want.emplace_back("update");
    s.transport.respond = [](const Recorded&) { return json_answer(spec_file("examples/v1/apps.json")); };
    REQUIRE(s.client->missing(missing));
    const Recorded& post = s.transport.requests.back();
    REQUIRE(post.header("Content-Digest") != nullptr);
    String digest;
    format_digest_field(Sha256::of(post.body), digest);
    CHECK(*post.header("Content-Digest") == std::string_view(digest));
    CHECK(post.header("Signature-Input")->find(R"("authorization" "content-digest")") != std::string::npos);

    // Signing needs a random source
    FakeTransport other;
    ClientConfig config;
    config.origin     = "https://shelf.example.org";
    config.user_agent = "LanternTests/0.4";
    auto no_random    = Client::create(other, config);
    REQUIRE(no_random);
    CHECK_FALSE(no_random->set_credentials("et_Zk81Qp-fictional", lea_key()));
    CHECK_FALSE(no_random->has_token());
}

TEST_CASE("client: a signature refused as expired is signed again with the server's Date, once")
{
    Setup s;
    s.shake();
    CHECK(s.client->clock_offset() == 0);
    REQUIRE(s.client->set_credentials("et_Zk81Qp-fictional", lea_key()));
    s.clock.now         = server_time - 3600; // the console's clock went back an hour
    int calls           = 0;
    s.transport.respond = [&](const Recorded& r)
    {
        ++calls;
        const std::string& input = *r.header("Signature-Input");
        if (input.find("created=1793372400;") != std::string::npos)
            return problem_answer(401, "signature_expired");
        return json_answer(spec_file("examples/v1/apps.json"));
    };
    REQUIRE(s.client->apps());
    CHECK(calls == 2);
    CHECK(s.client->clock_offset() == 3600);
    // Each try has its own nonce
    const auto nonce = [](const Recorded& r)
    {
        const std::string& input = *r.header("Signature-Input");
        return input.substr(input.find("nonce="), 30);
    };
    const std::size_t n = s.transport.requests.size();
    CHECK(nonce(s.transport.requests[n - 1]) != nonce(s.transport.requests[n - 2]));

    // Refused twice: the second 401 is the answer
    calls               = 0;
    s.transport.respond = [&](const Recorded&)
    {
        ++calls;
        return problem_answer(401, "signature_expired");
    };
    const auto page = s.client->apps();
    REQUIRE_FALSE(page);
    CHECK(calls == 2);
    CHECK(page.error().code() == Code::signature_expired);

    // A 401 of another kind is not tried again, and says what to do
    calls               = 0;
    s.transport.respond = [&](const Recorded&)
    {
        ++calls;
        return problem_answer(401, "signature_invalid",
            { { "Accept-Signature",
                R"(lantern=("@method" "@target-uri" "authorization");keyid="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";alg="ed25519")" } });
    };
    const auto other = s.client->apps();
    REQUIRE_FALSE(other);
    CHECK(calls == 1);
    CHECK(other.error().code() == Code::signature_invalid);
    CHECK(other.error().detail().find("another device key") != std::string_view::npos);
}

TEST_CASE("client: a bearer token the server binds to a key it does not have")
{
    Setup s;
    s.shake();
    REQUIRE(s.client->set_bearer_token("et_Zk81Qp-fictional"));
    s.transport.respond = [](const Recorded& r)
    {
        CHECK(r.header("Signature-Input") == nullptr);
        return problem_answer(401, "signature_required");
    };
    const auto page = s.client->apps();
    REQUIRE_FALSE(page);
    CHECK(page.error().code() == Code::signature_required);
    CHECK(page.error().detail().find("pair again") != std::string_view::npos);
    CHECK(s.transport.requests.size() == 2); // the handshake, and this one: no retry
}

TEST_CASE("client: Deprecation goes to the app's log (3.4)")
{
    struct Log final : DeprecationLog
    {
        std::vector<std::string> seen;
        void deprecated(std::string_view url, std::string_view deprecation, std::string_view sunset) override
        {
            seen.push_back(std::string(url) + " " + std::string(deprecation) + " " + std::string(sunset));
        }
    } log;
    FakeTransport transport;
    ClientConfig config;
    config.origin       = "https://shelf.example.org";
    config.user_agent   = "LanternTests/0.4";
    config.deprecations = &log;
    auto client         = Client::create(transport, config);
    REQUIRE(client);
    transport.respond = [](const Recorded&)
    {
        Answer a = json_answer(handshake_json);
        a.headers.emplace_back("Deprecation", "@1793318400");
        a.headers.emplace_back("Sunset", "Sun, 01 Aug 2027 00:00:00 GMT");
        return a;
    };
    REQUIRE(client->handshake());
    REQUIRE(log.seen.size() == 1);
    CHECK(log.seen[0]
        == "https://shelf.example.org/.well-known/lantern @1793318400 Sun, 01 Aug 2027 00:00:00 GMT");
}

TEST_CASE("pairing: the server's key seen, shown, pinned; the polls signed; the token kept")
{
    Setup s(true);
    s.trust.allow_unverified();
    s.shake();
    // The transport saw the server's certificate while the client asked
    const Digest spki   = Sha256::of(std::string_view("the server's SubjectPublicKeyInfo"));
    s.transport.respond = [&](const Recorded& r)
    {
        CHECK(r.header("Authorization") == nullptr);
        const std::string_view seen = "the server's SubjectPublicKeyInfo";
        static_cast<void>(s.trust.accept(
            std::span(reinterpret_cast<const std::uint8_t*>(seen.data()), seen.size()), false));
        const std::string body = spec_file("examples/v1/pairing-code.json");
        return json_answer(body);
    };
    const std::array<std::string_view, 2> scopes { "library", "saves" };
    PairingOptions options;
    options.device = "Lea's Switch";
    options.scopes = scopes;
    auto pairing   = s.client->start_pairing(options);
    REQUIRE(pairing);
    REQUIRE(pairing->key);
    REQUIRE(pairing->spki);
    CHECK(same_digest(*pairing->spki, spki));
    const auto short_text = short_form(spki);
    CHECK(pairing->fingerprint_view() == std::string_view(short_text.data(), short_text.size()));
    CHECK(s.trust.mode() == ServerTrust::Mode::pinned); // the polls go over that key alone
    const Recorded& asked = s.transport.requests.back();
    CHECK(asked.method == "POST");
    CHECK(asked.body.find(R"("key":{"alg":"ed25519","public_key":")") != std::string::npos);
    CHECK(asked.header("Signature-Input") == nullptr);

    int polls           = 0;
    s.transport.respond = [&](const Recorded& r)
    {
        ++polls;
        CHECK(r.header("Authorization") == nullptr);
        REQUIRE(r.header("Signature-Input") != nullptr);
        CHECK(r.header("Signature-Input")->starts_with(R"(lantern=("@method" "@target-uri");)"));
        if (polls == 1)
            return status_answer(202);
        if (polls == 2)
            return problem_answer(429, "slow_down", { { "Retry-After", "20" } });
        return json_answer(
            R"({"schema":1,"token":"et_Lea-fictional-token","scopes":["library"],"bound":true})");
    };
    struct Store final : CredentialStore
    {
        std::optional<Credentials> kept;
        std::string uid;
        Result<std::optional<Credentials>> load(std::string_view, Allocator) override { return kept; }
        Result<void> store(std::string_view id, const Credentials& credentials) override
        {
            uid  = std::string(id);
            kept = credentials;
            return {};
        }
        Result<void> erase(std::string_view) override
        {
            kept.reset();
            return {};
        }
    } store;
    CHECK(s.client->poll_pairing(*pairing, &store) == PollState::waiting);
    CHECK(s.client->poll_pairing(*pairing, &store) == PollState::waiting);
    CHECK(pairing->wait == 20);
    CHECK(s.client->poll_pairing(*pairing, &store) == PollState::paired);
    CHECK(s.client->has_token());
    REQUIRE(store.kept);
    CHECK(store.uid == "6f1c2a8e-0000-4000-8000-000000000001");
    CHECK(store.kept->token == "et_Lea-fictional-token");
    REQUIRE(store.kept->key);
    CHECK(DeviceKey::from_seed(*store.kept->key).public_key() == pairing->key->public_key());
    REQUIRE(store.kept->spki);
    CHECK(same_digest(*store.kept->spki, spki));

    // Another start: the key is pinned again from the store
    Setup later(true);
    later.shake();
    REQUIRE(later.client->sign_in(store) == true);
    CHECK(later.trust.mode() == ServerTrust::Mode::pinned);
    REQUIRE(later.client->device_key() != nullptr);
    REQUIRE(later.client->forget(store));
    CHECK_FALSE(store.kept);
    CHECK_FALSE(later.client->has_token());
}

TEST_CASE("pairing: nothing secret over a key nobody verified, and a code of the wrong form")
{
    Setup s(true);
    s.shake();
    s.trust.allow_unverified();
    REQUIRE(s.client->set_bearer_token("et_Zk81Qp-fictional"));
    const auto page = s.client->apps();
    REQUIRE_FALSE(page);
    CHECK(page.error().category() == Category::refused);

    s.client->clear_bearer_token();
    s.transport.respond = [](const Recorded&)
    {
        return json_answer(R"({"schema":1,"code":"KQ4M","verify":"https://shelf.example.org/pair",
            "verify_complete":"https://shelf.example.org/pair?code=KQ4M","poll":"/api/lantern/v1/pairing/p_1",
            "interval":5,"expires":600})");
    };
    const std::array<std::string_view, 1> scopes { "library" };
    PairingOptions options;
    options.device = "Lea's Switch";
    options.scopes = scopes;
    CHECK_FALSE(s.client->start_pairing(options));
    // A poll elsewhere than the server's origin
    s.transport.respond = [](const Recorded&)
    {
        return json_answer(R"({"schema":1,"code":"KQ4M-7TXD","verify":"https://shelf.example.org/pair",
            "verify_complete":"https://shelf.example.org/pair?code=KQ4M-7TXD",
            "poll":"https://elsewhere.example.org/p_1","interval":5,"expires":600})");
    };
    CHECK_FALSE(s.client->start_pairing(options));
    options.invitation = "KQ4M-7TXD";
    CHECK_FALSE(s.client->start_pairing(options)); // too short for an invitation
    options.invitation = {};
    options.device     = "Lea\n's Switch";
    CHECK_FALSE(s.client->start_pairing(options));
}

TEST_CASE("saves: one request's headers, and a resumable upload's conflict")
{
    Setup s;
    s.shake();
    REQUIRE(s.client->set_credentials("et_Zk81Qp-fictional", lea_key()));
    const std::string archive = "PK fictional archive";
    SaveInfo info;
    info.kind              = "account";
    info.game_version_code = 196608;
    info.profile           = "Léa";
    info.note              = "Chapter 4";
    s.transport.respond
        = [](const Recorded&) { return json_answer(spec_file("examples/v1/save.json"), 201); };
    REQUIRE(s.client->upload_save(
        "0100ABCD00010000", std::as_bytes(std::span(archive.data(), archive.size())), info));
    const Recorded& post = s.transport.requests.back();
    CHECK(post.url == "https://shelf.example.org/api/lantern/v1/saves/0100ABCD00010000");
    CHECK(*post.header("Content-Type") == "application/zip");
    CHECK(*post.header("Lantern-Save-Kind") == "account");
    CHECK(*post.header("Lantern-Game-Version") == "196608");
    CHECK(*post.header("Lantern-Profile") == "L%C3%A9a");
    CHECK(*post.header("Lantern-Note") == "Chapter%204");
    REQUIRE(post.header("Content-Digest") != nullptr);
    CHECK(post.header("Signature-Input")->find("content-digest") != std::string::npos);
    // Above limits.save_body (64 here): resumably
    const std::string big(65, 'x');
    CHECK(s.client->upload_save("0100ABCD00010000", std::as_bytes(std::span(big.data(), big.size())), info)
              .error()
              .category()
        == Category::limit);

    // 9.3: the server has 4 bytes the client did not know of
    const std::string data = "0123456789";
    UploadRequest request;
    request.size   = data.size();
    request.sha256 = Sha256::of(data);
    struct Source final : UploadSource
    {
        const std::string& text;
        explicit Source(const std::string& t)
            : text(t)
        {
        }
        Result<void> read(std::uint64_t offset, std::span<std::byte> out) override
        {
            std::copy_n(reinterpret_cast<const std::byte*>(text.data()) + offset, out.size(), out.begin());
            return {};
        }
    } source(data);
    std::uint64_t have  = 4;
    s.transport.respond = [&](const Recorded& r)
    {
        if (r.method == "POST")
            return json_answer(
                R"({"schema":1,"upload":"/api/lantern/v1/uploads/u_1","chunk_size":3,"offset":0,
                "expires":"2026-10-31T09:12:00Z"})",
                201);
        if (r.method == "HEAD")
            return status_answer(
                204, { { "Upload-Offset", std::to_string(have) }, { "Upload-Length", "10" } });
        const std::uint64_t offset = std::stoull(*r.header("Upload-Offset"));
        CHECK(*r.header("Content-Type") == "application/offset+octet-stream");
        if (offset != have)
            return problem_answer(409, "conflict", { { "Upload-Offset", std::to_string(have) } });
        have += r.body.size();
        if (have == 10)
            return json_answer(spec_file("examples/v1/save.json"), 201);
        return status_answer(204, { { "Upload-Offset", std::to_string(have) } });
    };
    UploadProgress progress;
    const auto save = s.client->upload_resumable("0100ABCD00010000", request, source, progress, 8);
    REQUIRE(save);
    REQUIRE(*save);
    CHECK(progress.url_size == 0);
    // POST, PATCH at 0 (409), HEAD (4), then chunks of 3 at most from 4 and from 7
    std::vector<std::string> methods;
    for (std::size_t i = s.transport.requests.size() - 5; i < s.transport.requests.size(); ++i)
        methods.push_back(s.transport.requests[i].method);
    CHECK(methods == std::vector<std::string> { "POST", "PATCH", "HEAD", "PATCH", "PATCH" });
    CHECK(*s.transport.requests.back().header("Upload-Offset") == "7");
}

TEST_CASE("discovery: the request, the replies kept and those dropped")
{
    String written;
    DiscoveryRequest request;
    request.lantern = "discover";
    write_discovery_request(request, written);
    CHECK(written == discovery_request());

    const std::string example = spec_file("examples/v1/discovery.json");
    const auto bytes_of
        = [](const std::string& text) { return std::as_bytes(std::span(text.data(), text.size())); };
    const auto reply = read_discovery_datagram(bytes_of(example));
    REQUIRE(reply);
    REQUIRE(*reply);
    CHECK((*reply)->name == "Living room shelf");
    CHECK((*reply)->port == 443U);

    CHECK_FALSE(
        read_discovery_datagram(bytes_of(spec_file("examples/v1/invalid/discovery.ownfoil-shape.json"))));
    CHECK_FALSE(read_discovery_datagram(bytes_of(std::string(R"({"schema":1,"lantern":"discover"})"))));
    CHECK_FALSE(read_discovery_datagram(bytes_of(std::string(R"({"schema":1,"lantern":"server","uid":"nope",
        "name":"x","port":1,"base":"/a","versions":[1]})"))));
    CHECK_FALSE(read_discovery_datagram(bytes_of(std::string(R"({"schema":1,"lantern":"server",
        "uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14","name":"x","port":1,"base":"/a/","versions":[1]})"))));
    CHECK_FALSE(read_discovery_datagram(bytes_of(std::string(R"({"schema":1,"lantern":"server",
        "uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14","name":"x","port":1,"base":"/a","versions":[2]})"))));
    std::string padded = example;
    padded.insert(1, 1200, ' ');
    CHECK(read_discovery_datagram(bytes_of(padded)).error().category() == Category::limit);
    // A newer schema: absent, never an error
    const auto newer = read_discovery_datagram(bytes_of(std::string(R"({"schema":2,"lantern":"beacon"})")));
    REQUIRE(newer);
    CHECK_FALSE(*newer);

    CHECK(discovered_origin("192.168.1.20", 443).value() == "https://192.168.1.20:443");
    CHECK(discovered_origin("fe80::1", 8443).value() == "https://[fe80::1]:8443");
    CHECK_FALSE(discovered_origin("192.168.1.20/x", 443));

    // A socket that hears two servers, one twice, and noise
    struct Socket final : UdpSocket
    {
        std::vector<std::pair<std::string, std::string>> replies; // address, datagram
        int sent = 0;
        Result<void> send_to(
            std::string_view address, std::uint16_t port, std::span<const std::byte> bytes) override
        {
            CHECK(address == "192.168.1.255");
            CHECK(port == discovery_port);
            CHECK(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size())
                == discovery_request());
            ++sent;
            return {};
        }
        Result<std::optional<Datagram>> receive(
            std::span<std::byte> buffer, std::chrono::milliseconds) override
        {
            if (replies.empty())
                return std::optional<Datagram> {};
            auto [address, text] = replies.front();
            replies.erase(replies.begin());
            Datagram d;
            d.size = std::min(text.size(), buffer.size());
            std::copy_n(reinterpret_cast<const std::byte*>(text.data()), d.size, buffer.begin());
            std::copy(address.begin(), address.end(), d.address.begin());
            d.address_size = address.size();
            d.port         = discovery_port;
            return std::optional<Datagram>(d);
        }
    } socket;
    std::string other = example;
    other.replace(other.find("6f1c2a8e"), 8, "7a2b3c4d");
    socket.replies = { { "192.168.1.20", example }, { "192.168.1.21", "not json at all" },
        { "192.168.1.20", example }, { "192.168.1.22", other }, { "192.168.1.23", std::string(1300, '{') } };
    struct Found final : DiscoveryHandler
    {
        std::vector<std::string> origins;
        bool on_server(const DiscoveredServer& server) override
        {
            origins.emplace_back(server.origin);
            return true;
        }
    } found;
    DiscoveryOptions options;
    options.address  = "192.168.1.255";
    options.wait     = std::chrono::milliseconds(60);
    options.attempts = 2;
    REQUIRE(discover(socket, options, found));
    CHECK(
        found.origins == std::vector<std::string> { "https://192.168.1.20:443", "https://192.168.1.22:443" });
    CHECK(socket.sent == 2);
}
