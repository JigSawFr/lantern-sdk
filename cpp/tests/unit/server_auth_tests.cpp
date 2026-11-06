// The server core's accounts (include/lantern/server.hpp, accounts.hpp):
// Bearer tokens kept as hashes and checked with their scopes (SPEC.md § 5.1),
// pairing and its limits (§ 5.2), the approval page (§ 5.3), and the signed
// requests of tokens bound to a device key (§ 5.4), with the replay window of
// the injected clock. The core is called in memory, with no socket; the
// conformance suite plays the same against the demo server.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <lantern/lantern.hpp>

using namespace lantern;

namespace
{

constexpr std::string_view uid  = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";
constexpr std::string_view host = "shelf.example.org";
constexpr std::int64_t start    = 1'793'000'000;

// Random bytes that differ at every call, and are the same at every run.
class CountingRandom final : public RandomSource
{
  public:
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        for (std::size_t at = 0; at < out.size(); at += 32)
        {
            const std::string seed = "unit-test-random:" + std::to_string(counter_++);
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

DeviceKey key_of(std::string_view phrase)
{
    return DeviceKey::from_seed(Sha256::of(phrase));
}

using Headers = std::vector<std::pair<std::string, std::string>>;

struct Call
{
    std::string method = "GET";
    std::string target;
    Headers headers;
    std::string body;
    std::string remote = "192.0.2.10";
};

ServerResponse send(const Server& server, const Call& call)
{
    const auto parsed = parse_target(call.target);
    REQUIRE(parsed);
    std::vector<QueryParam> query;
    for (const auto& [name, value] : parsed->query)
        query.push_back({ name, value });
    std::vector<Header> headers;
    bool has_host = false;
    for (const auto& [name, value] : call.headers)
    {
        headers.push_back({ name, value });
        has_host = has_host || name == "Host";
    }
    if (!has_host)
        headers.push_back({ "Host", host });
    ServerRequest request;
    request.method  = call.method;
    request.path    = parsed->path;
    request.query   = query;
    request.headers = headers;
    request.body    = std::as_bytes(std::span(call.body.data(), call.body.size()));
    request.scheme  = "http";
    request.target  = call.target;
    request.remote  = call.remote;
    return server.handle(request);
}

std::string_view header(const ServerResponse& response, std::string_view name)
{
    return response.headers.get(name).value_or(std::string_view {});
}

Problem problem_of(const ServerResponse& response, std::uint16_t status, std::string_view code)
{
    CHECK(response.status == status);
    CHECK(header(response, "Content-Type") == "application/problem+json");
    auto read = read_problem(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->status == status);
    CHECK((*read)->code == code);
    return std::move(**read);
}

// Signs `call` as § 5.4 says: the Authorization it carries (a poll has none), its Content-Digest, then
// Signature-Input and Signature.
void sign(
    Call& call, const DeviceKey& key, std::string_view token, std::int64_t created, std::string_view nonce)
{
    std::string authorization;
    if (!token.empty())
    {
        authorization = "Bearer " + std::string(token);
        call.headers.emplace_back("Authorization", authorization);
    }
    String digest;
    if (!call.body.empty())
    {
        format_digest_field(Sha256::of(std::string_view(call.body)), digest);
        call.headers.emplace_back("Content-Digest", std::string(digest));
    }
    const auto uri = target_uri("http://" + std::string(host) + call.target);
    REQUIRE(uri);
    SignedComponents components;
    components.method         = call.method;
    components.target_uri     = *uri;
    components.authorization  = authorization;
    components.content_digest = digest;
    SignatureHeaders signature;
    REQUIRE(sign_components(key, components, created, nonce, signature));
    call.headers.emplace_back("Signature-Input", std::string(signature.signature_input));
    call.headers.emplace_back("Signature", std::string(signature.signature));
}

std::string nonce_n(int n)
{
    return "unit-test-nonce-padded-" + std::to_string(1000 + n);
}

// A server with accounts over a library of one app.
struct Fixture
{
    static constexpr std::string_view lea_plain  = "et_lea-plain-0123456789abcdef0123456789abcdef";
    static constexpr std::string_view lea_bound  = "et_lea-bound-0123456789abcdef0123456789abcdef";
    static constexpr std::string_view lea_brief  = "et_lea-brief-0123456789abcdef0123456789abcdef";
    static constexpr std::string_view ben_token  = "et_ben-saves-0123456789abcdef0123456789abcdef";
    static constexpr std::string_view ice_token  = "et_ice-frozen-0123456789abcdef0123456789abcdef";
    static constexpr std::string_view over_token = "et_lea-admin-0123456789abcdef0123456789abcdef";

    MemoryLibrary library { "/api/lantern" };
    CountingRandom random;
    FakeClock clock;
    MemoryAccountStore store;
    ServerOptions options;
    DeviceKey key = key_of("unit test device key");
    std::optional<Server> server;

    explicit Fixture(bool require_auth = false, bool bound_only = false)
    {
        AppDraft draft;
        draft.platform = "switch";
        draft.title_id = "0100AA0000010000";
        draft.app_id   = "0100AA0000010000";
        draft.type     = "base";
        draft.name     = "Zeta Run";
        draft.format   = "nsp";
        draft.added    = "2026-10-01T10:00:00Z";
        REQUIRE(library.add_app(draft, bytes("zeta-base-0123456789")));

        constexpr std::array<std::string_view, 2> lea { "library", "saves" };
        constexpr std::array<std::string_view, 1> saves { "saves" };
        constexpr std::array<std::string_view, 1> library_only { "library" };
        constexpr std::array<std::string_view, 2> with_admin { "library", "admin" };
        REQUIRE(store.add_account("lea", lea));
        REQUIRE(store.add_account("ben", saves));
        REQUIRE(store.add_account("ice", library_only, true));
        REQUIRE(store.add_token(lea_plain, "lea", "Lea's phone", lea, std::nullopt, start));
        REQUIRE(store.add_token(lea_bound, "lea", "Lea's console", lea, key.public_key(), start));
        REQUIRE(store.add_token(lea_brief, "lea", "A loan", lea, std::nullopt, start, start + 100));
        REQUIRE(store.add_token(ben_token, "ben", "Ben's console", saves, std::nullopt, start));
        REQUIRE(store.add_token(ice_token, "ice", "Ice's console", library_only, std::nullopt, start));
        // The device holds admin, its account does not: the token never does either
        REQUIRE(store.add_token(over_token, "lea", "A device", with_admin, std::nullopt, start));

        options.uid          = uid;
        options.name         = "Test shelf";
        options.scheme       = "http";
        options.accounts     = &store;
        options.require_auth = require_auth;
        options.bound_only   = bound_only;
        remake();
    }

    void remake()
    {
        auto made = Server::create(library, options, random, clock);
        REQUIRE(made);
        server.emplace(std::move(*made));
    }

    [[nodiscard]] ServerResponse get(
        std::string target, std::string_view token = {}, std::string remote = "192.0.2.10") const
    {
        Call call;
        call.target = std::move(target);
        call.remote = std::move(remote);
        if (!token.empty())
            call.headers.emplace_back("Authorization", "Bearer " + std::string(token));
        return send(*server, call);
    }

    // A signed GET with lea's bound token.
    [[nodiscard]] ServerResponse get_signed(
        std::string target, int nonce, std::int64_t created = 0, std::string_view token = lea_bound) const
    {
        Call call;
        call.target = std::move(target);
        sign(call, key, token, created != 0 ? created : clock.now, nonce_n(nonce));
        return send(*server, call);
    }

    [[nodiscard]] ServerResponse post_pairing(std::string body, std::string remote = "192.0.2.10") const
    {
        Call call;
        call.method = "POST";
        call.target = "/api/lantern/v1/pairing";
        call.headers.emplace_back("Content-Type", "application/json");
        call.body   = std::move(body);
        call.remote = std::move(remote);
        return send(*server, call);
    }

    [[nodiscard]] std::string pairing_body(
        bool with_key, std::string_view scopes = R"(["library","saves"])") const
    {
        std::string body = R"({"schema":1,"device":"Lea's Switch","scopes":)" + std::string(scopes);
        if (with_key)
        {
            String text;
            base64_encode(key.public_key(), text);
            body += R"(,"key":{"alg":"ed25519","public_key":")" + std::string(text) + R"("})";
        }
        return body + "}";
    }
};

Handshake handshake_of(const ServerResponse& response)
{
    REQUIRE(response.status == 200);
    auto read = read_handshake(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

std::vector<std::string> scopes_of(const Handshake& hello)
{
    std::vector<std::string> out;
    for (const String& scope : hello.account.scopes)
        out.emplace_back(scope);
    return out;
}

// A pairing the device made with its key: the code document.
PairingCode start_pairing(Fixture& f, bool with_key = true)
{
    const ServerResponse response = f.post_pairing(f.pairing_body(with_key));
    REQUIRE(response.status == 200);
    auto read = read_pairing_code(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

// A signed poll of a pairing made with a key (no Authorization, § 5.4).
ServerResponse poll_signed(Fixture& f, const PairingCode& pairing, int nonce)
{
    Call call;
    call.target = std::string(pairing.poll);
    sign(call, f.key, {}, f.clock.now, nonce_n(nonce));
    return send(*f.server, call);
}

} // namespace

TEST_CASE("accounts: a key is a device's when it is canonical, on the curve and of large order")
{
    const auto bad = [](std::string_view hex)
    {
        const auto digest = digest_from_hex(hex);
        REQUIRE(digest);
        return !ed25519_is_device_key(*digest);
    };
    const auto good = key_of("a device").public_key();
    CHECK(ed25519_is_device_key(good));
    // The identity, the point of order 2, the points of order 8 (SPEC.md § 5.4, L-5.4-12)
    CHECK(bad("0100000000000000000000000000000000000000000000000000000000000000"));
    CHECK(bad("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    CHECK(bad("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"));
    CHECK(bad("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"));
    // y = p, which is not canonical
    CHECK(bad("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    // A y with no point of the curve on it
    CHECK(bad("0200000000000000000000000000000000000000000000000000000000000000"));
}

TEST_CASE("accounts: the helpers read scopes and codes as the specification writes them")
{
    const std::array<std::string_view, 4> asked { "saves", "bogus", "library", "saves" };
    const Vector<String> kept = ordered_scopes(asked, Allocator {});
    REQUIRE(kept.size() == 2);
    CHECK(kept[0] == "library");
    CHECK(kept[1] == "saves");
    CHECK(typed_code("kq4m 7txd", Allocator {}) == "KQ4M7TXD");
    CHECK(typed_code("KQ4M-7TXD", Allocator {}) == "KQ4M7TXD");
    CHECK(is_account_name("lea.b_2-x"));
    CHECK_FALSE(is_account_name(""));
    CHECK_FALSE(is_account_name("lea b"));
    CHECK_FALSE(is_account_name(std::string(65, 'a')));
    CHECK(constant_time_equal("abc", "abc"));
    CHECK_FALSE(constant_time_equal("abc", "abd"));
    CHECK_FALSE(constant_time_equal("abc", "abcd"));
}

TEST_CASE("accounts: the memory store refuses what it cannot keep, and keeps a token as a hash")
{
    MemoryAccountStore store;
    constexpr std::array<std::string_view, 1> library { "library" };
    constexpr std::array<std::string_view, 1> bogus { "bogus" };
    CHECK(store.add_account("lea", library));
    CHECK_FALSE(store.add_account("lea", library)); // taken
    CHECK_FALSE(store.add_account("not a name", library));
    CHECK_FALSE(store.add_account("ben", bogus)); // not a scope of § 4.2
    CHECK_FALSE(store.add_token("", "lea", "x", library));
    const auto device = store.add_token("et_a-token", "lea", "Phone", library, std::nullopt, start);
    REQUIRE(device);
    CHECK(device->id.size() == 18);
    CHECK(device->id.starts_with("d_"));
    CHECK(device->id == store.add_token("et_a-token", "lea", "Phone", library)->id); // from the hash
    const auto found = store.device_of(Sha256::of(std::string_view("et_a-token")), start, Allocator {});
    REQUIRE(found);
    REQUIRE(*found);
    CHECK((*found)->user == "lea");
    // Only the hash opens it
    const auto other = store.device_of(Sha256::of(std::string_view("et_a-tokeN")), start, Allocator {});
    REQUIRE(other);
    CHECK_FALSE(*other);
    CHECK(*store.revoke_device(device->id));
    CHECK_FALSE(*store.revoke_device(device->id));
    CHECK_FALSE(*store.device_of(Sha256::of(std::string_view("et_a-token")), start, Allocator {}));
    CHECK(*store.delete_account("lea"));
    CHECK_FALSE(*store.delete_account("lea"));
}

TEST_CASE("accounts: create refuses options that break § 5")
{
    Fixture f;
    const auto make = [&](auto change)
    {
        ServerOptions options = f.options;
        change(options);
        return Server::create(f.library, options, f.random, f.clock);
    };
    CHECK(make([](ServerOptions&) {}));
    CHECK_FALSE(make([](ServerOptions& o) { o.skew = 59; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.skew = 901; }));
    CHECK(make([](ServerOptions& o) { o.skew = 900; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.pairing_interval = 0; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.pairing_expires = 601; })); // a code lives 10 minutes at most
    CHECK_FALSE(make([](ServerOptions& o) { o.pairing_requests = 0; }));
    CHECK_FALSE(make([](ServerOptions& o) { o.verify = "pair"; }));
    CHECK(make([](ServerOptions& o) { o.verify = "https://app.example.org/pair"; }));
    // Without accounts there is nothing to require or bind
    CHECK_FALSE(make(
        [](ServerOptions& o)
        {
            o.accounts     = nullptr;
            o.require_auth = true;
        }));
    CHECK_FALSE(make(
        [](ServerOptions& o)
        {
            o.accounts   = nullptr;
            o.bound_only = true;
        }));
}

TEST_CASE("accounts: the handshake of a server with accounts offers pairing and signatures to every caller")
{
    Fixture f;
    for (const std::string_view token : { std::string_view {}, Fixture::lea_plain, Fixture::ice_token })
    {
        const Handshake hello = handshake_of(f.get("/.well-known/lantern", token));
        CHECK(hello.features.pairing == 1);
        CHECK(hello.features.signatures == 1);
        CHECK(hello.features.admin == 0);
        CHECK(hello.features.saves == 0); // not served yet, whatever the scope
        REQUIRE(hello.auth);
        CHECK(hello.auth->bearer_only);
        CHECK(hello.auth->skew == 300);
    }
    // No token: anonymous, who reads the library of a public server
    Handshake hello = handshake_of(f.get("/api/lantern/v1/"));
    CHECK(hello.account.state == "anonymous");
    CHECK(scopes_of(hello) == std::vector<std::string> { "library" });
    CHECK(hello.features.library == 1);
    CHECK_FALSE(hello.account.bound);
    // A token: its account, its scopes, not bound
    hello = handshake_of(f.get("/api/lantern/v1/", Fixture::lea_plain));
    CHECK(hello.account.state == "active");
    CHECK(hello.account.name == "lea");
    CHECK(scopes_of(hello) == std::vector<std::string> { "library", "saves" });
    REQUIRE(hello.account.bound);
    CHECK_FALSE(*hello.account.bound);
    CHECK(hello.features.library == 1);
}

TEST_CASE("accounts: a token reads the library; an unknown, a revoked and an expired one give 401")
{
    Fixture f;
    CHECK(f.get("/api/lantern/v1/apps", Fixture::lea_plain).status == 200);
    CHECK(header(f.get("/api/lantern/v1/apps", Fixture::lea_plain), "Cache-Control") == "private");
    for (const char* path : { "/.well-known/lantern", "/api/lantern/v1/apps" })
    {
        ServerResponse r = f.get(path, "et_not-a-token");
        problem_of(r, 401, "unauthorized");
        CHECK(header(r, "WWW-Authenticate") == R"(Bearer realm="lantern", error="invalid_token")");
        CHECK_FALSE(std::string_view(r.body).contains("et_not-a-token")); // no secret in an answer
        Call basic;
        basic.target = path;
        basic.headers.emplace_back("Authorization", "Basic YTpi");
        r = send(*f.server, basic);
        problem_of(r, 401, "unauthorized");
        CHECK(header(r, "WWW-Authenticate") == R"(Bearer realm="lantern")");
    }
    // Expired: lea_brief lives 100 seconds
    CHECK(f.get("/api/lantern/v1/apps", Fixture::lea_brief).status == 200);
    f.clock.now = start + 100;
    problem_of(f.get("/api/lantern/v1/apps", Fixture::lea_brief), 401, "unauthorized");
    CHECK(f.get("/api/lantern/v1/apps", Fixture::lea_plain).status == 200);
    // Revoked, at once
    const auto device = f.store.devices("lea", f.clock.now, Allocator {});
    REQUIRE(device);
    REQUIRE_FALSE(device->empty());
    const auto plain
        = std::ranges::find_if(*device, [](const PairedDevice& d) { return d.name == "Lea's phone"; });
    REQUIRE(plain != device->end());
    CHECK(*f.store.revoke_device(plain->id));
    problem_of(f.get("/api/lantern/v1/apps", Fixture::lea_plain), 401, "unauthorized");
}

TEST_CASE(
    "accounts: a token without the scope gets 403, one of a frozen account too, and scopes are cut back")
{
    Fixture f;
    const ServerResponse r = f.get("/api/lantern/v1/apps", Fixture::ben_token);
    problem_of(r, 403, "forbidden");
    CHECK(header(r, "WWW-Authenticate") == "");
    // The handshake still answers, with the library at 0
    Handshake hello = handshake_of(f.get("/api/lantern/v1/", Fixture::ben_token));
    CHECK(hello.features.library == 0);
    CHECK(hello.features.pairing == 1);
    CHECK(scopes_of(hello) == std::vector<std::string> { "saves" });

    problem_of(f.get("/api/lantern/v1/apps", Fixture::ice_token), 403, "account_frozen");
    hello = handshake_of(f.get("/api/lantern/v1/", Fixture::ice_token));
    CHECK(hello.account.state == "frozen");
    CHECK(hello.features.library == 0);
    CHECK(hello.features.pairing == 1);
    CHECK(hello.features.signatures == 1);
    // Thawed, it reads again
    REQUIRE(*f.store.set_frozen("ice", false));
    CHECK(f.get("/api/lantern/v1/apps", Fixture::ice_token).status == 200);

    // The device holds admin, its account does not
    hello = handshake_of(f.get("/api/lantern/v1/", Fixture::over_token));
    CHECK(scopes_of(hello) == std::vector<std::string> { "library" });
    // An account cut back: its tokens are too
    constexpr std::array<std::string_view, 1> saves { "saves" };
    REQUIRE(*f.store.set_scopes("lea", saves));
    problem_of(f.get("/api/lantern/v1/apps", Fixture::lea_plain), 403, "forbidden");
    // An account deleted: its tokens are unknown at once
    REQUIRE(*f.store.delete_account("lea"));
    problem_of(f.get("/api/lantern/v1/apps", Fixture::lea_plain), 401, "unauthorized");
}

TEST_CASE("accounts: a private server asks for a token on the library, and nowhere else")
{
    Fixture f(true);
    const ServerResponse r = f.get("/api/lantern/v1/apps");
    problem_of(r, 401, "unauthorized");
    CHECK(header(r, "WWW-Authenticate") == R"(Bearer realm="lantern")");
    CHECK(f.get("/api/lantern/v1/apps", Fixture::lea_plain).status == 200);
    const Handshake hello = handshake_of(f.get("/.well-known/lantern"));
    CHECK(hello.account.state == "anonymous");
    CHECK(hello.account.scopes.empty());
    CHECK(hello.features.library == 0);
    CHECK(hello.features.pairing == 1);
    CHECK(hello.features.signatures == 1);
    CHECK(f.post_pairing(f.pairing_body(true)).status == 200);
}

TEST_CASE("signatures: a bound token is worth nothing without its key")
{
    Fixture f;
    // Unsigned: signature_required, with Accept-Signature and the Bearer challenge
    ServerResponse r = f.get("/api/lantern/v1/apps", Fixture::lea_bound);
    problem_of(r, 401, "signature_required");
    CHECK(header(r, "WWW-Authenticate") == R"(Bearer realm="lantern", error="invalid_token")");
    const auto accept = parse_accept_signature(header(r, "Accept-Signature"));
    REQUIRE(accept);
    REQUIRE(accept->covered().size() == 3);
    CHECK(accept->covered()[2] == "authorization");
    const auto keyid = key_thumbprint(f.key.public_key());
    CHECK(accept->keyid == std::string_view(keyid.data(), keyid.size()));
    // The handshake of a bound token is signed too
    problem_of(f.get("/.well-known/lantern", Fixture::lea_bound), 401, "signature_required");
    // Signed: it reads
    r = f.get_signed("/api/lantern/v1/apps?page_size=1", 1);
    CHECK(r.status == 200);
    Call handshake;
    handshake.target = "/.well-known/lantern";
    sign(handshake, f.key, Fixture::lea_bound, f.clock.now, nonce_n(2));
    const Handshake hello = handshake_of(send(*f.server, handshake));
    REQUIRE(hello.account.bound);
    CHECK(*hello.account.bound);
    // A token with no key needs no signature
    CHECK(f.get("/api/lantern/v1/apps", Fixture::lea_plain).status == 200);
}

TEST_CASE("signatures: a signature by another key, over another target or of another form is invalid")
{
    Fixture f;
    Call call;
    call.target = "/api/lantern/v1/apps";
    sign(call, key_of("another key"), Fixture::lea_bound, f.clock.now, nonce_n(1));
    problem_of(send(*f.server, call), 401, "signature_invalid");

    // Signed for one target, sent to another
    Call moved;
    moved.target = "/api/lantern/v1/apps?page_size=1";
    sign(moved, f.key, Fixture::lea_bound, f.clock.now, nonce_n(2));
    moved.target = "/api/lantern/v1/apps?page_size=2";
    problem_of(send(*f.server, moved), 401, "signature_invalid");

    // Signed for another token
    Call token;
    token.target = "/api/lantern/v1/apps";
    sign(token, f.key, Fixture::lea_plain, f.clock.now, nonce_n(3));
    for (auto& [name, value] : token.headers)
    {
        if (name == "Authorization")
            value = "Bearer " + std::string(Fixture::lea_bound);
    }
    problem_of(send(*f.server, token), 401, "signature_invalid");

    // Components in another order, or another algorithm, or a mangled value
    Call good;
    good.target = "/api/lantern/v1/apps";
    sign(good, f.key, Fixture::lea_bound, f.clock.now, nonce_n(4));
    for (const auto& [from, to] : std::vector<std::pair<std::string_view, std::string_view>> {
             { R"(("@method" "@target-uri" "authorization"))",
                 R"(("@target-uri" "@method" "authorization"))" },
             { R"(alg="ed25519")", R"(alg="rsa-v1_5")" }, { "lantern=(", "other=(" },
             { ";created=", ";created=0" } })
    {
        Call changed = good;
        for (auto& [name, value] : changed.headers)
        {
            if (name == "Signature-Input")
            {
                const std::size_t at = value.find(from);
                REQUIRE(at != std::string::npos);
                value.replace(at, from.size(), to);
            }
        }
        problem_of(send(*f.server, changed), 401, "signature_invalid");
    }
    // One header without the other
    Call lone = good;
    std::erase_if(lone.headers, [](const auto& entry) { return entry.first == "Signature"; });
    problem_of(send(*f.server, lone), 401, "signature_required");
    // The good one still holds: a refused signature took no nonce
    CHECK(send(*f.server, good).status == 200);
}

TEST_CASE("signatures: created outside the window is expired, on either side, and the clock decides")
{
    Fixture f;
    problem_of(f.get_signed("/api/lantern/v1/apps", 1, f.clock.now - 301), 401, "signature_expired");
    problem_of(f.get_signed("/api/lantern/v1/apps", 2, f.clock.now + 301), 401, "signature_expired");
    CHECK(f.get_signed("/api/lantern/v1/apps", 3, f.clock.now - 300).status == 200);
    CHECK(f.get_signed("/api/lantern/v1/apps", 4, f.clock.now + 300).status == 200);
    // The server's clock moves; a signature made for the old time is stale
    Call call;
    call.target = "/api/lantern/v1/apps";
    sign(call, f.key, Fixture::lea_bound, f.clock.now, nonce_n(5));
    f.clock.now += 400;
    problem_of(send(*f.server, call), 401, "signature_expired");
    // A server that announces another window
    f.options.skew = 60;
    f.remake();
    problem_of(f.get_signed("/api/lantern/v1/apps", 6, f.clock.now - 61), 401, "signature_expired");
    CHECK(f.get_signed("/api/lantern/v1/apps", 7, f.clock.now - 60).status == 200);
    CHECK(handshake_of(f.get("/.well-known/lantern")).auth->skew == 60);
}

TEST_CASE("signatures: a nonce is taken once per key, for twice the window")
{
    Fixture f;
    CHECK(f.get_signed("/api/lantern/v1/apps", 1).status == 200);
    const ServerResponse again = f.get_signed("/api/lantern/v1/apps", 1);
    problem_of(again, 401, "signature_replayed");
    CHECK(header(again, "WWW-Authenticate") == R"(Bearer realm="lantern", error="invalid_token")");
    // The very same request, byte for byte, replayed by the network
    Call call;
    call.target = "/api/lantern/v1/apps?page_size=1";
    sign(call, f.key, Fixture::lea_bound, f.clock.now, nonce_n(2));
    CHECK(send(*f.server, call).status == 200);
    problem_of(send(*f.server, call), 401, "signature_replayed");
    // Still remembered 590 seconds on: a signature made at the edge of the window (created = now + skew,
    // good until now + 2 skew) cannot be played again
    Call edge;
    edge.target = "/api/lantern/v1/apps";
    sign(edge, f.key, Fixture::lea_bound, f.clock.now + 300, nonce_n(3));
    CHECK(send(*f.server, edge).status == 200);
    f.clock.now += 590;
    problem_of(send(*f.server, edge), 401, "signature_replayed");
    // Gone from the window: expired, and the memory is released
    f.clock.now += 20;
    problem_of(send(*f.server, edge), 401, "signature_expired");
    CHECK(f.get_signed("/api/lantern/v1/apps", 3).status == 200); // the nonce is free again
}

TEST_CASE("signatures: the nonces kept are bounded, and a full memory refuses rather than forgets")
{
    Fixture f;
    f.options.nonce_limit = 3;
    f.remake();
    for (int n = 1; n <= 3; ++n)
        CHECK(f.get_signed("/api/lantern/v1/apps", n).status == 200);
    const ServerResponse full = f.get_signed("/api/lantern/v1/apps", 4);
    problem_of(full, 429, "slow_down");
    CHECK_FALSE(header(full, "Retry-After").empty());
    problem_of(f.get_signed("/api/lantern/v1/apps", 1), 401, "signature_replayed");
    // Room again once the oldest are out of their window
    f.clock.now += 601;
    CHECK(f.get_signed("/api/lantern/v1/apps", 4).status == 200);
}

TEST_CASE("signatures: a body is signed with its Content-Digest, and a body that differs is a 422")
{
    Fixture f;
    const std::string body = R"({"schema":1,"installed":[],"want":["base"]})";
    const auto post        = [&](int nonce, const std::string& sent, bool digest)
    {
        Call call;
        call.method = "POST";
        call.target = "/api/lantern/v1/apps/missing?platform=switch";
        call.headers.emplace_back("Content-Type", "application/json");
        call.body = body;
        sign(call, f.key, Fixture::lea_bound, f.clock.now, nonce_n(nonce));
        if (!digest)
            std::erase_if(call.headers, [](const auto& entry) { return entry.first == "Content-Digest"; });
        call.body = sent;
        return send(*f.server, call);
    };
    CHECK(post(1, body, true).status == 200);
    problem_of(post(2, body + " ", true), 422, "digest_mismatch");
    problem_of(post(3, body, false), 401, "signature_invalid");
    const ServerResponse refused = post(4, body, false);
    const auto accept            = parse_accept_signature(header(refused, "Accept-Signature"));
    REQUIRE(accept);
    CHECK(accept->covered().size() == 4);
    // The digest was refused after the signature held: the nonce is spent
    problem_of(post(2, body, true), 401, "signature_replayed");
}

TEST_CASE("signatures: a request without a Host this server can read is a 400")
{
    Fixture f;
    for (const char* bad : { "a/b", "user@host", "" })
    {
        Call call;
        call.target = "/api/lantern/v1/apps";
        call.headers.emplace_back("Host", bad);
        sign(call, f.key, Fixture::lea_bound, f.clock.now, nonce_n(1));
        problem_of(send(*f.server, call), 400, "bad_request");
    }
}

TEST_CASE("signatures: a server that takes only bound tokens refuses the others and a pairing without a key")
{
    Fixture f(false, true);
    const Handshake hello = handshake_of(f.get("/.well-known/lantern"));
    REQUIRE(hello.auth);
    CHECK_FALSE(hello.auth->bearer_only);
    const ServerResponse r = f.get("/api/lantern/v1/apps", Fixture::lea_plain);
    problem_of(r, 401, "signature_required");
    CHECK(header(r, "WWW-Authenticate") == R"(Bearer realm="lantern", error="invalid_token")");
    CHECK(f.get_signed("/api/lantern/v1/apps", 1).status == 200);
    // Anonymous reads still work on a public server: no token, nothing to bind
    CHECK(f.get("/api/lantern/v1/apps").status == 200);
    const ServerResponse unkeyed = f.post_pairing(f.pairing_body(false));
    problem_of(unkeyed, 400, "key_required");
    CHECK(f.post_pairing(f.pairing_body(true)).status == 200);
}

TEST_CASE("pairing: the flow from the code to a token that works, signed")
{
    Fixture f;
    const ServerResponse started = f.post_pairing(f.pairing_body(true));
    REQUIRE(started.status == 200);
    CHECK(header(started, "Cache-Control") == "no-store");
    CHECK_FALSE(started.headers.get("ETag"));
    auto read = read_pairing_code(started.body);
    REQUIRE(read);
    REQUIRE(*read);
    const PairingCode& pairing = **read;
    // The code: 8 symbols of the alphabet, in groups of 4 (L-5.2-5)
    REQUIRE(pairing.code.size() == 9);
    CHECK(pairing.code[4] == '-');
    for (const char c : pairing.code)
    {
        const bool in_alphabet = c == '-' || std::string_view("23456789ABCDEFGHJKLMNPQRSTUVWXYZ").contains(c);
        CHECK(in_alphabet);
    }
    CHECK(pairing.verify == "http://shelf.example.org/pair");
    CHECK(std::string(pairing.verify_complete)
        == "http://shelf.example.org/pair?code=" + std::string(pairing.code));
    CHECK(pairing.poll.starts_with("/api/lantern/v1/pairing/p_"));
    CHECK(pairing.poll.size() >= std::string_view("/api/lantern/v1/pairing/p_").size() + 32); // 192 bits
    CHECK(pairing.interval == 5);
    CHECK(pairing.expires == 600);

    // The user has not approved: 202 to a signed poll, and the poll itself is signed (L-5.4-11)
    problem_of(send(*f.server,
                   [&]
                   {
                       Call c;
                       c.target = std::string(pairing.poll);
                       return c;
                   }()),
        401, "signature_required");
    ServerResponse waiting = poll_signed(f, pairing, 1);
    CHECK(waiting.status == 202);
    CHECK(header(waiting, "Content-Length") == "0");
    CHECK(header(waiting, "Cache-Control") == "no-store");
    // Someone else's key learns nothing from the address
    Call other;
    other.target = std::string(pairing.poll);
    sign(other, key_of("another key"), {}, f.clock.now, nonce_n(2));
    problem_of(send(*f.server, other), 401, "signature_invalid");
    // Too soon: 429 with the seconds left, counted from the last poll answered
    f.clock.now += 1;
    ServerResponse slow = poll_signed(f, pairing, 3);
    problem_of(slow, 429, "slow_down");
    CHECK(header(slow, "Retry-After") == "4");
    f.clock.now += 1;
    slow = poll_signed(f, pairing, 4);
    CHECK(header(slow, "Retry-After") == "3"); // a refused poll moved nothing (L-5.2-15)

    // The user approves on the server's side, typing the code any way they like
    std::string typed(pairing.code);
    typed = "  " + typed.substr(0, 4) + " " + typed.substr(5);
    for (char& c : typed)
        c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    const auto waiting_entry = f.server->waiting_pairing(typed);
    REQUIRE(waiting_entry);
    REQUIRE(*waiting_entry);
    CHECK((*waiting_entry)->device == "Lea's Switch");
    CHECK((*waiting_entry)->key == f.key.public_key());
    const auto granted = f.server->approve_pairing(typed, "lea");
    REQUIRE(granted);
    REQUIRE(*granted);
    REQUIRE((*granted)->size() == 2);

    f.clock.now += 3; // five seconds after the last poll answered
    const ServerResponse done = poll_signed(f, pairing, 5);
    REQUIRE(done.status == 200);
    CHECK(header(done, "Cache-Control") == "no-store");
    CHECK_FALSE(done.headers.get("ETag"));
    auto token = read_pairing_token(done.body);
    REQUIRE(token);
    REQUIRE(*token);
    CHECK((*token)->token.starts_with("et_"));
    CHECK((*token)->token.size() >= 3 + 43); // 256 bits (L-5.1-2)
    REQUIRE((*token)->bound);
    CHECK(*(*token)->bound);
    REQUIRE((*token)->scopes.size() == 2);
    CHECK_FALSE((*token)->expires);
    const std::string secret((*token)->token);
    // Given once
    f.clock.now += 5;
    problem_of(poll_signed(f, pairing, 6), 410, "gone");

    // The token works, signed by the key it was bound to; unsigned or by another key it does not
    CHECK(f.get_signed("/api/lantern/v1/apps", 7, 0, secret).status == 200);
    problem_of(f.get("/api/lantern/v1/apps", secret), 401, "signature_required");
    const Handshake hello = [&]
    {
        Call call;
        call.target = "/api/lantern/v1/";
        sign(call, f.key, secret, f.clock.now, nonce_n(8));
        return handshake_of(send(*f.server, call));
    }();
    CHECK(hello.account.name == "lea");
    CHECK(scopes_of(hello) == std::vector<std::string> { "library", "saves" });
    // The store holds the hash of the token, and a device that it names
    const auto device = f.store.device_of(Sha256::of(std::string_view(secret)), f.clock.now, Allocator {});
    REQUIRE(device);
    REQUIRE(*device);
    CHECK((*device)->name == "Lea's Switch");
    CHECK((*device)->key == f.key.public_key());
    CHECK((*device)->id.size() == 18);
}

TEST_CASE("pairing: the scopes granted are those asked for that the account holds, and a token may expire")
{
    Fixture f;
    f.options.token_lifetime = 3600;
    f.remake();
    const ServerResponse started
        = f.post_pairing(f.pairing_body(false, R"(["admin","saves","library","nonsense"])"));
    REQUIRE(started.status == 200);
    const PairingCode pairing = std::move(**read_pairing_code(started.body));
    // Ben holds saves only; the device asked for more
    const auto granted = f.server->approve_pairing(pairing.code, "ben");
    REQUIRE(granted);
    REQUIRE(*granted);
    REQUIRE((*granted)->size() == 1);
    CHECK((**granted)[0] == "saves");
    Call poll;
    poll.target               = std::string(pairing.poll);
    const ServerResponse done = send(*f.server, poll); // a pairing without a key polls unsigned
    REQUIRE(done.status == 200);
    const PairingToken token = std::move(**read_pairing_token(done.body));
    REQUIRE(token.bound);
    CHECK_FALSE(*token.bound);
    REQUIRE(token.expires);
    CHECK(*token.expires == 3600);
    CHECK(f.get("/api/lantern/v1/", token.token).status == 200);
    f.clock.now += 3600;
    problem_of(f.get("/api/lantern/v1/", token.token), 401, "unauthorized");
    // The app can narrow what it approves, and no account is a usage error
    const ServerResponse again = f.post_pairing(f.pairing_body(false));
    const PairingCode second   = std::move(**read_pairing_code(again.body));
    constexpr std::array<std::string_view, 1> only_library { "library" };
    const auto narrowed = f.server->approve_pairing(second.code, "lea", only_library);
    REQUIRE(narrowed);
    REQUIRE(*narrowed);
    CHECK((*narrowed)->size() == 1);
    const ServerResponse third = f.post_pairing(f.pairing_body(false));
    const PairingCode code3    = std::move(**read_pairing_code(third.body));
    CHECK_FALSE(f.server->approve_pairing(code3.code, "nobody"));
    // Nothing waits under a code that was never given, or already decided
    CHECK(*f.server->approve_pairing("ZZZZ-ZZZZ", "lea") == std::nullopt);
    CHECK(*f.server->approve_pairing(second.code, "lea") == std::nullopt);
}

TEST_CASE("pairing: a refusal and an expiry are a 410, and the address says no more")
{
    Fixture f;
    const PairingCode refused = start_pairing(f);
    REQUIRE(*f.server->refuse_pairing(refused.code));
    CHECK_FALSE(*f.server->refuse_pairing(refused.code));
    CHECK(poll_signed(f, refused, 1).status == 410);
    problem_of(poll_signed(f, refused, 2), 410, "gone"); // forgotten once told

    const PairingCode late = start_pairing(f);
    f.clock.now += 601;
    CHECK(poll_signed(f, late, 3).status == 410); // expired: unknown, signed or not (nothing to check it by)
    CHECK_FALSE(*f.server->waiting_pairing(late.code));
    CHECK(*f.server->approve_pairing(late.code, "lea") == std::nullopt);

    Call unknown;
    unknown.target = "/api/lantern/v1/pairing/p_does-not-exist";
    problem_of(send(*f.server, unknown), 410, "gone");
    // Not by POST, not by HEAD
    unknown.method = "POST";
    problem_of(send(*f.server, unknown), 405, "bad_request");
}

TEST_CASE("pairing: requests per address are limited, and the window moves with the clock")
{
    Fixture f;
    for (int i = 0; i < 30; ++i)
        CHECK(f.post_pairing(f.pairing_body(false)).status == 200);
    const ServerResponse limited = f.post_pairing(f.pairing_body(false));
    problem_of(limited, 429, "slow_down");
    CHECK(header(limited, "Retry-After") == "60");
    // Another address is not held back
    CHECK(f.post_pairing(f.pairing_body(false), "192.0.2.11").status == 200);
    f.clock.now += 30;
    CHECK(header(f.post_pairing(f.pairing_body(false)), "Retry-After") == "30");
    f.clock.now += 30;
    CHECK(f.post_pairing(f.pairing_body(false)).status == 200);

    // Fewer codes wait than the store takes
    MemoryAccountStore small(Allocator {}, 2);
    Fixture g;
    g.options.accounts = &small;
    g.remake();
    CHECK(g.post_pairing(g.pairing_body(false), "192.0.2.1").status == 200);
    CHECK(g.post_pairing(g.pairing_body(false), "192.0.2.2").status == 200);
    problem_of(g.post_pairing(g.pairing_body(false), "192.0.2.3"), 429, "slow_down");
}

TEST_CASE("pairing: an invitation is unknown here, wrong codes are counted per address")
{
    Fixture f;
    const std::string body
        = R"({"schema":1,"device":"Lea's Switch","scopes":["library"],"invitation":"ABCD-EFGH-JKLM-NPQR"})";
    for (int i = 0; i < 10; ++i)
        problem_of(f.post_pairing(body), 410, "gone");
    const ServerResponse limited = f.post_pairing(body);
    problem_of(limited, 429, "slow_down");
    CHECK_FALSE(header(limited, "Retry-After").empty());
    // A pairing without an invitation is another thing
    CHECK(f.post_pairing(f.pairing_body(false)).status == 200);
    // Another address has its own count
    problem_of(f.post_pairing(body, "192.0.2.99"), 410, "gone");
}

TEST_CASE("pairing: a request that breaks § 5.2 is a 400, a document of a later schema a 422")
{
    Fixture f;
    const auto bad = [&](std::string_view body, std::uint16_t status, std::string_view code)
    { problem_of(f.post_pairing(std::string(body)), status, code); };
    bad(R"({"schema":1,"device":"x"})", 400, "bad_request"); // no scopes
    bad(R"({"schema":1,"device":"x","scopes":[]})", 400, "bad_request");
    bad(R"({"schema":1,"device":"x","scopes":["bogus"]})", 400, "bad_request");
    bad(R"({"schema":1,"device":"  ","scopes":["library"]})", 400, "bad_request");
    bad("{\"schema\":1,\"device\":\"a\\u0007b\",\"scopes\":[\"library\"]}", 400, "bad_request");
    bad(R"({"schema":1,"scopes":["library"]})", 400, "bad_request");
    bad(R"(["library"])", 400, "bad_request");
    bad("not json", 400, "bad_request");
    bad(R"({"schema":2,"device":"x","scopes":["library"]})", 422, "unsupported_schema");
    bad(R"({"device":"x","scopes":["library"]})", 400, "bad_request");
    // Keys: not base64 of 32 bytes, another algorithm, the identity, a point of order 8, not on the curve
    for (const std::string_view key :
        { R"({"alg":"ed25519","public_key":"AAAA"})", R"({"alg":"rsa","public_key":"AAAA"})",
            R"({"alg":"ed25519","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})",
            R"({"alg":"ed25519","public_key":"JuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/AU="})",
            R"({"alg":"ed25519","public_key":"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})" })
        bad(R"({"schema":1,"device":"x","scopes":["library"],"key":)" + std::string(key) + "}", 400,
            "bad_request");
    // A type other than JSON, and a bad token: refused before the pairing is looked at
    Call call;
    call.method = "POST";
    call.target = "/api/lantern/v1/pairing";
    call.headers.emplace_back("Content-Type", "text/plain");
    call.body = f.pairing_body(false);
    problem_of(send(*f.server, call), 400, "bad_request");
    call.headers.clear();
    call.headers.emplace_back("Content-Type", "application/json");
    call.headers.emplace_back("Authorization", "Bearer et_not-a-token");
    problem_of(send(*f.server, call), 401, "unauthorized");
    // Not by GET
    call.method = "GET";
    call.headers.clear();
    problem_of(send(*f.server, call), 405, "bad_request");
}

TEST_CASE("pairing: a server without accounts has no such route, and takes no token")
{
    MemoryLibrary library;
    CountingRandom random;
    FakeClock clock;
    ServerOptions options;
    options.uid  = uid;
    options.name = "Shelf";
    auto server  = Server::create(library, options, random, clock);
    REQUIRE(server);
    Call call;
    call.method = "POST";
    call.target = "/api/lantern/v1/pairing";
    call.headers.emplace_back("Content-Type", "application/json");
    call.body = R"({"schema":1,"device":"x","scopes":["library"]})";
    problem_of(send(*server, call), 404, "not_found");
    call.method = "GET";
    call.target = "/api/lantern/v1/pairing/p_x";
    problem_of(send(*server, call), 404, "not_found");
    call.target = "/pair";
    problem_of(send(*server, call), 404, "not_found");
    const Handshake hello = handshake_of(send(*server,
        []
        {
            Call c;
            c.target = "/.well-known/lantern";
            return c;
        }()));
    CHECK(hello.features.pairing == 0);
    CHECK(hello.features.signatures == 0);
    CHECK_FALSE(hello.auth);
    CHECK_FALSE(server->waiting_pairing("ABCD-EFGH"));
    CHECK_FALSE(server->approve_pairing("ABCD-EFGH", "lea"));
    CHECK_FALSE(server->refuse_pairing("ABCD-EFGH"));
}

TEST_CASE("pairing: the approval page shows the server's key and approves nothing")
{
    Fixture f;
    // Plain HTTP on loopback: no key to show
    ServerResponse page = f.get("/pair?code=KQ4M-7TXD");
    REQUIRE(page.status == 200);
    CHECK(header(page, "Content-Type") == "text/html; charset=utf-8");
    CHECK(header(page, "Cache-Control") == "no-store");
    CHECK(header(page, "X-Frame-Options") == "DENY");
    CHECK(std::string_view(page.body).contains("KQ4M-7TXD"));
    CHECK(std::string_view(page.body).contains("no TLS key"));
    CHECK(std::string_view(page.body).contains(R"(<meta name="referrer" content="no-referrer">)"));
    CHECK_FALSE(std::string_view(page.body).contains("<form"));
    // With the key of the certificate: its short form (§ 5.3)
    f.options.spki = digest_from_hex("3f9a1c07b2e455d0000000000000000000000000000000000000000000000000");
    f.remake();
    page = f.get("/pair");
    REQUIRE(page.status == 200);
    CHECK(std::string_view(page.body).contains("3F9A 1C07 B2E4 55D0"));
    // What the user typed is text, never markup
    page = f.get("/pair?code=%3Cscript%3E");
    CHECK_FALSE(std::string_view(page.body).contains("<script>"));
    CHECK(std::string_view(page.body).contains("&lt;script&gt;"));
    // Opening it approved nothing
    const PairingCode pairing = start_pairing(f);
    std::ignore               = f.get("/pair?code=" + std::string(pairing.code));
    CHECK(poll_signed(f, pairing, 1).status == 202);
    // HEAD has no body; POST is not taken
    Call head;
    head.method                 = "HEAD";
    head.target                 = "/pair";
    const ServerResponse headed = send(*f.server, head);
    CHECK(headed.status == 200);
    CHECK(headed.body.empty());
    CHECK(header(headed, "Content-Length") != "0");
    head.method = "POST";
    problem_of(send(*f.server, head), 405, "bad_request");
    // The approval page of the app's own: an absolute address, no page here
    f.options.verify = "https://app.example.org/approve";
    f.remake();
    problem_of(f.get("/pair"), 404, "not_found");
    const ServerResponse started = f.post_pairing(f.pairing_body(false));
    const PairingCode own        = std::move(**read_pairing_code(started.body));
    CHECK(own.verify == "https://app.example.org/approve");
    CHECK(
        std::string(own.verify_complete) == "https://app.example.org/approve?code=" + std::string(own.code));
}

TEST_CASE("pairing: the address a pairing's Host and scheme give is the one in its documents")
{
    Fixture f;
    Call call;
    call.method = "POST";
    call.target = "/api/lantern/v1/pairing";
    call.headers.emplace_back("Content-Type", "application/json");
    call.headers.emplace_back("Host", "Shelf.Example.org:8080");
    call.body       = f.pairing_body(false);
    const auto read = read_pairing_code(send(*f.server, call).body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->verify == "http://shelf.example.org:8080/pair");
    call.headers.back().second = "";
    problem_of(send(*f.server, call), 400, "bad_request");
}

namespace
{

// A store that sees what the server hands it, to look at what is kept.
class SpyStore final : public AccountStore
{
  public:
    explicit SpyStore(MemoryAccountStore& inner)
        : inner_(&inner)
    {
    }

    std::vector<Digest> hashes;
    std::vector<std::string> tokens_seen_by_device_of;

    Result<std::optional<StoredAccount>> account(std::string_view name, const Allocator& allocator) override
    {
        return inner_->account(name, allocator);
    }
    Result<std::optional<PairedDevice>> device_of(
        const Digest& hash, std::int64_t now, const Allocator& allocator) override
    {
        return inner_->device_of(hash, now, allocator);
    }
    Result<void> add_device(const PairedDevice& device, const Digest& hash) override
    {
        hashes.push_back(hash);
        return inner_->add_device(device, hash);
    }
    Result<Vector<PairedDevice>> devices(
        std::string_view user, std::int64_t now, const Allocator& allocator) override
    {
        return inner_->devices(user, now, allocator);
    }
    Result<bool> revoke_device(std::string_view id) override { return inner_->revoke_device(id); }
    Result<PairingAdded> add_pairing(const PendingPairing& entry, std::int64_t now) override
    {
        return inner_->add_pairing(entry, now);
    }
    Result<std::optional<PendingPairing>> pairing(
        std::string_view poll, std::int64_t now, const Allocator& allocator) override
    {
        return inner_->pairing(poll, now, allocator);
    }
    Result<std::optional<PendingPairing>> pairing_by_code(
        std::string_view code, std::int64_t now, const Allocator& allocator) override
    {
        return inner_->pairing_by_code(code, now, allocator);
    }
    Result<bool> approve_pairing(std::string_view poll, std::string_view user,
        std::span<const std::string_view> granted, std::string_view token,
        std::optional<std::int64_t> lifetime, std::int64_t now) override
    {
        return inner_->approve_pairing(poll, user, granted, token, lifetime, now);
    }
    Result<bool> refuse_pairing(std::string_view poll, std::int64_t now) override
    {
        return inner_->refuse_pairing(poll, now);
    }
    Result<PairingPoll> poll_pairing(
        std::string_view poll, std::int64_t now, const Allocator& allocator) override
    {
        return inner_->poll_pairing(poll, now, allocator);
    }
    Result<void> forget_user(std::string_view user) override { return inner_->forget_user(user); }

  private:
    MemoryAccountStore* inner_;
};

} // namespace

TEST_CASE("accounts: the server hands a store the hash of a token, never the token, and any store will do")
{
    Fixture f;
    SpyStore spy(f.store);
    f.options.accounts = &spy;
    f.remake();
    const PairingCode pairing = start_pairing(f);
    REQUIRE(*f.server->approve_pairing(pairing.code, "lea"));
    f.clock.now += 5;
    const ServerResponse done = poll_signed(f, pairing, 1);
    REQUIRE(done.status == 200);
    const PairingToken token = std::move(**read_pairing_token(done.body));
    REQUIRE(spy.hashes.size() == 1);
    CHECK(spy.hashes[0] == Sha256::of(std::string_view(token.token)));
    // And a request with it reaches the store as a hash too
    CHECK(f.get_signed("/api/lantern/v1/apps", 2, 0, token.token).status == 200);
    CHECK(f.get_signed("/api/lantern/v1/apps", 3, 0, Fixture::lea_bound).status == 200);
}

TEST_CASE("accounts: a store that fails makes the request a 500, with nothing of the token in it")
{
    class Failing final : public AccountStore
    {
      public:
        Result<std::optional<StoredAccount>> account(std::string_view, const Allocator&) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<std::optional<PairedDevice>> device_of(const Digest&, std::int64_t, const Allocator&) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<void> add_device(const PairedDevice&, const Digest&) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<Vector<PairedDevice>> devices(std::string_view, std::int64_t, const Allocator&) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<bool> revoke_device(std::string_view) override { return fail(Category::storage, "disk gone"); }
        Result<PairingAdded> add_pairing(const PendingPairing&, std::int64_t) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<std::optional<PendingPairing>> pairing(
            std::string_view, std::int64_t, const Allocator&) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<std::optional<PendingPairing>> pairing_by_code(
            std::string_view, std::int64_t, const Allocator&) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<bool> approve_pairing(std::string_view, std::string_view, std::span<const std::string_view>,
            std::string_view, std::optional<std::int64_t>, std::int64_t) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<bool> refuse_pairing(std::string_view, std::int64_t) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<PairingPoll> poll_pairing(std::string_view, std::int64_t, const Allocator&) override
        {
            return fail(Category::storage, "disk gone");
        }
        Result<void> forget_user(std::string_view) override { return fail(Category::storage, "disk gone"); }
    };
    Fixture f;
    Failing failing;
    f.options.accounts = &failing;
    f.remake();
    const ServerResponse r = f.get("/api/lantern/v1/apps", "et_whatever-token");
    problem_of(r, 500, "internal");
    CHECK_FALSE(std::string_view(r.body).contains("et_whatever-token"));
    CHECK_FALSE(std::string_view(r.body).contains("disk gone"));
    problem_of(f.post_pairing(f.pairing_body(false)), 500, "internal");
    // Anonymous reads of a public server do not ask the store
    CHECK(f.get("/api/lantern/v1/apps").status == 200);
}
