// The server core's requests for games and administration (include/lantern/
// server.hpp, requests.hpp, accounts.hpp; SPEC.md § 11, § 5.5-5.7): asking
// and withdrawing, the admin deciding, accounts, devices, pairings approved
// with a rating cap, invitations, an account deleted whole. The core is called
// in memory, with no socket; the conformance suite plays the same against the
// demo server.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
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
constexpr std::string_view mixed  = "0100DD0000040000"; // rated PEGI 16 and ESRB E
constexpr std::string_view bare   = "0100EE0000050000"; // not rated

class CountingRandom final : public RandomSource
{
  public:
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        for (std::size_t at = 0; at < out.size(); at += 32)
        {
            const std::string seed = "requests-test-random:" + std::to_string(counter_++);
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

Title title_of(std::string_view id, std::string_view name,
    std::initializer_list<std::pair<std::string_view, std::string_view>> ratings)
{
    Title title;
    title.platform = "switch";
    title.title_id = id;
    title.name     = name;
    for (const auto& [system, value] : ratings)
    {
        Rating rating;
        rating.system = system;
        rating.rating = value;
        title.ratings.push_back(rating);
    }
    return title;
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

// The `id` of the object that holds `marker`.
std::string id_around(std::string_view json, std::string_view marker)
{
    const std::size_t at = json.find(marker);
    REQUIRE(at != std::string_view::npos);
    return text_of(json.substr(json.rfind(R"("id":")", at)), "id");
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
};

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

    Fixture()
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
        REQUIRE(library.add_app(draft_of(gentle, "Gentle"), bytes("gentle")));
        REQUIRE(library.add_app(draft_of(mature, "Mature"), bytes("mature")));
        REQUIRE(library.add_title(title_of(gentle, "Gentle", { { "PEGI", "3" } })));
        REQUIRE(library.add_title(title_of(mature, "Mature", { { "PEGI", "18" } })));
        options.uid      = uid;
        options.name     = "Test shelf";
        options.scheme   = "http";
        options.accounts = &store;
        options.requests = &requests;
        options.saves    = &saves;
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
        request.method  = call.method;
        request.path    = parsed->path;
        request.query   = query;
        request.headers = headers;
        request.body    = std::as_bytes(std::span(call.body.data(), call.body.size()));
        request.scheme  = "http";
        request.target  = call.target;
        request.remote  = remote;
        return server->handle(request);
    }

    [[nodiscard]] ServerResponse get(
        std::string route, std::string_view token = root, std::string_view platform = "switch") const
    {
        Call call;
        call.target = std::move(route);
        return go(std::move(call), token, platform);
    }

    // A request with a JSON body.
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

    [[nodiscard]] ServerResponse ask(
        std::string_view title_id, std::string_view token = lea, std::string_view platform = "switch") const
    {
        return send("POST", "/requests", R"({"schema":1,"title_id":")" + std::string(title_id) + "\"}", token,
            platform);
    }

    // POST /pairing, anonymously, with an invitation's code when given.
    [[nodiscard]] ServerResponse start_pairing(
        std::string_view invitation = {}, std::string_view remote = "192.0.2.10") const
    {
        std::string body = R"({"schema":1,"device":"Lea's tablet","scopes":["library","saves"])";
        if (!invitation.empty())
            body += R"(,"invitation":")" + std::string(invitation) + "\"";
        body += "}";
        Call call;
        call.method = "POST";
        call.target = "/pairing";
        call.body   = body;
        call.headers.emplace_back("Content-Type", "application/json");
        return go(std::move(call), {}, {}, remote);
    }

    // A pairing started: its poll address, without the base.
    [[nodiscard]] std::string pair(
        std::string_view invitation = {}, std::string_view remote = "192.0.2.10") const
    {
        const ServerResponse r = start_pairing(invitation, remote);
        REQUIRE(r.status == 200);
        return text_of(r.body, "poll").substr(base.size());
    }

    // The only pairing waiting, approved by the admin with `decision` (a JSON object's members).
    [[nodiscard]] ServerResponse decide(std::string_view members) const
    {
        const std::string id = text_of(get("/admin/pairings").body, "id");
        return send("POST", "/admin/pairings/" + id, R"({"schema":1,)" + std::string(members) + "}");
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

    // The invitation an admin makes for `user`, with `extra` members of the document: its answer.
    [[nodiscard]] ServerResponse invite(std::string_view user, std::string_view extra = R"("devices":1)",
        std::string_view scopes = R"(["library"])", std::string_view expires = "2026-10-31T00:00:00Z") const
    {
        return send("POST", "/admin/invitations",
            R"({"schema":1,"user":")" + std::string(user) + R"(","scopes":)" + std::string(scopes)
                + R"(,"expires":")" + std::string(expires) + R"(",)" + std::string(extra) + "}");
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

// A code as a user types it: lower case, spaces for dashes.
std::string typed(std::string code)
{
    std::ranges::transform(
        code, code.begin(), [](char c) { return c == '-' ? ' ' : static_cast<char>(std::tolower(c)); });
    return code;
}

} // namespace

TEST_CASE("requests: asking, asking again, listing and withdrawing")
{
    const Fixture f;
    const ServerResponse first = f.ask(absent);
    REQUIRE(first.status == 201);
    const std::string id = text_of(first.body, "id");
    CHECK(id.starts_with("r_"));
    CHECK(text_of(first.body, "status") == "open");
    CHECK(text_of(first.body, "platform") == "switch");
    CHECK(text_of(first.body, "title_id") == absent);

    // The same open title gives the open request (L-11-1)
    const ServerResponse again = f.ask(absent);
    CHECK(again.status == 200);
    CHECK(text_of(again.body, "id") == id);
    // A title of the library is named by it
    const ServerResponse named = f.ask(gentle);
    REQUIRE(named.status == 201);
    CHECK(text_of(named.body, "name") == "Gentle");

    // Newest first, and of the platform asked for
    const ServerResponse listed = f.get("/requests", lea);
    CHECK(listed.status == 200);
    CHECK(text_of(listed.body, "id") == text_of(named.body, "id"));
    CHECK(listed.body.contains(id));
    CHECK(f.get("/requests", lea, "android").body.contains(R"("requests":[])"));
    // Every device of an account reads the same; another account sees none of them
    CHECK(f.get("/requests", kim).body.contains(R"("requests":[])"));

    // Withdrawing: its own request whatever its status, another's is not found (L-11-2)
    refused(f.send("DELETE", "/requests/" + id, {}, kim), 404, "not_found");
    CHECK(f.send("DELETE", "/requests/" + id, {}, lea).status == 204);
    refused(f.send("DELETE", "/requests/" + id, {}, lea), 404, "not_found");
    refused(f.send("DELETE", "/requests/r_unknown", {}, lea), 404, "not_found");
    // Asked again after withdrawing: a new request
    const ServerResponse fresh = f.ask(absent);
    CHECK(fresh.status == 201);
    CHECK(text_of(fresh.body, "id") != id);
}

TEST_CASE("requests: what a request must be, and who may ask")
{
    const Fixture f;
    refused(f.ask("not a title id"), 400, "bad_request");
    refused(f.ask("0100"), 400, "bad_request"); // a Switch title id is 16 hex digits
    refused(f.send("POST", "/requests", R"({"schema":1})", lea), 400, "bad_request");
    refused(f.send("POST", "/requests", R"({"schema":2,"title_id":"0100CC0000030000"})", lea), 422,
        "unsupported_schema");
    // The platform: the body's, else the client's (§ 4.3), else a 400
    refused(f.ask(absent, lea, ""), 400, "bad_request");
    CHECK(f.send("POST", "/requests", R"({"schema":1,"platform":"switch","title_id":"0100CC0000030000"})",
               lea, "")
              .status
        == 201);
    refused(f.send("POST", "/requests", R"({"schema":1,"platform":"web","title_id":"x"})", lea), 400,
        "bad_request");
    // The scope requests, and a token
    refused(f.ask(absent, reader), 403, "forbidden");
    refused(f.ask(absent, ""), 401, "unauthorized");
    refused(f.get("/requests", reader), 403, "forbidden");
    // The family is listed to those who hold the scope
    CHECK(f.get("/", lea).body.contains(R"("requests":1)"));
    CHECK(f.get("/", reader).body.contains(R"("requests":0)"));
}

TEST_CASE("requests: a server with no request store offers none")
{
    Fixture f;
    f.options.requests = nullptr;
    f.remake();
    refused(f.get("/requests", lea), 404, "not_found");
    CHECK(f.get("/", lea).body.contains(R"("requests":0)"));
    refused(f.get("/admin/requests"), 404, "not_found");
    CHECK_FALSE(f.server->settle_requests().has_value());
    // A request belongs to an account
    ServerOptions anonymous;
    anonymous.uid      = uid;
    anonymous.name     = "Test shelf";
    anonymous.requests = &f.requests;
    CHECK_FALSE(Server::create(f.library, anonymous, f.random, f.clock).has_value());
}

TEST_CASE("requests: an admin lists them, declines with a reason, marks one done; both are final")
{
    const Fixture f;
    const std::string mine   = text_of(f.ask(absent, lea).body, "id");
    const std::string theirs = text_of(f.ask(absent, kim).body, "id");
    const std::string third  = text_of(f.ask("0100CC0000040000", kim).body, "id");

    const ServerResponse all = f.get("/admin/requests");
    CHECK(all.status == 200);
    CHECK(all.body.contains(R"("total":3)"));
    CHECK(text_of(all.body, "id") == third); // newest first, each with its user
    CHECK(text_of(all.body, "user") == "kim");
    CHECK(f.get("/admin/requests?user=lea").body.contains(R"("total":1)"));
    CHECK(f.get("/admin/requests?status=done").body.contains(R"("total":0)"));
    CHECK(f.get("/admin/requests?platform=android").body.contains(R"("total":0)"));
    refused(f.get("/admin/requests?status=maybe"), 400, "bad_request");
    refused(f.get("/admin/requests", lea), 403, "forbidden");
    refused(f.get("/admin/requests", ""), 401, "unauthorized");

    const std::string route = "/admin/requests/" + mine;
    refused(f.send("POST", route, R"({"schema":1,"decision":"maybe"})"), 400, "bad_request");
    refused(f.send("POST", route, R"({"schema":1,"decision":"done","reason":"no"})"), 400, "bad_request");
    const ServerResponse declined = f.send(
        "POST", route, R"({"schema":1,"decision":"decline","reason":"Only the games this household owns."})");
    CHECK(declined.status == 200);
    CHECK(text_of(declined.body, "status") == "declined");
    CHECK(text_of(declined.body, "user") == "lea");
    // The requester reads the reason as the admin wrote it (L-11-5)
    const ServerResponse seen = f.get("/requests", lea);
    CHECK(text_of(seen.body, "status") == "declined");
    CHECK(text_of(seen.body, "reason") == "Only the games this household owns.");
    // Final (L-11-3): nothing changes it, and asking again makes a new request
    refused(f.send("POST", route, R"({"schema":1,"decision":"done"})"), 409, "conflict");
    CHECK(f.ask(absent, lea).status == 201);

    const ServerResponse done
        = f.send("POST", "/admin/requests/" + theirs, R"({"schema":1,"decision":"done"})");
    CHECK(done.status == 200);
    CHECK(text_of(done.body, "status") == "done");
    CHECK_FALSE(done.body.contains("reason"));
    refused(
        f.send("POST", "/admin/requests/" + theirs, R"({"schema":1,"decision":"decline"})"), 409, "conflict");
    refused(
        f.send("POST", "/admin/requests/r_unknown", R"({"schema":1,"decision":"done"})"), 404, "not_found");
    CHECK(f.get("/admin/requests?status=open").body.contains(R"("total":2)"));
    // A request withdrawn is gone for the admin too
    CHECK(f.send("DELETE", "/requests/" + third, {}, kim).status == 204);
    CHECK(f.get("/admin/requests?status=open").body.contains(R"("total":1)"));
}

TEST_CASE("requests: a title that arrives in the library settles its open requests")
{
    Fixture f;
    const std::string id = text_of(f.ask(absent, lea).body, "id");
    REQUIRE_FALSE(id.empty());
    const auto before = f.server->settle_requests();
    REQUIRE(before);
    CHECK(*before == 0);
    REQUIRE(f.library.add_app(draft_of(absent, "Arrived"), bytes("arrived")));
    const auto after = f.server->settle_requests();
    REQUIRE(after);
    CHECK(*after == 1);
    CHECK(text_of(f.get("/requests", lea).body, "status") == "done");
    // Nothing is settled twice
    const auto last = f.server->settle_requests();
    REQUIRE(last);
    CHECK(*last == 0);
}

TEST_CASE("admin: every route needs the scope admin, and the family is offered to those who hold it")
{
    const Fixture f;
    for (const std::string route :
        { "/admin/users", "/admin/devices", "/admin/pairings", "/admin/invitations", "/admin/requests" })
    {
        refused(f.get(route, lea), 403, "forbidden");
        refused(f.get(route, ""), 401, "unauthorized");
        CHECK(f.get(route, root).status == 200);
    }
    CHECK(f.get("/", root).body.contains(R"("admin":1)"));
    CHECK(f.get("/", lea).body.contains(R"("admin":0)"));
    CHECK(f.send("DELETE", "/admin/users").status == 405);
    refused(f.get("/admin/nothing"), 404, "not_found");

    // An option that says no offers none
    Fixture off;
    off.options.admin = false;
    off.remake();
    refused(off.get("/admin/users"), 404, "not_found");
    CHECK(off.get("/").body.contains(R"("admin":0)"));
}

TEST_CASE("admin: accounts made, listed, frozen and changed, with no password and no token in the documents")
{
    const Fixture f;
    const ServerResponse listed = f.get("/admin/users");
    CHECK(listed.body.contains(R"("total":4)"));
    CHECK(text_of(listed.body, "name") == "kim"); // by name
    CHECK_FALSE(listed.body.contains("et_"));
    CHECK_FALSE(listed.body.contains("password"));

    const ServerResponse made
        = f.send("POST", "/admin/users", R"({"schema":1,"name":"sam","scopes":["saves","library"]})");
    CHECK(made.status == 201);
    CHECK(text_of(made.body, "state") == "active");
    CHECK(made.body.contains(R"("scopes":["library","saves"])"));
    refused(f.send("POST", "/admin/users", R"({"schema":1,"name":"sam","scopes":[]})"), 409, "conflict");
    refused(f.send("POST", "/admin/users", R"({"schema":1,"name":"not a name","scopes":[]})"), 400,
        "bad_request");
    refused(
        f.send("POST", "/admin/users", R"({"schema":1,"name":"tom","scopes":["root"]})"), 400, "bad_request");
    refused(f.send("POST", "/admin/users", R"({"schema":1,"name":"tom","scopes":["admin","admin"]})"), 400,
        "bad_request");

    // A frozen account loses its access on its next request (L-5.7-3), and gets it back when thawed
    CHECK(f.get("/apps", lea).status == 200);
    const ServerResponse frozen = f.send("PATCH", "/admin/users/lea", R"({"schema":1,"state":"frozen"})");
    CHECK(frozen.status == 200);
    CHECK(text_of(frozen.body, "state") == "frozen");
    refused(f.get("/apps", lea), 403, "account_frozen");
    CHECK(f.send("PATCH", "/admin/users/lea", R"({"schema":1,"state":"active"})").status == 200);
    CHECK(f.get("/apps", lea).status == 200);
    // The scopes of the account bound those of its devices
    CHECK(f.send("PATCH", "/admin/users/lea", R"({"schema":1,"scopes":["library"]})").status == 200);
    refused(f.get("/saves", lea), 403, "forbidden");
    refused(f.send("PATCH", "/admin/users/lea", R"({"schema":1})"), 400, "bad_request");
    refused(f.send("PATCH", "/admin/users/lea", R"({"schema":1,"state":"gone"})"), 400, "bad_request");
    refused(f.send("PATCH", "/admin/users/nobody", R"({"schema":1,"state":"frozen"})"), 404, "not_found");
}

TEST_CASE("admin: deleting an account asks to be confirmed, never the caller's own, and erases it whole")
{
    const Fixture f;
    REQUIRE(f.ask(absent, lea).status == 201);
    const ServerResponse invitation = f.invite("lea", R"("devices":2)");
    REQUIRE(invitation.status == 201);
    const std::string code = text_of(invitation.body, "code");
    // A pairing approved for her and not collected
    const std::string poll = f.pair();
    REQUIRE(f.decide(R"("decision":"approve","user":"lea")").status == 204);

    refused(f.send("DELETE", "/admin/users/lea"), 400, "bad_request");
    refused(f.send("DELETE", "/admin/users/lea?confirm=le"), 400, "bad_request");
    refused(f.send("DELETE", "/admin/users/root?confirm=root"), 409, "conflict");
    refused(f.send("DELETE", "/admin/users/nobody?confirm=nobody"), 404, "not_found");
    CHECK(f.send("DELETE", "/admin/users/lea?confirm=lea").status == 204);

    // Her token gives 401, her invitation 410, the pairing waiting for her is gone, her requests too
    refused(f.get("/requests", lea), 401, "unauthorized");
    refused(f.start_pairing(code, "192.0.2.20"), 410, "gone");
    refused(f.get(poll, ""), 410, "gone");
    CHECK(f.get("/admin/requests").body.contains(R"("total":0)"));
    refused(f.send("DELETE", "/admin/users/lea?confirm=lea"), 404, "not_found");
    // A new account of the same name inherits nothing
    CHECK(
        f.send("POST", "/admin/users", R"({"schema":1,"name":"lea","scopes":["library","requests"]})").status
        == 201);
    CHECK(f.get("/admin/devices?user=lea").body.contains(R"("total":0)"));
    CHECK(f.get("/admin/invitations").body.contains(R"("total":0)"));
}

TEST_CASE("admin: the save backups of a deleted account are erased with it")
{
    Fixture f;
    const std::string archive = "PK\x03\x04" + std::string(96, 'a');
    Call call;
    call.method = "POST";
    call.target = "/saves/" + std::string(gentle);
    call.body   = archive;
    call.headers.emplace_back("Content-Type", "application/zip");
    call.headers.emplace_back("Content-Digest", digest_of(archive));
    REQUIRE(f.go(std::move(call), lea).status == 201);
    const auto before = f.saves.saves("lea", Allocator());
    REQUIRE(before);
    CHECK(before->size() == 1);
    CHECK(f.send("DELETE", "/admin/users/lea?confirm=lea").status == 204);
    const auto after = f.saves.saves("lea", Allocator());
    REQUIRE(after);
    CHECK(after->empty());
}

TEST_CASE("admin: a pairing waiting is listed with its code, approved for the scopes asked and the account's")
{
    const Fixture f;
    const std::string poll      = f.pair();
    const ServerResponse listed = f.get("/admin/pairings");
    CHECK(listed.body.contains(R"("total":1)"));
    CHECK(text_of(listed.body, "code").size() == 9);
    CHECK(text_of(listed.body, "device") == "Lea's tablet");
    const std::string id = text_of(listed.body, "id");
    CHECK(id.starts_with("pr_"));
    refused(f.get("/admin/pairings", lea), 403, "forbidden");

    const std::string route = "/admin/pairings/" + id;
    refused(f.send("POST", "/admin/pairings/pr_unknown", R"({"schema":1,"decision":"approve"})"), 404,
        "not_found");
    refused(f.send("POST", route, R"({"schema":1,"decision":"maybe"})"), 400, "bad_request");
    refused(
        f.send("POST", route, R"({"schema":1,"decision":"approve","user":"nobody"})"), 400, "bad_request");
    refused(
        f.send("POST", route, R"({"schema":1,"decision":"approve","rating_cap":{"age":6,"system":"PEGI"}})"),
        400, "bad_request");
    // `reader` holds `library` alone: of the two scopes asked, one is granted (L-5.7-4)
    CHECK(f.send("POST", route,
               R"({"schema":1,"decision":"approve","user":"reader","rating_cap":{"age":6,"unrated":"hide"}})")
              .status
        == 204);
    const ServerResponse token = f.get(poll, "");
    REQUIRE(token.status == 200);
    CHECK(token.body.contains(R"("scopes":["library"])"));
    CHECK(token.body.contains(R"("rating_cap":{"age":6,"unrated":"hide"})"));
    // Decided: no longer waiting
    refused(f.send("POST", route, R"({"schema":1,"decision":"refuse"})"), 404, "not_found");
    CHECK(f.get("/admin/pairings").body.contains(R"("total":0)"));

    // Refused: the device's poll gives 410
    const std::string other = f.pair();
    CHECK(f.decide(R"("decision":"refuse")").status == 204);
    refused(f.get(other, ""), 410, "gone");
    // `user` is the admin's own account when absent
    const std::string mine = f.pair();
    CHECK(f.decide(R"("decision":"approve")").status == 204);
    const std::string root_token = text_of(f.get(mine, "").body, "token");
    REQUIRE_FALSE(root_token.empty());
    CHECK(f.get("/", root_token).body.contains(R"("name":"root")"));
}

TEST_CASE("admin: devices are listed without their token and revoked at once")
{
    const Fixture f;
    const std::string poll = f.pair();
    REQUIRE(f.decide(R"("decision":"approve","user":"lea","scopes":["library"])").status == 204);
    const std::string token = text_of(f.get(poll, "").body, "token");
    REQUIRE_FALSE(token.empty());
    CHECK(f.get("/apps", token).status == 200);

    const ServerResponse listed = f.get("/admin/devices?user=lea");
    CHECK(listed.body.contains(R"("total":2)")); // her console and the tablet
    CHECK_FALSE(listed.body.contains("et_"));
    CHECK_FALSE(listed.body.contains(token));
    CHECK(f.get("/admin/devices").body.contains(R"("total":5)"));
    const std::string tablet = id_around(listed.body, R"("device":"Lea's tablet")");
    CHECK(f.send("DELETE", "/admin/devices/" + tablet).status == 204);
    refused(f.get("/apps", token), 401, "unauthorized");
    refused(f.send("DELETE", "/admin/devices/" + tablet), 404, "not_found");
    CHECK(f.get("/apps", lea).status == 200);
}

TEST_CASE("rating caps: what is above the cap is hidden everywhere (SPEC.md § 5.6)")
{
    const Fixture f;
    const std::string token = f.capped_token(R"({"age":12})");

    // The handshake shows the cap to its token (L-5.6-2)
    CHECK(f.get("/", token).body.contains(R"("rating_cap":{"age":12})"));
    CHECK_FALSE(f.get("/", lea).body.contains("rating_cap"));
    // Listings, with a total of what the token sees
    const ServerResponse apps = f.get("/apps", token);
    CHECK(apps.body.contains(R"("total":1)"));
    CHECK(apps.body.contains("Gentle"));
    CHECK_FALSE(apps.body.contains("Mature"));
    CHECK(f.get("/apps", lea).body.contains(R"("total":2)"));
    // Titles: one gives 404, many list the hidden ids in `unknown`
    CHECK(f.get("/titles/" + std::string(gentle), token).status == 200);
    refused(f.get("/titles/" + std::string(mature), token), 404, "not_found");
    const ServerResponse many
        = f.get("/titles?ids=" + std::string(gentle) + "," + std::string(mature), token);
    CHECK(many.body.contains(R"("unknown":[")" + std::string(mature) + R"("])"));
    CHECK(f.get("/titles/" + std::string(mature), lea).status == 200);
    // The file of a hidden app
    const std::string file
        = text_of(f.get("/apps?title_id=" + std::string(mature), lea).body, "file").substr(base.size());
    CHECK(f.get(file, lea).status == 200);
    refused(f.get(file, token), 404, "not_found");
    // What is missing leaves the hidden app out
    const ServerResponse missing
        = f.send("POST", "/apps/missing", R"({"schema":1,"installed":[],"want":["base"]})", token);
    CHECK(missing.body.contains(R"("total":1)"));
}

TEST_CASE("rating caps: a cap of a system, the highest age otherwise, and what is not rated")
{
    Fixture f;
    REQUIRE(f.library.add_app(draft_of(mixed, "Mixed"), bytes("mixed")));
    REQUIRE(f.library.add_title(title_of(mixed, "Mixed", { { "PEGI", "16" }, { "ESRB", "E" } })));
    REQUIRE(f.library.add_app(draft_of(bare, "Bare"), bytes("bare")));
    REQUIRE(f.library.add_title(title_of(bare, "Bare", {})));

    // A cap of a system reads a title's rating of that system: Mixed is E (6), under T (13)
    const std::string esrb    = f.capped_token(R"({"system":"ESRB","rating":"T"})");
    const ServerResponse seen = f.get("/apps", esrb);
    CHECK(seen.body.contains(R"("total":3)")); // Gentle, Mixed and Bare; not Mature
    CHECK(seen.body.contains("Mixed"));
    CHECK_FALSE(seen.body.contains("Mature"));
    // A cap of an age reads the highest age of the ratings: Mixed is 16 by PEGI, and unrated hides Bare
    const std::string strict    = f.capped_token(R"({"age":12,"unrated":"hide"})");
    const ServerResponse narrow = f.get("/apps", strict);
    CHECK(narrow.body.contains(R"("total":1)"));
    CHECK(narrow.body.contains("Gentle"));
}

TEST_CASE("invitations: a device pairs with one at once, as many as it says, then 410 (SPEC.md § 5.5)")
{
    Fixture f;
    refused(f.invite("lea", R"("devices":101)"), 400, "bad_request");
    refused(f.invite("lea", R"("devices":0)"), 400, "bad_request");
    refused(f.invite("nobody"), 400, "bad_request");
    // Beyond the account's scopes, more than 30 days, in the past, a bad cap, a note with a line break
    refused(f.invite("reader", R"("devices":1)", R"(["library","saves"])"), 400, "bad_request");
    refused(f.invite("lea", R"("devices":1)", R"(["library"])", "2026-12-05T00:00:00Z"), 400, "bad_request");
    refused(f.invite("lea", R"("devices":1)", R"(["library"])", "2026-10-01T00:00:00Z"), 400, "bad_request");
    refused(f.invite("lea", R"("devices":1,"rating_cap":{"age":6,"rating":"3"})"), 400, "bad_request");
    refused(f.invite("lea", R"("devices":1,"note":"a\nb")"), 400, "bad_request");
    {
        Fixture off;
        off.options.admin = false;
        off.remake();
        refused(off.invite("lea"), 404, "not_found");
    }

    const ServerResponse made
        = f.invite("lea", R"("devices":2,"rating_cap":{"age":12},"note":"Lea's consoles")");
    REQUIRE(made.status == 201);
    const std::string id   = text_of(made.body, "id");
    const std::string code = text_of(made.body, "code");
    CHECK(id.starts_with("i_"));
    CHECK(code.size() == 19);
    CHECK(code.find_first_of("01OI") == std::string::npos);
    CHECK(text_of(made.body, "link") == "http://shelf.example.org/pair?invitation=" + code);
    CHECK(made.body.contains(R"("used":0)"));
    CHECK(f.get("/admin/invitations").body.contains(id));
    refused(f.get("/admin/invitations", lea), 403, "forbidden");

    // Typed as a user types it, the pairing is approved at once, for the account, the scopes the invitation
    // holds and its cap: the first poll gives the token
    const std::string poll     = f.pair(typed(code));
    const ServerResponse first = f.get(poll, "");
    REQUIRE(first.status == 200);
    CHECK(first.body.contains(R"("scopes":["library"])"));
    CHECK(first.body.contains(R"("rating_cap":{"age":12})"));
    const std::string token = text_of(first.body, "token");
    CHECK(f.get("/", token).body.contains(R"("name":"lea")"));
    CHECK(f.get("/admin/devices?user=lea").body.contains(R"("invitation":")" + id));
    CHECK(f.get("/admin/invitations").body.contains(R"("used":1)"));

    // The second device, then no more (L-5.5-1, L-5.5-2)
    REQUIRE(f.get(f.pair(code), "").status == 200);
    refused(f.start_pairing(code), 410, "gone");
    CHECK(f.get("/admin/invitations").body.contains(R"("total":0)"));
    refused(f.start_pairing("ZZZZ-ZZZZ-ZZZZ-ZZZZ"), 410, "gone");

    // Revoked: its code gives 410, and a device paired with it keeps its token
    const ServerResponse other = f.invite("lea");
    const std::string other_id = text_of(other.body, "id");
    CHECK(f.send("DELETE", "/admin/invitations/" + other_id).status == 204);
    refused(f.start_pairing(text_of(other.body, "code")), 410, "gone");
    refused(f.send("DELETE", "/admin/invitations/" + other_id), 404, "not_found");
    CHECK(f.get("/apps", token).status == 200);

    // Expired
    const ServerResponse brief = f.invite("lea");
    CHECK(f.get("/admin/invitations").body.contains(text_of(brief.body, "id")));
    f.clock.now += 6 * 86400;
    refused(f.start_pairing(text_of(brief.body, "code")), 410, "gone");
    CHECK_FALSE(f.get("/admin/invitations").body.contains(text_of(brief.body, "id")));
}

TEST_CASE("invitations: wrong codes are limited per address, as pairing codes are (L-5.5-3)")
{
    const Fixture f;
    for (int i = 0; i < 10; ++i)
        refused(f.start_pairing("ZZZZ-ZZZZ-ZZZZ-ZZZZ", "192.0.2.77"), 410, "gone");
    const ServerResponse limited = f.start_pairing("ZZZZ-ZZZZ-ZZZZ-ZZZZ", "192.0.2.77");
    refused(limited, 429, "slow_down");
    CHECK_FALSE(limited.headers.get("Retry-After").value_or("").empty());
    // Another address is not limited, and a real code of the limited one is refused too
    refused(f.start_pairing("ZZZZ-ZZZZ-ZZZZ-ZZZZ", "192.0.2.78"), 410, "gone");
    const std::string code = text_of(f.invite("lea").body, "code");
    refused(f.start_pairing(code, "192.0.2.77"), 429, "slow_down");
    CHECK(f.start_pairing(code, "192.0.2.78").status == 200);
}
