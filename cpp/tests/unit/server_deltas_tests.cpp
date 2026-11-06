// The server core's differential updates (include/lantern/server.hpp, chunks.hpp; SPEC.md § 22): the chunk
// indexes a MemoryLibrary writes once per file, against vectors/chunks.json, the route
// <base>/v1/chunks/sha256/<hex> (scope, platform, rating cap, 404), the chunks read as ranges of the file,
// and the family left out when the server does not offer it. The core is called in memory, with no socket;
// the conformance suite plays the same against the demo server.
#include <doctest.h>

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lantern/lantern.hpp>

#include "support.hpp"

using namespace lantern;
using lantern::test::spec_file;

namespace
{

constexpr std::string_view uid    = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";
constexpr std::int64_t start      = 1'793'000'000;
constexpr std::string_view base   = "/api/lantern/v1";
constexpr std::string_view root   = "et_root-0123456789abcdef0123456789abcdef";
constexpr std::string_view lea    = "et_lea-0123456789abcdef0123456789abcdef";
constexpr std::string_view nolib  = "et_nolib-0123456789abcdef0123456789abcd";
constexpr std::string_view gentle = "0100AA0000010000"; // rated PEGI 3, 200,000 bytes
constexpr std::string_view mature = "0100BB0000020000"; // rated PEGI 18, 150,000 bytes
constexpr std::string_view tiny   = "0100CC0000030000"; // rated PEGI 3, 10 bytes: no index

using Bytes = std::vector<std::byte>;

class CountingRandom final : public RandomSource
{
  public:
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        for (std::size_t at = 0; at < out.size(); at += 32)
        {
            const std::string seed = "deltas-test-random:" + std::to_string(counter_++);
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

// The vectors' files: SHA-256(seed || i, i on 8 bytes big-endian), cut to size.
Bytes stream(std::string_view seed, std::size_t size)
{
    Bytes out;
    out.reserve(size + 32);
    for (std::uint64_t i = 0; out.size() < size; ++i)
    {
        std::string input(seed);
        for (int shift = 56; shift >= 0; shift -= 8)
            input.push_back(static_cast<char>((i >> static_cast<unsigned>(shift)) & 0xFFU));
        const Digest digest = Sha256::of(input);
        for (const std::uint8_t b : digest)
            out.push_back(static_cast<std::byte>(b));
    }
    out.resize(size);
    return out;
}

std::string hex_of(const Digest& digest)
{
    const auto hex = to_hex(digest);
    return { hex.data(), hex.size() };
}

AppDraft draft_of(std::string_view id, std::string_view name, std::uint64_t version = 1)
{
    AppDraft draft;
    draft.platform     = "switch";
    draft.title_id     = id;
    draft.app_id       = id;
    draft.type         = "base";
    draft.version_code = version;
    draft.name         = name;
    draft.format       = "nsp";
    return draft;
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

// The bytes a library file holds.
std::string reader_text(const LibraryFile& file)
{
    std::string out(static_cast<std::size_t>(file.size), '\0');
    std::size_t done = 0;
    while (done < out.size())
    {
        const auto got = file.reader->read(
            done, std::as_writable_bytes(std::span(out.data() + done, out.size() - done)));
        REQUIRE(got);
        REQUIRE(*got > 0);
        done += *got;
    }
    return out;
}

std::string_view header(const ServerResponse& response, std::string_view name)
{
    return response.headers.get(name).value_or(std::string_view {});
}

void refused(const ServerResponse& response, std::uint16_t status, std::string_view code)
{
    CHECK(response.status == status);
    const auto read = read_problem(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->code == code);
}

struct Call
{
    std::string method = "GET";
    std::string target;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

// A request to `server`, `route` below the base; `token` empty: anonymous.
ServerResponse go(
    const Server& server, Call call, std::string_view token, std::string_view platform = "switch")
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
    request.remote  = "192.0.2.10";
    return server.handle(request);
}

ServerResponse get(const Server& server, std::string route, std::string_view token = {},
    std::string_view platform = "switch", std::string_view range = {})
{
    Call call;
    call.target = std::move(route);
    if (!range.empty())
        call.headers.emplace_back("Range", std::string(range));
    return go(server, std::move(call), token, platform);
}

Server server_of(
    Library& library, RandomSource& random, Clock& clock, bool deltas, AccountStore* accounts = nullptr)
{
    ServerOptions options;
    options.uid      = uid;
    options.name     = "Test shelf";
    options.scheme   = "http";
    options.accounts = accounts;
    options.deltas   = deltas;
    auto made        = Server::create(library, options, random, clock);
    REQUIRE(made);
    return std::move(*made);
}

// A library with an app of the vectors' kind, a server over it, and the app as the server lists it.
struct Shelf
{
    MemoryLibrary library { "/api/lantern" };
    CountingRandom random;
    FakeClock clock;
    std::optional<Server> server;

    Shelf(const ChunkingOptions& chunking, const Bytes& content)
    {
        REQUIRE(library.offer_deltas(chunking));
        REQUIRE(library.add_app(draft_of(gentle, "Gentle"), content));
        server.emplace(server_of(library, random, clock, true));
    }
};

json::Document parsed(const std::string& text, std::deque<std::string>& keep)
{
    keep.push_back(text);
    auto read = json::parse(keep.back());
    REQUIRE(read);
    return std::move(*read);
}

Bytes file_of(const json::Value& file)
{
    if (file.find("zeros") != nullptr)
        return Bytes(static_cast<std::size_t>(*file.find("zeros")->to_u64()), std::byte { 0 });
    return stream(file.find("seed")->text(), static_cast<std::size_t>(*file.find("size")->to_u64()));
}

} // namespace

TEST_CASE("deltas: the indexes the library writes are the vectors' (SPEC.md 22.1, L-22.1-1)")
{
    const std::string text = spec_file("vectors/chunks.json");
    REQUIRE(!text.empty());
    std::deque<std::string> keep;
    const json::Document doc = parsed(text, keep);
    std::size_t checked      = 0;
    for (const json::Value& v : doc.root().find("cases")->items())
    {
        const json::Value& file = *v.find("file");
        // The edited version is built from the first file; its index is the client's tests'
        if (file.find("edit") != nullptr)
            continue;
        CAPTURE(v.find("name")->text());
        const Bytes content = file_of(file);
        ChunkingOptions chunking;
        chunking.chunker_size  = *v.find("chunker")->find("size")->to_u64();
        chunking.min_file_size = 0;
        const Shelf shelf(chunking, content);

        // The app names the index: its address, size and SHA-256
        const ServerResponse apps = get(*shelf.server, "/apps");
        REQUIRE(apps.status == 200);
        const std::string file_hex = hex_of(Sha256::of(content));
        CHECK(file_hex == v.find("file_sha256")->text());
        CHECK(apps.body.contains(R"("chunks":{"url":"/api/lantern/v1/chunks/sha256/)" + file_hex
            + R"(","size":)" + std::to_string(*v.find("index_size")->to_u64()) + R"(,"sha256":")"
            + std::string(v.find("index_sha256")->text()) + R"("})"));

        // The index is the vector's bytes
        const ServerResponse index = get(*shelf.server, "/chunks/sha256/" + file_hex);
        REQUIRE(index.status == 200);
        CHECK(body_of(index) == v.find("index")->text());
        CHECK(header(index, "Content-Type") == "application/json");
        ++checked;
    }
    CHECK(checked == 5);
}

TEST_CASE("deltas: an index is read by this library's own client and names the file's chunks")
{
    const Bytes content = stream("an app", 200'000);
    ChunkingOptions chunking;
    chunking.min_file_size = 1;
    const Shelf shelf(chunking, content);
    const std::string file_hex = hex_of(Sha256::of(content));
    const ServerResponse reply = get(*shelf.server, "/chunks/sha256/" + file_hex);
    REQUIRE(reply.status == 200);
    const std::string raw = body_of(reply);
    // A chunker is chosen by the file's size when none is given: 64 KiB for this one
    const auto index = read_chunk_index(raw, nullptr, Sha256::of(content), content.size());
    REQUIRE(index);
    REQUIRE(*index);
    CHECK((*index)->chunker_size == 65536);
    CHECK((*index)->chunks.size() > 1);
    // Each chunk is a range of the file (§ 6.6) with the bytes and SHA-256 the index gives
    const std::string file = text_of(get(*shelf.server, "/apps").body, "file").substr(base.size());
    CHECK_FALSE(file.empty());
    std::uint64_t offset = 0;
    std::size_t read     = 0;
    for (const IndexedChunk& chunk : (*index)->chunks)
    {
        const std::string last = std::to_string(offset + chunk.length - 1);
        const ServerResponse range
            = get(*shelf.server, file, {}, "switch", "bytes=" + std::to_string(offset) + "-" + last);
        REQUIRE(range.status == 206);
        const std::string bytes = body_of(range);
        CHECK(bytes.size() == chunk.length);
        CHECK(Sha256::of(std::string_view(bytes)) == chunk.sha256);
        offset += chunk.length;
        ++read;
    }
    CHECK(read == (*index)->chunks.size());
    CHECK(offset == content.size());
}

namespace
{

struct Fixture
{
    MemoryLibrary library { "/api/lantern" };
    CountingRandom random;
    FakeClock clock;
    MemoryAccountStore store;
    std::optional<Server> server;
    std::string gentle_hex;
    std::string mature_hex;
    std::string tiny_hex;

    explicit Fixture(bool deltas = true, bool offer = true)
    {
        constexpr std::array<std::string_view, 2> all { "library", "admin" };
        constexpr std::array<std::string_view, 1> only_library { "library" };
        constexpr std::array<std::string_view, 1> only_saves { "saves" };
        REQUIRE(store.add_account("root", all, false, start));
        REQUIRE(store.add_account("lea", only_library, false, start));
        REQUIRE(store.add_account("nolib", only_saves, false, start));
        REQUIRE(store.add_token(root, "root", "Root's console", all, std::nullopt, start));
        REQUIRE(store.add_token(lea, "lea", "Lea's console", only_library, std::nullopt, start));
        REQUIRE(store.add_token(nolib, "nolib", "A tablet", only_saves, std::nullopt, start));
        if (offer)
        {
            ChunkingOptions chunking;
            chunking.min_file_size = 100'000;
            REQUIRE(library.offer_deltas(chunking));
        }
        const Bytes big   = stream("gentle", 200'000);
        const Bytes large = stream("mature", 150'000);
        const Bytes small = stream("tiny", 10);
        gentle_hex        = hex_of(Sha256::of(big));
        mature_hex        = hex_of(Sha256::of(large));
        tiny_hex          = hex_of(Sha256::of(small));
        REQUIRE(library.add_app(draft_of(gentle, "Gentle"), big));
        REQUIRE(library.add_app(draft_of(mature, "Mature"), large));
        REQUIRE(library.add_app(draft_of(tiny, "Tiny"), small));
        REQUIRE(library.add_title(title_of(gentle, "Gentle", "3")));
        REQUIRE(library.add_title(title_of(mature, "Mature", "18")));
        REQUIRE(library.add_title(title_of(tiny, "Tiny", "3")));
        server.emplace(server_of(library, random, clock, deltas, &store));
    }

    [[nodiscard]] ServerResponse get(std::string route, std::string_view token = lea,
        std::string_view platform = "switch", std::string_view range = {}) const
    {
        return ::get(*server, std::move(route), token, platform, range);
    }

    [[nodiscard]] ServerResponse send(
        std::string method, std::string route, std::string body = {}, std::string_view token = root) const
    {
        Call call;
        call.method = std::move(method);
        call.target = std::move(route);
        call.body   = std::move(body);
        if (!call.body.empty())
            call.headers.emplace_back("Content-Type", "application/json");
        return go(*server, std::move(call), token);
    }

    // The token of a device paired and approved by the admin with `cap`, for `lea`, the scope library.
    [[nodiscard]] std::string capped_token(std::string_view cap) const
    {
        const ServerResponse pairing
            = send("POST", "/pairing", R"({"schema":1,"device":"Lea's tablet","scopes":["library"]})", {});
        REQUIRE(pairing.status == 200);
        const std::string poll = text_of(pairing.body, "poll").substr(base.size());
        const std::string id   = text_of(get("/admin/pairings", root).body, "id");
        REQUIRE(send("POST", "/admin/pairings/" + id,
                    R"({"schema":1,"decision":"approve","user":"lea","scopes":["library"],"rating_cap":)"
                        + std::string(cap) + "}")
                    .status
            == 204);
        const std::string token = text_of(get(poll, {}).body, "token");
        REQUIRE_FALSE(token.empty());
        return token;
    }
};

} // namespace

TEST_CASE("deltas: the route gives the index of a file the caller reads (L-22.1-2)")
{
    const Fixture f;
    CHECK(f.get("/").body.contains(R"("deltas":1)"));
    const ServerResponse reply = f.get("/chunks/sha256/" + f.gentle_hex);
    REQUIRE(reply.status == 200);
    CHECK(header(reply, "Content-Type") == "application/json");
    CHECK(header(reply, "Cache-Control") == "private, max-age=31536000, immutable");
    CHECK(header(reply, "Accept-Ranges") == "bytes");
    const std::string raw = body_of(reply);
    CHECK(raw.contains(R"("alg":"lantern-cdc-1")"));
    CHECK(raw.starts_with(R"({"chunker":)"));
    CHECK(raw.contains(R"("schema":1,"sha256":")" + f.gentle_hex + R"(","size":200000})"));
    // Its address, size and SHA-256 are the app's `chunks`
    const std::string apps(f.get("/apps").body);
    CHECK(apps.contains(R"("chunks":{"url":"/api/lantern/v1/chunks/sha256/)" + f.gentle_hex + R"(","size":)"
        + std::to_string(raw.size()) + R"(,"sha256":")" + hex_of(Sha256::of(std::string_view(raw)))
        + R"("})"));
    CHECK(header(reply, "Repr-Digest").contains(":"));
    // The same bytes by the index's own SHA-256, for a client that keeps them
    CHECK(body_of(f.get("/chunks/sha256/" + f.mature_hex)).starts_with(R"({"chunker":)"));
    // HEAD: the head alone; a range of the index
    const ServerResponse head = f.send("HEAD", "/chunks/sha256/" + f.gentle_hex, {}, lea);
    CHECK(head.status == 200);
    CHECK(head.body.empty());
    CHECK_FALSE(head.file.has_value());
    CHECK(header(head, "Content-Length") == std::to_string(raw.size()));
    const ServerResponse part = f.get("/chunks/sha256/" + f.gentle_hex, lea, "switch", "bytes=0-9");
    CHECK(part.status == 206);
    CHECK(body_of(part) == raw.substr(0, 10));
    // Anonymous on a server that asks for no token: the scope everyone holds
    CHECK(f.get("/chunks/sha256/" + f.gentle_hex, {}).status == 200);
}

TEST_CASE("deltas: what the route does not have is a 404 (L-22.1-2)")
{
    const Fixture f;
    // A small file has no index; an unknown file, a SHA-256 in upper case and one that is not one
    refused(f.get("/chunks/sha256/" + f.tiny_hex), 404, "not_found");
    refused(f.get("/chunks/sha256/" + std::string(64, '0')), 404, "not_found");
    std::string upper = f.gentle_hex;
    for (char& c : upper)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    refused(f.get("/chunks/sha256/" + upper), 404, "not_found");
    refused(f.get("/chunks/sha256/xyz"), 404, "not_found");
    // Another platform than the file's: the server has no such file
    refused(f.get("/chunks/sha256/" + f.gentle_hex, lea, "linux"), 404, "not_found");
    // A token without the scope library
    CHECK(f.get("/chunks/sha256/" + f.gentle_hex, nolib).status == 403);
    // Only GET and HEAD
    CHECK(f.send("POST", "/chunks/sha256/" + f.gentle_hex, R"({"schema":1})", lea).status == 405);
}

TEST_CASE("deltas: a rating cap hides the index of what it hides (SPEC.md 5.6)")
{
    const Fixture f;
    const std::string token = f.capped_token(R"({"age":12})");
    CHECK(f.get("/chunks/sha256/" + f.gentle_hex, token).status == 200);
    refused(f.get("/chunks/sha256/" + f.mature_hex, token), 404, "not_found");
    CHECK(f.get("/chunks/sha256/" + f.mature_hex, lea).status == 200);
    // Its chunks are ranges of the file, which the cap hides as well
    const std::string file
        = text_of(f.get("/apps?title_id=" + std::string(mature), lea).body, "file").substr(base.size());
    CHECK(f.get(file, lea, "switch", "bytes=0-9").status == 206);
    refused(f.get(file, token, "switch", "bytes=0-9"), 404, "not_found");
}

TEST_CASE("deltas: a server that does not offer them says so, and has no route")
{
    // The library writes indexes, the server does not serve them: `deltas` is 0 and the route a 404
    const Fixture off(false);
    CHECK(off.get("/").body.contains(R"("deltas":0)"));
    refused(off.get("/chunks/sha256/" + off.gentle_hex), 404, "not_found");
    // The server offers them, the library has none: `deltas` is 1 and no app names an index
    const Fixture none(true, false);
    CHECK(none.get("/").body.contains(R"("deltas":1)"));
    CHECK_FALSE(none.get("/apps").body.contains(R"("chunks")"));
    refused(none.get("/chunks/sha256/" + none.gentle_hex), 404, "not_found");
    // A caller who does not read the library is not told of the family
    CHECK(none.get("/", nolib).body.contains(R"("deltas":0)"));
}

TEST_CASE("deltas: the library's options, and what it keeps")
{
    MemoryLibrary library { "/api/lantern" };
    // A chunker is a power of two from 64 KiB to 4 MiB, or 0 to choose
    ChunkingOptions bad;
    bad.chunker_size = 1000;
    CHECK_FALSE(library.offer_deltas(bad));
    bad.chunker_size = 32768;
    CHECK_FALSE(library.offer_deltas(bad));
    bad.chunker_size = 65536 + 1;
    CHECK_FALSE(library.offer_deltas(bad));
    // Before offer_deltas(), no app has chunks
    const Bytes content = stream("kept", 300'000);
    const auto before   = library.add_app(draft_of(gentle, "Gentle"), content);
    REQUIRE(before);
    CHECK_FALSE(before->chunks.has_value());
    ChunkingOptions chunking;
    chunking.chunker_size  = 131072;
    chunking.min_file_size = 200'000;
    REQUIRE(library.offer_deltas(chunking));
    // A file below the least is left out; one above has its index, once for the same bytes
    const auto small = library.add_app(draft_of(tiny, "Tiny"), stream("small", 199'999));
    REQUIRE(small);
    CHECK_FALSE(small->chunks.has_value());
    const auto first = library.add_app(draft_of(mature, "Mature", 1), content);
    const auto again = library.add_app(draft_of(mature, "Mature", 2), content);
    REQUIRE(first);
    REQUIRE(again);
    REQUIRE(first->chunks);
    REQUIRE(again->chunks);
    CHECK(first->chunks->sha256 == again->chunks->sha256);
    CHECK(std::string_view(first->chunks->url)
        == "/api/lantern/v1/chunks/sha256/" + hex_of(Sha256::of(content)));
    const auto kept = library.chunk_index(Sha256::of(content), {});
    REQUIRE(kept);
    REQUIRE(*kept);
    CHECK((*kept)->size == first->chunks->size);
    CHECK((*kept)->sha256 == first->chunks->sha256);
    CHECK((*kept)->content_type == "application/json");
    const std::string raw = reader_text(**kept);
    const auto index      = read_chunk_index(raw, nullptr, Sha256::of(content), content.size());
    REQUIRE(index);
    REQUIRE(*index);
    CHECK((*index)->chunker_size == 131072);
    // The index goes with the last app that names the file
    CHECK(library.remove_app(first->id));
    const auto still = library.chunk_index(Sha256::of(content), {});
    REQUIRE(still);
    CHECK(still->has_value());
    // (the app added before has no `chunks`: it keeps no index alive)
    CHECK(library.remove_app(again->id));
    const auto gone = library.chunk_index(Sha256::of(content), {});
    REQUIRE(gone);
    CHECK_FALSE(gone->has_value());
}

TEST_CASE("deltas: a homebrew package of enough bytes carries chunks too, for its platform")
{
    MemoryLibrary library { "/api/lantern" };
    ChunkingOptions chunking;
    chunking.min_file_size = 100'000;
    REQUIRE(library.offer_deltas(chunking));
    const Bytes content = stream("a homebrew package", 150'000);
    Homebrew entry;
    entry.id             = "org.example.big";
    entry.platform       = "switch";
    entry.kind           = "tool";
    entry.name           = "Big";
    entry.version        = "1.0.0";
    entry.build          = 1;
    entry.package.format = "nro";
    entry.package.path   = "/switch/org.example.big/org.example.big.nro";
    entry.package.size   = content.size();
    entry.package.sha256 = Sha256::of(content);
    ManifestEntry single;
    single.path                   = entry.package.path;
    single.size                   = entry.package.size;
    single.sha256                 = entry.package.sha256;
    entry.package.manifest_sha256 = manifest_digest(std::span(&single, 1));
    const std::array<std::span<const std::byte>, 1> contents { content };
    const auto served = library.add_homebrew(entry, contents);
    REQUIRE(served);
    REQUIRE(served->package.chunks);

    CountingRandom random;
    FakeClock clock;
    const Server server         = server_of(library, random, clock, true);
    const std::string file_hex  = hex_of(entry.package.sha256);
    const ServerResponse listed = get(server, "/homebrew");
    REQUIRE(listed.status == 200);
    CHECK(listed.body.contains(R"("chunks":{"url":"/api/lantern/v1/chunks/sha256/)" + file_hex + R"(",)"));
    const ServerResponse index = get(server, "/chunks/sha256/" + file_hex);
    REQUIRE(index.status == 200);
    const std::string raw = body_of(index);
    CHECK(raw.size() == served->package.chunks->size);
    CHECK(Sha256::of(std::string_view(raw)) == served->package.chunks->sha256);
    // The platform of the package: another one has no such file
    refused(get(server, "/chunks/sha256/" + file_hex, {}, "linux"), 404, "not_found");
    // The index goes with the entry
    CHECK(library.remove_homebrew("switch", "org.example.big"));
    refused(get(server, "/chunks/sha256/" + file_hex), 404, "not_found");
    const auto gone = library.chunk_index(entry.package.sha256, {});
    REQUIRE(gone);
    CHECK_FALSE(gone->has_value());
}
