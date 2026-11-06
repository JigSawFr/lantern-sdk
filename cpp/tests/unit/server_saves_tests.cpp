// The server core's save backups (include/lantern/server.hpp, saves.hpp;
// SPEC.md § 9): a save sent in one request, the resumable upload with its
// offsets and its cut chunks, the digests the server checks, the backups kept
// per title, the scope `saves`, and the backups encrypted on the device kept as
// sent (§ 9.4). The core is called in memory, with no socket; the conformance
// suite plays the same against the demo server.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
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
constexpr std::string_view lea    = "et_lea-0123456789abcdef0123456789abcdef";
constexpr std::string_view kim    = "et_kim-0123456789abcdef0123456789abcdef";
constexpr std::string_view reader = "et_reader-0123456789abcdef0123456789ab";
constexpr std::string_view title  = "0100ABCD00010000";

class CountingRandom final : public RandomSource
{
  public:
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        for (std::size_t at = 0; at < out.size(); at += 32)
        {
            const std::string seed = "saves-test-random:" + std::to_string(counter_++);
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

// A body read from memory, cut after `cut` bytes as a lost connection is.
class SliceBody final : public BodyReader
{
  public:
    SliceBody(std::string_view data, std::size_t cut)
        : data_(data)
        , cut_(std::min(cut, data.size()))
    {
    }

    Result<std::size_t> read(std::span<std::byte> buffer) override
    {
        if (at_ >= cut_)
        {
            if (cut_ < data_.size())
                return fail(Category::transport, "the connection was cut");
            return std::size_t { 0 };
        }
        const std::size_t take = std::min({ buffer.size(), cut_ - at_, std::size_t { 1000 } });
        std::ranges::copy_n(reinterpret_cast<const std::byte*>(data_.data()) + at_,
            static_cast<std::ptrdiff_t>(take), buffer.begin());
        at_ += take;
        return take;
    }

  private:
    std::string_view data_;
    std::size_t cut_;
    std::size_t at_ = 0;
};

// The bytes of a large zip, made as they are asked for: a body no test holds.
std::byte generated_byte(std::uint64_t index)
{
    constexpr std::string_view head = "PK\x03\x04";
    if (index < head.size())
        return static_cast<std::byte>(head[static_cast<std::size_t>(index)]);
    return static_cast<std::byte>((index * 2654435761ULL) >> 13U);
}

class GeneratedBody final : public BodyReader
{
  public:
    explicit GeneratedBody(std::uint64_t total)
        : total_(total)
    {
    }

    Result<std::size_t> read(std::span<std::byte> buffer) override
    {
        const std::size_t take
            = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), total_ - at_));
        for (std::size_t i = 0; i < take; ++i)
            buffer[i] = generated_byte(at_ + i);
        at_ += take;
        return take;
    }

    [[nodiscard]] Digest digest() const
    {
        Sha256 hash;
        for (std::uint64_t i = 0; i < total_; ++i)
        {
            const std::byte one = generated_byte(i);
            hash.update(std::span(&one, 1));
        }
        return hash.finish();
    }

  private:
    std::uint64_t total_;
    std::uint64_t at_ = 0;
};

using Headers = std::vector<std::pair<std::string, std::string>>;

struct Call
{
    std::string method = "GET";
    std::string target;
    Headers headers;
    std::string body;
    BodyReader* stream          = nullptr;
    std::uint64_t stream_length = 0;
};

ServerResponse send(const Server& server, const Call& call)
{
    const auto parsed = parse_target(call.target);
    REQUIRE(parsed);
    std::vector<QueryParam> query;
    for (const auto& [name, value] : parsed->query)
        query.push_back({ name, value });
    std::vector<Header> headers;
    for (const auto& [name, value] : call.headers)
        headers.push_back({ name, value });
    ServerRequest request;
    request.method        = call.method;
    request.path          = parsed->path;
    request.query         = query;
    request.headers       = headers;
    request.stream        = call.stream;
    request.stream_length = call.stream_length;
    if (call.stream == nullptr)
        request.body = std::as_bytes(std::span(call.body.data(), call.body.size()));
    request.scheme = "http";
    request.target = call.target;
    request.remote = "192.0.2.10";
    return server.handle(request);
}

std::string_view header(const ServerResponse& response, std::string_view name)
{
    return response.headers.get(name).value_or(std::string_view {});
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

void refused(const ServerResponse& response, std::uint16_t status, std::string_view code)
{
    CHECK(response.status == status);
    CHECK(header(response, "Content-Type") == "application/problem+json");
    auto read = read_problem(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->code == code);
}

// A zip's first bytes and `size` bytes in all, and its Content-Digest.
std::string zip_of(std::size_t size, char fill = 'a')
{
    std::string out = "PK\x03\x04";
    out.resize(size, fill);
    return out;
}

std::string digest_of(std::string_view bytes)
{
    String text;
    format_digest_field(Sha256::of(bytes), text);
    return std::string(text);
}

std::string hex_of(std::string_view bytes)
{
    const auto hex = to_hex(Sha256::of(bytes));
    return std::string(hex.data(), hex.size());
}

// The header of an encrypted backup (§ 9.4): LTNE2E01, the key id's 8 bytes, then whatever follows.
std::string encrypted_of(std::string_view key_id_hex, std::size_t size)
{
    std::string out = "LTNE2E01";
    for (std::size_t i = 0; i < 16; i += 2)
        out.push_back(static_cast<char>(std::stoi(std::string(key_id_hex.substr(i, 2)), nullptr, 16)));
    out.resize(size, '\x5a');
    return out;
}

struct Fixture
{
    MemoryLibrary library { "/api/lantern" };
    CountingRandom random;
    FakeClock clock;
    MemoryAccountStore store;
    MemorySaveStore saves;
    ServerOptions options;
    std::optional<Server> server;

    explicit Fixture(SaveLimits limits = {}, bool encrypted = true, bool with_saves = true,
        std::pmr::memory_resource* memory = nullptr)
    {
        constexpr std::array<std::string_view, 2> with { "library", "saves" };
        constexpr std::array<std::string_view, 1> without { "library" };
        REQUIRE(store.add_account("lea", with));
        REQUIRE(store.add_account("kim", with));
        REQUIRE(store.add_account("reader", without));
        REQUIRE(store.add_token(lea, "lea", "Lea's console", with, std::nullopt, start));
        REQUIRE(store.add_token(kim, "kim", "Kim's console", with, std::nullopt, start));
        REQUIRE(store.add_token(reader, "reader", "A tablet", without, std::nullopt, start));
        options.uid             = uid;
        options.name            = "Test shelf";
        options.scheme          = "http";
        options.accounts        = &store;
        options.saves           = with_saves ? &saves : nullptr;
        options.save_limits     = limits;
        options.encrypted_saves = encrypted;
        auto made               = Server::create(
            library, options, random, clock, memory != nullptr ? Allocator(memory) : Allocator());
        REQUIRE(made);
        server.emplace(std::move(*made));
    }

    [[nodiscard]] ServerResponse go(
        Call call, std::string_view token = lea, std::string_view platform = "switch") const
    {
        call.target = std::string(base) + call.target;
        call.headers.emplace_back("Host", "shelf.example.org");
        if (!token.empty())
            call.headers.emplace_back("Authorization", "Bearer " + std::string(token));
        if (!platform.empty())
            call.headers.emplace_back("Lantern-Platform", std::string(platform));
        return send(*server, call);
    }

    [[nodiscard]] ServerResponse get(std::string route, std::string_view token = lea) const
    {
        Call call;
        call.target = std::move(route);
        return go(std::move(call), token);
    }

    // POST /saves/{title}: `bytes` as the body, with the Content-Digest of `announced` (its own when empty).
    [[nodiscard]] ServerResponse post_save(std::string_view bytes, std::string_view announced = {},
        Headers extra = {}, std::string_view token = lea, std::string_view id = title) const
    {
        Call call;
        call.method = "POST";
        call.target = "/saves/" + std::string(id);
        call.body   = bytes;
        call.headers.emplace_back("Content-Type", "application/zip");
        if (announced != "none")
            call.headers.emplace_back("Content-Digest", digest_of(announced.empty() ? bytes : announced));
        for (auto& item : extra)
            call.headers.push_back(std::move(item));
        return go(std::move(call), token);
    }

    // POST /saves/{title}/uploads: the upload of `bytes` (or of the size and digest told).
    [[nodiscard]] ServerResponse open(
        std::string_view bytes, std::string_view fields = {}, std::string_view token = lea) const
    {
        Call call;
        call.method = "POST";
        call.target = "/saves/" + std::string(title) + "/uploads";
        call.headers.emplace_back("Content-Type", "application/json");
        call.body = R"({"schema":1,"size":)" + std::to_string(bytes.size()) + R"(,"sha256":")" + hex_of(bytes)
            + "\"" + std::string(fields) + "}";
        return go(std::move(call), token);
    }

    [[nodiscard]] ServerResponse patch(const std::string& address, std::uint64_t offset,
        std::string_view chunk, Headers extra = {}, std::string_view token = lea) const
    {
        Call call;
        call.method = "PATCH";
        call.target = address.substr(base.size());
        call.body   = chunk;
        call.headers.emplace_back("Content-Type", "application/offset+octet-stream");
        call.headers.emplace_back("Upload-Offset", std::to_string(offset));
        for (auto& item : extra)
            call.headers.push_back(std::move(item));
        return go(std::move(call), token);
    }

    [[nodiscard]] ServerResponse upload_call(
        std::string_view method, const std::string& address, std::string_view token = lea) const
    {
        Call call;
        call.method = std::string(method);
        call.target = address.substr(base.size());
        return go(std::move(call), token);
    }

    [[nodiscard]] Save saved(const ServerResponse& response) const
    {
        CHECK(response.status == 201);
        auto read = read_save(response.body);
        REQUIRE(read);
        REQUIRE(*read);
        return std::move(**read);
    }

    // The upload an `open()` made: its address and chunk size.
    [[nodiscard]] UploadSession opened(const ServerResponse& response) const
    {
        CHECK(response.status == 201);
        auto read = read_upload_session(response.body);
        REQUIRE(read);
        REQUIRE(*read);
        CHECK(header(response, "Location") == std::string((*read)->upload));
        return std::move(**read);
    }

    [[nodiscard]] Saves listed(std::string route = "/saves", std::string_view token = lea) const
    {
        const ServerResponse response = get(std::move(route), token);
        CHECK(response.status == 200);
        auto read = read_saves(response.body);
        REQUIRE(read);
        REQUIRE(*read);
        return std::move(**read);
    }
};

} // namespace

TEST_CASE("saves: a save sent in one request is checked, kept, listed and read back whole")
{
    Fixture f;
    const std::string archive = zip_of(3000);
    ServerResponse made       = f.post_save(archive, {},
              { { "Lantern-Save-Kind", "account" }, { "Lantern-Save-Slot", "slot-1" },
                  { "Lantern-Game-Version", "196608" }, { "Lantern-Profile", "L%C3%A9a" },
                  { "Lantern-Note", "Chapter%204" } });
    const Save save           = f.saved(made);
    CHECK(save.platform == "switch");
    CHECK(save.title_id == title);
    CHECK(save.size == archive.size());
    CHECK(save.sha256 == Sha256::of(std::string_view(archive)));
    CHECK(save.kind == "account");
    CHECK(save.slot == "slot-1");
    CHECK(save.game_version_code == std::uint64_t { 196608 });
    CHECK(save.profile
        == "L\xc3\xa9"
           "a");
    CHECK(save.note == "Chapter 4");
    CHECK(save.device == "Lea's console");
    CHECK(save.created == "2026-10-26T07:33:20Z");
    CHECK_FALSE(save.encryption.has_value());

    const Saves all = f.listed();
    REQUIRE(all.saves.size() == 1);
    CHECK(all.saves[0].save_id == save.save_id);

    const ServerResponse file = f.get("/saves/" + std::string(title) + "/" + std::string(save.save_id));
    CHECK(file.status == 200);
    CHECK(header(file, "Content-Type") == "application/zip");
    CHECK(header(file, "Repr-Digest") == digest_of(archive));
    CHECK(body_of(file) == archive);

    // A range of it, and the listing's validators
    Call ranged;
    ranged.target = "/saves/" + std::string(title) + "/" + std::string(save.save_id);
    ranged.headers.emplace_back("Range", "bytes=0-3");
    const ServerResponse part = f.go(std::move(ranged));
    CHECK(part.status == 206);
    CHECK(body_of(part) == "PK\x03\x04");
    const ServerResponse listing = f.get("/saves");
    REQUIRE(!header(listing, "ETag").empty());
    Call again;
    again.target = "/saves";
    again.headers.emplace_back("If-None-Match", std::string(header(listing, "ETag")));
    CHECK(f.go(std::move(again)).status == 304);

    // Removed (204), then gone (404)
    Call drop;
    drop.method = "DELETE";
    drop.target = "/saves/" + std::string(title) + "/" + std::string(save.save_id);
    CHECK(f.go(drop).status == 204);
    refused(f.go(drop), 404, "not_found");
    CHECK(f.listed().saves.empty());
}

TEST_CASE("saves: the Content-Digest, the platform, the title and the archive are checked")
{
    Fixture f;
    const std::string archive = zip_of(100);
    refused(f.post_save(archive, "none"), 400, "bad_request");
    refused(f.post_save(archive, "other bytes"), 422, "digest_mismatch");
    Call malformed;
    malformed.method = "POST";
    malformed.target = "/saves/" + std::string(title);
    malformed.body   = archive;
    malformed.headers.emplace_back("Content-Digest", "sha-512=:AAAA:");
    refused(f.go(malformed), 400, "bad_request");
    // No platform (L-4.3-4), a title that is not the platform's, a platform of no save
    {
        Call call;
        call.method = "POST";
        call.target = "/saves/" + std::string(title);
        call.body   = archive;
        call.headers.emplace_back("Content-Digest", digest_of(archive));
        refused(f.go(call, lea, ""), 400, "bad_request");
        refused(f.post_save(archive, {}, {}, lea, "not-a-switch-id"), 400, "bad_request");
        refused(f.go(call, lea, "web"), 400, "bad_request");
    }
    // Not a zip: a 400, whatever the digest says; the fields are held to § 13
    const std::string notes = "this is not a zip archive at all";
    refused(f.post_save(notes), 400, "bad_request");
    refused(f.post_save(archive, {}, { { "Lantern-Save-Kind", "party" } }), 400, "bad_request");
    refused(f.post_save(archive, {}, { { "Lantern-Save-Slot", "no spaces" } }), 400, "bad_request");
    refused(f.post_save(archive, {}, { { "Lantern-Game-Version", "-1" } }), 400, "bad_request");
    refused(f.post_save(archive, {}, { { "Lantern-Note", "%FF%FE" } }), 400, "bad_request");
    refused(f.post_save(archive, {}, { { "Lantern-Profile", std::string(65, 'x') } }), 400, "bad_request");
    CHECK(f.listed().saves.empty());
    CHECK(f.saved(f.post_save(archive)).size == archive.size());
}

TEST_CASE("saves: a save above limits.save_body is a 413 and nothing is kept")
{
    SaveLimits limits;
    limits.body = 1000;
    Fixture f(limits);
    const std::string big = zip_of(1001);
    refused(f.post_save(big), 413, "too_large");
    CHECK(f.saved(f.post_save(zip_of(1000))).size == 1000);
    CHECK(f.listed().saves.size() == 1);
    // The handshake says the limits
    auto shake = read_handshake(body_of(f.get("/")));
    REQUIRE(shake);
    REQUIRE(*shake);
    CHECK((*shake)->limits->save_body == std::optional<std::uint64_t> { 1000 });
}

TEST_CASE("saves: the oldest backups beyond saves_kept_per_title are dropped, per title and per account")
{
    SaveLimits limits;
    limits.kept = 2;
    Fixture f(limits);
    std::vector<std::string> ids;
    for (int i = 0; i < 4; ++i)
    {
        f.clock.now += 60;
        ids.push_back(std::string(f.saved(f.post_save(zip_of(50 + static_cast<std::size_t>(i)))).save_id));
    }
    const std::string other_title = "0100ABCD00020000";
    f.clock.now += 60;
    const std::string other_id
        = std::string(f.saved(f.post_save(zip_of(70), {}, {}, lea, other_title)).save_id);
    f.clock.now += 60;
    const std::string kims = std::string(f.saved(f.post_save(zip_of(80), {}, {}, kim)).save_id);

    const Saves mine = f.listed();
    REQUIRE(mine.saves.size() == 3);
    // Per title, the newest first
    CHECK(mine.saves[0].title_id == title);
    CHECK(std::string_view(mine.saves[0].save_id) == ids[3]);
    CHECK(std::string_view(mine.saves[1].save_id) == ids[2]);
    CHECK(std::string_view(mine.saves[2].title_id) == other_title);
    CHECK(std::string_view(mine.saves[2].save_id) == other_id);
    CHECK(f.listed("/saves?title_id=" + other_title).saves.size() == 1);
    CHECK(f.listed("/saves?platform=vita").saves.empty());
    // Kim sees her own alone
    const Saves hers = f.listed("/saves", kim);
    REQUIRE(hers.saves.size() == 1);
    CHECK(std::string_view(hers.saves[0].save_id) == kims);
    refused(f.get("/saves/" + std::string(title) + "/" + kims), 404, "not_found");
}

TEST_CASE("saves: the scope saves, and a server with no store has no route")
{
    Fixture f;
    refused(f.get("/saves", reader), 403, "forbidden");
    refused(f.get("/saves", ""), 401, "unauthorized");
    refused(f.post_save(zip_of(10), {}, {}, reader), 403, "forbidden");
    refused(f.open(zip_of(10), {}, reader), 403, "forbidden");
    // The handshake offers saves to whoever holds the scope
    const auto offered = [&](std::string_view token)
    {
        auto shake = read_handshake(body_of(f.get("/", token)));
        REQUIRE(shake);
        REQUIRE(*shake);
        return std::pair<std::uint64_t, std::uint64_t> { (*shake)->features.saves.value_or(99),
            (*shake)->features.encrypted_saves.value_or(99) };
    };
    CHECK(offered(lea) == std::pair<std::uint64_t, std::uint64_t> { 1, 1 });
    CHECK(offered(reader) == std::pair<std::uint64_t, std::uint64_t> { 0, 0 });
    CHECK(offered("") == std::pair<std::uint64_t, std::uint64_t> { 0, 0 });

    Fixture none({}, true, false);
    refused(none.get("/saves"), 404, "not_found");
    auto shake = read_handshake(body_of(none.get("/")));
    REQUIRE(shake);
    REQUIRE(*shake);
    CHECK((*shake)->features.saves == std::optional<std::uint64_t> { 0 });
    CHECK((*shake)->features.encrypted_saves == std::optional<std::uint64_t> { 0 });
    CHECK_FALSE((*shake)->limits->save_body.has_value());
}

TEST_CASE("saves: an upload in chunks, with the offsets, the 409 and the digests of § 9.3")
{
    SaveLimits limits;
    limits.chunk = 400;
    Fixture f(limits);
    const std::string archive = zip_of(1000, 'q');
    const UploadSession up
        = f.opened(f.open(archive, R"(,"kind":"device","game_version_code":7,"note":"n")"));
    CHECK(up.chunk_size == 400);
    CHECK(up.offset == 0);
    CHECK(up.expires == "2026-10-27T07:33:20Z");
    CHECK(std::string_view(up.upload).starts_with("/api/lantern/v1/uploads/u_"));
    const std::string address(up.upload);

    ServerResponse head = f.upload_call("HEAD", address);
    CHECK(head.status == 204);
    CHECK(header(head, "Upload-Offset") == "0");
    CHECK(header(head, "Upload-Length") == "1000");
    CHECK(header(head, "Lantern-Chunk-Size") == "400");

    // A chunk above chunk_size (413), past the size (400), at another offset (409 with the server's),
    // unreadable (400)
    refused(f.patch(address, 0, std::string(401, 'x')), 413, "too_large");
    ServerResponse wrong = f.patch(address, 5, archive.substr(0, 100));
    refused(wrong, 409, "conflict");
    CHECK(header(wrong, "Upload-Offset") == "0");
    Call typed;
    typed.method = "PATCH";
    typed.target = address.substr(base.size());
    typed.body   = archive.substr(0, 100);
    typed.headers.emplace_back("Content-Type", "application/octet-stream");
    typed.headers.emplace_back("Upload-Offset", "0");
    refused(f.go(typed), 400, "bad_request");
    refused(f.patch(address, 0, archive.substr(0, 100), { { "Content-Digest", "nonsense" } }), 400,
        "bad_request");

    // A chunk with the digest of another is refused whole: the upload stays where it was
    refused(f.patch(address, 0, archive.substr(0, 400), { { "Content-Digest", digest_of("not that") } }), 422,
        "digest_mismatch");
    CHECK(header(f.upload_call("HEAD", address), "Upload-Offset") == "0");

    const ServerResponse first = f.patch(
        address, 0, archive.substr(0, 400), { { "Content-Digest", digest_of(archive.substr(0, 400)) } });
    CHECK(first.status == 204);
    CHECK(header(first, "Upload-Offset") == "400");
    CHECK(header(f.upload_call("HEAD", address), "Upload-Offset") == "400");
    // Only the account that opened it sees it
    CHECK(f.upload_call("HEAD", address, kim).status == 404);
    refused(f.patch(address, 400, archive.substr(400, 400), {}, kim), 404, "not_found");
    const ServerResponse second = f.patch(address, 400, archive.substr(400, 400));
    CHECK(second.status == 204);
    refused(f.patch(address, 800, std::string(201, 'x')), 400, "bad_request");

    const ServerResponse last = f.patch(address, 800, archive.substr(800));
    const Save save           = f.saved(last);
    CHECK(header(last, "Upload-Offset") == "1000");
    CHECK(save.size == 1000);
    CHECK(save.sha256 == Sha256::of(std::string_view(archive)));
    CHECK(save.kind == "device");
    CHECK(save.game_version_code == std::uint64_t { 7 });
    CHECK(save.note == "n");
    CHECK(body_of(f.get("/saves/" + std::string(title) + "/" + std::string(save.save_id))) == archive);
    // It is over: the upload is gone
    CHECK(f.upload_call("HEAD", address).status == 404);
}

TEST_CASE("saves: an upload whose archive is not the one announced is discarded (422)")
{
    SaveLimits limits;
    limits.chunk = 400;
    Fixture f(limits);
    const std::string archive  = zip_of(600);
    const std::string tampered = zip_of(600, 'b');
    const UploadSession up     = f.opened(f.open(archive));
    const std::string address(up.upload);
    CHECK(f.patch(address, 0, tampered.substr(0, 400)).status == 204);
    refused(f.patch(address, 400, tampered.substr(400)), 422, "digest_mismatch");
    CHECK(f.upload_call("HEAD", address).status == 404);
    CHECK(f.listed().saves.empty());

    // An archive that is no zip is a 400 and discarded as well
    const std::string notes    = "this is not a zip archive at all";
    const UploadSession second = f.opened(f.open(notes));
    refused(f.patch(std::string(second.upload), 0, notes), 400, "bad_request");
    CHECK(f.upload_call("HEAD", std::string(second.upload)).status == 404);
}

TEST_CASE("saves: an upload above limits.save_size is a 413; one is abandoned, or expires")
{
    SaveLimits limits;
    limits.body         = 1000;
    limits.size         = 5000;
    limits.upload_hours = 2;
    Fixture f(limits);
    ServerResponse big = f.open("x");
    CHECK(big.status == 201);
    Call too_big;
    too_big.method = "POST";
    too_big.target = "/saves/" + std::string(title) + "/uploads";
    too_big.headers.emplace_back("Content-Type", "application/json");
    too_big.body = R"({"schema":1,"size":5001,"sha256":")" + hex_of("x") + "\"}";
    refused(f.go(too_big), 413, "too_large");
    too_big.body = R"({"schema":2,"size":5001,"sha256":")" + hex_of("x") + "\"}";
    refused(f.go(too_big), 422, "unsupported_schema");
    too_big.body = R"({"schema":1,"size":10,"sha256":"nothex"})";
    refused(f.go(too_big), 400, "bad_request");
    too_big.body = R"({"schema":1,"size":10,"sha256":")" + hex_of("x") + R"(","kind":"party"})";
    refused(f.go(too_big), 400, "bad_request");

    const std::string address(f.opened(big).upload);
    CHECK(f.upload_call("DELETE", address).status == 204);
    CHECK(f.upload_call("HEAD", address).status == 404);
    refused(f.upload_call("DELETE", address), 404, "not_found");

    const std::string kept(f.opened(f.open("y")).upload);
    CHECK(f.upload_call("HEAD", kept).status == 204);
    f.clock.now += 2 * 3600 + 1;
    CHECK(f.upload_call("HEAD", kept).status == 404);
}

TEST_CASE("saves: a chunk cut by a lost connection keeps what came, and the upload resumes from the offset")
{
    SaveLimits limits;
    limits.chunk = 4096;
    Fixture f(limits);
    const std::string archive = zip_of(3000, 'z');
    const std::string address(f.opened(f.open(archive)).upload);

    // The connection is lost after 1234 bytes of the chunk, which carries no digest of its own
    SliceBody cut(archive, 1234);
    Call interrupted;
    interrupted.method = "PATCH";
    interrupted.target = address.substr(base.size());
    interrupted.headers.emplace_back("Content-Type", "application/offset+octet-stream");
    interrupted.headers.emplace_back("Upload-Offset", "0");
    interrupted.stream        = &cut;
    interrupted.stream_length = archive.size();
    CHECK(f.go(interrupted).status == 400);
    // HEAD says how much was kept (§ 9.3), and the client resumes there
    const ServerResponse head = f.upload_call("HEAD", address);
    CHECK(header(head, "Upload-Offset") == "1234");
    SliceBody rest(std::string_view(archive).substr(1234), archive.size());
    Call resumed;
    resumed.method = "PATCH";
    resumed.target = address.substr(base.size());
    resumed.headers.emplace_back("Content-Type", "application/offset+octet-stream");
    resumed.headers.emplace_back("Upload-Offset", "1234");
    resumed.stream        = &rest;
    resumed.stream_length = archive.size() - 1234;
    const Save save       = f.saved(f.go(resumed));
    CHECK(body_of(f.get("/saves/" + std::string(title) + "/" + std::string(save.save_id))) == archive);

    // A cut chunk that carried its digest is not kept at all: whole chunks only
    const std::string second_address(f.opened(f.open(archive)).upload);
    SliceBody cut_again(archive, 500);
    Call vouched;
    vouched.method = "PATCH";
    vouched.target = second_address.substr(base.size());
    vouched.headers.emplace_back("Content-Type", "application/offset+octet-stream");
    vouched.headers.emplace_back("Upload-Offset", "0");
    vouched.headers.emplace_back("Content-Digest", digest_of(archive));
    vouched.stream        = &cut_again;
    vouched.stream_length = archive.size();
    CHECK(f.go(vouched).status == 400);
    CHECK(header(f.upload_call("HEAD", second_address), "Upload-Offset") == "0");
}

TEST_CASE("saves: a large body is streamed to the store, never held whole")
{
    constexpr std::uint64_t total = std::uint64_t { 4 } << 20U;
    SaveLimits limits;
    limits.body = total;
    std::pmr::synchronized_pool_resource upstream;
    CountingResource counted(&upstream);
    Fixture f(limits, true, true, &counted);
    GeneratedBody body(total);
    const Digest digest = body.digest();
    String announced;
    format_digest_field(digest, announced);

    Call call;
    call.method = "POST";
    call.target = "/saves/" + std::string(title);
    call.headers.emplace_back("Content-Type", "application/zip");
    call.headers.emplace_back("Content-Digest", std::string(announced));
    call.stream              = &body;
    call.stream_length       = total;
    const std::size_t before = counted.peak();
    const Save save          = f.saved(f.go(std::move(call)));
    CHECK(save.size == total);
    CHECK(save.sha256 == digest);
    // The server's own memory stayed far below the body (the store keeps the archive in its own)
    CHECK(counted.peak() - before < total / 8);

    // The archive back, and the wrong digest of a streamed body (422, nothing kept)
    const ServerResponse file = f.get("/saves/" + std::string(title) + "/" + std::string(save.save_id));
    CHECK(file.status == 200);
    CHECK(file.file->length == total);
    GeneratedBody again(total);
    Call wrong;
    wrong.method = "POST";
    wrong.target = "/saves/" + std::string(title);
    wrong.headers.emplace_back("Content-Type", "application/zip");
    wrong.headers.emplace_back("Content-Digest", digest_of("other"));
    wrong.stream        = &again;
    wrong.stream_length = total;
    refused(f.go(std::move(wrong)), 422, "digest_mismatch");
    CHECK(f.listed().saves.size() == 1);

    // Above limits.save_body: refused before a byte is read
    GeneratedBody over(total + 1);
    Call large;
    large.method = "POST";
    large.target = "/saves/" + std::string(title);
    large.headers.emplace_back("Content-Digest", digest_of("x"));
    large.stream        = &over;
    large.stream_length = total + 1;
    refused(f.go(std::move(large)), 413, "too_large");
    // A route that takes no such body says so
    GeneratedBody elsewhere(total);
    Call missing;
    missing.method = "POST";
    missing.target = "/apps/missing";
    missing.headers.emplace_back("Content-Type", "application/json");
    missing.stream        = &elsewhere;
    missing.stream_length = total;
    refused(f.go(std::move(missing)), 413, "too_large");
}

TEST_CASE("saves: an encrypted backup is kept as sent, listed with its encryption and read back as bytes")
{
    Fixture f;
    constexpr std::string_view key_id = "0a1b2c3d4e5f6071";
    const std::string sealed          = encrypted_of(key_id, 500);
    const std::string scheme          = "lantern-save-e2e-1; key_id=" + std::string(key_id);

    // In one request, with the header
    Call one;
    one.method = "POST";
    one.target = "/saves/" + std::string(title);
    one.body   = sealed;
    one.headers.emplace_back("Content-Type", "application/octet-stream");
    one.headers.emplace_back("Content-Digest", digest_of(sealed));
    one.headers.emplace_back("Lantern-Save-Encryption", scheme);
    const Save single = f.saved(f.go(one));
    REQUIRE(single.encryption.has_value());
    CHECK(single.encryption->scheme == "lantern-save-e2e-1");
    CHECK(single.encryption->key_id == key_id);
    CHECK(single.size == sealed.size());
    CHECK(single.sha256 == Sha256::of(std::string_view(sealed)));

    // In an upload, with the descriptor
    const std::string address(
        f.opened(
             f.open(sealed, R"(,"encryption":{"scheme":"lantern-save-e2e-1","key_id":"0a1b2c3d4e5f6071"})"))
            .upload);
    const Save uploaded = f.saved(f.patch(address, 0, sealed));
    REQUIRE(uploaded.encryption.has_value());
    CHECK(uploaded.encryption->key_id == key_id);

    const ServerResponse file = f.get("/saves/" + std::string(title) + "/" + std::string(uploaded.save_id));
    CHECK(header(file, "Content-Type") == "application/octet-stream");
    CHECK(body_of(file) == sealed);
    const Saves all = f.listed();
    REQUIRE(all.saves.size() == 2);
    CHECK(std::ranges::all_of(
        all.saves, [&](const Save& s) { return s.encryption && s.encryption->key_id == key_id; }));

    // Its header names the key id; another scheme or a malformed id is a 400
    const std::string other = encrypted_of("ffffffffffffffff", 500);
    Call wrong_key          = one;
    wrong_key.body          = other;
    wrong_key.headers[1]    = { "Content-Digest", digest_of(other) };
    refused(f.go(wrong_key), 400, "bad_request");
    Call wrong_scheme       = one;
    wrong_scheme.headers[2] = { "Lantern-Save-Encryption", "age-1; key_id=" + std::string(key_id) };
    refused(f.go(wrong_scheme), 400, "bad_request");
    Call short_id       = one;
    short_id.headers[2] = { "Lantern-Save-Encryption", "lantern-save-e2e-1; key_id=0A1B" };
    refused(f.go(short_id), 400, "bad_request");
    refused(
        f.open(sealed, R"(,"encryption":{"scheme":"lantern-save-e2e-1","key_id":"zz"})"), 400, "bad_request");
    // A backup sent in clear that is not a zip is refused, as one that claims to be encrypted and is not
    refused(f.post_save(sealed), 400, "bad_request");
    Call plain       = one;
    plain.body       = zip_of(500);
    plain.headers[1] = { "Content-Digest", digest_of(plain.body) };
    refused(f.go(plain), 400, "bad_request");
}

TEST_CASE("saves: a server that keeps no encrypted backup answers 400 to one (L-9.4-5)")
{
    Fixture f({}, false);
    constexpr std::string_view key_id = "0a1b2c3d4e5f6071";
    const std::string sealed          = encrypted_of(key_id, 100);
    Call one;
    one.method = "POST";
    one.target = "/saves/" + std::string(title);
    one.body   = sealed;
    one.headers.emplace_back("Content-Digest", digest_of(sealed));
    one.headers.emplace_back("Lantern-Save-Encryption", "lantern-save-e2e-1; key_id=" + std::string(key_id));
    refused(f.go(one), 400, "bad_request");
    refused(f.open(sealed, R"(,"encryption":{"scheme":"lantern-save-e2e-1","key_id":"0a1b2c3d4e5f6071"})"),
        400, "bad_request");
    CHECK(f.listed().saves.empty());
    // Saves in clear still work, and the handshake says what is offered
    CHECK(f.saved(f.post_save(zip_of(40))).size == 40);
    auto shake = read_handshake(body_of(f.get("/")));
    REQUIRE(shake);
    REQUIRE(*shake);
    CHECK((*shake)->features.saves == std::optional<std::uint64_t> { 1 });
    CHECK((*shake)->features.encrypted_saves == std::optional<std::uint64_t> { 0 });
}

TEST_CASE("saves: the limits are checked when the server is made")
{
    MemoryLibrary library { "/api/lantern" };
    CountingRandom random;
    FakeClock clock;
    MemoryAccountStore accounts;
    MemorySaveStore saves;
    ServerOptions options;
    options.uid      = uid;
    options.name     = "Test shelf";
    options.accounts = &accounts;
    options.saves    = &saves;
    CHECK(Server::create(library, options, random, clock));
    options.save_limits.body = options.save_limits.size + 1;
    CHECK_FALSE(Server::create(library, options, random, clock));
    options.save_limits      = {};
    options.save_limits.kept = 0;
    CHECK_FALSE(Server::create(library, options, random, clock));
    options.save_limits = {};
    options.accounts    = nullptr;
    CHECK_FALSE(Server::create(library, options, random, clock));
}
