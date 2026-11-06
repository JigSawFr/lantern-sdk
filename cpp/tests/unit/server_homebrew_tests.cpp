// The homebrew (SPEC.md § 8) and the cheat sets (§ 10) on the server core:
// the listing, the entries with their manifests and signatures, the updates,
// what the library refuses, and the sets with their scopes, written, replaced
// and deleted. The core is called in memory; the conformance suite plays the
// same against the demo server.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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

constexpr std::string_view uid  = "3d5c7e1a-0b2f-4c6d-9e8a-1f2b3c4d5e6f";
constexpr std::int64_t start    = 1'793'000'000;
constexpr std::string_view base = "/api/lantern/v1";

class FixedRandom final : public RandomSource
{
  public:
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        std::ranges::fill(out, std::uint8_t { 0x42 });
        return {};
    }
};

class FakeClock final : public Clock
{
  public:
    std::int64_t unix_seconds() override { return start; }
};

std::vector<std::byte> bytes(std::string_view text)
{
    const auto view = std::as_bytes(std::span(text.data(), text.size()));
    return { view.begin(), view.end() };
}

using Headers = std::vector<std::pair<std::string, std::string>>;

struct Call
{
    std::string method = "GET";
    std::string target;
    Headers headers;
    std::string body;
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

DeviceKey signing_key()
{
    return DeviceKey::from_seed(Sha256::of(std::string_view("unit test author key")));
}

// A package of one file, and its bytes, before the library serves them.
struct Built
{
    Package package;
    std::vector<std::byte> content;
};

Built nro_package(std::string_view id, std::string_view label)
{
    Built built;
    built.content        = bytes(std::string("nro of ") + std::string(label));
    built.package.format = "nro";
    built.package.path   = "/switch/" + std::string(id) + "/" + std::string(id) + ".nro";
    built.package.size   = built.content.size();
    built.package.sha256 = Sha256::of(built.content);
    ManifestEntry single;
    single.path                   = built.package.path;
    single.size                   = built.package.size;
    single.sha256                 = built.package.sha256;
    built.package.manifest_sha256 = manifest_digest(std::span(&single, 1));
    return built;
}

// An archive of two files, one of them under the Switch's config root.
Built zip_package(std::string_view id, std::string_view label)
{
    Built built;
    built.content        = bytes(std::string("zip of ") + std::string(label));
    built.package.format = "zip";
    built.package.size   = built.content.size();
    built.package.sha256 = Sha256::of(built.content);
    for (const std::string folder : { "/switch/", "/config/" })
    {
        built.package.manifest.emplace_back();
        ManifestEntry& file = built.package.manifest.back();
        file.path           = folder + std::string(id) + "/data.bin";
        file.size           = 4;
        file.sha256         = Sha256::of(std::string_view("data"));
    }
    built.package.manifest_sha256 = manifest_digest(built.package.manifest);
    return built;
}

void sign(Homebrew& entry, const DeviceKey& key)
{
    String public_key;
    base64_encode(key.public_key(), public_key);
    const auto signature_of = [&](const Package& package)
    {
        String message;
        signed_message(
            entry.id, entry.platform, entry.build, package.sha256, package.manifest_sha256, message);
        const SignatureBytes signature
            = key.sign(std::span(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
        Signature out;
        out.alg        = "ed25519";
        out.public_key = public_key;
        base64_encode(signature, out.value);
        return out;
    };
    entry.signature = signature_of(entry.package);
    for (Package& package : entry.packages)
        package.signature = signature_of(package);
}

Homebrew entry_of(std::string_view id, std::string_view platform, std::string_view kind,
    std::string_view name, std::uint64_t build, Built& built)
{
    Homebrew entry;
    entry.id       = id;
    entry.platform = platform;
    entry.kind     = kind;
    entry.name     = name;
    entry.version  = "1.0.0";
    entry.build    = build;
    entry.package  = built.package;
    return entry;
}

Result<Homebrew> serve(MemoryLibrary& library, const Homebrew& entry, const Built& built)
{
    const std::array<std::span<const std::byte>, 1> contents { built.content };
    return library.add_homebrew(entry, contents);
}

CheatWrite cheat_of(std::string_view platform, std::string_view title_id, std::string_view build_id,
    std::string_view source, std::string_view text)
{
    CheatWrite set;
    set.platform = platform;
    set.title_id = title_id;
    set.build_id = build_id;
    set.source   = source;
    set.text     = text;
    return set;
}

constexpr std::string_view reader_token = "et_reader-0123456789abcdef0123456789abcdef";
constexpr std::string_view writer_token = "et_writer-0123456789abcdef0123456789abcdef";
constexpr std::string_view plain_token  = "et_plain-0123456789abcdef0123456789abcdef";

// Homebrew on two platforms, cheat sets, and accounts: a writer of cheat sets, a reader, one that only
// reads the library.
struct Fixture
{
    MemoryLibrary library { "/api/lantern" };
    FixedRandom random;
    FakeClock clock;
    MemoryAccountStore store;
    ServerOptions options;
    std::optional<Server> server;
    DeviceKey author = signing_key();

    explicit Fixture(bool writes = true, bool brew = true)
    {
        if (brew)
        {
            Built star     = zip_package("org.example.starjar", "star jar");
            Homebrew entry = entry_of("org.example.starjar", "switch", "tool", "Star Jar", 10200, star);
            entry.genres   = { "education" };
            sign(entry, author);
            REQUIRE(serve(library, entry, star));

            Built clock_pack = nro_package("org.example.mothclock", "moth clock");
            entry        = entry_of("org.example.mothclock", "switch", "game", "moth clock", 400, clock_pack);
            entry.genres = { "puzzle" };
            REQUIRE(serve(library, entry, clock_pack));

            // A kind a reader does not know is read as `app`
            Built odd = nro_package("org.example.oddity", "oddity");
            entry     = entry_of("org.example.oddity", "switch", "gadget", "Oddity", 7, odd);
            REQUIRE(serve(library, entry, odd));

            // The id of Star Jar on another platform: a package of Linux is a zip
            Built linux_pack = zip_package("org.example.starjar", "star jar for linux");
            linux_pack.package.manifest.clear();
            linux_pack.package.manifest.emplace_back();
            linux_pack.package.manifest.back().path   = "/org.example.starjar/data.bin";
            linux_pack.package.manifest.back().size   = 4;
            linux_pack.package.manifest.back().sha256 = Sha256::of(std::string_view("data"));
            linux_pack.package.manifest_sha256        = manifest_digest(linux_pack.package.manifest);
            entry = entry_of("org.example.starjar", "linux", "tool", "Star Jar", 10100, linux_pack);
            REQUIRE(serve(library, entry, linux_pack));
        }
        REQUIRE(library.add_cheat(cheat_of("switch", "0100AB1200010000", "AB12CD34EF560789", "Community list",
            "[Lamp]\n04000000 0011A0B0 00000063\n")));
        REQUIRE(library.add_cheat(cheat_of("switch", "0100AB1200010000", "AB12CD34EF560789", "Mira",
            "[Comets]\n04000000 0011A0C8 00000001\n")));
        REQUIRE(library.add_cheat(cheat_of("switch", "0100CD3400020000", "0123456789ABCDEF", "Community list",
            "[Moon]\n04000000 00ABC010 0000FFFF\n")));
        library.accept_cheat_writes(writes);

        constexpr std::array<std::string_view, 4> every { "library", "cheats", "cheats.write", "saves" };
        constexpr std::array<std::string_view, 2> reads { "library", "cheats" };
        constexpr std::array<std::string_view, 1> library_only { "library" };
        REQUIRE(store.add_account("writer", every));
        REQUIRE(store.add_account("reader", reads));
        REQUIRE(store.add_account("plain", library_only));
        REQUIRE(store.add_token(writer_token, "writer", "A console", every, std::nullopt, start));
        REQUIRE(store.add_token(reader_token, "reader", "A phone", reads, std::nullopt, start));
        REQUIRE(store.add_token(plain_token, "plain", "A tablet", library_only, std::nullopt, start));
        options.uid      = uid;
        options.name     = "Test shelf";
        options.scheme   = "http";
        options.accounts = &store;
        auto made        = Server::create(library, options, random, clock);
        REQUIRE(made);
        server.emplace(std::move(*made));
    }

    [[nodiscard]] ServerResponse get(
        std::string route, std::string_view token = {}, std::string_view platform = {}) const
    {
        Call call;
        call.target = std::string(base) + route;
        if (!token.empty())
            call.headers.emplace_back("Authorization", "Bearer " + std::string(token));
        if (!platform.empty())
            call.headers.emplace_back("Lantern-Platform", std::string(platform));
        return send(*server, call);
    }

    [[nodiscard]] ServerResponse write(std::string method, std::string route, std::string_view token,
        std::string body = {}, std::string_view platform = {}) const
    {
        Call call;
        call.method = std::move(method);
        call.target = std::string(base) + route;
        if (!token.empty())
            call.headers.emplace_back("Authorization", "Bearer " + std::string(token));
        if (!platform.empty())
            call.headers.emplace_back("Lantern-Platform", std::string(platform));
        if (!body.empty())
        {
            call.headers.emplace_back("Content-Type", "application/json");
            call.body = std::move(body);
        }
        return send(*server, call);
    }
};

HomebrewPage page_of(const ServerResponse& response)
{
    REQUIRE(response.status == 200);
    auto read = read_homebrew_page(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

std::vector<std::string> ids_of(const HomebrewPage& page)
{
    std::vector<std::string> out;
    for (const Homebrew& entry : page.items)
        out.push_back(std::string(entry.platform) + "/" + std::string(entry.id));
    return out;
}

CheatSets sets_of(const ServerResponse& response)
{
    REQUIRE(response.status == 200);
    auto read = read_cheat_sets(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

std::string cheat_body(std::string_view platform, std::string_view title_id, std::string_view build_id,
    std::string_view source, std::string_view text)
{
    std::string out = R"({"schema":1,"platform":")" + std::string(platform) + R"(","title_id":")"
        + std::string(title_id) + "\"";
    if (!build_id.empty())
        out += R"(,"build_id":")" + std::string(build_id) + "\"";
    if (!source.empty())
        out += R"(,"source":")" + std::string(source) + "\"";
    return out + R"(,"text":")" + std::string(text) + "\"}";
}

constexpr std::string_view good_text = R"([New cheat]\n04000000 00000000 00000001\n)";

} // namespace

TEST_CASE("homebrew: a listing leaves the manifests out, an entry keeps them and its signature verifies")
{
    const Fixture f;
    const HomebrewPage listed = page_of(f.get("/homebrew?platform=switch"));
    // Sorted by name, case ignored
    CHECK(ids_of(listed)
        == std::vector<std::string> {
            "switch/org.example.mothclock", "switch/org.example.oddity", "switch/org.example.starjar" });
    CHECK(listed.total == 3);
    CHECK(listed.items[2].package.manifest.empty());
    CHECK(listed.items[2].package.size > 0);

    const ServerResponse response = f.get("/homebrew/org.example.starjar", {}, "switch");
    REQUIRE(response.status == 200);
    CHECK(header(response, "ETag").size() > 2);
    auto read = read_homebrew(response.body);
    REQUIRE(read);
    REQUIRE(*read);
    const Homebrew& entry = **read;
    REQUIRE(entry.package.manifest.size() == 2);
    CHECK(entry.package.manifest[0].path == "/switch/org.example.starjar/data.bin");
    CHECK(manifest_digest(entry.package.manifest) == entry.package.manifest_sha256);
    CHECK(entry.package.file.starts_with("/api/lantern/v1/files/f_"));
    const auto signature = verify_package_signature(entry, entry.package);
    REQUIRE(signature);
    CHECK(signature->is_signed);
    CHECK(signature->public_key == signing_key().public_key());

    // The package is a file like an app's, with the digest of the whole
    const ServerResponse package
        = f.get(std::string(entry.package.file).substr(std::string_view("/api/lantern/v1").size()));
    REQUIRE(package.status == 200);
    CHECK(body_of(package) == "zip of star jar");

    // The same ETag again gives 304
    Call again;
    again.target = std::string(base) + "/homebrew/org.example.starjar";
    again.headers.emplace_back("Lantern-Platform", "switch");
    again.headers.emplace_back("If-None-Match", std::string(header(response, "ETag")));
    CHECK(send(*f.server, again).status == 304);
}

TEST_CASE("homebrew: names, kinds, genres, pages and the ids of two platforms")
{
    const Fixture f;
    CHECK(ids_of(page_of(f.get("/homebrew?q=STAR"))).size() == 2);
    // The listing names the platform it is of, apart from the ids that two share
    CHECK(ids_of(page_of(f.get("/homebrew?kind=game")))
        == std::vector<std::string> { "switch/org.example.mothclock" });
    // `gadget` is not a kind a reader knows: it is an app
    CHECK(ids_of(page_of(f.get("/homebrew?kind=app")))
        == std::vector<std::string> { "switch/org.example.oddity" });
    CHECK(ids_of(page_of(f.get("/homebrew?genre=puzzle")))
        == std::vector<std::string> { "switch/org.example.mothclock" });
    CHECK(page_of(f.get("/homebrew?kind=lanternconformance")).items.empty());
    refused(f.get("/homebrew?kind=Not%20a%20kind"), 400, "bad_request");
    refused(f.get("/homebrew?genre=Not%20a%20genre"), 400, "bad_request");
    refused(f.get("/homebrew?sort=added"), 400, "bad_request");

    // Pages of one: each entry once, the cursor of one listing is no other's
    std::vector<std::string> seen;
    std::string cursor;
    for (int pages = 0; pages < 10; ++pages)
    {
        const HomebrewPage page = page_of(
            f.get("/homebrew?page_size=1" + (cursor.empty() ? std::string() : "&cursor=" + cursor)));
        CHECK(page.items.size() == 1);
        seen.push_back(ids_of(page).front());
        if (page.next.empty())
            break;
        cursor = page.next;
    }
    // By name, then platform
    CHECK(seen
        == std::vector<std::string> { "switch/org.example.mothclock", "switch/org.example.oddity",
            "linux/org.example.starjar", "switch/org.example.starjar" });
    refused(f.get("/homebrew?kind=game&cursor=" + cursor), 400, "bad_request");

    // An id that two platforms have
    refused(f.get("/homebrew/org.example.starjar"), 400, "bad_request");
    CHECK(f.get("/homebrew/org.example.starjar", {}, "linux").status == 200);
    refused(f.get("/homebrew/org.example.nothing", {}, "switch"), 404, "not_found");
    refused(f.get("/homebrew/Not-An-Id"), 404, "not_found");
}

TEST_CASE("homebrew: the updates are the entries newer than what is installed, on a platform")
{
    const Fixture f;
    const auto post = [&](std::string_view body, std::string_view platform = "switch")
    { return f.write("POST", "/homebrew/updates", {}, std::string(body), platform); };
    const HomebrewPage newer = page_of(post(R"({"schema":1,"installed":[
        {"id":"org.example.starjar","build":10100},{"id":"org.example.mothclock","build":400},
        {"id":"org.example.absent","build":1},{"id":"org.example.starjar","build":10000}]})"));
    CHECK(ids_of(newer) == std::vector<std::string> { "switch/org.example.starjar" });
    // The highest installed build counts, and the platform's entry alone
    CHECK(page_of(post(R"({"schema":1,"installed":[{"id":"org.example.starjar","build":10200}]})"))
              .items.empty());
    CHECK(
        ids_of(page_of(post(R"({"schema":1,"installed":[{"id":"org.example.starjar","build":0}]})", "linux")))
        == std::vector<std::string> { "linux/org.example.starjar" });
    refused(post(R"({"schema":1,"installed":[]})", ""), 400, "bad_request");
    refused(post(R"({"schema":2,"installed":[]})"), 422, "unsupported_schema");
    refused(post(R"({"schema":1,"installed":[{"id":"Not An Id","build":1}]})"), 400, "bad_request");
    refused(post(R"({"schema":1})"), 400, "bad_request");
    refused(f.get("/homebrew/updates"), 405, "bad_request");
}

TEST_CASE("homebrew: the library refuses what § 8 and the profile do not allow")
{
    MemoryLibrary library;
    const DeviceKey author = signing_key();
    Built built            = nro_package("org.example.thing", "thing");
    const Homebrew good    = entry_of("org.example.thing", "switch", "tool", "Thing", 1, built);
    REQUIRE(serve(library, good, built));
    // The same id replaces the entry
    CHECK(serve(library, good, built));
    CHECK(library.remove_homebrew("switch", "org.example.thing"));
    CHECK_FALSE(library.remove_homebrew("switch", "org.example.thing"));

    const auto refuses
        = [&](const Homebrew& entry, const Built& with) { CHECK_FALSE(serve(library, entry, with)); };
    Homebrew bad = good;
    bad.package.size += 1;
    refuses(bad, built);
    bad = good;
    bad.package.sha256[0] ^= 1U;
    refuses(bad, built);
    bad = good;
    bad.package.manifest_sha256[0] ^= 1U;
    refuses(bad, built);
    // A file where the profile puts none of this format, or outside its roots
    bad              = good;
    bad.package.path = "/atmosphere/thing.nro";
    refuses(bad, built);
    bad    = good;
    bad.id = "Thing";
    refuses(bad, built);
    bad          = good;
    bad.platform = "web";
    refuses(bad, built);
    bad      = good;
    bad.kind = "Tool";
    refuses(bad, built);
    bad      = good;
    bad.name = "";
    refuses(bad, built);
    // An architecture on a platform that has one, a kind port with no port, a port on another kind
    bad = good;
    bad.package.arch.emplace_back("aarch64");
    refuses(bad, built);
    bad      = good;
    bad.kind = "port";
    refuses(bad, built);
    bad = good;
    bad.port.emplace();
    refuses(bad, built);
    // Requirements: a text, and the shapes of the keys it knows
    bad = good;
    bad.requires_.emplace();
    refuses(bad, built);
    bad.requires_->text = "Atmosphere";
    CHECK(serve(library, bad, built));
    bad.requires_->min.emplace();
    bad.requires_->min->members.emplace_back("ram_mb", "\"lots\"");
    refuses(bad, built);

    // Signatures: one that verifies, one that does not, packages signed by several keys
    Homebrew signed_entry = good;
    sign(signed_entry, author);
    CHECK(serve(library, signed_entry, built));
    signed_entry.build += 1;
    refuses(signed_entry, built);
    Homebrew other = good;
    sign(other, DeviceKey::from_seed(Sha256::of(std::string_view("another author"))));
    other.signature->alg = "rsa";
    refuses(other, built);

    // An entry per architecture on Linux: each of `packages` has its arch and a signature, by one key
    Built first  = zip_package("org.example.harbor", "first");
    Built second = zip_package("org.example.harbor", "second");
    for (Built* item : { &first, &second })
    {
        item->package.manifest.clear();
        item->package.manifest.emplace_back();
        item->package.manifest.back().path   = "/org.example.harbor/data.bin";
        item->package.manifest.back().size   = 4;
        item->package.manifest.back().sha256 = Sha256::of(std::string_view("data"));
        item->package.manifest_sha256        = manifest_digest(item->package.manifest);
    }
    first.package.arch  = { "aarch64" };
    second.package.arch = { "x86_64" };
    Homebrew harbor     = entry_of("org.example.harbor", "linux", "tool", "Harbor", 5, first);
    harbor.packages.push_back(second.package);
    sign(harbor, author);
    const std::array<std::span<const std::byte>, 2> both { first.content, second.content };
    CHECK(library.add_homebrew(harbor, both));
    const std::array<std::span<const std::byte>, 1> one { first.content };
    CHECK_FALSE(library.add_homebrew(harbor, one));
    harbor.packages[0].arch.clear();
    CHECK_FALSE(library.add_homebrew(harbor, both));
    harbor.packages[0].arch = { "x86_64" };
    // The entry's package signed by one key, the other by another
    Homebrew mixed     = harbor;
    Homebrew other_key = harbor;
    sign(other_key, DeviceKey::from_seed(Sha256::of(std::string_view("a second key"))));
    mixed.signature = other_key.signature;
    CHECK_FALSE(library.add_homebrew(mixed, both));
    CHECK(library.add_homebrew(harbor, both));
    // The files of an entry go with it
    CHECK(library.remove_homebrew("linux", "org.example.harbor"));
    CHECK_FALSE(
        library.file("f_" + std::string(to_hex(first.package.sha256).data(), 24), {}).value().has_value());
}

TEST_CASE("homebrew: a library that offers none has no route, and the handshake says so")
{
    const Fixture f(true, false);
    refused(f.get("/homebrew"), 404, "not_found");
    refused(f.get("/homebrew/org.example.starjar"), 404, "not_found");
    refused(f.write("POST", "/homebrew/updates", {}, R"({"schema":1,"installed":[]})", "switch"), 404,
        "not_found");
    auto hello = read_handshake(f.get("/").body);
    REQUIRE(hello);
    REQUIRE(*hello);
    CHECK((*hello)->features.homebrew == 0);
    CHECK((*hello)->features.cheats == 1);

    const Fixture all;
    hello = read_handshake(all.get("/", reader_token).body);
    REQUIRE(hello);
    REQUIRE(*hello);
    CHECK((*hello)->features.homebrew == 1);
    CHECK((*hello)->features.cheats == 1);
    // A token without the scope cheats has no cheat sets, nor the homebrew without library
    hello = read_handshake(all.get("/", plain_token).body);
    REQUIRE(hello);
    REQUIRE(*hello);
    CHECK((*hello)->features.homebrew == 1);
    CHECK((*hello)->features.cheats == 0);
}

TEST_CASE("cheats: the sets are listed with their filters and their text is a file")
{
    const Fixture f;
    // Anyone reads them on a server that asks for no token
    const CheatSets all = sets_of(f.get("/cheats"));
    REQUIRE(all.cheats.size() == 3);
    // By platform, title, build, source
    CHECK(all.cheats[0].source == "Community list");
    CHECK(all.cheats[1].source == "Mira");
    CHECK(all.cheats[2].title_id == "0100CD3400020000");
    CHECK(all.cheats[0].id.starts_with("cs_"));
    CHECK(all.cheats[0].updated.ends_with("Z"));

    CHECK(sets_of(f.get("/cheats?title_id=0100AB1200010000")).cheats.size() == 2);
    CHECK(sets_of(f.get("/cheats?title_id=0100AB1200010000&build_id=AB12CD34EF560789")).cheats.size() == 2);
    CHECK(sets_of(f.get("/cheats?build_id=0123456789ABCDEF")).cheats.size() == 1);
    CHECK(sets_of(f.get("/cheats?build_id=FFFF")).cheats.empty());
    CHECK(sets_of(f.get("/cheats", {}, "switch")).cheats.size() == 3);
    CHECK(sets_of(f.get("/cheats", {}, "linux")).cheats.empty());
    refused(f.get("/cheats?build_id=not%20a%20build"), 400, "bad_request");
    refused(f.get("/cheats?title_id=not%20a%20title"), 400, "bad_request");

    const CheatSet& first     = all.cheats[0];
    const ServerResponse text = f.get("/cheats/" + std::string(first.id));
    REQUIRE(text.status == 200);
    const std::string body = body_of(text);
    CHECK(body == "[Lamp]\n04000000 0011A0B0 00000063\n");
    CHECK(first.size == body.size());
    CHECK(first.sha256 == Sha256::of(std::string_view(body)));
    CHECK(header(text, "Repr-Digest").starts_with("sha-256=:"));
    refused(f.get("/cheats/cs_nothing"), 404, "not_found");
    // Another platform's set is not found under this one
    refused(f.get("/cheats/" + std::string(first.id), {}, "linux"), 404, "not_found");
}

TEST_CASE("cheats: the scope cheats reads them, and a server that asks for a token asks for one")
{
    Fixture f;
    CHECK(f.get("/cheats", reader_token).status == 200);
    CHECK(f.get("/cheats", writer_token).status == 200);
    refused(f.get("/cheats", plain_token), 403, "forbidden");
    refused(f.get("/cheats", "et_unknown-0123456789abcdef0123456789abcdef"), 401, "unauthorized");

    // Anonymous callers hold `library` and `cheats` on a public server
    auto hello = read_handshake(f.get("/").body);
    REQUIRE(hello);
    REQUIRE(*hello);
    REQUIRE((*hello)->account.scopes.size() == 2);
    CHECK((*hello)->account.scopes[1] == "cheats");

    f.options.require_auth = true;
    auto made              = Server::create(f.library, f.options, f.random, f.clock);
    REQUIRE(made);
    f.server.emplace(std::move(*made));
    refused(f.get("/cheats"), 401, "unauthorized");
    CHECK(f.get("/cheats", reader_token).status == 200);
}

TEST_CASE("cheats: a set is written, replaced and deleted with the scope cheats.write")
{
    const Fixture f;
    const std::string body = cheat_body("switch", "0100EF5600030000", "0123", "Lantern tests", good_text);
    // Without the scope: nothing, whatever else the token holds
    refused(f.write("POST", "/cheats", {}, body), 401, "unauthorized");
    refused(f.write("POST", "/cheats", reader_token, body), 403, "forbidden");
    refused(f.write("POST", "/cheats", plain_token, body), 403, "forbidden");

    const ServerResponse made = f.write("POST", "/cheats", writer_token, body);
    REQUIRE(made.status == 201);
    auto read = read_cheat_set(made.body);
    REQUIRE(read);
    REQUIRE(*read);
    const CheatSet& set = **read;
    CHECK(set.platform == "switch");
    CHECK(set.build_id == "0123");
    CHECK(set.source == "Lantern tests");
    CHECK(set.size == 39);
    const std::string route = "/cheats/" + std::string(set.id);

    CHECK(sets_of(f.get("/cheats?title_id=0100EF5600030000")).cheats.size() == 1);
    CHECK(body_of(f.get(route)) == "[New cheat]\n04000000 00000000 00000001\n");
    // Again: the set exists, PUT replaces it
    refused(f.write("POST", "/cheats", writer_token, body), 409, "conflict");

    // The text and the note change; the platform, title, build and source stay
    const std::string newer
        = cheat_body("switch", "0100EF5600030000", "0123", "Lantern tests", R"([Newer]\n)");
    refused(f.write("PUT", route, reader_token, newer), 403, "forbidden");
    const ServerResponse replaced = f.write("PUT", route, writer_token, newer);
    CHECK(replaced.status == 204);
    CHECK(header(replaced, "Content-Length") == "0");
    CHECK(body_of(f.get(route)) == "[Newer]\n");
    const CheatSets listed = sets_of(f.get("/cheats?title_id=0100EF5600030000"));
    REQUIRE(listed.cheats.size() == 1);
    CHECK(listed.cheats[0].sha256 == Sha256::of(std::string_view("[Newer]\n")));
    refused(f.write("PUT", route, writer_token,
                cheat_body("switch", "0100EF5600030000", "0123", "Another", R"([Newer]\n)")),
        400, "bad_request");
    refused(f.write("PUT", "/cheats/cs_nothing", writer_token, newer), 404, "not_found");

    refused(f.write("DELETE", route, reader_token), 403, "forbidden");
    CHECK(f.write("DELETE", route, writer_token).status == 204);
    refused(f.get(route), 404, "not_found");
    refused(f.write("DELETE", route, writer_token), 404, "not_found");
    CHECK(sets_of(f.get("/cheats?title_id=0100EF5600030000")).cheats.empty());

    // A source left out is Lantern
    const ServerResponse unsourced = f.write(
        "POST", "/cheats", writer_token, cheat_body("switch", "0100EF5600030000", "0123", "", good_text));
    REQUIRE(unsourced.status == 201);
    read = read_cheat_set(unsourced.body);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->source == "Lantern");
}

TEST_CASE("cheats: a server that takes no writes answers 405, and a set must be what the profile says")
{
    const Fixture off(false);
    refused(off.write("POST", "/cheats", writer_token,
                cheat_body("switch", "0100EF5600030000", "0123", "x", good_text)),
        405, "bad_request");
    const ServerResponse allowed = off.write("DELETE", "/cheats/cs_nothing", writer_token);
    CHECK(allowed.status == 405);
    CHECK(header(allowed, "Allow") == "GET, HEAD");

    const Fixture f;
    const auto post = [&](std::string_view platform, std::string_view title, std::string_view build,
                          std::string_view text, std::uint16_t status, std::string_view code = "bad_request")
    {
        refused(f.write("POST", "/cheats", writer_token,
                    cheat_body(platform, title, build, "Lantern tests", text)),
            status, code);
    };
    // The build_id of the Switch is upper-case hex, and a set is Atmosphere's text
    post("switch", "0100EF5600030000", "", good_text, 400);
    post("switch", "0100EF5600030000", "abc", good_text, 400);
    post("switch", "0100EF5600030000", "0123", R"(not a cheat\n)", 400);
    post("switch", "0100EF5600030000", "0123", R"(0400 0000\n)", 400);
    post("switch", "0100EF5600030000", "0123", R"(bell \u0007\n)", 400);
    post("switch", "not-a-title", "0123", good_text, 400);
    // No cheats on Android and Linux, none for the web; the 3DS's depend on no build
    post("android", "org.example.thing", "", good_text, 400);
    post("linux", "thing", "", good_text, 400);
    post("web", "thing", "", good_text, 400);
    post("3ds", "0004000000123400", "0123", good_text, 400);
    // A PS4's set is a document
    post("ps4", "CUSA12345", "12.34", "not json", 400);
    // A text above 1 MiB
    post("switch", "0100EF5600030000", "0123", std::string(std::size_t { 1 } << 20U, 'a') + "a", 413,
        "too_large");

    CHECK(f.write("POST", "/cheats", writer_token, cheat_body("3ds", "0004000000123400", "", "x", good_text))
              .status
        == 201);
    CHECK(f.write("POST", "/cheats", writer_token,
               cheat_body("ps4", "CUSA12345", "12.34", "x", R"({\"mods\":[]})"))
              .status
        == 201);
    refused(
        f.write("POST", "/cheats", writer_token, R"({"schema":1,"platform":"switch"})"), 400, "bad_request");
    refused(f.write("POST", "/cheats", writer_token, R"({"schema":2,"platform":"switch"})"), 422,
        "unsupported_schema");
    // A note of 120 bytes at most
    const std::string long_note(121, 'n');
    refused(f.write("POST", "/cheats", writer_token,
                R"({"schema":1,"platform":"switch","title_id":"0100EF5600030000","build_id":"0123","note":")"
                    + long_note + R"(","text":"[a]\n"})"),
        400, "bad_request");
}
