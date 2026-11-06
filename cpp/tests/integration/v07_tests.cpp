// Draft 0.7 against the reference server: the chunk indexes it serves, a
// newer package put together from an older one and ranges of the file (from
// the server, a mirror, a peer, and the library exported as files), the
// hostile answers that make a client read the whole file, the upload's HEAD
// with its chunk size, and the discovery of a library at an address.
// Fictional names and games: Lea, Frostline Tales.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lantern/lantern.hpp>

#include "posix_http.hpp"
#include "posix_system.hpp"

using namespace lantern;

namespace
{

constexpr std::string_view frostline = "0100ABCD00010000";

std::string env(const char* name)
{
    const char* value = std::getenv(name);
    REQUIRE_MESSAGE(value != nullptr, "run through run_server.py: ", name, " is not set");
    return value;
}

// Wraps a transport and lies about the ranges it reads: a byte of a chunk
// changed, or a range cut short.
class Meddler final : public Transport
{
  public:
    enum class Mode : std::uint8_t
    {
        none,
        flip,
        cut,
    };

    explicit Meddler(Transport& inner) noexcept
        : inner_(inner)
    {
    }

    Mode mode       = Mode::none;
    unsigned ranges = 0;
    unsigned plain  = 0;

    Result<void> send(const Request& request, ResponseHandler& handler) override
    {
        std::uint64_t length = 0;
        for (const Header& header : request.headers)
        {
            if (header.name != "Range")
                continue;
            // bytes=first-last
            const std::string_view value = header.value;
            const std::size_t dash       = value.find('-');
            if (value.starts_with("bytes=") && dash != std::string_view::npos)
            {
                const auto first = std::stoull(std::string(value.substr(6, dash - 6)));
                const auto last  = std::stoull(std::string(value.substr(dash + 1)));
                length           = last - first + 1;
            }
        }
        if (length == 0)
        {
            ++plain;
            return inner_.send(request, handler);
        }
        ++ranges;
        if (mode == Mode::none)
            return inner_.send(request, handler);
        Adapter adapter(handler, mode, length);
        return inner_.send(request, adapter);
    }

  private:
    class Adapter final : public ResponseHandler
    {
      public:
        Adapter(ResponseHandler& inner, Mode mode, std::uint64_t length) noexcept
            : inner_(inner)
            , mode_(mode)
            , length_(length)
        {
        }
        bool on_status(std::uint16_t status) override
        {
            status_ = status;
            return inner_.on_status(status);
        }
        bool on_header(std::string_view name, std::string_view value) override
        {
            return inner_.on_header(name, value);
        }
        bool on_body(std::span<const std::byte> chunk) override
        {
            if (status_ != 206)
                return inner_.on_body(chunk);
            if (mode_ == Mode::cut)
            {
                // Everything but the last 5 bytes of the range
                const std::uint64_t keep = length_ > 5 ? length_ - 5 : 0;
                if (seen_ >= keep)
                    return true;
                const auto take
                    = static_cast<std::size_t>(std::min<std::uint64_t>(chunk.size(), keep - seen_));
                seen_ += take;
                return inner_.on_body(chunk.first(take));
            }
            std::vector<std::byte> copy(chunk.begin(), chunk.end());
            if (!flipped_ && seen_ + copy.size() > length_ / 2)
            {
                copy[0] ^= std::byte { 1 };
                flipped_ = true;
            }
            seen_ += copy.size();
            return inner_.on_body(copy);
        }

      private:
        ResponseHandler& inner_;
        Mode mode_;
        std::uint64_t length_;
        std::uint64_t seen_   = 0;
        std::uint16_t status_ = 0;
        bool flipped_         = false;
    };

    Transport& inner_;
};

struct Device
{
    posix::LoopbackTransport loopback;
    Meddler transport;
    posix::SystemRandom random;
    std::optional<Client> client;

    Device(const Device&)            = delete;
    Device& operator=(const Device&) = delete;

    explicit Device(const std::string& origin, bool as_admin = false)
        : transport(loopback)
    {
        ClientConfig config;
        config.origin     = origin;
        config.user_agent = "LanternCppTests/0.7";
        config.platform   = "switch";
        config.random     = &random;
        auto made         = Client::create(transport, config);
        REQUIRE(made);
        client.emplace(std::move(*made));
        if (as_admin)
        {
            KeySeed seed {};
            REQUIRE(base64_decode(env("LANTERN_TEST_KEY"), seed));
            REQUIRE(client->set_credentials(env("LANTERN_TEST_TOKEN"), DeviceKey::from_seed(seed)));
        }
        const auto shaken = client->handshake();
        REQUIRE(shaken);
        REQUIRE(*shaken);
    }

    Client* operator->() { return &*client; }
};

class StringSink final : public DownloadSink
{
  public:
    std::string bytes;
    Result<void> write(std::span<const std::byte> chunk) override
    {
        bytes.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return {};
    }
    Result<void> restart() override
    {
        bytes.clear();
        return {};
    }
};

class StringSource final : public UploadSource
{
  public:
    explicit StringSource(const std::string& text)
        : text_(text)
    {
    }
    Result<void> read(std::uint64_t offset, std::span<std::byte> out) override
    {
        std::copy_n(reinterpret_cast<const std::byte*>(text_.data()) + offset, out.size(), out.begin());
        return {};
    }

  private:
    const std::string& text_;
};

// The older and the newer version of the reference library's update (400,000
// bytes, a few kilobytes changed and inserted), which the server cuts.
struct Pair
{
    App older;
    App newer;
};

Pair delta_pair(const std::vector<App>& apps)
{
    std::vector<const App*> cut;
    for (const App& app : apps)
    {
        if (app.chunks)
            cut.push_back(&app);
    }
    REQUIRE(cut.size() == 2);
    std::ranges::sort(cut, [](const App* a, const App* b) { return a->version_code < b->version_code; });
    return { *cut[0], *cut[1] };
}

std::vector<App> all_apps(Device& device)
{
    std::vector<App> apps;
    std::string cursor;
    for (int pages = 0; pages < 100; ++pages)
    {
        AppsQuery query;
        query.cursor    = cursor;
        const auto page = device->apps(query);
        REQUIRE(page);
        REQUIRE(*page);
        for (const App& app : (*page)->items)
            apps.push_back(app);
        if ((*page)->next.empty())
            break;
        cursor = (*page)->next;
    }
    return apps;
}

DownloadTarget target_of(const App& app)
{
    return { app.file, app.size, app.sha256 };
}

std::string whole(Device& device, const App& app)
{
    DownloadState state;
    StringSink sink;
    REQUIRE(device->download(target_of(app), state, sink));
    REQUIRE(sink.bytes.size() == app.size);
    return sink.bytes;
}

std::vector<Seed> seed_of(const std::string& bytes)
{
    return { std::as_bytes(std::span(bytes.data(), bytes.size())) };
}

std::string empty_zip(std::size_t size)
{
    std::string zip("PK\x05\x06", 4);
    zip.append(16, '\0');
    zip.push_back(static_cast<char>(size & 0xFFU));
    zip.push_back(static_cast<char>((size >> 8U) & 0xFFU));
    zip.append(size, 'L');
    return zip;
}

// The folder of a static library, read through the device's own files.
class FolderFiles final : public StaticFiles
{
  public:
    explicit FolderFiles(std::string root)
        : root_(std::move(root))
    {
    }
    unsigned reads = 0;
    Result<void> read(std::string_view path, std::uint64_t offset, DownloadSink& sink) override
    {
        ++reads;
        if (!is_static_path(path))
            return fail(Category::invalid_response, "not a path below the root");
        const std::string full = root_ + "/" + std::string(path);
        std::FILE* file        = std::fopen(full.c_str(), "rb");
        if (file == nullptr)
            return std::unexpected(Error::from_status(404));
        if (offset != 0 && std::fseek(file, static_cast<long>(offset), SEEK_SET) != 0)
        {
            std::fclose(file);
            return fail(Category::storage, "seek");
        }
        std::array<char, 4096> buffer {};
        std::size_t got = 0;
        while ((got = std::fread(buffer.data(), 1, buffer.size(), file)) > 0)
        {
            if (auto written = sink.write(std::as_bytes(std::span(buffer.data(), got))); !written)
            {
                std::fclose(file);
                return written;
            }
        }
        std::fclose(file);
        return {};
    }

  private:
    std::string root_;
};

} // namespace

TEST_CASE("v07: the handshake offers deltas, and an app carries its chunks")
{
    Device device(env("LANTERN_TEST_PUBLIC"));
    CHECK(device->offers(Family::deltas) == 1);
    CHECK(device->server()->features.deltas.value_or(0) == 1);
    const Pair pair = delta_pair(all_apps(device));
    CHECK(pair.older.title_id == pair.newer.title_id);
    CHECK(pair.older.version_code < pair.newer.version_code);
    REQUIRE(pair.newer.chunks);
    CHECK(pair.newer.chunks->url.find("/v1/chunks/sha256/") != std::string::npos);

    // By `chunks.url`, and by the file's SHA-256 alone: the same index
    const auto index = device->chunk_index(*pair.newer.chunks, target_of(pair.newer));
    REQUIRE(index);
    REQUIRE(*index);
    const auto by_hash = device->chunk_index_of(pair.newer.sha256, pair.newer.size);
    REQUIRE(by_hash);
    REQUIRE(*by_hash);
    CHECK((*index)->chunks.size() == (*by_hash)->chunks.size());
    CHECK((*index)->chunks.size() > 3);
    CHECK((*index)->size == pair.newer.size);
    // A file the server has no index for: not found
    Digest nothing {};
    CHECK_FALSE(device->chunk_index_of(nothing, 10));
}

TEST_CASE("v07: a newer package from the older one and the ranges of the new file")
{
    Device device(env("LANTERN_TEST_PUBLIC"));
    const Pair pair         = delta_pair(all_apps(device));
    const std::string older = whole(device, pair.older);
    const std::string newer = whole(device, pair.newer);
    const auto seeds        = seed_of(older);

    StringSink sink;
    const unsigned before = device.transport.ranges;
    const auto report = device->download_with_seeds(target_of(pair.newer), *pair.newer.chunks, seeds, sink);
    REQUIRE(report);
    CHECK_FALSE(report->whole_file);
    CHECK(sink.bytes == newer);
    CHECK(report->from_seeds + report->from_ranges == newer.size());
    // A few kilobytes changed: most of the file is the older version's
    CHECK(report->from_ranges < newer.size() / 2);
    CHECK(report->from_seeds > newer.size() / 2);
    CHECK(report->requests >= 1);
    CHECK(device.transport.ranges - before == report->requests);

    // The index kept by the app, then used
    const auto index = device->chunk_index(*pair.newer.chunks, target_of(pair.newer));
    REQUIRE(index);
    REQUIRE(*index);
    StringSink again;
    const auto second = device->download_with_index(target_of(pair.newer), **index, seeds, again);
    REQUIRE(second);
    CHECK(again.bytes == newer);

    // The same file from a mirror (the server's own file at another address, untrusted)
    const std::string public_origin = env("LANTERN_TEST_PUBLIC");
    const auto file                 = resolve_url(*split_url(public_origin), pair.newer.file);
    REQUIRE(file);
    std::vector<Mirror> mirrors(1);
    mirrors[0].url = *file;
    DeltaOptions options;
    options.mirrors = mirrors;
    StringSink mirrored;
    const auto from_mirror
        = device->download_with_seeds(target_of(pair.newer), *pair.newer.chunks, seeds, mirrored, options);
    REQUIRE(from_mirror);
    CHECK_FALSE(from_mirror->whole_file);
    CHECK(mirrored.bytes == newer);

    // A seed that holds nothing of the file: it is read whole
    const std::string unrelated(300000, 'x');
    const auto none = seed_of(unrelated);
    StringSink all;
    const auto whole_file = device->download_with_seeds(target_of(pair.newer), *pair.newer.chunks, none, all);
    REQUIRE(whole_file);
    CHECK(whole_file->whole_file);
    CHECK(all.bytes == newer);
}

TEST_CASE("v07: the reference peer reads the ranges with a grant")
{
    Device device(env("LANTERN_TEST_PUBLIC"));
    const Pair pair         = delta_pair(all_apps(device));
    const std::string older = whole(device, pair.older);
    const std::string newer = whole(device, pair.newer);
    const auto grant        = device->grant(pair.newer.sha256);
    REQUIRE(grant);
    REQUIRE(*grant);
    const std::string peer_origin = env("LANTERN_TEST_PEER");
    const auto parts              = split_url(peer_origin);
    REQUIRE(parts);
    const std::array<DeltaPeer, 1> peers { DeltaPeer {
        PeerEndpoint { parts->host, parts->port, "/lantern", false }, &**grant } };
    DeltaOptions options;
    options.peers = peers;
    StringSink sink;
    const auto seeds = seed_of(older);
    const auto report
        = device->download_with_seeds(target_of(pair.newer), *pair.newer.chunks, seeds, sink, options);
    REQUIRE(report);
    CHECK_FALSE(report->whole_file);
    CHECK(sink.bytes == newer);
}

TEST_CASE("v07: hostile ranges: a chunk changed, a range cut short, a wrong index (L-22.3-2, L-22.3-4)")
{
    Device device(env("LANTERN_TEST_PUBLIC"));
    const Pair pair         = delta_pair(all_apps(device));
    const std::string older = whole(device, pair.older);
    const std::string newer = whole(device, pair.newer);
    const auto seeds        = seed_of(older);

    for (const Meddler::Mode mode : { Meddler::Mode::flip, Meddler::Mode::cut })
    {
        device.transport.mode = mode;
        StringSink sink;
        const auto report
            = device->download_with_seeds(target_of(pair.newer), *pair.newer.chunks, seeds, sink);
        REQUIRE(report);
        // Every source is the server, and it lied: the file whole, and right
        CHECK(report->whole_file);
        CHECK(sink.bytes == newer);
    }
    device.transport.mode = Meddler::Mode::none;

    // An index whose size is not the one `chunks` gives
    AppChunks wrong = *pair.newer.chunks;
    wrong.size += 1;
    StringSink sink;
    const unsigned ranges = device.transport.ranges;
    const auto report     = device->download_with_seeds(target_of(pair.newer), wrong, seeds, sink);
    REQUIRE(report);
    CHECK(report->whole_file);
    CHECK(sink.bytes == newer);
    CHECK(device.transport.ranges == ranges);

    // An index whose SHA-256 is not the one `chunks` gives
    wrong = *pair.newer.chunks;
    wrong.sha256[0] ^= 1U;
    StringSink other;
    const auto again = device->download_with_seeds(target_of(pair.newer), wrong, seeds, other);
    REQUIRE(again);
    CHECK(again->whole_file);
    CHECK(other.bytes == newer);

    // The target is not the file the index is of
    DownloadTarget lie = target_of(pair.newer);
    lie.size += 1;
    CHECK_FALSE(device->chunk_index(*pair.newer.chunks, lie).value_or(std::nullopt).has_value());
}

TEST_CASE("v07: the library as files: the index at its path, and the update from a folder and over HTTP")
{
    posix::LoopbackTransport transport;
    auto http = HttpStaticFiles::create(transport, env("LANTERN_TEST_STATIC"), "LanternCppTests/0.7");
    REQUIRE(http);
    FolderFiles folder(env("LANTERN_TEST_STATIC_DIR"));
    for (StaticFiles* files : { static_cast<StaticFiles*>(&*http), static_cast<StaticFiles*>(&folder) })
    {
        auto opened = StaticLibrary::open(*files);
        REQUIRE(opened);
        REQUIRE(*opened);
        StaticLibrary& library = **opened;
        std::vector<App> apps;
        std::string cursor;
        for (int pages = 0; pages < 1000; ++pages)
        {
            const auto page = library.apps("switch", cursor);
            REQUIRE(page);
            REQUIRE(*page);
            for (const App& app : (*page)->items)
                apps.push_back(app);
            if ((*page)->next.empty())
                break;
            cursor = (*page)->next;
        }
        const Pair pair = delta_pair(apps);
        REQUIRE(pair.newer.chunks);
        CHECK_FALSE(pair.newer.chunks->url.starts_with("/"));

        DownloadState state;
        StringSink older;
        REQUIRE(library.download(target_of(pair.older), state, older));
        StringSink newer;
        state.reset();
        REQUIRE(library.download(target_of(pair.newer), state, newer));

        const auto index = library.chunk_index(*pair.newer.chunks, target_of(pair.newer));
        REQUIRE(index);
        REQUIRE(*index);
        CHECK((*index)->chunks.size() > 3);

        StringSink sink;
        const auto seeds = seed_of(older.bytes);
        const auto report
            = library.download_with_seeds(target_of(pair.newer), *pair.newer.chunks, seeds, sink);
        REQUIRE(report);
        CHECK_FALSE(report->whole_file);
        CHECK(sink.bytes == newer.bytes);
        CHECK(report->from_ranges < newer.bytes.size() / 2);
    }
}

TEST_CASE("v07: an address is a server or a static library (L-21.3-3)")
{
    posix::LoopbackTransport transport;
    const auto server = find_library(transport, env("LANTERN_TEST_PUBLIC") + "/", "LanternCppTests/0.7");
    REQUIRE(server);
    REQUIRE(*server);
    CHECK((*server)->kind == LibraryKind::server);
    CHECK(std::string_view((*server)->root) == env("LANTERN_TEST_PUBLIC"));
    CHECK_FALSE((*server)->handshake.static_.has_value());

    const auto files = find_library(transport, env("LANTERN_TEST_STATIC"), "LanternCppTests/0.7");
    REQUIRE(files);
    REQUIRE(*files);
    CHECK((*files)->kind == LibraryKind::static_library);
    CHECK(std::string_view((*files)->root) == env("LANTERN_TEST_STATIC"));
    CHECK((*files)->handshake.static_.has_value());
}

TEST_CASE("v07: an upload's HEAD gives the chunk size, so the address alone resumes it (L-9.3-3)")
{
    Device device(env("LANTERN_TEST_PRIVATE"), true);
    const std::string large = empty_zip(40000);
    UploadRequest request;
    request.size       = large.size();
    request.sha256     = Sha256::of(large);
    request.kind       = "account";
    request.profile    = "Ines";
    const auto session = device->open_upload(frostline, request);
    REQUIRE(session);
    REQUIRE(*session);
    const std::string upload((*session)->upload);
    const auto head = device->upload_head(upload);
    REQUIRE(head);
    CHECK(head->offset == 0);
    CHECK(head->length == large.size());
    REQUIRE(head->chunk_size);
    CHECK(*head->chunk_size == (*session)->chunk_size);

    // A chunk went; the app kept the address and nothing else
    const auto chunk = device->upload_chunk(upload, 0, std::as_bytes(std::span(large.data(), 10000)));
    REQUIRE(chunk);
    UploadProgress resumed;
    std::copy(upload.begin(), upload.end(), resumed.url.begin());
    resumed.url_size = upload.size();
    StringSource source(large);
    const auto finished = device->upload_resumable(frostline, request, source, resumed, 16384);
    REQUIRE(finished);
    REQUIRE(*finished);
    CHECK((*finished)->size == large.size());
    CHECK(same_digest((*finished)->sha256, request.sha256));
    REQUIRE(device->delete_save(**finished));
}
