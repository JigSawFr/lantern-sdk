// Draft 0.5 against the reference server: the event stream and long
// polling, grants and the reference peer, a mirror, sync, encrypted save
// backups, deleting an account, and the library exported as a static
// library, read over HTTP and from its folder. Fictional names and games:
// Lea, Noor and Ines, Frostline Tales.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <chrono>
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

struct Device
{
    posix::LoopbackTransport transport;
    posix::SystemRandom random;
    std::optional<Client> client;

    Device(const Device&)            = delete;
    Device& operator=(const Device&) = delete;

    // With `as_admin`, the CI's device: mila's token and key, every scope.
    explicit Device(const std::string& origin, bool as_admin = false)
    {
        ClientConfig config;
        config.origin     = origin;
        config.user_agent = "LanternCppTests/0.5";
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

// The events a stream gives, until the kind waited for.
struct Waiter final : EventHandler
{
    std::vector<std::pair<EventKind, std::string>> seen;
    EventKind until = EventKind::ready;
    bool on_event(const StreamEvent& event) override
    {
        seen.emplace_back(event.kind, std::string(event.data));
        return event.kind != until;
    }
};

App first_app(Device& device)
{
    const auto page = device->apps();
    REQUIRE(page);
    REQUIRE(*page);
    REQUIRE(!(*page)->items.empty());
    return (*page)->items.front();
}

// The app ids of a listing, sorted, to compare two of them.
std::vector<std::string> ids(std::span<const App> apps)
{
    std::vector<std::string> out;
    for (const App& app : apps)
        out.emplace_back(app.app_id);
    std::ranges::sort(out);
    return out;
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

TEST_CASE("v05: the handshake's new families and limits")
{
    Device device(env("LANTERN_TEST_PUBLIC"));
    CHECK(device->offers(Family::events) == 1);
    CHECK(device->offers(Family::peers) == 1);
    const Handshake& hello = *device->server();
    REQUIRE(hello.limits);
    CHECK(hello.limits->heartbeat.value_or(0) >= 5);
    CHECK(device->event_silence_limit().count() == 2 * static_cast<long>(*hello.limits->heartbeat));
    CHECK(grant_key_of(hello));
    Device admin(env("LANTERN_TEST_PRIVATE"), true);
    CHECK(admin->offers(Family::sync) == 1);
    CHECK(admin->offers(Family::encrypted_saves) == 1);
}

TEST_CASE("v05: the event stream, resumed with Last-Event-ID, and the same events by long polling")
{
    Device lea(env("LANTERN_TEST_PRIVATE"), true);
    EventStreamState state;
    Waiter ready;
    REQUIRE(lea->events(state, ready));
    REQUIRE(ready.seen.size() == 1);
    CHECK(ready.seen[0].first == EventKind::ready);
    REQUIRE(!state.last_id_view().empty());
    const std::string since(state.last_id_view());

    // Something the account may see happens: a request
    RequestCreate wish;
    wish.platform   = "switch";
    wish.title_id   = frostline;
    const auto made = lea->request_title(wish);
    REQUIRE(made);
    REQUIRE(*made);

    // The stream again, from where it stood: the request comes after `ready`
    Waiter request;
    request.until = EventKind::request;
    REQUIRE(lea->events(state, request));
    REQUIRE(!request.seen.empty());
    CHECK(request.seen.front().first == EventKind::ready);
    CHECK(request.seen.back().first == EventKind::request);
    const auto read = read_request_event(request.seen.back().second);
    REQUIRE(read);
    REQUIRE(*read);
    CHECK((*read)->id == (*made)->id);
    CHECK((*read)->status == "open");

    // Long polling: the same event after the same token, at once
    const auto polled = lea->wait_changes(since, 5);
    REQUIRE(polled);
    REQUIRE(*polled);
    CHECK(std::ranges::any_of((*polled)->events, [](const Event& e) { return e.event == "request"; }));
    CHECK_FALSE((*polled)->since.empty());
    REQUIRE(lea->withdraw_request((*made)->id));

    // A token the server never gave: 400, and the position is forgotten
    EventStreamState unknown;
    unknown.set_last_id("s_00000000_1");
    Waiter none;
    const auto refused = lea->events(unknown, none);
    REQUIRE_FALSE(refused);
    CHECK((refused.error().status() == 400 || refused.error().status() == 410));
    CHECK(unknown.last_id_view().empty());
}

TEST_CASE("v05: a grant, the reference peer's file with it, and the same file from a mirror")
{
    Device device(env("LANTERN_TEST_PUBLIC"));
    const App app    = first_app(device);
    const auto grant = device->grant(app.sha256);
    REQUIRE(grant);
    REQUIRE(*grant);
    CHECK((*grant)->size == app.size);

    // The peer verifies the grant by the server's key; the client checks the bytes
    const std::string peer_origin = env("LANTERN_TEST_PEER");
    const auto parts              = split_url(peer_origin);
    REQUIRE(parts);
    const PeerEndpoint peer { parts->host, parts->port, "/lantern", false };
    const auto holds = device->peer_holds(peer, **grant);
    REQUIRE(holds);
    CHECK(*holds);
    DownloadState state;
    StringSink sink;
    REQUIRE(device->download_from_peer(peer, **grant, { app.file, app.size, app.sha256 }, state, sink));
    CHECK(sink.bytes.size() == app.size);

    // A grant for another file is no grant for this one: the peer says 403
    const auto page = device->apps();
    REQUIRE(page);
    REQUIRE(*page);
    REQUIRE((*page)->items.size() > 1);
    const App& other   = (*page)->items[1];
    Grant forged       = **grant;
    forged.sha256      = other.sha256;
    forged.size        = other.size;
    const auto refused = device->peer_holds(peer, forged);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().status() == 403);

    // A mirror: the server's own file at another address, read untrusted
    const auto file = resolve_url(*split_url(env("LANTERN_TEST_PUBLIC")), app.file);
    REQUIRE(file);
    std::vector<Mirror> mirrors(1);
    mirrors[0].url = *file;
    DownloadState mirror_state;
    StringSink mirrored;
    REQUIRE(
        device->download_with_mirrors(mirrors, { app.file, app.size, app.sha256 }, mirror_state, mirrored));
    CHECK(mirrored.bytes == sink.bytes);
}

TEST_CASE("v05: the peer answers a discovery datagram that asks for peers")
{
    auto socket = posix::UdpBroadcastSocket::open();
    REQUIRE(socket);
    struct Found final : DiscoveryHandler
    {
        std::vector<std::string> peers;
        std::vector<std::vector<std::string>> servers;
        std::uint16_t port = 0;
        bool on_server(const DiscoveredServer&) override { return true; }
        bool on_peer(const DiscoveredPeer& peer) override
        {
            peers.emplace_back(peer.reply->name);
            servers.emplace_back();
            for (const String& uid : peer.reply->servers)
                servers.back().emplace_back(uid);
            port = peer.endpoint.port;
            return true;
        }
    } found;
    DiscoveryOptions options;
    options.address  = "127.0.0.1";
    options.port     = static_cast<std::uint16_t>(std::stoi(env("LANTERN_TEST_PEER_DISCOVERY_PORT")));
    options.wait     = std::chrono::milliseconds(1200);
    options.attempts = 2;
    options.peers    = true;
    REQUIRE(discover(*socket, options, found));
    REQUIRE(found.peers.size() == 1);
    CHECK(found.peers[0] == "Lea's Switch");
    Device device(env("LANTERN_TEST_PUBLIC"));
    REQUIRE(found.servers[0].size() == 1);
    CHECK(found.servers[0][0] == std::string_view(device->server()->uid));
    const std::string peer_origin = env("LANTERN_TEST_PEER");
    CHECK(peer_origin.ends_with(":" + std::to_string(found.port)));
}

TEST_CASE("v05: sync with consent, the merge, If-Match, deletion and the generation")
{
    Device lea(env("LANTERN_TEST_PRIVATE"), true);
    // Nothing before consent (L-20.1-1)
    const auto asked = lea->sync_state();
    REQUIRE_FALSE(asked);
    CHECK(asked.error().category() == Category::refused);

    REQUIRE(lea->set_sync_consent({ true, false }));
    const auto state = lea->sync_state();
    REQUIRE(state);
    REQUIRE(*state);
    const std::string generation((*state)->generation);
    const std::string device((*state)->device);
    CHECK(device.starts_with("d_"));

    Wish wish;
    wish.platform = "switch";
    wish.title_id = frostline;
    wish.note     = "For the holidays";
    SyncItem item;
    item.key = *wish_key("switch", frostline);
    write_wish(wish, item.value);
    String now;
    format_sync_time(std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count(),
        now);
    item.updated       = now;
    const auto written = lea->sync_write(sync_wishes, std::span(&item, 1));
    REQUIRE(written);
    REQUIRE(*written);
    REQUIRE((*written)->items.size() == 1);
    const std::uint64_t rev = (*written)->items[0].rev.value_or(0);
    CHECK(rev > 0);
    const auto back = read_wish((*written)->items[0].value);
    REQUIRE(back);
    CHECK(back->note == "For the holidays");

    // What changed after the rev before: this wish
    const auto changed = lea->sync_items(sync_wishes, rev - 1);
    REQUIRE(changed);
    REQUIRE(*changed);
    CHECK(std::ranges::any_of((*changed)->items, [&](const SyncItem& i) { return i.key == item.key; }));

    // All or nothing: a stale If-Match changes nothing (412)
    const auto stale = lea->sync_write(sync_wishes, std::span(&item, 1), rev - 1);
    REQUIRE_FALSE(stale);
    CHECK(stale.error().effective_code() == Code::precondition_failed);
    CHECK(lea->sync_write(sync_wishes, std::span(&item, 1), (*written)->rev));

    // What is installed: only by name, the device's own item
    SyncItem mine;
    mine.key = device;
    Installed installed;
    installed.device   = "Lea's Switch";
    installed.platform = "switch";
    write_installed(installed, mine.value);
    mine.updated = now;
    CHECK_FALSE(lea->sync_write(sync_installed, std::span(&mine, 1)));
    REQUIRE(lea->set_sync_consent({ true, true }, lea->sync_generation()));
    REQUIRE(lea->sync_write(sync_installed, std::span(&mine, 1)));

    // Another console of Lea's keeps the generation it read; Lea deletes all
    Device other(env("LANTERN_TEST_PRIVATE"), true);
    REQUIRE(other->set_sync_consent({ true, false }, generation));
    REQUIRE(lea->sync_delete());
    const auto asleep = other->sync_items(sync_wishes);
    REQUIRE_FALSE(asleep);
    CHECK(asleep.error().category() == Category::refused);
    CHECK_FALSE(other->sync_consent().sync);
    // Lea's own device reads the new generation
    const auto fresh = lea->sync_state();
    REQUIRE(fresh);
    REQUIRE(*fresh);
    CHECK(std::string_view((*fresh)->generation) != generation);
}

TEST_CASE("v05: an encrypted backup, sent resumably and in one request, kept as sent, opened back")
{
    Device lea(env("LANTERN_TEST_PRIVATE"), true);
    posix::SystemRandom random;
    const auto key = SaveKey::generate(random);
    REQUIRE(key);
    // A save of a few chunks, the last one short
    std::string archive;
    for (std::size_t i = 0; i < 2 * save_chunk_size + 1234; ++i)
        archive.push_back(static_cast<char>((i * 31 + 7) % 253));
    const auto header = make_save_header(*key, random);
    REQUIRE(header);
    StringSource plain(archive);
    auto source = EncryptingSource::create(*key, *header, plain, archive.size());
    REQUIRE(source);
    UploadRequest request;
    request.kind = "account";
    REQUIRE(source->describe(request));
    UploadProgress progress;
    const auto saved = lea->upload_resumable(frostline, request, *source, progress, 50000);
    REQUIRE(saved);
    REQUIRE(*saved);
    const Save& save = **saved;
    REQUIRE(save.encryption);
    const auto id = key->id_text();
    CHECK(save.encryption->key_id == std::string_view(id.data(), id.size()));
    CHECK(save.size == encrypted_save_size(archive.size()));

    // Downloaded and opened as it comes: the archive, whole
    StringSink restored;
    DecryptingSink opening(*key, restored);
    DownloadState state;
    REQUIRE(lea->download_save(save, state, opening));
    REQUIRE(opening.finish());
    CHECK(restored.bytes == archive);

    // Another key opens nothing
    const auto other = SaveKey::generate(random);
    REQUIRE(other);
    StringSink nothing;
    DecryptingSink wrong(*other, nothing);
    DownloadState again;
    CHECK_FALSE(lea->download_save(save, again, wrong));
    CHECK(nothing.bytes.empty());

    // A small one in one request, with Lantern-Save-Encryption
    const std::string small = "Frostline Tales, chapter 3";
    Vector<std::byte> sealed;
    const auto small_header = make_save_header(*key, random);
    REQUIRE(small_header);
    REQUIRE(encrypt_save(*key, *small_header, std::as_bytes(std::span(small.data(), small.size())), sealed));
    SaveInfo info;
    info.kind              = "account";
    info.encryption_key_id = std::string_view(id.data(), id.size());
    const auto one         = lea->upload_save(frostline, sealed, info);
    REQUIRE(one);
    REQUIRE(*one);
    REQUIRE((*one)->encryption);
    REQUIRE(lea->delete_save(**one));
    REQUIRE(lea->delete_save(save));
}

TEST_CASE("v05: an account deleted, its name typed again; the caller's own refused")
{
    Device lea(env("LANTERN_TEST_PRIVATE"), true);
    AdminUserCreate ines;
    ines.name = "ines";
    ines.scopes.emplace_back("library");
    REQUIRE(lea->admin_create_user(ines));
    CHECK_FALSE(lea->admin_delete_user("ines", "ine"));
    REQUIRE(lea->admin_delete_user("ines", "ines"));
    const auto users = lea->admin_users();
    REQUIRE(users);
    REQUIRE(*users);
    CHECK(std::ranges::none_of((*users)->items, [](const AdminUser& u) { return u.name == "ines"; }));
    const auto gone = lea->admin_delete_user("ines", "ines");
    REQUIRE_FALSE(gone);
    CHECK(gone.error().status() == 404);
    const auto own = lea->admin_delete_user("mila", "mila");
    REQUIRE_FALSE(own);
    CHECK(own.error().status() == 409);
}

TEST_CASE("v05: the library as a static library, over HTTP and from its folder, as the server answers")
{
    posix::LoopbackTransport transport;
    auto http = HttpStaticFiles::create(transport, env("LANTERN_TEST_STATIC"), "LanternCppTests/0.5");
    REQUIRE(http);
    FolderFiles folder(env("LANTERN_TEST_STATIC_DIR"));
    Device server(env("LANTERN_TEST_PUBLIC"));
    for (StaticFiles* files : { static_cast<StaticFiles*>(&*http), static_cast<StaticFiles*>(&folder) })
    {
        auto opened = StaticLibrary::open(*files);
        REQUIRE(opened);
        REQUIRE(*opened);
        StaticLibrary& library = **opened;
        CHECK(library.handshake().base == ".");
        CHECK(library.handshake().static_->page_size == 2);

        // Every page of the Switch's apps, chained by their cursors
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
        REQUIRE(!apps.empty());

        // What a Switch with Frostline Tales 1.0 is missing: as the server says
        MissingRequest request;
        InstalledApp installed;
        installed.app_id       = frostline;
        installed.version_code = 0;
        request.installed.push_back(installed);
        request.want        = { "update", "dlc", "base" };
        const auto computed = library.missing("switch", request);
        REQUIRE(computed);
        const auto answered = server->missing(request);
        REQUIRE(answered);
        REQUIRE(*answered);
        CHECK(ids(*computed) == ids((*answered)->items));

        // A file, checked; a title and a homebrew entry where § 21.1 puts them
        const App& app = apps.front();
        DownloadState state;
        StringSink sink;
        REQUIRE(library.download({ app.file, app.size, app.sha256 }, state, sink));
        CHECK(sink.bytes.size() == app.size);
        const auto title = library.title("switch", app.title_id);
        REQUIRE(title);
        REQUIRE(*title);
        const auto homebrew = library.homebrew("switch");
        REQUIRE(homebrew);
        REQUIRE(*homebrew);
        REQUIRE(!(*homebrew)->items.empty());
        const auto entry = library.homebrew_entry("switch", (*homebrew)->items.front().id);
        REQUIRE(entry);
        REQUIRE(*entry);
        CHECK(plan_install(**entry, (**entry).package));
        const auto cheats = library.cheats("switch", frostline);
        REQUIRE(cheats);
    }
    CHECK(folder.reads > 0);
}
