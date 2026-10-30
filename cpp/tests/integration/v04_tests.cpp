// Draft 0.4 against the reference server: pairing with a device key and
// signed polls, an admin's approval through § 5.7, invitations, signed
// requests and the clock's correction, the routes that write (saves, cheat
// sets, requests), and LAN discovery. Every name and game here is made up:
// Lea, Noor and Ines, and Frostline Tales.
#include <doctest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
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

DeviceKey test_key()
{
    KeySeed seed {};
    REQUIRE(base64_decode(env("LANTERN_TEST_KEY"), seed));
    return DeviceKey::from_seed(seed);
}

// The device's clock, which a test may set wrong.
class TestClock final : public Clock
{
  public:
    std::int64_t skew = 0;
    std::int64_t unix_seconds() override
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count()
            + skew;
    }
};

// A client of one server, with what a console has: a transport, a random
// source and a clock.
struct Device
{
    posix::LoopbackTransport transport;
    posix::SystemRandom random;
    TestClock clock;
    std::optional<Client> client;

    // The client holds the transport, the source and the clock: it stays where it is made
    Device(const Device&)            = delete;
    Device& operator=(const Device&) = delete;

    // With `as_admin`, the CI's device: mila's token, every scope, admin included.
    explicit Device(const std::string& origin, bool as_admin = false)
    {
        ClientConfig config;
        config.origin     = origin;
        config.user_agent = "LanternCppTests/0.4";
        config.platform   = "switch";
        config.random     = &random;
        config.clock      = &clock;
        auto made         = Client::create(transport, config);
        REQUIRE(made);
        client.emplace(std::move(*made));
        if (as_admin)
            REQUIRE(client->set_credentials(env("LANTERN_TEST_TOKEN"), test_key()));
        REQUIRE(client->handshake());
        if (as_admin)
            REQUIRE(client->offers(Family::admin) == 1);
    }

    Client& operator*() { return *client; }
    Client* operator->() { return &*client; }
};

// RFC 3339, `days` from now.
std::string in_days(int days)
{
    const auto when     = std::chrono::system_clock::now() + std::chrono::hours(24 * days);
    const std::time_t t = std::chrono::system_clock::to_time_t(when);
    std::tm utc {};
    gmtime_r(&t, &utc);
    std::array<char, 32> text {};
    const std::size_t size = std::strftime(text.data(), text.size(), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return { text.data(), size };
}

// A zip archive with nothing in it but a comment of `size` bytes: what a
// server takes as a save (a zip), of the size a test wants.
std::string empty_zip(std::size_t size)
{
    std::string zip("PK\x05\x06", 4);
    zip.append(16, '\0');
    zip.push_back(static_cast<char>(size & 0xFFU));
    zip.push_back(static_cast<char>((size >> 8U) & 0xFFU));
    zip.append(size, 'L');
    return zip;
}

std::span<const std::byte> bytes(const std::string& text)
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

class StringSource final : public UploadSource
{
  public:
    explicit StringSource(const std::string& text)
        : text_(text)
    {
    }
    Result<void> read(std::uint64_t offset, std::span<std::byte> out) override
    {
        reads += 1;
        std::copy_n(reinterpret_cast<const std::byte*>(text_.data()) + offset, out.size(), out.begin());
        return {};
    }
    int reads = 0;

  private:
    const std::string& text_;
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

class MemoryStore final : public CredentialStore
{
  public:
    std::vector<std::pair<std::string, Credentials>> kept;

    Result<std::optional<Credentials>> load(std::string_view uid, Allocator allocator) override
    {
        for (const auto& [key, value] : kept)
        {
            if (key == uid)
            {
                Credentials out(allocator);
                out.token.assign(value.token);
                out.key  = value.key;
                out.spki = value.spki;
                return std::optional<Credentials>(std::move(out));
            }
        }
        return std::optional<Credentials> {};
    }
    Result<void> store(std::string_view uid, const Credentials& credentials) override
    {
        static_cast<void>(erase(uid));
        kept.emplace_back(std::string(uid), credentials);
        return {};
    }
    Result<void> erase(std::string_view uid) override
    {
        std::erase_if(kept, [&](const auto& entry) { return entry.first == uid; });
        return {};
    }
};

const AdminPairing* waiting_with(const AdminPairings& page, std::string_view code)
{
    for (const AdminPairing& item : page.items)
    {
        if (item.code == code)
            return &item;
    }
    return nullptr;
}

} // namespace

TEST_CASE("pairing: a console asks with a key, an admin approves through 5.7, the console polls signed")
{
    Device console(env("LANTERN_TEST_PRIVATE"));
    CHECK(console->server()->account.state == "anonymous");
    CHECK(console->offers(Family::pairing) == 1);
    CHECK(console->offers(Family::signatures) == 1);

    const std::array<std::string_view, 2> scopes { "library", "saves" };
    PairingOptions options;
    options.device = "Lea's Switch";
    options.scopes = scopes;
    auto pairing   = console->start_pairing(options);
    REQUIRE(pairing);
    REQUIRE(pairing->key);
    CHECK(is_pairing_code(pairing->code.code));
    // verify_complete: verify with the code, for a QR code the console draws
    CHECK(pairing->code.verify_complete.starts_with(pairing->code.verify));
    CHECK(pairing->code.verify_complete.find(pairing->code.code) != std::string::npos);

    // Waiting; polled again at once, the server asks to slow down
    REQUIRE(console->poll_pairing(*pairing) == PollState::waiting);
    REQUIRE(console->poll_pairing(*pairing) == PollState::waiting);
    CHECK(pairing->wait >= 10);

    // The admin sees the code and the key's short fingerprint (L-5.7-5), and approves less than asked
    Device lea_admin(env("LANTERN_TEST_PRIVATE"), true);
    const auto waiting = lea_admin->admin_pairings();
    REQUIRE(waiting);
    REQUIRE(*waiting);
    const AdminPairing* found = waiting_with(**waiting, pairing->code.code);
    REQUIRE(found != nullptr);
    const auto fingerprint = pairing->key->fingerprint();
    CHECK(found->key == std::string_view(fingerprint.data(), fingerprint.size()));
    CHECK(found->device == "Lea's Switch");
    AdminPairingDecision decision;
    decision.decision = "approve";
    decision.scopes.emplace_back("library");
    REQUIRE(lea_admin->admin_decide_pairing(found->id, decision));

    // The poll waits out the interval it was asked to keep
    std::this_thread::sleep_for(std::chrono::milliseconds(4200));
    MemoryStore store;
    const auto polled = console->poll_pairing(*pairing, &store);
    REQUIRE(polled);
    CHECK(*polled == PollState::paired);
    CHECK(console->has_token());
    REQUIRE(console->device_key() != nullptr);
    REQUIRE(store.kept.size() == 1);
    CHECK(store.kept[0].second.key.has_value());

    // Signed from now on: the handshake shows the bound token and its scope
    REQUIRE(console->handshake());
    CHECK(console->server()->account.bound == true);
    REQUIRE(console->server()->account.scopes.size() == 1);
    CHECK(console->server()->account.scopes[0] == "library");
    CHECK(console->offers(Family::saves) == 0);
    const auto page = console->apps();
    REQUIRE(page);
    REQUIRE(*page);

    // Collected once: the same poll is gone
    const auto again = console->poll_pairing(*pairing);
    REQUIRE_FALSE(again);
    CHECK(again.error().effective_code() == Code::gone);

    // Another client of the same device signs in from the store
    Device later(env("LANTERN_TEST_PRIVATE"));
    REQUIRE(later->sign_in(store) == true);
    REQUIRE(later->handshake());
    CHECK(later->server()->account.state == "active");

    // The admin revokes the device: it loses its access at once (L-5.7-3)
    const auto devices = lea_admin->admin_devices();
    REQUIRE(devices);
    REQUIRE(*devices);
    const AdminDevice* mine = nullptr;
    for (const AdminDevice& device : (*devices)->items)
    {
        if (device.device == "Lea's Switch"
            && device.key == std::string_view(fingerprint.data(), fingerprint.size()))
            mine = &device;
    }
    REQUIRE(mine != nullptr);
    CHECK(mine->bound);
    REQUIRE(lea_admin->admin_revoke_device(mine->id));
    const auto revoked = console->apps();
    REQUIRE_FALSE(revoked);
    CHECK(revoked.error().status() == 401);
}

TEST_CASE("pairing: refused by the admin, the poll gets 410")
{
    Device console(env("LANTERN_TEST_PRIVATE"));
    const std::array<std::string_view, 1> scopes { "library" };
    PairingOptions options;
    options.device = "Noor's 3DS";
    options.scopes = scopes;
    auto pairing   = console->start_pairing(options);
    REQUIRE(pairing);
    Device lea_admin(env("LANTERN_TEST_PRIVATE"), true);
    const auto waiting = lea_admin->admin_pairings();
    REQUIRE(waiting);
    const AdminPairing* found = waiting_with(**waiting, pairing->code.code);
    REQUIRE(found != nullptr);
    AdminPairingDecision decision;
    decision.decision = "refuse";
    REQUIRE(lea_admin->admin_decide_pairing(found->id, decision));
    const auto polled = console->poll_pairing(*pairing);
    REQUIRE_FALSE(polled);
    CHECK(polled.error().effective_code() == Code::gone);
}

TEST_CASE("invitations: an account made by the admin, its invitation redeemed, then frozen")
{
    Device lea_admin(env("LANTERN_TEST_PRIVATE"), true);
    const auto users = lea_admin->admin_users();
    REQUIRE(users);
    REQUIRE(*users);
    CHECK(std::ranges::any_of((*users)->items, [](const AdminUser& user) { return user.name == "mila"; }));

    AdminUserCreate noor;
    noor.name = "noor";
    noor.scopes.emplace_back("library");
    noor.scopes.emplace_back("requests");
    const auto made = lea_admin->admin_create_user(noor);
    REQUIRE(made);
    REQUIRE(*made);
    CHECK((*made)->name == "noor");
    CHECK((*made)->state == "active");
    const auto twice = lea_admin->admin_create_user(noor);
    REQUIRE_FALSE(twice);
    CHECK(twice.error().code() == Code::conflict);

    InvitationCreate invite;
    invite.user = "noor";
    invite.scopes.emplace_back("library");
    invite.expires        = in_days(1);
    invite.devices        = 1;
    invite.note           = "Noor's consoles";
    const auto invitation = lea_admin->admin_create_invitation(invite);
    REQUIRE(invitation);
    REQUIRE(*invitation);
    const auto link = parse_invitation_link((*invitation)->link);
    REQUIRE(link);
    CHECK(link->code == (*invitation)->code);
    CHECK_FALSE(link->spki); // plain HTTP on loopback: no key to pin

    // Redeemed: approved at once, the first poll gives the token (SPEC.md 5.5)
    Device console(env("LANTERN_TEST_PRIVATE"));
    const std::array<std::string_view, 2> scopes { "library", "saves" };
    PairingOptions options;
    options.device     = "Noor's Switch";
    options.scopes     = scopes;
    options.invitation = link->code;
    auto pairing       = console->start_pairing(options);
    REQUIRE(pairing);
    REQUIRE(console->poll_pairing(*pairing) == PollState::paired);
    REQUIRE(console->handshake());
    CHECK(console->server()->account.name == "noor");
    REQUIRE(console->server()->account.scopes.size() == 1);
    CHECK(console->server()->account.scopes[0] == "library");

    // Used up: a second device is refused, 410 gone (L-5.5-1)
    Device second(env("LANTERN_TEST_PRIVATE"));
    options.device     = "Noor's Vita";
    const auto refused = second->start_pairing(options);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().effective_code() == Code::gone);

    // Frozen: the device sees it on its next call (L-5.7-3)
    AdminUserUpdate freeze;
    freeze.state      = "frozen";
    const auto frozen = lea_admin->admin_update_user("noor", freeze);
    REQUIRE(frozen);
    REQUIRE(*frozen);
    CHECK((*frozen)->state == "frozen");
    REQUIRE(console->handshake());
    CHECK(console->server()->account.state == "frozen");
    CHECK(console->offers(Family::library) == 0);

    // Its invitations listed, then revoked
    const auto listed = lea_admin->admin_invitations();
    REQUIRE(listed);
    REQUIRE(*listed);
    InvitationCreate other = invite;
    other.devices          = 2;
    const auto spare       = lea_admin->admin_create_invitation(other);
    REQUIRE(spare);
    REQUIRE(lea_admin->admin_revoke_invitation((*spare)->id));
    const auto gone = lea_admin->admin_revoke_invitation((*spare)->id);
    REQUIRE_FALSE(gone);
    CHECK(gone.error().status() == 404);
}

TEST_CASE("signatures: a clock an hour off is corrected from the server's Date, once")
{
    Device device(env("LANTERN_TEST_PRIVATE"), true);
    // The handshake's Date set the offset (Annex B.9): about nothing here
    CHECK(device->clock_offset() > -5);
    CHECK(device->clock_offset() < 5);
    // The console's clock goes an hour back: the first signature is refused
    // as expired, the client takes the Date of that 401 and signs again
    device.clock.skew = -3600;
    const auto page   = device->apps();
    REQUIRE(page);
    CHECK(device->clock_offset() > 3590);
    CHECK(device->clock_offset() < 3610);
    CHECK(device->apps());
}

TEST_CASE("saves: one request, resumable chunks, a resume after a cut, a download, a removal")
{
    Device device(env("LANTERN_TEST_PRIVATE"), true);
    REQUIRE(device->offers(Family::saves) == 1);

    // 9.2: in one request, with its Content-Digest
    const std::string small = empty_zip(300);
    SaveInfo info;
    info.kind              = "account";
    info.game_version_code = 196608;
    info.profile           = "Léa";
    info.note              = "Chapter 4, by the lake";
    const auto sent        = device->upload_save(frostline, bytes(small), info);
    REQUIRE(sent);
    REQUIRE(*sent);
    const Save& save = **sent;
    CHECK(save.platform == "switch");
    CHECK(save.title_id == frostline);
    CHECK(save.size == small.size());
    CHECK(same_digest(save.sha256, Sha256::of(small)));
    CHECK(save.profile == "Léa");
    CHECK(save.note == "Chapter 4, by the lake");
    CHECK(save.game_version_code == 196608U);

    StringSink sink;
    DownloadState state;
    REQUIRE(device->download_save(save, state, sink));
    CHECK(sink.bytes == small);

    // 9.3: in chunks of 16 KiB
    const std::string large = empty_zip(40000);
    UploadRequest request;
    request.size    = large.size();
    request.sha256  = Sha256::of(large);
    request.kind    = "account";
    request.profile = "Ines";
    StringSource source(large);
    UploadProgress progress;
    const auto uploaded = device->upload_resumable(frostline, request, source, progress, 16384);
    REQUIRE(uploaded);
    REQUIRE(*uploaded);
    CHECK((*uploaded)->size == large.size());
    CHECK(source.reads == 3);
    CHECK(progress.url_size == 0);

    // A cut: the first chunk went, the app kept an older offset; HEAD says where to go on
    const auto session = device->open_upload(frostline, request);
    REQUIRE(session);
    REQUIRE(*session);
    const std::string_view upload = (*session)->upload;
    const auto chunk              = device->upload_chunk(upload, 0, bytes(large).first(10000));
    REQUIRE(chunk);
    CHECK(chunk->offset == 10000);
    const auto conflict = device->upload_chunk(upload, 0, bytes(large).first(10000));
    REQUIRE_FALSE(conflict);
    CHECK(conflict.error().code() == Code::conflict);
    CHECK(device->upload_offset(upload) == 10000U);
    UploadProgress resumed;
    std::copy(upload.begin(), upload.end(), resumed.url.begin());
    resumed.url_size   = upload.size();
    resumed.chunk_size = (*session)->chunk_size;
    StringSource rest(large);
    const auto finished = device->upload_resumable(frostline, request, rest, resumed, 16384);
    REQUIRE(finished);
    REQUIRE(*finished);
    CHECK(rest.reads == 2); // 10000 to 26384, then to the end

    // A wrong digest: the server checks the whole archive (L-9.3-4)
    UploadRequest wrong = request;
    wrong.sha256        = Sha256::of(small);
    StringSource again(large);
    UploadProgress fresh;
    const auto refused = device->upload_resumable(frostline, wrong, again, fresh, 65536);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code() == Code::digest_mismatch);

    // An abandoned upload is gone
    const auto dropped = device->open_upload(frostline, request);
    REQUIRE(dropped);
    REQUIRE(device->abandon_upload((*dropped)->upload));
    CHECK_FALSE(device->upload_offset((*dropped)->upload));

    // Listed, then removed (L-9.1-3)
    const auto listed = device->saves(frostline);
    REQUIRE(listed);
    REQUIRE(*listed);
    CHECK(std::ranges::any_of((*listed)->saves, [&](const Save& s) { return s.save_id == save.save_id; }));
    REQUIRE(device->delete_save(save));
    const auto after = device->saves(frostline);
    REQUIRE(after);
    CHECK(std::ranges::none_of((*after)->saves, [&](const Save& s) { return s.save_id == save.save_id; }));
}

TEST_CASE("cheats: a set written, replaced, refused twice, removed")
{
    Device device(env("LANTERN_TEST_PRIVATE"), true);
    CheatWrite set;
    set.platform    = "switch";
    set.title_id    = frostline;
    set.build_id    = "4A1B2C3D4E5F6071";
    set.source      = "Lantern tests";
    set.note        = "Lamp oil";
    set.text        = "[Endless lamp oil]\n04000000 00ABCDEF 00000063\n";
    const auto made = device->create_cheat_set(set);
    REQUIRE(made);
    REQUIRE(*made);
    const CheatSet created = **made;
    CHECK(created.source == "Lantern tests");
    CHECK(device->cheat_text(created) == set.text);

    const auto twice = device->create_cheat_set(set);
    REQUIRE_FALSE(twice);
    CHECK(twice.error().code() == Code::conflict);

    set.text = "[Endless lamp oil]\n04000000 00ABCDEF 000003E7\n";
    REQUIRE(device->replace_cheat_set(created.id, set));
    CheatsQuery query;
    query.title_id  = frostline;
    const auto sets = device->cheats(query);
    REQUIRE(sets);
    const auto replaced
        = std::ranges::find_if((*sets)->cheats, [&](const CheatSet& s) { return s.id == created.id; });
    REQUIRE(replaced != (*sets)->cheats.end());
    CHECK(device->cheat_text(*replaced) == set.text);

    REQUIRE(device->delete_cheat_set(created.id));
    const auto gone = device->delete_cheat_set(created.id);
    REQUIRE_FALSE(gone);
    CHECK(gone.error().status() == 404);
}

TEST_CASE("requests: asked, asked again, listed, withdrawn")
{
    Device device(env("LANTERN_TEST_PRIVATE"), true);
    RequestCreate wish;
    wish.title_id    = "0100FFFF00010000";
    const auto first = device->request_title(wish);
    REQUIRE(first);
    REQUIRE(*first);
    CHECK((*first)->status == "open");
    CHECK((*first)->platform == "switch");
    const auto second = device->request_title(wish);
    REQUIRE(second);
    CHECK((*second)->id == (*first)->id);
    const auto listed = device->requests();
    REQUIRE(listed);
    CHECK(std::ranges::any_of(
        (*listed)->requests, [&](const TitleRequest& r) { return r.id == (*first)->id; }));
    REQUIRE(device->withdraw_request((*first)->id));
    const auto gone = device->withdraw_request((*first)->id);
    REQUIRE_FALSE(gone);
    CHECK(gone.error().status() == 404);
}

TEST_CASE("discovery: the public server answers the datagram on loopback")
{
    auto socket = posix::UdpBroadcastSocket::open();
    REQUIRE(socket);
    struct Found final : DiscoveryHandler
    {
        std::vector<std::string> origins;
        std::vector<std::string> names;
        bool on_server(const DiscoveredServer& server) override
        {
            origins.emplace_back(server.origin);
            names.emplace_back(server.reply->name);
            return true;
        }
    } found;
    DiscoveryOptions options;
    options.address  = "127.0.0.1";
    options.port     = static_cast<std::uint16_t>(std::stoi(env("LANTERN_TEST_DISCOVERY_PORT")));
    options.wait     = std::chrono::milliseconds(1200);
    options.attempts = 3;
    REQUIRE(discover(*socket, options, found));
    REQUIRE(found.origins.size() == 1); // three requests, one server
    const std::string public_origin = env("LANTERN_TEST_PUBLIC");
    const std::string port          = public_origin.substr(public_origin.rfind(':'));
    CHECK(found.origins[0] == "https://127.0.0.1" + port);
}

TEST_CASE("a malicious server (when run_server.py has one)")
{
    // The shared malicious test server is another project's; this case runs
    // against it once run_server.py is given --hostile-server. A client
    // must come out of every one of its answers with an error, never a crash.
    const char* origin = std::getenv("LANTERN_TEST_HOSTILE");
    if (origin == nullptr)
        return;
    posix::LoopbackTransport transport(std::chrono::seconds(5));
    posix::SystemRandom random;
    ClientConfig config;
    config.origin     = origin;
    config.user_agent = "LanternCppTests/0.4";
    config.platform   = "switch";
    config.random     = &random;
    auto client       = Client::create(transport, config);
    REQUIRE(client);
    const auto shake = client->handshake();
    if (!shake || !*shake)
        return;
    static_cast<void>(client->apps());
    static_cast<void>(client->title(frostline));
    static_cast<void>(client->homebrew());
    CheatsQuery query;
    static_cast<void>(client->cheats(query));
}
