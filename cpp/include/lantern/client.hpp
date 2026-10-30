// The client of draft 0.5: the handshake, pairing (with a device key, an
// invitation, a QR code), signed requests, the apps' listing with its
// cursors, what the device is missing, changes, titles, homebrew (the
// listing, an entry, the updates), save backups (listed, downloaded, sent
// in one request or resumably, removed, encrypted on the device), cheat
// sets (read and written), requests, the administration API, events (a
// stream, or long polling), grants, mirrors and peers, sync, and verified
// downloads. Everything goes through the app's Transport.
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/credentials.hpp>
#include <lantern/device_key.hpp>
#include <lantern/document.hpp>
#include <lantern/download.hpp>
#include <lantern/error.hpp>
#include <lantern/events.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/memory.hpp>
#include <lantern/peers.hpp>
#include <lantern/sync.hpp>
#include <lantern/tls.hpp>
#include <lantern/transport.hpp>
#include <lantern/types.hpp>
#include <lantern/url.hpp>

namespace lantern
{

// § 3.4: a route, a parameter or a schema going away.
class DeprecationLog
{
  public:
    DeprecationLog()                                 = default;
    DeprecationLog(const DeprecationLog&)            = default;
    DeprecationLog(DeprecationLog&&)                 = default;
    DeprecationLog& operator=(const DeprecationLog&) = default;
    DeprecationLog& operator=(DeprecationLog&&)      = default;
    virtual ~DeprecationLog()                        = default;

    // `deprecation` as sent ("@1793318400"), `sunset` an HTTP date or empty.
    virtual void deprecated(std::string_view url, std::string_view deprecation, std::string_view sunset) = 0;
};

struct ClientConfig
{
    // The server's origin: "https://shelf.example.org" or
    // "https://192.0.2.10:8443"; plain HTTP only on loopback (SPEC.md § 2).
    std::string_view origin;
    // "Name/version" (§ 2, required).
    std::string_view user_agent;
    // Lantern-Platform (§ 4.3), sent on every call: the platform the client
    // runs on. Empty: none sent, and the server answers for every platform.
    std::string_view platform;
    // Accept-Language, as the app builds it ("fr, en;q=0.5"), or empty.
    std::string_view accept_language;
    // Limits and memory of every document read (§ 13).
    DecodeOptions decode {};
    // The most of a problem+json body read for an error.
    std::size_t max_error_body = std::size_t { 64 } * 1024;
    // Cryptographic random bytes (device_key.hpp): for a device key at
    // pairing and a nonce per signed request. Required to pair with a key
    // or to sign; without it, the client takes bearer-only tokens alone.
    RandomSource* random = nullptr;
    // The time a signature is made at; the system's clock when null. The
    // client corrects it with the server's Date (§ 5.4, Annex B.9).
    Clock* clock = nullptr;
    // The transport's view of the server's key (tls.hpp), when the app gave
    // the transport one: the client then pins the key it pairs over, and
    // sends no token over a connection it has not verified (§ 5.3).
    ServerTrust* trust = nullptr;
    // An app's own signer, called after the client's (rarely needed: the
    // client signs with its device key itself).
    RequestSigner* signer = nullptr;
    // Told of each Deprecation a server announces (§ 3.4, L-3.4-5), for the
    // app's log; nothing is done otherwise.
    DeprecationLog* deprecations = nullptr;
};

// § 5.2: how a device asks to pair.
struct PairingOptions
{
    std::string_view device; // the name the user sees ("Lea's Switch")
    std::span<const std::string_view> scopes; // "library", "saves", …
    // An invitation's code (§ 5.5): the pairing is approved at once.
    std::string_view invitation;
    // Make a device key and bind the token to it (§ 5.4, L-5.4-2). Off
    // only for a server that still takes bearer-only tokens.
    bool bind_key = true;
};

// A pairing in progress, kept by the app while it polls.
struct Pairing
{
    using allocator_type = Allocator;

    PairingCode code; // code, verify, verify_complete (a QR code), poll, interval, expires
    std::optional<DeviceKey> key; // the device key, when bound
    // The server's key seen at pairing (when the app gave a ServerTrust):
    // its short form is shown next to the code and the QR code (§ 5.3).
    std::optional<Digest> spki;
    std::array<char, 19> fingerprint {};
    // Seconds to wait before the next poll (`interval`, more after a 429).
    std::uint32_t wait = 5;

    explicit Pairing(const allocator_type& allocator = {})
        : code(allocator)
    {
    }
    [[nodiscard]] std::string_view fingerprint_view() const noexcept
    {
        return spki ? std::string_view(fingerprint.data(), fingerprint.size()) : std::string_view {};
    }
};

enum class PollState : std::uint8_t
{
    waiting, // 202: poll again after Pairing::wait seconds
    paired, // 200: the client holds its token (and key) now
};

// § 9.2: what goes with a save sent in one request.
struct SaveInfo
{
    std::string_view platform; // overrides the configuration's
    std::string_view kind; // account, device, bcat, cache, other
    std::string_view slot;
    std::optional<std::uint64_t> game_version_code;
    std::string_view profile; // UTF-8, 64 bytes at most
    std::string_view note; // UTF-8, 120 bytes at most
    // An archive encrypted on the device (§ 9.4, encrypted_save.hpp): its
    // save key's id, sent as Lantern-Save-Encryption. Leave `profile` and
    // `note` out unless the user wants them shown (L-9.4-6).
    std::string_view encryption_key_id;
};

// Where a resumable upload reads the archive from (§ 9.3).
class UploadSource
{
  public:
    UploadSource()                               = default;
    UploadSource(const UploadSource&)            = default;
    UploadSource(UploadSource&&)                 = default;
    UploadSource& operator=(const UploadSource&) = default;
    UploadSource& operator=(UploadSource&&)      = default;
    virtual ~UploadSource()                      = default;

    // Fills `out` with the bytes from `offset` on; `out` is never past the
    // archive's end.
    [[nodiscard]] virtual Result<void> read(std::uint64_t offset, std::span<std::byte> out) = 0;
};

// An upload in progress: the app keeps it to resume after a restart.
struct UploadProgress
{
    std::array<char, 512> url {}; // the upload's address, empty before it is opened
    std::size_t url_size     = 0;
    std::uint64_t offset     = 0; // what the server has
    std::uint64_t chunk_size = 0;

    [[nodiscard]] std::string_view url_view() const noexcept { return { url.data(), url_size }; }
    void reset() noexcept { *this = UploadProgress {}; }
};

// A chunk sent: where the server is, and the save once the last chunk is in.
struct ChunkResult
{
    using allocator_type = Allocator;

    std::uint64_t offset = 0;
    std::optional<Save> save;

    explicit ChunkResult(const allocator_type& /*allocator*/ = {}) { }
};

// § 5.7's pages.
struct PageQuery
{
    std::optional<std::uint32_t> page_size;
    std::string_view cursor;
};

struct AppsQuery
{
    std::string_view platform; // overrides Lantern-Platform
    std::string_view type;
    std::string_view title_id;
    std::string_view q;
    std::string_view sort; // "name", "added" or "release"
    std::optional<std::uint32_t> page_size;
    std::string_view cursor; // a page's `next`
};

struct HomebrewQuery
{
    std::string_view platform;
    std::string_view q;
    std::string_view kind;
    std::string_view genre;
    std::optional<std::uint32_t> page_size;
    std::string_view cursor;
};

struct CheatsQuery
{
    std::string_view platform;
    std::string_view title_id;
    std::string_view build_id;
};

// The families of § 4.2, for Client::offers().
enum class Family : std::uint8_t
{
    library,
    titles,
    changes,
    sections,
    homebrew,
    saves,
    cheats,
    requests,
    pairing,
    signatures,
    admin,
    events,
    peers,
    sync,
    encrypted_saves,
};

// What Client::events() and Client::wait_changes() take.
struct EventsQuery
{
    // A platform for the `library` events (§ 18.2): the configuration's
    // Lantern-Platform otherwise.
    std::string_view platform;
};

class Client
{
  public:
    // Checks the configuration: an origin of HTTPS (or HTTP on loopback)
    // with no path, a User-Agent of the form Name/version, a platform name.
    [[nodiscard]] static Result<Client> create(Transport& transport, const ClientConfig& config);

    // `Authorization: Bearer <token>` on every call to the server's origin,
    // and to no other (§ 2, § 5.1): a bearer-only token, or one bound to
    // `key`, with which every request that carries it is then signed (§ 5.4).
    [[nodiscard]] Result<void> set_bearer_token(std::string_view token);
    [[nodiscard]] Result<void> set_credentials(std::string_view token, const DeviceKey& key);
    void clear_bearer_token() noexcept;
    [[nodiscard]] bool has_token() const noexcept { return !token_.empty(); }
    [[nodiscard]] const DeviceKey* device_key() const noexcept { return signer_ ? &signer_->key() : nullptr; }
    // Seconds the client adds to its clock for `created` (the server's Date
    // minus the device's time).
    [[nodiscard]] std::int64_t clock_offset() const noexcept { return clock_offset_; }

    // What the app kept for this server (by its uid, so after handshake()):
    // the token, the key, the pin (given to the ServerTrust). False when it
    // kept nothing: the device pairs.
    [[nodiscard]] Result<bool> sign_in(CredentialStore& store);
    // Forgets this server's credentials, here and in the store.
    [[nodiscard]] Result<void> forget(CredentialStore& store);

    // § 5.2: asks for a code, with a new device key unless told otherwise.
    // Over a certificate no CA vouches for, the ServerTrust's key is taken
    // (it sends nothing secret yet), shown in Pairing::fingerprint and
    // pinned for the polls (§ 5.3). Needs the handshake.
    [[nodiscard]] Result<Pairing> start_pairing(const PairingOptions& options);
    // GET poll, signed by the pairing's key (§ 5.4): `waiting` until the
    // user approves; `paired` once, with the token set on this client and
    // kept in `store` when one is given. 410 (gone): refused, expired or
    // collected; 429 (slow_down) makes Pairing::wait longer.
    [[nodiscard]] Result<PollState> poll_pairing(Pairing& pairing, CredentialStore* store = nullptr);

    // GET /.well-known/lantern (§ 4.2). Every other call needs it first: it
    // gives the base path and the families offered to this caller. Absent
    // (an empty optional) for a handshake of a newer schema.
    [[nodiscard]] Read<Handshake> handshake();
    [[nodiscard]] const Handshake* server() const noexcept { return handshake_ ? &*handshake_ : nullptr; }
    // The schema the server writes for a family, 0 when it does not offer
    // it to this caller (or before the handshake).
    [[nodiscard]] std::uint64_t offers(Family family) const noexcept;

    // § 6.2: a page; pass its `next` as the next query's cursor. A 410
    // (Code::gone) means the cursor expired: read the list from its start.
    [[nodiscard]] Read<AppsPage> apps(const AppsQuery& query = {});
    // § 6.3: needs a platform (the configuration's, or `platform`).
    [[nodiscard]] Read<AppsPage> missing(
        const MissingRequest& request, std::string_view cursor = {}, std::string_view platform = {});
    // § 6.4: without `since`, no apps and the current token.
    [[nodiscard]] Read<Changes> changes(std::string_view since = {});
    [[nodiscard]] Read<Sections> sections();
    // § 7.1, § 7.2 (100 ids at most), § 7.3.
    [[nodiscard]] Read<Title> title(std::string_view title_id);
    [[nodiscard]] Read<Titles> titles(std::span<const std::string_view> ids);
    [[nodiscard]] Read<TitleChanges> title_changes(std::string_view since = {});
    // § 8.5.
    [[nodiscard]] Read<HomebrewPage> homebrew(const HomebrewQuery& query = {});
    [[nodiscard]] Read<Homebrew> homebrew_entry(std::string_view id);
    [[nodiscard]] Read<HomebrewPage> homebrew_updates(
        const HomebrewUpdatesRequest& request, std::string_view cursor = {}, std::string_view platform = {});
    // § 10.
    [[nodiscard]] Read<CheatSets> cheats(const CheatsQuery& query = {});
    // A set's text (1 MiB at most), checked against its size and SHA-256.
    [[nodiscard]] Result<String> cheat_text(const CheatSet& set);
    // With scope cheats.write: POST (201, the new set; 409 conflict when it
    // exists), PUT (204) and DELETE (204).
    [[nodiscard]] Read<CheatSet> create_cheat_set(const CheatWrite& set);
    [[nodiscard]] Result<void> replace_cheat_set(std::string_view id, const CheatWrite& set);
    [[nodiscard]] Result<void> delete_cheat_set(std::string_view id);

    // § 9: the account's backups, newest first per title.
    [[nodiscard]] Read<Saves> saves(std::string_view title_id = {}, std::string_view platform = {});
    // The archive, checked as any file (§ 6.6).
    [[nodiscard]] Result<void> download_save(const Save& save, DownloadState& state, DownloadSink& sink);
    [[nodiscard]] Result<void> delete_save(const Save& save);
    // § 9.2: a save of at most limits.save_body bytes, in one request, with
    // its Content-Digest.
    [[nodiscard]] Read<Save> upload_save(
        std::string_view title_id, std::span<const std::byte> archive, const SaveInfo& info);
    // § 9.3, one step at a time.
    [[nodiscard]] Read<UploadSession> open_upload(
        std::string_view title_id, const UploadRequest& request, std::string_view platform = {});
    // HEAD: what the server has of the upload.
    [[nodiscard]] Result<std::uint64_t> upload_offset(std::string_view upload);
    // PATCH: a chunk at `offset`; a 409 gives the server's offset in the
    // error's detail and in `progress` through upload_resumable().
    [[nodiscard]] Result<ChunkResult> upload_chunk(
        std::string_view upload, std::uint64_t offset, std::span<const std::byte> chunk);
    [[nodiscard]] Result<void> abandon_upload(std::string_view upload);
    // § 9.3 whole: opens the upload when `progress` has none, or asks the
    // server where it is (HEAD) when it has one, then sends the rest in
    // chunks of at most `max_chunk` bytes (and the server's chunk_size).
    // A lost connection leaves `progress` where the server is: call again
    // to resume. Success is the save entry, once the server checked the
    // whole archive's SHA-256.
    [[nodiscard]] Read<Save> upload_resumable(std::string_view title_id, const UploadRequest& request,
        UploadSource& source, UploadProgress& progress, std::size_t max_chunk = std::size_t { 1024 } * 1024,
        std::string_view platform = {});

    // § 11.
    [[nodiscard]] Read<TitleRequests> requests(std::string_view platform = {});
    // 201 for a new request, 200 for the open one of the same title.
    [[nodiscard]] Read<TitleRequest> request_title(const RequestCreate& request);
    [[nodiscard]] Result<void> withdraw_request(std::string_view id);

    // § 5.7, scope admin.
    [[nodiscard]] Read<AdminUsers> admin_users(const PageQuery& page = {});
    [[nodiscard]] Read<AdminUser> admin_create_user(const AdminUserCreate& user);
    [[nodiscard]] Read<AdminUser> admin_update_user(std::string_view name, const AdminUserUpdate& change);
    [[nodiscard]] Read<AdminDevices> admin_devices(std::string_view user = {}, const PageQuery& page = {});
    [[nodiscard]] Result<void> admin_revoke_device(std::string_view id);
    // Each waiting pairing's code and key, to compare with the console's
    // screen next to the server's short fingerprint as pinned (L-5.7-5).
    [[nodiscard]] Read<AdminPairings> admin_pairings(const PageQuery& page = {});
    [[nodiscard]] Result<void> admin_decide_pairing(
        std::string_view id, const AdminPairingDecision& decision);
    [[nodiscard]] Read<Invitations> admin_invitations(const PageQuery& page = {});
    [[nodiscard]] Read<Invitation> admin_create_invitation(const InvitationCreate& invitation);
    [[nodiscard]] Result<void> admin_revoke_invitation(std::string_view id);
    // Deletes an account and everything it holds (L-5.7-7): `confirm` is the
    // name as the user typed it again, which must be the account's; the
    // server refuses the caller's own (409).
    [[nodiscard]] Result<void> admin_delete_user(std::string_view name, std::string_view confirm);

    // § 18.1: the stream of events, from `state.last_id` (Last-Event-ID) on,
    // until the server ends it, the handler stops it, or the transport is
    // cut. Each event read moves `state.last_id`; a 410 forgets it (read
    // again what is shown); `state.failures` counts the connections that
    // failed in a row, for EventStreamState::reconnect_delay().
    [[nodiscard]] Result<void> events(
        EventStreamState& state, EventHandler& handler, const EventsQuery& query = {});
    // § 18.3: changes?since=&wait=, the events after `since` (its `events`),
    // answered as soon as one comes or after `wait` seconds (lowered to the
    // server's limits.wait). The transport's timeout must be longer.
    [[nodiscard]] Read<Changes> wait_changes(
        std::string_view since, std::uint32_t wait, const EventsQuery& query = {});
    // Twice the server's heartbeat: a stream silent that long is dead (§ 18.1).
    [[nodiscard]] std::chrono::seconds event_silence_limit() const noexcept;

    // § 19.3: a grant for a file the caller may read, for a peer.
    [[nodiscard]] Read<Grant> grant(const Digest& sha256);
    // § 19.2: the file from a mirror, checked by `target`'s size and
    // SHA-256 (the server's document's); nothing of the server's sent to it.
    [[nodiscard]] Result<void> download_from_mirror(
        std::string_view mirror, const DownloadTarget& target, DownloadState& state, DownloadSink& sink);
    // Each mirror in turn, then the server: what a mirror served that fails
    // its check is dropped, and the next source tried (L-19.1-3).
    [[nodiscard]] Result<void> download_with_mirrors(std::span<const Mirror> mirrors,
        const DownloadTarget& target, DownloadState& state, DownloadSink& sink);
    // § 19.4: whether a peer holds the file (HEAD), and the file from it,
    // with the grant alone; checked by `target`'s size and SHA-256.
    [[nodiscard]] Result<bool> peer_holds(const PeerEndpoint& peer, const Grant& grant);
    [[nodiscard]] Result<void> download_from_peer(const PeerEndpoint& peer, const Grant& grant,
        const DownloadTarget& target, DownloadState& state, DownloadSink& sink);

    // § 20: nothing of sync before the user's consent (L-20.1-1). The app
    // gives what it kept for this profile and server: the consent and the
    // generation the client reported last (empty the first time).
    [[nodiscard]] Result<void> set_sync_consent(const SyncConsent& consent, std::string_view generation = {});
    [[nodiscard]] const SyncConsent& sync_consent() const noexcept { return sync_consent_; }
    // The account's sync generation, as the client last read it: kept by
    // the app with the consent.
    [[nodiscard]] std::string_view sync_generation() const noexcept { return sync_generation_; }
    // GET /v1/sync. A generation other than the one kept means the data was
    // deleted: the client turns sync off (Category::refused) and the app
    // asks its user again (L-20.3-2).
    [[nodiscard]] Read<SyncState> sync_state();
    // GET /v1/sync/{collection}: with `since`, the items changed after that
    // rev, deletions included (410: read the collection whole).
    [[nodiscard]] Read<SyncCollection> sync_items(
        std::string_view collection, std::optional<std::uint64_t> since = {}, const PageQuery& page = {});
    // PATCH /v1/sync/{collection}: items merged by § 20.4's rule, each
    // answered as the server keeps it. With `if_match`, the collection's
    // rev as read: all or nothing, 412 (precondition_failed) when it
    // changed. 409: the data was deleted since (sync turned off).
    [[nodiscard]] Read<SyncCollection> sync_write(std::string_view collection,
        std::span<const SyncItem> items, std::optional<std::uint64_t> if_match = {});
    // DELETE /v1/sync/{collection}, or every collection with an empty name.
    [[nodiscard]] Result<void> sync_delete(std::string_view collection = {});

    // § 6.6: downloads `target` into `sink`, from `state.received` on (a
    // Range request), hashing as it goes; success only when the whole file
    // is there and its SHA-256 is the target's. A transport error leaves
    // `state` at what was received: call again to resume. A digest or size
    // that does not match is Category::integrity: the sink holds nothing to
    // install, and `state` is reset.
    [[nodiscard]] Result<void> download(
        const DownloadTarget& target, DownloadState& state, DownloadSink& sink);

    [[nodiscard]] Allocator allocator() const noexcept { return allocator_; }

  private:
    Client(Transport& transport, const ClientConfig& config);

    struct Response;
    struct Call;
    class Collector;
    class Retry;
    class EventReceiver;

    [[nodiscard]] Result<void> ready(Family family) const;
    [[nodiscard]] Result<String> api_url(std::string_view path) const;
    [[nodiscard]] Result<void> exchange(const Call& call, ResponseHandler& handler);
    [[nodiscard]] Result<void> send_once(const Call& call, ResponseHandler& handler);
    [[nodiscard]] Result<Response> fetch(const Call& call);
    [[nodiscard]] Result<Response> fetch(Method method, std::string_view url, std::string_view body = {});
    template <class T, class Reader>
    [[nodiscard]] Read<T> read(
        Method method, std::string_view url, Reader reader, std::string_view body = {});
    template <class T, class Reader> [[nodiscard]] Read<T> read(const Call& call, Reader reader);
    // A call whose answer is a status alone (204): an error for anything but 2xx.
    [[nodiscard]] Result<Response> expect(const Call& call);
    [[nodiscard]] Error problem(const Response& response) const;
    [[nodiscard]] Error problem(
        std::uint16_t status, std::string_view body, std::string_view retry_after) const;
    void refine_signature_error(Error& error) const;
    void take_server_date(std::string_view date);
    void update_accept_schema();
    [[nodiscard]] UrlParts origin() const noexcept;
    [[nodiscard]] Result<void> use_key(const DeviceKey& key);
    [[nodiscard]] Result<void> sync_ready(std::string_view collection, bool writing) const;
    [[nodiscard]] Result<void> sync_generation_seen(std::string_view generation);
    [[nodiscard]] Result<void> transfer(
        const Call& base, const DownloadTarget& target, DownloadState& state, DownloadSink& sink);

    Transport* transport_;
    Allocator allocator_;
    DecodeOptions decode_;
    std::size_t max_error_body_;
    RequestSigner* app_signer_;
    RandomSource* random_;
    Clock* clock_;
    ServerTrust* trust_;
    DeprecationLog* deprecations_;
    // The device key's signer, when the token is bound (or a pairing polls)
    std::optional<DeviceSigner> signer_;
    std::int64_t clock_offset_ = 0;
    String accept_signature_;
    String origin_text_;
    String user_agent_;
    String platform_;
    String accept_language_;
    String token_;
    String base_;
    String accept_schema_;
    std::optional<Handshake> handshake_;
    SyncConsent sync_consent_;
    String sync_generation_;
    String sync_device_;
};

} // namespace lantern
