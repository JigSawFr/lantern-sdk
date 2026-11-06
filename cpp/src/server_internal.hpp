// What the server's source files share: its configuration, the error a
// handler answers with, the helpers that build a response, the sealed
// cursors of § 6.2, and who calls (tokens, signatures, pairing: § 5). Not
// installed.
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>

#include <lantern/accounts.hpp>
#include <lantern/document.hpp>
#include <lantern/error.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/memory.hpp>
#include <lantern/requests.hpp>
#include <lantern/saves.hpp>
#include <lantern/server.hpp>
#include <lantern/sync_store.hpp>

namespace lantern::detail
{

// What a request changes in the server itself, behind one mutex: the nonces
// taken (§ 5.4) and the requests per address (§ 5.2). Time is the injected
// Clock's, in Unix seconds.
struct AuthRuntime
{
    // "<keyid> <nonce>" -> when it may be forgotten
    std::pmr::unordered_map<String, std::int64_t> nonces;
    std::int64_t next_prune = 0;
    // address -> the seconds its recent events happened at
    std::pmr::unordered_map<String, Vector<std::int64_t>> pairing_hits;
    std::pmr::unordered_map<String, Vector<std::int64_t>> invitation_hits;
    std::mutex mutex;

    explicit AuthRuntime(const Allocator& memory)
        : nonces(memory)
        , pairing_hits(memory)
        , invitation_hits(memory)
    {
    }
};

// What changed in a library, as an event keeps it.
struct EventChange
{
    using allocator_type = Allocator;

    String family;
    String platform;
    String title_id;
    bool by_ratings = false; // a cap reads `ratings`, not the title
    Vector<Rating> ratings;

    explicit EventChange(const allocator_type& allocator)
        : family(allocator)
        , platform(allocator)
        , title_id(allocator)
        , ratings(allocator)
    {
    }
    EventChange(const EventChange& other, const allocator_type& allocator)
        : family(other.family, allocator)
        , platform(other.platform, allocator)
        , title_id(other.title_id, allocator)
        , by_ratings(other.by_ratings)
        , ratings(other.ratings, allocator)
    {
    }
    EventChange(EventChange&& other, const allocator_type& allocator)
        : family(std::move(other.family), allocator)
        , platform(std::move(other.platform), allocator)
        , title_id(std::move(other.title_id), allocator)
        , by_ratings(other.by_ratings)
        , ratings(std::move(other.ratings), allocator)
    {
    }
    EventChange(const EventChange&)            = default;
    EventChange(EventChange&&)                 = default;
    EventChange& operator=(const EventChange&) = default;
    EventChange& operator=(EventChange&&)      = default;
    ~EventChange()                             = default;
};

// An event as kept (§ 18.2): its place in the journal, its type, its document
// as JSON text, and who may see it. `ready` and `shutdown` are not kept.
struct EventRecord
{
    using allocator_type = Allocator;

    std::uint64_t seq = 0;
    String event;
    String data; // the document, one line of JSON
    String scope; // the scope a caller needs
    String user; // the account it is about, when it is about one
    String platform;
    String title_id;
    Vector<EventChange> changes; // the event `library`
    // The library journal's position when it was recorded: its id resumes `changes` from there.
    String journal_epoch;
    std::uint64_t journal_position = 0;

    explicit EventRecord(const allocator_type& allocator)
        : event(allocator)
        , data(allocator)
        , scope(allocator)
        , user(allocator)
        , platform(allocator)
        , title_id(allocator)
        , changes(allocator)
        , journal_epoch(allocator)
    {
    }
};

// The journal of events, in memory, behind one mutex: the last `keep` events,
// where they begin, and the streams open per token or address (§ 18.4).
struct EventHub
{
    mutable std::mutex mutex;
    // Changes with the process: an id of another epoch is too old.
    String epoch;
    std::uint64_t seq   = 0;
    std::uint64_t floor = 0; // the ids at or below it are gone
    std::size_t keep    = 0;
    bool stopping       = false;
    std::pmr::deque<EventRecord> events;
    std::pmr::unordered_map<String, std::uint32_t> streams;
    // Changes with each event and when the server stops: what an adapter waits on.
    std::atomic<std::uint64_t> mark { 0 };

    explicit EventHub(const Allocator& memory)
        : epoch(memory)
        , events(memory)
        , streams(memory)
    {
    }
};

// The server's configuration, fixed at create(): every request reads it.
struct ServerState final : LibraryObserver, std::enable_shared_from_this<ServerState>
{
    Library* library       = nullptr;
    Clock* clock           = nullptr;
    RandomSource* random   = nullptr;
    AccountStore* accounts = nullptr;
    Allocator allocator;
    String uid;
    String name;
    String base;
    String scheme;
    String software_name;
    String software_version;
    String motd;
    Vector<String> cors_origins;
    bool cors_any                   = false;
    bool hsts                       = false;
    bool compression                = false;
    std::uint32_t compression_min   = 0;
    std::uint32_t hsts_max_age      = 0;
    std::uint32_t page_limit        = 0;
    std::uint32_t default_page_size = 0;
    std::uint32_t cursor_lifetime   = 0;
    bool require_auth               = false;
    bool bound_only                 = false;
    std::uint32_t skew              = 0;
    std::uint32_t nonce_limit       = 0;
    String verify; // a path of this server (starting with /), or an absolute URL
    std::optional<Digest> spki;
    std::uint32_t token_lifetime      = 0;
    std::uint32_t pairing_interval    = 0;
    std::uint32_t pairing_expires     = 0;
    std::uint32_t pairing_requests    = 0;
    std::uint32_t pairing_window      = 0;
    std::uint32_t invitation_attempts = 0;
    std::uint32_t invitation_window   = 0;
    // Seals the cursors (HMAC-SHA-256); wiped with the server.
    std::array<std::uint8_t, 32> secret {};
    mutable AuthRuntime runtime;
    // The cheat sets are read and written one request at a time (§ 10: a set
    // that exists answers 409, which two writes at once would miss).
    mutable std::mutex cheats_mutex;
    // The save backups (§ 9): where they are kept, the limits, whether encrypted ones are taken. A store's
    // calls are atomic; this mutex makes a check and the change it leads to one step (a backup kept, then
    // the oldest dropped), and guards `writing`, the uploads a request writes now: a second chunk of the
    // same upload meanwhile is a 409.
    SaveStore* saves = nullptr;
    SaveLimits save_limits;
    bool encrypted_saves = false;
    mutable std::mutex saves_mutex;
    mutable Vector<String> writing;
    // The requests for games (§ 11) and their store; this mutex makes the check (an open request for the
    // title already?) and the change it leads to one step.
    RequestStore* requests = nullptr;
    mutable std::mutex requests_mutex;
    // The sync data (§ 20) and its store; this mutex makes a write's checks (generation, If-Match, the
    // limit) and the changes they lead to one step.
    SyncStore* sync = nullptr;
    mutable std::mutex sync_mutex;
    // The grant key (§ 19.3), when the server offers peers: its seed and public key, the grants' lifetime.
    bool peers = false;
    std::array<std::uint8_t, 32> grant_seed {};
    std::array<std::uint8_t, 32> grant_public {};
    std::uint32_t grant_lifetime = 0;
    // Differential updates (§ 22): the chunk indexes are served.
    bool deltas = false;
    // The administration API (§ 5.7) and the invitations (§ 5.5): the account store keeps what they need.
    bool admin = false;
    // Events (§ 18): offered, the limits, and the journal.
    bool events                   = false;
    bool observing                = false; // the library tells this state of its changes
    std::uint32_t heartbeat       = 0;
    std::uint32_t event_streams   = 0;
    std::uint32_t wait_limit      = 0;
    std::uint32_t stream_lifetime = 0;
    mutable EventHub hub;

    // Told by the library (LibraryObserver).
    void library_changed(std::span<const LibraryChange> changes) override;

    explicit ServerState(const Allocator& memory)
        : allocator(memory)
        , uid(memory)
        , name(memory)
        , base(memory)
        , scheme(memory)
        , software_name(memory)
        , software_version(memory)
        , motd(memory)
        , cors_origins(memory)
        , verify(memory)
        , runtime(memory)
        , writing(memory)
        , hub(memory)
    {
    }
    ServerState(const ServerState&)            = delete;
    ServerState& operator=(const ServerState&) = delete;
    ServerState(ServerState&&)                 = delete;
    ServerState& operator=(ServerState&&)      = delete;
    ~ServerState();
};

// An error a handler answers with (§ 12). `title` is a static text.
struct ProblemError
{
    std::uint16_t status = 500;
    Code code            = Code::internal;
    std::string_view title;
    String detail;
    ResponseHeaders headers;

    explicit ProblemError(const Allocator& allocator)
        : detail(allocator)
        , headers(allocator)
    {
    }
};

using Answer = std::expected<ServerResponse, ProblemError>;

[[nodiscard]] ProblemError make_problem(const ServerState& state, std::uint16_t status, Code code,
    std::string_view detail, std::string_view title = {});
[[nodiscard]] ProblemError bad_request(const ServerState& state, std::string_view detail);
[[nodiscard]] ProblemError not_found(const ServerState& state, std::string_view detail);
[[nodiscard]] ProblemError gone(const ServerState& state, std::string_view detail);
[[nodiscard]] ProblemError method_not_allowed(const ServerState& state, std::string_view allowed);
[[nodiscard]] ProblemError internal_error(const ServerState& state);

// The problem+json response of `error`, with the caching headers of § 14.
[[nodiscard]] ServerResponse problem_response(
    const ServerState& state, const ServerRequest& request, const ProblemError& error);

// A JSON document: a strong ETag on a 200 to GET or HEAD, If-None-Match
// honoured with a 304 (§ 14), the caching headers, Vary on what the answer
// depends on.
// `validators` false: no ETag and no 304, for a document given once (a token).
[[nodiscard]] ServerResponse json_response(const ServerState& state, const ServerRequest& request,
    String&& body, std::uint16_t status = 200, bool validators = true);

// Vary and Cache-Control of an answer to `request` (§ 14).
void caching_headers(ResponseHeaders& headers, const ServerRequest& request);

// Browsers (§ 2.5) and HSTS (§ 2).
[[nodiscard]] bool is_cors_route(const ServerState& state, std::string_view path) noexcept;
[[nodiscard]] Answer preflight(const ServerState& state, const ServerRequest& request);
void add_cors_headers(const ServerState& state, const ServerRequest& request, ServerResponse& response);
void add_hsts_header(const ServerState& state, const ServerRequest& request, ServerResponse& response);
[[nodiscard]] bool is_cors_origin(std::string_view origin) noexcept;

// A request's JSON document (§ 3.2, § 12), checked before it is bound: 413
// above the limit, 400 when it is not JSON, not I-JSON, beyond § 13 or has no
// integer `schema`, 422 `unsupported_schema` for a schema this server cannot
// read. The text is the body's.
struct RequestDocument
{
    std::string_view text;
    DecodeOptions options;
};

// `limit` is the body's largest size: above the usual one only for a cheat
// set (§ 10), whose text is one string as long as the body allows.
[[nodiscard]] std::expected<RequestDocument, ProblemError> request_document(
    const ServerState& state, const ServerRequest& request, std::size_t limit = 0);
[[nodiscard]] String number_text(std::uint64_t value, const Allocator& allocator);

// Text helpers.
[[nodiscard]] bool equal_fold(std::string_view a, std::string_view b) noexcept;
[[nodiscard]] std::string_view trim(std::string_view text) noexcept;
// ASCII case folded; the bytes of other characters are kept (a UTF-8 text
// is searched as it was written).
[[nodiscard]] String fold(std::string_view text, const Allocator& allocator);
// "2026-10-10T12:00:00Z" (a fraction is allowed) as Unix seconds.
[[nodiscard]] std::optional<std::int64_t> parse_time(std::string_view text) noexcept;

// The key an apps' listing is sorted by: unique, because it ends with the id.
struct SortKey
{
    std::int64_t major = 0;
    String minor;
    String id;

    explicit SortKey(const Allocator& allocator)
        : minor(allocator)
        , id(allocator)
    {
    }
};

[[nodiscard]] int compare(const SortKey& a, const SortKey& b) noexcept;

// What a cursor holds once opened: where the page before it ended.
struct CursorPosition
{
    SortKey key;
    // The key's `minor` was too long for a cursor: the position is found by
    // `key.id` among the items.
    bool by_id = false;

    explicit CursorPosition(const Allocator& allocator)
        : key(allocator)
    {
    }
};

// The identity of a listing (its route and filters): a cursor of another
// listing is refused.
[[nodiscard]] String scope_of(std::span<const std::string_view> parts, const Allocator& allocator);
[[nodiscard]] String seal_cursor(const ServerState& state, std::string_view scope, const SortKey& key);
// 400 for a cursor the server never gave or of another listing, 410 for one
// that expired.
[[nodiscard]] std::expected<CursorPosition, ProblemError> open_cursor(
    const ServerState& state, std::string_view cursor, std::string_view scope);

// A `since` token (§ 6.4, § 7.3): a position of the library's journal, sealed
// like a cursor. `kind` is 's' for <base>/v1/changes, 't' for the titles'.
[[nodiscard]] String seal_since(
    const ServerState& state, char kind, std::string_view epoch, std::uint64_t position);
// The position a token names: 400 for a token the server never gave (or of
// the other kind), 410 for one of another epoch or older than the journal.
[[nodiscard]] std::expected<std::uint64_t, ProblemError> open_since(
    const ServerState& state, char kind, std::string_view token, const JournalPosition& journal);

// A token of `changes` with its place among the events (§ 18.1: the stream's
// ids and `changes?since=` share their tokens): the journal's position, and
// the events' (the hub's epoch, the last event it covers).
[[nodiscard]] String seal_event_since(const ServerState& state, std::string_view journal_epoch,
    std::uint64_t journal_position, std::uint64_t event_seq);
// The event a token of `changes` comes after, and the epoch of the events it
// counts from: 400 for a token the server never gave; the caller checks the
// epoch and the floor (410).
struct EventPlace
{
    String epoch;
    std::uint64_t seq = 0;

    explicit EventPlace(const Allocator& allocator)
        : epoch(allocator)
    {
    }
};
[[nodiscard]] std::expected<EventPlace, ProblemError> open_event_since(
    const ServerState& state, std::string_view token);

// The platform a caller names (§ 4.3): ?platform=, else the Lantern-Platform
// header; nothing for every platform. 400 for what is not a name.
[[nodiscard]] std::expected<std::optional<std::string_view>, ProblemError> platform_param(
    const ServerState& state, const ServerRequest& request);
// An app as a document lists it (§ 6.1).
void write_app_json(json::Writer& w, const App& app);
// An image (§ 7.1) and the ratings (§ 7.1) as documents write them.
void write_image_object(json::Writer& w, const Image& image);
void write_ratings(json::Writer& w, const Vector<Rating>& ratings);

// A page of a listing sorted by `keys` (one per item; `id` of each is the
// item's own, unique): where it starts and ends in the sorted order and the
// cursor of the next page, from the request's page_size and cursor (§ 6.2).
// `scope` is the listing's identity (scope_of()).
struct PageWindow
{
    Vector<std::size_t> order; // the items' indexes, sorted by their keys
    std::size_t from  = 0; // the first item of the page, in `order`
    std::size_t count = 0;
    String next; // the cursor of the next page; empty after the last

    explicit PageWindow(const Allocator& allocator)
        : order(allocator)
        , next(allocator)
    {
    }
};

[[nodiscard]] std::expected<PageWindow, ProblemError> page_window(const ServerState& state,
    const ServerRequest& request, std::span<const SortKey> keys, std::string_view scope);

// A file of the library served whole or by range (§ 6.6), as <base>/v1/files.
[[nodiscard]] Answer serve_library_file(
    const ServerState& state, const ServerRequest& request, const LibraryFile& file);

// An answer with no body (§ 10, § 11: DELETE answers 204).
[[nodiscard]] ServerResponse no_content(const ServerState& state, const ServerRequest& request);

struct Caller;

// Rating caps (§ 5.6): what a capped caller does not see. The age a rating is
// read as, the age of a title for a cap, and whether it is above the cap.
[[nodiscard]] std::optional<std::uint64_t> rating_age(
    std::string_view system, std::string_view rating) noexcept;
// Whether a caller of `cap` must not see what has `ratings`: above the cap's age, or unrated with `unrated`
// `hide`. A cap the table cannot read hides everything rated, so that it never loosens.
[[nodiscard]] bool above_cap(const RatingCap& cap, const Vector<Rating>& ratings) noexcept;
// Why `cap` is not a rating cap of § 5.6; empty when it is.
[[nodiscard]] std::string_view cap_problem(const RatingCap& cap) noexcept;
// A rating cap as a document writes it.
void write_rating_cap(json::Writer& w, const RatingCap& cap);

// What one caller does not see: the titles above its cap, looked up in the library's titles. Without a cap
// it hides nothing and asks the library nothing.
class CapFilter
{
  public:
    explicit CapFilter(const Allocator& allocator)
        : titles_(allocator)
        , none_(allocator)
    {
    }

    // A caller's filter: the library's titles are read once when the caller has a cap.
    [[nodiscard]] static std::expected<CapFilter, ProblemError> of(
        const ServerState& state, const Caller& caller);

    [[nodiscard]] bool active() const noexcept { return cap_.has_value(); }
    // What has these ratings (a homebrew's, a title's).
    [[nodiscard]] bool hides(const Vector<Rating>& ratings) const noexcept;
    // A title, and so its apps and cheat sets; a title the library does not describe is unrated.
    [[nodiscard]] bool hides_title(std::string_view platform, std::string_view title_id) const noexcept;

  private:
    std::optional<RatingCap> cap_;
    Vector<Title> titles_;
    Vector<Rating> none_;
};

// Whether the file <base>/v1/files/<name> belongs to an app or a homebrew the filter hides.
[[nodiscard]] std::expected<bool, ProblemError> file_hidden(
    const ServerState& state, const CapFilter& filter, std::string_view name);

// Changes (§ 6.4), titles (§ 7) and sections (§ 6.5): each 404 when the
// library does not offer the family.
[[nodiscard]] Answer changes_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer titles_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer title_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view title_id);
[[nodiscard]] Answer title_changes_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer sections_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);

// Homebrew (§ 8) and cheats (§ 10): each 404 when the library does not offer
// the family.
[[nodiscard]] Answer homebrew_list_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer homebrew_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view id);
[[nodiscard]] Answer homebrew_updates_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer cheats_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer cheat_text_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view id);
[[nodiscard]] Answer cheat_post_route(const ServerState& state, const ServerRequest& request);
[[nodiscard]] Answer cheat_write_route(
    const ServerState& state, const ServerRequest& request, std::string_view id);

// What § 10 and Annex A say a set to write must be, as a text for a 400; empty
// when the set is fine. The set's `source` is already filled in.
[[nodiscard]] std::string_view cheat_problem(const CheatWrite& set);
// The largest cheat set (§ 13), and what a body holding one may weigh.
inline constexpr std::size_t cheat_limit = std::size_t { 1 } << 20U;
inline constexpr std::size_t cheat_body  = std::size_t { 3 } << 20U;

// Save backups (§ 9) and encrypted ones (§ 9.4), for a caller with the scope
// `saves`: each 404 when the server keeps none.
[[nodiscard]] Answer saves_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer save_post_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view title_id);
[[nodiscard]] Answer upload_open_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view title_id);
[[nodiscard]] Answer upload_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view upload_id);
[[nodiscard]] Answer save_route(const ServerState& state, const ServerRequest& request, const Caller& caller,
    std::string_view title_id, std::string_view save_id);

// Who calls (§ 4.2, § 5.1): no token (anonymous), a token of an account, or
// of an account that is frozen. A token is checked against the store; its
// scopes are the device's, cut back to the account's.
struct Caller
{
    enum class State : std::uint8_t
    {
        anonymous,
        active,
        frozen,
    };

    State state = State::anonymous;
    String name; // the account's, when there is one
    String device; // what the user calls the paired device, when there is one
    String device_id; // the paired device's id (`d_…`, § 5.7), when there is one
    Vector<String> scopes; // in the order of known_scopes
    std::optional<PublicKey> key; // the token is bound to it
    std::optional<RatingCap> rating_cap; // what its device may see (§ 5.6)

    explicit Caller(const Allocator& allocator)
        : name(allocator)
        , device(allocator)
        , device_id(allocator)
        , scopes(allocator)
    {
    }

    [[nodiscard]] bool has(std::string_view scope) const noexcept;
};

// The caller of `request`: 401 `unauthorized` for a token the store does not
// know (revoked and expired included), for another scheme, or for an empty
// token. A server with no AccountStore takes no token.
[[nodiscard]] std::expected<Caller, ProblemError> identify(
    const ServerState& state, const ServerRequest& request);
// The signature of a request that carries a token bound to a key (§ 5.4);
// nothing for a caller whose token has no key (unless the server takes only
// bound tokens). 401 with the code § 5.4 gives, 422 `digest_mismatch`.
[[nodiscard]] std::optional<ProblemError> check_request_signature(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
// Whether the caller may read the library (§ 5.1): nothing, or the problem.
[[nodiscard]] std::optional<ProblemError> check_library(const ServerState& state, const Caller& caller);
// The same for another scope of § 4.2: anonymous callers hold `library` and
// `cheats` on a server that asks for no token, nothing else.
[[nodiscard]] std::optional<ProblemError> check_scope(
    const ServerState& state, const Caller& caller, std::string_view scope);

// Events (§ 18): an event recorded for the callers who may see it. `data` is its
// document, a JSON object; `scope` the scope a caller needs; `user`, `platform`
// and `title_id` what it is about, each empty for none. Nothing without `events`.
void record_event(const ServerState& state, std::string_view event, std::string_view data,
    std::string_view scope, std::string_view user, std::string_view platform, std::string_view title_id,
    std::span<const LibraryChange> changes = {});
// The events that follow what a route did: a backup kept, a request made, changed or withdrawn, a
// pairing waiting.
void record_library_event(const ServerState& state, std::span<const LibraryChange> changes);
void record_save_event(const ServerState& state, std::string_view user, const Save& save);
void record_request_event(const ServerState& state, const StoredRequest& request, bool deleted);
void record_pairing_event(const ServerState& state, const PendingPairing& pairing);
// The event `sync` (§ 18.2): a collection of the account `user` changed to revision `rev` (0: erased).
void record_sync_event(
    const ServerState& state, std::string_view user, std::string_view collection, std::uint64_t rev);
// Whether the caller may read any kind of event (§ 18.2): nothing, or the problem.
[[nodiscard]] std::optional<ProblemError> check_events(const ServerState& state, const Caller& caller);
// The stream (§ 18.1) and the long poll of `changes` (§ 18.3).
[[nodiscard]] Answer events_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer long_poll_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
// The token of `changes` for now, with the events' place when the server offers them.
[[nodiscard]] String changes_token(const ServerState& state, const JournalPosition& journal);
// The members `added` and `removed` of the document of `changes` (§ 6.4).
void write_app_changes(json::Writer& w, const AppChanges& changes);

// Requests for games (§ 11), for a caller with the scope `requests`: each 404 when the server keeps none.
[[nodiscard]] Answer requests_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller);
[[nodiscard]] Answer request_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view id);

// Sync (§ 20), for a caller with the scope `sync.read` (reading) or `sync.write`: each 404 when the server
// keeps no sync data. `collection` is the name after /v1/sync/, empty for /v1/sync itself.
[[nodiscard]] Answer sync_route(const ServerState& state, const ServerRequest& request, const Caller& caller,
    std::string_view collection, bool whole);
// Erases an account's sync data (§ 5.7, L-20.5-3); nothing without a store.
[[nodiscard]] Result<void> forget_sync(const ServerState& state, std::string_view user);

// Grants for peers (§ 19.3), for a caller with the scope `library`: 404 when the server offers none.
[[nodiscard]] Answer grant_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view hex);

// The chunk index of a file (§ 22.1), for a caller with the scope `library`: 404 when the caller may not read
// the file or the library gives it no `chunks`. `hex` is the file's SHA-256.
[[nodiscard]] Answer chunks_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view hex);

// The admin's side of the requests (§ 11): every account's, and deciding an open one.
[[nodiscard]] Answer admin_requests_route(const ServerState& state, const ServerRequest& request);
[[nodiscard]] Answer admin_request_route(
    const ServerState& state, const ServerRequest& request, std::string_view id);

// The administration API (§ 5.7), for a caller with the scope `admin`: `resource` is users, devices,
// pairings, invitations or requests, `id` the name or the id after it, if any.
[[nodiscard]] Answer admin_route(const ServerState& state, const ServerRequest& request, const Caller& caller,
    std::string_view resource, std::string_view id);
// Whether the administration API has that route, and the methods it takes.
[[nodiscard]] std::string_view admin_methods(std::string_view resource, bool has_id) noexcept;

// Unix seconds as "2026-10-10T12:00:00Z".
[[nodiscard]] String utc_text(std::int64_t seconds, const Allocator& allocator);
// <verify> of a request: the approval page's address, absolute.
[[nodiscard]] std::expected<String, ProblemError> pairing_verify_url(
    const ServerState& state, const ServerRequest& request);
// Approves `entry` for the account `account` (§ 5.2, § 5.5, § 5.7): the scopes it asked for that `only` holds
// (all of them when `restrict` is false) and the account holds, the cap and the invitation it came by. The
// token waits for the device's next poll. Nothing when the pairing was decided meanwhile.
[[nodiscard]] Result<std::optional<Vector<String>>> approve_entry(const ServerState& state,
    const PendingPairing& entry, const StoredAccount& account, bool restrict,
    std::span<const std::string_view> only, const std::optional<RatingCap>& cap, std::string_view invitation,
    const Allocator& allocator);

// Pairing (§ 5.2): POST <base>/v1/pairing, GET <base>/v1/pairing/<poll>, and
// the approval page at ServerState::verify.
[[nodiscard]] Answer pairing_start(const ServerState& state, const ServerRequest& request);
[[nodiscard]] Answer pairing_poll(
    const ServerState& state, const ServerRequest& request, std::string_view poll);
[[nodiscard]] bool is_approval_path(const ServerState& state, std::string_view path) noexcept;
[[nodiscard]] Answer approval_page(const ServerState& state, const ServerRequest& request);

} // namespace lantern::detail
