// What the server's source files share: its configuration, the error a
// handler answers with, the helpers that build a response, the sealed
// cursors of § 6.2, and who calls (tokens, signatures, pairing: § 5). Not
// installed.
#pragma once

#include <array>
#include <cstdint>
#include <expected>
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
#include <lantern/server.hpp>

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

// The server's configuration, fixed at create(): every request reads it.
struct ServerState
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

[[nodiscard]] std::expected<RequestDocument, ProblemError> request_document(
    const ServerState& state, const ServerRequest& request);
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

// The platform a caller names (§ 4.3): ?platform=, else the Lantern-Platform
// header; nothing for every platform. 400 for what is not a name.
[[nodiscard]] std::expected<std::optional<std::string_view>, ProblemError> platform_param(
    const ServerState& state, const ServerRequest& request);
// An app as a document lists it (§ 6.1).
void write_app_json(json::Writer& w, const App& app);

// Changes (§ 6.4), titles (§ 7) and sections (§ 6.5): each 404 when the
// library does not offer the family.
[[nodiscard]] Answer changes_route(const ServerState& state, const ServerRequest& request);
[[nodiscard]] Answer titles_route(const ServerState& state, const ServerRequest& request);
[[nodiscard]] Answer title_route(
    const ServerState& state, const ServerRequest& request, std::string_view title_id);
[[nodiscard]] Answer title_changes_route(const ServerState& state, const ServerRequest& request);
[[nodiscard]] Answer sections_route(const ServerState& state, const ServerRequest& request);

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
    Vector<String> scopes; // in the order of known_scopes
    std::optional<PublicKey> key; // the token is bound to it

    explicit Caller(const Allocator& allocator)
        : name(allocator)
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

// Pairing (§ 5.2): POST <base>/v1/pairing, GET <base>/v1/pairing/<poll>, and
// the approval page at ServerState::verify.
[[nodiscard]] Answer pairing_start(const ServerState& state, const ServerRequest& request);
[[nodiscard]] Answer pairing_poll(
    const ServerState& state, const ServerRequest& request, std::string_view poll);
[[nodiscard]] bool is_approval_path(const ServerState& state, std::string_view path) noexcept;
[[nodiscard]] Answer approval_page(const ServerState& state, const ServerRequest& request);

} // namespace lantern::detail
