// What the server's source files share: its configuration, the error a
// handler answers with, the helpers that build a response, and the sealed
// cursors of § 6.2. Not installed.
#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/memory.hpp>
#include <lantern/server.hpp>

namespace lantern::detail
{

// The server's configuration, fixed at create(): every request reads it.
struct ServerState
{
    Library* library = nullptr;
    Clock* clock     = nullptr;
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
    // Seals the cursors (HMAC-SHA-256); wiped with the server.
    std::array<std::uint8_t, 32> secret {};

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
[[nodiscard]] ServerResponse json_response(
    const ServerState& state, const ServerRequest& request, String&& body, std::uint16_t status = 200);

// Vary and Cache-Control of an answer to `request` (§ 14).
void caching_headers(ResponseHeaders& headers, const ServerRequest& request);

// Browsers (§ 2.5) and HSTS (§ 2).
[[nodiscard]] bool is_cors_route(const ServerState& state, std::string_view path) noexcept;
[[nodiscard]] Answer preflight(const ServerState& state, const ServerRequest& request);
void add_cors_headers(const ServerState& state, const ServerRequest& request, ServerResponse& response);
void add_hsts_header(const ServerState& state, const ServerRequest& request, ServerResponse& response);
[[nodiscard]] bool is_cors_origin(std::string_view origin) noexcept;

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

} // namespace lantern::detail
