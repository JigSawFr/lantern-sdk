// The server core's HTTP layer, independent of any framework: requests and
// responses, problem+json errors (SPEC.md § 12), JSON documents with their
// ETag and caching headers (§ 14), browsers (§ 2.5) and HSTS (§ 2).
#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>

#include <lantern/hkdf.hpp>
#include <lantern/json.hpp>
#include <lantern/server.hpp>

#include "server_internal.hpp"

namespace lantern
{

namespace
{

constexpr std::string_view problem_type = "https://lantern.boreale.dev/errors/";
// § 2.2: the language of the server's own texts.
constexpr std::string_view language = "en";

constexpr std::string_view cors_methods = "GET, HEAD, POST, PUT, PATCH, DELETE";
constexpr std::array cors_headers {
    std::string_view { "Authorization" },
    std::string_view { "Content-Type" },
    std::string_view { "Content-Digest" },
    std::string_view { "Signature" },
    std::string_view { "Signature-Input" },
    std::string_view { "Accept-Schema" },
    std::string_view { "Lantern-Platform" },
    std::string_view { "Lantern-Save-Kind" },
    std::string_view { "Lantern-Save-Slot" },
    std::string_view { "Lantern-Game-Version" },
    std::string_view { "Lantern-Profile" },
    std::string_view { "Lantern-Note" },
    std::string_view { "Lantern-Save-Encryption" },
    std::string_view { "Upload-Offset" },
    std::string_view { "If-Match" },
    std::string_view { "If-None-Match" },
    std::string_view { "If-Range" },
    std::string_view { "Range" },
    std::string_view { "Last-Event-ID" },
};
constexpr std::string_view cors_exposed
    = "Date, ETag, Content-Range, Accept-Ranges, Repr-Digest, Retry-After, WWW-Authenticate, "
      "Accept-Signature, Upload-Offset, Upload-Length, Lantern-Chunk-Size, Allow, Deprecation, Sunset, Link";
constexpr std::string_view cors_max_age = "600";

struct StatusName
{
    std::uint16_t status;
    std::string_view text;
    std::string_view title; // § 12's title of an error
};

constexpr std::array status_names {
    StatusName { 200, "OK", "" },
    StatusName { 204, "No Content", "" },
    StatusName { 206, "Partial Content", "" },
    StatusName { 304, "Not Modified", "" },
    StatusName { 400, "Bad Request", "Bad request" },
    StatusName { 401, "Unauthorized", "Unauthorized" },
    StatusName { 403, "Forbidden", "Forbidden" },
    StatusName { 404, "Not Found", "Not found" },
    StatusName { 405, "Method Not Allowed", "Method not allowed" },
    StatusName { 409, "Conflict", "Conflict" },
    StatusName { 410, "Gone", "Gone" },
    StatusName { 411, "Length Required", "Length required" },
    StatusName { 413, "Content Too Large", "Too large" },
    StatusName { 416, "Range Not Satisfiable", "Range not satisfiable" },
    StatusName { 422, "Unprocessable Content", "Unprocessable" },
    StatusName { 429, "Too Many Requests", "Slow down" },
    StatusName { 500, "Internal Server Error", "Internal error" },
    StatusName { 503, "Service Unavailable", "Unavailable" },
};

const StatusName* find_status(std::uint16_t status) noexcept
{
    for (const StatusName& name : status_names)
    {
        if (name.status == status)
            return &name;
    }
    return nullptr;
}

int hex_value(char c) noexcept
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// Percent-decodes `text` (and reads "+" as a space for a query); false for
// a bad escape or a control character.
bool percent_decode(std::string_view text, bool plus_is_space, String& out)
{
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        char c = text[i];
        if (c == '%')
        {
            const int high = i + 2 < text.size() ? hex_value(text[i + 1]) : -1;
            const int low  = i + 2 < text.size() ? hex_value(text[i + 2]) : -1;
            if (high < 0 || low < 0)
                return false;
            c = static_cast<char>((static_cast<unsigned>(high) << 4U) | static_cast<unsigned>(low));
            i += 2;
        }
        else if (c == '+' && plus_is_space)
            c = ' ';
        const auto byte = static_cast<unsigned char>(c);
        if (byte < 0x20 || byte == 0x7f)
            return false;
        out.push_back(c);
    }
    return true;
}

// Lower-case hex of the first 16 bytes of the digest: 32 characters.
std::array<char, 32> short_hex(const Digest& digest) noexcept
{
    const auto hex = to_hex(digest);
    std::array<char, 32> out {};
    std::copy_n(hex.begin(), out.size(), out.begin());
    return out;
}

// If-None-Match as HTTP says (§ 14): `*`, or a tag compared weakly (W/ ignored).
bool matches(std::string_view header, std::string_view etag) noexcept
{
    while (!header.empty())
    {
        const std::size_t comma = header.find(',');
        std::string_view tag    = detail::trim(header.substr(0, comma));
        header = comma == std::string_view::npos ? std::string_view {} : header.substr(comma + 1);
        if (tag.starts_with("W/"))
            tag.remove_prefix(2);
        if (tag == "*" || tag == etag)
            return true;
    }
    return false;
}

} // namespace

std::optional<std::string_view> ServerRequest::header(std::string_view name) const noexcept
{
    for (const Header& header : headers)
    {
        if (detail::equal_fold(header.name, name))
            return header.value;
    }
    return std::nullopt;
}

std::optional<std::string_view> ServerRequest::param(std::string_view name) const noexcept
{
    for (const QueryParam& param : query)
    {
        if (param.name == name && !param.value.empty())
            return param.value;
    }
    return std::nullopt;
}

Result<ParsedTarget> parse_target(std::string_view target, const Allocator& allocator)
{
    if (!target.starts_with('/'))
        return fail(Category::invalid_response, "a request target that is not a path");
    ParsedTarget out(allocator);
    const std::size_t mark = target.find('?');
    if (!percent_decode(target.substr(0, mark), false, out.path))
        return fail(Category::invalid_response, "a path with a bad escape or a control character");
    std::string_view query = mark == std::string_view::npos ? std::string_view {} : target.substr(mark + 1);
    while (!query.empty())
    {
        const std::size_t amp        = query.find('&');
        const std::string_view piece = query.substr(0, amp);
        query = amp == std::string_view::npos ? std::string_view {} : query.substr(amp + 1);
        if (piece.empty())
            continue;
        const std::size_t equal = piece.find('=');
        String name(allocator);
        String value(allocator);
        if (!percent_decode(piece.substr(0, equal), true, name)
            || (equal != std::string_view::npos && !percent_decode(piece.substr(equal + 1), true, value)))
            return fail(Category::invalid_response, "a query with a bad escape or a control character");
        out.query.emplace_back(std::move(name), std::move(value));
    }
    return out;
}

void ResponseHeaders::set(std::string_view name, std::string_view value)
{
    erase(name);
    add(name, value);
}

void ResponseHeaders::add(std::string_view name, std::string_view value)
{
    entries_.emplace_back(name, value);
}

void ResponseHeaders::erase(std::string_view name)
{
    std::erase_if(entries_, [&](const auto& entry) { return detail::equal_fold(entry.first, name); });
}

std::optional<std::string_view> ResponseHeaders::get(std::string_view name) const noexcept
{
    for (const auto& entry : entries_)
    {
        if (detail::equal_fold(entry.first, name))
            return std::string_view(entry.second);
    }
    return std::nullopt;
}

Result<std::size_t> MemoryFileReader::read(std::uint64_t offset, std::span<std::byte> buffer)
{
    if (offset >= bytes_.size())
        return std::size_t { 0 };
    const std::size_t take
        = std::min<std::size_t>(buffer.size(), bytes_.size() - static_cast<std::size_t>(offset));
    std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset), take, buffer.begin());
    return take;
}

std::string_view status_text(std::uint16_t status) noexcept
{
    const StatusName* found = find_status(status);
    return found != nullptr ? found->text : std::string_view { "Unknown" };
}

namespace detail
{

ServerState::~ServerState()
{
    secure_wipe(secret);
}

bool equal_fold(std::string_view a, std::string_view b) noexcept
{
    const auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(), [&](char x, char y) { return lower(x) == lower(y); });
}

std::string_view trim(std::string_view text) noexcept
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.remove_suffix(1);
    return text;
}

String fold(std::string_view text, const Allocator& allocator)
{
    String out(text, allocator);
    for (char& c : out)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

std::optional<std::int64_t> parse_time(std::string_view text) noexcept
{
    // YYYY-MM-DDTHH:MM:SS, a fraction of up to 9 digits, then Z
    if (text.size() < 20 || text.back() != 'Z')
        return std::nullopt;
    const auto digits = [&](std::size_t at, std::size_t count) -> std::optional<std::int64_t>
    {
        std::int64_t value = 0;
        for (std::size_t i = at; i < at + count; ++i)
        {
            if (text[i] < '0' || text[i] > '9')
                return std::nullopt;
            value = value * 10 + (text[i] - '0');
        }
        return value;
    };
    if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':')
        return std::nullopt;
    if (text.size() > 20 && (text[19] != '.' || text.size() > 30))
        return std::nullopt;
    const auto year   = digits(0, 4);
    const auto month  = digits(5, 2);
    const auto day    = digits(8, 2);
    const auto hour   = digits(11, 2);
    const auto minute = digits(14, 2);
    const auto second = digits(17, 2);
    if (!year || !month || !day || !hour || !minute || !second || *month < 1 || *month > 12 || *day < 1
        || *day > 31 || *hour > 23 || *minute > 59 || *second > 60)
        return std::nullopt;
    // Days since 1970-01-01 (the proleptic Gregorian calendar)
    const std::int64_t y    = *year - (*month <= 2 ? 1 : 0);
    const std::int64_t era  = y / 400;
    const std::int64_t yoe  = y - era * 400;
    const std::int64_t doy  = (153 * (*month + (*month > 2 ? -3 : 9)) + 2) / 5 + *day - 1;
    const std::int64_t doe  = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = era * 146097 + doe - 719468;
    return days * 86400 + *hour * 3600 + *minute * 60 + *second;
}

ProblemError make_problem(const ServerState& state, std::uint16_t status, Code code, std::string_view detail,
    std::string_view title)
{
    ProblemError error(state.allocator);
    error.status = status;
    error.code   = code;
    if (title.empty())
    {
        const StatusName* found = find_status(status);
        title                   = found != nullptr && !found->title.empty() ? found->title : "Error";
    }
    error.title = title;
    error.detail.assign(detail);
    return error;
}

ProblemError bad_request(const ServerState& state, std::string_view detail)
{
    return make_problem(state, 400, Code::bad_request, detail);
}

ProblemError not_found(const ServerState& state, std::string_view detail)
{
    return make_problem(state, 404, Code::not_found, detail);
}

ProblemError gone(const ServerState& state, std::string_view detail)
{
    return make_problem(state, 410, Code::gone, detail);
}

ProblemError method_not_allowed(const ServerState& state, std::string_view allowed)
{
    ProblemError error = make_problem(
        state, 405, Code::bad_request, "This route does not take that method.", "Method not allowed");
    error.headers.set("Allow", allowed);
    return error;
}

ProblemError internal_error(const ServerState& state)
{
    return make_problem(state, 500, Code::internal, "The server failed; try again later.");
}

namespace
{

String problem_document(const ServerState& state, const ProblemError& error)
{
    String out(state.allocator);
    json::Writer w(out);
    String type(problem_type, state.allocator);
    for (const char c : code_name(error.code))
        type.push_back(c == '_' ? '-' : c);
    w.begin_object();
    w.key("schema");
    w.number(std::uint64_t { 1 });
    w.key("type");
    w.string(type);
    w.key("title");
    w.string(error.title);
    w.key("status");
    w.number(static_cast<std::uint64_t>(error.status));
    w.key("code");
    w.string(code_name(error.code));
    if (!error.detail.empty())
    {
        w.key("detail");
        w.string(error.detail);
    }
    w.key("language");
    w.string(language);
    w.end_object();
    return out;
}

void set_length(ResponseHeaders& headers, std::size_t length)
{
    std::array<char, 24> text {};
    const auto result = std::to_chars(text.data(), text.data() + text.size(), length);
    headers.set(
        "Content-Length", std::string_view(text.data(), static_cast<std::size_t>(result.ptr - text.data())));
}

} // namespace

void caching_headers(ResponseHeaders& headers, const ServerRequest& request)
{
    headers.set("Vary", "Authorization, Lantern-Platform, Accept-Language");
    headers.set("Cache-Control", request.header("Authorization") ? "private" : "no-cache");
}

ServerResponse problem_response(
    const ServerState& state, const ServerRequest& request, const ProblemError& error)
{
    String body = problem_document(state, error);
    ServerResponse response(state.allocator);
    response.status = error.status;
    caching_headers(response.headers, request);
    for (const auto& [name, value] : error.headers.entries())
        response.headers.set(name, value);
    response.headers.set("Content-Type", "application/problem+json");
    response.headers.set("Content-Language", language);
    set_length(response.headers, body.size());
    if (request.method != "HEAD")
        response.body = std::move(body);
    return response;
}

ServerResponse json_response(const ServerState& state, const ServerRequest& request, String&& body,
    std::uint16_t status, bool validators)
{
    ServerResponse response(state.allocator);
    response.status = status;
    caching_headers(response.headers, request);
    response.headers.set("Vary", "Authorization, Lantern-Platform, Accept-Language, Accept-Encoding");
    response.headers.set("Content-Type", "application/json");
    if (status == 200 && validators && (request.method == "GET" || request.method == "HEAD"))
    {
        const auto tag = short_hex(Sha256::of(std::string_view(body)));
        String etag(state.allocator);
        etag.push_back('"');
        etag.append(tag.data(), tag.size());
        etag.push_back('"');
        response.headers.set("ETag", etag);
        if (const auto given = request.header("If-None-Match"); given && matches(*given, etag))
        {
            response.status = 304;
            response.headers.erase("Content-Type");
            response.headers.set("Content-Length", "0");
            return response;
        }
    }
    set_length(response.headers, body.size());
    if (request.method != "HEAD")
        response.body = std::move(body);
    return response;
}

bool is_cors_origin(std::string_view origin) noexcept
{
    if (origin.starts_with("https://"))
        origin.remove_prefix(8);
    else if (origin.starts_with("http://"))
        origin.remove_prefix(7);
    else
        return false;
    std::size_t host = 0;
    if (origin.starts_with('['))
    {
        const std::size_t close = origin.find(']');
        if (close == std::string_view::npos || close == 1)
            return false;
        const auto inside = origin.substr(1, close - 1);
        if (!std::ranges::all_of(inside, [](char c) { return hex_value(c) >= 0 || c == ':' || c == '.'; }))
            return false;
        host = close + 1;
    }
    else
    {
        const auto name_char = [](char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.'
                || c == '-';
        };
        while (host < origin.size() && name_char(origin[host]))
            ++host;
        if (host == 0)
            return false;
    }
    const std::string_view rest = origin.substr(host);
    if (rest.empty())
        return true;
    if (!rest.starts_with(':') || rest.size() < 2 || rest.size() > 6)
        return false;
    return std::ranges::all_of(rest.substr(1), [](char c) { return c >= '0' && c <= '9'; });
}

bool is_cors_route(const ServerState& state, std::string_view path) noexcept
{
    return path == "/.well-known/lantern"
        || (path.starts_with(state.base) && path.size() > state.base.size()
            && path[state.base.size()] == '/');
}

namespace
{

// The Access-Control-Allow-Origin of this request: "*", or its Origin when
// the server allows it; nothing when it does not (or the request has no
// Origin, or is not to a route of the text).
std::optional<std::string_view> cors_allow(const ServerState& state, const ServerRequest& request)
{
    const auto origin = trim(request.header("Origin").value_or(std::string_view {}));
    if (state.cors_origins.empty() || origin.empty() || !is_cors_route(state, request.path))
        return std::nullopt;
    if (state.cors_any)
        return std::string_view { "*" };
    const bool allowed
        = std::ranges::any_of(state.cors_origins, [&](const String& item) { return item == origin; });
    return allowed ? std::optional<std::string_view>(origin) : std::nullopt;
}

} // namespace

Answer preflight(const ServerState& state, const ServerRequest& request)
{
    if (!cors_allow(state, request) || !request.header("Access-Control-Request-Method"))
        return std::unexpected(method_not_allowed(state, cors_methods));
    // The headers a page asks to send, named as we know them; all of them
    // when it names none of ours
    String allowed(state.allocator);
    std::string_view asked = request.header("Access-Control-Request-Headers").value_or(std::string_view {});
    while (!asked.empty())
    {
        const std::size_t comma     = asked.find(',');
        const std::string_view item = trim(asked.substr(0, comma));
        asked = comma == std::string_view::npos ? std::string_view {} : asked.substr(comma + 1);
        for (const std::string_view known : cors_headers)
        {
            if (!equal_fold(known, item))
                continue;
            if (!allowed.contains(known))
            {
                if (!allowed.empty())
                    allowed.append(", ");
                allowed.append(known);
            }
            break;
        }
    }
    if (allowed.empty())
    {
        for (const std::string_view name : cors_headers)
        {
            if (!allowed.empty())
                allowed.append(", ");
            allowed.append(name);
        }
    }
    ServerResponse response(state.allocator);
    response.status = 204;
    response.headers.set("Access-Control-Allow-Methods", cors_methods);
    response.headers.set("Access-Control-Allow-Headers", allowed);
    response.headers.set("Access-Control-Max-Age", cors_max_age);
    response.headers.set("Cache-Control", "no-store");
    response.headers.set("Vary", "Access-Control-Request-Headers");
    response.headers.set("Content-Length", "0");
    if (equal_fold(
            trim(request.header("Access-Control-Request-Private-Network").value_or(std::string_view {})),
            "true"))
        response.headers.set("Access-Control-Allow-Private-Network", "true");
    return response;
}

void add_cors_headers(const ServerState& state, const ServerRequest& request, ServerResponse& response)
{
    // The headers of an origin the server allows (L-2.5-2), errors included;
    // never a credential: no Access-Control-Allow-Credentials (L-2.5-5)
    if (const auto allow = cors_allow(state, request))
    {
        response.headers.set("Access-Control-Allow-Origin", *allow);
        if (response.status != 204 || request.method != "OPTIONS")
            response.headers.set("Access-Control-Expose-Headers", cors_exposed);
    }
    if (!state.cors_origins.empty() && !state.cors_any && is_cors_route(state, request.path))
    {
        const auto vary = response.headers.get("Vary");
        if (!vary)
            response.headers.set("Vary", "Origin");
        else
        {
            bool has_origin       = false;
            std::string_view rest = *vary;
            while (!rest.empty())
            {
                const std::size_t comma = rest.find(',');
                has_origin              = has_origin || equal_fold(trim(rest.substr(0, comma)), "Origin");
                rest = comma == std::string_view::npos ? std::string_view {} : rest.substr(comma + 1);
            }
            if (!has_origin)
            {
                String joined(*vary, state.allocator);
                joined.append(", Origin");
                response.headers.set("Vary", joined);
            }
        }
    }
}

void add_hsts_header(const ServerState& state, const ServerRequest& request, ServerResponse& response)
{
    // L-2-11: on an answer that went over TLS, or when the server is told it
    // is served over HTTPS (a proxy ends TLS); never over plain HTTP otherwise
    const std::string_view scheme = request.scheme.empty() ? std::string_view(state.scheme) : request.scheme;
    if (!state.hsts && scheme != "https")
        return;
    String value("max-age=", state.allocator);
    std::array<char, 16> age {};
    const auto result = std::to_chars(age.data(), age.data() + age.size(), state.hsts_max_age);
    value.append(age.data(), static_cast<std::size_t>(result.ptr - age.data()));
    response.headers.set("Strict-Transport-Security", value);
}

} // namespace detail

ServerResponse problem_response(
    std::uint16_t status, Code code, std::string_view detail_text, const Allocator& allocator)
{
    // No server's state to ask: a state of defaults is all the document needs
    const detail::ServerState state(allocator);
    const ServerRequest request {};
    return detail::problem_response(state, request, detail::make_problem(state, status, code, detail_text));
}

} // namespace lantern
