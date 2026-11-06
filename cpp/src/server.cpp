// The server core's routes (SPEC.md § 4.2, § 6): the handshake, the apps,
// what a device is missing, the files.
#include <lantern/server.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <numeric>
#include <system_error>

#include <lantern/byte_range.hpp>
#include <lantern/client.hpp>
#include <lantern/digest.hpp>
#include <lantern/missing.hpp>
#include <lantern/profiles.hpp>

#include "server_internal.hpp"

namespace lantern
{

using detail::Answer;
using detail::ProblemError;
using detail::ServerState;

namespace
{

// A request document's largest body here, well within SPEC.md § 13's 32 MiB.
constexpr std::size_t body_limit = std::size_t { 1 } << 20U;
constexpr std::size_t max_words  = 16;
// I-JSON's largest integer (§ 2.3): 2^53 - 1.
constexpr std::uint64_t max_safe_integer = 9007199254740991ULL;

constexpr std::string_view bearer_challenge = R"(Bearer realm="lantern")";

bool is_word(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 32 && text.front() >= 'a' && text.front() <= 'z'
        && std::ranges::all_of(
            text, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; });
}

bool is_format_word(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 16
        && std::ranges::all_of(text, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); });
}

bool is_requires_word(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 32 && text.front() != '-'
        && std::ranges::all_of(
            text, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
}

String number_text(std::uint64_t value, const Allocator& allocator)
{
    std::array<char, 24> text {};
    const auto result = std::to_chars(text.data(), text.data() + text.size(), value);
    return { text.data(), static_cast<std::size_t>(result.ptr - text.data()), allocator };
}

// The platforms a caller names (§ 4.3): ?platform=, else the
// Lantern-Platform header; nothing for every platform.
std::expected<std::optional<std::string_view>, ProblemError> platform_of(
    const ServerState& state, const ServerRequest& request)
{
    std::string_view name = request.param("platform").value_or(std::string_view {});
    if (name.empty())
        name = detail::trim(request.header("Lantern-Platform").value_or(std::string_view {}));
    if (name.empty())
        return std::optional<std::string_view> {};
    if (!is_platform_name(name))
        return std::unexpected(detail::bad_request(state, "That is not a platform's name."));
    return std::optional<std::string_view>(name);
}

// A listing's page_size (§ 6.2): a positive integer, lowered to the limit.
std::expected<std::uint32_t, ProblemError> page_size_of(
    const ServerState& state, const ServerRequest& request)
{
    const auto text = request.param("page_size");
    if (!text)
        return std::min(state.default_page_size, state.page_limit);
    std::uint64_t value = 0;
    for (const char c : *text)
    {
        if (c < '0' || c > '9')
            return std::unexpected(detail::bad_request(state, "page_size is a positive integer."));
        value = std::min<std::uint64_t>(
            value * 10 + static_cast<std::uint64_t>(c - '0'), std::numeric_limits<std::uint32_t>::max());
    }
    if (value < 1)
        return std::unexpected(detail::bad_request(state, "page_size is a positive integer."));
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(value, state.page_limit));
}

std::expected<std::string_view, ProblemError> sort_of(const ServerState& state, const ServerRequest& request)
{
    const std::string_view sort = request.param("sort").value_or("name");
    if (sort != "name" && sort != "added" && sort != "release")
        return std::unexpected(detail::bad_request(state, "sort is name, added, release."));
    return sort;
}

// Who calls (§ 5.1): this server has no tokens yet, so a request carries
// none, or is refused.
std::optional<ProblemError> check_caller(const ServerState& state, const ServerRequest& request)
{
    const auto header = request.header("Authorization");
    if (!header)
        return std::nullopt;
    const std::string_view text   = detail::trim(*header);
    const std::size_t space       = text.find(' ');
    const std::string_view scheme = text.substr(0, space);
    const std::string_view value
        = space == std::string_view::npos ? std::string_view {} : detail::trim(text.substr(space + 1));
    if (!detail::equal_ignoring_case(scheme, "bearer") || value.empty())
    {
        ProblemError error = detail::make_problem(
            state, 401, Code::unauthorized, "Send a token: Authorization: Bearer <token>.");
        error.headers.set("WWW-Authenticate", bearer_challenge);
        return error;
    }
    ProblemError error
        = detail::make_problem(state, 401, Code::unauthorized, "Unknown, revoked or expired token.");
    error.headers.set("WWW-Authenticate", R"(Bearer realm="lantern", error="invalid_token")");
    return error;
}

// The handshake (§ 4.2) of an anonymous caller.
Answer handshake(const ServerState& state, const ServerRequest& request)
{
    auto platforms = state.library->platforms(state.allocator);
    if (!platforms)
        return std::unexpected(detail::internal_error(state));
    Vector<String> served(state.allocator);
    for (String& platform : *platforms)
    {
        if (is_served_platform(platform) && std::ranges::find(served, platform) == served.end())
            served.push_back(std::move(platform));
    }
    std::ranges::sort(served);

    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("uid");
    w.string(state.uid);
    w.key("name");
    w.string(state.name);
    if (!state.software_name.empty())
    {
        w.key("software");
        w.begin_object();
        w.key("name");
        w.string(state.software_name);
        w.key("version");
        w.string(state.software_version);
        w.end_object();
    }
    w.key("base");
    w.string(state.base);
    w.key("versions");
    w.begin_array();
    w.number(std::uint64_t { 1 });
    w.end_array();
    w.key("platforms");
    w.begin_array();
    for (const String& platform : served)
        w.string(platform);
    w.end_array();
    if (!state.motd.empty())
    {
        w.key("motd");
        w.string(state.motd);
        w.key("language");
        w.string("en");
    }
    w.key("account");
    w.begin_object();
    w.key("state");
    w.string("anonymous");
    w.key("scopes");
    w.begin_array();
    w.string("library");
    w.end_array();
    w.end_object();
    // Per family, the schema it is written in, or 0: only `library` is here
    w.key("features");
    w.begin_object();
    constexpr std::array families { std::string_view { "library" }, std::string_view { "titles" },
        std::string_view { "changes" }, std::string_view { "sections" }, std::string_view { "homebrew" },
        std::string_view { "saves" }, std::string_view { "cheats" }, std::string_view { "requests" },
        std::string_view { "pairing" }, std::string_view { "signatures" }, std::string_view { "admin" },
        std::string_view { "events" }, std::string_view { "peers" }, std::string_view { "sync" },
        std::string_view { "encrypted_saves" }, std::string_view { "deltas" } };
    for (const std::string_view family : families)
    {
        w.key(family);
        w.number(family == "library" ? known_schema : std::uint64_t { 0 });
    }
    w.end_object();
    w.key("limits");
    w.begin_object();
    w.key("page_size");
    w.number(static_cast<std::uint64_t>(state.page_limit));
    w.end_object();
    w.end_object();
    return detail::json_response(state, request, std::move(out));
}

void write_app(json::Writer& w, const App& app)
{
    w.begin_object();
    w.key("id");
    w.string(app.id);
    w.key("platform");
    w.string(app.platform);
    w.key("title_id");
    w.string(app.title_id);
    w.key("app_id");
    w.string(app.app_id);
    w.key("type");
    w.string(app.type);
    w.key("version_code");
    w.number(app.version_code);
    if (!app.version_name.empty())
    {
        w.key("version_name");
        w.string(app.version_name);
    }
    if (!app.name.empty())
    {
        w.key("name");
        w.string(app.name);
    }
    w.key("size");
    w.number(app.size);
    w.key("format");
    w.string(app.format);
    if (!app.requires_.empty())
    {
        w.key("requires");
        w.begin_array();
        for (const String& token : app.requires_)
            w.string(token);
        w.end_array();
    }
    if (!app.includes.empty())
    {
        w.key("includes");
        w.begin_array();
        for (const AppInclude& include : app.includes)
            write(w, include);
        w.end_array();
    }
    w.key("sha256");
    const auto hex = to_hex(app.sha256);
    w.string(std::string_view(hex.data(), hex.size()));
    if (!app.added.empty())
    {
        w.key("added");
        w.string(app.added);
    }
    w.key("file");
    w.string(app.file);
    if (!app.atlas.empty())
    {
        w.key("atlas");
        w.string(app.atlas);
    }
    if (app.installed_size)
    {
        w.key("installed_size");
        w.number(*app.installed_size);
    }
    if (!app.mirrors.empty())
    {
        w.key("mirrors");
        w.begin_array();
        for (const Mirror& mirror : app.mirrors)
        {
            w.begin_object();
            w.key("url");
            w.string(mirror.url);
            w.end_object();
        }
        w.end_array();
    }
    if (app.chunks)
    {
        w.key("chunks");
        w.begin_object();
        w.key("url");
        w.string(app.chunks->url);
        w.key("size");
        w.number(app.chunks->size);
        w.key("sha256");
        const auto chunks_hex = to_hex(app.chunks->sha256);
        w.string(std::string_view(chunks_hex.data(), chunks_hex.size()));
        w.end_object();
    }
    w.end_object();
}

detail::SortKey sort_key(const App& app, std::string_view sort, const Allocator& allocator)
{
    detail::SortKey key(allocator);
    key.id.assign(app.id);
    if (sort == "added")
        key.major = -detail::parse_time(app.added).value_or(0);
    else if (sort == "release")
        key.major = 1; // the release is a title's (§ 7.1): this server has none, every app is without one
    else
        key.minor = detail::fold(app.name, allocator);
    return key;
}

// The page of `items` (any order) after the cursor, `size` at most, with its
// `total` and its `next` (§ 6.2).
Answer apps_page(const ServerState& state, const ServerRequest& request, std::span<const App* const> items,
    std::string_view scope, std::string_view sort)
{
    const auto size = page_size_of(state, request);
    if (!size)
        return std::unexpected(size.error());
    Vector<detail::SortKey> keys(state.allocator);
    keys.reserve(items.size());
    for (const App* app : items)
        keys.push_back(sort_key(*app, sort, state.allocator));
    Vector<std::size_t> order(state.allocator);
    order.reserve(items.size());
    for (std::size_t i = 0; i < items.size(); ++i)
        order.push_back(i);
    std::ranges::sort(
        order, [&](std::size_t a, std::size_t b) { return detail::compare(keys[a], keys[b]) < 0; });

    std::size_t from = 0;
    if (const auto cursor = request.param("cursor"))
    {
        auto position = detail::open_cursor(state, *cursor, scope);
        if (!position)
            return std::unexpected(std::move(position.error()));
        if (position->by_id)
        {
            const auto found = std::ranges::find_if(
                order, [&](std::size_t i) { return items[i]->id == position->key.id; });
            if (found == order.end())
                return std::unexpected(
                    detail::gone(state, "Cursor expired: read the list again from its start."));
            from = static_cast<std::size_t>(found - order.begin()) + 1;
        }
        else
        {
            // After the item the last page ended with, whether or not it is still there
            const auto after = std::ranges::partition_point(
                order, [&](std::size_t i) { return detail::compare(keys[i], position->key) <= 0; });
            from = static_cast<std::size_t>(after - order.begin());
        }
    }
    const std::size_t count = std::min<std::size_t>(*size, order.size() - from);
    const bool more         = from + count < order.size();

    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("items");
    w.begin_array();
    for (std::size_t i = from; i < from + count; ++i)
        write_app(w, *items[order[i]]);
    w.end_array();
    w.key("total");
    w.number(static_cast<std::uint64_t>(items.size()));
    w.key("next");
    if (more)
        w.string(detail::seal_cursor(state, scope, keys[order[from + count - 1]]));
    else
        w.null();
    w.end_object();
    return detail::json_response(state, request, std::move(out));
}

// GET <base>/v1/apps (§ 6.2).
Answer apps_route(const ServerState& state, const ServerRequest& request)
{
    const auto platform = platform_of(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const std::string_view type     = request.param("type").value_or(std::string_view {});
    const std::string_view title_id = request.param("title_id").value_or(std::string_view {});
    const std::string_view text     = request.param("q").value_or(std::string_view {});
    // A format no app has gives an empty list, never an error (L-6.2-7)
    const std::string_view format = request.param("format").value_or(std::string_view {});
    if (!type.empty() && !is_word(type))
        return std::unexpected(
            detail::bad_request(state, "type is a lower-case word, such as base, update or dlc."));
    if (!title_id.empty() && !is_core_id(title_id))
        return std::unexpected(
            detail::bad_request(state, "title_id is 1 to 128 letters, digits, '.', '_' and '-'."));
    const auto sort = sort_of(state, request);
    if (!sort)
        return std::unexpected(sort.error());

    AppsFilter filter;
    filter.platform = platform->value_or(std::string_view {});
    filter.type     = type;
    filter.format   = format;
    filter.title_id = title_id;
    filter.q        = text;
    auto listed     = state.library->apps(filter, state.allocator);
    if (!listed)
        return std::unexpected(detail::internal_error(state));
    const String needle = detail::fold(text, state.allocator);
    Vector<const App*> kept(state.allocator);
    for (const App& app : *listed)
    {
        if ((platform->has_value() && app.platform != **platform) || (!type.empty() && app.type != type)
            || (!format.empty() && app.format != format) || (!title_id.empty() && app.title_id != title_id)
            || (!needle.empty() && !detail::fold(app.name, state.allocator).contains(needle)))
            continue;
        kept.push_back(&app);
    }
    // `none` and an empty value differ in a scope as they do for the filter
    const std::array<std::string_view, 8> parts { "apps", platform->has_value() ? "p" : "-", filter.platform,
        type, format, title_id, text, *sort };
    const String scope = detail::scope_of(parts, state.allocator);
    return apps_page(state, request, kept, scope, *sort);
}

// The digits of a whole number, if they are one that fits.
std::optional<std::uint64_t> whole_number(std::string_view digits) noexcept
{
    std::uint64_t out = 0;
    const auto result = std::from_chars(digits.data(), digits.data() + digits.size(), out);
    if (result.ec != std::errc {} || result.ptr != digits.data() + digits.size())
        return std::nullopt;
    return out;
}

// I-JSON (RFC 7493, § 2.3): no name twice in an object, no integer beyond
// 2^53 - 1. The parser has refused unpaired surrogates and a byte order mark.
bool is_i_json(const json::Value& value)
{
    switch (value.kind())
    {
        case json::Kind::number:
        {
            const std::string_view text = value.text();
            if (text.find_first_of(".eE") == std::string_view::npos)
            {
                const std::string_view digits = text.starts_with('-') ? text.substr(1) : text;
                const auto magnitude          = whole_number(digits);
                return magnitude && *magnitude <= max_safe_integer;
            }
            // A fraction or an exponent: refused when its whole part cannot be exact
            const std::size_t point    = text.find_first_of(".eE");
            const std::size_t whole    = text.substr(0, point).size() - (text.starts_with('-') ? 1 : 0);
            const std::size_t exponent = text.find_first_of("eE");
            if (whole > 16)
                return false;
            if (exponent != std::string_view::npos)
            {
                std::string_view digits = text.substr(exponent + 1);
                if (digits.starts_with('+'))
                    digits.remove_prefix(1);
                std::int64_t power = 0;
                const auto result  = std::from_chars(digits.data(), digits.data() + digits.size(), power);
                const bool zero = text.substr(0, exponent).find_first_not_of("-0.") == std::string_view::npos;
                return result.ec == std::errc {} && (zero || power < 16);
            }
            return true;
        }
        case json::Kind::array:
            return std::ranges::all_of(
                value.items(), [](const json::Value& item) { return is_i_json(item); });
        case json::Kind::object:
        {
            const auto members = value.members();
            for (std::size_t i = 0; i < members.size(); ++i)
            {
                for (std::size_t j = 0; j < i; ++j)
                {
                    if (members[i].key == members[j].key)
                        return false;
                }
                if (!is_i_json(members[i].value))
                    return false;
            }
            return true;
        }
        default:
            return true;
    }
}

bool is_json_media_type(std::string_view header) noexcept
{
    const std::string_view type = detail::trim(header.substr(0, header.find(';')));
    return detail::equal_ignoring_case(type, "application/json");
}

// A client's JSON document (§ 3.2, § 12) bound to a MissingRequest: 413 above
// the limit, 400 when it is not JSON, not I-JSON, beyond § 13 or has no integer
// `schema`, 422 `unsupported_schema` for a schema this server cannot read.
std::expected<MissingRequest, ProblemError> read_missing_request(
    const ServerState& state, const ServerRequest& request)
{
    if (request.body.size() > body_limit)
        return std::unexpected(
            detail::make_problem(state, 413, Code::too_large, "At most 1048576 bytes here."));
    if (!is_json_media_type(request.header("Content-Type").value_or(std::string_view {})))
        return std::unexpected(detail::bad_request(state, "The body is application/json."));
    const std::string_view text(reinterpret_cast<const char*>(request.body.data()), request.body.size());
    json::Limits limits;
    limits.max_document = body_limit;
    const auto document = json::parse(text, limits, state.allocator.resource());
    if (!document || !is_i_json(document->root()))
        return std::unexpected(
            detail::bad_request(state, "The body is not a document this server can read."));
    const json::Value* schema = document->root().is_object() ? document->root().find("schema") : nullptr;
    const auto number         = schema != nullptr && schema->is_number() ? schema->to_u64() : std::nullopt;
    if (!number || *number < 1)
        return std::unexpected(detail::bad_request(state, "The body is an object with an integer schema."));
    if (*number > known_schema)
    {
        String why("This server reads schema 1 here, not ", state.allocator);
        why.append(number_text(*number, state.allocator));
        why.push_back('.');
        return std::unexpected(
            detail::make_problem(state, 422, Code::unsupported_schema, why, "Unsupported schema"));
    }
    DecodeOptions options;
    options.limits = limits;
    options.memory = state.allocator.resource();
    auto bound     = read_document<MissingRequest>(
        text, known_schema, options, [](BindContext& c, MissingRequest& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(detail::bad_request(
            state, "installed is a list of {app_id, version_code}, want a list of base, update or dlc."));
    return std::move(**bound);
}

// POST <base>/v1/apps/missing (§ 6.3).
Answer missing_route(const ServerState& state, const ServerRequest& request)
{
    auto document = read_missing_request(state, request);
    if (!document)
        return std::unexpected(std::move(document.error()));
    const auto words = [&](const std::optional<Vector<String>>& list, bool (*valid)(std::string_view)) -> bool
    {
        return !list
            || (list->size() <= max_words
                && std::ranges::all_of(*list, [&](const String& word) { return valid(word); }));
    };
    if (!words(document->formats, is_format_word) || !words(document->satisfies, is_requires_word))
        return std::unexpected(detail::bad_request(state,
            "formats and satisfies are arrays of at most 16 words, a format's or a requires token's."));
    const auto platform = platform_of(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    if (!platform->has_value())
        return std::unexpected(
            detail::bad_request(state, "Name a platform: Lantern-Platform or ?platform= (SPEC.md § 4.3)."));
    if (std::ranges::any_of(
            document->installed, [](const InstalledApp& item) { return !is_core_id(item.app_id); }))
        return std::unexpected(detail::bad_request(state, "installed is a list of {app_id, version_code}."));
    if (document->want.empty()
        || std::ranges::any_of(document->want,
            [](const String& what) { return what != "base" && what != "update" && what != "dlc"; }))
        return std::unexpected(detail::bad_request(state, "want lists base, update or dlc."));
    const auto sort = sort_of(state, request);
    if (!sort)
        return std::unexpected(sort.error());

    AppsFilter filter;
    filter.platform = **platform;
    auto listed     = state.library->apps(filter, state.allocator);
    if (!listed)
        return std::unexpected(detail::internal_error(state));
    Vector<App> ofplatform(state.allocator);
    for (App& app : *listed)
    {
        if (app.platform == **platform)
            ofplatform.push_back(std::move(app));
    }
    const Vector<App> found = missing_apps(ofplatform, **platform, *document, state.allocator);
    Vector<const App*> items(state.allocator);
    for (const App& app : found)
        items.push_back(&app);

    // The listing's identity: the platform, what is installed and wanted, the filters, the sort
    Vector<String> texts(state.allocator);
    texts.emplace_back("missing");
    texts.emplace_back(**platform);
    Vector<String> installed(state.allocator);
    for (const InstalledApp& item : document->installed)
    {
        String entry(item.app_id, state.allocator);
        entry.push_back(':');
        entry.append(number_text(item.version_code, state.allocator));
        installed.push_back(std::move(entry));
    }
    std::ranges::sort(installed);
    String joined(state.allocator);
    for (const String& entry : installed)
    {
        joined.append(entry);
        joined.push_back(',');
    }
    texts.push_back(std::move(joined));
    Vector<String> want(document->want, state.allocator);
    std::ranges::sort(want);
    want.erase(std::ranges::unique(want).begin(), want.end());
    String wanted(state.allocator);
    for (const String& entry : want)
    {
        wanted.append(entry);
        wanted.push_back(',');
    }
    texts.push_back(std::move(wanted));
    for (const std::optional<Vector<String>>* list : { &document->formats, &document->satisfies })
    {
        String listed_words(state.allocator);
        if (*list)
        {
            Vector<String> sorted(**list, state.allocator);
            std::ranges::sort(sorted);
            listed_words.push_back('[');
            for (const String& word : sorted)
            {
                listed_words.append(word);
                listed_words.push_back(',');
            }
        }
        else
            listed_words.push_back('-');
        texts.push_back(std::move(listed_words));
    }
    texts.emplace_back(*sort);
    Vector<std::string_view> parts(state.allocator);
    for (const String& text : texts)
        parts.emplace_back(text);
    const String scope = detail::scope_of(parts, state.allocator);
    return apps_page(state, request, items, scope, *sort);
}

// GET <base>/v1/files/<name> (§ 6.6): the whole file or one range of it,
// with the validators and the digest of the whole file on every answer.
Answer file_route(const ServerState& state, const ServerRequest& request, std::string_view name)
{
    auto found = state.library->file(name, state.allocator);
    if (!found)
        return std::unexpected(detail::internal_error(state));
    if (!*found)
        return std::unexpected(detail::not_found(state, "No such file; read the app again."));
    const LibraryFile& file = **found;

    ServerResponse response(state.allocator);
    detail::caching_headers(response.headers, request);
    const auto hex = to_hex(file.sha256);
    String etag(state.allocator);
    etag.push_back('"');
    etag.append(hex.data(), 32);
    etag.push_back('"');
    String repr(state.allocator);
    format_digest_field(file.sha256, repr);
    response.headers.set("Content-Type", file.content_type);
    response.headers.set("Accept-Ranges", "bytes");
    response.headers.set("ETag", etag);
    response.headers.set("Repr-Digest", repr);

    std::uint64_t first = 0;
    std::uint64_t last  = file.size == 0 ? 0 : file.size - 1;
    const auto asked    = request.header("Range");
    const auto if_range = request.header("If-Range");
    if (asked && (!if_range || detail::trim(*if_range) == etag))
    {
        const RangeParse range = parse_range_header(*asked, file.size);
        if (range.verdict == RangeVerdict::unsatisfiable)
        {
            String why("The file is ", state.allocator);
            why.append(number_text(file.size, state.allocator));
            why.append(" bytes.");
            ProblemError error
                = detail::make_problem(state, 416, Code::bad_request, why, "Range not satisfiable");
            String content_range("bytes */", state.allocator);
            content_range.append(number_text(file.size, state.allocator));
            error.headers.set("Content-Range", content_range);
            return std::unexpected(std::move(error));
        }
        if (range.verdict == RangeVerdict::satisfiable)
        {
            first           = range.first;
            last            = range.last;
            response.status = 206;
            String content_range("bytes ", state.allocator);
            content_range.append(number_text(first, state.allocator));
            content_range.push_back('-');
            content_range.append(number_text(last, state.allocator));
            content_range.push_back('/');
            content_range.append(number_text(file.size, state.allocator));
            response.headers.set("Content-Range", content_range);
        }
    }
    const std::uint64_t length = file.size == 0 ? 0 : last - first + 1;
    response.headers.set("Content-Length", number_text(length, state.allocator));
    if (request.method != "HEAD" && length != 0)
        response.file = ServerFile { file.reader, first, length };
    return response;
}

struct Route
{
    enum class Kind : std::uint8_t
    {
        none,
        apps,
        missing,
        file,
    };
    Kind kind = Kind::none;
    std::string_view allowed; // the methods it takes
    std::string_view name; // the file's
};

// <base>/v1/<rest>: the route it names, if this server has one.
Route route_of(std::string_view rest) noexcept
{
    std::array<std::string_view, 3> segments;
    std::size_t count = 0;
    while (true)
    {
        const std::size_t slash = rest.find('/');
        if (count == segments.size())
            return {};
        segments[count++] = rest.substr(0, slash);
        if (slash == std::string_view::npos)
            break;
        rest.remove_prefix(slash + 1);
    }
    if (count == 1 && segments[0] == "apps")
        return { Route::Kind::apps, "GET, HEAD", {} };
    if (count == 2 && segments[0] == "apps" && segments[1] == "missing")
        return { Route::Kind::missing, "POST", {} };
    if (count == 2 && segments[0] == "files" && !segments[1].empty())
        return { Route::Kind::file, "GET, HEAD", segments[1] };
    return {};
}

bool takes(std::string_view allowed, std::string_view method) noexcept
{
    while (!allowed.empty())
    {
        const std::size_t comma = allowed.find(',');
        if (detail::trim(allowed.substr(0, comma)) == method)
            return true;
        allowed = comma == std::string_view::npos ? std::string_view {} : allowed.substr(comma + 1);
    }
    return false;
}

Answer route(const ServerState& state, const ServerRequest& request)
{
    // § 2.4: a parameter given twice is a 400
    for (std::size_t i = 0; i < request.query.size(); ++i)
    {
        for (std::size_t j = 0; j < i; ++j)
        {
            if (request.query[i].name == request.query[j].name)
                return std::unexpected(detail::bad_request(state, "Each query parameter is given once."));
        }
    }
    const std::string_view path = request.path;
    const std::string_view base = state.base;
    const bool shake            = path == "/.well-known/lantern"
        || (path.starts_with(base)
            && (path.substr(base.size()) == "/v1" || path.substr(base.size()) == "/v1/"));
    if (shake)
    {
        if (auto refused = check_caller(state, request))
            return std::unexpected(std::move(*refused));
        if (request.method != "GET" && request.method != "HEAD")
            return std::unexpected(detail::method_not_allowed(state, "GET, HEAD"));
        return handshake(state, request);
    }
    String prefix(base, state.allocator);
    prefix.append("/v1/");
    if (!path.starts_with(prefix))
        return std::unexpected(detail::not_found(state, "No such route on this server."));
    const Route chosen = route_of(path.substr(prefix.size()));
    if (chosen.kind == Route::Kind::none)
        return std::unexpected(detail::not_found(state, "No such route on this server."));
    if (auto refused = check_caller(state, request))
        return std::unexpected(std::move(*refused));
    if (!takes(chosen.allowed, request.method))
        return std::unexpected(detail::method_not_allowed(state, chosen.allowed));
    switch (chosen.kind)
    {
        case Route::Kind::apps:
            return apps_route(state, request);
        case Route::Kind::missing:
            return missing_route(state, request);
        case Route::Kind::file:
            return file_route(state, request, chosen.name);
        case Route::Kind::none:
            break;
    }
    return std::unexpected(detail::not_found(state, "No such route on this server."));
}

} // namespace

Result<Server> Server::create(Library& library, const ServerOptions& options, RandomSource& random,
    Clock& clock, const Allocator& allocator)
{
    if (!is_valid_server_uid(options.uid))
        return fail(Category::usage, "uid is a UUID of version 4 or 7, in lower case (SPEC.md 4.2)");
    if (options.name.empty() || options.name.size() > 512)
        return fail(Category::usage, "name is 1 to 512 bytes");
    if (!options.base.starts_with('/'))
        return fail(Category::usage, "base is a path, such as /api/lantern");
    if (options.hsts_max_age < 15552000)
        return fail(
            Category::usage, "hsts_max_age is 15552000 seconds (six months) or more (SPEC.md 2, L-2-11)");
    if (options.page_limit < 1 || options.page_limit > 1000 || options.default_page_size < 1)
        return fail(Category::usage, "page_limit is 1 to 1000 (SPEC.md 13), default_page_size at least 1");
    if (options.cursor_lifetime < 1)
        return fail(Category::usage, "cursor_lifetime is at least a second");
    if (options.scheme != "https" && options.scheme != "http")
        return fail(Category::usage, "scheme is https or http");
    for (const std::string_view origin : options.cors_origins)
    {
        if (origin != "*" && !detail::is_cors_origin(origin))
            return fail(Category::usage, "cors_origins: an origin (https://app.example.org) or *");
    }

    auto state = std::allocate_shared<ServerState>(
        std::pmr::polymorphic_allocator<ServerState>(allocator), allocator);
    state->library = &library;
    state->clock   = &clock;
    state->uid.assign(options.uid);
    state->name.assign(options.name);
    state->base.assign(options.base);
    while (state->base.ends_with('/'))
        state->base.pop_back();
    state->scheme.assign(options.scheme);
    state->software_name.assign(options.software_name);
    state->software_version.assign(options.software_version);
    state->motd.assign(options.motd);
    for (const std::string_view origin : options.cors_origins)
    {
        state->cors_origins.emplace_back(origin);
        state->cors_any = state->cors_any || origin == "*";
    }
    state->hsts              = options.hsts;
    state->hsts_max_age      = options.hsts_max_age;
    state->page_limit        = options.page_limit;
    state->default_page_size = options.default_page_size;
    state->cursor_lifetime   = options.cursor_lifetime;
    if (auto filled = random.fill(state->secret); !filled)
        return std::unexpected(filled.error());
    return Server(std::move(state));
}

std::string_view Server::base() const noexcept
{
    return state_->base;
}

ServerResponse Server::handle(const ServerRequest& request) const
{
    const ServerState& state = *state_;
    Answer answer            = request.method == "OPTIONS" && detail::is_cors_route(state, request.path)
                   ? detail::preflight(state, request)
                   : route(state, request);
    ServerResponse response
        = answer ? std::move(*answer) : detail::problem_response(state, request, answer.error());
    detail::add_cors_headers(state, request, response);
    detail::add_hsts_header(state, request, response);
    return response;
}

} // namespace lantern
