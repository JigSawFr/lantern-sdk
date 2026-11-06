// The server core's routes (SPEC.md § 4.2, § 5.2, § 6): the handshake, the
// apps, what a device is missing, the files, pairing.
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
#include <lantern/ed25519.hpp>
#include <lantern/encoding.hpp>
#include <lantern/missing.hpp>
#include <lantern/profiles.hpp>
#include <lantern/requests.hpp>
#include <lantern/saves.hpp>
#include <lantern/sync_store.hpp>

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

std::expected<std::string_view, ProblemError> sort_of(const ServerState& state, const ServerRequest& request)
{
    const std::string_view sort = request.param("sort").value_or("name");
    if (sort != "name" && sort != "added" && sort != "release")
        return std::unexpected(detail::bad_request(state, "sort is name, added, release."));
    return sort;
}

// The handshake (§ 4.2) for `caller`.
Answer handshake(const ServerState& state, const ServerRequest& request, const detail::Caller& caller)
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
    const bool reads_library = !detail::check_library(state, caller).has_value();
    w.key("account");
    w.begin_object();
    if (!caller.name.empty())
    {
        w.key("name");
        w.string(caller.name);
    }
    w.key("state");
    switch (caller.state)
    {
        case detail::Caller::State::anonymous:
            w.string("anonymous");
            break;
        case detail::Caller::State::active:
            w.string("active");
            break;
        case detail::Caller::State::frozen:
            w.string("frozen");
            break;
    }
    w.key("scopes");
    w.begin_array();
    if (caller.state == detail::Caller::State::anonymous)
    {
        // What everyone holds on a server that asks for no token (§ 4.2)
        if (!state.require_auth)
        {
            w.string("library");
            if (state.library->offers_cheats())
                w.string("cheats");
        }
    }
    else
    {
        for (const String& scope : caller.scopes)
            w.string(scope);
    }
    w.end_array();
    if (caller.state != detail::Caller::State::anonymous)
    {
        w.key("bound");
        w.boolean(caller.key.has_value());
        if (caller.rating_cap)
        {
            w.key("rating_cap");
            detail::write_rating_cap(w, *caller.rating_cap);
        }
    }
    w.end_object();
    // Per family, the schema it is written in, or 0: `library` and the
    // families the library offers (titles, changes, sections, homebrew) for a
    // caller who may read it, `cheats` for one with that scope, `saves` and
    // `encrypted_saves` for one with the scope `saves` when there is a store,
    // `requests` for one with that scope when there is a store, `admin` for
    // one with that scope when the account store administers, `events` for
    // one who may read any kind of event when the server offers them, and
    // `pairing` and `signatures` for every caller (§ 4.2, L-4.2-5) when the
    // server has accounts; nothing else is here yet
    const bool titles   = reads_library && state.library->offers_titles();
    const bool changes  = reads_library && state.library->journal() != nullptr;
    const bool sections = reads_library && state.library->offers_sections();
    const bool homebrew = reads_library && state.library->offers_homebrew();
    const bool cheats
        = !detail::check_scope(state, caller, "cheats").has_value() && state.library->offers_cheats();
    const bool saves = state.saves != nullptr && !detail::check_scope(state, caller, "saves").has_value();
    const bool requests
        = state.requests != nullptr && !detail::check_scope(state, caller, "requests").has_value();
    const bool admin  = state.admin && !detail::check_scope(state, caller, "admin").has_value();
    const bool events = state.events && !detail::check_events(state, caller).has_value();
    const bool peers  = state.peers && reads_library;
    const bool sync   = state.sync != nullptr && !detail::check_scope(state, caller, "sync.read").has_value();
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
        const bool offered = (family == "library" && reads_library) || (family == "titles" && titles)
            || (family == "changes" && changes) || (family == "sections" && sections)
            || (family == "homebrew" && homebrew) || (family == "cheats" && cheats)
            || (family == "saves" && saves) || (family == "encrypted_saves" && saves && state.encrypted_saves)
            || (family == "requests" && requests) || (family == "admin" && admin)
            || (family == "events" && events) || (family == "peers" && peers) || (family == "sync" && sync)
            || ((family == "pairing" || family == "signatures") && state.accounts != nullptr);
        w.key(family);
        w.number(offered ? known_schema : std::uint64_t { 0 });
    }
    w.end_object();
    if (state.accounts != nullptr)
    {
        w.key("auth");
        w.begin_object();
        w.key("bearer_only");
        w.boolean(!state.bound_only);
        w.key("skew");
        w.number(static_cast<std::uint64_t>(state.skew));
        w.end_object();
    }
    if (state.peers)
    {
        // The same for every caller (L-19.3-3)
        String key(state.allocator);
        base64_encode(state.grant_public, key);
        w.key("peers");
        w.begin_object();
        w.key("key");
        w.string(key);
        w.key("grant_lifetime");
        w.number(static_cast<std::uint64_t>(state.grant_lifetime));
        w.end_object();
    }
    w.key("limits");
    w.begin_object();
    w.key("page_size");
    w.number(static_cast<std::uint64_t>(state.page_limit));
    if (state.sync != nullptr)
    {
        w.key("sync_items");
        w.number(static_cast<std::uint64_t>(state.sync->item_limit()));
    }
    if (state.saves != nullptr)
    {
        w.key("save_body");
        w.number(state.save_limits.body);
        w.key("save_size");
        w.number(state.save_limits.size);
        w.key("saves_kept_per_title");
        w.number(static_cast<std::uint64_t>(state.save_limits.kept));
    }
    if (state.events)
    {
        w.key("heartbeat");
        w.number(static_cast<std::uint64_t>(state.heartbeat));
        w.key("event_streams");
        w.number(static_cast<std::uint64_t>(state.event_streams));
        w.key("wait");
        w.number(static_cast<std::uint64_t>(state.wait_limit));
    }
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
    Vector<detail::SortKey> keys(state.allocator);
    keys.reserve(items.size());
    for (const App* app : items)
        keys.push_back(sort_key(*app, sort, state.allocator));
    const auto window = detail::page_window(state, request, keys, scope);
    if (!window)
        return std::unexpected(window.error());

    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("items");
    w.begin_array();
    for (std::size_t i = window->from; i < window->from + window->count; ++i)
        write_app(w, *items[window->order[i]]);
    w.end_array();
    w.key("total");
    w.number(static_cast<std::uint64_t>(items.size()));
    w.key("next");
    if (window->next.empty())
        w.null();
    else
        w.string(window->next);
    w.end_object();
    return detail::json_response(state, request, std::move(out));
}

// GET <base>/v1/apps (§ 6.2).
Answer apps_route(const ServerState& state, const ServerRequest& request, const detail::Caller& caller)
{
    const auto platform = platform_of(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const auto cap = detail::CapFilter::of(state, caller);
    if (!cap)
        return std::unexpected(cap.error());
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
            || cap->hides_title(app.platform, app.title_id)
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
    return detail::equal_fold(type, "application/json");
}

// A client's JSON document bound to a MissingRequest (§ 6.3), after the
// checks of detail::request_document().
std::expected<MissingRequest, ProblemError> read_missing_request(
    const ServerState& state, const ServerRequest& request)
{
    const auto prepared = detail::request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<MissingRequest>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, MissingRequest& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(detail::bad_request(
            state, "installed is a list of {app_id, version_code}, want a list of base, update or dlc."));
    return std::move(**bound);
}

// POST <base>/v1/apps/missing (§ 6.3).
Answer missing_route(const ServerState& state, const ServerRequest& request, const detail::Caller& caller)
{
    auto document = read_missing_request(state, request);
    if (!document)
        return std::unexpected(std::move(document.error()));
    const auto cap = detail::CapFilter::of(state, caller);
    if (!cap)
        return std::unexpected(cap.error());
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
        if (app.platform == **platform && !cap->hides_title(app.platform, app.title_id))
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
        entry.append(detail::number_text(item.version_code, state.allocator));
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
Answer serve_file(const ServerState& state, const ServerRequest& request, const LibraryFile& file)
{
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
            why.append(detail::number_text(file.size, state.allocator));
            why.append(" bytes.");
            ProblemError error
                = detail::make_problem(state, 416, Code::bad_request, why, "Range not satisfiable");
            String content_range("bytes */", state.allocator);
            content_range.append(detail::number_text(file.size, state.allocator));
            error.headers.set("Content-Range", content_range);
            return std::unexpected(std::move(error));
        }
        if (range.verdict == RangeVerdict::satisfiable)
        {
            first           = range.first;
            last            = range.last;
            response.status = 206;
            String content_range("bytes ", state.allocator);
            content_range.append(detail::number_text(first, state.allocator));
            content_range.push_back('-');
            content_range.append(detail::number_text(last, state.allocator));
            content_range.push_back('/');
            content_range.append(detail::number_text(file.size, state.allocator));
            response.headers.set("Content-Range", content_range);
        }
    }
    const std::uint64_t length = file.size == 0 ? 0 : last - first + 1;
    response.headers.set("Content-Length", detail::number_text(length, state.allocator));
    if (request.method != "HEAD" && length != 0)
        response.file = ServerFile { file.reader, first, length };
    return response;
}

// GET <base>/v1/files/<name> (§ 6.6).
Answer file_route(const ServerState& state, const ServerRequest& request, const detail::Caller& caller,
    std::string_view name)
{
    const auto cap = detail::CapFilter::of(state, caller);
    if (!cap)
        return std::unexpected(cap.error());
    const auto hidden = detail::file_hidden(state, *cap, name);
    if (!hidden)
        return std::unexpected(hidden.error());
    if (*hidden)
        return std::unexpected(detail::not_found(state, "No such file; read the app again."));
    auto found = state.library->file(name, state.allocator);
    if (!found)
        return std::unexpected(detail::internal_error(state));
    if (!*found)
        return std::unexpected(detail::not_found(state, "No such file; read the app again."));
    return serve_file(state, request, **found);
}

// Whether a title shows the image of that name: its url ends with
// /v1/media/<name> (§ 7.1).
bool shows_media(const Title& title, std::string_view suffix) noexcept
{
    const auto shown = [&](const std::optional<Image>& image)
    { return image && !image->external.value_or(false) && std::string_view(image->url).ends_with(suffix); };
    return shown(title.icon) || shown(title.banner)
        || std::ranges::any_of(title.screenshots, [&](const Image& image)
            { return !image.external.value_or(false) && std::string_view(image.url).ends_with(suffix); });
}

// GET <base>/v1/media/<name> (§ 7.1, L-7.1-2): an image of a title, on this
// origin, named by its content, so that it is kept for good (L-14-5).
Answer media_route(const ServerState& state, const ServerRequest& request, std::string_view name)
{
    String suffix("/v1/media/", state.allocator);
    suffix.append(name);
    auto titles = state.library->titles(
        request.header("Accept-Language").value_or(std::string_view {}), state.allocator);
    if (!titles)
        return std::unexpected(detail::internal_error(state));
    if (std::ranges::none_of(*titles, [&](const Title& title) { return shows_media(title, suffix); }))
        return std::unexpected(detail::not_found(state, "No such image."));
    auto found = state.library->media(name, state.allocator);
    if (!found)
        return std::unexpected(detail::internal_error(state));
    if (!*found)
        return std::unexpected(detail::not_found(state, "No such image."));
    auto served = serve_file(state, request, **found);
    if (served && served->status < 300)
    {
        served->headers.set("Cache-Control",
            request.header("Authorization") ? "private, max-age=31536000, immutable"
                                            : "public, max-age=31536000, immutable");
    }
    return served;
}

struct Route
{
    enum class Kind : std::uint8_t
    {
        none,
        apps,
        missing,
        file,
        changes,
        titles,
        title_changes,
        title,
        media,
        sections,
        homebrew_list,
        homebrew_updates,
        homebrew,
        cheats,
        cheat,
        saves,
        save_post,
        upload_open,
        save,
        upload,
        pairing_start,
        pairing_poll,
        requests,
        request,
        admin,
        events,
        sync_all,
        sync_collection,
        grant,
    };
    Kind kind = Kind::none;
    std::string_view allowed; // the methods it takes
    std::string_view
        name; // the file's, the pairing's poll address, a title's, an upload's, an admin resource
    std::string_view second; // a save's id, an admin resource's name or id
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
        return { Route::Kind::apps, "GET, HEAD", {}, {} };
    if (count == 2 && segments[0] == "apps" && segments[1] == "missing")
        return { Route::Kind::missing, "POST", {}, {} };
    if (count == 2 && segments[0] == "files" && !segments[1].empty())
        return { Route::Kind::file, "GET, HEAD", segments[1], {} };
    if (count == 1 && segments[0] == "changes")
        return { Route::Kind::changes, "GET, HEAD", {}, {} };
    if (count == 1 && segments[0] == "titles")
        return { Route::Kind::titles, "GET, HEAD", {}, {} };
    if (count == 2 && segments[0] == "titles" && segments[1] == "changes")
        return { Route::Kind::title_changes, "GET, HEAD", {}, {} };
    if (count == 2 && segments[0] == "titles" && !segments[1].empty())
        return { Route::Kind::title, "GET, HEAD", segments[1], {} };
    if (count == 2 && segments[0] == "media" && !segments[1].empty())
        return { Route::Kind::media, "GET, HEAD", segments[1], {} };
    if (count == 1 && segments[0] == "sections")
        return { Route::Kind::sections, "GET, HEAD", {}, {} };
    if (count == 1 && segments[0] == "homebrew")
        return { Route::Kind::homebrew_list, "GET, HEAD", {}, {} };
    if (count == 2 && segments[0] == "homebrew" && segments[1] == "updates")
        return { Route::Kind::homebrew_updates, "POST", {}, {} };
    if (count == 2 && segments[0] == "homebrew" && !segments[1].empty())
        return { Route::Kind::homebrew, "GET, HEAD", segments[1], {} };
    if (count == 1 && segments[0] == "cheats")
        return { Route::Kind::cheats, "GET, HEAD, POST", {}, {} };
    if (count == 2 && segments[0] == "cheats" && !segments[1].empty())
        return { Route::Kind::cheat, "GET, HEAD, PUT, DELETE", segments[1], {} };
    if (count == 1 && segments[0] == "saves")
        return { Route::Kind::saves, "GET, HEAD", {}, {} };
    if (count == 2 && segments[0] == "saves" && !segments[1].empty())
        return { Route::Kind::save_post, "POST", segments[1], {} };
    if (count == 3 && segments[0] == "saves" && !segments[1].empty() && segments[2] == "uploads")
        return { Route::Kind::upload_open, "POST", segments[1], {} };
    if (count == 3 && segments[0] == "saves" && !segments[1].empty() && !segments[2].empty())
        return { Route::Kind::save, "GET, HEAD, DELETE", segments[1], segments[2] };
    if (count == 2 && segments[0] == "uploads" && !segments[1].empty())
        return { Route::Kind::upload, "HEAD, PATCH, DELETE", segments[1], {} };
    if (count == 1 && segments[0] == "events")
        return { Route::Kind::events, "GET", {}, {} };
    if (count == 1 && segments[0] == "sync")
        return { Route::Kind::sync_all, "GET, HEAD, DELETE", {}, {} };
    if (count == 2 && segments[0] == "sync" && !segments[1].empty())
        return { Route::Kind::sync_collection, "GET, HEAD, PATCH, DELETE", segments[1], {} };
    if (count == 3 && segments[0] == "grants" && segments[1] == "sha256" && !segments[2].empty())
        return { Route::Kind::grant, "GET, HEAD", segments[2], {} };
    if (count == 1 && segments[0] == "pairing")
        return { Route::Kind::pairing_start, "POST", {}, {} };
    if (count == 2 && segments[0] == "pairing" && !segments[1].empty())
        return { Route::Kind::pairing_poll, "GET", segments[1], {} };
    if (count == 1 && segments[0] == "requests")
        return { Route::Kind::requests, "GET, HEAD, POST", {}, {} };
    if (count == 2 && segments[0] == "requests" && !segments[1].empty())
        return { Route::Kind::request, "DELETE", segments[1], {} };
    if (segments[0] == "admin" && (count == 2 || (count == 3 && !segments[2].empty())))
    {
        const std::string_view methods = detail::admin_methods(segments[1], count == 3);
        if (!methods.empty())
            return { Route::Kind::admin, methods, segments[1],
                count == 3 ? segments[2] : std::string_view {} };
    }
    return {};
}

bool is_saves_route(Route::Kind kind) noexcept
{
    return kind == Route::Kind::saves || kind == Route::Kind::save_post || kind == Route::Kind::upload_open
        || kind == Route::Kind::save || kind == Route::Kind::upload;
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
    if (detail::is_approval_path(state, path))
        return detail::approval_page(state, request);
    const bool shake = path == "/.well-known/lantern"
        || (path.starts_with(base)
            && (path.substr(base.size()) == "/v1" || path.substr(base.size()) == "/v1/"));
    if (shake)
    {
        const auto caller = detail::identify(state, request);
        if (!caller)
            return std::unexpected(caller.error());
        if (auto refused = detail::check_request_signature(state, request, *caller))
            return std::unexpected(std::move(*refused));
        if (request.method != "GET" && request.method != "HEAD")
            return std::unexpected(detail::method_not_allowed(state, "GET, HEAD"));
        return handshake(state, request, *caller);
    }
    String prefix(base, state.allocator);
    prefix.append("/v1/");
    if (!path.starts_with(prefix))
        return std::unexpected(detail::not_found(state, "No such route on this server."));
    const Route chosen = route_of(path.substr(prefix.size()));
    if (chosen.kind == Route::Kind::none)
        return std::unexpected(detail::not_found(state, "No such route on this server."));
    const bool pairing
        = chosen.kind == Route::Kind::pairing_start || chosen.kind == Route::Kind::pairing_poll;
    if (pairing && state.accounts == nullptr)
        return std::unexpected(detail::not_found(state, "This server does not offer it."));
    // The families a library offers, or not (§ 4.2)
    bool offered = true;
    switch (chosen.kind)
    {
        case Route::Kind::changes:
            // With `wait`, a long poll of the events, which a library with no journal gives too (§ 18.3)
            offered = state.library->journal() != nullptr || (state.events && request.param("wait"));
            break;
        case Route::Kind::events:
            offered = state.events;
            break;
        case Route::Kind::titles:
        case Route::Kind::title_changes:
        case Route::Kind::title:
        case Route::Kind::media:
            offered = state.library->offers_titles();
            break;
        case Route::Kind::sections:
            offered = state.library->offers_sections();
            break;
        case Route::Kind::homebrew_list:
        case Route::Kind::homebrew_updates:
        case Route::Kind::homebrew:
            offered = state.library->offers_homebrew();
            break;
        case Route::Kind::cheats:
        case Route::Kind::cheat:
            offered = state.library->offers_cheats();
            break;
        case Route::Kind::saves:
        case Route::Kind::save_post:
        case Route::Kind::upload_open:
        case Route::Kind::save:
        case Route::Kind::upload:
            offered = state.saves != nullptr;
            break;
        case Route::Kind::requests:
        case Route::Kind::request:
            offered = state.requests != nullptr;
            break;
        case Route::Kind::admin:
            offered = state.admin && (chosen.name != "requests" || state.requests != nullptr);
            break;
        case Route::Kind::sync_all:
        case Route::Kind::sync_collection:
            offered = state.sync != nullptr;
            break;
        case Route::Kind::grant:
            offered = state.peers;
            break;
        default:
            break;
    }
    if (!offered)
        return std::unexpected(detail::not_found(state, "This server does not offer it."));
    // A server that takes no cheat set writes answers 405 to a write (§ 10)
    const bool cheat_route = chosen.kind == Route::Kind::cheats || chosen.kind == Route::Kind::cheat;
    const std::string_view allowed
        = cheat_route && !state.library->writes_cheats() ? std::string_view { "GET, HEAD" } : chosen.allowed;
    const auto caller = detail::identify(state, request);
    if (!caller)
        return std::unexpected(caller.error());
    // A request held and asked again was checked the first time: its nonce is taken once (L-5.4-9)
    if (!request.resumed)
    {
        if (auto refused = detail::check_request_signature(state, request, *caller))
            return std::unexpected(std::move(*refused));
    }
    if (!takes(allowed, request.method))
        return std::unexpected(detail::method_not_allowed(state, allowed));
    if (!pairing)
    {
        // Whoever reaches the server may ask to pair; the library asks for its scope (§ 5.1), the
        // cheat sets for theirs (writing: another)
        const bool reading     = request.method == "GET" || request.method == "HEAD";
        std::string_view scope = "library";
        if (cheat_route)
            scope = reading ? "cheats" : "cheats.write";
        if (is_saves_route(chosen.kind))
            scope = "saves";
        if (chosen.kind == Route::Kind::requests || chosen.kind == Route::Kind::request)
            scope = "requests";
        if (chosen.kind == Route::Kind::admin)
            scope = "admin";
        if (chosen.kind == Route::Kind::sync_all || chosen.kind == Route::Kind::sync_collection)
            scope = reading ? "sync.read" : "sync.write";
        // The events are for whoever may read one kind of them (§ 18.2)
        const bool long_poll = chosen.kind == Route::Kind::changes && state.events && request.param("wait");
        if (chosen.kind == Route::Kind::events || long_poll)
        {
            if (auto refused = detail::check_events(state, *caller))
                return std::unexpected(std::move(*refused));
        }
        else if (auto refused = detail::check_scope(state, *caller, scope))
        {
            return std::unexpected(std::move(*refused));
        }
    }
    // A body the adapter left unread (too large to buffer) is for the uploads alone
    if (request.stream != nullptr && chosen.kind != Route::Kind::save_post
        && chosen.kind != Route::Kind::upload)
        return std::unexpected(
            detail::make_problem(state, 413, Code::too_large, "That body is larger than this route takes."));
    switch (chosen.kind)
    {
        case Route::Kind::apps:
            return apps_route(state, request, *caller);
        case Route::Kind::missing:
            return missing_route(state, request, *caller);
        case Route::Kind::file:
            return file_route(state, request, *caller, chosen.name);
        case Route::Kind::changes:
            return detail::changes_route(state, request, *caller);
        case Route::Kind::titles:
            return detail::titles_route(state, request, *caller);
        case Route::Kind::title_changes:
            return detail::title_changes_route(state, request, *caller);
        case Route::Kind::title:
            return detail::title_route(state, request, *caller, chosen.name);
        case Route::Kind::media:
            return media_route(state, request, chosen.name);
        case Route::Kind::sections:
            return detail::sections_route(state, request, *caller);
        case Route::Kind::homebrew_list:
            return detail::homebrew_list_route(state, request, *caller);
        case Route::Kind::homebrew_updates:
            return detail::homebrew_updates_route(state, request, *caller);
        case Route::Kind::homebrew:
            return detail::homebrew_route(state, request, *caller, chosen.name);
        case Route::Kind::cheats:
            return request.method == "POST" ? detail::cheat_post_route(state, request)
                                            : detail::cheats_route(state, request, *caller);
        case Route::Kind::cheat:
            if (request.method == "PUT" || request.method == "DELETE")
                return detail::cheat_write_route(state, request, chosen.name);
            return detail::cheat_text_route(state, request, *caller, chosen.name);
        case Route::Kind::saves:
            return detail::saves_route(state, request, *caller);
        case Route::Kind::save_post:
            return detail::save_post_route(state, request, *caller, chosen.name);
        case Route::Kind::upload_open:
            return detail::upload_open_route(state, request, *caller, chosen.name);
        case Route::Kind::save:
            return detail::save_route(state, request, *caller, chosen.name, chosen.second);
        case Route::Kind::upload:
            return detail::upload_route(state, request, *caller, chosen.name);
        case Route::Kind::requests:
            return detail::requests_route(state, request, *caller);
        case Route::Kind::request:
            return detail::request_route(state, request, *caller, chosen.name);
        case Route::Kind::admin:
            return detail::admin_route(state, request, *caller, chosen.name, chosen.second);
        case Route::Kind::events:
            return detail::events_route(state, request, *caller);
        case Route::Kind::sync_all:
            return detail::sync_route(state, request, *caller, {}, true);
        case Route::Kind::sync_collection:
            return detail::sync_route(state, request, *caller, chosen.name, false);
        case Route::Kind::grant:
            return detail::grant_route(state, request, *caller, chosen.name);
        case Route::Kind::pairing_start:
            return detail::pairing_start(state, request);
        case Route::Kind::pairing_poll:
            return detail::pairing_poll(state, request, chosen.name);
        case Route::Kind::none:
            break;
    }
    return std::unexpected(detail::not_found(state, "No such route on this server."));
}

} // namespace

namespace detail
{

std::expected<std::optional<std::string_view>, ProblemError> platform_param(
    const ServerState& state, const ServerRequest& request)
{
    return platform_of(state, request);
}

void write_app_json(json::Writer& w, const App& app)
{
    write_app(w, app);
}

Answer serve_library_file(const ServerState& state, const ServerRequest& request, const LibraryFile& file)
{
    return serve_file(state, request, file);
}

String number_text(std::uint64_t value, const Allocator& allocator)
{
    std::array<char, 24> text {};
    const auto result = std::to_chars(text.data(), text.data() + text.size(), value);
    return { text.data(), static_cast<std::size_t>(result.ptr - text.data()), allocator };
}

std::expected<RequestDocument, ProblemError> request_document(
    const ServerState& state, const ServerRequest& request, std::size_t limit)
{
    if (limit == 0)
        limit = body_limit;
    if (request.body.size() > limit)
    {
        String why("At most ", state.allocator);
        why.append(number_text(limit, state.allocator));
        why.append(" bytes here.");
        return std::unexpected(make_problem(state, 413, Code::too_large, why));
    }
    if (!is_json_media_type(request.header("Content-Type").value_or(std::string_view {})))
        return std::unexpected(bad_request(state, "The body is application/json."));
    RequestDocument out;
    out.text = std::string_view(reinterpret_cast<const char*>(request.body.data()), request.body.size());
    out.options.limits.max_document = limit;
    if (limit > body_limit)
        out.options.limits.max_string = limit;
    out.options.memory  = state.allocator.resource();
    const auto document = json::parse(out.text, out.options.limits, state.allocator.resource());
    if (!document || !is_i_json(document->root()))
        return std::unexpected(bad_request(state, "The body is not a document this server can read."));
    const json::Value* schema = document->root().is_object() ? document->root().find("schema") : nullptr;
    const auto number         = schema != nullptr && schema->is_number() ? schema->to_u64() : std::nullopt;
    if (!number || *number < 1)
        return std::unexpected(bad_request(state, "The body is an object with an integer schema."));
    if (*number > known_schema)
    {
        String why("This server reads schema 1 here, not ", state.allocator);
        why.append(number_text(*number, state.allocator));
        why.push_back('.');
        return std::unexpected(make_problem(state, 422, Code::unsupported_schema, why, "Unsupported schema"));
    }
    return out;
}

} // namespace detail

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
    if (options.accounts == nullptr)
    {
        if (options.require_auth || options.bound_only)
            return fail(Category::usage, "require_auth and bound_only need accounts");
    }
    else
    {
        if (options.skew < 60 || options.skew > 900)
            return fail(Category::usage, "skew is 60 to 900 seconds (SPEC.md 5.4)");
        if (options.pairing_interval < 1 || options.pairing_interval > 60)
            return fail(Category::usage, "pairing_interval is 1 to 60 seconds (SPEC.md 5.2)");
        if (options.pairing_expires < 1 || options.pairing_expires > 600)
            return fail(
                Category::usage, "pairing_expires is 1 to 600 seconds: a code lives 10 minutes at most");
        if (options.pairing_requests < 1 || options.pairing_window < 1 || options.invitation_attempts < 1
            || options.invitation_window < 1 || options.nonce_limit < 1)
            return fail(Category::usage, "the pairing limits and the nonce limit are at least 1");
        if (!options.verify.starts_with('/')
            && !(options.verify.starts_with("https://") || options.verify.starts_with("http://")))
            return fail(Category::usage, "verify is a path of this server or an absolute URL");
        if (options.verify.find_first_of(" \t\r\n\"<>") != std::string_view::npos)
            return fail(Category::usage, "verify holds a character a URL does not");
    }

    if (options.saves != nullptr)
    {
        const SaveLimits& limits = options.save_limits;
        if (options.accounts == nullptr)
            return fail(Category::usage, "saves need accounts: a backup belongs to one");
        if (limits.body < 1 || limits.body > limits.size || limits.size > max_safe_integer || limits.kept < 1
            || limits.chunk < 1 || limits.upload_hours < 1)
            return fail(
                Category::usage, "save_limits: 1 <= body <= size, chunk, kept and upload_hours at least 1");
    }

    if (options.requests != nullptr && options.accounts == nullptr)
        return fail(Category::usage, "requests need accounts: a request belongs to one");

    if (options.sync != nullptr)
    {
        if (options.accounts == nullptr)
            return fail(Category::usage, "sync needs accounts: its data belongs to one");
        if (options.sync->item_limit() < 1 || options.sync->item_limit() > 100000)
            return fail(Category::usage, "limits.sync_items is 1 to 100000 (SPEC.md 13)");
    }
    if (options.grant_seed && (options.grant_lifetime < 1 || options.grant_lifetime > 900))
        return fail(Category::usage, "grant_lifetime is 1 to 900 seconds (SPEC.md 19.3)");

    if (options.events
        && (options.heartbeat < 5 || options.heartbeat > 60 || options.event_streams < 1
            || options.wait_limit < 30 || options.wait_limit > 300 || options.events_kept < 1
            || options.events_kept > 1'000'000 || options.stream_lifetime < 60))
        return fail(Category::usage,
            "events: heartbeat 5 to 60 s, event_streams 1 or more, wait_limit 30 to 300 s (SPEC.md 18.4), "
            "events_kept 1 to 1000000, stream_lifetime 60 s or more");

    auto state = std::allocate_shared<ServerState>(
        std::pmr::polymorphic_allocator<ServerState>(allocator), allocator);
    state->library  = &library;
    state->clock    = &clock;
    state->random   = &random;
    state->accounts = options.accounts;
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
    state->require_auth      = options.require_auth;
    state->bound_only        = options.bound_only;
    state->skew              = options.skew;
    state->nonce_limit       = options.nonce_limit;
    state->verify.assign(options.verify);
    state->spki                = options.spki;
    state->token_lifetime      = options.token_lifetime;
    state->pairing_interval    = options.pairing_interval;
    state->pairing_expires     = options.pairing_expires;
    state->pairing_requests    = options.pairing_requests;
    state->pairing_window      = options.pairing_window;
    state->invitation_attempts = options.invitation_attempts;
    state->invitation_window   = options.invitation_window;
    state->saves               = options.saves;
    state->save_limits         = options.save_limits;
    state->encrypted_saves     = options.saves != nullptr && options.encrypted_saves;
    state->requests            = options.requests;
    state->sync                = options.sync;
    if (options.grant_seed)
    {
        state->peers          = true;
        state->grant_seed     = *options.grant_seed;
        state->grant_public   = ed25519_public_key(*options.grant_seed);
        state->grant_lifetime = options.grant_lifetime;
    }
    state->admin = options.accounts != nullptr && options.admin && options.accounts->administers();
    if (auto filled = random.fill(state->secret); !filled)
        return std::unexpected(filled.error());
    if (options.events)
    {
        // An event id does not outlive the process: its epoch is drawn now
        std::array<std::uint8_t, 6> epoch {};
        if (auto filled = random.fill(epoch); !filled)
            return std::unexpected(filled.error());
        state->events          = true;
        state->heartbeat       = options.heartbeat;
        state->event_streams   = options.event_streams;
        state->wait_limit      = options.wait_limit;
        state->stream_lifetime = options.stream_lifetime;
        base64url_encode(epoch, state->hub.epoch);
        state->hub.keep = options.events_kept;
        library.observe(state.get());
        state->observing = true;
    }
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
