// The routes of the library's other families (SPEC.md § 6.4, § 6.5, § 7):
// changes, sections, and the titles with their changes.
#include <algorithm>

#include <lantern/profiles.hpp>

#include "server_internal.hpp"

namespace lantern::detail
{

namespace
{

// § 7.2: the most ids one request asks for.
constexpr std::size_t max_titles_at_once = 100;

std::string_view languages_of(const ServerRequest& request) noexcept
{
    return request.header("Accept-Language").value_or(std::string_view {});
}

void write_text_member(json::Writer& w, std::string_view name, std::string_view text)
{
    if (text.empty())
        return;
    w.key(name);
    w.string(text);
}

void write_words_member(json::Writer& w, std::string_view name, const Vector<String>& words)
{
    if (words.empty())
        return;
    w.key(name);
    w.begin_array();
    for (const String& word : words)
        w.string(word);
    w.end_array();
}

void write_players_member(json::Writer& w, const TitlePlayers& players)
{
    w.key("players");
    w.begin_object();
    if (players.min)
    {
        w.key("min");
        w.number(*players.min);
    }
    if (players.max)
    {
        w.key("max");
        w.number(*players.max);
    }
    if (players.online)
    {
        w.key("online");
        w.boolean(*players.online);
    }
    if (players.online_max)
    {
        w.key("online_max");
        w.number(*players.online_max);
    }
    w.end_object();
}

// A title's members (§ 7.1), in an object the caller has opened.
void write_title_members(json::Writer& w, const Title& title)
{
    w.key("platform");
    w.string(title.platform);
    w.key("title_id");
    w.string(title.title_id);
    write_text_member(w, "language", title.language);
    w.key("name");
    w.string(title.name);
    write_text_member(w, "publisher", title.publisher);
    write_text_member(w, "developer", title.developer);
    write_text_member(w, "release", title.release);
    write_text_member(w, "updated", title.updated);
    write_text_member(w, "atlas", title.atlas);
    write_words_member(w, "genres", title.genres);
    write_words_member(w, "tags", title.tags);
    if (title.players)
        write_players_member(w, *title.players);
    if (!title.ratings.empty())
    {
        w.key("ratings");
        write_ratings(w, title.ratings);
    }
    write_words_member(w, "languages", title.languages);
    write_text_member(w, "summary", title.summary);
    write_text_member(w, "description", title.description);
    if (title.icon)
    {
        w.key("icon");
        write_image_object(w, *title.icon);
    }
    if (title.banner)
    {
        w.key("banner");
        write_image_object(w, *title.banner);
    }
    if (!title.screenshots.empty())
    {
        w.key("screenshots");
        w.begin_array();
        for (const Image& image : title.screenshots)
            write_image_object(w, image);
        w.end_array();
    }
    if (title.video)
    {
        w.key("video");
        w.begin_object();
        w.key("url");
        w.string(title.video->url);
        w.key("external");
        w.boolean(title.video->external);
        w.end_object();
    }
}

void write_title_object(json::Writer& w, const Title& title)
{
    w.begin_object();
    write_title_members(w, title);
    w.end_object();
}

bool title_before(const Title* a, const Title* b) noexcept
{
    return a->platform != b->platform ? a->platform < b->platform : a->title_id < b->title_id;
}

} // namespace

void write_image_object(json::Writer& w, const Image& image)
{
    w.begin_object();
    w.key("url");
    w.string(image.url);
    if (image.width)
    {
        w.key("width");
        w.number(*image.width);
    }
    if (image.height)
    {
        w.key("height");
        w.number(*image.height);
    }
    if (image.sha256)
    {
        w.key("sha256");
        const auto hex = to_hex(*image.sha256);
        w.string(std::string_view(hex.data(), hex.size()));
    }
    if (image.external)
    {
        w.key("external");
        w.boolean(*image.external);
    }
    w.end_object();
}

void write_ratings(json::Writer& w, const Vector<Rating>& ratings)
{
    w.begin_array();
    for (const Rating& rating : ratings)
    {
        w.begin_object();
        w.key("system");
        w.string(rating.system);
        w.key("rating");
        w.string(rating.rating);
        w.end_object();
    }
    w.end_array();
}

Answer changes_route(const ServerState& state, const ServerRequest& request)
{
    Journal* journal = state.library->journal();
    if (journal == nullptr)
        return std::unexpected(not_found(state, "This server does not offer it."));
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const auto now = journal->position(state.allocator);
    if (!now)
        return std::unexpected(internal_error(state));

    AppChanges changes(state.allocator);
    if (const auto since = request.param("since"))
    {
        const auto after = open_since(state, 's', *since, *now);
        if (!after)
            return std::unexpected(after.error());
        auto found = journal->app_changes(*after, platform->value_or(std::string_view {}), state.allocator);
        if (!found)
            return std::unexpected(internal_error(state));
        changes = std::move(*found);
    }
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("added");
    w.begin_array();
    for (const App& app : changes.added)
        write_app_json(w, app);
    w.end_array();
    w.key("removed");
    w.begin_array();
    for (const String& id : changes.removed)
        w.string(id);
    w.end_array();
    w.key("since");
    w.string(seal_since(state, 's', now->epoch, now->position));
    w.end_object();
    return json_response(state, request, std::move(out));
}

Answer titles_route(const ServerState& state, const ServerRequest& request)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    // The ids asked for, each once, in the order they came
    Vector<std::string_view> ids(state.allocator);
    std::size_t asked        = 0;
    std::string_view pending = request.param("ids").value_or(std::string_view {});
    while (!pending.empty())
    {
        const std::size_t comma   = pending.find(',');
        const std::string_view id = pending.substr(0, comma);
        pending = comma == std::string_view::npos ? std::string_view {} : pending.substr(comma + 1);
        if (id.empty())
            continue;
        if (++asked > max_titles_at_once)
            return std::unexpected(bad_request(state, "At most 100 ids at once."));
        if (!is_core_id(id))
            return std::unexpected(
                bad_request(state, "A title id is 1 to 128 letters, digits, '.', '_' and '-'."));
        if (!std::ranges::contains(ids, id))
            ids.push_back(id);
    }
    if (ids.empty())
        return std::unexpected(bad_request(state, "ids lists the title ids, comma-separated."));

    auto all = state.library->titles(languages_of(request), state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    Vector<const Title*> chosen(state.allocator);
    for (const Title& title : *all)
    {
        if ((!platform->has_value() || title.platform == **platform)
            && std::ranges::contains(ids, std::string_view(title.title_id)))
            chosen.push_back(&title);
    }
    std::ranges::sort(chosen, title_before);

    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("titles");
    w.begin_array();
    for (const Title* title : chosen)
        write_title_object(w, *title);
    w.end_array();
    w.key("unknown");
    w.begin_array();
    for (const std::string_view id : ids)
    {
        const bool known
            = std::ranges::any_of(chosen, [&](const Title* title) { return title->title_id == id; });
        if (!known)
            w.string(id);
    }
    w.end_array();
    w.end_object();
    return json_response(state, request, std::move(out));
}

Answer title_route(const ServerState& state, const ServerRequest& request, std::string_view title_id)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    auto all = state.library->titles(languages_of(request), state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    const Title* found = nullptr;
    for (const Title& title : *all)
    {
        if (title.title_id != title_id || (platform->has_value() && title.platform != **platform))
            continue;
        if (found != nullptr)
            return std::unexpected(
                bad_request(state, "Several platforms have it: name one (Lantern-Platform)."));
        found = &title;
    }
    if (found == nullptr)
        return std::unexpected(not_found(state, "No such title on this server."));
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_title_members(w, *found);
    w.end_object();
    return json_response(state, request, std::move(out));
}

Answer title_changes_route(const ServerState& state, const ServerRequest& request)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const auto since = request.param("since");
    Journal* journal = state.library->journal();

    TitleDelta delta(state.allocator);
    String epoch(state.allocator);
    std::uint64_t position = 0;
    if (journal == nullptr)
    {
        // No journal: no token can be old enough or new enough (§ 6.4)
        if (since)
            return std::unexpected(gone(state, "This server keeps no journal: read the titles again."));
    }
    else
    {
        const auto now = journal->position(state.allocator);
        if (!now)
            return std::unexpected(internal_error(state));
        epoch    = now->epoch;
        position = now->position;
        if (since)
        {
            const auto after = open_since(state, 't', *since, *now);
            if (!after)
                return std::unexpected(after.error());
            auto found = journal->title_changes(
                *after, platform->value_or(std::string_view {}), languages_of(request), state.allocator);
            if (!found)
                return std::unexpected(internal_error(state));
            delta = std::move(*found);
        }
    }
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("titles");
    w.begin_array();
    for (const Title& title : delta.titles)
        write_title_object(w, title);
    w.end_array();
    w.key("removed");
    w.begin_array();
    for (const RemovedTitle& gone_title : delta.removed)
    {
        w.begin_object();
        w.key("platform");
        w.string(gone_title.platform);
        w.key("title_id");
        w.string(gone_title.title_id);
        w.end_object();
    }
    w.end_array();
    w.key("since");
    w.string(seal_since(state, 't', epoch, position));
    w.key("more");
    w.boolean(delta.more);
    w.end_object();
    return json_response(state, request, std::move(out));
}

Answer sections_route(const ServerState& state, const ServerRequest& request)
{
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    AppsFilter filter;
    filter.platform = platform->value_or(std::string_view {});
    auto apps       = state.library->apps(filter, state.allocator);
    if (!apps)
        return std::unexpected(internal_error(state));
    auto sections = state.library->sections(languages_of(request), state.allocator);
    if (!sections)
        return std::unexpected(internal_error(state));

    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("sections");
    w.begin_array();
    for (const Section& section : *sections)
    {
        // The apps this caller sees, each once; a shelf of none is left out
        Vector<std::string_view> ids(state.allocator);
        for (const String& id : section.apps)
        {
            if (std::ranges::contains(ids, std::string_view(id)))
                continue;
            for (const App& app : *apps)
            {
                if (app.id == id && (!platform->has_value() || app.platform == **platform))
                {
                    ids.push_back(id);
                    break;
                }
            }
        }
        if (ids.empty())
            continue;
        w.begin_object();
        w.key("id");
        w.string(section.id);
        w.key("title");
        w.string(section.title);
        w.key("apps");
        w.begin_array();
        for (const std::string_view id : ids)
            w.string(id);
        w.end_array();
        w.end_object();
    }
    w.end_array();
    w.end_object();
    return json_response(state, request, std::move(out));
}

} // namespace lantern::detail
