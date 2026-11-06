// The requests for games (SPEC.md § 11): the account's own, asking and
// withdrawing, and the admin's side of them (§ 5.7), listing every account's
// and deciding an open one. `done` and `declined` are final (L-11-3).
#include <algorithm>
#include <array>
#include <limits>

#include <lantern/document.hpp>
#include <lantern/encoding.hpp>
#include <lantern/profiles.hpp>
#include <lantern/requests.hpp>

#include "server_internal.hpp"

namespace lantern
{

namespace
{

using detail::Answer;
using detail::Caller;
using detail::ProblemError;
using detail::ServerState;

// Open requests an account may hold at once.
constexpr std::size_t open_limit = 1000;
constexpr std::size_t id_bytes   = 9;

bool is_status(std::string_view text) noexcept
{
    return text == "open" || text == "done" || text == "declined";
}

// A request as listed (§ 11), in an object the caller has opened; `with_user` for the admin's listing.
void write_request_members(
    json::Writer& w, const StoredRequest& item, const Allocator& allocator, bool with_user)
{
    w.key("id");
    w.string(item.id);
    w.key("platform");
    w.string(item.platform);
    w.key("title_id");
    w.string(item.title_id);
    if (!item.name.empty())
    {
        w.key("name");
        w.string(item.name);
    }
    w.key("status");
    w.string(item.status);
    w.key("created");
    w.string(detail::utc_text(item.created, allocator));
    w.key("updated");
    w.string(detail::utc_text(item.updated, allocator));
    if (item.status == "declined" && !item.reason.empty())
    {
        w.key("reason");
        w.string(item.reason);
    }
    if (with_user)
    {
        w.key("user");
        w.string(item.user);
    }
}

// The order of a listing: newest first, the later made first among those of one second.
detail::SortKey newest_first(const StoredRequest& item, std::size_t position, const Allocator& allocator)
{
    detail::SortKey key(allocator);
    key.major = -item.created;
    // Fixed width, so that the text sorts as the number does
    const String text = detail::number_text(std::numeric_limits<std::uint64_t>::max() - position, allocator);
    key.minor.assign(20 - text.size(), '0');
    key.minor.append(text);
    key.id.assign(item.id);
    return key;
}

// A title's name, from the library's titles, else its apps; empty when it knows none.
std::expected<String, ProblemError> title_name(
    const ServerState& state, std::string_view platform, std::string_view title_id)
{
    String name(state.allocator);
    if (state.library->offers_titles())
    {
        auto titles = state.library->titles({}, state.allocator);
        if (!titles)
            return std::unexpected(detail::internal_error(state));
        for (const Title& title : *titles)
        {
            if (title.platform == platform && title.title_id == title_id)
                return String(title.name, state.allocator);
        }
    }
    AppsFilter filter;
    filter.platform = platform;
    filter.title_id = title_id;
    auto apps       = state.library->apps(filter, state.allocator);
    if (!apps)
        return std::unexpected(detail::internal_error(state));
    for (const App& app : *apps)
    {
        if (app.platform == platform && app.title_id == title_id && !app.name.empty())
            return String(app.name, state.allocator);
    }
    return name;
}

ProblemError limit_reached(const ServerState& state)
{
    ProblemError error
        = detail::make_problem(state, 429, Code::slow_down, "At most 1000 open requests per account.");
    error.headers.set("Retry-After", "3600");
    return error;
}

} // namespace

namespace detail
{

Answer requests_route(const ServerState& state, const ServerRequest& request, const Caller& caller)
{
    if (request.method != "POST")
    {
        const auto platform = platform_param(state, request);
        if (!platform)
            return std::unexpected(platform.error());
        auto mine = state.requests->requests(caller.name, state.allocator);
        if (!mine)
            return std::unexpected(internal_error(state));
        Vector<std::size_t> order(state.allocator);
        for (std::size_t i = 0; i < mine->size(); ++i)
        {
            if (!platform->has_value() || (*mine)[i].platform == **platform)
                order.push_back(i);
        }
        // Newest first (§ 11)
        std::ranges::sort(order,
            [&](std::size_t a, std::size_t b)
            {
                const StoredRequest& x = (*mine)[a];
                const StoredRequest& y = (*mine)[b];
                return x.created != y.created ? x.created > y.created : a > b;
            });
        String out(state.allocator);
        json::Writer w(out);
        w.begin_object();
        w.key("schema");
        w.number(known_schema);
        w.key("requests");
        w.begin_array();
        for (const std::size_t i : order)
        {
            w.begin_object();
            write_request_members(w, (*mine)[i], state.allocator, false);
            w.end_object();
        }
        w.end_array();
        w.end_object();
        return json_response(state, request, std::move(out));
    }

    const auto prepared = request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<RequestCreate>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, RequestCreate& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(bad_request(state, "A request is {schema, platform?, title_id}."));
    const RequestCreate& doc  = **bound;
    std::string_view platform = doc.platform;
    if (platform.empty())
    {
        const auto named = platform_param(state, request);
        if (!named)
            return std::unexpected(named.error());
        const std::optional<std::string_view> header_platform = *named;
        if (!header_platform)
            return std::unexpected(
                bad_request(state, "Name a platform: Lantern-Platform or ?platform= (SPEC.md § 4.3)."));
        platform = *header_platform;
    }
    if (!is_platform_name(platform))
        return std::unexpected(bad_request(state, "platform is a platform's name (SPEC.md § 4.3)."));
    const Profile* profile = find_profile(platform);
    if (!is_served_platform(platform) || !is_core_id(doc.title_id)
        || (profile != nullptr && profile->title_id != nullptr && !profile->title_id(doc.title_id)))
    {
        String why("title_id is not a title id of ", state.allocator);
        why.append(platform);
        why.push_back('.');
        return std::unexpected(bad_request(state, why));
    }
    auto name = title_name(state, platform, doc.title_id);
    if (!name)
        return std::unexpected(std::move(name.error()));

    std::array<std::uint8_t, id_bytes> raw {};
    if (!state.random->fill(raw))
        return std::unexpected(internal_error(state));
    StoredRequest made(state.allocator);
    made.id.assign("r_");
    base64url_encode(raw, made.id);
    made.user     = caller.name;
    made.platform = platform;
    made.title_id = doc.title_id;
    made.name     = std::move(*name);
    made.status   = "open";
    made.created  = state.clock->unix_seconds();
    made.updated  = made.created;

    const std::scoped_lock lock(state.requests_mutex);
    auto mine = state.requests->requests(caller.name, state.allocator);
    if (!mine)
        return std::unexpected(internal_error(state));
    std::size_t open = 0;
    for (const StoredRequest& item : *mine)
    {
        if (item.status != "open")
            continue;
        ++open;
        if (item.platform == platform && item.title_id == doc.title_id)
        {
            // The same title asked again: the open request (§ 11, L-11-1)
            String out(state.allocator);
            json::Writer w(out);
            w.begin_object();
            w.key("schema");
            w.number(known_schema);
            write_request_members(w, item, state.allocator, false);
            w.end_object();
            return json_response(state, request, std::move(out), 200, false);
        }
    }
    if (open >= open_limit)
        return std::unexpected(limit_reached(state));
    if (auto added = state.requests->add(made); !added)
        return std::unexpected(internal_error(state));
    record_request_event(state, made, false);
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_request_members(w, made, state.allocator, false);
    w.end_object();
    return json_response(state, request, std::move(out), 201, false);
}

Answer request_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view id)
{
    const std::scoped_lock lock(state.requests_mutex);
    // What it was, for the event that tells it withdrawn
    auto before = state.requests->request(id, state.allocator);
    if (!before)
        return std::unexpected(internal_error(state));
    auto gone = state.requests->remove(caller.name, id, state.allocator);
    if (!gone)
        return std::unexpected(internal_error(state));
    // Whatever its status (L-11-2); another account's request is not found
    if (!*gone)
        return std::unexpected(not_found(state, "No such request of this account."));
    if (*before)
        record_request_event(state, **before, true);
    return no_content(state, request);
}

Answer admin_requests_route(const ServerState& state, const ServerRequest& request)
{
    const std::string_view status = request.param("status").value_or(std::string_view {});
    const std::string_view user   = request.param("user").value_or(std::string_view {});
    if (!status.empty() && !is_status(status))
        return std::unexpected(bad_request(state, "status is open, done or declined."));
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    auto all = state.requests->requests({}, state.allocator);
    if (!all)
        return std::unexpected(internal_error(state));
    Vector<const StoredRequest*> kept(state.allocator);
    Vector<SortKey> keys(state.allocator);
    for (std::size_t i = 0; i < all->size(); ++i)
    {
        const StoredRequest& item = (*all)[i];
        if ((!status.empty() && item.status != status) || (!user.empty() && item.user != user)
            || (platform->has_value() && item.platform != **platform))
            continue;
        kept.push_back(&item);
        keys.push_back(newest_first(item, i, state.allocator));
    }
    const std::array<std::string_view, 5> parts { "admin-requests", status, user,
        platform->has_value() ? "p" : "-", platform->value_or(std::string_view {}) };
    const auto window = page_window(state, request, keys, scope_of(parts, state.allocator));
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
    {
        w.begin_object();
        write_request_members(w, *kept[window->order[i]], state.allocator, true);
        w.end_object();
    }
    w.end_array();
    w.key("total");
    w.number(static_cast<std::uint64_t>(kept.size()));
    w.key("next");
    if (window->next.empty())
        w.null();
    else
        w.string(window->next);
    w.end_object();
    return json_response(state, request, std::move(out));
}

Answer admin_request_route(const ServerState& state, const ServerRequest& request, std::string_view id)
{
    const auto prepared = request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<AdminRequestDecision>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, AdminRequestDecision& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(bad_request(state, "A decision is {schema, decision, reason?}."));
    const AdminRequestDecision& doc = **bound;
    if ((doc.decision != "decline" && doc.decision != "done")
        || (doc.decision == "done" && !doc.reason.empty()))
        return std::unexpected(bad_request(
            state, "decision is decline (with a reason, if any) or done; a reason goes with decline only."));

    const std::scoped_lock lock(state.requests_mutex);
    auto found = state.requests->request(id, state.allocator);
    if (!found)
        return std::unexpected(internal_error(state));
    if (!*found)
        return std::unexpected(not_found(state, "No such request."));
    if ((*found)->status != "open")
    {
        String why("The request is ", state.allocator);
        why.append((*found)->status);
        why.append(": it is final.");
        return std::unexpected(make_problem(state, 409, Code::conflict, why));
    }
    StoredRequest decided((**found), state.allocator);
    decided.status  = doc.decision == "done" ? "done" : "declined";
    decided.reason  = doc.reason;
    decided.updated = state.clock->unix_seconds();
    const auto changed
        = state.requests->set_status(decided.id, decided.status, decided.reason, decided.updated);
    if (!changed)
        return std::unexpected(internal_error(state));
    if (!*changed)
        return std::unexpected(not_found(state, "No such request."));
    record_request_event(state, decided, false);
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    write_request_members(w, decided, state.allocator, true);
    w.end_object();
    return json_response(state, request, std::move(out), 200, false);
}

} // namespace detail

Result<std::size_t> Server::settle_requests() const
{
    const ServerState& state = *state_;
    if (state.requests == nullptr)
        return fail(Category::usage, "the server keeps no requests");
    const AppsFilter filter {};
    auto apps = state.library->apps(filter, state.allocator);
    if (!apps)
        return std::unexpected(apps.error());
    const std::scoped_lock lock(state.requests_mutex);
    auto all = state.requests->requests({}, state.allocator);
    if (!all)
        return std::unexpected(all.error());
    std::size_t settled    = 0;
    const std::int64_t now = state.clock->unix_seconds();
    for (const StoredRequest& item : *all)
    {
        if (item.status != "open")
            continue;
        const bool arrived = std::ranges::any_of(*apps,
            [&](const App& app) { return app.platform == item.platform && app.title_id == item.title_id; });
        if (!arrived)
            continue;
        const auto changed = state.requests->set_status(item.id, "done", {}, now);
        if (!changed)
            return std::unexpected(changed.error());
        if (*changed)
        {
            ++settled;
            StoredRequest done(item, state.allocator);
            done.status  = "done";
            done.updated = now;
            detail::record_request_event(state, done, false);
        }
    }
    return settled;
}

} // namespace lantern
