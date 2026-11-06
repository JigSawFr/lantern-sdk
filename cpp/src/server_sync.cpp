// Sync (SPEC.md § 20): what the account keeps (the overview), a collection
// read whole or after a revision, written item by item by the merge rule, and
// erased. The collections of this version are `wishes` and `installed`.
#include <algorithm>
#include <array>
#include <charconv>
#include <unordered_map>

#include <lantern/document.hpp>
#include <lantern/profiles.hpp>
#include <lantern/sync.hpp>
#include <lantern/sync_store.hpp>

#include "server_internal.hpp"

namespace lantern
{

namespace
{

using detail::Answer;
using detail::Caller;
using detail::ProblemError;
using detail::ServerState;

constexpr std::array<std::string_view, 2> collections { sync_wishes, sync_installed };
// Items in one write (§ 13).
constexpr std::size_t write_limit = 1000;

bool is_device_id(std::string_view text) noexcept
{
    return text.size() == 18 && text.starts_with("d_")
        && std::ranges::all_of(
            text.substr(2), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

bool is_collection(std::string_view name) noexcept
{
    return std::ranges::any_of(collections, [&](std::string_view known) { return known == name; });
}

ProblemError no_such_collection(const ServerState& state)
{
    return detail::not_found(state, "No such collection: wishes, installed.");
}

// An item sent, of its collection's form (§ 20.2, § 20.4, L-20.4-6); 403 for another device's item of
// `installed` (L-20.4-5).
std::optional<ProblemError> check_item(const ServerState& state, const Caller& caller,
    std::string_view collection, const SyncItem& item, const DecodeOptions& options)
{
    const bool has_value                  = !item.value.empty();
    const std::optional<bool> deleted_now = item.deleted;
    if (item.rev)
        return detail::bad_request(
            state, "An item is {key, value, updated} or {key, deleted: true, updated} (SPEC.md § 20.2).");
    if (!parse_sync_time(item.updated))
        return detail::bad_request(
            state, "updated is a UTC time to the millisecond, such as 2026-10-30T09:12:03.250Z.");
    if (has_value == deleted_now.has_value() || (deleted_now && !*deleted_now))
        return detail::bad_request(state, "An item has a value, or deleted: true, not both.");
    if (collection == sync_wishes)
    {
        const std::size_t slash         = item.key.find('/');
        const std::string_view key      = item.key;
        const std::string_view platform = slash == std::string_view::npos ? key : key.substr(0, slash);
        const std::string_view title
            = slash == std::string_view::npos ? std::string_view {} : key.substr(slash + 1);
        if (!is_platform_name(platform) || !is_core_id(title))
            return detail::bad_request(state, "A wish's key is <platform>/<title_id> (SPEC.md § 20.2).");
        if (has_value)
        {
            const auto wish = read_wish(item.value, options);
            if (!wish || wish->platform != platform || wish->title_id != title)
                return detail::bad_request(
                    state, "A wish is {platform, title_id, name?, note?}, those of its key.");
        }
        return std::nullopt;
    }
    if (!is_device_id(item.key))
        return detail::bad_request(state, "An item of installed is keyed by its device's id, d_….");
    if (has_value && !read_installed(item.value, options))
        return detail::bad_request(state,
            "installed is {device, platform, apps: [{app_id, version_code}], homebrew: [{id, build}]} "
            "(SPEC.md § 20.2).");
    if (item.key != caller.device_id)
        return detail::make_problem(
            state, 403, Code::forbidden, "A device writes its own item of installed only (SPEC.md § 20.4).");
    return std::nullopt;
}

Answer overview_route(const ServerState& state, const ServerRequest& request, const Caller& caller)
{
    const auto overview = state.sync->overview(caller.name, state.clock->unix_seconds(), state.allocator);
    if (!overview)
        return std::unexpected(detail::internal_error(state));
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("generation");
    w.string(overview->generation);
    w.key("collections");
    w.begin_object();
    for (const std::string_view name : collections)
    {
        std::uint64_t rev   = 0;
        std::uint64_t items = 0;
        for (const SyncCollectionInfo& info : overview->collections)
        {
            if (info.name == name)
            {
                rev   = info.rev;
                items = info.items;
            }
        }
        w.key(name);
        w.begin_object();
        w.key("rev");
        w.number(rev);
        w.key("items");
        w.number(items);
        w.end_object();
    }
    w.end_object();
    if (is_device_id(caller.device_id))
    {
        w.key("device");
        w.string(caller.device_id);
    }
    w.end_object();
    return detail::json_response(state, request, std::move(out));
}

Answer erase_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view collection)
{
    {
        const std::scoped_lock lock(state.sync_mutex);
        if (auto erased = state.sync->erase(caller.name, collection, state.allocator); !erased)
            return std::unexpected(detail::internal_error(state));
    }
    if (collection.empty())
    {
        for (const std::string_view name : collections)
            detail::record_sync_event(state, caller.name, name, 0);
    }
    else
    {
        detail::record_sync_event(state, caller.name, collection, 0);
    }
    return detail::no_content(state, request);
}

Answer read_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view collection)
{
    std::string_view since_text;
    std::optional<std::uint64_t> since;
    if (const auto given = request.param("since"))
    {
        since_text          = *given;
        std::uint64_t value = 0;
        const auto parsed = std::from_chars(since_text.data(), since_text.data() + since_text.size(), value);
        if (parsed.ec != std::errc {} || parsed.ptr != since_text.data() + since_text.size())
            return std::unexpected(detail::bad_request(state, "since is a revision, an integer."));
        since = value;
    }
    const auto snapshot
        = state.sync->read(caller.name, collection, state.clock->unix_seconds(), state.allocator);
    if (!snapshot)
        return std::unexpected(detail::internal_error(state));
    if (since)
    {
        if (*since > snapshot->rev)
            return std::unexpected(
                detail::bad_request(state, "This revision was never given: read the collection whole."));
        if (*since < snapshot->floor)
            return std::unexpected(detail::gone(state, "Its deletions are gone: read the collection whole."));
    }
    Vector<const SyncItem*> kept(state.allocator);
    Vector<detail::SortKey> keys(state.allocator);
    for (const SyncItem& item : snapshot->items)
    {
        const bool shown = since ? item.rev.value_or(0) > *since : !item.deleted.value_or(false);
        if (!shown)
            continue;
        kept.push_back(&item);
        detail::SortKey key(state.allocator);
        key.major = since ? static_cast<std::int64_t>(item.rev.value_or(0)) : 0;
        key.id.assign(item.key);
        keys.push_back(std::move(key));
    }
    const std::array<std::string_view, 5> parts { "sync", caller.name, collection,
        since ? since_text : std::string_view { "-" }, snapshot->generation };
    const auto window = detail::page_window(state, request, keys, detail::scope_of(parts, state.allocator));
    if (!window)
        return std::unexpected(window.error());
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("collection");
    w.string(collection);
    w.key("generation");
    w.string(snapshot->generation);
    w.key("rev");
    w.number(snapshot->rev);
    w.key("items");
    w.begin_array();
    for (std::size_t i = window->from; i < window->from + window->count; ++i)
        write(w, *kept[window->order[i]]);
    w.end_array();
    w.key("next");
    if (window->next.empty())
        w.null();
    else
        w.string(window->next);
    w.end_object();
    return detail::json_response(state, request, std::move(out));
}

// The item as the server keeps it once it took `sent` (§ 20.4): its `updated` as kept, its revision.
SyncItem kept_item(const SyncItem& sent, std::int64_t updated, std::uint64_t rev, const Allocator& allocator)
{
    SyncItem out(sent, allocator);
    out.updated.clear();
    format_sync_time(updated, out.updated);
    out.rev = rev;
    if (!out.deleted.value_or(false))
        out.deleted.reset();
    return out;
}

Answer write_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view collection)
{
    const auto prepared = detail::request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<SyncWrite>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, SyncWrite& value) { return bind(c, value); });
    if (!bound || !*bound || (*bound)->items.empty() || (*bound)->items.size() > write_limit)
        return std::unexpected(
            detail::bad_request(state, "A write is {schema, generation, items}, 1 to 1000 items."));
    const SyncWrite& doc = **bound;
    for (const SyncItem& item : doc.items)
    {
        if (auto refused = check_item(state, caller, collection, item, prepared->options))
            return std::unexpected(std::move(*refused));
    }
    std::pmr::unordered_map<std::string_view, const SyncItem*> sent(state.allocator);
    for (const SyncItem& item : doc.items)
    {
        if (!sent.try_emplace(item.key, &item).second)
            return std::unexpected(detail::bad_request(state, "An item's key twice in one write."));
    }

    const std::int64_t now = state.clock->unix_seconds();
    std::uint64_t rev      = 0;
    std::uint64_t before   = 0;
    Vector<SyncItem> answers(state.allocator);
    String generation(state.allocator);
    {
        const std::scoped_lock lock(state.sync_mutex);
        const auto snapshot = state.sync->read(caller.name, collection, now, state.allocator);
        if (!snapshot)
            return std::unexpected(detail::internal_error(state));
        generation = snapshot->generation;
        before     = snapshot->rev;
        rev        = snapshot->rev;
        // L-20.4-4: the data was deleted since
        if (doc.generation != snapshot->generation)
            return std::unexpected(detail::make_problem(state, 409, Code::conflict,
                "This sync data was deleted since: ask the user again (SPEC.md § 20.3)."));
        // L-20.4-3: all or nothing
        if (const auto match = request.header("If-Match"))
        {
            String expected("\"", state.allocator);
            expected.append(snapshot->generation);
            expected.push_back('-');
            expected.append(detail::number_text(snapshot->rev, state.allocator));
            expected.push_back('"');
            if (detail::trim(*match) != expected)
                return std::unexpected(detail::make_problem(state, 412, Code::precondition_failed,
                    "The collection changed since it was read: read it again.", "Precondition failed"));
        }
        std::pmr::unordered_map<std::string_view, const SyncItem*> have(state.allocator);
        have.reserve(snapshot->items.size());
        for (const SyncItem& item : snapshot->items)
            have.try_emplace(item.key, &item);
        std::size_t fresh = 0;
        for (const SyncItem& item : doc.items)
        {
            if (!have.contains(item.key))
                ++fresh;
        }
        if (snapshot->items.size() + fresh > state.sync->item_limit())
        {
            String why("A collection holds ", state.allocator);
            why.append(detail::number_text(state.sync->item_limit(), state.allocator));
            why.append(" items at most here.");
            return std::unexpected(detail::make_problem(state, 413, Code::too_large, why));
        }
        Vector<SyncItem> changes(state.allocator);
        for (const SyncItem& item : doc.items)
        {
            const auto found      = have.find(item.key);
            const SyncItem* known = found == have.end() ? nullptr : found->second;
            const auto merged     = sync_merge(known, item, now * 1000, state.skew, state.allocator);
            if (!merged)
                return std::unexpected(detail::bad_request(state, "An item's value is not JSON."));
            if (merged->replaced)
            {
                ++rev;
                changes.push_back(kept_item(item, merged->updated, rev, state.allocator));
                answers.push_back(changes.back());
            }
            else if (known != nullptr)
            {
                // The item as the server has it; the merge keeps the one it has when it does not replace
                answers.emplace_back(*known);
            }
        }
        if (!changes.empty())
        {
            if (auto written = state.sync->write(caller.name, collection, changes, rev, now); !written)
                return std::unexpected(detail::internal_error(state));
        }
    }
    if (rev != before)
        detail::record_sync_event(state, caller.name, collection, rev);
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("collection");
    w.string(collection);
    w.key("generation");
    w.string(generation);
    w.key("rev");
    w.number(rev);
    w.key("items");
    w.begin_array();
    for (const SyncItem& item : answers)
        write(w, item);
    w.end_array();
    w.end_object();
    return detail::json_response(state, request, std::move(out), 200, false);
}

} // namespace

namespace detail
{

Answer sync_route(const ServerState& state, const ServerRequest& request, const Caller& caller,
    std::string_view collection, bool whole)
{
    const bool reading = request.method == "GET" || request.method == "HEAD";
    if (whole)
        return reading ? overview_route(state, request, caller) : erase_route(state, request, caller, {});
    if (!is_collection(collection))
        return std::unexpected(no_such_collection(state));
    if (reading)
        return read_route(state, request, caller, collection);
    if (request.method == "PATCH")
        return write_route(state, request, caller, collection);
    return erase_route(state, request, caller, collection);
}

Result<void> forget_sync(const ServerState& state, std::string_view user)
{
    if (state.sync == nullptr)
        return {};
    const std::scoped_lock lock(state.sync_mutex);
    return state.sync->forget(user);
}

} // namespace detail

} // namespace lantern
