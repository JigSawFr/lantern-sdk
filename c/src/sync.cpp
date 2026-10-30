// Sync (§ 20): consent, the collections, the merge rule, and the values of
// wishes and of what a device has installed.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/sync.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

Resource* resource_of(const lantern_client* client) noexcept
{
    return client->resource.get();
}

lantern::SyncItem item_of(const lantern_sync_item_input& input, lantern::Allocator allocator)
{
    lantern::SyncItem item(allocator);
    item.key     = text(input.key);
    item.value   = text(input.value);
    item.updated = text(input.updated);
    if (input.deleted)
        item.deleted = true;
    return item;
}

template <class T, class Out>
lantern_status give_value(Resource* resource, lantern::Result<T>&& read, Out** out, lantern_error* error)
{
    if (!read)
        return fail(error, read.error());
    *out = reinterpret_cast<Out*>(box_new<T>(resource, std::move(*read)));
    return ok(error);
}

const lantern::Installed* as_installed(const lantern_installed_value* value) noexcept
{
    return reinterpret_cast<const lantern::Installed*>(value);
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_client_set_sync_consent(
    lantern_client* client, const lantern_sync_consent* consent, const char* generation, lantern_error* error)
{
    if (client == nullptr || consent == nullptr)
        return usage(error, "a NULL argument");
    const lantern_sync_consent c = copy_struct(consent);
    lantern::SyncConsent settings;
    settings.sync      = c.sync;
    settings.installed = c.installed;
    const auto set     = client->client.set_sync_consent(settings, text(generation));
    if (!set)
        return fail(error, set.error());
    return ok(error);
}

LANTERN_API void lantern_client_get_sync_consent(const lantern_client* client, lantern_sync_consent* out)
{
    if (out == nullptr)
        return;
    lantern_sync_consent result {};
    result.struct_size = sizeof(result);
    if (client != nullptr)
    {
        result.sync      = client->client.sync_consent().sync;
        result.installed = client->client.sync_consent().installed;
    }
    give_struct(result, out);
}

LANTERN_API lantern_str lantern_client_sync_generation(const lantern_client* client)
{
    if (client == nullptr)
        return empty_str();
    // A view of the client's whole String: NUL-terminated
    const std::string_view generation = client->client.sync_generation();
    return generation.empty() ? empty_str() : lantern_str { generation.data(), generation.size() };
}

LANTERN_API lantern_status lantern_client_sync_state(
    lantern_client* client, lantern_sync_state** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const lantern_status status
        = give_read<lantern::SyncState>(resource_of(client), client->client.sync_state(), out, error);
    if (status >= 0)
        ok(error);
    return status;
}

LANTERN_API lantern_status lantern_client_sync_items(lantern_client* client, const char* collection,
    bool has_since, uint64_t since, const lantern_page_query* page, lantern_sync_collection** out,
    lantern_error* error)
{
    if (client == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                       = nullptr;
    const lantern_page_query p = copy_struct(page);
    lantern::PageQuery query;
    if (p.page_size != 0)
        query.page_size = p.page_size;
    query.cursor                = text(p.cursor);
    const lantern_status status = give_read<lantern::SyncCollection>(resource_of(client),
        client->client.sync_items(
            text(collection), has_since ? std::optional<std::uint64_t>(since) : std::nullopt, query),
        out, error);
    if (status >= 0)
        ok(error);
    return status;
}

LANTERN_API lantern_status lantern_client_sync_write(lantern_client* client, const char* collection,
    const lantern_sync_item_input* items, size_t count, bool has_if_match, uint64_t if_match,
    lantern_sync_collection** out, lantern_error* error)
{
    if (client == nullptr || out == nullptr || (items == nullptr && count != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const lantern::Allocator allocator(resource_of(client));
    lantern::Vector<lantern::SyncItem> list(allocator);
    list.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
        list.push_back(item_of(items[i], allocator));
    const lantern_status status = give_read<lantern::SyncCollection>(resource_of(client),
        client->client.sync_write(
            text(collection), list, has_if_match ? std::optional<std::uint64_t>(if_match) : std::nullopt),
        out, error);
    if (status >= 0)
        ok(error);
    return status;
}

LANTERN_API lantern_status lantern_client_sync_delete(
    lantern_client* client, const char* collection, lantern_error* error)
{
    if (client == nullptr)
        return usage(error, "client is NULL");
    const auto deleted = client->client.sync_delete(text(collection));
    if (!deleted)
        return fail(error, deleted.error());
    return ok(error);
}

LANTERN_API bool lantern_is_sync_collection(const char* name)
{
    return lantern::is_sync_collection(text(name));
}

LANTERN_API bool lantern_parse_sync_time(const char* value, int64_t* milliseconds)
{
    const auto parsed = lantern::parse_sync_time(text(value));
    if (!parsed)
        return false;
    if (milliseconds != nullptr)
        *milliseconds = *parsed;
    return true;
}

LANTERN_API void lantern_format_sync_time(int64_t milliseconds, char out[32])
{
    if (out == nullptr)
        return;
    lantern::String written { lantern::Allocator(Resource::standard()) };
    lantern::format_sync_time(milliseconds, written);
    copy_text(written, out, 32);
}

LANTERN_API lantern_status lantern_canonical_json(const char* json, size_t size,
    const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (out == nullptr || (json == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto canonical = lantern::canonical_json(
        std::string_view(json == nullptr ? "" : json, size), lantern::Allocator(resource.get()));
    if (!canonical)
        return fail(error, canonical.error());
    *out = give_string(resource.get(), std::move(*canonical));
    return ok(error);
}

LANTERN_API lantern_status lantern_sync_merge_items(const lantern_sync_item_input* have,
    const lantern_sync_item_input* sent, int64_t now, int64_t skew, lantern_sync_merge* out,
    lantern_error* error)
{
    if (sent == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    const lantern::Allocator allocator(Resource::standard());
    const lantern::SyncItem sent_item = item_of(*sent, allocator);
    std::optional<lantern::SyncItem> kept;
    if (have != nullptr)
        kept.emplace(item_of(*have, allocator));
    const auto merged = lantern::sync_merge(kept ? &*kept : nullptr, sent_item, now, skew, allocator);
    if (!merged)
        return fail(error, merged.error());
    lantern_sync_merge result {};
    result.struct_size = sizeof(result);
    result.replaced    = merged->replaced;
    result.updated     = merged->updated;
    give_struct(result, out);
    return ok(error);
}

LANTERN_API lantern_status lantern_write_wish(const lantern_wish_input* wish,
    const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (wish == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    const lantern_wish_input w = copy_struct(wish);
    const lantern::Allocator memory(resource.get());
    lantern::Wish value(memory);
    value.platform = text(w.platform);
    value.title_id = text(w.title_id);
    value.name     = text(w.name);
    value.note     = text(w.note);
    lantern::String json(memory);
    lantern::write_wish(value, json);
    *out = give_string(resource.get(), std::move(json));
    return ok(error);
}

LANTERN_API lantern_status lantern_read_wish(const char* value, size_t size,
    const lantern_allocator* allocator, lantern_wish** out, lantern_error* error)
{
    if (out == nullptr || (value == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    return give_value(resource.get(),
        lantern::read_wish(
            std::string_view(value == nullptr ? "" : value, size), decode_options(nullptr, resource.get())),
        out, error);
}

LANTERN_API lantern_status lantern_wish_key(const char* platform, const char* title_id,
    const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto key = lantern::wish_key(text(platform), text(title_id), lantern::Allocator(resource.get()));
    if (!key)
        return fail(error, key.error());
    *out = give_string(resource.get(), std::move(*key));
    return ok(error);
}

LANTERN_API lantern_status lantern_write_installed(const lantern_installed_input* installed,
    const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (installed == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                             = nullptr;
    const lantern_installed_input in = copy_struct(installed);
    if ((in.apps == nullptr && in.app_count != 0) || (in.homebrew == nullptr && in.homebrew_count != 0))
        return usage(error, "a NULL array with items");
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    const lantern::Allocator memory(resource.get());
    lantern::Installed value(memory);
    value.device   = text(in.device);
    value.platform = text(in.platform);
    value.apps.reserve(in.app_count);
    for (std::size_t i = 0; i < in.app_count; ++i)
    {
        value.apps.emplace_back();
        value.apps.back().app_id       = text(in.apps[i].app_id);
        value.apps.back().version_code = in.apps[i].version_code;
    }
    value.homebrew.reserve(in.homebrew_count);
    for (std::size_t i = 0; i < in.homebrew_count; ++i)
    {
        value.homebrew.emplace_back();
        value.homebrew.back().id    = text(in.homebrew[i].id);
        value.homebrew.back().build = in.homebrew[i].build;
    }
    lantern::String json(memory);
    lantern::write_installed(value, json);
    *out = give_string(resource.get(), std::move(json));
    return ok(error);
}

LANTERN_API lantern_status lantern_read_installed(const char* value, size_t size,
    const lantern_allocator* allocator, lantern_installed_value** out, lantern_error* error)
{
    if (out == nullptr || (value == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    return give_value(resource.get(),
        lantern::read_installed(
            std::string_view(value == nullptr ? "" : value, size), decode_options(nullptr, resource.get())),
        out, error);
}

LANTERN_API void lantern_installed_value_free(lantern_installed_value* installed)
{
    unbox(reinterpret_cast<lantern::Installed*>(installed));
}

LANTERN_API lantern_str lantern_installed_value_get_device(const lantern_installed_value* installed)
{
    return installed == nullptr ? empty_str() : view(as_installed(installed)->device);
}

LANTERN_API lantern_str lantern_installed_value_get_platform(const lantern_installed_value* installed)
{
    return installed == nullptr ? empty_str() : view(as_installed(installed)->platform);
}

LANTERN_API size_t lantern_installed_value_get_app_count(const lantern_installed_value* installed)
{
    return installed == nullptr ? 0 : as_installed(installed)->apps.size();
}

LANTERN_API bool lantern_installed_value_get_app(
    const lantern_installed_value* installed, size_t index, lantern_installed_app* out)
{
    if (installed == nullptr || out == nullptr || index >= as_installed(installed)->apps.size())
        return false;
    const lantern::InstalledApp& app = as_installed(installed)->apps[index];
    out->app_id                      = app.app_id.c_str();
    out->version_code                = app.version_code;
    return true;
}

LANTERN_API size_t lantern_installed_value_get_homebrew_count(const lantern_installed_value* installed)
{
    return installed == nullptr ? 0 : as_installed(installed)->homebrew.size();
}

LANTERN_API bool lantern_installed_value_get_homebrew(
    const lantern_installed_value* installed, size_t index, lantern_installed_homebrew* out)
{
    if (installed == nullptr || out == nullptr || index >= as_installed(installed)->homebrew.size())
        return false;
    const lantern::InstalledHomebrew& entry = as_installed(installed)->homebrew[index];
    out->id                                 = entry.id.c_str();
    out->build                              = entry.build;
    return true;
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
