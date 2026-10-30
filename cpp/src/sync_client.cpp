// Sync (SPEC.md § 20), a client's side: consent first, the generation kept,
// writes merged by § 20.4's rule or all or nothing with If-Match.
#include <lantern/client.hpp>

#include "client_internal.hpp"

#include <array>
#include <charconv>

namespace lantern
{

using detail::add_query;
using detail::bytes_of;
using detail::header_value;

namespace
{

constexpr std::size_t max_items      = 1000;
constexpr std::size_t max_generation = 128;

} // namespace

Result<void> Client::set_sync_consent(const SyncConsent& consent, std::string_view generation)
{
    if (generation.size() > max_generation || !header_value(generation) || generation.contains('"'))
        return fail(Category::usage, "a sync generation of 128 printable characters at most");
    sync_consent_ = consent;
    // L-20.1-2: what is installed only with sync itself on
    if (!sync_consent_.sync)
        sync_consent_.installed = false;
    sync_generation_.assign(generation);
    return {};
}

Result<void> Client::sync_ready(std::string_view collection, bool writing) const
{
    if (auto ok = ready(Family::sync); !ok)
        return ok;
    if (!sync_consent_.sync)
        return fail(Category::refused, "sync needs its user's consent first (SPEC.md 20.1)");
    if (!collection.empty() && !is_sync_collection(collection))
        return fail(Category::usage, "not a sync collection's name (SPEC.md 20.2)");
    if (writing && collection == sync_installed && !sync_consent_.installed)
        return fail(Category::refused,
            "what this console has installed needs its user's consent by name (SPEC.md 20.1)");
    return {};
}

Result<void> Client::sync_generation_seen(std::string_view generation)
{
    if (sync_generation_.empty())
    {
        if (generation.size() > max_generation || !header_value(generation) || generation.contains('"'))
            return fail(Category::invalid_response, "a sync generation not of SPEC.md 20.3's form");
        sync_generation_.assign(generation);
        return {};
    }
    if (generation == sync_generation_)
        return {};
    // L-20.3-2: the data was deleted; nothing of the copy goes back
    sync_consent_ = SyncConsent {};
    sync_generation_.clear();
    sync_device_.clear();
    return fail(Category::refused,
        "the account's sync data was deleted: sync is off until its user agrees again (SPEC.md 20.3)");
}

Read<SyncState> Client::sync_state()
{
    if (auto ok = sync_ready({}, false); !ok)
        return std::unexpected(ok.error());
    auto url      = api_url("/sync");
    auto read_one = read<SyncState>(Method::get, *url, read_sync_state);
    if (!read_one || !*read_one)
        return read_one;
    if (auto seen = sync_generation_seen((*read_one)->generation); !seen)
        return std::unexpected(seen.error());
    sync_device_.assign((*read_one)->device);
    return read_one;
}

Read<SyncCollection> Client::sync_items(
    std::string_view collection, std::optional<std::uint64_t> since, const PageQuery& page)
{
    if (auto ok = sync_ready(collection, false); !ok)
        return std::unexpected(ok.error());
    if (collection.empty())
        return fail(Category::usage, "a sync collection's name");
    auto url = api_url("/sync/");
    url->append(collection);
    bool first = true;
    if (since)
    {
        std::array<char, 24> digits {};
        auto* const end = std::to_chars(digits.data(), digits.data() + digits.size(), *since).ptr;
        add_query(*url, first, "since",
            std::string_view(digits.data(), static_cast<std::size_t>(end - digits.data())));
    }
    add_query(*url, first, "page_size", page.page_size);
    add_query(*url, first, "cursor", page.cursor);
    auto read_one = read<SyncCollection>(Method::get, *url, read_sync_collection);
    if (!read_one || !*read_one)
        return read_one;
    if (auto seen = sync_generation_seen((*read_one)->generation); !seen)
        return std::unexpected(seen.error());
    return read_one;
}

Read<SyncCollection> Client::sync_write(
    std::string_view collection, std::span<const SyncItem> items, std::optional<std::uint64_t> if_match)
{
    if (auto ok = sync_ready(collection, true); !ok)
        return std::unexpected(ok.error());
    if (collection.empty())
        return fail(Category::usage, "a sync collection's name");
    if (items.empty() || items.size() > max_items)
        return fail(Category::usage, "a sync write of 1 to 1000 items (SPEC.md 13)");
    if (sync_generation_.empty())
        return fail(
            Category::usage, "read the account's sync (its generation) before writing (SPEC.md 20.3)");
    SyncWrite write(allocator_);
    write.generation.assign(sync_generation_);
    write.items.reserve(items.size());
    for (const SyncItem& item : items)
    {
        const bool deleted = item.deleted.value_or(false);
        if (item.key.empty() || item.key.size() > 512 || !parse_sync_time(item.updated)
            || deleted == !item.value.empty())
            return fail(
                Category::usage, "an item is a key, a value or a deletion, and a sync time (SPEC.md 20.2)");
        // L-20.4-5: a device writes its own item of `installed` only
        if (collection == sync_installed && (sync_device_.empty() || item.key != sync_device_))
            return fail(
                Category::usage, "a device writes its own item of installed only: read sync_state() first");
        write.items.emplace_back(item);
        write.items.back().rev.reset(); // the server gives it
    }
    auto url = api_url("/sync/");
    url->append(collection);
    String body(allocator_);
    write_sync_write(write, body);
    String match(allocator_);
    std::array<Header, 1> extra {};
    std::size_t extras = 0;
    if (if_match)
    {
        std::array<char, 24> digits {};
        auto* const end = std::to_chars(digits.data(), digits.data() + digits.size(), *if_match).ptr;
        match.push_back('"');
        match.append(sync_generation_);
        match.push_back('-');
        match.append(digits.data(), end);
        match.push_back('"');
        extra[extras++] = { "If-Match", match };
    }
    Call call;
    call.method   = Method::patch;
    call.url      = *url;
    call.body     = bytes_of(body);
    call.extra    = std::span(extra.data(), extras);
    auto read_one = read<SyncCollection>(call, read_sync_collection);
    if (!read_one)
    {
        // L-20.4-4: another generation: the data was deleted since
        if (read_one.error().status() == 409 && read_one.error().effective_code() == Code::conflict)
        {
            sync_consent_ = SyncConsent {};
            sync_generation_.clear();
            sync_device_.clear();
        }
        return read_one;
    }
    if (*read_one)
    {
        if (auto seen = sync_generation_seen((*read_one)->generation); !seen)
            return std::unexpected(seen.error());
    }
    return read_one;
}

Result<void> Client::sync_delete(std::string_view collection)
{
    if (auto ok = sync_ready(collection, false); !ok)
        return ok;
    auto url = api_url("/sync");
    if (!collection.empty())
    {
        url->push_back('/');
        url->append(collection);
    }
    Call call;
    call.method = Method::delete_;
    call.url    = *url;
    if (auto done = expect(call); !done)
        return std::unexpected(done.error());
    // § 20.5: a new generation; the next read takes it
    sync_generation_.clear();
    return {};
}

} // namespace lantern
