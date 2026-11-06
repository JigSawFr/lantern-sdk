// MemorySyncStore (sync_store.hpp): sync data held in memory.
#include <lantern/sync_store.hpp>

#include <algorithm>
#include <array>

#include <lantern/encoding.hpp>

namespace lantern
{

namespace
{

constexpr std::size_t generation_bytes = 9;

} // namespace

MemorySyncStore::MemorySyncStore(
    RandomSource& random, std::uint32_t item_limit, std::int64_t retention, const Allocator& allocator)
    : allocator_(allocator)
    , random_(&random)
    , limit_(item_limit)
    , retention_(retention)
    , accounts_(allocator)
{
}

Result<String> MemorySyncStore::fresh_generation()
{
    std::array<std::uint8_t, generation_bytes> raw {};
    if (auto filled = random_->fill(raw); !filled)
        return std::unexpected(filled.error());
    String out("g_", allocator_);
    base64url_encode(raw, out);
    return out;
}

Result<MemorySyncStore::Account*> MemorySyncStore::account(std::string_view user)
{
    const String key(user, allocator_);
    const auto found = accounts_.find(key);
    if (found != accounts_.end())
        return &found->second;
    auto generation = fresh_generation();
    if (!generation)
        return std::unexpected(generation.error());
    const auto at         = accounts_.try_emplace(key).first;
    at->second.generation = std::move(*generation);
    return &at->second;
}

void MemorySyncStore::purge(Collection& collection, std::int64_t now) const
{
    for (auto at = collection.items.begin(); at != collection.items.end();)
    {
        const SyncItem& item = at->second.item;
        if (item.deleted.value_or(false) && at->second.at + retention_ < now)
        {
            collection.floor = std::max<std::uint64_t>(collection.floor, item.rev.value_or(0));
            at               = collection.items.erase(at);
        }
        else
        {
            ++at;
        }
    }
}

Result<SyncOverview> MemorySyncStore::overview(
    std::string_view user, std::int64_t now, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    const auto held = account(user);
    if (!held)
        return std::unexpected(held.error());
    Account* const mine = *held;
    SyncOverview out(allocator);
    out.generation.assign(mine->generation);
    for (auto& [name, collection] : mine->collections)
    {
        purge(collection, now);
        SyncCollectionInfo info(allocator);
        info.name.assign(name);
        info.rev = collection.rev;
        for (const auto& [key, kept] : collection.items)
        {
            if (!kept.item.deleted.value_or(false))
                ++info.items;
        }
        out.collections.push_back(std::move(info));
    }
    return out;
}

Result<SyncSnapshot> MemorySyncStore::read(
    std::string_view user, std::string_view collection, std::int64_t now, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    const auto held = account(user);
    if (!held)
        return std::unexpected(held.error());
    Account* const mine = *held;
    SyncSnapshot out(allocator);
    out.generation.assign(mine->generation);
    const auto found = mine->collections.find(String(collection, allocator_));
    if (found == mine->collections.end())
        return out;
    purge(found->second, now);
    out.rev   = found->second.rev;
    out.floor = found->second.floor;
    out.items.reserve(found->second.items.size());
    for (const auto& [key, kept] : found->second.items)
        out.items.emplace_back(kept.item);
    return out;
}

Result<void> MemorySyncStore::write(std::string_view user, std::string_view collection,
    std::span<const SyncItem> items, std::uint64_t rev, std::int64_t now)
{
    const std::scoped_lock lock(mutex_);
    const auto held = account(user);
    if (!held)
        return std::unexpected(held.error());
    Account* const mine = *held;
    const auto at       = mine->collections.try_emplace(String(collection, allocator_)).first;
    Collection& kept    = at->second;
    for (const SyncItem& item : items)
    {
        const auto slot   = kept.items.try_emplace(String(item.key, allocator_)).first;
        slot->second.item = SyncItem(item, allocator_);
        slot->second.at   = now;
    }
    kept.rev = std::max(kept.rev, rev);
    return {};
}

Result<String> MemorySyncStore::erase(
    std::string_view user, std::string_view collection, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    const auto held = account(user);
    if (!held)
        return std::unexpected(held.error());
    Account* const mine = *held;
    if (collection.empty())
        mine->collections.clear();
    else
        mine->collections.erase(String(collection, allocator_));
    auto generation = fresh_generation();
    if (!generation)
        return std::unexpected(generation.error());
    mine->generation = *generation;
    return String(*generation, allocator);
}

Result<void> MemorySyncStore::forget(std::string_view user)
{
    const std::scoped_lock lock(mutex_);
    accounts_.erase(String(user, allocator_));
    return {};
}

} // namespace lantern
