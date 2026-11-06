// MemoryRequestStore (requests.hpp): requests held in memory.
#include <lantern/requests.hpp>

#include <algorithm>

namespace lantern
{

MemoryRequestStore::MemoryRequestStore(const Allocator& allocator)
    : allocator_(allocator)
    , kept_(allocator)
{
}

Result<Vector<StoredRequest>> MemoryRequestStore::requests(std::string_view user, const Allocator& allocator)
{
    Vector<StoredRequest> out(allocator);
    const std::scoped_lock lock(mutex_);
    for (const StoredRequest& item : kept_)
    {
        if (user.empty() || item.user == user)
            out.emplace_back(item);
    }
    return out;
}

Result<std::optional<StoredRequest>> MemoryRequestStore::request(
    std::string_view id, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    for (const StoredRequest& item : kept_)
    {
        if (item.id == id)
            return std::optional<StoredRequest>(std::in_place, item, allocator);
    }
    return std::optional<StoredRequest> {};
}

Result<void> MemoryRequestStore::add(const StoredRequest& request)
{
    const std::scoped_lock lock(mutex_);
    kept_.emplace_back(request);
    return {};
}

Result<bool> MemoryRequestStore::set_status(
    std::string_view id, std::string_view status, std::string_view reason, std::int64_t updated)
{
    const std::scoped_lock lock(mutex_);
    for (StoredRequest& item : kept_)
    {
        if (item.id != id)
            continue;
        item.status.assign(status);
        item.reason.assign(reason);
        item.updated = updated;
        return true;
    }
    return false;
}

Result<std::optional<StoredRequest>> MemoryRequestStore::remove(
    std::string_view user, std::string_view id, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    for (auto it = kept_.begin(); it != kept_.end(); ++it)
    {
        if (it->id == id && it->user == user)
        {
            std::optional<StoredRequest> gone(std::in_place, *it, allocator);
            kept_.erase(it);
            return gone;
        }
    }
    return std::optional<StoredRequest> {};
}

Result<void> MemoryRequestStore::forget(std::string_view user)
{
    const std::scoped_lock lock(mutex_);
    std::erase_if(kept_, [&](const StoredRequest& item) { return item.user == user; });
    return {};
}

} // namespace lantern
