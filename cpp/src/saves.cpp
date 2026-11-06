// MemorySaveStore (saves.hpp): save backups and uploads held in memory.
#include <lantern/saves.hpp>

#include <algorithm>
#include <cstddef>

namespace lantern
{

MemorySaveStore::MemorySaveStore(const Allocator& allocator)
    : allocator_(allocator)
    , kept_(allocator)
    , parts_(allocator)
{
}

MemorySaveStore::Part* MemorySaveStore::find_part(std::string_view id)
{
    for (Part& part : parts_)
    {
        if (part.upload.id == id)
            return &part;
    }
    return nullptr;
}

Result<Vector<Save>> MemorySaveStore::saves(std::string_view user, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    Vector<Save> out(allocator);
    for (const Kept& item : kept_)
    {
        if (item.user == user)
            out.push_back(item.save);
    }
    return out;
}

Result<std::optional<LibraryFile>> MemorySaveStore::archive(
    std::string_view user, std::string_view save_id, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    for (const Kept& item : kept_)
    {
        if (item.user != user || item.save.save_id != save_id)
            continue;
        LibraryFile file(allocator);
        file.size   = item.save.size;
        file.sha256 = item.save.sha256;
        file.content_type.assign(item.save.encryption ? "application/octet-stream" : "application/zip");
        file.reader = item.reader;
        return std::optional<LibraryFile>(std::move(file));
    }
    return std::optional<LibraryFile> {};
}

Result<bool> MemorySaveStore::drop(std::string_view user, std::string_view save_id)
{
    const std::scoped_lock lock(mutex_);
    const Kept* found = nullptr;
    for (const Kept& item : kept_)
    {
        if (item.user == user && item.save.save_id == save_id)
            found = &item;
    }
    if (found == nullptr)
        return false;
    kept_.erase(kept_.begin() + (found - kept_.data()));
    return true;
}

Result<void> MemorySaveStore::open_upload(const StoredUpload& upload)
{
    const std::scoped_lock lock(mutex_);
    if (find_part(upload.id) != nullptr)
        return fail(Category::storage, "that upload exists");
    StoredUpload mine(allocator_);
    mine.id.assign(upload.id);
    mine.user.assign(upload.user);
    mine.save    = Save(upload.save, allocator_);
    mine.expires = upload.expires;
    parts_.push_back(Part { std::move(mine), Vector<std::byte>(allocator_) });
    return {};
}

Result<std::optional<StoredUpload>> MemorySaveStore::upload(std::string_view id, const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    const Part* part = find_part(id);
    if (part == nullptr)
        return std::optional<StoredUpload> {};
    StoredUpload out(allocator);
    out.id.assign(part->upload.id);
    out.user.assign(part->upload.user);
    out.save    = Save(part->upload.save, allocator);
    out.expires = part->upload.expires;
    out.offset  = part->bytes.size();
    return std::optional<StoredUpload>(std::move(out));
}

Result<Vector<StoredUpload>> MemorySaveStore::uploads(const Allocator& allocator)
{
    const std::scoped_lock lock(mutex_);
    Vector<StoredUpload> out(allocator);
    for (const Part& part : parts_)
    {
        StoredUpload item(allocator);
        item.id.assign(part.upload.id);
        item.user.assign(part.upload.user);
        item.save    = Save(part.upload.save, allocator);
        item.expires = part.upload.expires;
        item.offset  = part.bytes.size();
        out.push_back(std::move(item));
    }
    return out;
}

Result<std::uint64_t> MemorySaveStore::append(std::string_view id, std::span<const std::byte> bytes)
{
    const std::scoped_lock lock(mutex_);
    Part* part = find_part(id);
    if (part == nullptr)
        return fail(Category::storage, "no such upload");
    part->bytes.insert(part->bytes.end(), bytes.begin(), bytes.end());
    return static_cast<std::uint64_t>(part->bytes.size());
}

Result<void> MemorySaveStore::truncate(std::string_view id, std::uint64_t size)
{
    const std::scoped_lock lock(mutex_);
    Part* part = find_part(id);
    if (part == nullptr)
        return fail(Category::storage, "no such upload");
    if (size < part->bytes.size())
        part->bytes.resize(static_cast<std::size_t>(size));
    return {};
}

Result<UploadState> MemorySaveStore::upload_state(std::string_view id)
{
    const std::scoped_lock lock(mutex_);
    const Part* part = find_part(id);
    if (part == nullptr)
        return fail(Category::storage, "no such upload");
    UploadState out;
    out.sha256    = Sha256::of(std::span<const std::byte>(part->bytes));
    out.head_size = std::min<std::size_t>(out.head.size(), part->bytes.size());
    std::ranges::copy_n(part->bytes.begin(), static_cast<std::ptrdiff_t>(out.head_size), out.head.begin());
    return out;
}

Result<void> MemorySaveStore::keep_upload(std::string_view id, const Save& save)
{
    const std::scoped_lock lock(mutex_);
    Part* part = find_part(id);
    if (part == nullptr)
        return fail(Category::storage, "no such upload");
    Kept item { String(part->upload.user, allocator_), Save(save, allocator_),
        std::make_shared<MemoryFileReader>(std::span<const std::byte>(part->bytes), allocator_) };
    kept_.push_back(std::move(item));
    parts_.erase(parts_.begin() + (part - parts_.data()));
    return {};
}

Result<void> MemorySaveStore::abandon(std::string_view id)
{
    const std::scoped_lock lock(mutex_);
    const Part* part = find_part(id);
    if (part != nullptr)
        parts_.erase(parts_.begin() + (part - parts_.data()));
    return {};
}

Result<void> MemorySaveStore::forget(std::string_view user)
{
    const std::scoped_lock lock(mutex_);
    std::erase_if(kept_, [&](const Kept& item) { return item.user == user; });
    std::erase_if(parts_, [&](const Part& part) { return part.upload.user == user; });
    return {};
}

} // namespace lantern
