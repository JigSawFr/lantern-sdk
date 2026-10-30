#include <lantern/memory.hpp>

#include <algorithm>
#include <cstdint>
#include <utility>

namespace lantern
{

bool Budget::charge(std::size_t bytes) noexcept
{
    if (bytes > limit_ - used_)
        return false;
    used_ += bytes;
    return true;
}

void* CountingResource::do_allocate(std::size_t bytes, std::size_t alignment)
{
    void* pointer = upstream_->allocate(bytes, alignment);
    current_ += bytes;
    peak_ = std::max(peak_, current_);
    ++allocations_;
    return pointer;
}

void CountingResource::do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment)
{
    upstream_->deallocate(pointer, bytes, alignment);
    current_ -= bytes;
}

Arena::Arena(Arena&& other) noexcept
    : upstream_(other.upstream_)
    , blocks_(std::exchange(other.blocks_, nullptr))
    , cursor_(std::exchange(other.cursor_, nullptr))
    , left_(std::exchange(other.left_, 0))
{
}

Arena& Arena::operator=(Arena&& other) noexcept
{
    if (this != &other)
    {
        release();
        upstream_ = other.upstream_;
        blocks_   = std::exchange(other.blocks_, nullptr);
        cursor_   = std::exchange(other.cursor_, nullptr);
        left_     = std::exchange(other.left_, 0);
    }
    return *this;
}

Arena::~Arena()
{
    release();
}

void Arena::release() noexcept
{
    while (blocks_ != nullptr)
    {
        Block* next            = blocks_->next;
        const std::size_t size = blocks_->size;
        upstream_->deallocate(blocks_, size, alignof(std::max_align_t));
        blocks_ = next;
    }
    cursor_ = nullptr;
    left_   = 0;
}

void* Arena::allocate(std::size_t bytes, std::size_t alignment)
{
    const auto address    = reinterpret_cast<std::uintptr_t>(cursor_);
    const std::size_t pad = (alignment - (address % alignment)) % alignment;
    if (cursor_ == nullptr || pad + bytes > left_)
    {
        constexpr std::size_t block_size = std::size_t { 16 } * 1024;
        const std::size_t header = (sizeof(Block) + alignof(std::max_align_t) - 1) / alignof(std::max_align_t)
            * alignof(std::max_align_t);
        const std::size_t size = header + std::max(block_size, bytes + alignment);
        auto* block            = static_cast<Block*>(upstream_->allocate(size, alignof(std::max_align_t)));
        block->next            = blocks_;
        block->size            = size;
        blocks_                = block;
        cursor_                = reinterpret_cast<std::byte*>(block) + header;
        left_                  = size - header;
        return allocate(bytes, alignment);
    }
    std::byte* out = cursor_ + pad;
    cursor_        = out + bytes;
    left_ -= pad + bytes;
    return out;
}

} // namespace lantern
