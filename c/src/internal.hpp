// What every source of the C API shares: the app's allocator seen as a
// std::pmr::memory_resource, the boxes the objects given to the app live in,
// errors, strings and the documents' readers.
#pragma once

#include <lantern/lantern.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory_resource>
#include <new>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

#include <lantern/document.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>

#include "generated/documents.hpp"

namespace lantern_c
{

// The app's allocator (or operator new, without one), counted: every
// object made with it holds a reference, so that a document outlives the
// client it came from.
class Resource final : public std::pmr::memory_resource
{
  public:
    // The default resource, for a NULL allocator: never freed.
    static Resource* standard() noexcept;
    // A resource over the app's allocator, or the default one for NULL; one
    // reference, given to the caller. Null for an allocator without its
    // functions.
    static Resource* make(const lantern_allocator* allocator) noexcept;

    void retain() noexcept;
    void release() noexcept;

    Resource(const Resource&)            = delete;
    Resource& operator=(const Resource&) = delete;
    Resource(Resource&&)                 = delete;
    Resource& operator=(Resource&&)      = delete;
    ~Resource() override                 = default;

  private:
    Resource() noexcept = default;
    explicit Resource(const lantern_allocator& allocator) noexcept;

    void* do_allocate(std::size_t bytes, std::size_t alignment) override;
    void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override;
    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override
    {
        return this == &other;
    }

    lantern_allocator allocator_ {};
    bool custom_ = false;
    std::atomic<std::size_t> references_ { 1 };
};

// A reference to a Resource, released with it.
class ResourceRef
{
  public:
    explicit ResourceRef(Resource* resource) noexcept
        : resource_(resource)
    {
        resource_->retain();
    }
    ResourceRef(const ResourceRef& other) noexcept
        : ResourceRef(other.resource_)
    {
    }
    ResourceRef& operator=(const ResourceRef&) = delete;
    ResourceRef(ResourceRef&&)                 = delete;
    ResourceRef& operator=(ResourceRef&&)      = delete;
    ~ResourceRef() { resource_->release(); }

    [[nodiscard]] Resource* get() const noexcept { return resource_; }

  private:
    Resource* resource_;
};

// The objects given to the app: each in a block of its resource, which
// begins with this header and holds a reference to the resource.
struct BoxHeader
{
    Resource* resource;
    std::size_t size;
    std::size_t alignment;
};

template <class T> constexpr std::size_t box_offset()
{
    return (sizeof(BoxHeader) + alignof(T) - 1) / alignof(T) * alignof(T);
}

template <class T, class... Args> T* box_new(Resource* resource, Args&&... args)
{
    constexpr std::size_t offset    = box_offset<T>();
    constexpr std::size_t alignment = std::max(alignof(BoxHeader), alignof(T));
    void* block                     = resource->allocate(offset + sizeof(T), alignment);
    auto* bytes                     = static_cast<std::byte*>(block);
    ::new (block) BoxHeader { resource, offset + sizeof(T), alignment };
    resource->retain();
    return ::new (bytes + offset) T(std::forward<Args>(args)...);
}

template <class T> void unbox(T* value) noexcept
{
    if (value == nullptr)
        return;
    auto* bytes             = reinterpret_cast<std::byte*>(value) - box_offset<T>();
    auto* header            = std::launder(reinterpret_cast<BoxHeader*>(bytes));
    Resource* resource      = header->resource;
    const std::size_t size  = header->size;
    const std::size_t align = header->alignment;
    value->~T();
    header->~BoxHeader();
    resource->deallocate(bytes, size, align);
    resource->release();
}

// Strings.
[[nodiscard]] lantern_str empty_str() noexcept;
// A view of a String: NUL-terminated, as every std::basic_string is.
[[nodiscard]] lantern_str view(const lantern::String& text) noexcept;
// NULL is the empty string.
[[nodiscard]] std::string_view text(const char* value) noexcept;
[[nodiscard]] lantern::String to_string(lantern_str value, lantern::Allocator allocator);
void copy_digest(const lantern::Digest& digest, std::uint8_t* out) noexcept;
[[nodiscard]] lantern::Digest digest_of(const std::uint8_t* bytes) noexcept;
// Copies `text` into a char array of `size` bytes, cut at a UTF-8 boundary.
void copy_text(std::string_view text, char* out, std::size_t size) noexcept;

// Errors.
[[nodiscard]] lantern_status status_of(lantern::Category category) noexcept;
[[nodiscard]] lantern::Category category_of(lantern_status status) noexcept;
// Fills `error` (when given) and returns its status.
lantern_status fail(lantern_error* error, const lantern::Error& what) noexcept;
lantern_status fail(lantern_error* error, lantern::Category category, std::string_view detail) noexcept;
lantern_status usage(lantern_error* error, std::string_view detail) noexcept;
lantern_status ok(lantern_error* error) noexcept;
// An app's callback that failed, as an Error of the library.
[[nodiscard]] lantern::Error from_callback(lantern_status status, const lantern_error* reported,
    lantern::Category fallback, std::string_view detail);

// A struct of the app's, copied as far as its struct_size says (a struct
// of an older header is shorter), the rest zero: the defaults.
template <class S> S copy_struct(const S* value) noexcept
{
    S out {};
    if (value != nullptr && value->struct_size > 0)
        std::memcpy(&out, value, std::min(value->struct_size, sizeof(S)));
    out.struct_size = sizeof(S);
    return out;
}

// Fills an output struct of the app's as far as its struct_size says.
template <class S> void give_struct(const S& value, S* out) noexcept
{
    if (out == nullptr || out->struct_size == 0)
        return;
    const std::size_t size = std::min(out->struct_size, sizeof(S));
    const std::size_t kept = out->struct_size;
    std::memcpy(out, &value, size);
    out->struct_size = kept;
}

// Decode options from the app's limits.
[[nodiscard]] lantern::DecodeOptions decode_options(
    const lantern_limits* limits, Resource* resource) noexcept;

// An owned string or list for the app.
[[nodiscard]] lantern_string* give_string(Resource* resource, lantern::String&& value);
[[nodiscard]] lantern_string* give_string(Resource* resource, std::string_view value);

// A document read: LANTERN_ABSENT for a newer schema, the box otherwise.
template <class T, class Out>
lantern_status give_read(Resource* resource, lantern::Read<T>&& read, Out** out, lantern_error* error)
{
    if (!read)
        return fail(error, read.error());
    if (!*read)
        return LANTERN_ABSENT;
    *out = wrap_mutable(box_new<T>(resource, std::move(**read)));
    return LANTERN_OK;
}

// lantern_read_*: the text, read with the app's limits and allocator.
template <class T, class Out, class Reader>
lantern_status read_text(const char* text, std::size_t size, const lantern_limits* limits,
    const lantern_allocator* allocator, Out** out, lantern_error* error, Reader reader)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    if (text == nullptr && size != 0)
        return usage(error, "text is NULL");
    Resource* resource = Resource::make(allocator);
    if (resource == nullptr)
        return usage(error, "an allocator without its functions");
    const ResourceRef reference(resource);
    resource->release();
    const lantern::DecodeOptions options = decode_options(limits, resource);
    const lantern_status status          = give_read<T>(
        resource, reader(std::string_view(text == nullptr ? "" : text, size), options), out, error);
    if (status == LANTERN_OK || status == LANTERN_ABSENT)
        ok(error);
    return status;
}

// The resource of an allocator the app passes to a function: a reference
// the caller holds for the call.
class ScopedResource
{
  public:
    explicit ScopedResource(const lantern_allocator* allocator) noexcept
        : resource_(Resource::make(allocator))
    {
    }
    ScopedResource(const ScopedResource&)            = delete;
    ScopedResource& operator=(const ScopedResource&) = delete;
    ScopedResource(ScopedResource&&)                 = delete;
    ScopedResource& operator=(ScopedResource&&)      = delete;
    ~ScopedResource()
    {
        if (resource_ != nullptr)
            resource_->release();
    }
    [[nodiscard]] Resource* get() const noexcept { return resource_; }
    [[nodiscard]] explicit operator bool() const noexcept { return resource_ != nullptr; }

  private:
    Resource* resource_;
};

} // namespace lantern_c
