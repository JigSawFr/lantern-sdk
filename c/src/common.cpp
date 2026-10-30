// Versions, errors, memory and strings.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory_resource>
#include <new>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/lantern.hpp>

#include "internal.hpp"

namespace lantern_c
{

// The resource ------------------------------------------------------------

namespace
{

// A resource cannot fail without an exception: the library keeps within
// its budget, and an allocator that still fails ends the program
void* allocate_or_end(const lantern_allocator& allocator, std::size_t bytes, std::size_t alignment) noexcept
{
    void* block = allocator.allocate(allocator.user, bytes, alignment);
    if (block == nullptr)
        std::abort();
    return block;
}

} // namespace

Resource* Resource::standard() noexcept
{
    static Resource resource;
    return &resource;
}

Resource::Resource(const lantern_allocator& allocator) noexcept
    : allocator_(allocator)
    , custom_(true)
{
}

Resource* Resource::make(const lantern_allocator* allocator) noexcept
{
    if (allocator == nullptr)
    {
        Resource* resource = standard();
        resource->retain();
        return resource;
    }
    const lantern_allocator copy = copy_struct(allocator);
    if (copy.allocate == nullptr || copy.deallocate == nullptr)
        return nullptr;
    return ::new (allocate_or_end(copy, sizeof(Resource), alignof(Resource))) Resource(copy);
}

void Resource::retain() noexcept
{
    if (custom_)
        references_.fetch_add(1, std::memory_order_relaxed);
}

void Resource::release() noexcept
{
    if (!custom_)
        return;
    if (references_.fetch_sub(1, std::memory_order_acq_rel) != 1)
        return;
    const lantern_allocator allocator = allocator_;
    this->~Resource();
    allocator.deallocate(allocator.user, this, sizeof(Resource), alignof(Resource));
}

void* Resource::do_allocate(std::size_t bytes, std::size_t alignment)
{
    if (!custom_)
        return std::pmr::new_delete_resource()->allocate(bytes, alignment);
    return allocate_or_end(allocator_, bytes, alignment);
}

void Resource::do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment)
{
    if (!custom_)
    {
        std::pmr::new_delete_resource()->deallocate(pointer, bytes, alignment);
        return;
    }
    allocator_.deallocate(allocator_.user, pointer, bytes, alignment);
}

lantern::DecodeOptions decode_options(const lantern_limits* limits, Resource* resource) noexcept
{
    lantern::DecodeOptions options;
    options.memory = resource;
    if (limits != nullptr)
    {
        const lantern_limits copy = copy_struct(limits);
        if (copy.max_document != 0)
            options.limits.max_document = copy.max_document;
        if (copy.max_depth != 0)
            options.limits.max_depth = copy.max_depth;
        if (copy.max_string != 0)
            options.limits.max_string = copy.max_string;
        if (copy.max_memory != 0)
            options.limits.max_memory = copy.max_memory;
    }
    return options;
}

// Strings -----------------------------------------------------------------

lantern_str empty_str() noexcept
{
    return { "", 0 };
}

lantern_str view(const lantern::String& text) noexcept
{
    return { text.c_str(), text.size() };
}

std::string_view text(const char* value) noexcept
{
    return value == nullptr ? std::string_view {} : std::string_view(value);
}

lantern::String to_string(lantern_str value, lantern::Allocator allocator)
{
    if (value.data == nullptr)
        return lantern::String(allocator);
    return { value.data, value.size, allocator };
}

void copy_digest(const lantern::Digest& digest, std::uint8_t* out) noexcept
{
    std::memcpy(out, digest.data(), digest.size());
}

lantern::Digest digest_of(const std::uint8_t* bytes) noexcept
{
    lantern::Digest digest {};
    if (bytes != nullptr)
        std::memcpy(digest.data(), bytes, digest.size());
    return digest;
}

void copy_text(std::string_view text, char* out, std::size_t size) noexcept
{
    if (out == nullptr || size == 0)
        return;
    std::size_t length = std::min(text.size(), size - 1);
    // Not in the middle of a character
    if (length < text.size())
    {
        while (length > 0 && (static_cast<unsigned char>(text[length]) & 0xC0U) == 0x80U)
            --length;
    }
    if (length > 0)
        std::memcpy(out, text.data(), length);
    out[length] = '\0';
}

lantern_string* give_string(Resource* resource, lantern::String&& value)
{
    auto* boxed = box_new<lantern::String>(resource, std::move(value), lantern::Allocator(resource));
    return reinterpret_cast<lantern_string*>(boxed);
}

lantern_string* give_string(Resource* resource, std::string_view value)
{
    auto* boxed = box_new<lantern::String>(resource, value, lantern::Allocator(resource));
    return reinterpret_cast<lantern_string*>(boxed);
}

// Errors ------------------------------------------------------------------

lantern_status status_of(lantern::Category category) noexcept
{
    switch (category)
    {
        case lantern::Category::protocol:
            return LANTERN_ERROR_PROTOCOL;
        case lantern::Category::transport:
            return LANTERN_ERROR_TRANSPORT;
        case lantern::Category::invalid_response:
            return LANTERN_ERROR_INVALID_RESPONSE;
        case lantern::Category::limit:
            return LANTERN_ERROR_LIMIT;
        case lantern::Category::integrity:
            return LANTERN_ERROR_INTEGRITY;
        case lantern::Category::signature:
            return LANTERN_ERROR_SIGNATURE;
        case lantern::Category::refused:
            return LANTERN_ERROR_REFUSED;
        case lantern::Category::unsupported:
            return LANTERN_ERROR_UNSUPPORTED;
        case lantern::Category::usage:
            return LANTERN_ERROR_USAGE;
        case lantern::Category::storage:
            return LANTERN_ERROR_STORAGE;
        case lantern::Category::memory:
            return LANTERN_ERROR_MEMORY;
    }
    return LANTERN_ERROR_USAGE;
}

lantern::Category category_of(lantern_status status) noexcept
{
    switch (status)
    {
        case LANTERN_ERROR_PROTOCOL:
            return lantern::Category::protocol;
        case LANTERN_ERROR_TRANSPORT:
            return lantern::Category::transport;
        case LANTERN_ERROR_INVALID_RESPONSE:
            return lantern::Category::invalid_response;
        case LANTERN_ERROR_LIMIT:
            return lantern::Category::limit;
        case LANTERN_ERROR_INTEGRITY:
            return lantern::Category::integrity;
        case LANTERN_ERROR_SIGNATURE:
            return lantern::Category::signature;
        case LANTERN_ERROR_REFUSED:
            return lantern::Category::refused;
        case LANTERN_ERROR_UNSUPPORTED:
            return lantern::Category::unsupported;
        case LANTERN_ERROR_STORAGE:
            return lantern::Category::storage;
        case LANTERN_ERROR_MEMORY:
            return lantern::Category::memory;
        default:
            return lantern::Category::usage;
    }
}

lantern_status fail(lantern_error* error, const lantern::Error& what) noexcept
{
    const lantern_status status = status_of(what.category());
    if (error == nullptr || error->struct_size == 0)
        return status;
    lantern_error out {};
    out.struct_size    = sizeof(lantern_error);
    out.status         = status;
    out.code           = static_cast<lantern_code>(what.code());
    out.effective_code = static_cast<lantern_code>(what.effective_code());
    out.http_status    = what.status();
    out.retry_after    = what.retry_after();
    copy_text(what.code_text(), out.code_text, sizeof(out.code_text));
    copy_text(what.title(), out.title, sizeof(out.title));
    copy_text(what.detail(), out.detail, sizeof(out.detail));
    give_struct(out, error);
    return status;
}

lantern_status fail(lantern_error* error, lantern::Category category, std::string_view detail) noexcept
{
    return fail(error, lantern::Error::make(category, detail));
}

lantern_status usage(lantern_error* error, std::string_view detail) noexcept
{
    return fail(error, lantern::Category::usage, detail);
}

lantern_status ok(lantern_error* error) noexcept
{
    if (error != nullptr && error->struct_size != 0)
    {
        lantern_error out {};
        out.struct_size = sizeof(lantern_error);
        give_struct(out, error);
    }
    return LANTERN_OK;
}

lantern::Error from_callback(
    lantern_status status, const lantern_error* reported, lantern::Category fallback, std::string_view detail)
{
    const lantern::Category category = status < 0 ? category_of(status) : fallback;
    if (reported != nullptr && reported->detail[0] != '\0')
        return lantern::Error::make(category, std::string_view(reported->detail));
    return lantern::Error::make(category, detail);
}

} // namespace lantern_c

using namespace lantern_c;

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API uint32_t lantern_version(void)
{
    return LANTERN_C_API_VERSION;
}

LANTERN_API const char* lantern_version_string(void)
{
    return LANTERN_VERSION_STRING;
}

LANTERN_API const char* lantern_spec_draft(void)
{
    static_assert(lantern::spec_draft == LANTERN_SPEC_DRAFT);
    return LANTERN_SPEC_DRAFT;
}

LANTERN_API const char* lantern_status_name(lantern_status status)
{
    switch (status)
    {
        case LANTERN_OK:
            return "ok";
        case LANTERN_ABSENT:
            return "absent";
        case LANTERN_ERROR_PROTOCOL:
        case LANTERN_ERROR_TRANSPORT:
        case LANTERN_ERROR_INVALID_RESPONSE:
        case LANTERN_ERROR_LIMIT:
        case LANTERN_ERROR_INTEGRITY:
        case LANTERN_ERROR_SIGNATURE:
        case LANTERN_ERROR_REFUSED:
        case LANTERN_ERROR_UNSUPPORTED:
        case LANTERN_ERROR_USAGE:
        case LANTERN_ERROR_STORAGE:
        case LANTERN_ERROR_MEMORY:
            // category_name() gives a string_view of a literal: NUL-terminated
            return lantern::category_name(category_of(status)).data();
        default:
            return "";
    }
}

LANTERN_API const char* lantern_code_name(lantern_code code)
{
    if (code < LANTERN_CODE_NONE || code > LANTERN_CODE_UNKNOWN)
        return "";
    const std::string_view name = lantern::code_name(static_cast<lantern::Code>(code));
    return name.empty() ? "" : name.data();
}

LANTERN_API lantern_code lantern_code_from_name(const char* name)
{
    return static_cast<lantern_code>(lantern::code_from_name(text(name)));
}

LANTERN_API lantern_code lantern_code_for_status(uint16_t status)
{
    return static_cast<lantern_code>(lantern::code_for_status(status));
}

LANTERN_API void lantern_error_init(lantern_error* error)
{
    if (error == nullptr)
        return;
    *error             = lantern_error {};
    error->struct_size = sizeof(lantern_error);
}

LANTERN_API void lantern_error_set(lantern_error* error, lantern_status status, const char* detail)
{
    if (error == nullptr || error->struct_size < offsetof(lantern_error, detail) + sizeof(error->detail))
        return;
    error->status = status;
    copy_text(text(detail), error->detail, sizeof(error->detail));
}

LANTERN_API lantern_str lantern_string_view(const lantern_string* string)
{
    if (string == nullptr)
        return empty_str();
    return view(*reinterpret_cast<const lantern::String*>(string));
}

LANTERN_API void lantern_string_free(lantern_string* string)
{
    unbox(reinterpret_cast<lantern::String*>(string));
}

LANTERN_API size_t lantern_strings_count(const lantern_strings* strings)
{
    return strings == nullptr ? 0
                              : reinterpret_cast<const lantern::Vector<lantern::String>*>(strings)->size();
}

LANTERN_API lantern_str lantern_strings_at(const lantern_strings* strings, size_t index)
{
    if (strings == nullptr)
        return empty_str();
    const auto& list = *reinterpret_cast<const lantern::Vector<lantern::String>*>(strings);
    return index < list.size() ? view(list[index]) : empty_str();
}

LANTERN_API void lantern_strings_free(lantern_strings* strings)
{
    unbox(reinterpret_cast<lantern::Vector<lantern::String>*>(strings));
}

LANTERN_API void lantern_sha256(const uint8_t* bytes, size_t size, uint8_t out[32])
{
    if (out == nullptr)
        return;
    const auto digest = lantern::Sha256::of(
        std::as_bytes(std::span(bytes == nullptr ? nullptr : bytes, bytes == nullptr ? 0 : size)));
    copy_digest(digest, out);
}

LANTERN_API void lantern_digest_to_hex(const uint8_t digest[32], char out[65])
{
    if (digest == nullptr || out == nullptr)
        return;
    const auto hex = lantern::to_hex(digest_of(digest));
    std::memcpy(out, hex.data(), hex.size());
    out[hex.size()] = '\0';
}

LANTERN_API bool lantern_digest_from_hex(const char* hex, uint8_t out[32])
{
    if (out == nullptr)
        return false;
    const auto digest = lantern::digest_from_hex(text(hex));
    if (!digest)
        return false;
    copy_digest(*digest, out);
    return true;
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
