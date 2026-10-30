// What an app keeps to resume a download or an upload after a restart: a
// small JSON document with `schema` 1 (c/README.md), read with the schema
// rule, and rewritten with the members a later version added kept.
//
//     {"schema":1,"received":2500,"hash":{"h":[…8 words],"block":"<128 hex>","length":2500},"etag":"\"v1\""}
//     {"schema":1,"url":"https://…/uploads/u_1","offset":16384,"chunk_size":16384}
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include <lantern/document.hpp>
#include <lantern/json.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

// The schema of both documents: a member that changes meaning raises it.
constexpr std::uint64_t state_schema = 1;

constexpr std::string_view hex_digits = "0123456789abcdef";

void write_hex(std::span<const std::uint8_t> bytes, lantern::String& out)
{
    for (const std::uint8_t byte : bytes)
    {
        out.push_back(hex_digits[byte >> 4U]);
        out.push_back(hex_digits[byte & 0x0FU]);
    }
}

bool read_hex(std::string_view text, std::span<std::uint8_t> out) noexcept
{
    if (text.size() != out.size() * 2)
        return false;
    for (std::size_t i = 0; i < out.size(); ++i)
    {
        const auto high = hex_digits.find(text[2 * i]);
        const auto low  = hex_digits.find(text[(2 * i) + 1]);
        if (high == std::string_view::npos || low == std::string_view::npos)
            return false;
        out[i] = static_cast<std::uint8_t>((high << 4U) | low);
    }
    return true;
}

// Each member as JSON text, for a new document or a rewrite.
struct Member
{
    std::string_view key;
    lantern::String json;
};

lantern_status save(const lantern::String& loaded, bool newer, std::span<const Member> members,
    Resource* resource, lantern_string** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    // Read from a newer document: what the app has must not be written over
    if (newer)
        return LANTERN_ABSENT;
    const lantern::Allocator allocator(resource);
    if (!loaded.empty())
    {
        lantern::Vector<lantern::Patch> patches(allocator);
        for (const Member& member : members)
            patches.push_back({ member.key, std::string_view(member.json) });
        auto rewritten = lantern::rewrite(loaded, state_schema, patches, allocator);
        if (!rewritten)
            return fail(error, rewritten.error());
        if (!*rewritten)
            return LANTERN_ABSENT;
        *out = give_string(resource, std::move(**rewritten));
        return ok(error);
    }
    lantern::String text(allocator);
    lantern::json::Writer w(text);
    w.begin_object();
    w.key("schema");
    w.number(state_schema);
    for (const Member& member : members)
    {
        w.key(member.key);
        w.raw(member.json);
    }
    w.end_object();
    *out = give_string(resource, std::move(text));
    return ok(error);
}

// Reads the document, or says it is newer (LANTERN_ABSENT).
lantern_status load(std::string_view text, Resource* resource,
    std::optional<lantern::json::Document>& document, bool& newer, lantern_error* error)
{
    newer             = false;
    const auto schema = lantern::peek_schema(text);
    if (!schema)
        return fail(error, schema.error());
    if (*schema > state_schema)
    {
        newer = true;
        return LANTERN_ABSENT;
    }
    auto parsed = lantern::json::parse(text, {}, resource);
    if (!parsed)
        return fail(error, parsed.error());
    document.emplace(std::move(*parsed));
    return LANTERN_OK;
}

// A member that is a whole number, or nothing (absent included).
std::optional<std::uint64_t> number_of(const lantern::json::Value* value) noexcept
{
    return value == nullptr ? std::nullopt : value->to_u64();
}

lantern_status invalid(lantern_error* error, std::string_view detail) noexcept
{
    return fail(error, lantern::Category::invalid_response, detail);
}

lantern::String number(std::uint64_t value, lantern::Allocator allocator)
{
    lantern::String out(allocator);
    lantern::json::Writer w(out);
    w.number(value);
    return out;
}

lantern::String string(std::string_view value, lantern::Allocator allocator)
{
    lantern::String out(allocator);
    lantern::json::Writer w(out);
    w.string(value);
    return out;
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_download_state_create(
    const lantern_allocator* allocator, lantern_download_state** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    *out = box_new<lantern_download_state>(resource.get(), resource.get());
    return ok(error);
}

LANTERN_API void lantern_download_state_free(lantern_download_state* state)
{
    unbox(state);
}

LANTERN_API void lantern_download_state_reset(lantern_download_state* state)
{
    if (state != nullptr)
        state->state.reset();
}

LANTERN_API uint64_t lantern_download_state_received(const lantern_download_state* state)
{
    return state == nullptr ? 0 : state->state.received;
}

LANTERN_API lantern_status lantern_download_state_save(
    const lantern_download_state* state, lantern_string** out, lantern_error* error)
{
    if (state == nullptr)
        return usage(error, "state is NULL");
    auto* resource = state->resource;
    const lantern::Allocator allocator(resource);
    const lantern::DownloadState& s = state->state;
    lantern::String hash(allocator);
    {
        lantern::json::Writer w(hash);
        w.begin_object();
        w.key("h");
        w.begin_array();
        for (const std::uint32_t word : s.hash.h)
            w.number(std::uint64_t { word });
        w.end_array();
        w.key("block");
        lantern::String block(allocator);
        write_hex(s.hash.block, block);
        w.string(block);
        w.key("length");
        w.number(s.hash.length);
        w.end_object();
    }
    const std::array<Member, 3> members { {
        { "received", number(s.received, allocator) },
        { "hash", std::move(hash) },
        { "etag", string(s.etag_view(), allocator) },
    } };
    return save(state->loaded, state->newer, members, resource, out, error);
}

LANTERN_API lantern_status lantern_download_state_load(
    lantern_download_state* state, const char* json, size_t size, lantern_error* error)
{
    if (state == nullptr || (json == nullptr && size != 0))
        return usage(error, "a NULL argument");
    auto* resource = state->resource;
    const std::string_view text(json == nullptr ? "" : json, size);
    std::optional<lantern::json::Document> document;
    bool newer                  = false;
    const lantern_status status = load(text, resource, document, newer, error);
    if (status == LANTERN_ABSENT)
    {
        state->state.reset();
        state->loaded.clear();
        state->newer = true;
        ok(error);
        return LANTERN_ABSENT;
    }
    if (status != LANTERN_OK)
        return status;
    if (!document)
        return invalid(error, "a download's state that is not a document");
    const lantern::json::Value& root = document->root();
    lantern::DownloadState read;
    const auto received = number_of(root.find("received"));
    const auto* hash    = root.find("hash");
    const auto* etag    = root.find("etag");
    if (!received || hash == nullptr || !hash->is_object())
        return invalid(error, "a download's state without its received bytes or its hash");
    read.received     = *received;
    const auto* words = hash->find("h");
    const auto* block = hash->find("block");
    const auto bytes  = number_of(hash->find("length"));
    if (words == nullptr || !words->is_array() || words->items().size() != read.hash.h.size()
        || block == nullptr || !block->is_string() || !bytes)
        return invalid(error, "a download's hash state of another form");
    for (std::size_t i = 0; i < read.hash.h.size(); ++i)
    {
        const auto word = words->items()[i].to_u64();
        if (!word || *word > UINT32_MAX)
            return invalid(error, "a download's hash state of another form");
        read.hash.h[i] = static_cast<std::uint32_t>(*word);
    }
    if (!read_hex(block->text(), read.hash.block))
        return invalid(error, "a download's hash block of another form");
    read.hash.length = *bytes;
    if (read.hash.length != read.received)
        return invalid(error, "a download's hash state that does not match its bytes");
    if (etag != nullptr)
    {
        if (!etag->is_string() || etag->text().size() > read.etag.size())
            return invalid(error, "a download's ETag of another form");
        std::ranges::copy(etag->text(), read.etag.begin());
        read.etag_size = etag->text().size();
    }
    state->state  = read;
    state->loaded = text;
    state->newer  = false;
    return ok(error);
}

LANTERN_API lantern_status lantern_upload_progress_create(
    const lantern_allocator* allocator, lantern_upload_progress** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    *out = box_new<lantern_upload_progress>(resource.get(), resource.get());
    return ok(error);
}

LANTERN_API void lantern_upload_progress_free(lantern_upload_progress* progress)
{
    unbox(progress);
}

LANTERN_API void lantern_upload_progress_reset(lantern_upload_progress* progress)
{
    if (progress != nullptr)
        progress->progress.reset();
}

LANTERN_API lantern_str lantern_upload_progress_url(const lantern_upload_progress* progress)
{
    if (progress == nullptr || progress->progress.url_size == 0)
        return empty_str();
    // The array is NUL-filled past url_size, unless the URL fills it
    const auto& url = progress->progress.url;
    if (progress->progress.url_size >= url.size())
        return empty_str();
    return { url.data(), progress->progress.url_size };
}

LANTERN_API uint64_t lantern_upload_progress_offset(const lantern_upload_progress* progress)
{
    return progress == nullptr ? 0 : progress->progress.offset;
}

LANTERN_API lantern_status lantern_upload_progress_save(
    const lantern_upload_progress* progress, lantern_string** out, lantern_error* error)
{
    if (progress == nullptr)
        return usage(error, "progress is NULL");
    auto* resource = progress->resource;
    const lantern::Allocator allocator(resource);
    const lantern::UploadProgress& p = progress->progress;
    const std::array<Member, 3> members { {
        { "url", string(p.url_view(), allocator) },
        { "offset", number(p.offset, allocator) },
        { "chunk_size", number(p.chunk_size, allocator) },
    } };
    return save(progress->loaded, progress->newer, members, resource, out, error);
}

LANTERN_API lantern_status lantern_upload_progress_load(
    lantern_upload_progress* progress, const char* json, size_t size, lantern_error* error)
{
    if (progress == nullptr || (json == nullptr && size != 0))
        return usage(error, "a NULL argument");
    auto* resource = progress->resource;
    const std::string_view text(json == nullptr ? "" : json, size);
    std::optional<lantern::json::Document> document;
    bool newer                  = false;
    const lantern_status status = load(text, resource, document, newer, error);
    if (status == LANTERN_ABSENT)
    {
        progress->progress.reset();
        progress->loaded.clear();
        progress->newer = true;
        ok(error);
        return LANTERN_ABSENT;
    }
    if (status != LANTERN_OK)
        return status;
    if (!document)
        return invalid(error, "an upload's progress that is not a document");
    const lantern::json::Value& root = document->root();
    const auto* url                  = root.find("url");
    const auto offset                = number_of(root.find("offset"));
    const auto chunk                 = number_of(root.find("chunk_size"));
    lantern::UploadProgress read;
    // The URL must leave room for the NUL lantern_upload_progress_url() keeps
    if (url == nullptr || !url->is_string() || url->text().size() >= read.url.size() || !offset || !chunk)
        return invalid(error, "an upload's progress of another form");
    std::ranges::copy(url->text(), read.url.begin());
    read.url_size      = url->text().size();
    read.offset        = *offset;
    read.chunk_size    = *chunk;
    progress->progress = read;
    progress->loaded   = text;
    progress->newer    = false;
    return ok(error);
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
