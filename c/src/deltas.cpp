// Differential updates (SPEC.md § 22), where an address leads (§ 21.3) and
// canonical JSON (§ 2.3): the C++ library's chunk indexes, the update put
// together from seeds and ranges, find_library() and canonical_json().
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

#include <lantern/canonical.hpp>
#include <lantern/chunks.hpp>
#include <lantern/static_library.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

constexpr std::size_t max_sources = 8;

const lantern::ChunkIndex* as_index(const lantern_chunk_index* index) noexcept
{
    return reinterpret_cast<const lantern::ChunkIndex*>(index);
}

lantern::DownloadTarget target_of(const lantern_download_target& target) noexcept
{
    lantern::DownloadTarget out;
    out.url    = text(target.url);
    out.size   = target.size;
    out.sha256 = digest_of(target.sha256);
    return out;
}

lantern::PeerEndpoint endpoint_of(const lantern_peer_endpoint& peer) noexcept
{
    lantern::PeerEndpoint out;
    out.host = text(peer.host);
    out.port = peer.port;
    out.base = text(peer.base);
    out.tls  = peer.tls;
    return out;
}

// The seeds, as the C++ library takes them.
bool seeds_of(const lantern_seed* seeds, std::size_t count, lantern::Vector<lantern::Seed>& out) noexcept
{
    if (seeds == nullptr && count != 0)
        return false;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
        if (seeds[i].bytes == nullptr && seeds[i].size != 0)
            return false;
        out.push_back(
            std::as_bytes(std::span(seeds[i].bytes, seeds[i].bytes == nullptr ? 0 : seeds[i].size)));
    }
    return true;
}

// The options of a call, copied for as long as it lasts.
struct Options
{
    lantern::Vector<lantern::DeltaPeer> peers;
    lantern::Vector<lantern::Mirror> mirrors;
    lantern::DeltaOptions out;

    explicit Options(lantern::Allocator allocator)
        : peers(allocator)
        , mirrors(allocator)
    {
    }

    // False, and `error` filled, for a NULL where there is none to be
    bool read(const lantern_delta_options* given, lantern_error* error)
    {
        if (given == nullptr)
            return true;
        const lantern_delta_options o = copy_struct(given);
        if ((o.peers == nullptr && o.peer_count != 0) || (o.mirrors == nullptr && o.mirror_count != 0))
        {
            usage(error, "a NULL array with items");
            return false;
        }
        for (std::size_t i = 0; i < o.peer_count && i < max_sources; ++i)
        {
            const lantern_delta_peer peer = copy_struct(&o.peers[i]);
            if (peer.endpoint == nullptr || peer.grant == nullptr)
            {
                usage(error, "a peer without its endpoint or its grant");
                return false;
            }
            peers.push_back({ endpoint_of(copy_struct(peer.endpoint)), as(peer.grant) });
        }
        for (std::size_t i = 0; i < o.mirror_count && i < max_sources; ++i)
        {
            if (o.mirrors[i] == nullptr)
            {
                usage(error, "a NULL mirror");
                return false;
            }
            mirrors.push_back(*as(o.mirrors[i]));
        }
        out.peers   = peers;
        out.mirrors = mirrors;
        if (o.has_gap)
            out.gap = o.gap;
        return true;
    }
};

lantern_status give_report(
    const lantern::Result<lantern::DeltaReport>& result, lantern_delta_report* out, lantern_error* error)
{
    if (!result)
        return fail(error, result.error());
    lantern_delta_report report {};
    report.struct_size = sizeof(report);
    report.from_seeds  = result->from_seeds;
    report.from_ranges = result->from_ranges;
    report.requests    = result->requests;
    report.whole_file  = result->whole_file;
    give_struct(report, out);
    return ok(error);
}

// An index read: LANTERN_ABSENT for none, the box otherwise.
lantern_status give_index(Resource* resource, lantern::Read<lantern::ChunkIndex>&& read,
    lantern_chunk_index** out, lantern_error* error)
{
    if (!read)
        return fail(error, read.error());
    ok(error);
    if (!*read)
        return LANTERN_ABSENT;
    *out = reinterpret_cast<lantern_chunk_index*>(box_new<lantern::ChunkIndex>(resource, std::move(**read)));
    return LANTERN_OK;
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API void lantern_chunk_index_free(lantern_chunk_index* index)
{
    unbox(reinterpret_cast<lantern::ChunkIndex*>(index));
}

LANTERN_API uint64_t lantern_chunk_index_size(const lantern_chunk_index* index)
{
    return index == nullptr ? 0 : as_index(index)->size;
}

LANTERN_API void lantern_chunk_index_sha256(const lantern_chunk_index* index, uint8_t out[32])
{
    if (index != nullptr && out != nullptr)
        copy_digest(as_index(index)->sha256, out);
}

LANTERN_API uint64_t lantern_chunk_index_chunker_size(const lantern_chunk_index* index)
{
    return index == nullptr ? 0 : as_index(index)->chunker_size;
}

LANTERN_API size_t lantern_chunk_index_count(const lantern_chunk_index* index)
{
    return index == nullptr ? 0 : as_index(index)->chunks.size();
}

LANTERN_API bool lantern_chunk_index_at(
    const lantern_chunk_index* index, size_t at, uint32_t* size, uint8_t sha256[32])
{
    if (index == nullptr || at >= as_index(index)->chunks.size())
        return false;
    const lantern::IndexedChunk& chunk = as_index(index)->chunks[at];
    if (size != nullptr)
        *size = chunk.length;
    if (sha256 != nullptr)
        copy_digest(chunk.sha256, sha256);
    return true;
}

LANTERN_API lantern_status lantern_read_chunk_index(const char* bytes, size_t size,
    const lantern_app_chunks* chunks, const uint8_t sha256[32], uint64_t file_size,
    const lantern_allocator* allocator, lantern_chunk_index** out, lantern_error* error)
{
    if (out == nullptr || sha256 == nullptr || (bytes == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    return give_index(resource.get(),
        lantern::read_chunk_index(std::string_view(bytes == nullptr ? "" : bytes, size),
            chunks == nullptr ? nullptr : as(chunks), digest_of(sha256), file_size,
            lantern::Allocator(resource.get())),
        out, error);
}

LANTERN_API lantern_status lantern_client_chunk_index(lantern_client* client,
    const lantern_app_chunks* chunks, const lantern_download_target* target, lantern_chunk_index** out,
    lantern_error* error)
{
    if (client == nullptr || chunks == nullptr || target == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give_index(client->resource.get(),
        client->client.chunk_index(*as(chunks), target_of(copy_struct(target))), out, error);
}

LANTERN_API lantern_status lantern_client_chunk_index_of(lantern_client* client, const uint8_t sha256[32],
    uint64_t file_size, lantern_chunk_index** out, lantern_error* error)
{
    if (client == nullptr || sha256 == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give_index(
        client->resource.get(), client->client.chunk_index_of(digest_of(sha256), file_size), out, error);
}

LANTERN_API lantern_status lantern_client_download_with_seeds(lantern_client* client,
    const lantern_download_target* target, const lantern_app_chunks* chunks, const lantern_seed* seeds,
    size_t seed_count, lantern_download_sink* sink, const lantern_delta_options* options,
    lantern_delta_report* report, lantern_error* error)
{
    if (client == nullptr || target == nullptr || chunks == nullptr || sink == nullptr)
        return usage(error, "a NULL argument");
    const lantern::Allocator allocator(client->resource.get());
    lantern::Vector<lantern::Seed> held(allocator);
    if (!seeds_of(seeds, seed_count, held))
        return usage(error, "a NULL seed with bytes");
    Options converted(allocator);
    if (!converted.read(options, error))
        return LANTERN_ERROR_USAGE;
    return give_report(client->client.download_with_seeds(
                           target_of(copy_struct(target)), *as(chunks), held, *sink->impl, converted.out),
        report, error);
}

LANTERN_API lantern_status lantern_client_download_with_index(lantern_client* client,
    const lantern_download_target* target, const lantern_chunk_index* index, const lantern_seed* seeds,
    size_t seed_count, lantern_download_sink* sink, const lantern_delta_options* options,
    lantern_delta_report* report, lantern_error* error)
{
    if (client == nullptr || target == nullptr || index == nullptr || sink == nullptr)
        return usage(error, "a NULL argument");
    const lantern::Allocator allocator(client->resource.get());
    lantern::Vector<lantern::Seed> held(allocator);
    if (!seeds_of(seeds, seed_count, held))
        return usage(error, "a NULL seed with bytes");
    Options converted(allocator);
    if (!converted.read(options, error))
        return LANTERN_ERROR_USAGE;
    return give_report(client->client.download_with_index(target_of(copy_struct(target)), *as_index(index),
                           held, *sink->impl, converted.out),
        report, error);
}

LANTERN_API lantern_status lantern_client_upload_head(
    lantern_client* client, const char* upload, lantern_upload_head* out, lantern_error* error)
{
    if (client == nullptr || upload == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    const auto head = client->client.upload_head(upload);
    if (!head)
        return fail(error, head.error());
    lantern_upload_head result {};
    result.struct_size    = sizeof(result);
    result.offset         = head->offset;
    result.has_length     = head->length.has_value();
    result.length         = head->length.value_or(0);
    result.has_chunk_size = head->chunk_size.has_value();
    result.chunk_size     = head->chunk_size.value_or(0);
    give_struct(result, out);
    return ok(error);
}

LANTERN_API lantern_status lantern_static_library_chunk_index(lantern_static_library* library,
    const lantern_app_chunks* chunks, const lantern_download_target* target, lantern_chunk_index** out,
    lantern_error* error)
{
    if (library == nullptr || chunks == nullptr || target == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give_index(library->memory,
        library->library.chunk_index(*as(chunks), target_of(copy_struct(target))), out, error);
}

LANTERN_API lantern_status lantern_static_library_download_with_seeds(lantern_static_library* library,
    const lantern_download_target* target, const lantern_app_chunks* chunks, const lantern_seed* seeds,
    size_t seed_count, lantern_download_sink* sink, const lantern_delta_options* options,
    lantern_delta_report* report, lantern_error* error)
{
    if (library == nullptr || target == nullptr || chunks == nullptr || sink == nullptr)
        return usage(error, "a NULL argument");
    const lantern::Allocator allocator(library->memory);
    lantern::Vector<lantern::Seed> held(allocator);
    if (!seeds_of(seeds, seed_count, held))
        return usage(error, "a NULL seed with bytes");
    Options converted(allocator);
    if (!converted.read(options, error))
        return LANTERN_ERROR_USAGE;
    return give_report(library->library.download_with_seeds(
                           target_of(copy_struct(target)), *as(chunks), held, *sink->impl, converted.out.gap),
        report, error);
}

LANTERN_API lantern_status lantern_find_library(lantern_transport* transport, const char* address,
    const char* user_agent, const lantern_limits* limits, const lantern_allocator* allocator,
    lantern_found_library** out, lantern_error* error)
{
    if (transport == nullptr || address == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto found = lantern::find_library(
        *transport->impl, text(address), text(user_agent), decode_options(limits, resource.get()));
    if (!found)
        return fail(error, found.error());
    ok(error);
    if (!*found)
        return LANTERN_ABSENT;
    *out = reinterpret_cast<lantern_found_library*>(
        box_new<lantern::FoundLibrary>(resource.get(), std::move(**found)));
    return LANTERN_OK;
}

LANTERN_API void lantern_found_library_free(lantern_found_library* found)
{
    unbox(reinterpret_cast<lantern::FoundLibrary*>(found));
}

LANTERN_API lantern_library_kind lantern_found_library_kind(const lantern_found_library* found)
{
    if (found == nullptr)
        return LANTERN_LIBRARY_SERVER;
    return reinterpret_cast<const lantern::FoundLibrary*>(found)->kind == lantern::LibraryKind::static_library
        ? LANTERN_LIBRARY_STATIC
        : LANTERN_LIBRARY_SERVER;
}

LANTERN_API lantern_str lantern_found_library_root(const lantern_found_library* found)
{
    return found == nullptr ? empty_str() : view(reinterpret_cast<const lantern::FoundLibrary*>(found)->root);
}

LANTERN_API const lantern_handshake* lantern_found_library_handshake(const lantern_found_library* found)
{
    return found == nullptr ? nullptr
                            : wrap(&reinterpret_cast<const lantern::FoundLibrary*>(found)->handshake);
}

LANTERN_API lantern_status lantern_canonical_number(
    const char* number, const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (number == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    lantern::String written((lantern::Allocator(resource.get())));
    if (auto done = lantern::canonical_number(text(number), written); !done)
        return fail(error, done.error());
    *out = give_string(resource.get(), std::move(written));
    return ok(error);
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
