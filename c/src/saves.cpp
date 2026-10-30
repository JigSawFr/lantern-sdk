// End-to-end encrypted save backups (§ 9.4, lantern-save-e2e-1): save keys,
// headers, an encrypting upload source, a decrypting download sink, and the
// primitives for the test vectors.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#include <lantern/encrypted_save.hpp>
#include <lantern/hkdf.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

const lantern::SaveKey* as_key(const lantern_save_key* key) noexcept
{
    return reinterpret_cast<const lantern::SaveKey*>(key);
}

lantern_status give_key(lantern::Result<lantern::SaveKey>&& key, const lantern_allocator* allocator,
    lantern_save_key** out, lantern_error* error)
{
    if (!key)
        return fail(error, key.error());
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    *out = reinterpret_cast<lantern_save_key*>(box_new<lantern::SaveKey>(resource.get(), std::move(*key)));
    return ok(error);
}

template <std::size_t N> void copy_chars(const std::array<char, N>& from, char* out) noexcept
{
    std::memcpy(out, from.data(), N);
    out[N] = '\0';
}

lantern::SaveHeader header_of(const std::uint8_t* bytes) noexcept
{
    lantern::SaveHeader header {};
    std::memcpy(header.data(), bytes, header.size());
    return header;
}

template <std::size_t N> std::array<std::uint8_t, N> array_of(const std::uint8_t* bytes) noexcept
{
    std::array<std::uint8_t, N> out {};
    std::memcpy(out.data(), bytes, N);
    return out;
}

std::span<const std::uint8_t> span_of(const std::uint8_t* bytes, std::size_t size) noexcept
{
    return { bytes, bytes == nullptr ? 0 : size };
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_save_key_generate(
    lantern_random* random, const lantern_allocator* allocator, lantern_save_key** out, lantern_error* error)
{
    if (random == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give_key(lantern::SaveKey::generate(*random), allocator, out, error);
}

LANTERN_API lantern_status lantern_save_key_from_bytes(
    const uint8_t bytes[32], const lantern_allocator* allocator, lantern_save_key** out, lantern_error* error)
{
    if (bytes == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out      = nullptr;
    auto copy = array_of<32>(bytes);
    auto key  = lantern::SaveKey::from_bytes(copy);
    lantern::secure_wipe(std::span<std::uint8_t>(copy));
    return give_key(std::move(key), allocator, out, error);
}

LANTERN_API lantern_status lantern_save_key_from_phrase(
    const char* phrase, const lantern_allocator* allocator, lantern_save_key** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    return give_key(lantern::SaveKey::from_phrase(text(phrase)), allocator, out, error);
}

LANTERN_API lantern_status lantern_save_key_from_qr(
    const char* value, const lantern_allocator* allocator, lantern_save_key** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    return give_key(lantern::SaveKey::from_qr(text(value)), allocator, out, error);
}

LANTERN_API void lantern_save_key_free(lantern_save_key* key)
{
    unbox(reinterpret_cast<lantern::SaveKey*>(key));
}

LANTERN_API void lantern_save_key_bytes(const lantern_save_key* key, uint8_t out[32])
{
    if (key != nullptr && out != nullptr)
        std::memcpy(out, as_key(key)->bytes().data(), as_key(key)->bytes().size());
}

LANTERN_API void lantern_save_key_id_text(const lantern_save_key* key, char out[17])
{
    if (key != nullptr && out != nullptr)
        copy_chars(as_key(key)->id_text(), out);
}

LANTERN_API void lantern_save_key_phrase(const lantern_save_key* key, char out[70])
{
    if (key != nullptr && out != nullptr)
        copy_chars(as_key(key)->phrase(), out);
}

LANTERN_API void lantern_save_key_qr_text(const lantern_save_key* key, char out[76])
{
    if (key != nullptr && out != nullptr)
        copy_chars(as_key(key)->qr_text(), out);
}

LANTERN_API uint64_t lantern_save_chunk_count(uint64_t archive_size)
{
    return lantern::save_chunk_count(archive_size);
}

LANTERN_API uint64_t lantern_encrypted_save_size(uint64_t archive_size)
{
    return lantern::encrypted_save_size(archive_size);
}

LANTERN_API lantern_status lantern_make_save_header(const lantern_save_key* key, lantern_random* random,
    uint8_t out[LANTERN_SAVE_HEADER_SIZE], lantern_error* error)
{
    if (key == nullptr || random == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    const auto header = lantern::make_save_header(*as_key(key), *random);
    if (!header)
        return fail(error, header.error());
    std::memcpy(out, header->data(), header->size());
    return ok(error);
}

LANTERN_API void lantern_make_save_header_with(const lantern_save_key* key, const uint8_t file_key[32],
    const uint8_t wrap_nonce[24], uint8_t out[LANTERN_SAVE_HEADER_SIZE])
{
    if (key == nullptr || file_key == nullptr || wrap_nonce == nullptr || out == nullptr)
        return;
    auto file         = array_of<32>(file_key);
    const auto header = lantern::make_save_header(*as_key(key), file, array_of<24>(wrap_nonce));
    lantern::secure_wipe(std::span<std::uint8_t>(file));
    std::memcpy(out, header.data(), header.size());
}

LANTERN_API lantern_status lantern_save_backup_key_id(
    const uint8_t* backup, size_t size, char out[17], lantern_error* error)
{
    if (out == nullptr || (backup == nullptr && size != 0))
        return usage(error, "a NULL argument");
    const auto id = lantern::save_key_id(std::as_bytes(span_of(backup, size)));
    if (!id)
        return fail(error, id.error());
    copy_chars(*id, out);
    return ok(error);
}

LANTERN_API lantern_status lantern_encrypting_source_create(const lantern_save_key* key,
    const uint8_t header[LANTERN_SAVE_HEADER_SIZE], lantern_upload_source* archive, uint64_t archive_size,
    const lantern_allocator* allocator, lantern_upload_source** out, lantern_error* error)
{
    if (key == nullptr || header == nullptr || archive == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto made = lantern::EncryptingSource::create(
        *as_key(key), header_of(header), *archive->impl, archive_size, lantern::Allocator(resource.get()));
    if (!made)
        return fail(error, made.error());
    auto* source = box_new<lantern::EncryptingSource>(resource.get(), std::move(*made));
    *out         = give_source(resource.get(), source, source);
    copy_chars(as_key(key)->id_text(), (*out)->key_id.data());
    return ok(error);
}

LANTERN_API lantern_status lantern_encrypting_source_describe(
    lantern_upload_source* source, lantern_upload_request* request, lantern_error* error)
{
    if (source == nullptr || request == nullptr)
        return usage(error, "a NULL argument");
    if (source->encrypting == nullptr)
        return usage(error, "not an encrypting source");
    lantern::UploadRequest described { lantern::Allocator(Resource::standard()) };
    const auto done = source->encrypting->describe(described);
    if (!done)
        return fail(error, done.error());
    lantern_upload_request result = copy_struct(request);
    result.size                   = described.size;
    copy_digest(described.sha256, result.sha256);
    result.encryption_scheme = LANTERN_SAVE_SCHEME;
    result.encryption_key_id = source->key_id.data();
    give_struct(result, request);
    return ok(error);
}

LANTERN_API lantern_status lantern_decrypting_sink_create(const lantern_save_key* key,
    lantern_download_sink* out, const lantern_allocator* allocator, lantern_download_sink** sink,
    lantern_error* error)
{
    if (key == nullptr || out == nullptr || sink == nullptr)
        return usage(error, "a NULL argument");
    *sink = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto* decrypting = box_new<lantern::DecryptingSink>(
        resource.get(), *as_key(key), *out->impl, lantern::Allocator(resource.get()));
    *sink = give_sink(resource.get(), decrypting, decrypting);
    return ok(error);
}

LANTERN_API lantern_status lantern_decrypting_sink_finish(lantern_download_sink* sink, lantern_error* error)
{
    if (sink == nullptr)
        return usage(error, "sink is NULL");
    if (sink->decrypting == nullptr)
        return usage(error, "not a decrypting sink");
    const auto finished = sink->decrypting->finish();
    if (!finished)
        return fail(error, finished.error());
    return ok(error);
}

LANTERN_API uint64_t lantern_decrypting_sink_archive_bytes(const lantern_download_sink* sink)
{
    return sink == nullptr || sink->decrypting == nullptr ? 0 : sink->decrypting->archive_bytes();
}

LANTERN_API lantern_status lantern_encrypt_save(const lantern_save_key* key,
    const uint8_t header[LANTERN_SAVE_HEADER_SIZE], const uint8_t* archive, size_t size,
    const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (key == nullptr || header == nullptr || out == nullptr || (archive == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    const lantern::Allocator memory(resource.get());
    lantern::Vector<std::byte> sealed(memory);
    const auto done = lantern::encrypt_save(
        *as_key(key), header_of(header), std::as_bytes(span_of(archive, size)), sealed);
    if (!done)
        return fail(error, done.error());
    *out = give_string(
        resource.get(), std::string_view(reinterpret_cast<const char*>(sealed.data()), sealed.size()));
    return ok(error);
}

LANTERN_API lantern_status lantern_decrypt_save(const lantern_save_key* key, const uint8_t* backup,
    size_t size, lantern_download_sink* out, lantern_error* error)
{
    if (key == nullptr || out == nullptr || (backup == nullptr && size != 0))
        return usage(error, "a NULL argument");
    const auto done = lantern::decrypt_save(*as_key(key), std::as_bytes(span_of(backup, size)), *out->impl,
        lantern::Allocator(Resource::standard()));
    if (!done)
        return fail(error, done.error());
    return ok(error);
}

LANTERN_API bool lantern_hkdf_sha256(const uint8_t* salt, size_t salt_size, const uint8_t* ikm,
    size_t ikm_size, const uint8_t* info, size_t info_size, uint8_t* out, size_t out_size)
{
    if ((salt == nullptr && salt_size != 0) || (ikm == nullptr && ikm_size != 0)
        || (info == nullptr && info_size != 0) || (out == nullptr && out_size != 0))
        return false;
    return lantern::hkdf_sha256(span_of(salt, salt_size), span_of(ikm, ikm_size), span_of(info, info_size),
        std::span(out, out == nullptr ? 0 : out_size));
}

LANTERN_API void lantern_hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out[32])
{
    if (key == nullptr || nonce == nullptr || out == nullptr)
        return;
    auto k            = array_of<32>(key);
    const auto subkey = lantern::hchacha20(k, array_of<16>(nonce));
    lantern::secure_wipe(std::span<std::uint8_t>(k));
    std::memcpy(out, subkey.data(), subkey.size());
}

LANTERN_API lantern_status lantern_xchacha20poly1305_seal(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t* aad, size_t aad_size, const uint8_t* plain, size_t size, uint8_t* sealed,
    lantern_error* error)
{
    if (key == nullptr || nonce == nullptr || sealed == nullptr || (aad == nullptr && aad_size != 0)
        || (plain == nullptr && size != 0))
        return usage(error, "a NULL argument");
    auto k          = array_of<32>(key);
    const auto done = lantern::xchacha20poly1305_seal(k, array_of<24>(nonce), span_of(aad, aad_size),
        span_of(plain, size), std::span(sealed, size + lantern::save_tag_size));
    lantern::secure_wipe(std::span<std::uint8_t>(k));
    if (!done)
        return fail(error, done.error());
    return ok(error);
}

LANTERN_API lantern_status lantern_xchacha20poly1305_open(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t* aad, size_t aad_size, const uint8_t* sealed, size_t sealed_size, uint8_t* plain,
    lantern_error* error)
{
    if (key == nullptr || nonce == nullptr || sealed == nullptr || (aad == nullptr && aad_size != 0))
        return usage(error, "a NULL argument");
    if (sealed_size < lantern::save_tag_size)
        return fail(error, lantern::Category::integrity, "shorter than a tag");
    const std::size_t size = sealed_size - lantern::save_tag_size;
    if (plain == nullptr && size != 0)
        return usage(error, "plain is NULL");
    auto k          = array_of<32>(key);
    const auto done = lantern::xchacha20poly1305_open(k, array_of<24>(nonce), span_of(aad, aad_size),
        span_of(sealed, sealed_size), std::span(plain, plain == nullptr ? 0 : size));
    lantern::secure_wipe(std::span<std::uint8_t>(k));
    if (!done)
        return fail(error, done.error());
    return ok(error);
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
