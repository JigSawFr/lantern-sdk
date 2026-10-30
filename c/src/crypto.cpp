// The server's key (§ 5.3), the device's key and signed requests (§ 5.4),
// and the digest fields.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#include <lantern/device_key.hpp>
#include <lantern/digest.hpp>
#include <lantern/ed25519.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/tls.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

const lantern::DeviceKey* as_key(const lantern_device_key* key) noexcept
{
    return reinterpret_cast<const lantern::DeviceKey*>(key);
}

lantern::SignedComponents components_of(const lantern_signed_components& c) noexcept
{
    lantern::SignedComponents out;
    out.method         = text(c.method);
    out.target_uri     = text(c.target_uri);
    out.authorization  = text(c.authorization);
    out.content_digest = text(c.content_digest);
    return out;
}

lantern_status give_key(lantern::Result<lantern::DeviceKey>&& key, const lantern_allocator* allocator,
    lantern_device_key** out, lantern_error* error)
{
    if (!key)
        return fail(error, key.error());
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    *out
        = reinterpret_cast<lantern_device_key*>(box_new<lantern::DeviceKey>(resource.get(), std::move(*key)));
    return ok(error);
}

template <std::size_t N> void copy_chars(const std::array<char, N>& from, char* out) noexcept
{
    std::memcpy(out, from.data(), N);
    out[N] = '\0';
}

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API void lantern_format_digest_field(const uint8_t digest[32], char out[55])
{
    if (digest == nullptr || out == nullptr)
        return;
    lantern::String field;
    lantern::format_digest_field(digest_of(digest), field);
    copy_text(field, out, 55);
}

LANTERN_API lantern_digest_field lantern_parse_digest_field(const char* value, uint8_t out[32])
{
    const lantern::ParsedDigest parsed = lantern::parse_digest_field(text(value));
    if (parsed.state == lantern::DigestField::sha256 && out != nullptr)
        copy_digest(parsed.sha256, out);
    return static_cast<lantern_digest_field>(parsed.state);
}

LANTERN_API void lantern_short_form(const uint8_t digest[32], char out[20])
{
    if (digest == nullptr || out == nullptr)
        return;
    copy_chars(lantern::short_form(digest_of(digest)), out);
}

LANTERN_API lantern_status lantern_spki_sha256(
    const uint8_t* certificate_der, size_t size, uint8_t out[32], lantern_error* error)
{
    if (out == nullptr || (certificate_der == nullptr && size != 0))
        return usage(error, "a NULL argument");
    const auto digest = lantern::spki_sha256(std::span(certificate_der, size));
    if (!digest)
        return fail(error, digest.error());
    copy_digest(*digest, out);
    return ok(error);
}

LANTERN_API lantern_status lantern_spki_sha256_pem(const char* pem, uint8_t out[32], lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    const auto digest = lantern::spki_sha256_pem(text(pem));
    if (!digest)
        return fail(error, digest.error());
    copy_digest(*digest, out);
    return ok(error);
}

LANTERN_API lantern_status lantern_trust_create(
    const lantern_allocator* allocator, lantern_trust** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    *out = box_new<lantern_trust>(resource.get());
    return ok(error);
}

LANTERN_API void lantern_trust_free(lantern_trust* trust)
{
    unbox(trust);
}

LANTERN_API void lantern_trust_require_ca(lantern_trust* trust)
{
    if (trust != nullptr)
        trust->trust.require_ca();
}

LANTERN_API void lantern_trust_pin(lantern_trust* trust, const uint8_t spki_sha256[32])
{
    if (trust != nullptr && spki_sha256 != nullptr)
        trust->trust.pin(digest_of(spki_sha256));
}

LANTERN_API void lantern_trust_allow_unverified(lantern_trust* trust)
{
    if (trust != nullptr)
        trust->trust.allow_unverified();
}

LANTERN_API lantern_trust_mode lantern_trust_get_mode(const lantern_trust* trust)
{
    return trust == nullptr ? LANTERN_TRUST_CA : static_cast<lantern_trust_mode>(trust->trust.mode());
}

LANTERN_API bool lantern_trust_get_pin(const lantern_trust* trust, uint8_t out[32])
{
    if (trust == nullptr || out == nullptr || !trust->trust.pinned())
        return false;
    copy_digest(*trust->trust.pinned(), out);
    return true;
}

LANTERN_API bool lantern_trust_get_seen(const lantern_trust* trust, uint8_t out[32])
{
    if (trust == nullptr || out == nullptr || !trust->trust.seen())
        return false;
    copy_digest(*trust->trust.seen(), out);
    return true;
}

LANTERN_API uint32_t lantern_trust_get_generation(const lantern_trust* trust)
{
    return trust == nullptr ? 0 : trust->trust.generation();
}

LANTERN_API bool lantern_trust_accept(
    lantern_trust* trust, const uint8_t* spki_der, size_t size, bool ca_verified)
{
    if (trust == nullptr || spki_der == nullptr)
        return false;
    return trust->trust.accept(std::span(spki_der, size), ca_verified);
}

LANTERN_API bool lantern_trust_accept_certificate(
    lantern_trust* trust, const uint8_t* certificate_der, size_t size, bool ca_verified)
{
    if (trust == nullptr || certificate_der == nullptr)
        return false;
    const auto spki = lantern::certificate_spki(std::span(certificate_der, size));
    if (!spki)
        return false;
    return trust->trust.accept(*spki, ca_verified);
}

LANTERN_API lantern_status lantern_parse_invitation_link(
    const char* link, lantern_invitation_link* out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    const auto parsed = lantern::parse_invitation_link(text(link));
    if (!parsed)
        return fail(error, parsed.error());
    lantern_invitation_link result {};
    result.struct_size = sizeof(result);
    copy_text(parsed->code, result.code, sizeof(result.code));
    if (parsed->spki)
    {
        result.has_spki = true;
        copy_digest(*parsed->spki, result.spki);
    }
    give_struct(result, out);
    return ok(error);
}

LANTERN_API bool lantern_is_pairing_code(const char* code)
{
    return lantern::is_pairing_code(text(code));
}

LANTERN_API bool lantern_is_invitation_code(const char* code)
{
    return lantern::is_invitation_code(text(code));
}

LANTERN_API lantern_status lantern_device_key_generate(lantern_random* random,
    const lantern_allocator* allocator, lantern_device_key** out, lantern_error* error)
{
    if (out == nullptr || random == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    return give_key(lantern::DeviceKey::generate(*random), allocator, out, error);
}

LANTERN_API lantern_status lantern_device_key_from_seed(const uint8_t seed[32],
    const lantern_allocator* allocator, lantern_device_key** out, lantern_error* error)
{
    if (out == nullptr || seed == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    lantern::KeySeed copy {};
    std::memcpy(copy.data(), seed, copy.size());
    auto key = lantern::DeviceKey::from_seed(copy);
    std::ranges::fill(copy, std::uint8_t { 0 });
    return give_key(std::move(key), allocator, out, error);
}

LANTERN_API void lantern_device_key_free(lantern_device_key* key)
{
    unbox(reinterpret_cast<lantern::DeviceKey*>(key));
}

LANTERN_API void lantern_device_key_seed(const lantern_device_key* key, uint8_t out[32])
{
    if (key == nullptr || out == nullptr)
        return;
    auto seed = as_key(key)->seed();
    std::memcpy(out, seed.data(), seed.size());
    std::ranges::fill(seed, std::uint8_t { 0 });
}

LANTERN_API void lantern_device_key_public_key(const lantern_device_key* key, uint8_t out[32])
{
    if (key == nullptr || out == nullptr)
        return;
    const auto& public_key = as_key(key)->public_key();
    std::memcpy(out, public_key.data(), public_key.size());
}

LANTERN_API void lantern_device_key_keyid(const lantern_device_key* key, char out[44])
{
    if (key == nullptr || out == nullptr)
        return;
    copy_chars(as_key(key)->keyid(), out);
}

LANTERN_API void lantern_device_key_fingerprint(const lantern_device_key* key, char out[20])
{
    if (key == nullptr || out == nullptr)
        return;
    copy_chars(as_key(key)->fingerprint(), out);
}

LANTERN_API void lantern_device_key_sign(
    const lantern_device_key* key, const uint8_t* message, size_t size, uint8_t out[64])
{
    if (key == nullptr || out == nullptr || (message == nullptr && size != 0))
        return;
    const auto signature = as_key(key)->sign(std::span(message, message == nullptr ? 0 : size));
    std::memcpy(out, signature.data(), signature.size());
}

LANTERN_API bool lantern_ed25519_verify(
    const uint8_t signature[64], const uint8_t public_key[32], const uint8_t* message, size_t size)
{
    if (signature == nullptr || public_key == nullptr || (message == nullptr && size != 0))
        return false;
    lantern::SignatureBytes s {};
    lantern::PublicKey k {};
    std::memcpy(s.data(), signature, s.size());
    std::memcpy(k.data(), public_key, k.size());
    return lantern::ed25519_verify(s, k, std::span(message, message == nullptr ? 0 : size));
}

LANTERN_API lantern_status lantern_target_uri(
    const char* url, const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto uri = lantern::target_uri(text(url), lantern::Allocator(resource.get()));
    if (!uri)
        return fail(error, uri.error());
    *out = give_string(resource.get(), std::move(*uri));
    return ok(error);
}

LANTERN_API lantern_status lantern_signature_base(const lantern_signed_components* components,
    int64_t created, const char* nonce, const char* keyid, const lantern_allocator* allocator,
    lantern_string** out, lantern_error* error)
{
    if (out == nullptr || components == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    const lantern::SignedComponents c = components_of(copy_struct(components));
    lantern::String params(lantern::Allocator(resource.get()));
    lantern::signature_params(c, created, text(nonce), text(keyid), params);
    lantern::String base(lantern::Allocator(resource.get()));
    lantern::signature_base(c, params, base);
    *out = give_string(resource.get(), std::move(base));
    return ok(error);
}

LANTERN_API lantern_status lantern_sign_components(const lantern_device_key* key,
    const lantern_signed_components* components, int64_t created, const char* nonce,
    const lantern_allocator* allocator, lantern_string** signature_input, lantern_string** signature,
    lantern_error* error)
{
    if (key == nullptr || components == nullptr || signature_input == nullptr || signature == nullptr)
        return usage(error, "a NULL argument");
    *signature_input = nullptr;
    *signature       = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    lantern::SignatureHeaders headers(lantern::Allocator(resource.get()));
    const auto signed_ = lantern::sign_components(
        *as_key(key), components_of(copy_struct(components)), created, text(nonce), headers);
    if (!signed_)
        return fail(error, signed_.error());
    *signature_input = give_string(resource.get(), std::move(headers.signature_input));
    *signature       = give_string(resource.get(), std::move(headers.signature));
    return ok(error);
}

LANTERN_API lantern_status lantern_check_signature(
    const lantern_signature_check* check, lantern_signature_verdict* out, lantern_error* error)
{
    if (check == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    const lantern_signature_check c = copy_struct(check);
    lantern::SignatureCheck in;
    in.method          = text(c.method);
    in.target_uri      = text(c.target_uri);
    in.authorization   = text(c.authorization);
    in.content_digest  = text(c.content_digest);
    in.has_body        = c.has_body;
    in.signature_input = text(c.signature_input);
    in.signature       = text(c.signature);
    std::memcpy(in.key.data(), c.public_key, in.key.size());
    in.now  = c.now;
    in.skew = c.skew == 0 ? lantern::default_skew : c.skew;
    if (c.has_body_sha256)
        in.body_sha256 = digest_of(c.body_sha256);
    const lantern::SignatureVerdict verdict = lantern::check_signature(in);
    lantern_signature_verdict result {};
    result.struct_size = sizeof(result);
    result.code        = static_cast<lantern_code>(verdict.code);
    copy_text(verdict.nonce, result.nonce, sizeof(result.nonce));
    copy_text(verdict.keyid, result.keyid, sizeof(result.keyid));
    give_struct(result, out);
    return ok(error);
}

LANTERN_API bool lantern_parse_http_date(const char* value, int64_t* out)
{
    const auto parsed = lantern::parse_http_date(text(value));
    if (!parsed)
        return false;
    if (out != nullptr)
        *out = *parsed;
    return true;
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
