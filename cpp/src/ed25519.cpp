#include <lantern/ed25519.hpp>

#include <lantern/encoding.hpp>
#include <lantern/homebrew.hpp>
#include <lantern/sha256.hpp>

extern "C"
{
#include "monocypher-ed25519.h"
}

#include <algorithm>
#include <array>

namespace lantern
{

namespace
{

using Encoding = std::array<std::uint8_t, 32>;

constexpr Encoding encoding(std::string_view hex)
{
    Encoding out {};
    const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>(nibble(hex[2 * i]) * 16 + nibble(hex[2 * i + 1]));
    return out;
}

// The points of small order (1, 2, 4 and 8), each with both values of the
// sign bit. A key or an R among them forges signatures that a cofactorless
// check accepts for some messages (with S = 0, about one in nine): refused
// whatever Monocypher's version does with them.
constexpr std::array<Encoding, 8> small_order {
    encoding("0100000000000000000000000000000000000000000000000000000000000000"),
    encoding("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    encoding("0000000000000000000000000000000000000000000000000000000000000000"),
    encoding("0000000000000000000000000000000000000000000000000000000000000080"),
    encoding("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    encoding("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    encoding("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    encoding("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
};

// p = 2^255 - 19 and the group's order L, little-endian.
constexpr Encoding field_prime = encoding("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
constexpr Encoding group_order = encoding("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

// Whether the little-endian number `a` (its top bit ignored when `y_only`) is below `b`.
bool below(const std::uint8_t* a, const Encoding& b, bool y_only) noexcept
{
    for (std::size_t i = b.size(); i-- > 0;)
    {
        const std::uint8_t byte = (y_only && i == 31) ? static_cast<std::uint8_t>(a[i] & 0x7FU) : a[i];
        if (byte != b[i])
            return byte < b[i];
    }
    return false;
}

// A point's encoding a verifier may take: y canonical (below p), and not
// of small order. Whether it decodes at all is Monocypher's to check for the
// key; an R that does not decode can never equal the encoding it computes.
bool acceptable_point(const std::uint8_t* point) noexcept
{
    if (!below(point, field_prime, true))
        return false;
    return std::ranges::none_of(
        small_order, [&](const Encoding& bad) { return std::equal(bad.begin(), bad.end(), point); });
}

} // namespace

bool ed25519_verify(const SignatureBytes& signature, const PublicKey& public_key,
    std::span<const std::uint8_t> message) noexcept
{
    // RFC 8032 5.1.7's checks, before the equation: A and R canonical and
    // not of small order, S below L
    if (!acceptable_point(public_key.data()) || !acceptable_point(signature.data())
        || !below(signature.data() + 32, group_order, false))
        return false;
    return crypto_ed25519_check(signature.data(), public_key.data(), message.data(), message.size()) == 0;
}

Result<PackageSignature> verify_package_signature(const Homebrew& entry, const Package& package)
{
    const bool main_package                   = &package == &entry.package;
    const std::optional<Signature>* signature = main_package ? &entry.signature : &package.signature;
    if (!signature->has_value())
    {
        if (!main_package && entry.signature)
            return fail(
                Category::signature, "a package of a signed entry without its own signature (SPEC.md 8.4)");
        return PackageSignature {};
    }
    const Signature& value = **signature;
    if (value.alg != "ed25519")
        return fail(Category::signature, "a signature of an algorithm other than ed25519");
    PackageSignature out;
    out.is_signed = true;
    SignatureBytes bytes {};
    if (!base64_decode(value.public_key, out.public_key) || !base64_decode(value.value, bytes))
        return fail(Category::signature, "a signature whose key or value is not of its size in base64");
    String message;
    signed_message(entry.id, entry.platform, entry.build, package.sha256, package.manifest_sha256, message);
    const auto* data = reinterpret_cast<const std::uint8_t*>(message.data());
    if (!ed25519_verify(bytes, out.public_key, std::span(data, message.size())))
        return fail(Category::signature, "the package's signature does not verify: install nothing");
    return out;
}

std::array<char, 19> short_fingerprint(std::span<const std::uint8_t> bytes) noexcept
{
    static constexpr std::string_view hex = "0123456789ABCDEF";
    const Digest digest                   = Sha256::of(std::as_bytes(bytes));
    std::array<char, 19> out {};
    std::size_t at = 0;
    for (std::size_t i = 0; i < 8; ++i)
    {
        if (i != 0 && i % 2 == 0)
            out[at++] = ' ';
        out[at++] = hex[digest[i] >> 4U];
        out[at++] = hex[digest[i] & 0x0FU];
    }
    return out;
}

} // namespace lantern
