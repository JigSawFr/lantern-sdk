#include <lantern/hkdf.hpp>

#include <algorithm>
#include <array>
#include <type_traits>

extern "C"
{
#include "monocypher.h"
}

namespace lantern
{

void secure_wipe(std::span<std::uint8_t> secret) noexcept
{
    if (!secret.empty())
        crypto_wipe(secret.data(), secret.size());
}

void secure_wipe(std::span<std::byte> secret) noexcept
{
    if (!secret.empty())
        crypto_wipe(secret.data(), secret.size());
}

namespace
{

constexpr std::size_t block = 64;

void wipe_state(Sha256& hash) noexcept
{
    // A state holds what the key made of it: overwritten through its bytes
    static_assert(std::is_trivially_copyable_v<Sha256>);
    secure_wipe(std::as_writable_bytes(std::span(&hash, 1)));
}

} // namespace

HmacSha256::HmacSha256(std::span<const std::uint8_t> key) noexcept
{
    std::array<std::uint8_t, block> pad {};
    if (key.size() > block)
    {
        Digest hashed = Sha256::of(std::as_bytes(key));
        std::ranges::copy(hashed, pad.begin());
        secure_wipe(hashed);
    }
    else
        std::ranges::copy(key, pad.begin());
    std::array<std::uint8_t, block> inner_pad {};
    std::array<std::uint8_t, block> outer_pad {};
    for (std::size_t i = 0; i < block; ++i)
    {
        inner_pad[i] = static_cast<std::uint8_t>(pad[i] ^ 0x36U);
        outer_pad[i] = static_cast<std::uint8_t>(pad[i] ^ 0x5CU);
    }
    inner_.update(std::as_bytes(std::span(inner_pad)));
    outer_.update(std::as_bytes(std::span(outer_pad)));
    secure_wipe(pad);
    secure_wipe(inner_pad);
    secure_wipe(outer_pad);
}

HmacSha256::~HmacSha256()
{
    wipe_state(inner_);
    wipe_state(outer_);
}

void HmacSha256::update(std::span<const std::uint8_t> bytes) noexcept
{
    inner_.update(std::as_bytes(bytes));
}

Digest HmacSha256::finish() noexcept
{
    Digest inner = inner_.finish();
    outer_.update(std::as_bytes(std::span(inner)));
    secure_wipe(inner);
    return outer_.finish();
}

Digest HmacSha256::of(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message) noexcept
{
    HmacSha256 mac(key);
    mac.update(message);
    return mac.finish();
}

bool hkdf_sha256(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm,
    std::span<const std::uint8_t> info, std::span<std::uint8_t> out) noexcept
{
    constexpr std::size_t hash = 32;
    if (out.size() > 255 * hash)
        return false;
    // Extract: PRK = HMAC(salt, IKM); an empty salt is a block of zeros
    const std::array<std::uint8_t, hash> zeros {};
    Digest prk = HmacSha256::of(salt.empty() ? std::span<const std::uint8_t>(zeros) : salt, ikm);
    // Expand: T(i) = HMAC(PRK, T(i-1) | info | i)
    Digest previous {};
    std::size_t written = 0;
    for (std::uint8_t counter = 1; written < out.size(); ++counter)
    {
        HmacSha256 mac(prk);
        if (counter > 1)
            mac.update(previous);
        mac.update(info);
        const std::array<std::uint8_t, 1> index { counter };
        mac.update(index);
        previous               = mac.finish();
        const std::size_t take = std::min(hash, out.size() - written);
        std::copy_n(previous.begin(), take, out.begin() + static_cast<std::ptrdiff_t>(written));
        written += take;
    }
    secure_wipe(prk);
    secure_wipe(previous);
    return true;
}

} // namespace lantern
