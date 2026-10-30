#include <lantern/device_key.hpp>

#include <algorithm>
#include <array>

#include <lantern/encoding.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>

extern "C"
{
#include "monocypher-ed25519.h"
#include "monocypher.h"
}

namespace lantern
{

Result<DeviceKey> DeviceKey::generate(RandomSource& random)
{
    KeySeed seed {};
    if (auto filled = random.fill(seed); !filled)
        return std::unexpected(filled.error());
    // A source that gives nothing (all zero) is broken, not random
    if (std::ranges::all_of(seed, [](std::uint8_t b) { return b == 0; }))
        return fail(Category::storage, "the random source gave only zeros");
    DeviceKey key = from_seed(seed);
    crypto_wipe(seed.data(), seed.size());
    return key;
}

DeviceKey DeviceKey::from_seed(const KeySeed& seed) noexcept
{
    DeviceKey key;
    KeySeed copy = seed; // Monocypher wipes the seed it is given
    crypto_ed25519_key_pair(key.secret_.data(), key.public_.data(), copy.data());
    return key;
}

DeviceKey::DeviceKey(const DeviceKey&) noexcept            = default;
DeviceKey& DeviceKey::operator=(const DeviceKey&) noexcept = default;

DeviceKey::DeviceKey(DeviceKey&& other) noexcept
    : secret_(other.secret_)
    , public_(other.public_)
{
    crypto_wipe(other.secret_.data(), other.secret_.size());
}

DeviceKey& DeviceKey::operator=(DeviceKey&& other) noexcept
{
    if (this != &other)
    {
        secret_ = other.secret_;
        public_ = other.public_;
        crypto_wipe(other.secret_.data(), other.secret_.size());
    }
    return *this;
}

DeviceKey::~DeviceKey()
{
    crypto_wipe(secret_.data(), secret_.size());
}

KeySeed DeviceKey::seed() const noexcept
{
    KeySeed out {};
    std::copy_n(secret_.begin(), out.size(), out.begin());
    return out;
}

std::array<char, 43> key_thumbprint(const PublicKey& public_key) noexcept
{
    const Digest digest = Sha256::of(std::as_bytes(std::span(public_key)));
    // 32 bytes are 43 characters of base64url without padding: no allocation
    std::array<char, 43> out {};
    static_cast<void>(base64url_encode(digest, out));
    return out;
}

std::array<char, 43> DeviceKey::keyid() const noexcept
{
    return key_thumbprint(public_);
}

std::array<char, 19> DeviceKey::fingerprint() const noexcept
{
    return short_fingerprint(public_);
}

SignatureBytes DeviceKey::sign(std::span<const std::uint8_t> message) const noexcept
{
    SignatureBytes out {};
    crypto_ed25519_sign(out.data(), secret_.data(), message.data(), message.size());
    return out;
}

} // namespace lantern
