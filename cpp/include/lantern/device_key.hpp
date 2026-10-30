// The device's key (SPEC.md § 5.4): an Ed25519 key pair the device makes
// for one server when it pairs, whose public half the server binds the
// token to. Every request that carries the token is then signed by it
// (http_signature.hpp), so a token copied off the device is worth nothing
// alone.
//
// The library makes the key from the app's RandomSource and signs with it;
// the app keeps it, with the token, through its CredentialStore
// (credentials.hpp): where its system protects keys, when it has such a
// place (L-5.4-5). Its private half is never sent anywhere (L-5.4-4).
#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <lantern/ed25519.hpp>
#include <lantern/error.hpp>

namespace lantern
{

// Random bytes, from the platform's cryptographic generator: getrandom()
// or getentropy() on Linux and the BSDs, BCryptGenRandom on Windows,
// SecRandomCopyBytes on Apple's systems, csrngGetRandomBytes on a Switch
// (libnx), sceKernelGetRandomNumber elsewhere. The library has none of its
// own: a key or a nonce from a generator that is not cryptographic is no
// key at all. adapters/posix gives one for POSIX systems.
class RandomSource
{
  public:
    RandomSource()                               = default;
    RandomSource(const RandomSource&)            = default;
    RandomSource(RandomSource&&)                 = default;
    RandomSource& operator=(const RandomSource&) = default;
    RandomSource& operator=(RandomSource&&)      = default;
    virtual ~RandomSource()                      = default;

    // Fills `out` entirely, or fails (Category::storage is fine).
    [[nodiscard]] virtual Result<void> fill(std::span<std::uint8_t> out) = 0;
};

using KeySeed = std::array<std::uint8_t, 32>;

class DeviceKey
{
  public:
    // A new key, for one server (§ 5.4: a device that pairs again makes a new one).
    [[nodiscard]] static Result<DeviceKey> generate(RandomSource& random);
    // The key of a seed the app kept (seed()).
    [[nodiscard]] static DeviceKey from_seed(const KeySeed& seed) noexcept;

    DeviceKey(const DeviceKey&) noexcept;
    DeviceKey& operator=(const DeviceKey&) noexcept;
    DeviceKey(DeviceKey&& other) noexcept;
    DeviceKey& operator=(DeviceKey&& other) noexcept;
    // Wipes the private key.
    ~DeviceKey();

    // The 32 bytes the app keeps: the whole key derives from them.
    [[nodiscard]] KeySeed seed() const noexcept;
    [[nodiscard]] const PublicKey& public_key() const noexcept { return public_; }
    // keyid (§ 5.4): the base64url of the SHA-256 of the public key, without
    // padding, 43 characters.
    [[nodiscard]] std::array<char, 43> keyid() const noexcept;
    // The short fingerprint of the public key, for people (§ 5.3's form).
    [[nodiscard]] std::array<char, 19> fingerprint() const noexcept;
    [[nodiscard]] SignatureBytes sign(std::span<const std::uint8_t> message) const noexcept;

  private:
    DeviceKey() = default;
    std::array<std::uint8_t, 64> secret_ {}; // Monocypher's: the seed, then the public key
    PublicKey public_ {};
};

// keyid of any Ed25519 public key.
[[nodiscard]] std::array<char, 43> key_thumbprint(const PublicKey& public_key) noexcept;

} // namespace lantern
