// HMAC-SHA-256 (RFC 2104) and HKDF-SHA-256 (RFC 5869), over the library's
// SHA-256, for the save keys of SPEC.md § 9.4; and a wipe of secrets that
// the compiler does not remove (Monocypher's crypto_wipe).
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include <lantern/sha256.hpp>

namespace lantern
{

// Overwrites a secret with zeros, in a way the optimiser keeps.
void secure_wipe(std::span<std::uint8_t> secret) noexcept;
void secure_wipe(std::span<std::byte> secret) noexcept;

class HmacSha256
{
  public:
    explicit HmacSha256(std::span<const std::uint8_t> key) noexcept;
    HmacSha256(const HmacSha256&)            = delete;
    HmacSha256& operator=(const HmacSha256&) = delete;
    HmacSha256(HmacSha256&&)                 = delete;
    HmacSha256& operator=(HmacSha256&&)      = delete;
    // Wipes the keyed states.
    ~HmacSha256();

    void update(std::span<const std::uint8_t> bytes) noexcept;
    [[nodiscard]] Digest finish() noexcept;

    [[nodiscard]] static Digest of(
        std::span<const std::uint8_t> key, std::span<const std::uint8_t> message) noexcept;

  private:
    Sha256 inner_;
    Sha256 outer_;
};

// HKDF-SHA-256: `out` filled from `ikm`, `salt` (empty: 32 zero bytes, as
// RFC 5869 says) and `info`; false, and `out` untouched, beyond 255 × 32
// bytes.
[[nodiscard]] bool hkdf_sha256(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm,
    std::span<const std::uint8_t> info, std::span<std::uint8_t> out) noexcept;

} // namespace lantern
