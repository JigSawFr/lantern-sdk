// SHA-256 (FIPS 180-4), incremental: a download is hashed as it streams,
// and its state can be saved with a partial file and taken up again after
// a restart, so a resumed download is still checked whole.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace lantern
{

using Digest = std::array<std::uint8_t, 32>;

class Sha256
{
  public:
    // Everything a hash in progress is: kept by the app with a partial
    // download (save it as it is, on the same machine).
    struct State
    {
        std::array<std::uint32_t, 8> h {};
        std::array<std::uint8_t, 64> block {};
        std::uint64_t length = 0; // bytes hashed so far
    };

    Sha256() noexcept;
    explicit Sha256(const State& state) noexcept
        : state_(state)
    {
    }

    void update(std::span<const std::byte> bytes) noexcept;
    void update(std::string_view text) noexcept;
    // The digest; the object starts over afterwards.
    [[nodiscard]] Digest finish() noexcept;
    [[nodiscard]] const State& state() const noexcept { return state_; }
    [[nodiscard]] std::uint64_t length() const noexcept { return state_.length; }

    [[nodiscard]] static Digest of(std::span<const std::byte> bytes) noexcept;
    [[nodiscard]] static Digest of(std::string_view text) noexcept;

  private:
    void compress(const std::uint8_t* block) noexcept;
    State state_;
};

// Lower-case hex, as the protocol writes digests (64 characters).
[[nodiscard]] std::array<char, 64> to_hex(const Digest& digest) noexcept;
// A digest from exactly 64 lower-case hex digits (SPEC.md's form); nothing
// for anything else, upper case included.
[[nodiscard]] std::optional<Digest> digest_from_hex(std::string_view hex) noexcept;
// Two digests compared in constant time.
[[nodiscard]] bool same_digest(const Digest& a, const Digest& b) noexcept;

} // namespace lantern
