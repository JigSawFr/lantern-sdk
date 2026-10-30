#include <lantern/sha256.hpp>

#include <algorithm>
#include <bit>
#include <cstring>

namespace lantern
{

namespace
{

constexpr std::array<std::uint32_t, 64> round_constants {
    0x428a2f98U,
    0x71374491U,
    0xb5c0fbcfU,
    0xe9b5dba5U,
    0x3956c25bU,
    0x59f111f1U,
    0x923f82a4U,
    0xab1c5ed5U,
    0xd807aa98U,
    0x12835b01U,
    0x243185beU,
    0x550c7dc3U,
    0x72be5d74U,
    0x80deb1feU,
    0x9bdc06a7U,
    0xc19bf174U,
    0xe49b69c1U,
    0xefbe4786U,
    0x0fc19dc6U,
    0x240ca1ccU,
    0x2de92c6fU,
    0x4a7484aaU,
    0x5cb0a9dcU,
    0x76f988daU,
    0x983e5152U,
    0xa831c66dU,
    0xb00327c8U,
    0xbf597fc7U,
    0xc6e00bf3U,
    0xd5a79147U,
    0x06ca6351U,
    0x14292967U,
    0x27b70a85U,
    0x2e1b2138U,
    0x4d2c6dfcU,
    0x53380d13U,
    0x650a7354U,
    0x766a0abbU,
    0x81c2c92eU,
    0x92722c85U,
    0xa2bfe8a1U,
    0xa81a664bU,
    0xc24b8b70U,
    0xc76c51a3U,
    0xd192e819U,
    0xd6990624U,
    0xf40e3585U,
    0x106aa070U,
    0x19a4c116U,
    0x1e376c08U,
    0x2748774cU,
    0x34b0bcb5U,
    0x391c0cb3U,
    0x4ed8aa4aU,
    0x5b9cca4fU,
    0x682e6ff3U,
    0x748f82eeU,
    0x78a5636fU,
    0x84c87814U,
    0x8cc70208U,
    0x90befffaU,
    0xa4506cebU,
    0xbef9a3f7U,
    0xc67178f2U,
};

constexpr std::array<std::uint32_t, 8> initial {
    0x6a09e667U,
    0xbb67ae85U,
    0x3c6ef372U,
    0xa54ff53aU,
    0x510e527fU,
    0x9b05688cU,
    0x1f83d9abU,
    0x5be0cd19U,
};

} // namespace

Sha256::Sha256() noexcept
{
    state_.h = initial;
}

void Sha256::compress(const std::uint8_t* block) noexcept
{
    std::array<std::uint32_t, 64> w {};
    for (std::size_t i = 0; i < 16; ++i)
    {
        w[i] = (static_cast<std::uint32_t>(block[4 * i]) << 24U)
            | (static_cast<std::uint32_t>(block[4 * i + 1]) << 16U)
            | (static_cast<std::uint32_t>(block[4 * i + 2]) << 8U)
            | static_cast<std::uint32_t>(block[4 * i + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i)
    {
        const std::uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
        const std::uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
        w[i]                   = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = state_.h[0];
    std::uint32_t b = state_.h[1];
    std::uint32_t c = state_.h[2];
    std::uint32_t d = state_.h[3];
    std::uint32_t e = state_.h[4];
    std::uint32_t f = state_.h[5];
    std::uint32_t g = state_.h[6];
    std::uint32_t h = state_.h[7];
    for (std::size_t i = 0; i < 64; ++i)
    {
        const std::uint32_t s1     = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const std::uint32_t choice = (e & f) ^ (~e & g);
        const std::uint32_t t1     = h + s1 + choice + round_constants[i] + w[i];
        const std::uint32_t s0     = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const std::uint32_t major  = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2     = s0 + major;
        h                          = g;
        g                          = f;
        f                          = e;
        e                          = d + t1;
        d                          = c;
        c                          = b;
        b                          = a;
        a                          = t1 + t2;
    }
    state_.h[0] += a;
    state_.h[1] += b;
    state_.h[2] += c;
    state_.h[3] += d;
    state_.h[4] += e;
    state_.h[5] += f;
    state_.h[6] += g;
    state_.h[7] += h;
}

void Sha256::update(std::span<const std::byte> bytes) noexcept
{
    const auto* data = reinterpret_cast<const std::uint8_t*>(bytes.data());
    std::size_t size = bytes.size();
    auto filled      = static_cast<std::size_t>(state_.length % 64);
    state_.length += size;
    if (filled != 0)
    {
        const std::size_t take = std::min<std::size_t>(64 - filled, size);
        std::memcpy(state_.block.data() + filled, data, take);
        data += take;
        size -= take;
        filled += take;
        if (filled < 64)
            return;
        compress(state_.block.data());
    }
    while (size >= 64)
    {
        compress(data);
        data += 64;
        size -= 64;
    }
    if (size != 0)
        std::memcpy(state_.block.data(), data, size);
}

void Sha256::update(std::string_view text) noexcept
{
    update(std::as_bytes(std::span(text.data(), text.size())));
}

Digest Sha256::finish() noexcept
{
    const std::uint64_t bits = state_.length * 8;
    auto filled              = static_cast<std::size_t>(state_.length % 64);
    state_.block[filled++]   = 0x80U;
    if (filled > 56)
    {
        std::memset(state_.block.data() + filled, 0, 64 - filled);
        compress(state_.block.data());
        filled = 0;
    }
    std::memset(state_.block.data() + filled, 0, 56 - filled);
    for (std::size_t i = 0; i < 8; ++i)
        state_.block[56 + i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    compress(state_.block.data());
    Digest out {};
    for (std::size_t i = 0; i < 8; ++i)
    {
        out[4 * i]     = static_cast<std::uint8_t>(state_.h[i] >> 24U);
        out[4 * i + 1] = static_cast<std::uint8_t>(state_.h[i] >> 16U);
        out[4 * i + 2] = static_cast<std::uint8_t>(state_.h[i] >> 8U);
        out[4 * i + 3] = static_cast<std::uint8_t>(state_.h[i]);
    }
    state_   = State {};
    state_.h = initial;
    return out;
}

Digest Sha256::of(std::span<const std::byte> bytes) noexcept
{
    Sha256 hash;
    hash.update(bytes);
    return hash.finish();
}

Digest Sha256::of(std::string_view text) noexcept
{
    Sha256 hash;
    hash.update(text);
    return hash.finish();
}

std::array<char, 64> to_hex(const Digest& digest) noexcept
{
    static constexpr std::string_view hex = "0123456789abcdef";
    std::array<char, 64> out {};
    for (std::size_t i = 0; i < digest.size(); ++i)
    {
        out[2 * i]     = hex[digest[i] >> 4U];
        out[2 * i + 1] = hex[digest[i] & 0x0FU];
    }
    return out;
}

std::optional<Digest> digest_from_hex(std::string_view hex) noexcept
{
    if (hex.size() != 64)
        return std::nullopt;
    const auto nibble = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        return -1;
    };
    Digest out {};
    for (std::size_t i = 0; i < out.size(); ++i)
    {
        const int high = nibble(hex[2 * i]);
        const int low  = nibble(hex[2 * i + 1]);
        if (high < 0 || low < 0)
            return std::nullopt;
        out[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return out;
}

bool same_digest(const Digest& a, const Digest& b) noexcept
{
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        difference = static_cast<std::uint8_t>(difference | (a[i] ^ b[i]));
    return difference == 0;
}

} // namespace lantern
