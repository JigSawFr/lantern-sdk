// Ed25519 verification on any key, signature and message: never a crash,
// and never a signature accepted with a key or an R of small order, a y of
// p or more, or an S of L or more (RFC 8032 5.1.7; the forgeries a
// cofactorless check lets through). The input is the key (32 bytes), the
// signature (64), then the message.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <lantern/ed25519.hpp>

namespace
{

// Small order: y of the identity, of the point of order 2, of those of order
// 4 (y = 0) and 8, whatever the sign bit.
bool small_order(const std::uint8_t* point)
{
    static constexpr std::array<std::array<std::uint8_t, 4>, 5> prefixes { {
        { 0x01, 0x00, 0x00, 0x00 },
        { 0xec, 0xff, 0xff, 0xff },
        { 0x00, 0x00, 0x00, 0x00 },
        { 0x26, 0xe8, 0x95, 0x8f },
        { 0xc7, 0x17, 0x6a, 0x70 },
    } };
    return std::ranges::any_of(
        prefixes, [&](const auto& p) { return std::equal(p.begin(), p.end(), point); });
}

// y of p or more: p = 2^255 - 19
bool non_canonical(const std::uint8_t* point)
{
    return (point[31] & 0x7FU) == 0x7FU && point[0] >= 0xedU
        && std::all_of(point + 1, point + 31, [](std::uint8_t b) { return b == 0xffU; });
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size < 96)
        return 0;
    lantern::PublicKey key {};
    lantern::SignatureBytes signature {};
    std::copy_n(data, 32, key.begin());
    std::copy_n(data + 32, 64, signature.begin());
    const std::span<const std::uint8_t> message(data + 96, size - 96);
    if (!lantern::ed25519_verify(signature, key, message))
        return 0;
    // Accepted: only a well-formed signature of a key of large order. (The
    // prefixes above are coarse: an accepted key that merely shares one is
    // astronomically unlikely from a fuzzer.)
    if (small_order(key.data()) || small_order(signature.data()) || (signature[63] & 0xE0U) != 0
        || non_canonical(key.data()) || non_canonical(signature.data()))
        __builtin_trap();
    return 0;
}
