// An encrypted backup, any bytes (SPEC.md § 9.4): the decryptor never
// crashes, hands on only chunks that opened, and accepts nothing but what
// the key sealed: an input that is not a backup of the fuzzer's key never
// finishes. Half the inputs are a real backup of the input's bytes with
// one byte changed, so that the chunks' checks are reached.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <lantern/encrypted_save.hpp>

namespace
{

class Sink final : public lantern::DownloadSink
{
  public:
    std::size_t bytes = 0;
    lantern::Result<void> write(std::span<const std::byte> chunk) override
    {
        bytes += chunk.size();
        return {};
    }
    lantern::Result<void> restart() override
    {
        bytes = 0;
        return {};
    }
};

const lantern::SaveKey& key()
{
    static const lantern::SaveKey made = lantern::SaveKey::from_bytes(lantern::SaveKeyBytes { 7, 1, 2, 3 });
    return made;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size == 0)
        return 0;
    const auto input = std::as_bytes(std::span(data + 1, size - 1));
    if ((data[0] & 1U) == 0)
    {
        // Any bytes: refused, unless they happen to be a backup of the key
        Sink sink;
        lantern::DecryptingSink opening(key(), sink);
        const auto written = opening.write(input);
        if (written && opening.finish())
            __builtin_trap();
        return 0;
    }
    // A backup of the input, then one byte flipped where the input says
    const lantern::SaveHeader header
        = lantern::make_save_header(key(), lantern::FileKey { 9 }, lantern::WrapNonce { 4 });
    lantern::Vector<std::byte> backup;
    if (!lantern::encrypt_save(key(), header, input, backup))
        __builtin_trap();
    Sink whole;
    if (!lantern::decrypt_save(key(), backup, whole) || whole.bytes != input.size())
        __builtin_trap();
    const std::size_t at = (static_cast<std::size_t>(data[0] >> 1U) * 131U + input.size()) % backup.size();
    backup[at] ^= std::byte { 0x20 };
    Sink changed;
    if (lantern::decrypt_save(key(), backup, changed))
        __builtin_trap(); // a changed byte never goes unnoticed (L-9.4-1)
    return 0;
}
