// A server's certificate, any bytes (SPEC.md § 5.3): the SPKI read within
// its bounds, or refused, never a crash; what a ServerTrust pinned to
// another key does with it.
#include <cstddef>
#include <cstdint>
#include <span>

#include <lantern/tls.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::span<const std::uint8_t> der(data, size);
    const auto spki = lantern::certificate_spki(der);
    if (spki)
    {
        if (spki->data() < data || spki->data() + spki->size() > data + size || spki->size() < 4)
            __builtin_trap();
        lantern::ServerTrust trust;
        trust.pin(lantern::Digest {});
        if (trust.accept(*spki, true))
            __builtin_trap(); // a SHA-256 of zeros is no key's
    }
    return 0;
}
