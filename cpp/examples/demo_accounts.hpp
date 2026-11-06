// The demo server's accounts: people and devices that do not exist, for the
// demo, the tests and the conformance run. The same as python/tests/demo.py's
// demo_accounts(): mira, who holds every scope, and the token of her console,
// bound to a key made from a fixed phrase; noor, who reads the library.
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include <lantern/lantern.hpp>

namespace lantern::demo
{

inline constexpr std::string_view token = "et_demo-0123456789abcdef0123456789abcdef";
// The seed of the console's key is the SHA-256 of this phrase: for the demo only, never a real device's.
inline constexpr std::string_view key_phrase = "Mira's fictional console key";

// The seed of the server's grant key (SPEC.md § 19.3) is the SHA-256 of this phrase: for the demo only.
inline constexpr std::string_view grant_phrase = "Demo shelf's fictional grant key";

inline std::array<std::uint8_t, 32> grant_seed()
{
    return Sha256::of(grant_phrase);
}

inline DeviceKey device_key()
{
    return DeviceKey::from_seed(Sha256::of(key_phrase));
}

// Adds mira, noor and the console's token to `store`.
inline Result<void> fill_accounts(MemoryAccountStore& store, std::int64_t now)
{
    if (auto added = store.add_account("mira", known_scopes, false, now); !added)
        return added;
    static constexpr std::array<std::string_view, 1> library { "library" };
    if (auto added = store.add_account("noor", library, false, now); !added)
        return added;
    const DeviceKey key = device_key();
    auto console = store.add_token(token, "mira", "Mira's console", known_scopes, key.public_key(), now);
    if (!console)
        return std::unexpected(console.error());
    return {};
}

} // namespace lantern::demo
