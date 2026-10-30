// What a paired device keeps for a server (SPEC.md § 5): its token, the
// device key the token is bound to (§ 5.4), and the server key it pinned
// (§ 5.3), all for the server's `uid`.
//
// The library decides; the app stores, as with homebrew pins
// (pinning.hpp): CredentialStore is the app's, kept where its system
// protects secrets when it has such a place (a keychain, a keystore, the
// console's own save area otherwise). The token and the key's seed are
// secrets: the app never logs them, and sends them nowhere (L-5.4-4).
#pragma once

#include <optional>
#include <string_view>

#include <lantern/device_key.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>

namespace lantern
{

struct Credentials
{
    using allocator_type = Allocator;

    String token; // the bearer token (§ 5.1)
    std::optional<KeySeed> key; // the device key, when the token is bound (§ 5.4)
    std::optional<Digest> spki; // the server key pinned at pairing (§ 5.3), when no CA vouches for it

    Credentials()
        : Credentials(allocator_type {})
    {
    }
    explicit Credentials(const allocator_type& allocator)
        : token(allocator)
    {
    }
};

class CredentialStore
{
  public:
    CredentialStore()                                  = default;
    CredentialStore(const CredentialStore&)            = default;
    CredentialStore(CredentialStore&&)                 = default;
    CredentialStore& operator=(const CredentialStore&) = default;
    CredentialStore& operator=(CredentialStore&&)      = default;
    virtual ~CredentialStore()                         = default;

    // What is kept for the server of `uid`, or nothing before it paired.
    [[nodiscard]] virtual Result<std::optional<Credentials>> load(std::string_view uid, Allocator allocator)
        = 0;
    // Replaces what is kept for `uid` (after a pairing, or a new pin).
    [[nodiscard]] virtual Result<void> store(std::string_view uid, const Credentials& credentials) = 0;
    // Forgets `uid` (its token was revoked, or the user pairs again).
    [[nodiscard]] virtual Result<void> erase(std::string_view uid) = 0;
};

} // namespace lantern
