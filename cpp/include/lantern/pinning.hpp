// Homebrew key pinning (SPEC.md § 8.4): on the first install of an id, the
// client pins its key, or that it had none; a later version signed by
// another key, or unsigned after a signed one, is refused unless the user
// explicitly accepts the change after seeing both keys' short fingerprints.
//
// The library decides; the app stores: KeyPinStore is the app's, kept
// wherever it keeps its state (a file on the SD card, a database), and the
// library only reads and writes pins through it.
//
// (Draft 0.4 changes tokens and pairing; server key pinning by SPKI, § 5.3,
// comes with it.)
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include <lantern/ed25519.hpp>
#include <lantern/error.hpp>

namespace lantern
{

struct PinnedKey
{
    bool is_signed = false; // false: the id was first installed unsigned
    PublicKey public_key {};
};

class KeyPinStore
{
  public:
    KeyPinStore()                              = default;
    KeyPinStore(const KeyPinStore&)            = default;
    KeyPinStore(KeyPinStore&&)                 = default;
    KeyPinStore& operator=(const KeyPinStore&) = default;
    KeyPinStore& operator=(KeyPinStore&&)      = default;
    virtual ~KeyPinStore()                     = default;

    // The pin of a homebrew id on a platform, or nothing before its first install.
    [[nodiscard]] virtual Result<std::optional<PinnedKey>> load(
        std::string_view platform, std::string_view id)
        = 0;
    [[nodiscard]] virtual Result<void> store(
        std::string_view platform, std::string_view id, const PinnedKey& pin)
        = 0;
};

enum class PinVerdict : std::uint8_t
{
    first_install, // nothing pinned yet: the key (or its absence) is pinned at install
    same, // the pinned key, or unsigned again
    newly_signed, // signed now, unsigned before: the key is pinned at install
    key_changed, // another key: refused unless the user accepts
    signature_removed, // unsigned after a signed version: refused unless the user accepts
};

struct PinCheck
{
    PinVerdict verdict = PinVerdict::first_install;
    std::optional<PinnedKey> pinned; // what was pinned before
    PinnedKey offered; // what the package carries

    // The change the app must show the user (both short fingerprints) and
    // that installs only when they accept it.
    [[nodiscard]] bool needs_consent() const noexcept
    {
        return verdict == PinVerdict::key_changed || verdict == PinVerdict::signature_removed;
    }
};

// Compares a verified package signature (verify_package_signature) with
// the pin.
[[nodiscard]] Result<PinCheck> check_pin(
    KeyPinStore& store, std::string_view platform, std::string_view id, const PackageSignature& signature);

// After the install: pins what the package carried. Refused
// (Category::signature) for a change the user did not accept.
[[nodiscard]] Result<void> commit_pin(KeyPinStore& store, std::string_view platform, std::string_view id,
    const PinCheck& check, bool user_accepted_change);

} // namespace lantern
