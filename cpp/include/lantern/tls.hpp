// The server's key (SPEC.md § 5.3): what a TLS transport checks of the
// certificate a server shows, through a callback, so that every adapter
// pins the same way.
//
// A server whose certificate the client's CA store accepts needs nothing
// more. A LAN server with a self-signed certificate is pinned: the SHA-256
// of its DER SubjectPublicKeyInfo (SPKI), which the user compared at
// pairing (its short form, "3F9A 1C07 B2E4 55D0"), kept per server `uid`.
// Once pinned, a changed key fails, whatever certificate carries it, until
// the user pairs again (L-5.3-4).
//
// A transport (adapters/curl, adapters/mbedtls) calls ServerTrust::accept()
// once per connection, with the leaf certificate's SPKI and whether its
// chain and name verified against the CA store, and goes on only when it
// returns true.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>

namespace lantern
{

class ServerTrust
{
  public:
    enum class Mode : std::uint8_t
    {
        ca, // the CA store decides (the default)
        pinned, // the SPKI's SHA-256 must be the pin, whatever the CA store says
        unverified, // any key, recorded: before pairing only, when nothing secret is sent (§ 5.3)
    };

    void require_ca() noexcept;
    void pin(const Digest& spki_sha256) noexcept;
    // Pairing with a server the CA store does not vouch for: its key is
    // taken and recorded (seen()), to be shown as a short fingerprint next
    // to the code and pinned once the code is given (Client::start_pairing
    // does both).
    void allow_unverified() noexcept;

    [[nodiscard]] Mode mode() const noexcept { return mode_; }
    [[nodiscard]] const std::optional<Digest>& pinned() const noexcept { return pin_; }
    // The SHA-256 of the SPKI of the last certificate a transport showed.
    [[nodiscard]] const std::optional<Digest>& seen() const noexcept { return seen_; }
    // Goes up each time the mode or the pin changes: a transport that keeps
    // connections opens a new one after a change.
    [[nodiscard]] std::uint32_t generation() const noexcept { return generation_; }

    // The transport's callback: true to go on with the connection.
    [[nodiscard]] bool accept(std::span<const std::uint8_t> spki_der, bool ca_verified) noexcept;

  private:
    Mode mode_ = Mode::ca;
    std::optional<Digest> pin_;
    std::optional<Digest> seen_;
    std::uint32_t generation_ = 0;
};

// The DER SubjectPublicKeyInfo of a DER X.509 certificate (a view into
// it), read with every length bounded; an error for anything that is not a
// certificate.
[[nodiscard]] Result<std::span<const std::uint8_t>> certificate_spki(
    std::span<const std::uint8_t> der) noexcept;

// The DER bytes of the first CERTIFICATE of a PEM text.
[[nodiscard]] Result<Vector<std::uint8_t>> pem_certificate(std::string_view pem, Allocator allocator = {});

// The SHA-256 of a certificate's SPKI (§ 5.3), from its DER or its PEM.
[[nodiscard]] Result<Digest> spki_sha256(std::span<const std::uint8_t> certificate_der) noexcept;
[[nodiscard]] Result<Digest> spki_sha256_pem(std::string_view pem, Allocator allocator = {});

// The short form of a fingerprint (§ 5.3): its first 16 hex digits, upper
// case, in groups of 4: "3F9A 1C07 B2E4 55D0".
[[nodiscard]] std::array<char, 19> short_form(const Digest& fingerprint) noexcept;

// What an invitation's link (§ 5.5) carries: its code, and the whole
// fingerprint of the server's key, which a client pins without asking the
// user to compare (§ 5.3).
struct InvitationLink
{
    std::string_view code; // "MZ7Q-4KHP-XW2N-8TRD", a view into the link
    std::optional<Digest> spki;
};

// Reads `invitation=` and `spki=` (64 lower-case hex digits) from the
// link's query; an error when it has no invitation code of § 5.5's form.
[[nodiscard]] Result<InvitationLink> parse_invitation_link(std::string_view link) noexcept;

// Whether `code` has the form of a pairing code (8 to 32 symbols of
// 23456789ABCDEFGHJKLMNPQRSTUVWXYZ in groups of 4 joined by -), and of an
// invitation's (16 to 32 symbols).
[[nodiscard]] bool is_pairing_code(std::string_view code) noexcept;
[[nodiscard]] bool is_invitation_code(std::string_view code) noexcept;

} // namespace lantern
