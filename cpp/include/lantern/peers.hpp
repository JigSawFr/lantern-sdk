// Mirrors and peers (SPEC.md § 19): a file is its SHA-256, so whoever
// serves its bytes serves the file, and a client checks them the same way
// wherever they come from.
//
// - Mirrors (§ 19.2) and peers are untrusted: Client::download_from_mirror
//   and Client::download_from_peer (client.hpp) send them no token, no
//   signature, nothing of the server's but a grant to a peer (L-19.1-2), and
//   check what they serve by the size and SHA-256 of the server's document
//   (L-19.1-1), stopping at the size; plain HTTP only to an address of a
//   private network (L-19.2-1, L-19.4-6).
// - Grants (§ 19.3): `<payload>.<signature>`, base64url; the payload the
//   canonical JSON of exp, purpose, sha256, size and uid; the signature
//   Ed25519 by the server's grant key (`peers.key` of its handshake), checked
//   strictly (ed25519.hpp). verify_grant() is a peer's check (L-19.4-1).
// - Finding peers (§ 19.5): a datagram with `"peers": true`, and the
//   peers' replies (discovery.hpp).
// - PeerGate: what a console that shares its files answers, without
//   networking of its own (the app's HTTP server asks it, then streams the
//   file it names): grant checked, files held whole only, its own networks
//   only, slots and a rate per address (L-19.4-1 to L-19.4-5).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/document.hpp>
#include <lantern/ed25519.hpp>
#include <lantern/error.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/sha256.hpp>
#include <lantern/transport.hpp>
#include <lantern/types.hpp>
#include <lantern/url.hpp>

namespace lantern
{

// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 or fe80::/10,
// written as an address (§ 19.2).
[[nodiscard]] bool is_private_host(std::string_view host) noexcept;
// § 19.2 and § 2: HTTPS, or plain HTTP to a private or loopback address.
[[nodiscard]] Result<void> check_untrusted_scheme(const UrlParts& url) noexcept;

inline constexpr std::size_t max_grant = 1024;

// A server whose grants a peer takes: its uid and its grant key.
struct GrantKey
{
    std::string_view uid;
    PublicKey key {};
};

// What a grant says, once it verified.
struct GrantClaims
{
    std::int64_t exp = 0;
    Digest sha256 {};
    std::uint64_t size = 0;
    std::array<char, 36> uid {};

    [[nodiscard]] std::string_view uid_view() const noexcept { return { uid.data(), uid.size() }; }
};

// The handshake's `peers.key` (base64 of 32 bytes).
[[nodiscard]] Result<PublicKey> grant_key_of(const Handshake& handshake) noexcept;

// L-19.4-1: the grant verifies by the key of the server it names, one of
// `servers` (those the peer paired with), its `exp` is not past at `now`
// (Unix seconds, by the peer's clock), and its file is `sha256`. Anything
// else is Category::refused, which a peer answers 403.
[[nodiscard]] Result<GrantClaims> verify_grant(std::string_view grant, const Digest& sha256, std::int64_t now,
    std::span<const GrantKey> servers) noexcept;

// A peer, where its discovery reply says it serves.
struct PeerEndpoint
{
    std::string_view host; // the reply's source address
    std::uint16_t port = 0;
    std::string_view base; // "/lantern"
    bool tls = false;
};

// A datagram read as a peer's reply (§ 19.5): absent for a newer schema; an
// error for one that is not a peer's reply of § 19.5's form.
[[nodiscard]] Read<PeerReply> read_peer_datagram(
    std::span<const std::byte> datagram, const DecodeOptions& options = {});
// Whether a peer takes the grants of the server of `uid`.
[[nodiscard]] bool peer_serves(const PeerReply& reply, std::string_view uid) noexcept;
// <scheme>://<host>:<port><base>/v1/blobs/sha256/<hex>; plain HTTP only to
// a private or loopback address (L-19.4-6).
[[nodiscard]] Result<String> peer_blob_url(
    const PeerEndpoint& peer, const Digest& sha256, Allocator allocator = {});

// The peer's side.

// The files a peer holds whole, whose size and SHA-256 it checked against
// its server's document: apps and homebrew packages only, never a save, a
// key or a document (L-19.4-2).
class HeldFiles
{
  public:
    HeldFiles()                            = default;
    HeldFiles(const HeldFiles&)            = default;
    HeldFiles(HeldFiles&&)                 = default;
    HeldFiles& operator=(const HeldFiles&) = default;
    HeldFiles& operator=(HeldFiles&&)      = default;
    virtual ~HeldFiles()                   = default;

    // The size of the file of that SHA-256, or nothing when it holds none.
    [[nodiscard]] virtual std::optional<std::uint64_t> size_of(const Digest& sha256) = 0;
};

struct PeerRequest
{
    std::string_view method; // GET or HEAD
    std::string_view target; // the path and query, as received
    std::string_view grant; // Lantern-Grant
    std::string_view range; // Range, or empty
    std::string_view if_range; // If-Range, or empty
    std::string_view remote_address; // the client's address, as text
};

// What to answer: the status, then either a problem document (`body`) or
// the file's bytes [offset, offset + length) (`serve`, never for HEAD).
struct PeerAnswer
{
    std::uint16_t status = 0;
    std::string_view body; // a problem document (static text), or empty
    bool serve = false;
    Digest sha256 {};
    std::uint64_t offset      = 0;
    std::uint64_t length      = 0;
    std::uint64_t size        = 0; // the whole file's
    std::uint32_t retry_after = 0; // seconds, for a 429
    // A slot taken: give it back with PeerGate::release() once sent.
    bool slot = false;

    // The headers to send: Content-Type, Content-Length, and for a file
    // Accept-Ranges, ETag, Repr-Digest and Content-Range (§ 6.6). Views of
    // this answer's own buffers: valid while it lives where it is.
    [[nodiscard]] std::span<const Header> headers() noexcept;

  private:
    std::array<Header, 8> headers_ {};
    std::array<char, 256> text_ {};
};

struct PeerLimits
{
    std::uint32_t slots      = 2; // downloads at once, 1 to 8 (§ 19.5)
    std::uint32_t per_second = 10; // requests per address
    std::string_view base    = "/lantern";
};

// Not thread-safe: an app that serves on several threads holds a lock
// around handle() and release().
class PeerGate
{
  public:
    PeerGate(
        std::span<const GrantKey> servers, HeldFiles& files, Clock& clock, const PeerLimits& limits = {});

    // While its user allows sharing: off, every request is 403 (L-19.4-3).
    void set_enabled(bool enabled) noexcept { enabled_ = enabled; }
    [[nodiscard]] bool enabled() const noexcept { return enabled_; }

    [[nodiscard]] PeerAnswer handle(const PeerRequest& request);
    // A download ended (served, or cut).
    void release() noexcept;
    [[nodiscard]] std::uint32_t active() const noexcept { return active_; }

  private:
    struct Visitor
    {
        std::array<char, 48> address {};
        std::size_t size    = 0;
        std::int64_t second = 0;
        std::uint32_t count = 0;
    };

    [[nodiscard]] bool too_fast(std::string_view address, std::int64_t now) noexcept;

    std::span<const GrantKey> servers_;
    HeldFiles* files_;
    Clock* clock_;
    PeerLimits limits_;
    bool enabled_         = true;
    std::uint32_t active_ = 0;
    std::array<Visitor, 32> visitors_ {};
};

} // namespace lantern
