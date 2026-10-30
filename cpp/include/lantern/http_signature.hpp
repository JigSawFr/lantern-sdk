// Signed requests (SPEC.md § 5.4, RFC 9421 HTTP Message Signatures): what a
// client signs, how, and how a server checks it.
//
// A request that carries a token bound to a device key carries
//
//     Signature-Input: lantern=("@method" "@target-uri"
//     "authorization");created=…;nonce="…";keyid="…";alg="ed25519" Signature: lantern=:<base64 of the 64
//     bytes>:
//
// with "content-digest" last among the components when it has a body (and
// its Content-Digest header), and nothing but "@method" "@target-uri" when it
// polls a pairing made with a key. The bytes are those of
// spec/vectors/signatures.json, which the unit tests pass byte for byte.
//
// DeviceSigner is the RequestSigner (transport.hpp) the client uses; the
// functions below it are the same steps one at a time, for a server or a
// test.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

#include <lantern/device_key.hpp>
#include <lantern/ed25519.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>
#include <lantern/transport.hpp>

namespace lantern
{

// The time a signature says it was made (`created`), in Unix seconds.
class Clock
{
  public:
    Clock()                        = default;
    Clock(const Clock&)            = default;
    Clock(Clock&&)                 = default;
    Clock& operator=(const Clock&) = default;
    Clock& operator=(Clock&&)      = default;
    virtual ~Clock()               = default;

    [[nodiscard]] virtual std::int64_t unix_seconds() = 0;
};

// std::chrono::system_clock: the device's own clock, often wrong on a
// console (§ 5.4, Annex B.9), which the client corrects with the server's
// Date.
class SystemClock final : public Clock
{
  public:
    [[nodiscard]] std::int64_t unix_seconds() override;
};

// The longest Signature-Input and Signature a client sends or a server
// reads (§ 13): 1 KiB each.
inline constexpr std::size_t max_signature_header = 1024;
// The window a server takes when its handshake says none (§ 5.4).
inline constexpr std::uint32_t default_skew = 300;

// "@target-uri" (§ 5.4, RFC 9421 § 2.2.2) of an absolute URL: its scheme,
// its host in lower case, its port only when it is not the scheme's
// default, then its path and query exactly as sent.
[[nodiscard]] Result<String> target_uri(std::string_view url, Allocator allocator = {});

// What a signature covers.
struct SignedComponents
{
    std::string_view method; // "GET"
    std::string_view target_uri; // as target_uri() gives it
    std::string_view authorization; // the header's value; empty when the request has none (a poll)
    std::string_view content_digest; // the header's value; empty when the request has no body
};

// The value of the `lantern` member of Signature-Input, which is also the
// signature base's "@signature-params": ("@method" …);created=…;nonce="…";keyid="…";alg="ed25519".
void signature_params(const SignedComponents& components, std::int64_t created, std::string_view nonce,
    std::string_view keyid, String& out);
// The signature base (RFC 9421 § 2.5): one line per component, then
// "@signature-params", joined by \n, without a final \n.
void signature_base(const SignedComponents& components, std::string_view params, String& out);

struct SignatureHeaders
{
    String signature_input; // "lantern=(…);created=…"
    String signature; // "lantern=:…:"

    explicit SignatureHeaders(Allocator allocator = {})
        : signature_input(allocator)
        , signature(allocator)
    {
    }
};

// Signs, with the `created` and the nonce given: the nonce is 22 to 64
// characters of base64url (§ 5.4).
[[nodiscard]] Result<void> sign_components(const DeviceKey& key, const SignedComponents& components,
    std::int64_t created, std::string_view nonce, SignatureHeaders& out);

// A new nonce: 16 random bytes, in base64url (22 characters).
[[nodiscard]] Result<std::array<char, 22>> make_nonce(RandomSource& random);

// The RequestSigner of a device key: signs each request that carries an
// Authorization header (a bound token) and, when asked, a poll of a
// pairing made with the key (SigningInput::keyed_poll); adds
// Content-Digest to a request with a body when the client has not.
class DeviceSigner final : public RequestSigner
{
  public:
    DeviceSigner(DeviceKey key, RandomSource& random, Clock& clock) noexcept
        : key_(std::move(key))
        , random_(&random)
        , clock_(&clock)
    {
    }

    [[nodiscard]] Result<void> sign(const SigningInput& request, HeaderSink& headers) override;

    // Seconds added to the clock: the server's Date minus the device's
    // time, so that `created` is within the server's window (§ 5.4, B.9).
    void set_clock_offset(std::int64_t seconds) noexcept { offset_ = seconds; }
    [[nodiscard]] std::int64_t clock_offset() const noexcept { return offset_; }
    [[nodiscard]] const DeviceKey& key() const noexcept { return key_; }

  private:
    DeviceKey key_;
    RandomSource* random_;
    Clock* clock_;
    std::int64_t offset_ = 0;
};

// What a server checks of a signed request (§ 5.4), in its order. The
// headers are as received; absent ones are empty.
struct SignatureCheck
{
    std::string_view method;
    std::string_view target_uri; // the request's, as target_uri() gives it
    std::string_view authorization; // empty for a poll
    std::string_view content_digest; // the request's Content-Digest
    bool has_body = false;
    std::string_view signature_input;
    std::string_view signature;
    PublicKey key {}; // the token's, or the pairing's
    std::int64_t now   = 0; // the server's clock
    std::uint32_t skew = default_skew;
    // The body's SHA-256, to check against its Content-Digest (422 digest_mismatch).
    std::optional<Digest> body_sha256;
};

struct SignatureVerdict
{
    // none when the signature holds; otherwise the code § 5.4 answers (401),
    // or digest_mismatch (422) for a body its Content-Digest does not match.
    Code code = Code::none;
    // The signature's nonce and keyid, for the caller's check of replays
    // (signature_replayed): views into SignatureCheck::signature_input.
    std::string_view nonce;
    std::string_view keyid;
};

// Checks a signed request as § 5.4 says, in its order: absent headers
// (signature_required); then the form, the components, Content-Digest, the
// keyid and the signature itself (signature_invalid); then `created`
// (signature_expired). Whether the nonce was seen is the caller's to know,
// with the verdict's nonce and keyid.
[[nodiscard]] SignatureVerdict check_signature(const SignatureCheck& check) noexcept;

// Accept-Signature (RFC 9421 § 5.1), as a server sends it with a 401 for a
// signature (L-5.4-10): lantern=("@method" "@target-uri" …);keyid="…";alg="ed25519".
struct AcceptSignature
{
    static constexpr std::size_t max_components = 8;
    std::array<std::string_view, max_components> components {};
    std::size_t component_count = 0;
    std::string_view keyid;
    std::string_view alg;

    [[nodiscard]] std::span<const std::string_view> covered() const noexcept
    {
        return { components.data(), component_count };
    }
};

// The `lantern` member of an Accept-Signature; nothing when there is none,
// or when it is not of that form.
[[nodiscard]] std::optional<AcceptSignature> parse_accept_signature(std::string_view value) noexcept;

// An HTTP date (RFC 9110 § 5.6.7, IMF-fixdate: "Sun, 06 Nov 1994 08:49:37
// GMT") in Unix seconds; nothing for another form.
[[nodiscard]] std::optional<std::int64_t> parse_http_date(std::string_view text) noexcept;

} // namespace lantern
