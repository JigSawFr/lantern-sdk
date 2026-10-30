// Pairing (SPEC.md § 5.2), with a device key (§ 5.4), an invitation (§ 5.5)
// and the server's key pinned (§ 5.3).
#include <lantern/client.hpp>

#include "client_internal.hpp"

#include <algorithm>

#include <lantern/encoding.hpp>
#include <lantern/json.hpp>

namespace lantern
{

using detail::bearer_token;
using detail::bytes_of;
using detail::plain_text;

namespace
{

constexpr std::size_t max_device_name = 512;
constexpr std::uint64_t max_interval  = 60;

} // namespace

Result<Pairing> Client::start_pairing(const PairingOptions& options)
{
    if (auto ok = ready(Family::pairing); !ok)
        return std::unexpected(ok.error());
    if (options.device.empty() || !plain_text(options.device, max_device_name))
        return fail(Category::usage, "a device's name is 1 to 512 bytes without control characters");
    if (options.scopes.empty())
        return fail(Category::usage, "a pairing asks for one scope at least");
    if (!options.invitation.empty() && !is_invitation_code(options.invitation))
        return fail(Category::usage, "not an invitation's code (SPEC.md 5.5)");

    Pairing pairing(allocator_);
    PairingRequest request(allocator_);
    request.device.assign(options.device);
    for (const std::string_view scope : options.scopes)
        request.scopes.emplace_back(scope);
    request.invitation.assign(options.invitation);
    if (options.bind_key)
    {
        if (random_ == nullptr)
            return fail(Category::usage, "a device key needs a RandomSource (ClientConfig::random)");
        auto key = DeviceKey::generate(*random_);
        if (!key)
            return std::unexpected(key.error());
        PublicKeyInfo info(allocator_);
        info.alg.assign("ed25519");
        base64_encode(key->public_key(), info.public_key);
        request.key.emplace(std::move(info));
        pairing.key.emplace(std::move(*key));
    }
    String body(allocator_);
    write_pairing_request(request, body);

    auto url = api_url("/pairing");
    Call call;
    call.method    = Method::post;
    call.url       = *url;
    call.body      = bytes_of(body);
    call.anonymous = true;
    auto code      = read<PairingCode>(call, read_pairing_code);
    if (!code)
        return std::unexpected(code.error());
    if (!*code)
        return fail(Category::unsupported, "a pairing code of a newer schema (SPEC.md 3.2)");
    PairingCode& document = **code;

    // What the console shows and polls must be of the form § 5.2 gives,
    // and the poll on the server's origin: it is signed (§ 2)
    if (!is_pairing_code(document.code))
        return fail(Category::invalid_response, "a pairing code not of SPEC.md 5.2's form");
    const auto poll = resolve_url(origin(), document.poll, allocator_);
    if (!poll)
        return std::unexpected(poll.error());
    const auto poll_parts = split_url(*poll);
    if (!poll_parts || !same_origin(*poll_parts, origin()))
        return fail(Category::invalid_response, "a poll address off the server's origin (SPEC.md 2)");
    for (const std::string_view link :
        { std::string_view(document.verify), std::string_view(document.verify_complete) })
    {
        const auto parts = split_url(link);
        if (!parts || !check_scheme(*parts))
            return fail(Category::invalid_response, "a verify address that is not an https URL");
    }
    if (!document.verify_complete.contains(document.code))
        return fail(Category::invalid_response, "a verify_complete without the code (SPEC.md 5.2)");

    // § 5.3: the key seen while asking is shown with the code, and the polls
    // go over that key alone
    if (trust_ != nullptr && trust_->seen())
    {
        pairing.spki        = *trust_->seen();
        pairing.fingerprint = short_form(*pairing.spki);
        if (trust_->mode() == ServerTrust::Mode::unverified)
            trust_->pin(*pairing.spki);
    }
    pairing.wait = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(document.interval, 1, max_interval));
    pairing.code = std::move(document);
    return pairing;
}

Result<PollState> Client::poll_pairing(Pairing& pairing, CredentialStore* store)
{
    if (!handshake_)
        return fail(Category::usage, "no handshake yet: call handshake() first");
    const String uid(handshake_->uid, allocator_);
    const auto url = resolve_url(origin(), pairing.code.poll, allocator_);
    if (!url)
        return std::unexpected(url.error());
    const auto parts = split_url(*url);
    if (!parts || !same_origin(*parts, origin()))
        return fail(Category::invalid_response, "a poll address off the server's origin (SPEC.md 2)");

    Call call;
    call.url       = *url;
    call.anonymous = true;
    std::optional<DeviceSigner> poll_signer;
    if (pairing.key)
    {
        if (random_ == nullptr)
            return fail(Category::usage, "a keyed poll needs a RandomSource (ClientConfig::random)");
        poll_signer.emplace(*pairing.key, *random_, *clock_);
        poll_signer->set_clock_offset(clock_offset_);
        call.poll_signer = &*poll_signer;
    }
    const auto response = fetch(call);
    if (!response)
        return std::unexpected(response.error());
    if (response->status == 202)
        return PollState::waiting;
    if (response->status == 429)
    {
        // RFC 8628's slow_down: poll less often, and at least as late as asked
        const Error error = problem(*response);
        pairing.wait      = std::max<std::uint32_t>(pairing.wait + 5, error.retry_after());
        pairing.wait      = std::min<std::uint32_t>(pairing.wait, 600);
        return PollState::waiting;
    }
    if (response->status != 200)
        return std::unexpected(problem(*response));
    if (!detail::json_media_type(response->content_type))
        return fail(Category::invalid_response, "a token that is not application/json");
    const auto read = read_pairing_token(response->body, decode_);
    if (!read)
        return std::unexpected(read.error());
    if (!*read)
        return fail(Category::unsupported, "a token of a newer schema (SPEC.md 3.2)");
    const PairingToken& token = **read;
    if (!bearer_token(token.token))
        return fail(Category::invalid_response, "a token that is not a bearer token (RFC 6750)");

    // A server that did not bind the token (bound: false) issued a
    // bearer-only one: the key is dropped
    const bool bound = pairing.key && token.bound.value_or(true);
    if (bound)
    {
        if (auto set = set_credentials(token.token, *pairing.key); !set)
            return std::unexpected(set.error());
    }
    else if (auto set = set_bearer_token(token.token); !set)
        return std::unexpected(set.error());

    if (store != nullptr)
    {
        Credentials credentials(allocator_);
        credentials.token.assign(token.token);
        if (bound)
            credentials.key = pairing.key->seed();
        if (trust_ != nullptr && trust_->mode() == ServerTrust::Mode::pinned)
            credentials.spki = trust_->pinned();
        if (auto kept = store->store(uid, credentials); !kept)
            return std::unexpected(kept.error());
    }
    return PollState::paired;
}

} // namespace lantern
