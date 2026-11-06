// The server core's side of SPEC.md § 5: who calls (tokens, kept as hashes,
// with their scopes), signed requests (§ 5.4, with the replay window of the
// injected Clock), pairing (§ 5.2, its limits per address) and the approval
// page (§ 5.3). No secret is written to a response but the token a device
// collects once, and none is put in an error's text.
#include <algorithm>
#include <array>

#include <lantern/accounts.hpp>
#include <lantern/document.hpp>
#include <lantern/ed25519.hpp>
#include <lantern/encoding.hpp>
#include <lantern/hkdf.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/json.hpp>
#include <lantern/server.hpp>
#include <lantern/types.hpp>

#include "server_internal.hpp"

namespace lantern
{

namespace
{

using detail::Answer;
using detail::Caller;
using detail::ProblemError;
using detail::ServerState;

constexpr std::string_view bearer_challenge        = R"(Bearer realm="lantern")";
constexpr std::string_view invalid_token_challenge = R"(Bearer realm="lantern", error="invalid_token")";
// The alphabet of a pairing code (§ 5.2): no 0, O, 1 or I
constexpr std::string_view code_alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
constexpr std::size_t code_symbols       = 8; // 40 bits
constexpr std::size_t poll_bytes         = 24; // 192 bits: whoever has it collects the token
constexpr std::size_t id_bytes           = 9;
constexpr std::size_t token_bytes        = 32; // 256 bits
constexpr std::size_t max_device_name    = 512;
// Addresses kept by the limits, then the idle ones are forgotten first
constexpr std::size_t max_addresses = 10000;
constexpr int code_attempts         = 8;

ProblemError unauthorized(const ServerState& state, std::string_view detail_text, bool invalid_token)
{
    ProblemError error = detail::make_problem(state, 401, Code::unauthorized, detail_text);
    error.headers.set("WWW-Authenticate", invalid_token ? invalid_token_challenge : bearer_challenge);
    return error;
}

ProblemError slow_down(const ServerState& state, std::int64_t wait, std::string_view detail_text)
{
    ProblemError error = detail::make_problem(state, 429, Code::slow_down, detail_text);
    error.headers.set("Retry-After",
        detail::number_text(static_cast<std::uint64_t>(std::max<std::int64_t>(wait, 1)), state.allocator));
    return error;
}

// Draws `out` entirely from the app's generator.
std::optional<ProblemError> draw(const ServerState& state, std::span<std::uint8_t> out)
{
    if (!state.random->fill(out))
        return detail::internal_error(state);
    return std::nullopt;
}

bool has_control(std::string_view text) noexcept
{
    return std::ranges::any_of(text,
        [](char c)
        {
            const auto byte = static_cast<unsigned char>(c);
            return byte < 0x20 || byte == 0x7f;
        });
}

// The seconds to wait before `key` has another event, or 0 when it may, and
// then the event is recorded when `record`. A fixed number of events in a
// window of seconds, per address. The caller holds the mutex.
std::int64_t limit(std::pmr::unordered_map<String, Vector<std::int64_t>>& hits, std::string_view key,
    std::uint32_t count, std::uint32_t window, std::int64_t now, bool record, const Allocator& allocator)
{
    const std::int64_t since = now - static_cast<std::int64_t>(window);
    if (hits.size() > max_addresses)
    {
        std::erase_if(
            hits, [&](const auto& entry) { return entry.second.empty() || entry.second.back() <= since; });
    }
    auto found = hits.find(String(key, allocator));
    if (found == hits.end())
    {
        if (!record)
            return 0;
        found = hits.emplace(String(key, allocator), Vector<std::int64_t>(allocator)).first;
    }
    Vector<std::int64_t>& list = found->second;
    std::erase_if(list, [&](std::int64_t when) { return when <= since; });
    if (list.size() < count)
    {
        if (record)
            list.push_back(now);
        return 0;
    }
    return list.front() + static_cast<std::int64_t>(window) - now;
}

enum class NonceResult : std::uint8_t
{
    taken,
    replayed,
    full,
};

// A nonce is kept for twice the window, per key (L-5.4-9), and taken once.
NonceResult take_nonce(
    const ServerState& state, std::string_view keyid, std::string_view nonce, std::int64_t now)
{
    String key(keyid, state.allocator);
    key.push_back(' ');
    key.append(nonce);
    detail::AuthRuntime& runtime = state.runtime;
    const std::scoped_lock lock(runtime.mutex);
    if (now >= runtime.next_prune || runtime.nonces.size() >= state.nonce_limit)
    {
        std::erase_if(runtime.nonces, [&](const auto& entry) { return entry.second <= now; });
        runtime.next_prune = now + static_cast<std::int64_t>(state.skew);
    }
    const auto found = runtime.nonces.find(key);
    if (found != runtime.nonces.end() && found->second > now)
        return NonceResult::replayed;
    if (found == runtime.nonces.end() && runtime.nonces.size() >= state.nonce_limit)
        return NonceResult::full;
    runtime.nonces.insert_or_assign(std::move(key), now + 2 * static_cast<std::int64_t>(state.skew));
    return NonceResult::taken;
}

ProblemError signature_problem(const ServerState& state, Code code, std::string_view detail_text,
    bool with_token, bool with_body, const PublicKey& key)
{
    std::string_view title = "Signature invalid";
    if (code == Code::signature_required)
        title = "Signature required";
    else if (code == Code::signature_expired)
        title = "Signature expired";
    else if (code == Code::signature_replayed)
        title = "Signature replayed";
    ProblemError error = detail::make_problem(state, 401, code, detail_text, title);
    error.headers.set("WWW-Authenticate", with_token ? invalid_token_challenge : bearer_challenge);
    // RFC 9421 § 5.1: the components and parameters this server wants (L-5.4-10)
    String wanted(R"(lantern=("@method" "@target-uri")", state.allocator);
    if (with_token)
        wanted.append(R"( "authorization")");
    if (with_body)
        wanted.append(R"( "content-digest")");
    wanted.push_back(')');
    const auto keyid = key_thumbprint(key);
    wanted.append(R"(;keyid=")");
    wanted.append(keyid.data(), keyid.size());
    wanted.append(R"(";alg="ed25519")");
    error.headers.set("Accept-Signature", wanted);
    return error;
}

// Checks the request's signature by `key`, in the order of § 5.4; the nonce
// is taken once the signature holds (and so is refused when it was seen).
std::optional<ProblemError> verify_signature(
    const ServerState& state, const ServerRequest& request, const PublicKey& key, bool with_token)
{
    const std::string_view host = detail::trim(request.header("Host").value_or(std::string_view {}));
    if (host.empty() || host.find_first_of("/?#@ \t") != std::string_view::npos)
        return detail::bad_request(state, "No Host this server can read.");
    const std::string_view scheme = request.scheme.empty() ? std::string_view(state.scheme) : request.scheme;
    String url(scheme, state.allocator);
    url.append("://");
    url.append(host);
    const std::string_view target = request.target.empty() ? request.path : request.target;
    if (!target.starts_with('/'))
        url.push_back('/');
    url.append(target);
    const auto uri = target_uri(url, state.allocator);
    if (!uri)
        return detail::bad_request(state, "No Host this server can read.");

    const bool has_body = request.body_size() != 0;
    SignatureCheck check;
    check.method     = request.method;
    check.target_uri = *uri;
    check.authorization
        = with_token ? request.header("Authorization").value_or(std::string_view {}) : std::string_view {};
    check.content_digest   = request.header("Content-Digest").value_or(std::string_view {});
    check.has_body         = has_body;
    check.signature_input  = request.header("Signature-Input").value_or(std::string_view {});
    check.signature        = request.header("Signature").value_or(std::string_view {});
    check.key              = key;
    const std::int64_t now = state.clock->unix_seconds();
    check.now              = now;
    check.skew             = state.skew;
    // A body the adapter did not buffer is checked against its Content-Digest by the route that reads it
    if (has_body && request.stream == nullptr)
        check.body_sha256 = Sha256::of(request.body);
    const SignatureVerdict verdict = check_signature(check);

    switch (verdict.code)
    {
        case Code::none:
        case Code::digest_mismatch:
            break;
        case Code::signature_required:
            return signature_problem(state, verdict.code,
                "This token is bound to a device key: sign the request (Signature-Input, Signature).",
                with_token, has_body, key);
        case Code::signature_expired:
        {
            String why("created is outside this server's window of ", state.allocator);
            why.append(detail::number_text(state.skew, state.allocator));
            why.append(" seconds: take its Date, and sign again with it.");
            return signature_problem(state, verdict.code, why, with_token, has_body, key);
        }
        default:
            return signature_problem(state, Code::signature_invalid,
                "The signature is not of the form SPEC.md 5.4 gives, or does not verify.", with_token,
                has_body, key);
    }
    switch (take_nonce(state, verdict.keyid, verdict.nonce, now))
    {
        case NonceResult::taken:
            break;
        case NonceResult::replayed:
            return signature_problem(state, Code::signature_replayed,
                "This nonce was taken already: a new one for each request.", with_token, has_body, key);
        case NonceResult::full:
            return slow_down(state, 1, "Too many signed requests are being tracked; try again in a moment.");
    }
    if (verdict.code == Code::digest_mismatch)
        return detail::make_problem(state, 422, Code::digest_mismatch,
            "The body does not match its Content-Digest.", "Digest mismatch");
    return std::nullopt;
}

// scheme://host of the request, as the signature's @target-uri writes them.
std::expected<String, ProblemError> origin_of(const ServerState& state, const ServerRequest& request)
{
    const std::string_view host = detail::trim(request.header("Host").value_or(std::string_view {}));
    if (host.empty() || host.find_first_of("/?#@ \t") != std::string_view::npos)
        return std::unexpected(detail::bad_request(state, "No Host this server can read."));
    const std::string_view scheme = request.scheme.empty() ? std::string_view(state.scheme) : request.scheme;
    String url(scheme, state.allocator);
    url.append("://");
    url.append(host);
    url.push_back('/');
    auto uri = target_uri(url, state.allocator);
    if (!uri)
        return std::unexpected(detail::bad_request(state, "No Host this server can read."));
    uri->pop_back();
    return std::move(*uri);
}

std::expected<String, ProblemError> verify_url(const ServerState& state, const ServerRequest& request)
{
    if (!state.verify.starts_with('/'))
        return String(state.verify, state.allocator);
    auto origin = origin_of(state, request);
    if (!origin)
        return std::unexpected(std::move(origin.error()));
    origin->append(state.verify);
    return std::move(*origin);
}

// A device's public key from a pairing request (§ 5.4): 400 unless it is an
// Ed25519 key that decodes canonically and is not of small order (L-5.4-12).
std::optional<PublicKey> device_key_of(const PublicKeyInfo& info)
{
    PublicKey key {};
    if (info.alg != "ed25519" || base64_decoded_size(info.public_key) != key.size()
        || !base64_decode(info.public_key, key) || !ed25519_is_device_key(key))
        return std::nullopt;
    return key;
}

String lower_hex(std::span<const std::uint8_t> bytes, const Allocator& allocator)
{
    constexpr std::string_view digits = "0123456789abcdef";
    String out(allocator);
    for (const std::uint8_t byte : bytes)
    {
        out.push_back(digits[byte >> 4U]);
        out.push_back(digits[byte & 0x0FU]);
    }
    return out;
}

String html_escape(std::string_view text, const Allocator& allocator)
{
    String out(allocator);
    for (const char c : text)
    {
        switch (c)
        {
            case '&':
                out.append("&amp;");
                break;
            case '<':
                out.append("&lt;");
                break;
            case '>':
                out.append("&gt;");
                break;
            case '"':
                out.append("&quot;");
                break;
            case '\'':
                out.append("&#39;");
                break;
            default:
                out.push_back(c);
        }
    }
    return out;
}

} // namespace

namespace detail
{

bool Caller::has(std::string_view scope) const noexcept
{
    return std::ranges::any_of(scopes, [&](const String& item) { return item == scope; });
}

std::expected<Caller, ProblemError> identify(const ServerState& state, const ServerRequest& request)
{
    Caller caller(state.allocator);
    const auto header = request.header("Authorization");
    if (!header)
        return caller;
    const std::string_view text   = trim(*header);
    const std::size_t space       = text.find(' ');
    const std::string_view scheme = text.substr(0, space);
    const std::string_view value
        = space == std::string_view::npos ? std::string_view {} : trim(text.substr(space + 1));
    if (!equal_fold(scheme, "bearer") || value.empty())
        return std::unexpected(unauthorized(state, "Send a token: Authorization: Bearer <token>.", false));
    // A server without accounts issues no token: every one is unknown
    if (state.accounts == nullptr)
        return std::unexpected(unauthorized(state, "Unknown, revoked or expired token.", true));
    const std::int64_t now = state.clock->unix_seconds();
    const auto device      = state.accounts->device_of(Sha256::of(value), now, state.allocator);
    if (!device)
        return std::unexpected(internal_error(state));
    if (!*device)
        return std::unexpected(unauthorized(state, "Unknown, revoked or expired token.", true));
    const auto account = state.accounts->account((*device)->user, state.allocator);
    if (!account)
        return std::unexpected(internal_error(state));
    if (!*account)
        return std::unexpected(unauthorized(state, "Unknown, revoked or expired token.", true));
    caller.state = (*account)->frozen ? Caller::State::frozen : Caller::State::active;
    caller.name  = (*account)->name;
    caller.device.assign((*device)->name);
    // A token never holds a scope its account does not (§ 5.1)
    for (const std::string_view known : known_scopes)
    {
        const auto holds = [&](const String& item) { return item == known; };
        if (std::ranges::any_of((*device)->scopes, holds) && std::ranges::any_of((*account)->scopes, holds))
            caller.scopes.emplace_back(known);
    }
    caller.key = (*device)->key;
    return caller;
}

std::optional<ProblemError> check_request_signature(
    const ServerState& state, const ServerRequest& request, const Caller& caller)
{
    if (caller.key)
        return verify_signature(state, request, *caller.key, true);
    if (state.bound_only && caller.state != Caller::State::anonymous)
    {
        const PublicKey none {};
        ProblemError error = signature_problem(state, Code::signature_required,
            "This server takes only tokens bound to a device key: pair this device again, with a key.", true,
            request.body_size() != 0, none);
        error.headers.erase("Accept-Signature");
        return error;
    }
    return std::nullopt;
}

std::optional<ProblemError> check_scope(
    const ServerState& state, const Caller& caller, std::string_view scope)
{
    switch (caller.state)
    {
        case Caller::State::anonymous:
            // Everyone holds `library` and `cheats`, unless the server asks for a token
            if (state.require_auth || (scope != "library" && scope != "cheats"))
                return unauthorized(state, "This server asks for a token.", false);
            return std::nullopt;
        case Caller::State::frozen:
            return make_problem(
                state, 403, Code::account_frozen, "This account may do nothing for now.", "Account frozen");
        case Caller::State::active:
            break;
    }
    if (!caller.has(scope))
    {
        String why("This account lacks the scope ", state.allocator);
        why.append(scope);
        why.push_back('.');
        return make_problem(state, 403, Code::forbidden, why);
    }
    return std::nullopt;
}

std::optional<ProblemError> check_library(const ServerState& state, const Caller& caller)
{
    return check_scope(state, caller, "library");
}

Answer pairing_start(const ServerState& state, const ServerRequest& request)
{
    const auto prepared = request_document(state, request);
    if (!prepared)
        return std::unexpected(prepared.error());
    auto bound = read_document<PairingRequest>(prepared->text, known_schema, prepared->options,
        [](BindContext& c, PairingRequest& value) { return bind(c, value); });
    if (!bound || !*bound)
        return std::unexpected(
            bad_request(state, "A pairing request is {schema, device, scopes, key?, invitation?}."));
    const PairingRequest& doc = **bound;

    const std::string_view device = trim(doc.device);
    if (device.empty() || device.size() > max_device_name || has_control(device))
        return std::unexpected(bad_request(
            state, "device is the device's name, 512 bytes at most, without control characters."));
    Vector<std::string_view> asked(state.allocator);
    for (const String& scope : doc.scopes)
        asked.push_back(scope);
    Vector<String> scopes = ordered_scopes(asked, state.allocator);
    if (scopes.empty())
        return std::unexpected(bad_request(state,
            "scopes names none of library, saves, cheats, cheats.write, requests, admin, sync.read, "
            "sync.write."));
    std::optional<PublicKey> key;
    if (doc.key)
    {
        key = device_key_of(*doc.key);
        if (!key)
            return std::unexpected(bad_request(
                state, "key is {alg: ed25519, public_key: the 32 bytes of an Ed25519 key, base64}."));
    }
    else if (state.bound_only)
    {
        return std::unexpected(make_problem(state, 400, Code::key_required,
            "This server binds every token to a device key: send one (key: {alg: ed25519, public_key}).",
            "Device key required"));
    }

    const std::int64_t now = state.clock->unix_seconds();
    {
        const std::scoped_lock lock(state.runtime.mutex);
        const std::int64_t wait = limit(state.runtime.pairing_hits, request.remote, state.pairing_requests,
            state.pairing_window, now, true, state.allocator);
        if (wait != 0)
            return std::unexpected(slow_down(state, wait, "Too many pairing requests from this address."));
        // Invitations (§ 5.5) are not offered here yet: every code is unknown, and counted
        if (!doc.invitation.empty())
        {
            const std::int64_t attempts = limit(state.runtime.invitation_hits, request.remote,
                state.invitation_attempts, state.invitation_window, now, false, state.allocator);
            if (attempts != 0)
                return std::unexpected(
                    slow_down(state, attempts, "Too many attempts at invitations from this address."));
            std::ignore = limit(state.runtime.invitation_hits, request.remote, state.invitation_attempts,
                state.invitation_window, now, true, state.allocator);
            return std::unexpected(make_problem(state, 410, Code::gone,
                "This invitation is unknown, expired, revoked or used up.", "Invitation gone"));
        }
    }

    PendingPairing entry(state.allocator);
    entry.device.assign(device);
    entry.scopes   = std::move(scopes);
    entry.key      = key;
    entry.created  = now;
    entry.expires  = now + static_cast<std::int64_t>(state.pairing_expires);
    entry.interval = state.pairing_interval;
    for (int attempt = 0; attempt < code_attempts; ++attempt)
    {
        std::array<std::uint8_t, code_symbols + poll_bytes + id_bytes> raw {};
        if (auto failed = draw(state, raw))
            return std::unexpected(std::move(*failed));
        entry.code.clear();
        for (std::size_t i = 0; i < code_symbols; ++i)
        {
            if (i == 4)
                entry.code.push_back('-');
            entry.code.push_back(code_alphabet[raw[i] & 31U]);
        }
        entry.poll.assign("p_");
        base64url_encode(std::span<const std::uint8_t>(raw).subspan(code_symbols, poll_bytes), entry.poll);
        entry.id.assign("pr_");
        base64url_encode(
            std::span<const std::uint8_t>(raw).subspan(code_symbols + poll_bytes, id_bytes), entry.id);
        secure_wipe(raw);
        const auto added = state.accounts->add_pairing(entry, now);
        if (!added)
            return std::unexpected(internal_error(state));
        if (*added == PairingAdded::full)
            return std::unexpected(
                slow_down(state, state.pairing_interval, "Too many pairings are waiting; try again later."));
        if (*added == PairingAdded::added)
        {
            auto verify = verify_url(state, request);
            if (!verify)
                return std::unexpected(std::move(verify.error()));
            String complete(*verify, state.allocator);
            complete.append(verify->contains('?') ? "&code=" : "?code=");
            complete.append(entry.code);
            String poll_path(state.base, state.allocator);
            poll_path.append("/v1/pairing/");
            poll_path.append(entry.poll);

            String out(state.allocator);
            json::Writer w(out);
            w.begin_object();
            w.key("schema");
            w.number(known_schema);
            w.key("code");
            w.string(entry.code);
            w.key("verify");
            w.string(*verify);
            w.key("verify_complete");
            w.string(complete);
            w.key("poll");
            w.string(poll_path);
            w.key("interval");
            w.number(static_cast<std::uint64_t>(entry.interval));
            w.key("expires");
            w.number(static_cast<std::uint64_t>(state.pairing_expires));
            w.end_object();
            ServerResponse response = json_response(state, request, std::move(out), 200, false);
            response.headers.set("Cache-Control", "no-store");
            return response;
        }
    }
    return std::unexpected(internal_error(state));
}

Answer pairing_poll(const ServerState& state, const ServerRequest& request, std::string_view poll)
{
    const std::int64_t now = state.clock->unix_seconds();
    const auto entry       = state.accounts->pairing(poll, now, state.allocator);
    if (!entry)
        return std::unexpected(internal_error(state));
    // A pairing made with a key polls with requests signed by it (§ 5.4, L-5.4-11)
    if (*entry && (*entry)->key)
    {
        if (auto refused = verify_signature(state, request, *(*entry)->key, false))
            return std::unexpected(std::move(*refused));
    }
    auto outcome = state.accounts->poll_pairing(poll, now, state.allocator);
    if (!outcome)
        return std::unexpected(internal_error(state));
    switch (outcome->kind)
    {
        case PairingPoll::Kind::unknown:
            return std::unexpected(gone(state, "Refused, expired, already collected or unknown."));
        case PairingPoll::Kind::refused:
            return std::unexpected(gone(state, "The user refused this device."));
        case PairingPoll::Kind::too_soon:
        {
            String why("Poll every ", state.allocator);
            why.append(number_text(state.pairing_interval, state.allocator));
            why.append(" seconds.");
            return std::unexpected(slow_down(state, outcome->retry_after, why));
        }
        case PairingPoll::Kind::waiting:
        {
            ServerResponse response(state.allocator);
            response.status = 202;
            caching_headers(response.headers, request);
            response.headers.set("Cache-Control", "no-store");
            response.headers.set("Content-Length", "0");
            return response;
        }
        case PairingPoll::Kind::approved:
            break;
    }
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("token");
    w.string(outcome->token);
    w.key("scopes");
    w.begin_array();
    for (const String& scope : outcome->scopes)
        w.string(scope);
    w.end_array();
    w.key("bound");
    w.boolean(outcome->bound);
    if (outcome->token_lifetime)
    {
        w.key("expires");
        w.number(static_cast<std::uint64_t>(*outcome->token_lifetime));
    }
    w.end_object();
    ServerResponse response = json_response(state, request, std::move(out), 200, false);
    response.headers.set("Cache-Control", "no-store");
    secure_wipe(std::span<std::uint8_t>(
        reinterpret_cast<std::uint8_t*>(outcome->token.data()), outcome->token.size()));
    return response;
}

bool is_approval_path(const ServerState& state, std::string_view path) noexcept
{
    return state.accounts != nullptr && state.verify.starts_with('/') && path == state.verify;
}

Answer approval_page(const ServerState& state, const ServerRequest& request)
{
    if (request.method != "GET" && request.method != "HEAD")
        return std::unexpected(method_not_allowed(state, "GET, HEAD"));
    std::string_view code
        = request.param("code").value_or(request.param("invitation").value_or(std::string_view {}));
    code = code.substr(0, 64);
    String shown(state.allocator);
    if (state.spki)
    {
        const auto hex = to_hex(*state.spki);
        for (std::size_t i = 0; i < 16; ++i)
        {
            if (i != 0 && i % 4 == 0)
                shown.push_back(' ');
            const char c = hex[i];
            shown.push_back((c >= 'a' && c <= 'f') ? static_cast<char>(c - 'a' + 'A') : c);
        }
    }
    else
        shown.assign("(no TLS key: plain HTTP on loopback)");
    String page(R"(<!doctype html><html lang="en"><head><meta charset="utf-8">)", state.allocator);
    page.append(R"(<meta name="referrer" content="no-referrer"><title>Pair a device</title></head><body>)");
    page.append("<h1>Pair a device</h1><p>This server's key: <code>");
    page.append(html_escape(shown, state.allocator));
    page.append("</code>. Compare it with the one the device shows.</p>");
    if (!code.empty())
    {
        page.append("<p>Code: <code>");
        page.append(html_escape(code, state.allocator));
        page.append("</code></p>");
    }
    page.append("<p>Sign in on this server to approve a device; this page approves nothing by itself.</p>");
    page.append("</body></html>");

    ServerResponse response(state.allocator);
    response.headers.set("Content-Type", "text/html; charset=utf-8");
    response.headers.set("Cache-Control", "no-store");
    response.headers.set("Content-Language", "en");
    response.headers.set("Referrer-Policy", "no-referrer");
    response.headers.set("X-Frame-Options", "DENY");
    response.headers.set(
        "Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'");
    response.headers.set("Content-Length", number_text(page.size(), state.allocator));
    if (request.method != "HEAD")
        response.body = std::move(page);
    return response;
}

} // namespace detail

// The app's side of a pairing.

Result<std::optional<PendingPairing>> Server::waiting_pairing(
    std::string_view code, const Allocator& allocator) const
{
    if (state_->accounts == nullptr)
        return fail(Category::usage, "the server has no accounts");
    return state_->accounts->pairing_by_code(code, state_->clock->unix_seconds(), allocator);
}

Result<std::optional<Vector<String>>> Server::approve_pairing(std::string_view code, std::string_view user,
    std::span<const std::string_view> scopes, const Allocator& allocator) const
{
    const ServerState& state = *state_;
    if (state.accounts == nullptr)
        return fail(Category::usage, "the server has no accounts");
    const std::int64_t now = state.clock->unix_seconds();
    const auto account     = state.accounts->account(user, allocator);
    if (!account)
        return std::unexpected(account.error());
    if (!*account)
        return fail(Category::usage, "no account of that name");
    const auto entry = state.accounts->pairing_by_code(code, now, allocator);
    if (!entry)
        return std::unexpected(entry.error());
    if (!*entry)
        return std::optional<Vector<String>> {};
    // The scopes it asked for, among those approved, that the account holds (§ 5.2, L-5.2-4)
    Vector<String> granted(allocator);
    for (const String& scope : (*entry)->scopes)
    {
        const auto same = [&](const auto& item) { return item == scope; };
        if ((scopes.empty() || std::ranges::any_of(scopes, same))
            && std::ranges::any_of((*account)->scopes, same))
            granted.push_back(scope);
    }
    std::array<std::uint8_t, 8 + token_bytes> raw {};
    if (auto drawn = state.random->fill(raw); !drawn)
        return std::unexpected(drawn.error());
    String token("et_", allocator);
    base64url_encode(std::span<const std::uint8_t>(raw).subspan(8, token_bytes), token);
    PairedDevice device(allocator);
    device.id = "d_";
    device.id.append(lower_hex(std::span<const std::uint8_t>(raw).first(8), allocator));
    secure_wipe(raw);
    device.user.assign(user);
    device.name    = (*entry)->device;
    device.scopes  = granted;
    device.key     = (*entry)->key;
    device.created = now;
    std::optional<std::int64_t> lifetime;
    if (state.token_lifetime != 0)
    {
        lifetime       = static_cast<std::int64_t>(state.token_lifetime);
        device.expires = now + *lifetime;
    }
    const Digest hash = Sha256::of(std::string_view(token));
    if (auto added = state.accounts->add_device(device, hash); !added)
        return std::unexpected(added.error());
    Vector<std::string_view> views(allocator);
    for (const String& scope : granted)
        views.push_back(scope);
    const auto approved = state.accounts->approve_pairing((*entry)->poll, user, views, token, lifetime, now);
    secure_wipe(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(token.data()), token.size()));
    if (!approved)
        return std::unexpected(approved.error());
    if (!*approved)
    {
        // Decided meanwhile: the token just made is not kept
        if (auto revoked = state.accounts->revoke_device(device.id); !revoked)
            return std::unexpected(revoked.error());
        return std::optional<Vector<String>> {};
    }
    return std::optional<Vector<String>>(std::move(granted));
}

Result<bool> Server::refuse_pairing(std::string_view code) const
{
    const ServerState& state = *state_;
    if (state.accounts == nullptr)
        return fail(Category::usage, "the server has no accounts");
    const std::int64_t now = state.clock->unix_seconds();
    const auto entry       = state.accounts->pairing_by_code(code, now, state.allocator);
    if (!entry)
        return std::unexpected(entry.error());
    if (!*entry)
        return false;
    return state.accounts->refuse_pairing((*entry)->poll, now);
}

} // namespace lantern
