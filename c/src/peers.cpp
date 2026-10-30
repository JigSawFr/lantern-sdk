// Mirrors and peers (§ 19): grants, downloads from mirrors and peers, a
// peer's datagram, and the gate of a console that shares its files.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/http_signature.hpp>
#include <lantern/peers.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

// The app's files behind the C++ interface.
class HeldFiles final : public lantern::HeldFiles
{
  public:
    explicit HeldFiles(const lantern_held_files_callbacks& callbacks) noexcept
        : callbacks_(callbacks)
    {
    }
    HeldFiles(const HeldFiles&)            = delete;
    HeldFiles& operator=(const HeldFiles&) = delete;
    HeldFiles(HeldFiles&&)                 = delete;
    HeldFiles& operator=(HeldFiles&&)      = delete;
    ~HeldFiles() override
    {
        if (callbacks_.release != nullptr)
            callbacks_.release(callbacks_.user);
    }

    [[nodiscard]] std::optional<std::uint64_t> size_of(const lantern::Digest& sha256) override
    {
        std::uint64_t size = 0;
        if (!callbacks_.size_of(callbacks_.user, sha256.data(), &size))
            return std::nullopt;
        return size;
    }

  private:
    lantern_held_files_callbacks callbacks_;
};

lantern::PeerEndpoint endpoint_of(const lantern_peer_endpoint& peer) noexcept
{
    lantern::PeerEndpoint out;
    out.host = text(peer.host);
    out.port = peer.port;
    out.base = text(peer.base);
    out.tls  = peer.tls;
    return out;
}

lantern::DownloadTarget target_of(const lantern_download_target& target) noexcept
{
    lantern::DownloadTarget out;
    out.url    = text(target.url);
    out.size   = target.size;
    out.sha256 = digest_of(target.sha256);
    return out;
}

lantern_status done(const lantern::Result<void>& result, lantern_error* error)
{
    if (!result)
        return fail(error, result.error());
    return ok(error);
}

// A server's uid and key, copied for as long as a gate lives.
struct OwnedKeys
{
    lantern::Vector<lantern::String> uids;
    lantern::Vector<lantern::GrantKey> keys;

    OwnedKeys(const lantern_grant_key* servers, std::size_t count, lantern::Allocator allocator)
        : uids(allocator)
        , keys(allocator)
    {
        uids.reserve(count);
        keys.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            uids.emplace_back(text(servers[i].uid));
            lantern::GrantKey key;
            std::memcpy(key.key.data(), servers[i].key, key.key.size());
            keys.push_back(key);
        }
        // The views once every text is where it stays
        for (std::size_t i = 0; i < count; ++i)
            keys[i].uid = uids[i];
    }
};

} // namespace

// The gate, and what it holds: the servers' keys, the app's files, a clock.
struct lantern_peer_gate
{
    Resource* memory; // the box's, which holds its reference
    OwnedKeys servers;
    HeldFiles files;
    lantern::SystemClock system;
    lantern::String base;
    lantern::PeerGate gate;

    lantern_peer_gate(Resource* resource, const lantern_grant_key* keys, std::size_t count,
        const lantern_held_files_callbacks& callbacks, lantern::Clock* clock,
        const lantern_peer_limits& limits)
        : memory(resource)
        , servers(keys, count, lantern::Allocator(resource))
        , files(callbacks)
        , base(limits.base == nullptr ? std::string_view("/lantern") : std::string_view(limits.base),
              lantern::Allocator(resource))
        , gate(servers.keys, files, clock == nullptr ? system : *clock, settings(limits, base))
    {
    }

  private:
    static lantern::PeerLimits settings(const lantern_peer_limits& limits, std::string_view base) noexcept
    {
        lantern::PeerLimits out;
        if (limits.slots != 0)
            out.slots = limits.slots;
        if (limits.per_second != 0)
            out.per_second = limits.per_second;
        out.base = base;
        return out;
    }
};

// An answer, its texts copied NUL-terminated.
struct lantern_peer_answer
{
    lantern::PeerAnswer answer;
    lantern::String body;
    lantern::Vector<lantern::String> texts;
    std::array<lantern_header, 8> headers {};
    std::size_t header_count = 0;

    lantern_peer_answer(const lantern::PeerAnswer& given, lantern::Allocator allocator)
        : answer(given)
        , body(given.body, allocator)
        , texts(allocator)
    {
        const auto lines = answer.headers();
        texts.reserve(lines.size() * 2);
        for (const lantern::Header& line : lines)
        {
            if (header_count >= headers.size())
                break;
            texts.emplace_back(line.name);
            texts.emplace_back(line.value);
            ++header_count;
        }
        for (std::size_t i = 0; i < header_count; ++i)
            headers.at(i) = { view(texts[2 * i]), view(texts[(2 * i) + 1]) };
    }
};

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_status lantern_grant_key_of(
    const lantern_handshake* handshake, uint8_t out[32], lantern_error* error)
{
    if (handshake == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    const auto key = lantern::grant_key_of(*as(handshake));
    if (!key)
        return fail(error, key.error());
    std::memcpy(out, key->data(), key->size());
    return ok(error);
}

LANTERN_API lantern_status lantern_verify_grant(const char* grant, const uint8_t sha256[32], int64_t now,
    const lantern_grant_key* servers, size_t server_count, lantern_grant_claims* out, lantern_error* error)
{
    if (sha256 == nullptr || (servers == nullptr && server_count != 0))
        return usage(error, "a NULL argument");
    const OwnedKeys keys(servers, server_count, lantern::Allocator(Resource::standard()));
    const auto claims = lantern::verify_grant(text(grant), digest_of(sha256), now, keys.keys);
    if (!claims)
        return fail(error, claims.error());
    if (out != nullptr)
    {
        lantern_grant_claims result {};
        result.struct_size = sizeof(result);
        result.exp         = claims->exp;
        copy_digest(claims->sha256, result.sha256);
        result.size = claims->size;
        copy_text(claims->uid_view(), result.uid, sizeof(result.uid));
        give_struct(result, out);
    }
    return ok(error);
}

LANTERN_API lantern_status lantern_client_grant(
    lantern_client* client, const uint8_t sha256[32], lantern_grant** out, lantern_error* error)
{
    if (client == nullptr || sha256 == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                        = nullptr;
    const lantern_status status = give_read<lantern::Grant>(
        client->resource.get(), client->client.grant(digest_of(sha256)), out, error);
    if (status >= 0)
        ok(error);
    return status;
}

LANTERN_API lantern_status lantern_client_download_from_mirror(lantern_client* client, const char* mirror,
    const lantern_download_target* target, lantern_download_state* state, lantern_download_sink* sink,
    lantern_error* error)
{
    if (client == nullptr || target == nullptr || state == nullptr || sink == nullptr)
        return usage(error, "a NULL argument");
    return done(client->client.download_from_mirror(
                    text(mirror), target_of(copy_struct(target)), state->state, *sink->impl),
        error);
}

LANTERN_API lantern_status lantern_client_download_with_mirrors(lantern_client* client,
    const lantern_mirror* const* mirrors, size_t mirror_count, const lantern_download_target* target,
    lantern_download_state* state, lantern_download_sink* sink, lantern_error* error)
{
    if (client == nullptr || target == nullptr || state == nullptr || sink == nullptr
        || (mirrors == nullptr && mirror_count != 0))
        return usage(error, "a NULL argument");
    const lantern::Allocator allocator(client->resource.get());
    lantern::Vector<lantern::Mirror> list(allocator);
    list.reserve(mirror_count);
    for (std::size_t i = 0; i < mirror_count; ++i)
    {
        if (mirrors[i] == nullptr)
            return usage(error, "a NULL mirror");
        list.push_back(*as(mirrors[i]));
    }
    return done(
        client->client.download_with_mirrors(list, target_of(copy_struct(target)), state->state, *sink->impl),
        error);
}

LANTERN_API lantern_status lantern_client_peer_holds(lantern_client* client,
    const lantern_peer_endpoint* peer, const lantern_grant* grant, bool* holds, lantern_error* error)
{
    if (client == nullptr || peer == nullptr || grant == nullptr || holds == nullptr)
        return usage(error, "a NULL argument");
    *holds          = false;
    const auto held = client->client.peer_holds(endpoint_of(copy_struct(peer)), *as(grant));
    if (!held)
        return fail(error, held.error());
    *holds = *held;
    return ok(error);
}

LANTERN_API lantern_status lantern_client_download_from_peer(lantern_client* client,
    const lantern_peer_endpoint* peer, const lantern_grant* grant, const lantern_download_target* target,
    lantern_download_state* state, lantern_download_sink* sink, lantern_error* error)
{
    if (client == nullptr || peer == nullptr || grant == nullptr || target == nullptr || state == nullptr
        || sink == nullptr)
        return usage(error, "a NULL argument");
    return done(client->client.download_from_peer(endpoint_of(copy_struct(peer)), *as(grant),
                    target_of(copy_struct(target)), state->state, *sink->impl),
        error);
}

LANTERN_API bool lantern_is_private_host(const char* host)
{
    return lantern::is_private_host(text(host));
}

LANTERN_API lantern_str lantern_discovery_request_peers(void)
{
    const std::string_view request = lantern::discovery_request(true);
    return { request.data(), request.size() };
}

LANTERN_API lantern_status lantern_read_peer_datagram(const uint8_t* bytes, size_t size,
    const lantern_allocator* allocator, lantern_peer_reply** out, lantern_error* error)
{
    if (out == nullptr || (bytes == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto read = lantern::read_peer_datagram(std::as_bytes(std::span(bytes, bytes == nullptr ? 0 : size)),
        decode_options(nullptr, resource.get()));
    const lantern_status status = give_read<lantern::PeerReply>(resource.get(), std::move(read), out, error);
    if (status >= 0)
        ok(error);
    return status;
}

LANTERN_API bool lantern_peer_serves(const lantern_peer_reply* reply, const char* uid)
{
    return reply != nullptr && lantern::peer_serves(*as(reply), text(uid));
}

LANTERN_API lantern_status lantern_peer_blob_url(const lantern_peer_endpoint* peer, const uint8_t sha256[32],
    const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (peer == nullptr || sha256 == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto url = lantern::peer_blob_url(
        endpoint_of(copy_struct(peer)), digest_of(sha256), lantern::Allocator(resource.get()));
    if (!url)
        return fail(error, url.error());
    *out = give_string(resource.get(), std::move(*url));
    return ok(error);
}

LANTERN_API lantern_status lantern_peer_gate_create(const lantern_grant_key* servers, size_t server_count,
    const lantern_held_files_callbacks* files, lantern_clock* clock, const lantern_peer_limits* limits,
    const lantern_allocator* allocator, lantern_peer_gate** out, lantern_error* error)
{
    if (out == nullptr || files == nullptr || (servers == nullptr && server_count != 0))
        return usage(error, "a NULL argument");
    *out                                 = nullptr;
    const lantern_held_files_callbacks c = copy_struct(files);
    const lantern_peer_limits l          = copy_struct(limits);
    if (c.size_of == nullptr)
        return usage(error, "size_of is NULL");
    if (l.slots > 8)
        return usage(error, "1 to 8 slots (SPEC.md 19.5)");
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    *out = box_new<lantern_peer_gate>(resource.get(), resource.get(), servers, server_count, c, clock, l);
    return ok(error);
}

LANTERN_API void lantern_peer_gate_free(lantern_peer_gate* gate)
{
    unbox(gate);
}

LANTERN_API void lantern_peer_gate_set_enabled(lantern_peer_gate* gate, bool enabled)
{
    if (gate != nullptr)
        gate->gate.set_enabled(enabled);
}

LANTERN_API uint32_t lantern_peer_gate_active(const lantern_peer_gate* gate)
{
    return gate == nullptr ? 0 : gate->gate.active();
}

LANTERN_API lantern_status lantern_peer_gate_handle(lantern_peer_gate* gate,
    const lantern_peer_request* request, lantern_peer_answer** out, lantern_error* error)
{
    if (gate == nullptr || request == nullptr || out == nullptr)
        return usage(error, "a NULL argument");
    *out                         = nullptr;
    const lantern_peer_request r = copy_struct(request);
    lantern::PeerRequest in;
    in.method                        = text(r.method);
    in.target                        = text(r.target);
    in.grant                         = text(r.grant);
    in.range                         = text(r.range);
    in.if_range                      = text(r.if_range);
    in.remote_address                = text(r.remote_address);
    const lantern::PeerAnswer answer = gate->gate.handle(in);
    Resource* resource               = gate->memory;
    *out = box_new<lantern_peer_answer>(resource, answer, lantern::Allocator(resource));
    return ok(error);
}

LANTERN_API void lantern_peer_gate_release(lantern_peer_gate* gate)
{
    if (gate != nullptr)
        gate->gate.release();
}

LANTERN_API void lantern_peer_answer_free(lantern_peer_answer* answer)
{
    unbox(answer);
}

LANTERN_API uint16_t lantern_peer_answer_status(const lantern_peer_answer* answer)
{
    return answer == nullptr ? 0 : answer->answer.status;
}

LANTERN_API lantern_str lantern_peer_answer_body(const lantern_peer_answer* answer)
{
    return answer == nullptr ? empty_str() : view(answer->body);
}

LANTERN_API bool lantern_peer_answer_serve(const lantern_peer_answer* answer)
{
    return answer != nullptr && answer->answer.serve;
}

LANTERN_API void lantern_peer_answer_sha256(const lantern_peer_answer* answer, uint8_t out[32])
{
    if (answer != nullptr && out != nullptr)
        copy_digest(answer->answer.sha256, out);
}

LANTERN_API uint64_t lantern_peer_answer_offset(const lantern_peer_answer* answer)
{
    return answer == nullptr ? 0 : answer->answer.offset;
}

LANTERN_API uint64_t lantern_peer_answer_length(const lantern_peer_answer* answer)
{
    return answer == nullptr ? 0 : answer->answer.length;
}

LANTERN_API uint64_t lantern_peer_answer_size(const lantern_peer_answer* answer)
{
    return answer == nullptr ? 0 : answer->answer.size;
}

LANTERN_API uint32_t lantern_peer_answer_retry_after(const lantern_peer_answer* answer)
{
    return answer == nullptr ? 0 : answer->answer.retry_after;
}

LANTERN_API bool lantern_peer_answer_slot(const lantern_peer_answer* answer)
{
    return answer != nullptr && answer->answer.slot;
}

LANTERN_API size_t lantern_peer_answer_header_count(const lantern_peer_answer* answer)
{
    return answer == nullptr ? 0 : answer->header_count;
}

LANTERN_API bool lantern_peer_answer_header_at(
    const lantern_peer_answer* answer, size_t index, lantern_header* out)
{
    if (answer == nullptr || out == nullptr || index >= answer->header_count)
        return false;
    *out = answer->headers.at(index);
    return true;
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
