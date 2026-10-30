// Mirrors and peers (SPEC.md § 19), a client's side: grants, and files read
// from sources it does not trust, checked by the server's document.
#include <lantern/client.hpp>

#include "client_internal.hpp"

#include <array>

namespace lantern
{

using detail::header_value;

namespace
{

constexpr std::size_t max_mirrors = 8;

// What a source that failed its check leaves: nothing of its bytes.
Result<void> drop(DownloadState& state, DownloadSink& sink)
{
    state.reset();
    return sink.restart();
}

} // namespace

Read<Grant> Client::grant(const Digest& sha256)
{
    if (auto ok = ready(Family::peers); !ok)
        return std::unexpected(ok.error());
    auto url       = api_url("/grants/sha256/");
    const auto hex = to_hex(sha256);
    url->append(hex.data(), hex.size());
    auto read_one = read<Grant>(Method::get, *url, read_grant);
    if (!read_one || !*read_one)
        return read_one;
    const Grant& got = **read_one;
    if (!same_digest(got.sha256, sha256))
        return fail(Category::invalid_response, "a grant for another file than the one asked (SPEC.md 19.3)");
    // Checked as a peer would check it, before it goes to any: by the
    // handshake's peers.key, for this server and file, not expired by the
    // server's clock (the device's, corrected by its Date)
    if (!handshake_)
        return fail(Category::usage, "no handshake yet");
    const auto key = grant_key_of(*handshake_);
    if (!key)
        return std::unexpected(key.error());
    const GrantKey server { handshake_->uid, *key };
    const auto claims
        = verify_grant(got.grant, sha256, clock_->unix_seconds() + clock_offset_, std::span(&server, 1));
    if (!claims || claims->size != got.size)
        return fail(Category::integrity,
            "a grant that does not verify by the server's peers.key, or expired (SPEC.md 19.3)");
    return read_one;
}

Result<void> Client::download_from_mirror(
    std::string_view mirror, const DownloadTarget& target, DownloadState& state, DownloadSink& sink)
{
    const auto parts = split_url(mirror);
    if (!parts)
        return std::unexpected(parts.error());
    if (auto scheme = check_untrusted_scheme(*parts); !scheme)
        return scheme;
    Call call;
    call.url       = mirror;
    call.untrusted = true;
    return transfer(call, target, state, sink);
}

Result<void> Client::download_with_mirrors(
    std::span<const Mirror> mirrors, const DownloadTarget& target, DownloadState& state, DownloadSink& sink)
{
    std::size_t tried = 0;
    for (const Mirror& mirror : mirrors)
    {
        if (++tried > max_mirrors)
            break;
        // Another source: its ETag is not this one's
        state.etag_size = 0;
        const auto done = download_from_mirror(mirror.url, target, state, sink);
        if (done)
            return done;
        // L-19.1-3: what failed is dropped, and the next source tried
        if (auto dropped = drop(state, sink); !dropped)
            return dropped;
    }
    state.etag_size = 0;
    return download(target, state, sink);
}

Result<bool> Client::peer_holds(const PeerEndpoint& peer, const Grant& grant)
{
    const auto url = peer_blob_url(peer, grant.sha256, allocator_);
    if (!url)
        return std::unexpected(url.error());
    if (!header_value(grant.grant))
        return fail(Category::usage, "a grant that is not a header value");
    const std::array<Header, 1> extra { { { "Lantern-Grant", grant.grant } } };
    Call call;
    call.method       = Method::head;
    call.url          = *url;
    call.untrusted    = true;
    call.accept       = "*/*";
    call.extra        = extra;
    const auto answer = fetch(call);
    if (!answer)
        return std::unexpected(answer.error());
    if (answer->status == 200)
        return true;
    if (answer->status == 404)
        return false;
    return std::unexpected(problem(*answer));
}

Result<void> Client::download_from_peer(const PeerEndpoint& peer, const Grant& grant,
    const DownloadTarget& target, DownloadState& state, DownloadSink& sink)
{
    if (!same_digest(grant.sha256, target.sha256) || grant.size != target.size)
        return fail(Category::usage, "a grant for another file than the one downloaded");
    if (!header_value(grant.grant))
        return fail(Category::usage, "a grant that is not a header value");
    const auto url = peer_blob_url(peer, target.sha256, allocator_);
    if (!url)
        return std::unexpected(url.error());
    const std::array<Header, 1> extra { { { "Lantern-Grant", grant.grant } } };
    Call call;
    call.url       = *url;
    call.untrusted = true;
    call.extra     = extra;
    return transfer(call, target, state, sink);
}

} // namespace lantern
