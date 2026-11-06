// Grants for peers (SPEC.md § 19.3): the server signs, with its grant key, that
// the caller may read one file, and a peer checks it without asking anyone.
#include <lantern/ed25519.hpp>
#include <lantern/peers.hpp>
#include <lantern/sha256.hpp>

#include "server_internal.hpp"

namespace lantern::detail
{

namespace
{

// The size of the file `sha256` names, among the apps and the homebrew packages the caller may read.
std::expected<std::optional<std::uint64_t>, ProblemError> readable_size(const ServerState& state,
    const ServerRequest& request, const CapFilter& cap, const Digest& sha256,
    std::optional<std::string_view> platform)
{
    AppsFilter filter;
    filter.platform = platform.value_or(std::string_view {});
    auto apps       = state.library->apps(filter, state.allocator);
    if (!apps)
        return std::unexpected(internal_error(state));
    for (const App& app : *apps)
    {
        if (same_digest(app.sha256, sha256) && !cap.hides_title(app.platform, app.title_id))
            return std::optional<std::uint64_t>(app.size);
    }
    if (!state.library->offers_homebrew())
        return std::optional<std::uint64_t> {};
    auto entries = state.library->homebrew(
        request.header("Accept-Language").value_or(std::string_view {}), state.allocator);
    if (!entries)
        return std::unexpected(internal_error(state));
    for (const Homebrew& entry : *entries)
    {
        if ((platform && entry.platform != *platform) || cap.hides(entry.ratings))
            continue;
        if (same_digest(entry.package.sha256, sha256))
            return std::optional<std::uint64_t>(entry.package.size);
        for (const Package& package : entry.packages)
        {
            if (same_digest(package.sha256, sha256))
                return std::optional<std::uint64_t>(package.size);
        }
    }
    return std::optional<std::uint64_t> {};
}

} // namespace

Answer grant_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view hex)
{
    const std::optional<Digest> sha256 = digest_from_hex(hex);
    if (!sha256)
        return std::unexpected(not_found(state, "A file is named by its SHA-256, lower-case hex."));
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const auto cap = CapFilter::of(state, caller);
    if (!cap)
        return std::unexpected(cap.error());
    const auto size = readable_size(state, request, *cap, *sha256, *platform);
    if (!size)
        return std::unexpected(size.error());
    // A file the server would not serve this caller is one it does not have (L-19.3-1)
    const std::optional<std::uint64_t> found = *size;
    if (!found)
        return std::unexpected(not_found(state, "No such file for this caller."));
    const std::int64_t exp = state.clock->unix_seconds() + state.grant_lifetime;
    const auto grant       = make_grant(state.grant_seed, state.uid, *sha256, *found, exp, state.allocator);
    if (!grant)
        return std::unexpected(internal_error(state));
    String out(state.allocator);
    json::Writer w(out);
    w.begin_object();
    w.key("schema");
    w.number(known_schema);
    w.key("sha256");
    w.string(hex);
    w.key("size");
    w.number(*found);
    w.key("grant");
    w.string(*grant);
    w.key("expires");
    w.string(utc_text(exp, state.allocator));
    w.end_object();
    ServerResponse response = json_response(state, request, std::move(out), 200, false);
    response.headers.set("Cache-Control", "no-store");
    return response;
}

} // namespace lantern::detail
