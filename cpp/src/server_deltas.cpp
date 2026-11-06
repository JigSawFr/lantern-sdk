// Differential updates (SPEC.md § 22): the chunk index of a file, at <base>/v1/chunks/sha256/<hex>. The
// index is a document the library wrote once; the chunks it names are ranges of the file, which the file
// route serves.
#include <lantern/sha256.hpp>

#include "server_internal.hpp"

namespace lantern::detail
{

namespace
{

// Whether an app or a homebrew package that carries `chunks`, which the caller may read, has the file
// `sha256`.
std::expected<bool, ProblemError> chunked_and_readable(const ServerState& state, const ServerRequest& request,
    const CapFilter& cap, const Digest& sha256, std::optional<std::string_view> platform)
{
    AppsFilter filter;
    filter.platform = platform.value_or(std::string_view {});
    auto apps       = state.library->apps(filter, state.allocator);
    if (!apps)
        return std::unexpected(internal_error(state));
    for (const App& app : *apps)
    {
        if (app.chunks && same_digest(app.sha256, sha256) && !cap.hides_title(app.platform, app.title_id))
            return true;
    }
    if (!state.library->offers_homebrew())
        return false;
    auto entries = state.library->homebrew(
        request.header("Accept-Language").value_or(std::string_view {}), state.allocator);
    if (!entries)
        return std::unexpected(internal_error(state));
    for (const Homebrew& entry : *entries)
    {
        if ((platform && entry.platform != *platform) || cap.hides(entry.ratings))
            continue;
        if (entry.package.chunks && same_digest(entry.package.sha256, sha256))
            return true;
        for (const Package& package : entry.packages)
        {
            if (package.chunks && same_digest(package.sha256, sha256))
                return true;
        }
    }
    return false;
}

} // namespace

Answer chunks_route(
    const ServerState& state, const ServerRequest& request, const Caller& caller, std::string_view hex)
{
    // A SHA-256 is lower-case hex (§ 2.3); anything else names no file
    const std::optional<Digest> sha256 = digest_from_hex(hex);
    if (!sha256)
        return std::unexpected(not_found(state, "A file is named by its SHA-256, lower-case hex."));
    const auto platform = platform_param(state, request);
    if (!platform)
        return std::unexpected(platform.error());
    const auto cap = CapFilter::of(state, caller);
    if (!cap)
        return std::unexpected(cap.error());
    const auto readable = chunked_and_readable(state, request, *cap, *sha256, *platform);
    if (!readable)
        return std::unexpected(readable.error());
    // A file the caller may not read, or that has no index, is one the server does not have (L-22.1-2)
    if (!*readable)
        return std::unexpected(not_found(state, "No chunk index for this file."));
    auto found = state.library->chunk_index(*sha256, state.allocator);
    if (!found)
        return std::unexpected(internal_error(state));
    if (!*found)
        return std::unexpected(not_found(state, "No chunk index for this file."));
    Answer served = serve_library_file(state, request, **found);
    if (served && served->status < 300)
    {
        // The index of a file is the same for good: it is named by the file's content
        served->headers.set("Cache-Control",
            request.header("Authorization") ? "private, max-age=31536000, immutable"
                                            : "public, max-age=31536000, immutable");
    }
    return served;
}

} // namespace lantern::detail
