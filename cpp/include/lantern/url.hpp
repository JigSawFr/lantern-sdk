// URLs, as far as the client needs them: an origin's parts, whether plain
// HTTP is allowed (SPEC.md § 2: on loopback addresses only), and whether a
// URL a document gives shares the server's origin (§ 2: tokens go nowhere
// else; § 7.1: never to an `external` address).
#pragma once

#include <cstdint>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>

namespace lantern
{

struct UrlParts
{
    std::string_view scheme; // "https" or "http", lower case
    std::string_view host; // without the brackets of an IPv6 literal
    std::uint16_t port = 0; // the default port of the scheme when none is written
    std::string_view authority; // host[:port] as written
    std::string_view target; // path and query, "/" at least
};

// Splits an absolute http(s) URL. No user information, no fragment.
[[nodiscard]] Result<UrlParts> split_url(std::string_view url) noexcept;

// 127.0.0.0/8 or ::1, written as an address (a name is not one).
[[nodiscard]] bool is_loopback_host(std::string_view host) noexcept;

// § 2: HTTPS, or plain HTTP to a loopback address.
[[nodiscard]] Result<void> check_scheme(const UrlParts& url) noexcept;

[[nodiscard]] bool same_origin(const UrlParts& a, const UrlParts& b) noexcept;

// A URL a document gives, made absolute against the server's origin: a
// path ("/api/lantern/v1/files/f_…") gets the origin; an absolute URL is
// taken as it is. Anything else is refused.
[[nodiscard]] Result<String> resolve_url(
    const UrlParts& origin, std::string_view reference, Allocator allocator = {});

} // namespace lantern
