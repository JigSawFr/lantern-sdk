#include <lantern/url.hpp>

#include <lantern/transport.hpp>

#include <algorithm>
#include <charconv>
#include <system_error>

namespace lantern
{

std::string_view method_name(Method method) noexcept
{
    switch (method)
    {
        case Method::get:
            return "GET";
        case Method::head:
            return "HEAD";
        case Method::post:
            return "POST";
        case Method::put:
            return "PUT";
        case Method::patch:
            return "PATCH";
        case Method::delete_:
            return "DELETE";
    }
    return "GET";
}

Result<UrlParts> split_url(std::string_view url) noexcept
{
    UrlParts out;
    const std::size_t colon = url.find("://");
    if (colon == std::string_view::npos)
        return fail(Category::usage, "not an absolute URL");
    out.scheme = url.substr(0, colon);
    if (out.scheme != "https" && out.scheme != "http")
        return fail(Category::usage, "a URL of a scheme other than https or http");
    const std::string_view rest = url.substr(colon + 3);
    const std::size_t slash     = std::min(rest.find_first_of("/?#"), rest.size());
    out.authority               = rest.substr(0, slash);
    out.target                  = rest.substr(slash);
    if (out.target.contains('#'))
        return fail(Category::usage, "a URL with a fragment");
    if (out.target.empty())
        out.target = "/";
    else if (out.target.front() != '/')
        return fail(Category::usage, "a URL whose path does not start with /");
    if (out.authority.empty() || out.authority.contains('@'))
        return fail(Category::usage, "a URL without a host, or with user information");
    std::string_view port_text;
    if (out.authority.front() == '[')
    {
        const std::size_t close = out.authority.find(']');
        if (close == std::string_view::npos)
            return fail(Category::usage, "a malformed IPv6 address");
        out.host                     = out.authority.substr(1, close - 1);
        const std::string_view after = out.authority.substr(close + 1);
        if (!after.empty())
        {
            if (after.front() != ':')
                return fail(Category::usage, "a malformed authority");
            port_text = after.substr(1);
        }
    }
    else
    {
        const std::size_t port_colon = out.authority.rfind(':');
        out.host                     = out.authority.substr(0, port_colon);
        if (port_colon != std::string_view::npos)
            port_text = out.authority.substr(port_colon + 1);
    }
    if (out.host.empty())
        return fail(Category::usage, "a URL without a host");
    for (const char c : out.host)
    {
        const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || c == '.' || c == '-' || c == ':' || c == '_';
        if (!allowed)
            return fail(Category::usage, "a host with a character it cannot have");
    }
    out.port = out.scheme == "https" ? 443 : 80;
    if (!port_text.empty())
    {
        unsigned value    = 0;
        const char* end   = port_text.data() + port_text.size();
        const auto result = std::from_chars(port_text.data(), end, value);
        if (result.ec != std::errc {} || result.ptr != end || value == 0 || value > 65535)
            return fail(Category::usage, "a URL whose port is not a port");
        out.port = static_cast<std::uint16_t>(value);
    }
    return out;
}

bool is_loopback_host(std::string_view host) noexcept
{
    if (host == "::1" || host == "0:0:0:0:0:0:0:1")
        return true;
    // 127.a.b.c, each a decimal from 0 to 255
    if (!host.starts_with("127."))
        return false;
    std::size_t parts = 0;
    std::size_t start = 0;
    for (;;)
    {
        const std::size_t end       = std::min(host.find('.', start), host.size());
        const std::string_view part = host.substr(start, end - start);
        unsigned value              = 0;
        const auto result           = std::from_chars(part.data(), part.data() + part.size(), value);
        if (part.empty() || part.size() > 3 || result.ec != std::errc {}
            || result.ptr != part.data() + part.size() || value > 255)
            return false;
        ++parts;
        if (end == host.size())
            break;
        start = end + 1;
    }
    return parts == 4;
}

Result<void> check_scheme(const UrlParts& url) noexcept
{
    if (url.scheme == "https")
        return {};
    if (url.scheme == "http" && is_loopback_host(url.host))
        return {};
    return fail(Category::usage, "plain HTTP is allowed only on a loopback address (SPEC.md 2)");
}

namespace
{

bool equal_ignoring_case(std::string_view a, std::string_view b) noexcept
{
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(),
            [](char x, char y)
            {
                const auto lower
                    = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
                return lower(x) == lower(y);
            });
}

} // namespace

bool same_origin(const UrlParts& a, const UrlParts& b) noexcept
{
    return a.scheme == b.scheme && equal_ignoring_case(a.host, b.host) && a.port == b.port;
}

Result<String> resolve_url(const UrlParts& origin, std::string_view reference, Allocator allocator)
{
    if (reference.starts_with("https://") || reference.starts_with("http://"))
    {
        const auto parts = split_url(reference);
        if (!parts)
            return fail(Category::invalid_response, "a URL the server gave is malformed");
        return String(reference, allocator);
    }
    if (reference.empty() || reference.front() != '/' || reference.starts_with("//"))
        return fail(Category::invalid_response, "a URL the server gave is neither absolute nor a path");
    String out(allocator);
    out.append(origin.scheme);
    out.append("://");
    out.append(origin.authority);
    out.append(reference);
    return out;
}

} // namespace lantern
