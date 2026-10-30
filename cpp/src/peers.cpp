// SPEC.md § 19: what a client checks of a mirror or a peer, grants, peers'
// discovery replies, and a peer's side.
#include <lantern/peers.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>

#include <lantern/digest.hpp>
#include <lantern/discovery.hpp>
#include <lantern/encoding.hpp>

namespace lantern
{

namespace
{

constexpr std::string_view purpose = "lantern-grant-1";

bool hex_digits(std::string_view text) noexcept
{
    return std::ranges::all_of(text,
        [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); });
}

bool is_uuid(std::string_view text) noexcept
{
    return text.size() == 36 && text[8] == '-' && text[13] == '-' && text[18] == '-' && text[23] == '-'
        && hex_digits(text.substr(0, 8)) && hex_digits(text.substr(9, 4)) && hex_digits(text.substr(14, 4))
        && hex_digits(text.substr(19, 4)) && hex_digits(text.substr(24));
}

// Four decimal parts of 0 to 255, without leading zeros: an IPv4 address.
std::optional<std::array<unsigned, 4>> ipv4(std::string_view host) noexcept
{
    std::array<unsigned, 4> parts {};
    std::size_t start = 0;
    for (std::size_t i = 0; i < 4; ++i)
    {
        const std::size_t end = i == 3 ? host.size() : host.find('.', start);
        if (end == std::string_view::npos)
            return std::nullopt;
        const std::string_view part = host.substr(start, end - start);
        unsigned value              = 0;
        const auto result           = std::from_chars(part.data(), part.data() + part.size(), value);
        if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == '0')
            || result.ec != std::errc {} || result.ptr != part.data() + part.size() || value > 255)
            return std::nullopt;
        parts[i] = value;
        start    = end + 1;
    }
    return parts;
}

// The first 16 bits of an IPv6 address, written as one (a zone allowed).
std::optional<unsigned> ipv6_first(std::string_view host) noexcept
{
    const std::string_view address = host.substr(0, host.find('%'));
    if (!address.contains(':') || address.size() > 45
        || !std::ranges::all_of(
            address, [](char c) { return c == ':' || c == '.' || hex_digits({ &c, 1 }); }))
        return std::nullopt;
    const std::string_view first = address.substr(0, address.find(':'));
    if (first.empty() || first.size() > 4)
        return std::nullopt;
    unsigned value    = 0;
    const auto result = std::from_chars(first.data(), first.data() + first.size(), value, 16);
    if (result.ec != std::errc {} || result.ptr != first.data() + first.size())
        return std::nullopt;
    return value;
}

// "123", without sign or leading zero.
std::optional<std::uint64_t> canonical_number(std::string_view text) noexcept
{
    if (text.empty() || text.size() > 20 || (text.size() > 1 && text.front() == '0'))
        return std::nullopt;
    std::uint64_t value = 0;
    const auto result   = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc {} || result.ptr != text.data() + text.size())
        return std::nullopt;
    return value;
}

// base64url without padding into `out`: the bytes written, nothing for a
// text that is not canonical (bits left over that are not zero) or too long.
std::optional<std::size_t> base64url_decode(std::string_view text, std::span<std::uint8_t> out) noexcept
{
    std::size_t size  = 0;
    std::uint32_t acc = 0;
    unsigned bits     = 0;
    for (const char c : text)
    {
        std::uint32_t value = 0;
        if (c >= 'A' && c <= 'Z')
            value = static_cast<std::uint32_t>(c - 'A');
        else if (c >= 'a' && c <= 'z')
            value = static_cast<std::uint32_t>(c - 'a' + 26);
        else if (c >= '0' && c <= '9')
            value = static_cast<std::uint32_t>(c - '0' + 52);
        else if (c == '-' || c == '_')
            value = c == '-' ? 62U : 63U;
        else
            return std::nullopt;
        acc = (acc << 6U) | value;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            if (size == out.size())
                return std::nullopt;
            out[size++] = static_cast<std::uint8_t>(acc >> bits);
            acc &= (1U << bits) - 1U;
        }
    }
    if (acc != 0 || bits >= 6)
        return std::nullopt;
    return size;
}

bool take(std::string_view& text, std::string_view prefix) noexcept
{
    if (!text.starts_with(prefix))
        return false;
    text.remove_prefix(prefix.size());
    return true;
}

Error refused(std::string_view why)
{
    return Error::make(Category::refused, why);
}

} // namespace

bool is_private_host(std::string_view host) noexcept
{
    if (const auto v4 = ipv4(host))
    {
        const auto& p = *v4;
        return p[0] == 10 || (p[0] == 172 && p[1] >= 16 && p[1] <= 31) || (p[0] == 192 && p[1] == 168);
    }
    if (const auto first = ipv6_first(host))
        return (*first & 0xFE00U) == 0xFC00U || (*first & 0xFFC0U) == 0xFE80U;
    return false;
}

Result<void> check_untrusted_scheme(const UrlParts& url) noexcept
{
    if (url.scheme == "https")
        return {};
    if (url.scheme == "http" && (is_private_host(url.host) || is_loopback_host(url.host)))
        return {};
    return fail(
        Category::refused, "plain HTTP to a mirror or a peer only on a private network (SPEC.md 19.2)");
}

Result<PublicKey> grant_key_of(const Handshake& handshake) noexcept
{
    PublicKey key {};
    if (!handshake.peers || !base64_decode(handshake.peers->key, key))
        return fail(Category::unsupported, "the server gives no grant key (peers.key, SPEC.md 19.3)");
    return key;
}

Result<GrantClaims> verify_grant(std::string_view grant, const Digest& sha256, std::int64_t now,
    std::span<const GrantKey> servers) noexcept
{
    const std::size_t dot = grant.find('.');
    if (grant.size() > max_grant || dot == std::string_view::npos || dot == 0
        || !is_base64url(grant.substr(0, dot), 1, max_grant) || !is_base64url(grant.substr(dot + 1), 86, 86))
        return std::unexpected(refused("not a grant (SPEC.md 19.3)"));
    // The payload and the signature, decoded
    std::array<std::uint8_t, max_grant> payload_bytes {};
    std::array<char, max_grant> text {};
    const auto size = base64url_decode(grant.substr(0, dot), payload_bytes);
    if (!size)
        return std::unexpected(refused("not a grant (SPEC.md 19.3)"));
    SignatureBytes signature {};
    if (base64url_decode(grant.substr(dot + 1), signature) != signature.size())
        return std::unexpected(refused("a grant's signature is not 64 bytes"));
    std::copy_n(reinterpret_cast<const char*>(payload_bytes.data()), *size, text.begin());
    const std::string_view payload(text.data(), *size);

    // The canonical form, and nothing else: these keys, in this order, no space
    GrantClaims claims;
    std::string_view rest = payload;
    if (!take(rest, R"({"exp":)"))
        return std::unexpected(refused("a grant's payload not of SPEC.md 19.3's form"));
    const bool negative = take(rest, "-");
    std::size_t digits  = rest.find(',');
    const auto exp      = canonical_number(rest.substr(0, digits));
    if (digits == std::string_view::npos || !exp || *exp > static_cast<std::uint64_t>(INT64_MAX)
        || (negative && *exp == 0))
        return std::unexpected(refused("a grant's exp is not a whole number"));
    claims.exp = negative ? -static_cast<std::int64_t>(*exp) : static_cast<std::int64_t>(*exp);
    rest.remove_prefix(digits);
    if (!take(rest, R"(,"purpose":")") || !take(rest, purpose) || !take(rest, R"(","sha256":")"))
        return std::unexpected(refused("a grant of another purpose (SPEC.md 19.3)"));
    const auto file = digest_from_hex(rest.substr(0, 64));
    if (!file)
        return std::unexpected(refused("a grant's sha256 is not 64 hex digits"));
    claims.sha256 = *file;
    rest.remove_prefix(64);
    if (!take(rest, R"(","size":)"))
        return std::unexpected(refused("a grant's payload not of SPEC.md 19.3's form"));
    digits           = rest.find(',');
    const auto bytes = canonical_number(rest.substr(0, digits));
    if (digits == std::string_view::npos || !bytes)
        return std::unexpected(refused("a grant's size is not a whole number"));
    claims.size = *bytes;
    rest.remove_prefix(digits);
    if (!take(rest, R"(,"uid":")") || rest.size() != 36 + 2 || !rest.ends_with(R"("})")
        || !is_uuid(rest.substr(0, 36)))
        return std::unexpected(refused("a grant's uid is not a server's"));
    std::copy_n(rest.begin(), 36, claims.uid.begin());

    // The server it names, among those the peer paired with
    const auto server
        = std::ranges::find_if(servers, [&](const GrantKey& key) { return key.uid == claims.uid_view(); });
    if (server == servers.end())
        return std::unexpected(refused("a grant of a server this peer did not pair with (SPEC.md 19.4)"));
    if (!ed25519_verify(signature, server->key, std::span(payload_bytes.data(), *size)))
        return std::unexpected(refused("a grant whose signature does not verify (SPEC.md 19.3)"));
    if (claims.exp < now)
        return std::unexpected(refused("an expired grant (SPEC.md 19.4)"));
    if (!same_digest(claims.sha256, sha256))
        return std::unexpected(refused("a grant for another file (SPEC.md 19.4)"));
    return claims;
}

Read<PeerReply> read_peer_datagram(std::span<const std::byte> datagram, const DecodeOptions& options)
{
    if (datagram.size() > max_discovery_datagram)
        return fail(Category::limit, "a discovery datagram above 1200 bytes (SPEC.md 4.1)");
    const std::string_view text(reinterpret_cast<const char*>(datagram.data()), datagram.size());
    DecodeOptions bounded       = options;
    bounded.limits.max_document = std::min(bounded.limits.max_document, max_discovery_datagram);
    auto read                   = read_peer_reply(text, bounded);
    if (!read || !*read)
        return read;
    const PeerReply& reply = **read;
    if (reply.lantern != "peer")
        return fail(Category::invalid_response, "a datagram that is not a peer's reply (SPEC.md 19.5)");
    if (!is_uuid(reply.uid) || reply.port == 0 || reply.port > 65535 || reply.slots == 0 || reply.slots > 8)
        return fail(Category::invalid_response, "a peer's reply not of SPEC.md 19.5's form");
    if (reply.base.empty() || reply.base.front() != '/' || reply.base.back() == '/'
        || reply.base.find_first_of("?#") != String::npos || reply.base.size() > 256)
        return fail(Category::invalid_response, "a peer's base that is not a path");
    if (reply.servers.empty() || reply.servers.size() > 16
        || !std::ranges::all_of(reply.servers, [](const String& uid) { return is_uuid(uid); }))
        return fail(Category::invalid_response, "a peer's servers are 1 to 16 uids (SPEC.md 19.5)");
    return read;
}

bool peer_serves(const PeerReply& reply, std::string_view uid) noexcept
{
    return std::ranges::any_of(reply.servers, [&](const String& server) { return server == uid; });
}

Result<String> peer_blob_url(const PeerEndpoint& peer, const Digest& sha256, Allocator allocator)
{
    if (peer.base.empty() || peer.base.front() != '/'
        || peer.base.find_first_of("?# ") != std::string_view::npos || peer.port == 0)
        return fail(Category::usage, "a peer is an address, a port and a base path");
    auto origin = discovered_origin(peer.host, peer.port, allocator);
    if (!origin)
        return std::unexpected(origin.error());
    if (!peer.tls)
        origin->replace(0, 5, "http"); // "https" -> "http"
    String url(*origin, allocator);
    url.append(peer.base);
    url.append("/v1/blobs/sha256/");
    const auto hex = to_hex(sha256);
    url.append(hex.data(), hex.size());
    const auto parts = split_url(url);
    if (!parts)
        return std::unexpected(parts.error());
    // L-19.4-6: a grant goes over plain HTTP to a private network only
    if (auto scheme = check_untrusted_scheme(*parts); !scheme)
        return std::unexpected(scheme.error());
    return url;
}

// The peer's side.

namespace
{

constexpr std::string_view problem_403
    = R"({"schema":1,"type":"https://lantern.boreale.dev/errors/forbidden","title":"Forbidden","status":403,"code":"forbidden","detail":"A grant of a server this peer paired with, for this file, not expired (SPEC.md 19.4).","language":"en"})";
constexpr std::string_view problem_404
    = R"({"schema":1,"type":"https://lantern.boreale.dev/errors/not-found","title":"Not found","status":404,"code":"not_found","detail":"This peer does not hold that file.","language":"en"})";
constexpr std::string_view problem_405
    = R"({"schema":1,"type":"https://lantern.boreale.dev/errors/bad-request","title":"Method not allowed","status":405,"code":"bad_request","detail":"A peer answers GET and HEAD.","language":"en"})";
constexpr std::string_view problem_416
    = R"({"schema":1,"type":"https://lantern.boreale.dev/errors/bad-request","title":"Range not satisfiable","status":416,"code":"bad_request","language":"en"})";
constexpr std::string_view problem_429
    = R"({"schema":1,"type":"https://lantern.boreale.dev/errors/slow-down","title":"Slow down","status":429,"code":"slow_down","detail":"Too many requests or downloads at once.","language":"en"})";

PeerAnswer problem(std::uint16_t status, std::string_view body, std::uint32_t retry_after = 0)
{
    PeerAnswer answer;
    answer.status      = status;
    answer.body        = body;
    answer.retry_after = retry_after;
    return answer;
}

struct Range
{
    std::uint64_t first = 0;
    std::uint64_t last  = 0;
};

// One range of "bytes=a-b", "bytes=a-" or "bytes=-n"; nothing for a range
// header the peer ignores; `unsatisfiable` for one outside the file.
std::optional<Range> parse_range(std::string_view value, std::uint64_t size, bool& unsatisfiable) noexcept
{
    unsatisfiable = false;
    if (!take(value, "bytes=") || value.contains(','))
        return std::nullopt;
    const std::size_t dash = value.find('-');
    if (dash == std::string_view::npos)
        return std::nullopt;
    const std::string_view a = value.substr(0, dash);
    const std::string_view b = value.substr(dash + 1);
    std::uint64_t first      = 0;
    std::uint64_t last       = 0;
    const auto number        = [](std::string_view text, std::uint64_t& out)
    {
        const auto result = std::from_chars(text.data(), text.data() + text.size(), out);
        return !text.empty() && result.ec == std::errc {} && result.ptr == text.data() + text.size();
    };
    if (a.empty())
    {
        std::uint64_t suffix = 0;
        if (!number(b, suffix))
            return std::nullopt;
        if (suffix == 0 || size == 0)
        {
            unsatisfiable = true;
            return std::nullopt;
        }
        first = size - std::min(size, suffix);
        last  = size - 1;
    }
    else
    {
        if (!number(a, first))
            return std::nullopt;
        if (b.empty())
            last = size == 0 ? 0 : size - 1;
        else if (!number(b, last) || last < first)
            return std::nullopt;
        if (first >= size)
        {
            unsatisfiable = true;
            return std::nullopt;
        }
        last = std::min(last, size - 1);
    }
    return Range { first, last };
}

std::size_t write_number(std::span<char> out, std::uint64_t value) noexcept
{
    const auto result = std::to_chars(out.data(), out.data() + out.size(), value);
    return static_cast<std::size_t>(result.ptr - out.data());
}

} // namespace

std::span<const Header> PeerAnswer::headers() noexcept
{
    std::size_t count = 0;
    std::size_t used  = 0;
    const auto text   = [&](std::string_view part) -> std::string_view
    {
        const std::size_t take = std::min(part.size(), text_.size() - used);
        std::copy_n(part.data(), take, text_.begin() + static_cast<std::ptrdiff_t>(used));
        const std::string_view out(text_.data() + used, take);
        used += take;
        return out;
    };
    const auto number = [&](std::uint64_t value) -> std::string_view
    {
        const std::size_t written = write_number(std::span(text_).subspan(used), value);
        const std::string_view out(text_.data() + used, written);
        used += written;
        return out;
    };
    const bool file = status == 200 || status == 206 || (status == 416 && size != 0);
    if (!body.empty())
    {
        headers_[count++] = { "Content-Type", "application/problem+json" };
        headers_[count++] = { "Content-Length", number(body.size()) };
        headers_[count++] = { "Cache-Control", "no-store" };
        if (retry_after != 0)
            headers_[count++] = { "Retry-After", number(retry_after) };
        if (status == 416)
        {
            const std::size_t start = used;
            static_cast<void>(text("bytes */"));
            static_cast<void>(number(size));
            headers_[count++] = { "Content-Range", std::string_view(text_.data() + start, used - start) };
        }
        return { headers_.data(), count };
    }
    if (!file)
        return { headers_.data(), count };
    headers_[count++] = { "Content-Type", "application/octet-stream" };
    headers_[count++] = { "Content-Length", number(length) };
    headers_[count++] = { "Accept-Ranges", "bytes" };
    headers_[count++] = { "Cache-Control", "no-store" };
    const auto hex    = to_hex(sha256);
    {
        const std::size_t start = used;
        static_cast<void>(text("\""));
        static_cast<void>(text(std::string_view(hex.data(), 32)));
        static_cast<void>(text("\""));
        headers_[count++] = { "ETag", std::string_view(text_.data() + start, used - start) };
    }
    {
        const std::size_t start = used;
        static_cast<void>(text("sha-256=:"));
        std::array<char, 44> b64 {};
        std::size_t produced = 0;
        // Standard base64 of the 32 bytes, with its one padding character
        static constexpr std::string_view alphabet
            = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (std::size_t i = 0; i < 32; i += 3)
        {
            const std::uint32_t group = (static_cast<std::uint32_t>(sha256[i]) << 16U)
                | (i + 1 < 32 ? static_cast<std::uint32_t>(sha256[i + 1]) << 8U : 0U)
                | (i + 2 < 32 ? static_cast<std::uint32_t>(sha256[i + 2]) : 0U);
            b64[produced++] = alphabet[(group >> 18U) & 63U];
            b64[produced++] = alphabet[(group >> 12U) & 63U];
            b64[produced++] = i + 1 < 32 ? alphabet[(group >> 6U) & 63U] : '=';
            b64[produced++] = i + 2 < 32 ? alphabet[group & 63U] : '=';
        }
        static_cast<void>(text(std::string_view(b64.data(), produced)));
        static_cast<void>(text(":"));
        headers_[count++] = { "Repr-Digest", std::string_view(text_.data() + start, used - start) };
    }
    if (status == 206)
    {
        const std::size_t start = used;
        static_cast<void>(text("bytes "));
        static_cast<void>(number(offset));
        static_cast<void>(text("-"));
        static_cast<void>(number(offset + length - 1));
        static_cast<void>(text("/"));
        static_cast<void>(number(size));
        headers_[count++] = { "Content-Range", std::string_view(text_.data() + start, used - start) };
    }
    return { headers_.data(), count };
}

PeerGate::PeerGate(
    std::span<const GrantKey> servers, HeldFiles& files, Clock& clock, const PeerLimits& limits)
    : servers_(servers)
    , files_(&files)
    , clock_(&clock)
    , limits_(limits)
{
    limits_.slots      = std::clamp<std::uint32_t>(limits_.slots, 1, 8);
    limits_.per_second = std::max<std::uint32_t>(limits_.per_second, 1);
}

bool PeerGate::too_fast(std::string_view address, std::int64_t now) noexcept
{
    if (address.size() > Visitor {}.address.size())
        address = address.substr(0, Visitor {}.address.size());
    Visitor* slot   = nullptr;
    Visitor* oldest = visitors_.data();
    for (Visitor& visitor : visitors_)
    {
        if (std::string_view(visitor.address.data(), visitor.size) == address)
        {
            slot = &visitor;
            break;
        }
        if (visitor.second < oldest->second)
            oldest = &visitor;
    }
    if (slot == nullptr)
    {
        slot = oldest;
        std::ranges::copy(address, slot->address.begin());
        slot->size   = address.size();
        slot->second = now;
        slot->count  = 0;
    }
    if (slot->second != now)
    {
        slot->second = now;
        slot->count  = 0;
    }
    return ++slot->count > limits_.per_second;
}

PeerAnswer PeerGate::handle(const PeerRequest& request)
{
    // L-19.4-3: only while its user allows it, and only to its own networks
    if (!enabled_ || !(is_private_host(request.remote_address) || is_loopback_host(request.remote_address)))
        return problem(403, problem_403);
    const std::int64_t now = clock_->unix_seconds();
    if (too_fast(request.remote_address, now))
        return problem(429, problem_429, 1);
    if (request.method != "GET" && request.method != "HEAD")
        return problem(405, problem_405);
    // <base>/v1/blobs/sha256/<hex>, and nothing else
    std::string_view path = request.target.substr(0, request.target.find('?'));
    if (!take(path, limits_.base) || !take(path, "/v1/blobs/sha256/"))
        return problem(404, problem_404);
    const auto sha256 = digest_from_hex(path);
    if (!sha256)
        return problem(404, problem_404);
    const auto claims = verify_grant(request.grant, *sha256, now, servers_);
    if (!claims)
        return problem(403, problem_403);
    const auto size = files_->size_of(*sha256);
    if (!size || *size != claims->size)
        return problem(404, problem_404);

    PeerAnswer answer;
    answer.sha256  = *sha256;
    answer.size    = *size;
    answer.status  = 200;
    answer.length  = *size;
    const auto hex = to_hex(*sha256);
    std::array<char, 34> etag {};
    etag.front() = '"';
    std::copy_n(hex.begin(), 32, etag.begin() + 1);
    etag.back() = '"';
    if (!request.range.empty()
        && (request.if_range.empty() || request.if_range == std::string_view(etag.data(), etag.size())))
    {
        bool unsatisfiable = false;
        const auto range   = parse_range(request.range, *size, unsatisfiable);
        if (unsatisfiable)
        {
            PeerAnswer out = problem(416, problem_416);
            out.size       = *size;
            return out;
        }
        if (range)
        {
            answer.status = 206;
            answer.offset = range->first;
            answer.length = range->last - range->first + 1;
        }
    }
    if (request.method == "HEAD")
        return answer;
    // L-19.4-4: `slots` downloads at once
    if (active_ >= limits_.slots)
        return problem(429, problem_429, 5);
    ++active_;
    answer.slot  = true;
    answer.serve = answer.length != 0;
    return answer;
}

void PeerGate::release() noexcept
{
    if (active_ > 0)
        --active_;
}

} // namespace lantern
