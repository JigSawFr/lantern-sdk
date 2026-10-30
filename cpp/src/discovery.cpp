#include <lantern/discovery.hpp>

#include <algorithm>
#include <array>
#include <charconv>

#include <lantern/url.hpp>

namespace lantern
{

namespace
{

constexpr std::string_view request_text = R"({"schema":1,"lantern":"discover"})";
constexpr std::string_view peers_text   = R"({"schema":1,"lantern":"discover","peers":true})";
constexpr std::size_t max_servers       = 64;

bool hex_digits(std::string_view text) noexcept
{
    return std::ranges::all_of(text,
        [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); });
}

// 8-4-4-4-12 hex digits.
bool is_uuid(std::string_view text) noexcept
{
    return text.size() == 36 && text[8] == '-' && text[13] == '-' && text[18] == '-' && text[23] == '-'
        && hex_digits(text.substr(0, 8)) && hex_digits(text.substr(9, 4)) && hex_digits(text.substr(14, 4))
        && hex_digits(text.substr(19, 4)) && hex_digits(text.substr(24));
}

} // namespace

std::string_view discovery_request(bool peers) noexcept
{
    return peers ? peers_text : request_text;
}

Read<DiscoveryReply> read_discovery_datagram(
    std::span<const std::byte> datagram, const DecodeOptions& options)
{
    if (datagram.size() > max_discovery_datagram)
        return fail(Category::limit, "a discovery datagram above 1200 bytes (SPEC.md 4.1)");
    const std::string_view text(reinterpret_cast<const char*>(datagram.data()), datagram.size());
    DecodeOptions bounded       = options;
    bounded.limits.max_document = std::min(bounded.limits.max_document, max_discovery_datagram);
    auto read                   = read_discovery_reply(text, bounded);
    if (!read || !*read)
        return read;
    const DiscoveryReply& reply = **read;
    if (reply.lantern != "server")
        return fail(Category::invalid_response, "a datagram that is not a server's reply (SPEC.md 4.1)");
    if (!is_uuid(reply.uid))
        return fail(Category::invalid_response, "a reply whose uid is not a UUID");
    if (reply.base.empty() || reply.base.front() != '/' || reply.base.back() == '/'
        || reply.base.find_first_of("?#") != String::npos)
        return fail(Category::invalid_response, "a reply whose base is not a path (SPEC.md 2)");
    if (std::ranges::find(reply.versions, std::uint64_t { 1 }) == reply.versions.end())
        return fail(Category::unsupported, "a server that does not serve version 1 of the protocol");
    return read;
}

Result<String> discovered_origin(std::string_view address, std::uint16_t port, Allocator allocator)
{
    // An IP address, as a socket writes it: nothing but what one holds
    const bool address_only = std::ranges::all_of(address,
        [](char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.'
                || c == ':';
        });
    if (address.empty() || address.size() > 60 || port == 0 || !address_only)
        return fail(Category::usage, "not an address and a port");
    String out(allocator);
    out.append("https://");
    const bool ipv6 = address.contains(':');
    if (ipv6)
        out.push_back('[');
    out.append(address);
    if (ipv6)
        out.push_back(']');
    out.push_back(':');
    std::array<char, 8> digits {};
    const auto result = std::to_chars(digits.data(), digits.data() + digits.size(), port);
    out.append(digits.data(), result.ptr);
    // What split_url takes is what a ClientConfig takes
    if (auto parts = split_url(out); !parts)
        return fail(Category::invalid_response, "a reply's source that is not an address");
    return out;
}

Result<void> discover(UdpSocket& socket, const DiscoveryOptions& options, DiscoveryHandler& handler)
{
    if (options.address.empty() || options.attempts == 0)
        return fail(Category::usage, "discovery needs an address and at least one attempt");
    const std::string_view text = discovery_request(options.peers);
    const auto request          = std::as_bytes(std::span(text.data(), text.size()));
    const Allocator allocator(options.decode.memory);
    Vector<String> seen(allocator);
    Vector<String> peers_seen(allocator);

    using steady       = std::chrono::steady_clock;
    const auto start   = steady::now();
    const auto end     = start + options.wait;
    const auto spacing = options.wait / options.attempts;
    unsigned sent      = 0;
    // One byte more than a datagram may have: a longer one is seen as such
    std::array<std::byte, max_discovery_datagram + 1> buffer {};
    for (;;)
    {
        const auto now = steady::now();
        if (sent < options.attempts && now >= start + spacing * sent)
        {
            if (auto done = socket.send_to(options.address, options.port, request); !done)
                return done;
            ++sent;
        }
        if (now >= end)
            return {};
        auto next_send     = sent < options.attempts ? start + spacing * sent : end;
        next_send          = std::min(next_send, end);
        const auto timeout = std::max(std::chrono::milliseconds(1),
            std::chrono::duration_cast<std::chrono::milliseconds>(next_send - steady::now()));
        const auto got     = socket.receive(buffer, timeout);
        if (!got)
            return std::unexpected(got.error());
        if (!*got || (*got)->size > max_discovery_datagram)
            continue;
        const Datagram& datagram = **got;
        // Anything that is not a reply of § 4.1 is dropped: discovery is a hint
        const auto bytes = std::span(buffer).first(datagram.size);
        const auto reply = read_discovery_datagram(bytes, options.decode);
        if (!reply || !*reply)
        {
            if (options.peers)
            {
                const auto peer = read_peer_datagram(bytes, options.decode);
                if (!peer || !*peer)
                    continue;
                const PeerReply& found = **peer;
                if (std::ranges::any_of(peers_seen, [&](const String& uid) { return uid == found.uid; })
                    || peers_seen.size() >= max_servers)
                    continue;
                peers_seen.emplace_back(found.uid);
                DiscoveredPeer out;
                out.address       = datagram.address_view();
                out.reply         = &found;
                out.endpoint.host = datagram.address_view();
                out.endpoint.port = static_cast<std::uint16_t>(found.port);
                out.endpoint.base = found.base;
                out.endpoint.tls  = found.tls;
                if (!handler.on_peer(out))
                    return {};
            }
            continue;
        }
        const DiscoveryReply& found = **reply;
        if (std::ranges::any_of(seen, [&](const String& uid) { return uid == found.uid; })
            || seen.size() >= max_servers)
            continue;
        const auto origin
            = discovered_origin(datagram.address_view(), static_cast<std::uint16_t>(found.port), allocator);
        if (!origin)
            continue;
        seen.emplace_back(found.uid);
        DiscoveredServer server;
        server.address = datagram.address_view();
        server.reply   = &found;
        server.origin  = *origin;
        if (!handler.on_server(server))
            return {};
    }
}

} // namespace lantern
