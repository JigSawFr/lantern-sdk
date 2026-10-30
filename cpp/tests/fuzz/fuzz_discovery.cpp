// A datagram on UDP 47115, any bytes (SPEC.md § 4.1): read as a server's
// reply, or dropped, never a crash; a reply read has a uid, a path for a
// base, version 1, and gives an origin a client can take.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/discovery.hpp>
#include <lantern/url.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const auto bytes = std::as_bytes(std::span(data, size));
    const auto read  = lantern::read_discovery_datagram(bytes);
    if (read && *read)
    {
        const lantern::DiscoveryReply& reply = **read;
        if (size > lantern::max_discovery_datagram || reply.uid.size() != 36 || reply.base.empty()
            || reply.base.front() != '/')
            __builtin_trap();
        const auto origin = lantern::discovered_origin("192.0.2.10", static_cast<std::uint16_t>(reply.port));
        if (reply.port != 0 && (!origin || !lantern::split_url(*origin)))
            __builtin_trap();
    }
    // The address part of a reply's source, as a socket could give it
    const std::string_view text(reinterpret_cast<const char*>(data), size < 64 ? size : 64);
    const auto origin = lantern::discovered_origin(text, 443);
    if (origin && !lantern::split_url(*origin))
        __builtin_trap();
    return 0;
}
