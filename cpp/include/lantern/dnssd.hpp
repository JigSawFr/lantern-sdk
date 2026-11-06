// DNS-SD (RFC 6763) over multicast DNS (RFC 6762), the client's side of
// SPEC.md § 4.1 (`_lantern._tcp`: `uid=`, `path=`, `v=`) and § 19.5
// (`_lantern-peer._tcp`: `servers=`, `path=`, `v=`, `tls=`).
//
// The client asks once, from a port that is not 5353: RFC 6762 § 6.7 has a
// responder answer such a question straight back to its sender, so the app's
// UdpSocket (the same as discover()'s) joins no multicast group and keeps
// nothing between two browses. An instance whose answer came without its port
// or its TXT is asked for them once. IPv4 only: the question goes to
// 224.0.0.251.
//
// What is found is a hint, as any discovery: nothing is trusted but through
// TLS and pairing (L-4.1-5). A message that is cut, loops, or says more than
// it can hold is dropped, never an error; a server's advertisement is held to
// the rules of its datagram reply (a uid that is a UUID, a path, version 1).
#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

#include <lantern/discovery.hpp>
#include <lantern/error.hpp>

namespace lantern
{

inline constexpr std::string_view mdns_group = "224.0.0.251";
inline constexpr std::uint16_t mdns_port     = 5353;

struct DnssdOptions
{
    // Where the question goes: the group and port of RFC 6762, or a
    // responder's own address and port to ask it alone.
    std::string_view address = mdns_group;
    std::uint16_t port       = mdns_port;
    // How long to listen after asking.
    std::chrono::milliseconds wait { 2000 };
    // Browse `_lantern-peer._tcp` (§ 19.5) instead of `_lantern._tcp`: the
    // peers come to `DiscoveryHandler::on_peer`, their `reply->uid` empty (an
    // advertisement has none), `reply->name` the instance's, and `slots` 1.
    bool peers = false;
    DecodeOptions decode {};
};

// Asks for the instances of the service, listens for `wait`, and hands each
// server (by uid) or peer (by name and address) found once to `handler`.
[[nodiscard]] Result<void> browse_dnssd(
    UdpSocket& socket, const DnssdOptions& options, DiscoveryHandler& handler);

} // namespace lantern
