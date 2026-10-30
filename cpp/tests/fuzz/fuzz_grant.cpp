// A grant, a peer's discovery reply and a static library's path, any bytes
// (SPEC.md § 19.3, § 19.5, § 21.1): never a crash; a grant never verifies
// without the server's signature, and a path accepted is relative, without
// "..", "\", a query or a scheme.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/peers.hpp>
#include <lantern/static_library.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    // A key nobody holds the private half of: nothing verifies by it
    lantern::GrantKey server;
    server.uid        = "6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14";
    server.key        = lantern::PublicKey { 0x16, 0x40, 0xd5, 0x2b };
    const auto claims = lantern::verify_grant(text, lantern::Digest {}, 0, std::span(&server, 1));
    if (claims)
        __builtin_trap();

    const auto peer = lantern::read_peer_datagram(std::as_bytes(std::span(data, size)));
    if (peer && *peer && ((*peer)->servers.empty() || (*peer)->slots == 0 || (*peer)->slots > 8))
        __builtin_trap();

    if (lantern::is_static_path(text)
        && (text.empty() || text.front() == '/' || text.contains('\\') || text.contains('?') || text == ".."
            || text.starts_with("../") || text.contains("/../") || text.ends_with("/..")))
        __builtin_trap();
    return 0;
}
