// Discovery on the LAN (§ 4.1).
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/discovery.hpp>

#include "callbacks.hpp"

using namespace lantern_c;

namespace
{

// The app's handler behind the C++ one; each server's texts are copied so
// that every lantern_str is NUL-terminated.
class Handler final : public lantern::DiscoveryHandler
{
  public:
    Handler(lantern_discovery_handler handler, lantern_discovery_peer_handler peers, void* user,
        Resource* resource) noexcept
        : handler_(handler)
        , peers_(peers)
        , user_(user)
        , resource_(resource)
    {
    }

    [[nodiscard]] bool on_server(const lantern::DiscoveredServer& server) override
    {
        const lantern::Allocator allocator(resource_);
        const lantern::String address(server.address, allocator);
        const lantern::String origin(server.origin, allocator);
        lantern_discovered_server out {};
        out.struct_size = sizeof(out);
        out.address     = view(address);
        out.origin      = view(origin);
        out.reply       = wrap(server.reply);
        return handler_(user_, &out);
    }

    [[nodiscard]] bool on_peer(const lantern::DiscoveredPeer& peer) override
    {
        if (peers_ == nullptr)
            return true;
        const lantern::Allocator allocator(resource_);
        const lantern::String address(peer.address, allocator);
        const lantern::String host(peer.endpoint.host, allocator);
        const lantern::String base(peer.endpoint.base, allocator);
        lantern_discovered_peer out {};
        out.struct_size          = sizeof(out);
        out.address              = view(address);
        out.reply                = wrap(peer.reply);
        out.endpoint.struct_size = sizeof(out.endpoint);
        out.endpoint.host        = host.c_str();
        out.endpoint.port        = peer.endpoint.port;
        out.endpoint.base        = base.c_str();
        out.endpoint.tls         = peer.endpoint.tls;
        return peers_(user_, &out);
    }

  private:
    lantern_discovery_handler handler_;
    lantern_discovery_peer_handler peers_;
    void* user_;
    Resource* resource_;
};

} // namespace

// NOLINTBEGIN(readability-identifier-naming,misc-use-internal-linkage)
extern "C" {

LANTERN_API lantern_str lantern_discovery_request(void)
{
    const std::string_view request = lantern::discovery_request();
    return { request.data(), request.size() };
}

LANTERN_API lantern_status lantern_read_discovery_datagram(const uint8_t* bytes, size_t size,
    const lantern_allocator* allocator, lantern_discovery_reply** out, lantern_error* error)
{
    if (out == nullptr || (bytes == nullptr && size != 0))
        return usage(error, "a NULL argument");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    const lantern::DecodeOptions options = decode_options(nullptr, resource.get());
    auto read                            = lantern::read_discovery_datagram(
        std::as_bytes(std::span(bytes, bytes == nullptr ? 0 : size)), options);
    const lantern_status status
        = give_read<lantern::DiscoveryReply>(resource.get(), std::move(read), out, error);
    if (status >= 0)
        ok(error);
    return status;
}

LANTERN_API lantern_status lantern_discovered_origin(const char* address, uint16_t port,
    const lantern_allocator* allocator, lantern_string** out, lantern_error* error)
{
    if (out == nullptr)
        return usage(error, "out is NULL");
    *out = nullptr;
    const ScopedResource resource(allocator);
    if (!resource)
        return usage(error, "an allocator without its functions");
    auto origin = lantern::discovered_origin(text(address), port, lantern::Allocator(resource.get()));
    if (!origin)
        return fail(error, origin.error());
    *out = give_string(resource.get(), std::move(*origin));
    return ok(error);
}

LANTERN_API lantern_status lantern_discover(lantern_udp_socket* socket,
    const lantern_discovery_options* options, lantern_discovery_handler handler, void* user,
    lantern_error* error)
{
    if (socket == nullptr || options == nullptr || handler == nullptr)
        return usage(error, "a NULL argument");
    const lantern_discovery_options o = copy_struct(options);
    Resource* resource                = socket->resource();
    lantern::DiscoveryOptions settings;
    settings.address  = text(o.address);
    settings.port     = o.port == 0 ? lantern::discovery_port : o.port;
    settings.wait     = std::chrono::milliseconds(o.wait_ms == 0 ? 1500 : o.wait_ms);
    settings.attempts = o.attempts == 0 ? 2 : o.attempts;
    settings.decode   = decode_options(o.limits, resource);
    settings.peers    = o.peers;
    Handler wrapped(handler, o.on_peer, user, resource);
    const auto found = lantern::discover(*socket, settings, wrapped);
    if (!found)
        return fail(error, found.error());
    return ok(error);
}

} // extern "C"
// NOLINTEND(readability-identifier-naming,misc-use-internal-linkage)
