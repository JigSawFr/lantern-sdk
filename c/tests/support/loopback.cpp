// The POSIX adapter of cpp/adapters/posix, seen through the C API's
// callbacks: what an app does with its own HTTP stack.
#include "loopback.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "posix_http.hpp"
#include "posix_system.hpp"

namespace
{

std::size_t sent = 0;

// The library's answer handler, fed by the adapter, cutting when asked
class Forward final : public lantern::ResponseHandler
{
  public:
    Forward(lantern_response* response, std::size_t cut_after) noexcept
        : response_(response)
        , left_(cut_after)
        , cuts_(cut_after != 0)
    {
    }
    bool on_status(std::uint16_t status) override { return lantern_response_status(response_, status); }
    bool on_header(std::string_view name, std::string_view value) override
    {
        return lantern_response_header(response_, name.data(), name.size(), value.data(), value.size());
    }
    bool on_body(std::span<const std::byte> chunk) override
    {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(chunk.data());
        if (cuts_ && chunk.size() > left_)
        {
            static_cast<void>(lantern_response_body(response_, bytes, left_));
            cut = true;
            return false;
        }
        left_ -= cuts_ ? chunk.size() : 0;
        return lantern_response_body(response_, bytes, chunk.size());
    }
    bool cut = false;

  private:
    lantern_response* response_;
    std::size_t left_;
    bool cuts_;
};

struct Loopback
{
    lantern::posix::LoopbackTransport transport;
    std::size_t cut_after = 0;
};

lantern_status send(
    void* user, const lantern_request* request, lantern_response* response, lantern_error* error)
{
    auto* loopback = static_cast<Loopback*>(user);
    // The library's request, back as the adapter takes it
    static thread_local lantern::Header headers[64];
    if (request->header_count > 64)
        return LANTERN_ERROR_USAGE;
    for (std::size_t i = 0; i < request->header_count; ++i)
        headers[i] = { { request->headers[i].name.data, request->headers[i].name.size },
            { request->headers[i].value.data, request->headers[i].value.size } };
    lantern::Request out;
    out.method  = static_cast<lantern::Method>(request->method);
    out.url     = { request->url.data, request->url.size };
    out.headers = std::span(headers, request->header_count);
    out.body    = std::as_bytes(std::span(request->body, request->body_size));
    Forward forward(response, loopback->cut_after);
    ++sent;
    const auto result = loopback->transport.send(out, forward);
    if (forward.cut)
    {
        lantern_error_set(error, LANTERN_ERROR_TRANSPORT, "connection reset (by the test)");
        return LANTERN_ERROR_TRANSPORT;
    }
    if (!result)
    {
        lantern_error_set(error, LANTERN_ERROR_TRANSPORT, std::string(result.error().detail()).c_str());
        return LANTERN_ERROR_TRANSPORT;
    }
    return LANTERN_OK;
}

void release(void* user)
{
    delete static_cast<Loopback*>(user);
}

lantern_status udp_send(
    void* user, const char* address, std::uint16_t port, const std::uint8_t* bytes, std::size_t size)
{
    auto* socket = static_cast<lantern::posix::UdpBroadcastSocket*>(user);
    return socket->send_to(address, port, std::as_bytes(std::span(bytes, size))) ? LANTERN_OK
                                                                                 : LANTERN_ERROR_TRANSPORT;
}

lantern_status udp_receive(void* user, std::uint8_t* buffer, std::size_t capacity, std::uint32_t timeout_ms,
    lantern_datagram* out, bool* received)
{
    auto* socket   = static_cast<lantern::posix::UdpBroadcastSocket*>(user);
    const auto got = socket->receive(
        std::as_writable_bytes(std::span(buffer, capacity)), std::chrono::milliseconds(timeout_ms));
    if (!got)
        return LANTERN_ERROR_TRANSPORT;
    *received = got->has_value();
    if (*received)
    {
        out->size                 = (*got)->size;
        const std::string_view at = (*got)->address_view();
        const std::size_t length  = std::min(at.size(), sizeof(out->address) - 1);
        at.copy(out->address, length);
        out->address[length] = '\0';
        out->port            = (*got)->port;
    }
    return LANTERN_OK;
}

void udp_release(void* user)
{
    delete static_cast<lantern::posix::UdpBroadcastSocket*>(user);
}

} // namespace

extern "C" {

lantern_transport* test_loopback_transport(size_t cut_after)
{
    auto* loopback                        = new Loopback;
    loopback->cut_after                   = cut_after;
    lantern_transport_callbacks callbacks = LANTERN_INIT(lantern_transport_callbacks);
    callbacks.user                        = loopback;
    callbacks.send                        = send;
    callbacks.release                     = release;
    lantern_transport* transport          = nullptr;
    if (lantern_transport_create(&callbacks, nullptr, &transport, nullptr) != LANTERN_OK)
    {
        delete loopback;
        return nullptr;
    }
    return transport;
}

size_t test_loopback_requests(void)
{
    return sent;
}

lantern_udp_socket* test_udp_socket(void)
{
    auto opened = lantern::posix::UdpBroadcastSocket::open();
    if (!opened)
        return nullptr;
    auto* socket                    = new lantern::posix::UdpBroadcastSocket(std::move(*opened));
    lantern_udp_callbacks callbacks = LANTERN_INIT(lantern_udp_callbacks);
    callbacks.user                  = socket;
    callbacks.send_to               = udp_send;
    callbacks.receive               = udp_receive;
    callbacks.release               = udp_release;
    lantern_udp_socket* out         = nullptr;
    if (lantern_udp_socket_create(&callbacks, nullptr, &out, nullptr) != LANTERN_OK)
    {
        delete socket;
        return nullptr;
    }
    return out;
}

} // extern "C"
