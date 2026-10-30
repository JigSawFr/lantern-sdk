#include "posix_http.hpp"

#include <lantern/url.hpp>

#include "http1.hpp"
#include "tcp.hpp"

namespace lantern::posix
{

Result<void> LoopbackTransport::send(const Request& request, ResponseHandler& handler)
{
    ++requests_;
    const auto url = split_url(request.url);
    if (!url)
        return std::unexpected(url.error());
    if (url->scheme != "http" || !is_loopback_host(url->host))
        return fail(Category::usage, "this adapter speaks plain HTTP to a loopback address only");
    auto socket = http1::TcpSocket::connect(url->host, url->port, timeout_, true);
    if (!socket)
        return std::unexpected(socket.error());
    return http1::exchange(*socket, *url, request, handler);
}

} // namespace lantern::posix
