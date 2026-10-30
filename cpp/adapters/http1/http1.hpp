// HTTP/1.1 over a byte stream, for the adapters that bring their own
// connection (adapters/posix's plain sockets, adapters/mbedtls's TLS): one
// request per connection (Connection: close), the answer's status, headers
// and body (Content-Length, chunked or delimited by the close) handed to the
// ResponseHandler as they come. Not installed on its own: each adapter
// compiles it in.
#pragma once

#include <cstddef>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/transport.hpp>
#include <lantern/url.hpp>

namespace lantern::http1
{

class Stream
{
  public:
    Stream()                         = default;
    Stream(const Stream&)            = default;
    Stream(Stream&&)                 = default;
    Stream& operator=(const Stream&) = default;
    Stream& operator=(Stream&&)      = default;
    virtual ~Stream()                = default;

    // Writes everything, or fails (Category::transport).
    [[nodiscard]] virtual Result<void> write(std::span<const char> bytes) = 0;
    // Reads what is there into `buffer`: 0 at the end of the stream.
    [[nodiscard]] virtual Result<std::size_t> read(std::span<char> buffer) = 0;
};

// Sends `request` to `url` (split from request.url) and reads its answer.
[[nodiscard]] Result<void> exchange(
    Stream& stream, const UrlParts& url, const Request& request, ResponseHandler& handler);

} // namespace lantern::http1
