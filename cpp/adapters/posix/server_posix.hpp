// A minimal blocking HTTP/1.1 listener over POSIX sockets, for the demo
// server and the conformance run: it accepts one connection at a time,
// reads one request (the head, then a body of Content-Length bytes), has the
// Server answer, writes the answer and closes (Connection: close). A body
// above `max_body` is not buffered when `max_stream` allows it: the server
// reads it from the connection piece by piece (ServerRequest::stream), as
// the save uploads do, and answers 413 on the routes that take none. Plain
// HTTP, on loopback unless the app names another address; no TLS, no
// keep-alive, no chunked request bodies. The responses the server holds (a
// long poll waiting for an event, an event stream: see ServerResponse) each
// get a thread of their own, joined when they end or when the listener goes;
// 64 at most at once, then a 429. Never for production: an app puts
// Server::handle() behind the HTTP server of its platform.
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

#include <lantern/server.hpp>

namespace lantern::posix
{

struct HoldRegistry;

struct ListenOptions
{
    // An address (not a name): loopback by default.
    std::string_view host = "127.0.0.1";
    // 0: a free port, which port() says.
    std::uint16_t port = 0;
    // For each read and write on a connection: a client that stalls is dropped.
    std::chrono::milliseconds timeout = std::chrono::seconds(15);
    // The largest body taken (Content-Length); a larger one is a 413.
    std::size_t max_body = std::size_t { 1 } << 20;
    // The largest body streamed rather than buffered (a body above `max_body`
    // and up to this); a larger one is a 413. 0: none is streamed.
    std::uint64_t max_stream = 0;
};

class HttpListener
{
  public:
    // Listens at once. `server` must outlive the listener.
    [[nodiscard]] static Result<HttpListener> listen(const Server& server, const ListenOptions& options = {});

    HttpListener(const HttpListener&)            = delete;
    HttpListener& operator=(const HttpListener&) = delete;
    HttpListener(HttpListener&& other) noexcept;
    HttpListener& operator=(HttpListener&& other) noexcept;
    ~HttpListener();

    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }

    // Waits up to `wait` for a connection and answers it: true when one was.
    [[nodiscard]] Result<bool> serve_one(std::chrono::milliseconds wait);
    // Answers connections until `stop` is set (checked every 100 ms). The
    // connections held meanwhile go on in their threads; they end with the
    // listener, or when the server shuts down (Server::shutdown()).
    void serve(const std::atomic<bool>& stop);

  private:
    HttpListener(const Server& server, const ListenOptions& options, int fd, std::uint16_t port);

    // Reads one request from the connection and answers it: false when it was refused or dropped.
    bool answer(int connection) const;

    const Server* server_;
    std::chrono::milliseconds timeout_;
    std::size_t max_body_;
    std::uint64_t max_stream_;
    int fd_             = -1;
    std::uint16_t port_ = 0;
    std::shared_ptr<HoldRegistry> holders_;
};

} // namespace lantern::posix
