// A minimal blocking HTTP/1.1 listener over POSIX sockets, for the demo
// server and the conformance run: it accepts one connection at a time,
// reads one request (the head, then a body of Content-Length bytes), has the
// Server answer, writes the answer and closes (Connection: close). Plain
// HTTP, on loopback unless the app names another address; no TLS, no
// keep-alive, no chunked request bodies. Never for production: an app puts
// Server::handle() behind the HTTP server of its platform.
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <lantern/server.hpp>

namespace lantern::posix
{

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
    // Answers connections until `stop` is set (checked every 100 ms).
    void serve(const std::atomic<bool>& stop);

  private:
    HttpListener(const Server& server, const ListenOptions& options, int fd, std::uint16_t port) noexcept
        : server_(&server)
        , timeout_(options.timeout)
        , max_body_(options.max_body)
        , fd_(fd)
        , port_(port)
    {
    }

    // Reads one request from the connection and answers it: false when it was refused or dropped.
    bool answer(int connection) const;

    const Server* server_;
    std::chrono::milliseconds timeout_;
    std::size_t max_body_;
    int fd_             = -1;
    std::uint16_t port_ = 0;
};

} // namespace lantern::posix
