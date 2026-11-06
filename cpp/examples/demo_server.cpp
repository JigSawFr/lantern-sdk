// The server core over a small fictional library, for a look and for the
// conformance run:
//
//     lantern_demo_server [port]
//     python3 spec/conformance/run.py http://127.0.0.1:PORT/ --origin https://app.example.org
//
// It serves anonymously and read-only (Lantern Core: the handshake, the
// apps, what a device is missing, the files), over plain HTTP on 127.0.0.1;
// it prints its URL and serves until it is stopped. No port, or 0: a free one.
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <lantern/lantern.hpp>

#include "demo_library.hpp"
#include "posix_system.hpp"
#include "server_posix.hpp"

namespace
{

std::atomic<bool> stop { false };

extern "C" void on_signal(int /*signal*/)
{
    stop.store(true);
}

int report(const lantern::Error& error)
{
    std::fprintf(
        stderr, "demo server: %.*s\n", static_cast<int>(error.detail().size()), error.detail().data());
    return 1;
}

} // namespace

int main(int argc, char** argv)
{
    unsigned port = 0;
    if (argc > 1)
    {
        char* end    = nullptr;
        const long n = std::strtol(argv[1], &end, 10);
        if (end == argv[1] || *end != '\0' || n < 0 || n > 65535)
        {
            std::fprintf(stderr, "usage: lantern_demo_server [port]\n");
            return 2;
        }
        port = static_cast<unsigned>(n);
    }

    lantern::MemoryLibrary library(lantern::demo::base);
    if (auto filled = lantern::demo::fill(library); !filled)
        return report(filled.error());

    const std::array<std::string_view, 1> origins { lantern::demo::origin };
    lantern::ServerOptions options;
    options.uid              = lantern::demo::uid;
    options.name             = "Demo shelf";
    options.base             = lantern::demo::base;
    options.scheme           = "http";
    options.cors_origins     = origins;
    options.software_name    = "lantern-sdk C++ demo";
    options.software_version = "0.1";
    lantern::posix::SystemRandom random;
    lantern::SystemClock clock;
    auto server = lantern::Server::create(library, options, random, clock);
    if (!server)
        return report(server.error());

    lantern::posix::ListenOptions listen;
    listen.port   = static_cast<std::uint16_t>(port);
    auto listener = lantern::posix::HttpListener::listen(*server, listen);
    if (!listener)
        return report(listener.error());

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::printf("http://127.0.0.1:%u/\n", static_cast<unsigned>(listener->port()));
    std::fflush(stdout);
    listener->serve(stop);
    return 0;
}
