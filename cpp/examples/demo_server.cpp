// The server core over a small fictional library, for a look and for the
// conformance run:
//
//     lantern_demo_server [port] [--private] [--no-encrypted-saves]
//     python3 spec/conformance/run.py http://127.0.0.1:PORT/ --origin https://app.example.org
//
// It serves the library (Lantern Core: the handshake, the apps, what a
// device is missing, the files, with its changes and sections, its titles
// with their images, its homebrew and its cheat sets) to anyone, takes cheat
// sets from a token with the scope cheats.write, keeps save backups (also
// encrypted ones) in memory for the accounts with the scope saves, keeps the
// requests for games of the accounts with the scope requests, keeps their
// sync data (wishes and what a console has installed, § 20) in memory for the
// scopes sync.read and sync.write, gives grants for peers (§ 19.3), tells what
// changes as events (a stream and the long poll of `changes`, § 18), gives the
// chunk indexes of its large files (differential updates, § 22), and pairs
// devices: the accounts of demo_accounts.hpp, a token bound to a key, signed
// requests, invitations. An account with the scope admin runs the
// administration API: accounts, devices, pairings, invitations, requests.
// `--private` asks for a token on the library; `--no-encrypted-saves` keeps
// no backup encrypted on the device (a 400, § 9.4). Plain HTTP on 127.0.0.1; it
// prints its URL and serves until it is stopped. No port, or 0: a free one.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <thread>

#include <lantern/lantern.hpp>

#include "demo_accounts.hpp"
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
    unsigned port   = 0;
    bool is_private = false;
    bool encrypted  = true;
    for (int i = 1; i < argc; ++i)
    {
        if (std::string_view(argv[i]) == "--private")
        {
            is_private = true;
            continue;
        }
        if (std::string_view(argv[i]) == "--no-encrypted-saves")
        {
            encrypted = false;
            continue;
        }
        char* end    = nullptr;
        const long n = std::strtol(argv[i], &end, 10);
        if (end == argv[i] || *end != '\0' || n < 0 || n > 65535)
        {
            std::fprintf(stderr, "usage: lantern_demo_server [port] [--private] [--no-encrypted-saves]\n");
            return 2;
        }
        port = static_cast<unsigned>(n);
    }

    lantern::MemoryLibrary library(lantern::demo::base);
    if (auto filled = lantern::demo::fill(library); !filled)
        return report(filled.error());

    lantern::SystemClock clock;
    lantern::MemoryAccountStore accounts;
    if (auto filled = lantern::demo::fill_accounts(accounts, clock.unix_seconds()); !filled)
        return report(filled.error());

    lantern::MemorySaveStore saves;
    lantern::MemoryRequestStore requests;
    lantern::posix::SystemRandom random;
    lantern::MemorySyncStore sync(random);
    const std::array<std::string_view, 1> origins { lantern::demo::origin };
    lantern::ServerOptions options;
    options.uid              = lantern::demo::uid;
    options.name             = "Demo shelf";
    options.base             = lantern::demo::base;
    options.scheme           = "http";
    options.cors_origins     = origins;
    options.software_name    = "lantern-sdk C++ demo";
    options.software_version = "0.1";
    options.accounts         = &accounts;
    options.require_auth     = is_private;
    options.saves            = &saves;
    options.requests         = &requests;
    options.sync             = &sync;
    options.grant_seed       = lantern::demo::grant_seed();
    options.encrypted_saves  = encrypted;
    options.deltas           = true;
    // Events: a line on a stream every 5 seconds at least, which keeps the conformance run short
    options.events     = true;
    options.heartbeat  = 5;
    options.wait_limit = 30;
    auto server        = lantern::Server::create(library, options, random, clock);
    if (!server)
        return report(server.error());

    lantern::posix::ListenOptions listen;
    listen.port = static_cast<std::uint16_t>(port);
    // A cheat set is 1 MiB of text at most (§ 13), escaped in its JSON body
    listen.max_body = std::size_t { 3 } << 20U;
    // A save of up to save_limits.size is streamed to the store, never buffered
    listen.max_stream = options.save_limits.size;
    auto listener     = lantern::posix::HttpListener::listen(*server, listen);
    if (!listener)
        return report(listener.error());

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::printf("http://127.0.0.1:%u/\n", static_cast<unsigned>(listener->port()));
    std::fflush(stdout);
    listener->serve(stop);
    // The streams still open are told, then the listener ends them
    server->shutdown();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    return 0;
}
