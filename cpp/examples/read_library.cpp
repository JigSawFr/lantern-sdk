// The README's example: the handshake, a listing, a verified download.
//
//     read_library http://127.0.0.1:8080 [platform]
//
// Over the loopback adapter (plain HTTP on 127.0.0.1 only); an app gives
// its own Transport, with TLS.
#include <cstdio>
#include <string>

#include <lantern/lantern.hpp>

#include "posix_http.hpp"

namespace
{

// Bytes kept in memory; an app writes them to its storage.
class Counting final : public lantern::DownloadSink
{
  public:
    std::uint64_t bytes = 0;
    lantern::Result<void> write(std::span<const std::byte> chunk) override
    {
        bytes += chunk.size();
        return {};
    }
    lantern::Result<void> restart() override
    {
        bytes = 0;
        return {};
    }
};

int report(const lantern::Error& error)
{
    const std::string_view category = lantern::category_name(error.category());
    const std::string_view code     = lantern::code_name(error.effective_code());
    std::fprintf(stderr, "error (%.*s, %u %.*s): %.*s\n", static_cast<int>(category.size()), category.data(),
        static_cast<unsigned>(error.status()), static_cast<int>(code.size()), code.data(),
        static_cast<int>(error.detail().size()), error.detail().data());
    return 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: read_library ORIGIN [platform]\n");
        return 2;
    }
    lantern::posix::LoopbackTransport transport;
    lantern::ClientConfig config;
    config.origin     = argv[1];
    config.user_agent = "ReadLibrary/0.3";
    config.platform   = argc > 2 ? argv[2] : "switch";
    auto client       = lantern::Client::create(transport, config);
    if (!client)
        return report(client.error());

    // 1. The handshake: the server's name, its base path, what it offers
    const auto server = client->handshake();
    if (!server)
        return report(server.error());
    if (!*server)
    {
        std::fprintf(stderr, "the server speaks a newer schema than this client reads\n");
        return 1;
    }
    std::printf("%s (%s)\n", (*server)->name.c_str(), (*server)->uid.c_str());

    // 2. The listing, page by page
    lantern::AppsQuery query;
    query.page_size = 50;
    std::string cursor;
    std::optional<lantern::App> first;
    do
    {
        query.cursor    = cursor;
        const auto page = client->apps(query);
        if (!page)
            return report(page.error());
        if (!*page)
            break; // a newer schema: the listing is unavailable to this client
        for (const lantern::App& app : (*page)->items)
        {
            std::printf("  %-24s %-6s v%-10llu %s\n", app.name.c_str(), app.type.c_str(),
                static_cast<unsigned long long>(app.version_code), app.app_id.c_str());
            if (!first)
                first.emplace(app, client->allocator());
        }
        cursor.assign((*page)->next);
    } while (!cursor.empty());

    // 3. A download, checked against the listing's size and SHA-256: success
    // only when the whole file's digest matches
    if (first)
    {
        Counting sink;
        lantern::DownloadState state;
        const auto done = client->download({ first->file, first->size, first->sha256 }, state, sink);
        if (!done)
            return report(done.error());
        std::printf("downloaded %s: %llu bytes, SHA-256 verified\n", first->name.c_str(),
            static_cast<unsigned long long>(sink.bytes));
    }
    return 0;
}
