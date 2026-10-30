// Downloads (SPEC.md § 6.6): Range to resume, the SHA-256 computed as the
// bytes come, Repr-Digest checked against the size and digest the listing
// gave. Nothing is done until the digest matches: a download returns
// success only then, and the app installs nothing before.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>

namespace lantern
{

// Where the bytes go: the app's file, or memory.
class DownloadSink
{
  public:
    DownloadSink()                               = default;
    DownloadSink(const DownloadSink&)            = default;
    DownloadSink(DownloadSink&&)                 = default;
    DownloadSink& operator=(const DownloadSink&) = default;
    DownloadSink& operator=(DownloadSink&&)      = default;
    virtual ~DownloadSink()                      = default;

    // Appends the next bytes.
    [[nodiscard]] virtual Result<void> write(std::span<const std::byte> bytes) = 0;
    // The server sends the file from its start again (it ignored the range,
    // or the file changed): drop what was written.
    [[nodiscard]] virtual Result<void> restart() = 0;
};

// The bytes kept in memory, up to a cap: a cheat set's text, a small file.
class MemorySink final : public DownloadSink
{
  public:
    MemorySink(std::size_t cap, Allocator allocator = {})
        : cap_(cap)
        , bytes_(allocator)
    {
    }
    [[nodiscard]] Result<void> write(std::span<const std::byte> bytes) override;
    [[nodiscard]] Result<void> restart() override;
    [[nodiscard]] std::string_view text() const noexcept { return bytes_; }

  private:
    std::size_t cap_;
    String bytes_;
};

// What the app knows of the file before it downloads it: from the app's,
// homebrew package's, save's or cheat set's entry.
struct DownloadTarget
{
    std::string_view url; // the entry's `file`, a path on the server or an absolute URL
    std::uint64_t size = 0;
    Digest sha256 {};
};

// A download in progress: what was received and its hash so far. Kept by
// the app between attempts (in memory, or saved next to the partial file)
// so that the next attempt asks only for the rest.
struct DownloadState
{
    std::uint64_t received = 0;
    Sha256::State hash     = Sha256().state();
    // The file's strong ETag, for If-Range: a file that changed comes whole.
    std::array<char, 128> etag {};
    std::size_t etag_size = 0;

    [[nodiscard]] std::string_view etag_view() const noexcept { return { etag.data(), etag_size }; }
    void reset() noexcept { *this = DownloadState {}; }
};

} // namespace lantern
