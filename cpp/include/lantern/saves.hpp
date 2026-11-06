// What a server keeps of the save backups (SPEC.md § 9) and of the resumable
// uploads under way: the interface the server core asks, and a complete store
// held in memory for tests, demos and as a reference to read.
//
// The server does the protocol's work: the platform and the fields, the
// Content-Digest of a request and the SHA-256 of the whole archive, the
// limits, the backups kept per title, the encrypted backups kept as sent
// (§ 9.4, never decrypted). A store keeps bytes and documents, per account,
// and never sees a whole archive at once: a body reaches it piece by piece
// (`append`), so that a large save is never held in memory by the server.
//
// A save sent in one request (§ 9.2) goes through the same calls as an
// upload: the server opens one for it, appends the body, and keeps it once
// it checked the digest. Every method is atomic. Several threads call them;
// the server sees to it that two requests never write the same upload at once.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/server.hpp>
#include <lantern/sha256.hpp>
#include <lantern/types.hpp>

namespace lantern
{

// An upload under way (§ 9.3): the backup it will make (`save`: its platform,
// title and fields, the `size` and `sha256` announced; `save_id` and `created`
// are given when it ends), the account that opened it, when it is gone (Unix
// seconds) and how many bytes the store holds (`offset`).
struct StoredUpload
{
    String id; // `u_` and letters, digits, `_` and `-`
    String user;
    Save save;
    std::int64_t expires = 0;
    std::uint64_t offset = 0;

    explicit StoredUpload(const Allocator& allocator = {})
        : id(allocator)
        , user(allocator)
        , save(allocator)
    {
    }
};

// What the bytes of an upload hold now: their SHA-256 and their first 16.
struct UploadState
{
    Digest sha256 {};
    std::array<std::byte, 16> head {};
    std::size_t head_size = 0; // fewer than 16 for a shorter upload
};

// Where a server keeps backups and uploads. A method that fails
// (Category::storage) makes the request a 500.
class SaveStore
{
  public:
    SaveStore()                            = default;
    SaveStore(const SaveStore&)            = default;
    SaveStore(SaveStore&&)                 = default;
    SaveStore& operator=(const SaveStore&) = default;
    SaveStore& operator=(SaveStore&&)      = default;
    virtual ~SaveStore()                   = default;

    // The account's backups, the oldest kept first.
    [[nodiscard]] virtual Result<Vector<Save>> saves(std::string_view user, const Allocator& allocator) = 0;
    // A backup's bytes, as kept: `size` and `sha256` those of the save,
    // `application/octet-stream` for an encrypted one and `application/zip`
    // otherwise. Nothing when the account has none of that id.
    [[nodiscard]] virtual Result<std::optional<LibraryFile>> archive(
        std::string_view user, std::string_view save_id, const Allocator& allocator)
        = 0;
    // Removes a backup; false when the account has none of that id.
    [[nodiscard]] virtual Result<bool> drop(std::string_view user, std::string_view save_id) = 0;

    // Starts an upload with no byte yet (`upload.offset` is ignored).
    [[nodiscard]] virtual Result<void> open_upload(const StoredUpload& upload) = 0;
    // The upload under way, with the bytes held now as its `offset`.
    [[nodiscard]] virtual Result<std::optional<StoredUpload>> upload(
        std::string_view id, const Allocator& allocator)
        = 0;
    [[nodiscard]] virtual Result<Vector<StoredUpload>> uploads(const Allocator& allocator) = 0;
    // Adds bytes at the end of the upload: its new offset.
    [[nodiscard]] virtual Result<std::uint64_t> append(std::string_view id, std::span<const std::byte> bytes)
        = 0;
    // Cuts the upload back to `size` bytes (a chunk that did not check out).
    [[nodiscard]] virtual Result<void> truncate(std::string_view id, std::uint64_t size) = 0;
    // The SHA-256 and the first bytes of what the upload holds.
    [[nodiscard]] virtual Result<UploadState> upload_state(std::string_view id) = 0;
    // The upload's bytes become the backup `save` (of the upload's account);
    // the upload is gone.
    [[nodiscard]] virtual Result<void> keep_upload(std::string_view id, const Save& save) = 0;
    // Drops an upload and its bytes.
    [[nodiscard]] virtual Result<void> abandon(std::string_view id) = 0;
    // Erases an account's backups and uploads (§ 5.7).
    [[nodiscard]] virtual Result<void> forget(std::string_view user) = 0;
};

// Backups and uploads held in memory, behind a mutex.
class MemorySaveStore final : public SaveStore
{
  public:
    explicit MemorySaveStore(const Allocator& allocator = {});

    [[nodiscard]] Result<Vector<Save>> saves(std::string_view user, const Allocator& allocator) override;
    [[nodiscard]] Result<std::optional<LibraryFile>> archive(
        std::string_view user, std::string_view save_id, const Allocator& allocator) override;
    [[nodiscard]] Result<bool> drop(std::string_view user, std::string_view save_id) override;
    [[nodiscard]] Result<void> open_upload(const StoredUpload& upload) override;
    [[nodiscard]] Result<std::optional<StoredUpload>> upload(
        std::string_view id, const Allocator& allocator) override;
    [[nodiscard]] Result<Vector<StoredUpload>> uploads(const Allocator& allocator) override;
    [[nodiscard]] Result<std::uint64_t> append(
        std::string_view id, std::span<const std::byte> bytes) override;
    [[nodiscard]] Result<void> truncate(std::string_view id, std::uint64_t size) override;
    [[nodiscard]] Result<UploadState> upload_state(std::string_view id) override;
    [[nodiscard]] Result<void> keep_upload(std::string_view id, const Save& save) override;
    [[nodiscard]] Result<void> abandon(std::string_view id) override;
    [[nodiscard]] Result<void> forget(std::string_view user) override;

  private:
    struct Kept
    {
        String user;
        Save save;
        std::shared_ptr<MemoryFileReader> reader;
    };
    struct Part
    {
        StoredUpload upload;
        Vector<std::byte> bytes;
    };

    Part* find_part(std::string_view id);

    Allocator allocator_;
    std::mutex mutex_;
    Vector<Kept> kept_;
    Vector<Part> parts_;
};

} // namespace lantern
