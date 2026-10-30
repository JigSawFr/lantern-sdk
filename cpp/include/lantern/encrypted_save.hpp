// End-to-end encrypted save backups, scheme `lantern-save-e2e-1` (SPEC.md
// § 9.4): the server keeps bytes it cannot read, by a key only the user's
// devices hold.
//
// - SaveKey: the user's 32 random bytes, made once, carried to their other
//   devices as a recovery phrase (56 symbols of the pairing alphabet, a
//   24-bit check) or a QR code; its key id (HKDF-SHA-256, info
//   "lantern-save-e2e-1 key id") and wrapping key (info "… wrap"). It
//   never goes to a server (L-9.4-2): the app keeps it where its system
//   protects keys, as a device key, and shows the phrase only when asked.
// - A backup: an 88-byte header (`LTNE2E01`, the key id, the wrap's nonce,
//   the file key sealed by the wrapping key), then the archive in chunks of
//   65,536 bytes, each sealed by the file key with XChaCha20-Poly1305 (the
//   IETF construction: HChaCha20, then RFC 8439's ChaCha20-Poly1305, which
//   Monocypher's crypto_aead_lock is), its nonce 16 zero bytes, the chunk's
//   index on 7 bytes big-endian and 01 for the last chunk, 00 otherwise, the
//   header as additional data.
// - EncryptingSource gives the encrypted bytes of an archive the app reads
//   through an UploadSource, at any offset, one chunk in memory: the source
//   of a resumable upload (§ 9.3). From the header kept, the same bytes
//   come again, so an upload resumes without keeping the encrypted file.
// - DecryptingSink opens a backup as it downloads, one chunk in memory, and
//   hands each chunk on only once it opened; finish() says whether the
//   whole backup did (L-9.4-1). Until then, restore nothing.
//
// Every secret (save key, wrapping key, file key, the buffers that held
// them) is wiped when its holder goes.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/client.hpp>
#include <lantern/device_key.hpp>
#include <lantern/download.hpp>
#include <lantern/error.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>
#include <lantern/types.hpp>

namespace lantern
{

inline constexpr std::string_view save_scheme = "lantern-save-e2e-1";
inline constexpr std::size_t save_chunk_size  = 65536;
inline constexpr std::size_t save_header_size = 88;
inline constexpr std::size_t save_tag_size    = 16;

using SaveKeyBytes   = std::array<std::uint8_t, 32>;
using SaveHeader     = std::array<std::uint8_t, save_header_size>;
using FileKey        = std::array<std::uint8_t, 32>;
using WrapNonce      = std::array<std::uint8_t, 24>;
using KeyId          = std::array<std::uint8_t, 8>;
using KeyIdText      = std::array<char, 16>;
using RecoveryPhrase = std::array<char, 69>; // 14 groups of 4 symbols, 13 dashes
using KeyQrText      = std::array<char, 75>; // "LANTERN-SAVE-KEY-1:" and 56 symbols

class SaveKey
{
  public:
    // A new key, from the system's secure random source.
    [[nodiscard]] static Result<SaveKey> generate(RandomSource& random);
    // The key the app kept.
    [[nodiscard]] static SaveKey from_bytes(const SaveKeyBytes& bytes) noexcept;
    // A recovery phrase as the user typed it: case, spaces and dashes are
    // ignored. Refused (Category::refused) when its check does not match
    // (L-9.4-7), or when it is not 56 symbols of the pairing alphabet.
    [[nodiscard]] static Result<SaveKey> from_phrase(std::string_view phrase) noexcept;
    // A QR code's text, "LANTERN-SAVE-KEY-1:" and the 56 symbols.
    [[nodiscard]] static Result<SaveKey> from_qr(std::string_view text) noexcept;

    SaveKey(const SaveKey& other) noexcept;
    SaveKey& operator=(const SaveKey& other) noexcept;
    SaveKey(SaveKey&& other) noexcept;
    SaveKey& operator=(SaveKey&& other) noexcept;
    ~SaveKey();

    // The 32 bytes the app keeps (never sent anywhere).
    [[nodiscard]] const SaveKeyBytes& bytes() const noexcept { return key_; }
    [[nodiscard]] const KeyId& id() const noexcept { return id_; }
    // The key id as the protocol writes it, 16 lower-case hex digits.
    [[nodiscard]] KeyIdText id_text() const noexcept;
    [[nodiscard]] const SaveKeyBytes& wrapping_key() const noexcept { return wrap_; }
    // "96PA-S67D-…", to show only when the user asks (L-9.4-8).
    [[nodiscard]] RecoveryPhrase phrase() const noexcept;
    // The QR code's text, in its alphanumeric mode.
    [[nodiscard]] KeyQrText qr_text() const noexcept;

  private:
    SaveKey() = default;
    void derive() noexcept;
    void wipe() noexcept;

    SaveKeyBytes key_ {};
    SaveKeyBytes wrap_ {};
    KeyId id_ {};
};

// How many chunks an archive of `archive_size` bytes makes (1 at least),
// and the size of its encrypted backup: 88 + n + 16 × chunks.
[[nodiscard]] std::uint64_t save_chunk_count(std::uint64_t archive_size) noexcept;
[[nodiscard]] std::uint64_t encrypted_save_size(std::uint64_t archive_size) noexcept;

// A new backup's header: a new file key and wrap nonce from `random`, for
// each backup (L-9.4-3). The app keeps the header (it holds nothing in
// clear but the key id) to resume an upload.
[[nodiscard]] Result<SaveHeader> make_save_header(const SaveKey& key, RandomSource& random);
// The same with the file key and nonce given: the test vectors' way.
[[nodiscard]] SaveHeader make_save_header(
    const SaveKey& key, const FileKey& file_key, const WrapNonce& nonce) noexcept;

// The key id a backup needs, from its first 16 bytes at least; an error
// for bytes that do not begin as an encrypted backup does.
[[nodiscard]] Result<KeyIdText> save_key_id(std::span<const std::byte> backup) noexcept;

// A backup's file key, from its header: seals and opens its chunks.
class SaveCipher
{
  public:
    // Checks the header: `LTNE2E01`, the key's id (another key's backup is
    // Category::refused), and the file key, which must open.
    [[nodiscard]] static Result<SaveCipher> open(const SaveKey& key, const SaveHeader& header) noexcept;

    SaveCipher(const SaveCipher& other) noexcept;
    SaveCipher& operator=(const SaveCipher& other) noexcept;
    SaveCipher(SaveCipher&& other) noexcept;
    SaveCipher& operator=(SaveCipher&& other) noexcept;
    ~SaveCipher();

    [[nodiscard]] const SaveHeader& header() const noexcept { return header_; }
    // Chunk `index`: `plain` (65,536 bytes, the last one fewer) into
    // `sealed`, plain.size() + 16 bytes.
    [[nodiscard]] Result<void> seal(std::uint64_t index, bool last, std::span<const std::byte> plain,
        std::span<std::byte> sealed) const noexcept;
    // The reverse; Category::integrity when it does not open.
    [[nodiscard]] Result<void> unseal(std::uint64_t index, bool last, std::span<const std::byte> sealed,
        std::span<std::byte> plain) const noexcept;

  private:
    SaveCipher() = default;
    FileKey file_key_ {};
    SaveHeader header_ {};
};

// An archive's encrypted bytes, for an upload (Client::upload_resumable).
class EncryptingSource final : public UploadSource
{
  public:
    // `archive`: the archive in clear, `archive_size` bytes.
    [[nodiscard]] static Result<EncryptingSource> create(const SaveKey& key, const SaveHeader& header,
        UploadSource& archive, std::uint64_t archive_size, Allocator allocator = {});

    EncryptingSource(const EncryptingSource&)            = delete;
    EncryptingSource& operator=(const EncryptingSource&) = delete;
    EncryptingSource(EncryptingSource&& other) noexcept;
    EncryptingSource& operator=(EncryptingSource&&) = delete;
    ~EncryptingSource() override;

    // The encrypted backup's size.
    [[nodiscard]] std::uint64_t size() const noexcept { return encrypted_save_size(archive_size_); }
    // Its SHA-256: the whole archive read and encrypted once.
    [[nodiscard]] Result<Digest> digest();
    // An upload's document for it: size, sha256, and `encryption` (the
    // scheme and the key id, in clear, § 9.4).
    [[nodiscard]] Result<void> describe(UploadRequest& request);

    [[nodiscard]] Result<void> read(std::uint64_t offset, std::span<std::byte> out) override;

  private:
    EncryptingSource(
        SaveCipher cipher, UploadSource& archive, std::uint64_t archive_size, Allocator allocator);
    [[nodiscard]] Result<void> load(std::uint64_t index);

    SaveCipher cipher_;
    UploadSource* archive_;
    std::uint64_t archive_size_;
    Vector<std::byte> plain_;
    Vector<std::byte> sealed_;
    std::optional<std::uint64_t> loaded_;
};

// Opens a backup as its bytes come.
class DecryptingSink final : public DownloadSink
{
  public:
    // `out` gets the archive, a chunk at a time, each once it opened.
    DecryptingSink(SaveKey key, DownloadSink& out, Allocator allocator = {});
    DecryptingSink(const DecryptingSink&)            = delete;
    DecryptingSink& operator=(const DecryptingSink&) = delete;
    DecryptingSink(DecryptingSink&&)                 = delete;
    DecryptingSink& operator=(DecryptingSink&&)      = delete;
    ~DecryptingSink() override;

    [[nodiscard]] Result<void> write(std::span<const std::byte> bytes) override;
    [[nodiscard]] Result<void> restart() override;
    // The end of the backup: its last chunk opens, marked last, and nothing
    // follows it. Only then is what `out` holds the archive.
    [[nodiscard]] Result<void> finish();
    // The archive's bytes handed on so far.
    [[nodiscard]] std::uint64_t archive_bytes() const noexcept { return archive_bytes_; }

  private:
    [[nodiscard]] Result<void> open_chunk(bool last);
    [[nodiscard]] Result<void> failed(const Error& error);

    SaveKey key_;
    DownloadSink* out_;
    std::optional<SaveCipher> cipher_;
    SaveHeader header_ {};
    std::size_t header_size_ = 0;
    Vector<std::byte> sealed_;
    Vector<std::byte> plain_;
    std::uint64_t index_         = 0;
    std::uint64_t archive_bytes_ = 0;
    std::optional<Error> error_;
    bool finished_ = false;
};

// The primitives, for the test vectors (vectors/encrypted-saves.json):
// HChaCha20, and XChaCha20-Poly1305 as draft-irtf-cfrg-xchacha-03 builds it
// (`sealed` is the ciphertext, then the 16-byte tag).
[[nodiscard]] std::array<std::uint8_t, 32> hchacha20(
    const std::array<std::uint8_t, 32>& key, const std::array<std::uint8_t, 16>& nonce) noexcept;
[[nodiscard]] Result<void> xchacha20poly1305_seal(const std::array<std::uint8_t, 32>& key,
    const WrapNonce& nonce, std::span<const std::uint8_t> aad, std::span<const std::uint8_t> plain,
    std::span<std::uint8_t> sealed) noexcept;
[[nodiscard]] Result<void> xchacha20poly1305_open(const std::array<std::uint8_t, 32>& key,
    const WrapNonce& nonce, std::span<const std::uint8_t> aad, std::span<const std::uint8_t> sealed,
    std::span<std::uint8_t> plain) noexcept;

// A whole backup in memory, both ways: for small saves and the tests.
[[nodiscard]] Result<void> encrypt_save(
    const SaveKey& key, const SaveHeader& header, std::span<const std::byte> archive, Vector<std::byte>& out);
[[nodiscard]] Result<void> decrypt_save(
    const SaveKey& key, std::span<const std::byte> backup, DownloadSink& out, Allocator allocator = {});

} // namespace lantern
