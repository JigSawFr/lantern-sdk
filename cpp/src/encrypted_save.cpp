// SPEC.md § 9.4: lantern-save-e2e-1.
#include <lantern/encrypted_save.hpp>

#include <algorithm>
#include <array>
#include <utility>

#include <lantern/hkdf.hpp>

extern "C"
{
#include "monocypher.h"
}

namespace lantern
{

namespace
{

constexpr std::string_view magic        = "LTNE2E01";
constexpr std::string_view info_key_id  = "lantern-save-e2e-1 key id";
constexpr std::string_view info_wrap    = "lantern-save-e2e-1 wrap";
constexpr std::string_view check_prefix = "lantern-save-key";
constexpr std::string_view qr_prefix    = "LANTERN-SAVE-KEY-1:";
// The pairing alphabet (§ 5.2): no 0, O, 1 or I
constexpr std::string_view alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
constexpr std::size_t symbols       = 56;
constexpr std::size_t sealed_chunk  = save_chunk_size + save_tag_size;
constexpr std::uint64_t max_chunks  = std::uint64_t { 1 } << 56U;
constexpr std::size_t wrapped_at    = 40;
constexpr std::size_t wrap_tag_at   = 72;
constexpr std::size_t wrap_nonce_at = 16;
constexpr std::size_t clear_header  = 16; // the wrap's additional data: magic and key id

std::span<const std::uint8_t> bytes_of(std::string_view text) noexcept
{
    return { reinterpret_cast<const std::uint8_t*>(text.data()), text.size() };
}

const std::uint8_t* raw(std::span<const std::byte> bytes) noexcept
{
    return reinterpret_cast<const std::uint8_t*>(bytes.data());
}

std::uint8_t* raw(std::span<std::byte> bytes) noexcept
{
    return reinterpret_cast<std::uint8_t*>(bytes.data());
}

// The 35 bytes a phrase writes: the key, then 3 bytes of check.
std::array<std::uint8_t, 35> phrase_bytes(const SaveKeyBytes& key) noexcept
{
    Sha256 hash;
    hash.update(check_prefix);
    hash.update(std::as_bytes(std::span(key)));
    Digest check = hash.finish();
    std::array<std::uint8_t, 35> out {};
    std::ranges::copy(key, out.begin());
    std::copy_n(check.begin(), 3, out.begin() + 32);
    secure_wipe(check);
    return out;
}

std::array<char, symbols> encode_symbols(const SaveKeyBytes& key) noexcept
{
    auto bytes = phrase_bytes(key);
    std::array<char, symbols> out {};
    for (std::size_t s = 0; s < symbols; ++s)
    {
        unsigned value = 0;
        for (std::size_t b = 0; b < 5; ++b)
        {
            const std::size_t bit = s * 5 + b;
            value = (value << 1U) | ((bytes[bit / 8] >> (7U - static_cast<unsigned>(bit % 8))) & 1U);
        }
        out[s] = alphabet[value];
    }
    secure_wipe(bytes);
    return out;
}

int symbol_value(char c) noexcept
{
    if (c >= 'a' && c <= 'z')
        c = static_cast<char>(c - 'a' + 'A');
    const std::size_t at = alphabet.find(c);
    return at == std::string_view::npos ? -1 : static_cast<int>(at);
}

// Chunk i's nonce: 16 zero bytes, i on 7 bytes big-endian, then 01 for the
// last chunk and 00 for the others.
WrapNonce chunk_nonce(std::uint64_t index, bool last) noexcept
{
    WrapNonce nonce {};
    for (std::size_t k = 0; k < 7; ++k)
        nonce[16 + k] = static_cast<std::uint8_t>(index >> (8U * (6U - static_cast<unsigned>(k))));
    nonce[23] = last ? 1U : 0U;
    return nonce;
}

} // namespace

// The key.

void SaveKey::derive() noexcept
{
    static_cast<void>(hkdf_sha256({}, key_, bytes_of(info_key_id), id_));
    static_cast<void>(hkdf_sha256({}, key_, bytes_of(info_wrap), wrap_));
}

void SaveKey::wipe() noexcept
{
    secure_wipe(key_);
    secure_wipe(wrap_);
    secure_wipe(id_);
}

Result<SaveKey> SaveKey::generate(RandomSource& random)
{
    SaveKey key;
    if (auto filled = random.fill(key.key_); !filled)
        return std::unexpected(filled.error());
    key.derive();
    return key;
}

SaveKey SaveKey::from_bytes(const SaveKeyBytes& bytes) noexcept
{
    SaveKey key;
    key.key_ = bytes;
    key.derive();
    return key;
}

Result<SaveKey> SaveKey::from_phrase(std::string_view phrase) noexcept
{
    std::array<std::uint8_t, symbols> values {};
    std::size_t count = 0;
    for (const char c : phrase)
    {
        if (c == ' ' || c == '-' || c == '\t')
            continue;
        const int value = symbol_value(c);
        if (value < 0)
            return fail(Category::refused, "a recovery phrase holds a symbol outside the pairing alphabet");
        if (count == symbols)
            return fail(Category::refused, "a recovery phrase is 56 symbols");
        values[count++] = static_cast<std::uint8_t>(value);
    }
    if (count != symbols)
        return fail(Category::refused, "a recovery phrase is 56 symbols");
    std::array<std::uint8_t, 35> bytes {};
    for (std::size_t s = 0; s < symbols; ++s)
    {
        for (std::size_t b = 0; b < 5; ++b)
        {
            const std::size_t bit = s * 5 + b;
            if (((values[s] >> (4U - static_cast<unsigned>(b))) & 1U) != 0)
                bytes[bit / 8] = static_cast<std::uint8_t>(bytes[bit / 8] | (0x80U >> (bit % 8)));
        }
    }
    SaveKey key;
    std::copy_n(bytes.begin(), 32, key.key_.begin());
    auto expected = phrase_bytes(key.key_);
    // L-9.4-7: a check that does not match is said before anything else
    const bool matches = std::equal(expected.begin() + 32, expected.end(), bytes.begin() + 32);
    secure_wipe(expected);
    secure_wipe(bytes);
    secure_wipe(values);
    if (!matches)
        return fail(Category::refused, "this recovery phrase's check does not match: a symbol is mistyped");
    key.derive();
    return key;
}

Result<SaveKey> SaveKey::from_qr(std::string_view text) noexcept
{
    if (!text.starts_with(qr_prefix) || text.size() != qr_prefix.size() + symbols)
        return fail(Category::refused, "not a save key's QR code (LANTERN-SAVE-KEY-1:)");
    return from_phrase(text.substr(qr_prefix.size()));
}

SaveKey::SaveKey(const SaveKey& other) noexcept
    : key_(other.key_)
    , wrap_(other.wrap_)
    , id_(other.id_)
{
}

SaveKey& SaveKey::operator=(const SaveKey& other) noexcept
{
    if (this != &other)
    {
        key_  = other.key_;
        wrap_ = other.wrap_;
        id_   = other.id_;
    }
    return *this;
}

SaveKey::SaveKey(SaveKey&& other) noexcept
    : key_(other.key_)
    , wrap_(other.wrap_)
    , id_(other.id_)
{
    other.wipe();
}

SaveKey& SaveKey::operator=(SaveKey&& other) noexcept
{
    if (this != &other)
    {
        key_  = other.key_;
        wrap_ = other.wrap_;
        id_   = other.id_;
        other.wipe();
    }
    return *this;
}

SaveKey::~SaveKey()
{
    wipe();
}

KeyIdText SaveKey::id_text() const noexcept
{
    static constexpr std::string_view hex = "0123456789abcdef";
    KeyIdText out {};
    for (std::size_t i = 0; i < id_.size(); ++i)
    {
        out[2 * i]     = hex[id_[i] >> 4U];
        out[2 * i + 1] = hex[id_[i] & 15U];
    }
    return out;
}

RecoveryPhrase SaveKey::phrase() const noexcept
{
    auto text = encode_symbols(key_);
    RecoveryPhrase out {};
    std::size_t at = 0;
    for (std::size_t s = 0; s < symbols; ++s)
    {
        if (s != 0 && s % 4 == 0)
            out[at++] = '-';
        out[at++] = text[s];
    }
    secure_wipe(std::as_writable_bytes(std::span(text)));
    return out;
}

KeyQrText SaveKey::qr_text() const noexcept
{
    auto text = encode_symbols(key_);
    KeyQrText out {};
    std::ranges::copy(qr_prefix, out.begin());
    std::ranges::copy(text, out.begin() + static_cast<std::ptrdiff_t>(qr_prefix.size()));
    secure_wipe(std::as_writable_bytes(std::span(text)));
    return out;
}

// Sizes and the header.

std::uint64_t save_chunk_count(std::uint64_t archive_size) noexcept
{
    return archive_size == 0 ? 1 : (archive_size + save_chunk_size - 1) / save_chunk_size;
}

std::uint64_t encrypted_save_size(std::uint64_t archive_size) noexcept
{
    return save_header_size + archive_size + save_tag_size * save_chunk_count(archive_size);
}

SaveHeader make_save_header(const SaveKey& key, const FileKey& file_key, const WrapNonce& nonce) noexcept
{
    SaveHeader header {};
    std::ranges::copy(magic, header.begin());
    std::ranges::copy(key.id(), header.begin() + 8);
    std::ranges::copy(nonce, header.begin() + wrap_nonce_at);
    crypto_aead_lock(header.data() + wrapped_at, header.data() + wrap_tag_at, key.wrapping_key().data(),
        nonce.data(), header.data(), clear_header, file_key.data(), file_key.size());
    return header;
}

Result<SaveHeader> make_save_header(const SaveKey& key, RandomSource& random)
{
    FileKey file_key {};
    WrapNonce nonce {};
    if (auto filled = random.fill(file_key); !filled)
        return std::unexpected(filled.error());
    if (auto filled = random.fill(nonce); !filled)
    {
        secure_wipe(file_key);
        return std::unexpected(filled.error());
    }
    const SaveHeader header = make_save_header(key, file_key, nonce);
    secure_wipe(file_key);
    return header;
}

Result<KeyIdText> save_key_id(std::span<const std::byte> backup) noexcept
{
    if (backup.size() < clear_header
        || !std::equal(magic.begin(), magic.end(), reinterpret_cast<const char*>(backup.data())))
        return fail(Category::unsupported, "not an encrypted backup (LTNE2E01, SPEC.md 9.4)");
    static constexpr std::string_view hex = "0123456789abcdef";
    KeyIdText out {};
    for (std::size_t i = 0; i < 8; ++i)
    {
        const auto byte = static_cast<std::uint8_t>(backup[8 + i]);
        out[2 * i]      = hex[byte >> 4U];
        out[2 * i + 1]  = hex[byte & 15U];
    }
    return out;
}

// The cipher.

Result<SaveCipher> SaveCipher::open(const SaveKey& key, const SaveHeader& header) noexcept
{
    if (!std::equal(magic.begin(), magic.end(), header.begin()))
        return fail(Category::unsupported, "not an encrypted backup (LTNE2E01, SPEC.md 9.4)");
    if (!std::equal(key.id().begin(), key.id().end(), header.begin() + 8))
        return fail(Category::refused, "a backup encrypted with another save key (SPEC.md 9.4)");
    SaveCipher cipher;
    cipher.header_ = header;
    if (crypto_aead_unlock(cipher.file_key_.data(), header.data() + wrap_tag_at, key.wrapping_key().data(),
            header.data() + wrap_nonce_at, header.data(), clear_header, header.data() + wrapped_at, 32)
        != 0)
        return fail(Category::integrity, "a backup's header does not open: it was changed (SPEC.md 9.4)");
    return cipher;
}

SaveCipher::SaveCipher(const SaveCipher& other) noexcept
    : file_key_(other.file_key_)
    , header_(other.header_)
{
}

SaveCipher& SaveCipher::operator=(const SaveCipher& other) noexcept
{
    file_key_ = other.file_key_;
    header_   = other.header_;
    return *this;
}

SaveCipher::SaveCipher(SaveCipher&& other) noexcept
    : file_key_(other.file_key_)
    , header_(other.header_)
{
    secure_wipe(other.file_key_);
}

SaveCipher& SaveCipher::operator=(SaveCipher&& other) noexcept
{
    if (this != &other)
    {
        file_key_ = other.file_key_;
        header_   = other.header_;
        secure_wipe(other.file_key_);
    }
    return *this;
}

SaveCipher::~SaveCipher()
{
    secure_wipe(file_key_);
}

Result<void> SaveCipher::seal(std::uint64_t index, bool last, std::span<const std::byte> plain,
    std::span<std::byte> sealed) const noexcept
{
    if (plain.size() > save_chunk_size || sealed.size() != plain.size() + save_tag_size
        || index >= max_chunks)
        return fail(Category::usage, "a chunk of 65,536 bytes at most, sealed into 16 bytes more");
    const WrapNonce nonce = chunk_nonce(index, last);
    crypto_aead_lock(raw(sealed), raw(sealed) + plain.size(), file_key_.data(), nonce.data(), header_.data(),
        header_.size(), raw(plain), plain.size());
    return {};
}

Result<void> SaveCipher::unseal(std::uint64_t index, bool last, std::span<const std::byte> sealed,
    std::span<std::byte> plain) const noexcept
{
    if (sealed.size() < save_tag_size || sealed.size() > sealed_chunk
        || plain.size() != sealed.size() - save_tag_size || index >= max_chunks)
        return fail(Category::integrity, "a chunk cut short or too long (SPEC.md 9.4)");
    const WrapNonce nonce = chunk_nonce(index, last);
    if (crypto_aead_unlock(raw(plain), raw(sealed) + plain.size(), file_key_.data(), nonce.data(),
            header_.data(), header_.size(), raw(sealed), plain.size())
        != 0)
    {
        secure_wipe(plain);
        return fail(
            Category::integrity, "a backup's chunk does not open: changed, moved, cut or not the last");
    }
    return {};
}

// Encrypting for an upload.

EncryptingSource::EncryptingSource(
    SaveCipher cipher, UploadSource& archive, std::uint64_t archive_size, Allocator allocator)
    : cipher_(std::move(cipher))
    , archive_(&archive)
    , archive_size_(archive_size)
    , plain_(allocator)
    , sealed_(allocator)
{
}

Result<EncryptingSource> EncryptingSource::create(const SaveKey& key, const SaveHeader& header,
    UploadSource& archive, std::uint64_t archive_size, Allocator allocator)
{
    auto cipher = SaveCipher::open(key, header);
    if (!cipher)
        return std::unexpected(cipher.error());
    if (save_chunk_count(archive_size) >= max_chunks)
        return fail(Category::limit, "an archive too large for 2^56 chunks");
    EncryptingSource source(std::move(*cipher), archive, archive_size, allocator);
    source.plain_.resize(save_chunk_size);
    source.sealed_.resize(sealed_chunk);
    return source;
}

EncryptingSource::EncryptingSource(EncryptingSource&& other) noexcept
    : cipher_(std::move(other.cipher_))
    , archive_(other.archive_)
    , archive_size_(other.archive_size_)
    , plain_(std::move(other.plain_))
    , sealed_(std::move(other.sealed_))
    , loaded_(other.loaded_)
{
    other.loaded_.reset();
}

EncryptingSource::~EncryptingSource()
{
    secure_wipe(std::span(plain_));
    secure_wipe(std::span(sealed_));
}

Result<void> EncryptingSource::load(std::uint64_t index)
{
    if (loaded_ == index)
        return {};
    loaded_.reset();
    const std::uint64_t chunks = save_chunk_count(archive_size_);
    const std::uint64_t from   = index * save_chunk_size;
    const auto length
        = static_cast<std::size_t>(std::min<std::uint64_t>(save_chunk_size, archive_size_ - from));
    const std::span<std::byte> plain(plain_.data(), length);
    if (length != 0)
    {
        if (auto read_ok = archive_->read(from, plain); !read_ok)
            return read_ok;
    }
    if (auto sealed
        = cipher_.seal(index, index + 1 == chunks, plain, std::span(sealed_.data(), length + save_tag_size));
        !sealed)
        return sealed;
    secure_wipe(plain);
    loaded_ = index;
    return {};
}

Result<void> EncryptingSource::read(std::uint64_t offset, std::span<std::byte> out)
{
    const std::uint64_t total = size();
    if (offset > total || out.size() > total - offset)
        return fail(Category::usage, "a read past the encrypted backup's end");
    std::size_t done = 0;
    while (done < out.size())
    {
        const std::uint64_t at = offset + done;
        if (at < save_header_size)
        {
            const auto take
                = static_cast<std::size_t>(std::min<std::uint64_t>(save_header_size - at, out.size() - done));
            std::copy_n(reinterpret_cast<const std::byte*>(cipher_.header().data()) + at, take,
                out.begin() + static_cast<std::ptrdiff_t>(done));
            done += take;
            continue;
        }
        const std::uint64_t in_chunks = at - save_header_size;
        const std::uint64_t index     = in_chunks / sealed_chunk;
        const auto within             = static_cast<std::size_t>(in_chunks % sealed_chunk);
        if (auto loaded = load(index); !loaded)
            return loaded;
        const std::uint64_t from = index * save_chunk_size;
        const std::size_t chunk_len
            = static_cast<std::size_t>(std::min<std::uint64_t>(save_chunk_size, archive_size_ - from))
            + save_tag_size;
        const std::size_t take = std::min(chunk_len - within, out.size() - done);
        std::copy_n(sealed_.begin() + static_cast<std::ptrdiff_t>(within), take,
            out.begin() + static_cast<std::ptrdiff_t>(done));
        done += take;
    }
    return {};
}

Result<Digest> EncryptingSource::digest()
{
    Sha256 hash;
    hash.update(std::as_bytes(std::span(cipher_.header())));
    const std::uint64_t chunks = save_chunk_count(archive_size_);
    for (std::uint64_t index = 0; index < chunks; ++index)
    {
        if (auto loaded = load(index); !loaded)
            return std::unexpected(loaded.error());
        const std::uint64_t from = index * save_chunk_size;
        const std::size_t length
            = static_cast<std::size_t>(std::min<std::uint64_t>(save_chunk_size, archive_size_ - from))
            + save_tag_size;
        hash.update(std::span<const std::byte>(sealed_.data(), length));
    }
    return hash.finish();
}

Result<void> EncryptingSource::describe(UploadRequest& request)
{
    const auto sha256 = digest();
    if (!sha256)
        return std::unexpected(sha256.error());
    request.size   = size();
    request.sha256 = *sha256;
    const auto id  = save_key_id(std::as_bytes(std::span(cipher_.header())));
    if (!id)
        return std::unexpected(id.error());
    SaveEncryption encryption(request.kind.get_allocator());
    encryption.scheme.assign(save_scheme);
    encryption.key_id.assign(id->data(), id->size());
    request.encryption.emplace(std::move(encryption));
    return {};
}

// Decrypting as it downloads.

DecryptingSink::DecryptingSink(const SaveKey& key, DownloadSink& out, Allocator allocator)
    : key_(key)
    , out_(&out)
    , sealed_(allocator)
    , plain_(allocator)
{
    sealed_.reserve(sealed_chunk);
    plain_.resize(save_chunk_size);
}

DecryptingSink::~DecryptingSink()
{
    secure_wipe(std::span(plain_));
    secure_wipe(header_);
}

Result<void> DecryptingSink::failed(const Error& error)
{
    error_ = error;
    secure_wipe(std::span(plain_));
    cipher_.reset();
    return std::unexpected(error);
}

Result<void> DecryptingSink::open_chunk(bool last)
{
    // L-9.4-1: an empty last chunk only for an empty archive, its only chunk
    if (last && index_ != 0 && sealed_.size() == save_tag_size)
        return failed(Error::make(Category::integrity, "an empty chunk after the last one (SPEC.md 9.4)"));
    const std::size_t length = sealed_.size() - std::min(sealed_.size(), save_tag_size);
    const std::span<std::byte> plain(plain_.data(), length);
    if (auto opened = cipher_->unseal(index_, last, sealed_, plain); !opened)
        return failed(opened.error());
    if (auto written = out_->write(plain); !written)
        return failed(written.error());
    secure_wipe(plain);
    archive_bytes_ += length;
    ++index_;
    sealed_.clear();
    return {};
}

Result<void> DecryptingSink::write(std::span<const std::byte> bytes)
{
    if (error_)
        return std::unexpected(*error_);
    if (finished_)
        return failed(Error::make(Category::integrity, "bytes after the backup's last chunk (SPEC.md 9.4)"));
    while (!bytes.empty())
    {
        if (header_size_ < save_header_size)
        {
            const std::size_t take = std::min(save_header_size - header_size_, bytes.size());
            std::copy_n(reinterpret_cast<const std::uint8_t*>(bytes.data()), take,
                header_.begin() + static_cast<std::ptrdiff_t>(header_size_));
            header_size_ += take;
            bytes = bytes.subspan(take);
            if (header_size_ == save_header_size)
            {
                auto cipher = SaveCipher::open(key_, header_);
                if (!cipher)
                    return failed(cipher.error());
                cipher_.emplace(std::move(*cipher));
            }
            continue;
        }
        // A full chunk followed by more bytes is not the last one
        if (sealed_.size() == sealed_chunk)
        {
            if (auto opened = open_chunk(false); !opened)
                return opened;
        }
        const std::size_t take = std::min(sealed_chunk - sealed_.size(), bytes.size());
        sealed_.insert(sealed_.end(), bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(take));
        bytes = bytes.subspan(take);
    }
    return {};
}

Result<void> DecryptingSink::restart()
{
    error_.reset();
    cipher_.reset();
    secure_wipe(header_);
    header_size_ = 0;
    sealed_.clear();
    index_         = 0;
    archive_bytes_ = 0;
    finished_      = false;
    return out_->restart();
}

Result<void> DecryptingSink::finish()
{
    if (error_)
        return std::unexpected(*error_);
    if (finished_)
        return {};
    if (header_size_ < save_header_size || !cipher_)
        return failed(Error::make(Category::integrity, "a backup cut inside its header (SPEC.md 9.4)"));
    if (sealed_.size() < save_tag_size)
        return failed(
            Error::make(Category::integrity, "a backup whose last chunk is missing or cut (SPEC.md 9.4)"));
    if (auto opened = open_chunk(true); !opened)
        return opened;
    finished_ = true;
    return {};
}

std::array<std::uint8_t, 32> hchacha20(
    const std::array<std::uint8_t, 32>& key, const std::array<std::uint8_t, 16>& nonce) noexcept
{
    std::array<std::uint8_t, 32> out {};
    crypto_chacha20_h(out.data(), key.data(), nonce.data());
    return out;
}

Result<void> xchacha20poly1305_seal(const std::array<std::uint8_t, 32>& key, const WrapNonce& nonce,
    std::span<const std::uint8_t> aad, std::span<const std::uint8_t> plain,
    std::span<std::uint8_t> sealed) noexcept
{
    if (sealed.size() != plain.size() + save_tag_size)
        return fail(Category::usage, "a sealed text is the plain text and 16 bytes");
    crypto_aead_lock(sealed.data(), sealed.data() + plain.size(), key.data(), nonce.data(), aad.data(),
        aad.size(), plain.data(), plain.size());
    return {};
}

Result<void> xchacha20poly1305_open(const std::array<std::uint8_t, 32>& key, const WrapNonce& nonce,
    std::span<const std::uint8_t> aad, std::span<const std::uint8_t> sealed,
    std::span<std::uint8_t> plain) noexcept
{
    if (sealed.size() < save_tag_size || plain.size() != sealed.size() - save_tag_size)
        return fail(Category::usage, "a plain text is the sealed text but its 16 bytes");
    if (crypto_aead_unlock(plain.data(), sealed.data() + plain.size(), key.data(), nonce.data(), aad.data(),
            aad.size(), sealed.data(), plain.size())
        != 0)
    {
        secure_wipe(plain);
        return fail(Category::integrity, "a sealed text that does not open");
    }
    return {};
}

Result<void> encrypt_save(
    const SaveKey& key, const SaveHeader& header, std::span<const std::byte> archive, Vector<std::byte>& out)
{
    auto cipher = SaveCipher::open(key, header);
    if (!cipher)
        return std::unexpected(cipher.error());
    const std::uint64_t chunks = save_chunk_count(archive.size());
    out.resize(static_cast<std::size_t>(encrypted_save_size(archive.size())));
    std::copy_n(reinterpret_cast<const std::byte*>(header.data()), header.size(), out.begin());
    std::size_t at = save_header_size;
    for (std::uint64_t index = 0; index < chunks; ++index)
    {
        const auto from          = static_cast<std::size_t>(index * save_chunk_size);
        const std::size_t length = std::min(save_chunk_size, archive.size() - from);
        if (auto sealed = cipher->seal(index, index + 1 == chunks, archive.subspan(from, length),
                std::span(out).subspan(at, length + save_tag_size));
            !sealed)
            return sealed;
        at += length + save_tag_size;
    }
    return {};
}

Result<void> decrypt_save(
    const SaveKey& key, std::span<const std::byte> backup, DownloadSink& out, Allocator allocator)
{
    DecryptingSink sink(key, out, allocator);
    if (auto written = sink.write(backup); !written)
        return written;
    return sink.finish();
}

} // namespace lantern
