// Draft 0.5's test vectors (spec/vectors), byte for byte: encrypted saves
// and their primitives, recovery phrases, grants, sync's merge rule, and a
// static library's paths.
#include <doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "support.hpp"

using namespace lantern;
using lantern::test::spec_file;

namespace
{

std::vector<std::uint8_t> unhex(std::string_view text)
{
    std::vector<std::uint8_t> out;
    const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i + 1 < text.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(nibble(text[i]) * 16 + nibble(text[i + 1])));
    return out;
}

template <std::size_t N> std::array<std::uint8_t, N> fixed(std::string_view text)
{
    const auto bytes = unhex(text);
    REQUIRE(bytes.size() == N);
    std::array<std::uint8_t, N> out {};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

std::string hex(std::span<const std::uint8_t> bytes)
{
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (const std::uint8_t b : bytes)
    {
        out.push_back(digits[b >> 4U]);
        out.push_back(digits[b & 15U]);
    }
    return out;
}

std::string hex(std::span<const std::byte> bytes)
{
    return hex(std::span(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()));
}

json::Document vectors(std::string_view name)
{
    const std::string text = spec_file(std::string("vectors/") + std::string(name));
    REQUIRE(!text.empty());
    static std::deque<std::string> keep; // the DOM's views live as long as the text, which never moves
    keep.push_back(text);
    json::Limits limits;
    limits.max_depth = 32;
    auto parsed      = json::parse(keep.back(), limits);
    REQUIRE(parsed);
    return std::move(*parsed);
}

std::string_view text_of(const json::Value& value, std::string_view key)
{
    const json::Value* found = value.find(key);
    REQUIRE(found != nullptr);
    return found->text();
}

std::uint64_t number_of(const json::Value& value, std::string_view key)
{
    const json::Value* found = value.find(key);
    REQUIRE(found != nullptr);
    const auto number = found->to_u64();
    REQUIRE(number);
    return *number;
}

// An archive of the vectors: hex, or {"size": n} of bytes i % 251.
std::vector<std::byte> archive_of(const json::Value& backup)
{
    const json::Value* archive = backup.find("archive");
    REQUIRE(archive != nullptr);
    std::vector<std::byte> out;
    if (archive->is_string())
    {
        for (const std::uint8_t b : unhex(archive->text()))
            out.push_back(static_cast<std::byte>(b));
        return out;
    }
    const auto size = number_of(*archive, "size");
    for (std::uint64_t i = 0; i < size; ++i)
        out.push_back(static_cast<std::byte>(i % 251));
    return out;
}

class Collect final : public DownloadSink
{
  public:
    std::vector<std::byte> bytes;
    unsigned restarts = 0;
    Result<void> write(std::span<const std::byte> chunk) override
    {
        bytes.insert(bytes.end(), chunk.begin(), chunk.end());
        return {};
    }
    Result<void> restart() override
    {
        bytes.clear();
        ++restarts;
        return {};
    }
};

class MemorySource final : public UploadSource
{
  public:
    explicit MemorySource(std::span<const std::byte> bytes)
        : bytes_(bytes)
    {
    }
    unsigned reads = 0;
    Result<void> read(std::uint64_t offset, std::span<std::byte> out) override
    {
        ++reads;
        REQUIRE(offset + out.size() <= bytes_.size());
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset), out.size(), out.begin());
        return {};
    }

  private:
    std::span<const std::byte> bytes_;
};

std::vector<std::byte> encrypted_of(const json::Value& backup)
{
    const auto key    = SaveKey::from_bytes(fixed<32>(text_of(backup, "save_key")));
    const auto header = make_save_header(
        key, fixed<32>(text_of(backup, "file_key")), fixed<24>(text_of(backup, "wrap_nonce")));
    const auto plain = archive_of(backup);
    Vector<std::byte> out;
    REQUIRE(encrypt_save(key, header, plain, out));
    return { out.begin(), out.end() };
}

} // namespace

TEST_CASE("encrypted saves: HKDF-SHA-256, HChaCha20 and XChaCha20-Poly1305 as the vectors give them")
{
    const auto doc          = vectors("encrypted-saves.json");
    const json::Value& root = doc.root();
    CHECK(number_of(root, "chunk") == save_chunk_size);
    CHECK(number_of(root, "header") == save_header_size);
    const json::Value* primitives = root.find("primitives");
    REQUIRE(primitives != nullptr);
    for (const json::Value& v : primitives->find("hkdf_sha256")->items())
    {
        const auto ikm              = unhex(text_of(v, "ikm"));
        const auto salt             = unhex(text_of(v, "salt"));
        const std::string_view info = text_of(v, "info");
        std::vector<std::uint8_t> okm(static_cast<std::size_t>(number_of(v, "length")));
        REQUIRE(hkdf_sha256(
            salt, ikm, std::span(reinterpret_cast<const std::uint8_t*>(info.data()), info.size()), okm));
        CHECK(hex(okm) == text_of(v, "okm"));
    }
    for (const json::Value& v : primitives->find("hchacha20")->items())
        CHECK(hex(hchacha20(fixed<32>(text_of(v, "key")), fixed<16>(text_of(v, "nonce"))))
            == text_of(v, "subkey"));
    for (const json::Value& v : primitives->find("xchacha20poly1305")->items())
    {
        const auto key   = fixed<32>(text_of(v, "key"));
        const auto nonce = fixed<24>(text_of(v, "nonce"));
        const auto aad   = unhex(text_of(v, "aad"));
        const auto plain = unhex(text_of(v, "plaintext"));
        std::vector<std::uint8_t> sealed(plain.size() + 16);
        REQUIRE(xchacha20poly1305_seal(key, nonce, aad, plain, sealed));
        CHECK(hex(sealed) == text_of(v, "sealed"));
        std::vector<std::uint8_t> opened(plain.size());
        REQUIRE(xchacha20poly1305_open(key, nonce, aad, sealed, opened));
        CHECK(opened == plain);
        sealed.back() ^= 1U;
        CHECK_FALSE(xchacha20poly1305_open(key, nonce, aad, sealed, opened));
    }
    // RFC 5869's first case, for HMAC and HKDF beyond one block
    const auto ikm  = std::vector<std::uint8_t>(22, 0x0b);
    const auto salt = unhex("000102030405060708090a0b0c");
    const auto info = unhex("f0f1f2f3f4f5f6f7f8f9");
    std::vector<std::uint8_t> okm(42);
    REQUIRE(hkdf_sha256(salt, ikm, info, okm));
    CHECK(hex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

TEST_CASE("encrypted saves: keys, their id, wrapping key, recovery phrase and QR text")
{
    const auto doc = vectors("encrypted-saves.json");
    for (const json::Value& v : doc.root().find("keys")->items())
    {
        const auto key = SaveKey::from_bytes(fixed<32>(text_of(v, "save_key")));
        const auto id  = key.id_text();
        CHECK(std::string_view(id.data(), id.size()) == text_of(v, "key_id"));
        CHECK(hex(key.wrapping_key()) == text_of(v, "wrapping_key"));
        const auto phrase = key.phrase();
        CHECK(std::string_view(phrase.data(), phrase.size()) == text_of(v, "phrase"));
        const auto qr = key.qr_text();
        CHECK(std::string_view(qr.data(), qr.size()) == text_of(v, "qr"));
        const auto back = SaveKey::from_phrase(text_of(v, "phrase"));
        REQUIRE(back);
        CHECK(back->bytes() == key.bytes());
        const auto scanned = SaveKey::from_qr(text_of(v, "qr"));
        REQUIRE(scanned);
        CHECK(scanned->bytes() == key.bytes());
    }
    for (const json::Value& v : doc.root().find("phrases")->items())
    {
        CAPTURE(text_of(v, "name"));
        const auto read = SaveKey::from_phrase(text_of(v, "phrase"));
        CHECK(read.has_value() == v.find("accepted")->boolean());
        if (!read)
            CHECK(read.error().category() == Category::refused);
    }
    CHECK_FALSE(
        SaveKey::from_qr("LANTERN-SAVE-KEY-2:96PAS67DK3MJ9ERCWDCAQG3KLNU373DAMC37H8ALVNK798595ASNRQCN"));
}

TEST_CASE("encrypted saves: each backup, byte for byte, and back")
{
    const auto doc = vectors("encrypted-saves.json");
    for (const json::Value& v : doc.root().find("backups")->items())
    {
        CAPTURE(text_of(v, "name"));
        const auto key = SaveKey::from_bytes(fixed<32>(text_of(v, "save_key")));
        const auto header
            = make_save_header(key, fixed<32>(text_of(v, "file_key")), fixed<24>(text_of(v, "wrap_nonce")));
        CHECK(hex(header) == text_of(v, "header"));
        const auto plain  = archive_of(v);
        const auto backup = encrypted_of(v);
        CHECK(backup.size() == number_of(v, "size"));
        CHECK(encrypted_save_size(plain.size()) == number_of(v, "size"));
        const auto digest = to_hex(Sha256::of(backup));
        CHECK(std::string_view(digest.data(), digest.size()) == text_of(v, "sha256"));
        if (const json::Value* whole = v.find("encrypted"))
            CHECK(hex(backup) == whole->text());
        // Each chunk's tag, where the layout puts it
        std::size_t at    = save_header_size;
        std::size_t index = 0;
        for (const json::Value& tag : v.find("chunk_tags")->items())
        {
            const std::size_t length = std::min(save_chunk_size, plain.size() - index * save_chunk_size);
            at += length;
            CHECK(hex(std::span(backup).subspan(at, 16)) == tag.text());
            at += 16;
            ++index;
        }
        CHECK(at == backup.size());

        // Opened whole, and fed a few bytes at a time
        Collect whole;
        REQUIRE(decrypt_save(key, backup, whole));
        CHECK(whole.bytes == plain);
        Collect pieces;
        DecryptingSink sink(key, pieces);
        for (std::size_t i = 0; i < backup.size(); i += 4093)
            REQUIRE(sink.write(std::span(backup).subspan(i, std::min<std::size_t>(4093, backup.size() - i))));
        REQUIRE(sink.finish());
        CHECK(pieces.bytes == plain);
        CHECK(sink.archive_bytes() == plain.size());

        // The upload's source gives the same bytes, at any offset, and their digest
        MemorySource source(plain);
        auto encrypting = EncryptingSource::create(key, header, source, plain.size());
        REQUIRE(encrypting);
        CHECK(encrypting->size() == backup.size());
        const auto sha = encrypting->digest();
        REQUIRE(sha);
        CHECK(to_hex(*sha) == digest);
        for (const std::size_t step : { std::size_t { 1000 }, std::size_t { 65552 }, std::size_t { 7 } })
        {
            std::vector<std::byte> read(backup.size());
            for (std::size_t i = 0; i < read.size(); i += step)
                REQUIRE(encrypting->read(i, std::span(read).subspan(i, std::min(step, read.size() - i))));
            CHECK(read == backup);
        }
        UploadRequest request;
        REQUIRE(encrypting->describe(request));
        CHECK(request.size == backup.size());
        REQUIRE(request.encryption);
        CHECK(request.encryption->scheme == "lantern-save-e2e-1");
        CHECK(request.encryption->key_id == "15d65cfba86a1bce");
        const auto id = save_key_id(backup);
        REQUIRE(id);
        CHECK(std::string_view(id->data(), id->size()) == "15d65cfba86a1bce");
    }
}

TEST_CASE("encrypted saves: every backup the vectors refuse is refused, and restores nothing")
{
    const auto doc          = vectors("encrypted-saves.json");
    const json::Value& root = doc.root();
    const auto backup_named = [&](std::string_view name) -> const json::Value&
    {
        for (const json::Value& v : root.find("backups")->items())
        {
            if (text_of(v, "name") == name)
                return v;
        }
        FAIL("no backup " << name);
        return root;
    };
    const auto second = SaveKey::from_bytes(fixed<32>(text_of(root.find("keys")->items()[1], "save_key")));
    for (const json::Value& v : root.find("refused")->items())
    {
        const std::string_view name      = text_of(v, "name");
        const std::string_view operation = text_of(v, "operation");
        CAPTURE(name);
        std::vector<std::byte> bytes;
        const json::Value* from = v.find("backup");
        if (from != nullptr && from->is_string())
            bytes = encrypted_of(backup_named(from->text()));
        auto key = SaveKey::from_bytes(fixed<32>(text_of(v, "save_key")));
        if (operation.starts_with("flip bit 0 of byte "))
        {
            const auto at = std::stoul(std::string(operation.substr(19)));
            bytes[at] ^= std::byte { 1 };
        }
        else if (operation == "flip bit 0 of the last byte")
            bytes.back() ^= std::byte { 1 };
        else if (operation == "read with the second key")
            key = second;
        else if (operation == "drop the last byte")
            bytes.pop_back();
        else if (operation == "keep the first 88 + 65552 bytes")
            bytes.resize(88 + 65552);
        else if (operation == "append 16 zero bytes")
            bytes.insert(bytes.end(), 16, std::byte { 0 });
        else if (operation == "swap the two chunks")
        {
            std::vector<std::byte> swapped(bytes.begin(), bytes.begin() + 88);
            swapped.insert(swapped.end(), bytes.begin() + 88 + 65552, bytes.end());
            swapped.insert(swapped.end(), bytes.begin() + 88, bytes.begin() + 88 + 65552);
            bytes = std::move(swapped);
        }
        else if (operation == "a zip in clear")
            bytes = archive_of(backup_named("An empty zip: one chunk"));
        else
            FAIL("an operation this test does not know: " << operation);
        const auto digest = to_hex(Sha256::of(bytes));
        CHECK(std::string_view(digest.data(), digest.size()) == text_of(v, "sha256"));
        Collect out;
        DecryptingSink sink(key, out);
        const auto written = sink.write(bytes);
        const auto done    = written ? sink.finish() : written;
        CHECK_FALSE(done);
        CHECK(v.find("opens")->boolean() == false);
        // What reached the sink before the failure is not a restore: the
        // app keeps nothing of it, and the last chunk never reached it
        CHECK(out.bytes.size() < 65536 + 1);
    }
}

TEST_CASE("encrypted saves: a new header for each backup, from the random source")
{
    class Counting final : public RandomSource
    {
      public:
        std::uint8_t next = 7;
        Result<void> fill(std::span<std::uint8_t> out) override
        {
            for (auto& b : out)
                b = next++;
            return {};
        }
    } random;
    const auto key = SaveKey::generate(random);
    REQUIRE(key);
    const auto first  = make_save_header(*key, random);
    const auto second = make_save_header(*key, random);
    REQUIRE(first);
    REQUIRE(second);
    CHECK(*first != *second);
    CHECK(SaveCipher::open(*key, *first));
    // A key moved from is wiped
    SaveKey moved = *key;
    const SaveKey taken(std::move(moved));
    CHECK(taken.bytes() == key->bytes());
    CHECK(moved.bytes() == SaveKeyBytes {});
}

TEST_CASE("grants: what a peer decides of each (vectors/grants.json)")
{
    const auto doc          = vectors("grants.json");
    const json::Value& root = doc.root();
    PublicKey key {};
    REQUIRE(base64_decode(text_of(*root.find("key"), "public_key"), key));
    for (const json::Value& v : root.find("cases")->items())
    {
        CAPTURE(text_of(v, "name"));
        const auto sha = digest_from_hex(text_of(v, "path_sha256"));
        REQUIRE(sha);
        std::vector<std::string> uids;
        std::vector<GrantKey> servers;
        for (const json::Member& m : v.find("servers")->members())
        {
            GrantKey server;
            server.uid = m.key;
            REQUIRE(base64_decode(m.value.text(), server.key));
            servers.push_back(server);
        }
        const auto verdict = verify_grant(
            text_of(v, "grant"), *sha, static_cast<std::int64_t>(number_of(v, "peer_time")), servers);
        CHECK(verdict.has_value() == v.find("serves")->boolean());
        if (verdict)
        {
            CHECK(verdict->size == 734003200);
            CHECK(verdict->exp == 1793346000);
            CHECK(verdict->uid_view() == "6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14");
        }
        else
            CHECK(verdict.error().category() == Category::refused);
    }
    // The payload is the vectors' bytes, and a grant beyond 1 KiB is none
    CHECK(text_of(root, "grant").starts_with("eyJleHAiOjE3OTMzNDYwMDAs"));
    const std::string long_grant(1100, 'A');
    CHECK_FALSE(verify_grant(long_grant, Digest {}, 0, {}));
    // A payload cut after its exp (found by fuzz_grant): refused, not read past
    String cut;
    const std::string_view head = R"({"exp":1793346000)";
    base64url_encode(std::span(reinterpret_cast<const std::uint8_t*>(head.data()), head.size()), cut);
    const std::string truncated = std::string(cut) + "." + std::string(86, 'A');
    CHECK_FALSE(verify_grant(truncated, Digest {}, 0, {}));
}

TEST_CASE("sync: the merge rule of every vector (vectors/sync-merge.json)")
{
    const auto doc          = vectors("sync-merge.json");
    const json::Value& root = doc.root();
    const auto now          = parse_sync_time(text_of(root, "server_time"));
    REQUIRE(now);
    const auto skew = static_cast<std::int64_t>(number_of(root, "skew"));
    const auto item = [](const json::Value& v)
    {
        SyncItem out;
        out.key = "switch/0100ABCD00010000";
        out.updated.assign(text_of(v, "updated"));
        if (const json::Value* value = v.find("value"))
        {
            String raw;
            json::Writer writer(raw);
            writer.value(*value);
            out.value = raw;
        }
        if (v.find("deleted") != nullptr)
            out.deleted = true;
        return out;
    };
    for (const json::Value& v : root.find("cases")->items())
    {
        CAPTURE(text_of(v, "name"));
        std::optional<SyncItem> have;
        if (const json::Value* kept = v.find("have"); kept != nullptr && kept->is_object())
            have = item(*kept);
        const SyncItem sent = item(*v.find("sent"));
        const auto merge    = sync_merge(have ? &*have : nullptr, sent, *now, skew);
        REQUIRE(merge);
        CHECK(merge->replaced == v.find("replaced")->boolean());
        const json::Value& kept = *v.find("kept");
        const SyncItem& winner  = merge->replaced ? sent : *have;
        String updated;
        format_sync_time(merge->replaced ? merge->updated : *parse_sync_time(winner.updated), updated);
        CHECK(updated == text_of(kept, "updated"));
        if (const json::Value* canonical = v.find("canonical"))
        {
            const auto ours   = canonical_json(have->value);
            const auto theirs = canonical_json(sent.value);
            REQUIRE(ours);
            REQUIRE(theirs);
            CHECK(*ours == text_of(*canonical, "have"));
            CHECK(*theirs == text_of(*canonical, "sent"));
        }
    }
}

TEST_CASE("sync: times to the millisecond, and canonical JSON")
{
    CHECK(parse_sync_time("1970-01-01T00:00:00Z") == 0);
    CHECK(parse_sync_time("2026-10-30T09:12:03.250Z") == parse_sync_time("2026-10-30T09:12:03.25Z"));
    CHECK(parse_sync_time("2024-02-29T00:00:00.5Z") == std::int64_t { 1709164800500 });
    CHECK_FALSE(parse_sync_time("2023-02-29T00:00:00Z"));
    CHECK_FALSE(parse_sync_time("2026-10-30T09:12:03.2500Z"));
    CHECK_FALSE(parse_sync_time("2026-10-30T09:12:03+01:00"));
    CHECK_FALSE(parse_sync_time("2026-10-30 09:12:03Z"));
    String text;
    format_sync_time(std::int64_t { 1709164800500 }, text);
    CHECK(text == "2024-02-29T00:00:00.500Z");
    const auto canonical = canonical_json(R"({"b":[1,{"z":true,"a":null}],"a":"Léa\n"})");
    REQUIRE(canonical);
    CHECK(*canonical == R"({"a":"Léa\n","b":[1,{"a":null,"z":true}]})");
    CHECK_FALSE(canonical_json(R"({"a":1,"a":2})"));
    String key;
    CHECK(wish_key("switch", "0100ABCD00010000"));
    CHECK_FALSE(wish_key("switch", "a/b"));
    Wish wish;
    wish.platform = "switch";
    wish.title_id = "0100ABCD00010000";
    wish.note     = "For Noor";
    String value;
    write_wish(wish, value);
    CHECK(value == R"({"platform":"switch","title_id":"0100ABCD00010000","note":"For Noor"})");
    const auto back = read_wish(value);
    REQUIRE(back);
    CHECK(back->note == "For Noor");
    CHECK_FALSE(read_wish(R"({"platform":"switch"})"));
}

TEST_CASE("static libraries: the paths a document may give (vectors/static-layout.json)")
{
    const auto doc = vectors("static-layout.json");
    for (const json::Value& v : doc.root().find("paths")->items())
    {
        CAPTURE(text_of(v, "path"));
        CHECK(is_static_path(text_of(v, "path")) == v.find("accepted")->boolean());
    }
    for (const json::Value& v : doc.root().find("routes")->items())
        CHECK(is_static_path(text_of(v, "file")));
    CHECK_FALSE(is_static_path(""));
    CHECK_FALSE(is_static_path(".."));
    CHECK_FALSE(is_static_path("v1/a\nb"));
    CHECK(is_static_path("v1/titles/switch/0100ABCD00010000.json"));
}
