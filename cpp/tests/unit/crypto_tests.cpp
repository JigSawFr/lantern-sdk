#include <doctest.h>

#include <array>
#include <string>
#include <vector>

#include "support.hpp"

using namespace lantern;
using lantern::test::spec_file;

namespace
{

std::string hex(const Digest& digest)
{
    const auto text = to_hex(digest);
    return { text.data(), text.size() };
}

template <std::size_t N> std::array<std::uint8_t, N> bytes_from_hex(std::string_view text)
{
    std::array<std::uint8_t, N> out {};
    for (std::size_t i = 0; i < N; ++i)
    {
        const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        out[i]            = static_cast<std::uint8_t>(nibble(text[2 * i]) * 16 + nibble(text[2 * i + 1]));
    }
    return out;
}

// A package entry signed by Ines, as the reference server serves it for
// spec/tests/library.py (Paper Lamp, its bytes made by library.nro()).
constexpr std::string_view paper_lamp = R"({"schema":1,"id":"org.example.paperlamp","platform":"switch",
    "name":"Paper Lamp","version":"0.9.2","build":902,"author":"Ines","kind":"game",
    "package":{"format":"nro","file":"/api/lantern/v1/files/f_t79P3U","size":16664,
    "sha256":"b89d5785039159b12b51f4a6ffc0b31977e7861593c09093583ce71bdae9d991",
    "path":"/switch/org.example.paperlamp/org.example.paperlamp.nro",
    "manifest_sha256":"d575c77f3cf22a11d4db1441478108d2cd76bc219a10dddbd775f045ae1f139e"},
    "signature":{"alg":"ed25519","public_key":"edUxrpjTXWII+TxG3hHJPh6yKbC0olH5G1CQarqi7vg=",
    "value":"Vx8lYqoXRvGEc375jMX2/heyu5sn5G81ojYSAn/ZWEr+IGo8JVtOEaELyOz0sU+vDOhFYdDIk09x3d3VNC3eDw=="}})";

Homebrew read_entry(std::string_view text)
{
    auto read = read_homebrew(text);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

} // namespace

TEST_CASE("sha256: FIPS 180-4's vectors")
{
    CHECK(hex(Sha256::of("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hex(Sha256::of("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(hex(Sha256::of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
        == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    Sha256 million;
    const std::string block(1000, 'a');
    for (int i = 0; i < 1000; ++i)
        million.update(block);
    CHECK(hex(million.finish()) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST_CASE("sha256: incremental, in any cut, and taken up from a saved state")
{
    std::string data;
    for (int i = 0; i < 1000; ++i)
        data += static_cast<char>(i * 7 + 3);
    const Digest whole = Sha256::of(data);
    for (const std::size_t step : { std::size_t { 1 }, std::size_t { 3 }, std::size_t { 63 },
             std::size_t { 64 }, std::size_t { 65 }, std::size_t { 1000 } })
    {
        Sha256 hash;
        for (std::size_t at = 0; at < data.size(); at += step)
            hash.update(std::string_view(data).substr(at, step));
        CHECK(hash.finish() == whole);
    }
    // A download cut at 333 bytes, its state kept, then resumed
    Sha256 first;
    first.update(std::string_view(data).substr(0, 333));
    const Sha256::State saved = first.state();
    Sha256 resumed(saved);
    CHECK(resumed.length() == 333);
    resumed.update(std::string_view(data).substr(333));
    CHECK(resumed.finish() == whole);
}

TEST_CASE("sha256: hex in the protocol's form")
{
    const Digest digest = Sha256::of("abc");
    CHECK(digest_from_hex(hex(digest)) == digest);
    CHECK_FALSE(digest_from_hex("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"));
    CHECK_FALSE(digest_from_hex("ba7816bf"));
    CHECK_FALSE(digest_from_hex(std::string(64, 'g')));
    CHECK(same_digest(digest, digest));
    Digest other = digest;
    other[31] ^= 1U;
    CHECK_FALSE(same_digest(digest, other));
}

TEST_CASE("base64: RFC 4648's vectors, canonical only")
{
    const auto encode = [](std::string_view text)
    {
        String out;
        base64_encode(std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()), out);
        return std::string(out);
    };
    CHECK(encode("") == "");
    CHECK(encode("f") == "Zg==");
    CHECK(encode("fo") == "Zm8=");
    CHECK(encode("foo") == "Zm9v");
    CHECK(encode("foobar") == "Zm9vYmFy");
    std::array<std::uint8_t, 3> out {};
    CHECK(base64_decode("Zm9v", out));
    CHECK(out == std::array<std::uint8_t, 3> { 'f', 'o', 'o' });
    std::array<std::uint8_t, 1> one {};
    CHECK(base64_decode("Zg==", one));
    CHECK_FALSE(base64_decode("Zh==", one)); // bits past the end
    CHECK_FALSE(base64_decode("Zg=", one)); // short padding
    CHECK_FALSE(base64_decode("Z===", one));
    CHECK_FALSE(base64_decode("Zg==Zg==", one));
    std::array<std::uint8_t, 2> two {};
    CHECK_FALSE(base64_decode("Zm=v", two));
    CHECK_FALSE(base64_decode("Zm9", two));
    CHECK_FALSE(base64_decode("Zm9v", two)); // not the size asked
    CHECK_FALSE(base64_decode("Zm-v", out));
}

TEST_CASE("digest fields: RFC 9530")
{
    const Digest digest = Sha256::of("abc");
    String field;
    format_digest_field(digest, field);
    CHECK(field == "sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:");

    const ParsedDigest parsed = parse_digest_field(field);
    CHECK(parsed.state == DigestField::sha256);
    CHECK(parsed.sha256 == digest);
    // Another algorithm first, parameters, spaces
    const ParsedDigest mixed = parse_digest_field(
        "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:, "
        "sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:;x=1");
    CHECK(mixed.state == DigestField::sha256);
    CHECK(mixed.sha256 == digest);
    CHECK(parse_digest_field("sha-512=:AAAA:").state == DigestField::absent);
    CHECK(parse_digest_field("").state == DigestField::absent);
    CHECK(parse_digest_field("sha-256=:AAAA:").state == DigestField::malformed);
    CHECK(parse_digest_field("sha-256=ungWv48").state == DigestField::malformed);
    CHECK(parse_digest_field("sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=").state
        == DigestField::malformed);
    CHECK(parse_digest_field("sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:,").state
        == DigestField::malformed);
}

TEST_CASE("ed25519: RFC 8032's vectors")
{
    const auto key1 = bytes_from_hex<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const auto sig1 = bytes_from_hex<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb"
                                         "8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    CHECK(ed25519_verify(sig1, key1, {}));
    const auto key2 = bytes_from_hex<32>("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    const auto sig2 = bytes_from_hex<64>("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085"
                                         "ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    const std::array<std::uint8_t, 1> message { 0x72 };
    CHECK(ed25519_verify(sig2, key2, message));
    CHECK_FALSE(ed25519_verify(sig2, key1, message));
    auto forged = sig2;
    forged[0] ^= 1U;
    CHECK_FALSE(ed25519_verify(forged, key2, message));
    const std::array<std::uint8_t, 1> other { 0x73 };
    CHECK_FALSE(ed25519_verify(sig2, key2, other));
}

TEST_CASE("ed25519: small-order keys and R, non-canonical encodings, S >= L are refused")
{
    // The 8 encodings of small-order points: as key and as R, S = 0, over
    // 16 messages, never a valid signature (cofactorless forgeries)
    const std::array<std::string_view, 8> small {
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    };
    int checked = 0;
    for (const std::string_view key_hex : small)
    {
        const auto key = bytes_from_hex<32>(key_hex);
        for (const std::string_view r_hex : small)
        {
            SignatureBytes signature {};
            const auto r = bytes_from_hex<32>(r_hex);
            std::copy(r.begin(), r.end(), signature.begin());
            for (std::uint8_t m = 0; m < 16; ++m)
            {
                const std::array<std::uint8_t, 2> message { m, static_cast<std::uint8_t>(m * 31U) };
                CHECK_FALSE(ed25519_verify(signature, key, message));
                ++checked;
            }
        }
    }
    CHECK(checked == 8 * 8 * 16);

    // A valid signature (RFC 8032's first vector), then broken three ways
    const auto key = bytes_from_hex<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const auto sig = bytes_from_hex<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8"
                                        "821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    REQUIRE(ed25519_verify(sig, key, {}));
    // S + L: the same S modulo L, not canonical
    const auto order = bytes_from_hex<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    auto malleable   = sig;
    unsigned carry   = 0;
    for (std::size_t i = 0; i < 32; ++i)
    {
        const unsigned sum = malleable[32 + i] + order[i] + carry;
        malleable[32 + i]  = static_cast<std::uint8_t>(sum);
        carry              = sum >> 8U;
    }
    CHECK_FALSE(ed25519_verify(malleable, key, {}));
    // A key or R whose y is p or more (p + 1: a non-canonical identity)
    const auto above_p
        = bytes_from_hex<32>("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    CHECK_FALSE(ed25519_verify(sig, above_p, {}));
    auto r_above_p = sig;
    std::copy(above_p.begin(), above_p.end(), r_above_p.begin());
    CHECK_FALSE(ed25519_verify(r_above_p, key, {}));
    // A key that is not a point
    auto not_a_point = key;
    not_a_point[0] ^= 0x01U;
    not_a_point[1] ^= 0x40U;
    CHECK_FALSE(ed25519_verify(sig, not_a_point, {}));
}

TEST_CASE("signature: the specification's example and the reference library's")
{
    // SPEC.md 8.4's bytes, for the example entry
    const Homebrew example = read_entry(spec_file("examples/v1/homebrew.json"));
    String message;
    signed_message(example.id, example.platform, example.build, example.package.sha256,
        example.package.manifest_sha256, message);
    CHECK(message
        == R"({"build":10400,"id":"org.example.frostline","manifest_sha256":"009dc459107edbdec10ad80d28f531e9080b74f3c27ffee59cc8c3d146ab5dc9","platform":"switch","purpose":"lantern-homebrew-1","sha256":"66be54ee71174fccdd55efddbbf0bf3a8cb467b774c5a6187c3676e02d1ac9a8"})");
    const auto verified = verify_package_signature(example, example.package);
    REQUIRE(verified);
    CHECK(verified->is_signed);

    // Paper Lamp, signed by Ines with the reference library's fictional key
    const Homebrew lamp = read_entry(paper_lamp);
    const auto lamp_ok  = verify_package_signature(lamp, lamp.package);
    REQUIRE(lamp_ok);
    CHECK(lamp_ok->is_signed);
    // And the manifest_sha256 of a single file is that of a manifest of one
    ManifestEntry single;
    single.path   = lamp.package.path;
    single.size   = lamp.package.size;
    single.sha256 = lamp.package.sha256;
    CHECK(manifest_digest(std::span(&single, 1)) == lamp.package.manifest_sha256);
}

TEST_CASE("signature: what does not verify is refused")
{
    // Another build than the one signed (the reference library's "forged")
    std::string text(paper_lamp);
    text.replace(text.find("\"build\":902"), 11, "\"build\":903");
    const Homebrew forged = read_entry(text);
    const auto refused    = verify_package_signature(forged, forged.package);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().category() == Category::signature);

    // Another algorithm, a key of the wrong size
    std::string other_alg(paper_lamp);
    other_alg.replace(other_alg.find("\"ed25519\""), 9, "\"ed448\"");
    CHECK_FALSE(verify_package_signature(read_entry(other_alg), read_entry(other_alg).package));
    std::string short_key(paper_lamp);
    short_key.replace(short_key.find("edUxrpjT"), 8, "");
    CHECK_FALSE(verify_package_signature(read_entry(short_key), read_entry(short_key).package));

    // Unsigned: not an error
    std::string unsigned_text(paper_lamp);
    unsigned_text.erase(unsigned_text.find(",\n    \"signature\""),
        unsigned_text.rfind('}') - unsigned_text.find(",\n    \"signature\""));
    const Homebrew plain = read_entry(unsigned_text);
    const auto none      = verify_package_signature(plain, plain.package);
    REQUIRE(none);
    CHECK_FALSE(none->is_signed);
}

TEST_CASE("signature: short fingerprints (SPEC.md 5.3, 8.4)")
{
    std::array<std::uint8_t, 32> key {};
    REQUIRE(base64_decode("M0Bukb4GJfaYOvOPYvyp2ADhHUWMv0tMim7BXcaN2k4=", key));
    const auto fingerprint = short_fingerprint(key);
    CHECK(std::string_view(fingerprint.data(), fingerprint.size()) == "BD9B 443F 1FE7 A9E4");
}

namespace
{

class MemoryPins final : public KeyPinStore
{
  public:
    std::vector<std::pair<std::string, PinnedKey>> pins;
    bool broken = false;

    Result<std::optional<PinnedKey>> load(std::string_view platform, std::string_view id) override
    {
        if (broken)
            return fail(Category::storage, "the SD card is gone");
        const std::string key = std::string(platform) + "/" + std::string(id);
        for (const auto& [name, pin] : pins)
        {
            if (name == key)
                return pin;
        }
        return std::optional<PinnedKey> {};
    }

    Result<void> store(std::string_view platform, std::string_view id, const PinnedKey& pin) override
    {
        const std::string key = std::string(platform) + "/" + std::string(id);
        for (auto& [name, existing] : pins)
        {
            if (name == key)
            {
                existing = pin;
                return {};
            }
        }
        pins.emplace_back(key, pin);
        return {};
    }
};

} // namespace

TEST_CASE("pinning: the library decides, the app stores")
{
    MemoryPins store;
    PackageSignature ines { true, {} };
    ines.public_key[0] = 1;
    PackageSignature lea { true, {} };
    lea.public_key[0] = 2;
    const PackageSignature none {};

    // First install: pinned
    auto check = check_pin(store, "switch", "org.example.paperlamp", ines);
    REQUIRE(check);
    CHECK(check->verdict == PinVerdict::first_install);
    CHECK_FALSE(check->needs_consent());
    REQUIRE(commit_pin(store, "switch", "org.example.paperlamp", *check, false));

    // The same key: nothing to ask
    check = check_pin(store, "switch", "org.example.paperlamp", ines);
    CHECK(check->verdict == PinVerdict::same);

    // Another key: refused unless the user accepts
    check = check_pin(store, "switch", "org.example.paperlamp", lea);
    CHECK(check->verdict == PinVerdict::key_changed);
    CHECK(check->needs_consent());
    REQUIRE(check->pinned);
    CHECK(check->pinned->public_key == ines.public_key);
    const auto refused = commit_pin(store, "switch", "org.example.paperlamp", *check, false);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().category() == Category::signature);
    CHECK(check_pin(store, "switch", "org.example.paperlamp", ines)->verdict == PinVerdict::same);
    REQUIRE(commit_pin(store, "switch", "org.example.paperlamp", *check, true));
    CHECK(check_pin(store, "switch", "org.example.paperlamp", lea)->verdict == PinVerdict::same);

    // Unsigned after signed: the same
    check = check_pin(store, "switch", "org.example.paperlamp", none);
    CHECK(check->verdict == PinVerdict::signature_removed);
    CHECK(check->needs_consent());

    // Unsigned first, then signed: pinned without asking
    REQUIRE(commit_pin(store, "switch", "org.example.frostline",
        *check_pin(store, "switch", "org.example.frostline", none), false));
    check = check_pin(store, "switch", "org.example.frostline", ines);
    CHECK(check->verdict == PinVerdict::newly_signed);
    CHECK_FALSE(check->needs_consent());

    // A pin per platform
    CHECK(check_pin(store, "3ds", "org.example.paperlamp", lea)->verdict == PinVerdict::first_install);

    // The store's own failure comes back as it is
    store.broken      = true;
    const auto broken = check_pin(store, "switch", "org.example.paperlamp", ines);
    REQUIRE_FALSE(broken);
    CHECK(broken.error().category() == Category::storage);
}
