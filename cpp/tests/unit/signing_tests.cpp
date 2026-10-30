// Signed requests (SPEC.md § 5.4) against spec/vectors/signatures.json, byte
// for byte; device keys; the server's key (§ 5.3) against
// spec/vectors/spki.json; HTTP dates and Accept-Signature.
#include <doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "support.hpp"

using namespace lantern;
using lantern::test::spec_file;

namespace
{

std::array<std::uint8_t, 32> seed_from_hex(std::string_view hex)
{
    const auto digest = digest_from_hex(hex);
    REQUIRE(digest);
    return *digest;
}

// A random source that gives the bytes it was told to, then fails.
class ScriptedRandom final : public RandomSource
{
  public:
    std::string bytes;
    Result<void> fill(std::span<std::uint8_t> out) override
    {
        if (bytes.size() < out.size())
            return fail(Category::storage, "no more scripted bytes");
        for (std::size_t i = 0; i < out.size(); ++i)
            out[i] = static_cast<std::uint8_t>(bytes[i]);
        bytes.erase(0, out.size());
        return {};
    }
};

class FixedClock final : public Clock
{
  public:
    std::int64_t now = 0;
    std::int64_t unix_seconds() override { return now; }
};

// The bytes a base64url nonce of 22 characters holds (16).
std::string nonce_bytes(std::string_view nonce)
{
    std::string text(nonce);
    for (char& c : text)
    {
        if (c == '-')
            c = '+';
        else if (c == '_')
            c = '/';
    }
    text += "==";
    std::array<std::uint8_t, 16> out {};
    REQUIRE(base64_decode(text, out));
    return { reinterpret_cast<const char*>(out.data()), out.size() };
}

std::string_view member(const json::Value& object, std::string_view key)
{
    const json::Value* value = object.find(key);
    return value != nullptr ? value->text() : std::string_view {};
}

class Collected final : public HeaderSink
{
  public:
    std::vector<std::pair<std::string, std::string>> headers;
    Result<void> add(std::string_view name, std::string_view value) override
    {
        headers.emplace_back(std::string(name), std::string(value));
        return {};
    }
    [[nodiscard]] std::string get(std::string_view name) const
    {
        for (const auto& [key, value] : headers)
        {
            if (key == name)
                return value;
        }
        return {};
    }
};

} // namespace

TEST_CASE("device keys: RFC 8032's test key, its keyid and fingerprint as the vectors give them")
{
    const std::string text = spec_file("vectors/signatures.json");
    REQUIRE_FALSE(text.empty());
    const auto document = json::parse(text);
    REQUIRE(document);
    const json::Value& key = *document->root().find("key");
    const DeviceKey device = DeviceKey::from_seed(seed_from_hex(member(key, "seed")));
    String public_key;
    base64_encode(device.public_key(), public_key);
    CHECK(public_key == member(key, "public_key"));
    const auto keyid = device.keyid();
    CHECK(std::string_view(keyid.data(), keyid.size()) == member(key, "keyid"));
    const auto fingerprint = device.fingerprint();
    CHECK(std::string_view(fingerprint.data(), fingerprint.size()) == member(key, "short_fingerprint"));
    // The seed it is kept by gives it back
    CHECK(DeviceKey::from_seed(device.seed()).public_key() == device.public_key());

    ScriptedRandom zeros;
    zeros.bytes.assign(32, '\0');
    CHECK_FALSE(DeviceKey::generate(zeros)); // a source of zeros is broken
    ScriptedRandom empty;
    CHECK_FALSE(DeviceKey::generate(empty));
}

TEST_CASE("signatures: every accepted request of the vectors, byte for byte")
{
    const std::string text = spec_file("vectors/signatures.json");
    const auto document    = json::parse(text);
    REQUIRE(document);
    const json::Value& root = document->root();
    const DeviceKey key     = DeviceKey::from_seed(seed_from_hex(member(*root.find("key"), "seed")));
    const auto created      = root.find("server_time")->to_i64();
    REQUIRE(created);

    const auto accepted = root.find("accepted")->items();
    REQUIRE(accepted.size() == 5);
    for (const json::Value& vector : accepted)
    {
        CAPTURE(member(vector, "name"));
        const json::Value& headers   = *vector.find("headers");
        const std::string_view input = member(headers, "Signature-Input");
        // The nonce, as the vector chose it
        const std::size_t at        = input.find("nonce=\"") + 7;
        const std::string_view once = input.substr(at, input.find('"', at) - at);

        const auto uri = target_uri(member(vector, "uri"));
        REQUIRE(uri);
        CHECK(*uri == member(vector, "uri"));
        SignedComponents components;
        components.method         = member(vector, "method");
        components.target_uri     = *uri;
        components.authorization  = member(headers, "Authorization");
        components.content_digest = member(headers, "Content-Digest");
        if (!member(vector, "body").empty())
        {
            String digest;
            format_digest_field(Sha256::of(member(vector, "body")), digest);
            CHECK(digest == components.content_digest);
        }
        String params;
        const auto keyid = key.keyid();
        signature_params(components, *created, once, std::string_view(keyid.data(), keyid.size()), params);
        String base;
        signature_base(components, params, base);
        CHECK(base == member(vector, "signature_base"));
        SignatureHeaders out;
        REQUIRE(sign_components(key, components, *created, once, out));
        CHECK(out.signature_input == input);
        CHECK(out.signature == member(headers, "Signature"));

        // And a server takes it, once
        SignatureCheck check;
        check.method                   = components.method;
        check.target_uri               = *uri;
        check.authorization            = components.authorization;
        check.content_digest           = components.content_digest;
        check.has_body                 = !member(vector, "body").empty();
        check.signature_input          = input;
        check.signature                = member(headers, "Signature");
        check.key                      = key.public_key();
        check.now                      = *created;
        check.body_sha256              = Sha256::of(member(vector, "body"));
        const SignatureVerdict verdict = check_signature(check);
        CHECK(verdict.code == Code::none);
        CHECK(verdict.nonce == once);
    }
}

TEST_CASE("signatures: the DeviceSigner signs the vector's GET with its nonce and clock")
{
    const std::string text = spec_file("vectors/signatures.json");
    const auto document    = json::parse(text);
    REQUIRE(document);
    const json::Value& root   = document->root();
    const DeviceKey key       = DeviceKey::from_seed(seed_from_hex(member(*root.find("key"), "seed")));
    const json::Value& first  = root.find("accepted")->items()[0];
    const json::Value& wanted = *first.find("headers");
    const json::Value& post   = root.find("accepted")->items()[1];
    const json::Value& poll   = root.find("accepted")->items()[4];

    ScriptedRandom random;
    // The two vectors whose nonce is 16 bytes, as the signer makes them,
    // then one for a poll
    random.bytes = nonce_bytes("tQ0Vb3Yt7sXx2c1mZ8kq4A") + nonce_bytes("Wm9nZ2xlLWZyb3N0bGluZQ")
        + std::string(16, 'p');
    FixedClock clock;
    clock.now = 1793345400 - 3600; // an hour behind: the offset makes it up
    DeviceSigner signer(key, random, clock);
    signer.set_clock_offset(3600);

    const std::array<Header, 2> headers { { { "User-Agent", "LanternTests/0.4" },
        { "Authorization", member(wanted, "Authorization") } } };
    SigningInput input;
    input.method  = "GET";
    input.target  = member(first, "uri");
    input.headers = headers;
    Collected out;
    REQUIRE(signer.sign(input, out));
    CHECK(out.get("Signature-Input") == member(wanted, "Signature-Input"));
    CHECK(out.get("Signature") == member(wanted, "Signature"));
    CHECK(out.get("Content-Digest").empty());

    // With a body: Content-Digest added, and covered
    SigningInput with_body;
    with_body.method         = "POST";
    with_body.target         = member(post, "uri");
    with_body.headers        = headers;
    with_body.content_digest = Sha256::of(member(post, "body"));
    Collected posted;
    REQUIRE(signer.sign(with_body, posted));
    CHECK(posted.get("Content-Digest") == member(*post.find("headers"), "Content-Digest"));
    CHECK(posted.get("Signature") == member(*post.find("headers"), "Signature"));

    // A poll of a keyed pairing: no Authorization, signed all the same, as
    // the poll's vector covers
    SigningInput polled;
    polled.method     = "GET";
    polled.target     = member(poll, "uri");
    polled.keyed_poll = true;
    Collected poll_out;
    REQUIRE(signer.sign(polled, poll_out));
    const std::string_view vector_input = member(*poll.find("headers"), "Signature-Input");
    CHECK(poll_out.get("Signature-Input").substr(0, 52) == vector_input.substr(0, 52));
    const std::string input_text     = poll_out.get("Signature-Input");
    const std::string signature_text = poll_out.get("Signature");
    SignatureCheck check;
    check.method          = "GET";
    check.target_uri      = member(poll, "uri");
    check.signature_input = input_text;
    check.signature       = signature_text;
    check.key             = key.public_key();
    check.now             = 1793345400;
    CHECK(check_signature(check).code == Code::none);

    // Without a token and not a poll: nothing is signed
    SigningInput anonymous;
    anonymous.method = "GET";
    anonymous.target = member(first, "uri");
    Collected none;
    REQUIRE(signer.sign(anonymous, none));
    CHECK(none.headers.empty());
    // The scripted bytes are spent: a signer without randomness fails
    CHECK_FALSE(signer.sign(input, out));
}

TEST_CASE("signatures: every refused request of the vectors, with its code, in 5.4's order")
{
    const std::string text = spec_file("vectors/signatures.json");
    const auto document    = json::parse(text);
    REQUIRE(document);
    const json::Value& root = document->root();
    const DeviceKey key     = DeviceKey::from_seed(seed_from_hex(member(*root.find("key"), "seed")));
    const auto now          = root.find("server_time")->to_i64();
    const auto skew         = root.find("skew")->to_u64();
    REQUIRE(now);
    REQUIRE(skew);

    // A server's nonces, per key, for the replay
    std::set<std::string> taken;
    const auto check_one = [&](const json::Value& request) -> Code
    {
        const json::Value& headers = *request.find("headers");
        const auto uri             = target_uri(member(request, "uri"));
        REQUIRE(uri);
        SignatureCheck check;
        check.method                   = member(request, "method");
        check.target_uri               = *uri;
        check.authorization            = member(headers, "Authorization");
        check.content_digest           = member(headers, "Content-Digest");
        check.has_body                 = !member(request, "body").empty();
        check.signature_input          = member(headers, "Signature-Input");
        check.signature                = member(headers, "Signature");
        check.key                      = key.public_key();
        check.now                      = *now;
        check.skew                     = static_cast<std::uint32_t>(*skew);
        const SignatureVerdict verdict = check_signature(check);
        if (verdict.code != Code::none)
            return verdict.code;
        const std::string seen = std::string(verdict.keyid) + "/" + std::string(verdict.nonce);
        return taken.insert(seen).second ? Code::none : Code::signature_replayed;
    };

    const auto accepted = root.find("accepted")->items();
    for (const json::Value& vector : root.find("refused")->items())
    {
        CAPTURE(member(vector, "name"));
        if (const json::Value* after = vector.find("after"))
        {
            for (const json::Value& name : after->items())
            {
                for (const json::Value& request : accepted)
                {
                    if (member(request, "name") == name.text())
                        CHECK(check_one(request) == Code::none);
                }
            }
        }
        CHECK(code_name(check_one(*vector.find("request"))) == member(vector, "code"));
    }
}

TEST_CASE("signatures: what a server refuses of the form")
{
    const DeviceKey key = DeviceKey::from_seed(
        seed_from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    SignedComponents components;
    components.method        = "GET";
    components.target_uri    = "https://shelf.example.org/api/lantern/v1/apps";
    components.authorization = "Bearer et_Zk81Qp-fictional";
    SignatureHeaders out;
    REQUIRE(sign_components(key, components, 1793345400, "AAAAAAAAAAAAAAAAAAAAAA", out));
    SignatureCheck check;
    check.method          = components.method;
    check.target_uri      = components.target_uri;
    check.authorization   = components.authorization;
    check.signature_input = out.signature_input;
    check.signature       = out.signature;
    check.key             = key.public_key();
    check.now             = 1793345400;
    CHECK(check_signature(check).code == Code::none);

    const auto with_input = [&](std::string input)
    {
        SignatureCheck changed  = check;
        changed.signature_input = input;
        return check_signature(changed).code;
    };
    const std::string good(out.signature_input);
    CHECK(with_input(good + ";x=1") == Code::signature_invalid);
    CHECK(with_input("other=" + good.substr(8)) == Code::signature_invalid);
    std::string other_alg = good;
    other_alg.replace(other_alg.find("ed25519"), 7, "rsa-v1_5-sha256");
    CHECK(with_input(other_alg) == Code::signature_invalid);
    std::string short_nonce = good;
    short_nonce.replace(short_nonce.find("AAAAAAAAAAAAAAAAAAAAAA"), 22, "AAAA");
    CHECK(with_input(short_nonce) == Code::signature_invalid);
    CHECK(with_input(std::string(1100, 'x')) == Code::signature_invalid);
    // A body announced but no Content-Digest covered
    SignatureCheck body = check;
    body.has_body       = true;
    CHECK(check_signature(body).code == Code::signature_invalid);
    // An hour off, either way
    SignatureCheck late = check;
    late.now += 301;
    CHECK(check_signature(late).code == Code::signature_expired);
    late.now = check.now - 300;
    CHECK(check_signature(late).code == Code::none);
    // A key of small order never verifies (L-8.4-4)
    SignatureCheck small = check;
    small.key            = {};
    small.key[0]         = 1;
    CHECK(check_signature(small).code == Code::signature_invalid);
    // A nonce the signer was given that is not base64url, or too short
    CHECK_FALSE(sign_components(key, components, 1793345400, "short", out));
    CHECK_FALSE(sign_components(key, components, 1793345400, "AAAAAAAAAAAAAAAAAAAAA+", out));
}

TEST_CASE("signatures: @target-uri as 5.4 says")
{
    CHECK(target_uri("https://Shelf.Example.ORG/api/lantern/v1/apps?q=Moss%20%26%20Ember").value()
        == "https://shelf.example.org/api/lantern/v1/apps?q=Moss%20%26%20Ember");
    CHECK(target_uri("https://shelf.example.org:443/x").value() == "https://shelf.example.org/x");
    CHECK(target_uri("https://shelf.example.org:8443/x").value() == "https://shelf.example.org:8443/x");
    CHECK(target_uri("http://127.0.0.1:80/x").value() == "http://127.0.0.1/x");
    CHECK(target_uri("http://[::1]:8080/x?a=b").value() == "http://[::1]:8080/x?a=b");
    CHECK(target_uri("https://shelf.example.org").value() == "https://shelf.example.org/");
    CHECK_FALSE(target_uri("ftp://shelf.example.org/x"));
}

TEST_CASE("signatures: Accept-Signature and HTTP dates")
{
    const auto wanted = parse_accept_signature(
        R"(other=("@method");alg="x", lantern=("@method" "@target-uri" "authorization");keyid="If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk";alg="ed25519")");
    REQUIRE(wanted);
    REQUIRE(wanted->covered().size() == 3);
    CHECK(wanted->covered()[2] == "authorization");
    CHECK(wanted->keyid == "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk");
    CHECK(wanted->alg == "ed25519");
    CHECK_FALSE(parse_accept_signature(R"(other=("@method"))"));
    CHECK_FALSE(parse_accept_signature(R"(lantern=("@method" "@target-uri")"));
    CHECK_FALSE(parse_accept_signature(R"(lantern=("A"))"));
    CHECK_FALSE(parse_accept_signature(std::string(2000, 'x')));

    CHECK(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT") == 784111777);
    CHECK(parse_http_date("Fri, 30 Oct 2026 16:00:00 GMT") == 1793376000);
    CHECK(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT") == 0);
    CHECK_FALSE(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"));
    CHECK_FALSE(parse_http_date("Sun Nov  6 08:49:37 1994"));
    CHECK_FALSE(parse_http_date("Sun, 06 Nov 1994 25:49:37 GMT"));
    CHECK_FALSE(parse_http_date("Sun, 06 Xyz 1994 08:49:37 GMT"));
}

TEST_CASE("the server's key: every certificate of vectors/spki.json, whole and short")
{
    const std::string text = spec_file("vectors/spki.json");
    REQUIRE_FALSE(text.empty());
    const auto document = json::parse(text);
    REQUIRE(document);
    const auto certificates = document->root().find("certificates")->items();
    REQUIRE(certificates.size() == 3);
    for (const json::Value& vector : certificates)
    {
        CAPTURE(member(vector, "name"));
        const auto digest = spki_sha256_pem(member(vector, "pem"));
        REQUIRE(digest);
        const auto hex = to_hex(*digest);
        CHECK(std::string_view(hex.data(), hex.size()) == member(vector, "spki_sha256"));
        const auto short_text = short_form(*digest);
        CHECK(std::string_view(short_text.data(), short_text.size()) == member(vector, "short"));

        // What a transport does with it, in each mode
        const auto der = pem_certificate(member(vector, "pem"));
        REQUIRE(der);
        const auto spki = certificate_spki(*der);
        REQUIRE(spki);
        ServerTrust trust;
        CHECK_FALSE(trust.accept(*spki, false)); // the CA store refused it
        CHECK(trust.accept(*spki, true));
        trust.allow_unverified();
        CHECK(trust.accept(*spki, false));
        REQUIRE(trust.seen());
        CHECK(same_digest(*trust.seen(), *digest));
        trust.pin(*digest);
        CHECK(trust.accept(*spki, false));
        Digest other = *digest;
        other[31] ^= 1U;
        trust.pin(other);
        CHECK_FALSE(trust.accept(*spki, true)); // pinned: the CA store does not decide
    }
    // Truncated or altered DER is refused, never read past its end
    const auto der = pem_certificate(member(certificates[0], "pem"));
    REQUIRE(der);
    for (std::size_t size = 0; size < der->size(); size += 7)
        CHECK_FALSE(certificate_spki(std::span(der->data(), size)));
    CHECK_FALSE(pem_certificate("no certificate here"));
    CHECK_FALSE(pem_certificate("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"));
}

TEST_CASE("pairing codes and invitations' links")
{
    CHECK(is_pairing_code("KQ4M-7TXD"));
    CHECK(is_pairing_code("KQ4M-7TXD-2345-6789-ABCD-EFGH-JKLM-NPQR"));
    CHECK_FALSE(is_pairing_code("KQ4M"));
    CHECK_FALSE(is_pairing_code("KQ4M-7TXO")); // O is not of the alphabet
    CHECK_FALSE(is_pairing_code("kq4m-7txd"));
    CHECK_FALSE(is_pairing_code("KQ4M-7TXD-"));
    CHECK_FALSE(is_pairing_code("KQ4M-7TXD-2345-6789-ABCD-EFGH-JKLM-NPQR-STUV"));
    CHECK(is_invitation_code("MZ7Q-4KHP-XW2N-8TRD"));
    CHECK_FALSE(is_invitation_code("MZ7Q-4KHP"));

    const auto link
        = parse_invitation_link("https://shelf.example.org/pair?invitation=MZ7Q-4KHP-XW2N-8TRD&spki="
                                "79315e024cf7f6e0f2553884fd098ac59df2e2a72f139d8e03b6ee62a2d13fd0");
    REQUIRE(link);
    CHECK(link->code == "MZ7Q-4KHP-XW2N-8TRD");
    REQUIRE(link->spki);
    const auto short_text = short_form(*link->spki);
    CHECK(std::string_view(short_text.data(), short_text.size()) == "7931 5E02 4CF7 F6E0");
    CHECK(parse_invitation_link("https://shelf.example.org/pair?invitation=MZ7Q-4KHP-XW2N-8TRD"));
    CHECK_FALSE(
        parse_invitation_link("https://shelf.example.org/pair?invitation=MZ7Q-4KHP-XW2N-8TRD&spki=3F9A"));
    CHECK_FALSE(parse_invitation_link("https://shelf.example.org/pair?code=KQ4M-7TXD"));
    CHECK_FALSE(parse_invitation_link("https://shelf.example.org/pair"));
}
