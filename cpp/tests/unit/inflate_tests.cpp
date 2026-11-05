// gzip (RFC 1952) as a server compresses a JSON answer (SPEC.md § 2.1).
#include <doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <lantern/inflate.hpp>
#include <lantern/lantern.hpp>

#include "support.hpp"

using namespace lantern;
using namespace lantern::test;

namespace
{

// What the test vectors were made of, with Python's gzip (mtime 0).
std::string hello()
{
    return "hello hello hello";
}

std::string schema_only()
{
    return R"({"schema":1})";
}

std::string listing()
{
    std::string out = R"({"schema":1,"items":[)";
    for (int i = 0; i < 60; ++i)
    {
        if (i != 0)
            out += ',';
        out += R"({"id":")" + std::to_string(i) + R"(","name":"Game )" + std::to_string(i) + R"("})";
    }
    return out + "]}";
}

std::string unhex(std::string_view hex)
{
    const auto nibble = [](char c) { return static_cast<unsigned>(c <= '9' ? c - '0' : c - 'a' + 10); };
    std::string out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<char>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    return out;
}

// A stored block (level 0), as a body of one block; the first byte of the deflate stream says its type.
const std::string stored_member
    = unhex("1f8b08000000000004ff011100eeff68656c6c6f2068656c6c6f2068656c6c6f8088f9e511000000");
// A fixed-Huffman block.
const std::string fixed_member = unhex("1f8b08000000000002ffab562a4ece48cd4d54b232ac05008cc1fb890c000000");
// A dynamic-Huffman block, a listing at level 9.
const std::string dynamic_member
    = unhex("1f8b08000000000002ff65d43b6a03311446e1ad04d553f8befc980d641121854906ec62dc389d99bd670a837e8e2a09"
            "9d4a1fd27db5e7cf6d59af6db6a9ddff96f5d9e6af57bbffb6b91ddad41ed775d9b79ffbf27168dbf44e86643d3992f7"
            "1448d15322654f85543d1d918e3d9d904e3d9d91ce3d5d902e726572987a0c20226224313131a298a818594c5c8c3026"
            "32461a131b238e898e91c7c4c7086422e4147211720ab9be99e1d1889053c845c829e422e4147211720ab90839855c84"
            "9c422e424e2117a1a0508850502844282814faaf868f254241a110a1a05088505028442828142214140a110a0a850825"
            "8552849242294249a114a1a450eaec19868f08258552849242294249a114a1a4508a50522845a828542254142a112a0a"
            "950815854a848a42a5f37918d02254142a112a0a950815854a848a42fbc1f6bdfd030e9941a7ce060000");
// Two megabytes of zeros, at level 9.
const std::string bomb
    = unhex("1f8b08000000000002ffedc13101000000c2a0f54f6d0c1fa00000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000be067e87898d00"
            "002000");

std::span<const std::byte> bytes(const std::string& text)
{
    return { reinterpret_cast<const std::byte*>(text.data()), text.size() };
}

Result<std::string> unzip(const std::string& body, std::size_t limit = std::size_t { 1 } << 20)
{
    String out;
    if (auto done = gunzip(bytes(body), limit, out); !done)
        return std::unexpected(done.error());
    return std::string(out);
}

std::uint32_t crc32(std::string_view data)
{
    std::uint32_t crc = 0xffffffffU;
    for (const char c : data)
    {
        crc ^= static_cast<std::uint8_t>(c);
        for (int k = 0; k < 8; ++k)
            crc = (crc & 1U) != 0 ? 0xedb88320U ^ (crc >> 1) : crc >> 1;
    }
    return ~crc;
}

void le32(std::string& out, std::uint32_t value)
{
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<char>((value >> (8 * i)) & 0xffU));
}

// A body made of one stored block, as a test makes it without a compressor.
std::string gzip_stored(std::string_view data)
{
    std::string out = unhex("1f8b0800000000000003");
    out.push_back('\x01');
    out.push_back(static_cast<char>(data.size() & 0xffU));
    out.push_back(static_cast<char>((data.size() >> 8) & 0xffU));
    out.push_back(static_cast<char>(~data.size() & 0xffU));
    out.push_back(static_cast<char>((~data.size() >> 8) & 0xffU));
    out.append(data);
    le32(out, crc32(data));
    le32(out, static_cast<std::uint32_t>(data.size()));
    return out;
}

} // namespace

TEST_CASE("gzip: stored, fixed and dynamic blocks decode")
{
    const auto stored = unzip(stored_member);
    REQUIRE(stored);
    CHECK(*stored == hello());
    const auto fixed = unzip(fixed_member);
    REQUIRE(fixed);
    CHECK(*fixed == schema_only());
    const auto dynamic = unzip(dynamic_member);
    REQUIRE(dynamic);
    CHECK(*dynamic == listing());
    CHECK(dynamic_member.size() < listing().size());
}

TEST_CASE("gzip: members one after the other make one document")
{
    const auto both = unzip(stored_member + fixed_member + dynamic_member);
    REQUIRE(both);
    CHECK(*both == hello() + schema_only() + listing());
}

TEST_CASE("gzip: the output is bounded by the limit, not after it")
{
    const auto refused = unzip(bomb, 1000);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().category() == Category::limit);
    const std::size_t two_mib = std::size_t { 2 } * 1024 * 1024;
    CHECK(unzip(bomb, two_mib));
    const auto short_by_one = unzip(bomb, two_mib - 1);
    REQUIRE_FALSE(short_by_one);
    CHECK(short_by_one.error().category() == Category::limit);
    // The limit is for the whole body, not for each member
    REQUIRE_FALSE(unzip(stored_member + stored_member, hello().size() + 1));
}

TEST_CASE("gzip: a body that is not one, or is cut, or does not check, is refused")
{
    const auto refused = [](const std::string& body)
    {
        const auto read = unzip(body);
        return !read && read.error().category() == Category::invalid_response;
    };
    CHECK(refused(""));
    CHECK(refused("not gzip at all, but long enough to hold a header"));
    CHECK(refused(dynamic_member.substr(0, dynamic_member.size() - 5)));
    CHECK(refused(dynamic_member.substr(0, 40)));
    CHECK(refused(dynamic_member + "xyz"));
    std::string crc     = dynamic_member;
    crc[crc.size() - 6] = static_cast<char>(crc[crc.size() - 6] ^ 0x01);
    CHECK(refused(crc));
    std::string size      = dynamic_member;
    size[size.size() - 1] = static_cast<char>(size[size.size() - 1] ^ 0x01);
    CHECK(refused(size));
    std::string method = dynamic_member;
    method[2]          = 7;
    CHECK(refused(method));
    std::string flags = dynamic_member;
    flags[3]          = static_cast<char>(0xe0);
    CHECK(refused(flags));
    // A block type that does not exist
    std::string block = stored_member;
    block[10]         = static_cast<char>(block[10] | 0x06);
    CHECK(refused(block));
}

TEST_CASE("gzip: every cut of a body ends in an error, not in a crash")
{
    for (std::size_t n = 0; n < dynamic_member.size(); ++n)
        CHECK_FALSE(unzip(dynamic_member.substr(0, n)));
    for (std::size_t n = 0; n < dynamic_member.size(); n += 7)
    {
        std::string flipped = dynamic_member;
        flipped[n]          = static_cast<char>(flipped[n] ^ 0x55);
        (void)unzip(flipped);
    }
}

TEST_CASE("client: a document the server compressed is read as it was")
{
    FakeTransport transport;
    const std::string apps = spec_file("examples/v1/apps.json");
    REQUIRE_FALSE(apps.empty());
    transport.respond = [&](const Recorded& r)
    {
        Answer answer;
        const bool shake = r.url.ends_with("/.well-known/lantern");
        answer.body      = gzip_stored(shake ? spec_file("examples/v1/handshake.json") : apps);
        answer.headers.emplace_back("Content-Encoding", "gzip");
        return answer;
    };
    ClientConfig config;
    config.origin     = "https://shelf.example.org";
    config.user_agent = "LanternTests/0.3";
    auto client       = Client::create(transport, config);
    REQUIRE(client);
    REQUIRE(client->handshake());
    const auto page = client->apps();
    REQUIRE(page);
    REQUIRE(*page);
    CHECK_FALSE((*page)->items.empty());
    REQUIRE(transport.requests.size() == 2);
    for (const Recorded& request : transport.requests)
    {
        REQUIRE(request.header("Accept-Encoding") != nullptr);
        CHECK(*request.header("Accept-Encoding") == "gzip");
    }
}

TEST_CASE("client: a document that expands beyond the limit is refused, and a coding not asked for too")
{
    FakeTransport transport;
    std::string coding = "gzip";
    std::string body;
    transport.respond = [&](const Recorded& r)
    {
        Answer answer;
        answer.body
            = r.url.ends_with("/.well-known/lantern") ? spec_file("examples/v1/handshake.json") : body;
        if (!r.url.ends_with("/.well-known/lantern"))
            answer.headers.emplace_back("Content-Encoding", coding);
        return answer;
    };
    ClientConfig config;
    config.origin                     = "https://shelf.example.org";
    config.user_agent                 = "LanternTests/0.3";
    config.decode.limits.max_document = 4096;
    auto client                       = Client::create(transport, config);
    REQUIRE(client);
    REQUIRE(client->handshake());
    body            = bomb;
    const auto read = client->apps();
    REQUIRE_FALSE(read);
    CHECK(read.error().category() == Category::limit);
    coding           = "br";
    body             = "{}";
    const auto other = client->apps();
    REQUIRE_FALSE(other);
    CHECK(other.error().category() == Category::invalid_response);
}
