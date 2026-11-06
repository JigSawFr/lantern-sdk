// gzip as a server writes it (SPEC.md § 2.1), read back by gunzip(), and the
// Accept-Encoding that lets it be sent.
#include <doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <lantern/deflate.hpp>
#include <lantern/inflate.hpp>

using namespace lantern;

namespace
{

constexpr std::size_t no_limit = std::size_t { 64 } << 20U;

std::span<const std::byte> view(std::string_view text)
{
    return std::as_bytes(std::span(text.data(), text.size()));
}

std::string packed(std::string_view data)
{
    String out;
    gzip(view(data), out);
    return std::string(out);
}

// Whether `data` comes back from gzip() and gunzip(); its packed size in `size`.
bool round_trips(std::string_view data, std::size_t* size = nullptr)
{
    const std::string zipped = packed(data);
    if (size != nullptr)
        *size = zipped.size();
    String back;
    const auto done = gunzip(view(zipped), no_limit, back);
    return done.has_value() && std::string_view(back) == data;
}

// Bytes that do not repeat, from a small generator.
std::string noise(std::size_t length, std::uint32_t seed)
{
    std::string out;
    std::uint32_t state = seed;
    for (std::size_t i = 0; i < length; ++i)
    {
        state = (state * 1664525U) + 1013904223U;
        out.push_back(static_cast<char>((state >> 24U) & 0xffU));
    }
    return out;
}

std::string json_listing(int items)
{
    std::string out = R"({"schema":1,"items":[)";
    for (int i = 0; i < items; ++i)
    {
        if (i != 0)
            out += ',';
        out += R"({"title_id":"0100AA)" + std::to_string(1000 + i) + R"(","name":"Game )" + std::to_string(i)
            + R"(","platform":"switch","size":)" + std::to_string(i * 7919) + "}";
    }
    return out + "]}";
}

} // namespace

TEST_CASE("gzip: the header, the trailer and the empty input")
{
    const std::string empty = packed("");
    REQUIRE(empty.size() == 10 + 2 + 8);
    CHECK(empty.substr(0, 4) == std::string("\x1f\x8b\x08\x00", 4));
    CHECK(empty.substr(4, 4) == std::string(4, '\0')); // no time: the same bytes every time
    CHECK(packed("hello") == packed("hello"));
    CHECK(round_trips(""));
}

TEST_CASE("gzip: the CRC-32 of the standard check value")
{
    CHECK(gzip_crc32(view("123456789")) == 0xcbf43926U);
    CHECK(gzip_crc32(view("")) == 0U);
}

TEST_CASE("gzip: short, repetitive, varied and long inputs read back")
{
    CHECK(round_trips("a"));
    CHECK(round_trips("ab"));
    CHECK(round_trips("abc"));
    CHECK(round_trips("hello hello hello hello"));
    CHECK(round_trips(std::string(1000, 'x')));
    CHECK(round_trips(std::string(100'000, '\0')));
    CHECK(round_trips(noise(5000, 1)));
    CHECK(round_trips(noise(70'000, 2)));
    CHECK(round_trips(json_listing(3)));
    CHECK(round_trips(json_listing(3000))); // more than 64 KiB
    std::string everything;
    for (int i = 0; i < 1024; ++i)
        everything.push_back(static_cast<char>(i & 0xff));
    CHECK(round_trips(everything));
}

TEST_CASE("gzip: repetitive and JSON input is much smaller")
{
    std::size_t size = 0;
    REQUIRE(round_trips(std::string(100'000, 'x'), &size));
    CHECK(size < 800);
    const std::string listing = json_listing(500);
    REQUIRE(round_trips(listing, &size));
    CHECK(size * 3 < listing.size());
}

TEST_CASE("gzip: matches of the longest length, and at the edges of the window")
{
    // 258 is the longest match; a run beyond it needs another
    for (const std::size_t run : { std::size_t { 257 }, std::size_t { 258 }, std::size_t { 259 },
             std::size_t { 260 }, std::size_t { 516 }, std::size_t { 517 } })
        CHECK(round_trips("q" + std::string(run, 'z') + "q"));
    // A block seen again at the far end of the window, just inside it and just outside
    const std::string block = noise(300, 7);
    for (const std::size_t gap : { std::size_t { 32768 - 300 - 1 }, std::size_t { 32768 - 300 },
             std::size_t { 32768 - 300 + 1 }, std::size_t { 32768 + 5 } })
        CHECK(round_trips(block + noise(gap, 9) + block));
    CHECK(round_trips("abcabcabcabcabc"));
    CHECK(round_trips("x" + noise(32767, 3) + "x"));
    CHECK(round_trips("xyz" + noise(32768 - 3, 4) + "xyz"));
    // Distances of every size class
    std::string spread;
    for (std::size_t d = 1; d < 40'000; d = (d * 3 / 2) + 1)
    {
        const std::string seen = noise(8, static_cast<std::uint32_t>(d));
        spread += seen + noise(d, static_cast<std::uint32_t>(d) + 1) + seen;
    }
    CHECK(round_trips(spread));
}

TEST_CASE("gzip: a body cut or changed does not pass gunzip")
{
    std::string zipped = packed(json_listing(40));
    String back;
    CHECK_FALSE(
        gunzip(view(std::string_view(zipped).substr(0, zipped.size() - 3)), no_limit, back).has_value());
    zipped[zipped.size() - 8] = static_cast<char>(zipped[zipped.size() - 8] ^ 1);
    back.clear();
    CHECK_FALSE(gunzip(view(zipped), no_limit, back).has_value());
}

TEST_CASE("Accept-Encoding: when gzip may be sent")
{
    struct Row
    {
        std::string_view header;
        bool gzip;
    };
    const std::array<Row, 26> table { {
        { "", false },
        { "gzip", true },
        { "GZIP", true },
        { "x-gzip", true },
        { "deflate, gzip", true },
        { "zstd, br, gzip", true },
        { "zstd, br", false },
        { "br;q=1.0, gzip;q=0.8", true },
        { "gzip;q=0", false },
        { "gzip;q=0.0", false },
        { "gzip; q=0.000", false },
        { "gzip;q=0.001", true },
        { "gzip;q=1", true },
        { "gzip;q=1.000", true },
        { "gzip;q=1.5", false },
        { "gzip;q=abc", false },
        { "gzip;q=", false },
        { "*", true },
        { "*;q=0", false },
        { "*;q=0.5", true },
        { "gzip;q=0, *", false },
        { "*, gzip;q=0", false },
        { "identity", false },
        { "identity;q=1, gzip;q=0.5", false },
        { "identity;q=0.5, gzip;q=0.5", true },
        { " gzip ; q=0.7 , br", true },
    } };
    for (const Row& row : table)
    {
        INFO(row.header);
        CHECK(accepts_gzip(row.header) == row.gzip);
    }
}
