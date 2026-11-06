// Draft 0.7: canonical JSON (RFC 8785), and differential updates (§ 22): the
// chunker, chunk indexes, the plan and the assembler against
// vectors/chunks.json, then the client's download from seeds against a
// transport that answers from memory, hostile answers included.
#include <doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "support.hpp"

using namespace lantern;
using lantern::test::Answer;
using lantern::test::FakeTransport;
using lantern::test::Recorded;
using lantern::test::spec_file;

namespace
{

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

using Bytes = std::vector<std::byte>;

constexpr std::size_t sz(std::uint64_t value)
{
    return static_cast<std::size_t>(value);
}

std::string text_of_bytes(std::span<const std::byte> bytes)
{
    return { reinterpret_cast<const char*>(bytes.data()), bytes.size() };
}

std::string hex_of(const Digest& digest)
{
    const auto hex = to_hex(digest);
    return { hex.data(), hex.size() };
}

Digest digest_of(std::string_view hex)
{
    const auto digest = digest_from_hex(hex);
    REQUIRE(digest);
    return *digest;
}

// The vectors' files: SHA-256(seed || i, i on 8 bytes big-endian), cut to size.
Bytes stream(std::string_view seed, std::size_t size)
{
    Bytes out;
    out.reserve(size + 32);
    for (std::uint64_t i = 0; out.size() < size; ++i)
    {
        std::string input(seed);
        for (int shift = 56; shift >= 0; shift -= 8)
            input.push_back(static_cast<char>((i >> static_cast<unsigned>(shift)) & 0xFFU));
        const Digest digest = Sha256::of(input);
        for (const std::uint8_t b : digest)
            out.push_back(static_cast<std::byte>(b));
    }
    out.resize(size);
    return out;
}

// The vectors' newer version: 777 bytes inserted at 300,000, 10,000 removed at 700,000.
Bytes edited_file(const Bytes& base)
{
    Bytes out(base.begin(), base.begin() + 300000);
    const Bytes inserted = stream("an insertion", 777);
    out.insert(out.end(), inserted.begin(), inserted.end());
    out.insert(out.end(), base.begin() + 300000, base.begin() + 700000);
    out.insert(out.end(), base.begin() + 710000, base.end());
    return out;
}

Bytes file_of(const json::Value& testcase, const Bytes& base)
{
    const json::Value& file = *testcase.find("file");
    if (file.find("zeros") != nullptr)
        return Bytes(sz(number_of(file, "zeros")), std::byte { 0 });
    if (file.find("edit") != nullptr)
        return edited_file(base);
    return stream(text_of(file, "seed"), sz(number_of(file, "size")));
}

class Collect final : public DownloadSink
{
  public:
    Bytes bytes;
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

AppChunks ref_of(const json::Value& entry)
{
    AppChunks ref;
    ref.url    = std::string(text_of(entry, "url"));
    ref.size   = number_of(entry, "size");
    ref.sha256 = digest_of(text_of(entry, "sha256"));
    return ref;
}

} // namespace

TEST_CASE("canonical JSON: the vectors (RFC 8785, SPEC.md 2.3)")
{
    const auto doc = vectors("canonical-json.json");
    for (const json::Value& v : doc.root().find("cases")->items())
    {
        CAPTURE(text_of(v, "name"));
        const auto canonical = canonical_json(text_of(v, "json"));
        REQUIRE(canonical);
        CHECK(*canonical == text_of(v, "canonical"));
        CHECK(hex_of(Sha256::of(std::string_view(*canonical))) == text_of(v, "sha256"));
    }
}

TEST_CASE("canonical JSON: numbers as ECMAScript writes them")
{
    const auto number = [](std::string_view text)
    {
        String out;
        REQUIRE(canonical_number(text, out));
        return std::string(out);
    };
    CHECK(number("0") == "0");
    CHECK(number("-0") == "0");
    CHECK(number("-0.0e5") == "0");
    CHECK(number("1.0") == "1");
    CHECK(number("100") == "100");
    CHECK(number("1e2") == "100");
    CHECK(number("1E+2") == "100");
    CHECK(number("-42") == "-42");
    CHECK(number("9007199254740991") == "9007199254740991");
    CHECK(number("9007199254740993") == "9007199254740992");
    CHECK(number("0.5") == "0.5");
    CHECK(number("4.50") == "4.5");
    CHECK(number("-0.000001") == "-0.000001");
    CHECK(number("0.0000001") == "1e-7");
    CHECK(number("123456.789e3") == "123456789");
    CHECK(number("1e20") == "100000000000000000000");
    CHECK(number("1e21") == "1e+21");
    CHECK(number("1.5e300") == "1.5e+300");
    CHECK(number("5e-324") == "5e-324");
    CHECK(number("4.9e-324") == "5e-324");
    CHECK(number("1.7976931348623157e308") == "1.7976931348623157e+308");
    CHECK(number("333333333.33333329") == "333333333.3333333");
    CHECK(number("0.30000000000000004") == "0.30000000000000004");
    CHECK(number("1e-400") == "0");
    String out;
    CHECK_FALSE(canonical_number("1e400", out));
    CHECK_FALSE(canonical_number("01", out));
    CHECK_FALSE(canonical_number("1.", out));
    CHECK_FALSE(canonical_number("+1", out));
    CHECK_FALSE(canonical_number("", out));
    CHECK_FALSE(canonical_number("1e", out));
}

TEST_CASE("canonical JSON: names by UTF-16 code units, strings escaped as little as can be")
{
    // U+1F3AE is the surrogates D83C DFAE: before U+FFFF, after U+00E9
    const auto sorted = canonical_json("{\"\\uffff\":1,\"\\ud83c\\udfae\":2,\"z\":3,\"\\u00e9\":4}");
    REQUIRE(sorted);
    CHECK(*sorted == "{\"z\":3,\"\xC3\xA9\":4,\"\xF0\x9F\x8E\xAE\":2,\"\xEF\xBF\xBF\":1}");
    const auto escaped = canonical_json("\"\\u001f\\u007f\\u0008\\u000c\\u2028\\/\"");
    REQUIRE(escaped);
    CHECK(*escaped == "\"\\u001f\x7f\\b\\f\xE2\x80\xA8/\"");
    // A key twice has no canonical form, nor a key twice once unescaped
    CHECK_FALSE(canonical_json(R"({"a":1,"a":2})"));
    CHECK_FALSE(canonical_json(R"({"a":1,"\u0061":2})"));
    CHECK_FALSE(canonical_json("[1e999]"));
}

TEST_CASE("chunks: lantern-cdc-1's gear table, and the sizes of a chunker")
{
    const auto doc          = vectors("chunks.json");
    const json::Value& gear = *doc.root().find("gear");
    const auto& table       = cdc_gear();
    const auto hex16        = [](std::uint64_t v)
    {
        std::string out;
        for (int shift = 60; shift >= 0; shift -= 4)
            out.push_back("0123456789abcdef"[(v >> static_cast<unsigned>(shift)) & 15U]);
        return out;
    };
    const auto& first = gear.find("first")->items();
    for (std::size_t i = 0; i < first.size(); ++i)
        CHECK(hex16(table[i]) == first[i].text());
    CHECK(hex16(table[255]) == text_of(gear, "last"));
    std::string all;
    for (const std::uint64_t v : table)
        for (int shift = 56; shift >= 0; shift -= 8)
            all.push_back(static_cast<char>((v >> static_cast<unsigned>(shift)) & 0xFFU));
    CHECK(hex_of(Sha256::of(std::string_view(all))) == text_of(gear, "sha256"));

    CHECK(is_cdc_size(65536));
    CHECK(is_cdc_size(4194304));
    CHECK_FALSE(is_cdc_size(32768));
    CHECK_FALSE(is_cdc_size(8388608));
    CHECK_FALSE(is_cdc_size(100000));
    const auto bounds = cdc_bounds(65536);
    REQUIRE(bounds);
    CHECK(bounds->min == 16384);
    CHECK(bounds->max == 262144);
    CHECK(bounds->mask == 0xFFFF000000000000ULL);
    CHECK_FALSE(cdc_bounds(1000));
    CHECK(cdc_size_for(1000) == 65536);
    CHECK(cdc_size_for(std::uint64_t { 64 } << 20U) == 65536);
    CHECK(cdc_size_for(std::uint64_t { 2 } << 30U) == 131072);
    CHECK_FALSE(cdc_size_for(std::uint64_t { 1 } << 50U));
}

TEST_CASE("chunks: the vectors' files cut, indexed and read back")
{
    const auto doc = vectors("chunks.json");
    Bytes base;
    for (const json::Value& v : doc.root().find("cases")->items())
    {
        CAPTURE(text_of(v, "name"));
        const Bytes data = file_of(v, base);
        if (v.find("file")->find("seed") != nullptr && v.find("file")->find("size") != nullptr
            && number_of(*v.find("file"), "size") == 1000000 && base.empty())
            base = data;
        CHECK(data.size() == number_of(v, "file_size"));
        CHECK(hex_of(Sha256::of(data)) == text_of(v, "file_sha256"));
        const std::uint64_t size = number_of(*v.find("chunker"), "size");
        const auto cuts          = cdc_cut(data, size);
        REQUIRE(cuts);
        const auto& chunks = v.find("chunks")->items();
        REQUIRE(cuts->size() == chunks.size());
        const auto& offsets = v.find("cuts")->items();
        for (std::size_t i = 0; i < chunks.size(); ++i)
        {
            const auto& pair = chunks[i].items();
            CHECK((*cuts)[i].length == *pair[0].to_u64());
            CHECK((*cuts)[i].offset == *offsets[i].to_u64());
            CHECK(hex_of(Sha256::of(std::span(data).subspan(sz((*cuts)[i].offset), sz((*cuts)[i].length))))
                == pair[1].text());
        }
        // The index, in the bytes whose size and SHA-256 the vector gives
        const std::string_view raw = text_of(v, "index");
        CHECK(raw.size() == number_of(v, "index_size"));
        CHECK(hex_of(Sha256::of(raw)) == text_of(v, "index_sha256"));
        const auto canonical = canonical_json(raw);
        REQUIRE(canonical);
        CHECK(*canonical == raw);
        AppChunks ref;
        ref.url          = "x";
        ref.size         = raw.size();
        ref.sha256       = digest_of(text_of(v, "index_sha256"));
        const auto index = read_chunk_index(raw, &ref, digest_of(text_of(v, "file_sha256")), data.size());
        REQUIRE(index);
        REQUIRE(*index);
        CHECK((*index)->chunks.size() == chunks.size());
        CHECK((*index)->chunker_size == size);
        // Asked by the file's SHA-256 alone: no `chunks` to compare with
        CHECK(read_chunk_index(raw, nullptr, digest_of(text_of(v, "file_sha256")), data.size()).has_value());
    }
}

TEST_CASE("chunks: the indexes a client refuses, and so reads the file whole (L-22.3-1)")
{
    const auto doc = vectors("chunks.json");
    for (const json::Value& v : doc.root().find("refused")->items())
    {
        CAPTURE(text_of(v, "name"));
        const AppChunks ref = ref_of(*v.find("chunks"));
        const auto index    = read_chunk_index(
            text_of(v, "index"), &ref, digest_of(text_of(v, "file_sha256")), number_of(v, "file_size"));
        CHECK_FALSE((index.has_value() && index->has_value()));
    }
    // A schema above 1 is absent, not an error (§ 3.2); a chunker it does not know too
    const auto schema = std::ranges::find_if(doc.root().find("refused")->items(),
        [](const json::Value& v) { return text_of(v, "name").starts_with("A schema above 1"); });
    REQUIRE(schema != doc.root().find("refused")->items().end());
    const AppChunks ref = ref_of(*schema->find("chunks"));
    const auto absent
        = read_chunk_index(text_of(*schema, "index"), &ref, digest_of(text_of(*schema, "file_sha256")), 1000);
    REQUIRE(absent);
    CHECK_FALSE(*absent);
}

TEST_CASE("chunks: an index that is not an index")
{
    const Digest sha       = digest_of(std::string(64, 'a'));
    const auto read        = [&](std::string_view raw) { return read_chunk_index(raw, nullptr, sha, 10); };
    const std::string head = R"({"chunker":{"alg":"lantern-cdc-1","size":65536},"chunks":)";
    const std::string tail = R"(,"schema":1,"sha256":")" + std::string(64, 'a') + R"(","size":10})";
    const std::string one  = R"([[10,")" + std::string(64, 'b') + R"("]])";
    CHECK(read(head + one + tail).value_or(std::nullopt).has_value());
    CHECK_FALSE(read("").has_value());
    CHECK_FALSE(read("[]").has_value());
    CHECK_FALSE(read(head + "[[10]]" + tail).has_value());
    CHECK_FALSE(read(head + "[[10,\"b\"]]" + tail).has_value());
    CHECK_FALSE(read(head + "[[10.0,\"" + std::string(64, 'b') + "\"]]" + tail).has_value());
    CHECK_FALSE(read(head + "[[10,\"" + std::string(64, 'b') + "\",1]]" + tail).has_value());
    CHECK_FALSE(
        read(head + "[[0,\"" + std::string(64, 'b') + "\"],[10,\"" + std::string(64, 'b') + "\"]]" + tail)
            .has_value());
    CHECK_FALSE(read(head + "[[5,\"" + std::string(64, 'b') + "\"]]" + tail).has_value());
    CHECK_FALSE(read(head + "[[10,\"" + std::string(64, 'B') + "\"]]" + tail).has_value());
    CHECK_FALSE(read(head + "{}" + tail).has_value());
    CHECK_FALSE(read(head + one + tail + " x").has_value());
    // A member twice
    CHECK_FALSE(read(head + one + R"(,"chunks":[])" + tail).has_value());
    // Unknown members are skipped (§ 3.2)
    const std::string extra
        = R"({"x-note":{"a":[1,2]},"chunker":{"alg":"lantern-cdc-1","size":65536,"x":1},"chunks":)";
    CHECK(read(extra + one + tail).value_or(std::nullopt).has_value());
    // Too large, whatever it says
    const std::string big(chunk_index_limit + 1, ' ');
    CHECK_FALSE(read(big).has_value());
    // 100,001 chunks
    std::string many = head + "[";
    for (std::size_t i = 0; i <= chunks_limit; ++i)
        many += (i == 0 ? "" : ",") + std::string("[1,\"") + std::string(64, 'b') + "\"]";
    many += "]" + tail;
    CHECK_FALSE(read_chunk_index(many, nullptr, sha, chunks_limit + 1).has_value());
}

namespace
{

struct Update
{
    Bytes old_file;
    Bytes new_file;
    std::string index;
    AppChunks chunks;
    DownloadTarget target {};
    std::string target_url;
    std::string chunks_path;
    ChunkIndex parsed;
};

// The vectors' older and newer versions, and the newer one's index.
Update make_update()
{
    static const auto doc = vectors("chunks.json");
    Update u;
    const auto& cases        = doc.root().find("cases")->items();
    u.old_file               = stream("lantern-cdc-1 vector", 1000000);
    u.new_file               = edited_file(u.old_file);
    const json::Value& entry = cases[4];
    REQUIRE(hex_of(Sha256::of(u.new_file)) == text_of(entry, "file_sha256"));
    u.index         = std::string(text_of(entry, "index"));
    u.target_url    = "/api/lantern/v1/blobs/sha256/" + std::string(text_of(entry, "file_sha256"));
    u.chunks_path   = "/api/lantern/v1/chunks/sha256/" + std::string(text_of(entry, "file_sha256"));
    u.chunks.url    = u.chunks_path;
    u.chunks.size   = number_of(entry, "index_size");
    u.chunks.sha256 = digest_of(text_of(entry, "index_sha256"));
    u.target.url    = u.target_url;
    u.target.size   = u.new_file.size();
    u.target.sha256 = digest_of(text_of(entry, "file_sha256"));
    auto parsed     = read_chunk_index(u.index, &u.chunks, u.target.sha256, u.target.size);
    REQUIRE(parsed);
    REQUIRE(*parsed);
    u.parsed = std::move(**parsed);
    return u;
}

} // namespace

TEST_CASE("chunks: the vectors' update, planned and put together")
{
    const auto doc            = vectors("chunks.json");
    const json::Value& update = *doc.root().find("update");
    const Update u            = make_update();
    CHECK(text_of(update, "index_sha256") == hex_of(u.chunks.sha256));
    const std::array<Seed, 1> seeds { Seed(u.old_file) };
    const auto plan = plan_delta(u.parsed, seeds);
    REQUIRE(plan);
    const auto& expected = update.find("plan")->items();
    REQUIRE(plan->steps.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i)
    {
        CAPTURE(i);
        const DeltaStep& step = plan->steps[i];
        CHECK(step.offset == number_of(expected[i], "offset"));
        CHECK(step.length == number_of(expected[i], "size"));
        CHECK(hex_of(step.sha256) == text_of(expected[i], "sha256"));
        const std::string from = "seed at " + std::to_string(step.seed_offset);
        CHECK(text_of(expected[i], "from") == (step.from_seed() ? from : std::string("read")));
    }
    CHECK(plan->to_read == number_of(update, "read"));
    CHECK(plan->seeded + plan->to_read == u.new_file.size());
    const auto ranges = delta_ranges(*plan);
    const auto& asked = update.find("ranges")->items();
    REQUIRE(ranges.size() == asked.size());
    for (std::size_t i = 0; i < asked.size(); ++i)
        CHECK("bytes=" + std::to_string(ranges[i].first) + "-" + std::to_string(ranges[i].last)
            == asked[i].text());
    // Neighbours a few kilobytes apart are joined when the gap allows it
    CHECK(delta_ranges(*plan, std::uint64_t { 1 } << 30U).size() == 1);

    // Put together: the ranges fed in odd pieces
    Collect sink;
    DeltaAssembler assembler(u.parsed, *plan, seeds, sink);
    REQUIRE(assembler.start());
    for (const ByteRange& range : ranges)
    {
        REQUIRE(assembler.begin_range(range));
        const auto body = std::span(u.new_file).subspan(sz(range.first), sz(range.length()));
        for (std::size_t at = 0; at < body.size(); at += 4099)
            REQUIRE(assembler.feed(body.subspan(at, std::min<std::size_t>(4099, body.size() - at))));
        REQUIRE(assembler.end_range());
        CHECK_FALSE(assembler.remaining(range));
    }
    REQUIRE(assembler.finish());
    CHECK(sink.bytes == u.new_file);
    CHECK(assembler.written() == u.new_file.size());
    CHECK(assembler.from_ranges() == plan->to_read);
    CHECK(assembler.from_seeds() == plan->seeded);
}

TEST_CASE("chunks: a seed that holds nothing of the file, and several seeds")
{
    const Update u    = make_update();
    const Bytes other = stream("unrelated", 500000);
    const std::array<Seed, 1> nothing { Seed(other) };
    const auto none = plan_delta(u.parsed, nothing);
    REQUIRE(none);
    CHECK(none->seeded == 0);
    CHECK(delta_ranges(*none, 0).size() == 1);
    CHECK(delta_ranges(*none, 0)[0] == ByteRange { 0, u.new_file.size() - 1 });
    // The newer file as its own seed: nothing to read; a seed first or second changes nothing
    const std::array<Seed, 2> both { Seed(other), Seed(u.new_file) };
    const auto all = plan_delta(u.parsed, both);
    REQUIRE(all);
    CHECK(all->to_read == 0);
    CHECK(delta_ranges(*all).empty());
    Collect sink;
    DeltaAssembler assembler(u.parsed, *all, both, sink);
    REQUIRE(assembler.start());
    REQUIRE(assembler.finish());
    CHECK(sink.bytes == u.new_file);
}

TEST_CASE("chunks: a chunk that does not match, a short range, more than asked (L-22.3-2, L-22.3-3)")
{
    const Update u = make_update();
    const std::array<Seed, 1> seeds { Seed(u.old_file) };
    const auto plan   = plan_delta(u.parsed, seeds);
    const auto ranges = delta_ranges(*plan);
    REQUIRE(plan);
    REQUIRE(!ranges.empty());
    const ByteRange first = ranges[0];
    const auto good       = std::span(u.new_file).subspan(sz(first.first), sz(first.length()));

    SUBCASE("one byte of a chunk changed: nothing of it is kept")
    {
        Bytes bad(good.begin(), good.end());
        bad[bad.size() / 2] ^= std::byte { 1 };
        Collect sink;
        DeltaAssembler assembler(u.parsed, *plan, seeds, sink);
        REQUIRE(assembler.start());
        const std::size_t before = sink.bytes.size();
        REQUIRE(assembler.begin_range(first));
        const auto fed = assembler.feed(bad);
        REQUIRE_FALSE(fed);
        CHECK(fed.error().category() == Category::integrity);
        // Only whole chunks that matched, before the bad one: never a byte of it
        CHECK(sink.bytes.size() < before + bad.size());
        CHECK(sink.bytes.size() <= u.new_file.size());
    }
    SUBCASE("a range cut short")
    {
        Collect sink;
        DeltaAssembler assembler(u.parsed, *plan, seeds, sink);
        REQUIRE(assembler.start());
        REQUIRE(assembler.begin_range(first));
        REQUIRE(assembler.feed(good.first(good.size() - 10)));
        CHECK_FALSE(assembler.end_range());
        // The chunks verified are kept, and the rest is still to read
        const auto rest = assembler.remaining(first);
        REQUIRE(rest);
        CHECK(rest->last == first.last);
        CHECK(rest->first >= first.first);
        CHECK(rest->first <= first.last);
        // Another source reads it
        REQUIRE(assembler.begin_range(*rest));
        REQUIRE(assembler.feed(std::span(u.new_file).subspan(sz(rest->first), sz(rest->length()))));
        REQUIRE(assembler.end_range());
        CHECK_FALSE(assembler.remaining(first));
    }
    SUBCASE("more than the range asked for")
    {
        Collect sink;
        DeltaAssembler assembler(u.parsed, *plan, seeds, sink);
        REQUIRE(assembler.start());
        REQUIRE(assembler.begin_range(first));
        const auto more = std::span(u.new_file).subspan(sz(first.first), sz(first.length() + 1));
        const auto fed  = assembler.feed(more);
        REQUIRE_FALSE(fed);
        CHECK(fed.error().category() == Category::integrity);
    }
    SUBCASE("a range that does not begin at the next chunk to read")
    {
        Collect sink;
        DeltaAssembler assembler(u.parsed, *plan, seeds, sink);
        REQUIRE(assembler.start());
        CHECK_FALSE(assembler.begin_range({ first.first + 1, first.last }));
        CHECK_FALSE(assembler.begin_range({ first.first, u.new_file.size() }));
    }
    SUBCASE("the whole file's check")
    {
        // An index whose file digest is not the bytes put together
        ChunkIndex wrong = u.parsed;
        wrong.sha256[0] ^= 1U;
        Collect sink;
        DeltaAssembler assembler(wrong, *plan, seeds, sink);
        REQUIRE(assembler.start());
        for (const ByteRange& range : ranges)
        {
            REQUIRE(assembler.begin_range(range));
            REQUIRE(assembler.feed(std::span(u.new_file).subspan(sz(range.first), sz(range.length()))));
            REQUIRE(assembler.end_range());
        }
        const auto done = assembler.finish();
        REQUIRE_FALSE(done);
        CHECK(done.error().category() == Category::integrity);
    }
}

// The client.

namespace
{

constexpr std::string_view deltas_handshake = R"({"schema":1,"uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14",
    "name":"Living room shelf","base":"/api/lantern","versions":[1],"platforms":["switch"],
    "account":{"state":"active","scopes":["library"],"bound":false},
    "features":{"library":1,"titles":1,"changes":1,"sections":0,"homebrew":1,"saves":1,"cheats":1,"requests":1,
                "pairing":1,"signatures":1,"admin":0,"events":1,"peers":1,"sync":0,"encrypted_saves":0,"deltas":1},
    "auth":{"bearer_only":true,"skew":300},
    "peers":{"key":"FkDVKwFG57y5KAWiHAahZeQ1pO2FxI5AehF/nZjLXq8=","grant_lifetime":600},
    "limits":{"page_size":500,"save_body":1048576,"save_size":1048576,"saves_kept_per_title":10}})";

Answer json_answer(std::string_view body, std::uint16_t status = 200)
{
    Answer a;
    a.status = status;
    a.body   = std::string(body);
    return a;
}

// A server, a mirror and a peer holding the newer file, with ways to lie.
struct Sources
{
    Update update;
    FakeTransport transport;
    std::optional<Client> client;
    // What the server says of the index and of ranges
    std::string index_body;
    bool ignore_range   = false;
    bool flip_a_byte    = false;
    bool cut_short      = false;
    bool range_too_long = false;
    bool wrong_range    = false;
    bool whole_is_wrong = false;
    // The mirror and the peer
    bool mirror_flips      = false;
    bool mirror_down       = false;
    bool peer_up           = false;
    unsigned server_ranges = 0;
    unsigned server_wholes = 0;
    unsigned mirror_ranges = 0;
    unsigned peer_ranges   = 0;

    Sources(const Sources&)            = delete;
    Sources& operator=(const Sources&) = delete;

    Sources()
        : update(make_update())
        , index_body(update.index)
    {
        update.target.url = update.target_url;
        ClientConfig config;
        config.origin     = "https://shelf.example.org";
        config.user_agent = "LanternTests/0.7";
        config.platform   = "switch";
        auto made         = Client::create(transport, config);
        REQUIRE(made);
        client.emplace(std::move(*made));
        transport.respond = [this](const Recorded& r) { return answer(r); };
        REQUIRE(client->handshake());
        REQUIRE(client->set_bearer_token("lt_lea-0123456789"));
    }

    Answer ranged(const Recorded& r, bool lie, bool flip)
    {
        const std::string* range = r.header("Range");
        Answer a;
        a.headers.clear();
        const std::string whole = text_of_bytes(update.new_file);
        if (range == nullptr || ignore_range)
        {
            a.status = 200;
            a.body   = whole;
            if (lie && whole_is_wrong)
                a.body[a.body.size() / 3] = static_cast<char>(a.body[a.body.size() / 3] ^ 1);
            return a;
        }
        std::uint64_t first = 0;
        std::uint64_t last  = 0;
        const std::string_view spec(*range);
        REQUIRE(spec.starts_with("bytes="));
        const std::size_t dash = spec.find('-');
        REQUIRE(dash != std::string_view::npos);
        first                    = std::stoull(std::string(spec.substr(6, dash - 6)));
        last                     = std::stoull(std::string(spec.substr(dash + 1)));
        a.status                 = 206;
        std::uint64_t shown_last = last;
        if (lie && wrong_range)
            --shown_last;
        a.headers.emplace_back("Content-Range",
            "bytes " + std::to_string(first) + "-" + std::to_string(shown_last) + "/"
                + std::to_string(whole.size()));
        a.body = whole.substr(sz(first), sz(last - first + 1));
        if (lie && range_too_long)
            a.body += whole.substr(sz(last + 1), 5000);
        if (flip)
            a.body[a.body.size() / 2] = static_cast<char>(a.body[a.body.size() / 2] ^ 1);
        if (lie && cut_short)
            a.cut_after = a.body.size() - 3;
        return a;
    }

    Answer answer(const Recorded& r)
    {
        if (r.url.ends_with("/.well-known/lantern"))
            return json_answer(deltas_handshake);
        if (r.url == "https://shelf.example.org" + update.chunks_path)
            return json_answer(index_body);
        if (r.url == "https://shelf.example.org" + update.target_url)
        {
            if (r.header("Range") != nullptr)
                ++server_ranges;
            else
                ++server_wholes;
            return ranged(r, true, flip_a_byte);
        }
        if (r.url.starts_with("https://mirror.example.net/"))
        {
            if (mirror_down)
                return json_answer("{}", 503);
            ++mirror_ranges;
            return ranged(r, false, mirror_flips);
        }
        if (r.url.starts_with("http://192.168.1.20:47116/"))
        {
            if (!peer_up)
                return json_answer("{}", 404);
            REQUIRE(r.header("Lantern-Grant") != nullptr);
            REQUIRE(r.header("Authorization") == nullptr);
            ++peer_ranges;
            return ranged(r, false, false);
        }
        return json_answer("{}", 404);
    }

    DeltaOptions options(std::uint64_t gap = 0)
    {
        DeltaOptions o;
        o.gap = gap;
        return o;
    }
};

} // namespace

TEST_CASE("client: features.deltas is surfaced like the other families")
{
    Sources s;
    CHECK(s.client->offers(Family::deltas) == 1);
    CHECK(s.client->offers(Family::sync) == 0);
    REQUIRE(s.client->server() != nullptr);
    CHECK(s.client->server()->features.deltas == 1);
}

TEST_CASE("client: the chunk index, by chunks.url and by the file's SHA-256")
{
    Sources s;
    const auto index = s.client->chunk_index(s.update.chunks, s.update.target);
    REQUIRE(index);
    REQUIRE(*index);
    CHECK((*index)->chunks.size() == s.update.parsed.chunks.size());
    REQUIRE(s.transport.requests.size() >= 1);
    CHECK(s.transport.requests.back().url == "https://shelf.example.org" + s.update.chunks_path);

    s.transport.requests.clear();
    const std::string route
        = "https://shelf.example.org/api/lantern/v1/chunks/sha256/" + hex_of(s.update.target.sha256);
    s.transport.respond = [&](const Recorded& r)
    {
        CHECK(r.url == route);
        return json_answer(s.update.index);
    };
    const auto by_hash = s.client->chunk_index_of(s.update.target.sha256, s.update.target.size);
    REQUIRE(by_hash);
    REQUIRE(*by_hash);
    CHECK(s.transport.requests.size() == 1);

    SUBCASE("bytes that are not those `chunks` gives")
    {
        s.transport.respond = [&](const Recorded&)
        {
            std::string tampered          = s.update.index;
            tampered[tampered.size() / 2] = tampered[tampered.size() / 2] == 'a' ? 'b' : 'a';
            return json_answer(tampered);
        };
        CHECK_FALSE(s.client->chunk_index(s.update.chunks, s.update.target));
    }
    SUBCASE("an answer larger than `chunks` says is not read to its end")
    {
        s.transport.respond
            = [&](const Recorded&) { return json_answer(s.update.index + std::string(100000, ' ')); };
        const auto big = s.client->chunk_index(s.update.chunks, s.update.target);
        REQUIRE_FALSE(big);
        CHECK(big.error().category() == Category::limit);
    }
    SUBCASE("a 404")
    {
        s.transport.respond = [&](const Recorded&) { return json_answer("{}", 404); };
        CHECK_FALSE(s.client->chunk_index(s.update.chunks, s.update.target));
    }
    SUBCASE("the family not offered")
    {
        s.transport.respond = [&](const Recorded&)
        {
            std::string text(deltas_handshake);
            text.replace(text.find("\"deltas\":1"), 10, "\"deltas\":0");
            return json_answer(text);
        };
        REQUIRE(s.client->handshake());
        CHECK_FALSE(s.client->chunk_index_of(s.update.target.sha256, s.update.target.size));
    }
}

TEST_CASE("client: a file put together from a seed and two ranges")
{
    Sources s;
    Collect sink;
    const std::array<Seed, 1> seeds { Seed(s.update.old_file) };
    const auto report
        = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, sink, s.options());
    REQUIRE(report);
    CHECK_FALSE(report->whole_file);
    CHECK(sink.bytes == s.update.new_file);
    CHECK(report->requests == 2);
    CHECK(s.server_ranges == 2);
    CHECK(s.server_wholes == 0);
    CHECK(report->from_seeds + report->from_ranges == s.update.new_file.size());
    CHECK(report->from_ranges == 369810);
    CHECK(sink.restarts == 0);
    // The ranges the vectors name, and the token to the server alone
    std::vector<std::string> asked;
    for (const Recorded& r : s.transport.requests)
        if (const std::string* range = r.header("Range"))
            asked.push_back(*range);
    REQUIRE(asked.size() == 2);
    CHECK(asked[0] == "bytes=223418-364436");
    CHECK(asked[1] == "bytes=528735-757525");

    // Joined by the default gap when the seed between them is small enough: still the same file
    Collect again;
    s.server_ranges = 0;
    const auto joined
        = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, again, s.options(1U << 30U));
    REQUIRE(joined);
    CHECK(again.bytes == s.update.new_file);
    CHECK(s.server_ranges == 1);

    // The seed is the file: no request but the index
    Collect same;
    s.transport.requests.clear();
    const std::array<Seed, 1> exact { Seed(s.update.new_file) };
    const auto nothing
        = s.client->download_with_seeds(s.update.target, s.update.chunks, exact, same, s.options());
    REQUIRE(nothing);
    CHECK(same.bytes == s.update.new_file);
    CHECK(nothing->from_ranges == 0);
    CHECK(s.transport.requests.size() == 1);
}

TEST_CASE("client: a verified prefix kept by the app is one more seed (Annex B.4)")
{
    Sources s;
    const std::array<Seed, 1> old_only { Seed(s.update.old_file) };
    Collect fresh;
    const auto first
        = s.client->download_with_seeds(s.update.target, s.update.chunks, old_only, fresh, s.options());
    REQUIRE(first);
    REQUIRE_FALSE(first->whole_file);

    SUBCASE("the bytes of an interrupted run")
    {
        // What an app keeps: the file's first bytes, as the sink received them
        const Bytes prefix(s.update.new_file.begin(),
            s.update.new_file.begin() + static_cast<std::ptrdiff_t>(s.update.new_file.size() / 2));
        const std::array<Seed, 2> seeds { Seed(s.update.old_file), Seed(prefix) };
        Collect resumed;
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, resumed, s.options());
        REQUIRE(report);
        CHECK_FALSE(report->whole_file);
        CHECK(resumed.bytes == s.update.new_file);
        CHECK(report->from_ranges < first->from_ranges);
        CHECK(report->from_seeds + report->from_ranges == s.update.new_file.size());
        CHECK(resumed.restarts == 0);
    }
    SUBCASE("a prefix alone, with no other seed")
    {
        const Bytes prefix(s.update.new_file.begin(),
            s.update.new_file.begin() + static_cast<std::ptrdiff_t>(s.update.new_file.size() / 2));
        const std::array<Seed, 1> seeds { Seed(prefix) };
        Collect resumed;
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, resumed, s.options());
        REQUIRE(report);
        CHECK_FALSE(report->whole_file);
        CHECK(resumed.bytes == s.update.new_file);
        CHECK(report->from_seeds > 0);
    }
    SUBCASE("garbage in place of the prefix shares nothing")
    {
        const Bytes garbage(sz(s.update.new_file.size() / 2), std::byte { 0x5A });
        const std::array<Seed, 2> seeds { Seed(s.update.old_file), Seed(garbage) };
        Collect resumed;
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, resumed, s.options());
        REQUIRE(report);
        CHECK_FALSE(report->whole_file);
        CHECK(resumed.bytes == s.update.new_file);
        CHECK(report->from_ranges == first->from_ranges);

        // Garbage alone: nothing to gain from ranges, the file whole, still exact
        const std::array<Seed, 1> only { Seed(garbage) };
        Collect whole;
        const auto all
            = s.client->download_with_seeds(s.update.target, s.update.chunks, only, whole, s.options());
        REQUIRE(all);
        CHECK(all->whole_file);
        CHECK(whole.bytes == s.update.new_file);
    }
}

TEST_CASE("client: any failure reads the whole file (L-22.3-4)")
{
    Sources s;
    Collect sink;
    const std::array<Seed, 1> seeds { Seed(s.update.old_file) };
    const auto run = [&]()
    {
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, sink, s.options());
        REQUIRE(report);
        return *report;
    };

    SUBCASE("a chunk of the server that does not match")
    {
        s.flip_a_byte            = true;
        const DeltaReport report = run();
        CHECK(report.whole_file);
    }
    SUBCASE("a range cut short")
    {
        s.cut_short = true;
        CHECK(run().whole_file);
    }
    SUBCASE("a server that ignores Range")
    {
        s.ignore_range           = true;
        const DeltaReport report = run();
        CHECK(report.whole_file);
        // The first range is refused when the whole file starts to come
        CHECK(s.server_wholes >= 1);
    }
    SUBCASE("a Content-Range that is not the range asked")
    {
        s.wrong_range = true;
        CHECK(run().whole_file);
    }
    SUBCASE("more than the range asked for")
    {
        s.range_too_long = true;
        CHECK(run().whole_file);
    }
    SUBCASE("a bad index: the file whole, and no range asked")
    {
        s.index_body[10]         = s.index_body[10] == 'a' ? 'b' : 'a';
        const DeltaReport report = run();
        CHECK(report.whole_file);
        CHECK(s.server_ranges == 0);
    }
    SUBCASE("an index of another file")
    {
        Update other = make_update();
        other.index
            = std::string(
                  R"({"chunker":{"alg":"lantern-cdc-1","size":65536},"chunks":[],"schema":1,"sha256":")")
            + std::string(64, 'c') + R"(","size":0})";
        s.index_body           = other.index;
        s.update.chunks.size   = other.index.size();
        s.update.chunks.sha256 = Sha256::of(other.index);
        CHECK(run().whole_file);
    }
    CHECK(sink.bytes == s.update.new_file);
    CHECK(sink.restarts >= 1);
}

TEST_CASE("client: mirrors and peers read the ranges, and what fails is dropped (L-19.1-3)")
{
    Sources s;
    Collect sink;
    const std::array<Seed, 1> seeds { Seed(s.update.old_file) };
    Mirror mirror;
    mirror.url = "https://mirror.example.net/files/new.bin";
    const std::array<Mirror, 1> mirrors { mirror };
    DeltaOptions options = s.options();
    options.mirrors      = mirrors;

    SUBCASE("a mirror serves both ranges")
    {
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, sink, options);
        REQUIRE(report);
        CHECK_FALSE(report->whole_file);
        CHECK(s.mirror_ranges == 2);
        CHECK(s.server_ranges == 0);
        for (const Recorded& r : s.transport.requests)
            if (r.url.starts_with("https://mirror.example.net/"))
            {
                CHECK(r.header("Authorization") == nullptr);
                CHECK(r.header("Lantern-Platform") == nullptr);
            }
    }
    SUBCASE("a mirror that lies about a chunk is dropped, the server reads the range")
    {
        s.mirror_flips = true;
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, sink, options);
        REQUIRE(report);
        CHECK_FALSE(report->whole_file);
        CHECK(s.mirror_ranges == 1); // asked once, never again
        CHECK(s.server_ranges == 2);
    }
    SUBCASE("a mirror that is down")
    {
        s.mirror_down = true;
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, sink, options);
        REQUIRE(report);
        CHECK_FALSE(report->whole_file);
        CHECK(s.server_ranges == 2);
    }
    SUBCASE("a peer first, with the grant alone")
    {
        s.peer_up = true;
        Grant grant;
        grant.grant  = "eyJhIjoxfQ.c2ln";
        grant.sha256 = s.update.target.sha256;
        grant.size   = s.update.target.size;
        PeerEndpoint endpoint;
        endpoint.host = "192.168.1.20";
        endpoint.port = 47116;
        endpoint.base = "/lantern";
        const std::array<DeltaPeer, 1> peers { DeltaPeer { endpoint, &grant } };
        options.peers = peers;
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, sink, options);
        REQUIRE(report);
        CHECK_FALSE(report->whole_file);
        CHECK(s.peer_ranges == 2);
        CHECK(s.mirror_ranges == 0);
        CHECK(s.server_ranges == 0);
    }
    SUBCASE("every source lying: the whole file")
    {
        s.mirror_flips = true;
        s.flip_a_byte  = true;
        const auto report
            = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, sink, options);
        REQUIRE(report);
        CHECK(report->whole_file);
    }
    CHECK(sink.bytes == s.update.new_file);
}

TEST_CASE("client: a whole file that is not the file is refused too")
{
    Sources s;
    Collect sink;
    s.whole_is_wrong = true;
    s.flip_a_byte    = true;
    const std::array<Seed, 1> seeds { Seed(s.update.old_file) };
    // The server's whole file is flipped as well: nothing is installed
    const auto report
        = s.client->download_with_seeds(s.update.target, s.update.chunks, seeds, sink, s.options());
    REQUIRE_FALSE(report);
    CHECK(report.error().category() == Category::integrity);
}

TEST_CASE("upload: HEAD gives Lantern-Chunk-Size for a client that kept the address alone (L-9.3-3)")
{
    Sources s;
    s.transport.respond = [&](const Recorded& r)
    {
        CHECK(r.method == "HEAD");
        Answer a;
        a.status = 204;
        a.headers
            = { { "Upload-Offset", "512" }, { "Upload-Length", "4096" }, { "Lantern-Chunk-Size", "1024" } };
        return a;
    };
    const auto head = s.client->upload_head("/api/lantern/v1/uploads/u_1");
    REQUIRE(head);
    CHECK(head->offset == 512);
    CHECK(head->length == 4096);
    CHECK(head->chunk_size == 1024);
    CHECK(s.client->upload_offset("/api/lantern/v1/uploads/u_1") == 512);

    s.transport.respond = [&](const Recorded&)
    {
        Answer a;
        a.status  = 204;
        a.headers = { { "Upload-Offset", "512" }, { "Lantern-Chunk-Size", "0" } };
        return a;
    };
    CHECK_FALSE(s.client->upload_head("/api/lantern/v1/uploads/u_1"));
    s.transport.respond = [&](const Recorded&)
    {
        Answer a;
        a.status  = 204;
        a.headers = { { "Upload-Offset", "512" } };
        return a;
    };
    const auto bare = s.client->upload_head("/api/lantern/v1/uploads/u_1");
    REQUIRE(bare);
    CHECK_FALSE(bare->chunk_size);
}

// Static libraries (§ 21.3, § 22 over files).

namespace
{

constexpr std::string_view static_handshake
    = R"({"schema":1,"uid":"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14","name":"Lea's library",
    "base":".","versions":[1],"platforms":["switch"],"language":"en",
    "account":{"state":"anonymous","scopes":["library"]},
    "features":{"library":1,"titles":1,"homebrew":1,"cheats":0,"changes":0,"sections":0,"saves":0,"encrypted_saves":0,
                "requests":0,"pairing":0,"signatures":0,"admin":0,"events":0,"peers":0,"sync":0,"deltas":1},
    "limits":{"page_size":1},"static":{"generated":"2026-10-30T18:00:00Z","page_size":1}})";

class MemoryFiles final : public StaticFiles
{
  public:
    std::map<std::string, std::string> files;
    std::vector<std::pair<std::string, std::uint64_t>> reads;
    // A source that cannot start at an offset gives the file whole
    bool no_seek = false;
    // Flips a byte of what a ranged read gives
    bool flip = false;

    Result<void> read(std::string_view path, std::uint64_t offset, DownloadSink& sink) override
    {
        reads.emplace_back(std::string(path), offset);
        const auto found = files.find(std::string(path));
        if (found == files.end())
            return std::unexpected(Error::from_status(404));
        std::string body = found->second;
        if (flip && offset != 0 && body.size() > offset + 100)
            body[static_cast<std::size_t>(offset) + 50]
                = static_cast<char>(body[static_cast<std::size_t>(offset) + 50] ^ 1);
        std::string_view rest(body);
        if (offset != 0 && no_seek)
        {
            if (auto restarted = sink.restart(); !restarted)
                return restarted;
        }
        else
            rest.remove_prefix(static_cast<std::size_t>(offset));
        // In pieces, as a file is read
        while (!rest.empty())
        {
            const std::size_t piece = std::min<std::size_t>(rest.size(), 10000);
            if (auto written = sink.write(std::as_bytes(std::span(rest.data(), piece))); !written)
                return written;
            rest.remove_prefix(piece);
        }
        return {};
    }
};

struct StaticDelta
{
    Update update;
    MemoryFiles files;
    std::optional<StaticLibrary> library;
    AppChunks chunks;
    DownloadTarget target {};
    std::string chunks_path;
    std::string file_path;

    StaticDelta(const StaticDelta&)            = delete;
    StaticDelta& operator=(const StaticDelta&) = delete;

    StaticDelta()
        : update(make_update())
    {
        const std::string hex       = hex_of(update.target.sha256);
        file_path                   = "v1/blobs/sha256/" + hex;
        chunks_path                 = "v1/chunks/sha256/" + hex + ".json";
        files.files["lantern.json"] = std::string(static_handshake);
        files.files[file_path]      = text_of_bytes(update.new_file);
        files.files[chunks_path]    = update.index;
        chunks.url                  = chunks_path;
        chunks.size                 = update.chunks.size;
        chunks.sha256               = update.chunks.sha256;
        target.url                  = file_path;
        target.size                 = update.new_file.size();
        target.sha256               = update.target.sha256;
        auto opened                 = StaticLibrary::open(files);
        REQUIRE(opened);
        REQUIRE(*opened);
        library.emplace(std::move(**opened));
        files.reads.clear();
    }
};

} // namespace

TEST_CASE("static library: a file put together from a seed and the ranges of its file")
{
    StaticDelta s;
    Collect sink;
    const std::array<Seed, 1> seeds { Seed(s.update.old_file) };
    const auto index = s.library->chunk_index(s.chunks, s.target);
    REQUIRE(index);
    REQUIRE(*index);

    s.files.reads.clear();
    const auto report = s.library->download_with_seeds(s.target, s.chunks, seeds, sink, 0);
    REQUIRE(report);
    CHECK_FALSE(report->whole_file);
    CHECK(sink.bytes == s.update.new_file);
    CHECK(report->requests == 2);
    CHECK(report->from_ranges == 369810);
    REQUIRE(s.files.reads.size() == 3);
    CHECK(s.files.reads[0].first == s.chunks_path);
    CHECK(s.files.reads[1] == std::pair<std::string, std::uint64_t> { s.file_path, 223418 });
    CHECK(s.files.reads[2] == std::pair<std::string, std::uint64_t> { s.file_path, 528735 });

    SUBCASE("a source that cannot start at an offset")
    {
        s.files.no_seek = true;
        Collect again;
        const auto done = s.library->download_with_seeds(s.target, s.chunks, seeds, again, 0);
        REQUIRE(done);
        CHECK_FALSE(done->whole_file);
        CHECK(again.bytes == s.update.new_file);
    }
    SUBCASE("a chunk that does not match: the whole file")
    {
        s.files.flip = true;
        Collect again;
        const auto done = s.library->download_with_seeds(s.target, s.chunks, seeds, again, 0);
        REQUIRE(done);
        CHECK(done->whole_file);
        CHECK(again.bytes == s.update.new_file);
    }
    SUBCASE("a bad index: the whole file, no range")
    {
        s.files.files[s.chunks_path][20] = 'X';
        Collect again;
        s.files.reads.clear();
        const auto done = s.library->download_with_seeds(s.target, s.chunks, seeds, again, 0);
        REQUIRE(done);
        CHECK(done->whole_file);
        CHECK(again.bytes == s.update.new_file);
        for (const auto& [path, offset] : s.files.reads)
            CHECK(offset == 0);
    }
    SUBCASE("an index off the root")
    {
        AppChunks wrong = s.chunks;
        wrong.url       = "../x.json";
        CHECK_FALSE(s.library->chunk_index(wrong, s.target));
    }
}

TEST_CASE("find_library: the origin's server first, then the address's static library (L-21.3-3)")
{
    FakeTransport transport;
    std::map<std::string, std::string> documents;
    transport.respond = [&](const Recorded& r)
    {
        const auto found = documents.find(r.url);
        return found == documents.end() ? json_answer("{}", 404) : json_answer(found->second);
    };
    const std::string hello(deltas_handshake);
    const std::string library(static_handshake);
    const auto find
        = [&](std::string_view address) { return find_library(transport, address, "LanternTests/0.7"); };

    SUBCASE("a server at the origin")
    {
        documents["https://shelf.example.org/.well-known/lantern"] = hello;
        const auto found = find("https://shelf.example.org/some/path");
        REQUIRE(found);
        REQUIRE(*found);
        CHECK((*found)->kind == LibraryKind::server);
        CHECK((*found)->root == "https://shelf.example.org");
        CHECK((*found)->handshake.name == "Living room shelf");
    }
    SUBCASE("a static library at the address, with or without its slash")
    {
        documents["https://files.example.org/lea/lantern.json"] = library;
        for (const std::string_view address :
            { "https://files.example.org/lea", "https://files.example.org/lea/" })
        {
            const auto found = find(address);
            REQUIRE(found);
            REQUIRE(*found);
            CHECK((*found)->kind == LibraryKind::static_library);
            CHECK((*found)->root == "https://files.example.org/lea/");
            CHECK((*found)->handshake.static_.has_value());
        }
    }
    SUBCASE("a static library's handshake at /.well-known/lantern never makes the origin's root a library")
    {
        documents["https://files.example.org/.well-known/lantern"] = library;
        const auto root                                            = find("https://files.example.org/");
        REQUIRE(root);
        CHECK_FALSE(root->has_value());
        // Its own lantern.json makes the address a static library, not a server
        documents["https://files.example.org/lantern.json"] = library;
        const auto with_file                                = find("https://files.example.org/");
        REQUIRE(with_file);
        REQUIRE(*with_file);
        CHECK((*with_file)->kind == LibraryKind::static_library);
        documents.erase("https://files.example.org/lantern.json");
        documents["https://files.example.org/lea/lantern.json"] = library;
        const auto below                                        = find("https://files.example.org/lea");
        REQUIRE(below);
        REQUIRE(*below);
        CHECK((*below)->root == "https://files.example.org/lea/");
    }
    SUBCASE("a server's document of a newer schema, an error and a folder without the file are passed over")
    {
        std::string newer = hello;
        newer.replace(newer.find("\"schema\":1"), 10, "\"schema\":2");
        documents["https://shelf.example.org/.well-known/lantern"] = newer;
        documents["https://shelf.example.org/lantern.json"]        = "not json";
        const auto none                                            = find("https://shelf.example.org/");
        REQUIRE(none);
        CHECK_FALSE(none->has_value());
        // Plain HTTP off loopback is refused (§ 2)
        CHECK_FALSE(find("http://shelf.example.org/"));
        CHECK_FALSE(find("ftp://shelf.example.org/"));
    }
}
