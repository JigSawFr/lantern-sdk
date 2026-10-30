#include <doctest.h>

#include <string>
#include <vector>

#include "support.hpp"

using namespace lantern;

namespace
{

// The events of a document, as a compact trace: {, }, [, ], k:<key>,
// s:<string>, n:<number>, true, false, null, END, or ERR.
std::string trace(std::string_view text, json::Limits limits = {})
{
    std::vector<char> scratch(limits.max_string);
    json::Reader reader(text, limits, scratch);
    std::string out;
    for (;;)
    {
        const json::Event event = reader.next();
        if (!out.empty())
            out += ' ';
        switch (event)
        {
            case json::Event::object_begin:
                out += '{';
                break;
            case json::Event::object_end:
                out += '}';
                break;
            case json::Event::array_begin:
                out += '[';
                break;
            case json::Event::array_end:
                out += ']';
                break;
            case json::Event::key:
                out += "k:" + std::string(reader.text());
                break;
            case json::Event::string:
                out += "s:" + std::string(reader.text());
                break;
            case json::Event::number:
                out += "n:" + std::string(reader.text());
                break;
            case json::Event::boolean:
                out += reader.boolean() ? "true" : "false";
                break;
            case json::Event::null:
                out += "null";
                break;
            case json::Event::end:
                out += "END";
                return out;
            case json::Event::error:
                out += "ERR";
                return out;
        }
    }
}

bool parses(std::string_view text, json::Limits limits = {})
{
    return trace(text, limits).ends_with("END");
}

} // namespace

TEST_CASE("json: the events of a document")
{
    CHECK(trace(R"({"a":[1,-2.5e3,true,false,null],"b":{"c":"d"}})")
        == "{ k:a [ n:1 n:-2.5e3 true false null ] k:b { k:c s:d } } END");
    CHECK(trace("  [ ]  ") == "[ ] END");
    CHECK(trace("{}") == "{ } END");
    CHECK(trace("\"lone\"") == "s:lone END");
    CHECK(trace("0") == "n:0 END");
}

TEST_CASE("json: RFC 8259's grammar, strictly")
{
    for (const char* bad : { "", " ", "{", "}", "[1,]", "{\"a\":1,}", "{\"a\" 1}", "{a:1}", "[01]", "[1.]",
             "[.5]", "[1e]", "[+1]", "[-]", "[tru]", "[nul]", "{\"a\":1}x", "[1 2]", "'a'", "[\"a\"\"b\"]",
             "{\"a\":}", "[,1]", "{,}", "\xEF\xBB\xBF{}" })
    {
        CAPTURE(bad);
        CHECK_FALSE(parses(bad));
    }
}

TEST_CASE("json: strings are unescaped and checked as UTF-8")
{
    CHECK(trace(R"(["a\"b\\c\/d\b\f\n\r\t"])") == "[ s:a\"b\\c/d\b\f\n\r\t ] END");
    CHECK(trace(R"(["\u00e9\u20ac\ud83c\udfee"])") == "[ s:\xC3\xA9\xE2\x82\xAC\xF0\x9F\x8F\xAE ] END");
    CHECK(trace("[\"Atmosph\xC3\xA8re\"]") == "[ s:Atmosph\xC3\xA8re ] END");
    // Lone surrogates, raw or escaped; an unknown escape; a raw control character
    CHECK_FALSE(parses(R"(["\ud83c"])"));
    CHECK_FALSE(parses(R"(["\udfee"])"));
    CHECK_FALSE(parses(R"(["\ud83c\u0041"])"));
    CHECK_FALSE(parses(R"(["\x"])"));
    CHECK_FALSE(parses(R"(["\u12"])"));
    CHECK_FALSE(parses("[\"a\nb\"]"));
    CHECK_FALSE(parses(std::string_view("[\"a\0b\"]", 7)));
    // UTF-8 that is not: overlong forms, surrogates, above U+10FFFF, cut
    for (const char* bad :
        { "[\"\xC0\xAF\"]", "[\"\xE0\x80\xAF\"]", "[\"\xED\xA0\x80\"]", "[\"\xF4\x90\x80\x80\"]",
            "[\"\xF5\x80\x80\x80\"]", "[\"\xC3\"]", "[\"\x80\"]", "[\"\xFF\"]", "[\"\xE2\x82\"]" })
    {
        CAPTURE(bad);
        CHECK_FALSE(parses(bad));
    }
}

TEST_CASE("json: SPEC.md 13's limits")
{
    // Depth 16: sixteen arrays open at once, not seventeen
    CHECK(parses(std::string(16, '[') + std::string(16, ']')));
    CHECK_FALSE(parses(std::string(17, '[') + std::string(17, ']')));
    // A string of 4096 bytes, not 4097, escaped or not
    CHECK(parses("[\"" + std::string(4096, 'a') + "\"]"));
    CHECK_FALSE(parses("[\"" + std::string(4097, 'a') + "\"]"));
    CHECK(parses("[\"\\n" + std::string(4095, 'a') + "\"]"));
    CHECK_FALSE(parses("[\"\\n" + std::string(4096, 'a') + "\"]"));
    // The document's size
    json::Limits small;
    small.max_document = 8;
    CHECK(parses("[1,2,3]", small));
    CHECK_FALSE(parses("[1,2,3,4]", small));
    // A limit that says why
    std::vector<char> scratch(4096);
    const std::string deep = std::string(40, '[');
    json::Reader reader(deep, {}, scratch);
    while (reader.next() != json::Event::error)
    {
    }
    CHECK(reader.error().category() == Category::limit);
}

TEST_CASE("json: skipping a value")
{
    const std::string text = R"({"skip":{"a":[1,{"b":2}],"c":"d"},"keep":3})";
    std::vector<char> scratch(4096);
    json::Reader reader(text, {}, scratch);
    REQUIRE(reader.next() == json::Event::object_begin);
    REQUIRE(reader.next() == json::Event::key);
    REQUIRE(reader.next() == json::Event::object_begin);
    const std::size_t begin = reader.token_begin();
    REQUIRE(reader.skip());
    CHECK(text.substr(begin, reader.position() - begin) == R"({"a":[1,{"b":2}],"c":"d"})");
    REQUIRE(reader.next() == json::Event::key);
    CHECK(reader.text() == "keep");
    REQUIRE(reader.next() == json::Event::number);
    CHECK(reader.next() == json::Event::object_end);
    CHECK(reader.next() == json::Event::end);
}

TEST_CASE("json: the DOM")
{
    const auto document = json::parse(R"({"schema":1,"items":[{"id":"a_1","size":734003200}],"next":null,
                                          "big":18446744073709551615,"neg":-3,"frac":1.5})");
    REQUIRE(document);
    const json::Value& root = document->root();
    REQUIRE(root.is_object());
    CHECK(root.members().size() == 6);
    CHECK(root.find("schema")->to_u64() == 1U);
    CHECK(root.find("big")->to_u64() == UINT64_MAX);
    CHECK(root.find("neg")->to_i64() == -3);
    CHECK_FALSE(root.find("neg")->to_u64());
    CHECK_FALSE(root.find("frac")->to_u64());
    CHECK(root.find("next")->kind() == json::Kind::null);
    CHECK(root.find("absent") == nullptr);
    const auto items = root.find("items")->items();
    REQUIRE(items.size() == 1);
    CHECK(items[0].find("id")->text() == "a_1");
    CHECK(document->memory_used() > 0);
}

TEST_CASE("json: the DOM stays within its memory budget")
{
    std::string text = "[";
    for (int i = 0; i < 2000; ++i)
        text += (i == 0 ? "" : ",") + std::string("\"lantern\"");
    text += "]";
    json::Limits limits;
    limits.max_memory   = 4096;
    const auto document = json::parse(text, limits);
    REQUIRE_FALSE(document);
    CHECK(document.error().category() == Category::memory);

    // What it takes from the resource, at most about its budget
    CountingResource counting;
    limits.max_memory  = 1 << 20;
    const auto bounded = json::parse(text, limits, &counting);
    REQUIRE(bounded);
    CHECK(counting.peak() <= limits.max_memory + 64 * 1024);
}

TEST_CASE("json: the writer escapes as Python's json.dumps(ensure_ascii=False)")
{
    String out;
    json::Writer writer(out);
    writer.begin_object();
    writer.key("path");
    writer.string("/switch/Fr\xC3\xB8stline \"one\"\\two\n\x01\x7F");
    writer.key("list");
    writer.begin_array();
    writer.number(std::uint64_t { 18446744073709551615U });
    writer.number(std::int64_t { -7 });
    writer.boolean(true);
    writer.null();
    writer.begin_object();
    writer.end_object();
    writer.end_array();
    writer.end_object();
    CHECK(out
        == "{\"path\":\"/switch/Fr\xC3\xB8stline "
           "\\\"one\\\"\\\\two\\n\\u0001\x7F\",\"list\":[18446744073709551615,-7,true,null,{}]}");

    // A DOM written back is the same document
    const auto document = json::parse(out);
    REQUIRE(document);
    String again;
    json::Writer(again).value(document->root());
    CHECK(again == out);
}
