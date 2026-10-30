// The tokenizer and the DOM on any bytes: no crash, no read out of bounds,
// within the limits; a document read back from its DOM reads the same.
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include <lantern/document.hpp>
#include <lantern/json.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    lantern::json::Limits limits;
    limits.max_memory = std::size_t { 16 } * 1024 * 1024;

    std::vector<char> scratch(limits.max_string);
    lantern::json::Reader reader(text, limits, scratch);
    std::size_t events = 0;
    for (;;)
    {
        const lantern::json::Event event = reader.next();
        if (event == lantern::json::Event::end || event == lantern::json::Event::error)
            break;
        if (reader.depth() > limits.max_depth || reader.text().size() > limits.max_string
            || ++events > size + 2)
            __builtin_trap();
    }

    const auto document = lantern::json::parse(text, limits);
    if (document)
    {
        lantern::String written;
        lantern::json::Writer(written).value(document->root());
        const auto again = lantern::json::parse(written, limits);
        if (!again)
            __builtin_trap();
        lantern::String twice;
        lantern::json::Writer(twice).value(again->root());
        if (twice != written)
            __builtin_trap();
    }
    static_cast<void>(lantern::peek_schema(text, limits));
    return 0;
}
