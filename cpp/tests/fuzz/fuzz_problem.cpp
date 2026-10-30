// A problem+json document from a server, any bytes: read, or refused, never
// a crash; what an Error keeps has no control character.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <lantern/types.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const auto read = lantern::read_problem(text);
    if (read && *read)
    {
        lantern::Error error = lantern::Error::from_status(static_cast<std::uint16_t>((*read)->status));
        error.set_code(lantern::code_from_name((*read)->code), (*read)->code);
        error.set_detail((*read)->detail);
        error.set_title((*read)->title);
        for (const char c : error.detail())
        {
            if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F)
                __builtin_trap();
        }
        static_cast<void>(error.effective_code());
    }
    return 0;
}
