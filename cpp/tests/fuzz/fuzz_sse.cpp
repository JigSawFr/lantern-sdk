// An event stream, any bytes in any cut (SPEC.md § 18.1): the parser never
// crashes, stays within its bounds whatever comes, and gives the same
// events whether the stream comes whole or a byte at a time. The first
// byte chooses the cut.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <lantern/events.hpp>

namespace
{

struct Recorder final : lantern::SseHandler
{
    std::vector<std::string> seen;
    bool on_event(const lantern::SseEvent& event) override
    {
        lantern::SseLimits limits;
        if (event.data.size() > limits.max_data || event.id.size() > limits.max_id || event.event.size() > 64)
            __builtin_trap();
        std::string entry(event.id);
        entry += '\x1f';
        entry += event.event;
        entry += '\x1f';
        entry += event.data;
        seen.push_back(std::move(entry));
        // Each event's document read as one of § 18.2's, or refused
        if (lantern::event_kind(event.event) == lantern::EventKind::library)
            static_cast<void>(lantern::read_library_event(event.data));
        else if (lantern::event_kind(event.event) == lantern::EventKind::request)
            static_cast<void>(lantern::read_request_event(event.data));
        else if (lantern::event_kind(event.event) == lantern::EventKind::shutdown)
            static_cast<void>(lantern::read_shutdown_event(event.data));
        return true;
    }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size == 0)
        return 0;
    const std::size_t step = 1 + data[0] % 17;
    const auto bytes       = std::as_bytes(std::span(data + 1, size - 1));

    lantern::SseParser whole;
    Recorder at_once;
    const auto first = whole.feed(bytes, at_once);

    lantern::SseParser cut;
    Recorder in_pieces;
    bool ok = true;
    for (std::size_t at = 0; at < bytes.size() && ok; at += step)
        ok = cut.feed(bytes.subspan(at, std::min(step, bytes.size() - at)), in_pieces).has_value();
    if (first.has_value() != ok || at_once.seen != in_pieces.seen
        || whole.last_event_id() != cut.last_event_id())
        __builtin_trap();
    return 0;
}
