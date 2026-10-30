// Server-Sent Events (the WHATWG HTML standard's event-stream
// interpretation), bounded, and the documents of SPEC.md § 18.2's events.
#include <lantern/events.hpp>

#include <algorithm>
#include <array>
#include <utility>

#include <lantern/json.hpp>

namespace lantern
{

namespace
{

constexpr std::array<std::string_view, 7> kind_names { "ready", "library", "request", "pairing", "save",
    "sync", "shutdown" };
constexpr std::array<std::uint8_t, 3> bom { 0xEFU, 0xBBU, 0xBFU };
constexpr std::uint32_t max_retry_ms = 24U * 3600U * 1000U;

} // namespace

SseParser::SseParser(Allocator allocator, const SseLimits& limits)
    : limits_(limits)
    , line_(allocator)
    , data_(allocator)
    , event_(allocator)
    , id_(allocator)
    , last_id_(allocator)
{
    // Once, at their bounds: a stream never makes them grow
    line_.reserve(limits_.max_line);
    data_.reserve(limits_.max_data);
    event_.reserve(64);
    id_.reserve(limits_.max_id);
    last_id_.reserve(limits_.max_id);
}

void SseParser::reset() noexcept
{
    line_.clear();
    data_.clear();
    event_.clear();
    id_.assign(last_id_);
    error_.reset();
    started_  = false;
    after_cr_ = false;
    stopped_  = false;
    bom_      = 0;
}

Result<void> SseParser::feed(std::span<const std::byte> bytes, SseHandler& handler)
{
    if (error_)
        return std::unexpected(*error_);
    for (const std::byte raw : bytes)
    {
        if (stopped_)
            return {};
        const auto byte = static_cast<std::uint8_t>(raw);
        if (!started_)
        {
            // One leading U+FEFF is not part of the stream
            if (byte == bom[bom_])
            {
                if (++bom_ == bom.size())
                {
                    started_ = true;
                    bom_     = 0;
                }
                continue;
            }
            started_ = true;
            // A partial BOM was text after all
            for (std::uint8_t i = 0; i < bom_; ++i)
                line_.push_back(static_cast<char>(bom[i]));
            bom_ = 0;
        }
        if (byte == '\n' && after_cr_)
        {
            after_cr_ = false; // CRLF: the line already ended at CR
            continue;
        }
        after_cr_ = byte == '\r';
        if (byte == '\r' || byte == '\n')
        {
            if (auto done = line(handler); !done)
            {
                error_ = done.error();
                return done;
            }
            line_.clear();
            continue;
        }
        if (line_.size() >= limits_.max_line)
        {
            error_ = Error::make(Category::limit, "an event stream's line above the limit");
            return std::unexpected(*error_);
        }
        line_.push_back(static_cast<char>(byte));
    }
    return {};
}

Result<void> SseParser::line(SseHandler& handler)
{
    const std::string_view text = line_;
    if (text.empty())
        return dispatch(handler);
    if (text.front() == ':')
    {
        if (!handler.on_comment(text.substr(1)))
            stopped_ = true;
        return {};
    }
    const std::size_t colon      = text.find(':');
    const std::string_view field = text.substr(0, colon);
    std::string_view value;
    if (colon != std::string_view::npos)
    {
        value = text.substr(colon + 1);
        if (value.starts_with(' '))
            value.remove_prefix(1);
    }
    if (field == "data")
    {
        if (value.size() + 1 > limits_.max_data - std::min(limits_.max_data, data_.size()))
            return fail(Category::limit, "an event's data above the limit (SPEC.md 13)");
        data_.append(value);
        data_.push_back('\n');
    }
    else if (field == "event")
    {
        if (value.size() > 64)
            return fail(Category::limit, "an event's name above 64 bytes");
        event_.assign(value);
    }
    else if (field == "id")
    {
        // An id with NUL is ignored, as the standard says
        if (!value.contains('\0'))
        {
            if (value.size() > limits_.max_id)
                return fail(Category::limit, "an event's id above the limit");
            id_.assign(value);
        }
    }
    else if (field == "retry")
    {
        if (!value.empty() && value.size() <= 9
            && std::ranges::all_of(value, [](char c) { return c >= '0' && c <= '9'; }))
        {
            std::uint32_t ms = 0;
            for (const char c : value)
                ms = ms * 10U + static_cast<std::uint32_t>(c - '0');
            handler.on_retry(std::min(ms, max_retry_ms));
        }
    }
    // Any other field is ignored
    return {};
}

Result<void> SseParser::dispatch(SseHandler& handler)
{
    last_id_.assign(id_);
    if (data_.empty())
    {
        event_.clear();
        return {};
    }
    data_.pop_back(); // the last line's LF
    SseEvent event;
    event.id        = last_id_;
    event.event     = event_.empty() ? std::string_view("message") : std::string_view(event_);
    event.data      = data_;
    const bool more = handler.on_event(event);
    data_.clear();
    event_.clear();
    if (!more)
        stopped_ = true;
    return {};
}

std::optional<EventKind> event_kind(std::string_view name) noexcept
{
    for (std::size_t i = 0; i < kind_names.size(); ++i)
    {
        if (kind_names[i] == name)
            return static_cast<EventKind>(i);
    }
    return std::nullopt;
}

std::string_view event_kind_name(EventKind kind) noexcept
{
    const auto index = static_cast<std::size_t>(kind);
    return index < kind_names.size() ? kind_names[index] : std::string_view {};
}

void EventStreamState::set_last_id(std::string_view id) noexcept
{
    if (id.size() > last_id.size())
        return; // an id above the bound is not one the parser gives
    std::ranges::copy(id, last_id.begin());
    last_id_size = id.size();
}

std::chrono::milliseconds EventStreamState::reconnect_delay(double jitter) const noexcept
{
    constexpr std::uint64_t cap = std::uint64_t { 5 } * 60 * 1000;
    std::uint64_t delay         = retry_ms;
    if (failures > 0)
    {
        const std::uint64_t base  = std::max<std::uint64_t>(retry_ms, 1000);
        const std::uint32_t steps = std::min<std::uint32_t>(failures, 16);
        delay                     = std::min(cap, base << steps);
        const double spread       = std::clamp(jitter, 0.0, 1.0);
        delay = std::min(cap, delay + static_cast<std::uint64_t>(static_cast<double>(delay) * spread / 2));
    }
    return std::chrono::milliseconds(
        static_cast<std::chrono::milliseconds::rep>(std::max<std::uint64_t>(delay, retry_ms)));
}

// The events' documents, read through the DOM: small, and of several forms.
namespace
{

// The parsed document of an event, or nothing for a newer schema.
Result<std::optional<json::Document>> parse_event(std::string_view data, const DecodeOptions& options)
{
    json::Limits limits = options.limits;
    limits.max_document = std::min<std::size_t>(limits.max_document, std::size_t { 8 } * 1024);
    const auto schema   = peek_schema(data, limits);
    if (!schema)
        return std::unexpected(schema.error());
    if (*schema > 1)
        return std::optional<json::Document> {};
    auto parsed = json::parse(data, limits, options.memory);
    if (!parsed)
        return std::unexpected(parsed.error());
    return std::optional<json::Document>(std::move(*parsed));
}

bool take_string(const json::Value& root, std::string_view key, String& out, bool required)
{
    const json::Value* value = root.find(key);
    if (value == nullptr)
        return !required;
    if (!value->is_string() || value->text().size() > 4096)
        return false;
    out.assign(value->text());
    return true;
}

bool take_strings(const json::Value& root, std::string_view key, Vector<String>& out)
{
    const json::Value* value = root.find(key);
    if (value == nullptr || !value->is_array() || value->items().empty() || value->items().size() > 64)
        return false;
    for (const json::Value& item : value->items())
    {
        if (!item.is_string() || item.text().empty() || item.text().size() > 64)
            return false;
        out.emplace_back(item.text());
    }
    return true;
}

Error bad_event(std::string_view what)
{
    return Error::make(Category::invalid_response, what);
}

} // namespace

Read<LibraryEvent> read_library_event(std::string_view data, const DecodeOptions& options)
{
    auto parsed = parse_event(data, options);
    if (!parsed)
        return std::unexpected(parsed.error());
    if (!*parsed)
        return std::optional<LibraryEvent> {};
    const json::Value& root = (*parsed)->root();
    LibraryEvent out(Allocator(options.memory));
    if (!take_strings(root, "families", out.families) || !take_strings(root, "platforms", out.platforms))
        return std::unexpected(
            bad_event("a library event without its families and platforms (SPEC.md 18.2)"));
    return std::optional<LibraryEvent>(std::move(out));
}

Read<RequestEvent> read_request_event(std::string_view data, const DecodeOptions& options)
{
    auto parsed = parse_event(data, options);
    if (!parsed)
        return std::unexpected(parsed.error());
    if (!*parsed)
        return std::optional<RequestEvent> {};
    const json::Value& root = (*parsed)->root();
    RequestEvent out(Allocator(options.memory));
    const json::Value* deleted = root.find("deleted");
    out.deleted = deleted != nullptr && deleted->kind() == json::Kind::boolean && deleted->boolean();
    if (!take_string(root, "id", out.id, true) || out.id.empty()
        || !take_string(root, "platform", out.platform, false)
        || !take_string(root, "title_id", out.title_id, false)
        || !take_string(root, "status", out.status, false) || (out.status.empty() == !out.deleted))
        return std::unexpected(
            bad_event("a request event without its id, and a status or deleted (SPEC.md 18.2)"));
    return std::optional<RequestEvent>(std::move(out));
}

Read<PairingEvent> read_pairing_event(std::string_view data, const DecodeOptions& options)
{
    auto parsed = parse_event(data, options);
    if (!parsed)
        return std::unexpected(parsed.error());
    if (!*parsed)
        return std::optional<PairingEvent> {};
    const json::Value& root = (*parsed)->root();
    PairingEvent out(Allocator(options.memory));
    if (!take_string(root, "id", out.id, true) || !take_string(root, "code", out.code, true)
        || !take_string(root, "device", out.device, true) || !take_string(root, "key", out.key, false)
        || !take_string(root, "expires", out.expires, true))
        return std::unexpected(
            bad_event("a pairing event without its id, code, device and expiry (SPEC.md 18.2)"));
    return std::optional<PairingEvent>(std::move(out));
}

Read<SaveEvent> read_save_event(std::string_view data, const DecodeOptions& options)
{
    auto parsed = parse_event(data, options);
    if (!parsed)
        return std::unexpected(parsed.error());
    if (!*parsed)
        return std::optional<SaveEvent> {};
    const json::Value& root = (*parsed)->root();
    SaveEvent out(Allocator(options.memory));
    if (!take_string(root, "platform", out.platform, true)
        || !take_string(root, "title_id", out.title_id, true)
        || !take_string(root, "save_id", out.save_id, true)
        || !take_string(root, "created", out.created, false)
        || !take_string(root, "device", out.device, false))
        return std::unexpected(bad_event("a save event without its platform, title and save (SPEC.md 18.2)"));
    return std::optional<SaveEvent>(std::move(out));
}

Read<SyncEvent> read_sync_event(std::string_view data, const DecodeOptions& options)
{
    auto parsed = parse_event(data, options);
    if (!parsed)
        return std::unexpected(parsed.error());
    if (!*parsed)
        return std::optional<SyncEvent> {};
    const json::Value& root = (*parsed)->root();
    SyncEvent out(Allocator(options.memory));
    const json::Value* rev = root.find("rev");
    const auto number      = rev != nullptr && rev->is_number() ? rev->to_u64() : std::nullopt;
    if (!take_string(root, "collection", out.collection, true) || out.collection.empty() || !number)
        return std::unexpected(bad_event("a sync event without its collection and rev (SPEC.md 18.2)"));
    out.rev = *number;
    return std::optional<SyncEvent>(std::move(out));
}

Read<ShutdownEvent> read_shutdown_event(std::string_view data, const DecodeOptions& options)
{
    auto parsed = parse_event(data, options);
    if (!parsed)
        return std::unexpected(parsed.error());
    if (!*parsed)
        return std::optional<ShutdownEvent> {};
    const json::Value& root = (*parsed)->root();
    ShutdownEvent out(Allocator(options.memory));
    if (const json::Value* retry = root.find("retry"); retry != nullptr)
    {
        const auto number = retry->is_number() ? retry->to_u64() : std::nullopt;
        if (!number)
            return std::unexpected(bad_event("a shutdown event whose retry is not a whole number"));
        out.retry = number;
    }
    return std::optional<ShutdownEvent>(std::move(out));
}

} // namespace lantern
