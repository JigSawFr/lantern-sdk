#include <lantern/document.hpp>

#include <algorithm>
#include <charconv>
#include <limits>
#include <system_error>

namespace lantern
{

namespace
{

// "<where>: <why>", cut to what an Error keeps.
void compose(
    std::array<char, 200>& buffer, std::size_t& size, std::string_view where, std::string_view why) noexcept
{
    size           = 0;
    const auto put = [&](std::string_view part)
    {
        const std::size_t n = std::min(part.size(), buffer.size() - size);
        std::copy_n(part.data(), n, buffer.data() + size);
        size += n;
    };
    put(where);
    put(": ");
    put(why);
}

template <class Integer> bool parse_integer(std::string_view text, Integer& out) noexcept
{
    const char* end   = text.data() + text.size();
    const auto result = std::from_chars(text.data(), end, out);
    return result.ec == std::errc {} && result.ptr == end;
}

} // namespace

Result<std::uint64_t> peek_schema(std::string_view text, const json::Limits& limits)
{
    Vector<char> scratch(limits.max_string, std::pmr::get_default_resource());
    json::Reader reader(text, limits, scratch);
    json::Event event = reader.next();
    if (event == json::Event::error)
        return std::unexpected(reader.error());
    if (event != json::Event::object_begin)
        return fail(Category::invalid_response, "the document is not a JSON object");
    std::optional<std::uint64_t> schema;
    for (;;)
    {
        event = reader.next();
        if (event == json::Event::object_end)
            break;
        if (event != json::Event::key)
            return std::unexpected(reader.error());
        if (reader.text() != "schema")
        {
            if (reader.next() == json::Event::error || !reader.skip())
                return std::unexpected(reader.error());
            continue;
        }
        if (schema)
            return fail(Category::invalid_response, "the document has two schema members");
        if (reader.next() != json::Event::number)
        {
            if (reader.failed())
                return std::unexpected(reader.error());
            return fail(Category::invalid_response, "schema is not an integer");
        }
        std::uint64_t value = 0;
        if (!parse_integer(reader.text(), value) || value == 0)
            return fail(Category::invalid_response, "schema is not a positive integer");
        schema = value;
    }
    if (reader.next() != json::Event::end)
        return std::unexpected(reader.error());
    if (!schema)
        return fail(Category::invalid_response, "the document has no schema (SPEC.md 3.2)");
    return *schema;
}

BindContext::BindContext(
    std::string_view text, const DecodeOptions& options, std::span<char> scratch) noexcept
    : reader_(text, options.limits, scratch)
    , allocator_(options.memory)
    , budget_(options.limits.max_memory)
{
}

bool BindContext::fail(Category category, std::string_view where, std::string_view why) noexcept
{
    std::array<char, 200> buffer {};
    std::size_t size = 0;
    compose(buffer, size, where, why);
    reader_.fail(category, std::string_view(buffer.data(), size));
    return false;
}

bool BindContext::charge(std::size_t bytes) noexcept
{
    if (budget_.charge(bytes))
        return true;
    reader_.fail(Category::memory, "the document needs more memory than the budget");
    return false;
}

bool BindContext::value_event(json::Event& event) noexcept
{
    if (has_pending_)
    {
        has_pending_ = false;
        event        = pending_;
    }
    else
        event = reader_.next();
    return event != json::Event::error;
}

bool BindContext::begin_object(std::string_view where) noexcept
{
    json::Event event {};
    if (!value_event(event))
        return false;
    if (event != json::Event::object_begin)
        return fail(Category::invalid_response, where, "not an object");
    return true;
}

bool BindContext::next_key(std::string_view& key) noexcept
{
    const json::Event event = reader_.next();
    if (event == json::Event::key)
    {
        key = reader_.text();
        return true;
    }
    return false;
}

bool BindContext::once(std::uint64_t& seen, unsigned bit, std::string_view where) noexcept
{
    const std::uint64_t mask = std::uint64_t { 1 } << bit;
    if ((seen & mask) != 0)
        return fail(Category::invalid_response, where, "the key appears twice");
    seen |= mask;
    return true;
}

bool BindContext::skip() noexcept
{
    json::Event event {};
    if (!value_event(event))
        return false;
    return reader_.skip();
}

bool BindContext::schema_value(std::string_view where) noexcept
{
    json::Event event {};
    if (!value_event(event))
        return false;
    std::uint64_t value = 0;
    if (event != json::Event::number || !parse_integer(reader_.text(), value) || value == 0)
        return fail(Category::invalid_response, where, "schema is not a positive integer");
    return true;
}

bool BindContext::string_text(std::string_view& text, std::size_t max_bytes, std::string_view where) noexcept
{
    json::Event event {};
    if (!value_event(event))
        return false;
    if (event != json::Event::string)
        return fail(Category::invalid_response, where, "not a string");
    text = reader_.text();
    if (text.size() > max_bytes)
        return fail(Category::limit, where, "longer than the limit");
    return true;
}

bool BindContext::string(String& out, std::size_t max_bytes, std::string_view where)
{
    std::string_view text;
    if (!string_text(text, max_bytes, where) || !charge(text.size() + 1))
        return false;
    out.assign(text);
    return true;
}

bool BindContext::nullable_string(String& out, std::size_t max_bytes, std::string_view where)
{
    json::Event event {};
    if (!value_event(event))
        return false;
    if (event == json::Event::null)
    {
        out.clear();
        return true;
    }
    pending_     = event;
    has_pending_ = true;
    return string(out, max_bytes, where);
}

bool BindContext::u64(
    std::uint64_t& out, std::uint64_t min, std::uint64_t max, std::string_view where) noexcept
{
    json::Event event {};
    if (!value_event(event))
        return false;
    if (event != json::Event::number || !parse_integer(reader_.text(), out))
        return fail(Category::invalid_response, where, "not an integer of its range");
    if (out < min || out > max)
        return fail(Category::invalid_response, where, "outside its range");
    return true;
}

bool BindContext::u64(
    std::optional<std::uint64_t>& out, std::uint64_t min, std::uint64_t max, std::string_view where) noexcept
{
    std::uint64_t value = 0;
    if (!u64(value, min, max, where))
        return false;
    out = value;
    return true;
}

bool BindContext::i64(std::int64_t& out, std::int64_t min, std::int64_t max, std::string_view where) noexcept
{
    json::Event event {};
    if (!value_event(event))
        return false;
    if (event != json::Event::number || !parse_integer(reader_.text(), out))
        return fail(Category::invalid_response, where, "not an integer of its range");
    if (out < min || out > max)
        return fail(Category::invalid_response, where, "outside its range");
    return true;
}

bool BindContext::i64(
    std::optional<std::int64_t>& out, std::int64_t min, std::int64_t max, std::string_view where) noexcept
{
    std::int64_t value = 0;
    if (!i64(value, min, max, where))
        return false;
    out = value;
    return true;
}

bool BindContext::boolean(bool& out, std::string_view where) noexcept
{
    json::Event event {};
    if (!value_event(event))
        return false;
    if (event != json::Event::boolean)
        return fail(Category::invalid_response, where, "not a boolean");
    out = reader_.boolean();
    return true;
}

bool BindContext::boolean(std::optional<bool>& out, std::string_view where) noexcept
{
    bool value = false;
    if (!boolean(value, where))
        return false;
    out = value;
    return true;
}

bool BindContext::digest(Digest& out, std::string_view where) noexcept
{
    std::string_view text;
    if (!string_text(text, 64, where))
        return false;
    const auto digest = digest_from_hex(text);
    if (!digest)
        return fail(Category::invalid_response, where, "not a SHA-256 in lower-case hex");
    out = *digest;
    return true;
}

bool BindContext::digest(std::optional<Digest>& out, std::string_view where) noexcept
{
    Digest value {};
    if (!digest(value, where))
        return false;
    out = value;
    return true;
}

bool BindContext::raw(String& out, std::string_view where)
{
    json::Event event {};
    if (!value_event(event))
        return false;
    if (event == json::Event::object_end || event == json::Event::array_end || event == json::Event::key)
        return fail(Category::invalid_response, where, "a value was expected");
    const std::size_t begin = reader_.token_begin();
    if (!reader_.skip())
        return false;
    const std::string_view text = reader_.input().substr(begin, reader_.position() - begin);
    if (!charge(text.size() + 1))
        return false;
    out.assign(text);
    return true;
}

bool BindContext::begin_array(std::string_view where) noexcept
{
    json::Event event {};
    if (!value_event(event))
        return false;
    if (event != json::Event::array_begin)
        return fail(Category::invalid_response, where, "not an array");
    return true;
}

bool BindContext::next_item(std::string_view /*where*/) noexcept
{
    const json::Event event = reader_.next();
    if (event == json::Event::array_end || event == json::Event::error)
        return false;
    pending_     = event;
    has_pending_ = true;
    return true;
}

bool BindContext::item_object(std::string_view where) noexcept
{
    return begin_object(where);
}

bool BindContext::strings(
    Vector<String>& out, std::size_t max_items, std::size_t max_bytes, std::string_view where)
{
    return array(out, max_items, where, [&](String& item) { return string(item, max_bytes, where); });
}

bool BindContext::integers(Vector<std::uint64_t>& out, std::size_t max_items, std::uint64_t min,
    std::uint64_t max, std::string_view where)
{
    return array(out, max_items, where, [&](std::uint64_t& item) { return u64(item, min, max, where); });
}

bool BindContext::keep_member(
    Vector<std::pair<String, String>>& out, std::string_view key, std::string_view where)
{
    if (!grow(out) || !charge(key.size() + 1))
        return false;
    // The key is in the tokenizer's scratch: copied before the value is read
    out.emplace_back();
    out.back().first.assign(key);
    return raw(out.back().second, where);
}

Read<String> rewrite(std::string_view original, std::uint64_t known_schema, std::span<const Patch> patches,
    Allocator allocator, MissingSchema missing, const json::Limits& limits)
{
    auto document = json::parse(original, limits, allocator.resource());
    if (!document)
        return std::unexpected(document.error());
    const json::Value& root = document->root();
    if (!root.is_object())
        return fail(Category::invalid_response, "the document is not a JSON object");
    const json::Value* schema = root.find("schema");
    if (schema == nullptr)
    {
        if (missing == MissingSchema::error)
            return fail(Category::invalid_response, "the document has no schema (SPEC.md 3.2)");
    }
    else
    {
        const auto value = schema->to_u64();
        if (!value || *value == 0)
            return fail(Category::invalid_response, "schema is not a positive integer");
        if (*value > known_schema)
            return std::optional<String> {};
    }
    for (const Patch& patch : patches)
    {
        if (patch.json && !json::parse(*patch.json, limits, allocator.resource()))
            return fail(Category::usage, "a patch's value is not JSON");
    }
    String out(allocator);
    out.reserve(original.size() + 64);
    json::Writer writer(out);
    const auto patch_for = [&](std::string_view key) -> const Patch*
    {
        for (const Patch& patch : patches)
        {
            if (patch.key == key)
                return &patch;
        }
        return nullptr;
    };
    writer.begin_object();
    for (const json::Member& member : root.members())
    {
        const Patch* patch = patch_for(member.key);
        if (patch == nullptr)
        {
            writer.key(member.key);
            writer.value(member.value);
        }
        else if (patch->json)
        {
            writer.key(member.key);
            writer.raw(*patch->json);
        }
    }
    for (std::size_t i = 0; i < patches.size(); ++i)
    {
        const Patch& patch = patches[i];
        const bool earlier = std::any_of(patches.begin(), patches.begin() + static_cast<std::ptrdiff_t>(i),
            [&](const Patch& other) { return other.key == patch.key; });
        if (patch.json && root.find(patch.key) == nullptr && !earlier)
        {
            writer.key(patch.key);
            writer.raw(*patch.json);
        }
    }
    writer.end_object();
    return std::optional<String>(std::move(out));
}

} // namespace lantern
