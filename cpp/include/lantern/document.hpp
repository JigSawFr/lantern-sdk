// Documents and the `schema` rule (SPEC.md § 3.2):
// - a reader ignores the fields it does not know;
// - a document of a `schema` higher than the reader knows is absent (the
//   feature is unavailable), never an error, and is never written back;
// - a document without `schema`, or with one that is not a positive
//   integer, breaks § 3.2 ("every document has an integer schema"): an
//   error of Category::invalid_response;
// - a document an app rewrites keeps the keys it does not know (rewrite()).
//
// Every generated reader (types.hpp) returns Read<T>: an error, or an
// optional that is empty for a newer `schema`.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

#include <lantern/error.hpp>
#include <lantern/json.hpp>
#include <lantern/memory.hpp>
#include <lantern/sha256.hpp>

namespace lantern
{

template <class T> using Read = Result<std::optional<T>>;

struct DecodeOptions
{
    json::Limits limits {};
    std::pmr::memory_resource* memory = std::pmr::get_default_resource();
};

// The `schema` of a JSON object document, without binding it: an error for
// a document that is not an object, or whose `schema` is missing or not a
// positive integer.
[[nodiscard]] Result<std::uint64_t> peek_schema(std::string_view text, const json::Limits& limits = {});

// What the generated readers bind with: the tokenizer, the allocator, the
// memory budget and the first error. Each binding call returns false on
// failure; error() then says why.
class BindContext
{
  public:
    BindContext(std::string_view text, const DecodeOptions& options, std::span<char> scratch) noexcept;

    [[nodiscard]] json::Reader& reader() noexcept { return reader_; }
    [[nodiscard]] Allocator allocator() const noexcept { return allocator_; }
    [[nodiscard]] const Error& error() const noexcept { return reader_.error(); }
    [[nodiscard]] bool failed() const noexcept { return reader_.failed(); }

    // Fails with "<type>.<field>: <why>".
    bool fail(Category category, std::string_view where, std::string_view why) noexcept;
    bool charge(std::size_t bytes) noexcept;

    // Reads the next event, which must begin an object.
    bool begin_object(std::string_view where) noexcept;
    // The next key of the object begun last; false at its end (failed()
    // tells an error from the end).
    bool next_key(std::string_view& key) noexcept;
    // Marks a known field as seen; false for a second one (a duplicate key).
    bool once(std::uint64_t& seen, unsigned bit, std::string_view where) noexcept;
    // Skips the value of a key this reader does not know.
    bool skip() noexcept;
    // Checks that the value of `schema` is a positive integer.
    bool schema_value(std::string_view where) noexcept;

    bool string(String& out, std::size_t max_bytes, std::string_view where);
    // A string, or null (left empty).
    bool nullable_string(String& out, std::size_t max_bytes, std::string_view where);
    bool u64(std::uint64_t& out, std::uint64_t min, std::uint64_t max, std::string_view where) noexcept;
    bool u64(std::optional<std::uint64_t>& out, std::uint64_t min, std::uint64_t max,
        std::string_view where) noexcept;
    bool i64(std::int64_t& out, std::int64_t min, std::int64_t max, std::string_view where) noexcept;
    bool i64(std::optional<std::int64_t>& out, std::int64_t min, std::int64_t max,
        std::string_view where) noexcept;
    bool boolean(bool& out, std::string_view where) noexcept;
    bool boolean(std::optional<bool>& out, std::string_view where) noexcept;
    // 64 lower-case hex digits (SPEC.md's form of a SHA-256).
    bool digest(Digest& out, std::string_view where) noexcept;
    bool digest(std::optional<Digest>& out, std::string_view where) noexcept;
    // The value's JSON text, as written, whatever it is.
    bool raw(String& out, std::string_view where);
    bool strings(Vector<String>& out, std::size_t max_items, std::size_t max_bytes, std::string_view where);
    bool integers(Vector<std::uint64_t>& out, std::size_t max_items, std::uint64_t min, std::uint64_t max,
        std::string_view where);

    // An array of objects (or anything `element` binds): `element(T&)` binds
    // one item; the next event is its first.
    template <class T, class Element>
    bool array(Vector<T>& out, std::size_t max_items, std::string_view where, Element element)
    {
        if (!begin_array(where))
            return false;
        for (;;)
        {
            if (!next_item(where))
                return !failed();
            if (out.size() >= max_items)
                return fail(Category::limit, where, "more items than the limit");
            if (!grow(out))
                return false;
            out.emplace_back();
            if (!element(out.back()))
                return false;
        }
    }

    // A member kept for a key this reader does not know, when the type asks
    // for its unknown members (additionalProperties).
    bool keep_member(Vector<std::pair<String, String>>& out, std::string_view key, std::string_view where);

    // The value's first event, for an element binder: the next event must
    // begin an object or an array, or be a scalar.
    bool begin_array(std::string_view where) noexcept;
    // Moves to the next item of the array begun last; false at its end.
    bool next_item(std::string_view where) noexcept;
    // An item already announced by next_item() must begin an object.
    bool item_object(std::string_view where) noexcept;

    template <class T> bool grow(Vector<T>& out)
    {
        if (out.size() < out.capacity())
            return true;
        const std::size_t capacity = out.capacity() < 4 ? 4 : out.capacity() * 2;
        if (!charge(capacity * sizeof(T)))
            return false;
        out.reserve(capacity);
        return true;
    }

  private:
    bool value_event(json::Event& event) noexcept;
    bool string_text(std::string_view& text, std::size_t max_bytes, std::string_view where) noexcept;

    json::Reader reader_;
    Allocator allocator_;
    Budget budget_;
    // An item announced by next_item(): its first event, already read
    json::Event pending_ = json::Event::end;
    bool has_pending_    = false;
};

// Reads a document: the `schema` first, then the binding. A newer `schema`
// gives an empty optional without binding anything.
template <class T, class Bind>
[[nodiscard]] Read<T> read_document(
    std::string_view text, std::uint64_t known_schema, const DecodeOptions& options, Bind bind)
{
    const auto schema = peek_schema(text, options.limits);
    if (!schema)
        return std::unexpected(schema.error());
    if (*schema > known_schema)
        return std::optional<T> {};
    Vector<char> scratch(options.limits.max_string, options.memory);
    BindContext context(text, options, scratch);
    T value(Allocator(options.memory));
    if (!bind(context, value))
        return std::unexpected(context.error());
    if (context.reader().next() != json::Event::end)
        return std::unexpected(context.error());
    return std::optional<T>(std::move(value));
}

// Rewriting a document the app keeps (its own file, or a document it sends
// back): the original's members are kept, in their order, unknown keys
// included; `patches` replace, add or remove members by key.
struct Patch
{
    std::string_view key;
    // The new value, as JSON (json::Writer writes it); nothing: remove the key.
    std::optional<std::string_view> json;
};

enum class MissingSchema : std::uint8_t
{
    error, // a protocol document: § 3.2 requires `schema`
    as_one, // a file of the app's that existed before it had `schema`
};

// The rewritten text; an empty optional when the original's `schema` is
// newer than `known_schema`: the app then MUST NOT write it (§ 3.2).
[[nodiscard]] Read<String> rewrite(std::string_view original, std::uint64_t known_schema,
    std::span<const Patch> patches, Allocator allocator, MissingSchema missing = MissingSchema::error,
    const json::Limits& limits = {});

} // namespace lantern
