// JSON: a pull tokenizer, a DOM built on it, and a writer. Our own, bounded
// by SPEC.md § 13 (document size, nesting depth 16, string length), strict
// RFC 8259 with every string checked as UTF-8 (overlong forms, surrogates
// and lone surrogate escapes refused).
//
// The tokenizer never allocates: a string with escapes is decoded into a
// scratch buffer the caller gives (at least Limits::max_string bytes), any
// other string is a view of the input. The generated readers bind documents
// straight from it into structs; the DOM is for what has no struct (the
// rewrite helper, the fuzzers, an app's own files).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <lantern/error.hpp>
#include <lantern/memory.hpp>

namespace lantern::json
{

// SPEC.md § 13. An app may lower them (a 3DS reads smaller documents); a
// value above the protocol's is the app's choice.
struct Limits
{
    std::size_t max_document = std::size_t { 32 } * 1024 * 1024; // bytes
    std::size_t max_depth    = 16; // objects and arrays open at once
    std::size_t max_string   = 4096; // bytes, after unescaping; keys too
    std::size_t max_memory   = std::size_t { 64 } * 1024 * 1024; // what one decode may allocate
};

enum class Event : std::uint8_t
{
    object_begin,
    object_end,
    array_begin,
    array_end,
    key, // text(): the key, unescaped
    string, // text(): the string, unescaped
    number, // text(): the number as written
    boolean, // boolean()
    null,
    end, // the document is complete
    error, // error() says why; every later call returns error again
};

class Reader
{
  public:
    // `scratch` holds an unescaped string; it should have max_string bytes.
    Reader(std::string_view text, const Limits& limits, std::span<char> scratch) noexcept;

    [[nodiscard]] Event next() noexcept;
    [[nodiscard]] std::string_view text() const noexcept { return text_; }
    [[nodiscard]] bool boolean() const noexcept { return boolean_; }
    // Objects and arrays open, the one just begun included.
    [[nodiscard]] std::size_t depth() const noexcept { return depth_; }
    // After next() returned the first event of a value (a scalar, or the
    // beginning of an object or array): moves past the whole value.
    [[nodiscard]] bool skip() noexcept;
    // Where the token of the last event begins, and where it ends: after
    // skip(), [token_begin(), position()) is the whole value's text.
    [[nodiscard]] std::size_t token_begin() const noexcept { return token_; }
    [[nodiscard]] std::size_t position() const noexcept { return pos_; }
    [[nodiscard]] std::string_view input() const noexcept { return input_; }
    [[nodiscard]] bool failed() const noexcept { return state_ == State::failed; }
    [[nodiscard]] const Error& error() const noexcept { return error_; }
    // Ends the reading with an error of the caller's (a binder's).
    void fail(Category category, std::string_view detail) noexcept;

  private:
    enum class State : std::uint8_t
    {
        value,
        first_value_or_close_array,
        comma_or_close_array,
        first_key_or_close_object,
        comma_or_close_object,
        done,
        failed,
    };

    Event value() noexcept;
    Event key() noexcept;
    Event close(bool object) noexcept;
    Event after_value(Event event) noexcept;
    Event error_event(Category category, std::string_view detail) noexcept;
    bool string() noexcept;
    bool number() noexcept;
    bool literal(std::string_view word) noexcept;
    bool append(const char* bytes, std::size_t count) noexcept;
    void skip_space() noexcept;

    std::string_view input_;
    Limits limits_;
    std::span<char> scratch_;
    std::size_t pos_     = 0;
    std::size_t token_   = 0;
    std::size_t depth_   = 0;
    std::uint64_t kinds_ = 0; // bit d: the container at depth d+1 is an object
    std::size_t out_     = 0;
    std::string_view text_;
    bool boolean_ = false;
    State state_  = State::value;
    Error error_;
};

// The DOM.

enum class Kind : std::uint8_t
{
    null,
    boolean,
    number,
    string,
    array,
    object,
};

struct Member;

class Value
{
  public:
    [[nodiscard]] Kind kind() const noexcept { return kind_; }
    [[nodiscard]] bool is_object() const noexcept { return kind_ == Kind::object; }
    [[nodiscard]] bool is_array() const noexcept { return kind_ == Kind::array; }
    [[nodiscard]] bool is_string() const noexcept { return kind_ == Kind::string; }
    [[nodiscard]] bool is_number() const noexcept { return kind_ == Kind::number; }
    [[nodiscard]] bool boolean() const noexcept { return boolean_; }
    // A string's text, unescaped; a number's text, as written.
    [[nodiscard]] std::string_view text() const noexcept { return { text_, size_ }; }
    // A number that is a whole number within the type, as written (no
    // fraction, no exponent).
    [[nodiscard]] std::optional<std::uint64_t> to_u64() const noexcept;
    [[nodiscard]] std::optional<std::int64_t> to_i64() const noexcept;
    [[nodiscard]] std::span<const Value> items() const noexcept;
    [[nodiscard]] std::span<const Member> members() const noexcept;
    // The first member of that name, or null.
    [[nodiscard]] const Value* find(std::string_view key) const noexcept;

  private:
    friend class Builder;
    Kind kind_         = Kind::null;
    bool boolean_      = false;
    const char* text_  = nullptr;
    std::size_t size_  = 0;
    const void* items_ = nullptr; // Value[] or Member[]
};

struct Member
{
    std::string_view key;
    Value value;
};

// A parsed document: its values live in its arena, freed with it.
class Document
{
  public:
    [[nodiscard]] const Value& root() const noexcept { return root_; }
    // What its nodes and strings took from the resource.
    [[nodiscard]] std::size_t memory_used() const noexcept { return used_; }

  private:
    friend class Builder;
    friend Result<Document> parse(
        std::string_view text, const Limits& limits, std::pmr::memory_resource* memory);
    explicit Document(std::pmr::memory_resource* memory) noexcept
        : arena_(memory)
    {
    }
    Arena arena_;
    Value root_;
    std::size_t used_ = 0;
};

[[nodiscard]] Result<Document> parse(std::string_view text, const Limits& limits = {},
    std::pmr::memory_resource* memory = std::pmr::get_default_resource());

// Writes compact JSON (no space), as SPEC.md § 8.2's canonical form wants:
// strings escaped as Python's json.dumps(ensure_ascii=False) escapes them,
// characters other than ASCII written as they are.
class Writer
{
  public:
    explicit Writer(String& out) noexcept
        : out_(out)
    {
    }

    void begin_object();
    void end_object();
    void begin_array();
    void end_array();
    void key(std::string_view name);
    void string(std::string_view text);
    void number(std::uint64_t value);
    void number(std::int64_t value);
    void boolean(bool value);
    void null();
    // A value already in JSON (as written by another writer or kept raw).
    void raw(std::string_view json);
    void value(const Value& value);

    static void escape(String& out, std::string_view text);

  private:
    void before_value();
    void open(char bracket);
    void close(char bracket);

    String& out_;
    std::uint64_t has_items_ = 0; // bit d: the container at depth d+1 has an item
    std::size_t depth_       = 0;
    bool after_key_          = false;
};

} // namespace lantern::json
