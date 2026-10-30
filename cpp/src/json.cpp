#include <lantern/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <system_error>
#include <utility>

namespace lantern::json
{

namespace
{

constexpr std::size_t max_depth_supported = 64;

bool is_digit(char c) noexcept
{
    return c >= '0' && c <= '9';
}

int hex_value(char c) noexcept
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

std::size_t encode_utf8(std::uint32_t code_point, std::array<char, 4>& out) noexcept
{
    if (code_point < 0x80U)
    {
        out[0] = static_cast<char>(code_point);
        return 1;
    }
    if (code_point < 0x800U)
    {
        out[0] = static_cast<char>(0xC0U | (code_point >> 6U));
        out[1] = static_cast<char>(0x80U | (code_point & 0x3FU));
        return 2;
    }
    if (code_point < 0x10000U)
    {
        out[0] = static_cast<char>(0xE0U | (code_point >> 12U));
        out[1] = static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU));
        out[2] = static_cast<char>(0x80U | (code_point & 0x3FU));
        return 3;
    }
    out[0] = static_cast<char>(0xF0U | (code_point >> 18U));
    out[1] = static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU));
    out[2] = static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU));
    out[3] = static_cast<char>(0x80U | (code_point & 0x3FU));
    return 4;
}

// The length of the well-formed UTF-8 sequence at `text[0]` (RFC 3629's
// table: no overlong form, no surrogate, nothing above U+10FFFF), or 0.
std::size_t utf8_sequence(std::string_view text) noexcept
{
    const auto byte = [&](std::size_t i) { return static_cast<unsigned char>(text[i]); };
    const auto in   = [&](std::size_t i, unsigned low, unsigned high)
    { return i < text.size() && byte(i) >= low && byte(i) <= high; };
    const unsigned lead = byte(0);
    if (lead >= 0xC2U && lead <= 0xDFU)
        return in(1, 0x80U, 0xBFU) ? 2 : 0;
    if (lead == 0xE0U)
        return in(1, 0xA0U, 0xBFU) && in(2, 0x80U, 0xBFU) ? 3 : 0;
    if ((lead >= 0xE1U && lead <= 0xECU) || lead == 0xEEU || lead == 0xEFU)
        return in(1, 0x80U, 0xBFU) && in(2, 0x80U, 0xBFU) ? 3 : 0;
    if (lead == 0xEDU)
        return in(1, 0x80U, 0x9FU) && in(2, 0x80U, 0xBFU) ? 3 : 0;
    if (lead == 0xF0U)
        return in(1, 0x90U, 0xBFU) && in(2, 0x80U, 0xBFU) && in(3, 0x80U, 0xBFU) ? 4 : 0;
    if (lead >= 0xF1U && lead <= 0xF3U)
        return in(1, 0x80U, 0xBFU) && in(2, 0x80U, 0xBFU) && in(3, 0x80U, 0xBFU) ? 4 : 0;
    if (lead == 0xF4U)
        return in(1, 0x80U, 0x8FU) && in(2, 0x80U, 0xBFU) && in(3, 0x80U, 0xBFU) ? 4 : 0;
    return 0;
}

} // namespace

Reader::Reader(std::string_view text, const Limits& limits, std::span<char> scratch) noexcept
    : input_(text)
    , limits_(limits)
    , scratch_(scratch)
{
    limits_.max_depth = std::min(limits_.max_depth, max_depth_supported);
    if (text.size() > limits_.max_document)
        static_cast<void>(error_event(Category::limit, "the document is larger than the limit"));
}

void Reader::fail(Category category, std::string_view detail) noexcept
{
    if (state_ != State::failed)
        static_cast<void>(error_event(category, detail));
}

Event Reader::error_event(Category category, std::string_view detail) noexcept
{
    error_ = Error::make(category, detail);
    state_ = State::failed;
    return Event::error;
}

void Reader::skip_space() noexcept
{
    while (pos_ < input_.size())
    {
        const char c = input_[pos_];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            return;
        ++pos_;
    }
}

Event Reader::next() noexcept
{
    if (state_ == State::failed)
        return Event::error;
    skip_space();
    token_            = pos_;
    const bool at_end = pos_ >= input_.size();
    const char c      = at_end ? '\0' : input_[pos_];
    switch (state_)
    {
        case State::value:
            return value();
        case State::first_value_or_close_array:
            return c == ']' ? close(false) : value();
        case State::comma_or_close_array:
            if (c == ']')
                return close(false);
            if (c != ',')
                return error_event(Category::invalid_response, "JSON: a comma or ] was expected");
            ++pos_;
            skip_space();
            token_ = pos_;
            return value();
        case State::first_key_or_close_object:
            return c == '}' ? close(true) : key();
        case State::comma_or_close_object:
            if (c == '}')
                return close(true);
            if (c != ',')
                return error_event(Category::invalid_response, "JSON: a comma or } was expected");
            ++pos_;
            skip_space();
            token_ = pos_;
            return key();
        case State::done:
            if (!at_end)
                return error_event(Category::invalid_response, "JSON: text after the document");
            return Event::end;
        case State::failed:
            break;
    }
    return Event::error;
}

Event Reader::after_value(Event event) noexcept
{
    if (depth_ == 0)
        state_ = State::done;
    else if (((kinds_ >> (depth_ - 1)) & 1U) != 0)
        state_ = State::comma_or_close_object;
    else
        state_ = State::comma_or_close_array;
    return event;
}

Event Reader::close(bool object) noexcept
{
    ++pos_;
    --depth_;
    return after_value(object ? Event::object_end : Event::array_end);
}

Event Reader::key() noexcept
{
    if (pos_ >= input_.size() || input_[pos_] != '"')
        return error_event(Category::invalid_response, "JSON: a key was expected");
    if (!string())
        return Event::error;
    skip_space();
    if (pos_ >= input_.size() || input_[pos_] != ':')
        return error_event(Category::invalid_response, "JSON: a colon was expected");
    ++pos_;
    state_ = State::value;
    return Event::key;
}

Event Reader::value() noexcept
{
    if (pos_ >= input_.size())
        return error_event(Category::invalid_response, "JSON: the document ends early");
    const char c = input_[pos_];
    switch (c)
    {
        case '{':
        case '[':
            if (depth_ >= limits_.max_depth)
                return error_event(Category::limit, "JSON: nested deeper than the limit");
            ++pos_;
            if (c == '{')
                kinds_ |= (std::uint64_t { 1 } << depth_);
            else
                kinds_ &= ~(std::uint64_t { 1 } << depth_);
            ++depth_;
            state_ = c == '{' ? State::first_key_or_close_object : State::first_value_or_close_array;
            return c == '{' ? Event::object_begin : Event::array_begin;
        case '"':
            return string() ? after_value(Event::string) : Event::error;
        case 't':
            boolean_ = true;
            return literal("true") ? after_value(Event::boolean) : Event::error;
        case 'f':
            boolean_ = false;
            return literal("false") ? after_value(Event::boolean) : Event::error;
        case 'n':
            return literal("null") ? after_value(Event::null) : Event::error;
        default:
            if (c == '-' || is_digit(c))
                return number() ? after_value(Event::number) : Event::error;
            return error_event(Category::invalid_response, "JSON: a value was expected");
    }
}

bool Reader::literal(std::string_view word) noexcept
{
    if (input_.substr(pos_, word.size()) != word)
    {
        static_cast<void>(error_event(Category::invalid_response, "JSON: an unknown word"));
        return false;
    }
    pos_ += word.size();
    return true;
}

bool Reader::number() noexcept
{
    const std::size_t begin = pos_;
    const auto digits       = [&]
    {
        const std::size_t from = pos_;
        while (pos_ < input_.size() && is_digit(input_[pos_]))
            ++pos_;
        return pos_ - from;
    };
    if (input_[pos_] == '-')
        ++pos_;
    if (pos_ < input_.size() && input_[pos_] == '0')
        ++pos_;
    else if (digits() == 0)
    {
        static_cast<void>(error_event(Category::invalid_response, "JSON: a malformed number"));
        return false;
    }
    if (pos_ < input_.size() && input_[pos_] == '.')
    {
        ++pos_;
        if (digits() == 0)
        {
            static_cast<void>(error_event(Category::invalid_response, "JSON: a malformed number"));
            return false;
        }
    }
    if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E'))
    {
        ++pos_;
        if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-'))
            ++pos_;
        if (digits() == 0)
        {
            static_cast<void>(error_event(Category::invalid_response, "JSON: a malformed number"));
            return false;
        }
    }
    if (pos_ - begin > limits_.max_string)
    {
        static_cast<void>(error_event(Category::limit, "JSON: a number longer than the limit"));
        return false;
    }
    text_ = input_.substr(begin, pos_ - begin);
    return true;
}

bool Reader::append(const char* bytes, std::size_t count) noexcept
{
    const std::size_t room = std::min(scratch_.size(), limits_.max_string);
    if (count > room - std::min(room, out_))
    {
        static_cast<void>(error_event(Category::limit, "JSON: a string longer than the limit"));
        return false;
    }
    std::memcpy(scratch_.data() + out_, bytes, count);
    out_ += count;
    return true;
}

bool Reader::string() noexcept
{
    ++pos_; // the opening quote
    const std::size_t begin = pos_;
    bool unescaped          = false;
    out_                    = 0;
    for (;;)
    {
        if (pos_ >= input_.size())
        {
            static_cast<void>(error_event(Category::invalid_response, "JSON: a string is not closed"));
            return false;
        }
        const auto c = static_cast<unsigned char>(input_[pos_]);
        if (c == '"')
            break;
        if (c < 0x20U)
        {
            static_cast<void>(
                error_event(Category::invalid_response, "JSON: a control character in a string"));
            return false;
        }
        if (c == '\\')
        {
            if (!unescaped)
            {
                unescaped = true;
                if (!append(input_.data() + begin, pos_ - begin))
                    return false;
            }
            if (pos_ + 1 >= input_.size())
            {
                static_cast<void>(error_event(Category::invalid_response, "JSON: a string is not closed"));
                return false;
            }
            const char escape = input_[pos_ + 1];
            char simple       = '\0';
            switch (escape)
            {
                case '"':
                    simple = '"';
                    break;
                case '\\':
                    simple = '\\';
                    break;
                case '/':
                    simple = '/';
                    break;
                case 'b':
                    simple = '\b';
                    break;
                case 'f':
                    simple = '\f';
                    break;
                case 'n':
                    simple = '\n';
                    break;
                case 'r':
                    simple = '\r';
                    break;
                case 't':
                    simple = '\t';
                    break;
                case 'u':
                    break;
                default:
                    static_cast<void>(error_event(Category::invalid_response, "JSON: an unknown escape"));
                    return false;
            }
            if (escape != 'u')
            {
                if (!append(&simple, 1))
                    return false;
                pos_ += 2;
                continue;
            }
            const auto hex4 = [&](std::size_t at) -> long
            {
                if (at + 4 > input_.size())
                    return -1;
                long value = 0;
                for (std::size_t k = 0; k < 4; ++k)
                {
                    const int digit = hex_value(input_[at + k]);
                    if (digit < 0)
                        return -1;
                    value = value * 16 + digit;
                }
                return value;
            };
            const long first = hex4(pos_ + 2);
            if (first < 0)
            {
                static_cast<void>(error_event(Category::invalid_response, "JSON: a malformed \\u escape"));
                return false;
            }
            auto code_point = static_cast<std::uint32_t>(first);
            pos_ += 6;
            if (code_point >= 0xDC00U && code_point <= 0xDFFFU)
            {
                static_cast<void>(error_event(Category::invalid_response, "JSON: a lone surrogate"));
                return false;
            }
            if (code_point >= 0xD800U && code_point <= 0xDBFFU)
            {
                const long second
                    = (pos_ + 1 < input_.size() && input_[pos_] == '\\' && input_[pos_ + 1] == 'u')
                    ? hex4(pos_ + 2)
                    : -1;
                if (second < 0xDC00 || second > 0xDFFF)
                {
                    static_cast<void>(error_event(Category::invalid_response, "JSON: a lone surrogate"));
                    return false;
                }
                code_point = 0x10000U + ((code_point - 0xD800U) << 10U)
                    + (static_cast<std::uint32_t>(second) - 0xDC00U);
                pos_ += 6;
            }
            std::array<char, 4> encoded {};
            if (!append(encoded.data(), encode_utf8(code_point, encoded)))
                return false;
            continue;
        }
        std::size_t length = 1;
        if (c >= 0x80U)
        {
            length = utf8_sequence(input_.substr(pos_));
            if (length == 0)
            {
                static_cast<void>(
                    error_event(Category::invalid_response, "JSON: a string that is not UTF-8"));
                return false;
            }
        }
        if (unescaped && !append(input_.data() + pos_, length))
            return false;
        pos_ += length;
    }
    if (unescaped)
        text_ = std::string_view(scratch_.data(), out_);
    else
    {
        if (pos_ - begin > limits_.max_string)
        {
            static_cast<void>(error_event(Category::limit, "JSON: a string longer than the limit"));
            return false;
        }
        text_ = input_.substr(begin, pos_ - begin);
    }
    ++pos_; // the closing quote
    return true;
}

bool Reader::skip() noexcept
{
    if (state_ == State::failed)
        return false;
    const bool container
        = state_ == State::first_key_or_close_object || state_ == State::first_value_or_close_array;
    if (!container)
        return true;
    const std::size_t target = depth_ - 1;
    for (;;)
    {
        const Event event = next();
        if (event == Event::error)
            return false;
        if ((event == Event::object_end || event == Event::array_end) && depth_ == target)
            return true;
    }
}

// The DOM.

std::optional<std::uint64_t> Value::to_u64() const noexcept
{
    if (kind_ != Kind::number)
        return std::nullopt;
    std::uint64_t out = 0;
    const char* end   = text_ + size_;
    const auto result = std::from_chars(text_, end, out);
    if (result.ec != std::errc {} || result.ptr != end)
        return std::nullopt;
    return out;
}

std::optional<std::int64_t> Value::to_i64() const noexcept
{
    if (kind_ != Kind::number)
        return std::nullopt;
    std::int64_t out  = 0;
    const char* end   = text_ + size_;
    const auto result = std::from_chars(text_, end, out);
    if (result.ec != std::errc {} || result.ptr != end)
        return std::nullopt;
    return out;
}

std::span<const Value> Value::items() const noexcept
{
    if (kind_ != Kind::array)
        return {};
    return { static_cast<const Value*>(items_), size_ };
}

std::span<const Member> Value::members() const noexcept
{
    if (kind_ != Kind::object)
        return {};
    return { static_cast<const Member*>(items_), size_ };
}

const Value* Value::find(std::string_view key) const noexcept
{
    for (const Member& member : members())
    {
        if (member.key == key)
            return &member.value;
    }
    return nullptr;
}

class Builder
{
  public:
    Builder(Document& document, Reader& reader, std::size_t memory_limit) noexcept
        : document_(document)
        , reader_(reader)
        , budget_(memory_limit)
    {
    }

    bool build(Event event, Value& out)
    {
        switch (event)
        {
            case Event::object_begin:
                return container(true, out);
            case Event::array_begin:
                return container(false, out);
            case Event::string:
                out.kind_ = Kind::string;
                return copy_text(out);
            case Event::number:
                out.kind_ = Kind::number;
                return copy_text(out);
            case Event::boolean:
                out.kind_    = Kind::boolean;
                out.boolean_ = reader_.boolean();
                return true;
            case Event::null:
                out.kind_ = Kind::null;
                return true;
            default:
                break;
        }
        if (!reader_.failed())
            reader_.fail(Category::invalid_response, "JSON: a value was expected");
        return false;
    }

    [[nodiscard]] std::size_t used() const noexcept { return budget_.used(); }

  private:
    void* take(std::size_t bytes, std::size_t alignment)
    {
        if (!budget_.charge(bytes + alignment))
        {
            reader_.fail(Category::memory, "JSON: the document needs more memory than the budget");
            return nullptr;
        }
        return document_.arena_.allocate(bytes, alignment);
    }

    bool copy_text(Value& out)
    {
        const std::string_view text = reader_.text();
        if (text.empty())
        {
            out.text_ = "";
            out.size_ = 0;
            return true;
        }
        auto* copy = static_cast<char*>(take(text.size(), 1));
        if (copy == nullptr)
            return false;
        std::memcpy(copy, text.data(), text.size());
        out.text_ = copy;
        out.size_ = text.size();
        return true;
    }

    bool container(bool object, Value& out)
    {
        out.kind_ = object ? Kind::object : Kind::array;
        // The items gathered on the resource, then copied once into the arena
        Vector<Member> members(document_.arena_.upstream());
        for (;;)
        {
            Event event = reader_.next();
            if (event == Event::object_end || event == Event::array_end)
                break;
            Member member;
            if (object)
            {
                if (event != Event::key)
                    return false;
                const std::string_view key = reader_.text();
                if (!key.empty())
                {
                    auto* copy = static_cast<char*>(take(key.size(), 1));
                    if (copy == nullptr)
                        return false;
                    std::memcpy(copy, key.data(), key.size());
                    member.key = std::string_view(copy, key.size());
                }
                event = reader_.next();
            }
            if (!budget_.charge(sizeof(Member)))
            {
                reader_.fail(Category::memory, "JSON: the document needs more memory than the budget");
                return false;
            }
            if (!build(event, member.value))
                return false;
            members.push_back(member);
        }
        if (reader_.failed())
            return false;
        out.size_ = members.size();
        if (members.empty())
            return true;
        if (object)
        {
            auto* copy = static_cast<Member*>(take(sizeof(Member) * members.size(), alignof(Member)));
            if (copy == nullptr)
                return false;
            std::ranges::uninitialized_copy(members, std::span(copy, members.size()));
            out.items_ = copy;
        }
        else
        {
            auto* copy = static_cast<Value*>(take(sizeof(Value) * members.size(), alignof(Value)));
            if (copy == nullptr)
                return false;
            for (std::size_t i = 0; i < members.size(); ++i)
                ::new (static_cast<void*>(copy + i)) Value(members[i].value);
            out.items_ = copy;
        }
        return true;
    }

    Document& document_;
    Reader& reader_;
    Budget budget_;
};

Result<Document> parse(std::string_view text, const Limits& limits, std::pmr::memory_resource* memory)
{
    Document document(memory);
    Vector<char> scratch(limits.max_string, memory);
    Reader reader(text, limits, scratch);
    Builder builder(document, reader, limits.max_memory);
    if (!builder.build(reader.next(), document.root_))
        return std::unexpected(reader.error());
    if (reader.next() != Event::end)
        return std::unexpected(reader.error());
    document.used_ = builder.used();
    return document;
}

// The writer.

void Writer::before_value()
{
    if (after_key_)
    {
        after_key_ = false;
        return;
    }
    if (depth_ == 0 || depth_ > max_depth_supported)
        return;
    const std::uint64_t bit = std::uint64_t { 1 } << (depth_ - 1);
    if ((has_items_ & bit) != 0)
        out_.push_back(',');
    has_items_ |= bit;
}

void Writer::open(char bracket)
{
    before_value();
    out_.push_back(bracket);
    if (depth_ < max_depth_supported)
        has_items_ &= ~(std::uint64_t { 1 } << depth_);
    ++depth_;
}

void Writer::close(char bracket)
{
    out_.push_back(bracket);
    if (depth_ > 0)
        --depth_;
}

void Writer::begin_object()
{
    open('{');
}
void Writer::end_object()
{
    close('}');
}
void Writer::begin_array()
{
    open('[');
}
void Writer::end_array()
{
    close(']');
}

void Writer::key(std::string_view name)
{
    before_value();
    escape(out_, name);
    out_.push_back(':');
    after_key_ = true;
}

void Writer::string(std::string_view text)
{
    before_value();
    escape(out_, text);
}

void Writer::number(std::uint64_t value)
{
    before_value();
    std::array<char, 24> buffer {};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    out_.append(buffer.data(), result.ptr);
}

void Writer::number(std::int64_t value)
{
    before_value();
    std::array<char, 24> buffer {};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    out_.append(buffer.data(), result.ptr);
}

void Writer::boolean(bool value)
{
    before_value();
    out_.append(value ? "true" : "false");
}

void Writer::null()
{
    before_value();
    out_.append("null");
}

void Writer::raw(std::string_view json)
{
    before_value();
    out_.append(json);
}

void Writer::value(const Value& value)
{
    switch (value.kind())
    {
        case Kind::null:
            null();
            return;
        case Kind::boolean:
            boolean(value.boolean());
            return;
        case Kind::number:
            raw(value.text());
            return;
        case Kind::string:
            string(value.text());
            return;
        case Kind::array:
            begin_array();
            for (const Value& item : value.items())
                this->value(item);
            end_array();
            return;
        case Kind::object:
            begin_object();
            for (const Member& member : value.members())
            {
                key(member.key);
                this->value(member.value);
            }
            end_object();
            return;
    }
}

void Writer::escape(String& out, std::string_view text)
{
    static constexpr std::string_view hex = "0123456789abcdef";
    out.push_back('"');
    for (const char c : text)
    {
        switch (c)
        {
            case '"':
                out.append("\\\"");
                break;
            case '\\':
                out.append("\\\\");
                break;
            case '\n':
                out.append("\\n");
                break;
            case '\r':
                out.append("\\r");
                break;
            case '\t':
                out.append("\\t");
                break;
            case '\b':
                out.append("\\b");
                break;
            case '\f':
                out.append("\\f");
                break;
            default:
            {
                const auto byte = static_cast<unsigned char>(c);
                if (byte < 0x20U)
                {
                    out.append("\\u00");
                    out.push_back(hex[byte >> 4U]);
                    out.push_back(hex[byte & 0x0FU]);
                }
                else
                    out.push_back(c);
            }
        }
    }
    out.push_back('"');
}

} // namespace lantern::json
