// SPEC.md § 2.3: canonical JSON, RFC 8785's scheme.
#include <lantern/canonical.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace lantern
{

namespace
{

constexpr long long exponent_clamp = 1000000000LL;
// Up to this many significant digits, the shortest form that reads back
// the same double is the digits themselves (a double holds 15 for sure),
// in the range where doubles are normal.
constexpr std::size_t exact_digits = 15;
constexpr long long exact_exponent = 290;
constexpr int max_double_digits    = 17;
constexpr long long es_fixed_limit = 21;
constexpr long long es_small_limit = -6;

bool is_digit(char c) noexcept
{
    return c >= '0' && c <= '9';
}

// A number's significant digits D (no leading nor trailing zero) and n,
// where the value is 0.D x 10^n; D empty for zero.
struct Decimal
{
    bool negative = false;
    String digits;
    long long exponent = 0;

    explicit Decimal(const Allocator& allocator)
        : digits(allocator)
    {
    }
};

// JSON's number: -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?
bool parse_decimal(std::string_view text, Decimal& out)
{
    std::size_t i = 0;
    if (i < text.size() && text[i] == '-')
    {
        out.negative = true;
        ++i;
    }
    const std::size_t int_begin = i;
    while (i < text.size() && is_digit(text[i]))
        ++i;
    const std::size_t int_digits = i - int_begin;
    if (int_digits == 0 || (text[int_begin] == '0' && int_digits > 1))
        return false;
    String all(out.digits.get_allocator());
    all.append(text.substr(int_begin, int_digits));
    long long point = static_cast<long long>(int_digits);
    if (i < text.size() && text[i] == '.')
    {
        ++i;
        const std::size_t frac_begin = i;
        while (i < text.size() && is_digit(text[i]))
            ++i;
        if (i == frac_begin)
            return false;
        all.append(text.substr(frac_begin, i - frac_begin));
    }
    if (i < text.size() && (text[i] == 'e' || text[i] == 'E'))
    {
        ++i;
        bool negative_exponent = false;
        if (i < text.size() && (text[i] == '+' || text[i] == '-'))
        {
            negative_exponent = text[i] == '-';
            ++i;
        }
        const std::size_t exp_begin = i;
        long long exponent          = 0;
        while (i < text.size() && is_digit(text[i]))
        {
            exponent = std::min(exponent * 10 + (text[i] - '0'), exponent_clamp);
            ++i;
        }
        if (i == exp_begin)
            return false;
        point += negative_exponent ? -exponent : exponent;
    }
    if (i != text.size())
        return false;
    const std::size_t first = all.find_first_not_of('0');
    if (first == String::npos)
        return true; // zero
    const std::size_t last = all.find_last_not_of('0');
    out.digits.assign(all, first, last - first + 1);
    out.exponent = point - static_cast<long long>(first);
    return true;
}

// The shortest digits and exponent that read back as `x` (positive, finite).
void shortest_digits(double x, Decimal& out)
{
    std::array<char, 40> text {};
    for (int precision = 1; precision <= max_double_digits; ++precision)
    {
        static_cast<void>(std::snprintf(text.data(), text.size(), "%.*e", precision - 1, x));
        if (std::strtod(text.data(), nullptr) == x || precision == max_double_digits)
            break;
    }
    // d[.ddd]e[+-]xx, whatever the locale's point
    out.digits.clear();
    const std::string_view view(text.data());
    std::size_t i = 0;
    while (i < view.size() && view[i] != 'e' && view[i] != 'E')
    {
        if (is_digit(view[i]))
            out.digits.push_back(view[i]);
        ++i;
    }
    const long long exponent = i < view.size() ? std::strtoll(text.data() + i + 1, nullptr, 10) : 0;
    const std::size_t last   = out.digits.find_last_not_of('0');
    out.digits.resize(last == String::npos ? 0 : last + 1);
    out.exponent = exponent + 1;
}

// A UTF-8 string as UTF-16 code units, one at a time.
class Utf16Units
{
  public:
    explicit Utf16Units(std::string_view text) noexcept
        : text_(text)
    {
    }

    // 0x10000 for the end (no code unit is that large).
    unsigned next() noexcept
    {
        if (low_ != 0)
        {
            const unsigned unit = low_;
            low_                = 0;
            return unit;
        }
        if (pos_ >= text_.size())
            return end;
        const auto lead = static_cast<unsigned char>(text_[pos_]);
        unsigned length = 1;
        unsigned point  = lead;
        if (lead >= 0xF0U)
        {
            length = 4;
            point  = lead & 0x07U;
        }
        else if (lead >= 0xE0U)
        {
            length = 3;
            point  = lead & 0x0FU;
        }
        else if (lead >= 0xC0U)
        {
            length = 2;
            point  = lead & 0x1FU;
        }
        for (unsigned k = 1; k < length && pos_ + k < text_.size(); ++k)
            point = (point << 6U) | (static_cast<unsigned char>(text_[pos_ + k]) & 0x3FU);
        pos_ += length;
        if (point >= 0x10000U)
        {
            point -= 0x10000U;
            low_ = 0xDC00U + (point & 0x3FFU);
            return 0xD800U + (point >> 10U);
        }
        return point;
    }

    static constexpr unsigned end = 0x10000U;

  private:
    std::string_view text_;
    std::size_t pos_ = 0;
    unsigned low_    = 0;
};

// RFC 8785 § 3.2.3: names compared as sequences of UTF-16 code units.
bool utf16_less(std::string_view a, std::string_view b) noexcept
{
    Utf16Units left(a);
    Utf16Units right(b);
    for (;;)
    {
        const unsigned x = left.next();
        const unsigned y = right.next();
        if (x != y)
            return x < y;
        if (x == Utf16Units::end)
            return false;
    }
}

Result<void> write_value(const json::Value& value, String& out, Allocator allocator, std::size_t depth)
{
    if (depth > 64)
        return fail(Category::limit, "a document nested too deep to canonicalize");
    switch (value.kind())
    {
        case json::Kind::object:
        {
            Vector<const json::Member*> members(allocator);
            members.reserve(value.members().size());
            for (const json::Member& member : value.members())
                members.push_back(&member);
            std::ranges::sort(members,
                [](const json::Member* a, const json::Member* b) { return utf16_less(a->key, b->key); });
            out.push_back('{');
            for (std::size_t i = 0; i < members.size(); ++i)
            {
                if (i != 0)
                {
                    if (members[i - 1]->key == members[i]->key)
                        return fail(
                            Category::invalid_response, "an object with a key twice has no canonical form");
                    out.push_back(',');
                }
                json::Writer::escape(out, members[i]->key);
                out.push_back(':');
                if (auto done = write_value(members[i]->value, out, allocator, depth + 1); !done)
                    return done;
            }
            out.push_back('}');
            return {};
        }
        case json::Kind::array:
        {
            out.push_back('[');
            bool first = true;
            for (const json::Value& item : value.items())
            {
                if (!first)
                    out.push_back(',');
                first = false;
                if (auto done = write_value(item, out, allocator, depth + 1); !done)
                    return done;
            }
            out.push_back(']');
            return {};
        }
        case json::Kind::string:
            json::Writer::escape(out, value.text());
            return {};
        case json::Kind::number:
            return canonical_number(value.text(), out);
        case json::Kind::boolean:
            out.append(value.boolean() ? "true" : "false");
            return {};
        case json::Kind::null:
            out.append("null");
            return {};
    }
    return {};
}

} // namespace

Result<void> canonical_number(std::string_view number, String& out)
{
    Decimal decimal(out.get_allocator());
    if (!parse_decimal(number, decimal))
        return fail(Category::invalid_response, "not a JSON number");
    if (decimal.digits.empty())
    {
        out.push_back('0');
        return {};
    }
    const bool simple = decimal.digits.size() <= exact_digits && decimal.exponent > -exact_exponent
        && decimal.exponent < exact_exponent;
    if (!simple)
    {
        // The double nearest to the number, then its shortest form
        String text(decimal.digits, decimal.digits.get_allocator());
        text.push_back('e');
        text.append(std::to_string(decimal.exponent - static_cast<long long>(decimal.digits.size())));
        const double x = std::strtod(text.c_str(), nullptr);
        if (std::isinf(x))
            return fail(Category::invalid_response, "a number beyond a double's range is not I-JSON");
        if (x == 0.0)
        {
            out.push_back('0');
            return {};
        }
        shortest_digits(x, decimal);
    }
    // ECMAScript's Number::toString, with k digits and the value 0.D x 10^n
    const std::string_view digits = decimal.digits;
    const auto k                  = static_cast<long long>(digits.size());
    const long long n             = decimal.exponent;
    if (decimal.negative)
        out.push_back('-');
    if (k <= n && n <= es_fixed_limit)
    {
        out.append(digits);
        out.append(static_cast<std::size_t>(n - k), '0');
    }
    else if (0 < n && n <= es_fixed_limit)
    {
        out.append(digits.substr(0, static_cast<std::size_t>(n)));
        out.push_back('.');
        out.append(digits.substr(static_cast<std::size_t>(n)));
    }
    else if (es_small_limit < n && n <= 0)
    {
        out.append("0.");
        out.append(static_cast<std::size_t>(-n), '0');
        out.append(digits);
    }
    else
    {
        const long long e = n - 1;
        out.push_back(digits.front());
        if (k > 1)
        {
            out.push_back('.');
            out.append(digits.substr(1));
        }
        out.push_back('e');
        out.push_back(e >= 0 ? '+' : '-');
        out.append(std::to_string(e >= 0 ? e : -e));
    }
    return {};
}

Result<void> write_canonical_json(const json::Value& value, String& out, Allocator allocator)
{
    return write_value(value, out, allocator, 0);
}

Result<String> canonical_json(std::string_view json, Allocator allocator, const json::Limits& limits)
{
    auto document = json::parse(json, limits, allocator.resource());
    if (!document)
        return std::unexpected(document.error());
    String out(allocator);
    out.reserve(json.size());
    if (auto done = write_value(document->root(), out, allocator, 0); !done)
        return std::unexpected(done.error());
    return out;
}

} // namespace lantern
