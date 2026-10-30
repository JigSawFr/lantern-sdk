// SPEC.md § 20: sync's times, canonical JSON, the merge rule and the
// collections' values.
#include <lantern/sync.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>
#include <utility>

#include <lantern/profiles.hpp>

namespace lantern
{

namespace
{

// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) noexcept
{
    year -= month <= 2 ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const auto yoe         = static_cast<unsigned>(year - era * 400);
    const unsigned doy     = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
    const unsigned doe     = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

struct Civil
{
    std::int64_t year;
    unsigned month;
    unsigned day;
};

Civil civil_from_days(std::int64_t days) noexcept
{
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const auto doe         = static_cast<unsigned>(days - era * 146097);
    const unsigned yoe     = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy     = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp      = (5 * doy + 2) / 153;
    const unsigned day     = doy - (153 * mp + 2) / 5 + 1;
    const unsigned month   = mp < 10 ? mp + 3 : mp - 9;
    return { static_cast<std::int64_t>(yoe) + era * 400 + (month <= 2 ? 1 : 0), month, day };
}

bool leap(std::int64_t year) noexcept
{
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

std::optional<unsigned> digits(std::string_view text) noexcept
{
    unsigned value = 0;
    for (const char c : text)
    {
        if (c < '0' || c > '9')
            return std::nullopt;
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    return value;
}

void write_canonical(const json::Value& value, String& out, Allocator allocator, bool& duplicate)
{
    switch (value.kind())
    {
        case json::Kind::object:
        {
            Vector<const json::Member*> members(allocator);
            members.reserve(value.members().size());
            for (const json::Member& member : value.members())
                members.push_back(&member);
            std::ranges::sort(
                members, [](const json::Member* a, const json::Member* b) { return a->key < b->key; });
            out.push_back('{');
            for (std::size_t i = 0; i < members.size(); ++i)
            {
                if (i != 0)
                {
                    out.push_back(',');
                    duplicate = duplicate || members[i - 1]->key == members[i]->key;
                }
                json::Writer::escape(out, members[i]->key);
                out.push_back(':');
                write_canonical(members[i]->value, out, allocator, duplicate);
            }
            out.push_back('}');
            return;
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
                write_canonical(item, out, allocator, duplicate);
            }
            out.push_back(']');
            return;
        }
        case json::Kind::string:
            json::Writer::escape(out, value.text());
            return;
        case json::Kind::number:
            out.append(value.text());
            return;
        case json::Kind::boolean:
            out.append(value.boolean() ? "true" : "false");
            return;
        case json::Kind::null:
            out.append("null");
            return;
    }
}

template <class T>
Result<T> read_value(std::string_view text, const DecodeOptions& options, std::string_view what)
{
    Vector<char> scratch(options.limits.max_string, options.memory);
    BindContext context(text, options, scratch);
    T value(Allocator(options.memory));
    if (!bind(context, value))
        return std::unexpected(context.error());
    if (context.reader().next() != json::Event::end)
        return std::unexpected(context.error().category() == Category::usage
                ? Error::make(Category::invalid_response, what)
                : context.error());
    return value;
}

} // namespace

bool is_sync_collection(std::string_view name) noexcept
{
    return !name.empty() && name.size() <= 32 && name.front() >= 'a' && name.front() <= 'z'
        && std::ranges::all_of(
            name, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; });
}

std::optional<std::int64_t> parse_sync_time(std::string_view text) noexcept
{
    // YYYY-MM-DDTHH:MM:SS[.f{1,3}]Z
    if (text.size() < 20 || text.size() > 24 || text[4] != '-' || text[7] != '-' || text[10] != 'T'
        || text[13] != ':' || text[16] != ':' || text.back() != 'Z')
        return std::nullopt;
    const auto year   = digits(text.substr(0, 4));
    const auto month  = digits(text.substr(5, 2));
    const auto day    = digits(text.substr(8, 2));
    const auto hour   = digits(text.substr(11, 2));
    const auto minute = digits(text.substr(14, 2));
    const auto second = digits(text.substr(17, 2));
    unsigned millis   = 0;
    if (text.size() > 20)
    {
        const std::string_view fraction = text.substr(20, text.size() - 21);
        const auto value                = digits(fraction);
        if (text[19] != '.' || fraction.empty() || !value)
            return std::nullopt;
        millis = *value * (fraction.size() == 1 ? 100U : fraction.size() == 2 ? 10U : 1U);
    }
    if (!year || !month || !day || !hour || !minute || !second || *month < 1 || *month > 12 || *day < 1
        || *hour > 23 || *minute > 59 || *second > 59)
        return std::nullopt;
    static constexpr std::array<unsigned, 12> month_days { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const unsigned last = month_days[*month - 1] + ((*month == 2 && leap(*year)) ? 1U : 0U);
    if (*day > last)
        return std::nullopt;
    const std::int64_t days = days_from_civil(*year, *month, *day);
    return ((days * 24 + *hour) * 60 + *minute) * 60 * 1000 + static_cast<std::int64_t>(*second) * 1000
        + millis;
}

void format_sync_time(std::int64_t milliseconds, String& out)
{
    const std::int64_t day_ms = std::int64_t { 86400 } * 1000;
    std::int64_t days         = milliseconds / day_ms;
    std::int64_t rest         = milliseconds % day_ms;
    if (rest < 0)
    {
        rest += day_ms;
        --days;
    }
    const Civil date = civil_from_days(days);
    std::array<char, 32> text {};
    const auto put = [&](std::size_t at, std::int64_t value, std::size_t width)
    {
        for (std::size_t i = 0; i < width; ++i)
        {
            text[at + width - 1 - i] = static_cast<char>('0' + value % 10);
            value /= 10;
        }
    };
    put(0, std::clamp<std::int64_t>(date.year, 0, 9999), 4);
    text[4] = '-';
    put(5, date.month, 2);
    text[7] = '-';
    put(8, date.day, 2);
    text[10] = 'T';
    put(11, rest / 3600000, 2);
    text[13] = ':';
    put(14, rest / 60000 % 60, 2);
    text[16] = ':';
    put(17, rest / 1000 % 60, 2);
    text[19] = '.';
    put(20, rest % 1000, 3);
    text[23] = 'Z';
    out.append(text.data(), 24);
}

Result<String> canonical_json(std::string_view json, Allocator allocator, const json::Limits& limits)
{
    auto document = json::parse(json, limits, allocator.resource());
    if (!document)
        return std::unexpected(document.error());
    String out(allocator);
    out.reserve(json.size());
    bool duplicate = false;
    write_canonical(document->root(), out, allocator, duplicate);
    if (duplicate)
        return fail(Category::invalid_response, "an object with a key twice has no canonical form");
    return out;
}

Result<SyncMerge> sync_merge(
    const SyncItem* have, const SyncItem& sent, std::int64_t now, std::int64_t skew, Allocator allocator)
{
    const auto sent_time    = parse_sync_time(sent.updated);
    const bool sent_deleted = sent.deleted.value_or(false);
    if (!sent_time)
        return fail(Category::usage, "an item's updated is not a sync time (SPEC.md 20.2)");
    if (!sent_deleted && sent.value.empty())
        return fail(Category::usage, "an item is a value or a deletion (SPEC.md 20.2)");
    SyncMerge merge;
    // L-20.4-2: a clock ahead does not win every conflict to come
    merge.updated = *sent_time > now + skew * 1000 ? now : *sent_time;
    if (have == nullptr)
    {
        merge.replaced = true;
        return merge;
    }
    const auto have_time = parse_sync_time(have->updated);
    if (!have_time)
        return fail(Category::usage, "a kept item's updated is not a sync time (SPEC.md 20.2)");
    const bool have_deleted = have->deleted.value_or(false);
    if (merge.updated != *have_time)
    {
        merge.replaced = merge.updated > *have_time;
        return merge;
    }
    // The same time: a deletion wins, then the greater canonical JSON
    if (have_deleted)
        return merge;
    if (sent_deleted)
    {
        merge.replaced = true;
        return merge;
    }
    const auto ours   = canonical_json(have->value, allocator);
    const auto theirs = canonical_json(sent.value, allocator);
    if (!ours)
        return std::unexpected(ours.error());
    if (!theirs)
        return std::unexpected(theirs.error());
    merge.replaced = std::string_view(*theirs) > std::string_view(*ours);
    return merge;
}

void write_wish(const Wish& wish, String& out)
{
    json::Writer writer(out);
    write(writer, wish);
}

void write_installed(const Installed& installed, String& out)
{
    json::Writer writer(out);
    write(writer, installed);
}

Result<Wish> read_wish(std::string_view value, const DecodeOptions& options)
{
    return read_value<Wish>(value, options, "a wish not of SPEC.md 20.2's form");
}

Result<Installed> read_installed(std::string_view value, const DecodeOptions& options)
{
    return read_value<Installed>(value, options, "an installed value not of SPEC.md 20.2's form");
}

Result<String> wish_key(std::string_view platform, std::string_view title_id, Allocator allocator)
{
    if (!is_platform_name(platform) || !is_core_id(title_id))
        return fail(Category::usage, "a wish's key is a platform and a title id (SPEC.md 20.2)");
    String key(allocator);
    key.append(platform);
    key.push_back('/');
    key.append(title_id);
    return key;
}

} // namespace lantern
