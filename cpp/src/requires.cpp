#include <lantern/requires.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>

#include <lantern/json.hpp>

namespace lantern
{

namespace
{

constexpr std::array<std::string_view, 3> common_min_keys { "glibc", "ram_mb", "screen" };
constexpr std::array<std::string_view, 4> known_gpus { "gles2", "gles3", "gl", "vulkan" };
constexpr std::array<std::string_view, 4> known_members { "text", "min", "gpu", "homebrew" };

// A dotted version: 1 to 4 parts of digits.
bool dotted(std::string_view text) noexcept
{
    if (text.empty() || text.front() == '.' || text.back() == '.')
        return false;
    std::size_t parts = 1;
    for (std::size_t i = 0; i < text.size(); ++i)
    {
        if (text[i] == '.')
        {
            if (text[i - 1] == '.')
                return false;
            ++parts;
        }
        else if (text[i] < '0' || text[i] > '9')
            return false;
    }
    return parts <= 4;
}

std::optional<std::uint64_t> parse_number(std::string_view text) noexcept
{
    std::uint64_t value = 0;
    const char* end     = text.data() + text.size();
    const auto result   = std::from_chars(text.data(), end, value);
    if (text.empty() || result.ec != std::errc {} || result.ptr != end)
        return std::nullopt;
    return value;
}

// "640x480" (§ 8.7): width and height, each 1 to 6 digits, not starting with 0.
std::optional<std::pair<std::uint64_t, std::uint64_t>> parse_screen(std::string_view text) noexcept
{
    const std::size_t x = text.find('x');
    if (x == std::string_view::npos)
        return std::nullopt;
    const std::string_view w = text.substr(0, x);
    const std::string_view h = text.substr(x + 1);
    const auto ok            = [](std::string_view part)
    {
        return !part.empty() && part.size() <= 6 && part[0] != '0'
            && std::ranges::all_of(part, [](char c) { return c >= '0' && c <= '9'; });
    };
    if (!ok(w) || !ok(h))
        return std::nullopt;
    const auto width  = parse_number(w);
    const auto height = parse_number(h);
    if (!width || !height)
        return std::nullopt;
    return std::pair { *width, *height };
}

void add(RequiresCheck& check, std::string_view key, ConditionState state,
    std::initializer_list<std::string_view> detail)
{
    check.conditions.emplace_back();
    Condition& condition = check.conditions.back();
    condition.key.assign(key);
    for (const std::string_view part : detail)
        condition.detail.append(part);
    condition.state = state;
}

std::string_view number_text(std::uint64_t value, std::array<char, 24>& buffer) noexcept
{
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    return { buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data()) };
}

// The JSON string a raw member holds, or nothing.
std::optional<std::string_view> raw_string(const json::Document& document)
{
    const json::Value& value = document.root();
    if (!value.is_string())
        return std::nullopt;
    return value.text();
}

void check_min(RequiresCheck& check, const Profile& profile, const DeviceFacts& device, std::string_view key,
    std::string_view raw, const Allocator& allocator)
{
    String name("min.", allocator);
    name.append(key);
    const bool common      = std::ranges::find(common_min_keys, key) != common_min_keys.end();
    const bool profile_key = std::ranges::find(profile.min_keys, key) != profile.min_keys.end();
    if (!common && !profile_key)
    {
        add(check, name, ConditionState::unreadable, { "a condition this client does not know: ", key });
        return;
    }
    const auto parsed = json::parse(raw, {}, allocator.resource());
    if (!parsed)
    {
        add(check, name, ConditionState::unreadable, { "a value of another form" });
        return;
    }
    std::array<char, 24> a {};
    std::array<char, 24> b {};
    if (key == "ram_mb")
    {
        const auto needed = parsed->root().to_u64();
        if (!needed)
        {
            add(check, name, ConditionState::unreadable, { "a value of another form" });
            return;
        }
        if (!device.ram_mb)
        {
            add(check, name, ConditionState::unreadable, { "this device's memory is not known" });
            return;
        }
        if (*device.ram_mb < *needed)
            add(check, name, ConditionState::failed,
                { number_text(*needed, a), " MiB of memory or more; this device has ",
                    number_text(*device.ram_mb, b), " MiB" });
        else
            add(check, name, ConditionState::met, {});
        return;
    }
    const auto text = raw_string(*parsed);
    if (key == "screen")
    {
        const auto needed = text ? parse_screen(*text) : std::nullopt;
        if (!needed)
        {
            add(check, name, ConditionState::unreadable, { "a value of another form" });
            return;
        }
        if (!device.screen_width || !device.screen_height)
        {
            add(check, name, ConditionState::unreadable, { "this device's screen is not known" });
            return;
        }
        if (*device.screen_width < needed->first || *device.screen_height < needed->second)
            add(check, name, ConditionState::failed, { "a screen of ", *text, " or more" });
        else
            add(check, name, ConditionState::met, {});
        return;
    }
    // A dotted version: glibc, firmware, atmosphere, luma, goldhen, sdk…
    if (!text || !dotted(*text))
    {
        add(check, name, ConditionState::unreadable, { "a value of another form" });
        return;
    }
    const auto known
        = std::ranges::find_if(device.versions, [&](const DeviceFacts::Version& v) { return v.key == key; });
    if (known == device.versions.end() || !dotted(known->value))
    {
        add(check, name, ConditionState::unreadable, { "this device's ", key, " is not known" });
        return;
    }
    if (compare_dotted(known->value, *text).value_or(0) < 0)
        add(check, name, ConditionState::failed,
            { key, " ", *text, " or later; this device has ", known->value });
    else
        add(check, name, ConditionState::met, {});
}

void check_gpu(RequiresCheck& check, const Requires& requires_, const DeviceFacts& device)
{
    if (requires_.gpu.empty())
        return;
    const bool all_known = std::ranges::all_of(requires_.gpu, [](const String& name)
        { return std::ranges::find(known_gpus, std::string_view(name)) != known_gpus.end(); });
    if (device.gpus)
    {
        const auto offered = [&](const String& name)
        { return std::ranges::find(*device.gpus, std::string_view(name)) != device.gpus->end(); };
        if (std::ranges::any_of(requires_.gpu, offered))
        {
            add(check, "gpu", ConditionState::met, {});
            return;
        }
        if (all_known)
        {
            add(check, "gpu", ConditionState::failed,
                { "none of the graphics interfaces it needs is on this device" });
            return;
        }
        add(check, "gpu", ConditionState::unreadable, { "a graphics interface this client does not know" });
        return;
    }
    add(check, "gpu", ConditionState::unreadable, { "this device's graphics interfaces are not known" });
}

} // namespace

std::optional<int> compare_dotted(std::string_view a, std::string_view b) noexcept
{
    if (!dotted(a) || !dotted(b))
        return std::nullopt;
    for (;;)
    {
        const std::size_t a_dot = std::min(a.find('.'), a.size());
        const std::size_t b_dot = std::min(b.find('.'), b.size());
        const std::uint64_t x   = a.empty() ? 0 : parse_number(a.substr(0, a_dot)).value_or(0);
        const std::uint64_t y   = b.empty() ? 0 : parse_number(b.substr(0, b_dot)).value_or(0);
        if (x != y)
            return x < y ? -1 : 1;
        a = a_dot < a.size() ? a.substr(a_dot + 1) : std::string_view {};
        b = b_dot < b.size() ? b.substr(b_dot + 1) : std::string_view {};
        if (a.empty() && b.empty())
            return 0;
    }
}

RequiresCheck check_requires(
    const Requires& requires_, const Profile& profile, const DeviceFacts& device, Allocator allocator)
{
    RequiresCheck check(allocator);
    if (requires_.min)
    {
        for (const auto& [key, raw] : requires_.min->members)
            check_min(check, profile, device, key, raw, allocator);
    }
    check_gpu(check, requires_, device);
    // A member this text does not list is a condition the client cannot
    // read, but a vendor's own (x-<vendor>-), which it ignores
    for (const auto& [key, raw] : requires_.extra)
    {
        if (std::string_view(key).starts_with("x-")
            || std::ranges::find(known_members, std::string_view(key)) != known_members.end())
            continue;
        add(check, key, ConditionState::unreadable, { "a requirement this client does not know: ", key });
    }
    const auto has = [&](ConditionState state)
    { return std::ranges::any_of(check.conditions, [&](const Condition& c) { return c.state == state; }); };
    if (has(ConditionState::failed))
        check.offer = Offer::refuse;
    else if (has(ConditionState::unreadable))
        check.offer = Offer::warn;
    else
        check.offer = Offer::offer;
    return check;
}

} // namespace lantern
