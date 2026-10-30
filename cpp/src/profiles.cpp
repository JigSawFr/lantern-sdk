#include <lantern/profiles.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>

namespace lantern
{

namespace
{

bool upper_hex(char c) noexcept
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
}
bool digit(char c) noexcept
{
    return c >= '0' && c <= '9';
}
bool upper(char c) noexcept
{
    return c >= 'A' && c <= 'Z';
}
bool lower(char c) noexcept
{
    return c >= 'a' && c <= 'z';
}

template <class Predicate> bool all_of(std::string_view text, Predicate predicate) noexcept
{
    return std::all_of(text.begin(), text.end(), predicate);
}

std::optional<std::uint64_t> parse_hex16(std::string_view text) noexcept
{
    if (text.size() != 16 || !all_of(text, upper_hex))
        return std::nullopt;
    std::uint64_t value = 0;
    std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return value;
}

std::optional<std::uint64_t> parse_decimal(std::string_view text, std::uint64_t max) noexcept
{
    if (text.empty() || text.size() > 20 || !all_of(text, digit) || (text.size() > 1 && text[0] == '0'))
        return std::nullopt;
    std::uint64_t value = 0;
    const auto result   = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc {} || value > max)
        return std::nullopt;
    return value;
}

// Annex A.1: 16 upper-case hex digits, the lowest 13 bits zero.
bool switch_title_id(std::string_view id) noexcept
{
    const auto value = parse_hex16(id);
    return value && (*value & 0x1FFFU) == 0;
}

bool switch_app_id(std::string_view type, std::string_view title_id, std::string_view app_id) noexcept
{
    const auto title = parse_hex16(title_id);
    const auto app   = parse_hex16(app_id);
    if (!title || !app || (*title & 0x1FFFU) != 0)
        return false;
    if (type == "base")
        return *app == *title;
    if (type == "update")
        return *app == *title + 0x800U;
    if (type == "dlc")
        return *app > *title + 0x800U;
    return false;
}

std::optional<std::uint64_t> switch_version(std::string_view text) noexcept
{
    if (!text.empty() && text[0] == 'v')
        text.remove_prefix(1);
    return parse_decimal(text, 0xFFFFFFFFU);
}

// Annex A.2.
bool ds_title_id(std::string_view id) noexcept
{
    return id.size() == 16 && (id.starts_with("00040000") || id.starts_with("00040002"))
        && all_of(id, upper_hex);
}

bool ds_app_id(std::string_view type, std::string_view title_id, std::string_view app_id) noexcept
{
    if (!ds_title_id(title_id) || app_id.size() != 16 || !all_of(app_id, upper_hex)
        || app_id.substr(8) != title_id.substr(8))
        return false;
    if (type == "base")
        return app_id == title_id;
    if (type == "update")
        return app_id.starts_with("0004000E");
    if (type == "dlc")
        return app_id.starts_with("0004008C");
    return false;
}

std::optional<std::uint64_t> ds_version(std::string_view text) noexcept
{
    return parse_decimal(text, 0xFFFFU);
}

// Annex A.3 and A.4: APP_VER "XX.YY" as XX × 100 + YY.
std::optional<std::uint64_t> app_ver(std::string_view text) noexcept
{
    if (text.size() != 5 || text[2] != '.' || !digit(text[0]) || !digit(text[1]) || !digit(text[3])
        || !digit(text[4]))
        return std::nullopt;
    const auto two = [](char a, char b)
    { return (static_cast<std::uint64_t>(a - '0') * 10) + static_cast<std::uint64_t>(b - '0'); };
    return two(text[0], text[1]) * 100 + two(text[3], text[4]);
}

bool vita_title_id(std::string_view id) noexcept
{
    return id.size() == 9 && all_of(id, [](char c) { return upper(c) || digit(c); });
}

// ^[A-Z]{2}[0-9]{4}-<title>_[0-9]{2}-[A-Z0-9]{16}$, the title's id inside.
bool content_id(
    std::string_view id, std::string_view title_id, bool (*title_form)(std::string_view) noexcept) noexcept
{
    if (id.size() != 36)
        return false;
    const std::string_view inner = id.substr(7, 9);
    return upper(id[0]) && upper(id[1]) && all_of(id.substr(2, 4), digit) && id[6] == '-' && title_form(inner)
        && id[16] == '_' && digit(id[17]) && digit(id[18]) && id[19] == '-'
        && all_of(id.substr(20), [](char c) { return upper(c) || digit(c); }) && inner == title_id;
}

bool vita_app_id(std::string_view type, std::string_view title_id, std::string_view app_id) noexcept
{
    if (!vita_title_id(title_id))
        return false;
    if (type == "base" || type == "update")
        return app_id == title_id;
    if (type == "dlc")
        return content_id(app_id, title_id, vita_title_id);
    return false;
}

bool ps4_title_id(std::string_view id) noexcept
{
    return id.size() == 9 && all_of(id.substr(0, 4), upper) && all_of(id.substr(4), digit);
}

bool ps4_app_id(std::string_view type, std::string_view title_id, std::string_view app_id) noexcept
{
    if (!ps4_title_id(title_id))
        return false;
    if (type == "base" || type == "update")
        return app_id == title_id;
    if (type == "dlc")
        return content_id(app_id, title_id, ps4_title_id);
    return false;
}

// Annex A.5: ^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$
bool android_package(std::string_view id) noexcept
{
    if (id.empty() || id.size() > 128)
        return false;
    std::size_t parts = 0;
    std::size_t start = 0;
    for (;;)
    {
        const std::size_t end       = std::min(id.find('.', start), id.size());
        const std::string_view part = id.substr(start, end - start);
        if (part.empty() || !(upper(part[0]) || lower(part[0]))
            || !all_of(part, [](char c) { return upper(c) || lower(c) || digit(c) || c == '_'; }))
            return false;
        ++parts;
        if (end == id.size())
            break;
        start = end + 1;
    }
    return parts >= 2;
}

bool android_app_id(std::string_view type, std::string_view title_id, std::string_view app_id) noexcept
{
    return type == "base" && android_package(title_id) && app_id == title_id;
}

std::optional<std::uint64_t> android_version(std::string_view text) noexcept
{
    return parse_decimal(text, 0x7FFFFFFFFFFFFFFFU);
}

bool no_title_id(std::string_view /*id*/) noexcept
{
    return false;
}
bool no_app_id(std::string_view /*type*/, std::string_view /*title*/, std::string_view /*app*/) noexcept
{
    return false;
}
std::optional<std::uint64_t> no_version(std::string_view /*text*/) noexcept
{
    return std::nullopt;
}

constexpr std::array<std::string_view, 3> base_update_dlc { "base", "update", "dlc" };
constexpr std::array<std::string_view, 1> base_only { "base" };
constexpr std::array<std::string_view, 0> none {};

constexpr std::array<std::string_view, 4> switch_formats { "nsp", "nsz", "xci", "xcz" };
constexpr std::array<HomebrewFormat, 3> switch_homebrew { {
    { "nro", Placement::single_file, "/switch/<id>/<id>.nro", false },
    { "ovl", Placement::single_file, "/switch/.overlays/", false },
    { "zip", Placement::archive, "", false },
} };
constexpr std::array<std::string_view, 2> switch_free { "/switch/<id>/", "/config/<id>/" };
constexpr std::array<std::string_view, 2> switch_consent { "/atmosphere/", "/switch/.overlays/" };
constexpr std::array<std::string_view, 2> switch_areas { "/switch/", "/config/" };
constexpr std::array<std::string_view, 2> switch_min { "firmware", "atmosphere" };

constexpr std::array<std::string_view, 1> ds_formats { "cia" };
constexpr std::array<HomebrewFormat, 3> ds_homebrew { {
    { "3dsx", Placement::single_file, "/3ds/<id>/<id>.3dsx", false },
    { "zip", Placement::archive, "", false },
    { "cia", Placement::system_installer, "", true },
} };
constexpr std::array<std::string_view, 1> ds_free { "/3ds/<id>/" };
constexpr std::array<std::string_view, 4> ds_consent { "/luma/", "/boot.firm", "/boot.3dsx", "/gm9/" };
constexpr std::array<std::string_view, 1> ds_areas { "/3ds/" };
constexpr std::array<std::string_view, 2> ds_min { "firmware", "luma" };

constexpr std::array<std::string_view, 2> vita_formats { "vpk", "pkg" };
constexpr std::array<HomebrewFormat, 1> vita_homebrew {
    { { "vpk", Placement::system_installer, "", true } }
};
constexpr std::array<std::string_view, 1> vita_free { "/ux0/data/<id>/" };
constexpr std::array<std::string_view, 2> vita_consent { "/ux0/tai/", "/ur0/tai/" };
constexpr std::array<std::string_view, 1> vita_areas { "/ux0/data/" };

constexpr std::array<std::string_view, 1> ps4_formats { "pkg" };
constexpr std::array<HomebrewFormat, 1> ps4_homebrew { { { "pkg", Placement::system_installer, "", true } } };
constexpr std::array<std::string_view, 1> ps4_free { "/data/<id>/" };
constexpr std::array<std::string_view, 1> ps4_consent { "/data/GoldHEN/" };
constexpr std::array<std::string_view, 1> ps4_areas { "/data/" };
constexpr std::array<std::string_view, 2> ps4_min { "firmware", "goldhen" };

constexpr std::array<std::string_view, 2> android_formats { "apk", "apks" };
constexpr std::array<HomebrewFormat, 2> android_homebrew { {
    { "apk", Placement::system_installer, "", false },
    { "apks", Placement::system_installer, "", false },
} };
constexpr std::array<std::string_view, 4> android_arches { "aarch64", "armhf", "x86", "x86_64" };
constexpr std::array<std::string_view, 1> android_min { "sdk" };

constexpr std::array<HomebrewFormat, 1> linux_homebrew { { { "zip", Placement::archive, "", false } } };
constexpr std::array<std::string_view, 5> linux_arches { "aarch64", "armhf", "x86", "x86_64", "riscv64" };
constexpr std::array<std::string_view, 1> linux_free { "/<id>/" };
constexpr std::array<std::string_view, 1> linux_consent { "/" };
constexpr std::array<std::string_view, 1> linux_areas { "/" };

constexpr std::array<Profile, 6> table { {
    { "switch", false, true, false, base_update_dlc, switch_formats, none, switch_homebrew, switch_free,
        switch_consent, switch_areas, switch_min, false, switch_title_id, switch_app_id, switch_version },
    { "3ds", true, true, false, base_update_dlc, ds_formats, none, ds_homebrew, ds_free, ds_consent, ds_areas,
        ds_min, true, ds_title_id, ds_app_id, ds_version },
    { "vita", true, true, false, base_update_dlc, vita_formats, none, vita_homebrew, vita_free, vita_consent,
        vita_areas, none, true, vita_title_id, vita_app_id, app_ver },
    { "ps4", true, true, false, base_update_dlc, ps4_formats, none, ps4_homebrew, ps4_free, ps4_consent,
        ps4_areas, ps4_min, true, ps4_title_id, ps4_app_id, app_ver },
    { "android", true, true, true, base_only, android_formats, android_arches, android_homebrew, none, none,
        none, android_min, true, android_package, android_app_id, android_version },
    { "linux", true, false, false, none, none, linux_arches, linux_homebrew, linux_free, linux_consent,
        linux_areas, none, false, no_title_id, no_app_id, no_version },
} };

} // namespace

std::span<const Profile> profiles() noexcept
{
    return table;
}

const Profile* find_profile(std::string_view platform) noexcept
{
    for (const Profile& profile : table)
    {
        if (profile.platform == platform)
            return &profile;
    }
    return nullptr;
}

const HomebrewFormat* find_homebrew_format(const Profile& profile, std::string_view format) noexcept
{
    for (const HomebrewFormat& entry : profile.homebrew_formats)
    {
        if (entry.format == format)
            return &entry;
    }
    return nullptr;
}

bool has_app_type(const Profile& profile, std::string_view type) noexcept
{
    return std::ranges::find(profile.app_types, type) != profile.app_types.end();
}

bool has_app_format(const Profile& profile, std::string_view format) noexcept
{
    return std::ranges::find(profile.app_formats, format) != profile.app_formats.end();
}

bool is_platform_name(std::string_view name) noexcept
{
    return !name.empty() && name.size() <= 32 && (lower(name[0]) || digit(name[0]))
        && all_of(name, [](char c) { return lower(c) || digit(c) || c == '-'; });
}

bool is_arch_name(std::string_view name) noexcept
{
    return !name.empty() && name.size() <= 32
        && all_of(name, [](char c) { return lower(c) || digit(c) || c == '_'; });
}

bool is_homebrew_id(std::string_view id) noexcept
{
    if (id.empty() || id.size() > 128 || !lower(id[0]))
        return false;
    std::size_t parts = 0;
    std::size_t start = 0;
    for (;;)
    {
        const std::size_t end       = std::min(id.find('.', start), id.size());
        const std::string_view part = id.substr(start, end - start);
        // The first part starts with a letter, the others with a letter or a digit
        if (part.empty() || (!lower(part[0]) && (parts == 0 || !digit(part[0])))
            || !all_of(part, [](char c) { return lower(c) || digit(c) || c == '_' || c == '-'; }))
            return false;
        ++parts;
        if (end == id.size())
            break;
        start = end + 1;
    }
    return parts >= 2;
}

bool is_core_id(std::string_view id) noexcept
{
    return !id.empty() && id.size() <= 128
        && all_of(
            id, [](char c) { return upper(c) || lower(c) || digit(c) || c == '.' || c == '_' || c == '-'; });
}

std::optional<String> version_name_3ds(std::uint64_t version_code, Allocator allocator)
{
    if (version_code > 0xFFFFU)
        return std::nullopt;
    const std::array<std::uint64_t, 3> parts { version_code >> 10U, (version_code >> 4U) & 0x3FU,
        version_code & 0x0FU };
    String out(allocator);
    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        if (i != 0)
            out.push_back('.');
        std::array<char, 8> buffer {};
        const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), parts[i]);
        out.append(buffer.data(), result.ptr);
    }
    return out;
}

} // namespace lantern
