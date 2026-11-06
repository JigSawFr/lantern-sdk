// SPEC.md § 6.3: what a device is missing.
#include <lantern/missing.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>

#include <lantern/profiles.hpp>

namespace lantern
{

Vector<App> missing_apps(std::span<const App> apps, std::string_view platform, const MissingRequest& request,
    const Allocator& allocator)
{
    const Profile* profile = find_profile(platform);
    const bool replaces    = profile != nullptr && profile->newer_base_is_update;
    const auto wants
        = [&](std::string_view what) { return std::ranges::find(request.want, what) != request.want.end(); };
    const auto by_app = [&](std::string_view app_id) -> const App*
    {
        const auto found = std::ranges::find_if(apps, [&](const App& app) { return app.app_id == app_id; });
        return found == apps.end() ? nullptr : &*found;
    };
    // An installed app that is one of ours also installs what it includes, whatever its variant (L-6.3-4)
    Vector<InstalledApp> held(request.installed, allocator);
    for (const InstalledApp& item : request.installed)
    {
        for (const App& app : apps)
        {
            if (app.app_id != item.app_id || app.version_code != item.version_code)
                continue;
            for (const AppInclude& inner : app.includes)
            {
                held.emplace_back();
                held.back().app_id       = inner.app_id;
                held.back().version_code = inner.version_code;
            }
        }
    }
    const auto installed = [&](std::string_view app_id)
    { return std::ranges::any_of(held, [&](const InstalledApp& i) { return i.app_id == app_id; }); };
    // The installed games, each with its highest version (§ 6.3)
    struct Game
    {
        String title;
        std::uint64_t version;
    };
    Vector<Game> have(allocator);
    for (const InstalledApp& item : held)
    {
        String title(allocator);
        std::string_view kind;
        if (const App* known = by_app(item.app_id))
        {
            title.assign(known->title_id);
            kind = known->type;
        }
        else if (platform == "switch" && item.app_id.size() == 16
            && std::ranges::all_of(
                item.app_id, [](char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'); }))
        {
            // Annex A.1: base ...000, update ...800, an add-on otherwise
            std::uint64_t id  = 0;
            const auto parsed = std::from_chars(item.app_id.data(), item.app_id.data() + 16, id, 16);
            if (parsed.ec != std::errc {})
                continue;
            const std::uint64_t low = id & 0x1FFFU;
            kind                    = "dlc";
            if (low == 0)
                kind = "base";
            else if (low == 0x800)
                kind = "update";
            std::array<char, 16> hex {};
            const std::uint64_t base = id & ~std::uint64_t { 0x1FFF };
            for (std::size_t i = 0; i < 16; ++i)
                hex[15 - i] = "0123456789ABCDEF"[(base >> (4 * i)) & 15U];
            title.assign(hex.data(), hex.size());
        }
        else
            continue; // a game this library does not know
        if (kind != "base" && kind != "update")
            continue;
        const auto found = std::ranges::find_if(have, [&](const Game& g) { return g.title == title; });
        if (found == have.end())
            have.push_back({ std::move(title), item.version_code });
        else
            found->version = std::max(found->version, item.version_code);
    }
    Vector<App> out(allocator);
    for (const Game& game : have)
    {
        std::optional<std::uint64_t> newest;
        const auto is_update = [&](const App& app)
        {
            if (app.title_id != game.title)
                return false;
            return replaces ? (app.type == "base" && installed(app.app_id)) : app.type == "update";
        };
        for (const App& app : apps)
        {
            if (is_update(app))
                newest = std::max(newest.value_or(0), app.version_code);
        }
        if (wants("update") && newest && *newest > game.version)
        {
            for (const App& app : apps)
            {
                if (is_update(app) && app.version_code == *newest)
                    out.emplace_back(app);
            }
        }
        if (wants("dlc"))
        {
            for (const App& app : apps)
            {
                if (app.title_id == game.title && app.type == "dlc" && !installed(app.app_id))
                    out.emplace_back(app);
            }
        }
    }
    if (wants("base"))
    {
        for (const App& app : apps)
        {
            if (app.type == "base"
                && std::ranges::none_of(have, [&](const Game& g) { return g.title == app.title_id; }))
                out.emplace_back(app);
        }
    }
    // What the device can install (L-6.3-3): a filter that is absent is not applied
    const auto words = [](const std::optional<Vector<String>>& list, const String& word)
    { return list.has_value() && std::ranges::find(*list, word) != list->end(); };
    std::erase_if(out,
        [&](const App& app)
        {
            if (request.formats && !words(request.formats, app.format))
                return true;
            return request.satisfies
                && !std::ranges::all_of(
                    app.requires_, [&](const String& token) { return words(request.satisfies, token); });
        });
    return out;
}

} // namespace lantern
