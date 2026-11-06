#include <lantern/variants.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <tuple>

namespace lantern
{

namespace
{

const App* address(const App& app) noexcept
{
    return &app;
}

const App* address(const App* app) noexcept
{
    return app;
}

template <class Apps> bool included_in(const App& app, Apps installed) noexcept
{
    if (app.type != "update")
        return false;
    return std::ranges::any_of(installed,
        [&](const auto& have)
        {
            return std::ranges::any_of(address(have)->includes, [&](const AppInclude& item)
                { return item.app_id == app.app_id && item.version_code >= app.version_code; });
        });
}

bool has(std::span<const std::string_view> words, const String& word) noexcept
{
    return std::ranges::find(words, std::string_view(word)) != words.end();
}

template <class Apps>
InstallDecision decide(const App& app, std::span<const std::string_view> formats,
    std::span<const std::string_view> satisfies, Apps installed, const Allocator& allocator)
{
    InstallDecision decision(allocator);
    if (!has(formats, app.format))
    {
        String why("format '", allocator);
        why.append(app.format);
        why.push_back('\'');
        decision.reasons.push_back(std::move(why));
    }
    for (const String& token : app.requires_)
    {
        if (has(satisfies, token))
            continue;
        String why("requires '", allocator);
        why.append(token);
        why.push_back('\'');
        decision.reasons.push_back(std::move(why));
    }
    if (included_in(app, installed))
        decision.reasons.emplace_back("already included by an installed app");
    if (!decision.reasons.empty())
        decision.verdict = Install::unavailable;
    return decision;
}

template <class Apps> const App* preferred(Apps variants) noexcept
{
    const App* best = nullptr;
    const auto key  = [](const App& a)
    { return std::tuple<std::size_t, std::uint64_t, std::string_view>(a.requires_.size(), a.size, a.id); };
    for (const auto& item : variants)
    {
        const App& app = *address(item);
        if (best == nullptr || key(app) < key(*best))
            best = &app;
    }
    return best;
}

} // namespace

bool included(const App& app, std::span<const App> installed) noexcept
{
    return included_in(app, installed);
}

bool included(const App& app, std::span<const App* const> installed) noexcept
{
    return included_in(app, installed);
}

InstallDecision install_decision(const App& app, std::span<const std::string_view> formats,
    std::span<const std::string_view> satisfies, std::span<const App> installed, const Allocator& allocator)
{
    return decide(app, formats, satisfies, installed, allocator);
}

InstallDecision install_decision(const App& app, std::span<const std::string_view> formats,
    std::span<const std::string_view> satisfies, std::span<const App* const> installed,
    const Allocator& allocator)
{
    return decide(app, formats, satisfies, installed, allocator);
}

const App* prefer_variant(std::span<const App> variants) noexcept
{
    return preferred(variants);
}

const App* prefer_variant(std::span<const App* const> variants) noexcept
{
    return preferred(variants);
}

} // namespace lantern
