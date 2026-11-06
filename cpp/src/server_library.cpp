// A Library held in memory (SPEC.md § 6.1): for tests and demos.
#include <algorithm>
#include <array>
#include <charconv>

#include <lantern/peers.hpp>
#include <lantern/profiles.hpp>
#include <lantern/server.hpp>
#include <lantern/url.hpp>

#include "server_internal.hpp"

namespace lantern
{

namespace
{

constexpr std::size_t max_text     = 512;
constexpr std::size_t max_requires = 8;
constexpr std::size_t max_includes = 16;
constexpr std::size_t max_mirrors  = 8;

bool lower_alnum(char c) noexcept
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z');
}

// `^[a-z][a-z0-9_]{0,31}$`: an app's type.
bool is_word(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 32 && text.front() >= 'a' && text.front() <= 'z'
        && std::ranges::all_of(text, [](char c) { return lower_alnum(c) || c == '_'; });
}

// `^[a-z0-9]{1,16}$`: a package format.
bool is_format(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 16 && std::ranges::all_of(text, lower_alnum);
}

// `^[a-z0-9][a-z0-9-]{0,31}$`: one token of an app's `requires`.
bool is_requires_token(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 32 && lower_alnum(text.front())
        && std::ranges::all_of(text, [](char c) { return lower_alnum(c) || c == '-'; });
}

Result<void> check_draft(const AppDraft& draft)
{
    if (!is_served_platform(draft.platform))
        return fail(Category::usage, "a platform that is not served (not a name, or web)");
    if (!is_core_id(draft.title_id) || !is_core_id(draft.app_id))
        return fail(Category::usage, "title_id and app_id are 1 to 128 letters, digits, '.', '_' and '-'");
    if (!is_word(draft.type) || !is_format(draft.format))
        return fail(Category::usage, "type is a lower-case word, format 1 to 16 letters or digits");
    if (draft.name.size() > max_text || draft.version_name.size() > max_text)
        return fail(Category::usage, "a name is 512 bytes at most");
    if (!draft.added.empty() && !detail::parse_time(draft.added))
        return fail(Category::usage, "added is a UTC time: 2026-10-10T12:00:00Z");
    if (draft.requires_.size() > max_requires || draft.includes.size() > max_includes
        || draft.mirrors.size() > max_mirrors)
        return fail(
            Category::usage, "requires 8 tokens, includes 16 versions and mirrors 8 addresses at most");
    for (std::size_t i = 0; i < draft.requires_.size(); ++i)
    {
        if (!is_requires_token(draft.requires_[i])
            || std::ranges::contains(draft.requires_.first(i), draft.requires_[i]))
            return fail(
                Category::usage, "requires lists each token once: lower-case letters, digits and '-'");
    }
    for (const AppInclude& include : draft.includes)
    {
        if (!is_core_id(include.app_id))
            return fail(Category::usage, "an included app_id is 1 to 128 letters, digits, '.', '_' and '-'");
    }
    for (const std::string_view mirror : draft.mirrors)
    {
        const auto parts = split_url(mirror);
        if (!parts || !check_untrusted_scheme(*parts))
            return fail(
                Category::usage, "a mirror is HTTPS, or HTTP at a private network's address (§ 19.2)");
    }
    // Annex A: what the platform's profile says of ids, types and formats
    const Profile* profile = find_profile(draft.platform);
    if (profile != nullptr
        && (!profile->title_id(draft.title_id) || !has_app_type(*profile, draft.type)
            || !profile->app_id(draft.type, draft.title_id, draft.app_id)
            || !has_app_format(*profile, draft.format)))
        return fail(
            Category::usage, "ids, type or format that the platform's profile does not allow (Annex A)");
    return {};
}

} // namespace

MemoryLibrary::MemoryLibrary(std::string_view base, const Allocator& allocator)
    : allocator_(allocator)
    , base_(base, allocator)
    , apps_(allocator)
    , files_(allocator)
{
    while (base_.ends_with('/'))
        base_.pop_back();
}

Result<App> MemoryLibrary::add_app(const AppDraft& draft, std::span<const std::byte> content)
{
    if (auto checked = check_draft(draft); !checked)
        return std::unexpected(checked.error());

    // The id comes from what identifies the package: the same call, the same app
    Sha256 identity;
    const auto part = [&](std::string_view text)
    {
        identity.update(text);
        identity.update(std::string_view("\x1f", 1));
    };
    part(draft.platform);
    part(draft.app_id);
    std::array<char, 24> number {};
    part(std::string_view(number.data(),
        static_cast<std::size_t>(
            std::to_chars(number.data(), number.data() + number.size(), draft.version_code).ptr
            - number.data())));
    part(draft.format);
    for (const std::string_view token : draft.requires_)
        part(token);
    const auto identity_hex = to_hex(identity.finish());

    App app(allocator_);
    app.id.assign("a_");
    app.id.append(identity_hex.data(), 18);
    if (std::ranges::any_of(apps_, [&](const App& other) { return other.id == app.id; }))
        return fail(
            Category::usage, "an app of that platform, app_id, version_code, format and requires is there");

    const Digest sha256 = Sha256::of(content);
    const auto file_hex = to_hex(sha256);
    String file_name("f_", allocator_);
    file_name.append(file_hex.data(), 24);
    app.platform.assign(draft.platform);
    app.title_id.assign(draft.title_id);
    app.app_id.assign(draft.app_id);
    app.type.assign(draft.type);
    app.version_code = draft.version_code;
    app.version_name.assign(draft.version_name);
    app.name.assign(draft.name);
    app.size = content.size();
    app.format.assign(draft.format);
    for (const std::string_view token : draft.requires_)
        app.requires_.emplace_back(token);
    for (const AppInclude& include : draft.includes)
        app.includes.emplace_back(include);
    app.sha256 = sha256;
    app.added.assign(draft.added);
    app.file.assign(base_);
    app.file.append("/v1/files/");
    app.file.append(file_name);
    for (const std::string_view mirror : draft.mirrors)
    {
        app.mirrors.emplace_back();
        app.mirrors.back().url.assign(mirror);
    }

    if (std::ranges::none_of(files_, [&](const Stored& stored) { return stored.name == file_name; }))
    {
        Stored stored;
        stored.name   = std::move(file_name);
        stored.sha256 = sha256;
        stored.reader = std::allocate_shared<MemoryFileReader>(
            std::pmr::polymorphic_allocator<MemoryFileReader>(allocator_), content, allocator_);
        files_.push_back(std::move(stored));
    }
    apps_.push_back(app);
    return app;
}

Result<Vector<String>> MemoryLibrary::platforms(const Allocator& allocator)
{
    Vector<String> out(allocator);
    for (const App& app : apps_)
    {
        if (std::ranges::none_of(out, [&](const String& platform) { return platform == app.platform; }))
            out.emplace_back(app.platform);
    }
    std::ranges::sort(out);
    return out;
}

Result<Vector<App>> MemoryLibrary::apps(const AppsFilter& filter, const Allocator& allocator)
{
    // Only the platform narrows here: the server applies the rest itself
    Vector<App> out(allocator);
    for (const App& app : apps_)
    {
        if (filter.platform.empty() || app.platform == filter.platform)
            out.emplace_back(app);
    }
    return out;
}

Result<std::optional<LibraryFile>> MemoryLibrary::file(std::string_view name, const Allocator& allocator)
{
    const auto found
        = std::ranges::find_if(files_, [&](const Stored& stored) { return stored.name == name; });
    if (found == files_.end())
        return std::optional<LibraryFile> {};
    LibraryFile out(allocator);
    out.size   = found->reader->bytes().size();
    out.sha256 = found->sha256;
    out.reader = found->reader;
    return std::optional<LibraryFile>(std::move(out));
}

} // namespace lantern
