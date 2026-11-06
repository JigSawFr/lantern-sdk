// A Library held in memory (SPEC.md § 6.1): for tests and demos.
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>

#include <lantern/chunks.hpp>
#include <lantern/ed25519.hpp>
#include <lantern/homebrew.hpp>
#include <lantern/json.hpp>
#include <lantern/paths.hpp>
#include <lantern/peers.hpp>
#include <lantern/profiles.hpp>
#include <lantern/server.hpp>
#include <lantern/sync.hpp>
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

constexpr std::size_t max_journal = 1'000'000;

bool is_decimal(std::string_view text) noexcept
{
    return std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

// A date (§ 2.3): 2025-03-14.
bool is_date(std::string_view text) noexcept
{
    return text.size() == 10 && text[4] == '-' && text[7] == '-' && is_decimal(text.substr(0, 4))
        && is_decimal(text.substr(5, 2)) && is_decimal(text.substr(8, 2));
}

// `^Q[1-9][0-9]{0,15}$`: an Atlas id.
bool is_atlas_id(std::string_view text) noexcept
{
    return text.size() >= 2 && text.size() <= 17 && text.front() == 'Q' && text[1] >= '1' && text[1] <= '9'
        && is_decimal(text.substr(1));
}

// `^[A-Z][A-Z0-9-]{1,15}$`: an age rating system.
bool is_rating_system(std::string_view text) noexcept
{
    return text.size() >= 2 && text.size() <= 16 && text.front() >= 'A' && text.front() <= 'Z'
        && std::ranges::all_of(
            text, [](char c) { return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'; });
}

bool is_genre(std::string_view text) noexcept
{
    static constexpr std::array<std::string_view, 15> genres { "action", "adventure", "rpg", "strategy",
        "simulation", "sports", "racing", "puzzle", "platformer", "shooter", "fighting", "music", "party",
        "education", "other" };
    return std::ranges::contains(genres, text);
}

bool is_absolute_web_url(std::string_view url) noexcept
{
    return url.starts_with("https://") || url.starts_with("http://");
}

// An image (§ 7.1): on this server's origin (a path) or marked external (absolute).
bool image_ok(const Image& image) noexcept
{
    if (image.url.empty() || image.url.size() > 4096 || (image.width && *image.width < 1)
        || (image.height && *image.height < 1))
        return false;
    return image.external.value_or(false) ? is_absolute_web_url(image.url) : image.url.starts_with('/');
}

Result<void> check_title(const Title& title)
{
    if (!is_served_platform(title.platform))
        return fail(Category::usage, "a platform that is not served (not a name, or web)");
    if (!is_core_id(title.title_id))
        return fail(Category::usage, "title_id is 1 to 128 letters, digits, '.', '_' and '-'");
    const Profile* profile = find_profile(title.platform);
    if (profile != nullptr && !profile->title_id(title.title_id))
        return fail(Category::usage, "a title_id that the platform's profile does not allow (Annex A)");
    if (title.name.empty() || title.name.size() > max_text || title.publisher.size() > max_text
        || title.developer.size() > max_text)
        return fail(Category::usage, "a title has a name, and its names are 512 bytes at most");
    if (title.language.size() > 35 || title.summary.size() > 4096 || title.description.size() > 4096)
        return fail(Category::usage, "language is 35 bytes at most, summary and description 4096");
    if ((!title.summary.empty() || !title.description.empty()) && title.language.empty())
        return fail(Category::usage, "a title with a summary or a description says its language (§ 2.2)");
    if (!title.release.empty() && !is_date(title.release))
        return fail(Category::usage, "release is a date: 2025-03-14");
    if (!title.updated.empty() && !detail::parse_time(title.updated))
        return fail(Category::usage, "updated is a UTC time: 2026-10-10T12:00:00Z");
    if (!title.atlas.empty() && !is_atlas_id(title.atlas))
        return fail(Category::usage, "atlas is a Wikidata item: Q900001");
    for (std::size_t i = 0; i < title.genres.size(); ++i)
    {
        bool twice = false;
        for (std::size_t j = 0; j < i; ++j)
            twice = twice || title.genres[j] == title.genres[i];
        if (!is_genre(title.genres[i]) || twice)
            return fail(Category::usage, "genres are from the list of § 7.1, each once");
    }
    if (title.tags.size() > 32
        || std::ranges::any_of(title.tags, [](const String& tag) { return tag.empty() || tag.size() > 64; }))
        return fail(Category::usage, "tags are 32 at most, 1 to 64 bytes each");
    if (title.players
        && ((title.players->min && *title.players->min < 1) || (title.players->max && *title.players->max < 1)
            || (title.players->online_max && *title.players->online_max < 1)))
        return fail(Category::usage, "a number of players is 1 or more");
    if (std::ranges::any_of(title.ratings,
            [](const Rating& rating) {
                return !is_rating_system(rating.system) || rating.rating.empty() || rating.rating.size() > 16;
            }))
        return fail(Category::usage, "a rating is an organisation's short name and 1 to 16 bytes");
    if (std::ranges::any_of(title.languages, [](const String& tag) { return tag.size() > 35; }))
        return fail(Category::usage, "a language tag is 35 bytes at most");
    if ((title.icon && !image_ok(*title.icon)) || (title.banner && !image_ok(*title.banner))
        || title.screenshots.size() > 16
        || std::ranges::any_of(title.screenshots, [](const Image& image) { return !image_ok(image); }))
        return fail(Category::usage,
            "images: 16 screenshots at most, each a path of this server or an absolute URL marked external");
    if (title.video && (!title.video->external || !is_absolute_web_url(title.video->url)))
        return fail(Category::usage, "a video is always external: an absolute URL");
    return {};
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

// `^[a-z][a-z0-9_-]{0,31}$`: a homebrew's kind.
bool is_kind(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 32 && text.front() >= 'a' && text.front() <= 'z'
        && std::ranges::all_of(text, [](char c) { return lower_alnum(c) || c == '_' || c == '-'; });
}

constexpr std::uint64_t max_safe_integer = 9007199254740991ULL;

bool is_dotted(std::string_view text) noexcept
{
    if (text.empty() || text.size() > 64 || text.front() == '.' || text.back() == '.')
        return false;
    return std::ranges::all_of(text, [](char c) { return (c >= '0' && c <= '9') || c == '.'; })
        && !text.contains("..");
}

// The value of a `requires.min` key, as JSON: "1.7.0", 512.
bool min_value_ok(std::string_view key, std::string_view json) noexcept
{
    const bool quoted            = json.size() >= 2 && json.front() == '"' && json.back() == '"';
    const std::string_view inner = quoted ? json.substr(1, json.size() - 2) : json;
    if (key == "ram_mb")
        return !quoted && !inner.empty() && inner.size() <= 8 && is_decimal(inner) && inner.front() != '0';
    if (key == "screen")
    {
        const std::size_t cross = inner.find('x');
        if (!quoted || cross == std::string_view::npos)
            return false;
        const auto size_ok = [](std::string_view part)
        { return !part.empty() && part.size() <= 6 && is_decimal(part) && part.front() != '0'; };
        return size_ok(inner.substr(0, cross)) && size_ok(inner.substr(cross + 1));
    }
    // The profile's keys and glibc are dotted versions; a key this library does not know is the author's
    static constexpr std::array<std::string_view, 6> dotted { "glibc", "firmware", "atmosphere", "luma",
        "goldhen", "sdk" };
    return !std::ranges::contains(dotted, key) || (quoted && is_dotted(inner));
}

// § 8.7: the shapes of the keys this library knows.
Result<void> check_requires(const Requires& requires_)
{
    if (requires_.text.empty() || requires_.text.size() > 4096)
        return fail(Category::usage, "requires has a text of 4096 bytes at most");
    if (requires_.min)
    {
        for (const auto& [key, value] : requires_.min->members)
        {
            if (!min_value_ok(key, value))
                return fail(Category::usage, "a requires.min value that is not of its key's form (§ 8.7)");
        }
    }
    if (requires_.gpu.size() > 8
        || std::ranges::any_of(requires_.gpu, [](const String& name) { return name.empty(); }))
        return fail(Category::usage, "requires.gpu lists 8 names at most");
    if (requires_.homebrew.size() > 32
        || std::ranges::any_of(requires_.homebrew, [](const Dependency& needed)
            { return !is_homebrew_id(needed.id) || needed.min_build > max_safe_integer; }))
        return fail(
            Category::usage, "requires.homebrew lists 32 homebrew at most, each by its id and min_build");
    return {};
}

// § 8.1: an entry's own fields, before its packages.
Result<void> check_homebrew_fields(const Homebrew& entry)
{
    if (!is_served_platform(entry.platform))
        return fail(Category::usage, "a platform that is not served (not a name, or web)");
    if (!is_homebrew_id(entry.id) || entry.system_id.size() > 128)
        return fail(
            Category::usage, "a homebrew id is reverse-DNS and lower-case, 128 bytes at most (§ 8.1)");
    if (!is_kind(entry.kind))
        return fail(Category::usage, "kind is a lower-case word, such as app, game, port or tool");
    if (entry.name.empty() || entry.name.size() > max_text || entry.author.size() > max_text
        || entry.version.empty() || entry.version.size() > max_text)
        return fail(
            Category::usage, "a homebrew has a name and a version, and its names are 512 bytes at most");
    if (entry.build > max_safe_integer)
        return fail(Category::usage, "build is an integer below 2^53");
    for (std::size_t i = 0; i < entry.genres.size(); ++i)
    {
        bool twice = false;
        for (std::size_t j = 0; j < i; ++j)
            twice = twice || entry.genres[j] == entry.genres[i];
        if (!is_genre(entry.genres[i]) || twice)
            return fail(Category::usage, "genres are from the list of § 7.1, each once");
    }
    if (entry.tags.size() > 32
        || std::ranges::any_of(entry.tags, [](const String& tag) { return tag.empty() || tag.size() > 64; }))
        return fail(Category::usage, "tags are 32 at most, 1 to 64 bytes each");
    if (entry.license.size() > 256 || entry.assets_license.size() > 256 || entry.source.size() > 4096
        || (!entry.source.empty() && !is_absolute_web_url(entry.source)))
        return fail(Category::usage, "license is 256 bytes at most, source an address");
    if (entry.language.size() > 35 || entry.summary.size() > 4096 || entry.description.size() > 4096)
        return fail(Category::usage, "language is 35 bytes at most, summary and description 4096");
    if ((!entry.summary.empty() || !entry.description.empty()) && entry.language.empty())
        return fail(Category::usage, "a homebrew with a summary or a description says its language (§ 2.2)");
    if ((entry.icon && !image_ok(*entry.icon)) || entry.screenshots.size() > 16
        || std::ranges::any_of(entry.screenshots, [](const Image& image) { return !image_ok(image); }))
        return fail(Category::usage,
            "images: 16 screenshots at most, each a path of this server or an absolute URL marked external");
    if (!entry.updated.empty() && !detail::parse_time(entry.updated))
        return fail(Category::usage, "updated is a UTC time: 2026-10-10T12:00:00Z");
    if (!entry.atlas.empty() && !is_atlas_id(entry.atlas))
        return fail(Category::usage, "atlas is a Wikidata item: Q900001");
    if (std::ranges::any_of(entry.ratings,
            [](const Rating& rating) {
                return !is_rating_system(rating.system) || rating.rating.empty() || rating.rating.size() > 16;
            }))
        return fail(Category::usage, "a rating is an organisation's short name and 1 to 16 bytes");
    if (entry.requires_)
    {
        if (auto checked = check_requires(*entry.requires_); !checked)
            return checked;
    }
    if (entry.port && entry.kind != "port")
        return fail(Category::usage, "only a homebrew of kind port has a port (§ 8.6)");
    return check_port(entry);
}

// One package of `entry` (the library's own copy: a signature is told apart
// by the address of its package) and its bytes: § 8.2, § 8.3, § 8.4.
Result<PackageSignature> check_package(
    const Homebrew& entry, const Package& package, std::span<const std::byte> content, bool is_main)
{
    if (!is_format(package.format))
        return fail(Category::usage, "a package's format is 1 to 16 letters or digits");
    if (package.size != content.size() || package.sha256 != Sha256::of(content))
        return fail(Category::usage, "a package's size and sha256 are those of its bytes (they are signed)");
    if (package.arch.size() > 8
        || std::ranges::any_of(package.arch, [](const String& name) { return !is_arch_name(name); }))
        return fail(Category::usage, "arch lists 8 architectures at most, each named as § 8.2 says");
    const Profile* profile = find_profile(entry.platform);
    if (profile != nullptr && profile->arches.empty() && !package.arch.empty())
        return fail(Category::usage, "a platform of one architecture has packages without arch (§ 8.2)");
    if (!is_main && package.arch.empty())
        return fail(Category::usage, "each of packages has its arch (§ 8.2)");
    if (package.mirrors.size() > max_mirrors)
        return fail(Category::usage, "a package has 8 mirrors at most");
    for (const Mirror& mirror : package.mirrors)
    {
        const auto parts = split_url(mirror.url);
        if (!parts || !check_untrusted_scheme(*parts))
            return fail(
                Category::usage, "a mirror is HTTPS, or HTTP at a private network's address (§ 19.2)");
    }
    if (profile != nullptr)
    {
        // Paths, roots, the format's place and the manifest's digest (§ 8.2, § 8.3)
        if (auto plan = plan_install(entry, package); !plan)
            return std::unexpected(plan.error());
    }
    else
    {
        if (package.manifest.size() > 4096 || manifest_digest(package.manifest) != package.manifest_sha256)
            return fail(
                Category::usage, "a manifest has 4096 files at most and the digest manifest_sha256 says");
        for (const ManifestEntry& file : package.manifest)
        {
            if (check_device_path(file.path) != PathProblem::none)
                return fail(Category::usage, "a manifest path breaks § 8.2's rules");
        }
    }
    return verify_package_signature(entry, package);
}

} // namespace

MemoryLibrary::MemoryLibrary(std::string_view base, const Allocator& allocator)
    : allocator_(allocator)
    , base_(base, allocator)
    , apps_(allocator)
    , files_(allocator)
    , media_(allocator)
    , titles_(allocator)
    , sections_(allocator)
    , homebrew_(allocator)
    , cheats_(allocator)
    , cheat_files_(allocator)
    , indexes_(allocator)
    , epoch_(allocator)
    , entries_(allocator)
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
    auto chunks = chunks_of(content, sha256);
    if (!chunks)
        return std::unexpected(chunks.error());
    app.chunks = std::move(*chunks);

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
    record(Entry::Kind::app_added, app.platform, app.id);
    notify("apps", app.platform, app.title_id);
    return app;
}

bool MemoryLibrary::has_app(std::string_view id) const noexcept
{
    return std::ranges::any_of(apps_, [&](const App& app) { return app.id == id; });
}

bool MemoryLibrary::remove_app(std::string_view id)
{
    for (std::size_t i = 0; i < apps_.size(); ++i)
    {
        if (apps_[i].id != id)
            continue;
        const App gone = apps_[i];
        apps_.erase(apps_.begin() + static_cast<std::ptrdiff_t>(i));
        // The package goes with the last app (or homebrew) that names it
        const std::string_view name = std::string_view(gone.file).substr(gone.file.rfind('/') + 1);
        if (!uses_file(name))
            std::erase_if(files_, [&](const Stored& stored) { return stored.name == name; });
        prune_indexes();
        record(Entry::Kind::app_removed, gone.platform, gone.id);
        notify("apps", gone.platform, gone.title_id);
        return true;
    }
    return false;
}

void MemoryLibrary::notify(std::string_view family, std::string_view platform, std::string_view title_id,
    const Vector<Rating>* ratings) const
{
    if (observer_ == nullptr)
        return;
    const std::array<LibraryChange, 1> changes { LibraryChange { family, platform, title_id, ratings } };
    observer_->library_changed(changes);
}

void MemoryLibrary::record(Entry::Kind kind, std::string_view platform, std::string_view key)
{
    if (keep_ == 0)
        return;
    Entry entry(allocator_);
    entry.position = ++sequence_;
    entry.kind     = kind;
    entry.platform.assign(platform);
    entry.key.assign(key);
    entries_.push_back(std::move(entry));
    if (entries_.size() > keep_)
    {
        const std::size_t dropped = entries_.size() - keep_;
        floor_                    = entries_[dropped - 1].position;
        entries_.erase(entries_.begin(), entries_.begin() + static_cast<std::ptrdiff_t>(dropped));
    }
}

Result<void> MemoryLibrary::keep_journal(std::size_t keep)
{
    if (keep < 1 || keep > max_journal)
        return fail(Category::usage, "a journal keeps 1 to 1000000 changes");
    if (keep_ == 0)
    {
        // Unique to this journal, so that a token of another process' is too old
        static std::atomic<std::uint64_t> counter { 0 };
        const auto now
            = static_cast<std::uint64_t>(std::chrono::system_clock::now().time_since_epoch().count());
        const auto number = (now << 8U) ^ counter.fetch_add(1);
        std::array<char, 24> text {};
        const auto result = std::to_chars(text.data(), text.data() + text.size(), number, 16);
        epoch_.assign(text.data(), static_cast<std::size_t>(result.ptr - text.data()));
    }
    keep_ = keep;
    return {};
}

const Title* MemoryLibrary::find_title(std::string_view platform, std::string_view title_id) const noexcept
{
    for (const Title& title : titles_)
    {
        if (title.platform == platform && title.title_id == title_id)
            return &title;
    }
    return nullptr;
}

Result<Title> MemoryLibrary::add_title(const Title& title)
{
    if (auto checked = check_title(title); !checked)
        return std::unexpected(checked.error());
    Title result(title, allocator_);
    bool replaced = false;
    for (Title& other : titles_)
    {
        if (other.platform == title.platform && other.title_id == title.title_id)
        {
            other    = result;
            replaced = true;
        }
    }
    if (!replaced)
        titles_.push_back(result);
    record(Entry::Kind::title, result.platform, result.title_id);
    titles_offered_ = true;
    notify("titles", result.platform, result.title_id);
    return result;
}

bool MemoryLibrary::remove_title(std::string_view platform, std::string_view title_id)
{
    for (std::size_t i = 0; i < titles_.size(); ++i)
    {
        if (titles_[i].platform == platform && titles_[i].title_id == title_id)
        {
            titles_.erase(titles_.begin() + static_cast<std::ptrdiff_t>(i));
            record(Entry::Kind::title, platform, title_id);
            notify("titles", platform, title_id);
            return true;
        }
    }
    return false;
}

Result<Image> MemoryLibrary::add_media(std::span<const std::byte> content, std::string_view extension)
{
    std::string_view type;
    if (extension == "png")
        type = "image/png";
    else if (extension == "jpg")
        type = "image/jpeg";
    else if (extension == "webp")
        type = "image/webp";
    else if (extension == "gif")
        type = "image/gif";
    else
        return fail(Category::usage, "an image is a png, jpg, webp or gif, its extension saying which");
    const Digest sha256 = Sha256::of(content);
    const auto hex      = to_hex(sha256);
    String name(hex.data(), hex.size(), allocator_);
    name.push_back('.');
    name.append(extension);
    if (std::ranges::none_of(media_, [&](const Stored& stored) { return stored.name == name; }))
    {
        Stored stored;
        stored.name         = name;
        stored.sha256       = sha256;
        stored.content_type = String(type, allocator_);
        stored.reader       = std::allocate_shared<MemoryFileReader>(
            std::pmr::polymorphic_allocator<MemoryFileReader>(allocator_), content, allocator_);
        media_.push_back(std::move(stored));
    }
    Image image(allocator_);
    image.url.assign(base_);
    image.url.append("/v1/media/");
    image.url.append(name);
    image.sha256 = sha256;
    return image;
}

Result<Section> MemoryLibrary::add_section(
    std::string_view id, std::string_view title, std::span<const std::string_view> apps)
{
    if (id.empty() || id.size() > max_text || title.size() > max_text)
        return fail(Category::usage, "a section's id is 1 to 512 bytes, its title 512 at most");
    if (std::ranges::any_of(apps, [](std::string_view app) { return app.empty() || app.size() > max_text; }))
        return fail(Category::usage, "an app's id in a section is 1 to 512 bytes");
    Section section(allocator_);
    section.id.assign(id);
    section.title.assign(title);
    for (const std::string_view app : apps)
        section.apps.emplace_back(app);
    sections_offered_ = true;
    for (Section& other : sections_)
    {
        if (other.id == id)
        {
            other = section;
            return section;
        }
    }
    sections_.push_back(section);
    return section;
}

bool MemoryLibrary::remove_section(std::string_view id)
{
    return std::erase_if(sections_, [&](const Section& section) { return section.id == id; }) > 0;
}

String MemoryLibrary::keep_file(std::span<const std::byte> content, const Digest& sha256)
{
    const auto hex = to_hex(sha256);
    String name("f_", allocator_);
    name.append(hex.data(), 24);
    if (std::ranges::none_of(files_, [&](const Stored& stored) { return stored.name == name; }))
    {
        Stored stored;
        stored.name   = name;
        stored.sha256 = sha256;
        stored.reader = std::allocate_shared<MemoryFileReader>(
            std::pmr::polymorphic_allocator<MemoryFileReader>(allocator_), content, allocator_);
        files_.push_back(std::move(stored));
    }
    String path(base_, allocator_);
    path.append("/v1/files/");
    path.append(name);
    return path;
}

bool MemoryLibrary::uses_file(std::string_view name) const noexcept
{
    const auto serves = [&](std::string_view file) { return file.ends_with(name); };
    if (std::ranges::any_of(apps_, [&](const App& app) { return serves(app.file); }))
        return true;
    return std::ranges::any_of(homebrew_,
        [&](const Homebrew& entry)
        {
            return serves(entry.package.file)
                || std::ranges::any_of(
                    entry.packages, [&](const Package& package) { return serves(package.file); });
        });
}

void MemoryLibrary::drop_unused_files(const Homebrew& gone)
{
    const auto drop = [&](const Package& package)
    {
        const std::string_view name = std::string_view(package.file).substr(package.file.rfind('/') + 1);
        if (!uses_file(name))
            std::erase_if(files_, [&](const Stored& stored) { return stored.name == name; });
    };
    drop(gone.package);
    for (const Package& package : gone.packages)
        drop(package);
    prune_indexes();
}

Result<Homebrew> MemoryLibrary::add_homebrew(
    const Homebrew& entry, std::span<const std::span<const std::byte>> contents)
{
    if (auto checked = check_homebrew_fields(entry); !checked)
        return std::unexpected(checked.error());
    if (entry.packages.size() > 16 || contents.size() != 1 + entry.packages.size())
        return fail(Category::usage, "an entry has 16 more packages at most, and the bytes of each");
    // The library's own copy: verify_package_signature() tells the package of the entry from the others by
    // address
    Homebrew result(entry, allocator_);
    std::optional<PublicKey> signer;
    for (std::size_t i = 0; i < contents.size(); ++i)
    {
        const Package& package = i == 0 ? result.package : result.packages[i - 1];
        const auto checked     = check_package(result, package, contents[i], i == 0);
        if (!checked)
            return std::unexpected(checked.error());
        if (!checked->is_signed)
            continue;
        if (signer && *signer != checked->public_key)
            return fail(Category::usage, "the packages of an entry are signed by one key (§ 8.4)");
        signer = checked->public_key;
    }
    if (!result.system_id.empty())
    {
        for (const Homebrew& other : homebrew_)
        {
            if (other.platform == result.platform && other.system_id == result.system_id
                && other.id != result.id)
                return fail(Category::usage, "two homebrew of a platform have the same system_id (§ 8.3)");
        }
    }
    // Everything is right: the files are served
    for (std::size_t i = 0; i < contents.size(); ++i)
    {
        Package& package = i == 0 ? result.package : result.packages[i - 1];
        package.file     = keep_file(contents[i], package.sha256);
        auto chunks      = chunks_of(contents[i], package.sha256);
        if (!chunks)
            return std::unexpected(chunks.error());
        if (deltas_offered_)
            package.chunks = std::move(*chunks);
    }
    for (Homebrew& other : homebrew_)
    {
        if (other.platform == result.platform && other.id == result.id)
        {
            const Homebrew replaced = std::move(other);
            other                   = result;
            drop_unused_files(replaced);
            homebrew_offered_ = true;
            notify("homebrew", result.platform, {}, &result.ratings);
            return result;
        }
    }
    homebrew_.push_back(result);
    homebrew_offered_ = true;
    notify("homebrew", result.platform, {}, &result.ratings);
    return result;
}

bool MemoryLibrary::remove_homebrew(std::string_view platform, std::string_view id)
{
    for (std::size_t i = 0; i < homebrew_.size(); ++i)
    {
        if (homebrew_[i].platform == platform && homebrew_[i].id == id)
        {
            const Homebrew gone = homebrew_[i];
            homebrew_.erase(homebrew_.begin() + static_cast<std::ptrdiff_t>(i));
            drop_unused_files(gone);
            notify("homebrew", gone.platform, {}, &gone.ratings);
            return true;
        }
    }
    return false;
}

Result<CheatSet> MemoryLibrary::put_cheat(const CheatWrite& given, std::string_view replacing)
{
    CheatWrite set(given, allocator_);
    if (set.source.empty())
        set.source.assign("Lantern");
    if (const std::string_view problem = detail::cheat_problem(set); !problem.empty())
        return fail(Category::usage, problem);

    CheatSet* same = nullptr;
    for (CheatSet& other : cheats_)
    {
        const bool key = other.platform == set.platform && other.title_id == set.title_id
            && other.build_id == set.build_id && other.source == set.source;
        if (replacing.empty() ? key : other.id == replacing)
            same = &other;
    }
    if (!replacing.empty() && same == nullptr)
        return fail(Category::usage, "no cheat set of that id");

    CheatSet made(allocator_);
    if (same != nullptr)
        made.id = same->id;
    else
    {
        // From what identifies the set: the same set, the same id
        Sha256 identity;
        for (const std::string_view part : { std::string_view(set.platform), std::string_view(set.title_id),
                 std::string_view(set.build_id), std::string_view(set.source) })
        {
            identity.update(part);
            identity.update(std::string_view("\x1f", 1));
        }
        const auto hex = to_hex(identity.finish());
        made.id.assign("cs_");
        made.id.append(hex.data(), 18);
    }
    made.platform  = set.platform;
    made.title_id  = set.title_id;
    made.build_id  = set.build_id;
    made.source    = set.source;
    made.note      = set.note;
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    String when(allocator_);
    format_sync_time(static_cast<std::int64_t>(now.count()), when);
    when.erase(19, 4); // whole seconds: 2026-10-10T12:00:00Z
    made.updated    = when;
    made.size       = set.text.size();
    const auto text = std::as_bytes(std::span(set.text.data(), set.text.size()));
    made.sha256     = Sha256::of(text);

    Stored stored;
    stored.name         = made.id;
    stored.sha256       = made.sha256;
    stored.content_type = String("text/plain; charset=utf-8", allocator_);
    stored.reader       = std::allocate_shared<MemoryFileReader>(
        std::pmr::polymorphic_allocator<MemoryFileReader>(allocator_), text, allocator_);
    if (same != nullptr)
    {
        *same        = made;
        Stored* slot = nullptr;
        for (Stored& file : cheat_files_)
        {
            if (file.name == made.id)
            {
                slot = &file;
                break;
            }
        }
        if (slot != nullptr)
            *slot = std::move(stored);
    }
    else
    {
        cheats_.push_back(made);
        cheat_files_.push_back(std::move(stored));
    }
    cheats_offered_ = true;
    notify("cheats", made.platform, made.title_id);
    return made;
}

Result<CheatSet> MemoryLibrary::add_cheat(const CheatWrite& set)
{
    return put_cheat(set, {});
}

bool MemoryLibrary::remove_cheat(std::string_view id)
{
    std::erase_if(cheat_files_, [&](const Stored& stored) { return stored.name == id; });
    for (std::size_t i = 0; i < cheats_.size(); ++i)
    {
        if (cheats_[i].id != id)
            continue;
        const CheatSet gone = cheats_[i];
        cheats_.erase(cheats_.begin() + static_cast<std::ptrdiff_t>(i));
        notify("cheats", gone.platform, gone.title_id);
        return true;
    }
    return false;
}

Result<Vector<Homebrew>> MemoryLibrary::homebrew(std::string_view /*languages*/, const Allocator& allocator)
{
    Vector<Homebrew> out(allocator);
    for (const Homebrew& entry : homebrew_)
        out.emplace_back(entry);
    return out;
}

Result<Vector<CheatSet>> MemoryLibrary::cheats(const Allocator& allocator)
{
    Vector<CheatSet> out(allocator);
    for (const CheatSet& set : cheats_)
        out.emplace_back(set);
    return out;
}

Result<std::optional<LibraryFile>> MemoryLibrary::cheat_file(std::string_view id, const Allocator& allocator)
{
    for (const Stored& stored : cheat_files_)
    {
        if (stored.name != id)
            continue;
        LibraryFile out(allocator);
        out.size         = stored.reader->bytes().size();
        out.sha256       = stored.sha256;
        out.content_type = stored.content_type;
        out.reader       = stored.reader;
        return std::optional<LibraryFile>(std::move(out));
    }
    return std::optional<LibraryFile> {};
}

Result<CheatSet> MemoryLibrary::write_cheat(
    const CheatWrite& set, std::string_view replacing, const Allocator& allocator)
{
    auto made = put_cheat(set, replacing);
    if (!made)
        return std::unexpected(made.error());
    return CheatSet(*made, allocator);
}

Result<bool> MemoryLibrary::delete_cheat(std::string_view id)
{
    return remove_cheat(id);
}

Result<Vector<Title>> MemoryLibrary::titles(std::string_view /*languages*/, const Allocator& allocator)
{
    Vector<Title> out(allocator);
    for (const Title& title : titles_)
        out.emplace_back(title);
    return out;
}

Result<std::optional<LibraryFile>> MemoryLibrary::media(std::string_view name, const Allocator& allocator)
{
    for (const Stored& stored : media_)
    {
        if (stored.name != name)
            continue;
        LibraryFile out(allocator);
        out.size         = stored.reader->bytes().size();
        out.sha256       = stored.sha256;
        out.content_type = stored.content_type;
        out.reader       = stored.reader;
        return std::optional<LibraryFile>(std::move(out));
    }
    return std::optional<LibraryFile> {};
}

Result<Vector<Section>> MemoryLibrary::sections(std::string_view /*languages*/, const Allocator& allocator)
{
    Vector<Section> out(allocator);
    for (const Section& section : sections_)
        out.emplace_back(section);
    return out;
}

Result<JournalPosition> MemoryLibrary::position(const Allocator& allocator)
{
    JournalPosition out(allocator);
    out.epoch.assign(epoch_);
    out.position = sequence_;
    out.oldest   = floor_;
    return out;
}

Result<AppChanges> MemoryLibrary::app_changes(
    std::uint64_t after, std::string_view platform, const Allocator& allocator)
{
    AppChanges out(allocator);
    for (const Entry& entry : entries_)
    {
        if (entry.position <= after || (!platform.empty() && entry.platform != platform))
            continue;
        if (entry.kind == Entry::Kind::app_added)
        {
            // Once, in the order they came, and only if still there
            if (std::ranges::any_of(out.added, [&](const App& app) { return app.id == entry.key; }))
                continue;
            for (const App& app : apps_)
            {
                if (app.id == entry.key)
                    out.added.emplace_back(app);
            }
        }
        else if (entry.kind == Entry::Kind::app_removed && !has_app(entry.key)
            && std::ranges::none_of(out.removed, [&](const String& id) { return id == entry.key; }))
        {
            out.removed.emplace_back(entry.key);
        }
    }
    std::ranges::sort(out.removed);
    return out;
}

Result<TitleDelta> MemoryLibrary::title_changes(std::uint64_t after, std::string_view platform,
    std::string_view /*languages*/, const Allocator& allocator)
{
    // The titles touched since, once each, in order of platform and id
    Vector<const Entry*> touched(allocator);
    for (const Entry& entry : entries_)
    {
        if (entry.kind != Entry::Kind::title || entry.position <= after
            || (!platform.empty() && entry.platform != platform))
            continue;
        if (std::ranges::none_of(touched, [&](const Entry* other)
                { return other->platform == entry.platform && other->key == entry.key; }))
            touched.push_back(&entry);
    }
    std::ranges::sort(touched, [](const Entry* a, const Entry* b)
        { return a->platform != b->platform ? a->platform < b->platform : a->key < b->key; });
    TitleDelta out(allocator);
    for (const Entry* entry : touched)
    {
        if (const Title* title = find_title(entry->platform, entry->key))
            out.titles.emplace_back(*title);
        else
        {
            out.removed.emplace_back();
            out.removed.back().platform.assign(entry->platform);
            out.removed.back().title_id.assign(entry->key);
        }
    }
    return out;
}

Result<Vector<String>> MemoryLibrary::platforms(const Allocator& allocator)
{
    Vector<String> out(allocator);
    for (const App& app : apps_)
    {
        if (std::ranges::none_of(out, [&](const String& platform) { return platform == app.platform; }))
            out.emplace_back(app.platform);
    }
    for (const Title& title : titles_)
    {
        if (std::ranges::none_of(out, [&](const String& platform) { return platform == title.platform; }))
            out.emplace_back(title.platform);
    }
    for (const Homebrew& entry : homebrew_)
    {
        if (std::ranges::none_of(out, [&](const String& platform) { return platform == entry.platform; }))
            out.emplace_back(entry.platform);
    }
    for (const CheatSet& set : cheats_)
    {
        if (std::ranges::none_of(out, [&](const String& platform) { return platform == set.platform; }))
            out.emplace_back(set.platform);
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

Result<void> MemoryLibrary::offer_deltas(const ChunkingOptions& options)
{
    if (options.chunker_size != 0 && !is_cdc_size(options.chunker_size))
        return fail(
            Category::usage, "a chunker's size is a power of two from 65536 to 4194304 (SPEC.md 22.1)");
    deltas_         = options;
    deltas_offered_ = true;
    return {};
}

Result<std::optional<AppChunks>> MemoryLibrary::chunks_of(
    std::span<const std::byte> content, const Digest& sha256)
{
    if (!deltas_offered_ || content.size() < deltas_.min_file_size)
        return std::optional<AppChunks> {};
    const auto file_hex = to_hex(sha256);
    const std::string_view name(file_hex.data(), file_hex.size());
    const Stored* kept = nullptr;
    for (const Stored& stored : indexes_)
    {
        if (stored.name == name)
            kept = &stored;
    }
    if (kept == nullptr)
    {
        const std::optional<std::uint64_t> size = deltas_.chunker_size != 0
            ? std::optional<std::uint64_t>(deltas_.chunker_size)
            : cdc_size_for(content.size());
        // A file too large for any chunker gets no index
        if (!size)
            return std::optional<AppChunks> {};
        const auto cuts = cdc_cut(content, *size, allocator_);
        if (!cuts)
            return std::unexpected(cuts.error());
        // Canonical JSON (§ 2.3): the names in order, no space
        String text(allocator_);
        json::Writer w(text);
        w.begin_object();
        w.key("chunker");
        w.begin_object();
        w.key("alg");
        w.string(cdc_algorithm);
        w.key("size");
        w.number(*size);
        w.end_object();
        w.key("chunks");
        w.begin_array();
        for (const Cut& cut : *cuts)
        {
            const auto chunk_hex = to_hex(Sha256::of(content.subspan(cut.offset, cut.length)));
            w.begin_array();
            w.number(static_cast<std::uint64_t>(cut.length));
            w.string(std::string_view(chunk_hex.data(), chunk_hex.size()));
            w.end_array();
        }
        w.end_array();
        w.key("schema");
        w.number(known_schema);
        w.key("sha256");
        w.string(name);
        w.key("size");
        w.number(static_cast<std::uint64_t>(content.size()));
        w.end_object();
        Stored stored;
        stored.name   = String(name, allocator_);
        stored.sha256 = Sha256::of(std::string_view(text));
        stored.reader = std::allocate_shared<MemoryFileReader>(
            std::pmr::polymorphic_allocator<MemoryFileReader>(allocator_),
            std::as_bytes(std::span(text.data(), text.size())), allocator_);
        indexes_.push_back(std::move(stored));
        kept = &indexes_.back();
    }
    AppChunks chunks(allocator_);
    chunks.url.assign(base_);
    chunks.url.append("/v1/chunks/sha256/");
    chunks.url.append(name);
    chunks.size   = kept->reader->bytes().size();
    chunks.sha256 = kept->sha256;
    return std::optional<AppChunks>(std::move(chunks));
}

void MemoryLibrary::prune_indexes()
{
    const auto used = [&](const Stored& index)
    {
        const auto uses = [&](const Digest& sha256)
        {
            const auto hex = to_hex(sha256);
            return index.name == std::string_view(hex.data(), hex.size());
        };
        for (const App& app : apps_)
        {
            if (app.chunks && uses(app.sha256))
                return true;
        }
        for (const Homebrew& entry : homebrew_)
        {
            if (entry.package.chunks && uses(entry.package.sha256))
                return true;
            for (const Package& package : entry.packages)
            {
                if (package.chunks && uses(package.sha256))
                    return true;
            }
        }
        return false;
    };
    std::erase_if(indexes_, [&](const Stored& index) { return !used(index); });
}

Result<std::optional<LibraryFile>> MemoryLibrary::chunk_index(
    const Digest& file_sha256, const Allocator& allocator)
{
    const auto hex = to_hex(file_sha256);
    for (const Stored& stored : indexes_)
    {
        if (stored.name != std::string_view(hex.data(), hex.size()))
            continue;
        LibraryFile out(allocator);
        out.size   = stored.reader->bytes().size();
        out.sha256 = stored.sha256;
        out.content_type.assign("application/json");
        out.reader = stored.reader;
        return std::optional<LibraryFile>(std::move(out));
    }
    return std::optional<LibraryFile> {};
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
