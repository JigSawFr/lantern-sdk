// A Library held in memory (SPEC.md § 6.1): for tests and demos.
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>

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

} // namespace

MemoryLibrary::MemoryLibrary(std::string_view base, const Allocator& allocator)
    : allocator_(allocator)
    , base_(base, allocator)
    , apps_(allocator)
    , files_(allocator)
    , media_(allocator)
    , titles_(allocator)
    , sections_(allocator)
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
        // The package goes with the last app that names it
        const std::string_view name = std::string_view(gone.file).substr(gone.file.rfind('/') + 1);
        if (std::ranges::none_of(
                apps_, [&](const App& other) { return std::string_view(other.file).ends_with(name); }))
        {
            std::erase_if(files_, [&](const Stored& stored) { return stored.name == name; });
        }
        record(Entry::Kind::app_removed, gone.platform, gone.id);
        return true;
    }
    return false;
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
