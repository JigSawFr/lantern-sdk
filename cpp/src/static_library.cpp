// SPEC.md § 21: static libraries, read as files.
#include <lantern/static_library.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>
#include <utility>

#include <lantern/digest.hpp>
#include <lantern/profiles.hpp>
#include <lantern/url.hpp>

namespace lantern
{

namespace
{

constexpr std::size_t max_cheat_text   = std::size_t { 1024 } * 1024;
constexpr std::uint64_t max_pages      = 100000;
constexpr std::size_t max_header_bytes = std::size_t { 8 } * 1024;

bool equal_ignoring_case(std::string_view a, std::string_view b) noexcept
{
    const auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(), [&](char x, char y) { return lower(x) == lower(y); });
}

// A path segment of an id: of the core's form, and not "." or "..".
bool segment(std::string_view id) noexcept
{
    return is_core_id(id) && id != "." && id != "..";
}

// The families a static library cannot offer (L-21.2-1).
bool offers_none_it_cannot(const HandshakeFeatures& f) noexcept
{
    const std::array families { &f.changes, &f.sections, &f.saves, &f.encrypted_saves, &f.requests,
        &f.pairing, &f.signatures, &f.admin, &f.events, &f.peers, &f.sync };
    return std::ranges::all_of(
        families, [](const std::optional<std::uint64_t>* value) { return value->value_or(0) == 0; });
}

// Hashes what it passes on, bounded by the file's size.
class HashingSink final : public DownloadSink
{
  public:
    HashingSink(const DownloadTarget& target, DownloadState& state, DownloadSink& out) noexcept
        : target_(target)
        , state_(state)
        , out_(out)
        , hash_(state.hash)
    {
    }

    Result<void> write(std::span<const std::byte> bytes) override
    {
        if (bytes.size() > target_.size - state_.received)
            return fail(Category::integrity, "a file with more bytes than its size");
        if (auto written = out_.write(bytes); !written)
            return written;
        hash_.update(bytes);
        state_.received += bytes.size();
        state_.hash = hash_.state();
        return {};
    }

    Result<void> restart() override
    {
        state_.reset();
        hash_ = Sha256();
        return out_.restart();
    }

    [[nodiscard]] Sha256& hash() noexcept { return hash_; }

  private:
    const DownloadTarget& target_;
    DownloadState& state_;
    DownloadSink& out_;
    Sha256 hash_;
};

// The answer of a static file over HTTP: its body to the sink, whatever
// its Content-Type (§ 21.3).
class FileHandler final : public ResponseHandler
{
  public:
    FileHandler(DownloadSink& sink, std::uint64_t offset) noexcept
        : sink_(sink)
        , offset_(offset)
    {
    }

    bool on_status(std::uint16_t status) override
    {
        status_ = status;
        if (status == 200 && offset_ != 0)
        {
            // The whole file again: the host ignored the range
            if (auto restarted = sink_.restart(); !restarted)
                return stop(restarted.error());
        }
        return true;
    }

    bool on_header(std::string_view name, std::string_view value) override
    {
        if (++headers_ > 64 || value.size() > max_header_bytes)
            return stop(Error::make(Category::limit, "an answer with too many or too long headers"));
        if (status_ == 206 && equal_ignoring_case(name, "Content-Range"))
        {
            std::string_view rest = value;
            std::uint64_t first   = 0;
            if (!rest.starts_with("bytes "))
                return stop(
                    Error::make(Category::invalid_response, "a Content-Range that is not the range asked"));
            rest.remove_prefix(6);
            const auto result = std::from_chars(rest.data(), rest.data() + rest.size(), first);
            if (result.ec != std::errc {} || first != offset_)
                return stop(
                    Error::make(Category::invalid_response, "a Content-Range that is not the range asked"));
            range_checked_ = true;
        }
        return true;
    }

    bool on_body(std::span<const std::byte> chunk) override
    {
        if (status_ != 200 && status_ != 206)
            return false;
        if (status_ == 206 && !range_checked_)
            return stop(Error::make(Category::invalid_response, "a 206 without its Content-Range"));
        if (auto written = sink_.write(chunk); !written)
            return stop(written.error());
        return true;
    }

    [[nodiscard]] std::uint16_t status() const noexcept { return status_; }
    [[nodiscard]] const std::optional<Error>& error() const noexcept { return error_; }

  private:
    bool stop(const Error& error)
    {
        error_ = error;
        return false;
    }

    DownloadSink& sink_;
    std::uint64_t offset_;
    std::uint16_t status_ = 0;
    std::size_t headers_  = 0;
    bool range_checked_   = false;
    std::optional<Error> error_;
};

// Percent-encodes what a path may hold that a request line may not.
void append_path(String& url, std::string_view path)
{
    static constexpr std::string_view hex = "0123456789ABCDEF";
    for (const char c : path)
    {
        const auto byte  = static_cast<unsigned char>(c);
        const bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || c == '-' || c == '.' || c == '_' || c == '~' || c == '/';
        if (plain)
            url.push_back(c);
        else
        {
            url.push_back('%');
            url.push_back(hex[byte >> 4U]);
            url.push_back(hex[byte & 15U]);
        }
    }
}

} // namespace

bool is_static_path(std::string_view path) noexcept
{
    if (path.empty() || path.size() > 4096 || path.front() == '/')
        return false;
    if (std::ranges::any_of(path,
            [](char c)
            {
                const auto byte = static_cast<unsigned char>(c);
                return c == '\\' || c == '?' || c == '#' || byte < 0x20U || byte == 0x7FU;
            }))
        return false;
    // A scheme: letters, digits, + . - then ':', before any '/'
    const std::size_t colon = path.find(':');
    if (colon != std::string_view::npos && colon < path.find('/'))
    {
        const std::string_view scheme = path.substr(0, colon);
        const bool is_scheme          = !scheme.empty()
            && ((scheme.front() >= 'a' && scheme.front() <= 'z')
                || (scheme.front() >= 'A' && scheme.front() <= 'Z'))
            && std::ranges::all_of(scheme,
                [](char c)
                {
                    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                        || c == '+' || c == '.' || c == '-';
                });
        if (is_scheme)
            return false;
    }
    // No ".." part
    std::size_t start = 0;
    for (;;)
    {
        const std::size_t end = std::min(path.find('/', start), path.size());
        if (path.substr(start, end - start) == "..")
            return false;
        if (end == path.size())
            return true;
        start = end + 1;
    }
}

// Over HTTP.

HttpStaticFiles::HttpStaticFiles(Transport& transport, Allocator allocator)
    : transport_(&transport)
    , root_(allocator)
    , user_agent_(allocator)
{
}

Result<HttpStaticFiles> HttpStaticFiles::create(
    Transport& transport, std::string_view root, std::string_view user_agent, Allocator allocator)
{
    const auto parts = split_url(root);
    if (!parts)
        return std::unexpected(parts.error());
    // § 21.3: § 2 holds, HTTPS but on loopback
    if (auto scheme = check_scheme(*parts); !scheme)
        return std::unexpected(scheme.error());
    if (!root.ends_with('/') || parts->target.find_first_of("?#") != std::string_view::npos)
        return fail(Category::usage, "a static library's root is an address ending with /, without a query");
    const std::size_t slash = user_agent.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 == user_agent.size()
        || std::ranges::any_of(
            user_agent, [](char c) { return static_cast<unsigned char>(c) < 0x20U || c == 0x7F; }))
        return fail(Category::usage, "the User-Agent is Name/version (SPEC.md 2)");
    HttpStaticFiles files(transport, allocator);
    files.root_.assign(root);
    files.user_agent_.assign(user_agent);
    return files;
}

Result<void> HttpStaticFiles::read(std::string_view path, std::uint64_t offset, DownloadSink& sink)
{
    if (!is_static_path(path))
        return fail(Category::invalid_response,
            "a static library's path that is not relative to its root (SPEC.md 21.1)");
    String url(root_);
    append_path(url, path);
    std::array<char, 40> range {};
    std::array<Header, 3> headers { { { "User-Agent", user_agent_ },
        { "Accept", "application/json, */*" } } };
    std::size_t count = 2;
    if (offset != 0)
    {
        const std::string_view prefix = "bytes=";
        std::ranges::copy(prefix, range.begin());
        const auto result
            = std::to_chars(range.data() + prefix.size(), range.data() + range.size() - 1, offset);
        *result.ptr      = '-';
        headers[count++] = { "Range",
            std::string_view(range.data(), static_cast<std::size_t>(result.ptr + 1 - range.data())) };
    }
    Request request;
    request.url     = url;
    request.headers = std::span(headers.data(), count);
    FileHandler handler(sink, offset);
    const auto sent = transport_->send(request, handler);
    if (handler.error())
        return std::unexpected(*handler.error());
    if (handler.status() != 0 && handler.status() != 200 && handler.status() != 206)
        return std::unexpected(Error::from_status(handler.status()));
    if (!sent)
        return sent;
    if (handler.status() == 0)
        return fail(Category::transport, "no answer");
    return {};
}

// The library.

StaticLibrary::StaticLibrary(StaticFiles& files, const DecodeOptions& options)
    : files_(&files)
    , decode_(options)
    , allocator_(options.memory)
    , handshake_(allocator_)
{
}

Result<String> StaticLibrary::fetch(std::string_view path, bool missing_ok, bool& missing)
{
    missing = false;
    MemorySink sink(decode_.limits.max_document, allocator_);
    if (auto done = files_->read(path, 0, sink); !done)
    {
        if (missing_ok && done.error().status() == 404)
        {
            missing = true;
            return String(allocator_);
        }
        return std::unexpected(done.error());
    }
    return String(sink.text(), allocator_);
}

Read<StaticLibrary> StaticLibrary::open(StaticFiles& files, const DecodeOptions& options)
{
    StaticLibrary library(files, options);
    bool missing    = false;
    const auto text = library.fetch("lantern.json", false, missing);
    if (!text)
        return std::unexpected(text.error());
    auto read = read_handshake(*text, options);
    if (!read)
        return std::unexpected(read.error());
    if (!*read)
        return std::optional<StaticLibrary> {};
    const Handshake& handshake = **read;
    if (!handshake.static_)
        return fail(Category::unsupported,
            "a handshake without static: a server, not a static library (SPEC.md 21.2)");
    if (handshake.base != ".")
        return fail(Category::invalid_response, "a static library's base is \".\" (SPEC.md 21.2)");
    if (!offers_none_it_cannot(handshake.features) || handshake.account.state != "anonymous")
        return fail(Category::invalid_response, "a static library offers a family it cannot (SPEC.md 21.2)");
    if (std::ranges::find(handshake.versions, std::uint64_t { 1 }) == handshake.versions.end())
        return fail(Category::unsupported, "a library that does not serve version 1 of the protocol");
    library.handshake_ = Handshake(std::move(**read), library.allocator_);
    return std::optional<StaticLibrary>(std::move(library));
}

Result<void> StaticLibrary::platform_ok(std::string_view platform) const
{
    if (!is_platform_name(platform)
        || std::ranges::find(handshake_.platforms, platform) == handshake_.platforms.end())
        return fail(Category::usage, "a platform the static library does not have (SPEC.md 21.1)");
    return {};
}

namespace
{

// A cursor of § 21.1: the page's number, 2 at least; empty for the first.
Result<std::uint64_t> page_number(std::string_view cursor)
{
    if (cursor.empty())
        return 1;
    std::uint64_t page = 0;
    const auto result  = std::from_chars(cursor.data(), cursor.data() + cursor.size(), page);
    if (result.ec != std::errc {} || result.ptr != cursor.data() + cursor.size() || page < 2
        || page > max_pages || cursor.front() == '0')
        return fail(Category::usage, "a static library's cursor is a page number (SPEC.md 21.1)");
    return page;
}

// A page's `next`: none, or the page after it (§ 21.1).
Result<void> next_ok(std::string_view cursor, std::string_view next)
{
    if (next.empty())
        return {};
    const auto page = page_number(cursor);
    if (!page)
        return std::unexpected(page.error());
    std::array<char, 24> digits {};
    auto* const end = std::to_chars(digits.data(), digits.data() + digits.size(), *page + 1).ptr;
    if (next != std::string_view(digits.data(), static_cast<std::size_t>(end - digits.data())))
        return fail(
            Category::invalid_response, "a static page whose next is not the page after it (SPEC.md 21.1)");
    return {};
}

} // namespace

Result<String> StaticLibrary::page_path(
    std::string_view family, std::string_view platform, std::string_view cursor) const
{
    if (auto ok = platform_ok(platform); !ok)
        return std::unexpected(ok.error());
    const auto page = page_number(cursor);
    if (!page)
        return std::unexpected(page.error());
    String path(allocator_);
    path.append("v1/");
    path.append(family);
    path.push_back('/');
    path.append(platform);
    path.append("/pages/");
    std::array<char, 24> digits {};
    auto* const end = std::to_chars(digits.data(), digits.data() + digits.size(), *page).ptr;
    path.append(digits.data(), end);
    path.append(".json");
    return path;
}

Read<AppsPage> StaticLibrary::apps(std::string_view platform, std::string_view cursor)
{
    const auto path = page_path("apps", platform, cursor);
    if (!path)
        return std::unexpected(path.error());
    bool missing    = false;
    const auto text = fetch(*path, false, missing);
    if (!text)
        return std::unexpected(text.error());
    auto read = read_apps_page(*text, decode_);
    if (!read || !*read)
        return read;
    if (auto ok = next_ok(cursor, (*read)->next); !ok)
        return std::unexpected(ok.error());
    for (const App& app : (*read)->items)
    {
        if (!is_static_path(app.file))
            return fail(
                Category::invalid_response, "an app's file that is not relative to the root (L-21.1-2)");
    }
    return read;
}

Read<Titles> StaticLibrary::titles(std::string_view platform, std::string_view cursor)
{
    const auto path = page_path("titles", platform, cursor);
    if (!path)
        return std::unexpected(path.error());
    bool missing    = false;
    const auto text = fetch(*path, false, missing);
    if (!text)
        return std::unexpected(text.error());
    auto read = read_titles(*text, decode_);
    if (!read || !*read)
        return read;
    if (auto ok = next_ok(cursor, (*read)->next); !ok)
        return std::unexpected(ok.error());
    return read;
}

Read<HomebrewPage> StaticLibrary::homebrew(std::string_view platform, std::string_view cursor)
{
    const auto path = page_path("homebrew", platform, cursor);
    if (!path)
        return std::unexpected(path.error());
    bool missing    = false;
    const auto text = fetch(*path, false, missing);
    if (!text)
        return std::unexpected(text.error());
    auto read = read_homebrew_page(*text, decode_);
    if (!read || !*read)
        return read;
    if (auto ok = next_ok(cursor, (*read)->next); !ok)
        return std::unexpected(ok.error());
    for (const Homebrew& entry : (*read)->items)
    {
        if (!is_static_path(entry.package.file)
            || std::ranges::any_of(entry.packages, [](const Package& p) { return !is_static_path(p.file); }))
            return fail(
                Category::invalid_response, "a package's file that is not relative to the root (L-21.1-2)");
    }
    return read;
}

Read<Title> StaticLibrary::title(std::string_view platform, std::string_view title_id)
{
    if (auto ok = platform_ok(platform); !ok)
        return std::unexpected(ok.error());
    if (!segment(title_id))
        return fail(Category::usage, "not a title id (SPEC.md 6.1)");
    String path(allocator_);
    path.append("v1/titles/");
    path.append(platform);
    path.push_back('/');
    path.append(title_id);
    path.append(".json");
    bool missing    = false;
    const auto text = fetch(path, false, missing);
    if (!text)
        return std::unexpected(text.error());
    return read_title(*text, decode_);
}

Read<Homebrew> StaticLibrary::homebrew_entry(std::string_view platform, std::string_view id)
{
    if (auto ok = platform_ok(platform); !ok)
        return std::unexpected(ok.error());
    if (!is_homebrew_id(id))
        return fail(Category::usage, "not a homebrew id (SPEC.md 8.1)");
    String path(allocator_);
    path.append("v1/homebrew/");
    path.append(platform);
    path.push_back('/');
    path.append(id);
    path.append(".json");
    bool missing    = false;
    const auto text = fetch(path, false, missing);
    if (!text)
        return std::unexpected(text.error());
    auto read = read_homebrew(*text, decode_);
    if (read && *read
        && (!is_static_path((*read)->package.file)
            || std::ranges::any_of(
                (*read)->packages, [](const Package& p) { return !is_static_path(p.file); })))
        return fail(
            Category::invalid_response, "a package's file that is not relative to the root (L-21.1-2)");
    return read;
}

Read<CheatSets> StaticLibrary::cheats(std::string_view platform, std::string_view title_id)
{
    if (auto ok = platform_ok(platform); !ok)
        return std::unexpected(ok.error());
    if (!segment(title_id))
        return fail(Category::usage, "not a title id (SPEC.md 6.1)");
    String path(allocator_);
    path.append("v1/cheats/");
    path.append(platform);
    path.push_back('/');
    path.append(title_id);
    path.append(".json");
    bool missing    = false;
    const auto text = fetch(path, true, missing);
    if (!text)
        return std::unexpected(text.error());
    if (missing)
        return std::optional<CheatSets>(CheatSets(allocator_));
    return read_cheat_sets(*text, decode_);
}

Result<String> StaticLibrary::cheat_text(const CheatSet& set)
{
    if (set.size > max_cheat_text)
        return fail(Category::limit, "a cheat set above 1 MiB (SPEC.md 13)");
    if (!segment(set.id))
        return fail(Category::invalid_response, "a cheat set's id that is no path segment");
    String path(allocator_);
    path.append("v1/cheats/");
    path.append(set.id);
    path.append(".txt");
    MemorySink sink(static_cast<std::size_t>(set.size), allocator_);
    DownloadState state;
    const DownloadTarget target { path, set.size, set.sha256 };
    if (auto done = download(target, state, sink); !done)
        return std::unexpected(done.error());
    return String(sink.text(), allocator_);
}

Result<void> StaticLibrary::download(const DownloadTarget& target, DownloadState& state, DownloadSink& sink)
{
    if (!is_static_path(target.url))
        return fail(Category::invalid_response, "a file that is not relative to the root (L-21.1-2)");
    if (state.received > target.size)
        return fail(Category::usage, "a download state past the file's size");
    HashingSink hashing(target, state, sink);
    if (state.received < target.size || target.size == 0)
    {
        if (auto done = files_->read(target.url, state.received, hashing); !done)
        {
            if (done.error().category() == Category::integrity)
                state.reset();
            return done;
        }
    }
    if (state.received != target.size)
        return fail(Category::transport, "the file was cut short: call again to resume");
    Sha256 hash(state.hash);
    if (!same_digest(hash.finish(), target.sha256))
    {
        state.reset();
        return fail(Category::integrity, "the file's SHA-256 is not the document's: install nothing");
    }
    return {};
}

Result<Vector<App>> StaticLibrary::missing(std::string_view platform, const MissingRequest& request)
{
    // Every app of the platform, page after page
    Vector<App> apps(allocator_);
    String cursor(allocator_);
    for (std::uint64_t pages = 0;; ++pages)
    {
        if (pages >= max_pages)
            return fail(Category::limit, "a listing of too many pages");
        auto page = this->apps(platform, cursor);
        if (!page)
            return std::unexpected(page.error());
        if (!*page)
            return fail(Category::unsupported, "a page of a newer schema (SPEC.md 3.2)");
        for (App& app : (*page)->items)
        {
            if (app.platform == platform)
                apps.push_back(std::move(app));
        }
        if ((*page)->next.empty())
            break;
        cursor.assign((*page)->next);
    }
    const Profile* profile = find_profile(platform);
    const bool replaces    = profile != nullptr && profile->newer_base_is_update;
    const auto wants
        = [&](std::string_view what) { return std::ranges::find(request.want, what) != request.want.end(); };
    const auto by_app = [&](std::string_view app_id) -> const App*
    {
        const auto found = std::ranges::find_if(apps, [&](const App& app) { return app.app_id == app_id; });
        return found == apps.end() ? nullptr : &*found;
    };
    const auto installed = [&](std::string_view app_id) {
        return std::ranges::any_of(
            request.installed, [&](const InstalledApp& i) { return i.app_id == app_id; });
    };
    // The installed games, each with its highest version (§ 6.3)
    struct Game
    {
        String title;
        std::uint64_t version;
    };
    Vector<Game> have(allocator_);
    for (const InstalledApp& item : request.installed)
    {
        String title(allocator_);
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
    Vector<App> out(allocator_);
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
    return out;
}

Result<Vector<Homebrew>> StaticLibrary::homebrew_updates(
    std::string_view platform, const HomebrewUpdatesRequest& request)
{
    Vector<Homebrew> out(allocator_);
    String cursor(allocator_);
    for (std::uint64_t pages = 0;; ++pages)
    {
        if (pages >= max_pages)
            return fail(Category::limit, "a listing of too many pages");
        auto page = homebrew(platform, cursor);
        if (!page)
            return std::unexpected(page.error());
        if (!*page)
            return fail(Category::unsupported, "a page of a newer schema (SPEC.md 3.2)");
        for (Homebrew& entry : (*page)->items)
        {
            std::optional<std::uint64_t> build;
            for (const InstalledHomebrew& item : request.installed)
            {
                if (item.id == entry.id)
                    build = std::max(build.value_or(0), item.build);
            }
            if (build && entry.build > *build)
                out.push_back(std::move(entry));
        }
        if ((*page)->next.empty())
            break;
        cursor.assign((*page)->next);
    }
    return out;
}

} // namespace lantern
